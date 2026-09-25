"""Thread-safe in-memory stores.

All mutations that must be atomic under concurrency (session create/revoke,
failure counting, lockout checks) happen while holding a single lock per
store, so concurrent requests observe a consistent state.
"""
from __future__ import annotations

import threading
import time

from .config import Settings
from .models import LockoutState, Session, User


class UserStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._users: dict[str, User] = {}

    def add(self, user: User) -> None:
        with self._lock:
            self._users[user.username] = user

    def get(self, username: str) -> User | None:
        with self._lock:
            return self._users.get(username)

    def bump_password_generation(self, username: str, new_hash: str) -> int:
        """Change password and invalidate all prior sessions via generation bump."""
        with self._lock:
            user = self._users[username]
            user.password_hash = new_hash
            user.password_generation += 1
            return user.password_generation


class SessionStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}

    def put(self, session: Session) -> None:
        with self._lock:
            self._sessions[session.session_id] = session

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def revoke(self, session_id: str) -> bool:
        """Revoke one session independently of the account's other sessions."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False
            session.revoked = True
            return True

    def revoke_all_for_user(self, username: str) -> int:
        with self._lock:
            count = 0
            for session in self._sessions.values():
                if session.username == username and not session.revoked:
                    session.revoked = True
                    count += 1
            return count

    def sessions_for_user(self, username: str) -> list[Session]:
        with self._lock:
            return [s for s in self._sessions.values() if s.username == username]


class LockoutStore:
    """Sliding-window failure counts and lockout per (account, source) pair.

    ``check_and_record`` performs the locked-check and the failure-record
    atomically under one lock, so a burst of concurrent failures cannot
    overshoot the threshold without the lock engaging.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = threading.Lock()
        self._states: dict[tuple[str, str], LockoutState] = {}

    def _prune(self, state: LockoutState, now: float) -> None:
        window = self._settings.login_failure_window_seconds
        state.failures = [t for t in state.failures if now - t < window]

    def locked_until(self, account: str, source: str) -> float:
        with self._lock:
            state = self._states.get((account, source))
            return state.locked_until if state else 0.0

    def record_failure(self, account: str, source: str, now: float | None = None) -> float:
        """Record one failure; returns the time until which the pair is locked
        (0.0 if this failure did not trigger a lock)."""
        now = time.monotonic() if now is None else now
        with self._lock:
            state = self._states.setdefault((account, source), LockoutState())
            self._prune(state, now)
            state.failures.append(now)
            if len(state.failures) >= self._settings.login_max_failures:
                state.locked_until = now + self._settings.login_lockout_seconds
                state.failures.clear()
                return state.locked_until
            return state.locked_until if state.locked_until > now else 0.0

    def record_success(self, account: str, source: str) -> None:
        """A successful login clears the failure history for the pair."""
        with self._lock:
            self._states.pop((account, source), None)
