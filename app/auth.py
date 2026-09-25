"""Authentication service: login, logout, session lifecycle, lockout.

Design notes
------------
* Login failures never reveal whether the account exists: unknown users go
  through the same verify path (against a dummy hash) and the same lockout
  bookkeeping, and both yield ``INVALID_CREDENTIALS`` unless locked.
* Lockout state is per (account, source) and maintained under one lock in
  ``LockoutStore``, so concurrent failures cannot overshoot the threshold.
* Sessions carry the user's ``password_generation``; a password change bumps
  the generation and invalidates all previously issued sessions.
* Each session is revoked independently; other sessions of the same account
  keep working.
"""
from __future__ import annotations

import time

from .config import Settings
from .errors import AuthError, ErrorCode
from .models import Session, User
from .security import new_token, verify_password
from .store import LockoutStore, SessionStore, UserStore

# Verified against when the account does not exist, so timing does not
# leak account existence. Value is a valid-format pbkdf2 hash.
_DUMMY_HASH = (
    "pbkdf2_sha256$120000$"
    "0123456789abcdef0123456789abcdef$"
    "9" * 64
)


class AuthService:
    def __init__(
        self,
        settings: Settings,
        users: UserStore,
        sessions: SessionStore,
        lockouts: LockoutStore,
    ) -> None:
        self._settings = settings
        self._users = users
        self._sessions = sessions
        self._lockouts = lockouts

    # ------------------------------------------------------------------ login
    def login(self, username: str, password: str, source: str) -> Session:
        now = time.monotonic()

        locked_until = self._lockouts.locked_until(username, source)
        if locked_until > now:
            raise AuthError(
                ErrorCode.ACCOUNT_LOCKED,
                f"account locked for {locked_until - now:.1f}s more",
            )

        user = self._users.get(username)
        stored_hash = user.password_hash if user else _DUMMY_HASH
        ok = verify_password(password, stored_hash)
        if user is None:
            ok = False

        if not ok:
            locked_until = self._lockouts.record_failure(username, source, now)
            if locked_until > now:
                raise AuthError(
                    ErrorCode.ACCOUNT_LOCKED,
                    f"too many failures; locked for "
                    f"{locked_until - now:.1f}s",
                )
            # Same message whether the user exists or not.
            raise AuthError(ErrorCode.INVALID_CREDENTIALS, "invalid username or password")

        self._lockouts.record_success(username, source)
        return self._issue_session(user, now)

    def _issue_session(self, user: User, now: float) -> Session:
        ttl = self._settings.session_ttl_seconds
        session = Session(
            session_id=new_token(),
            username=user.username,
            created_at=now,
            expires_at=now + ttl,
            csrf_token=new_token(),
            csrf_expires_at=now + min(ttl, self._settings.csrf_ttl_seconds),
            password_generation=user.password_generation,
        )
        self._sessions.put(session)
        return session

    # --------------------------------------------------------------- sessions
    def authenticate(self, session_id: str | None) -> Session:
        """Resolve a session id to a live session or raise with a reason."""
        if not session_id:
            raise AuthError(ErrorCode.SESSION_MISSING, "no session cookie")
        session = self._sessions.get(session_id)
        if session is None or session.revoked:
            raise AuthError(ErrorCode.SESSION_INVALID, "session unknown or revoked")
        now = time.monotonic()
        if session.is_expired(now):
            raise AuthError(ErrorCode.SESSION_EXPIRED, "session expired")
        user = self._users.get(session.username)
        if user is None or user.password_generation != session.password_generation:
            raise AuthError(
                ErrorCode.SESSION_INVALID, "session invalidated by password change"
            )
        return session

    def logout(self, session_id: str) -> bool:
        """Revoke exactly this session; sibling sessions stay valid."""
        return self._sessions.revoke(session_id)

    def refresh(self, session_id: str) -> Session:
        """Extend a live session's expiry (and re-issue its CSRF token).

        Refresh is only allowed inside the refresh window near expiry, so
        the effective maximum idle time stays bounded and deterministic.
        """
        session = self.authenticate(session_id)
        now = time.monotonic()
        remaining = session.expires_at - now
        if remaining > self._settings.refresh_window_seconds:
            raise AuthError(
                ErrorCode.SESSION_INVALID,
                f"refresh only allowed within "
                f"{self._settings.refresh_window_seconds:.0f}s of expiry "
                f"({remaining:.0f}s remaining)",
            )
        session.expires_at = now + self._settings.session_ttl_seconds
        session.csrf_token = new_token()
        session.csrf_expires_at = now + min(
            self._settings.session_ttl_seconds, self._settings.csrf_ttl_seconds
        )
        return session

    def change_password(self, session_id: str, old_password: str, new_password: str) -> int:
        """Change password; invalidates *all* sessions of the account
        (including the current one) via generation bump + revocation."""
        session = self.authenticate(session_id)
        user = self._users.get(session.username)
        assert user is not None  # authenticate() guarantees the user exists
        if not verify_password(old_password, user.password_hash):
            raise AuthError(ErrorCode.INVALID_CREDENTIALS, "old password mismatch")
        from .security import hash_password

        self._users.bump_password_generation(user.username, hash_password(new_password))
        return self._sessions.revoke_all_for_user(user.username)

    # ------------------------------------------------------------------ users
    def get_user(self, username: str) -> User | None:
        return self._users.get(username)
