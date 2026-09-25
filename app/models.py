"""Core domain data types."""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class User:
    username: str
    password_hash: str
    roles: frozenset[str]
    # Bumped on every password change; sessions issued before this
    # generation are considered invalid.
    password_generation: int = 0


@dataclass
class Session:
    session_id: str
    username: str
    created_at: float
    expires_at: float
    csrf_token: str
    csrf_expires_at: float
    password_generation: int  # generation at login time
    revoked: bool = False

    def is_expired(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        return now >= self.expires_at


@dataclass
class LockoutState:
    """Failure tracking for one (account, source) pair."""
    failures: list[float] = field(default_factory=list)
    locked_until: float = 0.0
