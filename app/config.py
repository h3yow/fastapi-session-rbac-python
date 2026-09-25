"""Tunable policy settings for sessions, lockout and CSRF."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    session_ttl_seconds: float = 1800.0        # absolute idle lifetime of a session
    refresh_window_seconds: float = 600.0      # refresh allowed when this much TTL remains
    csrf_ttl_seconds: float = 1800.0           # CSRF token lifetime (<= session TTL)
    login_max_failures: int = 5                # failures before lockout
    login_failure_window_seconds: float = 300.0  # sliding window for counting failures
    login_lockout_seconds: float = 300.0       # how long an account/source stays locked


DEFAULT_SETTINGS = Settings()
