"""CSRF protection for state-changing requests.

Tokens are issued per session at login/refresh and bound to that session.
A state-changing request must present the token of *its own* session in the
``X-CSRF-Token`` header. Missing, expired, or cross-session tokens are
rejected with distinguishable reasons.
"""
from __future__ import annotations

import hmac
import time

from .errors import CsrfError, ErrorCode
from .models import Session

CSRF_HEADER = "X-CSRF-Token"


def validate_csrf(session: Session, presented_token: str | None) -> None:
    if not presented_token:
        raise CsrfError(ErrorCode.CSRF_MISSING, f"missing {CSRF_HEADER} header")
    now = time.monotonic()
    if now >= session.csrf_expires_at:
        raise CsrfError(ErrorCode.CSRF_INVALID, "csrf token expired")
    if not hmac.compare_digest(presented_token, session.csrf_token):
        raise CsrfError(
            ErrorCode.CSRF_INVALID, "csrf token does not match this session"
        )
