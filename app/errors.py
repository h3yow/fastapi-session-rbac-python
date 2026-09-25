"""Error codes and exception types.

Every rejection carries a machine-readable ``code`` so that callers and
tests can distinguish *why* a request was rejected (e.g. bad credentials
vs. locked account vs. missing permission vs. revoked permission).
"""
from __future__ import annotations

from enum import StrEnum


class ErrorCode(StrEnum):
    # Authentication
    INVALID_CREDENTIALS = "invalid_credentials"  # wrong user/password (never reveals which)
    ACCOUNT_LOCKED = "account_locked"            # too many failures, temporarily locked
    SESSION_EXPIRED = "session_expired"
    SESSION_INVALID = "session_invalid"          # unknown / revoked / password-changed
    SESSION_MISSING = "session_missing"
    # CSRF
    CSRF_MISSING = "csrf_missing"
    CSRF_INVALID = "csrf_invalid"                # expired or not bound to this session
    # Authorization
    FORBIDDEN_ROLE = "forbidden_role"            # authenticated but lacks the role
    FORBIDDEN_PERMISSION = "forbidden_permission"  # lacks (or lost) the permission


class AuthError(Exception):
    """Authentication / session failure (HTTP 401)."""

    status_code = 401

    def __init__(self, code: ErrorCode, detail: str = "") -> None:
        self.code = code
        self.detail = detail or code.value
        super().__init__(self.detail)


class ForbiddenError(Exception):
    """Authorization failure (HTTP 403)."""

    status_code = 403

    def __init__(self, code: ErrorCode, detail: str = "") -> None:
        self.code = code
        self.detail = detail or code.value
        super().__init__(self.detail)


class CsrfError(Exception):
    """CSRF validation failure (HTTP 403)."""

    status_code = 403

    def __init__(self, code: ErrorCode, detail: str = "") -> None:
        self.code = code
        self.detail = detail or code.value
        super().__init__(self.detail)
