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
    SESSION_MISSING = "session_missing"          # no session cookie presented
    SESSION_UNKNOWN = "session_unknown"          # no such session id at all
    SESSION_REVOKED = "session_revoked"          # deliberately revoked (logout / kicked)
    SESSION_PASSWORD_CHANGED = "session_password_changed"  # bulk-invalidated by password change
    SESSION_EXPIRED = "session_expired"
    SESSION_INVALID = "session_invalid"          # generic invalid (e.g. refresh too early)
    # Session administration
    SESSION_NOT_FOUND = "session_not_found"      # revoke target does not exist
    SESSION_ALREADY_REVOKED = "session_already_revoked"  # revoke target already dead
    # CSRF
    CSRF_MISSING = "csrf_missing"
    CSRF_INVALID = "csrf_invalid"                # expired or not bound to this session
    # Authorization
    FORBIDDEN_ROLE = "forbidden_role"            # authenticated but lacks the role
    FORBIDDEN_PERMISSION = "forbidden_permission"  # role never had the permission
    PERMISSION_REVOKED = "permission_revoked"    # had it at startup, revoked at runtime


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


class NotFoundError(Exception):
    """Lookup failure (HTTP 404), e.g. revoking an unknown session."""

    status_code = 404

    def __init__(self, code: ErrorCode, detail: str = "") -> None:
        self.code = code
        self.detail = detail or code.value
        super().__init__(self.detail)


class ConflictError(Exception):
    """State conflict (HTTP 409), e.g. revoking an already-revoked session."""

    status_code = 409

    def __init__(self, code: ErrorCode, detail: str = "") -> None:
        self.code = code
        self.detail = detail or code.value
        super().__init__(self.detail)
