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
    # Runtime management
    ROLE_NOT_FOUND = "role_not_found"            # admin targeted an unknown role
    SESSION_NOT_FOUND = "session_not_found"      # revoke targeted an unknown session
    SESSION_ALREADY_INVALID = "session_already_invalid"  # revoke targeted a dead session


# Fine-grained session invalidation reasons (carried in ``error.reason``).
# The top-level ``code`` stays stable (existing clients/tests), while
# ``reason`` lets operators tell the invalidation causes apart:
SESSION_REASON_MISSING = "missing"              # no session cookie at all
SESSION_REASON_UNKNOWN = "unknown"              # server never knew this id
SESSION_REASON_KICKED = "kicked"                # explicitly revoked (logout/admin)
SESSION_REASON_PASSWORD_CHANGED = "password_changed"  # bulk-invalidated
SESSION_REASON_EXPIRED = "expired"              # exceeded absolute TTL

# Fine-grained permission-denial reasons (carried in ``error.reason``):
PERM_REASON_NEVER_GRANTED = "never_granted"             # role never had it
PERM_REASON_REVOKED_AT_RUNTIME = "revoked_at_runtime"   # granted, then hot-revoked


class _AppError(Exception):
    def __init__(self, code: ErrorCode, detail: str = "", reason: str | None = None) -> None:
        self.code = code
        self.detail = detail or code.value
        # Optional machine-readable sub-cause; only emitted when set.
        self.reason = reason
        super().__init__(self.detail)


class AuthError(_AppError):
    """Authentication / session failure (HTTP 401)."""

    status_code = 401


class ForbiddenError(_AppError):
    """Authorization failure (HTTP 403)."""

    status_code = 403


class CsrfError(_AppError):
    """CSRF validation failure (HTTP 403)."""

    status_code = 403


class NotFoundError(_AppError):
    """Target resource does not exist (HTTP 404)."""

    status_code = 404


class ConflictError(_AppError):
    """Target resource exists but is in an incompatible state (HTTP 409)."""

    status_code = 409
