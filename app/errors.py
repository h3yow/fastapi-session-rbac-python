"""统一错误码与异常类型。

所有认证 / 授权 / 限流拒绝都通过错误码区分，便于调用方与测试断言。
"""

from __future__ import annotations

# ---- 认证类 ----
E_INVALID_CREDENTIALS = "invalid_credentials"
E_ACCOUNT_LOCKED = "account_locked"
E_NOT_AUTHENTICATED = "not_authenticated"
E_SESSION_EXPIRED = "session_expired"
E_SESSION_REVOKED = "session_revoked"
E_PASSWORD_CHANGED = "session_invalidated_by_password_change"

# ---- 授权类 ----
E_FORBIDDEN = "forbidden"
E_PERMISSION_REVOKED = "permission_revoked"

# ---- CSRF ----
E_CSRF_MISSING = "csrf_token_missing"
E_CSRF_INVALID = "csrf_token_invalid"

# ---- 资源 ----
E_NOT_FOUND = "not_found"


class AppError(Exception):
    """业务拒绝异常，携带稳定错误码与可读原因。"""

    def __init__(self, code: str, message: str, status_code: int = 403) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
