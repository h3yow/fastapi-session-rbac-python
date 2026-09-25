"""CSRF 防护：双重提交令牌 + 会话绑定校验。

规则：
- 登录成功后，会话内生成 csrf_token；通过可读 Cookie 下发给前端，前端在所有
  状态变更请求（POST/PUT/PATCH/DELETE）中以 X-CSRF-Token 头回传。
- 服务端只接受与会话内记录恒定时间相等的令牌：
    * 缺失 / 为空   -> csrf_token_missing
    * 与会话不匹配  -> csrf_token_invalid（含过期会话的旧令牌、他人令牌错用）
- 安全方法（GET/HEAD/OPTIONS）不校验。
"""

from __future__ import annotations

import hmac

from .errors import E_CSRF_INVALID, E_CSRF_MISSING, AppError
from .models import Session

CSRF_HEADER = "X-CSRF-Token"

# 需要防护的状态变更方法
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def verify_csrf(session: Session, presented_token: str | None) -> None:
    """令牌缺失/为空 -> csrf_token_missing；不匹配 -> csrf_token_invalid。"""
    if not presented_token:
        raise AppError(
            E_CSRF_MISSING,
            f"missing {CSRF_HEADER} header for state-changing request",
            status_code=403,
        )
    if not hmac.compare_digest(presented_token, session.csrf_token):
        raise AppError(
            E_CSRF_INVALID,
            "presented CSRF token does not match the session token",
            status_code=403,
        )
