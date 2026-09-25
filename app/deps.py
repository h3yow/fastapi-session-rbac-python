"""FastAPI 依赖：会话解析、CSRF 校验、权限断言。

依赖链：require_permission(p) -> enforce_csrf -> require_session
默认拒绝：任何受保护资源都必须显式声明所需权限，未声明/不满足一律拒绝。
"""

from __future__ import annotations

import logging

from fastapi import Depends, Request

from .csrf import CSRF_HEADER, UNSAFE_METHODS, verify_csrf
from .errors import E_FORBIDDEN, AppError
from .models import Session
from .rbac import RBACService

logger = logging.getLogger("deps")

SESSION_COOKIE = "sid"
CSRF_COOKIE = "csrf_token"


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def get_container(request: Request):
    return request.app.state.container


def require_session(request: Request) -> Session:
    """从 Cookie 解析并校验会话（含过期/撤销/改密判定与滑动续期）。"""
    container = get_container(request)
    session_id = request.cookies.get(SESSION_COOKIE)
    return container.auth.authenticate(session_id)


def enforce_csrf(
    request: Request, session: Session = Depends(require_session)
) -> Session:
    """状态变更方法强制 CSRF 校验；安全方法直接放行。"""
    if request.method in UNSAFE_METHODS:
        presented = request.headers.get(CSRF_HEADER)
        logger.info(
            "csrf check method=%s sid=%s token_present=%s",
            request.method,
            session.session_id[:8],
            bool(presented),
        )
        verify_csrf(session, presented)
    return session


def require_permission(permission: str):
    """生成依赖：会话 + CSRF（按方法）+ 权限断言（默认拒绝，原因可区分）。"""

    def _dep(
        request: Request,
        session: Session = Depends(enforce_csrf),
    ) -> Session:
        container = get_container(request)
        rbac: RBACService = container.rbac
        user = container.store.get_user(session.username)
        if user is None:
            # 理论不可达（authenticate 已校验），双保险：默认拒绝
            raise AppError(E_FORBIDDEN, "user no longer exists", status_code=403)
        logger.info(
            "authorize user=%s required=%s sid=%s",
            user.username,
            permission,
            session.session_id[:8],
        )
        rbac.authorize(user, session, permission)
        return session

    return _dep
