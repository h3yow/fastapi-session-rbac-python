"""HTTP 路由。

公开（匿名可访问，行为与原骨架兼容）：
- GET  /                 -> {"Hello": "World"}
- GET  /healthz          -> 存活探针
- POST /api/auth/login   -> 登录
- POST /api/auth/logout  -> 登出（凭据无效时幂等成功）

需登录 / 权限（默认拒绝）：
- GET    /api/profile                 需登录
- POST   /api/auth/change-password    需登录 + CSRF
- GET    /api/sessions                需登录，列出本账户有效会话
- DELETE /api/sessions/{session_id}   需登录 + CSRF；属主本人或 session:revoke
- GET    /api/articles                需 article:read
- POST   /api/articles                需 article:write + CSRF
- POST   /api/admin/grant             需 admin:users + CSRF
- POST   /api/admin/revoke            需 admin:users + CSRF
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field

from .deps import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    client_ip,
    enforce_csrf,
    get_container,
    require_permission,
    require_session,
)
from .errors import E_FORBIDDEN, E_NOT_FOUND, AppError
from .models import Session

logger = logging.getLogger("routes")

router = APIRouter()


# ---- 请求 / 响应模型 ------------------------------------------------------
class LoginIn(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class ChangePasswordIn(BaseModel):
    old_password: str = Field(min_length=1)
    new_password: str = Field(min_length=8)


class ArticleIn(BaseModel):
    title: str = Field(min_length=1)
    body: str = ""


class PermissionIn(BaseModel):
    username: str = Field(min_length=1)
    permission: str = Field(min_length=1)


# ---- 匿名可访问（行为保持兼容） -------------------------------------------
@router.get("/")
def read_root() -> dict[str, str]:
    return {"Hello": "World"}


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/api/auth/login", status_code=204)
def login(payload: LoginIn, request: Request, response: Response) -> None:
    container = get_container(request)
    session = container.auth.login(
        payload.username, payload.password, client_ip(request)
    )
    # sid 不允许被脚本读取（防 XSS 窃取）；csrf_token 需要前端读取，故不用 httponly
    response.set_cookie(
        SESSION_COOKIE,
        session.session_id,
        httponly=True,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE,
        session.csrf_token,
        httponly=False,
        samesite="strict",
        path="/",
    )
    logger.info(
        "login cookies issued user=%s sid=%s csrf=%s",
        session.username,
        session.session_id[:8],
        session.csrf_token[:8],
    )


@router.post("/api/auth/logout", status_code=204)
def logout(request: Request, response: Response) -> None:
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        get_container(request).auth.logout(session_id)
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


# ---- 需登录 ---------------------------------------------------------------
@router.get("/api/profile")
def profile(request: Request, session: Session = Depends(require_session)) -> dict:
    user = get_container(request).store.get_user(session.username)
    return {
        "username": user.username,
        "roles": sorted(user.roles),
        "permissions": sorted(get_container(request).rbac.effective_permissions(user)),
    }


@router.post("/api/auth/change-password", status_code=204)
def change_password(
    payload: ChangePasswordIn,
    request: Request,
    session: Session = Depends(enforce_csrf),
) -> None:
    container = get_container(request)
    # 先改密（会撤销该用户全部既有会话，包括当前会话）
    container.auth.change_password(
        session.username, payload.old_password, payload.new_password
    )


@router.get("/api/sessions")
def list_sessions(
    request: Request, session: Session = Depends(require_session)
) -> dict:
    sessions = get_container(request).auth.list_live_sessions(session.username)
    return {
        "sessions": [
            {
                "session_id": s.session_id,
                "created_at": s.created_at.isoformat(),
                "last_seen_at": s.last_seen_at.isoformat(),
                "expires_at": s.expires_at.isoformat(),
                "current": s.session_id == session.session_id,
            }
            for s in sorted(sessions, key=lambda s: s.created_at)
        ]
    }


@router.delete("/api/sessions/{session_id}", status_code=204)
def revoke_session_route(
    session_id: str,
    request: Request,
    session: Session = Depends(enforce_csrf),
) -> None:
    """属主可撤销自己的会话；持 session:revoke 权限者（管理员）可撤销任意会话。"""
    container = get_container(request)
    target = container.store.get_session(session_id)
    if target is None:
        raise AppError(E_NOT_FOUND, "session not found", status_code=404)

    user = container.store.get_user(session.username)
    is_owner = target.username == session.username
    can_revoke = "session:revoke" in container.rbac.effective_permissions(user)
    logger.info(
        "revoke attempt actor=%s target_owner=%s is_owner=%s can_revoke=%s",
        user.username,
        target.username,
        is_owner,
        can_revoke,
    )
    if not is_owner and not can_revoke:
        raise AppError(
            E_FORBIDDEN,
            "only the session owner or a session:revoke holder may revoke",
            status_code=403,
        )
    container.store.revoke_session(session_id)


# ---- 受权限保护的业务接口 --------------------------------------------------
@router.get("/api/articles")
def list_articles(
    request: Request, session: Session = Depends(require_permission("article:read"))
) -> dict:
    return {"articles": [{"id": 1, "title": "Welcome"}], "viewer": session.username}


@router.post("/api/articles", status_code=201)
def create_article(
    payload: ArticleIn,
    request: Request,
    session: Session = Depends(require_permission("article:write")),
) -> dict:
    logger.info("article created actor=%s title=%r", session.username, payload.title)
    return {"id": 2, "title": payload.title, "body": payload.body, "author": session.username}


# ---- 在线权限管理（立即生效，无需重启） ------------------------------------
@router.post("/api/admin/grant", status_code=204)
def admin_grant(
    payload: PermissionIn,
    request: Request,
    session: Session = Depends(require_permission("admin:users")),
) -> None:
    logger.info(
        "grant actor=%s target=%s permission=%s",
        session.username,
        payload.username,
        payload.permission,
    )
    get_container(request).rbac.grant_permission(
        payload.username, payload.permission
    )


@router.post("/api/admin/revoke", status_code=204)
def admin_revoke(
    payload: PermissionIn,
    request: Request,
    session: Session = Depends(require_permission("admin:users")),
) -> None:
    logger.info(
        "revoke-permission actor=%s target=%s permission=%s",
        session.username,
        payload.username,
        payload.permission,
    )
    get_container(request).rbac.revoke_permission(
        payload.username, payload.permission
    )
