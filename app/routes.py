"""HTTP routes and application factory."""
from __future__ import annotations

import logging
import time

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .auth import AuthService
from .config import DEFAULT_SETTINGS, Settings
from .csrf import CSRF_HEADER, validate_csrf
from .deps import (
    get_auth_service,
    get_current_session,
    get_policy_engine,
    require_permission,
)
from .errors import (
    AuthError,
    ConflictError,
    CsrfError,
    ErrorCode,
    ForbiddenError,
    NotFoundError,
    SESSION_REASON_EXPIRED,
    SESSION_REASON_KICKED,
    SESSION_REASON_PASSWORD_CHANGED,
)
from .models import Session
from .rbac import PolicyEngine
from .security import hash_password
from .store import LockoutStore, SessionStore, UserStore
from .models import User

logger = logging.getLogger("app.routes")

SESSION_COOKIE = "session_id"

DEFAULT_ROLES: dict[str, set[str]] = {
    "reader": {"reports:read"},
    "editor": {"reports:read", "reports:write"},
    "admin": {
        "reports:read",
        "reports:write",
        "admin:users",
        # New runtime-management capabilities, admin-only by default.
        "admin:roles:write",
        "admin:sessions:write",
    },
}


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str


class RolePermissionsRequest(BaseModel):
    permissions: list[str]


def _session_payload(session: Session) -> dict:
    return {
        "session_id": session.session_id,
        "username": session.username,
        "expires_in": session.expires_at - session.created_at,
        "csrf_token": session.csrf_token,
    }


def _session_info(session: Session, now: float,
                  current_generation: int | None = None) -> dict:
    """One session row for listing endpoints: identity, timing and liveness."""
    if (
        current_generation is not None
        and session.password_generation != current_generation
    ):
        status = SESSION_REASON_PASSWORD_CHANGED
    elif session.revoked:
        status = SESSION_REASON_KICKED
    elif session.is_expired(now):
        status = SESSION_REASON_EXPIRED
    else:
        status = "active"
    return {
        "session_id": session.session_id,
        "username": session.username,
        "created_at": round(session.created_at, 3),
        "expires_at": round(session.expires_at, 3),
        "age_seconds": round(now - session.created_at, 3),
        "remaining_seconds": round(session.expires_at - now, 3),
        "status": status,
    }


def create_app(
    settings: Settings = DEFAULT_SETTINGS,
    roles: dict[str, set[str]] | None = None,
) -> FastAPI:
    app = FastAPI(title="session-rbac-demo")

    users = UserStore()
    sessions = SessionStore()
    app.state.auth_service = AuthService(
        settings, users, sessions, LockoutStore(settings)
    )
    app.state.policy_engine = PolicyEngine(roles or DEFAULT_ROLES)
    app.state.user_store = users

    # --------------------------------------------------------- error handling
    def _error_body(exc) -> dict:
        body: dict = {"code": exc.code.value, "detail": exc.detail}
        # Only present when a fine-grained reason applies.
        if getattr(exc, "reason", None):
            body["reason"] = exc.reason
        return {"error": body}

    @app.exception_handler(AuthError)
    async def _auth_error(_: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=_error_body(exc))

    @app.exception_handler(ForbiddenError)
    async def _forbidden(_: Request, exc: ForbiddenError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=_error_body(exc))

    @app.exception_handler(CsrfError)
    async def _csrf(_: Request, exc: CsrfError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=_error_body(exc))

    @app.exception_handler(NotFoundError)
    async def _not_found(_: Request, exc: NotFoundError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=_error_body(exc))

    @app.exception_handler(ConflictError)
    async def _conflict(_: Request, exc: ConflictError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=_error_body(exc))

    # ------------------------------------------------------- anonymous routes
    @app.get("/")
    def read_root() -> dict:
        # Pre-existing anonymous endpoint; behaviour unchanged.
        return {"Hello": "World"}

    @app.post("/login")
    def login(
        body: LoginRequest,
        request: Request,
        response: Response,
        auth: AuthService = Depends(get_auth_service),
    ) -> dict:
        source = request.client.host if request.client else "unknown"
        session = auth.login(body.username, body.password, source)
        response.set_cookie(
            SESSION_COOKIE, session.session_id, httponly=True, samesite="lax"
        )
        return _session_payload(session)

    # ------------------------------------------------------ session endpoints
    @app.post("/logout")
    def logout(
        request: Request,
        response: Response,
        session: Session = Depends(get_current_session),
        auth: AuthService = Depends(get_auth_service),
    ) -> dict:
        validate_csrf(session, request.headers.get(CSRF_HEADER))
        auth.logout(session.session_id)
        response.delete_cookie(SESSION_COOKIE)
        return {"logged_out": True}

    @app.post("/refresh")
    def refresh(
        request: Request,
        session: Session = Depends(get_current_session),
        auth: AuthService = Depends(get_auth_service),
    ) -> dict:
        validate_csrf(session, request.headers.get(CSRF_HEADER))
        renewed = auth.refresh(session.session_id)
        return _session_payload(renewed)

    @app.post("/change-password")
    def change_password(
        body: PasswordChangeRequest,
        request: Request,
        session: Session = Depends(get_current_session),
        auth: AuthService = Depends(get_auth_service),
    ) -> dict:
        validate_csrf(session, request.headers.get(CSRF_HEADER))
        revoked = auth.change_password(
            session.session_id, body.old_password, body.new_password
        )
        return {"changed": True, "sessions_revoked": revoked}

    @app.get("/me")
    def me(session: Session = Depends(get_current_session)) -> dict:
        return {"username": session.username, "session_id": session.session_id}

    # -------------------------------------------------------- protected demo
    @app.get("/reports")
    def read_reports(session: Session = Depends(require_permission("reports:read"))) -> dict:
        return {"reports": ["q1", "q2"], "by": session.username}

    @app.post("/reports")
    def write_report(
        request: Request,
        session: Session = Depends(require_permission("reports:write")),
    ) -> dict:
        validate_csrf(session, request.headers.get(CSRF_HEADER))
        return {"created": True, "by": session.username}

    @app.get("/admin/users")
    def list_users(
        request: Request,
        session: Session = Depends(require_permission("admin:users")),
    ) -> dict:
        store: UserStore = request.app.state.user_store
        _ = store  # listing kept simple for the demo
        return {"actor": session.username}

    # --------------------------------------------- own session introspection
    @app.get("/me/sessions")
    def list_my_sessions(
        session: Session = Depends(get_current_session),
        auth: AuthService = Depends(get_auth_service),
    ) -> dict:
        now = time.monotonic()
        current_user = auth.get_user(session.username)
        generation = current_user.password_generation if current_user else None
        rows = [
            _session_info(s, now, generation)
            for s in auth.list_sessions(session.username)
        ]
        # Newest first; each session is individually identifiable.
        rows.sort(key=lambda r: r["created_at"], reverse=True)
        logger.info("list_my_sessions actor=%s count=%d", session.username, len(rows))
        return {"username": session.username, "sessions": rows}

    @app.delete("/me/sessions/{target_session_id}")
    def revoke_my_session(
        target_session_id: str,
        request: Request,
        session: Session = Depends(get_current_session),
        auth: AuthService = Depends(get_auth_service),
    ) -> dict:
        validate_csrf(session, request.headers.get(CSRF_HEADER))
        target = auth.get_session(target_session_id)
        # Unknown id or a session belonging to someone else is simply
        # "not found" for this account scope.
        if target is None or target.username != session.username:
            logger.info("self-revoke actor=%s target=...%s -> not_found",
                        session.username, target_session_id[-6:])
            raise NotFoundError(
                ErrorCode.SESSION_NOT_FOUND,
                f"no such session for user {session.username}",
            )
        return _revoke_result(target_session_id, auth.revoke_session(target_session_id))

    # ----------------------------------------------- runtime policy management
    @app.get("/admin/roles/{role}")
    def get_role(
        role: str,
        session: Session = Depends(require_permission("admin:roles:write")),
        policy: PolicyEngine = Depends(get_policy_engine),
    ) -> dict:
        perms = policy.role_permissions(role)
        if perms is None:
            raise NotFoundError(ErrorCode.ROLE_NOT_FOUND, f"role {role!r} not found")
        version, _ = policy.snapshot()
        return {"role": role, "permissions": sorted(perms), "policy_version": version}

    @app.put("/admin/roles/{role}/permissions")
    def update_role(
        role: str,
        body: RolePermissionsRequest,
        request: Request,
        session: Session = Depends(require_permission("admin:roles:write")),
        policy: PolicyEngine = Depends(get_policy_engine),
    ) -> dict:
        validate_csrf(session, request.headers.get(CSRF_HEADER))
        try:
            version = policy.update_role(role, set(body.permissions))
        except KeyError:
            raise NotFoundError(
                ErrorCode.ROLE_NOT_FOUND,
                f"role {role!r} not found; create roles via configuration",
            )
        logger.info(
            "update_role actor=%s role=%s permissions=%s -> policy v%d",
            session.username, role, body.permissions, version,
        )
        return {"role": role, "permissions": body.permissions,
                "policy_version": version}

    # --------------------------------------------- admin session management
    @app.get("/admin/users/{username}/sessions")
    def admin_list_user_sessions(
        username: str,
        session: Session = Depends(require_permission("admin:sessions:write")),
        auth: AuthService = Depends(get_auth_service),
    ) -> dict:
        if auth.get_user(username) is None:
            raise NotFoundError(ErrorCode.SESSION_NOT_FOUND,
                                f"user {username!r} not found")
        target_user = auth.get_user(username)
        generation = target_user.password_generation if target_user else None
        now = time.monotonic()
        rows = sorted(
            (_session_info(s, now, generation) for s in auth.list_sessions(username)),
            key=lambda r: r["created_at"], reverse=True,
        )
        logger.info("admin_list_sessions actor=%s target=%s count=%d",
                    session.username, username, len(rows))
        return {"username": username, "sessions": rows}

    @app.delete("/admin/sessions/{target_session_id}")
    def admin_revoke_session(
        target_session_id: str,
        request: Request,
        session: Session = Depends(require_permission("admin:sessions:write")),
        auth: AuthService = Depends(get_auth_service),
    ) -> dict:
        validate_csrf(session, request.headers.get(CSRF_HEADER))
        if auth.get_session(target_session_id) is None:
            logger.info("admin-revoke actor=%s target=...%s -> not_found",
                        session.username, target_session_id[-6:])
            raise NotFoundError(ErrorCode.SESSION_NOT_FOUND, "no such session")
        return _revoke_result(target_session_id,
                              auth.revoke_session(target_session_id),
                              actor=session.username)

    return app


def _revoke_result(session_id: str, result: str, actor: str | None = None) -> dict:
    """Map the store's idempotent revocation outcome onto an HTTP response."""
    if result == "revoked":
        logger.info("revoke actor=%s sid=...%s -> revoked", actor, session_id[-6:])
        return {"revoked": True, "session_id": session_id, "result": "revoked"}
    # It existed a moment ago but was already dead: deterministic 409.
    logger.info("revoke actor=%s sid=...%s -> already_invalid",
                actor, session_id[-6:])
    raise ConflictError(
        ErrorCode.SESSION_ALREADY_INVALID,
        "session was already revoked or expired",
    )


def seed_user(app: FastAPI, username: str, password: str, roles: set[str]) -> None:
    """Test/demo helper: create a user in the app's store."""
    store: UserStore = app.state.user_store
    store.add(User(username=username, password_hash=hash_password(password),
                   roles=frozenset(roles)))
