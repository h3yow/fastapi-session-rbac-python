"""HTTP routes and application factory."""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .auth import AuthService
from .config import DEFAULT_SETTINGS, Settings
from .csrf import CSRF_HEADER, validate_csrf
from .deps import get_auth_service, get_current_session, require_permission
from .errors import AuthError, CsrfError, ForbiddenError
from .models import Session
from .rbac import PolicyEngine
from .security import hash_password
from .store import LockoutStore, SessionStore, UserStore
from .models import User

SESSION_COOKIE = "session_id"

DEFAULT_ROLES: dict[str, set[str]] = {
    "reader": {"reports:read"},
    "editor": {"reports:read", "reports:write"},
    "admin": {"reports:read", "reports:write", "admin:users"},
}


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str


def _session_payload(session: Session) -> dict:
    return {
        "session_id": session.session_id,
        "username": session.username,
        "expires_in": session.expires_at - session.created_at,
        "csrf_token": session.csrf_token,
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
    @app.exception_handler(AuthError)
    async def _auth_error(_: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code.value, "detail": exc.detail}},
        )

    @app.exception_handler(ForbiddenError)
    async def _forbidden(_: Request, exc: ForbiddenError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code.value, "detail": exc.detail}},
        )

    @app.exception_handler(CsrfError)
    async def _csrf(_: Request, exc: CsrfError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code.value, "detail": exc.detail}},
        )

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

    return app


def seed_user(app: FastAPI, username: str, password: str, roles: set[str]) -> None:
    """Test/demo helper: create a user in the app's store."""
    store: UserStore = app.state.user_store
    store.add(User(username=username, password_hash=hash_password(password),
                   roles=frozenset(roles)))
