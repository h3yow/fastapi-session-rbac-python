"""FastAPI dependency providers wiring services into routes."""
from __future__ import annotations

from typing import Annotated

from fastapi import Cookie, Depends, Request

from .auth import AuthService
from .errors import ForbiddenError, ErrorCode
from .models import Session
from .rbac import PolicyEngine


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


def get_policy_engine(request: Request) -> PolicyEngine:
    return request.app.state.policy_engine


def get_current_session(
    session_id: Annotated[str | None, Cookie()] = None,
    auth: AuthService = Depends(get_auth_service),
) -> Session:
    """Default-deny: any session problem raises 401 with a reason code."""
    return auth.authenticate(session_id)


def require_permission(permission: str):
    """Dependency factory enforcing a permission under the *current* policy.

    The policy is read at request time, so permission changes apply to
    subsequent requests without a restart. Denials distinguish "role not
    held" from "permission not granted (or revoked)".
    """

    def checker(
        session: Session = Depends(get_current_session),
        auth: AuthService = Depends(get_auth_service),
        policy: PolicyEngine = Depends(get_policy_engine),
    ) -> Session:
        user = auth.get_user(session.username)
        roles = user.roles if user else frozenset()
        if not roles:
            raise ForbiddenError(ErrorCode.FORBIDDEN_ROLE, "account has no roles")
        if not policy.has_permission(roles, permission):
            raise ForbiddenError(
                ErrorCode.FORBIDDEN_PERMISSION,
                f"permission '{permission}' not granted to roles "
                f"{sorted(roles)} (policy v{policy.version})",
            )
        return session

    return checker
