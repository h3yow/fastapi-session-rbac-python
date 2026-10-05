"""FastAPI dependency providers wiring services into routes."""
from __future__ import annotations

from typing import Annotated

from fastapi import Cookie, Depends, Request

from .auth import AuthService
from .errors import ForbiddenError, ErrorCode
from .models import Session
from .rbac import DenialReason, PolicyEngine


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
    subsequent requests without a restart. Denials distinguish three
    cases: the account holds no roles, the role never had the permission,
    or the permission was revoked at runtime.
    """

    def checker(
        session: Session = Depends(get_current_session),
        auth: AuthService = Depends(get_auth_service),
        policy: PolicyEngine = Depends(get_policy_engine),
    ) -> Session:
        user = auth.get_user(session.username)
        roles = user.roles if user else frozenset()
        if policy.has_permission(roles, permission):
            return session
        reason = policy.classify_denial(roles, permission)
        if reason is DenialReason.NO_ROLE:
            raise ForbiddenError(ErrorCode.FORBIDDEN_ROLE, "account has no roles")
        if reason is DenialReason.REVOKED_RUNTIME:
            raise ForbiddenError(
                ErrorCode.PERMISSION_REVOKED,
                f"permission '{permission}' was revoked from roles "
                f"{sorted(roles)} at runtime (policy v{policy.version})",
            )
        raise ForbiddenError(
            ErrorCode.FORBIDDEN_PERMISSION,
            f"permission '{permission}' not granted to roles "
            f"{sorted(roles)} (policy v{policy.version})",
        )

    return checker
