"""基于角色与权限的访问控制。默认拒绝。

权限模型：
- 每个用户直接持有 permissions 集合，同时持有 roles 集合。
- 角色 -> 权限映射在角色表中维护，用户的“有效权限”= 直接权限 ∪ 角色权限。
- 会话在登录时保存一份权限快照，用于区分“从未拥有”与“登录后被撤销”：
    * 快照含该权限但当前有效权限不含 -> permission_revoked
    * 快照也不含                      -> forbidden
- 权限变更直接改写存储中的用户记录，后续请求立即生效，无需重启。
"""

from __future__ import annotations

from .errors import E_FORBIDDEN, E_PERMISSION_REVOKED, AppError
from .models import Session, User
from .store import Store


class RBACService:
    def __init__(
        self,
        store: Store,
        role_permissions: dict[str, set[str]] | None = None,
    ) -> None:
        self.store = store
        self.role_permissions: dict[str, set[str]] = role_permissions or {}

    def effective_permissions(self, user: User) -> set[str]:
        """直接权限 ∪ 所有角色赋予的权限。"""
        perms = set(user.permissions)
        for role in user.roles:
            perms |= self.role_permissions.get(role, set())
        return perms

    def authorize(self, user: User, session: Session, required: str) -> None:
        """具备权限则正常返回，否则按可区分错误码拒绝（默认拒绝）。"""
        current = self.effective_permissions(user)
        if required in current:
            return
        if required in session.permission_snapshot:
            raise AppError(
                E_PERMISSION_REVOKED,
                f"permission {required!r} was granted at login but has since been revoked",
                status_code=403,
            )
        raise AppError(
            E_FORBIDDEN,
            f"permission {required!r} is required for this resource",
            status_code=403,
        )

    # ---- 在线变更：对后续请求立即生效 ------------------------------------
    def grant_permission(self, username: str, permission: str) -> None:
        with self.store.lock():
            user = self.store.get_user(username)
            if user is None:
                raise AppError("user_not_found", f"unknown user {username!r}", 404)
            user.permissions.add(permission)

    def revoke_permission(self, username: str, permission: str) -> None:
        with self.store.lock():
            user = self.store.get_user(username)
            if user is None:
                raise AppError("user_not_found", f"unknown user {username!r}", 404)
            user.permissions.discard(permission)

    def grant_role(self, username: str, role: str) -> None:
        with self.store.lock():
            user = self.store.get_user(username)
            if user is None:
                raise AppError("user_not_found", f"unknown user {username!r}", 404)
            user.roles.add(role)

    def revoke_role(self, username: str, role: str) -> None:
        with self.store.lock():
            user = self.store.get_user(username)
            if user is None:
                raise AppError("user_not_found", f"unknown user {username!r}", 404)
            user.roles.discard(role)
