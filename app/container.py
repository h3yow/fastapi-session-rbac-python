"""服务装配：集中创建存储与服务实例，并播种演示用户/角色。"""

from __future__ import annotations

from dataclasses import dataclass

from .auth import AuthService
from .models import User
from .rbac import RBACService
from .security import hash_password, new_salt
from .store import Store

# 角色 -> 权限
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {"article:read", "article:write", "admin:users", "session:revoke"},
    "editor": {"article:read", "article:write"},
    "reader": {"article:read"},
}


@dataclass
class Container:
    store: Store
    rbac: RBACService
    auth: AuthService


def _make_user(
    username: str, password: str, roles: set[str], permissions: set[str] | None = None
) -> User:
    salt = new_salt()
    return User(
        username=username,
        password_salt=salt,
        password_hash=hash_password(password, salt),
        roles=set(roles),
        permissions=set(permissions or ()),
    )


def seed_users(store: Store) -> None:
    store.upsert_user(_make_user("admin", "admin-pass", {"admin"}))
    store.upsert_user(_make_user("alice", "alice-pass", {"editor"}))
    store.upsert_user(_make_user("bob", "bob-pass", {"reader"}))
    # 一个只拥有直接权限（无角色）的用户，用于验证直接授权与撤销
    store.upsert_user(
        _make_user("carol", "carol-pass", set(), {"article:read"})
    )


def build_container() -> Container:
    store = Store()
    rbac = RBACService(store, role_permissions={k: set(v) for k, v in ROLE_PERMISSIONS.items()})
    auth = AuthService(store, rbac=rbac)
    seed_users(store)
    return Container(store=store, rbac=rbac, auth=auth)
