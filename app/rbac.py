"""Role/permission policy with hot-reload support.

The policy is held behind a lock and replaced atomically, so permission
changes take effect for subsequent requests without a restart. Each update
bumps a version so tests and logs can cite the exact policy evaluated.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Policy:
    version: int
    role_permissions: dict[str, frozenset[str]] = field(default_factory=dict)


class PolicyEngine:
    def __init__(self, role_permissions: dict[str, set[str]] | None = None) -> None:
        self._lock = threading.Lock()
        self._policy = Policy(
            version=1,
            role_permissions={
                role: frozenset(perms) for role, perms in (role_permissions or {}).items()
            },
        )

    @property
    def version(self) -> int:
        with self._lock:
            return self._policy.version

    def update(self, role_permissions: dict[str, set[str]]) -> int:
        """Atomically replace the policy; returns the new version."""
        with self._lock:
            self._policy = Policy(
                version=self._policy.version + 1,
                role_permissions={
                    role: frozenset(perms) for role, perms in role_permissions.items()
                },
            )
            return self._policy.version

    def permissions_for(self, roles: set[str] | frozenset[str]) -> frozenset[str]:
        with self._lock:
            policy = self._policy
        result: set[str] = set()
        for role in roles:
            result |= policy.role_permissions.get(role, frozenset())
        return frozenset(result)

    def has_permission(self, roles: set[str] | frozenset[str], permission: str) -> bool:
        return permission in self.permissions_for(roles)
