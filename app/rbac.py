"""Role/permission policy with hot-reload support.

The policy is held behind a lock and replaced atomically, so permission
changes take effect for subsequent requests without a restart. Each update
bumps a version so tests and logs can cite the exact policy evaluated.

The engine also remembers the *base* (startup) policy, so a denial can be
classified as "this role never had the permission" vs. "the permission was
revoked at runtime" — two operationally very different situations.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import StrEnum


class DenialReason(StrEnum):
    """Why a permission check failed."""
    NO_ROLE = "no_role"              # account holds no roles at all
    NOT_GRANTED = "not_granted"      # role never had the permission
    REVOKED_RUNTIME = "revoked_runtime"  # had it at startup, revoked at runtime


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
        # Immutable snapshot of the startup policy, used to distinguish
        # "never granted" from "revoked at runtime".
        self._base = self._policy

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

    def grant(self, role: str, permission: str) -> int:
        """Add one permission to one role; returns the new version."""
        with self._lock:
            return self._set_membership(role, permission, present=True)

    def revoke(self, role: str, permission: str) -> int:
        """Remove one permission from one role; returns the new version."""
        with self._lock:
            return self._set_membership(role, permission, present=False)

    def _set_membership(self, role: str, permission: str, present: bool) -> int:
        current = dict(self._policy.role_permissions)
        perms = set(current.get(role, frozenset()))
        if present:
            perms.add(permission)
        else:
            perms.discard(permission)
        current[role] = frozenset(perms)
        self._policy = Policy(version=self._policy.version + 1, role_permissions=current)
        return self._policy.version

    def snapshot(self) -> dict:
        """Consistent view of the current policy for inspection endpoints."""
        with self._lock:
            policy = self._policy
        return {
            "version": policy.version,
            "roles": {role: sorted(perms) for role, perms in sorted(policy.role_permissions.items())},
        }

    def permissions_for(self, roles: set[str] | frozenset[str]) -> frozenset[str]:
        with self._lock:
            policy = self._policy
        result: set[str] = set()
        for role in roles:
            result |= policy.role_permissions.get(role, frozenset())
        return frozenset(result)

    def has_permission(self, roles: set[str] | frozenset[str], permission: str) -> bool:
        return permission in self.permissions_for(roles)

    def classify_denial(
        self, roles: set[str] | frozenset[str], permission: str
    ) -> DenialReason:
        """Explain why ``permission`` is denied for ``roles``.

        "Revoked at runtime" means at least one of the roles held the
        permission in the startup policy but no longer does — as opposed
        to the role simply never having had it.
        """
        if not roles:
            return DenialReason.NO_ROLE
        with self._lock:
            policy = self._policy
            base = self._base
        for role in roles:
            if permission in base.role_permissions.get(role, frozenset()) and (
                permission not in policy.role_permissions.get(role, frozenset())
            ):
                return DenialReason.REVOKED_RUNTIME
        return DenialReason.NOT_GRANTED
