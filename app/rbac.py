"""Role/permission policy with hot-reload support.

The policy is held behind a lock and replaced atomically, so permission
changes take effect for subsequent requests without a restart. Each update
bumps a version so tests and logs can cite the exact policy evaluated.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

from .errors import PERM_REASON_NEVER_GRANTED, PERM_REASON_REVOKED_AT_RUNTIME


@dataclass(frozen=True)
class Policy:
    version: int
    role_permissions: dict[str, frozenset[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    """Result of evaluating one permission under the current policy."""

    allowed: bool
    version: int
    # None when allowed; otherwise ``never_granted`` / ``revoked_at_runtime``.
    reason: str | None = None


class PolicyEngine:
    def __init__(self, role_permissions: dict[str, set[str]] | None = None) -> None:
        self._lock = threading.Lock()
        initial = {
            role: frozenset(perms) for role, perms in (role_permissions or {}).items()
        }
        self._policy = Policy(version=1, role_permissions=initial)
        # Union of every permission a role has held in any version. This is
        # what lets a denial say "you used to have this and it was revoked at
        # runtime" instead of the generic "role never had it".
        self._ever_granted: dict[str, set[str]] = {
            role: set(perms) for role, perms in initial.items()
        }

    @property
    def version(self) -> int:
        with self._lock:
            return self._policy.version

    def _snapshot_locked(self) -> dict[str, frozenset[str]]:
        return {role: perms for role, perms in self._policy.role_permissions.items()}

    def snapshot(self) -> tuple[int, dict[str, frozenset[str]]]:
        """Current (version, role -> permissions) mapping."""
        with self._lock:
            return self._policy.version, self._snapshot_locked()

    def role_permissions(self, role: str) -> frozenset[str] | None:
        with self._lock:
            perms = self._policy.role_permissions.get(role)
            return frozenset(perms) if perms is not None else None

    def update(self, role_permissions: dict[str, set[str]]) -> int:
        """Atomically replace the whole policy; returns the new version."""
        with self._lock:
            new_mapping = {
                role: frozenset(perms) for role, perms in role_permissions.items()
            }
            self._policy = Policy(version=self._policy.version + 1,
                                  role_permissions=new_mapping)
            for role, perms in new_mapping.items():
                self._ever_granted.setdefault(role, set()).update(perms)
            return self._policy.version

    def update_role(self, role: str, permissions: set[str] | frozenset[str]) -> int:
        """Atomically replace one role's permissions, leaving other roles
        untouched. Raises ``KeyError`` if the role does not exist (so unknown
        roles can't be silently invented). Returns the new version."""
        with self._lock:
            if role not in self._policy.role_permissions:
                raise KeyError(role)
            new_mapping = self._snapshot_locked()
            new_mapping[role] = frozenset(permissions)
            self._policy = Policy(version=self._policy.version + 1,
                                  role_permissions=new_mapping)
            self._ever_granted.setdefault(role, set()).update(new_mapping[role])
            return self._policy.version

    def permissions_for(self, roles: set[str] | frozenset[str]) -> frozenset[str]:
        with self._lock:
            policy = self._policy
        result: set[str] = set()
        for role in roles:
            result |= policy.role_permissions.get(role, frozenset())
        return frozenset(result)

    def has_permission(self, roles: set[str] | frozenset[str], permission: str) -> bool:
        return self.explain(roles, permission).allowed

    def explain(self, roles: set[str] | frozenset[str], permission: str) -> Decision:
        """Evaluate a permission and, on denial, classify *why*:

        * ``revoked_at_runtime`` - some held role had this permission in an
          earlier policy version but no longer does;
        * ``never_granted``      - none of the held roles ever had it.
        """
        with self._lock:
            version = self._policy.version
            current: set[str] = set()
            ever: set[str] = set()
            for role in roles:
                current |= self._policy.role_permissions.get(role, frozenset())
                ever |= self._ever_granted.get(role, set())
        if permission in current:
            return Decision(True, version)
        reason = (
            PERM_REASON_REVOKED_AT_RUNTIME
            if permission in ever
            else PERM_REASON_NEVER_GRANTED
        )
        return Decision(False, version, reason)
