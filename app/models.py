"""领域模型：用户、会话、失败计数。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class User:
    username: str
    password_hash: str
    password_salt: str
    roles: set[str] = field(default_factory=set)
    permissions: set[str] = field(default_factory=set)
    # 密码版本：每次改密递增；旧会话因版本不匹配而失效
    password_version: int = 0


@dataclass
class Session:
    session_id: str
    username: str
    csrf_token: str
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    absolute_deadline: datetime
    password_version: int
    # 登录时的权限快照，用于区分 forbidden（从未拥有）与 permission_revoked（后被撤销）
    permission_snapshot: set[str] = field(default_factory=set)
    revoked: bool = False


@dataclass
class FailureCounter:
    """按 (账户, 来源IP) 维度的失败计数与锁定状态。"""

    key: str
    failures: int = 0
    locked_until: datetime | None = None
