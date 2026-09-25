"""认证服务：登录、登出、会话续期、改密、失败计数与锁定。

锁定策略（确定性、可复现）：
- 维度：(账户, 来源IP)，计数键 f"{username}|{source_ip}"。
  无论账户是否存在，失败都按同一响应拒绝，不泄漏账户是否存在。
- 阈值：连续失败达到 MAX_FAILURES 次，立即锁定 LOCK_DURATION。
- 解除：锁定到期后的下一次请求自动解除（计数清零）——这是唯一解除途径；
        成功登录同样会清零计数。锁定期间任何凭据都不被校验。
- 并发：计数递增与置锁在 Store 的同一把锁内完成，并发失败不可能把计数“冲掉”，
        达到阈值后的后续请求一律得到 account_locked，无法被并发绕过。
- 滑动续期：每次通过认证的请求若剩余有效期 <= IDLE_TIMEOUT，则把 expires_at
        向后顺延一个 IDLE_TIMEOUT，但永不超过创建时刻起的 ABSOLUTE_TIMEOUT。
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from .errors import (
    E_ACCOUNT_LOCKED,
    E_INVALID_CREDENTIALS,
    E_NOT_AUTHENTICATED,
    E_PASSWORD_CHANGED,
    E_SESSION_EXPIRED,
    E_SESSION_REVOKED,
    AppError,
)
from .models import Session, User
from .rbac import RBACService
from .security import hash_password, new_salt, new_token, verify_password
from .store import Store

logger = logging.getLogger("auth")

MAX_FAILURES = 5
LOCK_DURATION = timedelta(minutes=15)
IDLE_TIMEOUT = timedelta(minutes=30)
ABSOLUTE_TIMEOUT = timedelta(hours=12)


def _failure_key(username: str, source_ip: str) -> str:
    return f"{username}|{source_ip}"


class AuthService:
    def __init__(
        self,
        store: Store,
        rbac: RBACService | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.rbac = rbac
        self.clock = clock or (lambda: datetime.now(UTC))

    # ---- 登录 / 登出 -----------------------------------------------------
    def login(self, username: str, password: str, source_ip: str) -> Session:
        key = _failure_key(username, source_ip)
        with self.store.lock():
            now = self.clock()
            counter = self.store.get_or_create_counter(key)

            # 锁定判定（到期自动解除是唯一解除路径）
            if counter.locked_until is not None:
                if now < counter.locked_until:
                    logger.info(
                        "login rejected: locked key=%s locked_until=%s",
                        key,
                        counter.locked_until.isoformat(),
                    )
                    raise AppError(
                        E_ACCOUNT_LOCKED,
                        "account is temporarily locked due to repeated failures",
                        status_code=423,
                    )
                counter.locked_until = None
                counter.failures = 0
                logger.info("lock expired and reset key=%s at=%s", key, now.isoformat())

            user = self.store.get_user(username)
            valid = user is not None and verify_password(
                password, user.password_salt, user.password_hash
            )
            if not valid:
                # 无论“用户不存在”还是“密码错误”，错误码与文案完全一致
                counter.failures += 1
                locked_now = counter.failures >= MAX_FAILURES
                if locked_now:
                    counter.locked_until = now + LOCK_DURATION
                logger.info(
                    "login failed key=%s failures=%d threshold=%d locked=%s",
                    key,
                    counter.failures,
                    MAX_FAILURES,
                    locked_now,
                )
                raise AppError(
                    E_INVALID_CREDENTIALS,
                    "invalid username or password",
                    status_code=401,
                )

            # 成功：清零计数
            counter.failures = 0
            counter.locked_until = None

            session = self._new_session(user, now)
            self.store.add_session(session)
            logger.info(
                "login ok user=%s sid=%s expires_at=%s",
                username,
                session.session_id,
                session.expires_at.isoformat(),
            )
            return session

    def logout(self, session_id: str) -> None:
        self.store.revoke_session(session_id)
        logger.info("logout sid=%s", session_id)

    # ---- 会话解析与续期 --------------------------------------------------
    def authenticate(self, session_id: str | None) -> Session:
        if not session_id:
            raise AppError(
                E_NOT_AUTHENTICATED,
                "no session cookie present",
                status_code=401,
            )
        with self.store.lock():
            now = self.clock()
            session = self.store.get_session(session_id)
            if session is None:
                logger.info("auth rejected: unknown sid=%s", session_id)
                raise AppError(
                    E_NOT_AUTHENTICATED, "session does not exist", status_code=401
                )
            if session.revoked:
                logger.info("auth rejected: revoked sid=%s", session_id)
                raise AppError(
                    E_SESSION_REVOKED, "session has been revoked", status_code=401
                )
            if now >= session.expires_at or now >= session.absolute_deadline:
                logger.info(
                    "auth rejected: expired sid=%s now=%s expires_at=%s absolute=%s",
                    session_id,
                    now.isoformat(),
                    session.expires_at.isoformat(),
                    session.absolute_deadline.isoformat(),
                )
                raise AppError(
                    E_SESSION_EXPIRED, "session has expired", status_code=401
                )

            user = self.store.get_user(session.username)
            if user is None or user.password_version != session.password_version:
                logger.info(
                    "auth rejected: password changed user=%s sid_pv=%s current_pv=%s",
                    session.username,
                    session.password_version,
                    None if user is None else user.password_version,
                )
                raise AppError(
                    E_PASSWORD_CHANGED,
                    "session invalidated because the password was changed",
                    status_code=401,
                )

            # 滑动续期：剩余时间不足一个空闲窗口则顺延，且不超过绝对上限
            remaining = session.expires_at - now
            if remaining <= IDLE_TIMEOUT:
                renewed = min(now + IDLE_TIMEOUT, session.absolute_deadline)
                logger.info(
                    "session sliding renew sid=%s remaining=%s old_exp=%s new_exp=%s",
                    session_id,
                    remaining,
                    session.expires_at.isoformat(),
                    renewed.isoformat(),
                )
                session.expires_at = renewed
            session.last_seen_at = now
            return session

    # ---- 改密：使全部既有会话失效 ----------------------------------------
    def change_password(
        self, username: str, old_password: str, new_password: str
    ) -> None:
        """改密只递增 password_version，不打 revoked 标记：

        - 这样既有会话因“密码版本不匹配”失效，错误码可与“被独立撤销”区分；
        - 多会话场景下所有既有会话（含当前会话）统一失效。
        """
        with self.store.lock():
            user = self.store.get_user(username)
            if user is None or not verify_password(
                old_password, user.password_salt, user.password_hash
            ):
                logger.info("change-password rejected: bad old password user=%s", username)
                raise AppError(
                    E_INVALID_CREDENTIALS,
                    "invalid username or password",
                    status_code=401,
                )
            user.password_salt = new_salt()
            user.password_hash = hash_password(new_password, user.password_salt)
            user.password_version += 1
            logger.info(
                "password changed user=%s new_pv=%d; existing sessions now stale",
                username,
                user.password_version,
            )

    # ---- 会话列举 --------------------------------------------------------
    def is_session_live(self, session: Session, now: datetime | None = None) -> bool:
        """会话当前是否有效：未撤销、未过期（空闲/绝对）、密码版本未过期。"""
        moment = now or self.clock()
        user = self.store.get_user(session.username)
        if user is None or user.password_version != session.password_version:
            return False
        if session.revoked:
            return False
        return moment < session.expires_at and moment < session.absolute_deadline

    def list_live_sessions(self, username: str) -> list[Session]:
        """列举某用户当前仍有效的会话（过滤已撤销/已过期/改密后失效的）。"""
        now = self.clock()
        with self.store.lock():
            return [
                s
                for s in self.store.list_user_sessions(username)
                if self.is_session_live(s, now)
            ]

    # ---- 内部 ------------------------------------------------------------
    def _new_session(self, user: User, now: datetime) -> Session:
        snapshot = set()
        if self.rbac is not None:
            snapshot = self.rbac.effective_permissions(user)
        return Session(
            session_id=new_token(),
            username=user.username,
            csrf_token=new_token(),
            created_at=now,
            last_seen_at=now,
            expires_at=now + IDLE_TIMEOUT,
            absolute_deadline=now + ABSOLUTE_TIMEOUT,
            password_version=user.password_version,
            permission_snapshot=snapshot,
        )
