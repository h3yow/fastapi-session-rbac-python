"""线程安全的内存存储：用户、会话、失败计数。

所有可变状态的读写都在一把 RLock 下完成，保证多请求并发下的一致性。
需要“检查-判定-写入”原子性的复合操作，由 service 层通过 lock() 取同一把锁包裹。
"""

from __future__ import annotations

import threading

from .models import FailureCounter, Session, User


class Store:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._users: dict[str, User] = {}
        self._sessions: dict[str, Session] = {}
        self._failures: dict[str, FailureCounter] = {}

    # 用户 ----------------------------------------------------------------
    def get_user(self, username: str) -> User | None:
        with self._lock:
            return self._users.get(username)

    def upsert_user(self, user: User) -> None:
        with self._lock:
            self._users[user.username] = user

    # 会话 ----------------------------------------------------------------
    def add_session(self, session: Session) -> None:
        with self._lock:
            self._sessions[session.session_id] = session

    def get_session(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def replace_session(self, session: Session) -> None:
        """持久化对会话字段（如 last_seen_at/expires_at）的修改。"""
        with self._lock:
            self._sessions[session.session_id] = session

    def revoke_session(self, session_id: str) -> None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is not None:
                session.revoked = True

    def revoke_user_sessions(
        self, username: str, *, except_id: str | None = None
    ) -> int:
        """撤销某用户全部会话（改密时使用），返回撤销数量。"""
        with self._lock:
            count = 0
            for session in self._sessions.values():
                if session.username != username:
                    continue
                if except_id is not None and session.session_id == except_id:
                    continue
                session.revoked = True
                count += 1
            return count

    def list_user_sessions(self, username: str) -> list[Session]:
        with self._lock:
            return [
                s
                for s in self._sessions.values()
                if s.username == username and not s.revoked
            ]

    # 失败计数 -------------------------------------------------------------
    def get_or_create_counter(self, key: str) -> FailureCounter:
        with self._lock:
            counter = self._failures.get(key)
            if counter is None:
                counter = FailureCounter(key=key)
                self._failures[key] = counter
            return counter

    def lock(self) -> threading.RLock:
        """允许 service 在同一临界区中完成“检查-判定-写入”复合操作。"""
        return self._lock
