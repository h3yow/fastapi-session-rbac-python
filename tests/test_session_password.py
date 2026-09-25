"""会话生命周期管理：并发会话独立撤销、改密后全部既有会话失效。"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from app.errors import (
    E_PASSWORD_CHANGED,
    E_SESSION_REVOKED,
)

logger = logging.getLogger("tests.session")


def _fresh_client(app) -> TestClient:
    return TestClient(app)


def test_multiple_concurrent_sessions_are_independently_revocable(app):
    """同一账户建立 3 个并发会话；撤销中间一个，其余两个必须继续可用。"""
    clients = [_fresh_client(app) for _ in range(3)]
    try:
        csrf_tokens = []
        for c in clients:
            r = c.post(
                "/api/auth/login",
                json={"username": "alice", "password": "alice-pass"},
            )
            assert r.status_code == 204
            csrf_tokens.append(r.cookies["csrf_token"])

        # 列出会话：应有 3 个有效会话
        listing = clients[0].get("/api/sessions").json()["sessions"]
        ids = [s["session_id"] for s in listing]
        logger.info("alice concurrent sessions: count=%d ids=%s", len(ids), ids)
        assert len(ids) == 3

        # 用第 2 个会话撤销它自己
        victim_id = ids[1]
        r = clients[1].delete(
            f"/api/sessions/{victim_id}",
            headers={"X-CSRF-Token": csrf_tokens[1]},
        )
        assert r.status_code == 204, r.text

        # 被撤销的会话立即失效
        r = clients[1].get("/api/profile")
        logger.info("revoked session -> %s %s", r.status_code, r.json())
        assert r.status_code == 401
        assert r.json()["error"]["code"] == E_SESSION_REVOKED

        # 另外两个会话不受影响
        for i in (0, 2):
            r = clients[i].get("/api/profile")
            assert r.status_code == 200, r.text
            assert r.json()["username"] == "alice"
        logger.info("the other two sessions remain valid")
    finally:
        for c in clients:
            c.close()


def test_concurrent_requests_on_distinct_sessions_all_succeed(app):
    """10 个线程各自持有独立会话并发访问，互不干扰。"""
    clients = [_fresh_client(app) for _ in range(10)]
    try:
        for c in clients:
            assert (
                c.post(
                    "/api/auth/login",
                    json={"username": "alice", "password": "alice-pass"},
                ).status_code
                == 204
            )

        def hit(i):
            r = clients[i].get("/api/profile")
            return i, r.status_code

        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(hit, range(10)))
        logger.info("concurrent distinct-session results: %s", results)
        assert all(code == 200 for _, code in results)
    finally:
        for c in clients:
            c.close()


def test_password_change_invalidates_all_existing_sessions(app):
    """关键输入：改密请求 + 旧会话。判定：旧会话立即得到
    session_invalidated_by_password_change；新密码可登录，旧密码不可。"""
    old = _fresh_client(app)
    other = _fresh_client(app)
    try:
        csrf = old.post(
            "/api/auth/login",
            json={"username": "alice", "password": "alice-pass"},
        ).cookies["csrf_token"]
        # 另一并发会话也应在改密后一起失效
        assert (
            other.post(
                "/api/auth/login",
                json={"username": "alice", "password": "alice-pass"},
            ).status_code
            == 204
        )

        r = old.post(
            "/api/auth/change-password",
            json={"old_password": "alice-pass", "new_password": "alice-NEW-1"},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 204, r.text
        logger.info("password changed; existing sessions must be invalid")

        # 两个既有会话均失效，且原因可区分为“改密导致”
        for c, name in ((old, "current"), (other, "concurrent")):
            r = c.get("/api/profile")
            logger.info("%s session after pw change -> %s %s", name, r.status_code, r.json())
            assert r.status_code == 401
            assert r.json()["error"]["code"] == E_PASSWORD_CHANGED

        # 旧密码登录失败，新密码登录成功
        r = old.post(
            "/api/auth/login",
            json={"username": "alice", "password": "alice-pass"},
        )
        assert r.status_code == 401
        r = old.post(
            "/api/auth/login",
            json={"username": "alice", "password": "alice-NEW-1"},
        )
        assert r.status_code == 204
    finally:
        old.close()
        other.close()


def test_password_change_requires_current_password_and_csrf(client):
    csrf = client.post(
        "/api/auth/login",
        json={"username": "bob", "password": "bob-pass"},
    ).cookies["csrf_token"]

    # 缺少 CSRF -> 拒绝
    r = client.post(
        "/api/auth/change-password",
        json={"old_password": "bob-pass", "new_password": "bob-NEW-123"},
    )
    assert r.status_code == 403
    logger.info("change-password without csrf -> %s", r.json()["error"]["code"])

    # 旧密码错误 -> 拒绝
    r = client.post(
        "/api/auth/change-password",
        json={"old_password": "WRONG", "new_password": "bob-NEW-123"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 401
    logger.info("change-password wrong old pw -> %s", r.json()["error"]["code"])


def test_non_owner_without_permission_cannot_revoke(app, client):
    """bob 尝试撤销 alice 的会话：属主非本人且无 session:revoke -> forbidden。"""
    admin = _fresh_client(app)  # 用 admin 登录以创建/查看 alice 会话不必要
    alice_c = _fresh_client(app)
    try:
        alice_c.post(
            "/api/auth/login",
            json={"username": "alice", "password": "alice-pass"},
        )
        alice_sessions = alice_c.get("/api/sessions").json()["sessions"]
        alice_sid = alice_sessions[0]["session_id"]

        b_csrf = client.post(
            "/api/auth/login",
            json={"username": "bob", "password": "bob-pass"},
        ).cookies["csrf_token"]
        r = client.delete(
            f"/api/sessions/{alice_sid}", headers={"X-CSRF-Token": b_csrf}
        )
        logger.info("bob revoking alice session -> %s %s", r.status_code, r.json())
        assert r.status_code == 403

        # alice 的会话仍可用
        assert alice_c.get("/api/profile").status_code == 200
    finally:
        admin.close()
        alice_c.close()


def test_stale_sessions_disappear_from_listing_after_password_change(app):
    """改密后用新密码登录，旧会话不得再出现在 /api/sessions 列表中。"""
    from fastapi.testclient import TestClient

    old = TestClient(app)
    try:
        old_csrf = old.post(
            "/api/auth/login",
            json={"username": "bob", "password": "bob-pass"},
        ).cookies["csrf_token"]
        old.post(
            "/api/auth/change-password",
            json={"old_password": "bob-pass", "new_password": "bob-FRESH-9"},
            headers={"X-CSRF-Token": old_csrf},
        )

        fresh = TestClient(app)
        try:
            fresh.post(
                "/api/auth/login",
                json={"username": "bob", "password": "bob-FRESH-9"},
            )
            listing = fresh.get("/api/sessions").json()["sessions"]
            logger.info("live sessions after password change: %d", len(listing))
            assert len(listing) == 1
            assert listing[0]["current"] is True
        finally:
            fresh.close()
    finally:
        old.close()
