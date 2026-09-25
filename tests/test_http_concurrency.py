"""HTTP 层并发与边界：多 TestClient + 线程，验证锁定阈值不可并发绕过、
来源维度隔离、并发撤销与判因稳定。"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app.errors import AppError

logger = logging.getLogger("tests.http_conc")


def test_concurrent_bad_logins_over_http_have_stable_codes(app):
    """12 个线程并发对同一账户发起错误密码登录：恰好 MAX_FAILURES 个
    invalid_credentials，其余 account_locked；随后正确密码也被锁。"""
    clients = [TestClient(app) for _ in range(12)]
    try:
        def attempt(i):
            r = clients[i].post(
                "/api/auth/login",
                json={"username": "bob", "password": "BAD-PW"},
            )
            return r.status_code, r.json()["error"]["code"]

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(attempt, range(12)))

        codes = [code for _, code in results]
        invalid = codes.count("invalid_credentials")
        locked = codes.count("account_locked")
        logger.info(
            "http concurrent bad logins total=%d invalid=%d locked=%d codes=%s",
            len(codes), invalid, locked, codes,
        )
        from app.auth import MAX_FAILURES
        assert invalid == MAX_FAILURES
        assert locked == 12 - MAX_FAILURES

        # 阈值后正确密码 -> 仍锁定
        r = clients[0].post(
            "/api/auth/login",
            json={"username": "bob", "password": "bob-pass"},
        )
        assert r.status_code == 423
        assert r.json()["error"]["code"] == "account_locked"
    finally:
        for c in clients:
            c.close()


def test_lockout_source_isolation_over_service():
    """同一账户，不同来源 IP 的失败计数互不影响（边界隔离）。"""
    from app.container import build_container

    c = build_container()
    for _ in range(5):
        with pytest.raises(AppError):
            c.auth.login("bob", "bad", "1.1.1.1")
    # 1.1.1.1 已锁；2.2.2.2 从未失败，可正常登录
    s = c.auth.login("bob", "bob-pass", "2.2.2.2")
    assert s.username == "bob"
    logger.info("source isolation ok: 1.1.1.1 locked while 2.2.2.2 logs in")


def test_concurrent_session_use_and_revocation(app):
    """2 个独立会话并发被使用；管理员撤销其中一个后，被撤会话稳定返回
    session_revoked，另一会话持续 200。"""
    victim = TestClient(app)
    survivor = TestClient(app)
    admin = TestClient(app)
    try:
        victim.post(
            "/api/auth/login",
            json={"username": "alice", "password": "alice-pass"},
        )
        survivor.post(
            "/api/auth/login",
            json={"username": "alice", "password": "alice-pass"},
        )
        admin_csrf = admin.post(
            "/api/auth/login",
            json={"username": "admin", "password": "admin-pass"},
        ).cookies["csrf_token"]

        victim_sid = next(
            s["session_id"]
            for s in victim.get("/api/sessions").json()["sessions"]
            if s["current"]
        )

        r = admin.delete(
            f"/api/sessions/{victim_sid}",
            headers={"X-CSRF-Token": admin_csrf},
        )
        assert r.status_code == 204, r.text
        logger.info("admin revoked victim session sid=%s", victim_sid[:8])

        def use_victim():
            r = victim.get("/api/profile")
            return r.status_code, r.json().get("error", {}).get("code")

        def use_survivor():
            r = survivor.get("/api/profile")
            return r.status_code, r.json().get("error", {}).get("code")

        with ThreadPoolExecutor(max_workers=2) as pool:
            vr = list(pool.map(lambda _: use_victim(), range(10)))
            sr = list(pool.map(lambda _: use_survivor(), range(10)))

        logger.info("victim results=%s survivor results=%s", vr[:3], sr[:3])
        assert all(code == 401 and reason == "session_revoked" for code, reason in vr)
        assert all(code == 200 for code, _ in sr)
    finally:
        victim.close()
        survivor.close()
        admin.close()


def test_revocation_mid_concurrent_requests_keeps_consistent_codes(app):
    """会话先被并发使用；撤销后再并发使用，全部得到相同的可解释判因。"""
    clients = [TestClient(app) for _ in range(6)]
    try:
        csrfs = []
        for c in clients:
            csrfs.append(
                c.post(
                    "/api/auth/login",
                    json={"username": "bob", "password": "bob-pass"},
                ).cookies["csrf_token"]
            )

        def profile(i):
            return clients[i].get("/api/profile").status_code

        with ThreadPoolExecutor(max_workers=6) as pool:
            ok = list(pool.map(profile, range(6)))
        assert ok == [200] * 6

        # 每个会话撤销自己（按 current 精确选中本会话，避免误撤他人）
        def self_revoke(i):
            r = clients[i].get("/api/sessions")
            sid = next(
                s["session_id"]
                for s in r.json()["sessions"]
                if s["current"]
            )
            return clients[i].delete(
                f"/api/sessions/{sid}",
                headers={"X-CSRF-Token": csrfs[i]},
            ).status_code

        with ThreadPoolExecutor(max_workers=6) as pool:
            revoked = list(pool.map(self_revoke, range(6)))
        assert revoked == [204] * 6

        with ThreadPoolExecutor(max_workers=6) as pool:
            after = list(pool.map(profile, range(6)))
        logger.info("post-revocation concurrent codes=%s", after)
        assert after == [401] * 6
    finally:
        for c in clients:
            c.close()
