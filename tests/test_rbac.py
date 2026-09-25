"""RBAC：默认拒绝、forbidden 与 permission_revoked 可区分、在线变更即时生效。"""

from __future__ import annotations

import logging

from app.errors import (
    E_FORBIDDEN,
    E_NOT_AUTHENTICATED,
    E_PERMISSION_REVOKED,
)

logger = logging.getLogger("tests.rbac")


def test_default_deny_anonymous_and_missing_permission(client):
    """匿名 -> not_authenticated；已登录但无权限 -> forbidden，两者可区分。"""
    r_anon = client.get("/api/articles")
    assert r_anon.status_code == 401
    assert r_anon.json()["error"]["code"] == E_NOT_AUTHENTICATED

    csrf = client.post(
        "/api/auth/login",
        json={"username": "alice", "password": "alice-pass"},
    ).cookies["csrf_token"]

    # alice 是 editor，从不具备 admin:users -> forbidden
    r = client.post(
        "/api/admin/grant",
        json={"username": "bob", "permission": "article:write"},
        headers={"X-CSRF-Token": csrf},
    )
    logger.info("alice -> admin:users: %s %s", r.status_code, r.json())
    assert r.status_code == 403
    assert r.json()["error"]["code"] == E_FORBIDDEN


def test_permission_revoked_is_distinguishable_from_forbidden(app):
    """carol 登录时持有 article:read（快照含）；管理员在线撤销后：
    同一（未过期）会话再访问 -> permission_revoked，而非 forbidden。"""
    from fastapi.testclient import TestClient

    carol = TestClient(app)
    admin = TestClient(app)
    try:
        carol.post(
            "/api/auth/login",
            json={"username": "carol", "password": "carol-pass"},
        )
        admin_csrf = admin.post(
            "/api/auth/login",
            json={"username": "admin", "password": "admin-pass"},
        ).cookies["csrf_token"]

        # 撤销前可访问
        assert carol.get("/api/articles").status_code == 200

        # 管理员在线撤销，不重启服务
        r = admin.post(
            "/api/admin/revoke",
            json={"username": "carol", "permission": "article:read"},
            headers={"X-CSRF-Token": admin_csrf},
        )
        assert r.status_code == 204, r.text

        # 同一 carol 会话（无需重新登录）下一次请求即被拒绝
        r = carol.get("/api/articles")
        logger.info("carol after online revoke -> %s %s", r.status_code, r.json())
        assert r.status_code == 403
        assert r.json()["error"]["code"] == E_PERMISSION_REVOKED
    finally:
        carol.close()
        admin.close()


def test_grant_takes_effect_for_subsequent_request_without_restart(app):
    """授权后，后续请求（同一会话）立即放行；且因快照原本不含该权限，
    放行依据是“当前有效权限”。"""
    from fastapi.testclient import TestClient

    bob = TestClient(app)
    admin = TestClient(app)
    try:
        bob_csrf = bob.post(
            "/api/auth/login",
            json={"username": "bob", "password": "bob-pass"},
        ).cookies["csrf_token"]
        admin_csrf = admin.post(
            "/api/auth/login",
            json={"username": "admin", "password": "admin-pass"},
        ).cookies["csrf_token"]

        # bob(reader) 不能发文
        r = bob.post(
            "/api/articles",
            json={"title": "x"},
            headers={"X-CSRF-Token": bob_csrf},
        )
        assert r.status_code == 403
        assert r.json()["error"]["code"] == E_FORBIDDEN

        # 在线授予直接权限
        r = admin.post(
            "/api/admin/grant",
            json={"username": "bob", "permission": "article:write"},
            headers={"X-CSRF-Token": admin_csrf},
        )
        assert r.status_code == 204, r.text

        # 同一 bob 会话，无需重登、无需重启：立即可以发文
        r = bob.post(
            "/api/articles",
            json={"title": "now allowed"},
            headers={"X-CSRF-Token": bob_csrf},
        )
        logger.info("bob post after grant -> %s %s", r.status_code, r.json())
        assert r.status_code == 201
        assert r.json()["title"] == "now allowed"
    finally:
        bob.close()
        admin.close()


def test_role_permission_changes_apply_immediately(client):
    """角色映射变更也即时生效：给 bob 加 editor 角色后可发文。"""
    c = client.app.state.container
    csrf = client.post(
        "/api/auth/login",
        json={"username": "bob", "password": "bob-pass"},
    ).cookies["csrf_token"]
    assert client.post(
        "/api/articles", json={"title": "t"}, headers={"X-CSRF-Token": csrf}
    ).status_code == 403

    c.rbac.grant_role("bob", "editor")
    r = client.post(
        "/api/articles", json={"title": "t"}, headers={"X-CSRF-Token": csrf}
    )
    logger.info("bob after editor role granted -> %s", r.status_code)
    assert r.status_code == 201


def test_admin_can_revoke_other_users_session(app):
    """管理员凭 session:revoke 可撤销他人会话；撤销判因 session_revoked。"""
    from fastapi.testclient import TestClient

    alice = TestClient(app)
    admin = TestClient(app)
    try:
        alice.post(
            "/api/auth/login",
            json={"username": "alice", "password": "alice-pass"},
        )
        admin_csrf = admin.post(
            "/api/auth/login",
            json={"username": "admin", "password": "admin-pass"},
        ).cookies["csrf_token"]

        # 通过 alice 自己拿到会话 id（也可由管理员业务接口查询）
        sid = next(
            s["session_id"]
            for s in alice.get("/api/sessions").json()["sessions"]
            if s["current"]
        )
        r = admin.delete(
            f"/api/sessions/{sid}", headers={"X-CSRF-Token": admin_csrf}
        )
        assert r.status_code == 204, r.text

        r = alice.get("/api/profile")
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "session_revoked"
        logger.info("admin revoked alice session; subsequent code=%s", r.json()["error"]["code"])
    finally:
        alice.close()
        admin.close()
