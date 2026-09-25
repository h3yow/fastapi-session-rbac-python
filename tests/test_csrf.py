"""CSRF 防护：缺失、错误、过期/跨会话令牌错用均须拒绝。"""

from __future__ import annotations

import logging

from fastapi.testclient import TestClient

from app.errors import (
    E_CSRF_INVALID,
    E_CSRF_MISSING,
    E_NOT_AUTHENTICATED,
)

logger = logging.getLogger("tests.csrf")


def test_csrf_missing_and_empty_rejected(client):
    client.post(
        "/api/auth/login",
        json={"username": "alice", "password": "alice-pass"},
    )

    r = client.post("/api/articles", json={"title": "x"})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == E_CSRF_MISSING

    r = client.post(
        "/api/articles", json={"title": "x"}, headers={"X-CSRF-Token": ""}
    )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == E_CSRF_MISSING
    logger.info("missing/empty csrf tokens rejected")


def test_csrf_wrong_token_rejected(client):
    client.post(
        "/api/auth/login",
        json={"username": "alice", "password": "alice-pass"},
    )
    r = client.post(
        "/api/articles",
        json={"title": "x"},
        headers={"X-CSRF-Token": "0" * 64},
    )
    logger.info("bogus token -> %s %s", r.status_code, r.json())
    assert r.status_code == 403
    assert r.json()["error"]["code"] == E_CSRF_INVALID


def test_csrf_token_from_another_session_is_rejected(app):
    """关键输入：A 的 sid Cookie + B 的 csrf_token（令牌与会话不匹配）。
    判定：csrf_token_invalid，绝不能放行。"""
    a = TestClient(app)
    b = TestClient(app)
    try:
        a_csrf = a.post(
            "/api/auth/login",
            json={"username": "alice", "password": "alice-pass"},
        ).cookies["csrf_token"]
        b_csrf = b.post(
            "/api/auth/login",
            json={"username": "bob", "password": "bob-pass"},
        ).cookies["csrf_token"]
        assert a_csrf != b_csrf

        # A 携带 B 的 CSRF 令牌发起写请求
        r = a.post(
            "/api/articles",
            json={"title": "confused deputy"},
            headers={"X-CSRF-Token": b_csrf},
        )
        logger.info("A sid + B csrf -> %s %s", r.status_code, r.json())
        assert r.status_code == 403
        assert r.json()["error"]["code"] == E_CSRF_INVALID
    finally:
        a.close()
        b.close()


def test_safe_methods_do_not_require_csrf(client):
    client.post(
        "/api/auth/login",
        json={"username": "alice", "password": "alice-pass"},
    )
    # GET 无需 CSRF 头
    r = client.get("/api/articles")
    assert r.status_code == 200
    logger.info("GET without csrf allowed: %s", r.status_code)


def test_csrf_endpoint_requires_session_first(client):
    """无会话时即使带上任意 CSRF 头，也应先被判为未认证。"""
    r = client.post(
        "/api/articles",
        json={"title": "x"},
        headers={"X-CSRF-Token": "0" * 64},
    )
    logger.info("no session + csrf -> %s %s", r.status_code, r.json())
    assert r.status_code == 401
    assert r.json()["error"]["code"] == E_NOT_AUTHENTICATED
