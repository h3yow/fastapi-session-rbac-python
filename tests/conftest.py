"""pytest 公共夹具：每次测试使用全新装配的应用（内存存储互不影响）。"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.container import build_container
from app.main import create_app

logger = logging.getLogger("tests")


@pytest.fixture
def container():
    return build_container()


@pytest.fixture
def app():
    application = create_app()
    return application


@pytest.fixture
def client(app) -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


def login(client: TestClient, username: str, password: str) -> str:
    """登录并返回该会话的 CSRF 令牌（sid 仅存于 httpOnly Cookie）。"""
    resp = client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert resp.status_code == 204, resp.text
    return resp.cookies["csrf_token"]


@pytest.fixture(autouse=True)
def _log_case(request):
    logger.info("==== TEST START %s ====", request.node.nodeid)
    yield
    logger.info("==== TEST END   %s ====", request.node.nodeid)
