import logging
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.routes import create_app, seed_user

logger = logging.getLogger("tests")


@pytest.fixture()
def settings() -> Settings:
    return Settings(
        session_ttl_seconds=1800.0,
        refresh_window_seconds=600.0,
        csrf_ttl_seconds=1800.0,
        login_max_failures=3,
        login_failure_window_seconds=300.0,
        login_lockout_seconds=300.0,
    )


@pytest.fixture()
def app(settings):
    application = create_app(settings)
    seed_user(application, "alice", "alice-password", {"reader"})
    seed_user(application, "bob", "bob-password", {"editor"})
    seed_user(application, "root", "root-password", {"admin"})
    seed_user(application, "norole", "norole-password", set())
    return application


@pytest.fixture()
def client(app):
    return TestClient(app, raise_server_exceptions=True)


def login(client, username, password, **kwargs):
    resp = client.post("/login", json={"username": username, "password": password}, **kwargs)
    logger.info(
        "login input user=%r -> status=%d body=%s",
        username, resp.status_code, resp.json(),
    )
    return resp


@pytest.fixture()
def alice_client(client):
    resp = login(client, "alice", "alice-password")
    assert resp.status_code == 200
    return client, resp.json()["csrf_token"]


@pytest.fixture()
def fake_clock(monkeypatch):
    """Deterministic monotonic clock, patched only into the app modules
    (the global ``time`` module is left untouched for the test client)."""
    import types

    import app.auth
    import app.csrf
    import app.models
    import app.store

    state = {"now": 1_000.0}
    fake_time = types.SimpleNamespace(monotonic=lambda: state["now"])
    for module in (app.auth, app.csrf, app.models, app.store):
        monkeypatch.setattr(module, "time", fake_time)

    def advance(seconds: float) -> None:
        state["now"] += seconds
        logger.info("clock advanced to %.1f", state["now"])

    advance.state = state
    return advance
