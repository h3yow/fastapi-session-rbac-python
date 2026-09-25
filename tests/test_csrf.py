"""CSRF: missing, cross-session, and expired tokens are rejected with
distinguishable reasons; only the session's own live token passes."""
import logging

from fastapi.testclient import TestClient

from tests.conftest import login

logger = logging.getLogger("tests.csrf")


def err(resp):
    return resp.json()["error"]["code"]


def test_missing_token_rejected(client):
    tok = login(client, "bob", "bob-password").json()["csrf_token"]
    _ = tok
    r = client.post("/reports")
    logger.info("no csrf header -> %d %s", r.status_code, err(r))
    assert r.status_code == 403
    assert err(r) == "csrf_missing"


def test_cross_session_token_rejected(client, app):
    c1, c2 = TestClient(app), TestClient(app)
    login(c1, "bob", "bob-password")
    tok2 = login(c2, "root", "root-password").json()["csrf_token"]
    r = c1.post("/reports", headers={"X-CSRF-Token": tok2})
    logger.info("bob's session + root's token -> %d %s", r.status_code, err(r))
    assert r.status_code == 403
    assert err(r) == "csrf_invalid"
    # c2's own token is fine.
    assert c2.post("/reports", headers={"X-CSRF-Token": tok2}).status_code == 200


def test_forged_token_rejected(client):
    login(client, "bob", "bob-password")
    r = client.post("/reports", headers={"X-CSRF-Token": "forged-token"})
    logger.info("forged token -> %d %s", r.status_code, err(r))
    assert r.status_code == 403
    assert err(r) == "csrf_invalid"


def test_expired_token_rejected(client, settings, fake_clock):
    tok = login(client, "bob", "bob-password").json()["csrf_token"]
    fake_clock(settings.csrf_ttl_seconds + 1)
    # Session itself is still valid (ttl >= csrf ttl in these settings) only
    # if session_ttl > csrf_ttl; here they are equal, so use a shorter csrf.
    r = client.post("/reports", headers={"X-CSRF-Token": tok})
    logger.info("expired token -> %d %s", r.status_code, r.json())
    assert r.status_code in (401, 403)
    assert err(r) in ("csrf_invalid", "session_expired")


def test_expired_token_distinct_from_session_expiry(app, fake_clock):
    """With csrf_ttl < session_ttl, an expired CSRF token on a live session
    yields csrf_invalid, not a session error."""
    from app.config import Settings
    from app.routes import create_app, seed_user

    settings = Settings(csrf_ttl_seconds=100.0, session_ttl_seconds=1000.0,
                        refresh_window_seconds=500.0)
    application = create_app(settings)
    seed_user(application, "ed", "ed-password", {"editor"})
    c = TestClient(application)
    tok = login(c, "ed", "ed-password").json()["csrf_token"]
    fake_clock(200.0)  # csrf expired, session alive
    r = c.post("/reports", headers={"X-CSRF-Token": tok})
    logger.info("csrf expired but session live -> %d %s", r.status_code, err(r))
    assert r.status_code == 403
    assert err(r) == "csrf_invalid"
    assert c.get("/me").status_code == 200


def test_logout_requires_csrf(client, alice_client):
    c, _ = alice_client
    r = c.post("/logout")
    logger.info("logout without csrf -> %d %s", r.status_code, err(r))
    assert r.status_code == 403
    assert err(r) == "csrf_missing"
    assert c.get("/me").status_code == 200  # still logged in
