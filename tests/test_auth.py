"""Session lifecycle: login/logout, expiry, renewal, password change,
independent revocation, and failure/lockout semantics."""
import logging

from tests.conftest import login

logger = logging.getLogger("tests.auth")


def err(resp):
    return resp.json()["error"]["code"]


class TestLoginFailures:
    def test_unknown_user_and_wrong_password_are_indistinguishable(self, client):
        r1 = login(client, "ghost", "whatever")
        r2 = login(client, "alice", "wrong-password")
        logger.info("unknown_user code=%s detail=%r", err(r1), r1.json()["error"]["detail"])
        logger.info("wrong_password code=%s detail=%r", err(r2), r2.json()["error"]["detail"])
        assert r1.status_code == r2.status_code == 401
        assert err(r1) == err(r2) == "invalid_credentials"
        assert r1.json()["error"]["detail"] == r2.json()["error"]["detail"]

    def test_lockout_after_threshold_and_distinct_code(self, client, settings):
        for i in range(settings.login_max_failures - 1):
            r = login(client, "alice", "wrong")
            assert err(r) == "invalid_credentials", f"attempt {i + 1}"
        r = login(client, "alice", "wrong")
        logger.info("attempt %d -> %s", settings.login_max_failures, err(r))
        assert err(r) == "account_locked"
        # Even the correct password is rejected while locked, with the
        # lockout code (distinguishable from bad credentials).
        r = login(client, "alice", "alice-password")
        logger.info("correct password while locked -> %s", err(r))
        assert r.status_code == 401
        assert err(r) == "account_locked"

    def test_lockout_expires_deterministically(self, client, settings, fake_clock):
        for _ in range(settings.login_max_failures):
            login(client, "alice", "wrong")
        assert err(login(client, "alice", "alice-password")) == "account_locked"
        fake_clock(settings.login_lockout_seconds - 1)
        assert err(login(client, "alice", "alice-password")) == "account_locked"
        fake_clock(1.5)  # now past locked_until
        r = login(client, "alice", "alice-password")
        logger.info("after lockout window -> status=%d", r.status_code)
        assert r.status_code == 200

    def test_successful_login_clears_failure_count(self, client, settings):
        login(client, "alice", "wrong")
        login(client, "alice", "wrong")
        assert login(client, "alice", "alice-password").status_code == 200
        # Counter was reset: another max-1 failures still no lock.
        for _ in range(settings.login_max_failures - 1):
            assert err(login(client, "alice", "wrong")) == "invalid_credentials"
        assert err(login(client, "alice", "wrong")) == "account_locked"


class TestSessionLifecycle:
    def test_logout_revokes_only_that_session(self, client):
        from fastapi.testclient import TestClient

        app = client.app
        c1, c2 = TestClient(app), TestClient(app)
        r1, r2 = login(c1, "alice", "alice-password"), login(c2, "alice", "alice-password")
        sid1, tok1 = r1.json()["session_id"], r1.json()["csrf_token"]
        assert c1.post("/logout", headers={"X-CSRF-Token": tok1}).status_code == 200
        # Present the revoked cookie explicitly to observe the invalid reason.
        r_me1, r_me2 = c1.get("/me", cookies={"session_id": sid1}), c2.get("/me")
        logger.info("after logout: s1 -> %s, s2 -> %d", err(r_me1), r_me2.status_code)
        assert err(r_me1) == "session_invalid"
        assert r_me2.status_code == 200  # sibling session unaffected

    def test_session_expiry(self, client, settings, fake_clock, alice_client):
        c, _ = alice_client
        fake_clock(settings.session_ttl_seconds + 1)
        r = c.get("/me")
        logger.info("after ttl: code=%s", err(r))
        assert r.status_code == 401
        assert err(r) == "session_expired"

    def test_refresh_window_semantics(self, client, settings, fake_clock, alice_client):
        c, tok = alice_client
        # Too early: outside the refresh window.
        r = c.post("/refresh", headers={"X-CSRF-Token": tok})
        logger.info("early refresh -> %s", err(r))
        assert r.status_code == 401
        # Inside the window: allowed, new token issued, expiry extended.
        fake_clock(settings.session_ttl_seconds - settings.refresh_window_seconds + 1)
        r = c.post("/refresh", headers={"X-CSRF-Token": tok})
        assert r.status_code == 200
        new_tok = r.json()["csrf_token"]
        logger.info("refreshed: new csrf differs=%s", new_tok != tok)
        assert new_tok != tok
        # Survives past the original expiry.
        fake_clock(settings.refresh_window_seconds + 1)
        assert c.get("/me").status_code == 200

    def test_password_change_invalidates_all_sessions(self, client):
        from fastapi.testclient import TestClient

        app = client.app
        c1, c2 = TestClient(app), TestClient(app)
        t1 = login(c1, "bob", "bob-password").json()["csrf_token"]
        login(c2, "bob", "bob-password")
        r = c1.post(
            "/change-password",
            json={"old_password": "bob-password", "new_password": "bob-new"},
            headers={"X-CSRF-Token": t1},
        )
        logger.info("change-password -> %d %s", r.status_code, r.json())
        assert r.status_code == 200
        assert r.json()["sessions_revoked"] == 2
        r1, r2 = c1.get("/me"), c2.get("/me")
        logger.info("old sessions -> %s / %s", err(r1), err(r2))
        assert err(r1) == err(r2) == "session_invalid"
        # New password works, old one does not.
        assert login(client, "bob", "bob-new").status_code == 200
        assert err(login(client, "bob", "bob-password")) == "invalid_credentials"

    def test_change_password_wrong_old_password(self, client, alice_client):
        c, tok = alice_client
        r = c.post(
            "/change-password",
            json={"old_password": "nope", "new_password": "x"},
            headers={"X-CSRF-Token": tok},
        )
        logger.info("wrong old password -> %s", err(r))
        assert r.status_code == 401
        assert err(r) == "invalid_credentials"
        assert c.get("/me").status_code == 200  # session still valid

    def test_missing_session_cookie(self, client):
        r = client.get("/me")
        assert r.status_code == 401
        assert err(r) == "session_missing"
