"""Session invalidation reasons must be distinguishable in the response:
unknown / kicked / password_changed / expired — and distinct from
permission denials."""
import logging

from fastapi.testclient import TestClient

from tests.conftest import login

logger = logging.getLogger("tests.reasons")


def body(resp):
    return resp.json()["error"]


class TestSessionReasons:
    def test_unknown_session(self, client):
        r = client.get("/me", cookies={"session_id": "totally-made-up"})
        logger.info("unknown cookie -> %s", body(r))
        assert r.status_code == 401
        assert body(r)["code"] == "session_invalid"
        assert body(r)["reason"] == "unknown"

    def test_kicked_session(self, app):
        c = TestClient(app)
        data = login(c, "alice", "alice-password").json()
        c.post("/logout", headers={"X-CSRF-Token": data["csrf_token"]})
        r = c.get("/me", cookies={"session_id": data["session_id"]})
        logger.info("logged-out cookie -> %s", body(r))
        assert body(r)["reason"] == "kicked"

    def test_password_changed_sessions(self, client):
        c1, c2 = TestClient(client.app), TestClient(client.app)
        t1 = login(c1, "bob", "bob-password").json()["csrf_token"]
        login(c2, "bob", "bob-password")
        c1.post("/change-password",
                json={"old_password": "bob-password", "new_password": "bob-new2"},
                headers={"X-CSRF-Token": t1})
        for c, label in ((c1, "changer"), (c2, "sibling")):
            r = c.get("/me")
            logger.info("after password change (%s) -> %s", label, body(r))
            assert r.status_code == 401
            assert body(r)["code"] == "session_invalid"
            assert body(r)["reason"] == "password_changed"

    def test_expired_session(self, client, settings, fake_clock, alice_client):
        c, _ = alice_client
        fake_clock(settings.session_ttl_seconds + 1)
        r = c.get("/me")
        logger.info("expired cookie -> %s", body(r))
        assert r.status_code == 401
        assert body(r)["code"] == "session_expired"
        assert body(r)["reason"] == "expired"

    def test_all_four_plus_missing_and_permission_are_distinct(self, client, app,
                                                               settings, fake_clock):
        # missing
        missing = client.get("/me")
        # unknown
        unknown = client.get("/me", cookies={"session_id": "bogus"})
        # kicked
        ck = TestClient(app)
        dk = login(ck, "alice", "alice-password").json()
        ck.post("/logout", headers={"X-CSRF-Token": dk["csrf_token"]})
        kicked = ck.get("/me", cookies={"session_id": dk["session_id"]})
        # expired
        ce = TestClient(app)
        login(ce, "alice", "alice-password")
        fake_clock(settings.session_ttl_seconds + 1)
        expired = ce.get("/me")
        # permission denial (different code family)
        fake_clock(-(settings.session_ttl_seconds + 1))  # not used for others
        cp = TestClient(app)
        dp = login(cp, "alice", "alice-password").json()
        forbidden = cp.post("/reports",
                            headers={"X-CSRF-Token": dp["csrf_token"]})

        labels = {
            "missing": body(missing),
            "unknown": body(unknown),
            "kicked": body(kicked),
            "expired": body(expired),
            "forbidden": body(forbidden),
        }
        for label, b in labels.items():
            logger.info("%-10s -> code=%s reason=%s",
                        label, b["code"], b.get("reason"))
        # Password-change separately.
        cb = TestClient(app)
        db = login(cb, "bob", "bob-password").json()
        cb.post("/change-password",
                json={"old_password": "bob-password", "new_password": "bob-x"},
                headers={"X-CSRF-Token": db["csrf_token"]})
        pwd = body(cb.get("/me"))
        logger.info("password   -> code=%s reason=%s", pwd["code"], pwd.get("reason"))

        reasons = {labels["missing"].get("reason"),
                   labels["unknown"].get("reason"),
                   labels["kicked"].get("reason"),
                   labels["expired"].get("reason"),
                   pwd.get("reason")}
        assert reasons == {"missing", "unknown", "kicked", "expired",
                           "password_changed"}
        # Session reasons are 401 codes; permission denial is a distinct 403.
        assert labels["forbidden"]["code"] == "forbidden_permission"
        assert forbidden.status_code == 403
