"""Session introspection and targeted revocation: self listing/kick,
admin listing/kick, isolation of siblings, and deterministic outcomes
for unknown/already-dead targets."""
import logging

from fastapi.testclient import TestClient

from tests.conftest import login
from tests.test_admin_roles import make_clients

logger = logging.getLogger("tests.sessions_admin")


def err(resp):
    return resp.json()["error"]["code"]


def reason(resp):
    return resp.json()["error"].get("reason")


class TestListOwnSessions:
    def test_lists_each_session_with_timing_and_status(self, app):
        c, tok, sid = make_clients(app, ("alice", "alice-password"))[0]
        c2 = TestClient(app)
        login(c2, "alice", "alice-password")

        r = c.get("/me/sessions")
        assert r.status_code == 200
        rows = r.json()["sessions"]
        logger.info("alice sessions: %s", rows)
        assert len(rows) == 2
        assert {row["session_id"] for row in rows} >= {sid}
        for row in rows:
            assert row["status"] == "active"
            assert row["created_at"] < row["expires_at"]
            assert row["remaining_seconds"] > 0
            assert row["username"] == "alice"

    def test_only_own_sessions_listed(self, app):
        (ac, _, _), (rc, _, rsid) = make_clients(
            app, ("root", "root-password"), ("alice", "alice-password"))
        r = rc.get("/me/sessions")
        ids = {row["session_id"] for row in r.json()["sessions"]}
        logger.info("alice sees ids=%s", ids)
        assert rsid in ids
        # Admin's session must not leak into alice's listing.
        admin_ids = {row["session_id"]
                     for row in ac.get("/me/sessions").json()["sessions"]}
        assert ids.isdisjoint(admin_ids)

    def test_anonymous_cannot_list(self, client):
        assert client.get("/me/sessions").status_code == 401

    def test_listing_marks_kicked_expired_password_changed(self, app, settings,
                                                           fake_clock):
        ac, atok, _ = make_clients(app, ("root", "root-password"))[0]

        # kicked session (alice; this account never changes password)
        ck = TestClient(app)
        dk = login(ck, "alice", "alice-password").json()
        ck.post("/logout", headers={"X-CSRF-Token": dk["csrf_token"]})
        alice_status = {
            r["session_id"]: r["status"]
            for r in ac.get("/admin/users/alice/sessions").json()["sessions"]
        }
        assert alice_status[dk["session_id"]] == "kicked"

        # expired session (norole account; never kicked / changed password)
        ce = TestClient(app)
        de = login(ce, "norole", "norole-password").json()
        fake_clock(settings.session_ttl_seconds + 1)
        # Re-login admin: its session was created before the clock jump.
        ac, atok, _ = make_clients(app, ("root", "root-password"))[0]
        norole_status = {
            r["session_id"]: r["status"]
            for r in ac.get("/admin/users/norole/sessions").json()["sessions"]
        }
        assert norole_status[de["session_id"]] == "expired"

        # password change bulk-invalidates bob's sessions. Rewind to a time
        # where the freshly-issued admin session is still valid.
        fake_clock(-(settings.session_ttl_seconds + 1))
        c3 = TestClient(app)
        d3 = login(c3, "bob", "bob-password").json()
        c3.post("/change-password",
                json={"old_password": "bob-password", "new_password": "bob-again"},
                headers={"X-CSRF-Token": d3["csrf_token"]})

        bob_status = {
            r["session_id"]: r["status"]
            for r in ac.get("/admin/users/bob/sessions").json()["sessions"]
        }
        logger.info("alice=%s bob=%s norole=%s",
                    alice_status, bob_status, norole_status)
        assert "password_changed" in bob_status.values()


class TestSelfRevoke:
    def test_revoke_exactly_one_sibling_unaffected(self, app):
        c1 = TestClient(app)
        c2 = TestClient(app)
        r1 = login(c1, "alice", "alice-password")
        r2 = login(c2, "alice", "alice-password")
        sid1, tok1 = r1.json()["session_id"], r1.json()["csrf_token"]
        sid2 = r2.json()["session_id"]

        r = c1.delete(f"/me/sessions/{sid1}",
                      headers={"X-CSRF-Token": tok1})
        logger.info("self revoke -> %d %s", r.status_code, r.json())
        assert r.status_code == 200
        assert r.json()["result"] == "revoked"

        r1after = c1.get("/me", cookies={"session_id": sid1})
        r2after = c2.get("/me", cookies={"session_id": sid2})
        logger.info("kicked=%s sibling=%s", err(r1after), r2after.status_code)
        assert r1after.status_code == 401
        assert reason(r1after) == "kicked"
        assert r2after.status_code == 200

    def test_revoke_requires_csrf(self, app):
        c, tok, sid = make_clients(app, ("alice", "alice-password"))[0]
        r = c.delete(f"/me/sessions/{sid}")
        assert r.status_code == 403 and err(r) == "csrf_missing"
        assert c.get("/me").status_code == 200

    def test_revoke_unknown_session_is_404(self, app):
        c, tok, sid = make_clients(app, ("alice", "alice-password"))[0]
        r = c.delete("/me/sessions/nonexistent-id",
                     headers={"X-CSRF-Token": tok})
        logger.info("revoke unknown -> %d %s", r.status_code, err(r))
        assert r.status_code == 404
        assert err(r) == "session_not_found"

    def test_cannot_revoke_other_users_session(self, app):
        (ac, atok, asid), (rc, _, rsid) = make_clients(
            app, ("alice", "alice-password"), ("root", "root-password"))
        # Alice tries to revoke root's session id within her own scope.
        r = ac.delete(f"/me/sessions/{rsid}",
                      headers={"X-CSRF-Token": atok})
        logger.info("alice kicks root via self endpoint -> %d %s",
                    r.status_code, err(r))
        assert r.status_code == 404
        # Root's session still works.
        assert rc.get("/me").status_code == 200

    def test_revoke_already_revoked_is_deterministic_409(self, app):
        c1 = TestClient(app)
        r1 = login(c1, "alice", "alice-password")
        sid1, tok1 = r1.json()["session_id"], r1.json()["csrf_token"]
        assert c1.delete(f"/me/sessions/{sid1}",
                         headers={"X-CSRF-Token": tok1}).status_code == 200
        # Repeat: idempotent target, but now clearly "already invalid".
        r = c1.delete(f"/me/sessions/{sid1}",
                      headers={"X-CSRF-Token": tok1},
                      cookies={"session_id": sid1})
        # Actor's own session is itself dead -> 401 kicked first.
        assert r.status_code == 401 and reason(r) == "kicked"

        # Admin targeting the same dead session gets a reproducible 409.
        ac, atok, _ = make_clients(app, ("root", "root-password"))[0]
        r = ac.delete(f"/admin/sessions/{sid1}",
                      headers={"X-CSRF-Token": atok})
        logger.info("admin re-revoke dead session -> %d %s",
                    r.status_code, err(r))
        assert r.status_code == 409
        assert err(r) == "session_already_invalid"
        # Repeatable.
        r2 = ac.delete(f"/admin/sessions/{sid1}",
                       headers={"X-CSRF-Token": atok})
        assert r2.status_code == 409


class TestAdminSessionManagement:
    def test_admin_can_list_other_users_sessions(self, app):
        (ac, _, _), = (make_clients(app, ("root", "root-password")))
        c = TestClient(app)
        r = login(c, "alice", "alice-password")
        asid = r.json()["session_id"]

        resp = ac.get("/admin/users/alice/sessions")
        assert resp.status_code == 200
        rows = resp.json()["sessions"]
        logger.info("admin lists alice -> %s", rows)
        assert any(row["session_id"] == asid for row in rows)

    def test_non_admin_cannot_admin_list_or_kick(self, app):
        (rc, rtok, rsid), = (make_clients(app, ("alice", "alice-password")))
        r = rc.get("/admin/users/alice/sessions")
        assert r.status_code == 403 and err(r) == "forbidden_permission"
        r = rc.delete(f"/admin/sessions/{rsid}",
                      headers={"X-CSRF-Token": rtok})
        assert r.status_code == 403 and err(r) == "forbidden_permission"
        # Session survived.
        assert rc.get("/me").status_code == 200

    def test_admin_kick_only_target_session(self, app):
        ac, atok, _ = make_clients(app, ("root", "root-password"))[0]
        c1 = TestClient(app)
        c2 = TestClient(app)
        s1 = login(c1, "alice", "alice-password").json()
        s2 = login(c2, "alice", "alice-password").json()

        r = ac.delete(f"/admin/sessions/{s1['session_id']}",
                      headers={"X-CSRF-Token": atok})
        logger.info("admin kick -> %d %s", r.status_code, r.json())
        assert r.status_code == 200

        r1 = c1.get("/me", cookies={"session_id": s1["session_id"]})
        r2 = c2.get("/me", cookies={"session_id": s2["session_id"]})
        logger.info("kicked=%s reason=%s sibling=%d",
                    err(r1), reason(r1), r2.status_code)
        assert r1.status_code == 401 and reason(r1) == "kicked"
        assert r2.status_code == 200

    def test_admin_kick_unknown_is_404(self, app):
        ac, atok, _ = make_clients(app, ("root", "root-password"))[0]
        r = ac.delete("/admin/sessions/never-existed",
                      headers={"X-CSRF-Token": atok})
        logger.info("admin kick unknown -> %d %s", r.status_code, err(r))
        assert r.status_code == 404 and err(r) == "session_not_found"

    def test_admin_list_unknown_user_is_404(self, app):
        ac, _, _ = make_clients(app, ("root", "root-password"))[0]
        r = ac.get("/admin/users/ghost/sessions")
        assert r.status_code == 404

    def test_admin_kick_requires_csrf(self, app):
        ac, _, _ = make_clients(app, ("root", "root-password"))[0]
        c = TestClient(app)
        sid = login(c, "alice", "alice-password").json()["session_id"]
        r = ac.delete(f"/admin/sessions/{sid}")
        assert r.status_code == 403 and err(r) == "csrf_missing"
        assert c.get("/me").status_code == 200
