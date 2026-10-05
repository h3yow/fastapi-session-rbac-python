"""Session administration: listing, targeted revocation (self & admin),
deterministic outcomes for unknown/already-revoked targets, and
distinguishable invalidation reasons."""
import logging

from fastapi.testclient import TestClient

from tests.conftest import login

logger = logging.getLogger("tests.sessions")


def err(resp):
    return resp.json()["error"]["code"]


def fresh_client(app, username, password):
    c = TestClient(app)
    r = login(c, username, password)
    assert r.status_code == 200
    body = r.json()
    return c, body["csrf_token"], body["session_id"]


class TestListOwnSessions:
    def test_lists_each_live_session_with_timing(self, app):
        c1, _, sid1 = fresh_client(app, "alice", "alice-password")
        c2, _, sid2 = fresh_client(app, "alice", "alice-password")
        r = c1.get("/sessions")
        body = r.json()["sessions"]
        logger.info("alice sessions -> %s",
                    [(s["session_id"][-6:], s["is_current"]) for s in body])
        assert r.status_code == 200
        ids = {s["session_id"] for s in body}
        assert ids == {sid1, sid2}  # each session individually identifiable
        for s in body:
            assert s["age_seconds"] >= 0
            assert s["expires_in_seconds"] > 0
            assert s["is_current"] == (s["session_id"] == sid1)

    def test_revoked_session_disappears_from_listing(self, app):
        c1, tok1, sid1 = fresh_client(app, "alice", "alice-password")
        c2, _, sid2 = fresh_client(app, "alice", "alice-password")
        assert c1.delete(f"/sessions/{sid2}", headers={"X-CSRF-Token": tok1}).status_code == 200
        r = c1.get("/sessions")
        ids = {s["session_id"] for s in r.json()["sessions"]}
        logger.info("after kicking %s -> listed=%s", sid2[-6:], [i[-6:] for i in ids])
        assert ids == {sid1}


class TestTargetedRevocation:
    def test_revoke_one_session_only_that_one_dies(self, app):
        c1, tok1, sid1 = fresh_client(app, "alice", "alice-password")
        c2, _, sid2 = fresh_client(app, "alice", "alice-password")
        c3, _, sid3 = fresh_client(app, "alice", "alice-password")
        r = c1.delete(f"/sessions/{sid2}", headers={"X-CSRF-Token": tok1})
        logger.info("revoke %s -> %d %s", sid2[-6:], r.status_code, r.json())
        assert r.status_code == 200

        r_victim = c2.get("/me")
        logger.info("victim session -> %d %s", r_victim.status_code, err(r_victim))
        assert r_victim.status_code == 401
        assert err(r_victim) == "session_revoked"
        # Siblings unaffected.
        assert c1.get("/me").status_code == 200
        assert c3.get("/me").status_code == 200

    def test_revoke_requires_csrf(self, app):
        c1, _, sid1 = fresh_client(app, "alice", "alice-password")
        r = c1.delete(f"/sessions/{sid1}")
        logger.info("revoke without csrf -> %d %s", r.status_code, err(r))
        assert r.status_code == 403
        assert err(r) == "csrf_missing"

    def test_revoke_unknown_session_is_reproducible_404(self, app):
        c1, tok1, _ = fresh_client(app, "alice", "alice-password")
        for i in range(2):  # same input -> same result, every time
            r = c1.delete("/sessions/does-not-exist",
                          headers={"X-CSRF-Token": tok1})
            logger.info("revoke unknown (attempt %d) -> %d %s",
                        i + 1, r.status_code, err(r))
            assert r.status_code == 404
            assert err(r) == "session_not_found"

    def test_revoke_already_revoked_is_reproducible_409(self, app):
        c1, tok1, sid1 = fresh_client(app, "alice", "alice-password")
        c2, _, sid2 = fresh_client(app, "alice", "alice-password")
        r = c1.delete(f"/sessions/{sid2}", headers={"X-CSRF-Token": tok1})
        assert r.status_code == 200
        for i in range(2):
            r = c1.delete(f"/sessions/{sid2}", headers={"X-CSRF-Token": tok1})
            logger.info("re-revoke (attempt %d) -> %d %s", i + 1, r.status_code, err(r))
            assert r.status_code == 409
            assert err(r) == "session_already_revoked"

    def test_cannot_address_other_users_session(self, app):
        alice, alice_tok, _ = fresh_client(app, "alice", "alice-password")
        _, _, bob_sid = fresh_client(app, "bob", "bob-password")
        r = alice.delete(f"/sessions/{bob_sid}",
                         headers={"X-CSRF-Token": alice_tok})
        logger.info("alice revokes bob's session -> %d %s", r.status_code, err(r))
        assert r.status_code == 404  # indistinguishable from unknown
        assert err(r) == "session_not_found"


class TestAdminSessionManagement:
    def test_admin_lists_and_kicks_other_users_session(self, app):
        bob1, _, bob_sid1 = fresh_client(app, "bob", "bob-password")
        bob2, _, bob_sid2 = fresh_client(app, "bob", "bob-password")
        admin, admin_tok, _ = fresh_client(app, "root", "root-password")

        r = admin.get("/admin/users/bob/sessions")
        ids = {s["session_id"] for s in r.json()["sessions"]}
        logger.info("admin sees bob's sessions -> %s", [i[-6:] for i in ids])
        assert r.status_code == 200
        assert ids == {bob_sid1, bob_sid2}

        r = admin.delete(f"/admin/users/bob/sessions/{bob_sid1}",
                         headers={"X-CSRF-Token": admin_tok})
        logger.info("admin kicks %s -> %d", bob_sid1[-6:], r.status_code)
        assert r.status_code == 200
        r = bob1.get("/me")
        assert r.status_code == 401 and err(r) == "session_revoked"
        assert bob2.get("/me").status_code == 200  # sibling unaffected

    def test_admin_revoke_wrong_user_is_404(self, app):
        _, _, alice_sid = fresh_client(app, "alice", "alice-password")
        admin, admin_tok, _ = fresh_client(app, "root", "root-password")
        r = admin.delete(f"/admin/users/bob/sessions/{alice_sid}",
                         headers={"X-CSRF-Token": admin_tok})
        logger.info("admin revokes alice's session under bob -> %d %s",
                    r.status_code, err(r))
        assert r.status_code == 404
        assert err(r) == "session_not_found"

    def test_non_admin_denied(self, app):
        alice, alice_tok, alice_sid = fresh_client(app, "alice", "alice-password")
        r = alice.get("/admin/users/alice/sessions")
        logger.info("reader lists sessions admin-style -> %d %s", r.status_code, err(r))
        assert r.status_code == 403
        assert err(r) == "forbidden_permission"
        r = alice.delete(f"/admin/users/alice/sessions/{alice_sid}",
                         headers={"X-CSRF-Token": alice_tok})
        assert r.status_code == 403
        assert err(r) == "forbidden_permission"


class TestInvalidationReasons:
    def test_all_reasons_are_distinguishable(self, app, settings, fake_clock):
        # 1. unknown session id
        c = TestClient(app)
        r_unknown = c.get("/me", cookies={"session_id": "never-issued"})

        # 2. deliberately revoked
        c_rev, tok_rev, sid_rev = fresh_client(app, "alice", "alice-password")
        c_rev.delete(f"/sessions/{sid_rev}", headers={"X-CSRF-Token": tok_rev})
        r_revoked = c_rev.get("/me", cookies={"session_id": sid_rev})

        # 3. expired
        c_exp, _, sid_exp = fresh_client(app, "bob", "bob-password")
        fake_clock(settings.session_ttl_seconds + 1)
        r_expired = c_exp.get("/me", cookies={"session_id": sid_exp})

        # 4. password changed (bulk invalidation)
        c_pw, tok_pw, sid_pw = fresh_client(app, "root", "root-password")
        c_pw.post("/change-password",
                  json={"old_password": "root-password", "new_password": "root-new"},
                  headers={"X-CSRF-Token": tok_pw})
        r_pw = c_pw.get("/me", cookies={"session_id": sid_pw})

        codes = {
            "unknown": err(r_unknown),
            "revoked": err(r_revoked),
            "expired": err(r_expired),
            "password_changed": err(r_pw),
        }
        logger.info("invalidation reasons -> %s", codes)
        assert codes == {
            "unknown": "session_unknown",
            "revoked": "session_revoked",
            "expired": "session_expired",
            "password_changed": "session_password_changed",
        }
        assert len(set(codes.values())) == 4  # no two reasons collapse together

    def test_session_reasons_differ_from_permission_denials(self, app):
        alice, alice_tok, _ = fresh_client(app, "alice", "alice-password")
        r_perm = alice.post("/reports", headers={"X-CSRF-Token": alice_tok})
        r_sess = TestClient(app).get("/me", cookies={"session_id": "nope"})
        logger.info("permission denial=%s session denial=%s",
                    err(r_perm), err(r_sess))
        assert r_perm.status_code == 403 and err(r_perm) == "forbidden_permission"
        assert r_sess.status_code == 401 and err(r_sess) == "session_unknown"
