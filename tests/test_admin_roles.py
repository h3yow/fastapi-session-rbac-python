"""Runtime role-permission management: protected, CSRF-guarded,
hot-effective, with denials that distinguish "never granted" from
"revoked at runtime"."""
import logging

from tests.conftest import login

logger = logging.getLogger("tests.admin_roles")


def err(resp):
    return resp.json()["error"]["code"]


def reason(resp):
    return resp.json()["error"].get("reason")


def admin_login(client):
    r = login(client, "root", "root-password")
    assert r.status_code == 200
    return r.json()["csrf_token"]


def bob_login(client):
    r = login(client, "bob", "bob-password")
    assert r.status_code == 200
    return r.json()["csrf_token"]


def make_clients(app, *users):
    """One independent TestClient (cookie jar) per (user, password)."""
    from fastapi.testclient import TestClient

    out = []
    for username, password in users:
        c = TestClient(app)
        r = login(c, username, password)
        assert r.status_code == 200
        out.append((c, r.json()["csrf_token"], r.json()["session_id"]))
    return out


class TestAdminRoleEndpointsDefaultDeny:
    def test_anonymous_cannot_touch_role_endpoints(self, client):
        r = client.get("/admin/roles/reader")
        logger.info("anonymous GET role -> %d %s", r.status_code, err(r))
        assert r.status_code == 401
        r = client.put("/admin/roles/reader/permissions",
                       json={"permissions": ["reports:read"]})
        assert r.status_code == 401

    def test_non_admin_gets_permission_denial(self, client, alice_client):
        c, _ = alice_client
        r = c.get("/admin/roles/reader")
        logger.info("reader GET role -> %d %s reason=%s",
                    r.status_code, err(r), reason(r))
        assert r.status_code == 403
        assert err(r) == "forbidden_permission"

    def test_admin_write_requires_csrf(self, client):
        admin_login(client)
        r = client.put("/admin/roles/reader/permissions",
                       json={"permissions": ["reports:read"]})
        logger.info("PUT role without csrf -> %d %s", r.status_code, err(r))
        assert r.status_code == 403
        assert err(r) == "csrf_missing"
        # Policy unchanged: reader still cannot write.
        r2 = login(client, "alice", "alice-password")
        tok = r2.json()["csrf_token"]
        assert client.post("/reports",
                           headers={"X-CSRF-Token": tok}).status_code == 403


class TestHotRoleAdjustment:
    def test_grant_then_revoke_one_role_takes_effect_immediately(self, app):
        (ac, atok, _), (bc, btok, _) = make_clients(
            app, ("root", "root-password"), ("bob", "bob-password"))

        # Editor has write initially.
        assert bc.post("/reports",
                       headers={"X-CSRF-Token": btok}).status_code == 200

        # Revoke reports:write from editor at runtime (no restart).
        r = ac.put(
            "/admin/roles/editor/permissions",
            json={"permissions": ["reports:read"]},
            headers={"X-CSRF-Token": atok},
        )
        logger.info("revoke editor write -> %d %s", r.status_code, r.json())
        assert r.status_code == 200
        assert r.json()["policy_version"] >= 2

        r = bc.post("/reports", headers={"X-CSRF-Token": btok})
        logger.info("after runtime revoke -> %d %s reason=%s",
                    r.status_code, err(r), reason(r))
        assert r.status_code == 403
        assert err(r) == "forbidden_permission"
        assert reason(r) == "revoked_at_runtime"

        # Re-grant: immediately effective again.
        r = ac.put(
            "/admin/roles/editor/permissions",
            json={"permissions": ["reports:read", "reports:write"]},
            headers={"X-CSRF-Token": atok},
        )
        assert r.status_code == 200
        assert bc.post("/reports",
                       headers={"X-CSRF-Token": btok}).status_code == 200

    def test_reason_never_granted_vs_revoked(self, app):
        (ac, atok, _), (rc, alice_tok, _) = make_clients(
            app, ("root", "root-password"), ("alice", "alice-password"))

        r = rc.post("/reports", headers={"X-CSRF-Token": alice_tok})
        logger.info("reader write never-held -> reason=%s", reason(r))
        assert reason(r) == "never_granted"

        # Grant then revoke so reader has "ever held" it.
        ac.put("/admin/roles/reader/permissions",
               json={"permissions": ["reports:read", "reports:write"]},
               headers={"X-CSRF-Token": atok})
        ac.put("/admin/roles/reader/permissions",
               json={"permissions": ["reports:read"]},
               headers={"X-CSRF-Token": atok})
        r = rc.post("/reports", headers={"X-CSRF-Token": alice_tok})
        logger.info("reader write runtime-revoked -> reason=%s", reason(r))
        assert reason(r) == "revoked_at_runtime"

        # A permission reader never held stays "never_granted" even after
        # other permissions were granted/revoked.
        r = rc.get("/admin/users")
        logger.info("reader admin:users -> reason=%s", reason(r))
        assert reason(r) == "never_granted"

    def test_other_roles_untouched_when_updating_one_role(self, app):
        (ac, atok, _), (bc, btok, _), (rc, _, asid) = make_clients(
            app, ("root", "root-password"), ("bob", "bob-password"),
            ("alice", "alice-password"))
        r = ac.put("/admin/roles/reader/permissions",
                   json={"permissions": []},
                   headers={"X-CSRF-Token": atok})
        assert r.status_code == 200
        # Editor unaffected.
        assert bc.post("/reports",
                       headers={"X-CSRF-Token": btok}).status_code == 200
        # Reader lost read.
        r = rc.get("/reports")
        assert r.status_code == 403
        assert reason(r) == "revoked_at_runtime"

    def test_unknown_role_is_404(self, client):
        atok = admin_login(client)
        r = client.get("/admin/roles/ghost")
        assert r.status_code == 404 and err(r) == "role_not_found"
        r = client.put("/admin/roles/ghost/permissions",
                       json={"permissions": ["x"]},
                       headers={"X-CSRF-Token": atok})
        logger.info("PUT unknown role -> %d %s", r.status_code, err(r))
        assert r.status_code == 404
        assert err(r) == "role_not_found"

    def test_get_role_returns_permissions(self, client):
        atok = admin_login(client)
        r = client.get("/admin/roles/editor", headers={"X-CSRF-Token": atok})
        assert r.status_code == 200
        body = r.json()
        logger.info("GET editor -> %s", body)
        assert body["permissions"] == ["reports:read", "reports:write"]
