"""Runtime policy administration: protected endpoints, immediate effect,
and revoked-vs-never-granted denial distinction."""
import logging

from fastapi.testclient import TestClient

from tests.conftest import login

logger = logging.getLogger("tests.admin_policy")


def err(resp):
    return resp.json()["error"]["code"]


def fresh_client(app, username, password):
    """A dedicated client (own cookie jar) logged in as the given user."""
    c = TestClient(app)
    r = login(c, username, password)
    assert r.status_code == 200
    return c, r.json()["csrf_token"]


class TestAdminEndpointProtection:
    def test_anonymous_denied_on_policy_endpoints(self, client):
        for method, path in [("get", "/admin/policy"),
                             ("post", "/admin/policy/grant"),
                             ("post", "/admin/policy/revoke")]:
            r = getattr(client, method)(path)
            logger.info("anonymous %s %s -> %d %s", method.upper(), path,
                        r.status_code, err(r))
            assert r.status_code == 401
            assert err(r) == "session_missing"

    def test_non_admin_denied_by_default(self, alice_client):
        c, tok = alice_client
        r = c.get("/admin/policy")
        logger.info("reader GET /admin/policy -> %d %s", r.status_code, err(r))
        assert r.status_code == 403
        assert err(r) == "forbidden_permission"  # reader never had admin:policy
        r = c.post("/admin/policy/grant",
                   json={"role": "reader", "permission": "reports:write"},
                   headers={"X-CSRF-Token": tok})
        logger.info("reader POST grant -> %d %s", r.status_code, err(r))
        assert r.status_code == 403
        assert err(r) == "forbidden_permission"

    def test_policy_mutation_requires_csrf(self, app):
        c, _ = fresh_client(app, "root", "root-password")
        r = c.post("/admin/policy/revoke",
                   json={"role": "editor", "permission": "reports:write"})
        logger.info("revoke without csrf -> %d %s", r.status_code, err(r))
        assert r.status_code == 403
        assert err(r) == "csrf_missing"

    def test_anonymous_root_unaffected(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert r.json() == {"Hello": "World"}


class TestRuntimePolicyChanges:
    def test_grant_takes_effect_immediately(self, app):
        alice, alice_tok = fresh_client(app, "alice", "alice-password")
        r = alice.post("/reports", headers={"X-CSRF-Token": alice_tok})
        assert r.status_code == 403
        logger.info("reader write before grant -> %s", err(r))

        admin, admin_tok = fresh_client(app, "root", "root-password")
        r = admin.post("/admin/policy/grant",
                       json={"role": "reader", "permission": "reports:write"},
                       headers={"X-CSRF-Token": admin_tok})
        logger.info("admin grant -> %d %s", r.status_code, r.json())
        assert r.status_code == 200

        r = alice.post("/reports", headers={"X-CSRF-Token": alice_tok})
        logger.info("reader write after grant -> %d", r.status_code)
        assert r.status_code == 200

    def test_revoke_takes_effect_immediately_and_is_distinguishable(self, app):
        bob, bob_tok = fresh_client(app, "bob", "bob-password")
        assert bob.post("/reports", headers={"X-CSRF-Token": bob_tok}).status_code == 200

        admin, admin_tok = fresh_client(app, "root", "root-password")
        r = admin.post("/admin/policy/revoke",
                       json={"role": "editor", "permission": "reports:write"},
                       headers={"X-CSRF-Token": admin_tok})
        logger.info("admin revoke -> %d %s", r.status_code, r.json())
        assert r.status_code == 200

        r = bob.post("/reports", headers={"X-CSRF-Token": bob_tok})
        logger.info("editor write after runtime revoke -> %d %s", r.status_code, err(r))
        assert r.status_code == 403
        # Runtime-revoked is a different outcome than "role never had it".
        assert err(r) == "permission_revoked"
        # Other permissions of the same role still work.
        assert bob.get("/reports").status_code == 200

    def test_never_granted_vs_runtime_revoked_are_distinct(self, app):
        alice, alice_tok = fresh_client(app, "alice", "alice-password")
        # reader never had reports:write at startup.
        r = alice.post("/reports", headers={"X-CSRF-Token": alice_tok})
        logger.info("never-granted denial -> %s", err(r))
        assert err(r) == "forbidden_permission"

        # editor had reports:write at startup; revoke it at runtime.
        admin, admin_tok = fresh_client(app, "root", "root-password")
        admin.post("/admin/policy/revoke",
                   json={"role": "editor", "permission": "reports:write"},
                   headers={"X-CSRF-Token": admin_tok})
        bob, bob_tok = fresh_client(app, "bob", "bob-password")
        r = bob.post("/reports", headers={"X-CSRF-Token": bob_tok})
        logger.info("runtime-revoked denial -> %s", err(r))
        assert err(r) == "permission_revoked"

    def test_policy_snapshot_visible_to_admin(self, app):
        admin, _ = fresh_client(app, "root", "root-password")
        r = admin.get("/admin/policy")
        body = r.json()
        logger.info("policy snapshot -> version=%d roles=%s",
                    body["version"], sorted(body["roles"]))
        assert r.status_code == 200
        assert body["version"] >= 1
        assert "reports:read" in body["roles"]["reader"]
