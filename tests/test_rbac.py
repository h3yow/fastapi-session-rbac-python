"""RBAC: default-deny, distinguishable denial reasons, hot policy updates."""
import logging

from tests.conftest import login

logger = logging.getLogger("tests.rbac")


def err(resp):
    return resp.json()["error"]["code"]


class TestDefaultDeny:
    def test_anonymous_root_still_works(self, client):
        r = client.get("/")
        logger.info("anonymous / -> %d %s", r.status_code, r.json())
        assert r.status_code == 200
        assert r.json() == {"Hello": "World"}

    def test_protected_endpoints_deny_anonymous(self, client):
        for method, path in [("get", "/me"), ("get", "/reports"),
                             ("post", "/reports"), ("get", "/admin/users")]:
            r = getattr(client, method)(path)
            logger.info("anonymous %s %s -> %d %s", method.upper(), path,
                        r.status_code, err(r))
            assert r.status_code == 401

    def test_unknown_endpoint_404(self, client):
        assert client.get("/nope").status_code == 404


class TestPermissionDecisions:
    def test_reader_can_read_but_not_write(self, alice_client):
        c, tok = alice_client
        r_read = c.get("/reports")
        r_write = c.post("/reports", headers={"X-CSRF-Token": tok})
        logger.info("reader read=%d write=%d(%s)",
                    r_read.status_code, r_write.status_code, err(r_write))
        assert r_read.status_code == 200
        assert r_write.status_code == 403
        assert err(r_write) == "forbidden_permission"

    def test_editor_can_write(self, client):
        login(client, "bob", "bob-password")
        # Fetch csrf token from login response is simpler via a fresh login.
        r = client.post("/login", json={"username": "bob", "password": "bob-password"})
        tok = r.json()["csrf_token"]
        assert client.post("/reports", headers={"X-CSRF-Token": tok}).status_code == 200

    def test_no_role_user_gets_role_denial(self, client):
        r = login(client, "norole", "norole-password")
        assert r.status_code == 200
        r = client.get("/reports")
        logger.info("role-less user -> %s", err(r))
        assert r.status_code == 403
        assert err(r) == "forbidden_role"

    def test_admin_only_endpoint(self, client, alice_client):
        c, _ = alice_client
        r = c.get("/admin/users")
        assert r.status_code == 403 and err(r) == "forbidden_permission"
        login(client, "root", "root-password")
        r = client.get("/admin/users")
        logger.info("admin /admin/users -> %d", r.status_code)
        assert r.status_code == 200


class TestHotPolicyUpdate:
    def test_permission_grant_takes_effect_without_restart(self, client, app, alice_client):
        c, tok = alice_client
        r = c.post("/reports", headers={"X-CSRF-Token": tok})
        assert r.status_code == 403  # reader lacks reports:write

        engine = app.state.policy_engine
        v = engine.update({
            "reader": {"reports:read", "reports:write"},
            "editor": {"reports:read", "reports:write"},
            "admin": {"reports:read", "reports:write", "admin:users"},
        })
        logger.info("policy updated to v%d; retrying same session", v)
        r = c.post("/reports", headers={"X-CSRF-Token": tok})
        logger.info("after grant -> %d", r.status_code)
        assert r.status_code == 200

    def test_permission_revocation_takes_effect_without_restart(self, client, app):
        r = login(client, "bob", "bob-password")
        tok = r.json()["csrf_token"]
        assert client.post("/reports", headers={"X-CSRF-Token": tok}).status_code == 200

        v = app.state.policy_engine.update({
            "reader": {"reports:read"},
            "editor": {"reports:read"},  # write revoked
            "admin": {"reports:read", "reports:write", "admin:users"},
        })
        r = client.post("/reports", headers={"X-CSRF-Token": tok})
        logger.info("policy v%d revoked editor write -> %d %s", v, r.status_code, err(r))
        assert r.status_code == 403
        # Distinguishable from "never granted": this was revoked at runtime.
        assert err(r) == "permission_revoked"
        # Read still allowed for the same session.
        assert client.get("/reports").status_code == 200
