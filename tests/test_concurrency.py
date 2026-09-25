"""Concurrency: lockout thresholds, session isolation and CSRF rejection
must hold when many requests race."""
import logging
from concurrent.futures import ThreadPoolExecutor

from app.config import Settings
from app.routes import create_app, seed_user
from fastapi.testclient import TestClient

logger = logging.getLogger("tests.concurrency")

THREADS = 16


def make_client(settings: Settings | None = None):
    app = create_app(settings or Settings())
    seed_user(app, "carol", "carol-password", {"editor"})
    return TestClient(app)


def run_parallel(fn, items):
    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        return list(pool.map(fn, items))


def codes(responses):
    out = []
    for r in responses:
        body = r.json()
        out.append(body.get("error", {}).get("code", "ok"))
    return out


class TestConcurrentLockout:
    def test_threshold_not_bypassed_by_concurrent_failures(self):
        settings = Settings(login_max_failures=5, login_lockout_seconds=300.0)
        client = make_client(settings)
        n = 30
        logger.info("firing %d concurrent bad logins, threshold=%d",
                    n, settings.login_max_failures)
        responses = run_parallel(
            lambda _: client.post(
                "/login", json={"username": "carol", "password": "wrong"}),
            range(n),
        )
        result_codes = codes(responses)
        logger.info("result codes: %s", {c: result_codes.count(c) for c in set(result_codes)})
        # No wrong-password attempt ever succeeds.
        assert all(r.status_code == 401 for r in responses)
        assert set(result_codes) <= {"invalid_credentials", "account_locked"}
        # The lock engaged at least once: the burst cannot all slip through
        # as plain invalid_credentials.
        assert "account_locked" in result_codes
        # After the burst the account is locked even for the right password.
        r = client.post("/login", json={"username": "carol", "password": "carol-password"})
        logger.info("correct password after burst -> %s", r.json()["error"]["code"])
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "account_locked"

    def test_concurrent_correct_logins_all_succeed_with_distinct_sessions(self):
        client = make_client()
        n = 12
        responses = run_parallel(
            lambda _: client.post(
                "/login", json={"username": "carol", "password": "carol-password"}),
            range(n),
        )
        sids = [r.json()["session_id"] for r in responses]
        logger.info("statuses=%s distinct_sessions=%d/%d",
                    {r.status_code for r in responses}, len(set(sids)), n)
        assert all(r.status_code == 200 for r in responses)
        assert len(set(sids)) == n

    def test_mixed_success_and_failure_stays_consistent(self):
        settings = Settings(login_max_failures=5)
        client = make_client(settings)
        # 3 failures < threshold 5, so no lock can engage regardless of order.
        creds = [("carol", "wrong")] * 3 + [("carol", "carol-password")] * 6
        responses = run_parallel(
            lambda cred: client.post(
                "/login", json={"username": cred[0], "password": cred[1]}),
            creds,
        )
        ok = sum(1 for r in responses if r.status_code == 200)
        locked = sum(1 for r in responses
                     if r.json().get("error", {}).get("code") == "account_locked")
        logger.info("mixed burst: ok=%d locked=%d", ok, locked)
        assert ok == 6
        assert locked == 0


class TestConcurrentSessionInvalidation:
    def test_password_change_invalidates_all_concurrent_sessions(self):
        client = make_client()
        n = 10
        logins = run_parallel(
            lambda _: client.post(
                "/login", json={"username": "carol", "password": "carol-password"}),
            range(n),
        )
        sids = [r.json()["session_id"] for r in logins]
        tok = logins[0].json()["csrf_token"]
        r = client.post(
            "/change-password",
            json={"old_password": "carol-password", "new_password": "carol-new"},
            headers={"X-CSRF-Token": tok},
            cookies={"session_id": sids[0]},
        )
        assert r.status_code == 200
        assert r.json()["sessions_revoked"] == n

        responses = run_parallel(
            lambda sid: client.get("/me", cookies={"session_id": sid}), sids)
        result_codes = codes(responses)
        logger.info("post-change /me codes: %s",
                    {c: result_codes.count(c) for c in set(result_codes)})
        assert all(c == "session_invalid" for c in result_codes)

    def test_revocation_is_independent_under_concurrency(self):
        client = make_client()
        n = 8
        logins = run_parallel(
            lambda _: client.post(
                "/login", json={"username": "carol", "password": "carol-password"}),
            range(n),
        )
        sids = [r.json()["session_id"] for r in logins]
        victim = sids[3]
        tok = logins[3].json()["csrf_token"]
        r = client.post("/logout", headers={"X-CSRF-Token": tok},
                        cookies={"session_id": victim})
        assert r.status_code == 200

        responses = run_parallel(
            lambda sid: client.get("/me", cookies={"session_id": sid}), sids)
        for sid, resp in zip(sids, responses):
            code = resp.json().get("error", {}).get("code", "ok")
            logger.info("session ...%s -> %s", sid[-6:], code)
            if sid == victim:
                assert resp.status_code == 401 and code == "session_invalid"
            else:
                assert resp.status_code == 200 and code == "ok"


class TestConcurrentCsrfMisuse:
    def test_wrong_tokens_always_rejected_session_survives(self):
        client = make_client()
        login = client.post(
            "/login", json={"username": "carol", "password": "carol-password"})
        sid = login.json()["session_id"]
        good_tok = login.json()["csrf_token"]

        responses = run_parallel(
            lambda i: client.post(
                "/reports",
                headers={"X-CSRF-Token": f"forged-{i}"},
                cookies={"session_id": sid}),
            range(20),
        )
        result_codes = codes(responses)
        logger.info("forged-token codes: %s",
                    {c: result_codes.count(c) for c in set(result_codes)})
        assert all(c == "csrf_invalid" for c in result_codes)
        # The legitimate token still works afterwards.
        r = client.post("/reports", headers={"X-CSRF-Token": good_tok},
                        cookies={"session_id": sid})
        logger.info("legit token after misuse burst -> %d", r.status_code)
        assert r.status_code == 200

    def test_concurrent_authorized_writes_with_valid_token(self):
        client = make_client()
        login = client.post(
            "/login", json={"username": "carol", "password": "carol-password"})
        sid, tok = login.json()["session_id"], login.json()["csrf_token"]
        responses = run_parallel(
            lambda _: client.post("/reports", headers={"X-CSRF-Token": tok},
                                  cookies={"session_id": sid}),
            range(20),
        )
        logger.info("authorized write statuses: %s",
                    {r.status_code for r in responses})
        assert all(r.status_code == 200 for r in responses)
