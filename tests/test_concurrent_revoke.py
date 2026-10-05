"""Concurrency: targeted revocation racing with in-flight requests must be
linearizable — once a revoke returns, the session can never authenticate
again; and an already-revoked target gives the same outcome repeatedly."""
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from app.config import Settings
from app.routes import create_app, seed_user
from tests.conftest import login

logger = logging.getLogger("tests.concurrent_revoke")

THREADS = 20


def err(resp):
    return resp.json().get("error", {}).get("code", "ok")


def make_app():
    app = create_app(Settings())
    seed_user(app, "alice", "alice-password", {"reader"})
    seed_user(app, "root", "root-password", {"admin"})
    return app


class TestRevokeRequestRace:
    def test_no_successful_auth_after_revocation(self):
        app = make_app()
        client = TestClient(app)
        data = login(client, "alice", "alice-password").json()
        sid = data["session_id"]
        auth = app.state.auth_service

        start = threading.Barrier(THREADS + 1)
        results: list[tuple[str, bool]] = []
        results_lock = threading.Lock()

        def hit(i):
            start.wait()
            try:
                s = auth.authenticate(sid)
                ok = s.session_id == sid
            except Exception as exc:  # noqa: BLE001 - record any rejection
                ok = False
                logger.info("worker %2d rejected: %s", i,
                            getattr(exc, "reason", exc))
            with results_lock:
                results.append((f"w{i}", ok))

        def revoke():
            start.wait()
            outcome = auth.revoke_session(sid)
            with results_lock:
                results.append(("revoker", outcome))
            return outcome

        with ThreadPoolExecutor(max_workers=THREADS + 1) as pool:
            futs = [pool.submit(hit, i) for i in range(THREADS)]
            rev_fut = pool.submit(revoke)
            revoke_outcome = rev_fut.result()
            for f in futs:
                f.result()

        assert revoke_outcome == "revoked"
        # Deterministic post-condition: every later attempt is rejected with
        # the kicked reason — a reported-successful revoke can never leave a
        # usable session behind.
        from app.errors import AuthError

        for _ in range(5):
            try:
                auth.authenticate(sid)
            except AuthError as exc:
                assert exc.reason == "kicked"
            else:  # pragma: no cover - would violate linearizability
                raise AssertionError("session authenticated after revocation")

    def test_observable_split_is_linear(self):
        """Concurrent mixed workload: a prefix of workers may succeed, but
        once the first rejection appears, no later success may appear."""
        app = make_app()
        client = TestClient(app)
        data = login(client, "alice", "alice-password").json()
        sid = data["session_id"]
        auth = app.state.auth_service

        order: list[str] = []
        order_lock = threading.Lock()
        start = threading.Barrier(THREADS + 1)

        def hit(i):
            start.wait()
            try:
                auth.authenticate(sid)
                event = "ok"
            except Exception:  # noqa: BLE001
                event = "no"
            with order_lock:
                order.append(event)

        def revoke():
            start.wait()
            with order_lock:
                order.append("revoke")
            return auth.revoke_session(sid)

        with ThreadPoolExecutor(max_workers=THREADS + 1) as pool:
            futs = [pool.submit(hit, i) for i in range(THREADS)]
            pool.submit(revoke)
            for f in futs:
                f.result()

        # Project to worker events and check the ok/no sequence is monotonic
        # (some oks, then only nos): no "ok" after a "no".
        worker_events = [e for e in order if e in ("ok", "no")]
        seen_no = False
        monotonic = True
        for e in worker_events:
            if e == "no":
                seen_no = True
            elif seen_no:
                monotonic = False
        logger.info("worker event sequence: %s", "".join(
            "O" if e == "ok" else "X" for e in worker_events))
        assert monotonic, f"success appeared after rejection: {worker_events}"

    def test_concurrent_revoke_same_sid_exactly_one_wins(self):
        app = make_app()
        client = TestClient(app)
        sid = login(client, "alice", "alice-password").json()["session_id"]
        auth = app.state.auth_service
        start = threading.Barrier(THREADS)

        def revoke(_):
            start.wait()
            return auth.revoke_session(sid)

        with ThreadPoolExecutor(max_workers=THREADS) as pool:
            outcomes = list(pool.map(revoke, range(THREADS)))
        logger.info("concurrent revoke outcomes: %s",
                    {o: outcomes.count(o) for o in set(outcomes)})
        assert outcomes.count("revoked") == 1
        assert outcomes.count("already_revoked") == THREADS - 1

        # Session unusable afterwards.
        from app.errors import AuthError

        try:
            auth.authenticate(sid)
            assert False, "expected rejection"
        except AuthError as exc:
            assert exc.reason == "kicked"


class TestHttpRevokeRace:
    def test_http_revoke_then_always_rejected(self):
        app = make_app()
        admin = TestClient(app)
        atok = login(admin, "root", "root-password").json()["csrf_token"]
        victim = TestClient(app)
        v = login(victim, "alice", "alice-password").json()
        sid = v["session_id"]

        r = admin.delete(f"/admin/sessions/{sid}",
                         headers={"X-CSRF-Token": atok})
        assert r.status_code == 200
        logger.info("HTTP revoke -> %s", r.json())

        with ThreadPoolExecutor(max_workers=THREADS) as pool:
            responses = list(pool.map(
                lambda _: client_get(app, sid), range(THREADS)))
        codes = [err(r) for r in responses]
        reasons = [r.json()["error"].get("reason") for r in responses]
        logger.info("post-revoke HTTP codes=%s reasons=%s",
                    {c: codes.count(c) for c in set(codes)},
                    {x: reasons.count(x) for x in set(reasons)})
        assert codes == ["session_invalid"] * THREADS
        assert reasons == ["kicked"] * THREADS

    def test_http_revoke_unknown_is_repeatable(self):
        app = make_app()
        admin = TestClient(app)
        atok = login(admin, "root", "root-password").json()["csrf_token"]
        for _ in range(3):
            r = admin.delete("/admin/sessions/does-not-exist",
                             headers={"X-CSRF-Token": atok})
            assert r.status_code == 404 and err(r) == "session_not_found"


def client_get(app, sid):
    # Fresh client per call avoids shared-cookie ambiguity; explicit cookie.
    c = TestClient(app)
    return c.get("/me", cookies={"session_id": sid})
