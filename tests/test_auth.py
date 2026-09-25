"""认证：登录失败、账户锁定（含并发）、会话过期与续期、登出。"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from app.auth import LOCK_DURATION, MAX_FAILURES, AuthService
from app.container import build_container
from app.errors import (
    E_ACCOUNT_LOCKED,
    E_INVALID_CREDENTIALS,
    E_NOT_AUTHENTICATED,
    E_SESSION_EXPIRED,
    E_SESSION_REVOKED,
    AppError,
)

logger = logging.getLogger("tests.auth")


class FakeClock:
    """可控时钟，用于确定性地测试过期/续期/锁定解除。"""

    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


def test_unknown_user_and_wrong_password_are_indistinguishable(client):
    """关键输入：不存在账户 vs 真实账户错误密码；判定：错误码/状态/文案必须一致。"""
    r1 = client.post(
        "/api/auth/login", json={"username": "ghost", "password": "whatever1"}
    )
    r2 = client.post(
        "/api/auth/login", json={"username": "alice", "password": "WRONG-password"}
    )
    logger.info(
        "ghost=%s %s | alice-wrong=%s %s",
        r1.status_code,
        r1.json(),
        r2.status_code,
        r2.json(),
    )
    assert r1.status_code == 401 == r2.status_code
    assert r1.json() == r2.json()
    assert r1.json()["error"]["code"] == E_INVALID_CREDENTIALS


def test_lockout_after_threshold_then_locked_distinguishable(client):
    """关键输入：连续 MAX_FAILURES 次错误密码。判定：第 N 次 invalid_credentials，
    之后（即使凭据正确）account_locked，两个原因必须可区分。"""
    for i in range(1, MAX_FAILURES):
        r = client.post(
            "/api/auth/login", json={"username": "bob", "password": "bad"}
        )
        assert r.status_code == 401
        assert r.json()["error"]["code"] == E_INVALID_CREDENTIALS
        logger.info("failure #%d -> %s", i, r.json()["error"]["code"])

    # 第 MAX_FAILURES 次：仍然返回凭据错误（本次尝试本身是失败的）
    r_threshold = client.post(
        "/api/auth/login", json={"username": "bob", "password": "bad"}
    )
    assert r_threshold.json()["error"]["code"] == E_INVALID_CREDENTIALS
    logger.info("failure #%d (threshold) -> %s", MAX_FAILURES, r_threshold.json())

    # 阈值之后：即使密码正确，也必须被锁定拒绝
    r_locked = client.post(
        "/api/auth/login", json={"username": "bob", "password": "bob-pass"}
    )
    logger.info("post-threshold correct password -> %s %s", r_locked.status_code, r_locked.json())
    assert r_locked.status_code == 423
    assert r_locked.json()["error"]["code"] == E_ACCOUNT_LOCKED


def test_lock_is_per_account_and_source(client):
    """bob 被锁不影响 alice；不同来源 IP 的计数器独立（通过 service 层验证维度）。"""
    c = build_container()
    for _ in range(MAX_FAILURES):
        with pytest.raises(AppError):
            c.auth.login("bob", "bad", "10.0.0.1")
    # bob 被锁
    with pytest.raises(AppError) as ei:
        c.auth.login("bob", "bob-pass", "10.0.0.1")
    assert ei.value.code == E_ACCOUNT_LOCKED
    # 同一 bob 换一个来源 IP：独立计数，可以正常登录
    s = c.auth.login("bob", "bob-pass", "10.0.0.2")
    assert s.username == "bob"
    logger.info("lock isolated by source: 10.0.0.1 locked, 10.0.0.2 login ok")


# ---- 会话生命周期（可控时钟） ---------------------------------------------
def _service_with_clock():
    from app.container import ROLE_PERMISSIONS, seed_users
    from app.rbac import RBACService
    from app.store import Store

    clock = FakeClock(datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC))
    store = Store()
    rbac = RBACService(store, role_permissions={k: set(v) for k, v in ROLE_PERMISSIONS.items()})
    auth = AuthService(store, rbac=rbac, clock=clock)
    seed_users(store)
    return auth, clock, store


def test_session_idle_expiry_then_sliding_renewal():
    """判定依据：过期基于 expires_at；剩余 <=30 分钟窗口时滑动续期。"""
    auth, clock, _ = _service_with_clock()
    s = auth.login("alice", "alice-pass", "ip")
    created_expires = s.expires_at

    # 前进 29 分钟：剩余 1 分钟 <= 30 分钟窗口 -> 触发续期
    clock.advance(timedelta(minutes=29))
    s2 = auth.authenticate(s.session_id)
    assert s2.expires_at > created_expires
    assert s2.last_seen_at == clock.now
    logger.info(
        "sliding: old_exp=%s new_exp=%s after 29m",
        created_expires.isoformat(),
        s2.expires_at.isoformat(),
    )

    # 前进 31 分钟（超过续期后的空闲超时）：会话过期
    clock.advance(timedelta(minutes=31))
    with pytest.raises(AppError) as ei:
        auth.authenticate(s.session_id)
    assert ei.value.code == E_SESSION_EXPIRED
    logger.info("expired as expected at %s", clock.now.isoformat())


def test_absolute_deadline_caps_sliding_renewal():
    """持续活跃也不能超过创建后 12 小时的绝对上限。"""
    auth, clock, _ = _service_with_clock()
    s = auth.login("alice", "alice-pass", "ip")

    # 每 20 分钟活动一次，一直续期到绝对上限之后
    for _ in range(40):  # 40 * 20m ~= 13.3h
        clock.advance(timedelta(minutes=20))
        try:
            s = auth.authenticate(s.session_id)
        except AppError as exc:
            assert exc.code == E_SESSION_EXPIRED
            break
    logger.info(
        "absolute deadline=%s final now=%s", s.absolute_deadline.isoformat(), clock.now.isoformat()
    )
    assert clock.now >= s.absolute_deadline
    with pytest.raises(AppError) as ei:
        auth.authenticate(s.session_id)
    assert ei.value.code == E_SESSION_EXPIRED


def test_lock_release_is_deterministic():
    """锁定解除条件确定且可复现：锁定期满前仍锁；期满瞬间自动解锁，计数清零。"""
    auth, clock, _ = _service_with_clock()
    for _ in range(MAX_FAILURES):
        with pytest.raises(AppError):
            auth.login("bob", "bad", "ip")

    # 距解除还有 1 秒：仍锁定
    clock.advance(LOCK_DURATION - timedelta(seconds=1))
    with pytest.raises(AppError) as ei:
        auth.login("bob", "bob-pass", "ip")
    assert ei.value.code == E_ACCOUNT_LOCKED

    # 再前进 1 秒：锁定期满，正确密码立即登录成功（计数已清零）
    clock.advance(timedelta(seconds=1))
    s = auth.login("bob", "bob-pass", "ip")
    assert s.username == "bob"
    logger.info("lock released exactly at now=%s", clock.now.isoformat())


def test_logout_revokes_session():
    auth, _clock, _ = _service_with_clock()
    s = auth.login("alice", "alice-pass", "ip")
    auth.logout(s.session_id)
    with pytest.raises(AppError) as ei:
        auth.authenticate(s.session_id)
    assert ei.value.code == E_SESSION_REVOKED


def test_missing_cookie_is_not_authenticated(client):
    r = client.get("/api/profile")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == E_NOT_AUTHENTICATED
    logger.info("no cookie -> %s", r.json()["error"]["code"])


# ---- 并发 -----------------------------------------------------------------
def test_concurrent_failures_cannot_bypass_threshold():
    """关键输入：20 个线程并发提交错误密码。判定依据：
    - 达到阈值前每次失败都计数（无丢失），达到阈值后计数稳定在 MAX_FAILURES；
    - 阈值后返回 account_locked 的请求数 == 20 - MAX_FAILURES；
    - 不存在任何一次并发请求在阈值之后用正确密码能登录成功。"""
    auth, _clock, store = _service_with_clock()
    key = "alice|ip"

    def one_bad_attempt(_):
        try:
            auth.login("alice", "wrong-password", "ip")
            return "ok"
        except AppError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(one_bad_attempt, range(20)))

    counter = store.get_or_create_counter(key)
    locked_results = [r for r in results if r == E_ACCOUNT_LOCKED]
    invalid_results = [r for r in results if r == E_INVALID_CREDENTIALS]
    logger.info(
        "concurrent bad attempts: invalid=%d locked=%d stored_failures=%d",
        len(invalid_results),
        len(locked_results),
        counter.failures,
    )
    # 计数稳定在阈值（锁定后不再累加），且锁定时间已设定
    assert counter.failures == MAX_FAILURES
    # 前 MAX_FAILURES 次（含置锁的那次）返回凭据错误，之后全部返回已锁定
    assert len(invalid_results) == MAX_FAILURES
    assert len(locked_results) == 20 - MAX_FAILURES
    assert counter.locked_until is not None

    # 阈值之后并发的“正确密码”尝试也必须全部被锁定拒绝
    def one_good_attempt(_):
        try:
            auth.login("alice", "alice-pass", "ip")
            return "ok"
        except AppError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=10) as pool:
        good_results = list(pool.map(one_good_attempt, range(10)))
    logger.info("concurrent correct-password attempts while locked: %s", good_results)
    assert good_results == [E_ACCOUNT_LOCKED] * 10
