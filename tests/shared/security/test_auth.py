"""test_auth.py"""

from datetime import datetime, timezone
import time
from unittest.mock import MagicMock, AsyncMock
import pytest
from fastapi import HTTPException, Request, Response

from app.shared.security import auth, middlewares
from app.shared.security.crypto import (
    get_ip_failures_dict,
    get_global_requests,
    set_cc_state,
)
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import (
    Account,
    User,
)
from app.shared.services.user import ensure_system_roles


@pytest.mark.asyncio
async def test_api_token_lifecycle():
    """Test multi-use resource access token lifecycle."""
    rtok = await auth.create_token("t1", "Subjects", "default", max_uses=2)
    assert len(rtok) == 192
    assert await auth.resolve_token(rtok) is not None
    assert await auth.resolve_token(rtok) is not None
    assert await auth.resolve_token(rtok) is None

    # Test exhausted token with max_uses=0 (new_remaining < 0)
    rtok_zero = await auth.create_token("t1", "Subjects", "default", max_uses=0)
    assert await auth.resolve_token(rtok_zero) is None


@pytest.mark.asyncio
async def test_session_token_and_2fa_temp_token():
    """Test session token, revocation, SSO exchange code, OOBE passcode lockout, and 2FA temporary token."""
    user_id = "test-user-id"
    sid = await auth.create_session_token(user_id, ttl=3600)
    assert len(sid) == 128
    assert await auth.resolve_user_from_token(sid) == user_id
    assert await auth.resolve_user_from_token("invalid-sid") is None

    # Test revoke_session_token (empty and valid)
    await auth.revoke_session_token("")
    await auth.revoke_session_token(sid)
    assert await auth.resolve_user_from_token(sid) is None

    # Test revoke_all_user_sessions (with and without except_token)
    sid1 = await auth.create_session_token(user_id, ttl=3600)
    sid2 = await auth.create_session_token(user_id, ttl=3600)
    await auth.revoke_all_user_sessions(user_id, except_token=sid1)
    assert await auth.resolve_user_from_token(sid1) == user_id
    assert await auth.resolve_user_from_token(sid2) is None
    await auth.revoke_all_user_sessions(user_id)
    assert await auth.resolve_user_from_token(sid1) is None

    # Test create_exchange_code and redeem_exchange_code (including IP mismatch and hincrby replay rejection)
    assert await auth.redeem_exchange_code("") is None
    assert await auth.redeem_exchange_code("non-existent-code") is None
    sid_ex = await auth.create_session_token(user_id, ttl=3600)
    ex_code = await auth.create_exchange_code(sid_ex, client_ip="203.0.113.10")
    assert await auth.redeem_exchange_code(ex_code, client_ip="203.0.113.10") == sid_ex
    assert await auth.redeem_exchange_code(ex_code, client_ip="203.0.113.10") is None
    ex_code_replay = await auth.create_exchange_code(sid_ex)
    from app.shared.utils.redis import get_redis
    from app.shared.utils.config import REDIS_DB_AUTH

    await get_redis(REDIS_DB_AUTH).hincrby(f"sso_exchange:{ex_code_replay}", "used", 1)
    assert await auth.redeem_exchange_code(ex_code_replay) is None
    ex_code_mismatch = await auth.create_exchange_code(sid_ex, client_ip="203.0.113.10")
    assert (
        await auth.redeem_exchange_code(ex_code_mismatch, client_ip="198.51.100.20")
        is None
    )

    # Test OOBE passcode lockout after 5 failures (global and per-IP), cooldown expiration, and clear_oobe_codes
    auth.clear_oobe_codes()
    assert auth.verify_oobe_passcode("ANY") is False
    auth.generate_oobe_codes()
    saved_code = auth.OOBE_PASSCODE
    saved_token = auth.get_oobe_token()
    assert auth.verify_oobe_token(saved_token) is True
    assert auth.verify_oobe_token("invalid-token") is False
    for _ in range(5):
        assert auth.verify_oobe_passcode("WRONG") is False
    assert auth.is_oobe_locked_out() is True
    assert auth.verify_oobe_passcode(saved_code) is False
    # Simulate cooldown expiration
    auth.OOBE_LOCKOUT_UNTIL = time.monotonic() - 1.0
    assert auth.is_oobe_locked_out() is False
    assert auth.verify_oobe_passcode("WRONG") is False
    assert auth.verify_oobe_passcode(saved_code) is True

    # Per-IP OOBE lockout & eviction (expired & unlocked eviction vs locked-out retention)
    now_mono = time.monotonic()
    auth._OOBE_IP_FAILS["10.9.9.1"] = (5, now_mono - 10.0)
    for i in range(1026):
        auth._OOBE_IP_FAILS[f"10.0.0.{i}"] = (1, 0.0)
    for _ in range(5):
        assert auth.verify_oobe_passcode("WRONG", client_ip="203.0.113.55") is False
    assert auth.is_oobe_locked_out("203.0.113.55") is True
    assert auth.is_oobe_locked_out("203.0.113.99") is False
    auth._OOBE_IP_FAILS["203.0.113.55"] = (5, time.monotonic() - 1.0)
    assert auth.is_oobe_locked_out("203.0.113.55") is False
    assert auth.verify_oobe_passcode(saved_code, client_ip="203.0.113.55") is True

    temp = await auth.create_2fa_temp_token(user_id)
    assert len(temp) == 128
    assert await auth.pop_2fa_temp_token(temp) == user_id
    with pytest.raises(HTTPException) as exc:
        await auth.pop_2fa_temp_token(temp)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_dependency(test_superadmin_user):
    """Test get_current_user dependency."""
    request = MagicMock(spec=Request)
    request.state = MagicMock()

    request.state.current_user_id = None
    async with AsyncSessionLocal() as db:
        with pytest.raises(HTTPException) as exc:
            await auth.get_current_user(request, db)
        assert exc.value.status_code == 401

    request.state.current_user_id = "non-existent-user-id"
    async with AsyncSessionLocal() as db:
        with pytest.raises(HTTPException) as exc:
            await auth.get_current_user(request, db)
        assert exc.value.status_code == 401

    request.state.current_user_id = test_superadmin_user
    async with AsyncSessionLocal() as db:
        user = await auth.get_current_user(request, db)
        assert user.id == test_superadmin_user


@pytest.mark.asyncio
async def test_rbac_and_permissions_dependencies(test_superadmin_user):
    """Test require_role priority enforcement."""
    async with AsyncSessionLocal() as db:
        await ensure_system_roles(db)
        superadmin = await db.get(User, test_superadmin_user)
        assert superadmin is not None

        role_check = auth.require_role(50)
        assert await role_check(superadmin, db) == superadmin

        role_check_high = auth.require_role(101)
        with pytest.raises(HTTPException) as exc:
            await role_check_high(superadmin, db)
        assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_middlewares_all_branches(test_superadmin_user):
    """Test CCProtectMiddleware, AdminAuthMiddleware, AccountContextMiddleware, and TenantMiddleware."""
    # 1. check_ip_blocked & record_ip_failure (list and tuple branches)
    middlewares.IP_FAILURE_LIMIT = 20
    middlewares.GLOBAL_CC_LIMIT = 500
    ip_dict = get_ip_failures_dict()
    now = time.time()
    ip_dict["1.1.1.1"] = [now - 1000] + [now] * 20
    assert middlewares.check_ip_blocked("1.1.1.1") is True

    ip_dict["2.2.2.2"] = (25, now)
    assert middlewares.check_ip_blocked("2.2.2.2") is True
    middlewares.record_ip_failure("2.2.2.2")

    ip_dict["3.3.3.3"] = (25, now - 1000)
    assert middlewares.check_ip_blocked("3.3.3.3") is False
    ip_dict["4.4.4.4"] = [now - 1000]
    assert middlewares.check_ip_blocked("4.4.4.4") is False
    old_max_ips = middlewares.MAX_TRACKED_IPS
    middlewares.MAX_TRACKED_IPS = 1
    ip_dict["expired-ip"] = [now - 1000]
    middlewares.record_ip_failure("5.5.5.5")
    middlewares.record_ip_failure("6.6.6.6")
    middlewares.MAX_TRACKED_IPS = old_max_ips
    ip_dict.clear()

    # Test Redis-backed check_ip_blocked_async and record_ip_failure_async
    from unittest.mock import patch

    with patch("app.shared.utils.config.is_initialized", return_value=True):
        middlewares.IP_FAILURE_LIMIT = 1
        await middlewares.record_ip_failure_async("198.51.100.99")
        ip_dict.clear()
        assert await middlewares.check_ip_blocked_async("198.51.100.99") is True
        middlewares.IP_FAILURE_LIMIT = 20

    # monitor_global_frequency over limit
    g_reqs = get_global_requests()
    g_reqs.extend([now - 10.0] + [now] * 505)
    middlewares.monitor_global_frequency()
    assert middlewares.get_cc_state() is True
    g_reqs.clear()
    set_cc_state(False)

    # CCProtectMiddleware dispatch: blocked IP (429) & CC active on /login (503)
    cc_mw = middlewares.CCProtectMiddleware(app=MagicMock())
    req_cc = MagicMock(spec=Request)
    req_cc.client = MagicMock()
    req_cc.client.host = "127.0.0.1"
    req_cc.headers = {"x-real-ip": "9.9.9.9"}
    req_cc.url.path = "/user/login"
    ip_dict["9.9.9.9"] = [now] * 25
    resp_429 = await cc_mw.dispatch(req_cc, AsyncMock())
    assert resp_429.status_code == 429
    ip_dict.clear()

    set_cc_state(True)
    middlewares.GLOBAL_CC_LIMIT = 0
    resp_503 = await cc_mw.dispatch(
        req_cc, AsyncMock(return_value=Response(status_code=200))
    )
    assert resp_503.status_code == 503
    middlewares.GLOBAL_CC_LIMIT = 100000
    set_cc_state(False)

    # 2. AdminAuthMiddleware: OPTIONS, missing Bearer, invalid token
    auth_mw = middlewares.AdminAuthMiddleware(app=MagicMock())
    req_opt = MagicMock(spec=Request)
    req_opt.method = "OPTIONS"
    assert (
        await auth_mw.dispatch(req_opt, AsyncMock(return_value=Response()))
    ).status_code == 200

    req_no_auth = MagicMock(spec=Request)
    req_no_auth.method = "GET"
    req_no_auth.url.path = "/account/list"
    req_no_auth.headers = {}
    assert (await auth_mw.dispatch(req_no_auth, AsyncMock())).status_code == 401

    # Invalid Bearer token -> 401
    req_bad_tok = MagicMock(spec=Request)
    req_bad_tok.method = "GET"
    req_bad_tok.url.path = "/account/acct-leg/info"
    req_bad_tok.headers = {"authorization": "Bearer invalid-tok"}
    req_bad_tok.client = None
    assert (await auth_mw.dispatch(req_bad_tok, AsyncMock())).status_code == 401

    # AdminAuthMiddleware(require_superadmin=True) with non-superadmin -> 403
    sa_mw = middlewares.AdminAuthMiddleware(app=MagicMock(), require_superadmin=True)
    ghost_tok = await auth.create_session_token("non-existent-sa-uid")
    req_sa_deny = MagicMock(spec=Request)
    req_sa_deny.method = "GET"
    req_sa_deny.url.path = "/stats"
    req_sa_deny.headers = {"authorization": f"Bearer {ghost_tok}"}
    assert (await sa_mw.dispatch(req_sa_deny, AsyncMock())).status_code == 403

    # Active normal user accessing require_superadmin=True -> 403 (line 189)
    async with AsyncSessionLocal() as db:
        db.add(
            User(
                id="normal-user-for-sa-mw",
                username="norm_sa_mw",
                email="normsamw@school.com",
                hashed_password="h",
                role_code="normal",
                is_active=True,
                created_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()
    norm_sa_tok = await auth.create_session_token("normal-user-for-sa-mw")
    req_norm_sa = MagicMock(spec=Request)
    req_norm_sa.method = "GET"
    req_norm_sa.url.path = "/stats"
    req_norm_sa.headers = {"authorization": f"Bearer {norm_sa_tok}"}
    assert (await sa_mw.dispatch(req_norm_sa, AsyncMock())).status_code == 403

    # 3. AccountContextMiddleware: OPTIONS, inactive account, unauthenticated, non-member
    acct_mw = middlewares.AccountContextMiddleware(
        app=MagicMock(), require_membership=True
    )
    assert (
        await acct_mw.dispatch(req_opt, AsyncMock(return_value=Response()))
    ).status_code == 200

    req_inactive = MagicMock(spec=Request)
    req_inactive.method = "GET"
    req_inactive.url.path = "/account/missing-acct-id/info"
    assert (await acct_mw.dispatch(req_inactive, AsyncMock())).status_code == 403

    async with AsyncSessionLocal() as db:
        db.add(
            Account(
                id="acct-mw-test",
                name="MW Test",
                slug="mw-test",
                api_key="k",
                is_active=True,
                created_at=datetime.now(timezone.utc),
            )
        )
        db.add(
            User(
                id="user-outsider-mw",
                username="outsider_mw",
                email="outmw@school.com",
                hashed_password="h",
                role_code="normal",
                is_active=True,
                created_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

    req_unauth_acct = MagicMock(spec=Request)
    req_unauth_acct.method = "GET"
    req_unauth_acct.url.path = "/account/acct-mw-test/info"
    req_unauth_acct.state = MagicMock()
    req_unauth_acct.state.current_user_id = None
    assert (await acct_mw.dispatch(req_unauth_acct, AsyncMock())).status_code == 401

    req_outsider_acct = MagicMock(spec=Request)
    req_outsider_acct.method = "GET"
    req_outsider_acct.url.path = "/account/acct-mw-test/info"
    req_outsider_acct.state = MagicMock()
    req_outsider_acct.state.current_user_id = "user-outsider-mw"
    assert (await acct_mw.dispatch(req_outsider_acct, AsyncMock())).status_code == 403

    req_sa_acct = MagicMock(spec=Request)
    req_sa_acct.method = "GET"
    req_sa_acct.url.path = "/account/acct-mw-test/info"
    req_sa_acct.state = MagicMock()
    req_sa_acct.state.current_user_id = test_superadmin_user
    assert (
        await acct_mw.dispatch(req_sa_acct, AsyncMock(return_value=Response()))
    ).status_code == 200

    # 4. TenantMiddleware: OPTIONS, no slug (403), unknown slug (403)
    ten_mw = middlewares.TenantMiddleware(app=MagicMock())
    assert (
        await ten_mw.dispatch(req_opt, AsyncMock(return_value=Response()))
    ).status_code == 200

    req_no_slug = MagicMock(spec=Request)
    req_no_slug.method = "GET"
    req_no_slug.url.path = "/api/v1/management-config"
    req_no_slug.headers = {"host": "127.0.0.1"}
    req_no_slug.query_params = {}
    assert (await ten_mw.dispatch(req_no_slug, AsyncMock())).status_code == 403

    req_bad_slug = MagicMock(spec=Request)
    req_bad_slug.method = "GET"
    req_bad_slug.url.path = "/api/v1/management-config"
    req_bad_slug.headers = {"x-tenant-slug": "non-existent-tenant"}
    req_bad_slug.query_params = {}
    assert (await ten_mw.dispatch(req_bad_slug, AsyncMock())).status_code == 403
