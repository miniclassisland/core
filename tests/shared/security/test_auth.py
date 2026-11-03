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
    AccountMember,
    MemberPermission,
    RolePermission,
    User,
)
from app.shared.services.user import ensure_system_roles
from app.shared.utils.tenant import tenant_ctx


@pytest.mark.asyncio
async def test_api_token_lifecycle():
    """Test API access token generation, validation/refresh, and revocation."""
    tenant_id = "test-account-00000000"

    assert await auth.revoke_token("", tenant_id=tenant_id) is False

    token = await auth.generate_token(scope="command", tenant_id=tenant_id, ttl=300)
    assert token is not None

    res = await auth.validate_and_refresh(token, tenant_id=tenant_id)
    assert res == ("command", tenant_id)

    assert await auth.validate_and_refresh("invalid-token", tenant_id=tenant_id) is None

    assert await auth.revoke_token(token, tenant_id=tenant_id) is True
    assert await auth.revoke_token(token, tenant_id=tenant_id) is False
    assert await auth.validate_and_refresh(token, tenant_id=tenant_id) is None

    # Multi-use resource token
    rtok = await auth.create_token("t1", "Subjects", "default", max_uses=2)
    assert await auth.resolve_token(rtok) is not None
    assert await auth.resolve_token(rtok) is not None
    assert await auth.resolve_token(rtok) is None


@pytest.mark.asyncio
async def test_session_token_and_2fa_temp_token():
    """Test session token and 2FA temporary token creation, resolution, and expiration."""
    user_id = "test-user-id"
    sid = await auth.create_session_token(user_id, ttl=3600)
    assert await auth.resolve_user_from_token(sid) == user_id
    assert await auth.resolve_user_from_token("invalid-sid") is None

    temp = await auth.create_2fa_temp_token(user_id)
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
    """Test require_role and require_permission (owner, role perms, member overrides, missing tenant)."""
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

        # Non-member permission check -> empty set
        assert await auth._get_member_permissions("no-member", "acct-rb") == set()

        # Setup a non-owner member with role permissions and member overrides
        m_id = "mem-rbac-1"
        db.add(
            AccountMember(
                id=m_id,
                user_id="user-rbac-1",
                account_id="acct-rb",
                role_in_account="editor",
                joined_at=datetime.now(timezone.utc),
            )
        )
        db.add_all(
            [
                RolePermission(role_code="editor", permission_code="config.read"),
                RolePermission(role_code="editor", permission_code="config.write"),
                MemberPermission(
                    member_id=m_id, permission_code="client.read", granted=True
                ),
                MemberPermission(
                    member_id=m_id, permission_code="config.write", granted=False
                ),
                AccountMember(
                    id="mem-owner-1",
                    user_id=test_superadmin_user,
                    account_id="acct-rb",
                    role_in_account="owner",
                    joined_at=datetime.now(timezone.utc),
                ),
            ]
        )
        await db.commit()

        perms = await auth._get_member_permissions("user-rbac-1", "acct-rb")
        assert "config.read" in perms
        assert "client.read" in perms
        assert "config.write" not in perms

        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.current_user_id = "user-rbac-1"

        # Empty tenant context -> 403
        tok_empty = tenant_ctx.set("")
        try:
            with pytest.raises(HTTPException) as exc_empty:
                await auth.require_permission("config.read")(request)
            assert exc_empty.value.status_code == 403
        finally:
            tenant_ctx.reset(tok_empty)

        tok = tenant_ctx.set("acct-rb")
        try:
            # Granted permission succeeds
            assert (
                await auth.require_permission("config.read", "client.read")(request)
                == "user-rbac-1"
            )
            # Missing permission raises 403
            with pytest.raises(HTTPException) as exc_perm:
                await auth.require_permission("config.write")(request)
            assert exc_perm.value.status_code == 403

            # Owner wildcard '*' succeeds
            request.state.current_user_id = test_superadmin_user
            assert (
                await auth.require_permission("anything")(request)
                == test_superadmin_user
            )
        finally:
            tenant_ctx.reset(tok)


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
    ip_dict.clear()

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

    # 2. AdminAuthMiddleware: OPTIONS, missing Bearer, legacy token, invalid token
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

    # Legacy command token
    cmd_tok = await auth.generate_token("command", tenant_id="acct-leg")
    req_leg = MagicMock(spec=Request)
    req_leg.method = "POST"
    req_leg.url.path = "/account/acct-leg/client/c1/command/restart"
    req_leg.headers = {"authorization": f"Bearer {cmd_tok}"}
    assert (
        await auth_mw.dispatch(req_leg, AsyncMock(return_value=Response()))
    ).status_code == 200

    # _check_legacy_token with no tenant
    assert await middlewares._check_legacy_token("bad", "/other") is False

    # Invalid Bearer token -> 401
    req_bad_tok = MagicMock(spec=Request)
    req_bad_tok.method = "GET"
    req_bad_tok.url.path = "/account/acct-leg/info"
    req_bad_tok.headers = {"authorization": "Bearer invalid-tok"}
    req_bad_tok.client = None
    assert (await auth_mw.dispatch(req_bad_tok, AsyncMock())).status_code == 401

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
