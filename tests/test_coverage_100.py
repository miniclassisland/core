import asyncio
from datetime import datetime, timezone
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
import pytest
from sqlalchemy import select, delete
from starlette.requests import Request

from app.admin.app import admin_app
from app.admin.settings import mask_sensitive_setting
from app.admin.ticket import _get_ticket_with_user, _message_count
from app.admin.user import _map_users_to_out
from app.client import get as client_get
from app.client.app import client_app
from app.grpc import session as grpc_session
from app.grpc.server import (
    ClientCommandDeliverServicer,
    ClientRegisterServicer,
    ConfigUploadServicer,
    HandshakeServicer,
    _sync_extend_response_to_client_record,
)
from app.grpc.session import GPGKeyManager, SessionManager
from app.management import account as mgmt_account
from app.management.app import management_app
from app.Protobuf.Client import (
    ClientRegisterCsReq_pb2,
    ConfigUploadScReq_pb2,
    HandshakeScReq_pb2,
)
from app.Protobuf.Enum import Retcode_pb2
from app.shared.db import schema_init
from app.shared.db.models import (
    Account,
    AccountMember,
    ClientRecord,
    CommunityBinding,
    ConfigUploadRecord,
    PreRegisteredClient,
    ResourceHistory,
    SubFile,
    SystemConfig,
    Ticket,
    User,
)
from app.shared.db.session import AsyncSessionLocal
from app.shared.schemas.schemas import (
    ApproveUserRequest,
    TicketAdminUpdate,
    TicketCreate,
)
from app.shared.security import auth, crypto, middlewares, turnstile
from app.shared.services import pairing as pairing_svc
from app.shared.services import ticket as ticket_svc
from app.shared.services import user as user_svc
from app.shared.utils import community as comm
from app.shared.utils import oobe, tenant
from app.shared.utils import redis as redis_util


@pytest.mark.asyncio
async def test_coverage_admin_and_cli_and_schemas_and_services(
    test_superadmin_user, monkeypatch, tmp_path
):
    """Cover remaining branches in admin/*, cli/user.py, schemas.py, crypto.py, middlewares.py, turnstile.py, pairing.py, ticket.py, user.py, oobe.py, redis.py, tenant.py."""
    # 1. admin/settings.py: mask_sensitive_setting
    assert mask_sensitive_setting("any_key", "") == ""
    assert mask_sensitive_setting("db_password", "secret123") == "***"
    assert (
        mask_sensitive_setting("redis_url", "redis://user:pass@localhost:6379/0")
        == "redis://user:***@localhost:6379/0"
    )
    assert mask_sensitive_setting("site_name", "MINI ClassIsland") == "MINI ClassIsland"

    # 2. schemas.py: ApproveUserRequest.resolved_quotas & TicketCreate / TicketAdminUpdate validators
    req_q = ApproveUserRequest(
        quotas={"max_clients": 10},
        max_grpc_connections=8,
        max_bandwidth_mb=2048,
        feature_ota=1,
        feature_audit=1,
        feature_risk=1,
    )
    resolved = req_q.resolved_quotas()
    assert resolved["max_clients"] == 10
    assert resolved["max_grpc_connections"] == 8
    assert resolved["feature.risk"] == 1

    with pytest.raises(ValueError):
        TicketCreate(
            subject="Sub", content="Body", category="other", priority="invalid_p"
        )
    upd_none = TicketAdminUpdate(status=None, priority=None)
    assert upd_none.status is None and upd_none.priority is None
    with pytest.raises(ValueError):
        TicketAdminUpdate(priority="invalid_p")

    # 3. crypto.py: normalize_resource_payload non-dict values inside TimeLayouts / ClassPlans
    tl_norm = crypto.normalize_resource_payload(
        "TimeLayout", {"TimeLayouts": {"bad": "not_a_dict"}}
    )
    assert tl_norm == {"TimeLayouts": {}}
    cp_norm = crypto.normalize_resource_payload(
        "ClassPlan", {"ClassPlans": {"bad": "not_a_dict"}}
    )
    assert cp_norm["ClassPlans"] == {}

    # 4. schema_init.py: _SEED_LOCKS cleanup when > 2048
    for i in range(2050):
        schema_init._SEED_LOCKS[f"dummy_lock_{i}"] = asyncio.Lock()
    async with AsyncSessionLocal() as db:
        await schema_init.seed_account_defaults("seed_overflow_test", db)
    assert len(schema_init._SEED_LOCKS) < 2050

    # 5. redis.py: _build_url with unix://
    with patch.object(redis_util, "REDIS_URL", "unix:///run/redis/redis.sock?db=0"):
        assert redis_util._build_url(2) == "unix:///run/redis/redis.sock?db=2"

    # 6. tenant.py: _LOCAL_ACCOUNT_CACHE eviction in get_cached_account & set_cached_account
    monkeypatch.setattr(tenant, "_MAX_LOCAL_ACCOUNT_CACHE", 1)
    dummy_acct = Account(
        id="t_cache_1",
        name="Cache 1",
        slug="cache_slug_1",
        api_key="k1",
        is_active=True,
        registration_mode="pairing",
    )
    await tenant.set_cached_account("cache_slug_1", dummy_acct)
    await tenant.set_cached_account("cache_slug_2", dummy_acct)
    tenant._LOCAL_ACCOUNT_CACHE.clear()
    tenant._LOCAL_ACCOUNT_CACHE["other"] = (999999999.0, dummy_acct)
    got_acct = await tenant.get_cached_account("cache_slug_2")
    assert got_acct is not None and got_acct.id == "t_cache_1"

    # 7. oobe.py: write_config_file OSError fallbacks
    monkeypatch.setattr(oobe, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(oobe, "CONFIG_FILE", tmp_path / "config.json")
    with (
        patch("os.open", side_effect=OSError("no os.open")),
        patch("os.chmod", side_effect=OSError("no os.chmod")),
    ):
        oobe.write_config_file(
            {"db_url": "postgresql://localhost/db", "redis_url": "", "domain": "ex.com"}
        )
    assert (tmp_path / "config.json").exists()

    # 8. turnstile.py: get_turnstile_secret_key (env, file, DB) & get_turnstile_allowed_hostnames (empty domain)
    monkeypatch.setenv("TURNSTILE_SECRET_KEY", "env_sec_123")
    assert await turnstile.get_turnstile_secret_key() == "env_sec_123"
    monkeypatch.delenv("TURNSTILE_SECRET_KEY", raising=False)
    monkeypatch.setattr(
        turnstile,
        "_load_file_config",
        lambda: {"turnstile_secret_key": "file_sec_456"},
    )
    assert await turnstile.get_turnstile_secret_key() == "file_sec_456"
    monkeypatch.setattr(turnstile, "_load_file_config", lambda: {})
    async with AsyncSessionLocal() as db:
        db.add(
            SystemConfig(
                key="turnstile_secret_key",
                value="db_sec_789",
                updated_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()
        assert await turnstile.get_turnstile_secret_key(db) == "db_sec_789"
        await db.execute(
            delete(SystemConfig).where(SystemConfig.key == "turnstile_secret_key")
        )
        await db.commit()
    monkeypatch.delenv("TURNSTILE_HOSTNAMES", raising=False)
    monkeypatch.setattr(turnstile, "BASE_DOMAIN", "")
    assert turnstile.get_turnstile_allowed_hostnames() == set()

    # 9. ticket.py service: enforce_ticket_write_limit Redis exception
    with patch(
        "app.shared.services.ticket.get_redis",
        side_effect=RuntimeError("redis down"),
    ):
        await ticket_svc.enforce_ticket_write_limit("u1", "create", 5)

    # 10. pairing.py service: create_pairing_request when pending_cnt >= _MAX_PENDING_PAIRING_CODES_PER_TENANT
    monkeypatch.setattr(pairing_svc, "_MAX_PENDING_PAIRING_CODES_PER_TENANT", 1)
    await pairing_svc.create_pairing_request(
        "t_pair", "uid_pair_1", "cid1", "AA:BB", "127.0.0.1"
    )
    code2 = await pairing_svc.create_pairing_request(
        "t_pair", "uid_pair_2", "cid2", "AA:CC", "127.0.0.1"
    )
    assert code2

    # 11. user.py service: _generate_unique_account_slug exhaustion, update_user id PermissionError & None user, _create_default_account with quotas
    async with AsyncSessionLocal() as db:
        with pytest.raises(PermissionError):
            await user_svc.update_user("nonexistent", db, id="new_id")
        assert await user_svc.update_user("nonexistent", db, display_name="X") is None
        u_quota = await user_svc.register_user(
            "u_quota@school.com",
            "ValidPass123!",
            "U Quota",
            db,
            username="u_quota",
            role_code="pending",
            is_active=False,
        )
        approved_u = await user_svc.approve_user(
            u_quota.id,
            db,
            can_create_account=True,
            quotas={"max_clients": 12, "feature.risk": 1},
        )
        assert approved_u is not None and approved_u.can_create_account is True

        # _generate_unique_account_slug fallback when all 16 candidates collide
        fake_res = MagicMock()
        fake_res.scalar_one_or_none.return_value = "existing_id"
        fake_db = AsyncMock()
        fake_db.execute.return_value = fake_res
        slug_fb = await user_svc._generate_unique_account_slug(fake_db)
        assert slug_fb.startswith("account_") and len(slug_fb) == 20

    # 12. middlewares.py: record_ip_failure_async with is_initialized()=True, _is_pending_user_allowed_request on /account/{id}/info GET, AdminAuthMiddleware inactive user, AccountContextMiddleware pending user
    await redis_util.get_redis(1).delete("cc:ip_fail:198.51.100.77")
    with patch("app.shared.utils.config.is_initialized", return_value=True):
        await middlewares.record_ip_failure_async("198.51.100.77")
    assert (
        middlewares._is_pending_user_allowed_request("/account/acct_1/info", "GET")
        is True
    )

    sa_sid = await auth.create_session_token(test_superadmin_user)
    sa_headers = {"Authorization": f"Bearer {sa_sid}"}
    admin_transport = ASGITransport(app=admin_app)
    mgmt_transport = ASGITransport(app=management_app)

    async with (
        AsyncClient(transport=admin_transport, base_url="http://test") as ac_admin,
        AsyncClient(transport=mgmt_transport, base_url="http://test") as ac_mgmt,
    ):
        # admin/ticket.py: _get_ticket_with_user unsafe id, _message_count, list_all_tickets invalid status/priority/category and unread_only=True
        async with AsyncSessionLocal() as db:
            assert await _map_users_to_out([], db) == []
            with pytest.raises(Exception):
                await _get_ticket_with_user(db, "bad\x00id")
            assert await _message_count(db, "t_nonexistent") == 0

        assert (
            await ac_admin.get("/ticket/list?status=invalid", headers=sa_headers)
        ).status_code == 400
        assert (
            await ac_admin.get("/ticket/list?priority=invalid", headers=sa_headers)
        ).status_code == 400
        assert (
            await ac_admin.get("/ticket/list?category=invalid", headers=sa_headers)
        ).status_code == 400
        assert (
            await ac_admin.get("/ticket/list?category=other", headers=sa_headers)
        ).status_code == 200
        assert (
            await ac_admin.get("/ticket/list?unread_only=true", headers=sa_headers)
        ).status_code == 200

        # admin/account.py: empty client list (380), empty pending list (418), update account new_id != account_id (224), PermissionError (248-249)
        assert (
            await ac_admin.get(
                "/client/list?account_id=no_such_acct", headers=sa_headers
            )
        ).json() == []
        assert (await ac_admin.get("/user/pending", headers=sa_headers)).json() == []

        r_create_acct = await ac_mgmt.post(
            "/account/apply",
            json={"name": "Cov Org"},
            headers=sa_headers,
        )
        acct_id = r_create_acct.json()["id"]

        r_immut = await ac_admin.post(
            f"/account/{acct_id}",
            json={"new_id": "different_id"},
            headers=sa_headers,
        )
        assert r_immut.status_code == 403

        with patch(
            "app.admin.account.update_account_info",
            side_effect=PermissionError("denied"),
        ):
            r_perm = await ac_admin.post(
                f"/account/{acct_id}",
                json={"name": "X"},
                headers=sa_headers,
            )
            assert r_perm.status_code == 403

        # admin/user.py: update_user_info email dup, username invalid/dup, qq_uin bind/error/unbind, role_code="banned", bind_or_rebind_user_qq 404/400, unbind_user_qq 404/200
        async with AsyncSessionLocal() as db:
            u_target = await user_svc.register_user(
                "target_u@school.com",
                "ValidPass123!",
                "Target U",
                db,
                username="target_u",
                role_code="normal",
                is_active=True,
            )
            target_uid = u_target.id

        # Duplicate email
        assert (
            await ac_admin.post(
                f"/user/{target_uid}",
                json={"email": "superadmin@school.com"},
                headers=sa_headers,
            )
        ).status_code == 400
        # Invalid username format
        assert (
            await ac_admin.post(
                f"/user/{target_uid}",
                json={"username": "bad!name"},
                headers=sa_headers,
            )
        ).status_code == 400
        # Duplicate username
        assert (
            await ac_admin.post(
                f"/user/{target_uid}",
                json={"username": "superadmin_test"},
                headers=sa_headers,
            )
        ).status_code == 400
        # qq_uin invalid format in update_user_info -> 400
        assert (
            await ac_admin.post(
                f"/user/{target_uid}",
                json={"qq_uin": "0123"},
                headers=sa_headers,
            )
        ).status_code == 400
        # qq_uin valid bind in update_user_info -> 200
        assert (
            await ac_admin.post(
                f"/user/{target_uid}",
                json={"qq_uin": "123456789"},
                headers=sa_headers,
            )
        ).status_code == 200
        # qq_uin empty string in update_user_info -> unbinds
        assert (
            await ac_admin.post(
                f"/user/{target_uid}",
                json={"qq_uin": ""},
                headers=sa_headers,
            )
        ).status_code == 200
        # bind_or_rebind_user_qq 404 & 400
        assert (
            await ac_admin.post(
                "/user/no_such_user/qq/bind",
                json={"qq_uin": "123456789"},
                headers=sa_headers,
            )
        ).status_code == 404
        assert (
            await ac_admin.post(
                f"/user/{target_uid}/qq/bind",
                json={"qq_uin": "bad_qq"},
                headers=sa_headers,
            )
        ).status_code == 400
        # unbind_user_qq 404 & 200
        assert (
            await ac_admin.post("/user/no_such_user/qq/unbind", headers=sa_headers)
        ).status_code == 404
        assert (
            await ac_admin.post(f"/user/{target_uid}/qq/unbind", headers=sa_headers)
        ).status_code == 200
        # Ban user via update_user_info -> line 283
        assert (
            await ac_admin.post(
                f"/user/{target_uid}",
                json={"role_code": "banned"},
                headers=sa_headers,
            )
        ).status_code == 200

        # Inactive non-pending user in AdminAuthMiddleware -> 403 (line 299)
        async with AsyncSessionLocal() as db:
            u_inact = await user_svc.register_user(
                "inact_u@school.com",
                "ValidPass123!",
                "Inact U",
                db,
                username="inact_u",
                role_code="normal",
                is_active=False,
            )
            inact_sid = await auth.create_session_token(u_inact.id)
        assert (
            await ac_mgmt.get(
                "/user/info", headers={"Authorization": f"Bearer {inact_sid}"}
            )
        ).status_code == 403

        # Pending user member accessing GET /account/{acct_id}/info -> AccountContextMiddleware line 409
        async with AsyncSessionLocal() as db:
            u_pend = await user_svc.register_user(
                "pend_ctx@school.com",
                "ValidPass123!",
                "Pend Ctx",
                db,
                username="pend_ctx",
                role_code="pending",
                is_active=False,
            )
            db.add(
                AccountMember(
                    id=str(uuid4()),
                    user_id=u_pend.id,
                    account_id=acct_id,
                    role_in_account="admin",
                    joined_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()
            pend_sid = await auth.create_session_token(u_pend.id)
            assert (
                await mgmt_account._get_effective_account_role(acct_id, u_pend.id, db)
                == "viewer"
            )
        r_pend_info = await ac_mgmt.get(
            f"/account/{acct_id}/info",
            headers={"Authorization": f"Bearer {pend_sid}"},
        )
        assert r_pend_info.status_code == 200

        # management/user.py: auth_user 401 (214-215), enable_2fa reset forbidden (414), confirm_2fa invalid JSON & missing pending_codes fallback (469-472)
        assert (
            await ac_mgmt.post(
                "/user/auth",
                json={"email": "nobody@school.com", "password": "WrongPassword123!"},
            )
        ).status_code == 401

        r_en = await ac_mgmt.post("/user/2fa/totp/enable", headers=sa_headers)
        assert r_en.status_code == 200
        secret = r_en.json()["secret"]
        # Corrupt pending_codes in redis so json.loads raises Exception (lines 469-470)
        rd_auth = redis_util.get_redis(1)
        await rd_auth.set(
            f"totp_pending_codes:{test_superadmin_user}", "{bad_json", ex=600
        )
        import pyotp

        code_now = pyotp.TOTP(secret).now()
        with patch(
            "app.management.user.verify_totp_once", AsyncMock(return_value=True)
        ):
            r_conf1 = await ac_mgmt.post(
                "/user/2fa/totp/confirm",
                json={"code": code_now},
                headers=sa_headers,
            )
            assert r_conf1.status_code == 200

            # Now call confirm_2fa again when totp_pending_codes is missing and remaining_recovery_count == 0 (lines 471-472)
            await crypto.delete_recovery_codes(test_superadmin_user)
            r_conf2 = await ac_mgmt.post(
                "/user/2fa/totp/confirm",
                json={"code": code_now},
                headers=sa_headers,
            )
            assert r_conf2.status_code == 200

        # Now user has totp_enabled=True and 10 recovery codes, so enable_2fa?reset=true without reset_flag raises 403 (line 414)
        r_en_forbid = await ac_mgmt.post(
            "/user/2fa/totp/enable?reset=true", headers=sa_headers
        )
        assert r_en_forbid.status_code == 403

        # Disable 2FA for superadmin so other tests aren't affected
        async with AsyncSessionLocal() as db:
            sa_u = (
                await db.execute(select(User).where(User.id == test_superadmin_user))
            ).scalar_one()
            sa_u.totp_enabled = False
            sa_u.totp_secret = None
            await db.commit()

        # management/ticket.py: 20 active tickets -> 429 (line 81), reply to resolved ticket -> reopens to open (line 243)
        async with AsyncSessionLocal() as db:
            now = datetime.now(timezone.utc)
            resolved_tid = str(uuid4())
            db.add(
                Ticket(
                    id=resolved_tid,
                    user_id=test_superadmin_user,
                    subject="Resolved T",
                    content="Body",
                    category="other",
                    priority="normal",
                    status="resolved",
                    created_at=now,
                    updated_at=now,
                )
            )
            for i in range(20):
                db.add(
                    Ticket(
                        id=str(uuid4()),
                        user_id=test_superadmin_user,
                        subject=f"Open {i}",
                        content="Body",
                        category="other",
                        priority="normal",
                        status="open",
                        created_at=now,
                        updated_at=now,
                    )
                )
            await db.commit()

        r_limit = await ac_mgmt.post(
            "/ticket",
            json={
                "subject": "21st Ticket",
                "content": "Should hit 429",
                "category": "other",
                "priority": "normal",
            },
            headers=sa_headers,
        )
        assert r_limit.status_code == 429

        r_reopen = await ac_mgmt.post(
            f"/ticket/{resolved_tid}/reply",
            json={"content": "Reopening resolved ticket"},
            headers=sa_headers,
        )
        assert r_reopen.status_code == 201

    # 13. cli/user.py: set-role banned (line 391)
    import concurrent.futures
    from typer.testing import CliRunner
    from app.cli.main import cli

    runner = CliRunner()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        res_cli = await asyncio.get_running_loop().run_in_executor(
            pool,
            lambda: runner.invoke(cli, ["user", "set-role", "inact_u", "banned"]),
        )
    assert res_cli.exit_code == 0


@pytest.mark.asyncio
async def test_coverage_client_api_get_grpc_and_session(
    test_superadmin_user, monkeypatch, tmp_path
):
    """Cover remaining lines in app/client/api.py, app/client/get.py, app/grpc/server.py, and app/grpc/session.py."""
    # 1. GPGKeyManager OSError and sign_detached branches (app/grpc/session.py)
    key_file = tmp_path / "gpg_test.key"
    with (
        patch("os.open", side_effect=OSError("no os.open")),
        patch("os.chmod", side_effect=OSError("no os.chmod")),
    ):
        km = GPGKeyManager(str(key_file))
    assert km.public_key_armor

    saved_pk = km.private_key
    km.private_key = None
    assert km.sign_detached("hello") == ""
    km.private_key = saved_pk

    # sign_detached outer exception branch
    fake_pk = MagicMock()
    fake_pk.sign.side_effect = RuntimeError("sign fail")
    fake_pk.key_algorithm = "bad"
    with patch("pgpy.PGPSignature.new", side_effect=RuntimeError("new fail")):
        km.private_key = fake_pk
        assert km.sign_detached("hello") == ""
    km.private_key = saved_pk

    # 2. SessionManager cache eviction, tenant mismatch, mark_client_extend_enabled, get_extend_enabled_clients, set_client_online (extend_enabled=True)
    sm = SessionManager(str(key_file))
    monkeypatch.setattr(grpc_session, "_MAX_LOCAL_SESSION_CACHE", 1)
    sid1 = await sm.create_session("tenant_a", "uid_1")
    sid2 = await sm.create_session("tenant_a", "uid_2")
    # Cached hit with tenant mismatch (line 256)
    assert await sm.validate_session(sid2, tenant_id="tenant_b") is None
    # Uncached lookup with cache eviction (265) and tenant mismatch (274)
    grpc_session._LOCAL_SESSION_CACHE.clear()
    grpc_session._LOCAL_SESSION_CACHE["dummy"] = (999999999.0, "u", "t")
    assert await sm.validate_session(sid1, tenant_id="tenant_b") is None

    # mark_client_extend_enabled & get_extend_enabled_clients (empty & populated) & set_client_online(extend_enabled=True)
    assert await sm.get_extend_enabled_clients("tenant_empty_ext") == {}
    await sm.mark_client_extend_enabled("tenant_a", "uid_1", version="2.0.0.3")
    ext_clients = await sm.get_extend_enabled_clients("tenant_a")
    assert "uid_1" in ext_clients and ext_clients["uid_1"]["version"] == "2.0.0.3"
    await sm.set_client_online(
        "tenant_a",
        "uid_2",
        ip="127.0.0.1",
        extend_enabled=True,
        extend_version="2.0.0.3",
    )

    # 3. app/client/get.py: invalidate_resource_cache pop, invalid resource_type token, cache eviction
    client_get._NORMALIZED_RESOURCE_CACHE[("acct_x", "Subjects", "default", 1)] = "{}"
    client_get.invalidate_resource_cache("acct_x", "Subjects", "default")
    assert (
        "acct_x",
        "Subjects",
        "default",
        1,
    ) not in client_get._NORMALIZED_RESOURCE_CACHE

    client_transport = ASGITransport(app=client_app)
    async with AsyncClient(
        transport=client_transport, base_url="http://test"
    ) as ac_client:
        # Invalid resource type in token -> 400 (line 64)
        bad_tok = await auth.create_token("default", "InvalidModel", "default")
        r_bad_tok = await ac_client.get(f"/get?token={bad_tok}")
        assert r_bad_tok.status_code == 400

        # Cache eviction in get_resource_by_token when len >= _MAX_RESOURCE_CACHE_SIZE (line 141)
        async with AsyncSessionLocal() as db:
            await schema_init.seed_account_defaults("default", db)
            await db.commit()
        monkeypatch.setattr(client_get, "_MAX_RESOURCE_CACHE_SIZE", 1)
        client_get._NORMALIZED_RESOURCE_CACHE[("other", "Subjects", "other", 1)] = "{}"
        good_tok = await auth.create_token("default", "Subjects", "default")
        r_good_tok = await ac_client.get(f"/get?token={good_tok}")
        assert r_good_tok.status_code == 200

        # 4. app/client/api.py: get_client_manifest with X-Extend-Management-Enabled: 1, unregister_client_http, report_client_hook_snapshot
        async with AsyncSessionLocal() as db:
            db.add(
                Account(
                    id="acct_ext_client",
                    name="Ext Client School",
                    slug="extschool",
                    api_key="k_ext",
                    is_active=True,
                    created_at=datetime.now(timezone.utc),
                )
            )
            db.add(
                ClientRecord(
                    uid="client_ext_1",
                    account_id="acct_ext_client",
                    client_id="Class_1",
                    display_name="Room 101",
                    mac="AA-BB-CC-DD-EE-01",
                    ip="127.0.0.1",
                    registered_at=datetime.now(timezone.utc),
                )
            )
            db.add(
                PreRegisteredClient(
                    id=str(uuid4()),
                    account_id="acct_ext_client",
                    label="Class_1",
                    class_identity="Class_1",
                    mac_address="AA-BB-CC-DD-EE-01",
                    bound_client_uid="client_ext_1",
                    created_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()

        client_app.state.session_manager = sm
        sid_ext = await sm.create_session("acct_ext_client", "client_ext_1")
        tenant_hdr = {"X-Tenant-Slug": "extschool"}

        # Manifest with x-extend-management-enabled: 1 (lines 150-166)
        r_man = await ac_client.get(
            "/api/v1/client/client_ext_1/manifest",
            headers={
                **tenant_hdr,
                "X-Extend-Management-Enabled": "1",
                "X-Extend-Management-Version": "2.0.0.3",
                "X-Client-Session": sid_ext,
            },
        )
        assert r_man.status_code == 200

        # report_client_hook_snapshot: 404 (missing device)
        r_snap_404 = await ac_client.post(
            "/api/v1/client/no_such_device/hook-snapshot",
            json={},
            headers=tenant_hdr,
        )
        assert r_snap_404.status_code == 404

        # Set client_ext_1 IP to 10.9.9.9 so default 127.0.0.1 doesn't match without session/mac
        async with AsyncSessionLocal() as db:
            rec_c = (
                await db.execute(
                    select(ClientRecord).where(ClientRecord.uid == "client_ext_1")
                )
            ).scalar_one()
            rec_c.ip = "10.9.9.9"
            await db.commit()

        # report_client_hook_snapshot: 403 unauthorized
        r_snap_403 = await ac_client.post(
            "/api/v1/client/client_ext_1/hook-snapshot",
            json={},
            headers={**tenant_hdr, "X-Forwarded-For": "192.0.2.55"},
        )
        assert r_snap_403.status_code == 403

        # report_client_hook_snapshot: authorized via session + dict fields (is_app_locked, plugin_settings, plugin_components, hardware_info)
        r_snap_ok1 = await ac_client.post(
            "/api/v1/client/client_ext_1/hook-snapshot",
            json={
                "version": "2.0.0.3",
                "is_app_locked": True,
                "plugin_settings": {"plugins": [{"id": "p1"}]},
                "plugin_components": {"components": [{"id": "c1", "name": "Comp 1"}]},
                "hardware_info": {"os": "Windows 11"},
            },
            headers={
                **tenant_hdr,
                "X-Client-Session": sid_ext,
                "X-Forwarded-For": "192.0.2.55",
            },
        )
        assert r_snap_ok1.status_code == 200
        assert r_snap_ok1.json()["is_app_locked"] is True

        # report_client_hook_snapshot: authorized via MAC header + camelCase / string fields (isAppLocked, settingsCatalog, registeredComponents, hardwareInfo) + IP match
        r_snap_ok2 = await ac_client.post(
            "/api/v1/client/client_ext_1/hook-snapshot",
            json={
                "isAppLocked": False,
                "settingsCatalog": '{"raw": 1}',
                "registeredComponents": '[{"id": "c1"}]',
                "hardwareInfo": '{"cpu": "x64"}',
            },
            headers={
                **tenant_hdr,
                "X-Client-Mac": "AA:BB:CC:DD:EE:01",
                "X-Forwarded-For": "192.0.2.55",
            },
        )
        assert r_snap_ok2.status_code == 200
        assert r_snap_ok2.json()["is_app_locked"] is False

        r_snap_ok3 = await ac_client.post(
            "/api/v1/client/client_ext_1/hook-snapshot",
            json={},
            headers={**tenant_hdr, "X-Forwarded-For": "10.9.9.9"},
        )
        assert r_snap_ok3.status_code == 200

        # unregister_client_http: 403 unauthorized, then authorized via session/MAC/IP, then already unregistered
        r_unreg_403 = await ac_client.post(
            "/api/v1/client/client_ext_1/unregister",
            headers={**tenant_hdr, "X-Forwarded-For": "192.0.2.55"},
        )
        assert r_unreg_403.status_code == 403

        # Test MAC & IP auth branches in unregister_client_http by creating two extra records
        async with AsyncSessionLocal() as db:
            db.add_all(
                [
                    ClientRecord(
                        uid="client_unreg_mac",
                        account_id="acct_ext_client",
                        mac="11-22-33-44-55-66",
                        ip="10.8.8.8",
                        registered_at=datetime.now(timezone.utc),
                    ),
                    ClientRecord(
                        uid="client_unreg_ip",
                        account_id="acct_ext_client",
                        mac="11-22-33-44-55-77",
                        ip="10.8.8.9",
                        registered_at=datetime.now(timezone.utc),
                    ),
                ]
            )
            await db.commit()

        r_unreg_mac = await ac_client.post(
            "/api/v1/client/client_unreg_mac/unregister",
            headers={
                **tenant_hdr,
                "X-Client-Mac": "11:22:33:44:55:66",
                "X-Forwarded-For": "192.0.2.55",
            },
        )
        assert (
            r_unreg_mac.status_code == 200
            and r_unreg_mac.json()["unregistered"] is True
        )

        r_unreg_ip = await ac_client.post(
            "/api/v1/client/client_unreg_ip/unregister",
            headers={**tenant_hdr, "X-Forwarded-For": "10.8.8.9"},
        )
        assert (
            r_unreg_ip.status_code == 200 and r_unreg_ip.json()["unregistered"] is True
        )

        r_unreg_sess = await ac_client.post(
            "/api/v1/client/client_ext_1/unregister",
            headers={
                **tenant_hdr,
                "X-Client-Session": sid_ext,
                "X-Forwarded-For": "192.0.2.55",
            },
        )
        assert (
            r_unreg_sess.status_code == 200
            and r_unreg_sess.json()["unregistered"] is True
        )

        # Already unregistered (line 442)
        r_unreg_again = await ac_client.post(
            "/api/v1/client/client_ext_1/unregister",
            headers=tenant_hdr,
        )
        assert (
            r_unreg_again.status_code == 200
            and r_unreg_again.json()["unregistered"] is False
        )

    # 5. app/grpc/server.py coverage:
    # - BeginHandshake empty cipher (line 284)
    # - CompleteHandshake tenant mismatch (line 330)
    # - UnRegister: empty ClientUid (572-576), MAC auth (607), IP auth (609), localhost auth (611), unauthorized (614-618), PreRegisteredClient unbind (634)
    # - ListenCommand: x-extend-management-enabled (732-734) & old_q QueueFull (775-776)
    # - _sync_extend_response_to_client_record all branches (883-936)
    # - UploadConfig existing completed record (1039-1042)
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                ClientRecord(
                    uid="grpc_hs_u1",
                    account_id="tenant_hs_1",
                    mac="AA-BB-CC-00-11-22",
                    ip="10.1.1.1",
                    registered_at=datetime.now(timezone.utc),
                ),
                ClientRecord(
                    uid="grpc_unreg_mac",
                    account_id="default",
                    mac="AA-BB-CC-00-11-33",
                    ip="10.1.1.2",
                    registered_at=datetime.now(timezone.utc),
                ),
                ClientRecord(
                    uid="grpc_unreg_ip",
                    account_id="default",
                    mac="AA-BB-CC-00-11-44",
                    ip="10.1.1.3",
                    registered_at=datetime.now(timezone.utc),
                ),
                ClientRecord(
                    uid="grpc_unreg_local",
                    account_id="default",
                    mac="AA-BB-CC-00-11-55",
                    ip="10.1.1.4",
                    registered_at=datetime.now(timezone.utc),
                ),
                ClientRecord(
                    uid="grpc_unreg_unauth",
                    account_id="default",
                    mac="AA-BB-CC-00-11-66",
                    ip="10.1.1.5",
                    registered_at=datetime.now(timezone.utc),
                ),
                PreRegisteredClient(
                    id=str(uuid4()),
                    account_id="default",
                    label="C_Mac",
                    class_identity="C_Mac",
                    mac_address="AA-BB-CC-00-11-33",
                    bound_client_uid="grpc_unreg_mac",
                    created_at=datetime.now(timezone.utc),
                ),
            ]
        )
        await db.commit()

    def _make_ctx(md_dict: dict, peer: str = "ipv4:127.0.0.1:50000"):
        ctx = MagicMock()
        ctx.invocation_metadata.return_value = list(md_dict.items())
        ctx.peer.return_value = peer
        ctx.abort = AsyncMock()
        return ctx

    hs_servicer = HandshakeServicer(sm)
    tok_t = tenant.tenant_ctx.set("tenant_hs_1")
    try:
        rsp_empty_cipher = await hs_servicer.BeginHandshake(
            HandshakeScReq_pb2.HandshakeScBeginHandShakeReq(
                ClientUid="grpc_hs_u1",
                ClientMac="AA-BB-CC-00-11-22",
                ChallengeTokenEncrypted="",
            ),
            _make_ctx({"cuid": "grpc_hs_u1"}),
        )
        assert rsp_empty_cipher.Retcode == Retcode_pb2.ServerInternalError
    finally:
        tenant.tenant_ctx.reset(tok_t)

    tok_t2 = tenant.tenant_ctx.set("tenant_hs_other")
    try:
        rsp_comp_mismatch = await hs_servicer.CompleteHandshake(
            HandshakeScReq_pb2.HandshakeScCompleteHandshakeReq(Accepted=True),
            _make_ctx({"cuid": "grpc_hs_u1"}),
        )
        assert rsp_comp_mismatch.Retcode == Retcode_pb2.InvalidRequest
    finally:
        tenant.tenant_ctx.reset(tok_t2)

    reg_servicer = ClientRegisterServicer(sm)
    # Empty ClientUid (572-576)
    ctx_empty_uid = _make_ctx({})
    await reg_servicer.UnRegister(
        ClientRegisterCsReq_pb2.ClientRegisterCsReq(ClientUid=""),
        ctx_empty_uid,
    )
    ctx_empty_uid.abort.assert_called_once()

    # Unauthorized remote IP and non-matching MAC (614-618)
    ctx_unauth = _make_ctx({}, peer="ipv4:198.51.100.99:12345")
    await reg_servicer.UnRegister(
        ClientRegisterCsReq_pb2.ClientRegisterCsReq(
            ClientUid="grpc_unreg_unauth", ClientMac="FF-FF-FF-FF-FF-FF"
        ),
        ctx_unauth,
    )
    ctx_unauth.abort.assert_called_once()

    # Authorized via MAC + PreRegisteredClient unbind (607, 634)
    ctx_mac = _make_ctx({}, peer="ipv4:198.51.100.99:12345")
    rsp_mac = await reg_servicer.UnRegister(
        ClientRegisterCsReq_pb2.ClientRegisterCsReq(
            ClientUid="grpc_unreg_mac", ClientMac="AA:BB:CC:00:11:33"
        ),
        ctx_mac,
    )
    assert rsp_mac.Retcode == Retcode_pb2.Success

    # Authorized via peer IP (609)
    ctx_ip = _make_ctx({}, peer="ipv4:10.1.1.3:12345")
    rsp_ip = await reg_servicer.UnRegister(
        ClientRegisterCsReq_pb2.ClientRegisterCsReq(ClientUid="grpc_unreg_ip"),
        ctx_ip,
    )
    assert rsp_ip.Retcode == Retcode_pb2.Success

    # Authorized via localhost peer_ip (611)
    ctx_local = _make_ctx({}, peer="ipv4:127.0.0.1:12345")
    rsp_local = await reg_servicer.UnRegister(
        ClientRegisterCsReq_pb2.ClientRegisterCsReq(ClientUid="grpc_unreg_local"),
        ctx_local,
    )
    assert rsp_local.Retcode == Retcode_pb2.Success

    # ListenCommand with x-extend-management-enabled=1 & old_q QueueFull (732-734, 775-776)
    cmd_servicer = ClientCommandDeliverServicer(sm)
    sid_listen = await sm.create_session("tenant_hs_1", "grpc_hs_u1")
    full_old_q: asyncio.Queue = asyncio.Queue(maxsize=1)
    full_old_q.put_nowait(
        None
    )  # Make old_q full and item is None so while loop drains it, wait: if while loop drains it, it won't be full at line 774!
    # To make old_q.empty() True during while loop yet raise QueueFull on put_nowait(None) at line 774:
    mock_old_q = MagicMock()
    mock_old_q.empty.return_value = True
    mock_old_q.put_nowait.side_effect = asyncio.QueueFull()
    cmd_servicer.client_queues["tenant_hs_1:grpc_hs_u1"] = mock_old_q

    async def _empty_req_iter():
        for _ in ():
            yield None

    ctx_listen = _make_ctx(
        {
            "session": sid_listen,
            "x-extend-management-enabled": "1",
            "x-extend-management-version": "2.0.0.3",
        }
    )
    gen = cmd_servicer.ListenCommand(_empty_req_iter(), ctx_listen)
    # Trigger generator up to queue.get() then cancel/close
    listen_task = asyncio.create_task(gen.__anext__())
    await asyncio.sleep(0.05)
    await cmd_servicer.disconnect_client("tenant_hs_1", "grpc_hs_u1")
    with pytest.raises((StopAsyncIteration, asyncio.CancelledError)):
        await listen_task

    # _sync_extend_response_to_client_record all branches (883-936) & UploadConfig existing completed record (1039-1042)
    async with AsyncSessionLocal() as db:
        await _sync_extend_response_to_client_record(db, "", "{}")
        await _sync_extend_response_to_client_record(db, "no_such_uid", "{}")
        await _sync_extend_response_to_client_record(
            db, "grpc_hs_u1", "", ext_enabled=True, ext_ver="2.0.0.3"
        )
        await _sync_extend_response_to_client_record(db, "grpc_hs_u1", "{bad_json")
        # JSON that parses to non-dict despite starting with '{' (via patched json.loads)
        with patch("app.grpc.server.json.loads", return_value=["not_dict"]):
            await _sync_extend_response_to_client_record(db, "grpc_hs_u1", "{}")
        await _sync_extend_response_to_client_record(
            db, "grpc_hs_u1", json.dumps({"action": "test", "data": "not_dict"})
        )
        await _sync_extend_response_to_client_record(
            db,
            "grpc_hs_u1",
            json.dumps(
                {
                    "action": "plugin.api_snapshot",
                    "data": {
                        "version": "2.0.0.3",
                        "isAppLocked": True,
                        "settingsCatalog": [{"id": "s1"}],
                        "registeredComponents": [{"id": "c1"}],
                    },
                }
            ),
        )
        await _sync_extend_response_to_client_record(
            db,
            "grpc_hs_u1",
            json.dumps({"action": "plugin.get_settings", "data": {"items": []}}),
        )
        await _sync_extend_response_to_client_record(
            db,
            "grpc_hs_u1",
            json.dumps({"action": "plugin.list_components", "data": {"items": []}}),
        )
        await _sync_extend_response_to_client_record(
            db,
            "grpc_hs_u1",
            json.dumps({"action": "hardware.get_info", "data": {"cpu": "arm64"}}),
        )
        db.add(
            ConfigUploadRecord(
                request_guid="already-completed-guid",
                account_id="tenant_hs_1",
                client_uid="grpc_hs_u1",
                config_type=1,
                status="completed",
                payload="old",
                uploaded_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

    up_servicer = ConfigUploadServicer(sm)
    rsp_up = await up_servicer.UploadConfig(
        ConfigUploadScReq_pb2.ConfigUploadScReq(
            RequestGuidId="already-completed-guid",
            Payload=json.dumps({"action": "hardware.info", "data": {"ram": 16}}),
        ),
        _make_ctx({"session": sid_listen}),
    )
    assert rsp_up.Retcode == Retcode_pb2.Success


@pytest.mark.asyncio
async def test_coverage_management_account_branches(test_superadmin_user, tmp_path):
    """Cover all remaining missed lines in app/management/account.py."""
    key_file = tmp_path / "mgmt_gpg.key"
    sm = SessionManager(str(key_file))
    cmd_servicer = ClientCommandDeliverServicer(sm)
    management_app.state.session_manager = sm
    management_app.state.command_servicer = cmd_servicer

    sa_sid = await auth.create_session_token(test_superadmin_user)
    sa_headers = {"Authorization": f"Bearer {sa_sid}"}
    mgmt_transport = ASGITransport(app=management_app)

    async with AsyncClient(transport=mgmt_transport, base_url="http://test") as ac_mgmt:
        r_acct = await ac_mgmt.post(
            "/account/apply",
            json={"name": "Mgmt Cov Org"},
            headers=sa_headers,
        )
        assert r_acct.status_code == 201
        acct_id = r_acct.json()["id"]

        # 505: update_account_basic_info with new_id != account_id -> 403
        assert (
            await ac_mgmt.post(
                f"/account/{acct_id}/info",
                json={"new_id": "other_id"},
                headers=sa_headers,
            )
        ).status_code == 403

        # 772: rename_access with control char -> 400
        assert (
            await ac_mgmt.post(
                f"/account/{acct_id}/access/{test_superadmin_user}/rename",
                json={"name": "bad\x01name"},
                headers=sa_headers,
            )
        ).status_code == 400

        # 1098-1099 & 1104: rename_invitation invalid max_uses
        r_inv = await ac_mgmt.post(
            f"/account/{acct_id}/invitation/create",
            json={"role_in_account": "member", "max_uses": 5},
            headers=sa_headers,
        )
        inv_id = r_inv.json()["id"]
        assert (
            await ac_mgmt.post(
                f"/account/{acct_id}/invitation/{inv_id}/rename",
                json={"max_uses": "not_an_int"},
                headers=sa_headers,
            )
        ).status_code == 400
        assert (
            await ac_mgmt.post(
                f"/account/{acct_id}/invitation/{inv_id}/rename",
                json={"max_uses": 999},
                headers=sa_headers,
            )
        ).status_code == 400

        # Create client records for _serialize_clients, plugin-components, lock/unlock, batch, delete, extend
        async with AsyncSessionLocal() as db:
            c1 = ClientRecord(
                uid="mc_1",
                account_id=acct_id,
                client_id="Class_A",
                display_name="Device A",
                mac="AA:BB:CC:DD:EE:FF",
                ip="127.0.0.1",
                plugin_components_json=json.dumps(
                    {
                        "components": [
                            "not_a_dict",
                            {"name": "no_id"},
                            {"id": "comp_1", "name": "Weather"},
                        ]
                    }
                ),
                registered_at=datetime.now(timezone.utc),
            )
            c2 = ClientRecord(
                uid="mc_2",
                account_id=acct_id,
                client_id="Class_B",
                display_name="Device B",
                mac="11:22:33:44:55:66",
                ip="127.0.0.1",
                plugin_components_json=json.dumps(
                    [{"id": "comp_1", "name": "Weather"}]
                ),
                registered_at=datetime.now(timezone.utc),
            )
            c3 = ClientRecord(
                uid="mc_3",
                account_id=acct_id,
                client_id="Class_C",
                display_name="Device C",
                mac="short",
                ip="127.0.0.1",
                plugin_components_json="",
                registered_at=datetime.now(timezone.utc),
            )
            db.add_all(
                [
                    c1,
                    c2,
                    c3,
                    PreRegisteredClient(
                        id=str(uuid4()),
                        account_id=acct_id,
                        label="Class_B",
                        class_identity="Class_B",
                        mac_address="11:22:33:44:55:66",
                        bound_client_uid="mc_2",
                        created_at=datetime.now(timezone.utc),
                    ),
                    PreRegisteredClient(
                        id=str(uuid4()),
                        account_id=acct_id,
                        label="Class_C",
                        class_identity="Class_C",
                        mac_address="short",
                        bound_client_uid="mc_3",
                        created_at=datetime.now(timezone.utc),
                    ),
                ]
            )
            await db.commit()

            # 2046 & 2053: _serialize_clients with account_id="" and role_in_account="viewer" (MAC masking)
            scope = {
                "type": "http",
                "app": management_app,
                "headers": [],
                "state": {"role_in_account": "viewer"},
            }
            fake_req = Request(scope)
            ser_items = await mgmt_account._serialize_clients(
                "", [c1, c3], fake_req, db
            )
            assert ser_items[0]["mac"] == "AA:BB:**:**:**:FF"
            assert ser_items[1]["mac"] == "***"

        # 2458-2506: GET /account/{acct_id}/client/plugin-components
        r_pcomp = await ac_mgmt.get(
            f"/account/{acct_id}/client/plugin-components",
            headers=sa_headers,
        )
        assert r_pcomp.status_code == 200
        assert r_pcomp.json()["totalCount"] == 1
        assert len(r_pcomp.json()["components"][0]["source_clients"]) == 2

        # Put online queue for mc_1 and mc_2 so commands deliver (covers 2343, 2673, 2980, etc.)
        q_mc1: asyncio.Queue = asyncio.Queue()
        q_mc2: asyncio.Queue = asyncio.Queue()
        cmd_servicer.client_queues[f"{acct_id}:mc_1"] = q_mc1
        cmd_servicer.client_queues[f"{acct_id}:mc_2"] = q_mc2

        # 2996-3013 & 3033-3050: lock_client_app & unlock_client_app (404 and 200)
        assert (
            await ac_mgmt.post(
                f"/account/{acct_id}/client/no_such/command/lock",
                headers=sa_headers,
            )
        ).status_code == 404
        assert (
            await ac_mgmt.post(
                f"/account/{acct_id}/client/no_such/command/unlock",
                headers=sa_headers,
            )
        ).status_code == 404

        r_lock = await ac_mgmt.post(
            f"/account/{acct_id}/client/mc_1/command/lock",
            headers=sa_headers,
        )
        assert r_lock.status_code == 200 and r_lock.json()["is_app_locked"] is True

        r_unlock = await ac_mgmt.post(
            f"/account/{acct_id}/client/mc_1/command/unlock",
            headers=sa_headers,
        )
        assert r_unlock.status_code == 200 and r_unlock.json()["is_app_locked"] is False

        # 2948: _dispatch_lock_command_to_client when servicer/sm is None
        management_app.state.command_servicer = None
        async with AsyncSessionLocal() as db:
            scope_none = {"type": "http", "app": management_app, "headers": []}
            assert (
                await mgmt_account._dispatch_lock_command_to_client(
                    Request(scope_none), acct_id, "mc_1", True, db
                )
                is False
            )
            await mgmt_account._notify_client_remote_exit(
                Request(scope_none), acct_id, "mc_1"
            )
        management_app.state.command_servicer = cmd_servicer

        # 2344-2345: _notify_client_remote_exit exception branch
        with patch.object(
            cmd_servicer, "send_command", side_effect=RuntimeError("boom")
        ):
            scope_ok = {"type": "http", "app": management_app, "headers": []}
            await mgmt_account._notify_client_remote_exit(
                Request(scope_ok), acct_id, "mc_1"
            )

        # 2650-2673 & 2713: batch_client_action lock, unlock, send_notification, delete (with PreRegisteredClient unbind)
        r_batch_lock = await ac_mgmt.post(
            f"/account/{acct_id}/client/batch",
            json={"action": "lock", "uids": ["mc_1", "nonexistent"]},
            headers=sa_headers,
        )
        assert r_batch_lock.status_code == 200 and r_batch_lock.json()["affected"] == 1

        r_batch_notif = await ac_mgmt.post(
            f"/account/{acct_id}/client/batch",
            json={
                "action": "send_notification",
                "uids": ["mc_1"],
                "notification": {"MessageMask": "Hello", "MessageContent": "World"},
            },
            headers=sa_headers,
        )
        assert (
            r_batch_notif.status_code == 200 and r_batch_notif.json()["affected"] == 1
        )

        r_batch_del = await ac_mgmt.post(
            f"/account/{acct_id}/client/batch",
            json={"action": "delete", "uids": ["mc_2"]},
            headers=sa_headers,
        )
        assert r_batch_del.status_code == 200 and r_batch_del.json()["affected"] == 1

        # 2392: delete_client with PreRegisteredClient unbind
        r_del_c3 = await ac_mgmt.delete(
            f"/account/{acct_id}/client/mc_3",
            headers=sa_headers,
        )
        assert r_del_c3.status_code == 200

        # 3214-3241 & 3323-3324: send_extend_command & broadcast_extend_command (feature.risk 403, lock.enable, lock.disable)
        async with AsyncSessionLocal() as db:
            from app.shared.services.quota import set_quota as _set_quota_svc

            await _set_quota_svc(acct_id, "feature.risk", 0, db)

        r_ext_risk_403 = await ac_mgmt.post(
            f"/account/{acct_id}/client/mc_1/command/extend",
            json={"action": "remote.screenshot", "payload": {}},
            headers=sa_headers,
        )
        assert r_ext_risk_403.status_code == 403

        r_bcast_risk_403 = await ac_mgmt.post(
            f"/account/{acct_id}/broadcast/extend",
            json={"action": "remote.exec_code", "payload": {}},
            headers=sa_headers,
        )
        assert r_bcast_risk_403.status_code == 403

        r_ext_lock = await ac_mgmt.post(
            f"/account/{acct_id}/client/mc_1/command/extend",
            json={"action": "lock.enable", "payload": {}},
            headers=sa_headers,
        )
        assert r_ext_lock.status_code == 200

        r_ext_unlock = await ac_mgmt.post(
            f"/account/{acct_id}/client/mc_1/command/extend",
            json={"action": "lock.disable", "payload": {}},
            headers=sa_headers,
        )
        assert r_ext_unlock.status_code == 200

        # 3449: list_audit_logs when rows is empty
        r_audit_empty = await ac_mgmt.get(
            f"/account/{acct_id}/audit/list",
            headers=sa_headers,
        )
        assert r_audit_empty.status_code == 200 and r_audit_empty.json() == []

        # 3564: _validate_resource_name invalid
        with pytest.raises(Exception):
            mgmt_account._validate_resource_name("../bad")

        # 3928-3939, 3961, 4021-4033, 4047-4048: list_resource_history & get_resource_history_version backfill, dedup, and corrupt JSON
        async with AsyncSessionLocal() as db:
            # Create a Subjects resource at version 5 with NO history rows so list_resource_history backfills (3928-3939)
            db.add(
                SubFile(
                    account_id=acct_id,
                    name="hist_test",
                    content='{"Subjects": {}}',
                    version=5,
                    updated_at=datetime.now(timezone.utc),
                )
            )
            # Also add duplicate version history rows to trigger seen_versions continue (3961)
            db.add_all(
                [
                    ResourceHistory(
                        account_id=acct_id,
                        resource_type="Subjects",
                        name="hist_test",
                        version=4,
                        content='{"Subjects": {}}',
                        created_at=datetime.now(timezone.utc),
                    ),
                    ResourceHistory(
                        account_id=acct_id,
                        resource_type="Subjects",
                        name="hist_test",
                        version=4,
                        content='{"Subjects": {}}',
                        created_at=datetime.now(timezone.utc),
                    ),
                ]
            )
            await db.commit()

        r_hist_list = await ac_mgmt.get(
            f"/account/{acct_id}/Subjects/history?name=hist_test",
            headers=sa_headers,
        )
        assert r_hist_list.status_code == 200
        assert [x["version"] for x in r_hist_list.json()] == [5, 4]

        # Delete version 5 from ResourceHistory so get_resource_history_version backfills it (4021-4033)
        async with AsyncSessionLocal() as db:
            from sqlalchemy import delete as sa_del

            await db.execute(
                sa_del(ResourceHistory).where(
                    ResourceHistory.account_id == acct_id,
                    ResourceHistory.name == "hist_test",
                    ResourceHistory.version == 5,
                )
            )
            # Also add a corrupted JSON history row at version 3 (4047-4048)
            db.add(
                ResourceHistory(
                    account_id=acct_id,
                    resource_type="Subjects",
                    name="hist_test",
                    version=3,
                    content="{corrupt_json",
                    created_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()

        r_hist_v5 = await ac_mgmt.get(
            f"/account/{acct_id}/Subjects/history/5?name=hist_test",
            headers=sa_headers,
        )
        assert r_hist_v5.status_code == 200

        r_hist_v3 = await ac_mgmt.get(
            f"/account/{acct_id}/Subjects/history/3?name=hist_test",
            headers=sa_headers,
        )
        assert r_hist_v3.status_code == 500


@pytest.mark.asyncio
async def test_coverage_community_all_remaining_branches(
    test_superadmin_user, monkeypatch, tmp_path
):
    """Cover all remaining missed lines in app/shared/utils/community.py."""
    # 1. mask_qq_uin whitespace, _generate_code edge spaces, _prune_expired_locked, clear/invalidate/get_active Redis exceptions
    assert comm.mask_qq_uin("   ") is None
    assert comm.mask_qq_uin("12345") == "12***45"
    assert comm.mask_qq_uin("1234") == "1***"

    # Force _generate_code edge space swap & all-spaces break (lines 135-140)
    with patch(
        "app.shared.utils.community.secrets.SystemRandom.shuffle",
        side_effect=lambda arr: arr.__setitem__(0, " "),
    ):
        c_gen = comm._generate_code()
        assert len(c_gen) == comm.CODE_LENGTH

    with (
        patch("app.shared.utils.community.CODE_CHARSET", " "),
        patch("app.shared.utils.community.string.ascii_lowercase", " "),
        patch("app.shared.utils.community.string.ascii_uppercase", " "),
        patch("app.shared.utils.community.string.digits", " "),
        patch("app.shared.utils.community.CODE_SYMBOLS", " "),
    ):
        c_spaces = comm._generate_code()
        assert len(c_spaces) == comm.CODE_LENGTH

    # _prune_expired_locked expired_codes loop (lines 157-159)
    with comm._lock:
        comm._code_users["exp_code_only"] = ("u_exp_only", 0.1)
        comm._user_codes["u_exp_only"] = ("exp_code_only", 999999999.0)
        comm._prune_expired_locked(100.0)
        assert "exp_code_only" not in comm._code_users

    # Redis exception branches in clear_all_pending_community_codes, invalidate_user_community_code, issue_user_community_code, get_active_user_community_code, get_active_user_for_code, match_and_consume_community_code
    with comm._lock:
        comm._user_codes["u_inv"] = ("old_mem_c", 999999999.0)
        comm._code_users["old_mem_c"] = ("u_inv", 999999999.0)
    await comm.invalidate_user_community_code("u_inv")

    with patch(
        "app.shared.utils.community.get_redis",
        side_effect=RuntimeError("redis down"),
    ):
        await comm.clear_all_pending_community_codes()
        await comm.invalidate_user_community_code("u_inv")
        assert await comm.get_active_user_community_code("u_inv") is None
        assert await comm.get_active_user_for_code("some_code") is None
        assert (
            await comm.match_and_consume_community_code("x" * comm.CODE_LENGTH) is None
        )

    # get_user_community_status & issue_user_community_code with SNOWLUMA_ONEBOT_TOKEN set & collision in _generate_code
    monkeypatch.setattr(comm, "SNOWLUMA_ONEBOT_TOKEN", "tok_test")
    async with AsyncSessionLocal() as db:
        db.add(
            CommunityBinding(
                user_id=test_superadmin_user,
                qq_uin="1480708359",
                group_id=str(comm.DEFAULT_QQ_GROUP_ID),
                is_manual=True,
                is_joined=True,
                bound_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()
        with patch(
            "app.shared.utils.community.sync_group_member_bindings",
            AsyncMock(return_value=0),
        ):
            st = await comm.get_user_community_status(test_superadmin_user, db)
            assert st["bound"] is True
            with pytest.raises(comm.CommunityAlreadyBoundError):
                await comm.issue_user_community_code(test_superadmin_user, db)

        # Unbind superadmin and test issue_user_community_code collision + Redis exception
        from sqlalchemy import delete as sa_del

        await db.execute(
            sa_del(CommunityBinding).where(
                CommunityBinding.user_id == test_superadmin_user
            )
        )
        await db.commit()

        with comm._lock:
            comm._user_codes[test_superadmin_user] = ("prev_mem", 999999999.0)
            comm._code_users["dup_code"] = ("other_u", 999999999.0)
        gen_seq = iter(["dup_code", "unique_code_123456789012"])
        with (
            patch(
                "app.shared.utils.community._generate_code",
                side_effect=lambda: next(gen_seq),
            ),
            patch(
                "app.shared.utils.community.get_redis",
                side_effect=RuntimeError("redis down"),
            ),
        ):
            c_issued, _ = await comm.issue_user_community_code(test_superadmin_user, db)
            assert c_issued == "unique_code_123456789012"

    # Match and consume with Redis exception when matched in memory (453-454)
    with patch(
        "app.shared.utils.community.get_redis",
        side_effect=RuntimeError("redis down"),
    ):
        matched_u = await comm.match_and_consume_community_code(
            "unique_code_123456789012"
        )
        assert matched_u == test_superadmin_user

    assert await comm.get_active_user_for_code("") is None
    assert comm._extract_candidate_answers("") == []
    assert comm.format_user_approved_notification(
        User(username="u1", display_name="U1"), max_clients=None
    ).endswith("MINI ClassIsland")

    # 2. get_snowluma_client, _call_onebot HTTP path, _extract_message_id, _send_private_msg_with_id, send_group_msg, _store_registration_msg_mapping, get_registration_user_for_msg
    client_http = comm.get_snowluma_client()
    assert client_http is not None
    await comm.stop_snowluma_poller()

    mock_http = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"status": "ok", "retcode": 0, "message_id": 777}
    mock_http.post.return_value = mock_resp
    res_ob = await comm._call_onebot(
        "send_group_msg",
        {"group_id": 123, "message": "hi"},
        base_url="http://127.0.0.1:3000",
        token="secret_tok",
        client=mock_http,
    )
    assert comm._extract_message_id(res_ob) == "777"
    assert comm._extract_message_id("not_a_dict") is None  # type: ignore[arg-type]
    assert comm._extract_message_id({"status": "ok"}) is None

    # No auth_token/client/base_url/onebot_caller -> returns early (624, 701, 1059)
    monkeypatch.setattr(comm, "SNOWLUMA_ONEBOT_TOKEN", "")
    assert await comm._send_private_msg_with_id("123456", 100, "msg") == (False, None)
    assert await comm.send_group_msg("msg") is False
    await comm._send_private_msg_and_kick("123456", 100, "msg")

    # Both send_private_msg attempts return retcode != 0 (656) & exception (657-661) & send_group_msg exception (718-724)
    assert await comm._send_private_msg_with_id(
        "123456",
        100,
        "msg",
        onebot_caller=AsyncMock(return_value={"retcode": 100}),
    ) == (False, None)
    assert await comm._send_private_msg_with_id(
        "123456",
        100,
        "msg",
        onebot_caller=AsyncMock(side_effect=RuntimeError("net err")),
    ) == (False, None)
    assert (
        await comm.send_group_msg(
            "msg",
            onebot_caller=AsyncMock(side_effect=RuntimeError("net err")),
        )
        is False
    )

    await comm._store_registration_msg_mapping("", "u1")
    with patch(
        "app.shared.utils.community.get_redis",
        side_effect=RuntimeError("redis down"),
    ):
        await comm._store_registration_msg_mapping("mid_err", "u1")
        assert await comm.get_registration_user_for_msg("") is None
        comm._reg_msg_users.clear()
        assert await comm.get_registration_user_for_msg("mid_err") is None

    # 3. notify_user_approved without max_clients (queries DB AccountQuota lines 921-934), notify_account_device_quota_changed (960, 995, 999), notify_group_site_announcement empty (1032), _send_private_msg_and_kick exception (1090-1096), handle_user_banned_in_community unbound (1120)
    async with AsyncSessionLocal() as db:
        sa_u = (
            await db.execute(select(User).where(User.id == test_superadmin_user))
        ).scalar_one()
        assert await comm.handle_user_banned_in_community(sa_u, db) is False
        assert await comm.admin_unbind_user_qq(sa_u, db) is False

        db.add(
            CommunityBinding(
                user_id=test_superadmin_user,
                qq_uin="1480708359",
                group_id=str(comm.DEFAULT_QQ_GROUP_ID),
                is_manual=True,
                is_joined=True,
                bound_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

        # notify_user_approved with max_clients=None -> queries DB
        ok_app = await comm.notify_user_approved(
            sa_u,
            db,
            max_clients=None,
            onebot_caller=AsyncMock(return_value={"retcode": 0}),
        )
        assert ok_app is True

        # notify_account_device_quota_changed with non-device quota key -> 0 (line 960)
        assert (
            await comm.notify_account_device_quota_changed(
                "any_acct", "feature.ota", db
            )
            == 0
        )

    assert await comm.notify_group_site_announcement("", "") is False
    await comm._send_private_msg_and_kick(
        "1480708359",
        100,
        "kick msg",
        onebot_caller=AsyncMock(side_effect=RuntimeError("kick err")),
    )

    # 4. admin_bind_or_rebind_user_qq: duplicate QQ (1179), OneBot exception (1216-1217), same QQ already bound & newly in group (1224-1240)
    async with AsyncSessionLocal() as db:
        u_other = await user_svc.register_user(
            "other_qq@school.com",
            "ValidPass123!",
            "Other QQ",
            db,
            username="other_qq",
            role_code="normal",
            is_active=True,
        )
        # Duplicate QQ (1480708359 is bound to superadmin) -> ValueError (line 1179)
        with pytest.raises(ValueError):
            await comm.admin_bind_or_rebind_user_qq(u_other, "1480708359", db)

        # Bind u_other when OneBot raises exception (1216-1217) -> is_joined=False
        b_other = await comm.admin_bind_or_rebind_user_qq(
            u_other,
            "222333444",
            db,
            onebot_caller=AsyncMock(side_effect=RuntimeError("onebot down")),
        )
        assert b_other.is_joined is False

        # Re-bind u_other to the SAME QQ "222333444" when OneBot reports they are now in group (lines 1224-1240)
        b_same = await comm.admin_bind_or_rebind_user_qq(
            u_other,
            "222333444",
            db,
            onebot_caller=AsyncMock(
                return_value={
                    "status": "ok",
                    "retcode": 0,
                    "data": [{"user_id": 222333444}],
                }
            ),
        )
        assert b_same.is_joined is True

        # 5. sync_group_member_bindings edge cases: non-ok response (1388), empty data (1392), empty active_uins (1400), different group_id (1408), newly_joined_updated (1413-1414, 1433-1434)
        b_other.is_joined = False
        db.add(
            CommunityBinding(
                user_id=str(uuid4()),
                qq_uin="999888777",
                group_id="999999",
                is_manual=True,
                is_joined=True,
                bound_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

        assert (
            await comm.sync_group_member_bindings(
                db, onebot_caller=AsyncMock(return_value={"status": "failed"})
            )
            == 0
        )
        assert (
            await comm.sync_group_member_bindings(
                db,
                onebot_caller=AsyncMock(
                    return_value={"status": "ok", "retcode": 0, "data": []}
                ),
            )
            == 0
        )
        assert (
            await comm.sync_group_member_bindings(
                db,
                onebot_caller=AsyncMock(
                    return_value={
                        "status": "ok",
                        "retcode": 0,
                        "data": [{"user_id": None}],
                    }
                ),
            )
            == 0
        )
        # Now return 1480708359 and 222333444 in group -> marks b_other.is_joined = True and commits (1413-1414, 1433-1434)
        assert (
            await comm.sync_group_member_bindings(
                db,
                onebot_caller=AsyncMock(
                    return_value={
                        "status": "ok",
                        "retcode": 0,
                        "data": [
                            {"user_id": 1480708359},
                            {"user_id": 222333444},
                        ],
                    }
                ),
            )
            == 0
        )

    # 6. _fetch_group_member_uins, _reject_group_request, _approve_and_notify_member edge cases
    assert await comm._fetch_group_member_uins(
        100, onebot_caller=AsyncMock(side_effect=RuntimeError("err"))
    ) == (set(), [])
    assert await comm._fetch_group_member_uins(
        100, onebot_caller=AsyncMock(return_value={"status": "fail"})
    ) == (set(), [])
    assert await comm._fetch_group_member_uins(
        100,
        onebot_caller=AsyncMock(
            return_value={"status": "ok", "retcode": 0, "data": "not_list"}
        ),
    ) == (set(), [])

    assert (
        await comm._reject_group_request(
            "f1",
            100,
            onebot_caller=AsyncMock(return_value={"status": "failed", "retcode": 100}),
        )
        is False
    )
    assert (
        await comm._reject_group_request(
            "f1",
            100,
            onebot_caller=AsyncMock(side_effect=RuntimeError("err")),
        )
        is False
    )

    # _approve_and_notify_member: approve_res failure (1579-1587), unbound_members fallback when diff_uins is empty (1607-1627), PM fallback & exception (1650-1669)
    dummy_user = User(id="du1", username="du1", display_name="DU1")
    res_app_fail = await comm._approve_and_notify_member(
        "f1",
        "123456",
        100,
        dummy_user,
        onebot_caller=AsyncMock(return_value={"status": "failed", "retcode": 1}),
    )
    assert res_app_fail[0] is False

    # Zero requester_uin where before_uins == after_uins (so diff_uins is empty, triggering lines 1607-1627) and send_private_msg raises exception (1664-1669)
    async def _zero_uin_same_members(action: str, params: dict):
        if action == "get_group_member_list":
            return {
                "status": "ok",
                "retcode": 0,
                "data": [
                    {
                        "user_id": 777888999,
                        "role": "member",
                        "join_time": 1700000000,
                        "nickname": "NewNick",
                    }
                ],
            }
        if action == "send_private_msg":
            raise RuntimeError("pm fail")
        return {"status": "ok", "retcode": 0}

    res_zero_fb = await comm._approve_and_notify_member(
        "f2",
        "0",
        100,
        dummy_user,
        onebot_caller=_zero_uin_same_members,
    )
    assert (
        res_zero_fb[0] is True
        and res_zero_fb[3] == "777888999"
        and res_zero_fb[4] == "NewNick"
    )

    # Also test PM second attempt in _approve_and_notify_member (line 1650)
    pm_calls_cnt = 0

    async def _approve_pm_fallback(action: str, params: dict):
        nonlocal pm_calls_cnt
        if action == "send_private_msg":
            pm_calls_cnt += 1
            if pm_calls_cnt == 1:
                return {"retcode": 100}
            return {"retcode": 0}
        return {"status": "ok", "retcode": 0}

    res_pm_fb = await comm._approve_and_notify_member(
        "f3",
        "777888999",
        100,
        dummy_user,
        onebot_caller=_approve_pm_fallback,
    )
    assert res_pm_fb[1] is True

    # 7. poll_snowluma_group_requests_once & process_pending_group_requests edge cases:
    # - non-ok response (1712), non-list data (1716), non-dict / checked / wrong group_id / empty flag (1721-1735)
    # - manual pre-bound user where _approve_and_notify_member returns approved=False -> rejects (1798)
    # - code matched to banned user -> rejects (1833)
    # - code matched to user who already has a binding -> rejects (1851)
    # - code matched to valid user where _approve_and_notify_member returns approved=False -> continues (1878)
    async with AsyncSessionLocal() as db:
        assert (
            await comm.process_pending_group_requests(
                db, onebot_caller=AsyncMock(return_value={"status": "fail"})
            )
            == 0
        )
        assert (
            await comm.poll_snowluma_group_requests_once(
                db,
                onebot_caller=AsyncMock(
                    return_value={"status": "ok", "retcode": 0, "data": "bad"}
                ),
            )
            == []
        )

        u_banned_join = await user_svc.register_user(
            "banned_j@school.com",
            "ValidPass123!",
            "Banned J",
            db,
            username="banned_j",
            role_code="banned",
            is_active=False,
        )
        u_already_b = await user_svc.register_user(
            "already_b@school.com",
            "ValidPass123!",
            "Already B",
            db,
            username="already_b",
            role_code="normal",
            is_active=True,
        )
        u_app_fail = await user_svc.register_user(
            "app_fail@school.com",
            "ValidPass123!",
            "App Fail",
            db,
            username="app_fail",
            role_code="normal",
            is_active=True,
        )
        db.add(
            CommunityBinding(
                user_id=u_already_b.id,
                qq_uin="666555444",
                group_id=str(comm.DEFAULT_QQ_GROUP_ID),
                is_manual=True,
                is_joined=False,
                bound_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

        now_m = asyncio.get_running_loop().time()
        with comm._lock:
            comm._user_codes[u_banned_join.id] = (
                "code_banned_123456789012",
                now_m + 600,
            )
            comm._code_users["code_banned_123456789012"] = (
                u_banned_join.id,
                now_m + 600,
            )
            comm._user_codes[u_already_b.id] = ("code_alrbnd_123456789012", now_m + 600)
            comm._code_users["code_alrbnd_123456789012"] = (u_already_b.id, now_m + 600)
            comm._user_codes[u_app_fail.id] = ("code_appfal_123456789012", now_m + 600)
            comm._code_users["code_appfal_123456789012"] = (u_app_fail.id, now_m + 600)

        async def _edge_poll_bot(action: str, params: dict):
            if action == "get_group_system_msg":
                return {
                    "status": "ok",
                    "retcode": 0,
                    "data": [
                        "not_a_dict",
                        {"checked": True},
                        {"checked": False, "group_id": 999},
                        {
                            "checked": False,
                            "group_id": comm.DEFAULT_QQ_GROUP_ID,
                            "flag": "",
                        },
                        # Manual bound user 666555444 where set_group_add_request(approve=True) fails -> hits line 1798
                        {
                            "checked": False,
                            "group_id": comm.DEFAULT_QQ_GROUP_ID,
                            "flag": "flag_manual_fail",
                            "requester_uin": 666555444,
                            "message": "any",
                        },
                        # Banned user code -> hits line 1833
                        {
                            "checked": False,
                            "group_id": comm.DEFAULT_QQ_GROUP_ID,
                            "flag": "flag_banned",
                            "requester_uin": 111222333,
                            "message": "code_banned_123456789012",
                        },
                        # Already bound user code -> hits line 1851
                        {
                            "checked": False,
                            "group_id": comm.DEFAULT_QQ_GROUP_ID,
                            "flag": "flag_alrbnd",
                            "requester_uin": 111222334,
                            "message": "code_alrbnd_123456789012",
                        },
                        # Normal user code where approve fails -> hits line 1878
                        {
                            "checked": False,
                            "group_id": comm.DEFAULT_QQ_GROUP_ID,
                            "flag": "flag_app_fail",
                            "requester_uin": 111222335,
                            "message": "code_appfal_123456789012",
                        },
                    ],
                }
            if action == "set_group_add_request" and params.get("approve") is True:
                return {"status": "failed", "retcode": 100}
            return {"status": "ok", "retcode": 0}

        await comm.poll_snowluma_group_requests_once(db, onebot_caller=_edge_poll_bot)

    # 8. _extract_reply_id_and_text, _parse_registration_action, _extract_quoted_text, handle_onebot_qr_login_event, handle_onebot_registration_reply_event
    rid1, txt1 = comm._extract_reply_id_and_text(
        {
            "reply": {"id": "r1"},
            "message": [
                "not_a_dict",
                {"type": "reply", "data": {"id": "r2"}},
                {"type": "text", "data": {"text": "同意"}},
            ],
        }
    )
    assert rid1 == "r1" and txt1 == "同意"
    rid2, txt2 = comm._extract_reply_id_and_text(
        {
            "source": {"id": "r3"},
            "raw_message": "[CQ:reply,id=r4]拒绝",
        }
    )
    assert rid2 == "r3" and txt2 == "拒绝"
    rid3, txt3 = comm._extract_reply_id_and_text(
        {"raw_message": "[CQ:reply,id=r5]approve"}
    )
    assert rid3 == "r5" and txt3 == "approve"

    assert comm._parse_registration_action("") is None
    assert comm._parse_registration_action("hello") is None
    assert comm._extract_quoted_text("not_a_dict") == ""  # type: ignore[arg-type]
    assert (
        comm._extract_quoted_text(
            {"data": {"message": [{"type": "text", "data": {"text": "quoted"}}]}}
        )
        == "quoted"
    )
    assert (
        comm._extract_quoted_text({"data": {"raw_message": "raw_quoted"}})
        == "raw_quoted"
    )

    # handle_onebot_qr_login_event all branches (2018-2096)
    assert await comm.handle_onebot_qr_login_event("not_dict") is None  # type: ignore[arg-type]
    assert await comm.handle_onebot_qr_login_event({"message": "hi"}) is None
    assert (
        await comm.handle_onebot_qr_login_event(
            {"sender": {"user_id": 1480708359}, "message": "no qr link"}
        )
        is None
    )
    # Unbound QQ sender with qr link
    assert (
        await comm.handle_onebot_qr_login_event(
            {
                "user_id": 909090909,
                "message": "miniclassisland://qr-login/some_token",
            }
        )
        is None
    )
    # Bound pending/banned user with qr link
    async with AsyncSessionLocal() as db:
        db.add(
            CommunityBinding(
                user_id=u_banned_join.id,
                qq_uin="808080808",
                group_id=str(comm.DEFAULT_QQ_GROUP_ID),
                is_manual=True,
                is_joined=True,
                bound_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()
    assert (
        await comm.handle_onebot_qr_login_event(
            {
                "user_id": 808080808,
                "message": "miniclassisland://qr-login/some_token",
            }
        )
        is None
    )

    # Valid bound user (1480708359 -> test_superadmin_user) with valid & invalid QR challenge
    qr_chal = await auth.create_qr_login_challenge("127.0.0.1")
    qr_pm_log: list[tuple[str, dict]] = []

    async def _qr_bot(action: str, params: dict):
        qr_pm_log.append((action, params))
        return {"status": "ok", "retcode": 0}

    qr_ok_res = await comm.handle_onebot_qr_login_event(
        {
            "message_id": "qr_msg_1001",
            "sender": {"user_id": 1480708359},
            "message": f"请帮我登录 {qr_chal['deeplink']}",
        },
        onebot_caller=_qr_bot,
    )
    assert qr_ok_res is not None and qr_ok_res["authorized"] is True

    # Duplicate message_id qr_msg_1001 returns None (line 2036)
    assert (
        await comm.handle_onebot_qr_login_event(
            {
                "message_id": "qr_msg_1001",
                "user_id": 1480708359,
                "message": qr_chal["deeplink"],
            },
            onebot_caller=_qr_bot,
        )
        is None
    )

    # Expired/invalid QR link via handle_onebot_registration_reply_event (covers 2085 and 2132-2142)
    qr_bad_res = await comm.handle_onebot_registration_reply_event(
        {
            "message_id": "qr_msg_1002",
            "user_id": 1480708359,
            "message": "miniclassisland://qr-login/expired_or_invalid_code",
        },
        onebot_caller=_qr_bot,
    )
    assert qr_bad_res is not None and qr_bad_res["authorized"] is False

    # handle_onebot_registration_reply_event edge branches (2118, 2121, 2154-2157, 2170, 2176-2178, 2196-2197, 2214)
    assert await comm.handle_onebot_registration_reply_event("not_dict") is None  # type: ignore[arg-type]
    assert (
        await comm.handle_onebot_registration_reply_event(
            {
                "sender": {"user_id": 1480708359},
                "reply": {"id": "unknown_rid", "message": "not a reg msg"},
                "message": "同意",
            },
            onebot_caller=AsyncMock(side_effect=RuntimeError("get_msg fail")),
        )
        is None
    )
    assert (
        await comm.handle_onebot_registration_reply_event(
            {
                "sender": {"user_id": 1480708359},
                "source": {"id": "unknown_rid2"},
                "message": "同意",
            },
            onebot_caller=AsyncMock(side_effect=RuntimeError("get_msg fail")),
        )
        is None
    )
    assert (
        await comm.handle_onebot_registration_reply_event(
            {
                "sender": {"user_id": 1480708359},
                "reply_id": "unknown_rid3",
                "message": "随便聊聊",
            }
        )
        is None
    )

    # 9. Lifecycle state & systemd detection & _snowluma_poll_loop & start/stop_snowluma_poller
    monkeypatch.setattr(comm, "CONFIG_DIR", tmp_path)
    bad_state_file = comm._get_lifecycle_state_file()
    bad_state_file.write_text("{corrupt", encoding="utf-8")
    assert comm._read_local_lifecycle_state() == {}

    with patch.object(comm.Path, "write_text", side_effect=OSError("disk full")):
        comm._write_local_lifecycle_state({"a": 1})

    # _consume_pending_restart via file timestamp (lines 2413-2414)
    comm.mark_pending_restart()
    comm._memory_pending_restart = 0.0
    assert comm._consume_pending_restart() is True

    # detect_is_systemd_restart subprocess exception (2435-2436)
    with (
        patch("shutil.which", return_value="/bin/systemctl"),
        patch("subprocess.run", side_effect=RuntimeError("subproc err")),
    ):
        assert comm.detect_is_systemd_restart() is False

    # _set_lifecycle_mode & _pop_lifecycle_mode Redis exception (2457-2458, 2482-2483)
    with patch(
        "app.shared.utils.community.get_redis",
        side_effect=RuntimeError("redis down"),
    ):
        await comm._set_lifecycle_mode("restart")
        assert await comm._pop_lifecycle_mode() == "restart"

    # _snowluma_poll_loop, start_snowluma_poller, stop_snowluma_poller (2540-2589)
    monkeypatch.setattr(comm, "SNOWLUMA_ONEBOT_TOKEN", "")
    assert comm.start_snowluma_poller() is None

    monkeypatch.setattr(comm, "SNOWLUMA_ONEBOT_TOKEN", "active_tok")
    monkeypatch.setattr(comm, "SNOWLUMA_POLL_INTERVAL", 1)
    call_iter = 0

    async def _fake_proc_req(_db):
        nonlocal call_iter
        call_iter += 1
        if call_iter == 1:
            raise RuntimeError("transient poll error")

    with (
        patch(
            "app.shared.utils.community.process_pending_group_requests",
            side_effect=_fake_proc_req,
        ),
        patch(
            "app.shared.utils.community.poll_snowluma_superadmin_replies_once",
            AsyncMock(return_value=[]),
        ),
        patch(
            "app.shared.utils.community.sync_group_member_bindings",
            AsyncMock(return_value=0),
        ),
    ):
        task1 = comm.start_snowluma_poller()
        assert task1 is not None
        # Calling start_snowluma_poller while task is running returns the same task (line 2570)
        assert comm.start_snowluma_poller() is task1
        await asyncio.sleep(0.05)
        await comm.stop_snowluma_poller()
        assert comm._snowluma_poller_task is None

    # Cover remaining 39 lines in community.py:
    # 152-154: _prune_expired_locked with expired _user_codes
    with comm._lock:
        comm._user_codes["exp_u1"] = ("EXPCODE1", 1.0)
        comm._code_users["EXPCODE1"] = ("exp_u1", 1.0)
        comm._prune_expired_locked(now=100.0)
    assert "exp_u1" not in comm._user_codes and "EXPCODE1" not in comm._code_users

    # 186, 190, 192: clear_all_pending_community_codes when Redis has keys
    rd_c = redis_util.get_redis(1)
    await rd_c.set(f"{comm._REDIS_USER_CODE_PREFIX}tmp_u", "TMPCODE", ex=60)
    await rd_c.set(f"{comm._REDIS_CODE_USER_PREFIX}TMPCODE", "tmp_u", ex=60)
    await comm.clear_all_pending_community_codes()

    # 224-229: is_user_community_bound
    async with AsyncSessionLocal() as db:
        assert await comm.is_user_community_bound("no_such_user", db) is False

    # 328, 353, 356-358, 380-382, 415, 437-439, 464-470:
    # issue_user_community_code with old_mem_code != prev_redis_code (328)
    async with AsyncSessionLocal() as db:
        u_c = await user_svc.register_user(
            "u_comm_cov@school.com",
            "ValidPass123!",
            "U Comm",
            db,
            username="u_comm_cov",
            role_code="normal",
            is_active=True,
        )
        with comm._lock:
            comm._user_codes[u_c.id] = ("OLDMEMCODE", time.monotonic() + 500)
            comm._code_users["OLDMEMCODE"] = (u_c.id, time.monotonic() + 500)
        await rd_c.set(f"{comm._REDIS_USER_CODE_PREFIX}{u_c.id}", "OLDREDISCODE", ex=60)
        c_new, _ = await comm.issue_user_community_code(u_c.id, db)

        # 353: get_active_user_community_code from in-memory cache
        assert await comm.get_active_user_community_code(u_c.id) == c_new
        # 356-358 & 380-382: get_active_user_community_code & get_active_user_for_code from Redis when memory cleared
        with comm._lock:
            comm._user_codes.clear()
            comm._code_users.clear()
        assert await comm.get_active_user_community_code(u_c.id) == c_new
        assert await comm.get_active_user_for_code(c_new) == u_c.id

        # 415: match_and_consume_community_code empty string
        assert await comm.match_and_consume_community_code("   ") is None

        # 464-470: match_and_consume_community_code from Redis when memory is cleared
        assert await comm.match_and_consume_community_code(c_new) == u_c.id

        # 437-439: match_and_consume_community_code substring match in memory
        c_sub, _ = await comm.issue_user_community_code(u_c.id, db)
        assert (
            await comm.match_and_consume_community_code(f"prefix_{c_sub}_suffix")
            == u_c.id
        )

        # 995 & 999: notify_account_device_quota_changed duplicate user in rows and empty qq_uin
        u_empty_qq = await user_svc.register_user(
            "u_empty_qq@school.com",
            "ValidPass123!",
            "U Empty QQ",
            db,
            username="u_empty_qq",
            role_code="normal",
            is_active=True,
        )
        acct_q = Account(
            id=str(uuid4()),
            name="Quota Dup Org",
            slug="quota_dup_org",
            api_key="kq",
            is_active=True,
            registration_mode="pairing",
            created_at=datetime.now(timezone.utc),
        )
        db.add_all(
            [
                acct_q,
                AccountMember(
                    id=str(uuid4()),
                    user_id=u_c.id,
                    account_id=acct_q.id,
                    role_in_account="owner",
                    joined_at=datetime.now(timezone.utc),
                ),
                AccountMember(
                    id=str(uuid4()),
                    user_id=u_empty_qq.id,
                    account_id=acct_q.id,
                    role_in_account="admin",
                    joined_at=datetime.now(timezone.utc),
                ),
                CommunityBinding(
                    user_id=u_c.id,
                    qq_uin="777888999",
                    group_id="100",
                    is_manual=True,
                    is_joined=True,
                    bound_at=datetime.now(timezone.utc),
                ),
                CommunityBinding(
                    user_id=u_empty_qq.id,
                    qq_uin="   ",
                    group_id="100",
                    is_manual=True,
                    is_joined=True,
                    bound_at=datetime.now(timezone.utc),
                ),
            ]
        )
        await db.commit()
        await comm.notify_account_device_quota_changed(
            acct_q.id,
            "max_clients",
            db,
            onebot_caller=AsyncMock(return_value={"status": "ok", "retcode": 0}),
        )

        # 1373, 1378: sync_group_member_bindings with empty table (1373) and onebot_caller=None (1378)
        with patch.object(
            comm,
            "_call_onebot",
            AsyncMock(return_value={"status": "failed", "retcode": 1}),
        ):
            await comm.sync_group_member_bindings(db, token="tok")

        await db.execute(delete(CommunityBinding))
        await db.commit()
        assert await comm.sync_group_member_bindings(db, token="tok") == 0

        # 1567, 1638: _approve_and_notify_member with onebot_caller=None
        with patch.object(
            comm,
            "_call_onebot",
            AsyncMock(return_value={"status": "ok", "retcode": 0}),
        ):
            await comm._approve_and_notify_member(
                "f1", "777888999", 100, u_c, token="tok"
            )

        # 2273, 2299, 2324: poll_snowluma_superadmin_replies_once
        monkeypatch.setattr(comm, "SNOWLUMA_ONEBOT_TOKEN", "")
        assert await comm.poll_snowluma_superadmin_replies_once(db) == []
        # 2299: poll_uins empty (no superadmin qq and no bound_rows)
        assert (
            await comm.poll_snowluma_superadmin_replies_once(
                db, onebot_caller=AsyncMock()
            )
            == []
        )
        # 2324: non-dict item in messages list
        db.add(
            CommunityBinding(
                user_id=u_c.id,
                qq_uin="777888999",
                group_id="100",
                is_manual=True,
                is_joined=True,
                bound_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()
        await comm.poll_snowluma_superadmin_replies_once(
            db,
            onebot_caller=AsyncMock(
                return_value={
                    "status": "ok",
                    "retcode": 0,
                    "data": ["not_a_dict"],
                }
            ),
        )

    # 2550-2551, 2553: _snowluma_poll_loop normal iteration & CancelledError
    with (
        patch(
            "app.shared.utils.community.process_pending_group_requests",
            AsyncMock(return_value=0),
        ),
        patch(
            "app.shared.utils.community.poll_snowluma_superadmin_replies_once",
            AsyncMock(return_value=[]),
        ),
        patch(
            "app.shared.utils.community.sync_group_member_bindings",
            AsyncMock(side_effect=[0, asyncio.CancelledError()]),
        ),
        patch("asyncio.sleep", AsyncMock()),
    ):
        with pytest.raises(asyncio.CancelledError):
            await comm._snowluma_poll_loop()
