"""test_account.py"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from httpx import ASGITransport, AsyncClient

from app.admin import account
from app.admin.app import admin_app
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import ClientRecord, User
from app.shared.security import auth
from app.shared.services.user import ensure_system_roles


def test_import():
    """Verify module import."""
    assert account is not None


@pytest.mark.asyncio
async def test_admin_root_and_account_endpoints(test_superadmin_user):
    """Test admin_app root health check, stats, account CRUD, quotas, pending approvals, and OOBE endpoints."""
    async with AsyncSessionLocal() as db:
        await ensure_system_roles(db)

    sid = await auth.create_session_token(test_superadmin_user)
    headers = {"Authorization": f"Bearer {sid}"}

    transport = ASGITransport(app=admin_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Root health check
        r_root = await client.get("/")
        assert r_root.status_code == 200
        assert r_root.json()["status"] == "ok"

        # 2. Platform stats (with and without online clients in session_manager)
        r_stats = await client.get("/stats", headers=headers)
        assert r_stats.status_code == 200
        assert "total_accounts" in r_stats.json()

        mock_sm = MagicMock()
        mock_sm.get_all_clients_status = AsyncMock(
            return_value=[{"uid": "online-uid-1"}]
        )
        with (
            patch("app.admin.account.get_command_servicer", return_value=None),
            patch("app.admin.account.get_session_manager", return_value=mock_sm),
        ):
            r_stats2 = await client.get("/stats", headers=headers)
            assert r_stats2.status_code == 200
            assert r_stats2.json()["online_clients"] == 1

        mock_cs = MagicMock()
        mock_cs.client_queues = {"t1:u1": MagicMock(), "t1:u2": MagicMock()}
        with patch("app.admin.account.get_command_servicer", return_value=mock_cs):
            r_stats3 = await client.get("/stats", headers=headers)
            assert r_stats3.status_code == 200
            assert r_stats3.json()["online_clients"] == 2

        # 3. Create account
        r_create = await client.post(
            "/account/create",
            json={"name": "Admin Created School", "slug": "admin-school"},
            headers=headers,
        )
        assert r_create.status_code == 201
        acct_data = r_create.json()
        acct_id = acct_data["id"]
        assert acct_data["slug"] == "admin-school"

        # Create account with duplicate slug -> 400
        r_create_bad = await client.post(
            "/account/create",
            json={"name": "Duplicate Slug", "slug": "admin-school"},
            headers=headers,
        )
        assert r_create_bad.status_code == 400

        # 4. List & Search accounts
        r_list = await client.get("/account/list", headers=headers)
        assert r_list.status_code == 200
        assert any(a["id"] == acct_id for a in r_list.json())

        r_search_all = await client.get("/account/search", headers=headers)
        assert r_search_all.status_code == 200

        r_search_q = await client.get(
            "/account/search", params={"q": "admin-school"}, headers=headers
        )
        assert r_search_q.status_code == 200
        assert len(r_search_q.json()) == 1

        # 5. Get account detail
        r_detail = await client.get(f"/account/{acct_id}", headers=headers)
        assert r_detail.status_code == 200
        assert r_detail.json()["id"] == acct_id

        r_detail_404 = await client.get("/account/non-existent", headers=headers)
        assert r_detail_404.status_code == 404

        # 6. Update account
        r_upd = await client.post(
            f"/account/{acct_id}",
            json={
                "name": "Updated School Name",
                "slug": "updated-school",
                "is_active": False,
                "registration_mode": "pairing",
            },
            headers=headers,
        )
        assert r_upd.status_code == 200
        assert r_upd.json()["slug"] == "updated-school"
        assert r_upd.json()["is_active"] is False
        assert r_upd.json()["registration_mode"] == "pairing"

        # Update 404
        r_upd_404 = await client.post(
            "/account/non-existent", json={"name": "X"}, headers=headers
        )
        assert r_upd_404.status_code == 404

        # Direct call to admin_update_account with model_construct invalid slug -> 400
        async with AsyncSessionLocal() as db:
            sa_obj = await db.get(User, test_superadmin_user)
            assert sa_obj is not None
            with pytest.raises(account.HTTPException) as exc_bad_slug:
                await account.admin_update_account(
                    acct_id,
                    account.AccountUpdate.model_construct(
                        new_id=None,
                        name=None,
                        slug="INVALID_SLUG!",
                        is_active=None,
                        registration_mode=None,
                    ),
                    db,
                    sa_obj,
                )
            assert exc_bad_slug.value.status_code == 400
            # Also test fallback when admin_user has no id attribute
            with pytest.raises(account.HTTPException) as exc_fallback_404:
                await account.admin_update_account(
                    "non-existent",
                    account.AccountUpdate(name="X"),
                    db,
                    None,  # type: ignore[arg-type]
                )
            assert exc_fallback_404.value.status_code == 404

        # Create a second account to test duplicate slug conflict
        r_create2 = await client.post(
            "/account/create",
            json={"name": "Second School", "slug": "second-school"},
            headers=headers,
        )
        assert r_create2.status_code == 201
        r_upd_dup = await client.post(
            f"/account/{acct_id}", json={"slug": "second-school"}, headers=headers
        )
        assert r_upd_dup.status_code == 400

        # 7. Quotas
        async with AsyncSessionLocal() as db:
            db.add(
                ClientRecord(
                    uid="client-for-quota",
                    account_id=acct_id,
                    registered_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()

        r_quotas = await client.get(f"/account/{acct_id}/quota", headers=headers)
        assert r_quotas.status_code == 200
        quotas_list = r_quotas.json()
        assert any(
            q["quota_key"] == "max_clients" and q["current_value"] == 1
            for q in quotas_list
        )

        mock_cs_q = MagicMock()
        mock_cs_q.tenant_clients = {acct_id: {"c1", "c2", "c3"}}
        with patch("app.admin.account.get_command_servicer", return_value=mock_cs_q):
            r_quotas_cs = await client.get(f"/account/{acct_id}/quota", headers=headers)
            assert r_quotas_cs.status_code == 200
            assert any(
                q["quota_key"] == "max_grpc_connections" and q["current_value"] == 3
                for q in r_quotas_cs.json()
            )

        r_set_quota = await client.post(
            f"/account/{acct_id}/quota",
            json={"quota_key": "max_clients", "max_value": 500},
            headers=headers,
        )
        assert r_set_quota.status_code == 200
        assert r_set_quota.json()["max_value"] == 500

        # 7.5 Global client list
        r_all_clients = await client.get("/client/list", headers=headers)
        assert r_all_clients.status_code == 200
        assert any(
            c["uid"] == "client-for-quota" and c["account_id"] == acct_id
            for c in r_all_clients.json()
        )
        r_filtered_clients = await client.get(
            "/client/list",
            params={"account_id": acct_id, "q": "client-for-quota"},
            headers=headers,
        )
        assert r_filtered_clients.status_code == 200
        assert len(r_filtered_clients.json()) == 1

        # 8. Delete account
        r_del_404 = await client.delete("/account/non-existent", headers=headers)
        assert r_del_404.status_code == 404

        r_del = await client.delete(f"/account/{acct_id}", headers=headers)
        assert r_del.status_code == 200
        assert r_del.json()["status"] == "deleted"

        # 9. Pending users approval & rejection
        async with AsyncSessionLocal() as db:
            u_pend1 = User(
                id="pend-1",
                username="pending_one",
                email="pend1@school.com",
                hashed_password="h",
                display_name="Pending 1",
                role_code="pending",
                is_active=False,
                created_at=datetime.now(timezone.utc),
            )
            u_pend2 = User(
                id="pend-2",
                username="pending_two",
                email="pend2@school.com",
                hashed_password="h",
                display_name="Pending 2",
                role_code="pending",
                is_active=False,
                created_at=datetime.now(timezone.utc),
            )
            db.add_all([u_pend1, u_pend2])
            await db.commit()

        r_pend_list = await client.get("/user/pending", headers=headers)
        assert r_pend_list.status_code == 200
        assert len(r_pend_list.json()) >= 2

        r_approve = await client.post("/user/pending/approve/pend-1", headers=headers)
        assert r_approve.status_code == 200
        assert r_approve.json()["role_code"] == "normal"

        r_approve_404 = await client.post(
            "/user/pending/approve/non-existent", headers=headers
        )
        assert r_approve_404.status_code == 404

        r_reject = await client.post("/user/pending/reject/pend-2", headers=headers)
        assert r_reject.status_code == 200

        r_reject_404 = await client.post(
            "/user/pending/reject/non-existent", headers=headers
        )
        assert r_reject_404.status_code == 404

        # 10. OOBE Verify & Configure
        auth.generate_oobe_codes()
        passcode = auth.OOBE_PASSCODE

        r_oobe_bad = await client.post("/oobe/verify", data={"passcode": "WRONG123"})
        assert r_oobe_bad.status_code == 403

        # Lockout 429 branch on /oobe/verify
        auth.OOBE_LOCKOUT_UNTIL = 999999999.0
        r_oobe_locked = await client.post("/oobe/verify", data={"passcode": passcode})
        assert r_oobe_locked.status_code == 429
        auth.OOBE_LOCKOUT_UNTIL = 0.0
        auth.OOBE_FAIL_COUNT = 0

        r_oobe_ok = await client.post("/oobe/verify", data={"passcode": passcode})
        assert r_oobe_ok.status_code == 200
        oobe_token = r_oobe_ok.json()["token"]

        r_cfg_bad_tok = await client.post(
            "/oobe/configure",
            data={
                "token": "bad-token",
                "db_url": "postgresql+psycopg://u:p@localhost/db",
                "redis_url": "redis://localhost:6379/0",
                "domain": "miniclassisland.com",
                "username": "admin",
                "email": "admin@school.com",
                "password": "Password123!",
            },
        )
        assert r_cfg_bad_tok.status_code == 403

        # Invalid OOBE input validation branches (db_url, redis_url, username, email, password)
        for bad_override in (
            {"db_url": "mysql://localhost/db"},
            {"redis_url": "http://localhost:6379"},
            {"username": "ab"},
            {"email": "not-an-email"},
            {"password": "weak"},
        ):
            base_form = {
                "token": oobe_token,
                "db_url": "postgresql+psycopg://u:p@localhost/db",
                "redis_url": "redis://localhost:6379/0",
                "domain": "miniclassisland.com",
                "username": "admin",
                "email": "admin@school.com",
                "password": "Password123!",
                **bad_override,
            }
            r_bad_in = await client.post("/oobe/configure", data=base_form)
            assert r_bad_in.status_code == 400

        with (
            patch("app.admin.account.write_config_file") as mock_write,
            patch(
                "app.admin.account.init_database", new_callable=AsyncMock
            ) as mock_init_db,
            patch("threading.Timer") as mock_timer,
        ):
            r_cfg_ok = await client.post(
                "/oobe/configure",
                data={
                    "token": oobe_token,
                    "db_url": "postgresql+psycopg://u:p@localhost/db",
                    "redis_url": "redis://localhost:6379/0",
                    "domain": "miniclassisland.com",
                    "username": "admin",
                    "email": "admin@school.com",
                    "password": "Password123!",
                },
            )
            assert r_cfg_ok.status_code == 200
            mock_write.assert_called_once()
            mock_init_db.assert_awaited_once()
            mock_timer.assert_called_once()

        auth.generate_oobe_codes()
        oobe_token = auth.get_oobe_token()
        with (
            patch("app.admin.account.init_database", new_callable=AsyncMock),
            patch(
                "app.admin.account.write_config_file",
                side_effect=RuntimeError("disk full"),
            ),
        ):
            r_cfg_err = await client.post(
                "/oobe/configure",
                data={
                    "token": oobe_token,
                    "db_url": "postgresql+psycopg://u:p@localhost/db",
                    "redis_url": "redis://localhost:6379/0",
                    "domain": "miniclassisland.com",
                    "username": "admin",
                    "email": "admin@school.com",
                    "password": "Password123!",
                },
            )
            assert r_cfg_err.status_code == 400
