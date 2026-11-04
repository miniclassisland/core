"""test_account.py"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

from app.management import account
from app.management.app import management_app
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import (
    Account,
    AuditLog,
    ClientRecord,
    CPFile,
    Invitation,
    PairingCode,
    PreRegisteredClient,
    ReservedName,
)
from app.shared.security.auth import create_session_token
from app.shared.services.user import register_user


def test_import():
    """Verify module import."""
    assert account is not None


@pytest.mark.asyncio
async def test_management_account_full_suite(test_superadmin_user):
    """Comprehensive test suite for app/management/account.py."""
    async with AsyncSessionLocal() as db:
        db.add(ReservedName(name="reserved-slug"))
        normal_user = await register_user(
            "norm@school.com",
            "NormPassword123!",
            "Normal User",
            db,
            username="norm_user",
            role_code="normal",
            is_active=True,
            can_create_account=False,
        )
        norm_uid = normal_user.id
        other_user = await register_user(
            "outsider@school.com",
            "OutsiderPass123!",
            "Outsider",
            db,
            username="outsider_user",
            role_code="normal",
            is_active=True,
            can_create_account=True,
        )
        outsider_uid = other_user.id
        await db.commit()

    sa_sid = await create_session_token(test_superadmin_user)
    sa_headers = {"Authorization": f"Bearer {sa_sid}"}
    norm_sid = await create_session_token(norm_uid)
    norm_headers = {"Authorization": f"Bearer {norm_sid}"}
    outsider_sid = await create_session_token(outsider_uid)
    outsider_headers = {"Authorization": f"Bearer {outsider_sid}"}

    # 1. Direct unit tests for setup_tenant_context edge cases
    async with AsyncSessionLocal() as db:
        with pytest.raises(HTTPException) as exc:
            await account.setup_tenant_context("non-existent", db, test_superadmin_user)
        assert exc.value.status_code == 403

        inactive_acct = Account(
            id="inactive-acct",
            name="Inactive",
            slug="inactive-slug",
            api_key="k",
            is_active=False,
            created_at=datetime.now(timezone.utc),
        )
        active_acct = Account(
            id="active-no-member",
            name="Active No Member",
            slug="active-no-member",
            api_key="k",
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        db.add_all([inactive_acct, active_acct])
        await db.commit()

        with pytest.raises(HTTPException) as exc2:
            await account.setup_tenant_context("active-no-member", db, norm_uid)
        assert exc2.value.status_code == 403

        # Superadmin is allowed even if not in AccountMember
        await account.setup_tenant_context("active-no-member", db, test_superadmin_user)

    transport = ASGITransport(app=management_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 2. Slug availability & Account apply/list/search/info/slug/name/api-key/preset
        assert (
            await client.get(
                "/account/availability/slug",
                params={"value": "BAD_SLUG!"},
                headers=sa_headers,
            )
        ).json()["available"] is False

        assert (
            await client.get(
                "/account/availability/slug",
                params={"value": "reserved-slug"},
                headers=sa_headers,
            )
        ).json()["available"] is False

        assert (
            await client.get(
                "/account/availability/slug",
                params={"value": "good-slug"},
                headers=sa_headers,
            )
        ).json()["available"] is True

        # Apply account without permission -> 403
        r_apply_403 = await client.post(
            "/account/apply",
            json={"name": "Norm School", "slug": "norm-school"},
            headers=norm_headers,
        )
        assert r_apply_403.status_code == 403

        # Apply account success
        r_apply = await client.post(
            "/account/apply",
            json={"name": "Main School", "slug": "main-school"},
            headers=sa_headers,
        )
        assert r_apply.status_code == 201
        acct_id = r_apply.json()["id"]

        # Apply account with duplicate slug -> 400
        r_apply_400 = await client.post(
            "/account/apply",
            json={"name": "Dup School", "slug": "main-school"},
            headers=sa_headers,
        )
        assert r_apply_400.status_code == 400

        # Slug taken check
        assert (
            await client.get(
                "/account/availability/slug",
                params={"value": "main-school"},
                headers=sa_headers,
            )
        ).json()["available"] is False

        # List & Search accounts
        r_list = await client.get("/account/list", headers=sa_headers)
        assert r_list.status_code == 200
        assert any(a["id"] == acct_id for a in r_list.json())

        r_search = await client.post(
            "/account/search", params={"q": "Main"}, headers=sa_headers
        )
        assert r_search.status_code == 200
        assert len(r_search.json()) >= 1

        # Account info, quota, slug, name, api-key, preset
        r_info = await client.get(f"/account/{acct_id}/info", headers=sa_headers)
        assert r_info.status_code == 200

        r_quota_get = await client.get(f"/account/{acct_id}/quota", headers=sa_headers)
        assert r_quota_get.status_code == 200
        assert any(q["quota_key"] == "max_grpc_connections" for q in r_quota_get.json())

        r_quota_set_403 = await client.post(
            f"/account/{acct_id}/quota",
            json={"quota_key": "max_grpc_connections", "max_value": 100},
            headers=norm_headers,
        )
        assert r_quota_set_403.status_code == 403

        r_quota_set_ok = await client.post(
            f"/account/{acct_id}/quota",
            json={"quota_key": "max_grpc_connections", "max_value": 250},
            headers=sa_headers,
        )
        assert r_quota_set_ok.status_code == 200
        assert r_quota_set_ok.json()["max_value"] == 250

        r_slug_bad = await client.post(
            f"/account/{acct_id}/info/slug",
            json={"slug": "INVALID!"},
            headers=sa_headers,
        )
        assert r_slug_bad.status_code == 400

        r_slug_ok = await client.post(
            f"/account/{acct_id}/info/slug",
            json={"slug": "main-school-v2"},
            headers=sa_headers,
        )
        assert r_slug_ok.status_code == 200
        assert r_slug_ok.json()["slug"] == "main-school-v2"

        r_name = await client.post(
            f"/account/{acct_id}/info/name",
            json={"name": "Main School V2"},
            headers=sa_headers,
        )
        assert r_name.status_code == 200
        assert r_name.json()["name"] == "Main School V2"

        r_regen = await client.post(
            f"/account/{acct_id}/info/api-key/regenerate", headers=sa_headers
        )
        assert r_regen.status_code == 200

        r_preset = await client.get(
            f"/account/{acct_id}/ManagementPreset.json", headers=sa_headers
        )
        assert r_preset.status_code == 200
        assert r_preset.json()["IsManagementEnabled"] is True
        assert "ClassIdentity" not in r_preset.json()

        r_preset_ci = await client.get(
            f"/account/{acct_id}/ManagementPreset.json",
            params={"class_identity": "Room-101"},
            headers=sa_headers,
        )
        assert r_preset_ci.status_code == 200
        assert r_preset_ci.json()["ClassIdentity"] == "Room-101"

        # 3. Invitations & Access Members
        r_inv_create = await client.post(
            f"/account/{acct_id}/invitation/create",
            json={"role_in_account": "admin", "max_uses": 1},
            headers=sa_headers,
        )
        assert r_inv_create.status_code == 201
        inv_id = r_inv_create.json()["id"]
        inv_code = r_inv_create.json()["code"]

        assert (
            await client.get(f"/account/{acct_id}/invitation/list", headers=sa_headers)
        ).status_code == 200
        assert (
            await client.get(
                f"/account/{acct_id}/invitation/search", headers=sa_headers
            )
        ).status_code == 200
        assert (
            await client.get(
                f"/account/{acct_id}/invitation/search",
                params={"q": inv_code[:4]},
                headers=sa_headers,
            )
        ).status_code == 200
        assert (
            await client.get(
                f"/account/{acct_id}/invitation/{inv_id}", headers=sa_headers
            )
        ).status_code == 200
        assert (
            await client.get(
                f"/account/{acct_id}/invitation/non-existent", headers=sa_headers
            )
        ).status_code == 404

        r_inv_ren = await client.post(
            f"/account/{acct_id}/invitation/{inv_id}/rename",
            json={"role_in_account": "member", "max_uses": 2},
            headers=sa_headers,
        )
        assert r_inv_ren.status_code == 200
        assert (
            await client.post(
                f"/account/{acct_id}/invitation/non-existent/rename",
                json={"max_uses": 5},
                headers=sa_headers,
            )
        ).status_code == 404

        # Accept invitation (invalid code -> 404, valid -> 200, already member -> 400)
        assert (
            await client.post(
                "/invitation/accept", json={"code": "BADCODE"}, headers=norm_headers
            )
        ).status_code == 404

        r_acc_inv = await client.post(
            "/invitation/accept", json={"code": inv_code}, headers=norm_headers
        )
        assert r_acc_inv.status_code == 200

        r_acc_dup = await client.post(
            "/invitation/accept", json={"code": inv_code}, headers=norm_headers
        )
        assert r_acc_dup.status_code == 400

        # Test max_uses reached and expired invitation branches
        async with AsyncSessionLocal() as db:
            db.add_all(
                [
                    Invitation(
                        id="inv-maxed",
                        account_id=acct_id,
                        inviter_user_id=test_superadmin_user,
                        code="MAXEDCODE",
                        max_uses=1,
                        used_count=1,
                        is_active=True,
                        created_at=datetime.now(timezone.utc),
                    ),
                    Invitation(
                        id="inv-expired",
                        account_id=acct_id,
                        inviter_user_id=test_superadmin_user,
                        code="EXPIREDCODE",
                        max_uses=5,
                        used_count=0,
                        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
                        is_active=True,
                        created_at=datetime.now(timezone.utc),
                    ),
                    Invitation(
                        id="inv-one-shot",
                        account_id=acct_id,
                        inviter_user_id=test_superadmin_user,
                        code="ONESHOTCODE",
                        max_uses=1,
                        used_count=0,
                        is_active=True,
                        created_at=datetime.now(timezone.utc),
                    ),
                ]
            )
            await db.commit()

        assert (
            await client.post(
                "/invitation/accept",
                json={"code": "MAXEDCODE"},
                headers=outsider_headers,
            )
        ).status_code == 400
        assert (
            await client.post(
                "/invitation/accept",
                json={"code": "EXPIREDCODE"},
                headers=outsider_headers,
            )
        ).status_code == 400
        assert (
            await client.post(
                "/invitation/accept",
                json={"code": "ONESHOTCODE"},
                headers=outsider_headers,
            )
        ).status_code == 200

        # Revoke invitation & 404
        assert (
            await client.delete(
                f"/account/{acct_id}/invitation/{inv_id}", headers=sa_headers
            )
        ).status_code == 200
        assert (
            await client.delete(
                f"/account/{acct_id}/invitation/non-existent", headers=sa_headers
            )
        ).status_code == 404

        # Access Member endpoints
        assert (
            await client.get(f"/account/{acct_id}/access/list", headers=sa_headers)
        ).status_code == 200
        assert (
            await client.get(f"/account/{acct_id}/access/search", headers=sa_headers)
        ).status_code == 200
        assert (
            await client.get(
                f"/account/{acct_id}/access/search",
                params={"q": "norm"},
                headers=sa_headers,
            )
        ).status_code == 200
        assert (
            await client.get(
                f"/account/{acct_id}/access/{norm_uid}", headers=sa_headers
            )
        ).status_code == 200
        assert (
            await client.get(
                f"/account/{acct_id}/access/non-existent", headers=sa_headers
            )
        ).status_code == 404

        assert (
            await client.post(
                f"/account/{acct_id}/access/{norm_uid}/rename",
                json={"name": "Normal Renamed"},
                headers=sa_headers,
            )
        ).status_code == 200
        assert (
            await client.post(
                f"/account/{acct_id}/access/non-existent/rename",
                json={"name": "X"},
                headers=sa_headers,
            )
        ).status_code == 404

        assert (
            await client.post(
                f"/account/{acct_id}/access/{norm_uid}",
                json={"role_in_account": "admin"},
                headers=sa_headers,
            )
        ).status_code == 200
        assert (
            await client.post(
                f"/account/{acct_id}/access/non-existent",
                json={"role_in_account": "admin"},
                headers=sa_headers,
            )
        ).status_code == 404

        assert (
            await client.delete(
                f"/account/{acct_id}/access/{outsider_uid}", headers=sa_headers
            )
        ).status_code == 204
        assert (
            await client.delete(
                f"/account/{acct_id}/access/non-existent", headers=sa_headers
            )
        ).status_code == 404

        # 4. Pairing & Registration Mode endpoints
        assert (
            await client.get(f"/account/{acct_id}/pairing/status", headers=sa_headers)
        ).status_code == 200
        assert (
            await client.post(
                f"/account/{acct_id}/pairing/mode",
                json={"registration_mode": "invalid"},
                headers=sa_headers,
            )
        ).status_code == 400
        assert (
            await client.post(
                f"/account/{acct_id}/pairing/mode",
                json={"registration_mode": "pre_reg"},
                headers=sa_headers,
            )
        ).status_code == 200
        assert (
            await client.post(f"/account/{acct_id}/pairing/enable", headers=sa_headers)
        ).status_code == 200
        assert (
            await client.post(f"/account/{acct_id}/pairing/disable", headers=sa_headers)
        ).status_code == 200

        async with AsyncSessionLocal() as db:
            db.add_all(
                [
                    PairingCode(
                        id="pair-1",
                        code="PAIR0001",
                        tenant_id=acct_id,
                        client_uid="cuid-p1",
                        client_id="Class1",
                        client_mac="AA-BB",
                        created_at=datetime.now(timezone.utc),
                    ),
                    PairingCode(
                        id="pair-2",
                        code="PAIR0002",
                        tenant_id=acct_id,
                        client_uid="cuid-p2",
                        client_id="Class2",
                        client_mac="CC-DD",
                        created_at=datetime.now(timezone.utc),
                    ),
                ]
            )
            await db.commit()

        assert (
            await client.get(f"/account/{acct_id}/pairing/list", headers=sa_headers)
        ).status_code == 200
        assert (
            await client.get(f"/account/{acct_id}/pairing/search", headers=sa_headers)
        ).status_code == 200
        assert (
            await client.get(
                f"/account/{acct_id}/pairing/search",
                params={"q": "PAIR0001"},
                headers=sa_headers,
            )
        ).status_code == 200

        assert (
            await client.post(
                f"/account/{acct_id}/pairing/pair-1/approve",
                json={"preset_profile": {"class_plan": "default"}},
                headers=sa_headers,
            )
        ).status_code == 200
        assert (
            await client.post(
                f"/account/{acct_id}/pairing/non-existent/approve", headers=sa_headers
            )
        ).status_code == 404

        assert (
            await client.post(
                f"/account/{acct_id}/pairing/pair-2/reject", headers=sa_headers
            )
        ).status_code == 200
        assert (
            await client.post(
                f"/account/{acct_id}/pairing/non-existent/reject", headers=sa_headers
            )
        ).status_code == 404

        # 5. Pre-Registration endpoints
        r_pre_c = await client.post(
            f"/account/{acct_id}/pre-registration/create",
            json={
                "label": "Room 101",
                "class_identity": "R101",
                "mac_address": "11-22-33-44-55-66",
                "preset_profile": {"class_plan": "default"},
            },
            headers=sa_headers,
        )
        assert r_pre_c.status_code == 201
        pre_id = r_pre_c.json()["id"]

        # Duplicate class_identity -> 400
        assert (
            await client.post(
                f"/account/{acct_id}/pre-registration/create",
                json={"label": "Dup", "class_identity": "R101"},
                headers=sa_headers,
            )
        ).status_code == 400

        # Batch create pre-reg (including blank and duplicate items)
        r_pre_b = await client.post(
            f"/account/{acct_id}/pre-registration/batch",
            json={
                "items": [
                    {"label": "Blank", "class_identity": "   "},
                    {"label": "Dup", "class_identity": "R101"},
                    {"label": "Room 102", "class_identity": "R102"},
                ]
            },
            headers=sa_headers,
        )
        assert r_pre_b.status_code == 201
        assert len(r_pre_b.json()) == 1

        assert (
            await client.get(
                f"/account/{acct_id}/pre-registration/list", headers=sa_headers
            )
        ).status_code == 200
        assert (
            await client.get(
                f"/account/{acct_id}/pre-registration/search", headers=sa_headers
            )
        ).status_code == 200
        assert (
            await client.get(
                f"/account/{acct_id}/pre-registration/search",
                params={"q": "R101"},
                headers=sa_headers,
            )
        ).status_code == 200
        assert (
            await client.get(
                f"/account/{acct_id}/pre-registration/{pre_id}", headers=sa_headers
            )
        ).status_code == 200
        assert (
            await client.get(
                f"/account/{acct_id}/pre-registration/non-existent", headers=sa_headers
            )
        ).status_code == 404

        assert (
            await client.post(
                f"/account/{acct_id}/pre-registration/{pre_id}/rename",
                json={
                    "label": "Room 101 Updated",
                    "class_identity": "R101U",
                    "mac_address": "AA-BB",
                },
                headers=sa_headers,
            )
        ).status_code == 200
        assert (
            await client.post(
                f"/account/{acct_id}/pre-registration/{pre_id}/rename",
                json={"name": "Room 101 By Name"},
                headers=sa_headers,
            )
        ).status_code == 200
        assert (
            await client.post(
                f"/account/{acct_id}/pre-registration/non-existent/rename",
                json={"label": "X"},
                headers=sa_headers,
            )
        ).status_code == 404

        assert (
            await client.post(
                f"/account/{acct_id}/pre-registration/{pre_id}/disable",
                headers=sa_headers,
            )
        ).status_code == 200
        assert (
            await client.post(
                f"/account/{acct_id}/pre-registration/non-existent/disable",
                headers=sa_headers,
            )
        ).status_code == 404

        assert (
            await client.post(
                f"/account/{acct_id}/pre-registration/{pre_id}/enable",
                headers=sa_headers,
            )
        ).status_code == 200
        assert (
            await client.post(
                f"/account/{acct_id}/pre-registration/non-existent/enable",
                headers=sa_headers,
            )
        ).status_code == 404

        assert (
            await client.post(
                f"/account/{acct_id}/pre-registration/{pre_id}/config",
                json={"preset_profile": {"class_plan": "default"}},
                headers=sa_headers,
            )
        ).status_code == 200
        assert (
            await client.post(
                f"/account/{acct_id}/pre-registration/non-existent/config",
                json={},
                headers=sa_headers,
            )
        ).status_code == 404

        assert (
            await client.get(
                f"/account/{acct_id}/pre-registration/{pre_id}/ManagementPreset.json",
                headers=sa_headers,
            )
        ).status_code == 200
        assert (
            await client.get(
                f"/account/{acct_id}/pre-registration/non-existent/ManagementPreset.json",
                headers=sa_headers,
            )
        ).status_code == 404

        assert (
            await client.delete(
                f"/account/{acct_id}/pre-registration/{pre_id}", headers=sa_headers
            )
        ).status_code == 204
        assert (
            await client.delete(
                f"/account/{acct_id}/pre-registration/non-existent", headers=sa_headers
            )
        ).status_code == 404

        # 6. Client Devices, Configs, Commands, Broadcast, Config Uploads, Audit Logs
        async with AsyncSessionLocal() as db:
            db.add_all(
                [
                    ClientRecord(
                        uid="dev-1",
                        account_id=acct_id,
                        client_id="Class-A",
                        display_name="Device A",
                        mac="AA-11",
                        ip="10.0.0.1",
                        registered_at=datetime.now(timezone.utc),
                        last_seen_at=datetime.now(timezone.utc),
                    ),
                    ClientRecord(
                        uid="dev-2",
                        account_id=acct_id,
                        client_id="Class-B",
                        display_name="Device B",
                        mac="BB-22",
                        ip="10.0.0.2",
                        registered_at=datetime.now(timezone.utc),
                    ),
                    AuditLog(
                        account_id=acct_id,
                        client_uid="dev-1",
                        event=1,
                        payload="",
                        decoded_json='{"data": {"Success": true}}',
                        timestamp_utc=1700000000,
                        received_at=datetime.now(timezone.utc),
                    ),
                    AuditLog(
                        account_id=acct_id,
                        client_uid="dev-1",
                        event=2,
                        payload="",
                        decoded_json="{bad-json",
                        timestamp_utc=1700000001,
                        received_at=datetime.now(timezone.utc),
                    ),
                ]
            )
            await db.commit()

        mock_sm = MagicMock()
        mock_sm.get_all_clients_status = AsyncMock(
            return_value=[{"uid": "dev-1", "status": "online", "ip": "10.0.0.1"}]
        )
        mock_sm.is_client_online = AsyncMock(return_value=True)
        mock_sm.set_client_offline = AsyncMock()

        mock_servicer = MagicMock()
        mock_servicer.send_command = AsyncMock(return_value=True)
        mock_servicer.disconnect_client = AsyncMock(return_value=True)

        with (
            patch("app.management.account.get_session_manager", return_value=mock_sm),
            patch(
                "app.management.account.get_command_servicer",
                return_value=mock_servicer,
            ),
        ):
            assert (
                await client.get(f"/account/{acct_id}/client/list", headers=sa_headers)
            ).status_code == 200
            assert (
                await client.get(
                    f"/account/{acct_id}/client/search", headers=sa_headers
                )
            ).status_code == 200
            assert (
                await client.get(
                    f"/account/{acct_id}/client/search",
                    params={"q": "dev-1"},
                    headers=sa_headers,
                )
            ).status_code == 200
            assert (
                await client.get(f"/account/{acct_id}/client/dev-1", headers=sa_headers)
            ).status_code == 200
            assert (
                await client.get(
                    f"/account/{acct_id}/client/non-existent", headers=sa_headers
                )
            ).status_code == 404
            assert (
                await client.get(
                    f"/account/{acct_id}/client/dev-1/status", headers=sa_headers
                )
            ).status_code == 200

            # Client config (__default__ and dev-1)
            assert (
                await client.get(
                    f"/account/{acct_id}/client/dev-1/config", headers=sa_headers
                )
            ).status_code == 200
            assert (
                await client.post(
                    f"/account/{acct_id}/client/__default__/config",
                    json={"class_plan": "default", "auto_sync": True},
                    headers=sa_headers,
                )
            ).status_code == 200
            assert (
                await client.post(
                    f"/account/{acct_id}/client/dev-1/config",
                    json={"class_plan": "default", "auto_sync": True},
                    headers=sa_headers,
                )
            ).status_code == 200
            assert (
                await client.post(
                    f"/account/{acct_id}/client/dev-1/config",
                    json={"use_default": True, "auto_sync": False},
                    headers=sa_headers,
                )
            ).status_code == 200

            # Rename, disable, enable, disconnect
            assert (
                await client.post(
                    f"/account/{acct_id}/client/dev-1/rename",
                    json={"display_name": "Dev 1 New", "client_id": "Class-A1"},
                    headers=sa_headers,
                )
            ).status_code == 200
            assert (
                await client.post(
                    f"/account/{acct_id}/client/dev-1/rename",
                    json={"name": "Dev 1 By Name"},
                    headers=sa_headers,
                )
            ).status_code == 200
            assert (
                await client.post(
                    f"/account/{acct_id}/client/non-existent/rename",
                    json={"name": "X"},
                    headers=sa_headers,
                )
            ).status_code == 404

            assert (
                await client.post(
                    f"/account/{acct_id}/client/dev-1/disable", headers=sa_headers
                )
            ).status_code == 200
            assert (
                await client.post(
                    f"/account/{acct_id}/client/non-existent/disable",
                    headers=sa_headers,
                )
            ).status_code == 404

            assert (
                await client.post(
                    f"/account/{acct_id}/client/dev-1/enable", headers=sa_headers
                )
            ).status_code == 200
            assert (
                await client.post(
                    f"/account/{acct_id}/client/non-existent/enable",
                    headers=sa_headers,
                )
            ).status_code == 404

            assert (
                await client.post(
                    f"/account/{acct_id}/client/dev-1/disconnect", headers=sa_headers
                )
            ).status_code == 200

            # Batch client actions
            assert (
                await client.post(
                    f"/account/{acct_id}/client/batch",
                    json={"action": "sync", "uids": []},
                    headers=sa_headers,
                )
            ).status_code == 400
            for act in ("sync", "restart", "disconnect", "disable", "enable"):
                r_b = await client.post(
                    f"/account/{acct_id}/client/batch",
                    json={"action": act, "uids": ["dev-1", "missing-uid"]},
                    headers=sa_headers,
                )
                assert r_b.status_code == 200

            assert (
                await client.post(
                    f"/account/{acct_id}/client/batch",
                    json={
                        "action": "assign_profile",
                        "uids": ["dev-1"],
                        "profile": {"class_plan": "default", "auto_sync": False},
                    },
                    headers=sa_headers,
                )
            ).status_code == 200

            assert (
                await client.post(
                    f"/account/{acct_id}/client/batch",
                    json={"action": "delete", "uids": ["dev-2"]},
                    headers=sa_headers,
                )
            ).status_code == 200

            # Commands: restart, update-data, send-notification, broadcast, get-config
            assert (
                await client.post(
                    f"/account/{acct_id}/client/dev-1/command/restart",
                    headers=sa_headers,
                )
            ).status_code == 200
            assert (
                await client.post(
                    f"/account/{acct_id}/client/dev-1/command/update-data",
                    headers=sa_headers,
                )
            ).status_code == 200
            assert (
                await client.post(
                    f"/account/{acct_id}/client/dev-1/command/send-notification",
                    json={"MessageMask": "Title", "MessageContent": "Hello"},
                    headers=sa_headers,
                )
            ).status_code == 200
            assert (
                await client.post(
                    f"/account/{acct_id}/broadcast/notification",
                    json={"MessageMask": "Broadcast", "MessageContent": "All"},
                    headers=sa_headers,
                )
            ).status_code == 200

            r_get_cfg = await client.post(
                f"/account/{acct_id}/client/dev-1/command/get-config",
                params={"config_type": 1},
                headers=sa_headers,
            )
            assert r_get_cfg.status_code == 200
            req_guid = r_get_cfg.json()["request_guid"]

            # Offline command delivery branches
            mock_servicer.send_command = AsyncMock(return_value=False)
            assert (
                await client.post(
                    f"/account/{acct_id}/client/dev-1/command/restart",
                    headers=sa_headers,
                )
            ).json()["status"] == "offline"
            assert (
                await client.post(
                    f"/account/{acct_id}/client/dev-1/command/send-notification",
                    json={"MessageMask": "Title", "MessageContent": "Hello"},
                    headers=sa_headers,
                )
            ).json()["status"] == "offline"

            # Config uploads list & detail
            assert (
                await client.get(
                    f"/account/{acct_id}/client/dev-1/config-uploads",
                    headers=sa_headers,
                )
            ).status_code == 200
            assert (
                await client.get(
                    f"/account/{acct_id}/config-upload/{req_guid}", headers=sa_headers
                )
            ).status_code == 200
            assert (
                await client.get(
                    f"/account/{acct_id}/config-upload/non-existent",
                    headers=sa_headers,
                )
            ).status_code == 404

            # Delete client & 404
            assert (
                await client.delete(
                    f"/account/{acct_id}/client/dev-1", headers=sa_headers
                )
            ).status_code == 200
            assert (
                await client.delete(
                    f"/account/{acct_id}/client/non-existent", headers=sa_headers
                )
            ).status_code == 404

        # Commands when gRPC servicer is None (unavailable)
        with (
            patch("app.management.account.get_command_servicer", return_value=None),
            patch("app.management.account.get_session_manager", return_value=None),
        ):
            assert (
                await client.post(
                    f"/account/{acct_id}/client/dev-1/command/restart",
                    headers=sa_headers,
                )
            ).json()["status"] == "error"
            assert (
                await client.post(
                    f"/account/{acct_id}/client/dev-1/command/get-config",
                    headers=sa_headers,
                )
            ).json()["status"] == "error"
            assert (
                await client.post(
                    f"/account/{acct_id}/client/dev-1/command/send-notification",
                    json={"MessageMask": "T", "MessageContent": "C"},
                    headers=sa_headers,
                )
            ).json()["status"] == "error"
            assert (
                await client.post(
                    f"/account/{acct_id}/broadcast/notification",
                    json={"MessageMask": "T", "MessageContent": "C"},
                    headers=sa_headers,
                )
            ).json()["status"] == "error"

        # Audit logs list, filter, clear, and credentials/encode
        assert (
            await client.get(
                f"/account/{acct_id}/audit/list",
                params={"client_uid": "dev-1", "event": 1},
                headers=sa_headers,
            )
        ).status_code == 200
        assert (
            await client.get(f"/account/{acct_id}/audit/list", headers=sa_headers)
        ).status_code == 200
        assert (
            await client.delete(f"/account/{acct_id}/audit/clear", headers=sa_headers)
        ).status_code == 200

        r_enc = await client.post(
            f"/account/{acct_id}/credentials/encode",
            json={"password": "MyPassword123"},
            headers=sa_headers,
        )
        assert r_enc.status_code == 200
        assert r_enc.json()["credential"] != ""

        # 7. Resource CRUD (create, list, get, write, patch, token, delete, batch)
        # Create
        assert (
            await client.post(
                f"/account/{acct_id}/InvalidRes/create",
                params={"name": "x"},
                headers=sa_headers,
            )
        ).json()["status"] == "error"
        assert (
            await client.post(
                f"/account/{acct_id}/Subjects/create",
                params={"name": "custom_sub"},
                headers=sa_headers,
            )
        ).json()["status"] == "success"
        assert (
            await client.post(
                f"/account/{acct_id}/Subjects/create",
                params={"name": "custom_sub"},
                headers=sa_headers,
            )
        ).json()["status"] == "error"

        # List
        assert (
            await client.get(f"/account/{acct_id}/InvalidRes/list", headers=sa_headers)
        ).status_code == 400
        assert (
            "custom_sub"
            in (
                await client.get(
                    f"/account/{acct_id}/Subjects/list", headers=sa_headers
                )
            ).json()
        )

        # Write (new, existing, Credentials, InvalidRes, version conflict)
        assert (
            await client.post(
                f"/account/{acct_id}/InvalidRes/write",
                params={"name": "x"},
                json={},
                headers=sa_headers,
            )
        ).json()["status"] == "error"
        assert (
            await client.post(
                f"/account/{acct_id}/Credentials/write",
                params={"name": "new_cred"},
                json={"UserCredential": "Plain123"},
                headers=sa_headers,
            )
        ).json()["status"] == "success"
        assert (
            await client.put(
                f"/account/{acct_id}/Subjects/write",
                params={"name": "custom_sub", "version": 999},
                json={"Subjects": {}},
                headers=sa_headers,
            )
        ).status_code == 409

        # Patch (InvalidRes, missing file, Credentials merge, nested merge)
        assert (
            await client.patch(
                f"/account/{acct_id}/InvalidRes/update",
                params={"name": "x"},
                json={},
                headers=sa_headers,
            )
        ).json()["status"] == "error"
        assert (
            await client.patch(
                f"/account/{acct_id}/Subjects/update",
                params={"name": "missing_file"},
                json={},
                headers=sa_headers,
            )
        ).json()["status"] == "error"
        assert (
            await client.patch(
                f"/account/{acct_id}/Credentials/update",
                params={"name": "new_cred"},
                json={"AdminCredential": "AdminPlain"},
                headers=sa_headers,
            )
        ).json()["status"] == "success"
        assert (
            await client.patch(
                f"/account/{acct_id}/Subjects/update",
                params={"name": "custom_sub"},
                json={"Subjects": {"nested": {"Name": "A"}}},
                headers=sa_headers,
            )
        ).json()["status"] == "success"
        assert (
            await client.patch(
                f"/account/{acct_id}/Subjects/update",
                params={"name": "custom_sub"},
                json={"Subjects": {"nested": {"TeacherName": "B"}}},
                headers=sa_headers,
            )
        ).json()["status"] == "success"

        # Token
        assert (
            await client.get(
                f"/account/{acct_id}/InvalidRes/token",
                params={"name": "x"},
                headers=sa_headers,
            )
        ).json()["status"] == "error"
        assert (
            await client.get(
                f"/account/{acct_id}/Subjects/token",
                params={"name": "missing"},
                headers=sa_headers,
            )
        ).json()["status"] == "error"
        assert (
            "token"
            in (
                await client.get(
                    f"/account/{acct_id}/Subjects/token",
                    params={"name": "custom_sub"},
                    headers=sa_headers,
                )
            ).json()
        )

        # Get content directly
        assert (
            await client.get(
                f"/account/{acct_id}/InvalidRes/custom_sub", headers=sa_headers
            )
        ).status_code == 400
        assert (
            await client.get(
                f"/account/{acct_id}/Subjects/missing_sub", headers=sa_headers
            )
        ).status_code == 404
        assert (
            await client.get(
                f"/account/{acct_id}/Subjects/custom_sub", headers=sa_headers
            )
        ).status_code == 200

        # Corrupted content in DB -> patch resets to {}, get raises 500
        async with AsyncSessionLocal() as db:
            db.add(
                CPFile(
                    account_id=acct_id,
                    name="corrupt_cp",
                    content="{bad_json",
                    version=1,
                    updated_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()

        assert (
            await client.get(
                f"/account/{acct_id}/ClassPlan/corrupt_cp", headers=sa_headers
            )
        ).status_code == 500
        assert (
            await client.patch(
                f"/account/{acct_id}/ClassPlan/update",
                params={"name": "corrupt_cp"},
                json={"ClassPlans": {}},
                headers=sa_headers,
            )
        ).json()["status"] == "success"

        # Account batch operations
        assert (
            await client.post(
                f"/account/{acct_id}/batch",
                json={
                    "operations": [
                        {
                            "action": "write",
                            "resource_type": "Subjects",
                            "name": "b_sub",
                            "payload": {},
                        }
                    ]
                },
                headers=sa_headers,
            )
        ).status_code == 200

        # Delete resource
        assert (
            await client.delete(
                f"/account/{acct_id}/InvalidRes/delete",
                params={"name": "x"},
                headers=sa_headers,
            )
        ).json()["status"] == "error"
        assert (
            await client.delete(
                f"/account/{acct_id}/Subjects/delete",
                params={"name": "missing"},
                headers=sa_headers,
            )
        ).json()["status"] == "error"
        assert (
            await client.delete(
                f"/account/{acct_id}/Subjects/delete",
                params={"name": "custom_sub"},
                headers=sa_headers,
            )
        ).json()["status"] == "success"

        # 8. Delete (deactivate) account: non-owner -> 403, owner -> 200
        assert (
            await client.delete(f"/account/{acct_id}", headers=norm_headers)
        ).status_code == 403
        assert (
            await client.delete(f"/account/{acct_id}", headers=sa_headers)
        ).status_code == 200


@pytest.mark.asyncio
async def test_management_account_direct_helpers_and_edge_branches(
    test_superadmin_user,
):
    """Test helper functions and defensive edge cases in app/management/account.py directly."""
    # 1. Payload depth and size limits
    deep: dict = {}
    cur = deep
    for _ in range(15):
        cur["a"] = {}
        cur = cur["a"]
    with pytest.raises(HTTPException) as exc_depth:
        account.validate_payload(deep)
    assert exc_depth.value.status_code == 400

    account._check_depth([[{"a": 1}]])

    large = {"data": "x" * (600 * 1024)}
    with pytest.raises(HTTPException) as exc_size:
        account.validate_payload(large)
    assert exc_size.value.status_code == 400

    # 2. _enrich_members empty, _profile_to_dict(None), & _prereg_out invalid json
    assert account._profile_to_dict(None)["class_plan"] == "default"
    async with AsyncSessionLocal() as db:
        assert await account._enrich_members([], db) == []
        bad_prereg = PreRegisteredClient(
            id="p-bad",
            account_id="a",
            label="L",
            class_identity="C",
            preset_profile_json="{bad-json",
            created_at=datetime.now(timezone.utc),
        )
        out = account._prereg_out(bad_prereg)
        assert out.preset_profile == {}

        # 3. Direct calls to endpoints where account was deleted after middleware check
        with pytest.raises(HTTPException) as exc_q_403:
            await account.set_account_quota_mgmt(
                "missing-id",
                account.QuotaSetRequest(quota_key="max_clients", max_value=10),
                db,
                "non-existent-user",
            )
        assert exc_q_403.value.status_code == 403
        with pytest.raises(HTTPException):
            await account.get_account_info("missing-id", db, test_superadmin_user)
        with pytest.raises(HTTPException) as exc_slug_403:
            await account.change_slug(
                "missing-id",
                account.SlugUpdate(slug="valid-slug"),
                db,
                "non-existent-user",
            )
        assert exc_slug_403.value.status_code == 403
        with pytest.raises(HTTPException):
            await account.change_slug(
                "missing-id",
                account.SlugUpdate(slug="valid-slug"),
                db,
                test_superadmin_user,
            )
        with pytest.raises(HTTPException):
            await account.change_account_name(
                "missing-id", account.AccountNameUpdate(name="Name"), db
            )
        with pytest.raises(HTTPException):
            await account.regenerate_account_api_key("missing-id", db)
        with pytest.raises(HTTPException):
            await account.download_account_preset("missing-id", "", db)
        with pytest.raises(HTTPException):
            await account.set_registration_mode("missing-id", {"mode": "open"}, db)
        with pytest.raises(HTTPException):
            await account.download_preset("missing-id", "pre-id", db)

        # Deactivate account when AccountMember exists as owner, but Account row is missing (line 231)
        db.add(
            account.AccountMember(
                id="mem-ghost-owner",
                account_id="ghost-acct-id",
                user_id=test_superadmin_user,
                role_in_account="owner",
                joined_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()
        with pytest.raises(HTTPException):
            await account.delete_account("ghost-acct-id", db, test_superadmin_user)

        # change_slug when update_account_slug returns None (line 284)
        with (
            patch(
                "app.management.account.update_account_slug",
                new_callable=AsyncMock,
                return_value=None,
            ),
            pytest.raises(HTTPException),
        ):
            await account.change_slug(
                "ghost-acct-id",
                account.SlugUpdate(slug="valid-slug"),
                db,
                test_superadmin_user,
            )

        # _serialize_clients and broadcast_notification when get_all_clients_status(account_id) is empty (lines 1540, 2341)
        mock_sm_empty = MagicMock()
        mock_sm_empty.get_all_clients_status = AsyncMock(return_value=[])
        mock_srv_ok = MagicMock()
        mock_srv_ok.send_command = AsyncMock(return_value=True)
        with (
            patch(
                "app.management.account.get_session_manager",
                return_value=mock_sm_empty,
            ),
            patch(
                "app.management.account.get_command_servicer",
                return_value=mock_srv_ok,
            ),
        ):
            await account._serialize_clients("ghost-acct-id", [], MagicMock(), db)
            await account.broadcast_notify(
                "ghost-acct-id",
                MagicMock(),
                account.BroadcastNotificationPayload(
                    MessageMask="M", MessageContent="C"
                ),
            )
