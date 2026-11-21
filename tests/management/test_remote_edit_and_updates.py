"""Tests for RemoteEdit, AssistAnother pure relay, selective DataUpdated sync, quotas, and disabled email updates."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.client.app import client_app
from app.management.app import management_app
from app.Protobuf.Enum import CommandTypes_pb2
from app.shared.db.models import (
    Account,
    AccountMember,
    CPFile,
    ClientProfile,
    ClientRecord,
    ConfigUploadRecord,
    PolicyFile,
    ResourceHistory,
    SubFile,
    TLFile,
)
from app.shared.db.session import AsyncSessionLocal
from app.shared.literals import DEFAULT_QUOTAS
from app.shared.security.auth import create_session_token
from app.shared.services.quota import check_quota, set_quota
from app.shared.services.sse import stream_account_events
from app.shared.services.user import register_user
from app.shared.utils.config import BASE_DOMAIN
from app.shared.utils.redis import close_redis


class FakeSessionManager:
    def __init__(self, online_pairs: set[tuple[str, str]]) -> None:
        self.online_pairs = set(online_pairs)

    async def is_client_online(self, account_id: str, client_uid: str) -> bool:
        return (account_id, client_uid) in self.online_pairs

    async def get_all_clients_status(self, account_id: str) -> list[dict[str, Any]]:
        return [{"uid": uid} for acct, uid in self.online_pairs if acct == account_id]

    def build_signed_command_envelope(
        self,
        *,
        request_guid: str,
        client_uid: str,
        action: str,
        payload: dict[str, Any],
        ttl_seconds: int = 120,
    ) -> dict[str, Any]:
        return {
            "requestGuid": request_guid,
            "clientUid": client_uid,
            "action": action,
            "payloadJson": json.dumps(payload, ensure_ascii=False),
            "ttlSeconds": ttl_seconds,
            "signature": "test-sig",
        }


SUBJECT_GUID = "11111111-1111-4111-8111-111111111111"


class FakeCommandServicer:
    def __init__(self, capture_response_data: dict[str, Any] | None = None) -> None:
        self.sent: list[tuple[str, str, int, Any]] = []
        self.capture_response_data = capture_response_data or {
            "Subjects": {"Subjects": {"sub-live": {"Name": "PhysicsLive"}}},
            "DefaultSettings": {"Theme": 2},
        }

    async def send_command(self, account_id: str, client_uid: str, cmd: Any) -> bool:
        payload_dict: Any = None
        if getattr(cmd, "Payload", b""):
            try:
                payload_dict = json.loads(cmd.Payload.decode("utf-8"))
            except Exception:
                payload_dict = cmd.Payload
        self.sent.append((account_id, client_uid, int(cmd.Type), payload_dict))

        if (
            isinstance(payload_dict, dict)
            and payload_dict.get("action") == "assist.capture_snapshot"
        ):
            req_guid = payload_dict["requestGuid"]
            wrapped = json.dumps(
                {
                    "requestGuid": req_guid,
                    "clientUid": client_uid,
                    "action": "assist.capture_snapshot",
                    "success": True,
                    "code": "OK",
                    "message": "Success",
                    "respondedAtUtc": int(datetime.now(timezone.utc).timestamp()),
                    "data": self.capture_response_data,
                    "integritySha256": "deadbeef",
                },
                ensure_ascii=False,
            )

            async def _complete_upload() -> None:
                await asyncio.sleep(0.05)
                async with AsyncSessionLocal() as poll_db:
                    rec = (
                        await poll_db.execute(
                            select(ConfigUploadRecord).where(
                                ConfigUploadRecord.request_guid == req_guid
                            )
                        )
                    ).scalar_one_or_none()
                    if rec is not None:
                        rec.status = "completed"
                        rec.payload = wrapped
                        await poll_db.commit()

            asyncio.create_task(_complete_upload())
        return True


@pytest.mark.asyncio
async def test_default_disabled_quotas_and_email_lock():
    quota_dict = dict(DEFAULT_QUOTAS)
    assert quota_dict["feature.remote_edit"] == 0
    assert quota_dict["feature.assist_another"] == 0

    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        acct = Account(
            id="acct-quota-test",
            name="Quota School",
            slug="quota-school",
            api_key="k-quota",
            is_active=True,
            created_at=now,
        )
        db.add(acct)
        await db.commit()

        # Even without seeded rows, both new features must be default-denied
        assert await check_quota("acct-quota-test", "feature.remote_edit", db) is False
        assert (
            await check_quota("acct-quota-test", "feature.assist_another", db) is False
        )

        await set_quota("acct-quota-test", "feature.remote_edit", 1, db)
        assert await check_quota("acct-quota-test", "feature.remote_edit", db) is True


@pytest.mark.asyncio
async def test_selective_sync_remote_edit_and_pure_relay_assist_another():
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        owner = await register_user(
            "owner_re@school.com",
            "OwnerPass123!",
            "Owner RE",
            db,
            username="owner_re",
            role_code="normal",
            is_active=True,
            can_create_account=True,
        )
        member = await register_user(
            "member_re@school.com",
            "MemberPass123!",
            "Member RE",
            db,
            username="member_re",
            role_code="normal",
            is_active=True,
            can_create_account=False,
        )
        acct = Account(
            id="acct-re",
            name="Remote Edit School",
            slug="re-school",
            api_key="k-re",
            is_active=True,
            created_at=now,
        )
        db.add_all(
            [
                acct,
                AccountMember(
                    user_id=owner.id,
                    account_id="acct-re",
                    role_in_account="owner",
                    joined_at=now,
                ),
                AccountMember(
                    user_id=member.id,
                    account_id="acct-re",
                    role_in_account="member",
                    joined_at=now,
                ),
                ClientRecord(
                    uid="client-a",
                    account_id="acct-re",
                    client_id="Room-A",
                    display_name="Teacher Desk A",
                    is_disabled=False,
                    extend_management_enabled=True,
                    extend_management_version="2.0.0.4",
                    is_app_locked=False,
                    registered_at=now,
                ),
                ClientRecord(
                    uid="client-b",
                    account_id="acct-re",
                    client_id="Room-B",
                    display_name="Classroom B",
                    is_disabled=False,
                    extend_management_enabled=True,
                    extend_management_version="2.0.0.4",
                    is_app_locked=False,
                    registered_at=now,
                ),
                ClientRecord(
                    uid="client-plain",
                    account_id="acct-re",
                    client_id="Room-Plain",
                    display_name="No MEE",
                    is_disabled=False,
                    extend_management_enabled=False,
                    registered_at=now,
                ),
                ClientProfile(
                    account_id="acct-re",
                    client_id="client-a",
                    subjects="custom_sub",
                    updated_at=now,
                ),
                ClientProfile(
                    account_id="acct-re",
                    client_id="client-b",
                    subjects="other_sub",
                    updated_at=now,
                ),
                SubFile(
                    account_id="acct-re",
                    name="custom_sub",
                    content=json.dumps({"Subjects": {SUBJECT_GUID: {"Name": "Math"}}}),
                    version=1,
                    updated_at=now,
                ),
                PolicyFile(
                    account_id="acct-re",
                    name="default",
                    content=json.dumps({"DisableProfileEditing": False}),
                    version=1,
                    updated_at=now,
                ),
            ]
        )
        await db.commit()
        owner_id = owner.id
        member_id = member.id

    owner_token = await create_session_token(owner_id)
    member_token = await create_session_token(member_id)
    owner_headers = {"Authorization": f"Bearer {owner_token}"}
    member_headers = {"Authorization": f"Bearer {member_token}"}

    sm = FakeSessionManager(
        {("acct-re", "client-a"), ("acct-re", "client-b"), ("acct-re", "client-plain")}
    )
    servicer = FakeCommandServicer()

    old_mgmt_sm = getattr(management_app.state, "session_manager", None)
    old_mgmt_sv = getattr(management_app.state, "command_servicer", None)
    old_cli_sm = getattr(client_app.state, "session_manager", None)
    old_cli_sv = getattr(client_app.state, "command_servicer", None)
    management_app.state.session_manager = sm
    management_app.state.command_servicer = servicer
    client_app.state.session_manager = sm
    client_app.state.command_servicer = servicer

    try:
        mgmt_transport = ASGITransport(app=management_app)
        cli_transport = ASGITransport(app=client_app)
        tenant_cli_headers = {"Host": f"re-school.{BASE_DOMAIN}"}

        async with (
            AsyncClient(transport=mgmt_transport, base_url="http://test") as mgmt,
            AsyncClient(transport=cli_transport, base_url="http://test") as cli,
        ):
            # 1. Quota disabled -> 403
            r_denied = await mgmt.post(
                "/account/acct-re/edit-session/create",
                json={
                    "mode": "RemoteEdit",
                    "editor_client_uid": "client-a",
                    "initial_view": "profile",
                    "resource_targets": {"Subjects": "custom_sub"},
                },
                headers=owner_headers,
            )
            assert r_denied.status_code == 403

            # Enable both feature quotas
            async with AsyncSessionLocal() as db:
                await set_quota("acct-re", "feature.remote_edit", 1, db)
                await set_quota("acct-re", "feature.assist_another", 1, db)

            # 2. Selective DataUpdated on /write?sync=true vs sync=false
            servicer.sent.clear()
            r_nosync = await mgmt.post(
                "/account/acct-re/Subjects/write",
                params={"name": "custom_sub"},
                json={"Subjects": {SUBJECT_GUID: {"Name": "Math v2"}}},
                headers=owner_headers,
            )
            assert r_nosync.status_code == 200
            assert r_nosync.json()["version"] == 2
            assert len(servicer.sent) == 0

            r_sync = await mgmt.post(
                "/account/acct-re/Subjects/write",
                params={"name": "custom_sub", "sync": "true"},
                json={"Subjects": {SUBJECT_GUID: {"Name": "Math v3"}}},
                headers=owner_headers,
            )
            assert r_sync.status_code == 200
            assert r_sync.json()["version"] == 3
            assert r_sync.json()["sync"] == {
                "matched_clients": 1,
                "notified_clients": 1,
            }
            assert [item[1] for item in servicer.sent] == ["client-a"]
            assert servicer.sent[0][2] == CommandTypes_pb2.DataUpdated

            # 3. Member RBAC cannot open or sync Policy/Credentials
            r_mem_forbidden = await mgmt.post(
                "/account/acct-re/edit-session/create",
                json={
                    "mode": "RemoteEdit",
                    "editor_client_uid": "client-a",
                    "initial_view": "policy",
                },
                headers=member_headers,
            )
            assert r_mem_forbidden.status_code == 403

            # 4. Non-MEE client rejected as editor
            r_no_mee = await mgmt.post(
                "/account/acct-re/edit-session/create",
                json={
                    "mode": "RemoteEdit",
                    "editor_client_uid": "client-plain",
                    "initial_view": "profile",
                },
                headers=owner_headers,
            )
            assert r_no_mee.status_code == 400

            # 5. RemoteEdit end-to-end flow: create -> bootstrap -> sync -> 409 conflict -> close
            servicer.sent.clear()
            r_re_create = await mgmt.post(
                "/account/acct-re/edit-session/create",
                json={
                    "mode": "RemoteEdit",
                    "editor_client_uid": "client-a",
                    "initial_view": "profile",
                    "resource_targets": {"Subjects": "custom_sub"},
                },
                headers=owner_headers,
            )
            assert r_re_create.status_code == 200
            re_session_id = r_re_create.json()["session"]["session_id"]
            assert len(servicer.sent) == 1
            open_env = servicer.sent[0][3]
            assert open_env["action"] == "edit_session.open"
            re_token = json.loads(open_env["payloadJson"])["token"]

            r_boot = await cli.get(
                f"/api/v1/client/client-a/edit-session/{re_session_id}/bootstrap",
                headers={**tenant_cli_headers, "X-Edit-Session-Token": re_token},
            )
            assert r_boot.status_code == 200
            boot_data = r_boot.json()
            assert boot_data["mode"] == "RemoteEdit"
            assert boot_data["versions"]["Subjects"] == 3
            assert (
                boot_data["resources"]["Subjects"]["Subjects"][SUBJECT_GUID]["Name"]
                == "Math v3"
            )

            servicer.sent.clear()
            r_sync_re = await cli.post(
                f"/api/v1/client/client-a/edit-session/{re_session_id}/sync",
                json={
                    "changes": {
                        "Subjects": {
                            "Subjects": {SUBJECT_GUID: {"Name": "Math RemoteEdited"}}
                        }
                    },
                    "base_versions": {"Subjects": 3},
                    "notify_clients": True,
                    "sequence": 1,
                },
                headers={**tenant_cli_headers, "X-Edit-Session-Token": re_token},
            )
            assert r_sync_re.status_code == 200
            assert r_sync_re.json()["versions"]["Subjects"] == 4
            assert r_sync_re.json()["sync"]["Subjects"] == {
                "matched_clients": 1,
                "notified_clients": 1,
            }
            assert [item[1] for item in servicer.sent] == ["client-a"]

            # Stale base_version triggers 409 conflict
            r_conflict = await cli.post(
                f"/api/v1/client/client-a/edit-session/{re_session_id}/sync",
                json={
                    "changes": {
                        "Subjects": {"Subjects": {SUBJECT_GUID: {"Name": "Stale"}}}
                    },
                    "base_versions": {"Subjects": 2},
                    "sequence": 2,
                },
                headers={**tenant_cli_headers, "X-Edit-Session-Token": re_token},
            )
            assert r_conflict.status_code == 409

            r_close_re = await cli.post(
                f"/api/v1/client/client-a/edit-session/{re_session_id}/close",
                headers={**tenant_cli_headers, "X-Edit-Session-Token": re_token},
            )
            assert r_close_re.status_code == 200

            # 6. AssistAnother pure E2E relay: NEVER mutates DB Resource or ClientProfile tables
            async with AsyncSessionLocal() as db:
                sub_before = (
                    await db.execute(
                        select(SubFile).where(
                            SubFile.account_id == "acct-re",
                            SubFile.name == "custom_sub",
                        )
                    )
                ).scalar_one()
                version_before = sub_before.version
                content_before = sub_before.content

            servicer.sent.clear()
            r_aa_create = await mgmt.post(
                "/account/acct-re/edit-session/create",
                json={
                    "mode": "AssistAnother",
                    "editor_client_uid": "client-a",
                    "target_client_uid": "client-b",
                    "initial_view": "settings",
                },
                headers=owner_headers,
            )
            assert r_aa_create.status_code == 200
            aa_session_id = r_aa_create.json()["session"]["session_id"]
            assert servicer.sent[0][1] == "client-b"
            assert servicer.sent[0][3]["action"] == "assist.capture_snapshot"
            assert servicer.sent[1][1] == "client-a"
            assert servicer.sent[1][3]["action"] == "edit_session.open"
            aa_token = json.loads(servicer.sent[1][3]["payloadJson"])["token"]

            r_aa_boot = await cli.get(
                f"/api/v1/client/client-a/edit-session/{aa_session_id}/bootstrap",
                headers={**tenant_cli_headers, "X-Edit-Session-Token": aa_token},
            )
            assert r_aa_boot.status_code == 200
            assert (
                r_aa_boot.json()["snapshot"]["Subjects"]["Subjects"]["sub-live"]["Name"]
                == "PhysicsLive"
            )

            servicer.sent.clear()
            r_aa_sync = await cli.post(
                f"/api/v1/client/client-a/edit-session/{aa_session_id}/sync",
                json={
                    "changes": {"DefaultSettings": {"Theme": 1}},
                    "sequence": 1,
                },
                headers={**tenant_cli_headers, "X-Edit-Session-Token": aa_token},
            )
            assert r_aa_sync.status_code == 200
            assert r_aa_sync.json()["relayed_scopes"] == ["DefaultSettings"]
            assert len(servicer.sent) == 1
            assert servicer.sent[0][1] == "client-b"
            assert servicer.sent[0][3]["action"] == "assist.apply_snapshot"

            # Verify DB resources untouched by AssistAnother
            async with AsyncSessionLocal() as db:
                sub_after = (
                    await db.execute(
                        select(SubFile).where(
                            SubFile.account_id == "acct-re",
                            SubFile.name == "custom_sub",
                        )
                    )
                ).scalar_one()
                assert sub_after.version == version_before
                assert sub_after.content == content_before
                hist_count = len(
                    (
                        await db.execute(
                            select(ResourceHistory).where(
                                ResourceHistory.account_id == "acct-re",
                                ResourceHistory.resource_type == "Subjects",
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                assert hist_count >= 1
    finally:
        management_app.state.session_manager = old_mgmt_sm
        management_app.state.command_servicer = old_mgmt_sv
        client_app.state.session_manager = old_cli_sm
        client_app.state.command_servicer = old_cli_sv


@pytest.mark.asyncio
async def test_granular_remote_edit_classplan_scope_and_sse():
    """Verify initial_view='classplan' restricts write scope while exposing read-only context and emitting SSE."""
    now = datetime.now(timezone.utc)
    cp_guid = "22222222-2222-4222-8222-222222222222"
    tl_guid = "33333333-3333-4333-8333-333333333333"
    try:
        async with AsyncSessionLocal() as db:
            owner = await register_user(
                "owner_gran@school.com",
                "OwnerPass123!",
                "Owner Granular",
                db,
                username="owner_gran",
                role_code="normal",
                is_active=True,
                can_create_account=True,
            )
            db.add_all(
                [
                    Account(
                        id="acct-re-gran",
                        name="Granular RE School",
                        slug="re-gran-school",
                        api_key="k-re-gran",
                        is_active=True,
                        created_at=now,
                    ),
                    AccountMember(
                        user_id=owner.id,
                        account_id="acct-re-gran",
                        role_in_account="owner",
                        joined_at=now,
                    ),
                    ClientRecord(
                        uid="client-g",
                        account_id="acct-re-gran",
                        client_id="Room-G",
                        display_name="Room G",
                        is_disabled=False,
                        extend_management_enabled=True,
                        extend_management_version="2.0.0.4",
                        is_app_locked=False,
                        registered_at=now,
                    ),
                    ClientProfile(
                        account_id="acct-re-gran",
                        client_id="client-g",
                        subjects="default",
                        time_layout="default",
                        class_plan="custom_cp",
                        updated_at=now,
                    ),
                    SubFile(
                        account_id="acct-re-gran",
                        name="default",
                        content=json.dumps(
                            {"Subjects": {SUBJECT_GUID: {"Name": "Math"}}}
                        ),
                        version=1,
                        updated_at=now,
                    ),
                    TLFile(
                        account_id="acct-re-gran",
                        name="default",
                        content=json.dumps(
                            {"TimeLayouts": {tl_guid: {"Name": "Standard"}}}
                        ),
                        version=1,
                        updated_at=now,
                    ),
                    CPFile(
                        account_id="acct-re-gran",
                        name="custom_cp",
                        content=json.dumps(
                            {
                                "ClassPlans": {
                                    cp_guid: {
                                        "Name": "Monday",
                                        "TimeLayoutId": tl_guid,
                                        "Classes": [],
                                    }
                                }
                            }
                        ),
                        version=1,
                        updated_at=now,
                    ),
                ]
            )
            await db.commit()
            await set_quota("acct-re-gran", "feature.remote_edit", 1, db)

        owner_token = await create_session_token(owner.id)
        owner_headers = {"Authorization": f"Bearer {owner_token}"}
        sm = FakeSessionManager({("acct-re-gran", "client-g")})
        servicer = FakeCommandServicer()

        old_mgmt_sm = getattr(management_app.state, "session_manager", None)
        old_mgmt_sv = getattr(management_app.state, "command_servicer", None)
        old_cli_sm = getattr(client_app.state, "session_manager", None)
        old_cli_sv = getattr(client_app.state, "command_servicer", None)
        management_app.state.session_manager = sm
        management_app.state.command_servicer = servicer
        client_app.state.session_manager = sm
        client_app.state.command_servicer = servicer

        try:
            tenant_cli_headers = {"Host": f"re-gran-school.{BASE_DOMAIN}"}
            async with (
                AsyncClient(
                    transport=ASGITransport(app=management_app), base_url="http://test"
                ) as mgmt,
                AsyncClient(
                    transport=ASGITransport(app=client_app), base_url="http://test"
                ) as cli,
            ):
                r_create = await mgmt.post(
                    "/account/acct-re-gran/edit-session/create",
                    json={
                        "mode": "RemoteEdit",
                        "editor_client_uid": "client-g",
                        "initial_view": "classplan",
                        "resource_targets": {"ClassPlan": "custom_cp"},
                    },
                    headers=owner_headers,
                )
                assert r_create.status_code == 200, r_create.text
                sess = r_create.json()["session"]
                assert sess["initial_view"] == "classplan"
                assert sess["allowed_scopes"] == ["ClassPlan"]
                re_token = json.loads(servicer.sent[-1][3]["payloadJson"])["token"]
                sid = sess["session_id"]

                # Bootstrap includes ClassPlan plus read-only TimeLayout & Subjects context
                r_boot = await cli.get(
                    f"/api/v1/client/client-g/edit-session/{sid}/bootstrap",
                    headers={**tenant_cli_headers, "X-Edit-Session-Token": re_token},
                )
                assert r_boot.status_code == 200, r_boot.text
                boot = r_boot.json()
                assert boot["allowed_scopes"] == ["ClassPlan"]
                assert "ClassPlan" in boot["resources"]
                assert "TimeLayout" in boot["resources"]
                assert "Subjects" in boot["resources"]
                assert set(boot["versions"].keys()) == {"ClassPlan"}

                # Mutating outside allowed_scopes is rejected with 403
                r_forbid = await cli.post(
                    f"/api/v1/client/client-g/edit-session/{sid}/sync",
                    json={
                        "changes": {
                            "Subjects": {"Subjects": {SUBJECT_GUID: {"Name": "Hack"}}}
                        },
                        "sequence": 1,
                    },
                    headers={**tenant_cli_headers, "X-Edit-Session-Token": re_token},
                )
                assert r_forbid.status_code == 403

                # Collect SSE events emitted when syncing allowed ClassPlan scope
                raw_chunks: list[bytes] = []

                async def _consume() -> None:
                    async for chunk in stream_account_events(
                        "acct-re-gran",
                        max_events=3,
                        max_duration_seconds=3.0,
                        keepalive_seconds=5.0,
                    ):
                        raw_chunks.append(chunk)

                consumer = asyncio.create_task(_consume())
                await asyncio.sleep(0.05)

                r_ok = await cli.post(
                    f"/api/v1/client/client-g/edit-session/{sid}/sync",
                    json={
                        "changes": {
                            "ClassPlan": {
                                "ClassPlans": {
                                    cp_guid: {
                                        "Name": "Tuesday",
                                        "TimeLayoutId": tl_guid,
                                        "Classes": [],
                                    }
                                }
                            }
                        },
                        "base_versions": {"ClassPlan": 1},
                        "notify_clients": False,
                        "sequence": 2,
                    },
                    headers={**tenant_cli_headers, "X-Edit-Session-Token": re_token},
                )
                assert r_ok.status_code == 200, r_ok.text
                assert r_ok.json()["versions"]["ClassPlan"] == 2

                await asyncio.wait_for(consumer, timeout=3.5)
                joined = b"".join(raw_chunks).decode("utf-8")
                assert "event: edit_session.updated" in joined
                assert "event: resource.updated" in joined
                assert '"updated_resources"' in joined
                assert '"custom_cp"' in joined
        finally:
            management_app.state.session_manager = old_mgmt_sm
            management_app.state.command_servicer = old_mgmt_sv
            client_app.state.session_manager = old_cli_sm
            client_app.state.command_servicer = old_cli_sv
    finally:
        await close_redis()
