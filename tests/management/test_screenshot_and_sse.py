"""Tests for 1 MiB chunked REST screenshot uploads and authenticated web SSE streams."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import json
import os
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
import pytest
from sqlalchemy import select
from starlette.datastructures import Headers

from app.Protobuf.Enum import Retcode_pb2
from app.admin.app import admin_app
from app.client.api import _parse_int_param
from app.client.app import client_app
from app.grpc.server import ConfigUploadServicer
from app.management.app import management_app
from app.shared.db.models import (
    Account,
    AccountMember,
    ClientRecord,
    ConfigUploadRecord,
    PairingCode,
)
from app.shared.db.session import AsyncSessionLocal
from app.shared.security.auth import (
    authorize_qr_login_challenge,
    create_session_token,
)
from app.shared.services.quota import set_quota
from app.shared.services.screenshot_upload import (
    MAX_SCREENSHOT_BYTES,
    MAX_SCREENSHOT_CHUNKS,
    SCREENSHOT_CHUNK_SIZE_BYTES,
    _BLOB_KEY_PREFIX,
    _META_KEY_PREFIX,
    _TOKEN_KEY_PREFIX,
    _detect_image_mime,
    _verify_upload_token,
    extract_upload_token_from_request,
    finalize_screenshot_upload,
    get_screenshot_blob,
    issue_screenshot_upload_token,
    store_screenshot_chunk,
)
from app.shared.services.sse import (
    _INSTANCE_ID,
    _MAX_QUEUE_SIZE,
    _SUBSCRIBERS,
    _dispatch_local,
    _redis_relay_loop,
    format_sse_frame,
    publish_account_event,
    publish_topic_event,
    stream_account_events,
)
from app.shared.services.user import ensure_system_roles, register_user
from app.shared.utils.config import BASE_DOMAIN, REDIS_DB_SESSION
from app.shared.utils.redis import close_redis, get_binary_redis, get_redis


class FakeSessionManager:
    def __init__(self, online_pairs: set[tuple[str, str]]) -> None:
        self.online_pairs = set(online_pairs)
        self.public_key_armor = "test-pub-key"

    async def is_client_online(self, account_id: str, client_uid: str) -> bool:
        return (account_id, client_uid) in self.online_pairs

    async def get_all_clients_status(self, account_id: str) -> list[dict[str, Any]]:
        return [{"uid": uid} for acct, uid in self.online_pairs if acct == account_id]

    async def validate_session(self, sid: str) -> str | None:
        return None

    async def get_session_tenant(self, sid: str) -> str | None:
        return None

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


class FakeCommandServicer:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str, int, Any]] = []

    async def send_command(self, account_id: str, client_uid: str, cmd: Any) -> bool:
        payload_dict: Any = None
        if getattr(cmd, "Payload", b""):
            try:
                payload_dict = json.loads(cmd.Payload.decode("utf-8"))
            except Exception:
                payload_dict = cmd.Payload
        self.sent.append((account_id, client_uid, int(cmd.Type), payload_dict))
        return True


def _parse_sse_frames(raw_bytes: bytes) -> list[tuple[str, dict[str, Any]]]:
    text = raw_bytes.decode("utf-8").replace("\r\n", "\n")
    frames: list[tuple[str, dict[str, Any]]] = []
    for block in text.split("\n\n"):
        if not block.strip():
            continue
        ev_name = ""
        data_lines: list[str] = []
        for line in block.split("\n"):
            if not line or line.startswith(":"):
                continue
            if line.startswith("event:"):
                ev_name = line.split(":", 1)[1].strip()
            elif line.startswith("data:"):
                data_lines.append(line.split(":", 1)[1].lstrip())
        if data_lines:
            frames.append((ev_name or "message", json.loads("\n".join(data_lines))))
    return frames


@pytest.mark.asyncio
async def test_remote_screenshot_chunked_rest_upload_and_download():
    now = datetime.now(timezone.utc)
    try:
        async with AsyncSessionLocal() as db:
            owner = await register_user(
                "owner_ss@school.com",
                "OwnerPass123!",
                "Owner SS",
                db,
                username="owner_ss",
                role_code="normal",
                is_active=True,
                can_create_account=True,
            )
            outsider = await register_user(
                "outsider_ss@school.com",
                "OutsiderPass123!",
                "Outsider SS",
                db,
                username="outsider_ss",
                role_code="normal",
                is_active=True,
                can_create_account=False,
            )
            db.add_all(
                [
                    Account(
                        id="acct-ss",
                        name="Screenshot School",
                        slug="ss-school",
                        api_key="k-ss",
                        is_active=True,
                        created_at=now,
                    ),
                    Account(
                        id="acct-other",
                        name="Other School",
                        slug="other-school",
                        api_key="k-other",
                        is_active=True,
                        created_at=now,
                    ),
                    AccountMember(
                        user_id=owner.id,
                        account_id="acct-ss",
                        role_in_account="owner",
                        joined_at=now,
                    ),
                    ClientRecord(
                        uid="client-ss-1",
                        account_id="acct-ss",
                        client_id="Room-SS-1",
                        display_name="Classroom SS 1",
                        ip="127.0.0.1",
                        is_disabled=False,
                        extend_management_enabled=True,
                        extend_management_version="2.0.0.4",
                        is_app_locked=False,
                        registered_at=now,
                    ),
                    ClientRecord(
                        uid="client-ss-2",
                        account_id="acct-ss",
                        client_id="Room-SS-2",
                        display_name="Classroom SS 2",
                        ip="127.0.0.2",
                        is_disabled=False,
                        extend_management_enabled=True,
                        extend_management_version="2.0.0.4",
                        is_app_locked=False,
                        registered_at=now,
                    ),
                ]
            )
            await db.commit()
            await set_quota("acct-ss", "feature.risk", 1, db)

        owner_token = await create_session_token(owner.id)
        outsider_token = await create_session_token(outsider.id)
        owner_headers = {"Authorization": f"Bearer {owner_token}"}
        outsider_headers = {"Authorization": f"Bearer {outsider_token}"}
        tenant_cli_headers = {"Host": f"ss-school.{BASE_DOMAIN}"}
        other_tenant_headers = {"Host": f"other-school.{BASE_DOMAIN}"}

        sm = FakeSessionManager(
            {("acct-ss", "client-ss-1"), ("acct-ss", "client-ss-2")}
        )
        servicer = FakeCommandServicer()
        prev_sm = getattr(management_app.state, "session_manager", None)
        prev_cs = getattr(management_app.state, "command_servicer", None)
        management_app.state.session_manager = sm
        management_app.state.command_servicer = servicer

        try:
            async with (
                AsyncClient(
                    transport=ASGITransport(app=management_app),
                    base_url="http://testserver",
                ) as mgmt_client,
                AsyncClient(
                    transport=ASGITransport(app=client_app),
                    base_url="http://testserver",
                ) as cli_client,
            ):
                # 1. Single remote.screenshot dispatch injects uploadToken, requestGuid, chunkSizeBytes
                r_disp = await mgmt_client.post(
                    "/account/acct-ss/client/client-ss-1/command/extend",
                    headers=owner_headers,
                    json={
                        "action": "remote.screenshot",
                        "payload": {"displayIndex": 0, "scale": 0.75},
                    },
                )
                assert r_disp.status_code == 200, r_disp.text
                req_guid = r_disp.json()["request_guid"]

                _, _, _, cmd_envelope = servicer.sent[-1]
                signed_payload = json.loads(cmd_envelope["payloadJson"])
                assert signed_payload["requestGuid"] == req_guid
                assert (
                    signed_payload["chunkSizeBytes"]
                    == SCREENSHOT_CHUNK_SIZE_BYTES
                    == 1_048_576
                )
                upload_token = signed_payload["uploadToken"]
                assert isinstance(upload_token, str) and len(upload_token) >= 24

                # 2. Broadcast remote.screenshot issues distinct per-client uploadTokens
                servicer.sent.clear()
                r_bcast = await mgmt_client.post(
                    "/account/acct-ss/client/broadcast/extend",
                    headers=owner_headers,
                    json={
                        "action": "remote.screenshot",
                        "payload": {"displayIndex": 0},
                    },
                )
                assert r_bcast.status_code == 200, r_bcast.text
                assert r_bcast.json()["sent_count"] == 2
                bcast_tokens = []
                bcast_guids = []
                for _, _, _, env in servicer.sent:
                    inner = json.loads(env["payloadJson"])
                    bcast_tokens.append(inner["uploadToken"])
                    bcast_guids.append(inner["requestGuid"])
                assert len(set(bcast_tokens)) == 2
                assert len(set(bcast_guids)) == 2

                # 3. Prepare a > 2.2 MiB valid PNG binary split into 1 MiB chunks
                png_bytes = b"\x89PNG\r\n\x1a\n" + os.urandom(2_359_296)
                chunks = [
                    png_bytes[i : i + SCREENSHOT_CHUNK_SIZE_BYTES]
                    for i in range(0, len(png_bytes), SCREENSHOT_CHUNK_SIZE_BYTES)
                ]
                assert len(chunks) == 3
                assert len(chunks[0]) == SCREENSHOT_CHUNK_SIZE_BYTES
                assert len(chunks[1]) == SCREENSHOT_CHUNK_SIZE_BYTES
                full_sha = hashlib.sha256(png_bytes).hexdigest()

                chunk_url = (
                    f"/api/v1/client/client-ss-1/screenshot-upload/{req_guid}/chunk"
                )
                complete_url = (
                    f"/api/v1/client/client-ss-1/screenshot-upload/{req_guid}/complete"
                )

                # 3a. Missing/invalid token -> 401
                r_unauth = await cli_client.put(
                    f"{chunk_url}?chunk_index=0&total_chunks=3",
                    headers={**tenant_cli_headers, "Authorization": "Bearer bad-token"},
                    content=chunks[0],
                )
                assert r_unauth.status_code == 401

                # 3b. Client UID mismatch -> 403
                r_wrong_cli = await cli_client.put(
                    f"/api/v1/client/client-ss-2/screenshot-upload/{req_guid}/chunk?chunk_index=0&total_chunks=3",
                    headers={
                        **tenant_cli_headers,
                        "Authorization": f"Bearer {upload_token}",
                    },
                    content=chunks[0],
                )
                assert r_wrong_cli.status_code == 403

                # 3c. Cross-tenant slug mismatch -> 403
                r_wrong_tenant = await cli_client.put(
                    f"{chunk_url}?chunk_index=0&total_chunks=3",
                    headers={
                        **other_tenant_headers,
                        "Authorization": f"Bearer {upload_token}",
                    },
                    content=chunks[0],
                )
                assert r_wrong_tenant.status_code == 403

                # 3d. Chunk SHA-256 mismatch -> 400
                r_bad_sha = await cli_client.put(
                    f"{chunk_url}?chunk_index=0&total_chunks=3",
                    headers={
                        **tenant_cli_headers,
                        "Authorization": f"Bearer {upload_token}",
                        "X-Chunk-Sha256": "0" * 64,
                    },
                    content=chunks[0],
                )
                assert r_bad_sha.status_code == 400

                # 3e. Chunk exceeding 1 MiB -> 413
                r_too_big = await cli_client.put(
                    f"{chunk_url}?chunk_index=0&total_chunks=3",
                    headers={
                        **tenant_cli_headers,
                        "Authorization": f"Bearer {upload_token}",
                    },
                    content=b"A" * (SCREENSHOT_CHUNK_SIZE_BYTES + 1),
                )
                assert r_too_big.status_code == 413

                # 4. Upload all 3 valid chunks (chunks 0-1 via query + Bearer; chunk 2 via headers only)
                for idx, chunk_data in enumerate(chunks):
                    if idx < 2:
                        r_up = await cli_client.put(
                            f"{chunk_url}?chunk_index={idx}&total_chunks=3",
                            headers={
                                **tenant_cli_headers,
                                "Authorization": f"Bearer {upload_token}",
                                "X-Chunk-Index": str(idx),
                                "X-Total-Chunks": "3",
                                "X-Chunk-Sha256": hashlib.sha256(
                                    chunk_data
                                ).hexdigest(),
                            },
                            content=chunk_data,
                        )
                    else:
                        r_up = await cli_client.post(
                            chunk_url,
                            headers={
                                "X-Screenshot-Upload-Token": upload_token,
                                "X-Chunk-Index": str(idx),
                                "X-Total-Chunks": "3",
                                "X-Chunk-Sha256": hashlib.sha256(
                                    chunk_data
                                ).hexdigest(),
                            },
                            content=chunk_data,
                        )
                    assert r_up.status_code == 200, r_up.text

                # 5. Finalize upload
                r_done = await cli_client.post(
                    complete_url,
                    headers={
                        **tenant_cli_headers,
                        "Authorization": f"Bearer {upload_token}",
                    },
                    json={
                        "mimeType": "image/png",
                        "width": 1920,
                        "height": 1080,
                        "originalWidth": 2560,
                        "originalHeight": 1440,
                        "boundsX": 0,
                        "boundsY": 0,
                        "displayIndex": 0,
                        "totalBytes": len(png_bytes),
                        "totalChunks": 3,
                        "chunkSizeBytes": SCREENSHOT_CHUNK_SIZE_BYTES,
                        "sha256": full_sha,
                    },
                )
                assert r_done.status_code == 200, r_done.text
                done_json = r_done.json()
                assert done_json["sizeBytes"] == len(png_bytes)
                assert done_json["sha256"] == full_sha

                # 6. Verify lightweight DB record without imageBase64
                async with AsyncSessionLocal() as db:
                    rec = (
                        await db.execute(
                            select(ConfigUploadRecord).where(
                                ConfigUploadRecord.request_guid == req_guid
                            )
                        )
                    ).scalar_one()
                    assert rec.status == "completed"
                    rec_payload = json.loads(rec.payload)
                    assert rec_payload["data"]["screenshotReady"] is True
                    assert rec_payload["data"]["sizeBytes"] == len(png_bytes)
                    assert rec_payload["data"]["originalWidth"] == 2560
                    assert rec_payload["data"]["originalHeight"] == 1440
                    assert "imageBase64" not in rec_payload["data"]

                # 7. Token cannot be replayed after finalization -> 401
                r_replay_chunk = await cli_client.put(
                    f"{chunk_url}?chunk_index=0&total_chunks=1",
                    headers={
                        **tenant_cli_headers,
                        "Authorization": f"Bearer {upload_token}",
                    },
                    content=chunks[2],
                )
                assert r_replay_chunk.status_code == 401

                # 8. Authenticated binary download matches original PNG byte-for-byte
                r_dl_unauth = await mgmt_client.get(
                    f"/account/acct-ss/screenshot/{req_guid}"
                )
                assert r_dl_unauth.status_code == 401

                r_dl_outsider = await mgmt_client.get(
                    f"/account/acct-ss/screenshot/{req_guid}",
                    headers=outsider_headers,
                )
                assert r_dl_outsider.status_code == 403

                r_dl = await mgmt_client.get(
                    f"/account/acct-ss/screenshot/{req_guid}",
                    headers=owner_headers,
                )
                assert r_dl.status_code == 200
                assert r_dl.headers["content-type"].startswith("image/png")
                assert r_dl.content == png_bytes

                r_dl_missing = await mgmt_client.get(
                    "/account/acct-ss/screenshot/non-existent-guid",
                    headers=owner_headers,
                )
                assert r_dl_missing.status_code == 404

                # 9. Late gRPC UploadConfig does not overwrite finalized screenshot record
                upload_servicer = ConfigUploadServicer(cast(Any, sm))
                grpc_ctx = SimpleNamespace(
                    invocation_metadata=lambda: [],
                    peer=lambda: "ipv4:127.0.0.1:50000",
                )
                grpc_req = SimpleNamespace(
                    RequestGuidId=req_guid,
                    Payload='{"data":{"imageBase64":"stale"}}',
                )
                grpc_rsp = await upload_servicer.UploadConfig(grpc_req, grpc_ctx)
                assert grpc_rsp.Retcode == Retcode_pb2.Success
                assert "Already finalized" in grpc_rsp.Message
                async with AsyncSessionLocal() as db:
                    rec_after = (
                        await db.execute(
                            select(ConfigUploadRecord).where(
                                ConfigUploadRecord.request_guid == req_guid
                            )
                        )
                    ).scalar_one()
                    assert '"screenshotReady"' in (rec_after.payload or "")
        finally:
            management_app.state.session_manager = prev_sm
            management_app.state.command_servicer = prev_cs
    finally:
        await close_redis()


@pytest.mark.asyncio
async def test_sse_authenticated_stream_and_live_events():
    now = datetime.now(timezone.utc)
    try:
        async with AsyncSessionLocal() as db:
            owner = await register_user(
                "owner_sse@school.com",
                "OwnerPass123!",
                "Owner SSE",
                db,
                username="owner_sse",
                role_code="normal",
                is_active=True,
                can_create_account=True,
            )
            outsider = await register_user(
                "outsider_sse@school.com",
                "OutsiderPass123!",
                "Outsider SSE",
                db,
                username="outsider_sse",
                role_code="normal",
                is_active=True,
                can_create_account=False,
            )
            db.add_all(
                [
                    Account(
                        id="acct-sse",
                        name="SSE School",
                        slug="sse-school",
                        api_key="k-sse",
                        is_active=True,
                        created_at=now,
                    ),
                    AccountMember(
                        user_id=owner.id,
                        account_id="acct-sse",
                        role_in_account="owner",
                        joined_at=now,
                    ),
                    ClientRecord(
                        uid="client-sse-1",
                        account_id="acct-sse",
                        client_id="Room-SSE-1",
                        display_name="Classroom SSE 1",
                        ip="127.0.0.1",
                        is_disabled=False,
                        extend_management_enabled=True,
                        extend_management_version="2.0.0.4",
                        is_app_locked=False,
                        registered_at=now,
                    ),
                    PairingCode(
                        id="pair-sse-1",
                        code="654321",
                        tenant_id="acct-sse",
                        client_uid="pending-client-1",
                        client_id="Room-Pending",
                        created_at=now,
                        used=False,
                        approved=False,
                        status="pending",
                    ),
                ]
            )
            await db.commit()
            await set_quota("acct-sse", "feature.remote_edit", 1, db)

        owner_token = await create_session_token(owner.id)
        outsider_token = await create_session_token(outsider.id)
        owner_headers = {"Authorization": f"Bearer {owner_token}"}
        outsider_headers = {"Authorization": f"Bearer {outsider_token}"}

        sm = FakeSessionManager({("acct-sse", "client-sse-1")})
        servicer = FakeCommandServicer()
        prev_sm = getattr(management_app.state, "session_manager", None)
        prev_cs = getattr(management_app.state, "command_servicer", None)
        management_app.state.session_manager = sm
        management_app.state.command_servicer = servicer

        try:
            async with AsyncClient(
                transport=ASGITransport(app=management_app),
                base_url="http://testserver",
            ) as mgmt_client:
                # 1. Auth checks
                r_no_auth = await mgmt_client.get("/account/acct-sse/events")
                assert r_no_auth.status_code == 401

                r_forbidden = await mgmt_client.get(
                    "/account/acct-sse/events", headers=outsider_headers
                )
                assert r_forbidden.status_code == 403

                r_missing_acct = await mgmt_client.get(
                    "/account/non-existent-acct/events", headers=owner_headers
                )
                assert r_missing_acct.status_code == 403

                # 2. End-to-end HTTP SSE endpoint receives connected + live published event
                async def _emit_soon() -> None:
                    await asyncio.sleep(0.08)
                    await publish_account_event(
                        "acct-sse",
                        "client.status",
                        {"client_uid": "client-sse-1", "reason": "http_probe"},
                    )

                emit_task = asyncio.create_task(_emit_soon())
                r_sse = await mgmt_client.get(
                    "/account/acct-sse/events?max_events=2&timeout_seconds=3.0",
                    headers=owner_headers,
                )
                await emit_task
                assert r_sse.status_code == 200
                assert r_sse.headers["content-type"].startswith("text/event-stream")
                http_frames = _parse_sse_frames(r_sse.content)
                assert [name for name, _ in http_frames] == [
                    "connected",
                    "client.status",
                ]
                assert http_frames[1][1]["event"] == "client.status"
                assert "timestamp" in http_frames[1][1]
                assert http_frames[1][1]["data"]["reason"] == "http_probe"

                # 3. Direct stream_account_events receives full set of event types from real actions
                collected: list[tuple[str, dict[str, Any]]] = []

                async def _consume() -> None:
                    async for chunk in stream_account_events(
                        "acct-sse",
                        max_events=6,
                        max_duration_seconds=4.0,
                        keepalive_seconds=5.0,
                    ):
                        collected.extend(_parse_sse_frames(chunk))

                consumer = asyncio.create_task(_consume())
                await asyncio.sleep(0.05)

                # Trigger client.status via rename endpoint
                r_rename = await mgmt_client.post(
                    "/account/acct-sse/client/client-sse-1/rename",
                    headers=owner_headers,
                    json={"display_name": "Classroom SSE Renamed"},
                )
                assert r_rename.status_code == 200

                # Trigger pairing.updated via reject endpoint
                r_reject = await mgmt_client.post(
                    "/account/acct-sse/pairing/pair-sse-1/reject",
                    headers=owner_headers,
                )
                assert r_reject.status_code == 200

                # Trigger edit_session.updated via edit-session/create endpoint
                r_sess = await mgmt_client.post(
                    "/account/acct-sse/edit-session/create",
                    headers=owner_headers,
                    json={
                        "mode": "RemoteEdit",
                        "editor_client_uid": "client-sse-1",
                        "initial_view": "profile",
                    },
                )
                assert r_sess.status_code == 200

                # Trigger command.completed and audit.created
                await publish_account_event(
                    "acct-sse",
                    "command.completed",
                    {
                        "request_guid": "cmd-1",
                        "client_uid": "client-sse-1",
                        "status": "completed",
                    },
                )
                await publish_account_event(
                    "acct-sse",
                    "audit.created",
                    {"id": 101, "client_uid": "client-sse-1", "event_type": 1},
                )

                await consumer
                event_names = [name for name, _ in collected]
                assert "connected" in event_names
                assert "client.status" in event_names
                assert "pairing.updated" in event_names
                assert "edit_session.updated" in event_names
                assert "command.completed" in event_names
                assert "audit.created" in event_names
        finally:
            management_app.state.session_manager = prev_sm
            management_app.state.command_servicer = prev_cs
    finally:
        await close_redis()


def test_binary_redis_sync_no_running_loop():
    """Verify get_binary_redis works outside a running event loop and can be closed cleanly."""
    bin_rd = get_binary_redis(REDIS_DB_SESSION)
    assert bin_rd is not None
    asyncio.run(close_redis())


@pytest.mark.asyncio
async def test_screenshot_upload_edge_cases_and_validation():
    """Exercise token header fallbacks, image magic checks, quota 429, and finalize error branches."""
    now = datetime.now(timezone.utc)
    try:
        # 1. Pool reuse inside running event loop
        b1 = get_binary_redis(REDIS_DB_SESSION)
        b2 = get_binary_redis(REDIS_DB_SESSION)
        assert b1 is b2

        # 2. Token header & query extraction branches
        req_ss_hdr = cast(
            Any,
            SimpleNamespace(
                headers=Headers(
                    {"authorization": "Bearer ", "x-screenshot-upload-token": "tok-ss"}
                )
            ),
        )
        assert extract_upload_token_from_request(req_ss_hdr, "qtok") == "tok-ss"

        req_up_hdr = cast(
            Any,
            SimpleNamespace(headers=Headers({"x-upload-token": "tok-up"})),
        )
        assert extract_upload_token_from_request(req_up_hdr, "qtok") == "tok-up"

        req_query = cast(Any, SimpleNamespace(headers=Headers({})))
        assert extract_upload_token_from_request(req_query, " qtok ") == "qtok"

        # 3. Image MIME magic detection
        assert _detect_image_mime(b"\x89PNG\r\n\x1a\nabc") == "image/png"
        assert _detect_image_mime(b"\xff\xd8\xff\xe0abc") == "image/jpeg"
        assert _detect_image_mime(b"RIFF1234WEBPdata") == "image/webp"
        assert _detect_image_mime(b"INVALID") is None

        # 4. _parse_int_param edge cases
        assert _parse_int_param(None, " 42 ", "chunk_index") == 42
        with pytest.raises(HTTPException) as exc_bad_int:
            _parse_int_param(None, "abc", "chunk_index")
        assert exc_bad_int.value.status_code == 400
        with pytest.raises(HTTPException) as exc_missing_int:
            _parse_int_param(None, "   ", "chunk_index")
        assert exc_missing_int.value.status_code == 400

        # 5. Token validation errors (empty, corrupted JSON, hash mismatch)
        with pytest.raises(HTTPException) as exc_empty:
            await _verify_upload_token(
                request_guid="g-unit-1", client_uid="c1", token=""
            )
        assert exc_empty.value.status_code == 401

        rd = get_redis(REDIS_DB_SESSION)
        await rd.set(f"{_TOKEN_KEY_PREFIX}g-corrupt", "{bad-json", ex=60)
        with pytest.raises(HTTPException) as exc_corrupt:
            await _verify_upload_token(
                request_guid="g-corrupt", client_uid="c1", token="tok"
            )
        assert exc_corrupt.value.status_code == 401
        await rd.delete(f"{_TOKEN_KEY_PREFIX}g-corrupt")

        # 6. store_screenshot_chunk bounds
        with pytest.raises(HTTPException) as exc_tc:
            await store_screenshot_chunk(
                client_uid="c1",
                request_guid="g-unit",
                chunk_index=0,
                total_chunks=0,
                chunk_bytes=b"a",
                token="t",
            )
        assert exc_tc.value.status_code == 400

        with pytest.raises(HTTPException) as exc_ci:
            await store_screenshot_chunk(
                client_uid="c1",
                request_guid="g-unit",
                chunk_index=2,
                total_chunks=2,
                chunk_bytes=b"a",
                token="t",
            )
        assert exc_ci.value.status_code == 400

        # 7. finalize_screenshot_upload validation & DB branches
        async with AsyncSessionLocal() as db:
            db.add(
                Account(
                    id="acct-unit",
                    name="Unit School",
                    slug="unit-school",
                    api_key="k-unit",
                    is_active=True,
                    created_at=now,
                )
            )
            await db.commit()

            with pytest.raises(HTTPException) as exc_ftc:
                await finalize_screenshot_upload(
                    db=db,
                    client_uid="c1",
                    request_guid="g-f1",
                    total_chunks=MAX_SCREENSHOT_CHUNKS + 1,
                    total_bytes=10,
                    token="t",
                )
            assert exc_ftc.value.status_code == 400

            with pytest.raises(HTTPException) as exc_ftb:
                await finalize_screenshot_upload(
                    db=db,
                    client_uid="c1",
                    request_guid="g-f1",
                    total_chunks=1,
                    total_bytes=MAX_SCREENSHOT_BYTES + 1,
                    token="t",
                )
            assert exc_ftb.value.status_code == 400

            tok = await issue_screenshot_upload_token("acct-unit", "cli-u1", "g-miss")
            with pytest.raises(HTTPException) as exc_miss:
                await finalize_screenshot_upload(
                    db=db,
                    client_uid="cli-u1",
                    request_guid="g-miss",
                    total_chunks=1,
                    total_bytes=10,
                    token=tok,
                )
            assert exc_miss.value.status_code == 400

            # Corrupt non-bytes chunk object in Redis client
            fake_bin = AsyncMock()
            fake_bin.get = AsyncMock(return_value="not-bytes")
            with patch(
                "app.shared.services.screenshot_upload.get_binary_redis",
                return_value=fake_bin,
            ):
                with pytest.raises(HTTPException) as exc_nonbytes:
                    await finalize_screenshot_upload(
                        db=db,
                        client_uid="cli-u1",
                        request_guid="g-miss",
                        total_chunks=1,
                        total_bytes=10,
                        token=tok,
                    )
                assert exc_nonbytes.value.status_code == 500

            # Valid stored chunk -> total_bytes mismatch, sha256 mismatch, invalid magic
            webp_blob = b"RIFF\x00\x00\x00\x00WEBP" + b"\x01" * 16
            bad_blob = b"NOT_AN_IMAGE_MAGIC_BYTES"
            tok_bad = await issue_screenshot_upload_token(
                "acct-unit", "cli-u1", "g-bad"
            )
            await store_screenshot_chunk(
                client_uid="cli-u1",
                request_guid="g-bad",
                chunk_index=0,
                total_chunks=1,
                chunk_bytes=bad_blob,
                token=tok_bad,
            )

            with pytest.raises(HTTPException) as exc_sz:
                await finalize_screenshot_upload(
                    db=db,
                    client_uid="cli-u1",
                    request_guid="g-bad",
                    total_chunks=1,
                    total_bytes=len(bad_blob) + 1,
                    token=tok_bad,
                )
            assert exc_sz.value.status_code == 400

            with pytest.raises(HTTPException) as exc_fsha:
                await finalize_screenshot_upload(
                    db=db,
                    client_uid="cli-u1",
                    request_guid="g-bad",
                    total_chunks=1,
                    total_bytes=len(bad_blob),
                    sha256_hex="f" * 64,
                    token=tok_bad,
                )
            assert exc_fsha.value.status_code == 400

            with pytest.raises(HTTPException) as exc_magic:
                await finalize_screenshot_upload(
                    db=db,
                    client_uid="cli-u1",
                    request_guid="g-bad",
                    total_chunks=1,
                    total_bytes=len(bad_blob),
                    token=tok_bad,
                )
            assert exc_magic.value.status_code == 400

            # Exceeded bandwidth quota -> 429
            await set_quota("acct-unit", "max_bandwidth_mb", 0, db)
            tok_q = await issue_screenshot_upload_token(
                "acct-unit", "cli-u1", "g-quota"
            )
            await store_screenshot_chunk(
                client_uid="cli-u1",
                request_guid="g-quota",
                chunk_index=0,
                total_chunks=1,
                chunk_bytes=webp_blob,
                token=tok_q,
            )
            with pytest.raises(HTTPException) as exc_429:
                await finalize_screenshot_upload(
                    db=db,
                    client_uid="cli-u1",
                    request_guid="g-quota",
                    total_chunks=1,
                    total_bytes=len(webp_blob),
                    token=tok_q,
                )
            assert exc_429.value.status_code == 429

            # Unlimited quota + no pre-existing ConfigUploadRecord -> inserts completed record
            await set_quota("acct-unit", "max_bandwidth_mb", -1, db)
            tok_ok = await issue_screenshot_upload_token(
                "acct-unit", "cli-u1", "g-newrec"
            )
            await store_screenshot_chunk(
                client_uid="cli-u1",
                request_guid="g-newrec",
                chunk_index=0,
                total_chunks=1,
                chunk_bytes=webp_blob,
                token=tok_ok,
            )
            res_ok = await finalize_screenshot_upload(
                db=db,
                client_uid="cli-u1",
                request_guid="g-newrec",
                total_chunks=1,
                total_bytes=len(webp_blob),
                token=tok_ok,
            )
            assert res_ok["mimeType"] == "image/webp"
            created_rec = (
                await db.execute(
                    select(ConfigUploadRecord).where(
                        ConfigUploadRecord.request_guid == "g-newrec"
                    )
                )
            ).scalar_one()
            assert created_rec.config_type == 100
            assert created_rec.status == "completed"

            # Corrupt blob metadata JSON falls back to empty dict in get_screenshot_blob
            assert await get_screenshot_blob("acct-unit", "no-such-guid") is None
            await rd.set(f"{_META_KEY_PREFIX}acct-unit:g-newrec", "{broken-json", ex=60)
            blob_out, meta_out = await get_screenshot_blob("acct-unit", "g-newrec") or (
                b"",
                {"unexpected": True},
            )
            assert blob_out == webp_blob
            assert meta_out == {}
            await get_binary_redis(REDIS_DB_SESSION).delete(
                f"{_BLOB_KEY_PREFIX}acct-unit:g-newrec"
            )
            await rd.delete(f"{_META_KEY_PREFIX}acct-unit:g-newrec")
    finally:
        await close_redis()


@pytest.mark.asyncio
async def test_sse_service_edge_cases_and_relay():
    """Cover SSE frame formatting, queue overflow drops, keepalives, disconnects, and Redis relay branches."""
    try:
        # 1. format_sse_frame with and without event_id
        frame_no_id = format_sse_frame("ping", {"ok": True}).decode("utf-8")
        assert "id: " not in frame_no_id
        assert "event: ping\n" in frame_no_id

        frame_with_id = format_sse_frame("ping", {"ok": True}, event_id="ev-9").decode(
            "utf-8"
        )
        assert frame_with_id.startswith("id: ev-9\nevent: ping\n")

        # 2. publish_account_event early returns and Redis error suppression
        env_empty = await publish_account_event("", "x", {})
        assert env_empty["event"] == "x"
        env_def = await publish_account_event("default", "x", {})
        assert env_def["account_id"] == "default"

        with patch(
            "app.shared.services.sse.get_redis", side_effect=RuntimeError("redis down")
        ):
            env_err = await publish_account_event(
                "acct-err", "client.status", {"ok": 1}
            )
            assert env_err["type"] == "client.status"

        # 3. _dispatch_local edge cases and full-queue drop-oldest
        loop = asyncio.get_running_loop()
        _dispatch_local(loop, "", {"type": "noop"})
        _dispatch_local(loop, "acct-no-subs", {"type": "noop"})

        tiny_q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=1)
        tiny_q.put_nowait({"seq": 1})
        _SUBSCRIBERS.setdefault(loop, {})["acct-full"] = {tiny_q}
        try:
            _dispatch_local(loop, "acct-full", {"seq": 2})
            assert tiny_q.get_nowait()["seq"] == 2
        finally:
            acct_map = _SUBSCRIBERS.get(loop, {})
            acct_map.pop("acct-full", None)
            if not acct_map:
                _SUBSCRIBERS.pop(loop, None)

        # 4. stream_account_events keepalive emission + timeout expiry
        keepalive_chunks: list[bytes] = []
        async for chunk in stream_account_events(
            "acct-ka",
            keepalive_seconds=0.02,
            max_duration_seconds=0.07,
        ):
            keepalive_chunks.append(chunk)
        assert any(c == b": keepalive\n\n" for c in keepalive_chunks)

        # 5. stream_account_events disconnects cleanly when request.is_disconnected() returns True
        disconnect_req = cast(
            Any, SimpleNamespace(is_disconnected=AsyncMock(return_value=True))
        )
        dc_chunks = [
            c
            async for c in stream_account_events(
                "acct-dc",
                request=disconnect_req,
                keepalive_seconds=0.5,
                max_duration_seconds=1.0,
            )
        ]
        assert len(dc_chunks) == 1
        assert b"event: connected" in dc_chunks[0]

        # 6. _redis_relay_loop branches: non-pmessage, non-str, bad JSON, non-dict, self-origin,
        # channel fallback without account_id, invalid channel without account_id, reconnect, exit
        relay_q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=_MAX_QUEUE_SIZE)
        _SUBSCRIBERS.setdefault(loop, {})["acct-relay"] = {relay_q}

        messages: list[Any] = [
            {"type": "subscribe"},
            {
                "type": "pmessage",
                "data": b"bytes-ignored",
                "channel": "mci:sse:acct-relay",
            },
            {"type": "pmessage", "data": "{not-json", "channel": "mci:sse:acct-relay"},
            {"type": "pmessage", "data": "[1, 2]", "channel": "mci:sse:acct-relay"},
            {
                "type": "pmessage",
                "data": json.dumps(
                    {"_origin": _INSTANCE_ID, "account_id": "acct-relay"}
                ),
                "channel": "mci:sse:acct-relay",
            },
            {
                "type": "pmessage",
                "data": json.dumps({"_origin": "worker-2", "type": "audit.created"}),
                "channel": "mci:sse:acct-relay",
            },
            {
                "type": "pmessage",
                "data": json.dumps({"_origin": "worker-2", "type": "audit.created"}),
                "channel": "unexpected:chan",
            },
            RuntimeError("transient pubsub error"),
            None,
        ]
        msg_iter = iter(messages)

        async def _fake_get_message(**_kwargs: Any) -> Any:
            nxt = next(msg_iter)
            if isinstance(nxt, Exception):
                # Remove subscribers before final None breaks the loop cleanly
                _SUBSCRIBERS.get(loop, {}).pop("acct-relay", None)
                if not _SUBSCRIBERS.get(loop):
                    _SUBSCRIBERS.pop(loop, None)
                raise nxt
            return nxt

        fake_pubsub = SimpleNamespace(
            psubscribe=AsyncMock(),
            get_message=_fake_get_message,
            punsubscribe=AsyncMock(),
            aclose=AsyncMock(),
        )
        fake_rd = SimpleNamespace(pubsub=lambda: fake_pubsub)

        try:
            with (
                patch("app.shared.services.sse.get_redis", return_value=fake_rd),
                patch("app.shared.services.sse.asyncio.sleep", new=AsyncMock()),
            ):
                await _redis_relay_loop(loop)
        finally:
            _SUBSCRIBERS.get(loop, {}).pop("acct-relay", None)
            if not _SUBSCRIBERS.get(loop):
                _SUBSCRIBERS.pop(loop, None)

        relayed = relay_q.get_nowait()
        assert relayed["type"] == "audit.created"
        assert "_origin" not in relayed
        assert fake_pubsub.punsubscribe.await_count >= 1
        assert fake_pubsub.aclose.await_count >= 1
    finally:
        await close_redis()


@pytest.mark.asyncio
async def test_new_sse_endpoints_qr_pairing_admin_and_user(test_superadmin_user):
    """Verify QR login SSE, client pairing-status SSE, SuperAdmin /events, and user /user/events streams."""
    now = datetime.now(timezone.utc)
    try:
        async with AsyncSessionLocal() as db:
            await ensure_system_roles(db)
            owner = await register_user(
                "owner_new_sse@school.com",
                "OwnerPass123!",
                "Owner New SSE",
                db,
                username="owner_new_sse",
                role_code="normal",
                is_active=True,
                can_create_account=True,
            )
            pending_user = await register_user(
                "pending_new_sse@school.com",
                "PendingPass123!",
                "Pending New SSE",
                db,
                username="pending_new_sse",
                role_code="pending",
                is_active=True,
                can_create_account=False,
            )
            db.add_all(
                [
                    Account(
                        id="acct-pair-sse",
                        name="Pairing SSE School",
                        slug="pair-sse-school",
                        api_key="k-pair-sse",
                        is_active=True,
                        created_at=now,
                    ),
                    AccountMember(
                        user_id=owner.id,
                        account_id="acct-pair-sse",
                        role_in_account="owner",
                        joined_at=now,
                    ),
                    PairingCode(
                        id="pair-evt-1",
                        code="778899",
                        tenant_id="acct-pair-sse",
                        client_uid="cli-pair-sse-1",
                        client_id="Room-Pair-SSE",
                        created_at=now,
                        used=False,
                        approved=False,
                        status="pending",
                    ),
                ]
            )
            await db.commit()

        sa_token = await create_session_token(test_superadmin_user)
        owner_token = await create_session_token(owner.id)
        pending_token = await create_session_token(pending_user.id)
        sa_headers = {"Authorization": f"Bearer {sa_token}"}
        owner_headers = {"Authorization": f"Bearer {owner_token}"}
        pending_headers = {"Authorization": f"Bearer {pending_token}"}

        sm = FakeSessionManager(set())
        prev_mgmt_sm = getattr(management_app.state, "session_manager", None)
        prev_cli_sm = getattr(client_app.state, "session_manager", None)
        management_app.state.session_manager = sm
        client_app.state.session_manager = sm

        try:
            async with (
                AsyncClient(
                    transport=ASGITransport(app=management_app),
                    base_url="http://testserver",
                ) as mgmt_client,
                AsyncClient(
                    transport=ASGITransport(app=client_app),
                    base_url="http://testserver",
                ) as cli_client,
                AsyncClient(
                    transport=ASGITransport(app=admin_app),
                    base_url="http://testserver",
                ) as adm_client,
            ):
                # 1. QR login SSE receives qr.updated authorized transition
                r_qr_create = await mgmt_client.post("/token/qr-login/create")
                assert r_qr_create.status_code == 200, r_qr_create.text
                qr_code = r_qr_create.json()["code"]

                async def _authorize_qr_soon() -> None:
                    await asyncio.sleep(0.08)
                    ok = await authorize_qr_login_challenge(qr_code, owner.id)
                    assert ok is True

                qr_auth_task = asyncio.create_task(_authorize_qr_soon())
                r_qr_sse = await mgmt_client.get(
                    f"/token/qr-login/events?code={qr_code}&timeout_seconds=3.0"
                )
                await qr_auth_task
                assert r_qr_sse.status_code == 200, r_qr_sse.text
                qr_frames = _parse_sse_frames(r_qr_sse.content)
                assert qr_frames[0][0] == "connected"
                qr_updates = [
                    payload for name, payload in qr_frames if name == "qr.updated"
                ]
                assert any(
                    (item.get("data") or {}).get("status") == "authorized"
                    for item in qr_updates
                )

                # 2. Client pairing-status SSE wakes up immediately upon pairing approval
                async def _approve_pairing_soon() -> None:
                    await asyncio.sleep(0.08)
                    r_app = await mgmt_client.post(
                        "/account/acct-pair-sse/pairing/pair-evt-1/approve",
                        headers=owner_headers,
                    )
                    assert r_app.status_code == 200, r_app.text

                pair_task = asyncio.create_task(_approve_pairing_soon())
                r_pair_sse = await cli_client.get(
                    "/api/v1/client/cli-pair-sse-1/pairing-status/events?code=778899&timeout_seconds=3.0",
                    headers={"Host": f"pair-sse-school.{BASE_DOMAIN}"},
                )
                await pair_task
                assert r_pair_sse.status_code == 200, r_pair_sse.text
                pair_frames = _parse_sse_frames(r_pair_sse.content)
                assert pair_frames[0][0] == "connected"
                pair_statuses = [
                    payload for name, payload in pair_frames if name == "pairing.status"
                ]
                assert any(
                    item.get("status") == "approved" and item.get("approved") is True
                    for item in pair_statuses
                )

                # 3. SuperAdmin /events and pending user /user/events receive registration & approval events
                async def _trigger_admin_and_user_events() -> None:
                    await asyncio.sleep(0.08)
                    await publish_topic_event(
                        "__admin__",
                        "registration.created",
                        {
                            "user_id": pending_user.id,
                            "email": "pending_new_sse@school.com",
                        },
                    )
                    r_upd = await adm_client.post(
                        f"/user/{pending_user.id}",
                        json={"role_code": "normal", "is_active": True},
                        headers=sa_headers,
                    )
                    assert r_upd.status_code == 200, r_upd.text

                trigger_task = asyncio.create_task(_trigger_admin_and_user_events())
                r_adm_sse, r_usr_sse = await asyncio.gather(
                    adm_client.get(
                        "/events?max_events=3&timeout_seconds=3.0",
                        headers=sa_headers,
                    ),
                    mgmt_client.get(
                        "/user/events?max_events=2&timeout_seconds=3.0",
                        headers=pending_headers,
                    ),
                )
                await trigger_task

                assert r_adm_sse.status_code == 200, r_adm_sse.text
                adm_frames = _parse_sse_frames(r_adm_sse.content)
                adm_names = [name for name, _ in adm_frames]
                assert "connected" in adm_names
                assert "registration.created" in adm_names
                assert "registration.updated" in adm_names

                assert r_usr_sse.status_code == 200, r_usr_sse.text
                usr_frames = _parse_sse_frames(r_usr_sse.content)
                assert [name for name, _ in usr_frames] == [
                    "connected",
                    "user.updated",
                ]
        finally:
            management_app.state.session_manager = prev_mgmt_sm
            client_app.state.session_manager = prev_cli_sm
    finally:
        await close_redis()
