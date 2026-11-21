"""Ephemeral session coordination service for RemoteEdit and AssistAnother."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from fastapi import HTTPException, status

from app.shared.utils.config import REDIS_DB_SESSION
from app.shared.utils.redis import get_redis

EDIT_SESSION_TTL_SECONDS = 1800  # 30 minutes sliding TTL
_SESSION_KEY_PREFIX = "mci:edit_session:"
_ACCOUNT_SET_PREFIX = "mci:account_edit_sessions:"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _session_key(session_id: str) -> str:
    return f"{_SESSION_KEY_PREFIX}{session_id}"


def _account_set_key(account_id: str) -> str:
    return f"{_ACCOUNT_SET_PREFIX}{account_id}"


def _sanitize_summary(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "session_id": data["session_id"],
        "mode": data["mode"],
        "account_id": data["account_id"],
        "role": data["role"],
        "editor_client_uid": data["editor_client_uid"],
        "editor_display_name": data.get("editor_display_name", ""),
        "target_client_uid": data.get("target_client_uid"),
        "target_display_name": data.get("target_display_name", ""),
        "initial_view": data.get("initial_view", "profile"),
        "allowed_scopes": list(data.get("allowed_scopes", [])),
        "resource_targets": dict(data.get("resource_targets", {})),
        "base_versions": dict(data.get("base_versions", {})),
        "created_at": data["created_at"],
        "expires_at": data["expires_at"],
        "last_sequence": int(data.get("last_sequence", 0)),
    }


async def create_edit_session(
    *,
    mode: str,
    account_id: str,
    role: str,
    created_by_user_id: str,
    editor_client_uid: str,
    editor_display_name: str,
    target_client_uid: Optional[str],
    target_display_name: str,
    initial_view: str,
    allowed_scopes: list[str],
    resource_targets: dict[str, str],
    base_versions: dict[str, int],
    relay_snapshot: Optional[dict[str, Any]] = None,
    capture_request_guid: Optional[str] = None,
    target_plugin_components: Optional[list[Any]] = None,
    target_plugin_settings: Optional[list[Any]] = None,
) -> tuple[dict[str, Any], str]:
    """Create and persist an ephemeral edit session in Redis, returning (session_dict, raw_token)."""
    rd = get_redis(REDIS_DB_SESSION)
    session_id = uuid.uuid4().hex
    raw_token = secrets.token_urlsafe(32)
    now_ts = int(time.time())
    expires_ts = now_ts + EDIT_SESSION_TTL_SECONDS
    now_iso = datetime.now(timezone.utc).isoformat()

    session_data: dict[str, Any] = {
        "session_id": session_id,
        "token_sha256": _hash_token(raw_token),
        "mode": mode,
        "account_id": account_id,
        "role": role,
        "created_by_user_id": created_by_user_id,
        "editor_client_uid": editor_client_uid,
        "editor_display_name": editor_display_name,
        "target_client_uid": target_client_uid,
        "target_display_name": target_display_name,
        "initial_view": initial_view,
        "allowed_scopes": allowed_scopes,
        "resource_targets": resource_targets,
        "base_versions": base_versions,
        "relay_snapshot": relay_snapshot,
        "capture_request_guid": capture_request_guid,
        "target_plugin_components": target_plugin_components or [],
        "target_plugin_settings": target_plugin_settings or [],
        "created_at": now_iso,
        "created_at_ts": now_ts,
        "expires_at": datetime.fromtimestamp(expires_ts, timezone.utc).isoformat(),
        "expires_at_ts": expires_ts,
        "last_sequence": 0,
    }

    pipe = rd.pipeline(transaction=False)
    pipe.set(
        _session_key(session_id),
        json.dumps(session_data, ensure_ascii=False),
        ex=EDIT_SESSION_TTL_SECONDS,
    )
    pipe.sadd(_account_set_key(account_id), session_id)
    pipe.expire(_account_set_key(account_id), EDIT_SESSION_TTL_SECONDS * 2)
    await pipe.execute()
    return session_data, raw_token


async def get_edit_session(session_id: str) -> Optional[dict[str, Any]]:
    """Fetch edit session JSON from Redis if active."""
    if not session_id:
        return None
    rd = get_redis(REDIS_DB_SESSION)
    raw = await rd.get(_session_key(session_id))
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


async def verify_client_edit_session(
    *,
    session_id: str,
    client_uid: str,
    token: str,
    tenant_id: Optional[str] = None,
) -> dict[str, Any]:
    """Authenticate an editor client request against an active edit session."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Edit-Session-Token",
        )
    session = await get_edit_session(session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Edit session not found or expired",
        )
    if not hmac.compare_digest(
        str(session.get("token_sha256", "")), _hash_token(token.strip())
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid edit session token",
        )
    if session.get("editor_client_uid") != client_uid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Client UID does not match editor session",
        )
    if tenant_id and tenant_id != "default" and session.get("account_id") != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant mismatch for edit session",
        )
    return session


async def save_edit_session(
    session: dict[str, Any],
    *,
    mutator: Optional[Callable[[dict[str, Any]], None]] = None,
) -> dict[str, Any]:
    """Update edit session state and renew sliding TTL in Redis."""
    if mutator is not None:
        mutator(session)
    now_ts = int(time.time())
    expires_ts = now_ts + EDIT_SESSION_TTL_SECONDS
    session["expires_at_ts"] = expires_ts
    session["expires_at"] = datetime.fromtimestamp(expires_ts, timezone.utc).isoformat()

    rd = get_redis(REDIS_DB_SESSION)
    pipe = rd.pipeline(transaction=False)
    pipe.set(
        _session_key(session["session_id"]),
        json.dumps(session, ensure_ascii=False),
        ex=EDIT_SESSION_TTL_SECONDS,
    )
    pipe.expire(_account_set_key(session["account_id"]), EDIT_SESSION_TTL_SECONDS * 2)
    await pipe.execute()
    return session


async def list_account_edit_sessions(account_id: str) -> list[dict[str, Any]]:
    """List active redacted edit session summaries for an account."""
    rd = get_redis(REDIS_DB_SESSION)
    idx_key = _account_set_key(account_id)
    ids = list(await rd.smembers(idx_key))
    if not ids:
        return []
    pipe = rd.pipeline(transaction=False)
    for sid in ids:
        pipe.get(_session_key(sid))
    results = await pipe.execute()

    stale: list[str] = []
    out: list[dict[str, Any]] = []
    for sid, raw in zip(ids, results):
        if not raw:
            stale.append(sid)
            continue
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            stale.append(sid)
            continue
        out.append(_sanitize_summary(data))
    if stale:
        await rd.srem(idx_key, *stale)
    out.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    return out


async def delete_edit_session(
    session_id: str, account_id: Optional[str] = None
) -> Optional[dict[str, Any]]:
    """Delete an edit session from Redis and return the prior state if found."""
    existing = await get_edit_session(session_id)
    rd = get_redis(REDIS_DB_SESSION)
    pipe = rd.pipeline(transaction=False)
    pipe.delete(_session_key(session_id))
    acct = account_id or (existing.get("account_id") if existing else None)
    if acct:
        pipe.srem(_account_set_key(acct), session_id)
    await pipe.execute()
    return existing


def sanitize_edit_session_summary(session: dict[str, Any]) -> dict[str, Any]:
    """Public helper returning non-sensitive session metadata."""
    return _sanitize_summary(session)


RESOURCE_TO_PROFILE_ATTR: dict[str, str] = {
    "ClassPlan": "class_plan",
    "TimeLayout": "time_layout",
    "Subjects": "subjects",
    "DefaultSettings": "default_settings",
    "Components": "components",
    "Policy": "policy",
    "Credentials": "credentials",
}


async def notify_clients_for_resource_update(
    account_id: str,
    resource_type: str,
    resource_name: str,
    db: Any,
    *,
    servicer: Any = None,
    sm: Any = None,
) -> dict[str, int]:
    """Find registered active clients bound to (resource_type, resource_name) and push DataUpdated to online ones."""
    from sqlalchemy import select
    from app.shared.db.models import ClientProfile, ClientRecord

    col_name = RESOURCE_TO_PROFILE_ATTR.get(resource_type)
    if not col_name:
        return {"matched_clients": 0, "notified_clients": 0}

    prof_rows = (
        (
            await db.execute(
                select(ClientProfile).where(ClientProfile.account_id == account_id)
            )
        )
        .scalars()
        .all()
    )
    prof_map = {p.client_id: p for p in prof_rows}
    default_prof = prof_map.get("__default__")

    client_rows = (
        (
            await db.execute(
                select(ClientRecord).where(
                    ClientRecord.account_id == account_id,
                    ClientRecord.is_disabled.is_(False),
                )
            )
        )
        .scalars()
        .all()
    )

    online_uids: set[str] = set()
    if sm is not None:
        try:
            online_list = await sm.get_all_clients_status(account_id)
            online_uids = {
                str(item.get("uid", "")).strip()
                for item in (online_list or [])
                if item.get("uid")
            }
        except Exception:
            online_uids = set()

    matched_clients = 0
    notified_clients = 0

    cmd = None
    if servicer is not None:
        from app.Protobuf.Server import ClientCommandDeliverScRsp_pb2
        from app.Protobuf.Enum import Retcode_pb2, CommandTypes_pb2

        cmd = ClientCommandDeliverScRsp_pb2.ClientCommandDeliverScRsp(
            RetCode=Retcode_pb2.Success,
            Type=CommandTypes_pb2.DataUpdated,
        )

    for client_rec in client_rows:
        prof = prof_map.get(client_rec.uid) or default_prof
        raw_bound = getattr(prof, col_name, None) if prof is not None else None
        effective_bound = raw_bound if raw_bound is not None else "default"
        if effective_bound != resource_name:
            continue

        matched_clients += 1
        if cmd is not None and servicer is not None:
            is_online = client_rec.uid in online_uids
            if not is_online and sm is not None:
                try:
                    is_online = bool(
                        await sm.is_client_online(account_id, client_rec.uid)
                    )
                except Exception:
                    is_online = False
            if is_online:
                try:
                    if await servicer.send_command(account_id, client_rec.uid, cmd):
                        notified_clients += 1
                except Exception:
                    pass

    return {
        "matched_clients": matched_clients,
        "notified_clients": notified_clients,
    }


async def dispatch_signed_extend_command(
    *,
    account_id: str,
    client_uid: str,
    action: str,
    payload: Optional[dict[str, Any]],
    sm: Any,
    servicer: Any,
    db: Optional[Any] = None,
    request_guid: Optional[str] = None,
    ttl_seconds: int = 120,
    record_upload: bool = True,
) -> tuple[bool, str]:
    """Sign and dispatch an MCI-EXTCMD-V1 command to a connected client."""
    req_guid = request_guid or str(uuid.uuid4())
    if sm is None or servicer is None:
        return False, req_guid

    if record_upload and db is not None:
        from app.shared.db.models import ConfigUploadRecord

        db.add(
            ConfigUploadRecord(
                request_guid=req_guid,
                account_id=account_id,
                client_uid=client_uid,
                config_type=100,
                status="pending",
                payload="",
                uploaded_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

    envelope_payload: Optional[dict[str, Any]] = payload
    if action == "remote.screenshot":
        from app.shared.services.screenshot_upload import (
            SCREENSHOT_CHUNK_SIZE_BYTES,
            issue_screenshot_upload_token,
        )

        envelope_payload = dict(payload or {})
        if not envelope_payload.get("uploadToken"):
            envelope_payload["uploadToken"] = await issue_screenshot_upload_token(
                account_id,
                client_uid,
                req_guid,
                ttl_seconds=max(120, ttl_seconds + 180),
            )
        envelope_payload.setdefault("requestGuid", req_guid)
        envelope_payload.setdefault("chunkSizeBytes", SCREENSHOT_CHUNK_SIZE_BYTES)

    envelope = sm.build_signed_command_envelope(
        request_guid=req_guid,
        client_uid=client_uid,
        action=action,
        payload=envelope_payload,
        ttl_seconds=ttl_seconds,
    )
    envelope_bytes = json.dumps(envelope, ensure_ascii=False).encode("utf-8")

    from app.Protobuf.Server import ClientCommandDeliverScRsp_pb2
    from app.Protobuf.Enum import Retcode_pb2, CommandTypes_pb2

    cmd = ClientCommandDeliverScRsp_pb2.ClientCommandDeliverScRsp(
        RetCode=Retcode_pb2.Success,
        Type=CommandTypes_pb2.DefaultCommand,
        Payload=envelope_bytes,
    )
    delivered = await servicer.send_command(account_id, client_uid, cmd)
    return bool(delivered), req_guid


async def poll_completed_config_upload(
    account_id: str,
    request_guid: str,
    timeout_sec: float = 4.0,
) -> Optional[dict[str, Any]]:
    """Wait via SSE event bus (with DB re-check fallback) for ConfigUploadRecord completion."""
    from sqlalchemy import select
    from app.shared.db.models import ConfigUploadRecord
    from app.shared.db.session import AsyncSessionLocal
    from app.shared.services.sse import subscribe_account_channel, wait_for_queue_event
    from app.shared.utils.tenant import set_search_path

    deadline = time.monotonic() + max(0.2, timeout_sec)
    async with subscribe_account_channel(account_id) as queue:
        while True:
            async with AsyncSessionLocal() as poll_db:
                await set_search_path(poll_db)
                res = await poll_db.execute(
                    select(ConfigUploadRecord).where(
                        ConfigUploadRecord.account_id == account_id,
                        ConfigUploadRecord.request_guid == request_guid,
                    )
                )
                rec = res.scalar_one_or_none()
                if rec is not None and rec.status == "completed":
                    raw_payload = rec.payload or ""
                    if not raw_payload.strip():
                        return {}
                    try:
                        parsed = json.loads(raw_payload)
                    except Exception:
                        return None
                    if not isinstance(parsed, dict):
                        return {"value": parsed}
                    # Unwrap MEE CommandExecutionResponse envelope when uploaded via gRPC ConfigUpload
                    if "requestGuid" in parsed and "success" in parsed:
                        if not parsed.get("success"):
                            raise HTTPException(
                                status_code=status.HTTP_502_BAD_GATEWAY,
                                detail=str(
                                    parsed.get("message")
                                    or "Target client failed to capture snapshot"
                                ),
                            )
                        inner = parsed.get("data")
                        return inner if isinstance(inner, dict) else {}
                    return parsed

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            await wait_for_queue_event(
                queue,
                event_types=("command.completed",),
                predicate=lambda env: str(
                    (env.get("data") or {}).get("request_guid") or ""
                )
                == request_guid,
                timeout_sec=min(remaining, 1.0),
            )
