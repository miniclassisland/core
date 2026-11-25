import json
import logging
import time
from datetime import datetime, timezone
from typing import Any
from fastapi import (
    APIRouter,
    Body,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import AsyncSessionLocal, get_db
from app.shared.db.models import (
    ClientRecord,
    ClientProfile,
    Account,
    PairingCode,
    ResourceHistory,
    MODEL_MAP,
)
from app.shared.db.schema_init import seed_account_defaults
from app.shared.literals import DEFAULT_RESOURCES
from app.shared.schemas.schemas import ClientManifest, EditSessionClientSyncRequest
from app.shared.security.crypto import normalize_resource_payload
from app.shared.utils.logging import get_client_ip_from_request
from app.shared.utils.tenant import (
    get_tenant_id_or_default,
    get_cached_account,
    set_search_path,
)
from app.shared.security.auth import create_token
from app.shared.services.edit_session import (
    delete_edit_session,
    dispatch_signed_extend_command,
    notify_clients_for_resource_update,
    save_edit_session,
    verify_client_edit_session,
)
from app.shared.services.pairing import check_approved
from app.shared.services.quota import check_quota, record_bandwidth_bytes
from app.shared.services.screenshot_upload import (
    extract_upload_token_from_request,
    finalize_screenshot_upload,
    store_screenshot_chunk,
)
from app.shared.services.sse import (
    create_sse_response,
    format_sse_frame,
    publish_account_event,
    subscribe_topic_channel,
    wait_for_queue_event,
)
from app.shared.runtime import get_command_servicer, get_session_manager

router = APIRouter()
logger = logging.getLogger(__name__)

# Registered valid resource types
VALID_RESOURCES = [
    "ClassPlan",
    "TimeLayout",
    "Subjects",
    "Policy",
    "DefaultSettings",
    "Components",
    "Credentials",
]

_LOOPBACK_IPS = {"127.0.0.1", "::1", "localhost", "testclient"}


def _ip_matches(grpc_ip: str, req_ip: str) -> bool:
    """Verify whether the HTTP request IP matches the client's registered gRPC IP."""
    if not grpc_ip or not req_ip:
        return False
    if grpc_ip == req_ip:
        return True
    return grpc_ip in _LOOPBACK_IPS and req_ip in _LOOPBACK_IPS


def _build_empty_manifest(
    org_name: str = "MINI ClassIsland Server",
) -> ClientManifest:
    """Build metadata-only Manifest without resource URLs for unregistered clients."""
    empty_src = {"Value": "", "Version": 0}
    return ClientManifest(
        ClassPlanSource=empty_src,
        TimeLayoutSource=empty_src,
        SubjectsSource=empty_src,
        DefaultSettingsSource=empty_src,
        PolicySource=empty_src,
        ComponentsSource=empty_src,
        CredentialSource=empty_src,
        ServerKind=1,
        OrganizationName=org_name,
        CoreVersion="2.6.4",
        ServerFlavor="miniclassisland",
        ServerSoftware="MINI ClassIsland",
    )


@router.get(
    "/v1/client/{client_uid}/manifest", response_model=ClientManifest, tags=["Client"]
)
@router.get(
    "/api/v1/client/{client_uid}/manifest",
    response_model=ClientManifest,
    tags=["Client"],
)
async def get_client_manifest(
    request: Request,
    response: Response,
    client_uid: str,
    db: AsyncSession = Depends(get_db),
):
    """Build Manifest JSON payload for requested client UID.

    - If the client has not joined management (no active ClientRecord), returns a
      metadata-only Manifest without any resource download URLs.
    - If the client has joined management, verifies that the HTTP request IP matches
      the gRPC IP recorded on the ClientRecord before issuing one-time `/get?token=...` URLs.
    """
    slug = getattr(request.state, "tenant_slug", "Unknown")
    response.headers["X-MiniClassIsland-Server"] = "miniclassisland"
    response.headers["X-Server-Flavor"] = "miniclassisland"
    tenant_id = get_tenant_id_or_default()
    client_ip = get_client_ip_from_request(request)
    short_uid = (
        f"{client_uid[:8]}...{client_uid[-5:]}" if len(client_uid) > 13 else client_uid
    )
    logger.info(
        "[%s][%s][%s] Client API Details: Requested Manifest",
        client_ip,
        slug,
        short_uid,
    )

    account = None
    if tenant_id and tenant_id != "default":
        if not await check_quota(tenant_id, "max_bandwidth_mb", db):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Account bandwidth quota (max_bandwidth_mb) exceeded",
            )
        account = (
            await get_cached_account(slug) if slug and slug != "Unknown" else None
        ) or (
            await db.execute(select(Account).where(Account.id == tenant_id))
        ).scalar_one_or_none()
    org_name = account.name if account and account.name else "MINI ClassIsland Server"

    client_record = (
        await db.execute(
            select(ClientRecord).where(
                ClientRecord.uid == client_uid,
                ClientRecord.account_id == tenant_id,
            )
        )
    ).scalar_one_or_none()

    if client_record is None:
        response.headers["X-Client-Registration-Status"] = "unregistered"
        record_bandwidth_bytes(tenant_id, 512)
        return _build_empty_manifest(org_name)
    if getattr(client_record, "is_disabled", False):
        response.headers["X-Client-Registration-Status"] = "disabled"
        record_bandwidth_bytes(tenant_id, 512)
        return _build_empty_manifest(org_name)
    response.headers["X-Client-Registration-Status"] = "registered"

    raw_extend = (
        (
            request.headers.get("x-extend-management-enabled")
            or request.headers.get("x-mci-extend-management")
            or ""
        )
        .strip()
        .lower()
    )
    if raw_extend in ("1", "true", "yes"):
        ext_ver = (
            request.headers.get("x-extend-management-version") or "2.0.0.4"
        ).strip()
        sm_ext = get_session_manager(request)
        if sm_ext is not None:
            await sm_ext.mark_client_extend_enabled(
                tenant_id,
                client_uid,
                version=ext_ver,
            )
        if (
            not getattr(client_record, "extend_management_enabled", False)
            or getattr(client_record, "extend_management_version", None) != ext_ver
        ):
            client_record.extend_management_enabled = True
            client_record.extend_management_version = ext_ver
            await db.commit()

    session_header = (
        request.headers.get("x-client-session") or request.headers.get("session") or ""
    ).strip()
    if session_header:
        sm = get_session_manager(request)
        session_uid = (
            await sm.validate_session(session_header, tenant_id=tenant_id)
            if sm is not None
            else None
        )
        if session_uid != client_uid:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid client session",
            )
    elif not _ip_matches(client_record.ip, client_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Client IP address mismatch",
        )

    # Resolve client-specific profile and account '__default__' fallback in a single query
    stmt = select(ClientProfile).where(
        ClientProfile.account_id == tenant_id,
        ClientProfile.client_id.in_([client_uid, "__default__"]),
    )
    prof_rows = (await db.execute(stmt)).scalars().all()
    prof_map = {row.client_id: row for row in prof_rows}
    if "__default__" not in prof_map:
        await seed_account_defaults(tenant_id, db, fast_check=True)
        prof_rows = (await db.execute(stmt)).scalars().all()
        prof_map = {row.client_id: row for row in prof_rows}
    p = prof_map.get(client_uid) or prof_map.get("__default__") or ClientProfile()

    cp = p.class_plan if p.class_plan is not None else "default"
    tl = p.time_layout if p.time_layout is not None else "default"
    sub = p.subjects if p.subjects is not None else "default"
    ds = p.default_settings if p.default_settings is not None else "default"
    pol = p.policy if p.policy is not None else "default"
    comp = p.components if p.components is not None else "default"
    cred = p.credentials if p.credentials is not None else "default"

    resource_names = {
        "ClassPlan": cp,
        "TimeLayout": tl,
        "Subjects": sub,
        "DefaultSettings": ds,
        "Policy": pol,
        "Components": comp,
        "Credentials": cred,
    }

    get_base_url = request.url_for("get_resource_by_token")
    sources: dict[str, dict] = {}
    for rt, res_name in resource_names.items():
        if not res_name:
            sources[rt] = {"Value": "", "Version": 0}
            continue
        model = MODEL_MAP[rt]
        ver_val = (
            await db.execute(
                select(model.version)
                .where(
                    model.account_id == tenant_id,
                    model.name == res_name,
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        if ver_val is None:
            sources[rt] = {"Value": "", "Version": 0}
        else:
            token = await create_token(tenant_id, rt, res_name, client_ip=client_ip)
            full_url = str(get_base_url.include_query_params(token=token))
            sources[rt] = {"Value": full_url, "Version": max(1, int(ver_val or 1))}

    record_bandwidth_bytes(tenant_id, 1024)
    raw_display_name = (getattr(client_record, "display_name", "") or "").strip()
    raw_client_id = (getattr(client_record, "client_id", "") or "").strip()
    return ClientManifest(
        ClassPlanSource=sources["ClassPlan"],
        TimeLayoutSource=sources["TimeLayout"],
        SubjectsSource=sources["Subjects"],
        DefaultSettingsSource=sources["DefaultSettings"],
        PolicySource=sources["Policy"],
        ComponentsSource=sources["Components"],
        CredentialSource=sources["Credentials"],
        ServerKind=1,
        OrganizationName=org_name,
        CoreVersion="2.6.4",
        ServerFlavor="miniclassisland",
        ServerSoftware="MINI ClassIsland",
        ClientDisplayName=raw_display_name or "未命名设备",
        ClientIdentity=raw_client_id,
        IsAppLocked=bool(getattr(client_record, "is_app_locked", False)),
    )


async def _evaluate_client_pairing_status(
    db: AsyncSession,
    *,
    tenant_id: str,
    client_uid: str,
    pairing_code: str,
    class_id: str,
    mac: str,
    client_ip: str | None,
    sm: Any,
) -> tuple[dict[str, Any], list[tuple[str, dict[str, Any]]]]:
    """Inspect/consume approved pairing status inside db session and return payload + events."""
    pub_key = getattr(sm, "public_key_armor", "") if sm else ""
    account_events: list[tuple[str, dict[str, Any]]] = []

    client_record = (
        await db.execute(
            select(ClientRecord).where(
                ClientRecord.uid == client_uid,
                ClientRecord.account_id == tenant_id,
            )
        )
    ).scalar_one_or_none()

    if client_record is not None:
        if getattr(client_record, "is_disabled", False):
            return {
                "status": "rejected",
                "approved": False,
                "registered": False,
                "ServerFlavor": "miniclassisland",
            }, account_events
        return {
            "status": "registered",
            "approved": True,
            "registered": True,
            "serverPublicKey": pub_key,
            "ServerFlavor": "miniclassisland",
            "ServerSoftware": "MINI ClassIsland",
            "ClientDisplayName": (
                getattr(client_record, "display_name", "") or ""
            ).strip()
            or "未命名设备",
            "ClientIdentity": (getattr(client_record, "client_id", "") or "").strip(),
        }, account_events

    stmt = (
        select(PairingCode)
        .where(
            PairingCode.client_uid == client_uid,
            PairingCode.tenant_id == tenant_id,
        )
        .order_by(PairingCode.created_at.desc())
    )
    if pairing_code:
        stmt = stmt.where(PairingCode.code == pairing_code)
    pairing_row = (await db.execute(stmt)).scalars().first()

    if pairing_row is None:
        if pairing_code:
            return {
                "status": "rejected",
                "approved": False,
                "registered": False,
                "ServerFlavor": "miniclassisland",
            }, account_events
        return {
            "status": "pending",
            "approved": False,
            "registered": False,
            "ServerFlavor": "miniclassisland",
        }, account_events

    row_status = str(getattr(pairing_row, "status", "pending") or "pending").lower()
    if row_status in ("rejected", "denied", "expired"):
        return {
            "status": row_status,
            "approved": False,
            "registered": False,
            "ServerFlavor": "miniclassisland",
        }, account_events

    if pairing_row.approved:
        effective_class_id = class_id.strip() or pairing_row.client_id or ""
        effective_mac = mac.strip() or pairing_row.client_mac or ""
        effective_ip = client_ip or pairing_row.client_ip or ""
        await check_approved(client_uid, tenant_id)
        existing_after = (
            await db.execute(
                select(ClientRecord).where(
                    ClientRecord.uid == client_uid,
                    ClientRecord.account_id == tenant_id,
                )
            )
        ).scalar_one_or_none()
        now = datetime.now(timezone.utc)
        rec = existing_after or ClientRecord(
            uid=client_uid,
            account_id=tenant_id,
            registered_at=now,
        )
        rec.account_id = tenant_id
        if effective_class_id:
            rec.client_id = effective_class_id
        if effective_mac:
            rec.mac = effective_mac
        if effective_ip:
            rec.ip = effective_ip
        rec.last_seen_at = now
        db.add(rec)
        await db.commit()
        account_events.append(
            (
                "client.status",
                {"uid": client_uid, "registered": True, "approved": True},
            )
        )
        account_events.append(
            (
                "pairing.updated",
                {
                    "client_uid": client_uid,
                    "status": "approved",
                    "code": pairing_row.code,
                },
            )
        )
        return {
            "status": "approved",
            "approved": True,
            "registered": True,
            "serverPublicKey": pub_key,
            "ServerFlavor": "miniclassisland",
            "ServerSoftware": "MINI ClassIsland",
            "ClientDisplayName": (getattr(rec, "display_name", "") or "").strip()
            or "未命名设备",
            "ClientIdentity": (getattr(rec, "client_id", "") or "").strip(),
        }, account_events

    return {
        "status": "pending",
        "approved": False,
        "registered": False,
        "code": pairing_row.code,
        "ServerFlavor": "miniclassisland",
    }, account_events


@router.get(
    "/v1/client/{client_uid}/pairing-status",
    tags=["Client"],
)
@router.get(
    "/api/v1/client/{client_uid}/pairing-status",
    tags=["Client"],
)
async def get_client_pairing_status(
    request: Request,
    response: Response,
    client_uid: str,
    code: str = "",
    class_id: str = "",
    mac: str = "",
    db: AsyncSession = Depends(get_db),
):
    """Lightweight HTTP pairing status endpoint for client pairing polling without re-triggering gRPC Register."""
    response.headers["X-MiniClassIsland-Server"] = "miniclassisland"
    response.headers["X-Server-Flavor"] = "miniclassisland"
    tenant_id = get_tenant_id_or_default()
    client_ip = get_client_ip_from_request(request)
    pairing_code = (code or request.headers.get("x-pairing-code") or "").strip().upper()
    sm = get_session_manager(request)

    payload, account_events = await _evaluate_client_pairing_status(
        db,
        tenant_id=tenant_id,
        client_uid=client_uid,
        pairing_code=pairing_code,
        class_id=class_id,
        mac=mac,
        client_ip=client_ip,
        sm=sm,
    )
    for ev_type, ev_data in account_events:
        await publish_account_event(tenant_id, ev_type, ev_data)
    return payload


@router.get(
    "/v1/client/{client_uid}/pairing-status/events",
    tags=["Client", "Realtime"],
)
@router.get(
    "/api/v1/client/{client_uid}/pairing-status/events",
    tags=["Client", "Realtime"],
)
async def subscribe_client_pairing_status_events(
    request: Request,
    client_uid: str,
    code: str = "",
    class_id: str = "",
    mac: str = "",
    timeout_seconds: float | None = Query(default=55.0, ge=1.0, le=120.0),
):
    """Stream pairing status transitions via SSE using transient short-lived DB sessions."""
    tenant_id = get_tenant_id_or_default()
    client_ip = get_client_ip_from_request(request)
    pairing_code = (code or request.headers.get("x-pairing-code") or "").strip().upper()
    sm = get_session_manager(request)

    async def _probe_once() -> dict[str, Any]:
        async with AsyncSessionLocal() as session_db:
            await set_search_path(session_db)
            payload, account_events = await _evaluate_client_pairing_status(
                session_db,
                tenant_id=tenant_id,
                client_uid=client_uid,
                pairing_code=pairing_code,
                class_id=class_id,
                mac=mac,
                client_ip=client_ip,
                sm=sm,
            )
        for ev_type, ev_data in account_events:
            await publish_account_event(tenant_id, ev_type, ev_data)
        return payload

    async def _stream():
        deadline = time.monotonic() + (timeout_seconds or 55.0)
        keepalive = 15.0
        terminal_statuses = {"approved", "registered", "rejected", "denied", "expired"}
        async with subscribe_topic_channel(f"pairing:{client_uid}") as queue:
            yield format_sse_frame(
                "connected",
                {
                    "topic": f"pairing:{client_uid}",
                    "ts": datetime.now(timezone.utc).isoformat(),
                },
            )
            initial = await _probe_once()
            yield format_sse_frame("pairing.status", initial)
            if str(initial.get("status") or "").lower() in terminal_statuses:
                return

            while True:
                if await request.is_disconnected():
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                envelope = await wait_for_queue_event(
                    queue,
                    event_types=("pairing.status",),
                    timeout_sec=min(keepalive, remaining),
                )
                if envelope is None:
                    refreshed = await _probe_once()
                    if str(refreshed.get("status") or "").lower() in terminal_statuses:
                        yield format_sse_frame("pairing.status", refreshed)
                        break
                    yield b": keepalive\n\n"
                    continue
                latest = await _probe_once()
                raw_data = envelope.get("data")
                ev_data = raw_data if isinstance(raw_data, dict) else {}
                ev_status = str(ev_data.get("status") or "").lower()
                if str(
                    latest.get("status") or ""
                ).lower() == "pending" and ev_status in (
                    "rejected",
                    "denied",
                    "expired",
                ):
                    latest = {
                        **latest,
                        "status": ev_status,
                        "approved": False,
                        "registered": False,
                    }
                yield format_sse_frame(
                    "pairing.status",
                    latest,
                    event_id=str(envelope.get("id") or "") or None,
                )
                if str(latest.get("status") or "").lower() in terminal_statuses:
                    break

    return create_sse_response(_stream())


@router.post(
    "/v1/client/{client_uid}/unregister",
    tags=["Client"],
)
@router.post(
    "/api/v1/client/{client_uid}/unregister",
    tags=["Client"],
)
async def unregister_client_http(
    request: Request,
    response: Response,
    client_uid: str,
    db: AsyncSession = Depends(get_db),
):
    """Allow a registered client device to proactively unbind from the management server upon exiting management."""
    from sqlalchemy import delete as sa_delete
    from app.shared.db.models import PreRegisteredClient

    response.headers["X-MiniClassIsland-Server"] = "miniclassisland"
    response.headers["X-Server-Flavor"] = "miniclassisland"
    tenant_id = get_tenant_id_or_default()
    client_ip = get_client_ip_from_request(request)

    rec = (
        await db.execute(
            select(ClientRecord).where(
                ClientRecord.uid == client_uid,
                ClientRecord.account_id == tenant_id,
            )
        )
    ).scalar_one_or_none()
    if rec is None:
        return {
            "status": "ok",
            "unregistered": False,
            "message": "Already unregistered",
        }

    session_header = (
        request.headers.get("x-client-session") or request.headers.get("session") or ""
    ).strip()
    sm = get_session_manager(request)
    authorized = False
    if session_header and sm is not None:
        session_uid = await sm.validate_session(session_header, tenant_id=tenant_id)
        if session_uid == client_uid:
            authorized = True
    if not authorized and _ip_matches(rec.ip, client_ip):
        authorized = True
    req_mac = (
        (request.headers.get("x-client-mac") or "").strip().upper().replace(":", "-")
    )
    rec_mac = (rec.mac or "").strip().upper().replace(":", "-")
    if not authorized and req_mac and rec_mac and req_mac == rec_mac:
        authorized = True

    if not authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized client unregistration request",
        )

    await db.execute(
        sa_delete(ClientProfile).where(
            ClientProfile.account_id == tenant_id,
            ClientProfile.client_id == client_uid,
        )
    )
    pre_rows = (
        (
            await db.execute(
                select(PreRegisteredClient).where(
                    PreRegisteredClient.account_id == tenant_id,
                    PreRegisteredClient.bound_client_uid == client_uid,
                )
            )
        )
        .scalars()
        .all()
    )
    for p in pre_rows:
        p.bound_client_uid = ""
    await db.delete(rec)
    await db.commit()

    if sm is not None:
        await sm.set_client_offline(tenant_id, client_uid)
    await publish_account_event(
        tenant_id,
        "client.status",
        {"uid": client_uid, "online": False, "removed": True},
    )
    return {"status": "ok", "unregistered": True}


@router.post(
    "/v1/client/{client_uid}/hook-snapshot",
    tags=["Client"],
)
@router.post(
    "/api/v1/client/{client_uid}/hook-snapshot",
    tags=["Client"],
)
async def report_client_hook_snapshot(
    request: Request,
    response: Response,
    client_uid: str,
    body: dict = Body(default={}),
    db: AsyncSession = Depends(get_db),
):
    """Capture and store plugin settings catalog, plugin components catalog, hardware info, and extend state reported by client Hook."""
    response.headers["X-MiniClassIsland-Server"] = "miniclassisland"
    response.headers["X-Server-Flavor"] = "miniclassisland"
    tenant_id = get_tenant_id_or_default()
    client_ip = get_client_ip_from_request(request)

    rec = (
        await db.execute(
            select(ClientRecord).where(
                ClientRecord.uid == client_uid,
                ClientRecord.account_id == tenant_id,
            )
        )
    ).scalar_one_or_none()
    if rec is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    session_header = (
        request.headers.get("x-client-session") or request.headers.get("session") or ""
    ).strip()
    sm = get_session_manager(request)
    authorized = False
    if session_header and sm is not None:
        session_uid = await sm.validate_session(session_header, tenant_id=tenant_id)
        if session_uid == client_uid:
            authorized = True
    if not authorized and _ip_matches(rec.ip, client_ip):
        authorized = True
    req_mac = (
        (request.headers.get("x-client-mac") or "").strip().upper().replace(":", "-")
    )
    rec_mac = (rec.mac or "").strip().upper().replace(":", "-")
    if not authorized and req_mac and rec_mac and req_mac == rec_mac:
        authorized = True

    if not authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized client hook snapshot request",
        )

    ext_ver = str(
        body.get("extend_management_version")
        or body.get("version")
        or request.headers.get("x-extend-management-version")
        or "2.0.0.4"
    ).strip()
    rec.extend_management_enabled = True
    rec.extend_management_version = ext_ver
    if sm is not None:
        await sm.mark_client_extend_enabled(tenant_id, client_uid, version=ext_ver)

    if "is_app_locked" in body and body["is_app_locked"] is not None:
        rec.is_app_locked = bool(body["is_app_locked"])
    elif "isAppLocked" in body and body["isAppLocked"] is not None:
        rec.is_app_locked = bool(body["isAppLocked"])

    settings_cat = (
        body.get("plugin_settings")
        if "plugin_settings" in body
        else body.get("settingsCatalog")
    )
    if settings_cat is not None:
        rec.plugin_settings_json = (
            settings_cat
            if isinstance(settings_cat, str)
            else json.dumps(settings_cat, ensure_ascii=False)
        )

    comp_cat = (
        body.get("plugin_components")
        if "plugin_components" in body
        else body.get("registeredComponents")
    )
    if comp_cat is not None:
        rec.plugin_components_json = (
            comp_cat
            if isinstance(comp_cat, str)
            else json.dumps(comp_cat, ensure_ascii=False)
        )

    hw_info = (
        body.get("hardware_info")
        if "hardware_info" in body
        else body.get("hardwareInfo")
    )
    if hw_info is not None:
        rec.hardware_info_json = (
            hw_info
            if isinstance(hw_info, str)
            else json.dumps(hw_info, ensure_ascii=False)
        )

    rec.last_seen_at = datetime.now(timezone.utc)
    await db.commit()
    await publish_account_event(
        tenant_id,
        "client.status",
        {
            "uid": client_uid,
            "extend_management_enabled": rec.extend_management_enabled,
            "extend_management_version": rec.extend_management_version,
            "is_app_locked": rec.is_app_locked,
        },
    )
    return {
        "status": "ok",
        "uid": client_uid,
        "extend_management_enabled": rec.extend_management_enabled,
        "extend_management_version": rec.extend_management_version,
        "is_app_locked": rec.is_app_locked,
    }


async def _ensure_active_editor_client(
    db: AsyncSession, account_id: str, client_uid: str
) -> ClientRecord:
    rec = (
        await db.execute(
            select(ClientRecord).where(
                ClientRecord.account_id == account_id,
                ClientRecord.uid == client_uid,
            )
        )
    ).scalar_one_or_none()
    if rec is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Editor client not found"
        )
    if rec.is_disabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Editor client is disabled"
        )
    if rec.is_app_locked:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Editor client is currently locked",
        )
    return rec


def _collect_account_plugin_metadata(
    rows: list[ClientRecord],
) -> tuple[list[Any], list[Any]]:
    comp_map: dict[str, Any] = {}
    settings_map: dict[str, Any] = {}
    for row in rows:
        raw_comp = getattr(row, "plugin_components_json", None)
        if raw_comp:
            try:
                parsed = json.loads(raw_comp)
                items = (
                    parsed.get("components", [])
                    if isinstance(parsed, dict)
                    else (parsed if isinstance(parsed, list) else [])
                )
                from app.shared.utils.plugin_components import (
                    normalize_plugin_component_item,
                )

                for idx, item in enumerate(items):
                    if isinstance(item, dict):
                        normalized = normalize_plugin_component_item(item)
                        if normalized is not None:
                            cid = normalized["id"]
                            existing = comp_map.get(cid)
                            if existing is None:
                                comp_map[cid] = normalized
                            elif normalized.get(
                                "isComponentContainer"
                            ) and not existing.get("isComponentContainer"):
                                existing["isComponentContainer"] = True
                                existing["isContainer"] = True
                        else:
                            cid = str(
                                item.get("id") or item.get("guid") or f"{row.uid}:{idx}"
                            )
                            comp_map.setdefault(cid, item)
            except Exception:
                pass
        raw_set = getattr(row, "plugin_settings_json", None)
        if raw_set:
            try:
                parsed_s = json.loads(raw_set)
                items_s = (
                    parsed_s.get("settings", [])
                    if isinstance(parsed_s, dict)
                    else (parsed_s if isinstance(parsed_s, list) else [])
                )
                for idx, item in enumerate(items_s):
                    if isinstance(item, dict):
                        sid = str(
                            item.get("id") or item.get("Id") or f"{row.uid}:s:{idx}"
                        )
                        settings_map.setdefault(sid, item)
            except Exception:
                pass
    return list(comp_map.values()), list(settings_map.values())


@router.get("/v1/client/{client_uid}/edit-session/{session_id}/bootstrap")
@router.get("/api/v1/client/{client_uid}/edit-session/{session_id}/bootstrap")
async def bootstrap_client_edit_session(
    client_uid: str,
    session_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Bootstrap isolated shadow editor data for RemoteEdit or pure-relay AssistAnother."""
    token = request.headers.get("X-Edit-Session-Token", "")
    tenant_id = get_tenant_id_or_default()
    session = await verify_client_edit_session(
        session_id=session_id,
        client_uid=client_uid,
        token=token,
        tenant_id=tenant_id,
    )
    account_id = session["account_id"]
    await _ensure_active_editor_client(db, account_id, client_uid)

    if session["mode"] == "AssistAnother":
        await save_edit_session(session)
        return {
            "status": "ok",
            "mode": "AssistAnother",
            "session_id": session_id,
            "target_client_uid": session.get("target_client_uid"),
            "target_display_name": session.get("target_display_name", ""),
            "initial_view": session.get("initial_view", "profile"),
            "allowed_scopes": session.get("allowed_scopes", []),
            "snapshot": session.get("relay_snapshot") or {},
            "plugin_components": session.get("target_plugin_components") or [],
            "plugin_settings": session.get("target_plugin_settings") or [],
        }

    # RemoteEdit: load editable resources plus read-only reference dependencies (TimeLayout/Subjects)
    allowed_scopes = list(session.get("allowed_scopes", []))
    readable_scopes = set(allowed_scopes)
    if "ClassPlan" in readable_scopes:
        readable_scopes.update(["TimeLayout", "Subjects"])
    elif "TimeLayout" in readable_scopes:
        readable_scopes.add("Subjects")

    resources: dict[str, Any] = {}
    versions: dict[str, int] = {}
    for res_type, res_name in (session.get("resource_targets") or {}).items():
        if res_type not in readable_scopes:
            continue
        model = MODEL_MAP.get(res_type)
        if model is None:
            continue
        rec = (
            await db.execute(
                select(model).where(
                    model.account_id == account_id,
                    model.name == res_name,
                )
            )
        ).scalar_one_or_none()
        if rec is not None:
            try:
                parsed = json.loads(rec.content or "{}")
            except Exception:
                parsed = {}
            if res_type in allowed_scopes:
                versions[res_type] = rec.version or 1
        else:
            parsed = dict(DEFAULT_RESOURCES.get(res_type, {}).get("default", {}))
            if res_type in allowed_scopes:
                versions[res_type] = 0
        resources[res_type] = normalize_resource_payload(res_type, parsed)

    client_rows = (
        (
            await db.execute(
                select(ClientRecord).where(ClientRecord.account_id == account_id)
            )
        )
        .scalars()
        .all()
    )
    plugin_components, plugin_settings = _collect_account_plugin_metadata(
        list(client_rows)
    )

    session["base_versions"] = dict(versions)
    await save_edit_session(session)

    return {
        "status": "ok",
        "mode": "RemoteEdit",
        "session_id": session_id,
        "target_client_uid": session.get("target_client_uid"),
        "target_display_name": session.get("target_display_name", ""),
        "initial_view": session.get("initial_view", "profile"),
        "allowed_scopes": session.get("allowed_scopes", []),
        "resource_targets": session.get("resource_targets", {}),
        "versions": versions,
        "resources": resources,
        "plugin_components": plugin_components,
        "plugin_settings": plugin_settings,
    }


@router.post("/v1/client/{client_uid}/edit-session/{session_id}/sync")
@router.post("/api/v1/client/{client_uid}/edit-session/{session_id}/sync")
async def sync_client_edit_session(
    client_uid: str,
    session_id: str,
    request: Request,
    body: EditSessionClientSyncRequest,
    db: AsyncSession = Depends(get_db),
):
    """Apply debounced delta sync from editor client (DB persistence for RemoteEdit; pure E2E relay for AssistAnother)."""
    from app.client.get import invalidate_resource_cache
    from app.management.account import _validate_resource_name, validate_payload

    token = request.headers.get("X-Edit-Session-Token", "")
    tenant_id = get_tenant_id_or_default()
    session = await verify_client_edit_session(
        session_id=session_id,
        client_uid=client_uid,
        token=token,
        tenant_id=tenant_id,
    )
    account_id = session["account_id"]
    await _ensure_active_editor_client(db, account_id, client_uid)

    current_seq = int(session.get("last_sequence", 0))
    if body.sequence is not None and body.sequence <= current_seq:
        return {"status": "ignored_stale", "last_sequence": current_seq}
    next_seq = body.sequence if body.sequence is not None else current_seq + 1

    allowed_scopes = set(session.get("allowed_scopes") or [])
    for scope, scope_payload in (body.changes or {}).items():
        if scope not in allowed_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Scope '{scope}' is not permitted in this edit session",
            )
        if not isinstance(scope_payload, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Payload for '{scope}' must be a JSON object",
            )
        validate_payload(scope_payload)

    if session["mode"] == "AssistAnother":
        target_uid = (session.get("target_client_uid") or "").strip()
        sm = get_session_manager(request)
        servicer = get_command_servicer(request)
        if (
            sm is None
            or servicer is None
            or not target_uid
            or not await sm.is_client_online(account_id, target_uid)
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="Target client is offline"
            )

        if body.changes:
            delivered, req_guid = await dispatch_signed_extend_command(
                account_id=account_id,
                client_uid=target_uid,
                action="assist.apply_snapshot",
                payload={
                    "session_id": session_id,
                    "editor_client_uid": client_uid,
                    "changes": body.changes,
                    "sequence": next_seq,
                },
                sm=sm,
                servicer=servicer,
                db=db,
                ttl_seconds=60,
                record_upload=False,
            )
            if not delivered:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Failed to relay changes to target client",
                )
        else:
            req_guid = ""

        def _mutate_assist(s: dict[str, Any]) -> None:
            snap = dict(s.get("relay_snapshot") or {})
            for k, v in (body.changes or {}).items():
                snap[k] = v
            s["relay_snapshot"] = snap
            s["last_sequence"] = next_seq

        await save_edit_session(session, mutator=_mutate_assist)
        await publish_account_event(
            account_id,
            "edit_session.updated",
            {
                "session_id": session_id,
                "mode": "AssistAnother",
                "action": "synced",
                "last_sequence": next_seq,
            },
        )
        return {
            "status": "ok",
            "mode": "AssistAnother",
            "relayed_scopes": list((body.changes or {}).keys()),
            "last_sequence": next_seq,
            "command_request_guid": req_guid,
        }

    # RemoteEdit mode: persist changes to server Resource tables with optimistic version checking
    now = datetime.now(timezone.utc)
    updated_versions: dict[str, int] = dict(session.get("base_versions") or {})
    updated_targets: list[tuple[str, str]] = []
    req_versions = body.base_versions or {}
    resource_targets = session.get("resource_targets") or {}

    for res_type, raw_payload in (body.changes or {}).items():
        res_name = _validate_resource_name(resource_targets.get(res_type, "default"))
        model = MODEL_MAP.get(res_type)
        if model is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported resource type: {res_type}",
            )
        existing = (
            await db.execute(
                select(model).where(
                    model.account_id == account_id,
                    model.name == res_name,
                )
            )
        ).scalar_one_or_none()

        expected_ver = req_versions.get(res_type, updated_versions.get(res_type))
        if (
            not body.force
            and existing is not None
            and expected_ver is not None
            and expected_ver != 0
            and (existing.version or 1) != expected_ver
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Version conflict on {res_type}/{res_name}: server={existing.version}, base={expected_ver}",
            )

        normalized = normalize_resource_payload(res_type, raw_payload)
        serialized = json.dumps(normalized, ensure_ascii=False)
        if existing is None:
            next_version = 1
            db.add(
                model(
                    account_id=account_id,
                    name=res_name,
                    content=serialized,
                    version=1,
                    updated_at=now,
                )
            )
        else:
            next_version = (existing.version or 0) + 1
            existing.content = serialized
            existing.version = next_version
            existing.updated_at = now

        db.add(
            ResourceHistory(
                account_id=account_id,
                resource_type=res_type,
                name=res_name,
                version=next_version,
                content=serialized,
                created_at=now,
            )
        )
        updated_versions[res_type] = next_version
        updated_targets.append((res_type, res_name))

    if updated_targets:
        await db.commit()
        for res_type, res_name in updated_targets:
            invalidate_resource_cache(account_id, res_type, res_name)

    sync_results: dict[str, dict[str, int]] = {}
    if body.notify_clients:
        targets_to_notify = (
            updated_targets
            if updated_targets
            else [
                (rt, rn) for rt, rn in resource_targets.items() if rt in allowed_scopes
            ]
        )
        sm = get_session_manager(request)
        servicer = get_command_servicer(request)
        for res_type, res_name in targets_to_notify:
            sync_results[res_type] = await notify_clients_for_resource_update(
                account_id, res_type, res_name, db, servicer=servicer, sm=sm
            )

    def _mutate_remote(s: dict[str, Any]) -> None:
        s["base_versions"] = updated_versions
        s["last_sequence"] = next_seq

    await save_edit_session(session, mutator=_mutate_remote)
    updated_resources = [
        {
            "resource_type": rt,
            "name": rn,
            "version": updated_versions.get(rt),
        }
        for rt, rn in updated_targets
    ]
    await publish_account_event(
        account_id,
        "edit_session.updated",
        {
            "session_id": session_id,
            "mode": "RemoteEdit",
            "action": "synced",
            "last_sequence": next_seq,
            "resource_targets": {
                rt: resource_targets.get(rt, "default") for rt in allowed_scopes
            },
            "updated_resources": updated_resources,
        },
    )
    for res_type, res_name in updated_targets:
        await publish_account_event(
            account_id,
            "resource.updated",
            {
                "resource_type": res_type,
                "name": res_name,
                "version": updated_versions.get(res_type),
                "action": "edit_session_sync",
                "session_id": session_id,
            },
        )
    resp_out: dict[str, Any] = {
        "status": "ok",
        "mode": "RemoteEdit",
        "versions": updated_versions,
        "last_sequence": next_seq,
    }
    if body.notify_clients:
        resp_out["sync"] = sync_results
    return resp_out


@router.post("/v1/client/{client_uid}/edit-session/{session_id}/close")
@router.post("/api/v1/client/{client_uid}/edit-session/{session_id}/close")
async def close_client_edit_session(
    client_uid: str,
    session_id: str,
    request: Request,
):
    """Close and remove an active ephemeral edit session from Redis."""
    token = request.headers.get("X-Edit-Session-Token", "")
    tenant_id = get_tenant_id_or_default()
    session = await verify_client_edit_session(
        session_id=session_id,
        client_uid=client_uid,
        token=token,
        tenant_id=tenant_id,
    )
    await delete_edit_session(session_id, session["account_id"])
    await publish_account_event(
        session["account_id"],
        "edit_session.updated",
        {
            "session_id": session_id,
            "mode": session.get("mode", ""),
            "action": "closed",
            "initial_view": session.get("initial_view", ""),
            "allowed_scopes": session.get("allowed_scopes", []),
            "resource_targets": session.get("resource_targets", {}),
        },
    )
    return {"status": "closed", "session_id": session_id}


def _parse_int_param(query_val: int | None, header_val: str | None, name: str) -> int:
    """Parse required integer parameter from query param or header."""
    if query_val is not None:
        return query_val
    if header_val is not None and header_val.strip():
        try:
            return int(header_val.strip())
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid integer value for {name}",
            ) from exc
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Missing required parameter: {name}",
    )


@router.put(
    "/v1/client/{client_uid}/screenshot-upload/{request_guid}/chunk", tags=["Client"]
)
@router.put(
    "/api/v1/client/{client_uid}/screenshot-upload/{request_guid}/chunk",
    tags=["Client"],
)
@router.post(
    "/v1/client/{client_uid}/screenshot-upload/{request_guid}/chunk", tags=["Client"]
)
@router.post(
    "/api/v1/client/{client_uid}/screenshot-upload/{request_guid}/chunk",
    tags=["Client"],
)
async def upload_client_screenshot_chunk(
    client_uid: str,
    request_guid: str,
    request: Request,
    chunk_index: int | None = None,
    total_chunks: int | None = None,
    token: str = "",
):
    """Receive a single <= 1 MiB binary screenshot chunk authenticated by one-time token."""
    idx_val = _parse_int_param(
        chunk_index, request.headers.get("x-chunk-index"), "chunk_index"
    )
    total_val = _parse_int_param(
        total_chunks, request.headers.get("x-total-chunks"), "total_chunks"
    )
    upload_token = extract_upload_token_from_request(request, token)
    chunk_sha = (request.headers.get("x-chunk-sha256") or "").strip()
    chunk_bytes = await request.body()
    return await store_screenshot_chunk(
        client_uid=client_uid,
        request_guid=request_guid,
        chunk_index=idx_val,
        total_chunks=total_val,
        chunk_bytes=chunk_bytes,
        token=upload_token,
        chunk_sha256=chunk_sha,
        request_account_id=get_tenant_id_or_default(),
    )


@router.post(
    "/v1/client/{client_uid}/screenshot-upload/{request_guid}/complete", tags=["Client"]
)
@router.post(
    "/api/v1/client/{client_uid}/screenshot-upload/{request_guid}/complete",
    tags=["Client"],
)
async def complete_client_screenshot_upload(
    client_uid: str,
    request_guid: str,
    request: Request,
    body: dict[str, Any] = Body(default={}),
    token: str = "",
    db: AsyncSession = Depends(get_db),
):
    """Finalize and reassemble chunked screenshot upload into verified image blob and command status."""
    upload_token = extract_upload_token_from_request(request, token)
    raw_total_chunks = (
        body.get("totalChunks")
        if body.get("totalChunks") is not None
        else body.get("total_chunks")
    )
    raw_total_bytes = (
        body.get("totalBytes")
        if body.get("totalBytes") is not None
        else body.get("total_bytes")
    )
    raw_display_index = (
        body.get("displayIndex")
        if body.get("displayIndex") is not None
        else body.get("display_index")
    )
    total_chunks = int(raw_total_chunks or 0)
    total_bytes = int(raw_total_bytes or 0)
    return await finalize_screenshot_upload(
        db=db,
        client_uid=client_uid,
        request_guid=request_guid,
        total_chunks=total_chunks,
        total_bytes=total_bytes,
        sha256_hex=str(body.get("sha256") or ""),
        mime_type=str(body.get("mimeType") or body.get("mime_type") or "image/png"),
        width=int(body.get("width") or 0),
        height=int(body.get("height") or 0),
        original_width=int(
            body.get("originalWidth") or body.get("original_width") or 0
        ),
        original_height=int(
            body.get("originalHeight") or body.get("original_height") or 0
        ),
        bounds_x=int(body.get("boundsX") or body.get("bounds_x") or 0),
        bounds_y=int(body.get("boundsY") or body.get("bounds_y") or 0),
        display_index=int(raw_display_index or 0),
        captured_at=str(body.get("capturedAt") or body.get("captured_at") or ""),
        token=upload_token,
        request_account_id=get_tenant_id_or_default(),
    )
