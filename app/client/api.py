import json
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.db.models import (
    ClientRecord,
    ClientProfile,
    Account,
    PairingCode,
    MODEL_MAP,
)
from app.shared.db.schema_init import seed_account_defaults
from app.shared.schemas.schemas import ClientManifest
from app.shared.utils.logging import get_client_ip_from_request
from app.shared.utils.tenant import (
    get_tenant_id_or_default,
    get_cached_account,
)
from app.shared.security.auth import create_token
from app.shared.services.pairing import check_approved
from app.shared.services.quota import check_quota, record_bandwidth_bytes
from app.shared.runtime import get_session_manager

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
        CoreVersion="2.6.1",
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
            request.headers.get("x-extend-management-version") or "2.0.0.3"
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
        CoreVersion="2.6.1",
        ServerFlavor="miniclassisland",
        ServerSoftware="MINI ClassIsland",
        ClientDisplayName=raw_display_name or "未命名设备",
        ClientIdentity=raw_client_id,
        IsAppLocked=bool(getattr(client_record, "is_app_locked", False)),
    )


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
    pub_key = sm.public_key_armor if sm else ""

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
            }
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
        }

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
            }
        return {
            "status": "pending",
            "approved": False,
            "registered": False,
            "ServerFlavor": "miniclassisland",
        }

    row_status = str(getattr(pairing_row, "status", "pending") or "pending").lower()
    if row_status in ("rejected", "denied", "expired"):
        return {
            "status": row_status,
            "approved": False,
            "registered": False,
            "ServerFlavor": "miniclassisland",
        }

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
        }

    return {
        "status": "pending",
        "approved": False,
        "registered": False,
        "code": pairing_row.code,
        "ServerFlavor": "miniclassisland",
    }


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
        or "2.0.0.3"
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
    return {
        "status": "ok",
        "uid": client_uid,
        "extend_management_enabled": rec.extend_management_enabled,
        "extend_management_version": rec.extend_management_version,
        "is_app_locked": rec.is_app_locked,
    }
