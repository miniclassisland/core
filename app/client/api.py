import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
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
        CoreVersion="2.0.0.0",
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
    response.headers["X-MiniClassIsland-Server"] = "1"
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

    if client_record is None or getattr(client_record, "is_disabled", False):
        record_bandwidth_bytes(tenant_id, 512)
        return _build_empty_manifest(org_name)

    session_header = (
        request.headers.get("x-client-session") or request.headers.get("session") or ""
    ).strip()
    if session_header:
        sm = get_session_manager()
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
        CoreVersion="2.0.0.0",
        ServerFlavor="miniclassisland",
        ServerSoftware="MINI ClassIsland",
        ClientDisplayName=raw_display_name or "未命名设备",
        ClientIdentity=raw_client_id,
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
    response.headers["X-MiniClassIsland-Server"] = "1"
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
