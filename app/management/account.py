import asyncio
import inspect
import json
import logging
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy import select, delete, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.db.models import (
    Account,
    AccountMember,
    User,
    PreRegisteredClient,
    PairingCode,
    Invitation,
    ClientRecord,
    ClientProfile,
    ConfigUploadRecord,
    AuditLog,
    SystemConfig,
    ResourceHistory,
    MODEL_MAP,
)
from app.shared.db.schema_init import seed_account_defaults, record_resource_history
from app.shared.schemas.schemas import (
    AccountOut,
    AccountCreate,
    AccountUpdate,
    AccountIdUpdate,
    AccountNameUpdate,
    SlugUpdate,
    AccessMemberOut,
    AccessRoleUpdate,
    InvitationOut,
    InvitationCreate,
    InvitationAcceptRequest,
    PairingCodeOut,
    PreRegCreate,
    PreRegBatchCreate,
    PreRegOut,
    StatusResponse,
    NotificationPayload,
    BroadcastNotificationPayload,
    ExtendCommandRequest,
    BroadcastExtendCommandRequest,
    BatchRequest,
)
from app.shared.security.auth import (
    get_current_user_id,
    create_token,
)
from app.shared.security.crypto import (
    encode_classisland_credential,
    normalize_resource_payload,
)
from app.shared.services.user import (
    create_account,
    update_account_info,
    update_account_slug,
    validate_slug_format,
    is_name_reserved,
    cleanup_account_data,
)
from app.shared.security.middlewares import record_ip_failure
from app.shared.utils.logging import get_client_ip_from_request
from app.shared.services.quota import (
    get_quotas,
    set_quota,
    get_bandwidth_mb,
    check_quota,
)
from app.shared.schemas.schemas import QuotaOut, QuotaSetRequest
from app.shared.literals import AUDIT_EVENT_NAMES, CONFIG_TYPE_NAMES, DEFAULT_RESOURCES
from app.shared.runtime import get_session_manager, get_command_servicer
from app.shared.utils.config import BASE_DOMAIN
from app.shared.utils.tenant import invalidate_cached_account

logger = logging.getLogger(__name__)

router = APIRouter()


# ---- 1. Tenant Context Adaptive Dependency ----

_VALID_ACCOUNT_ROLES = {"owner", "admin", "member", "viewer"}


async def _get_effective_account_role(
    account_id: str,
    user_id: str,
    db: AsyncSession,
) -> Optional[str]:
    """Return effective role in account ('owner' for superadmin, 'viewer' for pending, else member role or None)."""
    member = (
        await db.execute(
            select(AccountMember).where(
                AccountMember.account_id == account_id,
                AccountMember.user_id == user_id,
            )
        )
    ).scalar_one_or_none()
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if u and u.role_code == "superadmin":
        return "owner"
    if member:
        if u and u.role_code == "pending":
            return "viewer"
        return member.role_in_account or "member"
    return None


async def _require_account_admin(
    account_id: str,
    user_id: str,
    db: AsyncSession,
) -> str:
    """Ensure caller has owner or admin role in the account."""
    role = await _get_effective_account_role(account_id, user_id, db)
    if role not in ("owner", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only account owner or admin can perform this operation",
        )
    return role


async def setup_tenant_context(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
    request: Request = None,  # type: ignore[assignment]
):
    """Set tenant ID and database search_path in coroutine context, and verify member permissions."""
    from app.shared.utils.tenant import tenant_ctx, schema_ctx, set_search_path

    cached_acct = (
        getattr(request.state, "current_account", None)
        if isinstance(request, Request)
        else None
    )
    if isinstance(cached_acct, Account) and cached_acct.id == account_id:
        account = cached_acct
    else:
        stmt = select(Account).where(Account.id == account_id)
        account = (await db.execute(stmt)).scalar_one_or_none()
    if not account or not account.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account invalid or non-existent",
        )

    role = await _get_effective_account_role(account_id, user_id, db)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized access: You are not a member of this account",
        )

    if isinstance(request, Request):
        request.state.role_in_account = role
        path = request.url.path
        path_lower = path.lower()
        is_mutating_get = path_lower.endswith(
            ("/create", "/delete", "/command/get-config")
        )
        is_credentials_path = f"/account/{account_id.lower()}/credentials" in path_lower
        if role == "viewer":
            if (
                request.method not in ("GET", "HEAD", "OPTIONS")
                or is_mutating_get
                or is_credentials_path
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Viewer role has read-only access and cannot access Credentials",
                )
        elif role == "member":
            if is_credentials_path:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only account owner or admin can access Credentials",
                )
            is_admin_only_path = any(
                seg in path_lower
                for seg in (
                    "/pairing/",
                    "/pre-registration/",
                    "/broadcast/",
                    f"/account/{account_id.lower()}/policy/",
                    "/client/",
                )
            )
            if is_admin_only_path and (
                request.method not in ("GET", "HEAD", "OPTIONS") or is_mutating_get
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only account owner or admin can perform this operation",
                )

    tenant_ctx.set(account.id)
    schema_ctx.set(f"tenant_{account.slug}")
    await set_search_path(db)


def _account_out(a: Account, *, include_api_key: bool = True) -> AccountOut:
    return AccountOut(
        id=a.id,
        name=a.name,
        slug=a.slug,
        api_key=a.api_key if include_api_key else "",
        is_active=a.is_active,
        registration_mode=getattr(a, "registration_mode", "pairing") or "pairing",
        created_at=(
            a.created_at.isoformat()
            if hasattr(a.created_at, "isoformat")
            else str(a.created_at)
        ),
    )


# ---- 2. Tenant Account Management ----


@router.get("/account/availability/slug", tags=["Availability"])
async def check_slug_availability(
    value: str = Query(..., min_length=3, max_length=64, description="Slug to check"),
    db: AsyncSession = Depends(get_db),
):
    """Check if account slug is available."""
    if not validate_slug_format(value):
        return {"available": False, "reason": "Slug format invalid"}
    if await is_name_reserved(value, db):
        return {"available": False, "reason": "Name is reserved by system"}
    result = await db.execute(select(Account.id).where(Account.slug == value))
    if result.scalar_one_or_none() is not None:
        return {"available": False, "reason": "Slug is already taken"}
    return {"available": True}


@router.get("/account/list", response_model=list[AccountOut], tags=["Account"])
async def list_accounts(
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """List all accounts that the current user has access to."""
    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    is_pending = bool(user and user.role_code == "pending")
    is_superadmin = bool(user and user.role_code == "superadmin")
    stmt = (
        select(Account, AccountMember.role_in_account)
        .join(AccountMember, Account.id == AccountMember.account_id)
        .where(AccountMember.user_id == user_id)
        .where(Account.is_active.is_(True))
    )
    rows = (await db.execute(stmt)).all()
    return [
        _account_out(
            a,
            include_api_key=(
                not is_pending and (is_superadmin or role in ("owner", "admin"))
            ),
        )
        for a, role in rows
    ]


@router.post("/account/search", response_model=list[AccountOut], tags=["Account"])
async def search_accounts(
    q: str = "",
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Search accessible accounts by name."""
    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    is_pending = bool(user and user.role_code == "pending")
    is_superadmin = bool(user and user.role_code == "superadmin")
    escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    stmt = (
        select(Account, AccountMember.role_in_account)
        .join(AccountMember, Account.id == AccountMember.account_id)
        .where(AccountMember.user_id == user_id)
        .where(Account.name.ilike(f"%{escaped}%", escape="\\"))
    )
    rows = (await db.execute(stmt)).all()
    return [
        _account_out(
            a,
            include_api_key=(
                not is_pending and (is_superadmin or role in ("owner", "admin"))
            ),
        )
        for a, role in rows
    ]


@router.post(
    "/account/apply",
    response_model=AccountOut,
    status_code=status.HTTP_201_CREATED,
    tags=["Account"],
)
async def apply_account(
    body: AccountCreate,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Apply to create a new account."""
    from sqlalchemy import func

    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if not user or (
        not user.can_create_account and user.role_code not in ("admin", "superadmin")
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied to create account",
        )
    if user.role_code != "superadmin":
        cfg_max = (
            await db.execute(
                select(SystemConfig).where(SystemConfig.key == "max_accounts_per_user")
            )
        ).scalar_one_or_none()
        try:
            max_accounts = int(cfg_max.value) if cfg_max and cfg_max.value else 0
        except ValueError:
            max_accounts = 0
        if max_accounts > 0:
            owned_count = (
                await db.scalar(
                    select(func.count(AccountMember.id))
                    .join(Account, Account.id == AccountMember.account_id)
                    .where(
                        AccountMember.user_id == user_id,
                        AccountMember.role_in_account == "owner",
                        Account.is_active.is_(True),
                    )
                )
                or 0
            )
            if owned_count >= max_accounts:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Maximum number of accounts per user reached",
                )
    try:
        account = await create_account(body.name, user_id, db, slug=body.slug)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return _account_out(account)


@router.delete("/account/{account_id}", tags=["Account"])
async def delete_account(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Deactivate account (Owner or Super Admin permission required, cleans up associated data)."""
    role = await _get_effective_account_role(account_id, uid, db)
    if role != "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only account owner can perform this operation",
        )
    acct = (
        await db.execute(select(Account).where(Account.id == account_id))
    ).scalar_one_or_none()
    if not acct:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Account not found"
        )

    acct.is_active = False
    await cleanup_account_data(account_id, acct.slug, db)
    await db.commit()
    return {
        "status": "ok",
        "message": "Account deactivated and associated data cleaned up",
    }


@router.get("/account/{account_id}/info", response_model=AccountOut, tags=["Account"])
async def get_account_info(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Get account information."""
    acct = (
        await db.execute(select(Account).where(Account.id == account_id))
    ).scalar_one_or_none()
    if not acct:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Account not found"
        )
    role = await _get_effective_account_role(account_id, uid, db)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized access: You are not a member of this account",
        )
    return _account_out(acct, include_api_key=role in ("owner", "admin"))


@router.get(
    "/account/{account_id}/quota",
    response_model=list[QuotaOut],
    tags=["Account"],
    dependencies=[Depends(setup_tenant_context)],
)
async def get_account_quotas_mgmt(
    account_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get all resource quotas and live usage for the account."""
    from sqlalchemy import func

    rows = await get_quotas(account_id, db)
    client_count = (
        await db.scalar(
            select(func.count(ClientRecord.uid)).where(
                ClientRecord.account_id == account_id
            )
        )
        or 0
    )
    sm = get_session_manager(request)
    grpc_conn_count = len(await sm.get_all_clients_status(account_id)) if sm else 0
    out = []
    for r in rows:
        if r.quota_key == "max_clients":
            cur = client_count
        elif r.quota_key == "max_grpc_connections":
            cur = grpc_conn_count
        elif r.quota_key == "max_bandwidth_mb":
            cur = get_bandwidth_mb(account_id, r.current_value)
        else:
            cur = r.current_value
        out.append(
            QuotaOut(
                id=r.id,
                account_id=r.account_id,
                quota_key=r.quota_key,
                max_value=r.max_value,
                current_value=cur,
            )
        )
    return out


@router.post(
    "/account/{account_id}/quota",
    response_model=QuotaOut,
    tags=["Account"],
    dependencies=[Depends(setup_tenant_context)],
)
async def set_account_quota_mgmt(
    account_id: str,
    body: QuotaSetRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Set a quota limit for the account (Super Admin only)."""
    u = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    if not u or u.role_code != "superadmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only Super Admin can modify resource quotas",
        )
    q = await set_quota(account_id, body.quota_key, body.max_value, db)
    return QuotaOut(
        id=q.id,
        account_id=q.account_id,
        quota_key=q.quota_key,
        max_value=q.max_value,
        current_value=q.current_value,
    )


@router.post(
    "/account/{account_id}/info",
    response_model=AccountOut,
    tags=["Account"],
)
async def update_account_basic_info(
    account_id: str,
    body: AccountUpdate,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Update account basic info (name, slug, registration_mode, is_active; Account ID is immutable)."""
    if body.new_id is not None and body.new_id.strip() != account_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account ID is immutable and cannot be modified",
        )
    try:
        acct = await update_account_info(
            account_id,
            uid,
            db,
            name=body.name,
            slug=body.slug,
            is_active=body.is_active,
            registration_mode=body.registration_mode,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    if not acct:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Account not found"
        )
    return _account_out(acct)


@router.post(
    "/account/{account_id}/info/id",
    response_model=AccountOut,
    tags=["Account"],
)
async def change_account_id(
    account_id: str,
    body: AccountIdUpdate,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Account ID is strictly immutable; reject all modification requests."""
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Account ID is immutable and cannot be modified",
    )


@router.post(
    "/account/{account_id}/info/slug", response_model=AccountOut, tags=["Account"]
)
async def change_slug(
    account_id: str,
    body: SlugUpdate,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Update account slug."""
    try:
        acct = await update_account_slug(account_id, body.slug, uid, db)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    if not acct:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Account not found"
        )
    return _account_out(acct)


@router.post(
    "/account/{account_id}/info/name",
    response_model=AccountOut,
    tags=["Account"],
)
async def change_account_name(
    account_id: str,
    body: AccountNameUpdate,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Update account organization display name and optional registration mode."""
    try:
        acct = await update_account_info(
            account_id,
            uid,
            db,
            name=body.name,
            registration_mode=body.registration_mode,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    if not acct:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Account not found"
        )
    return _account_out(acct)


@router.post(
    "/account/{account_id}/info/api-key/regenerate",
    response_model=AccountOut,
    tags=["Account"],
    dependencies=[Depends(setup_tenant_context)],
)
@router.post(
    "/account/{account_id}/info/regenerate-api-key",
    response_model=AccountOut,
    tags=["Account"],
    dependencies=[Depends(setup_tenant_context)],
)
async def regenerate_account_api_key(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Regenerate account API key."""
    if isinstance(uid, str):
        await _require_account_admin(account_id, uid, db)
    acct = (
        await db.execute(select(Account).where(Account.id == account_id))
    ).scalar_one_or_none()
    if not acct:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Account not found"
        )
    acct.api_key = secrets.token_urlsafe(32)
    await db.commit()
    await invalidate_cached_account(acct.slug)
    return _account_out(acct)


@router.get(
    "/account/{account_id}/ManagementPreset.json",
    tags=["Account"],
    dependencies=[Depends(setup_tenant_context)],
)
async def download_account_preset(
    account_id: str,
    class_identity: str = "",
    db: AsyncSession = Depends(get_db),
):
    """Download ManagementPreset.json for the account."""
    acct = (
        await db.execute(select(Account).where(Account.id == account_id))
    ).scalar_one_or_none()
    if not acct or not acct.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found or deactivated",
        )
    res: dict[str, Any] = {
        "IsManagementEnabled": True,
        "ManagementServerKind": 1,
        "ManagementServer": f"https://{acct.slug}.{BASE_DOMAIN}",
        "ManagementServerGrpc": f"https://{acct.slug}.{BASE_DOMAIN}",
    }
    if class_identity:
        res["ClassIdentity"] = class_identity
    return res


# ---- 3. Tenant Access Control ----


async def _enrich_members(
    rows: list[AccountMember], db: AsyncSession
) -> list[AccessMemberOut]:
    if not rows:
        return []
    user_ids = list({m.user_id for m in rows})
    users = (
        (await db.execute(select(User).where(User.id.in_(user_ids)))).scalars().all()
    )
    user_map = {u.id: u for u in users}
    out = []
    for m in rows:
        u = user_map.get(m.user_id)
        out.append(
            AccessMemberOut(
                id=m.id,
                user_id=m.user_id,
                account_id=m.account_id,
                role_in_account=m.role_in_account,
                joined_at=(
                    m.joined_at.isoformat()
                    if hasattr(m.joined_at, "isoformat")
                    else str(m.joined_at)
                ),
                username=u.username if u else "",
                display_name=u.display_name if u else "",
                email=u.email if u else "",
            )
        )
    return out


@router.get(
    "/account/{account_id}/access/list",
    response_model=list[AccessMemberOut],
    tags=["Access"],
    dependencies=[Depends(setup_tenant_context)],
)
async def list_access(
    account_id: str,
    db: AsyncSession = Depends(get_db),
):
    """List members under the account."""
    rows = (
        (
            await db.execute(
                select(AccountMember).where(AccountMember.account_id == account_id)
            )
        )
        .scalars()
        .all()
    )
    return await _enrich_members(list(rows), db)


@router.post(
    "/account/{account_id}/access/{user_id}/rename",
    tags=["Access"],
    dependencies=[Depends(setup_tenant_context)],
)
async def rename_access(
    account_id: str,
    user_id: str,
    body: dict = Body(default={}),
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Update display name for member user."""
    if isinstance(uid, str):
        await _require_account_admin(account_id, uid, db)
    m = (
        await db.execute(
            select(AccountMember).where(
                AccountMember.account_id == account_id,
                or_(AccountMember.user_id == user_id, AccountMember.id == user_id),
            )
        )
    ).scalar_one_or_none()
    if not m:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Member not found"
        )
    user = (
        await db.execute(select(User).where(User.id == m.user_id))
    ).scalar_one_or_none()
    if (
        user
        and user.role_code == "superadmin"
        and isinstance(uid, str)
        and uid != user.id
    ):
        actor = (
            await db.execute(select(User).where(User.id == uid))
        ).scalar_one_or_none()
        if not actor or actor.role_code != "superadmin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot modify Super Admin display name",
            )
    raw_name = body.get("name") or body.get("display_name") or ""
    cleaned_name = str(raw_name).strip()
    if len(cleaned_name) > 128 or any(
        ord(c) < 32 or ord(c) == 127 for c in cleaned_name
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid display name length or characters",
        )
    if user and cleaned_name:
        user.display_name = cleaned_name
        await db.commit()
    return {"status": "ok", "message": "Member updated"}


@router.get(
    "/account/{account_id}/access/search",
    response_model=list[AccessMemberOut],
    tags=["Access"],
    dependencies=[Depends(setup_tenant_context)],
)
async def search_access(
    account_id: str,
    q: str = "",
    db: AsyncSession = Depends(get_db),
):
    """Search account members by user_id, username, display_name, or email."""
    rows = (
        (
            await db.execute(
                select(AccountMember).where(AccountMember.account_id == account_id)
            )
        )
        .scalars()
        .all()
    )
    enriched = await _enrich_members(list(rows), db)
    if not q:
        return enriched
    ql = q.lower()
    return [
        m
        for m in enriched
        if ql in m.user_id.lower()
        or ql in m.username.lower()
        or ql in m.display_name.lower()
        or ql in m.email.lower()
    ]


@router.get(
    "/account/{account_id}/access/{user_id}",
    response_model=AccessMemberOut,
    tags=["Access"],
    dependencies=[Depends(setup_tenant_context)],
)
async def get_access_detail(
    account_id: str,
    user_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get member details by user_id or member id."""
    m = (
        await db.execute(
            select(AccountMember).where(
                AccountMember.account_id == account_id,
                or_(AccountMember.user_id == user_id, AccountMember.id == user_id),
            )
        )
    ).scalar_one_or_none()
    if not m:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Member not found"
        )
    res = await _enrich_members([m], db)
    return res[0]


@router.delete(
    "/account/{account_id}/access/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Access"],
    dependencies=[Depends(setup_tenant_context)],
)
async def delete_access(
    account_id: str,
    user_id: str,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Remove member from account."""
    actor_role = "owner"
    if isinstance(uid, str):
        actor_role = await _require_account_admin(account_id, uid, db)
    m = (
        await db.execute(
            select(AccountMember).where(
                AccountMember.account_id == account_id,
                or_(AccountMember.id == user_id, AccountMember.user_id == user_id),
            )
        )
    ).scalar_one_or_none()
    if not m:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Member record not found"
        )
    if m.role_in_account == "owner":
        if actor_role != "owner":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only account owner can remove another owner",
            )
        from sqlalchemy import func

        owner_count = (
            await db.scalar(
                select(func.count(AccountMember.id)).where(
                    AccountMember.account_id == account_id,
                    AccountMember.role_in_account == "owner",
                )
            )
            or 0
        )
        if owner_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove the last owner of the account",
            )
    await db.delete(m)
    await db.commit()


@router.post(
    "/account/{account_id}/access/{user_id}",
    response_model=AccessMemberOut,
    tags=["Access"],
    dependencies=[Depends(setup_tenant_context)],
)
async def update_access(
    account_id: str,
    user_id: str,
    body: AccessRoleUpdate,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Update member's role within account."""
    actor_role = "owner"
    if isinstance(uid, str):
        actor_role = await _require_account_admin(account_id, uid, db)
    if body.role_in_account not in _VALID_ACCOUNT_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role_in_account: {body.role_in_account}",
        )
    m = (
        await db.execute(
            select(AccountMember).where(
                AccountMember.account_id == account_id,
                or_(AccountMember.id == user_id, AccountMember.user_id == user_id),
            )
        )
    ).scalar_one_or_none()
    if not m:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Member record not found"
        )
    target_user = (
        await db.execute(select(User).where(User.id == m.user_id))
    ).scalar_one_or_none()
    if (
        target_user
        and target_user.role_code == "pending"
        and body.role_in_account != "viewer"
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Pending users are restricted to viewer role until approved by a Super Administrator",
        )
    if (
        m.role_in_account == "owner" or body.role_in_account == "owner"
    ) and actor_role != "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only account owner can grant or modify owner role",
        )
    if m.role_in_account == "owner" and body.role_in_account != "owner":
        from sqlalchemy import func

        owner_count = (
            await db.scalar(
                select(func.count(AccountMember.id)).where(
                    AccountMember.account_id == account_id,
                    AccountMember.role_in_account == "owner",
                )
            )
            or 0
        )
        if owner_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot demote the last owner of the account",
            )
    m.role_in_account = body.role_in_account
    await db.commit()
    await db.refresh(m)
    res = await _enrich_members([m], db)
    return res[0]


# ---- 4. Tenant Invitation Management ----


def _inv_out(inv: Invitation) -> InvitationOut:
    return InvitationOut(
        id=inv.id,
        account_id=inv.account_id,
        inviter_user_id=inv.inviter_user_id,
        code=inv.code,
        role_in_account=inv.role_in_account,
        max_uses=inv.max_uses,
        used_count=inv.used_count,
        expires_at=(
            inv.expires_at.isoformat()
            if inv.expires_at and hasattr(inv.expires_at, "isoformat")
            else (str(inv.expires_at) if inv.expires_at else None)
        ),
        is_active=inv.is_active,
        created_at=(
            inv.created_at.isoformat()
            if hasattr(inv.created_at, "isoformat")
            else str(inv.created_at)
        ),
    )


@router.get(
    "/account/{account_id}/invitation/list",
    response_model=list[InvitationOut],
    tags=["Invite"],
    dependencies=[Depends(setup_tenant_context)],
)
async def list_invitations(
    account_id: str,
    db: AsyncSession = Depends(get_db),
):
    """List all invitations under account."""
    rows = (
        (
            await db.execute(
                select(Invitation)
                .where(Invitation.account_id == account_id)
                .order_by(Invitation.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [_inv_out(inv) for inv in rows]


@router.get(
    "/account/{account_id}/invitation/search",
    response_model=list[InvitationOut],
    tags=["Invite"],
    dependencies=[Depends(setup_tenant_context)],
)
async def search_invitations(
    account_id: str,
    q: str = "",
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """Search invitations by code."""
    stmt = select(Invitation).where(Invitation.account_id == account_id)
    if q:
        escaped_q = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        stmt = stmt.where(Invitation.code.ilike(f"%{escaped_q}%", escape="\\"))
    stmt = (
        stmt.order_by(Invitation.created_at.desc())
        .limit(min(max(1, limit), 500))
        .offset(max(0, offset))
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [_inv_out(inv) for inv in rows]


@router.post(
    "/account/{account_id}/invitation/{invitation_id}/rename",
    tags=["Invite"],
    dependencies=[Depends(setup_tenant_context)],
)
async def rename_invitation(
    account_id: str,
    invitation_id: str,
    body: dict = Body(default={}),
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Update invitation role or max_uses."""
    actor_role = "owner"
    if isinstance(uid, str):
        actor_role = await _require_account_admin(account_id, uid, db)
    inv = (
        await db.execute(
            select(Invitation).where(
                Invitation.id == invitation_id,
                Invitation.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Invitation not found"
        )
    if "role_in_account" in body and body["role_in_account"]:
        new_role = str(body["role_in_account"])
        if new_role not in _VALID_ACCOUNT_ROLES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role_in_account: {new_role}",
            )
        if new_role == "owner" and actor_role != "owner":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only account owner can assign owner role to an invitation",
            )
        inv.role_in_account = new_role
    if "max_uses" in body and body["max_uses"] is not None:
        try:
            max_uses_val = int(body["max_uses"])
        except (ValueError, TypeError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="max_uses must be an integer between 1 and 100",
            )
        if max_uses_val < 1 or max_uses_val > 100:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="max_uses must be between 1 and 100",
            )
        inv.max_uses = max_uses_val
    await db.commit()
    return _inv_out(inv)


@router.get(
    "/account/{account_id}/invitation/{invitation_id}",
    response_model=InvitationOut,
    tags=["Invite"],
    dependencies=[Depends(setup_tenant_context)],
)
async def get_invitation(
    account_id: str,
    invitation_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get invitation details."""
    inv = (
        await db.execute(
            select(Invitation).where(
                Invitation.id == invitation_id,
                Invitation.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Invitation not found"
        )
    return _inv_out(inv)


@router.post(
    "/account/{account_id}/invitation/create",
    response_model=InvitationOut,
    status_code=status.HTTP_201_CREATED,
    tags=["Invite"],
    dependencies=[Depends(setup_tenant_context)],
)
async def create_invitation(
    account_id: str,
    body: InvitationCreate,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Create a new invitation code."""
    actor_role = "owner"
    if isinstance(uid, str):
        actor_role = await _require_account_admin(account_id, uid, db)
    if body.role_in_account not in _VALID_ACCOUNT_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role_in_account: {body.role_in_account}",
        )
    if body.role_in_account == "owner" and actor_role != "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only account owner can create an owner invitation",
        )
    inv = Invitation(
        account_id=account_id,
        inviter_user_id=uid,
        role_in_account=body.role_in_account,
        max_uses=body.max_uses,
        expires_at=body.expires_at,
        created_at=datetime.now(timezone.utc),
    )
    db.add(inv)
    await db.commit()
    await db.refresh(inv)
    return _inv_out(inv)


@router.delete(
    "/account/{account_id}/invitation/{invitation_id}",
    tags=["Invite"],
    dependencies=[Depends(setup_tenant_context)],
)
async def revoke_invitation(
    account_id: str,
    invitation_id: str,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Revoke specified invitation code."""
    if isinstance(uid, str):
        await _require_account_admin(account_id, uid, db)
    inv = (
        await db.execute(
            select(Invitation).where(
                Invitation.id == invitation_id,
                Invitation.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Invitation not found"
        )
    inv.is_active = False
    await db.commit()
    return {"status": "ok", "message": f"Invitation {invitation_id} revoked"}


@router.post("/invitation/accept", tags=["Invite"])
@router.post("/account/invitation/accept", tags=["Invite"])
async def accept_invitation(
    body: InvitationAcceptRequest,
    request: Request = None,  # type: ignore[assignment]
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Redeem an invitation code to join an account."""
    code = body.code.strip()
    inv = (
        await db.execute(
            select(Invitation).where(Invitation.code == code).with_for_update()
        )
    ).scalar_one_or_none()
    if not inv or not inv.is_active:
        if isinstance(request, Request):
            record_ip_failure(get_client_ip_from_request(request) or "unknown")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation code invalid or revoked",
        )
    if inv.max_uses > 0 and inv.used_count >= inv.max_uses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invitation code has reached maximum uses",
        )
    now = datetime.now(timezone.utc)
    if inv.expires_at and inv.expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invitation code has expired",
        )

    existing = (
        await db.execute(
            select(AccountMember).where(
                AccountMember.account_id == inv.account_id,
                AccountMember.user_id == uid,
            )
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You are already a member of this account",
        )

    user = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    assigned_role = (
        "viewer"
        if (user and user.role_code == "pending")
        else (inv.role_in_account or "member")
    )

    db.add(
        AccountMember(
            id=str(uuid.uuid4()),
            user_id=uid,
            account_id=inv.account_id,
            role_in_account=assigned_role,
            joined_at=now,
        )
    )
    inv.used_count = (inv.used_count or 0) + 1
    if inv.max_uses > 0 and inv.used_count >= inv.max_uses:
        inv.is_active = False
    await db.commit()
    return {
        "status": "ok",
        "account_id": inv.account_id,
        "role_in_account": assigned_role,
    }


# ---- 5. Client Pairing Code & Registration Mode Management ----


def _pairing_out(r: PairingCode) -> PairingCodeOut:
    return PairingCodeOut(
        id=r.id,
        code=r.code,
        client_uid=getattr(r, "client_uid", "") or "",
        client_id=getattr(r, "client_id", "") or "",
        client_mac=getattr(r, "client_mac", "") or "",
        client_ip=getattr(r, "client_ip", "") or "",
        status=getattr(r, "status", "pending")
        or ("approved" if getattr(r, "approved", False) else "pending"),
        approved=bool(getattr(r, "approved", False)),
        used=bool(getattr(r, "used", False)),
        created_at=(
            r.created_at.isoformat()
            if hasattr(r.created_at, "isoformat")
            else str(getattr(r, "created_at", ""))
        ),
    )


@router.get(
    "/account/{account_id}/pairing/status",
    tags=["Pairing"],
    dependencies=[Depends(setup_tenant_context)],
)
async def get_pairing_status(
    account_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get current registration mode and pairing status for the account."""
    acct = (
        await db.execute(select(Account).where(Account.id == account_id))
    ).scalar_one_or_none()
    mode = (
        getattr(acct, "registration_mode", "pairing") if acct else "pairing"
    ) or "pairing"
    return {
        "enabled": mode == "pairing",
        "registration_mode": mode,
    }


@router.post(
    "/account/{account_id}/pairing/mode",
    tags=["Pairing"],
    dependencies=[Depends(setup_tenant_context)],
)
async def set_registration_mode(
    account_id: str,
    body: dict = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """Update device registration mode ('open' | 'pairing' | 'pre_reg') for the account."""
    mode = str(body.get("registration_mode") or body.get("mode") or "pairing").strip()
    if mode not in ("open", "pairing", "pre_reg"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid registration_mode"
        )
    acct = (
        await db.execute(select(Account).where(Account.id == account_id))
    ).scalar_one_or_none()
    if not acct:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Account not found"
        )
    acct.registration_mode = mode
    await db.commit()
    await invalidate_cached_account(acct.slug)
    return {"status": "ok", "registration_mode": mode, "enabled": mode == "pairing"}


@router.get(
    "/account/{account_id}/pairing/list",
    response_model=list[PairingCodeOut],
    tags=["Pairing"],
    dependencies=[Depends(setup_tenant_context)],
)
async def list_pairing_codes(
    account_id: str,
    db: AsyncSession = Depends(get_db),
):
    """List pairing codes for current account."""
    rows = (
        (
            await db.execute(
                select(PairingCode)
                .where(PairingCode.tenant_id == account_id)
                .order_by(PairingCode.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [_pairing_out(r) for r in rows]


@router.get(
    "/account/{account_id}/pairing/search",
    response_model=list[PairingCodeOut],
    tags=["Pairing"],
    dependencies=[Depends(setup_tenant_context)],
)
async def search_pairing_codes(
    account_id: str,
    q: str = "",
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """Search pairing codes."""
    stmt = select(PairingCode).where(PairingCode.tenant_id == account_id)
    if q:
        escaped_q = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped_q}%"
        stmt = stmt.where(
            or_(
                PairingCode.code.ilike(pattern, escape="\\"),
                PairingCode.client_id.ilike(pattern, escape="\\"),
                PairingCode.client_uid.ilike(pattern, escape="\\"),
                PairingCode.client_mac.ilike(pattern, escape="\\"),
            )
        )
    stmt = (
        stmt.order_by(PairingCode.created_at.desc())
        .limit(min(max(1, limit), 500))
        .offset(max(0, offset))
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [_pairing_out(r) for r in rows]


@router.post(
    "/account/{account_id}/pairing/enable",
    tags=["Pairing"],
    dependencies=[Depends(setup_tenant_context)],
)
async def enable_pairing(
    account_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Enable pairing code mode for this account."""
    acct = (
        await db.execute(select(Account).where(Account.id == account_id))
    ).scalar_one_or_none()
    if acct:
        acct.registration_mode = "pairing"
        await db.commit()
        await invalidate_cached_account(acct.slug)
    return {"status": "ok", "enabled": True, "registration_mode": "pairing"}


@router.post(
    "/account/{account_id}/pairing/disable",
    tags=["Pairing"],
    dependencies=[Depends(setup_tenant_context)],
)
async def disable_pairing(
    account_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Disable pairing code mode (revert to open mode) for this account."""
    acct = (
        await db.execute(select(Account).where(Account.id == account_id))
    ).scalar_one_or_none()
    if acct:
        acct.registration_mode = "open"
        await db.commit()
        await invalidate_cached_account(acct.slug)
    return {"status": "ok", "enabled": False, "registration_mode": "open"}


@router.post(
    "/account/{account_id}/pairing/{pairing_id}/reject",
    tags=["Pairing"],
    dependencies=[Depends(setup_tenant_context)],
)
async def reject_pairing(
    account_id: str,
    pairing_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Reject (revoke) pairing code."""
    row = (
        await db.execute(
            select(PairingCode).where(
                or_(PairingCode.id == pairing_id, PairingCode.code == pairing_id),
                PairingCode.tenant_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Pairing code not found"
        )
    await db.delete(row)
    await db.commit()
    return {"status": "ok", "message": f"Pairing code {pairing_id} rejected"}


@router.post(
    "/account/{account_id}/pairing/{pairing_id}/approve",
    tags=["Pairing"],
    dependencies=[Depends(setup_tenant_context)],
)
async def approve_pairing_code(
    account_id: str,
    pairing_id: str,
    body: Optional[dict] = Body(default=None),
    db: AsyncSession = Depends(get_db),
):
    """Approve pairing code with optional initial profile assignment."""
    row = (
        await db.execute(
            select(PairingCode).where(
                or_(PairingCode.id == pairing_id, PairingCode.code == pairing_id),
                PairingCode.tenant_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Pairing code not found"
        )
    row.approved = True
    row.status = "approved"
    if body and isinstance(body.get("preset_profile"), dict):
        row.preset_profile_json = json.dumps(body["preset_profile"], ensure_ascii=False)
    await db.commit()
    return {"status": "ok", "message": f"Pairing code {pairing_id} approved"}


# ---- 6. Pre-Registered Client Management ----

_PROFILE_KEY_PAIRS = (
    ("class_plan", "ClassPlan"),
    ("time_layout", "TimeLayout"),
    ("subjects", "Subjects"),
    ("default_settings", "DefaultSettings"),
    ("policy", "Policy"),
    ("components", "Components"),
    ("credentials", "Credentials"),
)


def _normalize_profile_dict(raw: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for snake_k, pascal_k in _PROFILE_KEY_PAIRS:
        val = raw.get(pascal_k) if pascal_k in raw else raw.get(snake_k)
        if val is not None:
            s = str(val)
            out[snake_k] = s
            out[pascal_k] = s
    return out


def _prereg_out(p: PreRegisteredClient) -> PreRegOut:
    preset: dict[str, str] = {}
    if getattr(p, "preset_profile_json", None):
        try:
            parsed = json.loads(p.preset_profile_json)
            if isinstance(parsed, dict):
                preset = _normalize_profile_dict(parsed)
        except Exception:
            pass
    return PreRegOut(
        id=p.id,
        account_id=p.account_id,
        label=p.label,
        class_identity=p.class_identity,
        mac_address=getattr(p, "mac_address", "") or "",
        is_enabled=bool(getattr(p, "is_enabled", True)),
        preset_profile=preset,
        bound_client_uid=getattr(p, "bound_client_uid", "") or "",
        created_at=(
            p.created_at.isoformat()
            if hasattr(p.created_at, "isoformat")
            else str(p.created_at)
        ),
    )


@router.post(
    "/account/{account_id}/pre-registration/create",
    response_model=PreRegOut,
    status_code=status.HTTP_201_CREATED,
    tags=["PreReg"],
    dependencies=[Depends(setup_tenant_context)],
)
async def create_pre_reg(
    account_id: str,
    body: PreRegCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create pre-registered client device, validating class_identity uniqueness."""
    ci = (body.class_identity or "").strip()
    mac = (body.mac_address or "").strip()
    if ci:
        dup = await db.execute(
            select(PreRegisteredClient).where(
                PreRegisteredClient.account_id == account_id,
                PreRegisteredClient.class_identity == ci,
            )
        )
        if dup.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="class_identity already exists",
            )
    p = PreRegisteredClient(
        id=str(uuid.uuid4()),
        account_id=account_id,
        label=body.label,
        class_identity=ci,
        mac_address=mac,
        is_enabled=True,
        preset_profile_json=json.dumps(
            _normalize_profile_dict(body.preset_profile or {}), ensure_ascii=False
        ),
        created_at=datetime.now(timezone.utc),
    )
    db.add(p)
    await db.commit()
    await db.refresh(p)
    return _prereg_out(p)


@router.post(
    "/account/{account_id}/pre-registration/batch",
    response_model=list[PreRegOut],
    status_code=status.HTTP_201_CREATED,
    tags=["PreReg"],
    dependencies=[Depends(setup_tenant_context)],
)
@router.post(
    "/account/{account_id}/pre-registration/batch-create",
    response_model=list[PreRegOut],
    status_code=status.HTTP_201_CREATED,
    tags=["PreReg"],
    dependencies=[Depends(setup_tenant_context)],
)
async def batch_create_pre_reg(
    account_id: str,
    body: PreRegBatchCreate,
    db: AsyncSession = Depends(get_db),
):
    """Batch create pre-registered client devices."""
    created: list[PreRegisteredClient] = []
    now = datetime.now(timezone.utc)
    for item in body.items:
        ci = (item.class_identity or "").strip()
        mac = (item.mac_address or "").strip()
        if not ci and not mac:
            continue
        if ci:
            dup = (
                await db.execute(
                    select(PreRegisteredClient).where(
                        PreRegisteredClient.account_id == account_id,
                        PreRegisteredClient.class_identity == ci,
                    )
                )
            ).scalar_one_or_none()
            if dup:
                continue
        p = PreRegisteredClient(
            id=str(uuid.uuid4()),
            account_id=account_id,
            label=item.label.strip() or ci or mac,
            class_identity=ci,
            mac_address=mac,
            is_enabled=True,
            preset_profile_json=json.dumps(
                _normalize_profile_dict(item.preset_profile or {}), ensure_ascii=False
            ),
            created_at=now,
        )
        db.add(p)
        created.append(p)
    await db.commit()
    return [_prereg_out(p) for p in created]


@router.get(
    "/account/{account_id}/pre-registration/list",
    response_model=list[PreRegOut],
    tags=["PreReg"],
    dependencies=[Depends(setup_tenant_context)],
)
async def list_pre_regs(
    account_id: str,
    db: AsyncSession = Depends(get_db),
):
    """List all pre-registered client device records for current account."""
    rows = (
        (
            await db.execute(
                select(PreRegisteredClient)
                .where(PreRegisteredClient.account_id == account_id)
                .order_by(PreRegisteredClient.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [_prereg_out(r) for r in rows]


@router.get(
    "/account/{account_id}/pre-registration/search",
    response_model=list[PreRegOut],
    tags=["PreReg"],
    dependencies=[Depends(setup_tenant_context)],
)
async def search_pre_regs(
    account_id: str,
    q: str = "",
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """Search pre-registered clients by class_identity, label, or mac_address."""
    stmt = select(PreRegisteredClient).where(
        PreRegisteredClient.account_id == account_id
    )
    if q:
        escaped_q = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped_q}%"
        stmt = stmt.where(
            or_(
                PreRegisteredClient.class_identity.ilike(pattern, escape="\\"),
                PreRegisteredClient.label.ilike(pattern, escape="\\"),
                PreRegisteredClient.mac_address.ilike(pattern, escape="\\"),
            )
        )
    stmt = (
        stmt.order_by(PreRegisteredClient.created_at.desc())
        .limit(min(max(1, limit), 500))
        .offset(max(0, offset))
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [_prereg_out(r) for r in rows]


@router.get(
    "/account/{account_id}/pre-registration/{pre_reg_id}",
    response_model=PreRegOut,
    tags=["PreReg"],
    dependencies=[Depends(setup_tenant_context)],
)
async def get_pre_reg(
    account_id: str,
    pre_reg_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get pre-registered client device details."""
    row = (
        await db.execute(
            select(PreRegisteredClient).where(
                PreRegisteredClient.id == pre_reg_id,
                PreRegisteredClient.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pre-registered client not found",
        )
    return _prereg_out(row)


@router.delete(
    "/account/{account_id}/pre-registration/{pre_reg_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["PreReg"],
    dependencies=[Depends(setup_tenant_context)],
)
async def delete_pre_reg(
    account_id: str,
    pre_reg_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete pre-registered client device record."""
    row = (
        await db.execute(
            select(PreRegisteredClient).where(
                PreRegisteredClient.id == pre_reg_id,
                PreRegisteredClient.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pre-registered client not found",
        )
    await db.delete(row)
    await db.commit()


@router.post(
    "/account/{account_id}/pre-registration/{pre_reg_id}/rename",
    response_model=PreRegOut,
    tags=["PreReg"],
    dependencies=[Depends(setup_tenant_context)],
)
async def rename_pre_reg(
    account_id: str,
    pre_reg_id: str,
    body: dict = Body(default={}),
    db: AsyncSession = Depends(get_db),
):
    """Update label, class_identity, or mac_address for pre-registered device."""
    row = (
        await db.execute(
            select(PreRegisteredClient).where(
                PreRegisteredClient.id == pre_reg_id,
                PreRegisteredClient.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pre-registered client not found",
        )
    if "label" in body and body["label"] is not None:
        row.label = str(body["label"]).strip()
    elif "name" in body and body["name"] is not None:
        row.label = str(body["name"]).strip()
    if "class_identity" in body and body["class_identity"] is not None:
        row.class_identity = str(body["class_identity"]).strip()
    if "mac_address" in body and body["mac_address"] is not None:
        row.mac_address = str(body["mac_address"]).strip()
    await db.commit()
    await db.refresh(row)
    return _prereg_out(row)


@router.post(
    "/account/{account_id}/pre-registration/{pre_reg_id}/enable",
    response_model=PreRegOut,
    tags=["PreReg"],
    dependencies=[Depends(setup_tenant_context)],
)
async def enable_pre_reg(
    account_id: str,
    pre_reg_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Enable pre-registered device."""
    row = (
        await db.execute(
            select(PreRegisteredClient).where(
                PreRegisteredClient.id == pre_reg_id,
                PreRegisteredClient.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pre-registered client not found",
        )
    row.is_enabled = True
    await db.commit()
    await db.refresh(row)
    return _prereg_out(row)


@router.post(
    "/account/{account_id}/pre-registration/{pre_reg_id}/disable",
    response_model=PreRegOut,
    tags=["PreReg"],
    dependencies=[Depends(setup_tenant_context)],
)
async def disable_pre_reg(
    account_id: str,
    pre_reg_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Disable pre-registered device."""
    row = (
        await db.execute(
            select(PreRegisteredClient).where(
                PreRegisteredClient.id == pre_reg_id,
                PreRegisteredClient.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pre-registered client not found",
        )
    row.is_enabled = False
    await db.commit()
    await db.refresh(row)
    return _prereg_out(row)


@router.post(
    "/account/{account_id}/pre-registration/{pre_reg_id}/config",
    response_model=PreRegOut,
    tags=["PreReg"],
    dependencies=[Depends(setup_tenant_context)],
)
async def config_pre_reg(
    account_id: str,
    pre_reg_id: str,
    body: dict = Body(default={}),
    db: AsyncSession = Depends(get_db),
):
    """Update preset profile configuration for pre-registered client."""
    row = (
        await db.execute(
            select(PreRegisteredClient).where(
                PreRegisteredClient.id == pre_reg_id,
                PreRegisteredClient.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pre-registered client not found",
        )
    raw_preset = body.get("preset_profile")
    preset: dict = raw_preset if isinstance(raw_preset, dict) else body
    clean_preset = _normalize_profile_dict(preset)
    row.preset_profile_json = json.dumps(clean_preset, ensure_ascii=False)
    await db.commit()
    await db.refresh(row)
    return _prereg_out(row)


@router.get(
    "/account/{account_id}/pre-registration/{pre_reg_id}/ManagementPreset.json",
    tags=["PreReg"],
    dependencies=[Depends(setup_tenant_context)],
)
async def download_preset(
    account_id: str,
    pre_reg_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Download OOBE ManagementPreset.json configuration archive for a specific pre-registered client device."""
    acct = (
        await db.execute(select(Account).where(Account.id == account_id))
    ).scalar_one_or_none()
    if not acct or not acct.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found or deactivated",
        )
    pre_reg = (
        await db.execute(
            select(PreRegisteredClient).where(
                PreRegisteredClient.id == pre_reg_id,
                PreRegisteredClient.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not pre_reg:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pre-registered client not found",
        )
    res: dict[str, Any] = {
        "IsManagementEnabled": True,
        "ManagementServerKind": 1,
        "ManagementServer": f"https://{acct.slug}.{BASE_DOMAIN}",
        "ManagementServerGrpc": f"https://{acct.slug}.{BASE_DOMAIN}",
    }
    if pre_reg.class_identity:
        res["ClassIdentity"] = pre_reg.class_identity
    return res


# ---- 7. Client Machine & Command Monitoring ----


def _profile_to_dict(p: Optional[ClientProfile]) -> dict[str, str]:
    cp = (p.class_plan if p.class_plan is not None else "default") if p else "default"
    tl = (p.time_layout if p.time_layout is not None else "default") if p else "default"
    sub = (p.subjects if p.subjects is not None else "default") if p else "default"
    ds = (
        (p.default_settings if p.default_settings is not None else "default")
        if p
        else "default"
    )
    pol = (p.policy if p.policy is not None else "default") if p else "default"
    comp = (p.components if p.components is not None else "default") if p else "default"
    cred = (
        (p.credentials if p.credentials is not None else "default") if p else "default"
    )
    return {
        "class_plan": cp,
        "time_layout": tl,
        "subjects": sub,
        "default_settings": ds,
        "policy": pol,
        "components": comp,
        "credentials": cred,
        "ClassPlan": cp,
        "TimeLayout": tl,
        "Subjects": sub,
        "DefaultSettings": ds,
        "Policy": pol,
        "Components": comp,
        "Credentials": cred,
    }


async def _serialize_clients(
    account_id: str,
    records: list[ClientRecord],
    request: Request,
    db: AsyncSession,
) -> list[dict[str, Any]]:
    sm = get_session_manager(request)
    online_list = await sm.get_all_clients_status(account_id) if sm else []
    online_map = {item["uid"]: item for item in online_list}
    ext_map: dict[str, dict[str, Any]] = {}
    if sm:
        ext_fn = getattr(sm, "get_extend_enabled_clients", None)
        if callable(ext_fn):
            raw_ext = ext_fn(account_id)
            if inspect.isawaitable(raw_ext):
                raw_ext = await raw_ext
            if isinstance(raw_ext, dict):
                ext_map = raw_ext

    profiles_rows = (
        (
            await db.execute(
                select(ClientProfile).where(ClientProfile.account_id == account_id)
            )
        )
        .scalars()
        .all()
    )
    prof_map = {p.client_id: p for p in profiles_rows}
    default_prof = prof_map.get("__default__")

    role_in_account = (
        getattr(request.state, "role_in_account", "owner")
        if isinstance(request, Request)
        else "owner"
    )
    can_view_full_mac = role_in_account in ("owner", "admin")

    out: list[dict[str, Any]] = []
    for r in records:
        is_online = r.uid in online_map
        if not is_online and sm and not account_id:
            is_online = await sm.is_client_online(account_id, r.uid)
        live_ip = online_map.get(r.uid, {}).get("ip") or getattr(r, "ip", "") or ""
        client_prof = prof_map.get(r.uid)
        raw_mac = r.mac or ""
        if can_view_full_mac or not raw_mac:
            mac_out = raw_mac
        else:
            mac_out = (
                f"{raw_mac[:5]}:**:**:**{raw_mac[-3:]}" if len(raw_mac) >= 8 else "***"
            )
        ext_info = ext_map.get(r.uid, {})
        online_info = online_map.get(r.uid, {})
        ext_enabled = bool(
            getattr(r, "extend_management_enabled", False)
            or ext_info.get("enabled")
            or online_info.get("extend_management_enabled")
        )
        ext_version = str(
            ext_info.get("version")
            or online_info.get("extend_management_version")
            or getattr(r, "extend_management_version", None)
            or ""
        )
        out.append(
            {
                "uid": r.uid,
                "client_id": r.client_id or "",
                "name": r.display_name or r.client_id or r.uid,
                "display_name": getattr(r, "display_name", "") or "",
                "mac": mac_out,
                "ip": live_ip,
                "is_disabled": bool(getattr(r, "is_disabled", False)),
                "is_app_locked": bool(getattr(r, "is_app_locked", False)),
                "online": is_online and not bool(getattr(r, "is_disabled", False)),
                "status": (
                    "disabled"
                    if getattr(r, "is_disabled", False)
                    else ("online" if is_online else "offline")
                ),
                "extend_management_enabled": ext_enabled,
                "extend_management_version": ext_version,
                "plugin_settings": _parse_json_safe(
                    getattr(r, "plugin_settings_json", None)
                ),
                "plugin_components": _parse_json_safe(
                    getattr(r, "plugin_components_json", None)
                ),
                "hardware_info": _parse_json_safe(
                    getattr(r, "hardware_info_json", None)
                ),
                "registered_at": (
                    r.registered_at.isoformat() if r.registered_at else None
                ),
                "last_seen_at": (
                    r.last_seen_at.isoformat() if r.last_seen_at is not None else None
                ),
                "has_custom_profile": client_prof is not None,
                "profile": _profile_to_dict(client_prof or default_prof),
                "profile_config": _profile_to_dict(client_prof or default_prof),
            }
        )
    return out


@router.get(
    "/account/{account_id}/client/list",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def list_clients(
    account_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get list of registered client devices with live status and profile bindings."""
    rows = (
        (
            await db.execute(
                select(ClientRecord)
                .where(ClientRecord.account_id == account_id)
                .order_by(ClientRecord.registered_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return await _serialize_clients(account_id, list(rows), request, db)


@router.get(
    "/account/{account_id}/client/search",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def search_clients(
    account_id: str,
    request: Request,
    q: str = "",
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """Search registered physical client devices by UID, ClassIdentity, display_name, MAC, or IP."""
    stmt = select(ClientRecord).where(ClientRecord.account_id == account_id)
    if q:
        escaped_q = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped_q}%"
        stmt = stmt.where(
            or_(
                ClientRecord.uid.ilike(pattern, escape="\\"),
                ClientRecord.client_id.ilike(pattern, escape="\\"),
                ClientRecord.display_name.ilike(pattern, escape="\\"),
                ClientRecord.mac.ilike(pattern, escape="\\"),
                ClientRecord.ip.ilike(pattern, escape="\\"),
            )
        )
    stmt = (
        stmt.order_by(ClientRecord.registered_at.desc())
        .limit(min(max(1, limit), 500))
        .offset(max(0, offset))
    )
    rows = (await db.execute(stmt)).scalars().all()
    return await _serialize_clients(account_id, list(rows), request, db)


@router.get(
    "/account/{account_id}/client/{client_id}/config",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def get_client_config(
    account_id: str,
    client_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get assigned profile resource mapping for a specific client or '__default__'."""
    await seed_account_defaults(account_id, db, fast_check=True)
    await db.commit()
    prof = (
        await db.execute(
            select(ClientProfile).where(
                ClientProfile.account_id == account_id,
                ClientProfile.client_id == client_id,
            )
        )
    ).scalar_one_or_none()
    default_prof = (
        await db.execute(
            select(ClientProfile).where(
                ClientProfile.account_id == account_id,
                ClientProfile.client_id == "__default__",
            )
        )
    ).scalar_one_or_none()
    return {
        "client_id": client_id,
        "has_custom_profile": prof is not None,
        "profile": _profile_to_dict(prof or default_prof),
        "profile_config": _profile_to_dict(prof or default_prof),
        "default_profile": _profile_to_dict(default_prof),
    }


@router.post(
    "/account/{account_id}/client/{client_id}/config",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def set_client_config(
    account_id: str,
    client_id: str,
    request: Request,
    body: dict = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """Update resource configuration set for physical client device (or '__default__')."""
    if body.get("use_default") is True and client_id != "__default__":
        await db.execute(
            delete(ClientProfile).where(
                ClientProfile.account_id == account_id,
                ClientProfile.client_id == client_id,
            )
        )
        await db.commit()
    else:
        prof = (
            await db.execute(
                select(ClientProfile).where(
                    ClientProfile.account_id == account_id,
                    ClientProfile.client_id == client_id,
                )
            )
        ).scalar_one_or_none()
        now = datetime.now(timezone.utc)
        if not prof:
            prof = ClientProfile(
                account_id=account_id,
                client_id=client_id,
                updated_at=now,
            )
        for snake_k, pascal_k in _PROFILE_KEY_PAIRS:
            val = body.get(pascal_k) if pascal_k in body else body.get(snake_k)
            if val is not None:
                setattr(prof, snake_k, str(val))
        prof.updated_at = now
        db.add(prof)
        await db.commit()

    # Automatically push DataUpdated command to online client(s) if requested (default True)
    if body.get("auto_sync", True):
        from app.Protobuf.Enum import CommandTypes_pb2

        if client_id == "__default__":
            sm = get_session_manager(request)
            online = await sm.get_all_clients_status(account_id) if sm else []
            for item in online:
                await _push_cmd(
                    request, account_id, item["uid"], CommandTypes_pb2.DataUpdated
                )
        else:
            await _push_cmd(
                request, account_id, client_id, CommandTypes_pb2.DataUpdated
            )

    return {
        "status": "ok",
        "message": "Client profile configuration updated",
        "client_id": client_id,
    }


@router.get(
    "/account/{account_id}/client/plugin-components",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def list_account_plugin_components(
    account_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Aggregate third-party and built-in component definitions captured from client Hook across the account."""
    rows = (
        (
            await db.execute(
                select(ClientRecord).where(ClientRecord.account_id == account_id)
            )
        )
        .scalars()
        .all()
    )
    comp_map: dict[str, dict[str, Any]] = {}
    for rec in rows:
        raw_comp = getattr(rec, "plugin_components_json", None)
        if not raw_comp:
            continue
        parsed = _parse_json_safe(raw_comp)
        comp_list: list[Any] = []
        if isinstance(parsed, dict) and isinstance(parsed.get("components"), list):
            comp_list = parsed["components"]
        elif isinstance(parsed, list):
            comp_list = parsed
        for item in comp_list:
            if not isinstance(item, dict):
                continue
            cid = str(item.get("id") or item.get("guid") or "").strip()
            if not cid:
                continue
            existing = comp_map.get(cid)
            if existing is None:
                entry = dict(item)
                entry["source_clients"] = [
                    {
                        "uid": rec.uid,
                        "display_name": rec.display_name or rec.client_id or rec.uid,
                    }
                ]
                comp_map[cid] = entry
            else:
                sources = existing.setdefault("source_clients", [])
                if not any(s.get("uid") == rec.uid for s in sources):
                    sources.append(
                        {
                            "uid": rec.uid,
                            "display_name": rec.display_name
                            or rec.client_id
                            or rec.uid,
                        }
                    )
    items = list(comp_map.values())
    return {
        "totalCount": len(items),
        "components": items,
    }


@router.get(
    "/account/{account_id}/client/{client_id}",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def get_client_detail(
    account_id: str,
    client_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Query registration details and online status for a specific client device."""
    record = (
        await db.execute(
            select(ClientRecord).where(
                ClientRecord.uid == client_id,
                ClientRecord.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Device not found"
        )
    items = await _serialize_clients(account_id, [record], request, db)
    return items[0]


async def _notify_client_remote_exit(
    request: Request, account_id: str, client_id: str
) -> None:
    """Push a signed management.exit command before disconnecting a removed device."""
    servicer = get_command_servicer(request)
    sm = get_session_manager(request)
    if not servicer or not sm:
        return
    try:
        from app.Protobuf.Server import ClientCommandDeliverScRsp_pb2
        from app.Protobuf.Command import GetClientConfig_pb2
        from app.Protobuf.Enum import Retcode_pb2, CommandTypes_pb2

        envelope = sm.build_signed_command_envelope(
            request_guid=str(uuid.uuid4()),
            client_uid=client_id,
            action="management.exit",
            payload={"reason": "removed_by_server"},
            ttl_seconds=120,
        )
        envelope_json = json.dumps(envelope, ensure_ascii=False)
        req_msg = GetClientConfig_pb2.GetClientConfig(
            RequestGuid=envelope_json,
            ConfigType=100,
        )
        cmd = ClientCommandDeliverScRsp_pb2.ClientCommandDeliverScRsp(
            RetCode=Retcode_pb2.Success,
            Type=CommandTypes_pb2.GetClientConfig,
            Payload=req_msg.SerializeToString(),
        )
        default_cmd = ClientCommandDeliverScRsp_pb2.ClientCommandDeliverScRsp(
            RetCode=Retcode_pb2.Success,
            Type=CommandTypes_pb2.DefaultCommand,
            Payload=envelope_json.encode("utf-8"),
        )
        d1 = await servicer.send_command(account_id, client_id, default_cmd)
        d2 = await servicer.send_command(account_id, client_id, cmd)
        if d1 or d2:
            await asyncio.sleep(0.15)
    except Exception:
        pass


@router.delete(
    "/account/{account_id}/client/{client_id}",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def delete_client(
    account_id: str,
    client_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Unregister and remove physical client device record."""
    record = (
        await db.execute(
            select(ClientRecord).where(
                ClientRecord.uid == client_id,
                ClientRecord.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Device not found"
        )
    await _notify_client_remote_exit(request, account_id, client_id)
    servicer = get_command_servicer(request)
    if servicer:
        await servicer.disconnect_client(account_id, client_id)
    sm = get_session_manager(request)
    if sm:
        await sm.set_client_offline(account_id, client_id)
    pre_rows = (
        (
            await db.execute(
                select(PreRegisteredClient).where(
                    PreRegisteredClient.account_id == account_id,
                    PreRegisteredClient.bound_client_uid == client_id,
                )
            )
        )
        .scalars()
        .all()
    )
    for pr in pre_rows:
        pr.bound_client_uid = ""
    await db.execute(
        delete(ClientProfile).where(
            ClientProfile.account_id == account_id,
            ClientProfile.client_id == client_id,
        )
    )
    await db.delete(record)
    await db.commit()
    return {"status": "ok", "message": "Deleted"}


@router.post(
    "/account/{account_id}/client/{client_id}/rename",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def rename_client(
    account_id: str,
    client_id: str,
    request: Request,
    body: dict = Body(default={}),
    db: AsyncSession = Depends(get_db),
):
    """Rename or update ClassIdentity / display_name for specified physical client machine."""
    record = (
        await db.execute(
            select(ClientRecord).where(
                ClientRecord.uid == client_id,
                ClientRecord.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Device not found"
        )
    if "display_name" in body and body["display_name"] is not None:
        record.display_name = str(body["display_name"]).strip()
    elif "name" in body and body["name"] is not None:
        record.display_name = str(body["name"]).strip()
    if "client_id" in body and body["client_id"] is not None:
        record.client_id = str(body["client_id"]).strip()
    await db.commit()

    from app.Protobuf.Enum import CommandTypes_pb2

    await _push_cmd(request, account_id, client_id, CommandTypes_pb2.DataUpdated)
    return {
        "status": "ok",
        "message": "Device updated",
        "client_id": record.client_id,
        "display_name": record.display_name,
    }


@router.get(
    "/account/{account_id}/client/{client_id}/status",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def get_client_status(
    account_id: str,
    client_id: str,
    request: Request,
):
    """Query heartbeat active online status for specified client."""
    sm = get_session_manager(request)
    online = await sm.is_client_online(account_id, client_id) if sm else False
    return {"client_id": client_id, "online": online}


@router.post(
    "/account/{account_id}/client/{client_id}/disconnect",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def disconnect_client(
    account_id: str,
    client_id: str,
    request: Request,
):
    """Disconnect physical client device."""
    servicer = get_command_servicer(request)
    if servicer:
        await servicer.disconnect_client(account_id, client_id)
    sm = get_session_manager(request)
    if sm:
        await sm.set_client_offline(account_id, client_id)
    return {"status": "ok", "message": "Client disconnected", "client_id": client_id}


@router.post(
    "/account/{account_id}/client/{client_id}/disable",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def disable_client(
    account_id: str,
    client_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Disable specified physical client device and disconnect active session."""
    record = (
        await db.execute(
            select(ClientRecord).where(
                ClientRecord.uid == client_id,
                ClientRecord.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Device not found"
        )
    record.is_disabled = True
    await db.commit()
    servicer = get_command_servicer(request)
    if servicer:
        await servicer.disconnect_client(account_id, client_id)
    sm = get_session_manager(request)
    if sm:
        await sm.set_client_offline(account_id, client_id)
    return {"status": "ok", "message": "Client disabled", "client_id": client_id}


@router.post(
    "/account/{account_id}/client/{client_id}/enable",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def enable_client(
    account_id: str,
    client_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Enable specified physical client device."""
    record = (
        await db.execute(
            select(ClientRecord).where(
                ClientRecord.uid == client_id,
                ClientRecord.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Device not found"
        )
    record.is_disabled = False
    await db.commit()
    return {"status": "ok", "message": "Client enabled", "client_id": client_id}


@router.post(
    "/account/{account_id}/client/batch",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def batch_client_action(
    account_id: str,
    request: Request,
    body: dict = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """Execute batch action ('sync', 'restart', 'disconnect', 'enable', 'disable', 'delete', 'lock', 'unlock', 'send_notification', 'assign_profile') on multiple clients."""
    action = str(body.get("action") or "").strip().lower()
    uids = body.get("uids") or body.get("client_uids") or []
    if not isinstance(uids, list) or not uids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="uids list is required"
        )

    from app.Protobuf.Enum import CommandTypes_pb2

    count = 0
    for uid in uids:
        uid_str = str(uid)
        if action in ("sync", "force_sync"):
            await _push_cmd(request, account_id, uid_str, CommandTypes_pb2.DataUpdated)
            count += 1
        elif action == "restart":
            await _push_cmd(request, account_id, uid_str, CommandTypes_pb2.RestartApp)
            count += 1
        elif action == "disconnect":
            servicer = get_command_servicer(request)
            if servicer:
                await servicer.disconnect_client(account_id, uid_str)
            sm = get_session_manager(request)
            if sm:
                await sm.set_client_offline(account_id, uid_str)
            count += 1
        elif action in ("lock", "unlock"):
            rec = (
                await db.execute(
                    select(ClientRecord).where(
                        ClientRecord.uid == uid_str,
                        ClientRecord.account_id == account_id,
                    )
                )
            ).scalar_one_or_none()
            if not rec:
                continue
            target_locked = action == "lock"
            rec.is_app_locked = target_locked
            await _dispatch_lock_command_to_client(
                request, account_id, uid_str, target_locked, db
            )
            count += 1
        elif action in ("send_notification", "notify"):
            raw_notif = body.get("notification") or body.get("payload") or {}
            notif_payload = NotificationPayload(
                **(raw_notif if isinstance(raw_notif, dict) else {})
            )
            res = await push_notify(account_id, uid_str, request, notif_payload)
            if res.status == "success":
                count += 1
        elif action in ("enable", "disable", "delete", "remove"):
            rec = (
                await db.execute(
                    select(ClientRecord).where(
                        ClientRecord.uid == uid_str,
                        ClientRecord.account_id == account_id,
                    )
                )
            ).scalar_one_or_none()
            if not rec:
                continue
            if action == "enable":
                rec.is_disabled = False
            elif action == "disable":
                rec.is_disabled = True
                servicer = get_command_servicer(request)
                if servicer:
                    await servicer.disconnect_client(account_id, uid_str)
            elif action in ("delete", "remove"):
                await _notify_client_remote_exit(request, account_id, uid_str)
                servicer = get_command_servicer(request)
                if servicer:
                    await servicer.disconnect_client(account_id, uid_str)
                sm = get_session_manager(request)
                if sm:
                    await sm.set_client_offline(account_id, uid_str)
                pre_rows = (
                    (
                        await db.execute(
                            select(PreRegisteredClient).where(
                                PreRegisteredClient.account_id == account_id,
                                PreRegisteredClient.bound_client_uid == uid_str,
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                for pr in pre_rows:
                    pr.bound_client_uid = ""
                await db.execute(
                    delete(ClientProfile).where(
                        ClientProfile.account_id == account_id,
                        ClientProfile.client_id == uid_str,
                    )
                )
                await db.delete(rec)
            count += 1
        elif action == "assign_profile":
            profile_data = body.get("profile") or body.get("profile_config") or {}
            if isinstance(profile_data, dict):
                await set_client_config(account_id, uid_str, request, profile_data, db)
                count += 1

    await db.commit()
    return {"status": "ok", "action": action, "affected": count}


# ---- 8. Remote Control Command Push & Config Uploads & Audit Logs ----


async def _push_cmd(
    request: Request, account_id: str, uid: str, cmd_type: int
) -> StatusResponse:
    """Helper function to deliver simple payload-less gRPC command."""
    servicer = get_command_servicer(request)
    if not servicer:
        return StatusResponse(status="error", message="gRPC service unavailable")

    from app.Protobuf.Server import ClientCommandDeliverScRsp_pb2
    from app.Protobuf.Enum import Retcode_pb2

    cmd = ClientCommandDeliverScRsp_pb2.ClientCommandDeliverScRsp(
        RetCode=Retcode_pb2.Success, Type=cmd_type
    )
    delivered = await servicer.send_command(account_id, uid, cmd)
    if not delivered:
        return StatusResponse(
            status="offline",
            message="Client is currently offline; command was not delivered",
        )
    return StatusResponse(status="success", message="Command delivered")


@router.get(
    "/account/{account_id}/client/{client_id}/command/get-config",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
@router.post(
    "/account/{account_id}/client/{client_id}/command/get-config",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def fetch_runtime_config(
    account_id: str,
    client_id: str,
    request: Request,
    config_type: int = Query(1, description="ConfigType enum (1..6)"),
    db: AsyncSession = Depends(get_db),
):
    """Request client to report full runtime snapshot configuration."""
    servicer = get_command_servicer(request)
    if not servicer:
        return {"status": "error", "message": "Communication channel closed"}

    from app.Protobuf.Server import ClientCommandDeliverScRsp_pb2
    from app.Protobuf.Command import GetClientConfig_pb2
    from app.Protobuf.Enum import Retcode_pb2, CommandTypes_pb2

    req_id = str(uuid.uuid4())
    db.add(
        ConfigUploadRecord(
            request_guid=req_id,
            account_id=account_id,
            client_uid=client_id,
            config_type=config_type,
            status="pending",
            payload="",
            uploaded_at=datetime.now(timezone.utc),
        )
    )
    await db.commit()

    config_req = GetClientConfig_pb2.GetClientConfig(
        RequestGuid=req_id, ConfigType=config_type
    )

    cmd = ClientCommandDeliverScRsp_pb2.ClientCommandDeliverScRsp(
        RetCode=Retcode_pb2.Success,
        Type=CommandTypes_pb2.GetClientConfig,
        Payload=config_req.SerializeToString(),
    )

    delivered = await servicer.send_command(account_id, client_id, cmd)
    return {
        "status": "success" if delivered else "offline",
        "message": (
            f"Request delivered, GUID: {req_id}" if delivered else "Client is offline"
        ),
        "request_guid": req_id,
        "config_type": config_type,
        "config_type_name": CONFIG_TYPE_NAMES.get(config_type, f"Type_{config_type}"),
    }


def _parse_json_safe(raw: str | None) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


@router.get(
    "/account/{account_id}/client/{client_id}/config-uploads",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def list_client_config_uploads(
    account_id: str,
    client_id: str,
    db: AsyncSession = Depends(get_db),
):
    """List uploaded runtime configuration snapshots for a client."""
    rows = (
        (
            await db.execute(
                select(ConfigUploadRecord)
                .where(
                    ConfigUploadRecord.account_id == account_id,
                    ConfigUploadRecord.client_uid == client_id,
                )
                .order_by(ConfigUploadRecord.uploaded_at.desc())
                .limit(50)
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "request_guid": r.request_guid,
            "client_uid": r.client_uid,
            "config_type": getattr(r, "config_type", 0) or 0,
            "config_type_name": CONFIG_TYPE_NAMES.get(
                getattr(r, "config_type", 0) or 0, "Snapshot"
            ),
            "status": getattr(r, "status", "completed") or "completed",
            "payload": r.payload,
            "payload_preview": (
                f"{r.payload[:200]}..."
                if r.payload and len(r.payload) > 200
                else (r.payload or "")
            ),
            "parsed_payload": _parse_json_safe(r.payload),
            "uploaded_at": r.uploaded_at.isoformat() if r.uploaded_at else None,
        }
        for r in rows
    ]


@router.get(
    "/account/{account_id}/config-upload/{request_guid}",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def get_config_upload_detail(
    account_id: str,
    request_guid: str,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific uploaded runtime configuration snapshot by request_guid."""
    r = (
        await db.execute(
            select(ConfigUploadRecord).where(
                ConfigUploadRecord.account_id == account_id,
                ConfigUploadRecord.request_guid == request_guid,
            )
        )
    ).scalar_one_or_none()
    if not r:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Config upload record not found",
        )
    return {
        "request_guid": r.request_guid,
        "client_uid": r.client_uid,
        "config_type": getattr(r, "config_type", 0) or 0,
        "config_type_name": CONFIG_TYPE_NAMES.get(
            getattr(r, "config_type", 0) or 0, "Snapshot"
        ),
        "status": getattr(r, "status", "completed") or "completed",
        "payload": r.payload,
        "payload_preview": (
            f"{r.payload[:200]}..."
            if r.payload and len(r.payload) > 200
            else (r.payload or "")
        ),
        "parsed_payload": _parse_json_safe(r.payload),
        "uploaded_at": r.uploaded_at.isoformat() if r.uploaded_at else None,
    }


@router.post(
    "/account/{account_id}/client/{client_id}/command/restart",
    response_model=StatusResponse,
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def restart_app(
    account_id: str,
    client_id: str,
    request: Request,
):
    """Control instruction: request physical client machine to restart main ClassIsland application."""
    from app.Protobuf.Enum import CommandTypes_pb2

    return await _push_cmd(request, account_id, client_id, CommandTypes_pb2.RestartApp)


async def _dispatch_lock_command_to_client(
    request: Request,
    account_id: str,
    client_id: str,
    locked: bool,
    db: AsyncSession,
) -> bool:
    """Persist lock state and dispatch signed lock.enable / lock.disable command to client."""
    servicer = get_command_servicer(request)
    sm = get_session_manager(request)
    if not servicer or not sm:
        return False

    from app.Protobuf.Server import ClientCommandDeliverScRsp_pb2
    from app.Protobuf.Enum import Retcode_pb2, CommandTypes_pb2

    action = "lock.enable" if locked else "lock.disable"
    req_guid = str(uuid.uuid4())
    db.add(
        ConfigUploadRecord(
            request_guid=req_guid,
            account_id=account_id,
            client_uid=client_id,
            config_type=100,
            status="pending",
            payload="",
            uploaded_at=datetime.now(timezone.utc),
        )
    )
    envelope = sm.build_signed_command_envelope(
        request_guid=req_guid,
        client_uid=client_id,
        action=action,
        payload={"locked": locked, "isAppLocked": locked},
        ttl_seconds=120,
    )
    envelope_bytes = json.dumps(envelope, ensure_ascii=False).encode("utf-8")
    cmd = ClientCommandDeliverScRsp_pb2.ClientCommandDeliverScRsp(
        RetCode=Retcode_pb2.Success,
        Type=CommandTypes_pb2.DefaultCommand,
        Payload=envelope_bytes,
    )
    delivered = await servicer.send_command(account_id, client_id, cmd)
    await _push_cmd(request, account_id, client_id, CommandTypes_pb2.DataUpdated)
    return delivered


@router.post(
    "/account/{account_id}/client/{client_id}/command/lock",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def lock_client_app(
    account_id: str,
    client_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Lock the client application via Extend Management and persist lock state."""
    record = (
        await db.execute(
            select(ClientRecord).where(
                ClientRecord.uid == client_id,
                ClientRecord.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Device not found"
        )
    record.is_app_locked = True
    delivered = await _dispatch_lock_command_to_client(
        request, account_id, client_id, True, db
    )
    await db.commit()
    return {
        "status": "success" if delivered else "queued",
        "delivered": delivered,
        "is_app_locked": True,
        "message": (
            "已发送锁定指令" if delivered else "已标记锁定，将在客户端上线后同步"
        ),
    }


@router.post(
    "/account/{account_id}/client/{client_id}/command/unlock",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def unlock_client_app(
    account_id: str,
    client_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Unlock the client application via Extend Management and persist lock state."""
    record = (
        await db.execute(
            select(ClientRecord).where(
                ClientRecord.uid == client_id,
                ClientRecord.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Device not found"
        )
    record.is_app_locked = False
    delivered = await _dispatch_lock_command_to_client(
        request, account_id, client_id, False, db
    )
    await db.commit()
    return {
        "status": "success" if delivered else "queued",
        "delivered": delivered,
        "is_app_locked": False,
        "message": "已发送解锁指令" if delivered else "已解除锁定状态",
    }


@router.post(
    "/account/{account_id}/client/{client_id}/command/update-data",
    response_model=StatusResponse,
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def force_sync(
    account_id: str,
    client_id: str,
    request: Request,
):
    """Control instruction: force physical machine to fetch and reload latest resource configuration."""
    from app.Protobuf.Enum import CommandTypes_pb2

    return await _push_cmd(request, account_id, client_id, CommandTypes_pb2.DataUpdated)


@router.post(
    "/account/{account_id}/client/{client_id}/command/send-notification",
    response_model=StatusResponse,
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def push_notify(
    account_id: str,
    client_id: str,
    request: Request,
    payload: NotificationPayload = Body(...),
):
    """Control instruction: send and display desktop notification on target client device."""
    servicer = get_command_servicer(request)
    if not servicer:
        return StatusResponse(status="error", message="gRPC channel not open")

    from app.Protobuf.Server import ClientCommandDeliverScRsp_pb2
    from app.Protobuf.Command import SendNotification_pb2
    from app.Protobuf.Enum import Retcode_pb2, CommandTypes_pb2

    notify = SendNotification_pb2.SendNotification(**payload.model_dump())

    cmd = ClientCommandDeliverScRsp_pb2.ClientCommandDeliverScRsp(
        RetCode=Retcode_pb2.Success,
        Type=CommandTypes_pb2.SendNotification,
        Payload=notify.SerializeToString(),
    )

    delivered = await servicer.send_command(account_id, client_id, cmd)
    if not delivered:
        return StatusResponse(
            status="offline",
            message="Client is offline; notification was not delivered",
        )
    return StatusResponse(status="success", message="Notification delivered")


@router.post(
    "/account/{account_id}/broadcast/notification",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
@router.post(
    "/account/{account_id}/client/broadcast/send-notification",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def broadcast_notify(
    account_id: str,
    request: Request,
    payload: BroadcastNotificationPayload = Body(...),
):
    """Broadcast desktop notification to all online clients or specified target_uids."""
    servicer = get_command_servicer(request)
    sm = get_session_manager(request)
    if not servicer or not sm:
        return {
            "status": "error",
            "message": "gRPC channel not open",
            "delivered_count": 0,
        }

    from app.Protobuf.Server import ClientCommandDeliverScRsp_pb2
    from app.Protobuf.Command import SendNotification_pb2
    from app.Protobuf.Enum import Retcode_pb2, CommandTypes_pb2

    notify_data = payload.model_dump(exclude={"target_uids", "client_uids"})
    notify = SendNotification_pb2.SendNotification(**notify_data)
    cmd = ClientCommandDeliverScRsp_pb2.ClientCommandDeliverScRsp(
        RetCode=Retcode_pb2.Success,
        Type=CommandTypes_pb2.SendNotification,
        Payload=notify.SerializeToString(),
    )

    targets = payload.target_uids or payload.client_uids
    if not targets:
        online_list = await sm.get_all_clients_status(account_id)
        targets = [item["uid"] for item in online_list]

    delivered_count = 0
    for uid in targets:
        if await servicer.send_command(account_id, uid, cmd):
            delivered_count += 1

    return {
        "status": "success",
        "message": f"Notification delivered to {delivered_count} online device(s)",
        "delivered_count": delivered_count,
    }


_ALLOWED_EXTEND_COMMAND_PREFIXES = (
    "hardware.",
    "settings.",
    "profile.",
    "components.",
    "automation.",
    "update.",
    "plugin.",
    "theme.",
    "remote.",
    "extend.",
    "system.",
    "management.",
    "client.",
    "lock.",
    "app.",
)


_RISK_EXTEND_COMMAND_ACTIONS = {
    "remote.exec_code",
    "remote.exec_command",
    "remote.screenshot",
    "remote.simulate_click",
}


@router.post(
    "/account/{account_id}/client/{client_id}/command/extend",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def send_extend_command(
    account_id: str,
    client_id: str,
    request: Request,
    body: ExtendCommandRequest = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """Dispatch a PGP-signed extended management command to a client with MiniClassIsland.ExtendManagement."""
    action = body.action.strip().lower()
    if not any(action.startswith(p) for p in _ALLOWED_EXTEND_COMMAND_PREFIXES):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported extended command action: {action}",
        )
    if action in _RISK_EXTEND_COMMAND_ACTIONS:
        if not await check_quota(account_id, "feature.risk", db):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="当前账户未开通风险远程运维功能权限",
            )

    if action in ("lock.enable", "app.lock"):
        rec = (
            await db.execute(
                select(ClientRecord).where(
                    ClientRecord.uid == client_id,
                    ClientRecord.account_id == account_id,
                )
            )
        ).scalar_one_or_none()
        if rec:
            rec.is_app_locked = True
    elif action in ("lock.disable", "app.unlock"):
        rec = (
            await db.execute(
                select(ClientRecord).where(
                    ClientRecord.uid == client_id,
                    ClientRecord.account_id == account_id,
                )
            )
        ).scalar_one_or_none()
        if rec:
            rec.is_app_locked = False

    servicer = get_command_servicer(request)
    sm = get_session_manager(request)
    if not servicer or not sm:
        return {
            "status": "error",
            "delivered": False,
            "message": "gRPC service unavailable",
            "request_guid": "",
            "action": action,
        }

    from app.Protobuf.Server import ClientCommandDeliverScRsp_pb2
    from app.Protobuf.Enum import Retcode_pb2, CommandTypes_pb2

    req_guid = str(uuid.uuid4())
    db.add(
        ConfigUploadRecord(
            request_guid=req_guid,
            account_id=account_id,
            client_uid=client_id,
            config_type=100,
            status="pending",
            payload="",
            uploaded_at=datetime.now(timezone.utc),
        )
    )
    await db.commit()

    envelope = sm.build_signed_command_envelope(
        request_guid=req_guid,
        client_uid=client_id,
        action=action,
        payload=body.payload,
        ttl_seconds=body.ttl_seconds,
    )
    envelope_bytes = json.dumps(envelope, ensure_ascii=False).encode("utf-8")

    cmd = ClientCommandDeliverScRsp_pb2.ClientCommandDeliverScRsp(
        RetCode=Retcode_pb2.Success,
        Type=CommandTypes_pb2.DefaultCommand,
        Payload=envelope_bytes,
    )
    delivered = await servicer.send_command(account_id, client_id, cmd)
    return {
        "status": "command_queued" if delivered else "offline",
        "delivered": delivered,
        "message": (
            "Extended command delivered" if delivered else "Client is currently offline"
        ),
        "request_guid": req_guid,
        "action": action,
        "config_type": 100,
        "config_type_name": "ExtendCommand",
    }


@router.post(
    "/account/{account_id}/broadcast/extend",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
@router.post(
    "/account/{account_id}/client/broadcast/extend",
    tags=["Client"],
    dependencies=[Depends(setup_tenant_context)],
)
async def broadcast_extend_command(
    account_id: str,
    request: Request,
    body: BroadcastExtendCommandRequest = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """Broadcast a PGP-signed extended management command to target or all online clients."""
    action = body.action.strip().lower()
    if not any(action.startswith(p) for p in _ALLOWED_EXTEND_COMMAND_PREFIXES):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported extended command action: {action}",
        )
    if action in _RISK_EXTEND_COMMAND_ACTIONS:
        if not await check_quota(account_id, "feature.risk", db):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="当前账户未开通风险远程运维功能权限",
            )

    servicer = get_command_servicer(request)
    sm = get_session_manager(request)
    if not servicer or not sm:
        return {
            "status": "error",
            "delivered_count": 0,
            "sent_count": 0,
            "total_targets": 0,
            "requests": [],
        }

    from app.Protobuf.Server import ClientCommandDeliverScRsp_pb2
    from app.Protobuf.Enum import Retcode_pb2, CommandTypes_pb2

    targets = body.target_uids or body.client_uids
    if not targets:
        online_list = await sm.get_all_clients_status(account_id)
        targets = [item["uid"] for item in online_list]

    delivered_count = 0
    requests_out: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    for uid in targets:
        uid_str = str(uid).strip()
        if not uid_str:
            continue
        req_guid = str(uuid.uuid4())
        db.add(
            ConfigUploadRecord(
                request_guid=req_guid,
                account_id=account_id,
                client_uid=uid_str,
                config_type=100,
                status="pending",
                payload="",
                uploaded_at=now,
            )
        )
        envelope = sm.build_signed_command_envelope(
            request_guid=req_guid,
            client_uid=uid_str,
            action=action,
            payload=body.payload,
            ttl_seconds=body.ttl_seconds,
        )
        envelope_bytes = json.dumps(envelope, ensure_ascii=False).encode("utf-8")
        cmd = ClientCommandDeliverScRsp_pb2.ClientCommandDeliverScRsp(
            RetCode=Retcode_pb2.Success,
            Type=CommandTypes_pb2.DefaultCommand,
            Payload=envelope_bytes,
        )
        ok = await servicer.send_command(account_id, uid_str, cmd)
        if ok:
            delivered_count += 1
        requests_out.append(
            {
                "client_uid": uid_str,
                "request_guid": req_guid,
                "delivered": ok,
            }
        )

    await db.commit()
    return {
        "status": "broadcast_queued",
        "action": action,
        "sent_count": delivered_count,
        "delivered_count": delivered_count,
        "total_targets": len(requests_out),
        "requests": requests_out,
    }


@router.get(
    "/account/{account_id}/audit/list",
    tags=["Audit"],
    dependencies=[Depends(setup_tenant_context)],
)
async def list_audit_logs(
    account_id: str,
    client_uid: str = "",
    event: Optional[int] = None,
    event_type: Optional[int] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """Query decoded client audit event logs for current tenant account."""
    stmt = select(AuditLog).where(AuditLog.account_id == account_id)
    if client_uid:
        stmt = stmt.where(AuditLog.client_uid == client_uid)
    ev_filter = event if event is not None else event_type
    if ev_filter is not None:
        stmt = stmt.where(AuditLog.event == ev_filter)
    rows = (
        (
            await db.execute(
                stmt.order_by(AuditLog.id.desc()).offset(offset).limit(limit)
            )
        )
        .scalars()
        .all()
    )

    uids_in_page = list({r.client_uid for r in rows if r.client_uid})
    if uids_in_page:
        clients = (
            (
                await db.execute(
                    select(ClientRecord).where(
                        ClientRecord.account_id == account_id,
                        ClientRecord.uid.in_(uids_in_page),
                    )
                )
            )
            .scalars()
            .all()
        )
        client_map = {c.uid: c.display_name or c.client_id or c.uid for c in clients}
    else:
        client_map = {}

    out = []
    for r in rows:
        decoded: dict[str, Any] = {}
        if getattr(r, "decoded_json", None):
            try:
                decoded = json.loads(r.decoded_json)
            except Exception:
                decoded = {}
        ts_iso = r.received_at.isoformat() if r.received_at else None
        out.append(
            {
                "id": r.id,
                "client_uid": r.client_uid,
                "client_name": client_map.get(r.client_uid, r.client_uid),
                "event": r.event,
                "event_type": r.event,
                "event_name": AUDIT_EVENT_NAMES.get(r.event, f"Event_{r.event}"),
                "decoded": decoded.get("data", decoded),
                "timestamp_utc": r.timestamp_utc,
                "received_at": ts_iso,
                "logged_at": ts_iso,
            }
        )
    return out


@router.delete(
    "/account/{account_id}/audit/clear",
    tags=["Audit"],
    dependencies=[Depends(setup_tenant_context)],
)
async def clear_audit_logs(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Clear audit logs for current tenant account."""
    if isinstance(uid, str):
        await _require_account_admin(account_id, uid, db)
    await db.execute(delete(AuditLog).where(AuditLog.account_id == account_id))
    await db.commit()
    return {"status": "ok", "message": "Audit logs cleared"}


@router.post(
    "/account/{account_id}/credentials/encode",
    tags=["Resource"],
    dependencies=[Depends(setup_tenant_context)],
)
async def encode_credential_endpoint(
    body: dict = Body(...),
):
    """Encode a plaintext password into an upstream ClassIsland Base64 Credential JSON string."""
    password = str(body.get("password") or "")
    return {"credential": encode_classisland_credential(password)}


# ---- 9. Config Resource CRUD (Tenant Config Resources DDL) ----

# Safety limits
MAX_PAYLOAD_BYTES = 512 * 1024  # 512 KB
MAX_NESTING_DEPTH = 64


def _check_depth(obj, current: int = 0) -> int:
    """Recursively check nesting depth and raise exception if limit exceeded."""
    if current > MAX_NESTING_DEPTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload nesting depth exceeded limit",
        )
    if isinstance(obj, dict):
        for v in obj.values():
            _check_depth(v, current + 1)
    elif isinstance(obj, list):
        for item in obj:
            _check_depth(item, current + 1)
    return current


def validate_payload(payload: dict) -> None:
    """Validate payload size and nesting depth."""
    raw = json.dumps(payload, ensure_ascii=False)
    if len(raw.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload size exceeds 512KB limit",
        )
    _check_depth(payload)


def check_version(record, client_version: Optional[int]) -> None:
    """Optimistic locking version validation."""
    if client_version is None:
        return
    if record.version != client_version:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Version conflict: server={record.version}, client={client_version}",
        )


def _validate_resource_name(name: str) -> str:
    """Validate configuration resource file name."""
    cleaned = name.strip()
    if (
        not cleaned
        or len(cleaned) > 128
        or "/" in cleaned
        or "\\" in cleaned
        or ".." in cleaned
        or any(ord(c) < 32 or ord(c) == 127 for c in cleaned)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid resource file name",
        )
    return cleaned


@router.get(
    "/account/{account_id}/{resource_type}/create",
    response_model=StatusResponse,
    tags=["Resource"],
    dependencies=[Depends(setup_tenant_context)],
)
@router.post(
    "/account/{account_id}/{resource_type}/create",
    response_model=StatusResponse,
    tags=["Resource"],
    dependencies=[Depends(setup_tenant_context)],
)
async def create_data(
    account_id: str,
    resource_type: str,
    name: str,
    db: AsyncSession = Depends(get_db),
):
    """Create a new tenant configuration file seeded with default template structure."""
    name = _validate_resource_name(name)
    model = MODEL_MAP.get(resource_type)
    if not model:
        return StatusResponse(status="error", message="Invalid resource type")
    existing = await db.execute(
        select(model).where(model.account_id == account_id, model.name == name)
    )
    if existing.scalar_one_or_none():
        return StatusResponse(status="error", message=f"{name} already exists")
    default_template = DEFAULT_RESOURCES.get(resource_type, {}).get("default", {})
    now = datetime.now(timezone.utc)
    serialized = json.dumps(default_template, ensure_ascii=False)
    db.add(
        model(
            account_id=account_id,
            name=name,
            content=serialized,
            version=1,
            updated_at=now,
        )
    )
    await record_resource_history(
        db,
        account_id=account_id,
        resource_type=resource_type,
        name=name,
        version=1,
        content=serialized,
        created_at=now,
    )
    await db.commit()
    from app.client.get import invalidate_resource_cache

    invalidate_resource_cache(account_id, resource_type, name)
    return StatusResponse(status="success", message=f"Created {name}")


@router.get(
    "/account/{account_id}/{resource_type}/list",
    tags=["Resource"],
    dependencies=[Depends(setup_tenant_context)],
)
async def list_data(
    account_id: str,
    resource_type: str,
    db: AsyncSession = Depends(get_db),
):
    """Get all configuration file names under resource category."""
    model = MODEL_MAP.get(resource_type)
    if not model:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid resource type"
        )
    await seed_account_defaults(account_id, db, fast_check=True)
    result = await db.execute(
        select(model.name)
        .where(model.account_id == account_id)
        .order_by(model.name.asc())
    )
    return result.scalars().all()


@router.get(
    "/account/{account_id}/{resource_type}/delete",
    response_model=StatusResponse,
    tags=["Resource"],
    dependencies=[Depends(setup_tenant_context)],
)
@router.delete(
    "/account/{account_id}/{resource_type}/delete",
    response_model=StatusResponse,
    tags=["Resource"],
    dependencies=[Depends(setup_tenant_context)],
)
async def delete_data(
    account_id: str,
    resource_type: str,
    name: str,
    db: AsyncSession = Depends(get_db),
):
    """Physically delete specified tenant configuration file."""
    name = _validate_resource_name(name)
    model = MODEL_MAP.get(resource_type)
    if not model:
        return StatusResponse(status="error", message="Invalid resource type")
    existing = await db.execute(
        select(model).where(model.account_id == account_id, model.name == name)
    )
    if not existing.scalar_one_or_none():
        return StatusResponse(status="error", message=f"{name} not found")
    await db.execute(
        delete(model).where(model.account_id == account_id, model.name == name)
    )
    await db.execute(
        delete(ResourceHistory).where(
            ResourceHistory.account_id == account_id,
            ResourceHistory.resource_type == resource_type,
            ResourceHistory.name == name,
        )
    )
    await db.commit()
    from app.client.get import invalidate_resource_cache

    invalidate_resource_cache(account_id, resource_type, name)
    return StatusResponse(status="success", message=f"Deleted {name}")


@router.patch(
    "/account/{account_id}/{resource_type}/update",
    response_model=StatusResponse,
    tags=["Resource"],
    dependencies=[Depends(setup_tenant_context)],
)
async def patch_data(
    account_id: str,
    resource_type: str,
    name: str,
    payload: dict = Body(...),
    version: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
):
    """Recursively merge incremental update to configuration file (with optimistic lock)."""
    name = _validate_resource_name(name)
    validate_payload(payload)
    model = MODEL_MAP.get(resource_type)
    if not model:
        return StatusResponse(status="error", message="Invalid model")
    record = (
        await db.execute(
            select(model).where(model.account_id == account_id, model.name == name)
        )
    ).scalar_one_or_none()
    if not record:
        return StatusResponse(status="error", message="File not found")
    check_version(record, version)
    try:
        current = json.loads(record.content) if record.content else {}
    except (json.JSONDecodeError, TypeError):
        current = {}

    def dict_deep_merge(base: dict, merge: dict) -> dict:
        for k, v in merge.items():
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                base[k] = dict_deep_merge(base[k], v)
            else:
                base[k] = v
        return base

    merged = normalize_resource_payload(
        resource_type, dict_deep_merge(current, payload)
    )
    now = datetime.now(timezone.utc)
    serialized = json.dumps(merged, ensure_ascii=False)
    next_version = (record.version or 0) + 1
    record.content = serialized
    record.version = next_version
    record.updated_at = now
    await record_resource_history(
        db,
        account_id=account_id,
        resource_type=resource_type,
        name=name,
        version=next_version,
        content=serialized,
        created_at=now,
    )
    await db.commit()
    from app.client.get import invalidate_resource_cache

    invalidate_resource_cache(account_id, resource_type, name)
    return StatusResponse(status="success", message="Merged successfully")


@router.get(
    "/account/{account_id}/{resource_type}/token",
    tags=["Resource"],
    dependencies=[Depends(setup_tenant_context)],
)
async def get_resource_token(
    account_id: str,
    resource_type: str,
    name: str,
    db: AsyncSession = Depends(get_db),
):
    """Verify configuration file existence and issue short-term download token."""
    name = _validate_resource_name(name)
    model = MODEL_MAP.get(resource_type)
    if not model:
        return {"status": "error", "message": "Invalid resource type"}

    record = (
        await db.execute(
            select(model).where(model.account_id == account_id, model.name == name)
        )
    ).scalar_one_or_none()
    if not record:
        return {"status": "error", "message": f"{name} not found"}

    token = await create_token(account_id, resource_type, name)
    return {"token": token, "url": f"/get?token={token}"}


@router.post(
    "/account/{account_id}/{resource_type}/write",
    response_model=StatusResponse,
    tags=["Resource"],
    dependencies=[Depends(setup_tenant_context)],
)
@router.put(
    "/account/{account_id}/{resource_type}/write",
    response_model=StatusResponse,
    tags=["Resource"],
    dependencies=[Depends(setup_tenant_context)],
)
async def write_data_endpoint(
    account_id: str,
    resource_type: str,
    name: str,
    payload: dict = Body(...),
    version: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
):
    """Overwriting data write endpoint for configuration file (with version conflict check)."""
    name = _validate_resource_name(name)
    validate_payload(payload)
    model = MODEL_MAP.get(resource_type)
    if not model:
        return StatusResponse(status="error", message="Invalid resource type")

    payload = normalize_resource_payload(resource_type, payload)

    record = (
        await db.execute(
            select(model).where(model.account_id == account_id, model.name == name)
        )
    ).scalar_one_or_none()
    if record:
        check_version(record, version)
    else:
        record = model(account_id=account_id, name=name)
    now = datetime.now(timezone.utc)
    serialized = json.dumps(payload, ensure_ascii=False)
    next_version = (record.version or 0) + 1
    record.content = serialized
    record.version = next_version
    record.updated_at = now
    db.add(record)
    await record_resource_history(
        db,
        account_id=account_id,
        resource_type=resource_type,
        name=name,
        version=next_version,
        content=serialized,
        created_at=now,
    )
    await db.commit()
    from app.client.get import invalidate_resource_cache

    invalidate_resource_cache(account_id, resource_type, name)
    return StatusResponse(status="success", message=f"{name} written successfully")


@router.post(
    "/account/{account_id}/batch",
    tags=["Bulk"],
    dependencies=[Depends(setup_tenant_context)],
)
async def account_batch_operations(
    account_id: str,
    req: BatchRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Execute batch resource operations under the specified account."""
    from app.admin.bulk import process_batch

    role = getattr(request.state, "role_in_account", "owner")
    if role == "member":
        for op in req.operations:
            if op.resource_type in ("Credentials", "Policy"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only account owner or admin can modify Credentials or Policy",
                )
    return await process_batch(req, db, account_id=account_id)


@router.get(
    "/account/{account_id}/{resource_type}/history",
    tags=["Resource"],
    dependencies=[Depends(setup_tenant_context)],
)
async def list_resource_history(
    account_id: str,
    resource_type: str,
    name: str = Query(..., min_length=1, max_length=255),
    db: AsyncSession = Depends(get_db),
):
    """List all historical versions of a specific configuration resource file."""
    model = MODEL_MAP.get(resource_type)
    if not model:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid resource type"
        )

    await seed_account_defaults(account_id, db, fast_check=True)

    record = (
        await db.execute(
            select(model).where(model.account_id == account_id, model.name == name)
        )
    ).scalar_one_or_none()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Resource {name} not found",
        )

    rows = (
        (
            await db.execute(
                select(ResourceHistory)
                .where(
                    ResourceHistory.account_id == account_id,
                    ResourceHistory.resource_type == resource_type,
                    ResourceHistory.name == name,
                )
                .order_by(ResourceHistory.version.desc(), ResourceHistory.id.desc())
            )
        )
        .scalars()
        .all()
    )

    current_ver = record.version or 1
    has_current = any(r.version == current_ver for r in rows)
    if not has_current:
        snap_time = record.updated_at or datetime.now(timezone.utc)
        await record_resource_history(
            db,
            account_id=account_id,
            resource_type=resource_type,
            name=name,
            version=current_ver,
            content=record.content or "{}",
            created_at=snap_time,
        )
        await db.commit()
        rows = (
            (
                await db.execute(
                    select(ResourceHistory)
                    .where(
                        ResourceHistory.account_id == account_id,
                        ResourceHistory.resource_type == resource_type,
                        ResourceHistory.name == name,
                    )
                    .order_by(ResourceHistory.version.desc(), ResourceHistory.id.desc())
                )
            )
            .scalars()
            .all()
        )
    else:
        await db.commit()

    seen_versions: set[int] = set()
    out = []
    for r in rows:
        if r.version in seen_versions:
            continue
        seen_versions.add(r.version)
        out.append(
            {
                "version": r.version,
                "name": r.name,
                "resource_type": r.resource_type,
                "updated_at": r.created_at.isoformat() if r.created_at else "",
                "size_bytes": len((r.content or "").encode("utf-8")),
                "is_current": r.version == current_ver,
            }
        )
    return out


@router.get(
    "/account/{account_id}/{resource_type}/history/{version}",
    tags=["Resource"],
    dependencies=[Depends(setup_tenant_context)],
)
async def get_resource_history_version(
    account_id: str,
    resource_type: str,
    version: int,
    name: str = Query(..., min_length=1, max_length=255),
    db: AsyncSession = Depends(get_db),
):
    """Get the normalized JSON content of a specific historical version of a configuration file."""
    model = MODEL_MAP.get(resource_type)
    if not model:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid resource type"
        )

    await seed_account_defaults(account_id, db, fast_check=True)

    row = (
        (
            await db.execute(
                select(ResourceHistory)
                .where(
                    ResourceHistory.account_id == account_id,
                    ResourceHistory.resource_type == resource_type,
                    ResourceHistory.name == name,
                    ResourceHistory.version == version,
                )
                .order_by(ResourceHistory.id.desc())
            )
        )
        .scalars()
        .first()
    )

    if not row:
        record = (
            await db.execute(
                select(model).where(model.account_id == account_id, model.name == name)
            )
        ).scalar_one_or_none()
        if record and (record.version or 1) == version:
            snap_time = record.updated_at or datetime.now(timezone.utc)
            await record_resource_history(
                db,
                account_id=account_id,
                resource_type=resource_type,
                name=name,
                version=version,
                content=record.content or "{}",
                created_at=snap_time,
            )
            await db.commit()
            raw_content = record.content or "{}"
            updated_iso = snap_time.isoformat()
        else:
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Historical version {version} of {name} not found",
            )
    else:
        await db.commit()
        raw_content = row.content or "{}"
        updated_iso = row.created_at.isoformat() if row.created_at else ""

    try:
        parsed = json.loads(raw_content) if raw_content else {}
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Corrupted historical resource content",
        )

    return {
        "version": version,
        "name": name,
        "resource_type": resource_type,
        "updated_at": updated_iso,
        "content": normalize_resource_payload(resource_type, parsed),
    }


@router.get(
    "/account/{account_id}/{resource_type}/{resource_id}",
    tags=["Resource"],
    dependencies=[Depends(setup_tenant_context)],
)
async def get_resource_content_endpoint(
    account_id: str,
    resource_type: str,
    resource_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Directly download/read resource JSON content by resource ID/name."""
    model = MODEL_MAP.get(resource_type)
    if not model:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid resource type"
        )

    await seed_account_defaults(account_id, db, fast_check=True)

    record = (
        await db.execute(
            select(model).where(
                model.account_id == account_id, model.name == resource_id
            )
        )
    ).scalar_one_or_none()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Resource {resource_id} not found",
        )

    try:
        parsed = json.loads(record.content) if record.content else {}
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Corrupted resource content",
        )
    return normalize_resource_payload(resource_type, parsed)
