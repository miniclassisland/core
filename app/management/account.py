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
    MODEL_MAP,
)
from app.shared.db.schema_init import seed_account_defaults
from app.shared.schemas.schemas import (
    AccountOut,
    AccountCreate,
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
    update_account_slug,
    validate_slug_format,
    is_name_reserved,
)
from app.shared.literals import AUDIT_EVENT_NAMES, CONFIG_TYPE_NAMES, DEFAULT_RESOURCES
from app.shared.runtime import get_session_manager, get_command_servicer
from app.shared.utils.config import BASE_DOMAIN
from app.shared.utils.tenant import invalidate_cached_account

logger = logging.getLogger(__name__)

router = APIRouter()


# ---- 1. Tenant Context Adaptive Dependency ----


async def setup_tenant_context(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Set tenant ID and database search_path in coroutine context, and verify member permissions."""
    from app.shared.utils.tenant import tenant_ctx, schema_ctx, set_search_path

    stmt = select(Account).where(Account.id == account_id)
    account = (await db.execute(stmt)).scalar_one_or_none()
    if not account or not account.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account invalid or non-existent",
        )

    # Verify if current user is a member of this account (or superadmin)
    member_stmt = select(AccountMember).where(
        AccountMember.account_id == account_id,
        AccountMember.user_id == user_id,
    )
    member = (await db.execute(member_stmt)).scalar_one_or_none()
    if not member:
        u = (
            await db.execute(select(User).where(User.id == user_id))
        ).scalar_one_or_none()
        if not u or u.role_code != "superadmin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Unauthorized access: You are not a member of this account",
            )

    tenant_ctx.set(account.id)
    schema_ctx.set(f"tenant_{account.slug}")
    await set_search_path(db)


def _account_out(a: Account) -> AccountOut:
    return AccountOut(
        id=a.id,
        name=a.name,
        slug=a.slug,
        api_key=a.api_key,
        is_active=a.is_active,
        registration_mode=getattr(a, "registration_mode", "open") or "open",
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
    stmt = (
        select(Account)
        .join(AccountMember, Account.id == AccountMember.account_id)
        .where(AccountMember.user_id == user_id)
        .where(Account.is_active.is_(True))
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [_account_out(a) for a in rows]


@router.post("/account/search", response_model=list[AccountOut], tags=["Account"])
async def search_accounts(
    q: str = "",
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Search accessible accounts by name."""
    stmt = (
        select(Account)
        .join(AccountMember, Account.id == AccountMember.account_id)
        .where(AccountMember.user_id == user_id)
        .where(Account.name.ilike(f"%{q}%"))
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [_account_out(a) for a in rows]


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
    """Deactivate account (Owner permission required, cleans up associated data)."""
    member = (
        await db.execute(
            select(AccountMember).where(
                AccountMember.account_id == account_id,
                AccountMember.user_id == uid,
            )
        )
    ).scalar_one_or_none()
    if not member or member.role_in_account != "owner":
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
    await invalidate_cached_account(acct.slug)
    await db.execute(
        delete(AccountMember).where(AccountMember.account_id == account_id)
    )
    await db.execute(
        delete(PreRegisteredClient).where(PreRegisteredClient.account_id == account_id)
    )
    await db.commit()
    return {
        "status": "ok",
        "message": "Account deactivated and associated data cleaned up",
    }


@router.get("/account/{account_id}/info", response_model=AccountOut, tags=["Account"])
async def get_account_info(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    _uid: str = Depends(get_current_user_id),
):
    """Get account information."""
    acct = (
        await db.execute(select(Account).where(Account.id == account_id))
    ).scalar_one_or_none()
    if not acct:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Account not found"
        )
    return _account_out(acct)


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
    dependencies=[Depends(setup_tenant_context)],
)
async def change_account_name(
    account_id: str,
    body: AccountNameUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update account organization display name."""
    acct = (
        await db.execute(select(Account).where(Account.id == account_id))
    ).scalar_one_or_none()
    if not acct:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Account not found"
        )
    acct.name = body.name.strip()
    await db.commit()
    await invalidate_cached_account(acct.slug)
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
):
    """Regenerate account API key."""
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
):
    """Update display name for member user."""
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
    new_name = body.get("name") or body.get("display_name") or ""
    if user and new_name:
        user.display_name = str(new_name).strip()
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
):
    """Remove member from account."""
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
):
    """Update member's role within account."""
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
    db: AsyncSession = Depends(get_db),
):
    """Search invitations by code."""
    rows = (
        (
            await db.execute(
                select(Invitation).where(Invitation.account_id == account_id)
            )
        )
        .scalars()
        .all()
    )
    if not q:
        return [_inv_out(inv) for inv in rows]
    return [_inv_out(inv) for inv in rows if q.lower() in (inv.code or "").lower()]


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
):
    """Update invitation role or max_uses."""
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
        inv.role_in_account = str(body["role_in_account"])
    if "max_uses" in body and body["max_uses"] is not None:
        inv.max_uses = int(body["max_uses"])
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
):
    """Revoke specified invitation code."""
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
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Redeem an invitation code to join an account."""
    code = body.code.strip()
    inv = (
        await db.execute(select(Invitation).where(Invitation.code == code))
    ).scalar_one_or_none()
    if not inv or not inv.is_active:
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

    db.add(
        AccountMember(
            id=str(uuid.uuid4()),
            user_id=uid,
            account_id=inv.account_id,
            role_in_account=inv.role_in_account or "member",
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
        "role_in_account": inv.role_in_account,
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
    mode = (getattr(acct, "registration_mode", "open") if acct else "open") or "open"
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
    mode = str(body.get("registration_mode") or body.get("mode") or "open").strip()
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
    db: AsyncSession = Depends(get_db),
):
    """Search pairing codes."""
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
    if not q:
        return [_pairing_out(r) for r in rows]
    ql = q.lower()
    return [
        _pairing_out(r)
        for r in rows
        if ql in (r.code or "").lower()
        or ql in (r.client_id or "").lower()
        or ql in (r.client_uid or "").lower()
        or ql in (r.client_mac or "").lower()
    ]


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
    db: AsyncSession = Depends(get_db),
):
    """Search pre-registered clients by class_identity, label, or mac_address."""
    rows = (
        (
            await db.execute(
                select(PreRegisteredClient).where(
                    PreRegisteredClient.account_id == account_id
                )
            )
        )
        .scalars()
        .all()
    )
    if not q:
        return [_prereg_out(r) for r in rows]
    ql = q.lower()
    return [
        _prereg_out(r)
        for r in rows
        if ql in (r.class_identity or "").lower()
        or ql in (r.label or "").lower()
        or ql in (getattr(r, "mac_address", "") or "").lower()
    ]


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
    preset = (
        body.get("preset_profile")
        if isinstance(body.get("preset_profile"), dict)
        else body
    )
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

    out: list[dict[str, Any]] = []
    for r in records:
        is_online = r.uid in online_map
        if not is_online and sm:
            is_online = await sm.is_client_online(account_id, r.uid)
        live_ip = online_map.get(r.uid, {}).get("ip") or getattr(r, "ip", "") or ""
        client_prof = prof_map.get(r.uid)
        out.append(
            {
                "uid": r.uid,
                "client_id": r.client_id or "",
                "name": r.display_name or r.client_id or r.uid,
                "display_name": getattr(r, "display_name", "") or "",
                "mac": r.mac or "",
                "ip": live_ip,
                "is_disabled": bool(getattr(r, "is_disabled", False)),
                "online": is_online and not bool(getattr(r, "is_disabled", False)),
                "status": (
                    "disabled"
                    if getattr(r, "is_disabled", False)
                    else ("online" if is_online else "offline")
                ),
                "registered_at": (
                    r.registered_at.isoformat() if r.registered_at else None
                ),
                "last_seen_at": (
                    r.last_seen_at.isoformat()
                    if getattr(r, "last_seen_at", None)
                    else None
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
    db: AsyncSession = Depends(get_db),
):
    """Search registered physical client devices by UID, ClassIdentity, display_name, MAC, or IP."""
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
    items = await _serialize_clients(account_id, list(rows), request, db)
    if not q:
        return items
    ql = q.lower()
    return [
        c
        for c in items
        if ql in c["uid"].lower()
        or ql in c["client_id"].lower()
        or ql in c["display_name"].lower()
        or ql in c["mac"].lower()
        or ql in c["ip"].lower()
    ]


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
    await seed_account_defaults(account_id, db)
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
    servicer = get_command_servicer(request)
    if servicer:
        await servicer.disconnect_client(account_id, client_id)
    sm = get_session_manager(request)
    if sm:
        await sm.set_client_offline(account_id, client_id)
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
    """Execute batch action ('sync', 'restart', 'disconnect', 'enable', 'disable', 'delete', 'assign_profile') on multiple clients."""
    action = str(body.get("action") or "").strip()
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
        elif action in ("enable", "disable", "delete"):
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
            elif action == "delete":
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

    clients = (
        (
            await db.execute(
                select(ClientRecord).where(ClientRecord.account_id == account_id)
            )
        )
        .scalars()
        .all()
    )
    client_map = {c.uid: c.display_name or c.client_id or c.uid for c in clients}

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
):
    """Clear audit logs for current tenant account."""
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
MAX_NESTING_DEPTH = 10


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
    model = MODEL_MAP.get(resource_type)
    if not model:
        return StatusResponse(status="error", message="Invalid resource type")
    existing = await db.execute(
        select(model).where(model.account_id == account_id, model.name == name)
    )
    if existing.scalar_one_or_none():
        return StatusResponse(status="error", message=f"{name} already exists")
    default_template = DEFAULT_RESOURCES.get(resource_type, {}).get("default", {})
    db.add(
        model(
            account_id=account_id,
            name=name,
            content=json.dumps(default_template, ensure_ascii=False),
            version=1,
            updated_at=datetime.now(timezone.utc),
        )
    )
    await db.commit()
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
    await seed_account_defaults(account_id, db)
    await db.commit()
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
    await db.commit()
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
    record.content = json.dumps(merged, ensure_ascii=False)
    record.version = (record.version or 0) + 1
    record.updated_at = datetime.now(timezone.utc)
    await db.commit()
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
    record.content = json.dumps(payload, ensure_ascii=False)
    record.version = (record.version or 0) + 1
    record.updated_at = datetime.now(timezone.utc)
    db.add(record)
    await db.commit()
    return StatusResponse(status="success", message=f"{name} written successfully")


@router.post(
    "/account/{account_id}/batch",
    tags=["Bulk"],
    dependencies=[Depends(setup_tenant_context)],
)
async def account_batch_operations(
    account_id: str,
    req: BatchRequest,
    db: AsyncSession = Depends(get_db),
):
    """Execute batch resource operations under the specified account."""
    from app.admin.bulk import process_batch

    return await process_batch(req, db, account_id=account_id)


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

    await seed_account_defaults(account_id, db)
    await db.commit()

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
