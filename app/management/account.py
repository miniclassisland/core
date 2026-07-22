import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from pydantic import EmailStr
from sqlalchemy import select, delete, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db, AsyncSessionLocal
from app.shared.db.models import (
    Account,
    AccountMember,
    PreRegisteredClient,
    PairingCode,
    Invitation,
    ClientRecord,
    MODEL_MAP,
)
from app.shared.schemas.schemas import (
    AccountOut,
    AccountCreate,
    SlugUpdate,
    AccessMemberOut,
    AccessRoleUpdate,
    InvitationOut,
    InvitationCreate,
    PairingCodeOut,
    PreRegCreate,
    PreRegOut,
    StatusResponse,
    NotificationPayload,
)
from app.shared.security.auth import (
    get_current_user_id,
    create_token,
)
from app.shared.security.crypto import verify_password
from app.shared.services.user import (
    create_account,
    update_account_slug,
    validate_slug_format,
    is_name_reserved,
)
from app.shared.utils.config import BASE_DOMAIN

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
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account invalid or non-existent")

    # Verify if current user is a member of this account
    member_stmt = select(AccountMember).where(
        AccountMember.account_id == account_id,
        AccountMember.user_id == user_id,
    )
    member = (await db.execute(member_stmt)).scalar_one_or_none()
    if not member:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized access: You are not a member of this account")

    tenant_ctx.set(account.id)
    schema_ctx.set(f"tenant_{account.slug}")
    await set_search_path(db)


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
        .where(Account.is_active == True)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [
        AccountOut(
            id=a.id,
            name=a.name,
            slug=a.slug,
            api_key=a.api_key,
            is_active=a.is_active,
            created_at=a.created_at.isoformat() if hasattr(a.created_at, "isoformat") else str(a.created_at),
        )
        for a in rows
    ]


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
    return [
        AccountOut(
            id=a.id,
            name=a.name,
            slug=a.slug,
            api_key=a.api_key,
            is_active=a.is_active,
            created_at=a.created_at.isoformat() if hasattr(a.created_at, "isoformat") else str(a.created_at),
        )
        for a in rows
    ]


@router.post("/account/apply", response_model=AccountOut, status_code=status.HTTP_201_CREATED, tags=["Account"])
async def apply_account(
    body: AccountCreate,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Apply to create a new account."""
    from app.shared.db.models import User
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user or not user.can_create_account:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied to create account")
    try:
        account = await create_account(body.name, user_id, db, slug=body.slug)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return AccountOut(
        id=account.id,
        name=account.name,
        slug=account.slug,
        api_key=account.api_key,
        is_active=account.is_active,
        created_at=account.created_at.isoformat() if hasattr(account.created_at, "isoformat") else str(account.created_at),
    )


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
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only account owner can perform this operation")
    acct = (await db.execute(select(Account).where(Account.id == account_id))).scalar_one_or_none()
    if not acct:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")
    
    acct.is_active = False
    await db.execute(delete(AccountMember).where(AccountMember.account_id == account_id))
    await db.execute(delete(PreRegisteredClient).where(PreRegisteredClient.account_id == account_id))
    await db.commit()
    return {"status": "ok", "message": "Account deactivated and associated data cleaned up"}


@router.get("/account/{account_id}/info", response_model=AccountOut, tags=["Account"])
async def get_account_info(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    _uid: str = Depends(get_current_user_id),
):
    """Get account information."""
    acct = (await db.execute(select(Account).where(Account.id == account_id))).scalar_one_or_none()
    if not acct:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")
    return AccountOut(
        id=acct.id,
        name=acct.name,
        slug=acct.slug,
        api_key=acct.api_key,
        is_active=acct.is_active,
        created_at=acct.created_at.isoformat() if hasattr(acct.created_at, "isoformat") else str(acct.created_at),
    )


@router.post("/account/{account_id}/info/slug", response_model=AccountOut, tags=["Account"])
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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")
    return AccountOut(
        id=acct.id,
        name=acct.name,
        slug=acct.slug,
        api_key=acct.api_key,
        is_active=acct.is_active,
        created_at=acct.created_at.isoformat() if hasattr(acct.created_at, "isoformat") else str(acct.created_at),
    )


# ---- 3. Tenant Access Control ----

def _member_out(m: AccountMember) -> AccessMemberOut:
    return AccessMemberOut(
        id=m.id,
        user_id=m.user_id,
        account_id=m.account_id,
        role_in_account=m.role_in_account,
        joined_at=str(m.joined_at),
    )


@router.get("/account/{account_id}/access/list", response_model=list[AccessMemberOut], tags=["Access"], dependencies=[Depends(setup_tenant_context)])
async def list_access(
    account_id: str,
    db: AsyncSession = Depends(get_db),
):
    """List members under the account."""
    rows = (await db.execute(select(AccountMember).where(AccountMember.account_id == account_id))).scalars().all()
    return [_member_out(m) for m in rows]


@router.post("/account/{account_id}/access/{user_id}/rename", tags=["Access"], dependencies=[Depends(setup_tenant_context)])
async def rename_access(account_id: str, user_id: str):
    """Rename member user."""
    return {"status": "ok", "message": "Not implemented yet"}


@router.get("/account/{account_id}/access/search", response_model=list[AccessMemberOut], tags=["Access"], dependencies=[Depends(setup_tenant_context)])
async def search_access(
    account_id: str,
    q: str = "",
    db: AsyncSession = Depends(get_db),
):
    """Search account members by user_id."""
    stmt = select(AccountMember).where(
        AccountMember.account_id == account_id,
        AccountMember.user_id.ilike(f"%{q}%"),
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [_member_out(m) for m in rows]


@router.get("/account/{account_id}/access/{user_id}", response_model=AccessMemberOut, tags=["Access"], dependencies=[Depends(setup_tenant_context)])
async def get_access_detail(
    account_id: str,
    user_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get member details by user_id."""
    m = (
        await db.execute(
            select(AccountMember).where(
                AccountMember.account_id == account_id,
                AccountMember.user_id == user_id,
            )
        )
    ).scalar_one_or_none()
    if not m:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")
    return _member_out(m)


@router.delete("/account/{account_id}/access/{user_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Access"], dependencies=[Depends(setup_tenant_context)])
async def delete_access(
    account_id: str,
    user_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Remove member from account."""
    m = (
        await db.execute(
            select(AccountMember).where(
                AccountMember.id == user_id,
                AccountMember.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not m:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member record not found")
    await db.delete(m)
    await db.commit()


@router.post("/account/{account_id}/access/{user_id}", response_model=AccessMemberOut, tags=["Access"], dependencies=[Depends(setup_tenant_context)])
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
                AccountMember.id == user_id,
                AccountMember.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not m:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member record not found")
    m.role_in_account = body.role_in_account
    await db.commit()
    await db.refresh(m)
    return _member_out(m)


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
        expires_at=str(inv.expires_at) if inv.expires_at else None,
        is_active=inv.is_active,
        created_at=str(inv.created_at),
    )


@router.get("/account/{account_id}/invitation/list", response_model=list[InvitationOut], tags=["Invite"], dependencies=[Depends(setup_tenant_context)])
async def list_invitations(
    account_id: str,
    db: AsyncSession = Depends(get_db),
):
    """List all invitations under account."""
    rows = (await db.execute(select(Invitation).where(Invitation.account_id == account_id))).scalars().all()
    return [_inv_out(inv) for inv in rows]


@router.get("/account/{account_id}/invitation/search", response_model=list[InvitationOut], tags=["Invite"], dependencies=[Depends(setup_tenant_context)])
async def search_invitations(
    account_id: str,
    q: str = "",
    db: AsyncSession = Depends(get_db),
):
    """Search invitations by code."""
    rows = (await db.execute(select(Invitation).where(Invitation.account_id == account_id))).scalars().all()
    if not q:
        return [_inv_out(inv) for inv in rows]
    return [_inv_out(inv) for inv in rows if q.lower() in (inv.code or "").lower()]


@router.post("/account/{account_id}/invitation/{invitation_id}/rename", tags=["Invite"], dependencies=[Depends(setup_tenant_context)])
async def rename_invitation(account_id: str, invitation_id: str):
    """Rename invitation code."""
    return {"status": "ok", "message": "Not implemented yet"}


@router.get("/account/{account_id}/invitation/{invitation_id}", response_model=InvitationOut, tags=["Invite"], dependencies=[Depends(setup_tenant_context)])
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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invitation not found")
    return _inv_out(inv)


@router.post("/account/{account_id}/invitation/create", response_model=InvitationOut, status_code=status.HTTP_201_CREATED, tags=["Invite"], dependencies=[Depends(setup_tenant_context)])
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


@router.delete("/account/{account_id}/invitation/{invitation_id}", tags=["Invite"], dependencies=[Depends(setup_tenant_context)])
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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invitation not found")
    inv.is_active = False
    await db.commit()
    return {"status": "ok", "message": f"Invitation {invitation_id} revoked"}


# ---- 5. Client Pairing Code Management ----

@router.get("/account/{account_id}/pairing/list", response_model=list[PairingCodeOut], tags=["Pairing"], dependencies=[Depends(setup_tenant_context)])
async def list_pairing_codes(
    db: AsyncSession = Depends(get_db),
):
    """List pairing codes for current account."""
    from app.shared.utils.tenant import get_tenant_id
    tid = get_tenant_id()
    rows = (await db.execute(select(PairingCode).where(PairingCode.tenant_id == tid))).scalars().all()
    return [
        PairingCodeOut(
            id=r.id,
            code=r.code,
            client_uid=getattr(r, "client_uid", "") or "",
            approved=getattr(r, "approved", False),
            used=getattr(r, "used", False),
            created_at=str(getattr(r, "created_at", "")),
        )
        for r in rows
    ]


@router.get("/account/{account_id}/pairing/search", response_model=list[PairingCodeOut], tags=["Pairing"], dependencies=[Depends(setup_tenant_context)])
async def search_pairing_codes(
    q: str = "",
    db: AsyncSession = Depends(get_db),
):
    """Search pairing codes."""
    from app.shared.utils.tenant import get_tenant_id
    tid = get_tenant_id()
    rows = (await db.execute(select(PairingCode).where(PairingCode.tenant_id == tid))).scalars().all()
    return [
        PairingCodeOut(
            id=r.id,
            code=r.code,
            client_uid=getattr(r, "client_uid", "") or "",
            approved=getattr(r, "approved", False),
            used=getattr(r, "used", False),
            created_at=str(getattr(r, "created_at", "")),
        )
        for r in rows
        if not q or q.lower() in (r.code or "").lower()
    ]


@router.post("/account/{account_id}/pairing/enable", tags=["Pairing"], dependencies=[Depends(setup_tenant_context)])
async def enable_pairing():
    """Enable pairing code functionality."""
    return {"status": "ok", "message": "Not implemented yet"}


@router.post("/account/{account_id}/pairing/disable", tags=["Pairing"], dependencies=[Depends(setup_tenant_context)])
async def disable_pairing():
    """Disable pairing code functionality."""
    return {"status": "ok", "message": "Not implemented yet"}


@router.post("/account/{account_id}/pairing/{pairing_id}/reject", tags=["Pairing"], dependencies=[Depends(setup_tenant_context)])
async def reject_pairing(
    pairing_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Reject (revoke) pairing code."""
    from app.shared.utils.tenant import get_tenant_id
    tid = get_tenant_id()
    row = (
        await db.execute(
            select(PairingCode).where(
                PairingCode.id == pairing_id,
                PairingCode.tenant_id == tid,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pairing code not found")
    await db.delete(row)
    await db.commit()
    return {"status": "ok", "message": f"Pairing code {pairing_id} rejected"}


@router.post("/account/{account_id}/pairing/{pairing_id}/approve", tags=["Pairing"], dependencies=[Depends(setup_tenant_context)])
async def approve_pairing_code(
    pairing_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Approve pairing code."""
    from app.shared.utils.tenant import get_tenant_id
    tid = get_tenant_id()
    row = (
        await db.execute(
            select(PairingCode).where(
                PairingCode.id == pairing_id,
                PairingCode.tenant_id == tid,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pairing code not found")
    row.approved = True
    await db.commit()
    return {"status": "ok", "message": f"Pairing code {pairing_id} approved"}


# ---- 6. Pre-Registered Client Management ----

def _prereg_out(p: PreRegisteredClient) -> PreRegOut:
    return PreRegOut(
        id=p.id,
        account_id=p.account_id,
        label=p.label,
        class_identity=p.class_identity,
        created_at=str(p.created_at),
    )


@router.post("/account/{account_id}/pre-registration/create", response_model=PreRegOut, status_code=status.HTTP_201_CREATED, tags=["PreReg"], dependencies=[Depends(setup_tenant_context)])
async def create_pre_reg(
    account_id: str,
    body: PreRegCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create pre-registered client device, validating class_identity uniqueness."""
    dup = await db.execute(
        select(PreRegisteredClient).where(
            PreRegisteredClient.account_id == account_id,
            PreRegisteredClient.class_identity == body.class_identity,
        )
    )
    if dup.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="class_identity already exists")
    p = PreRegisteredClient(
        id=str(uuid.uuid4()),
        account_id=account_id,
        label=body.label,
        class_identity=body.class_identity,
        created_at=datetime.now(timezone.utc),
    )
    db.add(p)
    await db.commit()
    await db.refresh(p)
    return _prereg_out(p)


@router.get("/account/{account_id}/pre-registration/list", response_model=list[PreRegOut], tags=["PreReg"], dependencies=[Depends(setup_tenant_context)])
async def list_pre_regs(
    account_id: str,
    db: AsyncSession = Depends(get_db),
):
    """List all pre-registered client device records for current account."""
    rows = (await db.execute(select(PreRegisteredClient).where(PreRegisteredClient.account_id == account_id))).scalars().all()
    return [_prereg_out(r) for r in rows]


@router.get("/account/{account_id}/pre-registration/search", response_model=list[PreRegOut], tags=["PreReg"], dependencies=[Depends(setup_tenant_context)])
async def search_pre_regs(
    account_id: str,
    q: str = "",
    db: AsyncSession = Depends(get_db),
):
    """Search pre-registered clients by class_identity."""
    rows = (await db.execute(select(PreRegisteredClient).where(PreRegisteredClient.account_id == account_id))).scalars().all()
    if not q:
        return [_prereg_out(r) for r in rows]
    return [_prereg_out(r) for r in rows if q.lower() in (r.class_identity or "").lower()]


@router.get("/account/{account_id}/pre-registration/{pre_reg_id}", response_model=PreRegOut, tags=["PreReg"], dependencies=[Depends(setup_tenant_context)])
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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pre-registered client not found")
    return _prereg_out(row)


@router.delete("/account/{account_id}/pre-registration/{pre_reg_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["PreReg"], dependencies=[Depends(setup_tenant_context)])
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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pre-registered client not found")
    await db.delete(row)
    await db.commit()


@router.post("/account/{account_id}/pre-registration/{pre_reg_id}/rename", tags=["PreReg"], dependencies=[Depends(setup_tenant_context)])
async def rename_pre_reg(account_id: str, pre_reg_id: str):
    """Rename pre-registered device."""
    return {"status": "ok", "message": "Not implemented yet"}


@router.post("/account/{account_id}/pre-registration/{pre_reg_id}/enable", tags=["PreReg"], dependencies=[Depends(setup_tenant_context)])
async def enable_pre_reg(account_id: str, pre_reg_id: str):
    """Enable pre-registered device."""
    return {"status": "ok", "message": "Not implemented yet"}


@router.post("/account/{account_id}/pre-registration/{pre_reg_id}/disable", tags=["PreReg"], dependencies=[Depends(setup_tenant_context)])
async def disable_pre_reg(account_id: str, pre_reg_id: str):
    """Disable pre-registered device."""
    return {"status": "ok", "message": "Not implemented yet"}


@router.post("/account/{account_id}/pre-registration/{pre_reg_id}/config", tags=["PreReg"], dependencies=[Depends(setup_tenant_context)])
async def config_pre_reg(account_id: str, pre_reg_id: str):
    """Update profile configuration for pre-registered client."""
    return {"status": "ok", "message": "Not implemented yet"}


@router.get("/account/{account_id}/pre-registration/{pre_reg_id}/ManagementPreset.json", tags=["PreReg"], dependencies=[Depends(setup_tenant_context)])
async def download_preset(
    account_id: str,
    pre_reg_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Download OOBE ManagementPreset.json configuration archive for a specific pre-registered client device."""
    acct = (await db.execute(select(Account).where(Account.id == account_id))).scalar_one_or_none()
    if not acct or not acct.is_active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found or deactivated")
    pre_reg = (
        await db.execute(
            select(PreRegisteredClient).where(
                PreRegisteredClient.id == pre_reg_id,
                PreRegisteredClient.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not pre_reg:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pre-registered client not found")
    return {
        "IsManagementEnabled": True,
        "ManagementServerKind": 1,
        "ManagementServer": f"https://{acct.slug}.{BASE_DOMAIN}",
        "ManagementServerGrpc": f"https://{acct.slug}.{BASE_DOMAIN}",
        "ClassIdentity": pre_reg.class_identity,
        "ManifestUrlTemplate": "",
    }


# ---- 7. Client Machine & Command Monitoring ----

@router.get("/account/{account_id}/client/list", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def list_clients(
    db: AsyncSession = Depends(get_db),
):
    """Get list of registered client UIDs for current tenant."""
    return (await db.execute(select(ClientRecord.uid))).scalars().all()


@router.get("/account/{account_id}/client/search", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def search_clients(
    q: str = "",
    db: AsyncSession = Depends(get_db),
):
    """Search registered physical client devices by UID."""
    rows = (await db.execute(select(ClientRecord))).scalars().all()
    if not q:
        return [r.uid for r in rows]
    return [r.uid for r in rows if q.lower() in (r.uid or "").lower()]


@router.get("/account/{account_id}/client/{client_id}", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def get_client_detail(
    account_id: str,
    client_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Query registration details and online status for a specific client device."""
    record = (await db.execute(select(ClientRecord).where(ClientRecord.uid == client_id))).scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    sm = getattr(request.app.state, "session_manager", None)
    online = await sm.is_client_online(account_id, client_id) if sm else False
    return {
        "uid": record.uid,
        "name": record.client_id,
        "mac": record.mac,
        "status": "online" if online else "offline",
        "registered_at": (record.registered_at.isoformat() if record.registered_at else None),
    }


@router.delete("/account/{account_id}/client/{client_id}", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def delete_client(
    client_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Unregister and remove physical client device record."""
    record = (await db.execute(select(ClientRecord).where(ClientRecord.uid == client_id))).scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    await db.delete(record)
    await db.commit()
    return {"status": "ok", "message": "Deleted"}


@router.post("/account/{account_id}/client/{client_id}/rename", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def rename_client(client_id: str):
    """Rename specified physical client machine."""
    return {"status": "ok", "message": "Not implemented yet", "client_id": client_id}


@router.get("/account/{account_id}/client/{client_id}/status", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def get_client_status(
    account_id: str,
    client_id: str,
    request: Request,
):
    """Query heartbeat active online status for specified client."""
    sm = getattr(request.app.state, "session_manager", None)
    online = await sm.is_client_online(account_id, client_id) if sm else False
    return {"client_id": client_id, "online": online}


@router.post("/account/{account_id}/client/{client_id}/disconnect", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def disconnect_client(client_id: str):
    """Disconnect physical client device."""
    return {"status": "ok", "message": "Not implemented yet", "client_id": client_id}


@router.post("/account/{account_id}/client/{client_id}/disable", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def disable_client(client_id: str):
    """Disable specified physical client device."""
    return {"status": "ok", "message": "Not implemented yet", "client_id": client_id}


@router.post("/account/{account_id}/client/{client_id}/enable", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def enable_client(client_id: str):
    """Enable specified physical client device."""
    return {"status": "ok", "message": "Not implemented yet", "client_id": client_id}


@router.post("/account/{account_id}/client/{client_id}/config", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def set_client_config(client_id: str):
    """Update resource configuration set for physical client device."""
    return {"status": "ok", "message": "Not implemented yet", "client_id": client_id}


# ---- 8. Remote Control Command Push ----

async def _push_cmd(request: Request, account_id: str, uid: str, cmd_type: int) -> StatusResponse:
    """Helper function to deliver simple payload-less gRPC command."""
    servicer = getattr(request.app.state, "command_servicer", None)
    if not servicer:
        return StatusResponse(status="error", message="gRPC service unavailable")

    from app.grpc.api.Protobuf.Server import ClientCommandDeliverScRsp_pb2
    from app.grpc.api.Protobuf.Enum import Retcode_pb2

    cmd = ClientCommandDeliverScRsp_pb2.ClientCommandDeliverScRsp(
        RetCode=Retcode_pb2.Success, Type=cmd_type
    )
    await servicer.send_command(account_id, uid, cmd)
    return StatusResponse(status="success", message="Command delivered")


@router.get("/account/{account_id}/client/{client_id}/command/get-config", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def fetch_runtime_config(
    account_id: str,
    client_id: str,
    config_type: int,
    request: Request,
):
    """Request client to report full runtime snapshot configuration."""
    servicer = getattr(request.app.state, "command_servicer", None)
    if not servicer:
        return {"status": "error", "message": "Communication channel closed"}

    from app.grpc.api.Protobuf.Server import ClientCommandDeliverScRsp_pb2
    from app.grpc.api.Protobuf.Command import GetClientConfig_pb2
    from app.grpc.api.Protobuf.Enum import Retcode_pb2, CommandTypes_pb2

    req_id = str(uuid.uuid4())
    config_req = GetClientConfig_pb2.GetClientConfig(
        RequestGuid=req_id, ConfigType=config_type
    )

    cmd = ClientCommandDeliverScRsp_pb2.ClientCommandDeliverScRsp(
        RetCode=Retcode_pb2.Success,
        Type=CommandTypes_pb2.GetClientConfig,
        Payload=config_req.SerializeToString(),
    )

    await servicer.send_command(account_id, client_id, cmd)
    return {
        "status": "success",
        "message": f"Request delivered, GUID: {req_id}",
        "request_guid": req_id,
    }


@router.post("/account/{account_id}/client/{client_id}/command/restart", response_model=StatusResponse, tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def restart_app(
    account_id: str,
    client_id: str,
    request: Request,
):
    """Control instruction: request physical client machine to restart main ClassIsland application."""
    from app.grpc.api.Protobuf.Enum import CommandTypes_pb2
    return await _push_cmd(request, account_id, client_id, CommandTypes_pb2.RestartApp)


@router.post("/account/{account_id}/client/{client_id}/command/update-data", response_model=StatusResponse, tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def force_sync(
    account_id: str,
    client_id: str,
    request: Request,
):
    """Control instruction: force physical machine to fetch and reload latest resource configuration."""
    from app.grpc.api.Protobuf.Enum import CommandTypes_pb2
    return await _push_cmd(request, account_id, client_id, CommandTypes_pb2.DataUpdated)


@router.post("/account/{account_id}/client/{client_id}/command/send-notification", response_model=StatusResponse, tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def push_notify(
    account_id: str,
    client_id: str,
    request: Request,
    payload: NotificationPayload = Body(...),
):
    """Control instruction: send and display desktop notification on target client device."""
    servicer = getattr(request.app.state, "command_servicer", None)
    if not servicer:
        return StatusResponse(status="error", message="gRPC channel not open")

    from app.grpc.api.Protobuf.Server import ClientCommandDeliverScRsp_pb2
    from app.grpc.api.Protobuf.Command import SendNotification_pb2
    from app.grpc.api.Protobuf.Enum import Retcode_pb2, CommandTypes_pb2

    notify = SendNotification_pb2.SendNotification(**payload.model_dump())

    cmd = ClientCommandDeliverScRsp_pb2.ClientCommandDeliverScRsp(
        RetCode=Retcode_pb2.Success,
        Type=CommandTypes_pb2.SendNotification,
        Payload=notify.SerializeToString(),
    )

    await servicer.send_command(account_id, client_id, cmd)
    return StatusResponse(status="success", message="Notification delivered")


# ---- 9. Config Resource CRUD (Tenant Config Resources DDL) ----

# Safety limits
MAX_PAYLOAD_BYTES = 512 * 1024  # 512 KB
MAX_NESTING_DEPTH = 10


def _check_depth(obj, current: int = 0) -> int:
    """Recursively check nesting depth and raise exception if limit exceeded."""
    if current > MAX_NESTING_DEPTH:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Payload nesting depth exceeded limit")
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
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Payload size exceeds 512KB limit")
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


@router.get("/account/{account_id}/{resource_type}/create", response_model=StatusResponse, tags=["Resource"], dependencies=[Depends(setup_tenant_context)])
async def create_data(
    resource_type: str,
    name: str,
    db: AsyncSession = Depends(get_db),
):
    """Create a new empty tenant configuration file."""
    model = MODEL_MAP.get(resource_type)
    if not model:
        return StatusResponse(status="error", message="Invalid resource type")
    existing = await db.execute(select(model).where(model.name == name))
    if existing.scalar_one_or_none():
        return StatusResponse(status="error", message=f"{name} already exists")
    db.add(
        model(name=name, content="{}", version=0, updated_at=datetime.now(timezone.utc))
    )
    await db.commit()
    return StatusResponse(status="success", message=f"Created {name}")


@router.get("/account/{account_id}/{resource_type}/list", tags=["Resource"], dependencies=[Depends(setup_tenant_context)])
async def list_data(
    resource_type: str,
    db: AsyncSession = Depends(get_db),
):
    """Get all configuration file names under resource category."""
    model = MODEL_MAP.get(resource_type)
    if not model:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid resource type")
    result = await db.execute(select(model.name))
    return result.scalars().all()


@router.get("/account/{account_id}/{resource_type}/delete", response_model=StatusResponse, tags=["Resource"], dependencies=[Depends(setup_tenant_context)])
@router.delete("/account/{account_id}/{resource_type}/delete", response_model=StatusResponse, tags=["Resource"], dependencies=[Depends(setup_tenant_context)])
async def delete_data(
    resource_type: str,
    name: str,
    db: AsyncSession = Depends(get_db),
):
    """Physically delete specified tenant configuration file."""
    model = MODEL_MAP.get(resource_type)
    if not model:
        return StatusResponse(status="error", message="Invalid resource type")
    existing = await db.execute(select(model).where(model.name == name))
    if not existing.scalar_one_or_none():
        return StatusResponse(status="error", message=f"{name} not found")
    await db.execute(delete(model).where(model.name == name))
    await db.commit()
    return StatusResponse(status="success", message=f"Deleted {name}")


@router.patch("/account/{account_id}/{resource_type}/update", response_model=StatusResponse, tags=["Resource"], dependencies=[Depends(setup_tenant_context)])
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
    record = (await db.execute(select(model).where(model.name == name))).scalar_one_or_none()
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

    record.content = json.dumps(dict_deep_merge(current, payload))
    record.version = (record.version or 0) + 1
    record.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return StatusResponse(status="success", message="Merged successfully")


@router.get("/account/{account_id}/{resource_type}/token", tags=["Resource"], dependencies=[Depends(setup_tenant_context)])
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

    record = (await db.execute(select(model).where(model.name == name))).scalar_one_or_none()
    if not record:
        return {"status": "error", "message": f"{name} not found"}

    token = await create_token(account_id, resource_type, name)
    return {"token": token, "url": f"/get?token={token}"}


@router.post("/account/{account_id}/{resource_type}/write", response_model=StatusResponse, tags=["Resource"], dependencies=[Depends(setup_tenant_context)])
@router.put("/account/{account_id}/{resource_type}/write", response_model=StatusResponse, tags=["Resource"], dependencies=[Depends(setup_tenant_context)])
async def write_data_endpoint(
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

    record = (await db.execute(select(model).where(model.name == name))).scalar_one_or_none()
    if record:
        check_version(record, version)
    else:
        record = model(name=name)
    record.content = json.dumps(payload)
    record.version = (record.version or 0) + 1
    record.updated_at = datetime.now(timezone.utc)
    db.add(record)
    await db.commit()
    return StatusResponse(status="success", message=f"{name} written successfully")
