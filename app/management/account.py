import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
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


# ---- 1. 租户上下文自适应依赖注入项 (Tenant context dependency) ----

async def setup_tenant_context(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """设置协程上下文中的租户 ID 和数据库 search_path，并验证成员权限。"""
    from app.shared.utils.tenant import tenant_ctx, schema_ctx, set_search_path

    stmt = select(Account).where(Account.id == account_id)
    account = (await db.execute(stmt)).scalar_one_or_none()
    if not account or not account.is_active:
        raise HTTPException(status_code=403, detail="账户异常或不存在")

    # 验证当前用户是否是该账户的成员
    member_stmt = select(AccountMember).where(
        AccountMember.account_id == account_id,
        AccountMember.user_id == user_id,
    )
    member = (await db.execute(member_stmt)).scalar_one_or_none()
    if not member:
        raise HTTPException(status_code=403, detail="越权访问：您不是该账户的成员")

    tenant_ctx.set(account.id)
    schema_ctx.set(f"tenant_{account.slug}")
    await set_search_path(db)


# ---- 2. 租户账户管理 (Tenant Account Management) ----

@router.get("/account/availability/slug", tags=["Availability"])
async def check_slug_availability(
    value: str = Query(..., min_length=3, max_length=64, description="待检查的 Slug"),
    db: AsyncSession = Depends(get_db),
):
    """检查账户 Slug 是否可用。"""
    if not validate_slug_format(value):
        return {"available": False, "reason": "Slug 格式不合法"}
    if await is_name_reserved(value, db):
        return {"available": False, "reason": "该名称为系统保留名"}
    result = await db.execute(select(Account.id).where(Account.slug == value))
    if result.scalar_one_or_none() is not None:
        return {"available": False, "reason": "该 Slug 已被占用"}
    return {"available": True}


@router.get("/account/list", response_model=list[AccountOut], tags=["Account"])
async def list_accounts(
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """列出当前用户有权限访问的所有账户。"""
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
    """按名称搜索当前用户可见的账户。"""
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


@router.post("/account/apply", response_model=AccountOut, status_code=201, tags=["Account"])
async def apply_account(
    body: AccountCreate,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """申请创建新账户。"""
    from app.shared.db.models import User
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user or not user.can_create_account:
        raise HTTPException(status_code=403, detail="无权创建账户")
    try:
        account = await create_account(body.name, user_id, db, slug=body.slug)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
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
    """停用账户（需 owner 权限，级联清理关联数据）。"""
    member = (
        await db.execute(
            select(AccountMember).where(
                AccountMember.account_id == account_id,
                AccountMember.user_id == uid,
            )
        )
    ).scalar_one_or_none()
    if not member or member.role_in_account != "owner":
        raise HTTPException(status_code=403, detail="仅账户所有者可执行此操作")
    acct = (await db.execute(select(Account).where(Account.id == account_id))).scalar_one_or_none()
    if not acct:
        raise HTTPException(status_code=404, detail="账户不存在")
    
    acct.is_active = False
    await db.execute(delete(AccountMember).where(AccountMember.account_id == account_id))
    await db.execute(delete(PreRegisteredClient).where(PreRegisteredClient.account_id == account_id))
    await db.commit()
    return {"message": "账户已停用，关联数据已清理"}


@router.get("/account/{account_id}/info", response_model=AccountOut, tags=["Account"])
async def get_account_info(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    _uid: str = Depends(get_current_user_id),
):
    """获取账户信息。"""
    acct = (await db.execute(select(Account).where(Account.id == account_id))).scalar_one_or_none()
    if not acct:
        raise HTTPException(status_code=404, detail="账户不存在")
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
    """修改账户 slug。"""
    try:
        acct = await update_account_slug(account_id, body.slug, uid, db)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    if not acct:
        raise HTTPException(status_code=404, detail="账户不存在")
    return AccountOut(
        id=acct.id,
        name=acct.name,
        slug=acct.slug,
        api_key=acct.api_key,
        is_active=acct.is_active,
        created_at=acct.created_at.isoformat() if hasattr(acct.created_at, "isoformat") else str(acct.created_at),
    )


# ---- 3. 成员访问控制管理 (Tenant Access Control) ----

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
    """列出账户下的具权用户。"""
    rows = (await db.execute(select(AccountMember).where(AccountMember.account_id == account_id))).scalars().all()
    return [_member_out(m) for m in rows]


@router.post("/account/{account_id}/access/{user_id}/rename", tags=["Access"], dependencies=[Depends(setup_tenant_context)])
async def rename_access(account_id: str, user_id: str):
    """重命名具权用户。"""
    return {"message": "暂未实现"}


@router.get("/account/{account_id}/access/search", response_model=list[AccessMemberOut], tags=["Access"], dependencies=[Depends(setup_tenant_context)])
async def search_access(
    account_id: str,
    q: str = "",
    db: AsyncSession = Depends(get_db),
):
    """按 user_id 搜索账户成员。"""
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
    """获取具权用户信息。"""
    m = (
        await db.execute(
            select(AccountMember).where(
                AccountMember.account_id == account_id,
                AccountMember.user_id == user_id,
            )
        )
    ).scalar_one_or_none()
    if not m:
        raise HTTPException(status_code=404, detail="成员不存在")
    return _member_out(m)


@router.delete("/account/{account_id}/access/{user_id}", status_code=204, tags=["Access"], dependencies=[Depends(setup_tenant_context)])
async def delete_access(
    account_id: str,
    user_id: str,
    db: AsyncSession = Depends(get_db),
):
    """移除账户成员。"""
    m = (
        await db.execute(
            select(AccountMember).where(
                AccountMember.id == user_id,
                AccountMember.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not m:
        raise HTTPException(status_code=404, detail="成员记录不存在")
    await db.delete(m)
    await db.commit()


@router.post("/account/{account_id}/access/{user_id}", response_model=AccessMemberOut, tags=["Access"], dependencies=[Depends(setup_tenant_context)])
async def update_access(
    account_id: str,
    user_id: str,
    body: AccessRoleUpdate,
    db: AsyncSession = Depends(get_db),
):
    """修改成员的账户内角色。"""
    m = (
        await db.execute(
            select(AccountMember).where(
                AccountMember.id == user_id,
                AccountMember.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not m:
        raise HTTPException(status_code=404, detail="成员记录不存在")
    m.role_in_account = body.role_in_account
    await db.commit()
    await db.refresh(m)
    return _member_out(m)


# ---- 4. 邀请管理 (Tenant Invitation Management) ----

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
    """列出账户下的邀请。"""
    rows = (await db.execute(select(Invitation).where(Invitation.account_id == account_id))).scalars().all()
    return [_inv_out(inv) for inv in rows]


@router.get("/account/{account_id}/invitation/search", response_model=list[InvitationOut], tags=["Invite"], dependencies=[Depends(setup_tenant_context)])
async def search_invitations(
    account_id: str,
    q: str = "",
    db: AsyncSession = Depends(get_db),
):
    """搜索邀请。"""
    rows = (await db.execute(select(Invitation).where(Invitation.account_id == account_id))).scalars().all()
    if not q:
        return [_inv_out(inv) for inv in rows]
    return [_inv_out(inv) for inv in rows if q.lower() in (inv.code or "").lower()]


@router.post("/account/{account_id}/invitation/{invitation_id}/rename", tags=["Invite"], dependencies=[Depends(setup_tenant_context)])
async def rename_invitation(account_id: str, invitation_id: str):
    """重命名邀请码。"""
    return {"message": "暂未实现"}


@router.get("/account/{account_id}/invitation/{invitation_id}", response_model=InvitationOut, tags=["Invite"], dependencies=[Depends(setup_tenant_context)])
async def get_invitation(
    account_id: str,
    invitation_id: str,
    db: AsyncSession = Depends(get_db),
):
    """获取邀请信息。"""
    inv = (
        await db.execute(
            select(Invitation).where(
                Invitation.id == invitation_id,
                Invitation.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="邀请不存在")
    return _inv_out(inv)


@router.post("/account/{account_id}/invitation/create", response_model=InvitationOut, status_code=201, tags=["Invite"], dependencies=[Depends(setup_tenant_context)])
async def create_invitation(
    account_id: str,
    body: InvitationCreate,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """创建新邀请码。"""
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
    """撤销指定邀请码。"""
    inv = (
        await db.execute(
            select(Invitation).where(
                Invitation.id == invitation_id,
                Invitation.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="邀请不存在")
    inv.is_active = False
    await db.commit()
    return {"message": f"邀请 {invitation_id} 已撤销"}


# ---- 5. 设备配对码管理 (Client Pairing Code Management) ----

@router.get("/account/{account_id}/pairing/list", response_model=list[PairingCodeOut], tags=["Pairing"], dependencies=[Depends(setup_tenant_context)])
async def list_pairing_codes(
    db: AsyncSession = Depends(get_db),
):
    """列出当前账户的配对码。"""
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
    """搜索配对码。"""
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
    """启用配对码功能。"""
    return {"message": "暂未实现"}


@router.post("/account/{account_id}/pairing/disable", tags=["Pairing"], dependencies=[Depends(setup_tenant_context)])
async def disable_pairing():
    """禁用配对码功能。"""
    return {"message": "暂未实现"}


@router.post("/account/{account_id}/pairing/{pairing_id}/reject", tags=["Pairing"], dependencies=[Depends(setup_tenant_context)])
async def reject_pairing(
    pairing_id: str,
    db: AsyncSession = Depends(get_db),
):
    """拒绝（撤销）配对码。"""
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
        raise HTTPException(status_code=404, detail="配对码不存在")
    await db.delete(row)
    await db.commit()
    return {"message": f"配对码 {pairing_id} 已拒绝"}


@router.post("/account/{account_id}/pairing/{pairing_id}/approve", tags=["Pairing"], dependencies=[Depends(setup_tenant_context)])
async def approve_pairing_code(
    pairing_id: str,
    db: AsyncSession = Depends(get_db),
):
    """批准配对码。"""
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
        raise HTTPException(status_code=404, detail="配对码不存在")
    row.approved = True
    await db.commit()
    return {"message": f"配对码 {pairing_id} 已批准"}


# ---- 6. 预注册物理客户端管理 (Pre-Registered Client Management) ----

def _prereg_out(p: PreRegisteredClient) -> PreRegOut:
    return PreRegOut(
        id=p.id,
        account_id=p.account_id,
        label=p.label,
        class_identity=p.class_identity,
        created_at=str(p.created_at),
    )


@router.post("/account/{account_id}/pre-registration/create", response_model=PreRegOut, status_code=201, tags=["PreReg"], dependencies=[Depends(setup_tenant_context)])
async def create_pre_reg(
    account_id: str,
    body: PreRegCreate,
    db: AsyncSession = Depends(get_db),
):
    """创建预注册客户端设备标识，校验 class_identity 唯一性。"""
    dup = await db.execute(
        select(PreRegisteredClient).where(
            PreRegisteredClient.account_id == account_id,
            PreRegisteredClient.class_identity == body.class_identity,
        )
    )
    if dup.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="该 class_identity 已存在")
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
    """列出当前账户所有的预注册客户端记录。"""
    rows = (await db.execute(select(PreRegisteredClient).where(PreRegisteredClient.account_id == account_id))).scalars().all()
    return [_prereg_out(r) for r in rows]


@router.get("/account/{account_id}/pre-registration/search", response_model=list[PreRegOut], tags=["PreReg"], dependencies=[Depends(setup_tenant_context)])
async def search_pre_regs(
    account_id: str,
    q: str = "",
    db: AsyncSession = Depends(get_db),
):
    """按标识模糊搜索预注册客户端设备。"""
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
    """查询指定预注册设备的具体详情信息。"""
    row = (
        await db.execute(
            select(PreRegisteredClient).where(
                PreRegisteredClient.id == pre_reg_id,
                PreRegisteredClient.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="预注册客户端不存在")
    return _prereg_out(row)


@router.delete("/account/{account_id}/pre-registration/{pre_reg_id}", status_code=204, tags=["PreReg"], dependencies=[Depends(setup_tenant_context)])
async def delete_pre_reg(
    account_id: str,
    pre_reg_id: str,
    db: AsyncSession = Depends(get_db),
):
    """删除指定的客户端预注册记录。"""
    row = (
        await db.execute(
            select(PreRegisteredClient).where(
                PreRegisteredClient.id == pre_reg_id,
                PreRegisteredClient.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="预注册客户端不存在")
    await db.delete(row)
    await db.commit()


@router.post("/account/{account_id}/pre-registration/{pre_reg_id}/rename", tags=["PreReg"], dependencies=[Depends(setup_tenant_context)])
async def rename_pre_reg(account_id: str, pre_reg_id: str):
    """重命名预注册设备。"""
    return {"message": "暂未实现"}


@router.post("/account/{account_id}/pre-registration/{pre_reg_id}/enable", tags=["PreReg"], dependencies=[Depends(setup_tenant_context)])
async def enable_pre_reg(account_id: str, pre_reg_id: str):
    """启用预注册设备。"""
    return {"message": "暂未实现"}


@router.post("/account/{account_id}/pre-registration/{pre_reg_id}/disable", tags=["PreReg"], dependencies=[Depends(setup_tenant_context)])
async def disable_pre_reg(account_id: str, pre_reg_id: str):
    """禁用预注册设备。"""
    return {"message": "暂未实现"}


@router.post("/account/{account_id}/pre-registration/{pre_reg_id}/config", tags=["PreReg"], dependencies=[Depends(setup_tenant_context)])
async def config_pre_reg(account_id: str, pre_reg_id: str):
    """修改预注册客户端的档案组配置。"""
    return {"message": "暂未实现"}


@router.get("/account/{account_id}/pre-registration/{pre_reg_id}/ManagementPreset.json", tags=["PreReg"], dependencies=[Depends(setup_tenant_context)])
async def download_preset(
    account_id: str,
    pre_reg_id: str,
    db: AsyncSession = Depends(get_db),
):
    """下载特定预注册客户端设备的开箱引导管理配置 JSON 档案。"""
    acct = (await db.execute(select(Account).where(Account.id == account_id))).scalar_one_or_none()
    if not acct or not acct.is_active:
        raise HTTPException(status_code=404, detail="账户不存在或已停用")
    pre_reg = (
        await db.execute(
            select(PreRegisteredClient).where(
                PreRegisteredClient.id == pre_reg_id,
                PreRegisteredClient.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not pre_reg:
        raise HTTPException(status_code=404, detail="预注册客户端不存在")
    return {
        "IsManagementEnabled": True,
        "ManagementServerKind": 1,
        "ManagementServer": f"https://{acct.slug}.{BASE_DOMAIN}",
        "ManagementServerGrpc": f"https://{acct.slug}.{BASE_DOMAIN}",
        "ClassIdentity": pre_reg.class_identity,
        "ManifestUrlTemplate": "",
    }


# ---- 7. 物理客户端与指令监控管理 (Client Machine & Commands) ----

@router.get("/account/{account_id}/client/list", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def list_clients(
    db: AsyncSession = Depends(get_db),
):
    """获取当前租户下所有已注册物理客户端设备的 UID 标识列表。"""
    return (await db.execute(select(ClientRecord.uid))).scalars().all()


@router.get("/account/{account_id}/client/search", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def search_clients(
    q: str = "",
    db: AsyncSession = Depends(get_db),
):
    """按 UID 标识模糊搜索物理客户端列表。"""
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
    """查询特定客户端硬件的连接注册详情与长连接在线状态。"""
    record = (await db.execute(select(ClientRecord).where(ClientRecord.uid == client_id))).scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="未找到设备")
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
    """注销并强制踢出物理客户端设备记录。"""
    record = (await db.execute(select(ClientRecord).where(ClientRecord.uid == client_id))).scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="未找到设备")
    await db.delete(record)
    await db.commit()
    return {"message": "已删除"}


@router.post("/account/{account_id}/client/{client_id}/rename", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def rename_client(client_id: str):
    """重命名指定的物理客户端机器。"""
    return {"message": "暂未实现", "client_id": client_id}


@router.get("/account/{account_id}/client/{client_id}/status", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def get_client_status(
    account_id: str,
    client_id: str,
    request: Request,
):
    """快速查询指定客户端的心跳在线活跃状态。"""
    sm = getattr(request.app.state, "session_manager", None)
    online = await sm.is_client_online(account_id, client_id) if sm else False
    return {"client_id": client_id, "online": online}


@router.post("/account/{account_id}/client/{client_id}/disconnect", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def disconnect_client(client_id: str):
    """断开物理客户端。"""
    return {"message": "暂未实现", "client_id": client_id}


@router.post("/account/{account_id}/client/{client_id}/disable", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def disable_client(client_id: str):
    """禁用指定物理客户端设备。"""
    return {"message": "暂未实现", "client_id": client_id}


@router.post("/account/{account_id}/client/{client_id}/enable", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def enable_client(client_id: str):
    """启用指定物理客户端设备。"""
    return {"message": "暂未实现", "client_id": client_id}


@router.post("/account/{account_id}/client/{client_id}/config", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def set_client_config(client_id: str):
    """修改物理客户端机器使用的资源配置组。"""
    return {"message": "暂未实现", "client_id": client_id}


# ---- 8. 远程实时控制命令推送 (Remote Control Instructions Push) ----

async def _push_cmd(request: Request, account_id: str, uid: str, cmd_type: int) -> StatusResponse:
    """下发简单的无负载 gRPC 指令辅助块。"""
    servicer = getattr(request.app.state, "command_servicer", None)
    if not servicer:
        return StatusResponse(status="error", message="gRPC 服务不可用")

    from app.grpc.api.Protobuf.Server import ClientCommandDeliverScRsp_pb2
    from app.grpc.api.Protobuf.Enum import Retcode_pb2

    cmd = ClientCommandDeliverScRsp_pb2.ClientCommandDeliverScRsp(
        RetCode=Retcode_pb2.Success, Type=cmd_type
    )
    await servicer.send_command(account_id, uid, cmd)
    return StatusResponse(status="success", message="指令已下发")


@router.get("/account/{account_id}/client/{client_id}/command/get-config", tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def fetch_runtime_config(
    account_id: str,
    client_id: str,
    config_type: int,
    request: Request,
):
    """主动请求终端向服务端同步汇报其当前运行状态的完整快照配置。"""
    servicer = getattr(request.app.state, "command_servicer", None)
    if not servicer:
        return {"status": "error", "message": "通讯通道关闭"}

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
        "message": f"请求已下发，ID: {req_id}",
        "request_guid": req_id,
    }


@router.post("/account/{account_id}/client/{client_id}/command/restart", response_model=StatusResponse, tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def restart_app(
    account_id: str,
    client_id: str,
    request: Request,
):
    """控制指令：要求指定物理客户端机重新启动 ClassIsland 主渲染应用。"""
    from app.grpc.api.Protobuf.Enum import CommandTypes_pb2
    return await _push_cmd(request, account_id, client_id, CommandTypes_pb2.RestartApp)


@router.post("/account/{account_id}/client/{client_id}/command/update-data", response_model=StatusResponse, tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def force_sync(
    account_id: str,
    client_id: str,
    request: Request,
):
    """控制指令：强制指定物理机器立刻拉取并覆盖最新的资源配置包。"""
    from app.grpc.api.Protobuf.Enum import CommandTypes_pb2
    return await _push_cmd(request, account_id, client_id, CommandTypes_pb2.DataUpdated)


@router.post("/account/{account_id}/client/{client_id}/command/send-notification", response_model=StatusResponse, tags=["Client"], dependencies=[Depends(setup_tenant_context)])
async def push_notify(
    account_id: str,
    client_id: str,
    request: Request,
    payload: NotificationPayload = Body(...),
):
    """控制指令：向指定的物理终端下发并置顶桌面浮窗通知。"""
    servicer = getattr(request.app.state, "command_servicer", None)
    if not servicer:
        return StatusResponse(status="error", message="gRPC 通道未开启")

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
    return StatusResponse(status="success", message="通知已递送")


# ---- 9. 资源包数据管理 CRUD (Tenant Config Resources DDL) ----

# 安全限制常量
MAX_PAYLOAD_BYTES = 512 * 1024  # 512 KB
MAX_NESTING_DEPTH = 10


def _check_depth(obj, current: int = 0) -> int:
    """递归检查嵌套深度，超限时抛出异常。"""
    if current > MAX_NESTING_DEPTH:
        raise HTTPException(status_code=400, detail="嵌套载荷深度超限")
    if isinstance(obj, dict):
        for v in obj.values():
            _check_depth(v, current + 1)
    elif isinstance(obj, list):
        for item in obj:
            _check_depth(item, current + 1)
    return current


def validate_payload(payload: dict) -> None:
    """校验 payload 大小和嵌套深度。"""
    raw = json.dumps(payload, ensure_ascii=False)
    if len(raw.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise HTTPException(status_code=400, detail="载荷体积超过 512KB 限制")
    _check_depth(payload)


def check_version(record, client_version: Optional[int]) -> None:
    """乐观锁校验版本。"""
    if client_version is None:
        return
    if record.version != client_version:
        raise HTTPException(
            status_code=409,
            detail=f"版本冲突：服务端={record.version}, 客户端={client_version}",
        )


@router.get("/account/{account_id}/{resource_type}/create", response_model=StatusResponse, tags=["Resource"], dependencies=[Depends(setup_tenant_context)])
async def create_data(
    resource_type: str,
    name: str,
    db: AsyncSession = Depends(get_db),
):
    """新建一个空的租户隔离配置文件。"""
    model = MODEL_MAP.get(resource_type)
    if not model:
        return StatusResponse(status="error", message="无效资源类型")
    existing = await db.execute(select(model).where(model.name == name))
    if existing.scalar_one_or_none():
        return StatusResponse(status="error", message=f"{name} 已存在")
    db.add(
        model(name=name, content="{}", version=0, updated_at=datetime.now(timezone.utc))
    )
    await db.commit()
    return StatusResponse(status="success", message=f"已创建 {name}")


@router.get("/account/{account_id}/{resource_type}/list", tags=["Resource"], dependencies=[Depends(setup_tenant_context)])
async def list_data(
    resource_type: str,
    db: AsyncSession = Depends(get_db),
):
    """获取指定资源分类下所有的配置文件。"""
    model = MODEL_MAP.get(resource_type)
    if not model:
        raise HTTPException(status_code=400, detail="无效资源类型")
    result = await db.execute(select(model.name))
    return result.scalars().all()


@router.get("/account/{account_id}/{resource_type}/delete", response_model=StatusResponse, tags=["Resource"], dependencies=[Depends(setup_tenant_context)])
@router.delete("/account/{account_id}/{resource_type}/delete", response_model=StatusResponse, tags=["Resource"], dependencies=[Depends(setup_tenant_context)])
async def delete_data(
    resource_type: str,
    name: str,
    db: AsyncSession = Depends(get_db),
):
    """物理删除指定的租户隔离配置文件。"""
    model = MODEL_MAP.get(resource_type)
    if not model:
        return StatusResponse(status="error", message="无效资源类型")
    existing = await db.execute(select(model).where(model.name == name))
    if not existing.scalar_one_or_none():
        return StatusResponse(status="error", message=f"未找到 {name}")
    await db.execute(delete(model).where(model.name == name))
    await db.commit()
    return StatusResponse(status="success", message=f"已删除 {name}")


@router.patch("/account/{account_id}/{resource_type}/update", response_model=StatusResponse, tags=["Resource"], dependencies=[Depends(setup_tenant_context)])
async def patch_data(
    account_id: str,
    resource_type: str,
    name: str,
    payload: dict = Body(...),
    version: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
):
    """递归合并增量更新指定的配置文件（含并发乐观锁）。"""
    validate_payload(payload)
    model = MODEL_MAP.get(resource_type)
    if not model:
        return StatusResponse(status="error", message="无效模型")
    record = (await db.execute(select(model).where(model.name == name))).scalar_one_or_none()
    if not record:
        return StatusResponse(status="error", message="文件未找到")
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
    return StatusResponse(status="success", message="合并成功")


@router.get("/account/{account_id}/{resource_type}/token", tags=["Resource"], dependencies=[Depends(setup_tenant_context)])
async def get_resource_token(
    account_id: str,
    resource_type: str,
    name: str,
    db: AsyncSession = Depends(get_db),
):
    """校验配置文件存在性并生成一个防盗链的短期下载授权 Token。"""
    model = MODEL_MAP.get(resource_type)
    if not model:
        return {"status": "error", "message": "无效类型"}

    record = (await db.execute(select(model).where(model.name == name))).scalar_one_or_none()
    if not record:
        return {"status": "error", "message": f"{name} 不存在"}

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
    """覆盖式数据替换写入配置文件（覆盖原 JSON，包含版本冲突校验）。"""
    validate_payload(payload)
    model = MODEL_MAP.get(resource_type)
    if not model:
        return StatusResponse(status="error", message="无效类型")

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
    return StatusResponse(status="success", message=f"{name} 已写入")
