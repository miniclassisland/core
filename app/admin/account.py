import os
import sys
import threading
from fastapi import APIRouter, Body, Depends, Form, HTTPException, Request, status
from sqlalchemy import select, func, delete, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.db.models import (
    Account,
    AccountMember,
    AccountQuota,
    User,
    ClientRecord,
    PreRegisteredClient,
    AuditLog,
)
from app.shared.schemas.schemas import (
    AccountOut,
    AccountCreate,
    AccountUpdate,
    QuotaOut,
    QuotaSetRequest,
    UserOut,
)
from app.shared.security.auth import (
    require_role,
    verify_oobe_passcode,
    verify_oobe_token,
    get_oobe_token,
)
from app.shared.services.user import (
    list_pending_users,
    reject_user,
    approve_user,
    create_account,
    validate_slug_format,
)
from app.shared.services.quota import get_quotas, set_quota
from app.shared.runtime import get_session_manager
from app.shared.utils.oobe import write_config_file, init_database
from app.shared.utils.tenant import invalidate_cached_account

router = APIRouter()
_sa = require_role(100)


def _to_out(user: User) -> UserOut:
    """Convert User model to response schema."""
    return UserOut(
        id=user.id,
        username=user.username,
        email=user.email,
        display_name=user.display_name,
        role_code=user.role_code,
        is_active=user.is_active,
        totp_enabled=bool(user.totp_enabled),
        can_create_account=user.can_create_account,
        created_at=(
            user.created_at.isoformat()
            if hasattr(user.created_at, "isoformat")
            else str(user.created_at)
        ),
    )


def _acct_out(a: Account) -> AccountOut:
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


# ---- 0. Global Platform Overview Stats ----


@router.get("/stats", tags=["Stats"])
async def get_platform_stats(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Get global platform statistics for Super Admin dashboard."""
    total_accounts = await db.scalar(select(func.count(Account.id))) or 0
    active_accounts = (
        await db.scalar(
            select(func.count(Account.id)).where(Account.is_active.is_(True))
        )
        or 0
    )
    total_users = await db.scalar(select(func.count(User.id))) or 0
    pending_users = (
        await db.scalar(select(func.count(User.id)).where(User.role_code == "pending"))
        or 0
    )
    total_clients = await db.scalar(select(func.count(ClientRecord.uid))) or 0
    total_audit_logs = await db.scalar(select(func.count(AuditLog.id))) or 0

    sm = get_session_manager(request)
    online_clients = 0
    if sm:
        accts = (await db.execute(select(Account.id))).scalars().all()
        seen_uids: set[str] = set()
        for aid in list(accts) + [""]:
            for item in await sm.get_all_clients_status(aid):
                seen_uids.add(item["uid"])
        online_clients = len(seen_uids)

    return {
        "total_accounts": total_accounts,
        "active_accounts": active_accounts,
        "total_users": total_users,
        "pending_users": pending_users,
        "total_clients": total_clients,
        "online_clients": online_clients,
        "total_audit_logs": total_audit_logs,
    }


# ---- 1. Account / Tenant Administration ----


@router.get("/account", response_model=list[AccountOut], tags=["Account"])
@router.get("/account/list", response_model=list[AccountOut], tags=["Account"])
async def list_accounts(
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """List all accounts across system."""
    res = await db.execute(select(Account).order_by(Account.created_at.desc()))
    return [_acct_out(a) for a in res.scalars().all()]


@router.get("/account/search", response_model=list[AccountOut], tags=["Account"])
async def search_accounts(
    q: str = "",
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Search accounts by name or slug."""
    stmt = select(Account).order_by(Account.created_at.desc())
    if q:
        pattern = f"%{q}%"
        stmt = stmt.where(or_(Account.name.ilike(pattern), Account.slug.ilike(pattern)))
    res = await db.execute(stmt)
    return [_acct_out(a) for a in res.scalars().all()]


@router.post(
    "/account/create",
    response_model=AccountOut,
    status_code=status.HTTP_201_CREATED,
    tags=["Account"],
)
async def admin_create_account(
    body: AccountCreate,
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(_sa),
):
    """Create a new tenant account as Super Admin."""
    owner_id = body.owner_user_id or admin_user.id
    try:
        acct = await create_account(body.name, owner_id, db, slug=body.slug)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return _acct_out(acct)


@router.get("/account/{account_id}", response_model=AccountOut, tags=["Account"])
async def get_account_detail(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Get account details by ID."""
    acct = (
        await db.execute(select(Account).where(Account.id == account_id))
    ).scalar_one_or_none()
    if not acct:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Account not found"
        )
    return _acct_out(acct)


@router.post("/account/{account_id}", response_model=AccountOut, tags=["Account"])
async def admin_update_account(
    account_id: str,
    body: AccountUpdate,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Update account properties (name, slug, is_active, registration_mode)."""
    acct = (
        await db.execute(select(Account).where(Account.id == account_id))
    ).scalar_one_or_none()
    if not acct:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Account not found"
        )
    old_slug = acct.slug
    if body.name is not None:
        acct.name = body.name.strip()
    if body.slug is not None and body.slug != acct.slug:
        if not validate_slug_format(body.slug):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Slug format invalid"
            )
        dup = (
            await db.execute(
                select(Account).where(
                    Account.slug == body.slug, Account.id != account_id
                )
            )
        ).scalar_one_or_none()
        if dup:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Slug is already taken"
            )
        acct.slug = body.slug
    if body.is_active is not None:
        acct.is_active = body.is_active
    if body.registration_mode is not None and body.registration_mode in (
        "open",
        "pairing",
        "pre_reg",
    ):
        acct.registration_mode = body.registration_mode
    await db.commit()
    await invalidate_cached_account(old_slug)
    await invalidate_cached_account(acct.slug)
    return _acct_out(acct)


@router.delete("/account/{account_id}", tags=["Account"])
async def admin_delete_account(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Delete an account and its associated records as Super Admin."""
    acct = (
        await db.execute(select(Account).where(Account.id == account_id))
    ).scalar_one_or_none()
    if not acct:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Account not found"
        )
    await invalidate_cached_account(acct.slug)
    await db.execute(
        delete(AccountMember).where(AccountMember.account_id == account_id)
    )
    await db.execute(delete(AccountQuota).where(AccountQuota.account_id == account_id))
    await db.execute(
        delete(PreRegisteredClient).where(PreRegisteredClient.account_id == account_id)
    )
    await db.delete(acct)
    await db.commit()
    return {"status": "deleted"}


@router.get(
    "/account/{account_id}/quota", response_model=list[QuotaOut], tags=["Account"]
)
async def admin_get_account_quotas(
    account_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Get all resource quotas for an account."""
    rows = await get_quotas(account_id, db)
    client_count = (
        await db.scalar(
            select(func.count(ClientRecord.uid)).where(
                ClientRecord.account_id == account_id
            )
        )
        or 0
    )
    out = []
    for r in rows:
        cur = client_count if r.quota_key == "max_clients" else r.current_value
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


@router.post("/account/{account_id}/quota", response_model=QuotaOut, tags=["Account"])
async def admin_set_account_quota(
    account_id: str,
    body: QuotaSetRequest = Body(...),
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Create or update a quota limit for an account."""
    q = await set_quota(account_id, body.quota_key, body.max_value, db)
    return QuotaOut(
        id=q.id,
        account_id=q.account_id,
        quota_key=q.quota_key,
        max_value=q.max_value,
        current_value=q.current_value,
    )


# ---- 2. Pending Approvals ----


@router.get("/user/pending", response_model=list[UserOut], tags=["Pending"])
@router.get("/user/pending/list", response_model=list[UserOut], tags=["Pending"])
async def get_pending(
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """List all pending user registration applications."""
    users = await list_pending_users(db)
    return [_to_out(u) for u in users]


@router.post(
    "/user/pending/approve/{user_id}", response_model=UserOut, tags=["Pending"]
)
@router.post(
    "/user/pending/{user_id}/approve", response_model=UserOut, tags=["Pending"]
)
async def approve_pending(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Approve a pending user registration application."""
    user = await approve_user(user_id, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found or not in pending state",
        )
    return _to_out(user)


@router.post(
    "/user/pending/reject/{user_id}", status_code=status.HTTP_200_OK, tags=["Pending"]
)
@router.post(
    "/user/pending/{user_id}/reject", status_code=status.HTTP_200_OK, tags=["Pending"]
)
async def reject_pending(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Reject a pending user registration application."""
    ok = await reject_user(user_id, db)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found or not in pending state",
        )
    return {"status": "rejected"}


# ---- 3. OOBE First-Time Setup Wizard ----


@router.post("/oobe/verify", tags=["OOBE"])
@router.post("/api/oobe/verify", tags=["OOBE"])
async def verify_passcode(passcode: str = Form(...)):
    """Verify pairing passcode and issue elevated execution token."""
    if not verify_oobe_passcode(passcode):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid passcode or expired"
        )
    return {"token": get_oobe_token()}


@router.post("/oobe/configure", tags=["OOBE"])
@router.post("/api/oobe/configure", tags=["OOBE"])
async def configure_system(
    token: str = Form(...),
    db_url: str = Form(...),
    redis_url: str = Form(...),
    domain: str = Form(...),
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
):
    """Verify token, write configuration, initialize database schema, and trigger restart."""
    if not verify_oobe_token(token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid token or expired"
        )

    config = {
        "db_url": db_url,
        "redis_url": redis_url,
        "domain": domain,
        "username": username,
        "email": email,
        "password": password,
    }

    try:
        write_config_file(config)
        await init_database(config)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Initialization failed: {str(e)}",
        )

    # Trigger system restart in 1 second
    threading.Timer(
        1.0, lambda: os.execv(sys.executable, [sys.executable] + sys.argv)
    ).start()
    return {"status": "ok", "message": "Initialization complete, system restarting"}
