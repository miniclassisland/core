import asyncio
import os
import re
import signal
import threading
from fastapi import APIRouter, Body, Depends, Form, HTTPException, Request, status
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.db.models import (
    Account,
    User,
    ClientRecord,
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
from app.shared.security import auth as auth_sec
from app.shared.security.auth import (
    require_role,
    verify_oobe_passcode,
    verify_oobe_token,
    get_oobe_token,
    clear_oobe_codes,
)
from app.shared.services.user import (
    list_pending_users,
    reject_user,
    approve_user,
    create_account,
    update_account_info,
    cleanup_account_data,
)
from app.shared.services.quota import get_quotas, set_quota, get_bandwidth_mb
from app.shared.runtime import get_command_servicer, get_session_manager
from app.shared.utils.oobe import write_config_file, init_database

router = APIRouter()
_sa = require_role(100)
_oobe_lock = asyncio.Lock()


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
        registration_mode=getattr(a, "registration_mode", "pairing") or "pairing",
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

    cs = get_command_servicer(request)
    sm = get_session_manager(request)
    online_clients = 0
    if cs and getattr(cs, "client_queues", None):
        online_clients = len(cs.client_queues)
    elif sm:
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
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        stmt = stmt.where(
            or_(
                Account.name.ilike(pattern, escape="\\"),
                Account.slug.ilike(pattern, escape="\\"),
            )
        )
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
    admin_user: User = Depends(_sa),
):
    """Update account properties (new_id, name, slug, is_active, registration_mode)."""
    uid = getattr(admin_user, "id", "")
    if not uid:
        u = (
            (await db.execute(select(User).where(User.role_code == "superadmin")))
            .scalars()
            .first()
        )
        uid = u.id if u else ""
    try:
        acct = await update_account_info(
            account_id,
            uid,
            db,
            new_id=body.new_id,
            name=body.name,
            slug=body.slug,
            is_active=body.is_active,
            registration_mode=body.registration_mode,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    if not acct:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Account not found"
        )
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
    await cleanup_account_data(account_id, acct.slug, db)
    await db.delete(acct)
    await db.commit()
    return {"status": "deleted"}


@router.get(
    "/account/{account_id}/quota", response_model=list[QuotaOut], tags=["Account"]
)
async def admin_get_account_quotas(
    account_id: str,
    request: Request,
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
    cs = get_command_servicer(request)
    sm = get_session_manager(request)
    if cs and getattr(cs, "tenant_clients", None) and account_id in cs.tenant_clients:
        grpc_conn_count = len(cs.tenant_clients[account_id])
    else:
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
async def verify_passcode(request: Request, passcode: str = Form(...)):
    """Verify pairing passcode and issue elevated execution token (rate-limited per source IP)."""
    from app.shared.utils.logging import get_client_ip_from_request

    client_ip = get_client_ip_from_request(request) or "unknown"
    if auth_sec.is_oobe_locked_out(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed OOBE attempts, please wait 60 seconds",
        )
    if not verify_oobe_passcode(passcode, client_ip=client_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid passcode or expired"
        )
    return {"token": get_oobe_token()}


def _validate_oobe_inputs(
    db_url: str,
    redis_url: str,
    username: str,
    email: str,
    password: str,
) -> dict[str, str]:
    """Validate OOBE form parameters against security & format requirements."""
    db_u = db_url.strip()
    if not db_u.startswith(("postgresql", "postgres")):
        raise ValueError("Database URL must start with postgresql")
    rd_u = redis_url.strip()
    if not rd_u.startswith(("redis://", "rediss://", "unix://")):
        raise ValueError(
            "Redis URL must start with redis://, rediss://, or unix://"
        )
    uname = username.strip().lower()
    if not re.match(r"^[a-z0-9_]{3,64}$", uname):
        raise ValueError(
            "Username must be 3-64 lowercase alphanumeric characters and underscores"
        )
    em = email.strip()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", em):
        raise ValueError("Invalid email format")
    if (
        len(password) < 12
        or not re.search(r"[A-Z]", password)
        or not re.search(r"[a-z]", password)
        or not re.search(r"[0-9]", password)
    ):
        raise ValueError(
            "Password must be at least 12 characters and contain uppercase, lowercase, and digits"
        )
    return {
        "db_url": db_u,
        "redis_url": rd_u,
        "username": uname,
        "email": em,
        "password": password,
    }


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
    async with _oobe_lock:
        if not verify_oobe_token(token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid token or expired",
            )

        try:
            validated = _validate_oobe_inputs(
                db_url, redis_url, username, email, password
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            )

        config = {
            **validated,
            "domain": domain.strip(),
        }

        saved_token = auth_sec.OOBE_TOKEN
        auth_sec.OOBE_TOKEN = ""
        try:
            await init_database(config)
            write_config_file(config)
            clear_oobe_codes()
        except Exception as e:
            auth_sec.OOBE_TOKEN = saved_token
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Initialization failed: {str(e)}",
            )

    # Trigger graceful daemon exit in 1 second so systemd / supervisor restarts into initialized mode
    threading.Timer(
        1.0,
        lambda: os.kill(os.getpid(), signal.SIGTERM),
    ).start()
    return {"status": "ok", "message": "Initialization complete, system restarting"}
