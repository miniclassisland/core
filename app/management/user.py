from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db, AsyncSessionLocal
from app.shared.db.models import User, SystemConfig
from app.shared.schemas.schemas import (
    UserOut,
    UserLoginRequest,
    UserRegisterRequest,
    EmailAvailabilityRequest,
    EmailUpdate,
    UsernameUpdate,
    DisplayNameUpdate,
    PasswordChange,
    PasswordReset,
    MessageResponse,
    TotpEnableResponse,
    TotpConfirmRequest,
    TotpDisableRequest,
    TotpVerifyRequest,
    TotpRecoverRequest,
)
from app.shared.security.auth import (
    get_current_user_id,
    create_session_token,
    create_2fa_temp_token,
    pop_2fa_temp_token,
    revoke_all_user_sessions,
)
from app.shared.security.crypto import (
    hash_password_async,
    verify_password_async,
    generate_totp_secret,
    get_totp_uri,
    verify_totp_once,
    generate_recovery_codes,
    store_recovery_codes,
    delete_recovery_codes,
    check_recovery_code,
    use_recovery_code,
    get_remaining_recovery_count,
)
from app.shared.services.user import (
    register_user,
    validate_username_format,
    is_name_reserved,
    login_user,
)
from app.shared.security.middlewares import record_ip_failure
from app.shared.security.turnstile import require_turnstile_verification
from app.shared.utils.logging import get_client_ip_from_request

router = APIRouter(prefix="/user")


# ---- 1. User Self-Registration & Availability Verification ----


@router.post("/apply", response_model=MessageResponse, tags=["User"])
async def apply_user(
    request: Request,
    payload: UserRegisterRequest = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """User submits registration application (respects registration_open, require_approval, default_role)."""
    client_ip = (
        get_client_ip_from_request(request) if hasattr(request, "headers") else ""
    )
    await require_turnstile_verification(
        payload.cf_turnstile_response, remote_ip=client_ip, db=db
    )
    cfg_rows = (
        (
            await db.execute(
                select(SystemConfig).where(
                    SystemConfig.key.in_(
                        ("registration_open", "require_approval", "default_role")
                    )
                )
            )
        )
        .scalars()
        .all()
    )
    cfg_map = {r.key: r.value for r in cfg_rows}

    if cfg_map.get("registration_open", "true").lower() == "false":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public user registration is currently disabled",
        )

    require_approval = cfg_map.get("require_approval", "true").lower() != "false"
    raw_default_role = cfg_map.get("default_role", "normal").strip()
    safe_default_role = (
        raw_default_role
        if raw_default_role not in ("superadmin", "admin", "banned", "pending", "")
        else "normal"
    )

    try:
        if require_approval:
            await register_user(
                payload.email,
                payload.password,
                payload.display_name,
                db,
                username=payload.username,
                role_code="pending",
                is_active=False,
            )
        else:
            await register_user(
                payload.email,
                payload.password,
                payload.display_name,
                db,
                username=payload.username,
                role_code=safe_default_role,
                is_active=True,
                can_create_account=False,
                create_default_account=True,
            )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return MessageResponse(
        message=(
            "Registration successful, awaiting administrator approval"
            if require_approval
            else "Registration successful"
        )
    )


@router.post("/availability/mail", tags=["Availability"])
async def check_mail_availability(
    request: Request,
    payload: EmailAvailabilityRequest = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """Real-time email availability check with Turnstile verification."""
    client_ip = (
        get_client_ip_from_request(request) if hasattr(request, "headers") else ""
    )
    await require_turnstile_verification(
        payload.cf_turnstile_response, remote_ip=client_ip, db=db
    )
    result = await db.execute(select(User.id).where(User.email == payload.email))
    exists = result.scalar_one_or_none() is not None
    return {"available": not exists}


@router.get("/availability/username", tags=["Availability"])
async def check_username_availability(
    value: str = Query(
        ..., min_length=3, max_length=64, description="Username to check"
    ),
    db: AsyncSession = Depends(get_db),
):
    """Check username availability (format, reserved list, and uniqueness)."""
    if not validate_username_format(value):
        return {"available": False, "reason": "Username format invalid"}
    if await is_name_reserved(value, db):
        return {"available": False, "reason": "Name is reserved by system"}
    result = await db.execute(select(User.id).where(User.username == value))
    if result.scalar_one_or_none() is not None:
        return {"available": False, "reason": "Username is already taken"}
    return {"available": True}


# ---- 2. Login Authentication ----


@router.post("/auth", tags=["User"])
async def user_login(
    request: Request,
    payload: UserLoginRequest = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """User login to acquire Session token; issues temporary token for 2FA if enabled."""
    client_ip = (
        get_client_ip_from_request(request) if hasattr(request, "headers") else ""
    )
    await require_turnstile_verification(
        payload.cf_turnstile_response, remote_ip=client_ip, db=db
    )
    try:
        token, user, needs_2fa = await login_user(payload.email, payload.password, db)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    if needs_2fa:
        temp = await create_2fa_temp_token(user.id)
        return {"requires_2fa": True, "temp_token": temp}
    return {"token": token}


# ---- 3. User Profile Management ----


@router.get("/info", response_model=UserOut, tags=["User"])
async def get_user_info(
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Get current logged-in user profile."""
    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
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


@router.post("/info/email", tags=["UserInfo"])
async def change_email(
    body: EmailUpdate,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Update current user's email address (restricted to Super Admin only)."""
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    if user.role_code != "superadmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email modification is disabled for standard users; please contact a Super Administrator",
        )
    dup = await db.execute(select(User).where(User.email == body.email, User.id != uid))
    if dup.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already registered",
        )
    user.email = body.email
    await db.commit()
    return {"status": "ok", "message": "Email updated"}


@router.post("/info/username", tags=["UserInfo"])
async def change_username(
    body: UsernameUpdate,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Update current user's username."""
    if not validate_username_format(body.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Username format invalid"
        )
    if await is_name_reserved(body.username, db):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Name is reserved by system"
        )
    dup = await db.execute(
        select(User).where(User.username == body.username, User.id != uid)
    )
    if dup.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Username is already taken"
        )
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    user.username = body.username
    await db.commit()
    return {"status": "ok", "message": "Username updated"}


@router.post("/info/display-name", tags=["UserInfo"])
async def change_display_name(
    body: DisplayNameUpdate,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Update current user's display name."""
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    user.display_name = body.display_name.strip()
    await db.commit()
    return {"status": "ok", "message": "Display name updated"}


@router.post("/info/password/change", tags=["UserInfo"])
async def change_password(
    body: PasswordChange,
    request: Request,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Change user password with old password verification."""
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    if not await verify_password_async(body.old_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect old password"
        )
    user.hashed_password = await hash_password_async(body.new_password)
    await db.commit()
    auth_hdr = request.headers.get("authorization", "")
    cur_tok = auth_hdr[7:] if auth_hdr.startswith("Bearer ") else None
    await revoke_all_user_sessions(uid, except_token=cur_tok)
    return {"status": "ok", "message": "Password updated"}


@router.post("/info/password/reset", tags=["UserInfo"])
async def reset_password(
    request: Request,
    body: PasswordReset = Body(default=None),
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Reset user password (requires Super Admin privilege; regular users must use /password/change)."""
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    if user.role_code != "superadmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Direct password reset without old password is restricted to Super Admin",
        )
    if body and body.new_password:
        user.hashed_password = await hash_password_async(body.new_password)
        await db.commit()
        auth_hdr = request.headers.get("authorization", "")
        cur_tok = auth_hdr[7:] if auth_hdr.startswith("Bearer ") else None
        await revoke_all_user_sessions(uid, except_token=cur_tok)
    return {"status": "ok", "message": "Password reset"}


# ---- 4. User 2FA TOTP Settings ----


@router.post("/2fa/totp/enable", response_model=TotpEnableResponse, tags=["2FA"])
async def enable_2fa(
    reset: bool = Query(
        False,
        description="Allow regenerating secret and recovery codes when 2FA is already enabled",
    ),
    uid: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Generate TOTP secret key and recovery codes for current user."""
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one()
    if user.totp_enabled and not reset:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is already enabled"
        )
    secret = generate_totp_secret()
    user.totp_secret = secret
    await db.commit()
    codes = generate_recovery_codes()
    await store_recovery_codes(uid, codes)
    return TotpEnableResponse(
        secret=secret,
        uri=get_totp_uri(secret, user.email),
        recovery_codes=codes,
    )


@router.post("/2fa/totp/confirm", tags=["2FA"])
async def confirm_2fa(
    body: TotpConfirmRequest,
    request: Request = None,  # type: ignore[assignment]
    uid: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Confirm and activate 2FA with one-time verification code."""
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one()
    if not user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Please call /enable first"
        )
    if not await verify_totp_once(uid, user.totp_secret or "", body.code):
        if isinstance(request, Request):
            record_ip_failure(get_client_ip_from_request(request) or "unknown")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP code"
        )
    user.totp_enabled = True
    await db.commit()
    return {"status": "2fa_enabled"}


@router.post("/2fa/totp/disable", tags=["2FA"])
async def disable_2fa(
    body: TotpDisableRequest,
    uid: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Disable TOTP 2FA for current user.

    Requires any of the following dual-factor combinations:
    - Password + TOTP code
    - Password + 1 recovery code
    - TOTP code + 1 recovery code
    - At least 2 distinct valid recovery codes
    """
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one()

    raw_codes: list[str] = []
    if body.recovery_code and body.recovery_code.strip():
        raw_codes.append(body.recovery_code.strip().upper())
    if body.second_recovery_code and body.second_recovery_code.strip():
        raw_codes.append(body.second_recovery_code.strip().upper())
    if body.recovery_codes:
        for rc in body.recovery_codes:
            if rc and rc.strip():
                raw_codes.append(rc.strip().upper())

    # Deduplicate recovery codes while preserving order
    unique_recovery_codes: list[str] = list(dict.fromkeys(raw_codes))

    has_pwd = bool(body.password and body.password.strip())
    has_totp = bool(body.totp_code and body.totp_code.strip())
    num_rec = len(unique_recovery_codes)

    valid_combination = (
        (has_pwd and has_totp)
        or (has_pwd and num_rec >= 1)
        or (has_totp and num_rec >= 1)
        or (num_rec >= 2)
    )
    if not valid_combination:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Disabling 2FA requires at least two recovery codes, "
                "or one recovery code + one TOTP code, "
                "or password + TOTP code, "
                "or password + one recovery code"
            ),
        )

    if has_pwd:
        if not await verify_password_async(body.password or "", user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect password"
            )

    if num_rec > 0:
        for rc in unique_recovery_codes:
            if not await check_recovery_code(uid, rc):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or used recovery code",
                )

    if has_totp:
        if not await verify_totp_once(
            uid, user.totp_secret or "", body.totp_code or ""
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code"
            )

    user.totp_enabled = False
    user.totp_secret = None
    await db.commit()
    await delete_recovery_codes(uid)
    return {"status": "2fa_disabled"}


@router.post("/2fa/totp/verify", tags=["2FA"])
async def verify_2fa_login(body: TotpVerifyRequest):
    """Complete 2FA login with one-time TOTP code using temp token."""
    uid = await pop_2fa_temp_token(body.temp_token)
    async with AsyncSessionLocal() as db:
        user = (await db.execute(select(User).where(User.id == uid))).scalar_one()
    if not await verify_totp_once(uid, user.totp_secret or "", body.code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code"
        )
    token = await create_session_token(uid)
    return {"token": token, "user_id": uid}


@router.post("/2fa/totp/recover", tags=["2FA"])
async def recover_2fa(body: TotpRecoverRequest):
    """Complete emergency login using 2FA recovery code."""
    uid = await pop_2fa_temp_token(body.temp_token)
    ok = await use_recovery_code(uid, body.recovery_code)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or used recovery code",
        )
    remaining = await get_remaining_recovery_count(uid)
    token = await create_session_token(uid)
    return {
        "token": token,
        "user_id": uid,
        "remaining_recovery_codes": remaining,
        "require_totp_reset": remaining <= 1,
    }
