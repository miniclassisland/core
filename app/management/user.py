from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from pydantic import EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db, AsyncSessionLocal
from app.shared.db.models import User
from app.shared.schemas.schemas import (
    UserOut,
    UserLoginRequest,
    UserRegisterRequest,
    EmailUpdate,
    UsernameUpdate,
    PasswordChange,
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
)
from app.shared.security.crypto import (
    hash_password,
    verify_password,
    generate_totp_secret,
    get_totp_uri,
    verify_totp,
    generate_recovery_codes,
    store_recovery_codes,
    use_recovery_code,
)
from app.shared.services.user import (
    register_user,
    validate_username_format,
    is_name_reserved,
    login_user,
)

router = APIRouter(prefix="/user")


# ---- 1. User Self-Registration & Availability Verification ----

@router.post("/apply", response_model=MessageResponse, tags=["User"])
async def apply_user(
    payload: UserRegisterRequest = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """User submits registration application (enters Pending status awaiting approval)."""
    try:
        await register_user(
            payload.email,
            payload.password,
            payload.display_name,
            db,
            username=payload.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return MessageResponse(message="Registration successful, awaiting administrator approval")


@router.get("/availability/mail", tags=["Availability"])
async def check_mail_availability(
    value: EmailStr = Query(..., description="Email address to check"),
    db: AsyncSession = Depends(get_db),
):
    """Real-time email availability check."""
    result = await db.execute(select(User.id).where(User.email == value))
    exists = result.scalar_one_or_none() is not None
    return {"available": not exists}


@router.get("/availability/username", tags=["Availability"])
async def check_username_availability(
    value: str = Query(..., min_length=3, max_length=64, description="Username to check"),
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
    payload: UserLoginRequest = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """User login to acquire Session token; issues temporary token for 2FA if enabled."""
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
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserOut(
        id=user.id,
        username=user.username,
        email=user.email,
        display_name=user.display_name,
        role_code=user.role_code,
        is_active=user.is_active,
        can_create_account=user.can_create_account,
        created_at=str(user.created_at),
    )


@router.post("/info/email", tags=["UserInfo"])
async def change_email(
    body: EmailUpdate,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Update current user's email address."""
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
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
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username format invalid")
    dup = await db.execute(
        select(User).where(User.username == body.username, User.id != uid)
    )
    if dup.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username is already taken")
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user.username = body.username
    await db.commit()
    return {"status": "ok", "message": "Username updated"}


@router.post("/info/password/change", tags=["UserInfo"])
async def change_password(
    body: PasswordChange,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Change user password with old password verification."""
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if not verify_password(body.old_password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect old password")
    user.hashed_password = hash_password(body.new_password)
    await db.commit()
    return {"status": "ok", "message": "Password updated"}


@router.post("/info/password/reset", tags=["UserInfo"])
async def reset_password(
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """Reset user password."""
    return {"status": "ok", "message": "Not implemented yet"}


# ---- 4. User 2FA TOTP Settings ----

@router.post("/2fa/totp/enable", response_model=TotpEnableResponse, tags=["2FA"])
async def enable_2fa(
    uid: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Generate TOTP secret key and recovery codes for current user."""
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one()
    if user.totp_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is already enabled")
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
    uid: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Confirm and activate 2FA with one-time verification code."""
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one()
    if not user.totp_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Please call /enable first")
    if not verify_totp(user.totp_secret, body.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP code")
    user.totp_enabled = True
    await db.commit()
    return {"status": "2fa_enabled"}


@router.post("/2fa/totp/disable", tags=["2FA"])
async def disable_2fa(
    body: TotpDisableRequest,
    uid: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """Disable TOTP 2FA for current user (requires password verification)."""
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one()
    if not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect password")
    user.totp_enabled = False
    user.totp_secret = None
    await db.commit()
    return {"status": "2fa_disabled"}


@router.post("/2fa/totp/verify", tags=["2FA"])
async def verify_2fa_login(body: TotpVerifyRequest):
    """Complete 2FA login with one-time TOTP code using temp token."""
    uid = await pop_2fa_temp_token(body.temp_token)
    async with AsyncSessionLocal() as db:
        user = (await db.execute(select(User).where(User.id == uid))).scalar_one()
    if not verify_totp(user.totp_secret, body.code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code")
    token = await create_session_token(uid)
    return {"token": token, "user_id": uid}


@router.post("/2fa/totp/recover", tags=["2FA"])
async def recover_2fa(body: TotpRecoverRequest):
    """Complete emergency login using 2FA recovery code."""
    uid = await pop_2fa_temp_token(body.temp_token)
    ok = await use_recovery_code(uid, body.recovery_code)
    if not ok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or used recovery code")
    token = await create_session_token(uid)
    return {"token": token, "user_id": uid}
