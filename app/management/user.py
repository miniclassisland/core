from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
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


# ---- 1. 用户自助申请与可用性验证 ----

@router.post("/apply", response_model=MessageResponse, tags=["User"])
async def apply_user(
    payload: UserRegisterRequest = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """用户提交申请注册新账号（进入 Pending 待审核状态）。"""
    try:
        await register_user(
            payload.email,
            payload.password,
            payload.display_name,
            db,
            username=payload.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return MessageResponse(message="注册成功，等待管理员审核")


@router.get("/availability/mail", tags=["Availability"])
async def check_mail_availability(
    value: EmailStr = Query(..., description="待检查的邮箱地址"),
    db: AsyncSession = Depends(get_db),
):
    """供前端实时校验邮箱是否可用（未注册过）。"""
    result = await db.execute(select(User.id).where(User.email == value))
    exists = result.scalar_one_or_none() is not None
    return {"available": not exists}


@router.get("/availability/username", tags=["Availability"])
async def check_username_availability(
    value: str = Query(..., min_length=3, max_length=64, description="待检查的用户名"),
    db: AsyncSession = Depends(get_db),
):
    """前端校验用户名是否可用（格式、黑名单保留名及唯一性校验）。"""
    if not validate_username_format(value):
        return {"available": False, "reason": "用户名格式不合法"}
    if await is_name_reserved(value, db):
        return {"available": False, "reason": "该名称为系统保留名"}
    result = await db.execute(select(User.id).where(User.username == value))
    if result.scalar_one_or_none() is not None:
        return {"available": False, "reason": "该用户名已被占用"}
    return {"available": True}


# ---- 2. 登录认证 ----

@router.post("/auth", tags=["User"])
async def user_login(
    payload: UserLoginRequest = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """用户登录获取 Session 令牌，如启用 2FA 则下发临时令牌进入二次验证阶段。"""
    try:
        token, user, needs_2fa = await login_user(payload.email, payload.password, db)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    if needs_2fa:
        temp = await create_2fa_temp_token(user.id)
        return {"requires_2fa": True, "temp_token": temp}
    return {"token": token}


# ---- 3. 用户个人基础资料管理 ----

@router.get("/info", response_model=UserOut, tags=["User"])
async def get_user_info(
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """查询并获取当前登录用户的基本信息。"""
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
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
    """修改当前已登录用户的绑定邮箱。"""
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    user.email = body.email
    await db.commit()
    return {"message": "邮箱已更新"}


@router.post("/info/username", tags=["UserInfo"])
async def change_username(
    body: UsernameUpdate,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """修改当前已登录用户的绑定用户名。"""
    if not validate_username_format(body.username):
        raise HTTPException(status_code=400, detail="用户名格式不合法")
    # 唯一性校验
    dup = await db.execute(
        select(User).where(User.username == body.username, User.id != uid)
    )
    if dup.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="该用户名已被占用")
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    user.username = body.username
    await db.commit()
    return {"message": "用户名已更新"}


@router.post("/info/password/change", tags=["UserInfo"])
async def change_password(
    body: PasswordChange,
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """当前已登录用户修改个人密码（需旧密码验证）。"""
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    if not verify_password(body.old_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="旧密码错误")
    user.hashed_password = hash_password(body.new_password)
    await db.commit()
    return {"message": "密码已修改"}


@router.post("/info/password/reset", tags=["UserInfo"])
async def reset_password(
    db: AsyncSession = Depends(get_db),
    uid: str = Depends(get_current_user_id),
):
    """当前用户重置密码。"""
    return {"message": "暂未实现"}


# ---- 4. 用户个人两步验证 (User 2FA TOTP Settings) ----

@router.post("/2fa/totp/enable", response_model=TotpEnableResponse, tags=["2FA"])
async def enable_2fa(
    uid: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """生成并分配当前用户的 TOTP 二维码绑定密钥与安全恢复码。"""
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one()
    if user.totp_enabled:
        raise HTTPException(status_code=400, detail="2FA 已启用")
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
    """提交一次性验证码，确认启用并激活双重认证。"""
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one()
    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="请先调用 /enable")
    if not verify_totp(user.totp_secret, body.code):
        raise HTTPException(status_code=400, detail="TOTP 码无效")
    user.totp_enabled = True
    await db.commit()
    return {"status": "2fa_enabled"}


@router.post("/2fa/totp/disable", tags=["2FA"])
async def disable_2fa(
    body: TotpDisableRequest,
    uid: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
):
    """当前登录用户自行关闭 TOTP 2FA（必须验证个人密码）。"""
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one()
    if not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="密码错误")
    user.totp_enabled = False
    user.totp_secret = None
    await db.commit()
    return {"status": "2fa_disabled"}


@router.post("/2fa/totp/verify", tags=["2FA"])
async def verify_2fa_login(body: TotpVerifyRequest):
    """输入一次性 TOTP 动态码以完成登录（无需 Bearer Session，使用 temp_token 进行提权）。"""
    uid = await pop_2fa_temp_token(body.temp_token)
    async with AsyncSessionLocal() as db:
        user = (await db.execute(select(User).where(User.id == uid))).scalar_one()
    if not verify_totp(user.totp_secret, body.code):
        raise HTTPException(status_code=401, detail="TOTP 码无效")
    token = await create_session_token(uid)
    return {"token": token, "user_id": uid}


@router.post("/2fa/totp/recover", tags=["2FA"])
async def recover_2fa(body: TotpRecoverRequest):
    """使用 2FA 安全恢复码完成紧急备用登录（无需 Bearer Session）。"""
    uid = await pop_2fa_temp_token(body.temp_token)
    ok = await use_recovery_code(uid, body.recovery_code)
    if not ok:
        raise HTTPException(status_code=401, detail="恢复码无效或已使用")
    token = await create_session_token(uid)
    return {"token": token, "user_id": uid}
