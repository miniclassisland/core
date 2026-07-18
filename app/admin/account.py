import os
import sys
import threading
from fastapi import APIRouter, Depends, Form, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.db.models import Account
from app.shared.schemas.schemas import AccountOut, UserOut
from app.shared.security.auth import (
    require_role,
    verify_oobe_passcode,
    verify_oobe_token,
    OOBE_TOKEN,
)
from app.shared.services.user import list_pending_users, reject_user, approve_user
from app.shared.utils.oobe import write_config_file, init_database

router = APIRouter()
_sa = require_role(100)


def _to_out(user) -> UserOut:
    """将 User 模型转换为响应模型。"""
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


# ---- 1. 账户（租户）管理 (Account/Tenant Admin) ----

@router.get("/account", response_model=list[AccountOut], tags=["Account"])
async def list_all_accounts(
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """列出所有租户账户（仅超管）。"""
    rows = (await db.execute(select(Account))).scalars().all()
    return [
        AccountOut(
            id=a.id,
            name=a.name,
            slug=a.slug,
            api_key=a.api_key,
            is_active=a.is_active,
            created_at=str(a.created_at),
        )
        for a in rows
    ]


# ---- 2. 用户注册申请审核 (User Registration Approvals) ----

@router.get("/user/pending/list", response_model=list[UserOut], tags=["Pending"])
async def get_pending_users(
    offset: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """列出所有待审核的注册申请用户。"""
    users = await list_pending_users(db, offset=offset, limit=limit)
    return [_to_out(u) for u in users]


@router.post("/user/pending/approve/{user_id}", response_model=UserOut, tags=["Pending"])
async def approve_pending(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """审核批准指定的用户注册申请。"""
    user = await approve_user(user_id, db)
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在或非待审核状态")
    return _to_out(user)


@router.post("/user/pending/reject/{user_id}", tags=["Pending"])
async def reject_pending(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """驳回/拒绝指定的用户注册申请。"""
    ok = await reject_user(user_id, db)
    if not ok:
        raise HTTPException(status_code=404, detail="用户不存在或非待审核状态")
    return {"message": "已拒绝"}


# ---- 3. OOBE 首次安装配置向导 (OOBE Configuration Guide) ----

@router.post("/oobe/verify", tags=["OOBE"])
async def verify_passcode(passcode: str = Form(...)):
    """校验引导界面的配对输入，并分发提权执行许可 Token。"""
    if not verify_oobe_passcode(passcode):
        raise HTTPException(status_code=403, detail="配对码错误或已失效")
    return {"token": OOBE_TOKEN}


@router.post("/oobe/configure", tags=["OOBE"])
async def configure_system(
    token: str = Form(...),
    db_url: str = Form(...),
    redis_url: str = Form(...),
    domain: str = Form(...),
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
):
    """验证配置阶段 Token 后执行数据库 DDL 与默认种子数据填充，完成后触发系统自重启。"""
    if not verify_oobe_token(token):
        raise HTTPException(status_code=403, detail="非法令牌或已过期")

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
        raise HTTPException(status_code=400, detail=f"初始化失败: {str(e)}")

    # 在一秒后触发程序重启以加载新配置文件
    threading.Timer(
        1.0, lambda: os.execv(sys.executable, [sys.executable] + sys.argv)
    ).start()
    return {"msg": "初始化完毕，系统重启中"}
