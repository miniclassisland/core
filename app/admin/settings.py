from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.db.models import SystemConfig
from app.shared.schemas.schemas import SettingsUpdate
from app.shared.security.auth import require_role

router = APIRouter(prefix="/settings", tags=["Settings"])
_sa = require_role(100)


@router.get("")
async def get_settings(
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """获取所有系统设置。"""
    rows = (await db.execute(select(SystemConfig))).scalars().all()
    return {r.key: r.value for r in rows}


@router.post("")
async def update_settings(
    body: SettingsUpdate,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """修改系统设置（仅白名单键）。"""
    now = datetime.now(timezone.utc)
    for key, value in body.items.items():
        stmt = select(SystemConfig).where(SystemConfig.key == key)
        cfg = (await db.execute(stmt)).scalar_one_or_none()
        if cfg:
            cfg.value = str(value)
            cfg.updated_at = now
        else:
            db.add(SystemConfig(key=key, value=str(value), updated_at=now))
    await db.commit()
    return {"message": "设置已更新"}
