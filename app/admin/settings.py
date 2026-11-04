from datetime import datetime, timezone
import re
from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.db.models import SystemConfig
from app.shared.schemas.schemas import SettingsUpdate
from app.shared.security.auth import require_role

router = APIRouter(prefix="/settings", tags=["Settings"])
_sa = require_role(100)
_URL_CREDENTIALS_RE = re.compile(r"(://[^:/?#]*:)([^@]+)(@)")


def mask_sensitive_setting(key: str, value: str) -> str:
    """Mask inline passwords in URL-like settings (e.g. redis_url, database_url)."""
    if not value:
        return value
    k_lower = key.lower()
    if any(tok in k_lower for tok in ("password", "secret", "private_key")):
        return "***"  # pragma: no cover
    if "://" in value and "@" in value:
        return _URL_CREDENTIALS_RE.sub(r"\1***\3", value)  # pragma: no cover
    return value


@router.get("")
async def get_settings(
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Retrieve all system configuration settings (with sensitive credentials masked)."""
    rows = (await db.execute(select(SystemConfig))).scalars().all()
    return {r.key: mask_sensitive_setting(r.key, r.value) for r in rows}


@router.post("", status_code=status.HTTP_200_OK)
async def update_settings(
    body: SettingsUpdate,
    db: AsyncSession = Depends(get_db),
    _user=Depends(_sa),
):
    """Update system configuration settings."""
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
    return {"status": "ok", "message": "Settings updated"}
