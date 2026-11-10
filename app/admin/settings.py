from datetime import datetime, timezone
import re
from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.db.models import SystemConfig
from app.shared.schemas.schemas import SettingsUpdate
from app.shared.security.auth import require_role
from app.shared.utils.community import notify_group_site_announcement

router = APIRouter(prefix="/settings", tags=["Settings"])
_sa = require_role(100)
_URL_CREDENTIALS_RE = re.compile(r"(://[^:/?#]*:)([^@]+)(@)")


def mask_sensitive_setting(key: str, value: str) -> str:
    """Mask inline passwords in URL-like settings (e.g. redis_url, database_url)."""
    if not value:
        return value
    k_lower = key.lower()
    if any(tok in k_lower for tok in ("password", "secret", "private_key")):
        return "***"
    if "://" in value and "@" in value:
        return _URL_CREDENTIALS_RE.sub(r"\1***\3", value)
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
    prev_rows = (
        (
            await db.execute(
                select(SystemConfig).where(
                    SystemConfig.key.in_(("announcement_title", "motd"))
                )
            )
        )
        .scalars()
        .all()
    )
    prev_map = {r.key: str(r.value or "").strip() for r in prev_rows}

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

    if "announcement_title" in body.items or "motd" in body.items:
        new_title = str(
            body.items.get("announcement_title", prev_map.get("announcement_title", ""))
            or ""
        ).strip()
        new_motd = str(body.items.get("motd", prev_map.get("motd", "")) or "").strip()
        if (new_title or new_motd) and (
            new_title != prev_map.get("announcement_title", "")
            or new_motd != prev_map.get("motd", "")
        ):
            await notify_group_site_announcement(new_title, new_motd)

    return {"status": "ok", "message": "Settings updated"}
