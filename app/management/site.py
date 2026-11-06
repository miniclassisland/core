"""Site-wide announcement endpoints."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.models import SystemConfig
from app.shared.db.session import get_db
from app.shared.security.auth import get_current_user_id

router = APIRouter(prefix="/site", tags=["Site"])


class SiteAnnouncementOut(BaseModel):
    """Site announcement payload shown in the authenticated web shell."""

    title: str = ""
    subtitle: str = ""


@router.get("/announcement", response_model=SiteAnnouncementOut)
async def get_site_announcement(
    db: AsyncSession = Depends(get_db),
    _user_id: str = Depends(get_current_user_id),
):
    """Return the current site-wide announcement for logged-in users."""
    rows = (
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
    values = {row.key: row.value for row in rows}
    return SiteAnnouncementOut(
        title=str(values.get("announcement_title") or "").strip(),
        subtitle=str(values.get("motd") or "").strip(),
    )
