"""Backend version information endpoint."""

from fastapi import APIRouter, Depends

from app import __version__
from app.shared.security.auth import get_current_user_id

router = APIRouter(tags=["Version"])


@router.get("/version")
async def get_version(_user_id: str = Depends(get_current_user_id)):
    """Return the running Core backend version."""
    return {"version": __version__}
