"""Embedded font distribution router for MINI ClassIsland."""

from pathlib import Path
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse

router = APIRouter(tags=["Fonts"])

_REPO_ROOT = Path(__file__).resolve().parents[3]
_FONTS_DIR = _REPO_ROOT / "assets" / "fonts"

_ALLOWED_FONTS = {
    "GoogleSansFlex-VariableFont.ttf",
    "NotoSansSC-VariableFont.ttf",
    "GoogleSansCode-VariableFont.ttf",
    "GoogleSansCode-Italic-VariableFont.ttf",
}


@router.get("/fonts/{font_name}")
async def get_embedded_font(font_name: str):
    """Serve embedded variable font files with long-term cache headers."""
    if font_name not in _ALLOWED_FONTS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Font not found"
        )
    path = _FONTS_DIR / font_name
    if not path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Font asset missing on server"
        )
    return FileResponse(
        path=str(path),
        media_type="font/ttf",
        headers={"Cache-Control": "public, max-age=31536000, immutable"},
    )
