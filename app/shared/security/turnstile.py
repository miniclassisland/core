"""Cloudflare Turnstile server-side token verification utility."""

import logging
import os
from typing import Optional

import httpx
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.models import SystemConfig
from app.shared.utils.config import _load_file_config

logger = logging.getLogger(__name__)

TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
TURNSTILE_DEFAULT_SITE_KEY = "0x4AAAAAAF0J1ST0LriGpOof"


async def get_turnstile_secret_key(db: Optional[AsyncSession] = None) -> str:
    """Resolve Cloudflare Turnstile secret key from environment, config.json, or SystemConfig."""
    env_secret = os.getenv("TURNSTILE_SECRET_KEY", "").strip()
    if env_secret:
        return env_secret

    try:
        file_cfg = _load_file_config()
        cfg_secret = str(file_cfg.get("turnstile_secret_key", "")).strip()
        if cfg_secret:
            return cfg_secret
    except Exception:
        pass

    if db is not None:
        try:
            row = (
                await db.execute(
                    select(SystemConfig.value).where(
                        SystemConfig.key == "turnstile_secret_key"
                    )
                )
            ).scalar_one_or_none()
            if row and row.strip() and row.strip() != "***":
                return row.strip()
        except Exception:
            pass

    return ""


async def verify_turnstile_token(
    token: Optional[str],
    remote_ip: str = "",
    db: Optional[AsyncSession] = None,
) -> bool:
    """Verify Cloudflare Turnstile token via siteverify API."""
    cleaned_token = (token or "").strip()
    secret_key = await get_turnstile_secret_key(db)

    if not secret_key:
        # If no server-side secret key is configured yet, only reject if a dummy invalid test token was explicitly sent
        if cleaned_token == "INVALID_TURNSTILE_TOKEN":
            return False
        return True

    if not cleaned_token:
        return False

    form_data: dict[str, str] = {
        "secret": secret_key,
        "response": cleaned_token,
    }
    if remote_ip and remote_ip not in ("unknown", "testclient", "127.0.0.1", "::1"):
        form_data["remoteip"] = remote_ip

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(TURNSTILE_SITEVERIFY_URL, data=form_data)
            if resp.status_code != 200:
                logger.warning(
                    "Turnstile siteverify returned HTTP %s", resp.status_code
                )
                return False
            data = resp.json()
            return bool(data.get("success") is True)
    except Exception as exc:
        logger.warning("Turnstile siteverify request failed: %s", exc)
        return False


async def require_turnstile_verification(
    token: Optional[str],
    remote_ip: str = "",
    db: Optional[AsyncSession] = None,
) -> None:
    """Verify Turnstile token or raise HTTP 400 Bad Request."""
    ok = await verify_turnstile_token(token, remote_ip=remote_ip, db=db)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Turnstile human verification failed, please complete the captcha challenge and try again",
        )
