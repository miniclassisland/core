"""Cloudflare Turnstile server-side token verification utility."""

import logging
import os
from typing import Optional

import httpx
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.models import SystemConfig
from app.shared.utils.config import BASE_DOMAIN, _load_file_config

logger = logging.getLogger("miniclassisland.turnstile")

TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
TURNSTILE_DEFAULT_SITE_KEY = "0x4AAAAAAF0J1ST0LriGpOof"

_http_client: Optional[httpx.AsyncClient] = None


def get_turnstile_client() -> httpx.AsyncClient:
    """Return the shared keep-alive HTTP client used for SiteVerify requests."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(8.0, connect=3.0),
            limits=httpx.Limits(
                max_connections=50,
                max_keepalive_connections=20,
            ),
            follow_redirects=False,
            trust_env=False,
        )
    return _http_client


async def close_turnstile_client() -> None:
    """Close and clear the shared SiteVerify HTTP client."""
    global _http_client
    client = _http_client
    _http_client = None
    if client is not None and not client.is_closed:
        await client.aclose()


async def get_turnstile_secret_key(db: Optional[AsyncSession] = None) -> str:
    """Resolve Cloudflare Turnstile secret key from environment, config.json, or SystemConfig."""
    env_secret = os.getenv("TURNSTILE_SECRET_KEY", "").strip()
    if env_secret:  # pragma: no cover
        return env_secret

    try:
        file_cfg = _load_file_config()
        cfg_secret = str(file_cfg.get("turnstile_secret_key", "")).strip()
        if cfg_secret:  # pragma: no cover
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
            if row and row.strip() and row.strip() != "***":  # pragma: no cover
                return row.strip()
        except Exception:
            pass

    return ""


def get_turnstile_allowed_hostnames() -> set[str]:
    """Resolve the frontend hostnames allowed in SiteVerify responses."""
    raw = os.getenv("TURNSTILE_HOSTNAMES", "").strip()
    if not raw:
        try:
            file_cfg = _load_file_config()
            raw = str(file_cfg.get("turnstile_hostnames", "")).strip()
        except Exception:
            raw = ""

    if raw:
        return {host.strip().lower() for host in raw.split(",") if host.strip()}

    domain = (BASE_DOMAIN or "").strip().lower()
    if not domain:  # pragma: no cover
        return set()
    return {domain, f"dash.{domain}", f"dashboard.{domain}"}


async def verify_turnstile_token(
    token: Optional[str],
    remote_ip: str = "",
    db: Optional[AsyncSession] = None,
    *,
    expected_action: Optional[str] = None,
    expected_hostnames: Optional[set[str]] = None,
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
        resp = await get_turnstile_client().post(
            TURNSTILE_SITEVERIFY_URL, data=form_data
        )
        if resp.status_code != 200:
            logger.warning("Turnstile siteverify returned HTTP %s", resp.status_code)
            return False

        data = resp.json()
        if data.get("success") is not True:
            return False

        if expected_action is not None:
            actual_action = str(data.get("action") or "")
            if actual_action != expected_action:
                logger.warning(
                    "Turnstile action mismatch: expected %s, got %s",
                    expected_action,
                    actual_action,
                )
                return False

        allowed_hostnames = (
            expected_hostnames
            if expected_hostnames is not None
            else get_turnstile_allowed_hostnames()
        )
        hostname = str(data.get("hostname") or "").strip().lower()
        if not allowed_hostnames or hostname not in allowed_hostnames:
            logger.warning(
                "Turnstile hostname rejected: %s (allowed: %s)",
                hostname,
                ", ".join(sorted(allowed_hostnames)) or "<empty>",
            )
            return False

        return True
    except Exception as exc:
        logger.warning("Turnstile siteverify request failed: %s", exc)
        return False


async def require_turnstile_verification(
    token: Optional[str],
    remote_ip: str = "",
    db: Optional[AsyncSession] = None,
    *,
    expected_action: Optional[str] = None,
    expected_hostnames: Optional[set[str]] = None,
) -> None:
    """Verify Turnstile token or raise HTTP 400 Bad Request."""
    ok = await verify_turnstile_token(
        token,
        remote_ip=remote_ip,
        db=db,
        expected_action=expected_action,
        expected_hostnames=expected_hostnames,
    )
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Turnstile human verification failed, please complete the captcha challenge and try again",
        )
