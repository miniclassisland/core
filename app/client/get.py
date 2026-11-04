import json
import logging
from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select, or_

from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import MODEL_MAP
from app.shared.literals import DEFAULT_RESOURCES
from app.shared.utils.tenant import set_search_path
from app.shared.security.auth import resolve_token
from app.shared.security.crypto import normalize_resource_payload
from app.shared.services.quota import check_quota, record_bandwidth_bytes

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/get", tags=["TokenGet"])
async def get_resource_by_token(token: str, request: Request):
    """Retrieve resource content by one-time download token."""
    result = await resolve_token(token)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or expired token"
        )

    tenant_id, resource_type, name, _token_ip = result
    model = MODEL_MAP.get(resource_type)
    if model is None:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid resource type"
        )

    effective_tid = tenant_id or "default"
    async with AsyncSessionLocal() as db:
        await set_search_path(db)
        if effective_tid != "default" and not await check_quota(
            effective_tid, "max_bandwidth_mb", db
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Account bandwidth quota (max_bandwidth_mb) exceeded",
            )
        row = (
            await db.execute(
                select(model).where(
                    model.account_id == effective_tid,
                    model.name == name,
                )
            )
        ).scalar_one_or_none()
        if row is None:
            row = (
                (
                    await db.execute(
                        select(model).where(
                            or_(model.account_id == "default", model.name == name),
                            model.name == name,
                        )
                    )
                )
                .scalars()
                .first()
            )

    if row is None:
        fallback = DEFAULT_RESOURCES.get(resource_type, {}).get(name)
        if fallback is not None:
            norm_fb = normalize_resource_payload(resource_type, fallback)
            record_bandwidth_bytes(effective_tid, 1024)
            return norm_fb
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found"
        )

    try:
        parsed = json.loads(row.content)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Corrupted resource content",
        )
    record_bandwidth_bytes(effective_tid, len(row.content.encode("utf-8")) + 256)
    return normalize_resource_payload(resource_type, parsed)
