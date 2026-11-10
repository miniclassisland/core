import json
import logging
from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select

from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import MODEL_MAP
from app.shared.literals import DEFAULT_RESOURCES
from app.shared.utils.tenant import set_search_path
from app.shared.utils.logging import get_client_ip_from_request
from app.shared.security.auth import resolve_token
from app.shared.security.crypto import normalize_resource_payload
from app.shared.services.quota import check_quota, record_bandwidth_bytes

router = APIRouter()
logger = logging.getLogger(__name__)

# Fast in-process cache of normalized JSON strings keyed by (account_id, resource_type, name, version)
_NORMALIZED_RESOURCE_CACHE: dict[tuple[str, str, str, int], str] = {}
_MAX_RESOURCE_CACHE_SIZE = 2048


def invalidate_resource_cache(
    account_id: str,
    resource_type: str | None = None,
    name: str | None = None,
) -> None:
    """Invalidate cached normalized JSON entries for an account/resource."""
    keys_to_remove = [
        k
        for k in _NORMALIZED_RESOURCE_CACHE
        if k[0] == account_id
        and (resource_type is None or k[1] == resource_type)
        and (name is None or k[2] == name)
    ]
    for k in keys_to_remove:
        _NORMALIZED_RESOURCE_CACHE.pop(k, None)


@router.get("/get", tags=["TokenGet"])
async def get_resource_by_token(token: str, request: Request):
    """Retrieve resource content by one-time download token."""
    req_ip = get_client_ip_from_request(request)
    result = await resolve_token(token, req_ip=req_ip)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or expired token"
        )

    tenant_id, resource_type, name, token_ip = result
    if (
        token_ip
        and req_ip
        and token_ip not in ("127.0.0.1", "::1", "testclient")
        and req_ip not in ("127.0.0.1", "::1", "testclient")
        and token_ip != req_ip
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token IP address mismatch",
        )
    model = MODEL_MAP.get(resource_type)
    if model is None:
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
        if (
            row is None
            and effective_tid != "default"
            and resource_type != "Credentials"
        ):
            row = (
                (
                    await db.execute(
                        select(model).where(
                            model.account_id == "default",
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

    cache_key = (
        row.account_id,
        resource_type,
        row.name,
        int(row.version or 1),
    )
    cached_json = _NORMALIZED_RESOURCE_CACHE.get(cache_key)
    resp_headers = {
        "X-MiniClassIsland-Server": "miniclassisland",
        "X-Server-Flavor": "miniclassisland",
    }
    if cached_json is not None:
        record_bandwidth_bytes(effective_tid, len(cached_json.encode("utf-8")) + 256)
        return Response(
            content=cached_json, media_type="application/json", headers=resp_headers
        )

    try:
        parsed = json.loads(row.content)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Corrupted resource content",
        )
    norm_obj = normalize_resource_payload(resource_type, parsed)
    norm_json = json.dumps(norm_obj, ensure_ascii=False)
    if len(_NORMALIZED_RESOURCE_CACHE) >= _MAX_RESOURCE_CACHE_SIZE:
        _NORMALIZED_RESOURCE_CACHE.pop(next(iter(_NORMALIZED_RESOURCE_CACHE)), None)
    _NORMALIZED_RESOURCE_CACHE[cache_key] = norm_json
    record_bandwidth_bytes(effective_tid, len(norm_json.encode("utf-8")) + 256)
    return Response(
        content=norm_json, media_type="application/json", headers=resp_headers
    )
