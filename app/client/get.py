import json
import logging
from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import Account, MODEL_MAP
from app.shared.utils.logging import get_client_ip_from_request
from app.shared.utils.tenant import set_search_path
from app.shared.security.auth import resolve_token
from app.grpc import SessionManager

router = APIRouter()
logger = logging.getLogger(__name__)
session_mgr = SessionManager()


@router.get("/get", tags=["TokenGet"])
async def get_resource_by_token(token: str, request: Request):
    """Retrieve resource content by download token with client IP verification."""
    result = await resolve_token(token)
    if result is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or expired token")

    tenant_id, resource_type, name, token_ip = result
    model = MODEL_MAP.get(resource_type)
    if model is None:  # pragma: no cover
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid resource type")

    # Client IP authorization
    client_ip = get_client_ip_from_request(request)
    if token_ip:
        online_ips = await session_mgr.get_all_online_ips(tenant_id)
        if client_ip not in online_ips:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Client IP not authorized")

    # Token carries tenant_id → query slug by tenant_id and switch corresponding schema search_path
    async with AsyncSessionLocal() as db:
        stmt = select(Account).where(Account.id == tenant_id)
        account = (await db.execute(stmt)).scalar_one_or_none()
        if account:
            await set_search_path(db, f"tenant_{account.slug}")
        else:
            await set_search_path(db)

        row = (
            await db.execute(select(model).where(model.name == name))
        ).scalar_one_or_none()

    if row is None:  # pragma: no cover
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")

    try:
        return json.loads(row.content)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Corrupted resource content")
