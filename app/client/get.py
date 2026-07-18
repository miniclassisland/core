import json
import logging
from fastapi import APIRouter, HTTPException, Request
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
    """通过令牌获取配置内容，附带 IP 鉴权。"""
    result = await resolve_token(token)
    if result is None:
        raise HTTPException(status_code=403, detail="Invalid or expired token")

    tenant_id, resource_type, name, token_ip = result
    model = MODEL_MAP.get(resource_type)
    if model is None:  # pragma: no cover
        raise HTTPException(status_code=400, detail="Invalid resource type")

    # IP 鉴权
    client_ip = get_client_ip_from_request(request)
    if token_ip:
        online_ips = await session_mgr.get_all_online_ips(tenant_id)
        if client_ip not in online_ips:
            return {}

    # 令牌携带 tenant_id → 根据 tenant_id 查询 slug 并切换对应 Schema 设置 search_path
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
        raise HTTPException(status_code=404, detail="Resource not found")

    try:
        return json.loads(row.content)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(status_code=500, detail="Corrupted resource")
