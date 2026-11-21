"""Shared serialization, validation, and rate-limiting helpers for quota/permission approval requests."""

import logging
from typing import Optional

from fastapi import HTTPException, status

from app.shared.db.models import Account, QuotaPermissionRequest, User
from app.shared.literals import PERMISSION_REQUEST_KEYS, QUOTA_REQUEST_KEYS
from app.shared.schemas.schemas import QuotaPermissionRequestOut
from app.shared.services.ticket import has_unsafe_control, iso, user_summary
from app.shared.utils.config import REDIS_DB_AUTH
from app.shared.utils.redis import get_redis

logger = logging.getLogger(__name__)

APPROVAL_CREATE_LIMIT_PER_HOUR = 20
MAX_QUOTA_REQUEST_VALUE = 1_000_000


def is_unsafe_request_id(value: str) -> bool:
    """Reject malformed path identifiers before they reach the database."""
    return len(value) > 64 or has_unsafe_control(value)


def validate_request_target_and_value(
    request_type: str,
    target_key: str,
    requested_value: int,
    current_value: int,
) -> int:
    """Validate that request_type, target_key, and requested_value are consistent."""
    if request_type == "quota":
        if target_key not in QUOTA_REQUEST_KEYS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="该配额项不支持增开配额申请",
            )
        if requested_value != -1 and (
            requested_value < 1 or requested_value > MAX_QUOTA_REQUEST_VALUE
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"申请的配额上限需为 1 ~ {MAX_QUOTA_REQUEST_VALUE}，或填 -1 表示不限制",
            )
        if current_value == -1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="该配额项当前已为不限制，无需再申请增开",
            )
        if requested_value != -1 and requested_value <= current_value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"申请的配额值必须大于当前配额上限（{current_value}）",
            )
        return requested_value

    if request_type == "permission":
        if target_key not in PERMISSION_REQUEST_KEYS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="该权限项不支持权限申请",
            )
        if current_value >= 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="该功能权限当前已开通，无需重复申请",
            )
        return 1

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="无效的申请类型",
    )


async def enforce_approval_write_limit(
    user_id: str,
    limit: int = APPROVAL_CREATE_LIMIT_PER_HOUR,
    window_seconds: int = 3600,
) -> None:
    """Apply a per-user fixed-window rate limit to approval request creation (fail-open)."""
    try:
        rd = get_redis(REDIS_DB_AUTH)
        key = f"approval_req:rate:create:{user_id}"
        count = await rd.incr(key)
        if count == 1:
            await rd.expire(key, window_seconds)
        if count > limit:
            ttl = await rd.ttl(key)
            retry_after = ttl if isinstance(ttl, int) and ttl > 0 else window_seconds
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="审批申请提交过于频繁，请稍后再试",
                headers={"Retry-After": str(retry_after)},
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Approval request rate limiter unavailable: %s", exc)


def approval_request_to_out(
    req: QuotaPermissionRequest,
    *,
    account: Optional[Account] = None,
    user: Optional[User] = None,
    mask_staff_ids: bool = False,
) -> QuotaPermissionRequestOut:
    """Serialize a QuotaPermissionRequest for API responses."""
    reviewed_by = req.reviewed_by
    if mask_staff_ids and reviewed_by:
        reviewed_by = "admin"
    return QuotaPermissionRequestOut(
        id=req.id,
        account_id=req.account_id,
        account_name=account.name if account else "",
        account_slug=account.slug if account else "",
        user_id=req.user_id,
        request_type=req.request_type,
        target_key=req.target_key,
        current_value=req.current_value,
        requested_value=req.requested_value,
        approved_value=req.approved_value,
        reason=req.reason,
        status=req.status,
        review_note=req.review_note or "",
        reviewed_by=reviewed_by,
        reviewed_at=iso(req.reviewed_at),
        created_at=iso(req.created_at) or "",
        updated_at=iso(req.updated_at) or "",
        user=user_summary(user),
    )
