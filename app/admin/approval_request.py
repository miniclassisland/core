"""Super-administrator dedicated approval channel for quota increases and permission requests."""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.models import Account, QuotaPermissionRequest, User
from app.shared.db.session import get_db
from app.shared.literals import APPROVAL_REQUEST_STATUSES, APPROVAL_REQUEST_TYPES
from app.shared.schemas.schemas import (
    QuotaPermissionRequestListOut,
    QuotaPermissionRequestOut,
    QuotaPermissionRequestReview,
)
from app.shared.security.auth import require_role
from app.shared.services.approval_request import (
    MAX_QUOTA_REQUEST_VALUE,
    approval_request_to_out,
    is_unsafe_request_id,
)
from app.shared.services.quota import set_quota
from app.shared.services.sse import publish_account_event, publish_topic_event
from app.shared.services.ticket import has_unsafe_control


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


router = APIRouter(
    prefix="/approval-request",
    tags=["ApprovalRequest"],
    dependencies=[Depends(_no_store)],
)
_sa = require_role(100)

_MSG_NOT_FOUND = "审批申请不存在"


async def _get_request_joined(
    db: AsyncSession, request_id: str
) -> tuple[QuotaPermissionRequest, Optional[Account], Optional[User]]:
    if is_unsafe_request_id(request_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=_MSG_NOT_FOUND
        )
    row = (
        await db.execute(
            select(QuotaPermissionRequest, Account, User)
            .join(
                Account, Account.id == QuotaPermissionRequest.account_id, isouter=True
            )
            .join(User, User.id == QuotaPermissionRequest.user_id, isouter=True)
            .where(QuotaPermissionRequest.id == request_id)
        )
    ).first()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=_MSG_NOT_FOUND
        )
    return row[0], row[1], row[2]


@router.get("/pending-count")
async def get_pending_approval_request_count(
    db: AsyncSession = Depends(get_db),
    _admin=Depends(_sa),
):
    """Return the count of pending quota/permission approval requests."""
    count = (
        await db.execute(
            select(func.count(QuotaPermissionRequest.id)).where(
                QuotaPermissionRequest.status == "pending"
            )
        )
    ).scalar_one()
    return {"count": int(count)}


@router.get("/list", response_model=QuotaPermissionRequestListOut)
async def list_all_approval_requests(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    req_status: Optional[str] = Query(None, alias="status"),
    request_type: Optional[str] = Query(None),
    account_id: Optional[str] = Query(None),
    q: str = Query("", max_length=200),
    db: AsyncSession = Depends(get_db),
    _admin=Depends(_sa),
):
    """List all quota and permission approval requests with filters."""
    filters = []
    if req_status:
        norm = req_status.strip().lower()
        if norm not in APPROVAL_REQUEST_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="无效的审批状态"
            )
        filters.append(QuotaPermissionRequest.status == norm)
    if request_type:
        norm_type = request_type.strip().lower()
        if norm_type not in APPROVAL_REQUEST_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="无效的申请类型"
            )
        filters.append(QuotaPermissionRequest.request_type == norm_type)
    if account_id:
        filters.append(QuotaPermissionRequest.account_id == account_id.strip())
    if q.strip():
        if has_unsafe_control(q):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="搜索关键词包含非法控制字符",
            )
        escaped_q = (
            q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        )
        term = f"%{escaped_q}%"
        filters.append(
            or_(
                QuotaPermissionRequest.reason.ilike(term, escape="\\"),
                QuotaPermissionRequest.target_key.ilike(term, escape="\\"),
                Account.name.ilike(term, escape="\\"),
                Account.slug.ilike(term, escape="\\"),
                User.username.ilike(term, escape="\\"),
                User.email.ilike(term, escape="\\"),
                User.display_name.ilike(term, escape="\\"),
            )
        )

    total = (
        await db.execute(
            select(func.count(QuotaPermissionRequest.id))
            .select_from(QuotaPermissionRequest)
            .join(
                Account, Account.id == QuotaPermissionRequest.account_id, isouter=True
            )
            .join(User, User.id == QuotaPermissionRequest.user_id, isouter=True)
            .where(*filters)
        )
    ).scalar_one()

    rows = (
        await db.execute(
            select(QuotaPermissionRequest, Account, User)
            .join(
                Account, Account.id == QuotaPermissionRequest.account_id, isouter=True
            )
            .join(User, User.id == QuotaPermissionRequest.user_id, isouter=True)
            .where(*filters)
            .order_by(QuotaPermissionRequest.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
    ).all()

    return QuotaPermissionRequestListOut(
        total=int(total),
        items=[
            approval_request_to_out(req, account=account, user=user)
            for req, account, user in rows
        ],
    )


@router.post("/{request_id}/approve", response_model=QuotaPermissionRequestOut)
async def approve_approval_request(
    request_id: str,
    payload: Optional[QuotaPermissionRequestReview] = Body(default=None),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(_sa),
):
    """Approve a pending request and immediately apply the target quota or permission."""
    req, account, user = await _get_request_joined(db, request_id)
    if req.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="该申请已被处理，无法重复审批",
        )

    review_note = payload.review_note if payload else ""
    if req.request_type == "permission":
        final_value = 1
    else:
        final_value = (
            payload.approved_value
            if payload and payload.approved_value is not None
            else req.requested_value
        )
        if final_value != -1 and (
            final_value < 1 or final_value > MAX_QUOTA_REQUEST_VALUE
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"批准的配额上限需为 1 ~ {MAX_QUOTA_REQUEST_VALUE}，或填 -1 表示不限制",
            )

    await set_quota(req.account_id, req.target_key, final_value, db)

    now = datetime.now(timezone.utc)
    req.status = "approved"
    req.approved_value = final_value
    req.review_note = review_note
    req.reviewed_by = admin.id
    req.reviewed_at = now
    req.updated_at = now
    await db.commit()
    await db.refresh(req)

    await publish_topic_event(
        "__admin__",
        "approval_request.updated",
        {"id": req.id, "account_id": req.account_id, "status": req.status},
    )
    await publish_account_event(
        req.account_id,
        "approval_request.updated",
        {"id": req.id, "status": req.status, "target_key": req.target_key},
    )

    return approval_request_to_out(req, account=account, user=user)


@router.post("/{request_id}/reject", response_model=QuotaPermissionRequestOut)
async def reject_approval_request(
    request_id: str,
    payload: Optional[QuotaPermissionRequestReview] = Body(default=None),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(_sa),
):
    """Reject a pending quota/permission approval request."""
    req, account, user = await _get_request_joined(db, request_id)
    if req.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="该申请已被处理，无法重复审批",
        )

    now = datetime.now(timezone.utc)
    req.status = "rejected"
    req.review_note = payload.review_note if payload else ""
    req.reviewed_by = admin.id
    req.reviewed_at = now
    req.updated_at = now
    await db.commit()
    await db.refresh(req)

    await publish_topic_event(
        "__admin__",
        "approval_request.updated",
        {"id": req.id, "account_id": req.account_id, "status": req.status},
    )
    await publish_account_event(
        req.account_id,
        "approval_request.updated",
        {"id": req.id, "status": req.status, "target_key": req.target_key},
    )

    return approval_request_to_out(req, account=account, user=user)
