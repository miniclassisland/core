"""Tenant-facing dedicated quota increase and permission approval request endpoints."""

from datetime import datetime, timezone
from typing import Optional

from fastapi import (
    APIRouter,
    Body,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.management.account import _get_effective_account_role
from app.shared.db.models import Account, QuotaPermissionRequest, User
from app.shared.db.session import get_db
from app.shared.literals import (
    APPROVAL_REQUEST_STATUSES,
    APPROVAL_REQUEST_TYPES,
    DEFAULT_QUOTAS,
)
from app.shared.schemas.schemas import (
    QuotaPermissionRequestCreate,
    QuotaPermissionRequestListOut,
    QuotaPermissionRequestOut,
)
from app.shared.security.auth import get_current_user_id
from app.shared.services.approval_request import (
    approval_request_to_out,
    enforce_approval_write_limit,
    is_unsafe_request_id,
    validate_request_target_and_value,
)
from app.shared.services.quota import get_quotas
from app.shared.services.sse import publish_topic_event
from app.shared.utils.community import notify_superadmin_new_approval_request


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


router = APIRouter(
    prefix="/account/{account_id}/approval-requests",
    tags=["ApprovalRequest"],
    dependencies=[Depends(_no_store)],
)

_DEFAULT_QUOTA_MAP = dict(DEFAULT_QUOTAS)
_MSG_NOT_FOUND = "审批申请不存在"


async def _ensure_account_member(
    account_id: str, user_id: str, db: AsyncSession, request: Request
) -> tuple[Account, str]:
    cached = getattr(request.state, "current_account", None)
    if isinstance(cached, Account) and cached.id == account_id:
        account = cached
    else:
        account = (
            await db.execute(select(Account).where(Account.id == account_id))
        ).scalar_one_or_none()
    if not account or not account.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="账户不存在或已停用",
        )
    role = await _get_effective_account_role(account_id, user_id, db)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权访问该账户",
        )
    return account, role


@router.get("", response_model=QuotaPermissionRequestListOut)
async def list_account_approval_requests(
    account_id: str,
    request: Request,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    req_status: Optional[str] = Query(None, alias="status"),
    request_type: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """List quota increase and permission approval requests for the current tenant account."""
    account, _role = await _ensure_account_member(account_id, user_id, db, request)
    filters = [QuotaPermissionRequest.account_id == account_id]
    if req_status:
        norm = req_status.strip().lower()
        if norm not in APPROVAL_REQUEST_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="无效的审批状态",
            )
        filters.append(QuotaPermissionRequest.status == norm)
    if request_type:
        norm_type = request_type.strip().lower()
        if norm_type not in APPROVAL_REQUEST_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="无效的申请类型",
            )
        filters.append(QuotaPermissionRequest.request_type == norm_type)

    total = (
        await db.execute(select(func.count(QuotaPermissionRequest.id)).where(*filters))
    ).scalar_one()
    rows = (
        (
            await db.execute(
                select(QuotaPermissionRequest)
                .where(*filters)
                .order_by(QuotaPermissionRequest.created_at.desc())
                .offset(offset)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return QuotaPermissionRequestListOut(
        total=int(total),
        items=[
            approval_request_to_out(r, account=account, mask_staff_ids=True)
            for r in rows
        ],
    )


@router.post(
    "",
    response_model=QuotaPermissionRequestOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_account_approval_request(
    account_id: str,
    request: Request,
    payload: QuotaPermissionRequestCreate = Body(...),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Submit a dedicated approval request to increase a quota or enable a permission."""
    account, role = await _ensure_account_member(account_id, user_id, db, request)
    if role not in ("owner", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="仅账户所有者或管理员可以提交配额与权限申请",
        )

    await enforce_approval_write_limit(user_id)

    # Check if there is already a pending request for the same target_key
    existing_pending = (
        await db.execute(
            select(QuotaPermissionRequest.id).where(
                QuotaPermissionRequest.account_id == account_id,
                QuotaPermissionRequest.target_key == payload.target_key,
                QuotaPermissionRequest.status == "pending",
            )
        )
    ).scalar_one_or_none()
    if existing_pending is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="该项已有待审批的申请，请等待管理员处理或先撤回后再提交",
        )

    # Limit total concurrent pending requests per account
    pending_count = (
        await db.execute(
            select(func.count(QuotaPermissionRequest.id)).where(
                QuotaPermissionRequest.account_id == account_id,
                QuotaPermissionRequest.status == "pending",
            )
        )
    ).scalar_one()
    if int(pending_count) >= 10:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="当前账户待审批申请数量已达上限（10 个）",
        )

    quotas = await get_quotas(account_id, db)
    quota_map = {q.quota_key: q.max_value for q in quotas}
    current_value = quota_map.get(
        payload.target_key, _DEFAULT_QUOTA_MAP.get(payload.target_key, 0)
    )

    resolved_value = validate_request_target_and_value(
        payload.request_type,
        payload.target_key,
        payload.requested_value,
        current_value,
    )

    now = datetime.now(timezone.utc)
    req = QuotaPermissionRequest(
        account_id=account_id,
        user_id=user_id,
        request_type=payload.request_type,
        target_key=payload.target_key,
        current_value=current_value,
        requested_value=resolved_value,
        approved_value=None,
        reason=payload.reason,
        status="pending",
        review_note="",
        reviewed_by=None,
        reviewed_at=None,
        created_at=now,
        updated_at=now,
    )
    db.add(req)
    await db.commit()
    await db.refresh(req)

    await publish_topic_event(
        "__admin__",
        "approval_request.created",
        {
            "id": req.id,
            "account_id": req.account_id,
            "request_type": req.request_type,
            "target_key": req.target_key,
        },
    )

    creator = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if creator is not None:
        await notify_superadmin_new_approval_request(
            creator,
            account.name,
            req.request_type,
            req.target_key,
            req.requested_value,
            req.reason,
            db,
        )

    return approval_request_to_out(req, account=account, mask_staff_ids=True)


@router.post("/{request_id}/cancel", response_model=QuotaPermissionRequestOut)
async def cancel_account_approval_request(
    account_id: str,
    request_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Cancel a pending quota/permission approval request."""
    account, role = await _ensure_account_member(account_id, user_id, db, request)
    if role not in ("owner", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="仅账户所有者或管理员可以撤回配额与权限申请",
        )
    if is_unsafe_request_id(request_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=_MSG_NOT_FOUND
        )

    req = (
        await db.execute(
            select(QuotaPermissionRequest).where(
                QuotaPermissionRequest.id == request_id,
                QuotaPermissionRequest.account_id == account_id,
            )
        )
    ).scalar_one_or_none()
    if not req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=_MSG_NOT_FOUND
        )
    if req.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="仅待审批状态的申请可以撤回",
        )

    req.status = "cancelled"
    req.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(req)

    await publish_topic_event(
        "__admin__",
        "approval_request.updated",
        {"id": req.id, "account_id": req.account_id, "status": req.status},
    )

    return approval_request_to_out(req, account=account, mask_staff_ids=True)
