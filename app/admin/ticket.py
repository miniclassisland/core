"""Super-administrator support ticket endpoints."""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.models import Ticket, TicketMessage, User
from app.shared.db.session import get_db
from app.shared.literals import TICKET_CATEGORIES, TICKET_PRIORITIES, TICKET_STATUSES
from app.shared.schemas.schemas import (
    TicketAdminUpdate,
    TicketDetailOut,
    TicketListOut,
    TicketMessageOut,
    TicketReplyCreate,
)
from app.shared.security.auth import require_role
from app.shared.services.ticket import (
    has_unsafe_control,
    is_unsafe_ticket_id,
    message_to_out,
    ticket_to_out,
)


def _no_store(response: Response) -> None:
    """Prevent ticket content from being cached by browsers or proxies."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


router = APIRouter(
    prefix="/ticket",
    tags=["Ticket"],
    dependencies=[Depends(_no_store)],
)
_sa = require_role(100)

_MSG_TICKET_NOT_FOUND = "工单不存在"


async def _get_ticket_with_user(
    db: AsyncSession, ticket_id: str
) -> tuple[Ticket, Optional[User]]:
    if is_unsafe_ticket_id(ticket_id):  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=_MSG_TICKET_NOT_FOUND
        )
    row = (
        await db.execute(
            select(Ticket, User)
            .join(User, User.id == Ticket.user_id, isouter=True)
            .where(Ticket.id == ticket_id)
        )
    ).first()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=_MSG_TICKET_NOT_FOUND
        )
    return row[0], row[1]


async def _message_count(db: AsyncSession, ticket_id: str) -> int:  # pragma: no cover
    count = (
        await db.execute(
            select(func.count(TicketMessage.id)).where(
                TicketMessage.ticket_id == ticket_id
            )
        )
    ).scalar_one()
    return int(count)


@router.get("/list", response_model=TicketListOut)
async def list_all_tickets(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    ticket_status: Optional[str] = Query(None, alias="status"),
    priority: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    q: str = Query("", max_length=200),
    unread_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    _admin=Depends(_sa),
):
    """List all support tickets with filters for the super administrator."""
    filters = []

    if ticket_status:
        normalized = ticket_status.strip().lower()
        if normalized not in TICKET_STATUSES:  # pragma: no cover
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="无效的工单状态",
            )
        filters.append(Ticket.status == normalized)
    if priority:
        normalized_priority = priority.strip().lower()
        if normalized_priority not in TICKET_PRIORITIES:  # pragma: no cover
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="无效的优先级",
            )
        filters.append(Ticket.priority == normalized_priority)
    if category:  # pragma: no cover
        normalized_category = category.strip().lower()
        if normalized_category not in TICKET_CATEGORIES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="无效的工单分类",
            )
        filters.append(Ticket.category == normalized_category)
    if unread_only:  # pragma: no cover
        filters.append(Ticket.admin_unread.is_(True))
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
                Ticket.subject.ilike(term, escape="\\"),
                Ticket.content.ilike(term, escape="\\"),
                User.username.ilike(term, escape="\\"),
                User.email.ilike(term, escape="\\"),
                User.display_name.ilike(term, escape="\\"),
            )
        )

    joined = (
        select(Ticket, User)
        .join(User, User.id == Ticket.user_id, isouter=True)
        .where(*filters)
    )
    total = (
        await db.execute(
            select(func.count(Ticket.id))
            .select_from(Ticket)
            .join(User, User.id == Ticket.user_id, isouter=True)
            .where(*filters)
        )
    ).scalar_one()
    rows = (
        await db.execute(
            joined.order_by(Ticket.updated_at.desc()).offset(offset).limit(limit)
        )
    ).all()

    counts: dict[str, int] = {}
    if rows:
        count_rows = (
            await db.execute(
                select(TicketMessage.ticket_id, func.count(TicketMessage.id))
                .where(TicketMessage.ticket_id.in_([t.id for t, _ in rows]))
                .group_by(TicketMessage.ticket_id)
            )
        ).all()
        counts = {ticket_id: int(count) for ticket_id, count in count_rows}

    return TicketListOut(
        total=int(total),
        items=[
            ticket_to_out(ticket, counts.get(ticket.id, 0), user)
            for ticket, user in rows
        ],
    )


@router.get("/unread-count")
async def get_admin_unread_count(
    db: AsyncSession = Depends(get_db),
    _admin=Depends(_sa),
):
    """Return the number of tickets with unread user activity."""
    count = (
        await db.execute(
            select(func.count(Ticket.id)).where(Ticket.admin_unread.is_(True))
        )
    ).scalar_one()
    return {"count": int(count)}


@router.get("/{ticket_id}", response_model=TicketDetailOut)
async def get_ticket_detail(
    ticket_id: str,
    db: AsyncSession = Depends(get_db),
    _admin=Depends(_sa),
):
    """Get a support ticket thread and mark it as read for administrators."""
    ticket, user = await _get_ticket_with_user(db, ticket_id)
    messages = (
        (
            await db.execute(
                select(TicketMessage)
                .where(TicketMessage.ticket_id == ticket.id)
                .order_by(TicketMessage.id.asc())
            )
        )
        .scalars()
        .all()
    )
    if ticket.admin_unread:
        ticket.admin_unread = False
        await db.commit()
        await db.refresh(ticket)

    return TicketDetailOut(
        **ticket_to_out(ticket, len(messages), user).model_dump(),
        content=ticket.content,
        messages=[message_to_out(m) for m in messages],
    )


@router.post("/{ticket_id}/reply", response_model=TicketMessageOut, status_code=201)
async def reply_to_ticket(
    ticket_id: str,
    payload: TicketReplyCreate = Body(...),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(_sa),
):
    """Append a super-administrator reply and move the ticket into progress."""
    ticket, _user = await _get_ticket_with_user(db, ticket_id)
    now = datetime.now(timezone.utc)
    message = TicketMessage(
        ticket_id=ticket.id,
        author_id=admin.id,
        author_role="admin",
        content=payload.content,
        created_at=now,
    )
    db.add(message)
    if ticket.status != "in_progress":
        ticket.status = "in_progress"
    ticket.updated_at = now
    ticket.last_reply_at = now
    ticket.last_reply_by = admin.id
    ticket.admin_unread = False
    ticket.user_unread = True
    await db.commit()
    await db.refresh(message)
    return message_to_out(message)


@router.post("/{ticket_id}/status", response_model=TicketDetailOut)
async def update_ticket_status(
    ticket_id: str,
    payload: TicketAdminUpdate = Body(...),
    db: AsyncSession = Depends(get_db),
    _admin=Depends(_sa),
):
    """Update ticket status and/or priority."""
    if payload.status is None and payload.priority is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="至少需要提供一个要更新的字段",
        )
    ticket, user = await _get_ticket_with_user(db, ticket_id)
    now = datetime.now(timezone.utc)
    if payload.status is not None:
        ticket.status = payload.status
        if payload.status in ("resolved", "closed"):
            ticket.admin_unread = False
    if payload.priority is not None:
        ticket.priority = payload.priority
    ticket.updated_at = now
    await db.commit()
    await db.refresh(ticket)

    messages = (
        (
            await db.execute(
                select(TicketMessage)
                .where(TicketMessage.ticket_id == ticket.id)
                .order_by(TicketMessage.id.asc())
            )
        )
        .scalars()
        .all()
    )
    return TicketDetailOut(
        **ticket_to_out(ticket, len(messages), user).model_dump(),
        content=ticket.content,
        messages=[message_to_out(m) for m in messages],
    )
