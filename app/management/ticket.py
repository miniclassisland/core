"""User-facing support ticket endpoints."""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.models import Ticket, TicketMessage
from app.shared.db.session import get_db
from app.shared.literals import TICKET_STATUSES
from app.shared.schemas.schemas import (
    TicketCreate,
    TicketDetailOut,
    TicketListOut,
    TicketMessageOut,
    TicketReplyCreate,
)
from app.shared.security.auth import get_current_user_id
from app.shared.services.ticket import (
    TICKET_CREATE_LIMIT_PER_HOUR,
    TICKET_REPLY_LIMIT_PER_HOUR,
    enforce_ticket_write_limit,
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

_MSG_TICKET_NOT_FOUND = "工单不存在"


async def _get_own_ticket(db: AsyncSession, ticket_id: str, user_id: str) -> Ticket:
    if is_unsafe_ticket_id(ticket_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=_MSG_TICKET_NOT_FOUND
        )
    ticket = (
        await db.execute(
            select(Ticket).where(Ticket.id == ticket_id, Ticket.user_id == user_id)
        )
    ).scalar_one_or_none()
    if not ticket:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=_MSG_TICKET_NOT_FOUND
        )
    return ticket


@router.post("", response_model=TicketDetailOut, status_code=status.HTTP_201_CREATED)
async def create_ticket(
    payload: TicketCreate = Body(...),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Create a support ticket owned by the current user."""
    await enforce_ticket_write_limit(user_id, "create", TICKET_CREATE_LIMIT_PER_HOUR)
    now = datetime.now(timezone.utc)
    ticket = Ticket(
        user_id=user_id,
        subject=payload.subject,
        content=payload.content,
        category=payload.category,
        priority=payload.priority,
        status="open",
        created_at=now,
        updated_at=now,
        last_reply_at=None,
        last_reply_by="",
        admin_unread=True,
        user_unread=False,
    )
    db.add(ticket)
    await db.commit()
    await db.refresh(ticket)
    return TicketDetailOut(
        **ticket_to_out(ticket).model_dump(),
        content=ticket.content,
        messages=[],
    )


@router.get("/unread-count")
async def get_unread_count(
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Return the number of tickets with unread replies for the current user."""
    count = (
        await db.execute(
            select(func.count(Ticket.id)).where(
                Ticket.user_id == user_id,
                Ticket.user_unread.is_(True),
            )
        )
    ).scalar_one()
    return {"count": int(count)}


@router.get("/list", response_model=TicketListOut)
async def list_tickets(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    ticket_status: Optional[str] = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """List the current user's tickets, newest activity first."""
    filters = [Ticket.user_id == user_id]
    if ticket_status:
        normalized = ticket_status.strip().lower()
        if normalized not in TICKET_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="无效的工单状态",
            )
        filters.append(Ticket.status == normalized)

    total = (
        await db.execute(select(func.count(Ticket.id)).where(*filters))
    ).scalar_one()
    rows = (
        (
            await db.execute(
                select(Ticket)
                .where(*filters)
                .order_by(Ticket.updated_at.desc())
                .offset(offset)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )

    counts: dict[str, int] = {}
    if rows:
        count_rows = (
            await db.execute(
                select(TicketMessage.ticket_id, func.count(TicketMessage.id))
                .where(TicketMessage.ticket_id.in_([t.id for t in rows]))
                .group_by(TicketMessage.ticket_id)
            )
        ).all()
        counts = {ticket_id: int(count) for ticket_id, count in count_rows}

    return TicketListOut(
        total=int(total),
        items=[
            ticket_to_out(t, counts.get(t.id, 0), mask_staff_ids=True) for t in rows
        ],
    )


@router.get("/{ticket_id}", response_model=TicketDetailOut)
async def get_ticket(
    ticket_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Get one of the current user's tickets and mark its replies as read."""
    ticket = await _get_own_ticket(db, ticket_id, user_id)
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
    if ticket.user_unread:
        ticket.user_unread = False
        await db.commit()
        await db.refresh(ticket)

    return TicketDetailOut(
        **ticket_to_out(ticket, len(messages), mask_staff_ids=True).model_dump(),
        content=ticket.content,
        messages=[message_to_out(m, mask_staff_ids=True) for m in messages],
    )


@router.post("/{ticket_id}/reply", response_model=TicketMessageOut, status_code=201)
async def reply_to_ticket(
    ticket_id: str,
    payload: TicketReplyCreate = Body(...),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Append a user reply to an open ticket."""
    ticket = await _get_own_ticket(db, ticket_id, user_id)
    if ticket.status == "closed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="工单已关闭，无法继续回复"
        )
    await enforce_ticket_write_limit(user_id, "reply", TICKET_REPLY_LIMIT_PER_HOUR)

    now = datetime.now(timezone.utc)
    message = TicketMessage(
        ticket_id=ticket.id,
        author_id=user_id,
        author_role="user",
        content=payload.content,
        created_at=now,
    )
    db.add(message)
    if ticket.status == "resolved":
        ticket.status = "open"
    ticket.updated_at = now
    ticket.last_reply_at = now
    ticket.last_reply_by = user_id
    ticket.admin_unread = True
    ticket.user_unread = False
    await db.commit()
    await db.refresh(message)
    return message_to_out(message)


@router.post("/{ticket_id}/close")
async def close_ticket(
    ticket_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Close one of the current user's tickets."""
    ticket = await _get_own_ticket(db, ticket_id, user_id)
    if ticket.status != "closed":
        ticket.status = "closed"
        ticket.updated_at = datetime.now(timezone.utc)
        await db.commit()
    return {"status": "ok", "message": "工单已关闭"}
