"""Shared support ticket serialization and abuse-control helpers."""

import logging
from datetime import datetime
from typing import Optional

from fastapi import HTTPException, status

from app.shared.db.models import Ticket, TicketMessage, User
from app.shared.schemas.schemas import TicketMessageOut, TicketOut
from app.shared.utils.config import REDIS_DB_AUTH
from app.shared.utils.redis import get_redis

logger = logging.getLogger(__name__)

TICKET_CREATE_LIMIT_PER_HOUR = 10
TICKET_REPLY_LIMIT_PER_HOUR = 60


def has_unsafe_control(value: str) -> bool:
    """Return True for control bytes that PostgreSQL text cannot store."""
    return any((ord(ch) < 32 and ch not in "\t\n\r") or ord(ch) == 127 for ch in value)


def is_unsafe_ticket_id(value: str) -> bool:
    """Reject malformed path identifiers before they reach the database."""
    return len(value) > 64 or has_unsafe_control(value)


async def enforce_ticket_write_limit(
    user_id: str,
    action: str,
    limit: int,
    window_seconds: int = 3600,
) -> None:
    """Apply a per-user fixed-window limit to ticket writes.

    The limiter fails open if Redis is unavailable so ticket access does not
    become dependent on a secondary service.
    """
    try:
        rd = get_redis(REDIS_DB_AUTH)
        key = f"ticket:rate:{action}:{user_id}"
        count = await rd.incr(key)
        if count == 1:
            await rd.expire(key, window_seconds)
        if count > limit:
            ttl = await rd.ttl(key)
            retry_after = ttl if isinstance(ttl, int) and ttl > 0 else window_seconds
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="工单操作过于频繁，请稍后再试",
                headers={"Retry-After": str(retry_after)},
            )
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover - Redis outage fallback
        logger.warning("Ticket rate limiter unavailable: %s", exc)


def iso(value: Optional[datetime]) -> Optional[str]:
    """Serialize an optional datetime for API responses."""
    return value.isoformat() if value else None


def user_summary(user: Optional[User]) -> Optional[dict]:
    """Return the user fields exposed to super administrators in ticket views."""
    if not user:
        return None
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "role_code": user.role_code,
        "is_active": bool(user.is_active),
    }


def ticket_to_out(
    ticket: Ticket,
    message_count: int = 0,
    user: Optional[User] = None,
    mask_staff_ids: bool = False,
) -> TicketOut:
    """Serialize a ticket for list and detail responses."""
    last_reply_by = ticket.last_reply_by
    if mask_staff_ids and last_reply_by and last_reply_by != ticket.user_id:
        last_reply_by = "admin"
    return TicketOut(
        id=ticket.id,
        user_id=ticket.user_id,
        subject=ticket.subject,
        category=ticket.category,
        priority=ticket.priority,
        status=ticket.status,
        created_at=iso(ticket.created_at) or "",
        updated_at=iso(ticket.updated_at) or "",
        last_reply_at=iso(ticket.last_reply_at),
        last_reply_by=last_reply_by,
        admin_unread=bool(ticket.admin_unread),
        user_unread=bool(ticket.user_unread),
        message_count=message_count,
        user=user_summary(user),
    )


def message_to_out(
    message: TicketMessage, mask_staff_ids: bool = False
) -> TicketMessageOut:
    """Serialize a ticket reply, optionally hiding staff account IDs."""
    author_id = message.author_id
    if mask_staff_ids and message.author_role == "admin":
        author_id = ""
    return TicketMessageOut(
        id=message.id,
        author_id=author_id,
        author_role=message.author_role,
        content=message.content,
        created_at=iso(message.created_at) or "",
    )
