"""Shared support ticket serialization helpers."""

from datetime import datetime
from typing import Optional

from app.shared.db.models import Ticket, TicketMessage, User
from app.shared.schemas.schemas import TicketMessageOut, TicketOut


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
) -> TicketOut:
    """Serialize a ticket for list and detail responses."""
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
        last_reply_by=ticket.last_reply_by,
        admin_unread=bool(ticket.admin_unread),
        user_unread=bool(ticket.user_unread),
        message_count=message_count,
        user=user_summary(user),
    )


def message_to_out(message: TicketMessage) -> TicketMessageOut:
    """Serialize a ticket reply."""
    return TicketMessageOut(
        id=message.id,
        author_id=message.author_id,
        author_role=message.author_role,
        content=message.content,
        created_at=iso(message.created_at) or "",
    )
