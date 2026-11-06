"""Tests for user-facing support ticket endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.admin.app import admin_app
from app.management.app import management_app
from app.shared.db.session import AsyncSessionLocal
from app.shared.security import auth
from app.shared.services.user import register_user


async def _create_user(email: str, username: str) -> str:
    async with AsyncSessionLocal() as db:
        user = await register_user(
            email,
            "TicketPass123!",
            "Ticket User",
            db,
            username=username,
            role_code="normal",
            is_active=True,
        )
        await db.commit()
        return user.id


@pytest.mark.asyncio
async def test_management_ticket_lifecycle(test_superadmin_user):
    """Users can create, read, reply to, and close their own tickets."""
    owner_id = await _create_user("ticket_owner@school.com", "ticket_owner")
    other_id = await _create_user("ticket_other@school.com", "ticket_other")

    owner_headers = {
        "Authorization": f"Bearer {await auth.create_session_token(owner_id)}"
    }
    other_headers = {
        "Authorization": f"Bearer {await auth.create_session_token(other_id)}"
    }
    admin_headers = {
        "Authorization": f"Bearer {await auth.create_session_token(test_superadmin_user)}"
    }

    transport = ASGITransport(app=management_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        assert (await client.get("/ticket/list")).status_code == 401

        created = await client.post(
            "/ticket",
            json={
                "subject": "无法同步课表",
                "content": "客户端一直提示同步失败。",
                "category": "bug",
                "priority": "high",
            },
            headers=owner_headers,
        )
        assert created.status_code == 201, created.text
        ticket = created.json()
        ticket_id = ticket["id"]
        assert ticket["status"] == "open"
        assert ticket["category"] == "bug"
        assert ticket["priority"] == "high"
        assert ticket["messages"] == []

        listed = await client.get("/ticket/list", headers=owner_headers)
        assert listed.status_code == 200
        assert listed.json()["total"] == 1
        assert listed.json()["items"][0]["id"] == ticket_id

        assert (
            await client.get(f"/ticket/{ticket_id}", headers=other_headers)
        ).status_code == 404
        assert (
            await client.post(
                f"/ticket/{ticket_id}/reply",
                json={"content": "越权回复"},
                headers=other_headers,
            )
        ).status_code == 404

        reply = await client.post(
            f"/ticket/{ticket_id}/reply",
            json={"content": "补充：错误码是 500。"},
            headers=owner_headers,
        )
        assert reply.status_code == 201, reply.text
        assert reply.json()["author_role"] == "user"

        detail = await client.get(f"/ticket/{ticket_id}", headers=owner_headers)
        assert detail.status_code == 200
        body = detail.json()
        assert body["content"] == "客户端一直提示同步失败。"
        assert len(body["messages"]) == 1
        assert body["user_unread"] is False

        unread = await client.get("/ticket/unread-count", headers=owner_headers)
        assert unread.status_code == 200
        assert unread.json()["count"] == 0

        # A superadmin reply (Admin API) marks the ticket as unread for the user.
        async with AsyncClient(
            transport=ASGITransport(app=admin_app), base_url="http://admin-test"
        ) as admin_client:
            admin_reply = await admin_client.post(
                f"/ticket/{ticket_id}/reply",
                json={"content": "管理员正在排查。"},
                headers=admin_headers,
            )
        assert admin_reply.status_code == 201, admin_reply.text
        assert admin_reply.json()["author_role"] == "admin"

        unread = await client.get("/ticket/unread-count", headers=owner_headers)
        assert unread.json()["count"] == 1
        listed = await client.get("/ticket/list", headers=owner_headers)
        assert listed.json()["items"][0]["user_unread"] is True

        detail = await client.get(f"/ticket/{ticket_id}", headers=owner_headers)
        assert detail.json()["user_unread"] is False
        assert len(detail.json()["messages"]) == 2

        closed = await client.post(f"/ticket/{ticket_id}/close", headers=owner_headers)
        assert closed.status_code == 200
        assert (
            await client.post(
                f"/ticket/{ticket_id}/reply",
                json={"content": "关闭后回复"},
                headers=owner_headers,
            )
        ).status_code == 409

        closed_list = await client.get(
            "/ticket/list?status=closed", headers=owner_headers
        )
        assert closed_list.json()["total"] == 1
        assert closed_list.json()["items"][0]["status"] == "closed"


@pytest.mark.asyncio
async def test_management_ticket_validation(test_superadmin_user):
    """Invalid categories, priorities, and blank content are rejected."""
    owner_id = await _create_user("ticket_invalid@school.com", "ticket_invalid")
    headers = {"Authorization": f"Bearer {await auth.create_session_token(owner_id)}"}
    transport = ASGITransport(app=management_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        bad_category = await client.post(
            "/ticket",
            json={
                "subject": "标题",
                "content": "正文",
                "category": "not-a-category",
            },
            headers=headers,
        )
        assert bad_category.status_code == 422

        blank = await client.post(
            "/ticket",
            json={"subject": "标题", "content": "   "},
            headers=headers,
        )
        assert blank.status_code == 422

        assert (
            await client.get("/ticket/list?status=unknown", headers=headers)
        ).status_code == 400
