"""Tests for super-administrator support ticket endpoints."""

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
async def test_admin_ticket_management(test_superadmin_user):
    """Superadmins can list, inspect, reply to, and update any ticket."""
    alice_id = await _create_user("ticket_alice@school.com", "ticket_alice")
    bob_id = await _create_user("ticket_bob@school.com", "ticket_bob")
    alice_headers = {
        "Authorization": f"Bearer {await auth.create_session_token(alice_id)}"
    }
    bob_headers = {"Authorization": f"Bearer {await auth.create_session_token(bob_id)}"}
    admin_headers = {
        "Authorization": f"Bearer {await auth.create_session_token(test_superadmin_user)}"
    }

    async with AsyncClient(
        transport=ASGITransport(app=management_app), base_url="http://test"
    ) as user_client:
        alice_ticket = (
            await user_client.post(
                "/ticket",
                json={
                    "subject": "登录后看不到客户端",
                    "content": "仪表盘为空。",
                    "category": "account",
                },
                headers=alice_headers,
            )
        ).json()
        bob_ticket = (
            await user_client.post(
                "/ticket",
                json={
                    "subject": "插件市场打不开",
                    "content": "一直转圈。",
                    "category": "client",
                    "priority": "high",
                },
                headers=bob_headers,
            )
        ).json()

    transport = ASGITransport(app=admin_app)
    async with AsyncClient(transport=transport, base_url="http://admin-test") as client:
        assert (await client.get("/ticket/list")).status_code == 401
        assert (
            await client.get("/ticket/list", headers=alice_headers)
        ).status_code == 403

        listed = await client.get("/ticket/list", headers=admin_headers)
        assert listed.status_code == 200, listed.text
        data = listed.json()
        assert data["total"] == 2
        assert {item["id"] for item in data["items"]} == {
            alice_ticket["id"],
            bob_ticket["id"],
        }
        assert all(item["user"]["username"] for item in data["items"])

        open_only = await client.get(
            "/ticket/list?status=open&priority=high", headers=admin_headers
        )
        assert open_only.json()["total"] == 1
        assert open_only.json()["items"][0]["id"] == bob_ticket["id"]

        searched = await client.get(
            "/ticket/list?q=ticket_alice", headers=admin_headers
        )
        assert searched.json()["total"] == 1
        assert searched.json()["items"][0]["id"] == alice_ticket["id"]

        unread = await client.get("/ticket/unread-count", headers=admin_headers)
        assert unread.json()["count"] == 2

        detail = await client.get(
            f"/ticket/{alice_ticket['id']}", headers=admin_headers
        )
        assert detail.status_code == 200
        assert detail.json()["admin_unread"] is False
        assert detail.json()["user"]["id"] == alice_id

        unread = await client.get("/ticket/unread-count", headers=admin_headers)
        assert unread.json()["count"] == 1

        reply = await client.post(
            f"/ticket/{alice_ticket['id']}/reply",
            json={"content": "请尝试重新登录后再查看。"},
            headers=admin_headers,
        )
        assert reply.status_code == 201, reply.text
        assert reply.json()["author_role"] == "admin"

        detail = await client.get(
            f"/ticket/{alice_ticket['id']}", headers=admin_headers
        )
        assert detail.json()["status"] == "in_progress"
        assert detail.json()["user_unread"] is True

        updated = await client.post(
            f"/ticket/{alice_ticket['id']}/status",
            json={"status": "resolved", "priority": "urgent"},
            headers=admin_headers,
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["status"] == "resolved"
        assert updated.json()["priority"] == "urgent"

        invalid = await client.post(
            f"/ticket/{alice_ticket['id']}/status",
            json={"status": "not-a-status"},
            headers=admin_headers,
        )
        assert invalid.status_code == 422

        empty = await client.post(
            f"/ticket/{alice_ticket['id']}/status",
            json={},
            headers=admin_headers,
        )
        assert empty.status_code == 400

        assert (
            await client.get("/ticket/does-not-exist", headers=admin_headers)
        ).status_code == 404
