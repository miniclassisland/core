"""Security regression tests for the support ticket APIs."""

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
async def test_ticket_idor_and_mass_assignment(test_superadmin_user):
    """Ticket ownership is enforced and request bodies cannot inject fields."""
    owner_id = await _create_user("sec_owner@school.com", "sec_owner")
    attacker_id = await _create_user("sec_attacker@school.com", "sec_attacker")
    owner_headers = {
        "Authorization": f"Bearer {await auth.create_session_token(owner_id)}"
    }
    attacker_headers = {
        "Authorization": f"Bearer {await auth.create_session_token(attacker_id)}"
    }
    admin_headers = {
        "Authorization": f"Bearer {await auth.create_session_token(test_superadmin_user)}"
    }

    async with AsyncClient(
        transport=ASGITransport(app=management_app), base_url="http://test"
    ) as client:
        created = await client.post(
            "/ticket",
            json={
                "subject": "安全测试工单",
                "content": "原始内容",
                "category": "other",
                "priority": "normal",
                # These fields must be ignored by the create schema.
                "user_id": attacker_id,
                "status": "closed",
                "admin_unread": False,
                "author_role": "admin",
            },
            headers=owner_headers,
        )
        assert created.status_code == 201, created.text
        ticket = created.json()
        ticket_id = ticket["id"]
        assert ticket["user_id"] == owner_id
        assert ticket["status"] == "open"
        assert ticket["admin_unread"] is True

        # Another user cannot read, reply to, or close the ticket.
        assert (
            await client.get(f"/ticket/{ticket_id}", headers=attacker_headers)
        ).status_code == 404
        assert (
            await client.post(
                f"/ticket/{ticket_id}/reply",
                json={"content": "越权回复"},
                headers=attacker_headers,
            )
        ).status_code == 404
        assert (
            await client.post(f"/ticket/{ticket_id}/close", headers=attacker_headers)
        ).status_code == 404

        # Reply body cannot forge the author or role.
        reply = await client.post(
            f"/ticket/{ticket_id}/reply",
            json={
                "content": "用户回复",
                "author_id": test_superadmin_user,
                "author_role": "admin",
            },
            headers=owner_headers,
        )
        assert reply.status_code == 201, reply.text
        assert reply.json()["author_id"] == owner_id
        assert reply.json()["author_role"] == "user"

    async with AsyncClient(
        transport=ASGITransport(app=admin_app), base_url="http://admin-test"
    ) as admin_client:
        admin_reply = await admin_client.post(
            f"/ticket/{ticket_id}/reply",
            json={"content": "管理员回复"},
            headers=admin_headers,
        )
        assert admin_reply.status_code == 201, admin_reply.text
        assert admin_reply.json()["author_id"] == test_superadmin_user

        admin_detail = await admin_client.get(
            f"/ticket/{ticket_id}", headers=admin_headers
        )
        assert admin_detail.status_code == 200
        admin_messages = admin_detail.json()["messages"]
        assert admin_messages[-1]["author_id"] == test_superadmin_user

    async with AsyncClient(
        transport=ASGITransport(app=management_app), base_url="http://test"
    ) as client:
        user_detail = await client.get(f"/ticket/{ticket_id}", headers=owner_headers)
        assert user_detail.status_code == 200
        payload = user_detail.json()
        assert payload["last_reply_by"] == "admin"
        assert payload["messages"][-1]["author_role"] == "admin"
        assert payload["messages"][-1]["author_id"] == ""


@pytest.mark.asyncio
async def test_ticket_injection_and_control_characters(test_superadmin_user):
    """SQL-like input, XSS text, and NUL bytes are handled without 500s."""
    owner_id = await _create_user("sec_input@school.com", "sec_input")
    headers = {"Authorization": f"Bearer {await auth.create_session_token(owner_id)}"}
    admin_headers = {
        "Authorization": f"Bearer {await auth.create_session_token(test_superadmin_user)}"
    }
    xss = "<script>alert('ticket-xss')</script>"
    sql = "'; DROP TABLE tickets; --"

    async with AsyncClient(
        transport=ASGITransport(app=management_app), base_url="http://test"
    ) as client:
        nul_create = await client.post(
            "/ticket",
            json={
                "subject": "NUL 测试",
                "content": "a\u0000b",
                "category": "other",
            },
            headers=headers,
        )
        assert nul_create.status_code == 422

        created = await client.post(
            "/ticket",
            json={
                "subject": f"XSS {xss}",
                "content": f"{xss}\n{sql}",
                "category": "bug",
                "priority": "high",
            },
            headers=headers,
        )
        assert created.status_code == 201, created.text
        ticket_id = created.json()["id"]
        assert created.headers["content-type"].startswith("application/json")
        assert created.headers["cache-control"] == "no-store"
        assert xss in created.json()["content"]
        assert sql in created.json()["content"]

        nul_reply = await client.post(
            f"/ticket/{ticket_id}/reply",
            json={"content": "bad\u0000reply"},
            headers=headers,
        )
        assert nul_reply.status_code == 422

        bad_status = await client.get(
            "/ticket/list?status=open%27%20OR%201%3D1--", headers=headers
        )
        assert bad_status.status_code == 400

        bad_id = await client.get("/ticket/%27%20OR%20%271%27%3D%271", headers=headers)
        assert bad_id.status_code == 404

        nul_id = await client.get("/ticket/bad%00id", headers=headers)
        assert nul_id.status_code in (400, 404)
        assert nul_id.status_code != 500

        # The table survives a SQL-like admin search.
        sql_probe = "nonexistent'; DROP TABLE tickets; --"
        async with AsyncClient(
            transport=ASGITransport(app=admin_app), base_url="http://admin-test"
        ) as admin_client:
            searched = await admin_client.get(
                f"/ticket/list?q={sql_probe}", headers=admin_headers
            )
            assert searched.status_code == 200
            assert searched.json()["total"] == 0
            nul_search = await admin_client.get(
                "/ticket/list?q=bad%00search", headers=admin_headers
            )
            assert nul_search.status_code == 400
            still_there = await admin_client.get(
                f"/ticket/{ticket_id}", headers=admin_headers
            )
            assert still_there.status_code == 200


@pytest.mark.asyncio
async def test_ticket_request_limits_and_methods(test_superadmin_user):
    """Oversized payloads and unsupported methods are rejected cleanly."""
    owner_id = await _create_user("sec_limits@school.com", "sec_limits")
    headers = {"Authorization": f"Bearer {await auth.create_session_token(owner_id)}"}

    async with AsyncClient(
        transport=ASGITransport(app=management_app), base_url="http://test"
    ) as client:
        oversized_subject = await client.post(
            "/ticket",
            json={
                "subject": "x" * 201,
                "content": "ok",
                "category": "other",
            },
            headers=headers,
        )
        assert oversized_subject.status_code == 422

        oversized_content = await client.post(
            "/ticket",
            json={
                "subject": "ok",
                "content": "x" * 5001,
                "category": "other",
            },
            headers=headers,
        )
        assert oversized_content.status_code == 422

        created = await client.post(
            "/ticket",
            json={
                "subject": "limit test",
                "content": "ok",
                "category": "other",
            },
            headers=headers,
        )
        ticket_id = created.json()["id"]

        oversized_reply = await client.post(
            f"/ticket/{ticket_id}/reply",
            json={"content": "x" * 5001},
            headers=headers,
        )
        assert oversized_reply.status_code == 422

        assert (
            await client.get("/ticket/list?offset=-1", headers=headers)
        ).status_code == 422
        assert (
            await client.get("/ticket/list?limit=0", headers=headers)
        ).status_code == 422
        assert (
            await client.get("/ticket/list?limit=201", headers=headers)
        ).status_code == 422

        # Huge but valid offsets return an empty page rather than an error.
        far_page = await client.get("/ticket/list?offset=1000000", headers=headers)
        assert far_page.status_code == 200
        assert far_page.json()["total"] == 1
        assert far_page.json()["items"] == []

        assert (
            await client.put("/ticket", json={}, headers=headers)
        ).status_code == 405
        assert (
            await client.delete(f"/ticket/{ticket_id}", headers=headers)
        ).status_code == 405


@pytest.mark.asyncio
async def test_ticket_create_rate_limit(test_superadmin_user):
    """A single user cannot flood the ticket table indefinitely."""
    owner_id = await _create_user("sec_spam@school.com", "sec_spam")
    headers = {"Authorization": f"Bearer {await auth.create_session_token(owner_id)}"}

    async with AsyncClient(
        transport=ASGITransport(app=management_app), base_url="http://test"
    ) as client:
        for index in range(10):
            response = await client.post(
                "/ticket",
                json={
                    "subject": f"rate limit {index}",
                    "content": "content",
                    "category": "other",
                },
                headers=headers,
            )
            assert response.status_code == 201, response.text

        blocked = await client.post(
            "/ticket",
            json={
                "subject": "rate limit blocked",
                "content": "content",
                "category": "other",
            },
            headers=headers,
        )
        assert blocked.status_code == 429
        assert int(blocked.headers["retry-after"]) > 0
        assert "过于频繁" in blocked.json()["detail"]
