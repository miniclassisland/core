"""Tests for the community join code administration endpoint."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.admin.app import admin_app
from app.shared.security import auth
from app.shared.utils.community import CODE_LENGTH


@pytest.mark.asyncio
async def test_admin_refresh_community_code(test_superadmin_user):
    """A super administrator can rotate the in-memory community code."""
    sid = await auth.create_session_token(test_superadmin_user)
    headers = {"Authorization": f"Bearer {sid}"}

    transport = ASGITransport(app=admin_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/community/refresh_code", headers=headers)
        assert r.status_code == 200
        assert len(r.json()["code"]) == CODE_LENGTH
