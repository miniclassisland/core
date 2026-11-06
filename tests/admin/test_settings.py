"""test_settings.py"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.admin import settings
from app.admin.app import admin_app
from app.shared.db.session import AsyncSessionLocal
from app.shared.security import auth
from app.shared.services.user import ensure_system_roles


def test_import():
    """Verify module import."""
    assert settings is not None


@pytest.mark.asyncio
async def test_admin_settings_endpoints(test_superadmin_user):
    """Test GET and POST /settings endpoints (both insert and update branches)."""
    async with AsyncSessionLocal() as db:
        await ensure_system_roles(db)

    sid = await auth.create_session_token(test_superadmin_user)
    headers = {"Authorization": f"Bearer {sid}"}

    transport = ASGITransport(app=admin_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Insert new settings
        r_post1 = await client.post(
            "/settings",
            json={
                "items": {
                    "announcement_title": "Welcome",
                    "motd": "Hello World",
                    "registration_open": "true",
                }
            },
            headers=headers,
        )
        assert r_post1.status_code == 200

        # Update existing setting
        r_post2 = await client.post(
            "/settings",
            json={
                "items": {
                    "announcement_title": "Updated announcement",
                    "motd": "Updated MOTD",
                }
            },
            headers=headers,
        )
        assert r_post2.status_code == 200

        # Get settings
        r_get = await client.get("/settings", headers=headers)
        assert r_get.status_code == 200
        data = r_get.json()
        assert data["announcement_title"] == "Updated announcement"
        assert data["motd"] == "Updated MOTD"
        assert data["registration_open"] == "true"
