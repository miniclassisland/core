"""Tests for the site announcement endpoint."""

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from app.management.app import management_app
from app.shared.db.models import SystemConfig
from app.shared.db.session import AsyncSessionLocal
from app.shared.security import auth


@pytest.mark.asyncio
async def test_site_announcement_endpoint(test_superadmin_user):
    """Announcements require auth and are read from announcement_title + motd."""
    transport = ASGITransport(app=management_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r_anon = await client.get("/site/announcement")
        assert r_anon.status_code == 401

        sid = await auth.create_session_token(test_superadmin_user)
        headers = {"Authorization": f"Bearer {sid}"}

        r_empty = await client.get("/site/announcement", headers=headers)
        assert r_empty.status_code == 200
        assert r_empty.json() == {"title": "", "subtitle": ""}

        now = datetime.now(timezone.utc)
        async with AsyncSessionLocal() as db:
            db.add(
                SystemConfig(
                    key="announcement_title",
                    value="Site notice",
                    updated_at=now,
                )
            )
            db.add(SystemConfig(key="motd", value="Details", updated_at=now))
            await db.commit()

        r = await client.get("/site/announcement", headers=headers)
        assert r.status_code == 200
        assert r.json() == {"title": "Site notice", "subtitle": "Details"}
