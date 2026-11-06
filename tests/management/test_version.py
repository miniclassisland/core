"""Tests for the backend version endpoint."""

import pytest
from httpx import ASGITransport, AsyncClient

from app import __version__
from app.admin.app import admin_app
from app.management.app import management_app
from app.shared.security import auth


@pytest.mark.asyncio
async def test_version_endpoint(test_superadmin_user):
    """The version endpoint is authenticated and reports the package version."""
    headers = {
        "Authorization": f"Bearer {await auth.create_session_token(test_superadmin_user)}"
    }

    async with AsyncClient(
        transport=ASGITransport(app=management_app), base_url="http://test"
    ) as client:
        assert (await client.get("/version")).status_code == 401
        response = await client.get("/version", headers=headers)
        assert response.status_code == 200
        assert response.json() == {"version": __version__}

    async with AsyncClient(
        transport=ASGITransport(app=admin_app), base_url="http://admin-test"
    ) as client:
        assert (await client.get("/version")).status_code == 401
        response = await client.get("/version", headers=headers)
        assert response.status_code == 200
        assert response.json() == {"version": __version__}
