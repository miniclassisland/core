"""test_token.py"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.management import token
from app.management.app import management_app
from app.shared.security.auth import create_session_token, resolve_user_from_token


def test_import():
    """Verify module import."""
    assert token is not None


@pytest.mark.asyncio
async def test_management_token_endpoints(test_superadmin_user):
    """Test management_app root health check and /token/refresh, /token/verify, /token/deactivate."""
    sid = await create_session_token(test_superadmin_user)
    headers = {"Authorization": f"Bearer {sid}"}

    transport = ASGITransport(app=management_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Root health check
        r_root = await client.get("/")
        assert r_root.status_code == 200
        assert r_root.json()["status"] == "ok"

        # Verify token
        r_ver = await client.post("/token/verify", headers=headers)
        assert r_ver.status_code == 200
        assert r_ver.json()["user_id"] == test_superadmin_user

        # Refresh token
        r_ref = await client.post("/token/refresh", headers=headers)
        assert r_ref.status_code == 200
        new_sid = r_ref.json()["token"]
        assert await resolve_user_from_token(new_sid) == test_superadmin_user

        # Deactivate token
        r_deact = await client.post("/token/deactivate", headers=headers)
        assert r_deact.status_code == 200
        assert await resolve_user_from_token(sid) is None
