"""test_bulk.py"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.management import bulk
from app.management.app import management_app
from app.shared.security.auth import create_session_token


def test_import():
    """Verify module import."""
    assert bulk is not None


@pytest.mark.asyncio
async def test_management_bulk_endpoint(test_superadmin_user):
    """Test POST /bulk on management_app."""
    sid = await create_session_token(test_superadmin_user)
    headers = {"Authorization": f"Bearer {sid}"}

    transport = ASGITransport(app=management_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r_bulk = await client.post(
            "/bulk",
            json={
                "operations": [
                    {
                        "action": "write",
                        "resource_type": "Subjects",
                        "name": "mgmt_sub",
                        "payload": {"Subjects": {}},
                    }
                ]
            },
            headers=headers,
        )
        assert r_bulk.status_code == 200
        assert r_bulk.json()["status"] == "success"
