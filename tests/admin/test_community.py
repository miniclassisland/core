"""Tests for the community join code administration endpoint."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.admin.app import admin_app
from app.shared.security import auth
from app.shared.utils import community
from app.shared.utils.community import CODE_LENGTH


@pytest.mark.asyncio
async def test_admin_refresh_community_code(
    test_superadmin_user, tmp_path, monkeypatch
):
    """A super administrator can rotate the in-memory community code."""
    monkeypatch.setattr(
        community,
        "_get_lifecycle_state_file",
        lambda: tmp_path / "nonexistent_lifecycle_state.json",
    )
    assert community._read_local_lifecycle_state() == {}

    sid = await auth.create_session_token(test_superadmin_user)
    headers = {"Authorization": f"Bearer {sid}"}

    transport = ASGITransport(app=admin_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/community/refresh_code", headers=headers)
        assert r.status_code == 200
        assert len(r.json()["code"]) == CODE_LENGTH
