"""Tests for the community join code endpoint."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.management.app import management_app
from app.shared.security import auth
from app.shared.utils.community import (
    CODE_CHARSET,
    CODE_LENGTH,
    CODE_SYMBOLS,
    get_community_code,
    refresh_community_code,
)


def test_community_code_shape():
    """The generated code has the requested length and character classes."""
    code = get_community_code()
    assert len(code) == CODE_LENGTH
    assert all(ch in CODE_CHARSET for ch in code)
    assert " " in code
    assert any(ch.isalpha() for ch in code)
    assert any(ch.isdigit() for ch in code)
    assert any(ch in CODE_SYMBOLS for ch in code)
    assert code[0] != " "
    assert code[-1] != " "


def test_refresh_community_code():
    """Refreshing returns a new valid in-memory code."""
    before = get_community_code()
    after = refresh_community_code()
    assert len(after) == CODE_LENGTH
    assert after != before


@pytest.mark.asyncio
async def test_community_code_endpoint(test_superadmin_user):
    """The code endpoint requires a session and rejects invalid Turnstile tokens."""
    transport = ASGITransport(app=management_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r_anon = await client.post("/community/code", json={})
        assert r_anon.status_code == 401

        sid = await auth.create_session_token(test_superadmin_user)
        headers = {"Authorization": f"Bearer {sid}"}

        r_ok = await client.post("/community/code", json={}, headers=headers)
        assert r_ok.status_code == 200
        assert len(r_ok.json()["code"]) == CODE_LENGTH

        r_bad = await client.post(
            "/community/code",
            json={"cf_turnstile_response": "INVALID_TURNSTILE_TOKEN"},
            headers=headers,
        )
        assert r_bad.status_code == 400
