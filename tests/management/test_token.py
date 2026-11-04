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

        # Refresh token (revokes old token sid and returns new_sid)
        r_ref = await client.post("/token/refresh", headers=headers)
        assert r_ref.status_code == 200
        new_sid = r_ref.json()["token"]
        assert await resolve_user_from_token(sid) is None
        assert await resolve_user_from_token(new_sid) == test_superadmin_user
        new_headers = {"Authorization": f"Bearer {new_sid}"}

        # Exchange & Redeem SSO code
        r_exch = await client.post("/token/exchange", headers=new_headers)
        assert r_exch.status_code == 200
        sso_code = r_exch.json()["code"]

        r_red_ok = await client.post("/token/redeem", json={"code": sso_code})
        assert r_red_ok.status_code == 200
        assert r_red_ok.json()["token"] == new_sid

        # Redeeming same code again or invalid code -> 401
        r_red_used = await client.post("/token/redeem", json={"code": sso_code})
        assert r_red_used.status_code == 401

        # Redeeming SSO code from mismatched IP -> 401
        r_exch_ip = await client.post(
            "/token/exchange",
            headers={**new_headers, "X-Real-IP": "203.0.113.10"},
        )
        sso_code_ip = r_exch_ip.json()["code"]
        r_red_bad_ip = await client.post(
            "/token/redeem",
            json={"code": sso_code_ip},
            headers={"X-Real-IP": "198.51.100.99"},
        )
        assert r_red_bad_ip.status_code == 401

        # Deactivate token
        r_deact = await client.post("/token/deactivate", headers=new_headers)
        assert r_deact.status_code == 200
        assert await resolve_user_from_token(new_sid) is None
