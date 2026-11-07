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


@pytest.mark.asyncio
async def test_login_security_certificate_lifecycle_and_flood_protection(
    test_superadmin_user,
):
    """Test Login Security Certificate issue, DeepLink redeem, <=1h session minting, <24h rotation (max 12 gens), and flood protection."""
    import time
    from app.shared.utils.config import REDIS_DB_AUTH
    from app.shared.utils.redis import get_redis
    from app.shared.security.auth import (
        _CERT_PREFIX,
        _cert_ip_reqs,
        _cert_id_last_mint,
    )

    _cert_ip_reqs.clear()
    _cert_id_last_mint.clear()

    sid = await create_session_token(test_superadmin_user)
    headers = {"Authorization": f"Bearer {sid}"}
    transport = ASGITransport(app=management_app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Wrong password rejected
        r_bad_pwd = await client.post(
            "/user/certificate/issue",
            headers=headers,
            json={"password": "WrongPassword123", "device_name": "Pixel 9"},
        )
        assert r_bad_pwd.status_code == 401

        # 2. Issue certificate with correct password ("SuperAdmin123!")
        r_issue = await client.post(
            "/user/certificate/issue",
            headers=headers,
            json={"password": "SuperAdmin123!", "device_name": "HarmonyOS Mate 60"},
        )
        assert r_issue.status_code == 200
        issue_data = r_issue.json()
        assert issue_data["expires_in"] == 300
        assert issue_data["generation"] == 0
        assert issue_data["max_generation"] == 12
        assert issue_data["deeplink"].startswith(
            "miniclassisland://exchange-certificate/"
        )
        deeplink = issue_data["deeplink"]

        # 3. Redeem using full DeepLink URI
        r_redeem = await client.post(
            "/token/certificate/redeem",
            json={"code": deeplink},
        )
        assert r_redeem.status_code == 200
        red_data = r_redeem.json()
        assert red_data["expires_in"] == 3600
        cert = red_data["certificate"]
        assert cert["generation"] == 0
        assert cert["max_generation"] == 12
        assert cert["device_name"] == "HarmonyOS Mate 60"
        assert await resolve_user_from_token(red_data["token"]) == test_superadmin_user

        # 4. Redeeming same exchange code a second time fails (single-use)
        r_redeem_again = await client.post(
            "/token/certificate/redeem",
            json={"code": issue_data["code"]},
        )
        assert r_redeem_again.status_code == 401

        # 5. Request <= 1h session token using certificate
        r_sess = await client.post(
            "/token/certificate/session",
            json={
                "cert_id": cert["cert_id"],
                "cert_secret": cert["cert_secret"],
                "ttl": 1800,
            },
        )
        assert r_sess.status_code == 200
        sess_data = r_sess.json()
        assert sess_data["expires_in"] == 1800
        assert sess_data["can_rotate"] is False
        assert await resolve_user_from_token(sess_data["token"]) == test_superadmin_user

        # Rapid duplicate session request within 2s returns cached token without minting new Redis session
        r_sess_dup = await client.post(
            "/token/certificate/session",
            json={
                "cert_id": cert["cert_id"],
                "cert_secret": cert["cert_secret"],
                "ttl": 1800,
            },
        )
        assert r_sess_dup.status_code == 200
        assert r_sess_dup.json()["token"] == sess_data["token"]

        # 6. Stateless pre-Redis MAC rejection for forged/random cert_secret
        r_forged = await client.post(
            "/token/certificate/session",
            json={
                "cert_id": cert["cert_id"],
                "cert_secret": "forged_random_secret_without_valid_hmac",
                "ttl": 3600,
            },
        )
        assert r_forged.status_code == 401

        # 7. Rotating before <24h remaining is rejected (400 Bad Request)
        r_rot_early = await client.post(
            "/token/certificate/rotate",
            json={
                "cert_id": cert["cert_id"],
                "cert_secret": cert["cert_secret"],
            },
        )
        assert r_rot_early.status_code == 400

        # 8. Fast-forward certificate expiry into <24h window and rotate up to generation 12
        rd = get_redis(REDIS_DB_AUTH)
        cur_cert = cert
        for expected_gen in range(1, 13):
            await rd.hset(
                f"{_CERT_PREFIX}:{cur_cert['cert_id']}",
                mapping={"expires_at": str(int(time.time()) + 3600)},
            )
            r_rot = await client.post(
                "/token/certificate/rotate",
                json={
                    "cert_id": cur_cert["cert_id"],
                    "cert_secret": cur_cert["cert_secret"],
                },
            )
            assert r_rot.status_code == 200
            rot_data = r_rot.json()
            assert rot_data["certificate"]["generation"] == expected_gen
            assert rot_data["certificate"]["family_id"] == cert["family_id"]
            # Old certificate is immediately invalidated
            r_old = await client.post(
                "/token/certificate/session",
                json={
                    "cert_id": cur_cert["cert_id"],
                    "cert_secret": cur_cert["cert_secret"],
                },
            )
            assert r_old.status_code == 401
            cur_cert = rot_data["certificate"]

        # 9. Generation 12 cannot rotate to generation 13 (403 Forbidden)
        await rd.hset(
            f"{_CERT_PREFIX}:{cur_cert['cert_id']}",
            mapping={"expires_at": str(int(time.time()) + 3600)},
        )
        r_rot_13 = await client.post(
            "/token/certificate/rotate",
            json={
                "cert_id": cur_cert["cert_id"],
                "cert_secret": cur_cert["cert_secret"],
            },
        )
        assert r_rot_13.status_code == 403

        # 10. List & Revoke certificates
        r_list = await client.get("/user/certificate/list", headers=headers)
        assert r_list.status_code == 200
        items = r_list.json()["items"]
        assert any(i["cert_id"] == cur_cert["cert_id"] for i in items)

        r_rev = await client.post(
            "/user/certificate/revoke",
            headers=headers,
            json={"cert_id": cur_cert["cert_id"]},
        )
        assert r_rev.status_code == 200

        # 11. Per-IP flood protection returns 429 when an external IP floods /token/certificate/session
        _cert_ip_reqs.clear()
        flood_headers = {"X-Real-IP": "198.51.100.77"}
        statuses = []
        for _ in range(25):
            resp = await client.post(
                "/token/certificate/session",
                headers=flood_headers,
                json={"cert_id": cur_cert["cert_id"], "cert_secret": "invalid"},
            )
            statuses.append(resp.status_code)
        assert 429 in statuses
        _cert_ip_reqs.clear()

        # 12. Reverse QR Code Web Login (Mobile -> Web)
        r_qr_create = await client.post("/token/qr-login/create")
        assert r_qr_create.status_code == 200
        qr_data = r_qr_create.json()
        assert qr_data["deeplink"].startswith("miniclassisland://qr-login/")

        r_qr_poll_1 = await client.get(f"/token/qr-login/poll?code={qr_data['code']}")
        assert r_qr_poll_1.status_code == 200
        assert r_qr_poll_1.json()["status"] == "pending"

        r_qr_auth = await client.post(
            "/token/qr-login/authorize",
            headers=headers,
            json={"code": qr_data["deeplink"]},
        )
        assert r_qr_auth.status_code == 200
        assert r_qr_auth.json()["authorized"] is True

        r_qr_poll_2 = await client.get(f"/token/qr-login/poll?code={qr_data['code']}")
        assert r_qr_poll_2.status_code == 200
        poll_2_data = r_qr_poll_2.json()
        assert poll_2_data["status"] == "authorized"
        assert (
            await resolve_user_from_token(poll_2_data["token"]) == test_superadmin_user
        )

        # Polling again after token consumption returns expired
        r_qr_poll_3 = await client.get(f"/token/qr-login/poll?code={qr_data['code']}")
        assert r_qr_poll_3.json()["status"] == "expired"
