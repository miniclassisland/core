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

        # 3. Redeem using full DeepLink URI (also verify exchange_code alias compatibility)
        r_redeem = await client.post(
            "/token/certificate/redeem",
            json={"exchange_code": deeplink},
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

        # Request <= 1h session token using certificate (also test last_used_at update when >5s old)
        rd = get_redis(REDIS_DB_AUTH)
        await rd.hset(
            f"{_CERT_PREFIX}:{cert['cert_id']}", mapping={"last_used_at": "0"}
        )
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


@pytest.mark.asyncio
async def test_certificate_and_qr_login_edge_branches(test_superadmin_user):
    """Cover remaining edge branches in app/management/token.py, app/management/user.py, and app/shared/security/auth.py."""
    import os
    import time
    from collections import deque
    import pyotp
    from app.shared.db.models import User
    from app.shared.db.session import AsyncSessionLocal
    from app.shared.security import auth
    from app.shared.utils.config import REDIS_DB_AUTH
    from app.shared.utils.redis import get_redis

    # 1. Secret key env branch & stateless cert verification edge cases
    old_sk = os.environ.get("SECRET_KEY")
    os.environ["SECRET_KEY"] = "custom-test-secret-key-for-hmac"
    assert auth._get_cert_mac_key() == b"custom-test-secret-key-for-hmac"
    if old_sk is None:
        os.environ.pop("SECRET_KEY", None)
    else:
        os.environ["SECRET_KEY"] = old_sk

    assert auth._verify_cert_secret_stateless("", "sec") is False
    assert auth._verify_cert_secret_stateless("not-a-uuid", "sec") is False
    assert (
        auth._verify_cert_secret_stateless(
            "00000000-0000-0000-0000-000000000000", "bad-secret"
        )
        is False
    )

    # 2. Rate limiter table eviction & window cleanup for both cert and qr_poll
    auth._cert_ip_reqs.clear()
    now_m = time.monotonic()
    for i in range(4098):
        auth._cert_ip_reqs[f"10.10.{i // 256}.{i % 256}"] = deque([now_m - 100.0])
    assert auth.check_cert_ip_rate_limit("203.0.113.1") is True
    auth._cert_ip_reqs.clear()
    for i in range(4098):
        auth._cert_ip_reqs[f"10.11.{i // 256}.{i % 256}"] = deque([now_m])
    auth._cert_ip_reqs["203.0.113.2"] = deque([now_m - 100.0, now_m])
    assert auth.check_cert_ip_rate_limit("203.0.113.3") is True
    assert auth.check_cert_ip_rate_limit("203.0.113.2") is True
    auth._cert_ip_reqs.clear()

    auth._qr_poll_ip_reqs.clear()
    for i in range(4098):
        auth._qr_poll_ip_reqs[f"10.12.{i // 256}.{i % 256}"] = deque([now_m - 100.0])
    assert auth.check_qr_poll_ip_rate_limit("203.0.113.10") is True
    auth._qr_poll_ip_reqs.clear()
    for i in range(4098):
        auth._qr_poll_ip_reqs[f"10.13.{i // 256}.{i % 256}"] = deque([now_m])
    auth._qr_poll_ip_reqs["203.0.113.11"] = deque([now_m - 100.0, now_m])
    assert auth.check_qr_poll_ip_rate_limit("203.0.113.12") is True
    assert auth.check_qr_poll_ip_rate_limit("203.0.113.11") is True
    auth._qr_poll_ip_reqs["203.0.113.13"] = deque(
        [now_m] * auth._QR_POLL_IP_MAX_REQ_PER_WINDOW
    )
    assert auth.check_qr_poll_ip_rate_limit("203.0.113.13") is False
    auth._qr_poll_ip_reqs.clear()

    # 3. Direct Redis edge cases for redeem / verify / rotate / list / revoke / qr_login
    rd = get_redis(REDIS_DB_AUTH)
    assert await auth.redeem_certificate_exchange_code("bad") is None

    # Replay on exchange code (used > 1)
    ex_1 = await auth.issue_login_certificate_and_exchange_code(test_superadmin_user)
    await rd.hset(f"{auth._CERT_EXCHANGE_PREFIX}:{ex_1['code']}", mapping={"used": "1"})
    assert await auth.redeem_certificate_exchange_code(ex_1["code"]) is None

    # Missing cert_data on exchange code
    ex_2 = await auth.issue_login_certificate_and_exchange_code(test_superadmin_user)
    await rd.delete(f"{auth._CERT_PREFIX}:{ex_2['cert_id']}")
    assert await auth.redeem_certificate_exchange_code(ex_2["code"]) is None

    # Expired cert_data on exchange code
    ex_3 = await auth.issue_login_certificate_and_exchange_code(test_superadmin_user)
    await rd.hset(
        f"{auth._CERT_PREFIX}:{ex_3['cert_id']}", mapping={"expires_at": "100"}
    )
    assert await auth.redeem_certificate_exchange_code(ex_3["code"]) is None

    # Verify cert: expired, hash mismatch & auto-revoke on 5 failures
    ex_4 = await auth.issue_login_certificate_and_exchange_code(test_superadmin_user)
    c4 = await auth.redeem_certificate_exchange_code(ex_4["code"])
    assert c4 is not None
    await rd.hset(f"{auth._CERT_PREFIX}:{c4['cert_id']}", mapping={"expires_at": "100"})
    assert await auth.verify_login_certificate(c4["cert_id"], c4["cert_secret"]) is None

    ex_5 = await auth.issue_login_certificate_and_exchange_code(test_superadmin_user)
    c5 = await auth.redeem_certificate_exchange_code(ex_5["code"])
    assert c5 is not None
    await rd.hset(
        f"{auth._CERT_PREFIX}:{c5['cert_id']}",
        mapping={"secret_hash": "0" * 64, "fail_count": "4"},
    )
    assert await auth.verify_login_certificate(c5["cert_id"], c5["cert_secret"]) is None

    # Rotate cert error branches: stateless fail, missing in Redis, expired, secret_hash mismatch
    with pytest.raises(ValueError):
        await auth.rotate_login_certificate("bad-id", "bad-sec")

    ex_6 = await auth.issue_login_certificate_and_exchange_code(test_superadmin_user)
    c6 = await auth.redeem_certificate_exchange_code(ex_6["code"])
    assert c6 is not None
    await rd.hset(f"{auth._CERT_PREFIX}:{c6['cert_id']}", mapping={"expires_at": "100"})
    with pytest.raises(ValueError):
        await auth.rotate_login_certificate(c6["cert_id"], c6["cert_secret"])
    with pytest.raises(ValueError):
        await auth.rotate_login_certificate(c6["cert_id"], c6["cert_secret"])

    ex_7 = await auth.issue_login_certificate_and_exchange_code(test_superadmin_user)
    c7 = await auth.redeem_certificate_exchange_code(ex_7["code"])
    assert c7 is not None
    await rd.hset(
        f"{auth._CERT_PREFIX}:{c7['cert_id']}", mapping={"secret_hash": "0" * 64}
    )
    with pytest.raises(ValueError):
        await auth.rotate_login_certificate(c7["cert_id"], c7["cert_secret"])

    # List & revoke certificates edge cases
    await auth.revoke_all_user_certificates(test_superadmin_user)
    assert await auth.list_user_certificates(test_superadmin_user) == []

    ex_8 = await auth.issue_login_certificate_and_exchange_code(test_superadmin_user)
    await rd.hset(
        f"{auth._CERT_PREFIX}:{ex_8['cert_id']}", mapping={"expires_at": "100"}
    )
    await rd.sadd(f"{auth._USER_CERTS_PREFIX}:{test_superadmin_user}", "ghost-cert-id")
    assert await auth.list_user_certificates(test_superadmin_user) == []
    assert await auth.revoke_user_certificate(test_superadmin_user, "") is False
    assert (
        await auth.revoke_user_certificate(test_superadmin_user, "non-existent")
        is False
    )

    # QR login edge cases
    assert (
        await auth.authorize_qr_login_challenge("bad-code", test_superadmin_user)
        is False
    )
    valid_fmt_wrong_sig = f"{'a' * 43}.{'0' * 64}"
    assert (
        await auth.authorize_qr_login_challenge(
            valid_fmt_wrong_sig, test_superadmin_user
        )
        is False
    )
    assert await auth.poll_qr_login_challenge("bad-code") == {"status": "expired"}

    qr_exp = await auth.create_qr_login_challenge("127.0.0.1")
    await rd.hset(
        f"{auth._QR_LOGIN_PREFIX}:{qr_exp['code']}", mapping={"expires_at": "100"}
    )
    assert (
        await auth.authorize_qr_login_challenge(qr_exp["code"], test_superadmin_user)
        is False
    )

    qr_exp2 = await auth.create_qr_login_challenge("127.0.0.1")
    await rd.hset(
        f"{auth._QR_LOGIN_PREFIX}:{qr_exp2['code']}", mapping={"expires_at": "100"}
    )
    assert await auth.poll_qr_login_challenge(qr_exp2["code"]) == {"status": "expired"}

    qr_missing = await auth.create_qr_login_challenge("127.0.0.1")
    await rd.delete(f"{auth._QR_LOGIN_PREFIX}:{qr_missing['code']}")
    assert (
        await auth.authorize_qr_login_challenge(
            qr_missing["code"], test_superadmin_user
        )
        is False
    )

    # 4. HTTP endpoint edge cases in app/management/token.py and app/management/user.py
    sid = await auth.create_session_token(test_superadmin_user)
    headers = {"Authorization": f"Bearer {sid}"}
    transport = ASGITransport(app=management_app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Mint cache > 4096 clear branch
        ex_m = await auth.issue_login_certificate_and_exchange_code(
            test_superadmin_user
        )
        cm = await auth.redeem_certificate_exchange_code(ex_m["code"])
        assert cm is not None
        for i in range(4098):
            auth._cert_id_last_mint[f"cid-{i}"] = (0.0, "tok", 3600)
        r_m = await client.post(
            "/token/certificate/session",
            json={"cert_id": cm["cert_id"], "cert_secret": cm["cert_secret"]},
        )
        assert r_m.status_code == 200

        # Invalid rotate -> 401
        r_rot_401 = await client.post(
            "/token/certificate/rotate",
            json={"cert_id": cm["cert_id"], "cert_secret": "invalid"},
        )
        assert r_rot_401.status_code == 401

        # QR authorize via certificate & invalid QR authorize (401 and 400)
        qr_c = await auth.create_qr_login_challenge()
        r_qr_cert = await client.post(
            "/token/qr-login/authorize",
            json={
                "code": qr_c["code"],
                "cert_id": cm["cert_id"],
                "cert_secret": cm["cert_secret"],
            },
        )
        assert r_qr_cert.status_code == 200

        # Authorizing an already-authorized code -> 400
        r_qr_400 = await client.post(
            "/token/qr-login/authorize",
            headers=headers,
            json={"code": qr_c["code"]},
        )
        assert r_qr_400.status_code == 400

        # Authorizing without token or valid cert -> 401
        r_qr_401 = await client.post(
            "/token/qr-login/authorize",
            json={"code": qr_c["code"], "cert_id": "bad", "cert_secret": "bad"},
        )
        assert r_qr_401.status_code == 401

        # Rate limit 429 branches on redeem, rotate, qr-login/create, qr-login/poll, qr-login/authorize
        rl_ip = "198.51.100.250"
        rl_headers = {"X-Real-IP": rl_ip}
        auth._cert_ip_reqs[rl_ip] = deque([time.monotonic()] * 25)
        auth._qr_poll_ip_reqs[rl_ip] = deque([time.monotonic()] * 200)

        assert (
            await client.post(
                "/token/certificate/redeem", headers=rl_headers, json={"code": "x"}
            )
        ).status_code == 429
        assert (
            await client.post(
                "/token/certificate/rotate",
                headers=rl_headers,
                json={"cert_id": "x", "cert_secret": "y"},
            )
        ).status_code == 429
        assert (
            await client.post("/token/qr-login/create", headers=rl_headers)
        ).status_code == 429
        assert (
            await client.get("/token/qr-login/poll?code=x", headers=rl_headers)
        ).status_code == 429
        assert (
            await client.post(
                "/token/qr-login/authorize", headers=rl_headers, json={"code": "x"}
            )
        ).status_code == 429
        auth._cert_ip_reqs.clear()
        auth._qr_poll_ip_reqs.clear()

        # Revoke all & revoke non-existent (404)
        r_rev_all = await client.post(
            "/user/certificate/revoke",
            headers=headers,
            json={"revoke_all": True},
        )
        assert r_rev_all.status_code == 200
        r_rev_404 = await client.post(
            "/user/certificate/revoke",
            headers=headers,
            json={"cert_id": "non-existent-id"},
        )
        assert r_rev_404.status_code == 404

        # 2FA branches in /user/certificate/issue and banned user branch
        totp_sec = pyotp.random_base32()
        from app.shared.security.crypto import store_recovery_codes

        async with AsyncSessionLocal() as db:
            u = await db.get(User, test_superadmin_user)
            assert u is not None
            u.totp_enabled = True
            u.totp_secret = totp_sec
            await db.commit()
        await store_recovery_codes(test_superadmin_user, ["RECOV-1234"])

        # Missing 2FA code -> 400
        assert (
            await client.post(
                "/user/certificate/issue",
                headers=headers,
                json={"password": "SuperAdmin123!"},
            )
        ).status_code == 400

        # Invalid TOTP -> 401
        assert (
            await client.post(
                "/user/certificate/issue",
                headers=headers,
                json={"password": "SuperAdmin123!", "totp_code": "000000"},
            )
        ).status_code == 401

        # Valid TOTP -> 200
        valid_totp = pyotp.TOTP(totp_sec).now()
        assert (
            await client.post(
                "/user/certificate/issue",
                headers=headers,
                json={"password": "SuperAdmin123!", "totp_code": valid_totp},
            )
        ).status_code == 200

        # Invalid recovery code -> 401
        assert (
            await client.post(
                "/user/certificate/issue",
                headers=headers,
                json={"password": "SuperAdmin123!", "recovery_code": "WRONG-CODE"},
            )
        ).status_code == 401

        # Valid recovery code -> 200
        assert (
            await client.post(
                "/user/certificate/issue",
                headers=headers,
                json={"password": "SuperAdmin123!", "recovery_code": "RECOV-1234"},
            )
        ).status_code == 200

        # Inactive user -> 403 (both via endpoint and direct call)
        from app.management.user import CertificateIssueRequest, issue_login_certificate
        from fastapi import HTTPException

        async with AsyncSessionLocal() as db:
            u = await db.get(User, test_superadmin_user)
            assert u is not None
            u.is_active = False
            await db.commit()
            with pytest.raises(HTTPException) as exc_info:
                await issue_login_certificate(
                    CertificateIssueRequest(password="SuperAdmin123!"),
                    None,  # type: ignore[arg-type]
                    uid=test_superadmin_user,
                    db=db,
                )
            assert exc_info.value.status_code == 403
