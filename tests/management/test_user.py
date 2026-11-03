"""test_user.py"""

import pyotp
import pytest
from httpx import ASGITransport, AsyncClient

from app.management import user
from app.management.app import management_app
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import ReservedName
from app.shared.security.auth import create_session_token
from app.shared.services.user import approve_user


def test_import():
    """Verify module import."""
    assert user is not None


@pytest.mark.asyncio
async def test_management_user_endpoints():
    """Test user self-registration, availability checks, login, profile updates, and 2FA flows."""
    async with AsyncSessionLocal() as db:
        db.add(ReservedName(name="reserved_name"))
        await db.commit()

    transport = ASGITransport(app=management_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Self-registration (/user/apply)
        r_apply = await client.post(
            "/user/apply",
            json={
                "username": "mgmt_user",
                "email": "mgmt@school.com",
                "password": "MgmtPassword123!",
                "display_name": "Mgmt User",
            },
        )
        assert r_apply.status_code == 200

        # Duplicate registration -> 400
        r_apply_dup = await client.post(
            "/user/apply",
            json={
                "username": "mgmt_user2",
                "email": "mgmt@school.com",
                "password": "MgmtPassword123!",
                "display_name": "Mgmt User 2",
            },
        )
        assert r_apply_dup.status_code == 400

        # 2. Availability checks
        r_mail_taken = await client.get(
            "/user/availability/mail", params={"value": "mgmt@school.com"}
        )
        assert r_mail_taken.json()["available"] is False

        r_mail_free = await client.get(
            "/user/availability/mail", params={"value": "free@school.com"}
        )
        assert r_mail_free.json()["available"] is True

        r_u_bad = await client.get(
            "/user/availability/username", params={"value": "BAD FORMAT!"}
        )
        assert r_u_bad.json()["available"] is False

        r_u_res = await client.get(
            "/user/availability/username", params={"value": "reserved_name"}
        )
        assert r_u_res.json()["available"] is False

        r_u_taken = await client.get(
            "/user/availability/username", params={"value": "mgmt_user"}
        )
        assert r_u_taken.json()["available"] is False

        r_u_free = await client.get(
            "/user/availability/username", params={"value": "free_username"}
        )
        assert r_u_free.json()["available"] is True

        # 3. Login before approval -> 401
        r_login_pending = await client.post(
            "/user/auth",
            json={"email": "mgmt@school.com", "password": "MgmtPassword123!"},
        )
        assert r_login_pending.status_code == 401

        # Approve user in DB and create a second user to test conflict cases
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            from app.shared.db.models import User
            from app.shared.services.user import register_user

            u_obj = (
                await db.execute(select(User).where(User.email == "mgmt@school.com"))
            ).scalar_one()
            uid = u_obj.id
            await approve_user(uid, db)

            await register_user(
                "other@school.com",
                "OtherPass123!",
                "Other",
                db,
                username="other_user",
                role_code="normal",
                is_active=True,
            )

        # 4. Login after approval -> token
        r_login_ok = await client.post(
            "/user/auth",
            json={"email": "mgmt@school.com", "password": "MgmtPassword123!"},
        )
        assert r_login_ok.status_code == 200
        sid = r_login_ok.json()["token"]
        headers = {"Authorization": f"Bearer {sid}"}

        # 5. User profile info & updates
        r_info = await client.get("/user/info", headers=headers)
        assert r_info.status_code == 200
        assert r_info.json()["username"] == "mgmt_user"

        # Email update (conflict & success)
        r_em_dup = await client.post(
            "/user/info/email", json={"email": "other@school.com"}, headers=headers
        )
        assert r_em_dup.status_code == 400

        r_em_ok = await client.post(
            "/user/info/email", json={"email": "mgmt_new@school.com"}, headers=headers
        )
        assert r_em_ok.status_code == 200

        # Username update (invalid format, conflict, success)
        r_un_bad = await client.post(
            "/user/info/username", json={"username": "INVALID!"}, headers=headers
        )
        assert r_un_bad.status_code == 400

        r_un_dup = await client.post(
            "/user/info/username", json={"username": "other_user"}, headers=headers
        )
        assert r_un_dup.status_code == 400

        r_un_ok = await client.post(
            "/user/info/username", json={"username": "mgmt_user_new"}, headers=headers
        )
        assert r_un_ok.status_code == 200

        # Display name update
        r_dn = await client.post(
            "/user/info/display-name",
            json={"display_name": "New Display Name"},
            headers=headers,
        )
        assert r_dn.status_code == 200

        # Password change & reset
        r_pw_bad = await client.post(
            "/user/info/password/change",
            json={"old_password": "Wrong", "new_password": "NewMgmtPassword1!"},
            headers=headers,
        )
        assert r_pw_bad.status_code == 400

        r_pw_ok = await client.post(
            "/user/info/password/change",
            json={
                "old_password": "MgmtPassword123!",
                "new_password": "NewMgmtPassword1!",
            },
            headers=headers,
        )
        assert r_pw_ok.status_code == 200

        r_pw_rst = await client.post(
            "/user/info/password/reset",
            json={"new_password": "MgmtPassword123!"},
            headers=headers,
        )
        assert r_pw_rst.status_code == 200

        # 6. 2FA TOTP flow
        # Confirm before enable -> 400
        r_conf_early = await client.post(
            "/user/2fa/totp/confirm", json={"code": "123456"}, headers=headers
        )
        assert r_conf_early.status_code == 400

        # Enable 2FA
        r_en = await client.post("/user/2fa/totp/enable", headers=headers)
        assert r_en.status_code == 200
        secret = r_en.json()["secret"]
        recovery_codes = r_en.json()["recovery_codes"]

        # Confirm with wrong code -> 400
        r_conf_bad = await client.post(
            "/user/2fa/totp/confirm", json={"code": "000000"}, headers=headers
        )
        assert r_conf_bad.status_code == 400

        # Confirm with valid TOTP code -> 200
        valid_code = pyotp.TOTP(secret).now()
        r_conf_ok = await client.post(
            "/user/2fa/totp/confirm", json={"code": valid_code}, headers=headers
        )
        assert r_conf_ok.status_code == 200

        # Calling enable again when already enabled -> 400
        r_en_again = await client.post("/user/2fa/totp/enable", headers=headers)
        assert r_en_again.status_code == 400

        # Login with 2FA enabled -> requires_2fa + temp_token
        r_login_2fa = await client.post(
            "/user/auth",
            json={"email": "mgmt_new@school.com", "password": "MgmtPassword123!"},
        )
        assert r_login_2fa.status_code == 200
        assert r_login_2fa.json()["requires_2fa"] is True
        temp_token1 = r_login_2fa.json()["temp_token"]

        # Verify 2FA login with wrong code (consumes temp_token1) -> 401
        r_ver_bad = await client.post(
            "/user/2fa/totp/verify",
            json={"temp_token": temp_token1, "code": "000000"},
        )
        assert r_ver_bad.status_code == 401

        # Verify 2FA login with valid code -> 200
        r_login_2fa2 = await client.post(
            "/user/auth",
            json={"email": "mgmt_new@school.com", "password": "MgmtPassword123!"},
        )
        temp_token2 = r_login_2fa2.json()["temp_token"]
        r_ver_ok = await client.post(
            "/user/2fa/totp/verify",
            json={"temp_token": temp_token2, "code": pyotp.TOTP(secret).now()},
        )
        assert r_ver_ok.status_code == 200
        assert "token" in r_ver_ok.json()

        # Recover 2FA with invalid recovery code -> 401
        r_login_2fa3 = await client.post(
            "/user/auth",
            json={"email": "mgmt_new@school.com", "password": "MgmtPassword123!"},
        )
        temp_token3 = r_login_2fa3.json()["temp_token"]
        r_rec_bad = await client.post(
            "/user/2fa/totp/recover",
            json={"temp_token": temp_token3, "recovery_code": "INVALIDCODE"},
        )
        assert r_rec_bad.status_code == 401

        # Recover 2FA with valid recovery code -> 200
        r_login_2fa4 = await client.post(
            "/user/auth",
            json={"email": "mgmt_new@school.com", "password": "MgmtPassword123!"},
        )
        temp_token4 = r_login_2fa4.json()["temp_token"]
        r_rec_ok = await client.post(
            "/user/2fa/totp/recover",
            json={"temp_token": temp_token4, "recovery_code": recovery_codes[0]},
        )
        assert r_rec_ok.status_code == 200
        assert "token" in r_rec_ok.json()

        # Disable 2FA (wrong password -> 401, right password -> 200)
        r_dis_bad = await client.post(
            "/user/2fa/totp/disable",
            json={"password": "WrongPassword"},
            headers=headers,
        )
        assert r_dis_bad.status_code == 401

        r_dis_ok = await client.post(
            "/user/2fa/totp/disable",
            json={"password": "MgmtPassword123!"},
            headers=headers,
        )
        assert r_dis_ok.status_code == 200

        # 7. Ghost user (valid session token for deleted user) -> 404 branches
        ghost_sid = await create_session_token("ghost-user-id")
        ghost_headers = {"Authorization": f"Bearer {ghost_sid}"}
        assert (
            await client.get("/user/info", headers=ghost_headers)
        ).status_code == 404
        assert (
            await client.post(
                "/user/info/email",
                json={"email": "ghost@school.com"},
                headers=ghost_headers,
            )
        ).status_code == 404
        assert (
            await client.post(
                "/user/info/username",
                json={"username": "ghost_user"},
                headers=ghost_headers,
            )
        ).status_code == 404
        assert (
            await client.post(
                "/user/info/display-name",
                json={"display_name": "Ghost"},
                headers=ghost_headers,
            )
        ).status_code == 404
        assert (
            await client.post(
                "/user/info/password/change",
                json={"old_password": "a", "new_password": "NewPassword123!"},
                headers=ghost_headers,
            )
        ).status_code == 404
        assert (
            await client.post(
                "/user/info/password/reset",
                json={"new_password": "NewPassword123!"},
                headers=ghost_headers,
            )
        ).status_code == 404
