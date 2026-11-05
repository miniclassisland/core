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
async def test_management_user_endpoints(test_superadmin_user):
    """Test user self-registration, availability checks, login, profile updates, and 2FA flows."""
    async with AsyncSessionLocal() as db:
        db.add(ReservedName(name="reserved_name"))
        await db.commit()

    transport = ASGITransport(app=management_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Self-registration (/user/apply): closed, open with approval, open without approval
        from datetime import datetime, timezone
        from sqlalchemy import delete
        from app.shared.db.models import SystemConfig

        async with AsyncSessionLocal() as db:
            db.add(
                SystemConfig(
                    key="registration_open",
                    value="false",
                    updated_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()

        r_apply_closed = await client.post(
            "/user/apply",
            json={
                "username": "mgmt_user",
                "email": "mgmt@school.com",
                "password": "MgmtPassword123!",
                "display_name": "Mgmt User",
            },
        )
        assert r_apply_closed.status_code == 403

        async with AsyncSessionLocal() as db:
            await db.execute(
                delete(SystemConfig).where(SystemConfig.key == "registration_open")
            )
            db.add_all(
                [
                    SystemConfig(
                        key="registration_open",
                        value="true",
                        updated_at=datetime.now(timezone.utc),
                    ),
                    SystemConfig(
                        key="require_approval",
                        value="false",
                        updated_at=datetime.now(timezone.utc),
                    ),
                ]
            )
            await db.commit()

        r_apply_auto = await client.post(
            "/user/apply",
            json={
                "username": "auto_user",
                "email": "auto@school.com",
                "password": "AutoPassword123!",
                "display_name": "Auto User",
            },
        )
        assert r_apply_auto.status_code == 200

        async with AsyncSessionLocal() as db:
            await db.execute(
                delete(SystemConfig).where(SystemConfig.key == "require_approval")
            )
            await db.commit()

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

        # Email update: regular user is forbidden (403), Super Admin is allowed
        r_em_forbidden = await client.post(
            "/user/info/email", json={"email": "mgmt_new@school.com"}, headers=headers
        )
        assert r_em_forbidden.status_code == 403

        sa_sid_early = await create_session_token(test_superadmin_user)
        sa_headers_early = {"Authorization": f"Bearer {sa_sid_early}"}
        r_em_dup = await client.post(
            "/user/info/email",
            json={"email": "other@school.com"},
            headers=sa_headers_early,
        )
        assert r_em_dup.status_code == 400

        r_em_ok = await client.post(
            "/user/info/email",
            json={"email": "superadmin_new@school.com"},
            headers=sa_headers_early,
        )
        assert r_em_ok.status_code == 200

        # Turnstile rejection test when invalid test token is sent
        r_ts_fail_login = await client.post(
            "/user/auth",
            json={
                "email": "mgmt@school.com",
                "password": "MgmtPassword123!",
                "cf_turnstile_response": "INVALID_TURNSTILE_TOKEN",
            },
        )
        assert r_ts_fail_login.status_code == 400

        r_ts_fail_reg = await client.post(
            "/user/apply",
            json={
                "username": "ts_fail_user",
                "email": "ts_fail@school.com",
                "password": "MgmtPassword123!",
                "display_name": "TS Fail",
                "cf_turnstile_response": "INVALID_TURNSTILE_TOKEN",
            },
        )
        assert r_ts_fail_reg.status_code == 400

        # Username update (invalid format, reserved, conflict, success)
        r_un_bad = await client.post(
            "/user/info/username", json={"username": "INVALID!"}, headers=headers
        )
        assert r_un_bad.status_code == 400

        r_un_res = await client.post(
            "/user/info/username", json={"username": "reserved_name"}, headers=headers
        )
        assert r_un_res.status_code == 400

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

        # Regular user calling /user/info/password/reset -> 403
        r_pw_rst_403 = await client.post(
            "/user/info/password/reset",
            json={"new_password": "MgmtPassword123!"},
            headers=headers,
        )
        assert r_pw_rst_403.status_code == 403

        # Change back using /user/info/password/change
        r_pw_back = await client.post(
            "/user/info/password/change",
            json={
                "old_password": "NewMgmtPassword1!",
                "new_password": "MgmtPassword123!",
            },
            headers=headers,
        )
        assert r_pw_back.status_code == 200

        # Superadmin calling /user/info/password/reset -> 200
        sa_sid = await create_session_token(test_superadmin_user)
        sa_headers = {"Authorization": f"Bearer {sa_sid}"}
        r_pw_rst = await client.post(
            "/user/info/password/reset",
            json={"new_password": "SuperAdmin123!"},
            headers=sa_headers,
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
        from app.shared.utils.redis import get_redis
        from app.shared.utils.config import REDIS_DB_AUTH

        valid_code = pyotp.TOTP(secret).now()
        r_conf_ok = await client.post(
            "/user/2fa/totp/confirm", json={"code": valid_code}, headers=headers
        )
        assert r_conf_ok.status_code == 200
        # Clear replay key in test so we can immediately test login verification in the same 30s window
        await get_redis(REDIS_DB_AUTH).delete(f"totp_used:{uid}:{valid_code}")

        # Calling enable again when already enabled -> 400
        r_en_again = await client.post("/user/2fa/totp/enable", headers=headers)
        assert r_en_again.status_code == 400

        # Login with 2FA enabled -> requires_2fa + temp_token
        r_login_2fa = await client.post(
            "/user/auth",
            json={"email": "mgmt@school.com", "password": "MgmtPassword123!"},
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
            json={"email": "mgmt@school.com", "password": "MgmtPassword123!"},
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
            json={"email": "mgmt@school.com", "password": "MgmtPassword123!"},
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
            json={"email": "mgmt@school.com", "password": "MgmtPassword123!"},
        )
        temp_token4 = r_login_2fa4.json()["temp_token"]
        r_rec_ok = await client.post(
            "/user/2fa/totp/recover",
            json={"temp_token": temp_token4, "recovery_code": recovery_codes[0]},
        )
        assert r_rec_ok.status_code == 200
        assert "token" in r_rec_ok.json()
        assert r_rec_ok.json()["remaining_recovery_codes"] == 7
        assert r_rec_ok.json()["require_totp_reset"] is False

        # Test second-to-last recovery code triggering require_totp_reset=True
        for idx in range(1, 6):
            r_login_tmp = await client.post(
                "/user/auth",
                json={"email": "mgmt@school.com", "password": "MgmtPassword123!"},
            )
            r_rec_tmp = await client.post(
                "/user/2fa/totp/recover",
                json={
                    "temp_token": r_login_tmp.json()["temp_token"],
                    "recovery_code": recovery_codes[idx],
                },
            )
            assert r_rec_tmp.status_code == 200

        # Now 2 recovery codes remain (index 6 and 7). Using index 6 (second-to-last) leaves 1 -> require_totp_reset=True
        r_login_second_last = await client.post(
            "/user/auth",
            json={"email": "mgmt@school.com", "password": "MgmtPassword123!"},
        )
        r_rec_second_last = await client.post(
            "/user/2fa/totp/recover",
            json={
                "temp_token": r_login_second_last.json()["temp_token"],
                "recovery_code": recovery_codes[6],
            },
        )
        assert r_rec_second_last.status_code == 200
        assert r_rec_second_last.json()["remaining_recovery_codes"] == 1
        assert r_rec_second_last.json()["require_totp_reset"] is True

        # Reset 2FA via /user/2fa/totp/enable?reset=true so we have fresh recovery codes
        r_en_reset = await client.post(
            "/user/2fa/totp/enable?reset=true", headers=headers
        )
        assert r_en_reset.status_code == 200
        secret = r_en_reset.json()["secret"]
        recovery_codes = r_en_reset.json()["recovery_codes"]
        valid_reset_code = pyotp.TOTP(secret).now()
        assert (
            await client.post(
                "/user/2fa/totp/confirm",
                json={"code": valid_reset_code},
                headers=headers,
            )
        ).status_code == 200
        await get_redis(REDIS_DB_AUTH).delete(f"totp_used:{uid}:{valid_reset_code}")

        # Disable 2FA: single factor only -> 400
        r_dis_single = await client.post(
            "/user/2fa/totp/disable",
            json={"password": "MgmtPassword123!"},
            headers=headers,
        )
        assert r_dis_single.status_code == 400

        # Disable 2FA: wrong password + recovery_code -> 401
        r_dis_bad = await client.post(
            "/user/2fa/totp/disable",
            json={"password": "WrongPassword", "recovery_code": recovery_codes[0]},
            headers=headers,
        )
        assert r_dis_bad.status_code == 401

        # Disable 2FA: password + invalid recovery_code -> 401
        r_dis_bad_rc = await client.post(
            "/user/2fa/totp/disable",
            json={"password": "MgmtPassword123!", "recovery_code": "INVALIDCODE"},
            headers=headers,
        )
        assert r_dis_bad_rc.status_code == 401

        # Disable 2FA: password + invalid totp_code -> 401
        r_dis_bad_totp = await client.post(
            "/user/2fa/totp/disable",
            json={"password": "MgmtPassword123!", "totp_code": "000000"},
            headers=headers,
        )
        assert r_dis_bad_totp.status_code == 401

        # Disable 2FA: two valid recovery codes -> 200
        r_dis_two_rc = await client.post(
            "/user/2fa/totp/disable",
            json={
                "recovery_code": recovery_codes[0],
                "second_recovery_code": recovery_codes[1],
                "recovery_codes": [recovery_codes[0], recovery_codes[1]],
            },
            headers=headers,
        )
        assert r_dis_two_rc.status_code == 200

        # Re-enable and test disable with password + totp_code -> 200
        r_en2 = await client.post("/user/2fa/totp/enable", headers=headers)
        secret2 = r_en2.json()["secret"]
        code2 = pyotp.TOTP(secret2).now()
        await client.post(
            "/user/2fa/totp/confirm", json={"code": code2}, headers=headers
        )
        await get_redis(REDIS_DB_AUTH).delete(f"totp_used:{uid}:{code2}")

        r_dis_ok = await client.post(
            "/user/2fa/totp/disable",
            json={
                "password": "MgmtPassword123!",
                "totp_code": pyotp.TOTP(secret2).now(),
            },
            headers=headers,
        )
        assert r_dis_ok.status_code == 200

        # 7. Ghost user (valid session token for deleted user) -> Middleware returns 403, direct endpoints raise 404
        ghost_sid = await create_session_token("ghost-user-id")
        ghost_headers = {"Authorization": f"Bearer {ghost_sid}"}
        assert (
            await client.get("/user/info", headers=ghost_headers)
        ).status_code == 403

        from unittest.mock import MagicMock
        from fastapi import HTTPException

        async with AsyncSessionLocal() as db:
            for coro in (
                user.get_user_info(db=db, user_id="ghost-user-id"),
                user.change_email(
                    body=user.EmailUpdate(email="ghost@school.com"),
                    db=db,
                    uid="ghost-user-id",
                ),
                user.change_username(
                    body=user.UsernameUpdate(username="ghost_user"),
                    db=db,
                    uid="ghost-user-id",
                ),
                user.change_display_name(
                    body=user.DisplayNameUpdate(display_name="Ghost"),
                    db=db,
                    uid="ghost-user-id",
                ),
                user.change_password(
                    body=user.PasswordChange(
                        old_password="a", new_password="NewPassword123!"
                    ),
                    request=MagicMock(),
                    db=db,
                    uid="ghost-user-id",
                ),
                user.reset_password(
                    request=MagicMock(),
                    body=user.PasswordReset(new_password="NewPassword123!"),
                    db=db,
                    uid="ghost-user-id",
                ),
            ):
                with pytest.raises(HTTPException) as exc_404:
                    await coro
                assert exc_404.value.status_code == 404
