"""test_user.py"""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.admin import user
from app.admin.app import admin_app
from app.shared.db.models import User
from app.shared.db.session import AsyncSessionLocal
from app.shared.security import auth
from app.shared.services.user import ensure_system_roles


def test_import():
    """Verify module import."""
    assert user is not None


@pytest.mark.asyncio
async def test_admin_user_and_2fa_endpoints(test_superadmin_user):
    """Test admin user CRUD, rename, password reset/change, and 2FA enable/disable/reset."""
    async with AsyncSessionLocal() as db:
        await ensure_system_roles(db)

    sid = await auth.create_session_token(test_superadmin_user)
    headers = {"Authorization": f"Bearer {sid}"}

    transport = ASGITransport(app=admin_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Create user
        r_create = await client.post(
            "/user/create",
            json={
                "username": "teacher_a",
                "email": "teacher_a@school.com",
                "password": "TeacherPass123!",
                "display_name": "Teacher A",
                "role_code": "admin",
            },
            headers=headers,
        )
        assert r_create.status_code == 201
        u_data = r_create.json()
        uid = u_data["id"]
        assert u_data["can_create_account"] is True

        # Create duplicate email -> 400
        r_dup = await client.post(
            "/user/create",
            json={
                "username": "teacher_b",
                "email": "teacher_a@school.com",
                "password": "TeacherPass123!",
                "display_name": "Teacher B",
            },
            headers=headers,
        )
        assert r_dup.status_code == 400

        # 2. List & Search users
        r_list = await client.get("/user/list", headers=headers)
        assert r_list.status_code == 200
        assert any(u["id"] == uid for u in r_list.json())

        r_search = await client.get(
            "/user/search", params={"q": "teacher_a"}, headers=headers
        )
        assert r_search.status_code == 200
        assert len(r_search.json()) >= 1

        # 3. Get user & 404
        r_get = await client.get(f"/user/{uid}", headers=headers)
        assert r_get.status_code == 200
        assert r_get.json()["username"] == "teacher_a"

        assert (
            await client.get("/user/non-existent", headers=headers)
        ).status_code == 404

        # 4. Update user & 404 & self-demote/invalid-role checks
        r_self_demote = await client.post(
            f"/user/{test_superadmin_user}",
            json={"is_active": False},
            headers=headers,
        )
        assert r_self_demote.status_code == 400

        r_bad_role = await client.post(
            f"/user/{uid}",
            json={"role_code": "non_existent_role"},
            headers=headers,
        )
        assert r_bad_role.status_code == 400

        r_upd = await client.post(
            f"/user/{uid}",
            json={
                "display_name": "Teacher A Updated",
                "role_code": "normal",
                "is_active": False,
                "totp_enabled": True,
            },
            headers=headers,
        )
        assert r_upd.status_code == 200
        assert r_upd.json()["display_name"] == "Teacher A Updated"
        assert r_upd.json()["totp_enabled"] is True

        r_upd_disable_totp = await client.post(
            f"/user/{uid}",
            json={"totp_enabled": False},
            headers=headers,
        )
        assert r_upd_disable_totp.status_code == 200
        assert r_upd_disable_totp.json()["totp_enabled"] is False

        # Updating a user whose current username is a reserved internal name (e.g. "admin")
        # without changing their username must succeed without "Name is reserved by system"
        async with AsyncSessionLocal() as db:
            sa_user = (
                await db.execute(select(User).where(User.id == test_superadmin_user))
            ).scalar_one()
            sa_user.username = "admin"
            await db.commit()

        r_upd_self_reserved = await client.post(
            f"/user/{test_superadmin_user}",
            json={
                "username": "admin",
                "display_name": "Super Admin Updated",
                "role_code": "superadmin",
                "is_active": True,
            },
            headers=headers,
        )
        assert r_upd_self_reserved.status_code == 200
        assert r_upd_self_reserved.json()["display_name"] == "Super Admin Updated"

        r_ren_same_reserved = await client.post(
            f"/user/{test_superadmin_user}/rename",
            json={"name": "admin"},
            headers=headers,
        )
        assert r_ren_same_reserved.status_code == 200

        async with AsyncSessionLocal() as db:
            sa_user = (
                await db.execute(select(User).where(User.id == test_superadmin_user))
            ).scalar_one()
            sa_user.username = "superadmin_test"
            await db.commit()

        # Changing another user's username to a reserved name is still rejected
        r_upd_to_reserved = await client.post(
            f"/user/{uid}",
            json={"username": "system"},
            headers=headers,
        )
        assert r_upd_to_reserved.status_code == 400
        assert "reserved" in r_upd_to_reserved.json()["detail"].lower()

        assert (
            await client.post(
                "/user/non-existent", json={"display_name": "X"}, headers=headers
            )
        ).status_code == 404

        # 5. Rename user & validation & 404
        async with AsyncSessionLocal() as db:
            from app.shared.db.models import ReservedName

            db.add(ReservedName(name="reserved_admin_name"))
            await db.commit()

        assert (
            await client.post(
                f"/user/{uid}/rename", json={"name": "BAD FORMAT!"}, headers=headers
            )
        ).status_code == 400
        assert (
            await client.post(
                f"/user/{uid}/rename",
                json={"name": "reserved_admin_name"},
                headers=headers,
            )
        ).status_code == 400
        assert (
            await client.post(
                f"/user/{uid}/rename",
                json={"name": "superadmin_test"},
                headers=headers,
            )
        ).status_code == 400

        r_ren = await client.post(
            f"/user/{uid}/rename", json={"name": "teacher_a_renamed"}, headers=headers
        )
        assert r_ren.status_code == 200
        assert r_ren.json()["status"] == "renamed"

        assert (
            await client.post(
                "/user/non-existent/rename", json={"name": "x"}, headers=headers
            )
        ).status_code == 404

        # 6. Password reset & change
        r_pw_reset = await client.post(
            f"/user/{uid}/password/reset",
            json={"new_password": "NewPassword123!"},
            headers=headers,
        )
        assert r_pw_reset.status_code == 200

        assert (
            await client.post(
                "/user/non-existent/password/reset",
                json={"new_password": "NewPassword123!"},
                headers=headers,
            )
        ).status_code == 404

        r_pw_chg_bad = await client.post(
            f"/user/{uid}/password/change",
            json={
                "old_password": "WrongOldPassword",
                "new_password": "ChangedPassword123!",
            },
            headers=headers,
        )
        assert r_pw_chg_bad.status_code == 400

        r_pw_chg_ok = await client.post(
            f"/user/{uid}/password/change",
            json={
                "old_password": "NewPassword123!",
                "new_password": "ChangedPassword123!",
            },
            headers=headers,
        )
        assert r_pw_chg_ok.status_code == 200

        assert (
            await client.post(
                "/user/non-existent/password/change",
                json={
                    "old_password": "a",
                    "new_password": "ChangedPassword123!",
                },
                headers=headers,
            )
        ).status_code == 404

        # 7. 2FA enable, reset, disable & 404s
        r_2fa_en = await client.post(f"/user/{uid}/2fa/enable", headers=headers)
        assert r_2fa_en.status_code == 200
        assert "secret" in r_2fa_en.json()

        r_2fa_rst = await client.post(f"/user/{uid}/2fa/reset", headers=headers)
        assert r_2fa_rst.status_code == 200

        r_2fa_dis = await client.post(f"/user/{uid}/2fa/disable", headers=headers)
        assert r_2fa_dis.status_code == 200

        for action in ("enable", "reset", "disable"):
            assert (
                await client.post(f"/user/non-existent/2fa/{action}", headers=headers)
            ).status_code == 404

        # 8. Delete user, self-delete protection, /user/info non-shadowing & 404
        r_self_info = await client.get("/user/info", headers=headers)
        assert r_self_info.status_code == 200
        assert r_self_info.json()["id"] == test_superadmin_user

        assert (
            await client.delete(f"/user/{test_superadmin_user}", headers=headers)
        ).status_code == 400

        r_del = await client.delete(f"/user/{uid}", headers=headers)
        assert r_del.status_code == 200

        assert (
            await client.delete("/user/non-existent", headers=headers)
        ).status_code == 404
