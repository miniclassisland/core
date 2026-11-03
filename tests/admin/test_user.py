"""test_user.py"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.admin import user
from app.admin.app import admin_app
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

        # 4. Update user & 404
        r_upd = await client.post(
            f"/user/{uid}",
            json={"display_name": "Teacher A Updated", "role_code": "normal"},
            headers=headers,
        )
        assert r_upd.status_code == 200
        assert r_upd.json()["display_name"] == "Teacher A Updated"

        assert (
            await client.post(
                "/user/non-existent", json={"display_name": "X"}, headers=headers
            )
        ).status_code == 404

        # 5. Rename user & 404
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

        # 8. Delete user & 404
        r_del = await client.delete(f"/user/{uid}", headers=headers)
        assert r_del.status_code == 200

        assert (
            await client.delete("/user/non-existent", headers=headers)
        ).status_code == 404
