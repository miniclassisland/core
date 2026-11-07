"""Tests for the per-user community join code and SnowLuma auto-approval integration."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.admin.app import admin_app
from app.management.app import management_app
from app.shared.db.models import User
from app.shared.db.session import AsyncSessionLocal
from app.shared.security import auth
from app.shared.services.user import approve_user, register_user
from app.shared.utils.community import (
    CODE_CHARSET,
    CODE_LENGTH,
    CODE_SYMBOLS,
    MSG_ALREADY_BOUND,
    MSG_CODE_PROMPT,
    get_active_user_for_code,
    get_community_code,
    issue_user_community_code,
    mask_qq_uin,
    poll_snowluma_group_requests_once,
    refresh_community_code,
    sync_group_member_bindings,
)
from app.shared.utils.config import (
    COMMUNITY_CODE_TTL_SECONDS,
    COMMUNITY_QQ_GROUP_ID,
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


def test_mask_qq_uin():
    """QQ masking produces 123****890 for 10-digit numbers and handles short/empty values."""
    assert mask_qq_uin("1234567890") == "123****890"
    assert mask_qq_uin("12345") == "12***45"
    assert mask_qq_uin(None) is None
    assert mask_qq_uin("") is None


@pytest.mark.asyncio
async def test_community_code_endpoint_and_snowluma_binding_flow(test_superadmin_user):
    """Per-user join code rotates on each request, expires in 15m, auto-approves in SnowLuma, and rejects once bound."""
    transport = ASGITransport(app=management_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r_anon = await client.post("/community/code", json={})
        assert r_anon.status_code == 401

        sid = await auth.create_session_token(test_superadmin_user)
        headers = {"Authorization": f"Bearer {sid}"}

        # 0. Check initial /community/status -> unbound
        r_status0 = await client.get("/community/status", headers=headers)
        assert r_status0.status_code == 200
        assert r_status0.json()["bound"] is False
        assert r_status0.json()["prompt"] == MSG_CODE_PROMPT

        # 1. First request generates a code bound to user with 15-minute TTL
        r1 = await client.post("/community/code", json={}, headers=headers)
        assert r1.status_code == 200
        data1 = r1.json()
        code1 = data1["code"]
        assert len(code1) == CODE_LENGTH
        assert data1["expires_in"] == COMMUNITY_CODE_TTL_SECONDS == 900
        assert data1["prompt"] == MSG_CODE_PROMPT
        assert await get_active_user_for_code(code1) == test_superadmin_user

        # 2. Second request generates a new code and immediately invalidates the old code
        r2 = await client.post("/community/code", json={}, headers=headers)
        assert r2.status_code == 200
        code2 = r2.json()["code"]
        assert len(code2) == CODE_LENGTH
        assert code2 != code1
        assert await get_active_user_for_code(code1) is None
        assert await get_active_user_for_code(code2) == test_superadmin_user

        # 3. Invalid Turnstile token is rejected
        r_bad = await client.post(
            "/community/code",
            json={"cf_turnstile_response": "INVALID_TURNSTILE_TOKEN"},
            headers=headers,
        )
        assert r_bad.status_code == 400

        # 4. Simulate SnowLuma pending group join requests:
        #    - First with invalidated code1 (should be ignored)
        #    - Second with active code2 (should be approved, bound, and private-messaged)
        onebot_calls: list[tuple[str, dict]] = []

        async def fake_onebot(action: str, params: dict):
            onebot_calls.append((action, params))
            if action == "get_group_system_msg":
                return {
                    "status": "ok",
                    "retcode": 0,
                    "data": [
                        {
                            "group_id": COMMUNITY_QQ_GROUP_ID,
                            "group_name": "This is MINI ClassIsland",
                            "request_id": 1001,
                            "requester_uin": 22222222,
                            "requester_nick": "OldCodeUser",
                            "invitor_uin": 0,
                            "invitor_nick": "",
                            "message": f"问题：请输入入群码\n答案：{code1}",
                            "checked": False,
                            "flag": "slreq:1:1001:1131427434:1:0",
                        },
                        {
                            "group_id": COMMUNITY_QQ_GROUP_ID,
                            "group_name": "This is MINI ClassIsland",
                            "request_id": 1002,
                            "requester_uin": 88888888,
                            "requester_nick": "ValidUser",
                            "invitor_uin": 0,
                            "invitor_nick": "",
                            "message": f"问题：请输入入群码\n答案：{code2}",
                            "checked": False,
                            "flag": "slreq:1:1002:1131427434:1:0",
                        },
                    ],
                }
            return {"status": "ok", "retcode": 0, "data": None}

        results = await poll_snowluma_group_requests_once(onebot_caller=fake_onebot)
        assert len(results) == 1
        res = results[0]
        assert res["handled"] is True
        assert res["approved"] is True
        assert res["private_sent"] is True
        assert res["user_id"] == test_superadmin_user
        assert res["qq_uin"] == "88888888"
        assert (
            res["message"]
            == "欢迎 Super Admin Test (superadmin_test) 加入交流群，您的 QQ 88888888 已自动绑定。如需解绑，请直接退出群聊或者联系运维"
        )

        # Verify OneBot actions called:
        # 1) get_group_system_msg
        # 2) set_group_add_request (reject invalid code1 with reason="无效的验证码")
        # 3) set_group_add_request (approve valid code2)
        # 4) send_private_msg
        actions = [a for a, _ in onebot_calls]
        assert actions == [
            "get_group_system_msg",
            "set_group_add_request",
            "set_group_add_request",
            "send_private_msg",
        ]
        assert onebot_calls[1][1] == {
            "flag": "slreq:1:1001:1131427434:1:0",
            "sub_type": "add",
            "approve": False,
            "reason": "无效的验证码",
        }
        assert onebot_calls[2][1] == {
            "flag": "slreq:1:1002:1131427434:1:0",
            "sub_type": "add",
            "approve": True,
        }
        assert onebot_calls[3][1] == {
            "user_id": 88888888,
            "message": "欢迎 Super Admin Test (superadmin_test) 加入交流群，您的 QQ 88888888 已自动绑定。如需解绑，请直接退出群聊或者联系运维",
        }

        # Code2 is now consumed/invalidated
        assert await get_active_user_for_code(code2) is None

        # 5. Once bound, requesting another join code is rejected by the backend (HTTP 403)
        r_bound = await client.post("/community/code", json={}, headers=headers)
        assert r_bound.status_code == 403
        assert r_bound.json()["detail"] == MSG_ALREADY_BOUND

        # 6. /community/status and /user/info show masked QQ
        r_status1 = await client.get("/community/status", headers=headers)
        assert r_status1.status_code == 200
        assert r_status1.json()["bound"] is True
        assert r_status1.json()["qq_masked"] == "888****888"
        assert r_status1.json()["prompt"] == MSG_ALREADY_BOUND

        r_uinfo = await client.get("/user/info", headers=headers)
        assert r_uinfo.status_code == 200
        assert r_uinfo.json()["bound_qq_masked"] == "888****888"

        # 7. Simulate member leaving the group -> auto-unbind -> can request code again
        async def fake_member_list_left(action: str, params: dict):
            if action == "get_group_member_list":
                return {
                    "status": "ok",
                    "retcode": 0,
                    "data": [
                        {"user_id": 1480708359}
                    ],  # 88888888 is no longer in the group
                }
            return {"status": "ok", "retcode": 0, "data": None}

        async with AsyncSessionLocal() as db:
            unbound_count = await sync_group_member_bindings(
                db, onebot_caller=fake_member_list_left
            )
            assert unbound_count == 1

        r_reissue = await client.post("/community/code", json={}, headers=headers)
        assert r_reissue.status_code == 200
        assert len(r_reissue.json()["code"]) == CODE_LENGTH


@pytest.mark.asyncio
async def test_pending_user_forced_viewer_and_admin_manual_qq_bind_rebind_unbind_ban(
    test_superadmin_user,
):
    """Test pending user login/forced viewer role, admin manual bind/rebind/unbind, and ban kick sync."""
    mgmt_transport = ASGITransport(app=management_app)
    admin_transport = ASGITransport(app=admin_app)

    sa_sid = await auth.create_session_token(test_superadmin_user)
    sa_headers = {"Authorization": f"Bearer {sa_sid}"}

    async with (
        AsyncClient(transport=mgmt_transport, base_url="http://test") as mgmt_client,
        AsyncClient(transport=admin_transport, base_url="http://test") as admin_client,
    ):
        # 1. Super admin creates an organization account and an admin-role invitation
        r_acct = await mgmt_client.post(
            "/account/apply",
            json={"name": "Test Org"},
            headers=sa_headers,
        )
        assert r_acct.status_code == 201
        acct_id = r_acct.json()["id"]

        r_inv = await mgmt_client.post(
            f"/account/{acct_id}/invitation/create",
            json={"role_in_account": "admin", "max_uses": 5},
            headers=sa_headers,
        )
        assert r_inv.status_code == 201
        inv_code = r_inv.json()["code"]

        # 2. Register a pending user (no default tenant created)
        async with AsyncSessionLocal() as db:
            pending_user = await register_user(
                "pending_member@school.com",
                "PendingPass123!",
                "Pending Member",
                db,
                username="pending_member",
                role_code="pending",
                is_active=False,
                create_default_account=False,
            )
            pending_uid = pending_user.id

        # Pending user logs in
        r_login = await mgmt_client.post(
            "/user/auth",
            json={
                "email": "pending_member@school.com",
                "password": "PendingPass123!",
            },
        )
        assert r_login.status_code == 200
        p_headers = {"Authorization": f"Bearer {r_login.json()['token']}"}

        # Pending user has 0 accounts initially and can get a join code
        r_p_accts = await mgmt_client.get("/account/list", headers=p_headers)
        assert r_p_accts.status_code == 200
        assert r_p_accts.json() == []

        r_p_code = await mgmt_client.post("/community/code", json={}, headers=p_headers)
        assert r_p_code.status_code == 200

        # Pending user accepts the "admin" invitation -> forced to "viewer"!
        r_accept = await mgmt_client.post(
            "/account/invitation/accept",
            json={"code": inv_code},
            headers=p_headers,
        )
        assert r_accept.status_code == 200
        assert r_accept.json()["role_in_account"] == "viewer"

        # Account owner tries to promote pending user to "admin" before approval -> 403 Forbidden!
        r_promote_fail = await mgmt_client.post(
            f"/account/{acct_id}/access/{pending_uid}",
            json={"role_in_account": "admin"},
            headers=sa_headers,
        )
        assert r_promote_fail.status_code == 403

        # Approve the user -> now account owner CAN promote them to "admin"
        async with AsyncSessionLocal() as db:
            await approve_user(pending_uid, db)

        r_promote_ok = await mgmt_client.post(
            f"/account/{acct_id}/access/{pending_uid}",
            json={"role_in_account": "admin"},
            headers=sa_headers,
        )
        assert r_promote_ok.status_code == 200
        assert r_promote_ok.json()["role_in_account"] == "admin"

        # 3. Super Admin manually binds pending_uid to QQ 1234567890
        r_bind = await admin_client.post(
            f"/user/{pending_uid}/qq/bind",
            json={"qq_uin": "1234567890"},
            headers=sa_headers,
        )
        assert r_bind.status_code == 200
        assert r_bind.json()["bound_qq"] == "1234567890"
        assert r_bind.json()["bound_qq_masked"] == "123****890"
        assert r_bind.json()["qq_bound_manual"] is True
        assert r_bind.json()["qq_joined_group"] is False

        # User checks /community/status -> sees manual bound prompt with 123****890
        r_st_manual = await mgmt_client.get("/community/status", headers=p_headers)
        assert r_st_manual.status_code == 200
        assert (
            r_st_manual.json()["prompt"]
            == "管理员已经将您的用户绑定到了 QQ（123****890），您可以直接使用这个号码加入群聊"
        )
        # User tries to get a join code -> 403 with manual bound prompt
        r_code_manual = await mgmt_client.post(
            "/community/code", json={}, headers=p_headers
        )
        assert r_code_manual.status_code == 403
        assert (
            r_code_manual.json()["detail"]
            == "管理员已经将您的用户绑定到了 QQ（123****890），您可以直接使用这个号码加入群聊"
        )

        # 4. Manually bound user applies to join QQ group with arbitrary password -> auto-approved!
        manual_calls: list[tuple[str, dict]] = []

        async def fake_manual_join(action: str, params: dict):
            manual_calls.append((action, params))
            if action == "get_group_system_msg":
                return {
                    "status": "ok",
                    "retcode": 0,
                    "data": [
                        {
                            "group_id": COMMUNITY_QQ_GROUP_ID,
                            "request_id": 2001,
                            "requester_uin": 1234567890,
                            "message": "随便填的密码123",
                            "checked": False,
                            "flag": "slreq:1:2001:1131427434:1:0",
                        }
                    ],
                }
            return {"status": "ok", "retcode": 0, "data": None}

        join_res = await poll_snowluma_group_requests_once(
            onebot_caller=fake_manual_join
        )
        assert len(join_res) == 1
        assert join_res[0]["approved"] is True
        assert (
            join_res[0]["message"]
            == "欢迎 Pending Member (pending_member) 加入交流群，您的 QQ 1234567890 已自动绑定。如需解绑，请直接退出群聊或者联系运维"
        )

        # 5. Super Admin rebinds (换绑) to 9876543210 (already in group!) -> bot sends unbind PM and kicks old QQ 1234567890, and sends manual bind PM to 9876543210
        from app.shared.utils.community import (
            admin_bind_or_rebind_user_qq,
            admin_unbind_user_qq,
            handle_user_banned_in_community,
        )

        rebind_calls: list[tuple[str, dict]] = []

        async def fake_rebind_onebot(action: str, params: dict):
            rebind_calls.append((action, params))
            if action == "get_group_member_list":
                return {
                    "status": "ok",
                    "retcode": 0,
                    "data": [{"user_id": 9876543210}],
                }
            return {"status": "ok", "retcode": 0, "data": []}

        async with AsyncSessionLocal() as db:
            u_obj = (
                await db.execute(select(User).where(User.id == pending_uid))
            ).scalar_one()
            await admin_bind_or_rebind_user_qq(
                u_obj, "9876543210", db, onebot_caller=fake_rebind_onebot
            )

        assert (
            "send_private_msg",
            {
                "user_id": 1234567890,
                "message": "管理员已将您的 QQ 1234567890 与 Pending Member (pending_member) 解绑",
                "auto_escape": True,
            },
        ) in rebind_calls
        assert (
            "set_group_kick",
            {
                "group_id": COMMUNITY_QQ_GROUP_ID,
                "user_id": 1234567890,
                "reject_add_request": False,
            },
        ) in rebind_calls
        assert (
            "send_private_msg",
            {
                "user_id": 9876543210,
                "message": "管理员已将您的 QQ 9876543210 与 Pending Member (pending_member) 绑定",
                "auto_escape": True,
            },
        ) in rebind_calls

        # 6. Super Admin unbinds (解绑) -> bot sends unbind PM and kicks 9876543210
        unbind_calls: list[tuple[str, dict]] = []

        async def fake_unbind_onebot(action: str, params: dict):
            unbind_calls.append((action, params))
            return {"status": "ok", "retcode": 0, "data": None}

        async with AsyncSessionLocal() as db:
            u_obj = (
                await db.execute(select(User).where(User.id == pending_uid))
            ).scalar_one()
            ok = await admin_unbind_user_qq(u_obj, db, onebot_caller=fake_unbind_onebot)
            assert ok is True

        assert [a for a, _ in unbind_calls] == ["send_private_msg", "set_group_kick"]
        assert (
            unbind_calls[0][1]["message"]
            == "管理员已将您的 QQ 9876543210 与 Pending Member (pending_member) 解绑"
        )
        assert unbind_calls[1][1]["user_id"] == 9876543210

        # 7. Re-bind and then ban user -> bot sends ban PM "您（Pending Member）已被封禁" and kicks from group
        ban_calls: list[tuple[str, dict]] = []

        async def fake_ban_onebot(action: str, params: dict):
            ban_calls.append((action, params))
            return {"status": "ok", "retcode": 0, "data": []}

        async with AsyncSessionLocal() as db:
            u_obj = (
                await db.execute(select(User).where(User.id == pending_uid))
            ).scalar_one()
            await admin_bind_or_rebind_user_qq(
                u_obj, "555666777", db, onebot_caller=fake_ban_onebot
            )
            ban_calls.clear()
            u_obj.role_code = "banned"
            await db.commit()
            kicked = await handle_user_banned_in_community(
                u_obj, db, onebot_caller=fake_ban_onebot
            )
            assert kicked is True

        assert [a for a, _ in ban_calls] == ["send_private_msg", "set_group_kick"]
        assert ban_calls[0][1]["message"] == "您（Pending Member）已被封禁"
        assert ban_calls[1][1]["user_id"] == 555666777


@pytest.mark.asyncio
async def test_community_code_ttl_expiration(test_superadmin_user):
    """Expired join codes are automatically pruned and rejected."""
    async with AsyncSessionLocal() as db:
        code, _ = await issue_user_community_code(
            test_superadmin_user, db, ttl_seconds=-1
        )
    assert await get_active_user_for_code(code) is None


@pytest.mark.asyncio
async def test_snowluma_zero_requester_uin_resolution(test_superadmin_user):
    """When SnowLuma returns requester_uin=0, approval still succeeds and resolves UIN via member list diff."""
    async with AsyncSessionLocal() as db:
        code, _ = await issue_user_community_code(test_superadmin_user, db)

    member_list_call_count = 0
    onebot_calls: list[tuple[str, dict]] = []

    async def fake_zero_uin_onebot(action: str, params: dict):
        nonlocal member_list_call_count
        onebot_calls.append((action, params))
        if action == "get_group_system_msg":
            return {
                "status": "ok",
                "retcode": 0,
                "data": [
                    {
                        "group_id": COMMUNITY_QQ_GROUP_ID,
                        "group_name": "This is MINI ClassIsland",
                        "request_id": 1794025078906375,
                        "requester_uin": 0,
                        "requester_nick": "",
                        "invitor_uin": 0,
                        "invitor_nick": "",
                        "message": f"问题：请提供访问密钥\n答案：{code}",
                        "checked": False,
                        "flag": "slreq:1:1794025078906375:1131427434:2:0",
                    }
                ],
            }
        if action == "get_group_member_list":
            member_list_call_count += 1
            if member_list_call_count == 1:
                return {
                    "status": "ok",
                    "retcode": 0,
                    "data": [{"user_id": 1480708359, "role": "admin"}],
                }
            return {
                "status": "ok",
                "retcode": 0,
                "data": [
                    {"user_id": 1480708359, "role": "admin"},
                    {"user_id": 3177219551, "role": "member", "join_time": 1794025500},
                ],
            }
        return {"status": "ok", "retcode": 0, "data": None}

    results = await poll_snowluma_group_requests_once(
        onebot_caller=fake_zero_uin_onebot
    )
    assert len(results) == 1
    assert results[0]["approved"] is True
    assert results[0]["qq_uin"] == "3177219551"
    assert results[0]["private_sent"] is True
    assert results[0]["user_id"] == test_superadmin_user
