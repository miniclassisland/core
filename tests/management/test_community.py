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
async def test_qq_bot_event_notifications_and_quote_reply_workflow(
    test_superadmin_user,
):
    """Test superadmin event reports (register, ticket, group join), quote-reply approve/refuse, user notifications (approved, device quota changed), group announcement, and restart/shutdown lifecycle notifications."""
    from datetime import datetime, timezone
    from unittest.mock import patch, MagicMock
    from app.shared.db.models import CommunityBinding, User
    from app.shared.services.quota import set_quota
    from app.shared.utils.community import (
        MSG_RESTART_RECOVERED,
        MSG_RESTARTING,
        MSG_SHUTDOWN_MAINTENANCE,
        MSG_SHUTDOWN_RECOVERED,
        detect_is_systemd_restart,
        format_group_announcement,
        format_superadmin_group_join_report,
        format_superadmin_registration_report,
        format_superadmin_ticket_report,
        format_user_approved_notification,
        format_user_quota_changed_notification,
        get_registration_user_for_msg,
        handle_onebot_registration_reply_event,
        mark_pending_restart,
        notify_group_site_announcement,
        notify_service_shutdown,
        notify_service_startup_recovery,
        notify_superadmin_group_join,
        notify_superadmin_new_registration,
        notify_superadmin_new_ticket,
        poll_snowluma_superadmin_replies_once,
    )

    # Bind test_superadmin_user to QQ 1480708359 in DB
    async with AsyncSessionLocal() as db:
        sa_user = (
            await db.execute(select(User).where(User.id == test_superadmin_user))
        ).scalar_one()
        sa_user.display_name = "Super Administrator"
        db.add(
            CommunityBinding(
                user_id=test_superadmin_user,
                qq_uin="1480708359",
                group_id=str(COMMUNITY_QQ_GROUP_ID),
                is_manual=True,
                is_joined=True,
                bound_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()
        await db.refresh(sa_user)

    # 1. Verify exact message formatting
    dummy_user = User(
        id="u-fmt-1",
        username="admin",
        email="admin@miniclassisland.com",
        display_name="Super Administrator",
        hashed_password="x",
        role_code="pending",
        is_active=False,
    )
    assert (
        format_superadmin_registration_report(dummy_user)
        == "新用户 Super Administrator(admin, admin@miniclassisland.com) 注册"
    )
    assert (
        format_superadmin_ticket_report(dummy_user, "工单标题", "工单正文")
        == "用户 Super Administrator(admin, admin@miniclassisland.com) 发起工单：工单标题\n工单正文"
    )
    assert (
        format_superadmin_group_join_report(dummy_user, "1234567890", "Name")
        == "用户 Super Administrator(admin, admin@miniclassisland.com) 刚刚使用 QQ 1234567890(Name) 加入了交流群"
    )
    assert (
        format_user_approved_notification(dummy_user)
        == "您 (Super Administrator) 的注册申请已经被批准，欢迎使用 MINI ClassIsland"
    )
    assert (
        format_user_quota_changed_notification(dummy_user, 10, 8)
        == "您 (Super Administrator) 的配额已经变更为最大允许注册 10 台设备，最大允许同时保持 8 台设备连接"
    )
    assert format_group_announcement("标题", "正文") == "新的站内公告【标题】：\n正文"

    # 2. Registration report + Quote-Reply Approve & Refuse
    onebot_log: list[tuple[str, dict]] = []
    next_msg_id = 5000

    async def fake_bot(action: str, params: dict):
        nonlocal next_msg_id
        onebot_log.append((action, params))
        if action == "send_private_msg":
            next_msg_id += 1
            return {
                "status": "ok",
                "retcode": 0,
                "data": {"message_id": next_msg_id},
            }
        if action == "send_group_msg":
            next_msg_id += 1
            return {
                "status": "ok",
                "retcode": 0,
                "data": {"message_id": next_msg_id},
            }
        return {"status": "ok", "retcode": 0, "data": None}

    async with AsyncSessionLocal() as db:
        reg_u1 = await register_user(
            "applicant1@miniclassisland.com",
            "ValidPass123!",
            "Applicant One",
            db,
            username="applicant_one",
            role_code="pending",
            is_active=False,
        )
        # Bind applicant_one QQ so they also get the approval PM when approved
        db.add(
            CommunityBinding(
                user_id=reg_u1.id,
                qq_uin="200001111",
                group_id=str(COMMUNITY_QQ_GROUP_ID),
                is_manual=True,
                is_joined=True,
                bound_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

        delivered = await notify_superadmin_new_registration(
            reg_u1, db, onebot_caller=fake_bot
        )
        assert len(delivered) == 1
        sa_uin, reg_msg_id1 = delivered[0]
        assert sa_uin == "1480708359"
        assert reg_msg_id1 == "5001"
        assert await get_registration_user_for_msg("5001") == reg_u1.id
        assert (
            onebot_log[-1][1]["message"]
            == "新用户 Applicant One(applicant_one, applicant1@miniclassisland.com) 注册"
        )

        # Quote-reply "同意" from Super Admin -> approves reg_u1 and sends approval PM to 200001111
        onebot_log.clear()
        reply_res1 = await handle_onebot_registration_reply_event(
            {
                "message_id": 9001,
                "user_id": 1480708359,
                "message": f"[CQ:reply,id={reg_msg_id1}] 同意",
            },
            db,
            onebot_caller=fake_bot,
        )
        assert reply_res1 is not None
        assert reply_res1["handled"] is True
        assert reply_res1["action"] == "approve"

        await db.refresh(reg_u1)
        assert reg_u1.role_code == "normal"
        assert reg_u1.is_active is True
        assert (
            "send_private_msg",
            {
                "user_id": 200001111,
                "message": "您 (Applicant One) 的注册申请已经被批准，欢迎使用 MINI ClassIsland，当前配额最大允许注册 6 台设备",
                "auto_escape": True,
            },
        ) in onebot_log

        # Duplicate message_id 9001 is ignored
        dup_res = await handle_onebot_registration_reply_event(
            {
                "message_id": 9001,
                "user_id": 1480708359,
                "message": f"[CQ:reply,id={reg_msg_id1}] 同意",
            },
            db,
            onebot_caller=fake_bot,
        )
        assert dup_res is None

        # Non-superadmin sender is ignored
        non_sa_res = await handle_onebot_registration_reply_event(
            {
                "message_id": 9002,
                "user_id": 99999999,
                "message": f"[CQ:reply,id={reg_msg_id1}] 同意",
            },
            db,
            onebot_caller=fake_bot,
        )
        assert non_sa_res is None

        # Second pending user -> Quote-reply "Refuse" via array segments & get_friend_msg_history poller
        reg_u2 = await register_user(
            "applicant2@miniclassisland.com",
            "ValidPass123!",
            "Applicant Two",
            db,
            username="applicant_two",
            role_code="pending",
            is_active=False,
        )
        delivered2 = await notify_superadmin_new_registration(
            reg_u2, db, onebot_caller=fake_bot
        )
        reg_msg_id2 = delivered2[0][1]

        async def fake_history_bot(action: str, params: dict):
            if action == "get_friend_msg_history":
                return {
                    "status": "ok",
                    "retcode": 0,
                    "data": {
                        "messages": [
                            {
                                "message_id": 9003,
                                "sender": {"user_id": 1480708359},
                                "message": [
                                    {"type": "reply", "data": {"id": reg_msg_id2}},
                                    {"type": "text", "data": {"text": "Refuse"}},
                                ],
                            }
                        ]
                    },
                }
            return await fake_bot(action, params)

        polled_replies = await poll_snowluma_superadmin_replies_once(
            db, onebot_caller=fake_history_bot
        )
        assert len(polled_replies) == 1
        assert polled_replies[0]["action"] == "refuse"
        assert (
            await db.execute(select(User).where(User.id == reg_u2.id))
        ).scalar_one_or_none() is None

        # Third pending user -> Quote-reply "Approve" when message_id is not in cache (resolved via get_msg text parsing)
        reg_u3 = await register_user(
            "applicant3@miniclassisland.com",
            "ValidPass123!",
            "Applicant Three",
            db,
            username="applicant_three",
            role_code="pending",
            is_active=False,
        )

        async def fake_get_msg_bot(action: str, params: dict):
            if action == "get_msg":
                return {
                    "status": "ok",
                    "retcode": 0,
                    "data": {
                        "message": "新用户 Applicant Three(applicant_three, applicant3@miniclassisland.com) 注册"
                    },
                }
            return await fake_bot(action, params)

        reply_res3 = await handle_onebot_registration_reply_event(
            {
                "message_id": 9004,
                "user_id": 1480708359,
                "reply_id": "88888",
                "raw_message": "Approve",
            },
            db,
            onebot_caller=fake_get_msg_bot,
        )
        assert reply_res3 is not None
        assert reply_res3["handled"] is True
        await db.refresh(reg_u3)
        assert reg_u3.role_code == "normal"

        # 3. Ticket creation report to superadmin
        onebot_log.clear()
        ticket_sent = await notify_superadmin_new_ticket(
            reg_u1, "无法连接集控", "客户端报错 503", db, onebot_caller=fake_bot
        )
        assert ticket_sent is True
        assert (
            onebot_log[-1][1]["message"]
            == "用户 Applicant One(applicant_one, applicant1@miniclassisland.com) 发起工单：无法连接集控\n客户端报错 503"
        )

        # 4. Auto-approved group join report to superadmin
        onebot_log.clear()
        join_sent = await notify_superadmin_group_join(
            reg_u1, "200001111", "NickOne", db, onebot_caller=fake_bot
        )
        assert join_sent is True
        assert (
            onebot_log[-1][1]["message"]
            == "用户 Applicant One(applicant_one, applicant1@miniclassisland.com) 刚刚使用 QQ 200001111(NickOne) 加入了交流群"
        )

        # 5. Quota change notification (only max_clients / max_grpc_connections notify owner/admin)
        from app.shared.db.models import AccountMember

        acct_member = (
            await db.execute(
                select(AccountMember).where(AccountMember.user_id == reg_u1.id)
            )
        ).scalar_one()
        acct_id = acct_member.account_id

        onebot_log.clear()
        # Changing max_bandwidth_mb does NOT trigger notification
        await set_quota(acct_id, "max_bandwidth_mb", 500, db, onebot_caller=fake_bot)
        assert onebot_log == []

        # Changing max_clients DOES trigger notification to account owner/admin
        await set_quota(acct_id, "max_clients", 15, db, onebot_caller=fake_bot)
        assert len(onebot_log) == 1
        assert (
            onebot_log[0][1]["message"]
            == "您 (Applicant One) 的配额已经变更为最大允许注册 15 台设备，最大允许同时保持 4 台设备连接"
        )

        onebot_log.clear()
        await set_quota(acct_id, "max_grpc_connections", 12, db, onebot_caller=fake_bot)
        assert len(onebot_log) == 1
        assert (
            onebot_log[0][1]["message"]
            == "您 (Applicant One) 的配额已经变更为最大允许注册 15 台设备，最大允许同时保持 12 台设备连接"
        )

    # 6. Group announcement broadcast
    onebot_log.clear()
    ann_ok = await notify_group_site_announcement(
        "维护通知", "今晚十点升级", onebot_caller=fake_bot
    )
    assert ann_ok is True
    assert onebot_log == [
        (
            "send_group_msg",
            {
                "group_id": COMMUNITY_QQ_GROUP_ID,
                "message": "新的站内公告【维护通知】：\n今晚十点升级",
                "auto_escape": True,
            },
        )
    ]
    assert await notify_group_site_announcement("", "", onebot_caller=fake_bot) is False

    # 7. Service restart vs shutdown lifecycle group notifications
    onebot_log.clear()
    mark_pending_restart()
    assert detect_is_systemd_restart() is True

    with (
        patch("shutil.which", return_value="/usr/bin/systemctl"),
        patch(
            "subprocess.run",
            return_value=MagicMock(
                returncode=0,
                stdout="123 miniclassisland-backend.service restart running\n",
            ),
        ),
    ):
        assert detect_is_systemd_restart() is True

    await notify_service_shutdown(is_restart=True, onebot_caller=fake_bot)
    assert onebot_log[-1][1]["message"] == MSG_RESTARTING
    rec_msg1 = await notify_service_startup_recovery(onebot_caller=fake_bot)
    assert rec_msg1 == MSG_RESTART_RECOVERED
    assert onebot_log[-1][1]["message"] == MSG_RESTART_RECOVERED

    await notify_service_shutdown(is_restart=False, onebot_caller=fake_bot)
    assert onebot_log[-1][1]["message"] == MSG_SHUTDOWN_MAINTENANCE
    rec_msg2 = await notify_service_startup_recovery(onebot_caller=fake_bot)
    assert rec_msg2 == MSG_SHUTDOWN_RECOVERED
    assert onebot_log[-1][1]["message"] == MSG_SHUTDOWN_RECOVERED

    # Subsequent startup with no pending lifecycle mode sends nothing
    assert await notify_service_startup_recovery(onebot_caller=fake_bot) is None

    # 8. Additional coverage for edge branches, CLI set/activate, and admin user update
    from app.shared.utils.community import (
        _extract_message_id,
        _extract_quoted_text,
        _extract_reply_id_and_text,
        _parse_registration_action,
        _pop_lifecycle_mode,
        _reg_msg_users,
        _send_private_msg_with_id,
        _set_lifecycle_mode,
        issue_user_community_code,
        notify_account_device_quota_changed,
        poll_snowluma_group_requests_once,
    )

    assert _extract_message_id({"message_id": 777}) == "777"
    assert _extract_message_id({}) is None

    async def fail_bot(action: str, params: dict):
        return {"status": "failed", "retcode": 100}

    assert (
        await _send_private_msg_with_id(
            "1480708359", 1131427434, "hi", onebot_caller=fail_bot
        )
    ) == (False, None)

    # Redis fallback for get_registration_user_for_msg when memory dict is cleared
    _reg_msg_users.pop("5001", None)
    assert await get_registration_user_for_msg("5001") is not None

    async with AsyncSessionLocal() as db:
        assert (
            await notify_account_device_quota_changed(
                "nonexistent", "max_bandwidth_mb", db
            )
            == 0
        )

        # Auto-approved normal user join via poll_snowluma_group_requests_once triggers notify_superadmin_group_join
        join_u = await register_user(
            "joiner_norm@miniclassisland.com",
            "ValidPass123!",
            "Joiner Norm",
            db,
            username="joiner_norm",
            role_code="normal",
            is_active=True,
        )
        join_code, _ = await issue_user_community_code(join_u.id, db)

        async def fake_join_bot(action: str, params: dict):
            if action == "get_group_system_msg":
                return {
                    "status": "ok",
                    "retcode": 0,
                    "data": [
                        {
                            "flag": "flag-join-norm",
                            "group_id": COMMUNITY_QQ_GROUP_ID,
                            "requester_uin": 300002222,
                            "requester_nick": "JoinerNick",
                            "message": f"问题：请输入密码\n答案：{join_code}",
                            "checked": False,
                        }
                    ],
                }
            return await fake_bot(action, params)

        join_res = await poll_snowluma_group_requests_once(
            db, onebot_caller=fake_join_bot
        )
        assert len(join_res) == 1
        assert join_res[0]["approved"] is True

    # Reply extraction and quoted text edge cases
    assert _extract_reply_id_and_text(
        {"reply": {"id": "111"}, "raw_message": "[CQ:reply,id=111] 同意"}
    ) == ("111", "同意")
    assert _extract_reply_id_and_text(
        {"source": {"message_id": "222"}, "raw_message": "拒绝"}
    ) == ("222", "拒绝")
    assert _extract_reply_id_and_text({"raw_message": "[CQ:reply,id=333] Approve"}) == (
        "333",
        "Approve",
    )
    assert _parse_registration_action("") is None
    assert _parse_registration_action("other") is None
    assert (
        _extract_quoted_text(
            {"message": [{"type": "text", "data": {"text": "quoted seg"}}]}
        )
        == "quoted seg"
    )
    assert _extract_quoted_text({"raw_message": "quoted raw"}) == "quoted raw"

    # handle_onebot_registration_reply_event edge branches (db=None, no reply_id, invalid action, reply/source dict, get_msg error)
    assert (
        await handle_onebot_registration_reply_event(
            {"user_id": 1480708359, "message": "hello"}, onebot_caller=fake_bot
        )
        is None
    )
    assert (
        await handle_onebot_registration_reply_event(
            {"user_id": 1480708359, "reply_id": "999", "message": "hello"},
            onebot_caller=fake_bot,
        )
        is None
    )
    assert (
        await handle_onebot_registration_reply_event(
            {
                "sender": {"user_id": 1480708359},
                "reply": {"id": "99991", "message": "not a reg msg"},
                "raw_message": "同意",
            },
            onebot_caller=fake_bot,
        )
        is None
    )

    async def raise_get_msg_bot(action: str, params: dict):
        if action == "get_msg":
            raise RuntimeError("boom")
        return await fake_bot(action, params)

    assert (
        await handle_onebot_registration_reply_event(
            {
                "user_id": 1480708359,
                "source": {"id": "99992", "raw_message": ""},
                "raw_message": "同意",
            },
            onebot_caller=raise_get_msg_bot,
        )
        is None
    )

    # poll_snowluma_superadmin_replies_once with db=None, failed retcode, and list data
    async def list_history_bot(action: str, params: dict):
        if action == "get_friend_msg_history":
            return {
                "status": "ok",
                "retcode": 0,
                "data": [{"message_id": 9099, "message": "plain"}],
            }
        return await fake_bot(action, params)

    assert (
        await poll_snowluma_superadmin_replies_once(onebot_caller=list_history_bot)
        == []
    )
    assert await poll_snowluma_superadmin_replies_once(onebot_caller=fail_bot) == []

    # Lifecycle mode file/redis fallbacks and empty mode clear
    await _set_lifecycle_mode("")
    await _set_lifecycle_mode("restart")
    from app.shared.utils import community as comm_mod

    comm_mod._memory_lifecycle_mode = ""
    assert await _pop_lifecycle_mode() == "restart"

    await _set_lifecycle_mode("stop")
    comm_mod._memory_lifecycle_mode = ""
    comm_mod._write_local_lifecycle_state({})
    assert await _pop_lifecycle_mode() == "stop"

    # Admin PATCH /user/{id} transitioning pending -> normal triggers notify_user_approved
    # CLI user activate & CLI sys set announcement_title/motd
    from app.admin.user import update_user_info
    from app.shared.schemas.schemas import UserUpdateRequest

    async with AsyncSessionLocal() as db:
        sa_obj = (
            await db.execute(select(User).where(User.id == test_superadmin_user))
        ).scalar_one()
        pend_admin_u = await register_user(
            "pend_admin@miniclassisland.com",
            "ValidPass123!",
            "Pend Admin",
            db,
            username="pend_admin",
            role_code="pending",
            is_active=False,
        )
        await update_user_info(
            pend_admin_u.id,
            UserUpdateRequest(
                username=None,
                display_name=None,
                qq_uin=None,
                role_code="normal",
                is_active=True,
            ),
            db=db,
            admin_user=sa_obj,
        )

        await register_user(
            "pend_cli@miniclassisland.com",
            "ValidPass123!",
            "Pend CLI",
            db,
            username="pend_cli",
            role_code="pending",
            is_active=False,
        )

    import asyncio as _asyncio
    import concurrent.futures
    from typer.testing import CliRunner
    from app.cli.main import cli

    runner = CliRunner()

    def _run_cli_cmds():
        r1 = runner.invoke(cli, ["user", "activate", "pend_cli"])
        r2 = runner.invoke(cli, ["sys", "set-setting", "announcement_title", "CLI标题"])
        r3 = runner.invoke(cli, ["sys", "set-setting", "motd", "CLI正文"])
        return r1.exit_code, r2.exit_code, r3.exit_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        c1, c2, c3 = await _asyncio.get_running_loop().run_in_executor(
            pool, _run_cli_cmds
        )
    assert (c1, c2, c3) == (0, 0, 0)

    # Clean up test superadmin binding so subsequent tests see clean state
    async with AsyncSessionLocal() as db:
        from sqlalchemy import delete as sql_delete

        await db.execute(
            sql_delete(CommunityBinding).where(
                CommunityBinding.user_id.in_([test_superadmin_user, join_u.id])
            )
        )
        await db.commit()
        # With no superadmin bindings in DB, poll_snowluma_superadmin_replies_once returns []
        assert (
            await poll_snowluma_superadmin_replies_once(db, onebot_caller=fake_bot)
            == []
        )


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

    # Also test _send_private_msg fallback to group temporary session when first send_private_msg fails
    from app.shared.utils.community import _send_private_msg

    pm_attempt = 0

    async def fake_pm_fallback(action: str, params: dict):
        nonlocal pm_attempt
        pm_attempt += 1
        if pm_attempt == 1:
            return {"status": "failed", "retcode": 100}
        return {"status": "ok", "retcode": 0}

    ok_fallback = await _send_private_msg(
        "3177219551",
        COMMUNITY_QQ_GROUP_ID,
        "test fallback",
        onebot_caller=fake_pm_fallback,
    )
    assert ok_fallback is True
    assert pm_attempt == 2
