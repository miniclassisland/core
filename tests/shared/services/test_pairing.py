"""test_pairing.py
"""

import pytest
from app.shared.services import pairing
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import PairingCode


@pytest.mark.asyncio
async def test_pairing_flow():
    """测试设备申请配对码、管理员审批与在线验证流程。"""
    tenant_id = "test-account-00000000"
    client_uid = "client-uid-12345"

    # 1. 验证初始状态：该客户端未被批准配对
    is_approved = await pairing.check_approved(client_uid, tenant_id)
    assert is_approved is False

    # 2. 申请生成配对码
    code = await pairing.create_pairing_request(
        tenant_id=tenant_id,
        client_uid=client_uid,
        client_id="class-room-1",
        client_mac="AA-BB-CC-DD-EE-FF",
        client_ip="192.168.1.100",
    )
    assert len(code) == 8

    # 重复请求应幂等返回相同的验证码
    code_dup = await pairing.create_pairing_request(
        tenant_id=tenant_id,
        client_uid=client_uid,
        client_id="class-room-1",
        client_mac="AA-BB-CC-DD-EE-FF",
        client_ip="192.168.1.100",
    )
    assert code_dup == code

    # 3. 列出当前商户下所有申请记录
    reqs = await pairing.list_pending(tenant_id)
    assert any(r.code == code for r in reqs)

    # 4. 管理员审批通过
    success = await pairing.approve_pairing(code, tenant_id)
    assert success is True

    # 重复审批或审批不存在的验证码应当返回 False
    assert await pairing.approve_pairing(code, tenant_id) is False
    assert await pairing.approve_pairing("INVALID", tenant_id) is False

    # 5. 校验结果：客户端现已被批准加入
    is_approved_now = await pairing.check_approved(client_uid, tenant_id)
    assert is_approved_now is True

    # 6. 管理员拒绝（撤销）测试
    code2 = await pairing.create_pairing_request(
        tenant_id=tenant_id,
        client_uid="client-uid-rejected",
        client_id="class-room-2",
        client_mac="11-22-33-44-55-66",
        client_ip="192.168.1.101",
    )
    # 执行拒绝（撤销）
    success_rej = await pairing.revoke_pairing(code2, tenant_id)
    assert success_rej is True

    is_approved_rej = await pairing.check_approved(
        "client-uid-rejected", tenant_id
    )
    assert is_approved_rej is False
