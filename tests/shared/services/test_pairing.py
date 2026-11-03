"""test_pairing.py"""

from datetime import datetime, timezone
import pytest
from app.shared.services import pairing
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import ClientProfile


@pytest.mark.asyncio
async def test_pairing_flow():
    """Test device pairing code request, lookup, approval (with preset_profile), check_approved, and revocation."""
    tenant_id = "test-account-00000000"
    client_uid = "client-uid-12345"

    assert await pairing.check_approved(client_uid, tenant_id) is False

    code = await pairing.create_pairing_request(
        tenant_id=tenant_id,
        client_uid=client_uid,
        client_id="class-room-1",
        client_mac="AA-BB-CC-DD-EE-FF",
        client_ip="192.168.1.100",
    )
    assert len(code) == 8

    code_dup = await pairing.create_pairing_request(
        tenant_id=tenant_id,
        client_uid=client_uid,
        client_id="class-room-1",
        client_mac="AA-BB-CC-DD-EE-FF",
        client_ip="192.168.1.100",
    )
    assert code_dup == code

    # Lookup by code
    found = await pairing.get_pairing_by_code(code, tenant_id)
    assert found is not None
    assert found.code == code

    reqs = await pairing.list_pending(tenant_id)
    assert any(r.code == code for r in reqs)

    # Approve with preset_profile
    success = await pairing.approve_pairing(
        code, tenant_id, preset_profile={"class_plan": "custom_cp"}
    )
    assert success is True

    assert await pairing.approve_pairing(code, tenant_id) is False
    assert await pairing.approve_pairing("INVALID", tenant_id) is False

    # check_approved consumes record and creates/updates ClientProfile
    is_approved_now = await pairing.check_approved(client_uid, tenant_id)
    assert is_approved_now is True

    # Test check_approved when ClientProfile already exists and when preset_profile_json is invalid JSON
    async with AsyncSessionLocal() as db:
        db.add(
            ClientProfile(
                account_id=tenant_id,
                client_id="client-uid-existing-prof",
                updated_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

    code_ex = await pairing.create_pairing_request(
        tenant_id=tenant_id, client_uid="client-uid-existing-prof"
    )
    await pairing.approve_pairing(
        code_ex, tenant_id, preset_profile={"subjects": "sub_a"}
    )
    assert await pairing.check_approved("client-uid-existing-prof", tenant_id) is True

    code_bad_json = await pairing.create_pairing_request(
        tenant_id=tenant_id, client_uid="client-uid-bad-json"
    )
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        from app.shared.db.models import PairingCode

        rec = (
            await db.execute(
                select(PairingCode).where(PairingCode.code == code_bad_json)
            )
        ).scalar_one()
        rec.approved = True
        rec.preset_profile_json = "{corrupted_json"
        await db.commit()
    assert await pairing.check_approved("client-uid-bad-json", tenant_id) is True

    # Revoke test
    code2 = await pairing.create_pairing_request(
        tenant_id=tenant_id,
        client_uid="client-uid-rejected",
        client_id="class-room-2",
        client_mac="11-22-33-44-55-66",
        client_ip="192.168.1.101",
    )
    assert await pairing.revoke_pairing(code2, tenant_id) is True
    assert await pairing.check_approved("client-uid-rejected", tenant_id) is False
