"""test_pairing.py"""

import json
from datetime import datetime, timezone
import pytest
from sqlalchemy import select
from app.shared.services import pairing
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import ClientProfile, PairingCode


@pytest.mark.asyncio
async def test_pairing_flow():
    """Test device pairing code request and check_approved (with preset_profile)."""
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

    # Approve with preset_profile
    async with AsyncSessionLocal() as db:
        rec = (
            await db.execute(select(PairingCode).where(PairingCode.code == code))
        ).scalar_one()
        rec.approved = True
        rec.status = "approved"
        rec.preset_profile_json = json.dumps({"class_plan": "custom_cp"})
        await db.commit()

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
    async with AsyncSessionLocal() as db:
        rec_ex = (
            await db.execute(select(PairingCode).where(PairingCode.code == code_ex))
        ).scalar_one()
        rec_ex.approved = True
        rec_ex.preset_profile_json = json.dumps({"subjects": "sub_a"})
        await db.commit()
    assert await pairing.check_approved("client-uid-existing-prof", tenant_id) is True

    code_bad_json = await pairing.create_pairing_request(
        tenant_id=tenant_id, client_uid="client-uid-bad-json"
    )
    async with AsyncSessionLocal() as db:
        rec_bad = (
            await db.execute(
                select(PairingCode).where(PairingCode.code == code_bad_json)
            )
        ).scalar_one()
        rec_bad.approved = True
        rec_bad.preset_profile_json = "{corrupted_json"
        await db.commit()
    assert await pairing.check_approved("client-uid-bad-json", tenant_id) is True
