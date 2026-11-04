"""MINI ClassIsland client device pairing and registration service."""

import json
import secrets
import logging
from datetime import datetime, timezone

from sqlalchemy import select

from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import PairingCode, ClientProfile
from app.shared.utils.tenant import set_search_path
from app.shared.literals import PAIRING_CHARSET, PAIRING_CODE_LEN

logger = logging.getLogger(__name__)

# Disambiguated pairing code character set
_CHARSET = PAIRING_CHARSET
_CODE_LEN = PAIRING_CODE_LEN


def generate_code() -> str:
    """Generate an 8-character easily distinguishable pairing code."""
    return "".join(secrets.choice(_CHARSET) for _ in range(_CODE_LEN))


async def create_pairing_request(
    tenant_id: str,
    client_uid: str,
    client_id: str = "",
    client_mac: str = "",
    client_ip: str = "",
) -> str:
    """Physical client requests a pairing code prior to long-connection registration."""
    effective_tid = tenant_id or "default"
    async with AsyncSessionLocal() as db:
        await set_search_path(db)
        stmt = (
            select(PairingCode)
            .where(PairingCode.client_uid == client_uid)
            .where(PairingCode.tenant_id == effective_tid)
            .where(PairingCode.used.is_(False))
        )
        existing = (await db.execute(stmt)).scalars().first()
        if existing:
            if client_id:
                existing.client_id = client_id
            if client_mac:
                existing.client_mac = client_mac
            if client_ip:
                existing.client_ip = client_ip
            await db.commit()
            return existing.code

        code = generate_code()
        record = PairingCode(
            code=code,
            tenant_id=effective_tid,
            client_uid=client_uid,
            client_id=client_id,
            client_mac=client_mac,
            client_ip=client_ip,
            status="pending",
            created_at=datetime.now(timezone.utc),
        )
        db.add(record)
        await db.commit()
        logger.info(
            "Generated pairing request code %s (tenant=%s, device=%s)",
            code,
            effective_tid,
            client_uid,
        )
        return code


async def check_approved(client_uid: str, tenant_id: str) -> bool:
    """Check if pairing request for device has been approved by admin. If so, consume and apply profile."""
    effective_tid = tenant_id or "default"
    async with AsyncSessionLocal() as db:
        await set_search_path(db)
        stmt = (
            select(PairingCode)
            .where(PairingCode.client_uid == client_uid)
            .where(PairingCode.tenant_id == effective_tid)
            .where(PairingCode.approved.is_(True))
            .where(PairingCode.used.is_(False))
        )
        record = (await db.execute(stmt)).scalar_one_or_none()
        if record:
            record.used = True
            record.status = "used"
            if record.preset_profile_json and record.preset_profile_json != "{}":
                try:
                    preset = json.loads(record.preset_profile_json)
                    if isinstance(preset, dict) and preset:
                        acct_id = tenant_id or "default"
                        prof = (
                            await db.execute(
                                select(ClientProfile).where(
                                    ClientProfile.account_id == acct_id,
                                    ClientProfile.client_id == client_uid,
                                )
                            )
                        ).scalar_one_or_none()
                        if not prof:
                            prof = ClientProfile(
                                account_id=acct_id,
                                client_id=client_uid,
                                updated_at=datetime.now(timezone.utc),
                            )
                        for snake_k, pascal_k in (
                            ("class_plan", "ClassPlan"),
                            ("time_layout", "TimeLayout"),
                            ("subjects", "Subjects"),
                            ("default_settings", "DefaultSettings"),
                            ("policy", "Policy"),
                            ("components", "Components"),
                            ("credentials", "Credentials"),
                        ):
                            val = (
                                preset.get(pascal_k)
                                if pascal_k in preset
                                else preset.get(snake_k)
                            )
                            if val is not None:
                                setattr(prof, snake_k, str(val))
                        prof.updated_at = datetime.now(timezone.utc)
                        db.add(prof)
                except Exception:
                    pass
            await db.commit()
            return True
    return False
