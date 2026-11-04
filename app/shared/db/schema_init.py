"""Multi-tenant database table and default resource initialization utility."""

import asyncio
import json
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.models import ClientProfile, MODEL_MAP
from app.shared.literals import DEFAULT_RESOURCES

_SEED_LOCKS: dict[str, asyncio.Lock] = {}


async def seed_account_defaults(account_id: str, db: AsyncSession) -> None:
    """Seed default 7 profile resources and '__default__' ClientProfile for a tenant account."""
    lock = _SEED_LOCKS.setdefault(account_id, asyncio.Lock())
    async with lock:
        now = datetime.now(timezone.utc)
        added = False
        for resource_type, templates in DEFAULT_RESOURCES.items():
            model = MODEL_MAP.get(resource_type)
            if not model:
                continue
            for name, content_dict in templates.items():
                existing = (
                    await db.execute(
                        select(model).where(
                            model.account_id == account_id,
                            model.name == name,
                        )
                    )
                ).scalar_one_or_none()
                if not existing:
                    db.add(
                        model(
                            account_id=account_id,
                            name=name,
                            content=json.dumps(content_dict, ensure_ascii=False),
                            version=1,
                            updated_at=now,
                        )
                    )
                    added = True

        default_profile = (
            await db.execute(
                select(ClientProfile).where(
                    ClientProfile.account_id == account_id,
                    ClientProfile.client_id == "__default__",
                )
            )
        ).scalar_one_or_none()
        if not default_profile:
            db.add(
                ClientProfile(
                    account_id=account_id,
                    client_id="__default__",
                    class_plan="default",
                    time_layout="default",
                    subjects="default",
                    default_settings="default",
                    policy="default",
                    components="default",
                    credentials="default",
                    updated_at=now,
                )
            )
            added = True

        if added:
            await db.commit()
