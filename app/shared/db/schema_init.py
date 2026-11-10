"""Multi-tenant database table and default resource initialization utility."""

import asyncio
import json
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.models import ClientProfile, MODEL_MAP, ResourceHistory
from app.shared.literals import DEFAULT_RESOURCES

_SEED_LOCKS: dict[str, asyncio.Lock] = {}


async def record_resource_history(
    db: AsyncSession,
    account_id: str,
    resource_type: str,
    name: str,
    version: int,
    content: str,
    created_at: datetime,
) -> None:
    """Append an immutable version snapshot for a tenant configuration resource."""
    db.add(
        ResourceHistory(
            account_id=account_id,
            resource_type=resource_type,
            name=name,
            version=version,
            content=content,
            created_at=created_at,
        )
    )


async def seed_account_defaults(
    account_id: str, db: AsyncSession, *, fast_check: bool = False
) -> None:
    """Seed default 7 profile resources and '__default__' ClientProfile for a tenant account."""
    if fast_check:
        has_default = (
            await db.execute(
                select(ClientProfile.client_id).where(
                    ClientProfile.account_id == account_id,
                    ClientProfile.client_id == "__default__",
                )
            )
        ).scalar_one_or_none()
        if has_default is not None:
            return

    if len(_SEED_LOCKS) > 2048:
        for k in [k for k, lk in _SEED_LOCKS.items() if not lk.locked()][:512]:
            _SEED_LOCKS.pop(k, None)
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
                    serialized = json.dumps(content_dict, ensure_ascii=False)
                    db.add(
                        model(
                            account_id=account_id,
                            name=name,
                            content=serialized,
                            version=1,
                            updated_at=now,
                        )
                    )
                    await record_resource_history(
                        db,
                        account_id=account_id,
                        resource_type=resource_type,
                        name=name,
                        version=1,
                        content=serialized,
                        created_at=now,
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
