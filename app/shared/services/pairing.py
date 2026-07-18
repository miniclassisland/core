"""MINIClassIsland 客户端设备配对与注册管理服务。
"""

import secrets
import logging
from datetime import datetime, timezone

from sqlalchemy import select, delete as sa_delete

from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import PairingCode
from app.shared.utils.tenant import set_search_path

logger = logging.getLogger(__name__)

# 易混淆排查的配对码字符集
_CHARSET = "2346789ABCEFGHJKLMNPRSTWXYZ"
_CODE_LEN = 8


def generate_code() -> str:
    """生成一个 8 位且易辨识的配对码。"""
    return "".join(secrets.choice(_CHARSET) for _ in range(_CODE_LEN))


async def create_pairing_request(
    tenant_id: str,
    client_uid: str,
    client_id: str = "",
    client_mac: str = "",
    client_ip: str = "",
) -> str:
    """物理客户端在长连接注册前申请一个设备配对码请求。"""
    code = generate_code()
    record = PairingCode(
        code=code,
        tenant_id=tenant_id,
        client_uid=client_uid,
        client_id=client_id,
        client_mac=client_mac,
        client_ip=client_ip,
        created_at=datetime.now(timezone.utc),
    )
    async with AsyncSessionLocal() as db:
        await set_search_path(db)
        db.add(record)
        await db.commit()
    logger.info("生成配对请求码 %s（租户=%s, 设备=%s）", code, tenant_id, client_uid)
    return code


async def check_approved(client_uid: str, tenant_id: str) -> bool:
    """物理设备检查其申请的配对请求是否已被管理员审核通过。如果是，则消费该配对请求。"""
    async with AsyncSessionLocal() as db:
        await set_search_path(db)
        stmt = (
            select(PairingCode)
            .where(PairingCode.client_uid == client_uid)
            .where(PairingCode.tenant_id == tenant_id)
            .where(PairingCode.approved.is_(True))
            .where(PairingCode.used.is_(False))
        )
        record = (await db.execute(stmt)).scalar_one_or_none()
        if record:
            record.used = True
            await db.commit()
            return True
    return False


async def get_pairing_by_code(code: str, tenant_id: str) -> PairingCode | None:
    """根据配对码查询详细的设备注册配对信息。"""
    async with AsyncSessionLocal() as db:
        await set_search_path(db)
        stmt = (
            select(PairingCode)
            .where(PairingCode.code == code)
            .where(PairingCode.tenant_id == tenant_id)
        )
        return (await db.execute(stmt)).scalar_one_or_none()


async def approve_pairing(code: str, tenant_id: str) -> bool:
    """管理员审批通过指定的客户端配对注册申请。"""
    async with AsyncSessionLocal() as db:
        await set_search_path(db)
        stmt = (
            select(PairingCode)
            .where(PairingCode.code == code)
            .where(PairingCode.tenant_id == tenant_id)
        )
        record = (await db.execute(stmt)).scalar_one_or_none()
        if not record or record.used:
            return False
        record.approved = True
        await db.commit()
        logger.info("审批配对码 %s（租户=%s）成功", code, tenant_id)
        return True


async def revoke_pairing(code: str, tenant_id: str) -> bool:
    """撤销/删除指定的配对请求。"""
    async with AsyncSessionLocal() as db:
        await set_search_path(db)
        result = await db.execute(
            sa_delete(PairingCode)
            .where(PairingCode.code == code)
            .where(PairingCode.tenant_id == tenant_id)
        )
        await db.commit()
        return result.rowcount > 0


async def list_pending(tenant_id: str) -> list[PairingCode]:
    """获取指定租户账户下所有处于等待审核中的客户端配对列表。"""
    async with AsyncSessionLocal() as db:
        await set_search_path(db)
        stmt = (
            select(PairingCode)
            .where(PairingCode.tenant_id == tenant_id)
            .where(PairingCode.used.is_(False))
            .order_by(PairingCode.created_at.desc())
        )
        result = await db.execute(stmt)
        return list(result.scalars().all())
