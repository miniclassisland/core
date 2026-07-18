"""gRPC 会话管理器。

包含了密钥对管理 (PGPy)、握手挑战状态、心跳在线状态，以及会话状态。
"""

import os
import uuid
import secrets
import json
import logging
import pgpy
from pgpy.constants import (
    PubKeyAlgorithm,
    KeyFlags,
    HashAlgorithm,
    SymmetricKeyAlgorithm,
)
import redis.asyncio as aioredis

from app.shared.utils.config import REDIS_DB_SESSION, KEY_FILE
from app.shared.utils.redis import get_redis

logger = logging.getLogger(__name__)

# 会话和握手过期时间配置
SESSION_TTL = 86400  # 24 小时
HANDSHAKE_TTL = 120  # 2 分钟
ONLINE_TTL = 60      # 60 秒


# ---- GPG 密钥生成与解密工具 ----

class GPGKeyManager:
    """管理 RSA 加密密钥对，负责导入、生成与挑战解密。"""

    def __init__(self, key_file: str):
        self._key_file = key_file
        self.private_key = None
        self.public_key_armor = ""
        self._load_or_generate()

    def _load_or_generate(self):
        """加载或动态创建 2048 位的 RSA 密钥对。"""
        if os.path.exists(self._key_file):
            try:
                k, _ = pgpy.PGPKey.from_file(self._key_file)
                self.private_key, self.public_key_armor = k, str(k.pubkey)
                return
            except Exception:
                logger.warning("密钥损坏，重新生成: %s", self._key_file)

        k = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        u = pgpy.PGPUID.new("CIMS Server", comment="ClassIsland")
        k.add_uid(
            u,
            usage={KeyFlags.EncryptCommunications},
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
        )
        self.private_key, self.public_key_armor = k, str(k.pubkey)
        with open(self._key_file, "w") as f:
            f.write(str(k))

    def decrypt(self, encrypted: str) -> str:
        """解密客户端上报的挑战 Token。"""
        try:
            msg = pgpy.PGPMessage.from_blob(encrypted)
            raw = self.private_key.decrypt(msg).message
            return bytes(raw) if isinstance(raw, bytearray) else raw
        except Exception as e:
            logger.error("GPG 解密失败: %s", e)
            return None


# ---- gRPC 对端 IP 解析工具 ----

def parse_grpc_peer_ip(peer: str) -> str:
    """清理并提取 peer 地址中的 IP 段。"""
    if not peer:
        return ""

    if peer.startswith("ipv4:"):
        return peer[5:].rsplit(":", 1)[0]

    if peer.startswith("ipv6:"):
        inner = peer[5:]
        if inner.startswith("["):
            return inner[1 : inner.index("]")]
        return inner.rsplit(":", 1)[0]

    return peer


# ---- 统一 Session 会话管理器类 ----

class SessionManager:
    """设备连接与长连接状态生命周期管理核心实体。"""

    def __init__(self, key_path: str = KEY_FILE, *, key_file: str | None = None):
        path = key_file or key_path
        self._km = GPGKeyManager(path)
        self.public_key_armor = self._km.public_key_armor
        self._private_key = self._km.private_key

    def decrypt_challenge(self, token: str) -> str:
        """解密挑战令牌。"""
        if self._private_key is None:
            return None
        return self._km.decrypt(token)

    async def store_pending_handshake(self, tenant_id: str, cuid: str, token: str):
        """缓存解密后的挑战令牌，等待 Complete 握手。"""
        rd = get_redis()  # 默认库
        key = f"handshake:{tenant_id}:{cuid}"
        await rd.set(key, token, ex=HANDSHAKE_TTL)

    async def pop_handshake_challenge(self, tenant_id: str, cuid: str) -> str:
        """获取挑战令牌并立即销毁。"""
        rd = get_redis()
        key = f"handshake:{tenant_id}:{cuid}"
        val = await rd.get(key)
        if val:
            await rd.delete(key)
        return val

    async def create_session(self, tenant_id: str, cuid: str) -> str:
        """为设备生成 session 令牌并绑定身份。"""
        rd = get_redis(REDIS_DB_SESSION)
        sid = str(uuid.uuid4())
        key = f"session:{sid}"
        await rd.hset(key, mapping={"cuid": cuid, "tenant_id": tenant_id})
        await rd.expire(key, SESSION_TTL)
        return sid

    async def complete_handshake(self, tenant_id: str, cuid: str, accepted: bool) -> str | None:
        """完成握手判定。"""
        pending = await self.pop_handshake_challenge(tenant_id, cuid)
        return await self.create_session(tenant_id, cuid) if pending and accepted else None

    async def validate_session(self, sid: str) -> str | None:
        """根据 session 获取对应的客户端 cuid。"""
        if not sid:
            return None
        rd = get_redis(REDIS_DB_SESSION)
        return await rd.hget(f"session:{sid}", "cuid")

    async def get_session_tenant(self, sid: str) -> str | None:
        """根据 session 获取对应的租户 ID。"""
        if not sid:
            return None
        rd = get_redis(REDIS_DB_SESSION)
        return await rd.hget(f"session:{sid}", "tenant_id")

    async def set_client_online(self, tid: str, cuid: str, ip: str = ""):
        """记录设备在线心跳，绑定 IP。"""
        rd = get_redis(REDIS_DB_SESSION)
        key = f"online:{tid}:{cuid}"
        await rd.hset(key, mapping={"status": "online", "ip": ip})
        await rd.expire(key, ONLINE_TTL)

    async def set_client_offline(self, tid: str, cuid: str):
        """显式下线设备。"""
        rd = get_redis(REDIS_DB_SESSION)
        await rd.delete(f"online:{tid}:{cuid}")

    async def is_client_online(self, tid: str, cuid: str) -> bool:
        """检查设备是否在线。"""
        rd = get_redis(REDIS_DB_SESSION)
        return await rd.exists(f"online:{tid}:{cuid}") > 0

    async def update_heartbeat(self, tid: str, cuid: str):
        """延长设备在线有效期。"""
        await self.set_client_online(tid, cuid, "")

    async def get_all_clients_status(self, tid: str) -> list[dict]:
        """获取指定商户下的所有设备在线列表。"""
        rd = get_redis(REDIS_DB_SESSION)
        prefix = f"online:{tid}:"
        res = []
        async for key in rd.scan_iter(match=f"{prefix}*"):
            data = await rd.hgetall(key)
            res.append(
                {"uid": key[len(prefix) :], "status": "online", "ip": data.get("ip", "")}
            )
        return res

    async def get_all_online_ips(self, tid: str) -> set[str]:
        """获取所有在线设备的 IP 地址集。"""
        rd = get_redis(REDIS_DB_SESSION)
        prefix = f"online:{tid}:"
        ips = set()
        async for key in rd.scan_iter(match=f"{prefix}*"):
            data = await rd.hgetall(key)
            raw_ip = data.get("ip", "")
            ip = (
                parse_grpc_peer_ip(raw_ip)
                if raw_ip.startswith(("ipv4:", "ipv6:"))
                else raw_ip
            )
            if ip:
                ips.add(ip)
        return ips
