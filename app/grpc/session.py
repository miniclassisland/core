"""gRPC session manager.

Contains key pair management (PGPy), handshake challenge state, heartbeat online state, and session state.
"""

import os
import uuid
import logging
from typing import Any
import pgpy
from pgpy.constants import (
    PubKeyAlgorithm,
    KeyFlags,
    HashAlgorithm,
    SymmetricKeyAlgorithm,
)

from app.shared.utils.config import REDIS_DB_SESSION, KEY_FILE
from app.shared.utils.redis import get_redis

logger = logging.getLogger(__name__)

# Session and handshake TTL configuration
SESSION_TTL = 86400  # 24 hours
HANDSHAKE_TTL = 120  # 2 minutes
ONLINE_TTL = 60  # 60 seconds


# ---- GPG Key Generation & Decryption ----


class GPGKeyManager:
    """Manages RSA encryption key pairs, handling import, generation, and challenge decryption."""

    def __init__(self, key_file: str):
        self._key_file = key_file
        self.private_key = None
        self.public_key_armor = ""
        self._load_or_generate()

    def _load_or_generate(self):
        """Load or dynamically create 2048-bit RSA key pair."""
        if os.path.exists(self._key_file):
            try:
                loaded: Any = pgpy.PGPKey.from_file(self._key_file)
                k, _ = loaded
                self.private_key, self.public_key_armor = k, str(k.pubkey)
                return
            except Exception:
                logger.warning("Key file corrupted, re-generating: %s", self._key_file)

        k = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        u = pgpy.PGPUID.new("MINI ClassIsland Server", comment="MINI ClassIsland")
        k.add_uid(
            u,
            usage={KeyFlags.EncryptCommunications},
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
        )
        self.private_key, self.public_key_armor = k, str(k.pubkey)
        with open(self._key_file, "w") as f:
            f.write(str(k))

    def decrypt(self, encrypted: str) -> Any:
        """Decrypt challenge Token uploaded by client."""
        try:
            msg = pgpy.PGPMessage.from_blob(encrypted)
            pk: Any = self.private_key
            raw = pk.decrypt(msg).message
            return bytes(raw) if isinstance(raw, bytearray) else raw
        except Exception as e:
            logger.error("GPG decryption failed: %s", e)
            return None


# ---- gRPC Peer IP Parser ----


def parse_grpc_peer_ip(peer: str) -> str:
    """Clean and extract IP segment from peer address."""
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


# ---- Session Manager Class ----


class SessionManager:
    """Core entity for device connection and long-connection lifecycle management."""

    def __init__(self, key_path: str = KEY_FILE, *, key_file: str | None = None):
        path = key_file or key_path
        self._km = GPGKeyManager(path)
        self.public_key_armor = self._km.public_key_armor
        self._private_key = self._km.private_key

    def decrypt_challenge(self, token: str) -> Any:
        """Decrypt challenge token."""
        if self._private_key is None:
            return None
        return self._km.decrypt(token)

    async def store_pending_handshake(self, tenant_id: str, cuid: str, token: str):
        """Cache decrypted challenge token awaiting Complete handshake."""
        rd = get_redis()  # Default DB
        key = f"handshake:{tenant_id}:{cuid}"
        await rd.set(key, token, ex=HANDSHAKE_TTL)

    async def pop_handshake_challenge(self, tenant_id: str, cuid: str) -> str | None:
        """Retrieve challenge token and delete immediately."""
        rd = get_redis()
        key = f"handshake:{tenant_id}:{cuid}"
        val = await rd.get(key)
        if val:
            await rd.delete(key)
        return val

    async def create_session(self, tenant_id: str, cuid: str) -> str:
        """Generate session token for device and bind identity."""
        rd = get_redis(REDIS_DB_SESSION)
        sid = str(uuid.uuid4())
        key = f"session:{sid}"
        await rd.hset(key, mapping={"cuid": cuid, "tenant_id": tenant_id})
        await rd.expire(key, SESSION_TTL)
        return sid

    async def complete_handshake(
        self, tenant_id: str, cuid: str, accepted: bool
    ) -> str | None:
        """Complete handshake evaluation."""
        pending = await self.pop_handshake_challenge(tenant_id, cuid)
        return (
            await self.create_session(tenant_id, cuid) if pending and accepted else None
        )

    async def validate_session(self, sid: str) -> str | None:
        """Retrieve corresponding client cuid from session ID."""
        if not sid:
            return None
        rd = get_redis(REDIS_DB_SESSION)
        return await rd.hget(f"session:{sid}", "cuid")

    async def get_session_tenant(self, sid: str) -> str | None:
        """Retrieve corresponding tenant ID from session ID."""
        if not sid:
            return None
        rd = get_redis(REDIS_DB_SESSION)
        return await rd.hget(f"session:{sid}", "tenant_id")

    async def set_client_online(self, tid: str, cuid: str, ip: str = ""):
        """Record device online heartbeat and bind IP."""
        rd = get_redis(REDIS_DB_SESSION)
        key = f"online:{tid}:{cuid}"
        await rd.hset(key, mapping={"status": "online", "ip": ip})
        await rd.expire(key, ONLINE_TTL)

    async def set_client_offline(self, tid: str, cuid: str):
        """Explicitly set device offline."""
        rd = get_redis(REDIS_DB_SESSION)
        await rd.delete(f"online:{tid}:{cuid}")

    async def is_client_online(self, tid: str, cuid: str) -> bool:
        """Check if device is online."""
        rd = get_redis(REDIS_DB_SESSION)
        if await rd.exists(f"online:{tid}:{cuid}") > 0:
            return True
        if tid and await rd.exists(f"online::{cuid}") > 0:
            return True
        return False

    async def update_heartbeat(self, tid: str, cuid: str):
        """Extend device online expiration."""
        rd = get_redis(REDIS_DB_SESSION)
        key = f"online:{tid}:{cuid}"
        if await rd.exists(key):
            await rd.expire(key, ONLINE_TTL)
        else:
            await self.set_client_online(tid, cuid, "")

    async def get_all_clients_status(self, tid: str) -> list[dict]:
        """Get all online devices status list under tenant."""
        rd = get_redis(REDIS_DB_SESSION)
        prefix = f"online:{tid}:"
        res = []
        async for key in rd.scan_iter(match=f"{prefix}*"):
            data = await rd.hgetall(key)
            res.append(
                {
                    "uid": key[len(prefix) :],
                    "status": "online",
                    "ip": data.get("ip", ""),
                }
            )
        return res

    async def get_all_online_ips(self, tid: str) -> set[str]:
        """Get set of IP addresses for all online devices."""
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
