"""gRPC session manager.

Contains key pair management (PGPy), handshake challenge state, heartbeat online state, and session state.
"""

import os
import secrets
import time
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
_LOCAL_SESSION_CACHE: dict[str, tuple[float, str, str]] = {}
_LOCAL_SESSION_TTL = 30.0
_MAX_LOCAL_SESSION_CACHE = 16384


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
        try:
            os.chmod(self._key_file, 0o600)
        except OSError:  # pragma: no cover
            pass

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

    async def store_pending_handshake(
        self, tenant_id: str, cuid: str, token: str, peer_ip: str = ""
    ):
        """Cache decrypted challenge token (and optional initiating peer IP) awaiting Complete handshake."""
        rd = get_redis()  # Default DB
        key = f"handshake:{tenant_id}:{cuid}"
        await rd.set(key, token, ex=HANDSHAKE_TTL)
        if peer_ip:
            await rd.set(f"handshake_ip:{tenant_id}:{cuid}", peer_ip, ex=HANDSHAKE_TTL)

    async def pop_handshake_challenge(self, tenant_id: str, cuid: str) -> str | None:
        """Retrieve challenge token and delete immediately."""
        rd = get_redis()
        key = f"handshake:{tenant_id}:{cuid}"
        val = await rd.get(key)
        if val:
            await rd.delete(key)
        return val

    async def pop_handshake_ip(self, tenant_id: str, cuid: str) -> str | None:
        """Retrieve initiating peer IP recorded during BeginHandshake and delete immediately."""
        rd = get_redis()
        key = f"handshake_ip:{tenant_id}:{cuid}"
        val = await rd.get(key)
        if val:
            await rd.delete(key)
        return val

    async def create_session(self, tenant_id: str, cuid: str) -> str:
        """Generate session token for device and bind identity."""
        rd = get_redis(REDIS_DB_SESSION)
        sid = secrets.token_urlsafe(32)
        key = f"session:{sid}"
        await rd.hset(key, mapping={"cuid": cuid, "tenant_id": tenant_id})
        await rd.expire(key, SESSION_TTL)
        if len(_LOCAL_SESSION_CACHE) >= _MAX_LOCAL_SESSION_CACHE:  # pragma: no cover
            _LOCAL_SESSION_CACHE.clear()
        _LOCAL_SESSION_CACHE[sid] = (
            time.monotonic() + _LOCAL_SESSION_TTL,
            cuid,
            tenant_id,
        )
        return sid

    async def validate_session(self, sid: str) -> str | None:
        """Retrieve corresponding client cuid from session ID."""
        if not sid:
            return None
        now = time.monotonic()
        hit = _LOCAL_SESSION_CACHE.get(sid)
        if hit is not None and now < hit[0]:
            return hit[1]
        rd = get_redis(REDIS_DB_SESSION)
        data = await rd.hgetall(f"session:{sid}")
        if not data or "cuid" not in data:
            return None
        cuid = data["cuid"]
        tid = data.get("tenant_id", "")
        if len(_LOCAL_SESSION_CACHE) >= _MAX_LOCAL_SESSION_CACHE:  # pragma: no cover
            _LOCAL_SESSION_CACHE.clear()
        _LOCAL_SESSION_CACHE[sid] = (now + _LOCAL_SESSION_TTL, cuid, tid)
        return cuid

    async def get_session_tenant(self, sid: str) -> str | None:
        """Retrieve corresponding tenant ID from session ID."""
        if not sid:
            return None
        now = time.monotonic()
        hit = _LOCAL_SESSION_CACHE.get(sid)
        if hit is not None and now < hit[0]:
            return hit[2]
        rd = get_redis(REDIS_DB_SESSION)
        return await rd.hget(f"session:{sid}", "tenant_id")

    async def set_client_online(self, tid: str, cuid: str, ip: str = ""):
        """Record device online heartbeat and bind IP via single Redis pipeline."""
        rd = get_redis(REDIS_DB_SESSION)
        key = f"online:{tid}:{cuid}"
        pipe = rd.pipeline(transaction=False)
        pipe.hset(key, mapping={"status": "online", "ip": ip})
        pipe.expire(key, ONLINE_TTL)
        if tid:
            idx_key = f"online_set:{tid}"
            pipe.sadd(idx_key, cuid)
            pipe.expire(idx_key, SESSION_TTL)
        await pipe.execute()

    async def set_client_offline(self, tid: str, cuid: str):
        """Explicitly set device offline via single Redis pipeline."""
        rd = get_redis(REDIS_DB_SESSION)
        pipe = rd.pipeline(transaction=False)
        pipe.delete(f"online:{tid}:{cuid}")
        if tid:
            pipe.srem(f"online_set:{tid}", cuid)
        await pipe.execute()

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
            if tid:
                await rd.expire(f"online_set:{tid}", SESSION_TTL)
        else:
            await self.set_client_online(tid, cuid, "")

    async def get_all_clients_status(self, tid: str) -> list[dict]:
        """Get all online devices status list under tenant via O(K_tenant) set index and pipeline."""
        rd = get_redis(REDIS_DB_SESSION)
        res = []
        seen: set[str] = set()
        if tid:
            idx_key = f"online_set:{tid}"
            members = list(await rd.smembers(idx_key))
            if not members:
                return res
            pipe = rd.pipeline(transaction=False)
            for cuid in members:
                pipe.hgetall(f"online:{tid}:{cuid}")
            results = await pipe.execute()
            stale: list[str] = []
            for cuid, data in zip(members, results):
                if data:
                    seen.add(cuid)
                    res.append(
                        {
                            "uid": cuid,
                            "status": "online",
                            "ip": data.get("ip", ""),
                        }
                    )
                else:
                    stale.append(cuid)
            if stale:
                await rd.srem(idx_key, *stale)
            return res

        prefix = "online::"
        async for key in rd.scan_iter(match=f"{prefix}*"):
            uid = key[len(prefix) :]
            if uid not in seen:
                data = await rd.hgetall(key)
                res.append(
                    {
                        "uid": uid,
                        "status": "online",
                        "ip": data.get("ip", ""),
                    }
                )
        return res
