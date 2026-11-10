"""gRPC session manager.

Contains key pair management (PGPy), handshake challenge state, heartbeat online state, and session state.
"""

import hashlib
import json
import os
import secrets
import time
import logging
from typing import Any

from app.shared.security import warning_filters  # noqa: F401  # must precede pgpy
import pgpy
from pgpy.constants import (
    PubKeyAlgorithm,
    KeyFlags,
    HashAlgorithm,
    SymmetricKeyAlgorithm,
    SignatureType,
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
            usage={KeyFlags.EncryptCommunications, KeyFlags.Sign},
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
        )
        self.private_key, self.public_key_armor = k, str(k.pubkey)
        try:
            fd = os.open(
                self._key_file,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            with os.fdopen(fd, "w") as f:
                f.write(str(k))
        except OSError:
            with open(self._key_file, "w") as f:
                f.write(str(k))
        try:
            os.chmod(self._key_file, 0o600)
        except OSError:
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

    def sign_detached(self, text: str) -> str:
        """Sign canonical text with server private key and return ASCII-armored detached signature."""
        if self.private_key is None:
            return ""
        try:
            pk: Any = self.private_key
            data = text.encode("utf-8")
            try:
                sig = pk.sign(data, hash=HashAlgorithm.SHA256)
            except Exception:
                raw_sig = pgpy.PGPSignature.new(
                    SignatureType.BinaryDocument,
                    pk.key_algorithm,
                    HashAlgorithm.SHA256,
                    pk.fingerprint.keyid,
                )
                sig = pk._sign(data, raw_sig)
            return str(sig)
        except Exception as e:
            logger.error("GPG signing failed: %s", e)
            return ""


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

    def build_signed_command_envelope(
        self,
        request_guid: str,
        client_uid: str,
        action: str,
        payload: dict[str, Any] | str | None = None,
        ttl_seconds: int = 120,
    ) -> dict[str, Any]:
        """Build a PGP-signed Extended Management Command envelope matching CommandSignatureVerifier."""
        if payload is None:
            payload_json = "{}"
        elif isinstance(payload, str):
            payload_json = payload
        else:
            payload_json = json.dumps(payload, ensure_ascii=False)
        issued_at = int(time.time())
        expires_at = issued_at + max(10, min(int(ttl_seconds), 600))
        norm_guid = request_guid.strip()
        norm_uid = client_uid.strip()
        norm_action = action.strip().lower()
        payload_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest().lower()
        canonical_text = (
            f"MCI-EXTCMD-V1|1|{norm_guid}|{norm_uid}|"
            f"{issued_at}|{expires_at}|{norm_action}|{payload_hash}"
        )
        signature = self._km.sign_detached(canonical_text)
        return {
            "version": 1,
            "requestGuid": norm_guid,
            "clientUid": norm_uid,
            "issuedAtUtc": issued_at,
            "expiresAtUtc": expires_at,
            "action": norm_action,
            "payloadJson": payload_json,
            "signature": signature,
        }

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
        if len(_LOCAL_SESSION_CACHE) >= _MAX_LOCAL_SESSION_CACHE:
            _LOCAL_SESSION_CACHE.pop(next(iter(_LOCAL_SESSION_CACHE)), None)
        _LOCAL_SESSION_CACHE[sid] = (
            time.monotonic() + _LOCAL_SESSION_TTL,
            cuid,
            tenant_id,
        )
        return sid

    async def validate_session(
        self, sid: str, *, tenant_id: str | None = None
    ) -> str | None:
        """Retrieve corresponding client cuid from session ID (with optional tenant verification)."""
        if not sid:
            return None
        now = time.monotonic()
        hit = _LOCAL_SESSION_CACHE.get(sid)
        if hit is not None and now < hit[0]:
            cached_cuid, cached_tid = hit[1], hit[2]
            if (
                tenant_id
                and tenant_id != "default"
                and cached_tid
                and cached_tid != "default"
                and cached_tid != tenant_id
            ):
                return None
            return cached_cuid
        rd = get_redis(REDIS_DB_SESSION)
        data = await rd.hgetall(f"session:{sid}")
        if not data or "cuid" not in data:
            return None
        cuid = data["cuid"]
        tid = data.get("tenant_id", "")
        if len(_LOCAL_SESSION_CACHE) >= _MAX_LOCAL_SESSION_CACHE:
            _LOCAL_SESSION_CACHE.pop(next(iter(_LOCAL_SESSION_CACHE)), None)
        _LOCAL_SESSION_CACHE[sid] = (now + _LOCAL_SESSION_TTL, cuid, tid)
        if (
            tenant_id
            and tenant_id != "default"
            and tid
            and tid != "default"
            and tid != tenant_id
        ):
            return None
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

    async def mark_client_extend_enabled(
        self, tid: str, cuid: str, version: str = "2.0.0.1"
    ):
        """Record that a client device has MiniClassIsland.ExtendManagement active."""
        rd = get_redis(REDIS_DB_SESSION)
        ext_key = f"extend_mgmt:{tid}:{cuid}"
        pipe = rd.pipeline(transaction=False)
        pipe.hset(
            ext_key,
            mapping={
                "enabled": "1",
                "version": version or "2.0.0.1",
                "updated_at": str(int(time.time())),
            },
        )
        pipe.expire(ext_key, SESSION_TTL * 7)
        if tid:
            pipe.sadd(f"extend_mgmt_set:{tid}", cuid)
            pipe.expire(f"extend_mgmt_set:{tid}", SESSION_TTL * 7)
        await pipe.execute()

    async def get_extend_enabled_clients(self, tid: str) -> dict[str, dict[str, str]]:
        """Return mapping of client_uid -> {enabled, version, updated_at} for tenant."""
        rd = get_redis(REDIS_DB_SESSION)
        out: dict[str, dict[str, str]] = {}
        if tid:
            members = list(await rd.smembers(f"extend_mgmt_set:{tid}"))
            if not members:
                return out
            pipe = rd.pipeline(transaction=False)
            for cuid in members:
                pipe.hgetall(f"extend_mgmt:{tid}:{cuid}")
            results = await pipe.execute()
            for cuid, data in zip(members, results):
                if data and data.get("enabled") == "1":
                    out[cuid] = data
        return out

    async def set_client_online(
        self,
        tid: str,
        cuid: str,
        ip: str = "",
        extend_enabled: bool = False,
        extend_version: str = "",
    ):
        """Record device online heartbeat and bind IP via single Redis pipeline."""
        rd = get_redis(REDIS_DB_SESSION)
        key = f"online:{tid}:{cuid}"
        mapping = {"status": "online", "ip": ip}
        if extend_enabled:
            mapping["extend_enabled"] = "1"
            mapping["extend_version"] = extend_version or "2.0.0.1"
        pipe = rd.pipeline(transaction=False)
        pipe.hset(key, mapping=mapping)
        pipe.expire(key, ONLINE_TTL)
        if tid:
            idx_key = f"online_set:{tid}"
            pipe.sadd(idx_key, cuid)
            pipe.expire(idx_key, SESSION_TTL)
        if extend_enabled:
            ext_key = f"extend_mgmt:{tid}:{cuid}"
            pipe.hset(
                ext_key,
                mapping={
                    "enabled": "1",
                    "version": extend_version or "2.0.0.1",
                    "updated_at": str(int(time.time())),
                },
            )
            pipe.expire(ext_key, SESSION_TTL * 7)
            if tid:
                pipe.sadd(f"extend_mgmt_set:{tid}", cuid)
                pipe.expire(f"extend_mgmt_set:{tid}", SESSION_TTL * 7)
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
            pipe = rd.pipeline(transaction=False)
            pipe.expire(key, ONLINE_TTL)
            if tid:
                pipe.expire(f"online_set:{tid}", SESSION_TTL)
            await pipe.execute()
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
                            "extend_management_enabled": data.get("extend_enabled")
                            == "1",
                            "extend_management_version": data.get("extend_version", ""),
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
