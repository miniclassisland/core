"""MINI ClassIsland cryptography and security services.

Includes Argon2id password hashing, TOTP (pyotp) generation/verification, Redis 2FA recovery code manager,
and upstream ClassIsland Credential Base64 JSON encoding.
"""

import asyncio
import base64
from collections import deque
import hashlib
import json
import os
import secrets
import uuid
from typing import Any
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.shared.utils.config import REDIS_DB_AUTH
from app.shared.utils.redis import get_redis
from app.shared.literals import (
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    RECOVERY_KEY_PREFIX,
    RECOVERY_CODE_COUNT,
    RECOVERY_CODE_LENGTH,
    LEGACY_RESOURCE_ID_MAP,
)

# Argon2id configuration (OWASP recommended parameters)
_hasher = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,  # 64MB
    parallelism=ARGON2_PARALLELISM,
)

_RECOVERY_KEY_PREFIX = RECOVERY_KEY_PREFIX
_RECOVERY_CODE_COUNT = RECOVERY_CODE_COUNT
_RECOVERY_CODE_LENGTH = RECOVERY_CODE_LENGTH


# ---- Argon2id Password Hashing ----


def hash_password(plain: str) -> str:
    """Hash plain password into Argon2id digest string."""
    return _hasher.hash(plain)


async def hash_password_async(plain: str) -> str:
    """Hash plain password in worker thread pool to avoid blocking the asyncio event loop."""
    return await asyncio.to_thread(_hasher.hash, plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify password match against hash in constant time."""
    try:
        return _hasher.verify(hashed, plain)
    except VerifyMismatchError:
        return False


async def verify_password_async(plain: str, hashed: str) -> bool:
    """Verify password match in worker thread pool to avoid blocking the asyncio event loop."""
    return await asyncio.to_thread(verify_password, plain, hashed)


# ---- Upstream ClassIsland Credential Encoding ----


def is_encoded_classisland_credential(value: str) -> bool:
    """Check if a string is already a Base64-encoded ClassIsland Credential JSON object."""
    if not value or not isinstance(value, str):
        return False
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True).decode("utf-8")
        parsed = json.loads(raw)
        return isinstance(parsed, dict) and isinstance(parsed.get("Items"), list)
    except Exception:
        return False


def encode_classisland_credential(password: str) -> str:
    """Encode plaintext password into upstream ClassIsland Credential Base64 JSON string.

    Upstream ClassIsland PasswordAuthorizeProvider expects:
      SHA256(UTF8(password) + salt_16_bytes) -> Base64 PasswordHash & Base64 PasswordSalt
    wrapped in Credential(Items=[CredentialItem(ProviderId="classisland.authProviders.password", ...)])
    and Base64-encoded.
    """
    if not password:
        return ""
    if is_encoded_classisland_credential(password):
        return password
    salt = os.urandom(16)
    digest = hashlib.sha256(password.encode("utf-8") + salt).digest()
    credential_obj = {
        "Items": [
            {
                "ProviderId": "classisland.authProviders.password",
                "ProviderSettings": {
                    "PasswordHash": base64.b64encode(digest).decode("ascii"),
                    "PasswordSalt": base64.b64encode(salt).decode("ascii"),
                },
                "CustomName": "",
                "IsCustomNameEnabled": False,
            }
        ]
    }
    raw_json = json.dumps(credential_obj, separators=(",", ":"), ensure_ascii=False)
    return base64.b64encode(raw_json.encode("utf-8")).decode("ascii")


def normalize_credentials_payload(payload: Any) -> Any:
    """Ensure UserCredential and AdminCredential in a Credentials payload are properly encoded."""
    if not isinstance(payload, dict):
        return payload
    out = dict(payload)
    for key in ("UserCredential", "AdminCredential"):
        val = out.get(key)
        if isinstance(val, str) and val and not is_encoded_classisland_credential(val):
            out[key] = encode_classisland_credential(val)
    return out


_EMPTY_GUID = "00000000-0000-0000-0000-000000000000"


def ensure_guid_str(value: str, *, allow_empty: bool = False) -> str:
    """Convert any identifier string into a valid canonical UUID string for upstream ClassIsland System.Guid."""
    if not value or not isinstance(value, str):
        return "" if allow_empty else _EMPTY_GUID
    s = value.strip()
    if not s:
        return "" if allow_empty else _EMPTY_GUID
    if s in LEGACY_RESOURCE_ID_MAP:
        return LEGACY_RESOURCE_ID_MAP[s]
    try:
        return str(uuid.UUID(s))
    except (ValueError, AttributeError):
        return str(uuid.uuid5(uuid.NAMESPACE_OID, f"miniclassisland:{s}"))


def _normalize_hhmmss(raw: str, default: str = "08:00:00") -> tuple[str, str]:
    """Return (StartSecond ISO string, StartTime HH:mm:ss string)."""
    if not raw or not isinstance(raw, str):
        return f"1970-01-01T{default}", default
    t_idx = raw.find("T")
    time_part = raw[t_idx + 1 :] if t_idx >= 0 else raw
    parts = time_part.split(":")
    h = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 8
    m = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    sec_str = parts[2].split(".")[0] if len(parts) > 2 else "00"
    sec = int(sec_str) if sec_str.isdigit() else 0
    span = f"{h:02d}:{m:02d}:{sec:02d}"
    return f"1970-01-01T{span}", span


def normalize_resource_payload(resource_type: str, payload: Any) -> Any:
    """Normalize resource JSON to strictly conform to upstream ClassIsland C# Profile/Model serialization."""
    if not isinstance(payload, dict):
        return payload

    if resource_type == "Credentials":
        return normalize_credentials_payload(payload)

    if resource_type == "Subjects":
        sub_val = payload.get("Subjects")
        raw_subs: dict = (
            sub_val
            if isinstance(sub_val, dict)
            else {k: v for k, v in payload.items() if isinstance(v, dict)}
        )
        norm_subs: dict[str, dict] = {}
        for k, v in raw_subs.items():
            if isinstance(v, dict):
                norm_subs[ensure_guid_str(str(k))] = dict(v)
        return {"Subjects": norm_subs}

    if resource_type == "TimeLayout":
        tl_val = payload.get("TimeLayouts")
        raw_tls: dict = (
            tl_val
            if isinstance(tl_val, dict)
            else {k: v for k, v in payload.items() if isinstance(v, dict)}
        )
        norm_tls: dict[str, dict] = {}
        for k, v in raw_tls.items():
            if not isinstance(v, dict):
                continue
            tl_copy = dict(v)
            layouts = tl_copy.get("Layouts")
            if isinstance(layouts, list):
                norm_items = []
                for item in layouts:
                    if not isinstance(item, dict):
                        continue
                    it = dict(item)
                    s_raw = it.get("StartTime") or it.get("StartSecond") or "08:00:00"
                    e_raw = it.get("EndTime") or it.get("EndSecond") or "08:45:00"
                    s_iso, s_span = _normalize_hhmmss(str(s_raw), "08:00:00")
                    e_iso, e_span = _normalize_hhmmss(str(e_raw), "08:45:00")
                    it["StartSecond"] = s_iso
                    it["EndSecond"] = e_iso
                    it["StartTime"] = s_span
                    it["EndTime"] = e_span
                    def_cls = it.get("DefaultClassId")
                    it["DefaultClassId"] = (
                        ensure_guid_str(str(def_cls)) if def_cls else _EMPTY_GUID
                    )
                    norm_items.append(it)
                tl_copy["Layouts"] = norm_items
            norm_tls[ensure_guid_str(str(k))] = tl_copy
        return {"TimeLayouts": norm_tls}

    if resource_type == "ClassPlan":
        has_wrapper = isinstance(payload.get("ClassPlans"), dict)
        raw_cps = (
            payload["ClassPlans"]
            if has_wrapper
            else {
                k: v
                for k, v in payload.items()
                if k != "ClassPlanGroups" and isinstance(v, dict)
            }
        )
        norm_cps: dict[str, dict] = {}
        for k, v in raw_cps.items():
            if not isinstance(v, dict):
                continue
            cp_copy = dict(v)
            tl_id = cp_copy.get("TimeLayoutId")
            cp_copy["TimeLayoutId"] = (
                ensure_guid_str(str(tl_id)) if tl_id else _EMPTY_GUID
            )
            assoc_grp = cp_copy.get("AssociatedGroup")
            cp_copy["AssociatedGroup"] = (
                ensure_guid_str(str(assoc_grp)) if assoc_grp else _EMPTY_GUID
            )
            ov_src = cp_copy.get("OverlaySourceId")
            if ov_src:
                cp_copy["OverlaySourceId"] = ensure_guid_str(str(ov_src))
            classes = cp_copy.get("Classes")
            if isinstance(classes, list):
                norm_classes = []
                for cls_item in classes:
                    if not isinstance(cls_item, dict):
                        continue
                    ci = dict(cls_item)
                    sub_id = ci.get("SubjectId")
                    ci["SubjectId"] = (
                        ensure_guid_str(str(sub_id)) if sub_id else _EMPTY_GUID
                    )
                    norm_classes.append(ci)
                cp_copy["Classes"] = norm_classes
            norm_cps[ensure_guid_str(str(k))] = cp_copy

        grp_val = payload.get("ClassPlanGroups")
        raw_groups: dict = (
            grp_val
            if isinstance(grp_val, dict)
            else {_EMPTY_GUID: {"Name": "默认课表群", "IsGlobal": False}}
        )
        norm_groups: dict[str, dict] = {}
        for gk, gv in raw_groups.items():
            if isinstance(gv, dict):
                norm_groups[ensure_guid_str(str(gk))] = dict(gv)
        return {"ClassPlans": norm_cps, "ClassPlanGroups": norm_groups}

    return payload


# ---- TOTP Two-Factor Authentication ----


def generate_totp_secret() -> str:
    """Randomly generate Base32 encoded TOTP secret key."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str) -> str:
    """Construct otpauth URI for client QR code scanning."""
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=email, issuer_name="MINI ClassIsland"
    )


def verify_totp(secret: str, code: str) -> bool:
    """Verify TOTP verification code with 30-second window tolerance."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


async def verify_totp_once(user_id: str, secret: str, code: str) -> bool:
    """Verify TOTP code and prevent replay within the validity window."""
    if not verify_totp(secret, code):
        return False
    rd = get_redis(REDIS_DB_AUTH)
    clean_code = code.strip()
    replay_key = f"totp_used:{user_id}:{clean_code}"
    acquired = await rd.set(replay_key, "1", ex=90, nx=True)
    return bool(acquired)


# ---- 2FA One-Time Recovery Codes ----


def generate_recovery_codes() -> list[str]:
    """Generate 8 2FA one-time HEX recovery codes."""
    return [
        secrets.token_hex(_RECOVERY_CODE_LENGTH // 2).upper()
        for _ in range(_RECOVERY_CODE_COUNT)
    ]


def _hash_recovery_code(code: str) -> str:
    """Compute SHA-256 hex digest of normalized uppercase recovery code."""
    return hashlib.sha256(code.strip().upper().encode("utf-8")).hexdigest()


async def store_recovery_codes(user_id: str, codes: list[str]) -> None:
    """Persist SHA-256 hashed one-time recovery codes into Redis set."""
    rd = get_redis(REDIS_DB_AUTH)
    key = f"{_RECOVERY_KEY_PREFIX}:{user_id}"
    await rd.delete(key)
    if codes:
        hashed_codes = [_hash_recovery_code(c) for c in codes]
        await rd.sadd(key, *hashed_codes)


async def delete_recovery_codes(user_id: str) -> None:
    """Delete all stored 2FA recovery codes for user."""
    rd = get_redis(REDIS_DB_AUTH)
    await rd.delete(f"{_RECOVERY_KEY_PREFIX}:{user_id}")


async def check_recovery_code(user_id: str, code: str) -> bool:
    """Check if a recovery code is valid for user without consuming it."""
    if not code or not code.strip():
        return False
    rd = get_redis(REDIS_DB_AUTH)
    key = f"{_RECOVERY_KEY_PREFIX}:{user_id}"
    hashed = _hash_recovery_code(code)
    if await rd.sismember(key, hashed):
        return True
    return bool(await rd.sismember(key, code.strip().upper()))


async def use_recovery_code(user_id: str, code: str) -> bool:
    """Verify and consume a one-time recovery code (supports hashed and legacy raw entries)."""
    rd = get_redis(REDIS_DB_AUTH)
    key = f"{_RECOVERY_KEY_PREFIX}:{user_id}"
    hashed = _hash_recovery_code(code)
    removed = await rd.srem(key, hashed)
    if removed > 0:
        return True
    removed_legacy = await rd.srem(key, code.strip().upper())
    return removed_legacy > 0


async def get_remaining_recovery_count(user_id: str) -> int:
    """Query count of remaining recovery codes for user."""
    rd = get_redis(REDIS_DB_AUTH)
    return await rd.scard(f"{_RECOVERY_KEY_PREFIX}:{user_id}")


# ---- CC Attack Protection Global State ----

_is_cc_attack_active: bool = False
_global_requests: deque[float] = deque()
_ip_failures: dict[str, Any] = {}


def get_cc_state() -> bool:
    """Get current CC attack protection active state."""
    return _is_cc_attack_active


def set_cc_state(state: bool):
    """Set current CC attack protection active state."""
    global _is_cc_attack_active
    _is_cc_attack_active = state


def get_ip_failures_dict() -> dict:
    """Get IP failure timestamp dict reference."""
    return _ip_failures


def get_global_requests() -> deque[float]:
    """Get global request timestamp deque reference."""
    return _global_requests
