"""MINI ClassIsland cryptography and security services.

Includes Argon2id password hashing, TOTP (pyotp) generation/verification, Redis 2FA recovery code manager,
and upstream ClassIsland Credential Base64 JSON encoding.
"""

import base64
import hashlib
import json
import os
import secrets
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


def verify_password(plain: str, hashed: str) -> bool:
    """Verify password match against hash in constant time."""
    try:
        return _hasher.verify(hashed, plain)
    except VerifyMismatchError:
        return False


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


def normalize_credentials_payload(payload: dict) -> dict:
    """Ensure UserCredential and AdminCredential in a Credentials payload are properly encoded."""
    if not isinstance(payload, dict):
        return payload
    out = dict(payload)
    for key in ("UserCredential", "AdminCredential"):
        val = out.get(key)
        if isinstance(val, str) and val and not is_encoded_classisland_credential(val):
            out[key] = encode_classisland_credential(val)
    return out


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


# ---- 2FA One-Time Recovery Codes ----


def generate_recovery_codes() -> list[str]:
    """Generate 8 2FA one-time HEX recovery codes."""
    return [
        secrets.token_hex(_RECOVERY_CODE_LENGTH // 2).upper()
        for _ in range(_RECOVERY_CODE_COUNT)
    ]


async def store_recovery_codes(user_id: str, codes: list[str]) -> None:
    """Persist one-time recovery codes into Redis set."""
    rd = get_redis(REDIS_DB_AUTH)
    key = f"{_RECOVERY_KEY_PREFIX}:{user_id}"
    await rd.delete(key)
    if codes:
        await rd.sadd(key, *codes)


async def use_recovery_code(user_id: str, code: str) -> bool:
    """Verify and consume a one-time recovery code."""
    rd = get_redis(REDIS_DB_AUTH)
    key = f"{_RECOVERY_KEY_PREFIX}:{user_id}"
    removed = await rd.srem(key, code.upper())
    return removed > 0


async def get_remaining_recovery_count(user_id: str) -> int:
    """Query count of remaining recovery codes for user."""
    rd = get_redis(REDIS_DB_AUTH)
    return await rd.scard(f"{_RECOVERY_KEY_PREFIX}:{user_id}")


# ---- CC Attack Protection Global State ----

_is_cc_attack_active: bool = False
_global_requests: list[float] = []
_ip_failures: dict[str, list[float]] = {}


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


def get_global_requests() -> list:
    """Get global request timestamp list reference."""
    return _global_requests
