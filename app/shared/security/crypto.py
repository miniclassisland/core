"""MINIClassIsland cryptography and security services.

Includes Argon2id password hashing, TOTP (pyotp) generation/verification, and Redis 2FA recovery code manager.
"""

import secrets
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.shared.utils.config import REDIS_DB_AUTH
from app.shared.utils.redis import get_redis

# Argon2id configuration (OWASP recommended parameters)
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64MB
    parallelism=4,
)

_RECOVERY_KEY_PREFIX = "recovery_codes"
_RECOVERY_CODE_COUNT = 8
_RECOVERY_CODE_LENGTH = 8


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


# ---- TOTP Two-Factor Authentication ----

def generate_totp_secret() -> str:
    """Randomly generate Base32 encoded TOTP secret key."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str) -> str:
    """Construct otpauth URI for client QR code scanning."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="MINIClassIsland")


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

