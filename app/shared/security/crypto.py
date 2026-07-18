"""MINIClassIsland 密码学与安全服务。

包含 Argon2id 密码哈希、TOTP (pyotp) 生成及验证，以及 Redis 2FA 恢复码管理器。
"""

import secrets
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.shared.utils.config import REDIS_DB_AUTH
from app.shared.utils.redis import get_redis

# Argon2id 参数配置（符合 OWASP 推荐）
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64MB
    parallelism=4,
)

_RECOVERY_KEY_PREFIX = "recovery_codes"
_RECOVERY_CODE_COUNT = 8
_RECOVERY_CODE_LENGTH = 8


# ---- Argon2id 密码哈希 ----

def hash_password(plain: str) -> str:
    """将明文密码哈希为 Argon2id 摘要字符串。"""
    return _hasher.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """验证密码是否与哈希匹配，防计时攻击。"""
    try:
        return _hasher.verify(hashed, plain)
    except VerifyMismatchError:
        return False


# ---- TOTP 双因素认证 ----

def generate_totp_secret() -> str:
    """随机生成 Base32 编码的 TOTP 密钥。"""
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str) -> str:
    """构建 otpauth 协议 URI，用于客户端扫码绑定。"""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="MINIClassIsland")


def verify_totp(secret: str, code: str) -> bool:
    """验证 TOTP 验证码，允许前后 30 秒的偏移窗口。"""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


# ---- 2FA 一次性恢复码 ----

def generate_recovery_codes() -> list[str]:
    """生成 8 个 2FA 一次性 HEX 格式恢复码。"""
    return [
        secrets.token_hex(_RECOVERY_CODE_LENGTH // 2).upper()
        for _ in range(_RECOVERY_CODE_COUNT)
    ]


async def store_recovery_codes(user_id: str, codes: list[str]) -> None:
    """将一次性恢复码持久化存入 Redis 集合（自动覆盖旧码）。"""
    rd = get_redis(REDIS_DB_AUTH)
    key = f"{_RECOVERY_KEY_PREFIX}:{user_id}"
    await rd.delete(key)
    if codes:
        await rd.sadd(key, *codes)


async def use_recovery_code(user_id: str, code: str) -> bool:
    """验证并立即消耗掉一个一次性恢复码。"""
    rd = get_redis(REDIS_DB_AUTH)
    key = f"{_RECOVERY_KEY_PREFIX}:{user_id}"
    removed = await rd.srem(key, code.upper())
    return removed > 0


async def get_remaining_recovery_count(user_id: str) -> int:
    """查询指定用户剩余可用的一次性恢复码个数。"""
    rd = get_redis(REDIS_DB_AUTH)
    return await rd.scard(f"{_RECOVERY_KEY_PREFIX}:{user_id}")


# ---- CC 攻击防护全局请求状态管理 ----

_is_cc_attack_active: bool = False
_global_requests: list[float] = []
_ip_failures: dict[str, list[float]] = {}


def get_cc_state() -> bool:
    """获取当前是否处于 CC 高频攻击保护。"""
    return _is_cc_attack_active


def set_cc_state(state: bool):
    """设置当前 CC 保护状态。"""
    global _is_cc_attack_active
    _is_cc_attack_active = state


def get_ip_failures_dict() -> dict:
    """获取所有记录 IP 失败时间的引用。"""
    return _ip_failures


def get_global_requests() -> list:
    """获取记录全局请求时间戳的引用。"""
    return _global_requests

