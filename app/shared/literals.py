import re

# ---- 1. 安全与身份验证参数 (Security & Auth) ----
TOKEN_BYTES = 192
DEFAULT_TTL = 300
GRACE_TTL = 30

RECOVERY_KEY_PREFIX = "recovery_codes"
RECOVERY_CODE_COUNT = 8
RECOVERY_CODE_LENGTH = 8

# Argon2id 消耗参数配置（符合 OWASP 推荐）
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64MB
ARGON2_PARALLELISM = 4


# ---- 2. 客户端配对参数 (Pairing) ----
PAIRING_CHARSET = "2346789ABCEFGHJKLMNPRSTWXYZ"
PAIRING_CODE_LEN = 8


# ---- 3. 业务服务参数与配置 (Services) ----
# 用户名与 Slug 正则校验器
USERNAME_RE = re.compile(r"^[a-z0-9_]{3,64}$")
SLUG_RE = re.compile(r"^[a-z0-9\-]{3,64}$")

# 默认账户限额规则
DEFAULT_QUOTAS = [
    ("max_clients", 50),
    ("max_bandwidth_mb", 1024),
    ("feature.ota", 1),
    ("feature.audit", 1),
]

# 系统内置角色预置数据
SYSTEM_ROLES = [
    ("banned", "已封禁", -1),
    ("pending", "待激活", 0),
    ("normal", "普通用户", 10),
    ("admin", "管理员", 90),
    ("superadmin", "超级管理员", 100),
]


# ---- 4. 数据模式校验参数 (Schemas) ----
SCHEMA_USERNAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{2,63}$")
SCHEMA_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,62}[a-z0-9]$")
PWD_UPPER = re.compile(r"[A-Z]")
PWD_LOWER = re.compile(r"[a-z]")
PWD_DIGIT = re.compile(r"[0-9]")

# 系统设置允许的 Key 白名单
ALLOWED_SETTINGS_KEYS = {
    "registration_open",
    "require_approval",
    "max_accounts_per_user",
    "default_role",
    "motd",
}
