import re

# ---- 1. Security & Auth ----
TOKEN_BYTES = 192
DEFAULT_TTL = 300
GRACE_TTL = 30

RECOVERY_KEY_PREFIX = "recovery_codes"
RECOVERY_CODE_COUNT = 8
RECOVERY_CODE_LENGTH = 8

# Argon2id cost parameters (OWASP recommendations)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64MB
ARGON2_PARALLELISM = 4


# ---- 2. Client Pairing ----
PAIRING_CHARSET = "2346789ABCEFGHJKLMNPRSTWXYZ"
PAIRING_CODE_LEN = 8


# ---- 3. Services Configuration ----
# Username and Slug regex validators
USERNAME_RE = re.compile(r"^[a-z0-9_]{3,64}$")
SLUG_RE = re.compile(r"^[a-z0-9\-]{3,64}$")

# Default account quota limits
DEFAULT_QUOTAS = [
    ("max_clients", 50),
    ("max_bandwidth_mb", 1024),
    ("feature.ota", 1),
    ("feature.audit", 1),
]

# System roles preset data
SYSTEM_ROLES = [
    ("banned", "Banned", -1),
    ("pending", "Pending Activation", 0),
    ("normal", "Normal User", 10),
    ("admin", "Administrator", 90),
    ("superadmin", "Super Administrator", 100),
]


# ---- 4. Schemas ----
SCHEMA_USERNAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{2,63}$")
SCHEMA_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,62}[a-z0-9]$")
PWD_UPPER = re.compile(r"[A-Z]")
PWD_LOWER = re.compile(r"[a-z]")
PWD_DIGIT = re.compile(r"[0-9]")

# Allowed system settings keys whitelist
ALLOWED_SETTINGS_KEYS = {
    "registration_open",
    "require_approval",
    "max_accounts_per_user",
    "default_role",
    "motd",
}
