"""MINIClassIsland shared literal constants."""

import re

# ---- System Metadata & Default Configurations ----
SYS_NAME = "MINI ClassIsland Core Management Backend System"
DEFAULT_BASE_DOMAIN = "miniclassisland.com"
DEFAULT_KEY_FILE = "miniclassisland_server.key"
DEFAULT_ADMIN_SECRET = "change-me"
DEFAULT_CONFIG_DIR = ".miniclassisland"
DEFAULT_CONFIG_FILE = "config.json"
DEFAULT_PID_FILE = "miniclassisland.pid"

# Default Database & Network Allocations
DEFAULT_PG_USER = "postgres"
DEFAULT_PG_PWD = "password"
DEFAULT_PG_ADDR = "localhost:5432"
DEFAULT_PG_DB = "miniclassisland"

DEFAULT_REDIS_ADDR = "localhost:6379"
DEFAULT_REDIS_DB = 0

DEFAULT_CLIENT_PORT = 27041
DEFAULT_MGMT_PORT = 27042
DEFAULT_ADMIN_PORT = 27043
DEFAULT_GRPC_PORT = 27044

PUBLIC_SCHEMA = "public"
REDIS_AUTH_PREFIX = "auth:"
TENANT_ID_KEY = "tenant_id"
SCHEMA_KEY = "schema"


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
USERNAME_RE = re.compile(r"^[a-z0-9_]{3,64}$")
SLUG_RE = re.compile(r"^[a-z0-9\-]{3,64}$")
SAFE_IDENTIFIER_RE = re.compile(r"^[a-z0-9_\-]+$")

DEFAULT_QUOTAS = [
    ("max_clients", 50),
    ("max_bandwidth_mb", 1024),
    ("feature.ota", 1),
    ("feature.audit", 1),
]

SYSTEM_ROLES = [
    ("banned", "Banned", -1),
    ("pending", "Pending Activation", 0),
    ("normal", "Normal User", 10),
    ("admin", "Administrator", 90),
    ("superadmin", "Super Administrator", 100),
]

ROLE_BANNED = "banned"
ROLE_PENDING = "pending"
ROLE_NORMAL = "normal"
ROLE_ADMIN = "admin"
ROLE_SUPERADMIN = "superadmin"


# ---- 4. Schemas ----
SCHEMA_USERNAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{2,63}$")
SCHEMA_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,62}[a-z0-9]$")
PWD_UPPER = re.compile(r"[A-Z]")
PWD_LOWER = re.compile(r"[a-z]")
PWD_DIGIT = re.compile(r"[0-9]")

ALLOWED_SETTINGS_KEYS = {
    "registration_open",
    "require_approval",
    "max_accounts_per_user",
    "default_role",
    "motd",
}

RESERVED_SUBDOMAINS = {
    "admin", "api", "www", "mail", "ftp", "ssh", "dns", "smtp",
    "pop", "imap", "ntp", "snmp", "ldap", "tcp", "udp", "system",
    "core", "dev", "test", "staging", "prod", "auth", "login",
}


# ---- 5. HTTP & API Error Messages ----
MSG_USER_NOT_FOUND = "User not found"
MSG_ACCOUNT_NOT_FOUND = "Account not found"
MSG_INVALID_CREDENTIALS = "Invalid username or password"
MSG_UNAUTHORIZED_ACCESS = "Unauthorized access"
MSG_PERMISSION_DENIED = "Permission denied"
MSG_ACCOUNT_SUSPENDED = "Account is suspended or pending approval"
MSG_REGISTRATION_CLOSED = "Self-registration is currently closed"
MSG_USERNAME_EXISTS = "Username already exists"
MSG_EMAIL_EXISTS = "Email address already registered"
MSG_SLUG_EXISTS = "Account slug already in use"
MSG_QUOTA_EXCEEDED = "Quota limit reached"
MSG_INVALID_2FA_CODE = "Invalid 2FA verification code"
MSG_2FA_REQUIRED = "2FA verification code required"
MSG_INVALID_PAIRING_CODE = "Invalid or expired pairing code"
MSG_PAIRING_NOT_FOUND = "Pairing request not found"
MSG_PAIRING_ALREADY_APPROVED = "Pairing request already approved"
MSG_TENANT_NOT_FOUND = "Tenant account not found"
MSG_INVALID_TENANT_CONTEXT = "Invalid tenant context"


# ---- 6. gRPC Status & Error Messages ----
MSG_GRPC_UNAUTHENTICATED = "Unauthenticated gRPC request"
MSG_GRPC_SESSION_INVALID = "Invalid gRPC session token"
MSG_GRPC_CLIENT_NOT_REGISTERED = "Client device not registered"
MSG_GRPC_HANDSHAKE_FAILED = "Handshake verification failed"


# ---- 7. Logging & Formats ----
LOG_FORMAT = "%(asctime)s.%(msecs)03d | %(levelname)-5s | %(port_tag)s | %(name)-30s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
