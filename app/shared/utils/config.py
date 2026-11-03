"""Global application configuration and initialization state checking.

Configuration priority: .miniclassisland/config.json > Environment variables > .env default values.
"""

import json
import logging
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.shared.literals import (
    DEFAULT_ADMIN_PORT,
    DEFAULT_ADMIN_SECRET,
    DEFAULT_BASE_DOMAIN,
    DEFAULT_CLIENT_PORT,
    DEFAULT_CONFIG_DIR,
    DEFAULT_CONFIG_FILE,
    DEFAULT_GRPC_PORT,
    DEFAULT_KEY_FILE,
    DEFAULT_MGMT_PORT,
    DEFAULT_PG_ADDR,
    DEFAULT_PG_DB,
    DEFAULT_PG_PWD,
    DEFAULT_PG_USER,
    DEFAULT_REDIS_ADDR,
    DEFAULT_REDIS_DB,
    PUBLIC_SCHEMA,
)

logger = logging.getLogger(__name__)

# Project root directory (relative to app/shared/utils/config.py)
_PROJECT_ROOT = Path(__file__).resolve().parents[3]


class AppSettings(BaseSettings):
    """MINI ClassIsland global settings, automatically loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=str(_PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database / Redis connection strings
    database_url: str = ""
    redis_url: str = ""

    # PostgreSQL environment variables fallback
    pg_user: str = DEFAULT_PG_USER
    pg_pwd: str = DEFAULT_PG_PWD
    pg_addr: str = DEFAULT_PG_ADDR
    pg_db: str = DEFAULT_PG_DB

    # Redis environment variables fallback
    redis_pwd: str = ""
    redis_addr: str = DEFAULT_REDIS_ADDR
    redis_db: int = DEFAULT_REDIS_DB

    # Multi-tenant base domain
    miniclassisland_base_domain: str = DEFAULT_BASE_DOMAIN

    # Service port allocations
    miniclassisland_client_port: int = DEFAULT_CLIENT_PORT
    miniclassisland_management_port: int = DEFAULT_MGMT_PORT
    miniclassisland_admin_port: int = DEFAULT_ADMIN_PORT
    miniclassisland_grpc_port: int = DEFAULT_GRPC_PORT

    # GPG key file and admin secret
    miniclassisland_key_file: str = DEFAULT_KEY_FILE
    miniclassisland_admin_secret: str = DEFAULT_ADMIN_SECRET


_settings = AppSettings()

# .miniclassisland directory and configuration file path
CONFIG_DIR = _PROJECT_ROOT / DEFAULT_CONFIG_DIR
CONFIG_FILE = CONFIG_DIR / DEFAULT_CONFIG_FILE


def is_initialized() -> bool:
    """Check if system initialization is complete (whether config file exists)."""
    return CONFIG_FILE.exists()


def _load_file_config() -> dict:
    """Load local config overrides from .miniclassisland/config.json."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


_file_cfg = _load_file_config()

# Module-level global constants
_default_db_url = f"postgresql+psycopg://{_settings.pg_user}:{_settings.pg_pwd}@{_settings.pg_addr}/{_settings.pg_db}"
_default_redis_url = f"redis://{f':{_settings.redis_pwd}@' if _settings.redis_pwd else ''}{_settings.redis_addr}/{_settings.redis_db}"

DATABASE_URL: str = (
    _file_cfg.get("database_url") or _settings.database_url or _default_db_url
)
REDIS_URL: str = _file_cfg.get("redis_url") or _settings.redis_url or _default_redis_url

# Redis logical database IDs
REDIS_DB_AUTH: int = 0
REDIS_DB_SESSION: int = 1
REDIS_DB_CACHE: int = 2

# Multi-tenant isolation variables
BASE_DOMAIN: str = (
    _file_cfg.get("base_domain")
    or _file_cfg.get("domain")
    or _settings.miniclassisland_base_domain
)
DEFAULT_SCHEMA: str = PUBLIC_SCHEMA

# Four port allocation constants
CLIENT_PORT: int = _settings.miniclassisland_client_port
MANAGEMENT_PORT: int = _settings.miniclassisland_management_port
ADMIN_PORT: int = _settings.miniclassisland_admin_port
GRPC_PORT: int = _settings.miniclassisland_grpc_port

# GPG key file name
KEY_FILE: str = _settings.miniclassisland_key_file


def validate_config() -> None:
    """Validate Database and Redis configuration before service startup."""
    if not is_initialized():
        return

    if not DATABASE_URL:
        raise RuntimeError(
            "Database connection must be provided via .miniclassisland/config.json, .env, or DATABASE_URL environment variable"
        )
    if not REDIS_URL:
        raise RuntimeError(
            "Redis connection must be provided via .env or REDIS_URL environment variable"
        )
