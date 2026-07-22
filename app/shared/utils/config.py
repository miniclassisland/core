"""Global application configuration and initialization state checking.

Configuration priority: .miniclassisland/config.json > Environment variables > .env default values.
"""

import json
import logging
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

# Project root directory (relative to app/shared/utils/config.py)
_PROJECT_ROOT = Path(__file__).resolve().parents[3]


class MINIClassIslandSettings(BaseSettings):
    """MINIClassIsland global settings, automatically loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=str(_PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database / Redis connection strings
    database_url: str = ""
    redis_url: str = ""

    # Multi-tenant base domain
    miniclassisland_base_domain: str = "miniclassisland.com"

    # Service port allocations
    miniclassisland_client_port: int = 27041
    miniclassisland_management_port: int = 27042
    miniclassisland_admin_port: int = 27043
    miniclassisland_grpc_port: int = 27044

    # GPG key file and admin secret
    miniclassisland_key_file: str = "miniclassisland_server.key"
    miniclassisland_admin_secret: str = "change-me"


_settings = MINIClassIslandSettings()

# .miniclassisland directory and configuration file path
CONFIG_DIR = _PROJECT_ROOT / ".miniclassisland"
CONFIG_FILE = CONFIG_DIR / "config.json"


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
DATABASE_URL: str = _file_cfg.get("database_url") or _settings.database_url
REDIS_URL: str = _settings.redis_url

# Redis logical database IDs
REDIS_DB_AUTH: int = 0
REDIS_DB_SESSION: int = 1
REDIS_DB_CACHE: int = 2

# Multi-tenant isolation variables
BASE_DOMAIN: str = _settings.miniclassisland_base_domain
DEFAULT_SCHEMA: str = "public"

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
        raise RuntimeError("Redis connection must be provided via .env or REDIS_URL environment variable")
