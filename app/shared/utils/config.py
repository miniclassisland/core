"""全局应用配置与初始化状态检测。

配置优先级：.miniclassisland/config.json > 环境变量 > .env 默认值。
"""

import json
import logging
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

# 项目根目录 (相对于 app/shared/utils/config.py)
_PROJECT_ROOT = Path(__file__).resolve().parents[3]


class MINIClassIslandSettings(BaseSettings):
    """MINIClassIsland 全局配置，自动从环境变量与 .env 文件加载。"""

    model_config = SettingsConfigDict(
        env_file=str(_PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # 数据库 / Redis 连接串
    database_url: str = ""
    redis_url: str = ""

    # 多租户托管根域名
    miniclassisland_base_domain: str = "miniclassisland.com"

    # 服务端口分配
    miniclassisland_client_port: int = 27041
    miniclassisland_management_port: int = 27042
    miniclassisland_admin_port: int = 27043
    miniclassisland_grpc_port: int = 27044

    # GPG 密钥文件与超管密钥
    miniclassisland_key_file: str = "miniclassisland_server.key"
    miniclassisland_admin_secret: str = "change-me"


_settings = MINIClassIslandSettings()

# .miniclassisland 目录与配置文件路径
CONFIG_DIR = _PROJECT_ROOT / ".miniclassisland"
CONFIG_FILE = CONFIG_DIR / "config.json"


def is_initialized() -> bool:
    """检测系统是否已完成初始化（即配置文件是否存在）。"""
    return CONFIG_FILE.exists()


def _load_file_config() -> dict:
    """从 .miniclassisland/config.json 加载本地配置覆盖项。"""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


_file_cfg = _load_file_config()

# 模块级全局常量暴露
DATABASE_URL: str = _file_cfg.get("database_url") or _settings.database_url
REDIS_URL: str = _settings.redis_url

# Redis 逻辑数据库编号
REDIS_DB_AUTH: int = 0
REDIS_DB_SESSION: int = 1
REDIS_DB_CACHE: int = 2

# 多租户隔离全局变量
BASE_DOMAIN: str = _settings.miniclassisland_base_domain
DEFAULT_SCHEMA: str = "public"

# 四端口分配常量
CLIENT_PORT: int = _settings.miniclassisland_client_port
MANAGEMENT_PORT: int = _settings.miniclassisland_management_port
ADMIN_PORT: int = _settings.miniclassisland_admin_port
GRPC_PORT: int = _settings.miniclassisland_grpc_port

# GPG 密钥文件名
KEY_FILE: str = _settings.miniclassisland_key_file


def validate_config() -> None:
    """在服务启动前校验数据库与 Redis 关键配置是否提供。"""
    if not is_initialized():
        return

    if not DATABASE_URL:
        raise RuntimeError(
            "必须通过 .miniclassisland/config.json、.env 或 DATABASE_URL 环境变量提供数据库连接"
        )
    if not REDIS_URL:
        raise RuntimeError("必须通过 .env 或 REDIS_URL 环境变量提供 Redis 连接")
