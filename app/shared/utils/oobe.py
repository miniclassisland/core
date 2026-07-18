"""MINIClassIsland OOBE 首次引导初始化与系统服务部署助手。
"""

import json
import uuid
import secrets
import logging
from pathlib import Path
from datetime import datetime, timezone

from app.shared.utils.config import CONFIG_DIR, CONFIG_FILE
from app.shared.db.session import engine, AsyncSessionLocal
from app.shared.db.models import Base, User, Account, AccountMember, SystemConfig, PermissionDef, ReservedName
from app.shared.security.crypto import hash_password
from app.shared.services.user import ensure_system_roles

logger = logging.getLogger(__name__)

# 系统保留用户名列表
_PROTOCOL = ["admin", "api", "www", "mail", "ftp", "ssh", "dns", "smtp", "pop", "imap", "ntp", "snmp", "ldap", "tcp", "udp", "http", "https", "ssl", "tls", "vpn", "proxy"]
_AUTH = ["login", "logout", "register", "signup", "signin", "auth", "oauth", "oauth2", "openid", "sso", "saml", "2fa", "mfa", "totp", "otp", "token", "session", "password", "passwd", "reset", "verify", "activate", "deactivate", "confirm", "callback", "redirect"]
_ADMIN = ["dashboard", "panel", "console", "manage", "management", "billing", "settings", "config", "configuration", "control", "monitor", "analytics", "metrics", "logs", "admin", "superadmin", "moderator", "operator"]
_SYSTEM = ["system", "root", "null", "undefined", "localhost", "cims", "server", "node", "cluster", "master", "slave", "worker", "daemon", "cron", "scheduler", "queue", "cache", "redis", "postgres", "database", "db", "env", "debug", "staging", "production", "dev", "test", "testing", "sandbox", "preview", "canary"]
_RESOURCE = ["cdn", "static", "assets", "media", "upload", "uploads", "download", "downloads", "files", "images", "img", "css", "js", "fonts", "icons", "favicon", "robots", "sitemap", "manifest", "sw", "service-worker"]
_API = ["grpc", "ws", "wss", "websocket", "graphql", "webhook", "webhooks", "rest", "rpc", "v1", "v2", "v3", "v4", "health", "healthcheck", "ping", "pong", "heartbeat", "status", "info", "version", "about", "docs", "spec", "app"]
_SOCIAL = ["profile", "account", "accounts", "user", "users", "team", "teams", "org", "organization", "group", "groups", "member", "members", "invite", "invites", "join", "follow", "followers", "following", "feed", "activity", "notification", "notifications", "message", "messages"]
_SECURITY = ["security", "abuse", "spam", "phishing", "malware", "virus", "report", "block", "ban", "suspend", "blacklist", "whitelist", "allowlist", "denylist", "captcha", "challenge", "audit", "compliance"]
_BRAND = ["classisland", "miniclassisland", "island", "ci", "class", "school", "campus", "education", "edu", "student", "teacher", "classroom", "lesson", "course"]
_MISC = ["demo", "example", "sample", "support", "help", "faq", "blog", "news", "press", "legal", "terms", "privacy", "policy", "copyright", "trademark", "contact", "home", "index", "main", "application", "service", "store", "shop", "marketplace", "plugin", "plugins", "extension", "extensions", "theme", "themes", "public", "private", "internal", "external", "new", "create", "edit", "delete", "remove", "update", "search", "explore", "discover", "trending", "popular"]

RESERVED_NAMES = sorted(set(_PROTOCOL + _AUTH + _ADMIN + _SYSTEM + _RESOURCE + _API + _SOCIAL + _SECURITY + _BRAND + _MISC))


def write_config_file(config: dict) -> None:
    """将数据库连接信息写入 .miniclassisland/config.json。"""
    CONFIG_DIR.mkdir(exist_ok=True)
    file_config = {"database_url": config["db_url"]}
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(file_config, f, indent=2, ensure_ascii=False)
    logger.info("配置已写入 %s", CONFIG_FILE)


async def init_database(config: dict) -> None:
    """连接数据库并执行完整初始化。"""
    # 动态注入 DATABASE_URL 到 config 模块
    import app.shared.utils.config as cfg
    cfg.DATABASE_URL = config["db_url"]
    
    # 刷新 engine
    from sqlalchemy.ext.asyncio import create_async_engine
    new_engine = create_async_engine(config["db_url"], echo=False)

    async with new_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    logger.info("数据库表已重新创建")

    # 写入系统配置到数据库
    await _init_system_config(config)
    # 创建默认数据
    await _init_default_data(config)
    logger.info("数据初始化完成")


async def _init_system_config(config: dict) -> None:
    """将非数据库连接的配置写入 system_config 表。"""
    now = datetime.now(timezone.utc)
    entries = [
        ("redis_url", config["redis_url"]),
        ("base_domain", config["domain"]),
        ("oobe_completed", "true"),
    ]
    async with AsyncSessionLocal() as db:
        for key, val in entries:
            db.add(SystemConfig(key=key, value=val, updated_at=now))
        await db.commit()


async def _init_default_data(config: dict) -> None:
    """创建超管用户、默认角色、权限定义和保留名。"""
    async with AsyncSessionLocal() as db:
        await ensure_system_roles(db)
        await _create_superadmin(config, db)
        await _init_permissions(db)
        await _init_reserved_names(db)


async def _create_superadmin(config: dict, db) -> None:
    """创建超级管理员用户和默认账户。"""
    now = datetime.now(timezone.utc)
    user = User(
        id=str(uuid.uuid4()),
        username=config["username"],
        email=config["email"],
        hashed_password=hash_password(config["password"]),
        display_name="超级管理员",
        role_code="superadmin",
        is_active=True,
        created_at=now,
    )
    db.add(user)
    
    account = Account(
        id=str(uuid.uuid4()),
        name="默认管理账户",
        slug=config["username"].replace("_", "-"),
        api_key=secrets.token_urlsafe(32),
        is_active=True,
        created_at=now,
    )
    db.add(account)
    
    db.add(
        AccountMember(
            id=str(uuid.uuid4()),
            user_id=user.id,
            account_id=account.id,
            role_in_account="owner",
            joined_at=now,
        )
    )
    await db.commit()
    logger.info("超级管理员用户 %s 已创建", config["username"])


async def _init_permissions(db) -> None:
    """初始化默认权限定义。"""
    perms = [
        ("client.read", "读取客户端", "client"),
        ("client.write", "修改客户端", "client"),
        ("client.delete", "删除客户端", "client"),
        ("command.execute", "执行远程命令", "command"),
        ("config.read", "读取配置", "config"),
        ("config.write", "修改配置", "config"),
        ("audit.read", "查看审计日志", "audit"),
        ("account.manage", "管理账户", "account"),
        ("member.manage", "管理成员", "member"),
    ]
    for code, label, cat in perms:
        db.add(PermissionDef(code=code, label=label, category=cat))
    await db.commit()


async def _init_reserved_names(db) -> None:
    """初始化保留名称注册表。"""
    for name in RESERVED_NAMES:
        db.add(ReservedName(name=name, reason="系统保留"))
    await db.commit()


def generate_systemd_service() -> None:
    """生成 miniclassisland-backend.service 文件并尝试安装到 systemd。"""
    import shutil
    import subprocess

    bin_path = shutil.which("miniclassisland")
    if not bin_path:
        # 回退
        bin_path = f"{shutil.which('uv') or 'uv'} run miniclassisland"

    work_dir = str(Path(__file__).resolve().parents[3])
    user = "root"

    service_content = f"""[Unit]
Description=MINIClassIsland Backend - ClassIsland Management Server
Documentation=https://github.com/ClassIsland/CIMS-backend
After=network.target postgresql.service redis.service
Wants=postgresql.service redis.service

[Service]
Type=simple
User={user}
Group={user}
WorkingDirectory={work_dir}
ExecStart={bin_path} daemon
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=miniclassisland-backend

# 安全加固
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths={work_dir}

# 环境
EnvironmentFile=-{work_dir}/.env

[Install]
WantedBy=multi-user.target
"""

    local_path = CONFIG_DIR / "miniclassisland-backend.service"
    local_path.write_text(service_content, encoding="utf-8")
    logger.info("服务文件已生成: %s", local_path)

    systemd_path = "/etc/systemd/system/miniclassisland-backend.service"
    try:
        install_cmd = ["sudo", "cp", str(local_path), systemd_path]
        result = subprocess.run(install_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            subprocess.run(["sudo", "systemctl", "daemon-reload"], capture_output=True, text=True)
            logger.info("服务已安装到 %s", systemd_path)
            print("✅ 服务已安装，启动: miniclassisland start")
    except Exception:
        print("⚠️ 无法自动安装服务文件，请手动复制配置。")
