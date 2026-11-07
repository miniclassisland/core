"""MINI ClassIsland OOBE first-time onboarding initialization and service deployment helper."""

import json
import os
import uuid
import secrets
import logging
from pathlib import Path
from datetime import datetime, timezone

from app.shared.utils.config import CONFIG_DIR, CONFIG_FILE
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import (
    Base,
    User,
    Account,
    AccountMember,
    AccountQuota,
    SystemConfig,
    ReservedName,
)
from app.shared.db.schema_init import seed_account_defaults
from app.shared.literals import DEFAULT_QUOTAS
from app.shared.security.crypto import hash_password_async
from app.shared.services.user import ensure_system_roles

logger = logging.getLogger(__name__)

# System reserved usernames list
_PROTOCOL = [
    "admin",
    "api",
    "www",
    "mail",
    "ftp",
    "ssh",
    "dns",
    "smtp",
    "pop",
    "imap",
    "ntp",
    "snmp",
    "ldap",
    "tcp",
    "udp",
    "http",
    "https",
    "ssl",
    "tls",
    "vpn",
    "proxy",
]
_AUTH = [
    "login",
    "logout",
    "register",
    "signup",
    "signin",
    "auth",
    "oauth",
    "oauth2",
    "openid",
    "sso",
    "saml",
    "2fa",
    "mfa",
    "totp",
    "otp",
    "token",
    "session",
    "password",
    "passwd",
    "reset",
    "verify",
    "activate",
    "deactivate",
    "confirm",
    "callback",
    "redirect",
]
_ADMIN = [
    "dashboard",
    "panel",
    "console",
    "manage",
    "management",
    "billing",
    "settings",
    "config",
    "configuration",
    "control",
    "monitor",
    "analytics",
    "metrics",
    "logs",
    "admin",
    "superadmin",
    "moderator",
    "operator",
]
_SYSTEM = [
    "system",
    "root",
    "null",
    "undefined",
    "localhost",
    "server",
    "node",
    "cluster",
    "master",
    "slave",
    "worker",
    "daemon",
    "cron",
    "scheduler",
    "queue",
    "cache",
    "redis",
    "postgres",
    "database",
    "db",
    "env",
    "debug",
    "staging",
    "production",
    "dev",
    "test",
    "testing",
    "sandbox",
    "preview",
    "canary",
]
_RESOURCE = [
    "cdn",
    "static",
    "assets",
    "media",
    "upload",
    "uploads",
    "download",
    "downloads",
    "files",
    "images",
    "img",
    "css",
    "js",
    "fonts",
    "icons",
    "favicon",
    "robots",
    "sitemap",
    "manifest",
    "sw",
    "service-worker",
]
_API = [
    "grpc",
    "ws",
    "wss",
    "websocket",
    "graphql",
    "webhook",
    "webhooks",
    "rest",
    "rpc",
    "v1",
    "v2",
    "v3",
    "v4",
    "health",
    "healthcheck",
    "ping",
    "pong",
    "heartbeat",
    "status",
    "info",
    "version",
    "about",
    "docs",
    "spec",
    "app",
]
_SOCIAL = [
    "profile",
    "account",
    "accounts",
    "user",
    "users",
    "team",
    "teams",
    "org",
    "organization",
    "group",
    "groups",
    "member",
    "members",
    "invite",
    "invites",
    "join",
    "follow",
    "followers",
    "following",
    "feed",
    "activity",
    "notification",
    "notifications",
    "message",
    "messages",
]
_SECURITY = [
    "security",
    "abuse",
    "spam",
    "phishing",
    "malware",
    "virus",
    "report",
    "block",
    "ban",
    "suspend",
    "blacklist",
    "whitelist",
    "allowlist",
    "denylist",
    "captcha",
    "challenge",
    "audit",
    "compliance",
]
_BRAND = [
    "classisland",
    "miniclassisland",
    "mini-classisland",
    "mini-class-island",
    "class-island",
    "island",
    "ci",
    "mci",
    "minici",
    "mini",
    "snowluma",
    "onebot",
    "napcat",
    "lagrange",
    "hellowrc",
    "wrc",
    "class",
    "school",
    "campus",
    "education",
    "edu",
    "student",
    "teacher",
    "classroom",
    "lesson",
    "course",
    "official",
    "verified",
    "authority",
    "staff",
    "founder",
    "owner",
]
_CLOUD_AND_INFRA = [
    "autoconfig",
    "autodiscover",
    "wpad",
    "isatap",
    "mta-sts",
    "dmarc",
    "dkim",
    "spf",
    "bimi",
    "acme",
    "letsencrypt",
    "certbot",
    "pki",
    "crl",
    "ocsp",
    "whois",
    "ns1",
    "ns2",
    "ns3",
    "ns4",
    "mx1",
    "mx2",
    "relay",
    "gateway",
    "edge",
    "origin",
    "ingress",
    "egress",
    "loadbalancer",
    "waf",
    "firewall",
    "ddos",
    "s3",
    "oss",
    "cos",
    "minio",
    "bucket",
    "storage",
    "backup",
    "backups",
    "archive",
    "archives",
    "mirror",
    "mirrors",
    "registry",
    "docker",
    "k8s",
    "kubernetes",
    "helm",
    "grafana",
    "prometheus",
    "sentry",
    "elastic",
    "kibana",
    "jaeger",
    "vault",
    "consul",
    "etcd",
    "zookeeper",
    "kafka",
    "rabbitmq",
    "nats",
    "mysql",
    "mariadb",
    "mongodb",
    "mongo",
    "sqlite",
    "clickhouse",
    "influxdb",
    "supabase",
    "firebase",
    "vercel",
    "netlify",
    "cloudflare",
    "github",
    "gitlab",
    "bitbucket",
    "gitee",
    "git",
    "svn",
    "jenkins",
    "actions",
    "runner",
    "runners",
    "telemetry",
    "swagger",
    "openapi",
    "redoc",
    "graphiql",
    "playground",
]
_GOV_AND_FINANCE = [
    "gov",
    "government",
    "ministry",
    "bureau",
    "police",
    "cyberpolice",
    "court",
    "procuratorate",
    "moe",
    "edugov",
    "edu-cn",
    "gov-cn",
    "org-cn",
    "ac-cn",
    "national",
    "central",
    "headquarters",
    "president",
    "principal",
    "headmaster",
    "director",
    "secretary",
    "committee",
    "foundation",
    "charity",
    "sponsor",
    "sponsors",
    "partner",
    "partners",
    "vip",
    "svip",
    "premium",
    "enterprise",
    "ultimate",
    "pay",
    "payment",
    "payments",
    "wallet",
    "bank",
    "banking",
    "finance",
    "financial",
    "invoice",
    "invoices",
    "receipt",
    "receipts",
    "order",
    "orders",
    "checkout",
    "refund",
    "refunds",
    "withdraw",
    "deposit",
    "recharge",
    "topup",
    "credit",
    "credits",
    "quota",
    "quotas",
    "redeem",
    "coupon",
    "coupons",
    "voucher",
    "lottery",
    "airdrop",
    "crypto",
    "bitcoin",
    "btc",
    "eth",
    "usdt",
    "web3",
    "nft",
    "kyc",
    "aml",
]
_SENSITIVE = [
    "fuck",
    "fucker",
    "fucking",
    "motherfucker",
    "shit",
    "bullshit",
    "bitch",
    "bastard",
    "asshole",
    "dick",
    "cock",
    "pussy",
    "cunt",
    "whore",
    "slut",
    "faggot",
    "nigger",
    "nigga",
    "retard",
    "shabi",
    "caonima",
    "cnm",
    "nmsl",
    "wcnm",
    "mmp",
    "mlgb",
    "gouzaizi",
    "wangbadan",
    "jianren",
    "biaozi",
    "choushabi",
    "naocan",
    "zhizhang",
    "porn",
    "porno",
    "pornhub",
    "xvideos",
    "xnxx",
    "onlyfans",
    "nsfw",
    "xxx",
    "sex",
    "sexy",
    "adult",
    "erotic",
    "hentai",
    "jav",
    "nude",
    "nudes",
    "naked",
    "escort",
    "prostitute",
    "prostitution",
    "camgirl",
    "fetish",
    "bdsm",
    "incest",
    "rape",
    "pedo",
    "pedophile",
    "loli",
    "shota",
    "seqing",
    "huangse",
    "maopian",
    "luoliao",
    "yuepao",
    "piaochang",
    "casino",
    "gamble",
    "gambling",
    "bet",
    "betting",
    "poker",
    "slots",
    "roulette",
    "baccarat",
    "liuhecai",
    "dubo",
    "bocai",
    "caipiao",
    "qipai",
    "shuadan",
    "daikuan",
    "luodai",
    "taoxian",
    "xiqian",
    "waigua",
    "dupin",
    "bingdu",
    "hailuoin",
    "qiangzhi",
    "junhuo",
    "zhayao",
    "hack",
    "hacker",
    "hacking",
    "crack",
    "keygen",
    "warez",
    "botnet",
    "trojan",
    "ransomware",
    "exploit",
    "0day",
    "zeroday",
    "carding",
    "darkweb",
    "onion",
    "falun",
    "falungong",
    "flg",
    "minghui",
    "dajiyuan",
    "epochtimes",
    "ntdtv",
    "xiejiao",
    "quannengshen",
    "dongfangshandian",
    "taidu",
    "zangdu",
    "jiangdu",
    "gangdu",
    "separatism",
    "terror",
    "terrorist",
    "terrorism",
    "isis",
    "isil",
    "alqaeda",
    "taliban",
    "nazi",
    "hitler",
    "fascist",
    "fascism",
    "genocide",
    "suicide",
    "selfharm",
    "zisha",
    "baokong",
    "kongbu",
    "xidada",
    "zhongnanhai",
    "gongchandang",
    "ccp",
    "cpc",
    "guomindang",
    "kmt",
    "tiananmen",
    "8964",
    "liusi",
    "june4",
    "fanqiang",
    "shadowsocks",
    "v2ray",
    "vmess",
    "vless",
    "hysteria",
]
_MISC = [
    "demo",
    "example",
    "sample",
    "support",
    "help",
    "faq",
    "blog",
    "news",
    "press",
    "legal",
    "terms",
    "privacy",
    "policy",
    "copyright",
    "trademark",
    "contact",
    "home",
    "index",
    "main",
    "application",
    "service",
    "store",
    "shop",
    "marketplace",
    "plugin",
    "plugins",
    "extension",
    "extensions",
    "theme",
    "themes",
    "public",
    "private",
    "internal",
    "external",
    "new",
    "create",
    "edit",
    "delete",
    "remove",
    "update",
    "search",
    "explore",
    "discover",
    "trending",
    "popular",
    "default",
    "client",
    "clients",
    "device",
    "devices",
    "terminal",
    "terminals",
    "pairing",
    "pre-registration",
    "invitation",
    "invitations",
    "access",
    "ticket",
    "tickets",
    "community",
    "oobe",
    "setup",
    "install",
    "installer",
    "upgrade",
    "release",
    "releases",
    "changelog",
    "roadmap",
    "feedback",
    "issue",
    "issues",
]

RESERVED_NAMES = sorted(
    set(
        _PROTOCOL
        + _AUTH
        + _ADMIN
        + _SYSTEM
        + _RESOURCE
        + _API
        + _SOCIAL
        + _SECURITY
        + _BRAND
        + _CLOUD_AND_INFRA
        + _GOV_AND_FINANCE
        + _SENSITIVE
        + _MISC
    )
)

SENSITIVE_SLUG_SUBSTRINGS = tuple(sorted(set(_SENSITIVE)))


def write_config_file(config: dict) -> None:
    """Write database connection information to .miniclassisland/config.json."""
    CONFIG_DIR.mkdir(exist_ok=True)
    file_config = {
        "database_url": config["db_url"],
        "redis_url": config.get("redis_url", ""),
        "base_domain": config.get("domain", ""),
    }
    try:
        fd = os.open(
            CONFIG_FILE,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(file_config, f, indent=2, ensure_ascii=False)
    except OSError:  # pragma: no cover
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(file_config, f, indent=2, ensure_ascii=False)
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:  # pragma: no cover
        pass
    logger.info("Configuration written to %s", CONFIG_FILE)


async def init_database(config: dict) -> None:
    """Connect to database (creating it if missing) and execute complete initialization."""
    import app.shared.utils.config as cfg
    from app.shared.db import session as db_session
    from sqlalchemy import text
    from sqlalchemy.engine import make_url
    from sqlalchemy.ext.asyncio import create_async_engine

    db_url_str = config["db_url"]
    cfg.DATABASE_URL = db_url_str

    # Ensure target PostgreSQL database exists before connecting to it
    try:
        parsed_url = make_url(db_url_str)
        target_db = parsed_url.database
        if target_db and target_db != "postgres":
            admin_url = parsed_url.set(database="postgres")
            admin_engine = create_async_engine(admin_url, isolation_level="AUTOCOMMIT")
            async with admin_engine.connect() as conn:
                exists = await conn.scalar(
                    text("SELECT 1 FROM pg_database WHERE datname = :d"),
                    {"d": target_db},
                )
                if not exists:
                    safe_db = target_db.replace('"', '""')
                    await conn.execute(text(f'CREATE DATABASE "{safe_db}"'))
                    logger.info("Created PostgreSQL database: %s", target_db)
            await admin_engine.dispose()
    except Exception as exc:
        logger.warning("Database existence check skipped or failed: %s", exc)

    new_engine = create_async_engine(db_url_str, echo=False)
    db_session.engine = new_engine
    db_session.AsyncSessionLocal.configure(bind=new_engine)

    async with new_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables ensured")

    await _init_system_config(config)
    await _init_default_data(config)
    logger.info("Data initialization complete")


async def _init_system_config(config: dict) -> None:
    """Write non-DB connection configs into system_config table."""
    now = datetime.now(timezone.utc)
    entries = [
        ("redis_url", config["redis_url"]),
        ("base_domain", config["domain"]),
        ("oobe_completed", "true"),
        ("registration_open", "true"),
        ("require_approval", "true"),
        ("max_accounts_per_user", "5"),
        ("default_role", "normal"),
        ("announcement_title", ""),
        ("motd", ""),
    ]
    async with AsyncSessionLocal() as db:
        for key, val in entries:
            await db.merge(SystemConfig(key=key, value=val, updated_at=now))
        await db.commit()


async def _init_default_data(config: dict) -> None:
    """Create superadmin user, default roles, and reserved names."""
    async with AsyncSessionLocal() as db:
        await ensure_system_roles(db)
        await _create_superadmin(config, db)
        await _init_reserved_names(db)


async def _create_superadmin(config: dict, db) -> None:
    """Create super administrator user and default account if not already present."""
    from sqlalchemy import select

    existing_u = (
        await db.execute(select(User).where(User.username == config["username"]))
    ).scalar_one_or_none()
    if existing_u:
        return

    now = datetime.now(timezone.utc)
    user = User(
        id=str(uuid.uuid4()),
        username=config["username"],
        email=config["email"],
        hashed_password=await hash_password_async(config["password"]),
        display_name="Super Administrator",
        role_code="superadmin",
        is_active=True,
        can_create_account=True,
        created_at=now,
    )
    db.add(user)

    account = Account(
        id=str(uuid.uuid4()),
        name="Default Management Account",
        slug=f"account_{secrets.token_hex(4)}",
        api_key=secrets.token_urlsafe(32),
        is_active=True,
        registration_mode="pairing",
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
    for key, val in DEFAULT_QUOTAS:
        db.add(
            AccountQuota(
                id=str(uuid.uuid4()),
                account_id=account.id,
                quota_key=key,
                max_value=val,
            )
        )
    await seed_account_defaults(account.id, db)
    await db.commit()
    logger.info("Superadmin user %s created", config["username"])


async def _init_reserved_names(db) -> None:
    """Initialize reserved name registry."""
    for name in RESERVED_NAMES:
        await db.merge(ReservedName(name=name, reason="System Reserved"))
    await db.commit()


def generate_systemd_service() -> None:
    """Generate miniclassisland-backend.service file and attempt systemd installation."""
    import os
    import re
    import subprocess
    import sys

    work_dir = str(Path(__file__).resolve().parents[3])
    work_dir = work_dir.replace("\n", "").replace("\r", "")
    venv_python = Path(work_dir) / ".venv" / "bin" / "python"
    if venv_python.exists():
        exec_start = f"{venv_python} -m app.main sys daemon"
    else:
        exec_start = f"{sys.executable} -m app.main sys daemon"

    raw_user = (
        os.environ.get("SUDO_USER") or os.environ.get("USER") or "miniclassisland"
    )
    user = (
        raw_user
        if (raw_user != "root" and re.match(r"^[a-z_][a-z0-9_-]{0,31}$", raw_user))
        else "miniclassisland"
    )

    service_content = f"""[Unit]
Description=MINI ClassIsland Backend Server
Documentation=https://github.com/MINIOpenSource/miniclassisland
After=network.target postgresql.service redis-server.service
Wants=postgresql.service redis-server.service

[Service]
Type=simple
User={user}
Group={user}
WorkingDirectory={work_dir}
ExecStart={exec_start}
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
StandardOutput=journal
StandardError=journal
SyslogIdentifier=miniclassisland-backend

# Environment
EnvironmentFile=-{work_dir}/.env

[Install]
WantedBy=multi-user.target
"""

    local_path = CONFIG_DIR / "miniclassisland-backend.service"
    local_path.write_text(service_content, encoding="utf-8")
    logger.info("Service file generated: %s", local_path)

    prefix = [] if (hasattr(os, "geteuid") and os.geteuid() == 0) else ["sudo", "-n"]
    venv_cli = Path(work_dir) / ".venv" / "bin" / "miniclassisland"
    if venv_cli.exists():
        for bin_path in ("/usr/local/bin/miniclassisland", "/usr/bin/miniclassisland"):
            try:
                subprocess.run(
                    prefix + ["ln", "-sf", str(venv_cli), bin_path],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except Exception:
                pass

    systemd_path = "/etc/systemd/system/miniclassisland-backend.service"
    try:
        result = subprocess.run(
            prefix + ["cp", str(local_path), systemd_path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            subprocess.run(
                prefix + ["systemctl", "daemon-reload"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            subprocess.run(
                prefix + ["systemctl", "enable", "miniclassisland-backend"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            logger.info("Service installed to %s", systemd_path)
            print("✅ Service installed. To start: miniclassisland sys start")
        else:
            print(f"ℹ️ Service file written to {local_path}")
    except Exception:
        print(f"ℹ️ Service file written to {local_path}")
