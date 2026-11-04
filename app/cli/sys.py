import asyncio
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import click
import typer
from sqlalchemy import func, select

from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import (
    Account,
    AuditLog,
    ClientRecord,
    SystemConfig,
    User,
)
from app.shared.utils.config import CONFIG_FILE
from app.shared.utils.oobe import write_config_file, init_database

sys_app = typer.Typer(
    help="System control and daemon process management",
    no_args_is_help=True,
)


def _require_args(**kwargs) -> None:
    """Display command help and exit(0) if any required parameter is omitted."""
    if any(v is None for v in kwargs.values()):
        ctx = click.get_current_context(silent=True)
        if ctx is not None:
            print(ctx.get_help())
        raise typer.Exit(code=0)


def _ask(prompt: str, default: str = "", validator=None) -> str:
    """Generic user input query with default value and validation."""
    while True:
        hint = f" [{default}]" if default else ""
        answer = input(f"{prompt}{hint}: ").strip() or default
        if validator:
            err = validator(answer)
            if err:
                print(f"  ❌ {err}")
                continue
        return answer


def validate_db_url(url: str) -> Optional[str]:
    if not url.startswith(("postgresql", "postgres")):
        return "Database URL must start with postgresql"
    return None


def validate_email(email: str) -> Optional[str]:
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return "Invalid email format"
    return None


def validate_password(pw: str) -> Optional[str]:
    if len(pw) < 12:
        return "Password length must be at least 12 characters"
    if not re.search(r"[A-Z]", pw):
        return "Password must contain uppercase letters"
    if not re.search(r"[a-z]", pw):
        return "Password must contain lowercase letters"
    if not re.search(r"[0-9]", pw):
        return "Password must contain numbers"
    if not re.search(r"[^A-Za-z0-9]", pw):
        return "Password must contain special characters"
    return None


def validate_username(name: str) -> Optional[str]:
    if not re.match(r"^[a-z0-9_]{3,64}$", name):
        return "Username must be 3-64 lowercase alphanumeric characters and underscores"
    return None


# ---- 1. Daemon runner ----


@sys_app.command("daemon")
def run_daemon():
    """Run all servers (Client / Management / Admin / gRPC) in blocking daemon mode."""
    from app.shared.utils.config import validate_config

    validate_config()

    from app.shared.utils.logging import setup_logging

    setup_logging()

    # Dynamically import start_servers to avoid eager module load errors
    from app.main import start_servers

    asyncio.run(start_servers())


# ---- 2. systemd integration ----


def _run_systemctl(action: str) -> None:
    """Run systemctl against miniclassisland-backend.service internally."""
    cmd = ["systemctl", action, "miniclassisland-backend"]
    if os.name != "nt" and os.getuid() != 0:
        cmd = ["sudo"] + cmd

    print(f"⏳ Executing: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    labels = {
        "start": "started",
        "stop": "stopped",
        "restart": "restarted",
        "enable": "enabled autostart for",
        "disable": "disabled autostart for",
    }
    action_label = labels.get(action, action)

    if result.returncode == 0:
        print(f"✅ miniclassisland-backend service {action_label}")
    else:
        print(f"❌ Operation failed: {result.stderr.strip()}")
        raise typer.Exit(code=1)


@sys_app.command("install-service")
def install_service():
    """Generate and install miniclassisland-backend systemd service."""
    from app.shared.utils.oobe import generate_systemd_service

    generate_systemd_service()


@sys_app.command("start")
def start_service():
    """Start background service via systemd."""
    _run_systemctl("start")


@sys_app.command("stop")
def stop_service():
    """Stop running background service via systemd."""
    _run_systemctl("stop")


@sys_app.command("restart")
def restart_service():
    """Restart background service via systemd."""
    _run_systemctl("restart")


@sys_app.command("startup")
def toggle_startup():
    """Toggle autostart status for service."""
    check = subprocess.run(
        ["systemctl", "is-enabled", "miniclassisland-backend"],
        capture_output=True,
        text=True,
    )
    currently_enabled = check.stdout.strip() == "enabled"
    action = "disable" if currently_enabled else "enable"
    _run_systemctl(action)


# ---- 3. Status and Monitoring ----


@sys_app.command("pid")
def show_pid():
    """View PID of running background daemon."""
    from app.shared.utils.pid import PID

    pid = PID.read()
    if pid is None:
        print("not running", file=sys.stderr)
    else:
        print(f"MINI ClassIsland Daemon is running with PID: {pid}")


@sys_app.command("status")
def get_status():
    """Check and display system configuration status."""
    s = "✅ Initialized" if CONFIG_FILE.exists() else "❌ Uninitialized"
    print(s)


@sys_app.command("stats")
def show_stats():
    """Display global platform statistics (accounts, users, clients, audit logs)."""

    async def _run():
        async with AsyncSessionLocal() as db:
            total_accounts = await db.scalar(select(func.count(Account.id))) or 0
            active_accounts = (
                await db.scalar(
                    select(func.count(Account.id)).where(Account.is_active.is_(True))
                )
                or 0
            )
            total_users = await db.scalar(select(func.count(User.id))) or 0
            pending_users = (
                await db.scalar(
                    select(func.count(User.id)).where(User.role_code == "pending")
                )
                or 0
            )
            total_clients = await db.scalar(select(func.count(ClientRecord.uid))) or 0
            total_audits = await db.scalar(select(func.count(AuditLog.id))) or 0
            print(f"Accounts:      {active_accounts} active / {total_accounts} total")
            print(f"Users:         {total_users} total ({pending_users} pending)")
            print(f"Clients:       {total_clients} registered")
            print(f"Audit Logs:    {total_audits}")

    asyncio.run(_run())


@sys_app.command("settings")
def list_settings():
    """Display all system configuration settings from database."""
    from app.admin.settings import mask_sensitive_setting

    async def _run():
        async with AsyncSessionLocal() as db:
            rows = (
                (await db.execute(select(SystemConfig).order_by(SystemConfig.key)))
                .scalars()
                .all()
            )
            if not rows:
                print("No system settings found")
                return
            for r in rows:
                print(f"  {r.key} = {mask_sensitive_setting(r.key, r.value)}")

    asyncio.run(_run())


@sys_app.command("set-setting")
def set_setting_cmd(
    key: Optional[str] = typer.Argument(None, help="Configuration key"),
    value: Optional[str] = typer.Argument(None, help="Configuration value"),
):
    """Set or update a system configuration key-value pair."""
    _require_args(key=key, value=value)

    async def _run():
        async with AsyncSessionLocal() as db:
            now = datetime.now(timezone.utc)
            cfg = (
                await db.execute(select(SystemConfig).where(SystemConfig.key == key))
            ).scalar_one_or_none()
            if cfg:
                cfg.value = str(value)
                cfg.updated_at = now
            else:
                db.add(
                    SystemConfig(
                        key=key or "",
                        value=str(value),
                        updated_at=now,
                    )
                )
            await db.commit()
            print(f"✅ Setting {key} updated to {value}")

    asyncio.run(_run())


@sys_app.command("monit")
def monit_logs():
    """Stream and monitor real-time logs (prefers journalctl, falls back to tail)."""
    # Prefer journalctl
    if shutil.which("journalctl"):
        check = subprocess.run(
            ["systemctl", "cat", "miniclassisland-backend"],
            capture_output=True,
            text=True,
        )
        if check.returncode == 0:
            print("📋 Monitoring systemd logs (miniclassisland-backend)")
            print("   Press Ctrl+C to exit\n")
            try:
                subprocess.run(
                    [
                        "journalctl",
                        "-u",
                        "miniclassisland-backend",
                        "-f",
                        "--no-pager",
                        "-n",
                        "100",
                        "-o",
                        "cat",
                    ],
                    check=False,
                )
            except KeyboardInterrupt:
                print("\n👋 Exited log monitoring")
            return

    # Fallback to tail -f
    log_dir = Path(".miniclassisland") / "logs"
    if not log_dir.exists():
        print(
            "❌ Log directory does not exist. Please start service first: miniclassisland start"
        )
        raise typer.Exit(code=1)

    log_files = sorted(log_dir.glob("miniclassisland-*.log"))
    if not log_files:
        print(
            "❌ No log files found. Please start service first: miniclassisland start"
        )
        raise typer.Exit(code=1)

    latest = log_files[-1]
    print(f"📋 Monitoring log file: {latest}")
    print("   Press Ctrl+C to exit\n")
    try:
        subprocess.run(["tail", "-f", "-n", "100", str(latest)], check=False)
    except KeyboardInterrupt:
        print("\n👋 Exited log monitoring")


# ---- 4. Interactive Installer ----


@sys_app.command("init")
def init_system(
    db_url: Optional[str] = typer.Option(
        None, "--db-url", help="PostgreSQL connection string"
    ),
    redis_url: Optional[str] = typer.Option(
        None, "--redis-url", help="Redis connection string"
    ),
    domain: Optional[str] = typer.Option(None, "--domain", help="System main domain"),
    username: Optional[str] = typer.Option(None, "--username", help="Admin username"),
    email: Optional[str] = typer.Option(None, "--email", help="Admin email"),
    password: Optional[str] = typer.Option(None, "--password", help="Admin password"),
    interactive: bool = typer.Option(
        True, "--interactive/--no-interactive", help="Run wizard in interactive mode"
    ),
):
    """System first-time installation and onboarding wizard."""
    if not interactive and (
        not db_url
        or not redis_url
        or not username
        or not email
        or not password
        or not domain
    ):
        print("❌ All parameters must be specified in non-interactive mode.")
        raise typer.Exit(code=1)

    config = {}
    if interactive:
        if CONFIG_FILE.exists():
            print("\n⚠️ Existing configuration detected.")
            print("Re-initializing will DELETE ALL DATA and re-create the database.")
            if not typer.confirm("Confirm to continue?", default=False):
                print("Operation aborted")
                raise typer.Exit()

        print("\n🚀 MINI ClassIsland Initialization Wizard\n")
        print("=" * 50)
        config["db_url"] = _ask(
            "PostgreSQL Connection URL",
            os.environ.get(
                "DATABASE_URL",
                "postgresql+psycopg://postgres:password@localhost:5432/miniclassisland",
            ),
            validate_db_url,
        )
        config["redis_url"] = _ask(
            "Redis Connection URL",
            os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        )
        print("\n--- Super Administrator Account ---")
        config["username"] = _ask("Username", "admin", validate_username)
        config["email"] = _ask("Email", "", validate_email)
        config["password"] = _ask("Password (≥12 chars)", "", validate_password)
        print("\n--- Service Settings ---")
        config["domain"] = _ask(
            "Base domain",
            os.environ.get("MINICLASSISLAND_BASE_DOMAIN", "miniclassisland.com"),
        )
    else:
        config = {
            "db_url": db_url,
            "redis_url": redis_url,
            "username": username,
            "email": email,
            "password": password,
            "domain": domain,
        }

    try:
        write_config_file(config)
        asyncio.run(init_database(config))
        from app.shared.utils.oobe import generate_systemd_service

        generate_systemd_service()
        print("✅ Initialization completed successfully!")
    except Exception as e:
        print(f"❌ Initialization failed: {str(e)}")
        raise typer.Exit(code=1)
