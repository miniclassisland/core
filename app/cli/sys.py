import asyncio
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional
import typer

from app.shared.utils.config import CONFIG_FILE, CLIENT_PORT, MANAGEMENT_PORT, ADMIN_PORT
from app.shared.utils.oobe import write_config_file, init_database

sys_app = typer.Typer(help="系统控制与守护进程管理")


def _ask(prompt: str, default: str = "", validator=None) -> str:
    """通用输入问询，带默认值和验证。"""
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
        return "数据库 URL 必须以 postgresql 开头"
    return None


def validate_email(email: str) -> Optional[str]:
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return "邮箱格式不合法"
    return None


def validate_password(pw: str) -> Optional[str]:
    if len(pw) < 12:
        return "密码长度不得少于 12 位"
    if not re.search(r"[A-Z]", pw):
        return "密码必须包含大写字母"
    if not re.search(r"[a-z]", pw):
        return "密码必须包含小写字母"
    if not re.search(r"[0-9]", pw):
        return "密码必须包含数字"
    if not re.search(r"[^A-Za-z0-9]", pw):
        return "密码必须包含特殊字符"
    return None


def validate_username(name: str) -> Optional[str]:
    if not re.match(r"^[a-z0-9_]{3,64}$", name):
        return "用户名需为 3~64 位小写字母数字下划线"
    return None


# ---- 1. 守护进程运行指令 (Daemon runner) ----

@sys_app.command("daemon")
def run_daemon():
    """以阻塞式前台守护进程模式运行所有服务端（Client / Management / Admin / gRPC）。"""
    from app.shared.utils.config import validate_config
    validate_config()

    from app.shared.utils.logging import setup_logging
    setup_logging()

    # 动态加载 app.main.start_servers，避免提前加载应用导致的依赖报错
    from app.main import start_servers
    asyncio.run(start_servers())


# ---- 2. 系统服务控制指令 (systemd integration) ----

def _run_systemctl(action: str) -> None:
    """内部运行 systemctl 对 miniclassisland-backend.service 执行控制动作。"""
    cmd = ["systemctl", action, "miniclassisland-backend"]
    if os.name != "nt" and os.getuid() != 0:
        cmd = ["sudo"] + cmd

    print(f"⏳ 正在执行: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    labels = {
        "start": "启动",
        "stop": "停止",
        "restart": "重启",
        "enable": "启用开机自启",
        "disable": "取消开机自启",
    }
    action_label = labels.get(action, action)

    if result.returncode == 0:
        print(f"✅ miniclassisland-backend 服务已{action_label}")
    else:
        print(f"❌ 操作失败: {result.stderr.strip()}")
        raise typer.Exit(code=1)


@sys_app.command("start")
def start_service():
    """通过 systemd 启动后台后端服务。"""
    _run_systemctl("start")


@sys_app.command("stop")
def stop_service():
    """通过 systemd 停止运行中的后台服务。"""
    _run_systemctl("stop")


@sys_app.command("restart")
def restart_service():
    """通过 systemd 强制重新启动服务。"""
    _run_systemctl("restart")


@sys_app.command("startup")
def toggle_startup():
    """切换服务的开机自启动配置状态（开关切换）。"""
    check = subprocess.run(
        ["systemctl", "is-enabled", "miniclassisland-backend"],
        capture_output=True,
        text=True,
    )
    currently_enabled = check.stdout.strip() == "enabled"
    action = "disable" if currently_enabled else "enable"
    _run_systemctl(action)


# ---- 3. 系统状态与日志监控 (Status and Monit) ----

@sys_app.command("pid")
def show_pid():
    """查看正在运行的后台守护进程的 PID。"""
    from app.shared.utils.pid import PID
    pid = PID.read()
    if pid is None:
        print("not running", file=sys.stderr)
    else:
        print(f"MINIClassIsland Daemon is running with PID: {pid}")


@sys_app.command("status")
def get_status():
    """检测并输出当前系统的配置初始化状态。"""
    s = "✅ 已初始化" if CONFIG_FILE.exists() else "❌ 未初始化"
    print(s)


@sys_app.command("monit")
def monit_logs():
    """滚动追踪监控系统的实时日志（优先使用 journalctl，回退 tail）。"""
    # 优先 journalctl
    if shutil.which("journalctl"):
        check = subprocess.run(
            ["systemctl", "cat", "miniclassisland-backend"],
            capture_output=True,
            text=True,
        )
        if check.returncode == 0:
            print("📋 正在监控 systemd 日志 (miniclassisland-backend)")
            print("   按 Ctrl+C 退出\n")
            try:
                subprocess.run(
                    ["journalctl", "-u", "miniclassisland-backend", "-f", "--no-pager", "-n", "100", "-o", "cat"],
                    check=False,
                )
            except KeyboardInterrupt:
                print("\n👋 已退出日志监控")
            return

    # 回退 tail -f
    log_dir = Path(".miniclassisland") / "logs"
    if not log_dir.exists():
        print("❌ 日志目录不存在。请先启动服务: miniclassisland start")
        raise typer.Exit(code=1)

    log_files = sorted(log_dir.glob("miniclassisland-*.log"))
    if not log_files:
        print("❌ 无日志文件。请先启动服务: miniclassisland start")
        raise typer.Exit(code=1)

    latest = log_files[-1]
    print(f"📋 正在监控日志: {latest}")
    print("   按 Ctrl+C 退出\n")
    try:
        subprocess.run(["tail", "-f", "-n", "100", str(latest)], check=False)
    except KeyboardInterrupt:
        print("\n👋 已退出日志监控")


# ---- 4. 首次启动初始化引导向导 (Interactive Installer) ----

@sys_app.command("init")
def init_system(
    db_url: Optional[str] = typer.Option(None, "--db-url", help="PostgreSQL 数据库连接串"),
    redis_url: Optional[str] = typer.Option(None, "--redis-url", help="Redis 连接串"),
    domain: Optional[str] = typer.Option(None, "--domain", help="系统主域名"),
    username: Optional[str] = typer.Option(None, "--username", help="管理员用户名"),
    email: Optional[str] = typer.Option(None, "--email", help="管理员邮箱"),
    password: Optional[str] = typer.Option(None, "--password", help="管理员密码"),
    interactive: bool = typer.Option(True, "--interactive/--no-interactive", help="是否以交互模式运行向导"),
):
    """系统首次安装初始化配置引导向导（支持命令行参数直接注入或交互式收集）。"""
    if not interactive and (not db_url or not redis_url or not username or not email or not password or not domain):
        print("❌ 非交互模式下必须指定全部初始化参数。")
        raise typer.Exit(code=1)

    config = {}
    if interactive:
        if CONFIG_FILE.exists():
            print("\n⚠️  检测到已有初始化配置。")
            print("重新初始化将 删除所有数据 并重建数据库。")
            if not typer.confirm("确认继续？", default=False):
                print("操作已中止")
                raise typer.Exit()

        print("\n🚀 MINIClassIsland 初始化向导\n")
        print("=" * 50)
        config["db_url"] = _ask(
            "PostgreSQL 连接 URL",
            os.environ.get("DATABASE_URL", "postgresql+psycopg://postgres:password@localhost:5432/miniclassisland"),
            validate_db_url,
        )
        config["redis_url"] = _ask(
            "Redis 连接 URL",
            os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        )
        print("\n--- 超级管理员账户 ---")
        config["username"] = _ask("用户名", "admin", validate_username)
        config["email"] = _ask("邮箱", "", validate_email)
        config["password"] = _ask("密码（≥12位）", "", validate_password)
        print("\n--- 服务配置 ---")
        config["domain"] = _ask("基础域名", os.environ.get("MINICLASSISLAND_BASE_DOMAIN", "miniclassisland.com"))
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
        print("✅ 初始化成功完成！")
    except Exception as e:
        print(f"❌ 初始化失败: {str(e)}")
        raise typer.Exit(code=1)
