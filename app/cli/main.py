import typer

from app.cli.account import account_app
from app.cli.cd import cd_app
from app.cli.ci import ci_app
from app.cli.client import client_app
from app.cli.sys import sys_app
from app.cli.user import user_app

# 定义主 Typer 应用
cli = typer.Typer(
    help="MINIClassIsland Core CLI 命令行工具",
    no_args_is_help=True,
)

# 注册子命令应用
cli.add_typer(sys_app, name="sys")
cli.add_typer(account_app, name="account")
cli.add_typer(user_app, name="user")
cli.add_typer(ci_app, name="ci")
cli.add_typer(client_app, name="client")
cli.add_typer(cd_app, name="cd")


@cli.command("about")
def about():
    """关于 MINIClassIsland。"""
    print("MINI ClassIsland Core Management Backend System")
    print("Version: 0.1.0")


def main():
    """CLI 入口点。"""
    cli()


if __name__ == "__main__":
    main()
