import typer

from app import __version__
from app.shared.literals import SYS_NAME
from app.cli.account import account_app
from app.cli.cd import cd_app
from app.cli.ci import ci_app
from app.cli.client import client_app
from app.cli.sys import sys_app
from app.cli.user import user_app

# Define main Typer application
cli = typer.Typer(
    help="MINI ClassIsland Core CLI Tool",
    no_args_is_help=True,
)

# Register sub-command apps
cli.add_typer(sys_app, name="sys")
cli.add_typer(account_app, name="account")
cli.add_typer(user_app, name="user")
cli.add_typer(ci_app, name="ci")
cli.add_typer(client_app, name="client")
cli.add_typer(cd_app, name="cd")


@cli.command("about")
def about():
    """About MINI ClassIsland."""
    print(SYS_NAME)
    print(f"Version: {__version__}")


def main():
    """CLI entrypoint."""
    cli()


if __name__ == "__main__":
    main()
