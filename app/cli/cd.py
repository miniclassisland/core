import typer

cd_app = typer.Typer(
    help="Configuration deployment and continuous delivery management",
    no_args_is_help=True,
)


@cd_app.command("a")
def cmd_a():
    """Deployment distribution placeholder command a."""
    print("cd cmd a executed")


@cd_app.command("b")
def cmd_b():
    """Deployment distribution placeholder command b."""
    print("cd cmd b executed")
