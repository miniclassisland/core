import typer

client_app = typer.Typer(help="Client devices and state management")


@client_app.command("a")
def cmd_a():
    """Client management placeholder command a."""
    print("client cmd a executed")


@client_app.command("b")
def cmd_b():
    """Client management placeholder command b."""
    print("client cmd b executed")
