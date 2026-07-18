import typer

client_app = typer.Typer(help="客户端设备与状态管理")


@client_app.command("a")
def cmd_a():
    """客户端管理占位命令 a。"""
    print("client cmd a executed")


@client_app.command("b")
def cmd_b():
    """客户端管理占位命令 b。"""
    print("client cmd b executed")
