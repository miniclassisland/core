import typer

cd_app = typer.Typer(help="配置分发与持续部署管理")


@cd_app.command("a")
def cmd_a():
    """部署分发占位命令 a。"""
    print("cd cmd a executed")


@cd_app.command("b")
def cmd_b():
    """部署分发占位命令 b。"""
    print("cd cmd b executed")
