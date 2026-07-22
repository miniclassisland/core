import os
import shutil
import sys
from pathlib import Path
from typing import Optional
import typer

ci_app = typer.Typer(help="CI 持续集成与工具链")
grpc_app = typer.Typer(help="gRPC 代码生成")
ci_app.add_typer(grpc_app, name="grpc")


@ci_app.command("build")
def build_package():
    """使用 uv build 构建项目发布包。"""
    import subprocess
    result = subprocess.run(["uv", "build"], capture_output=True, text=True)
    if result.returncode == 0:
        print("built successfully")
        print(result.stdout)
    else:
        print(f"Build failed: {result.stderr}", file=sys.stderr)
        raise typer.Exit(code=result.returncode)


@grpc_app.command("generate")
def generate_grpc():
    """编译 Protobuf 目录下的所有 .proto 文件到 app/Protobuf 目录下。"""
    import grpc_tools.protoc

    proto_dir = Path("Protobuf")
    # 查找所有的 .proto 文件
    proto_files = list(proto_dir.rglob("*.proto"))
    if not proto_files:
        print("No proto files found under Protobuf", file=sys.stderr)
        raise typer.Exit(code=1)

    # 目标生成目录为 app/Protobuf
    out_dir = Path("app/Protobuf")
    if out_dir.exists():
        try:
            shutil.rmtree(out_dir)
        except Exception:
            pass
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    # 写入 app/Protobuf/__init__.py 修正模块导入路径，建立 sys.modules 别名避免污染 sys.path
    api_init = out_dir / "__init__.py"
    try:
        api_init.write_text(
            "import sys\n"
            "sys.modules['Protobuf'] = sys.modules[__name__]\n",
            encoding="utf-8"
        )
    except Exception:
        pass

    # 准备 protoc 编译命令参数
    args = [
        "grpc_tools.protoc",
        "-I.",
        "--python_out=app",
        "--grpc_python_out=app",
        "--pyi_out=app",
    ]
    
    proto_args = []
    for p in proto_files:
        parts = p.parts
        if "Protobuf" in parts:
            idx = parts.index("Protobuf")
            proto_args.append(os.path.join(*parts[idx:]))
        else:
            proto_args.append(str(p))
            
    args.extend(proto_args)

    # 运行 protoc 编译
    ret = grpc_tools.protoc.main(args)
    if ret != 0:
        print(f"Failed to compile: protoc returned {ret}", file=sys.stderr)
        raise typer.Exit(code=255)

    # 编译成功后，为生成的文件夹递归生成 __init__.py 并 touch
    def create_inits(directory: Path):
        try:
            if not directory.exists():
                return
            for child in directory.iterdir():
                if child.is_dir():
                    init_file = child / "__init__.py"
                    if not init_file.exists():
                        init_file.touch()
                    create_inits(child)
        except Exception:
            pass

    try:
        create_inits(out_dir)
    except Exception:
        pass

    print("Protocol buffer generated successfully.")
