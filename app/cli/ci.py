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
    """编译 api/Protobuf 目录下的所有 .proto 文件到 app/grpc 目录下。"""
    import grpc_tools.protoc

    proto_dir = Path("api/Protobuf")
    # 查找所有的 .proto 文件
    proto_files = list(proto_dir.rglob("*.proto"))
    if not proto_files:
        print("No proto files found under api/Protobuf", file=sys.stderr)
        raise typer.Exit(code=1)

    # 目标生成目录为 app/grpc
    out_dir = Path("app/grpc")
    if out_dir.exists():
        try:
            shutil.rmtree(out_dir)
        except Exception:
            pass
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    # 为所有子目录生成 __init__.py 以使其成为 Python 包
    api_dir = out_dir / "api"
    try:
        api_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    
    # 写入 api/__init__.py 修正模块导入路径
    api_init = api_dir / "__init__.py"
    try:
        api_init.write_text(
            "import sys\n"
            "from pathlib import Path\n"
            "sys.path.append(str(Path(__file__).parent.resolve()))\n",
            encoding="utf-8"
        )
    except Exception:
        pass

    # 准备 protoc 编译命令参数
    args = [
        "grpc_tools.protoc",
        "-Iapi/",
        f"--python_out={out_dir}",
        f"--grpc_python_out={out_dir}",
        f"--pyi_out={out_dir}",
    ]
    
    proto_args = []
    for p in proto_files:
        parts = p.parts
        if "api" in parts:
            idx = parts.index("api")
            proto_args.append(os.path.join(*parts[idx+1:]))
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

    protobuf_gen_dir = out_dir / "Protobuf"
    try:
        if protobuf_gen_dir.exists():
            init_file = protobuf_gen_dir / "__init__.py"
            if not init_file.exists():
                init_file.touch()
            create_inits(protobuf_gen_dir)
    except Exception:
        pass

    print("Protocol buffer generated successfully.")
