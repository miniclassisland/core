import os
import shutil
import sys
from pathlib import Path
import typer

ci_app = typer.Typer(help="CI continuous integration and toolchain")
grpc_app = typer.Typer(help="gRPC code generation")
ci_app.add_typer(grpc_app, name="grpc")


@ci_app.command("build")
def build_package():
    """Build project distribution package using uv build."""
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
    """Compile all .proto files under Protobuf/ directory into app/Protobuf/."""
    import grpc_tools.protoc

    proto_dir = Path("Protobuf")
    # Find all .proto files
    proto_files = list(proto_dir.rglob("*.proto"))
    if not proto_files:
        print("No proto files found under Protobuf", file=sys.stderr)
        raise typer.Exit(code=1)

    # Target output directory is app/Protobuf
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

    # Write app/Protobuf/__init__.py to alias sys.modules['Protobuf']
    api_init = out_dir / "__init__.py"
    try:
        api_init.write_text(
            "import sys\n" "sys.modules['Protobuf'] = sys.modules[__name__]\n",
            encoding="utf-8",
        )
    except Exception:
        pass

    # Prepare protoc compilation parameters
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

    # Run protoc compilation
    ret = grpc_tools.protoc.main(args)
    if ret != 0:
        print(f"Failed to compile: protoc returned {ret}", file=sys.stderr)
        raise typer.Exit(code=255)

    # Recursively create __init__.py for generated folders
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
