import sys
import os

# 移除 sys.path 中的 tests 目录，避免其子目录（如 tests/grpc）遮蔽同名的第三方标准库（如 grpc）
paths_to_remove = []
for path in sys.path:
    normalized = os.path.normpath(path)
    parts = normalized.split(os.sep)
    if parts and parts[-1] == "tests":
        paths_to_remove.append(path)

for path in paths_to_remove:
    try:
        sys.path.remove(path)
    except ValueError:
        pass
