"""test_main.py"""

from app import main


def test_main_exports():
    """验证主入口文件正确导出了 cli 对象。"""
    assert hasattr(main, "cli")
    assert "cli" in main.__all__
