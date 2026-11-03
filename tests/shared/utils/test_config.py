"""test_config.py"""

import json
from unittest.mock import MagicMock, AsyncMock, patch
import pytest

from app.shared.utils import config, oobe


def test_config_values_and_helpers(tmp_path):
    """Verify global configuration values, file config loading, and validate_config branches."""
    assert config.KEY_FILE.endswith("miniclassisland_server.key")
    assert "miniclassisland" in config.DATABASE_URL
    assert "redis" in config.REDIS_URL
    assert config.BASE_DOMAIN is not None
    assert config.GRPC_PORT > 0
    assert config.CLIENT_PORT > 0
    assert config.MANAGEMENT_PORT > 0
    assert config.ADMIN_PORT > 0

    missing_cfg = tmp_path / "missing_config.json"
    with patch.object(config, "CONFIG_FILE", missing_cfg):
        assert config.is_initialized() is False
        assert config._load_file_config() == {}
        config.validate_config()

    existing_cfg = tmp_path / "existing_config.json"
    existing_cfg.write_text(
        json.dumps({"database_url": "postgresql://x"}), encoding="utf-8"
    )
    with patch.object(config, "CONFIG_FILE", existing_cfg):
        assert config.is_initialized() is True
        assert config._load_file_config() == {"database_url": "postgresql://x"}
        config.validate_config()
        orig_db = config.DATABASE_URL
        orig_rd = config.REDIS_URL
        try:
            config.DATABASE_URL = ""
            with pytest.raises(RuntimeError):
                config.validate_config()
            config.DATABASE_URL = orig_db
            config.REDIS_URL = ""
            with pytest.raises(RuntimeError):
                config.validate_config()
        finally:
            config.DATABASE_URL = orig_db
            config.REDIS_URL = orig_rd


@pytest.mark.asyncio
async def test_oobe_utilities(tmp_path):
    """Test write_config_file, init_database, and generate_systemd_service in app/shared/utils/oobe.py."""
    cfg_dir = tmp_path / ".miniclassisland"
    cfg_file = cfg_dir / "config.json"

    sample_cfg = {
        "db_url": config.DATABASE_URL,
        "redis_url": config.REDIS_URL,
        "domain": "miniclassisland.com",
        "username": "admin",
        "email": "admin@miniclassisland.com",
        "password": "AdminPassword123!",
    }

    with (
        patch.object(oobe, "CONFIG_DIR", cfg_dir),
        patch.object(oobe, "CONFIG_FILE", cfg_file),
    ):
        oobe.write_config_file(sample_cfg)
        assert cfg_file.exists()

        mock_conn = AsyncMock()
        mock_conn.scalar = AsyncMock(return_value=None)
        mock_conn.execute = AsyncMock()
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = mock_conn
        mock_admin_engine = MagicMock()
        mock_admin_engine.connect.return_value = mock_ctx
        mock_admin_engine.dispose = AsyncMock()

        from sqlalchemy.ext.asyncio import create_async_engine as real_create

        def side_effect_engine(url, **kwargs):
            if kwargs.get("isolation_level") == "AUTOCOMMIT":
                return mock_admin_engine
            return real_create(url, **kwargs)

        with patch(
            "sqlalchemy.ext.asyncio.create_async_engine",
            side_effect=side_effect_engine,
        ):
            await oobe.init_database(sample_cfg)

        def side_effect_engine_err(url, **kwargs):
            if kwargs.get("isolation_level") == "AUTOCOMMIT":
                raise RuntimeError("pg admin connect error")
            return real_create(url, **kwargs)

        with patch(
            "sqlalchemy.ext.asyncio.create_async_engine",
            side_effect=side_effect_engine_err,
        ):
            await oobe.init_database(sample_cfg)

        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("subprocess.run", return_value=MagicMock(returncode=0)),
        ):
            oobe.generate_systemd_service()

        with (
            patch("pathlib.Path.exists", return_value=False),
            patch("subprocess.run", return_value=MagicMock(returncode=1)),
        ):
            oobe.generate_systemd_service()

        with patch("subprocess.run", side_effect=OSError("no sudo")):
            oobe.generate_systemd_service()
