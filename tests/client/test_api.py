"""test_api.py"""

from datetime import datetime, timezone
from urllib.parse import urlparse
from unittest.mock import patch
import pytest
from httpx import ASGITransport, AsyncClient

from app.client import api
from app.client.app import client_app
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import Account, ClientProfile, ClientRecord
from app.shared.utils.config import BASE_DOMAIN


def test_import():
    """Verify module import and helper functions."""
    assert api is not None
    assert api._ip_matches("", "127.0.0.1") is False
    assert api._ip_matches("203.0.113.5", "203.0.113.5") is True
    assert api._ip_matches("127.0.0.1", "testclient") is True
    assert api._ip_matches("203.0.113.5", "198.51.100.9") is False


@pytest.mark.asyncio
async def test_client_app_endpoints():
    """Test client_app root, metadata-only vs full manifest, gRPC IP check, /get token URLs, and embedded fonts."""
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        acct = Account(
            id="acct-client-test",
            name="Test Client School",
            slug="clientschool",
            api_key="k",
            is_active=True,
            created_at=now,
        )
        reg_client_ok = ClientRecord(
            uid="some-long-client-uid-12345",
            account_id="acct-client-test",
            client_id="C1",
            ip="203.0.113.10",
            is_disabled=False,
            registered_at=now,
        )
        reg_client_empty = ClientRecord(
            uid="uid-empty-profile",
            account_id="acct-client-test",
            client_id="C2",
            ip="127.0.0.1",
            is_disabled=False,
            registered_at=now,
        )
        reg_client_disabled = ClientRecord(
            uid="uid-disabled",
            account_id="acct-client-test",
            client_id="C3",
            ip="127.0.0.1",
            is_disabled=True,
            registered_at=now,
        )
        prof_empty = ClientProfile(
            account_id="acct-client-test",
            client_id="uid-empty-profile",
            class_plan="",
            time_layout="non_existent_tl",
            subjects="default",
            default_settings="default",
            policy="default",
            components="default",
            credentials="default",
            updated_at=now,
        )
        db.add_all(
            [
                acct,
                reg_client_ok,
                reg_client_empty,
                reg_client_disabled,
                prof_empty,
            ]
        )
        await db.commit()

    transport = ASGITransport(app=client_app)
    host_headers = {"Host": f"clientschool.{BASE_DOMAIN}"}

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Root health check
        r_root = await client.get("/")
        assert r_root.status_code == 200
        assert r_root.json()["status"] == "ok"

        # 2a. Unregistered client (not joined management) -> metadata-only Manifest
        r_unreg = await client.get(
            "/api/v1/client/unregistered-uid-99999/manifest",
            headers=host_headers,
        )
        assert r_unreg.status_code == 200
        unreg_data = r_unreg.json()
        assert unreg_data["OrganizationName"] == "Test Client School"
        assert unreg_data["ClassPlanSource"] == {"Value": "", "Version": 0}
        assert unreg_data["CredentialSource"] == {"Value": "", "Version": 0}

        # 2b. Disabled client -> metadata-only Manifest
        r_dis = await client.get(
            "/api/v1/client/uid-disabled/manifest",
            headers=host_headers,
        )
        assert r_dis.status_code == 200
        assert r_dis.json()["ClassPlanSource"] == {"Value": "", "Version": 0}

        # 2c. Registered client with mismatched IP -> 403 Forbidden
        r_ip_bad = await client.get(
            "/api/v1/client/some-long-client-uid-12345/manifest",
            headers={**host_headers, "X-Real-IP": "198.51.100.99"},
        )
        assert r_ip_bad.status_code == 403

        # 2c-session. Registered client with valid/invalid X-Client-Session header
        from unittest.mock import AsyncMock

        mock_sm = AsyncMock()
        mock_sm.validate_session = AsyncMock(return_value="some-long-client-uid-12345")
        with patch("app.client.api.get_session_manager", return_value=mock_sm):
            r_sess_ok = await client.get(
                "/api/v1/client/some-long-client-uid-12345/manifest",
                headers={
                    **host_headers,
                    "X-Real-IP": "198.51.100.99",
                    "X-Client-Session": "valid-session-id",
                },
            )
            assert r_sess_ok.status_code == 200
            mock_sm.validate_session = AsyncMock(return_value="other-uid")
            r_sess_bad = await client.get(
                "/api/v1/client/some-long-client-uid-12345/manifest",
                headers={
                    **host_headers,
                    "X-Real-IP": "198.51.100.99",
                    "X-Client-Session": "bad-session-id",
                },
            )
            assert r_sess_bad.status_code == 403

        # 2d. Registered client with matching gRPC IP -> full Manifest with /get?token=... URLs
        r_man = await client.get(
            "/api/v1/client/some-long-client-uid-12345/manifest",
            headers={**host_headers, "X-Real-IP": "203.0.113.10"},
        )
        assert r_man.status_code == 200
        man_data = r_man.json()
        assert man_data["OrganizationName"] == "Test Client School"
        assert man_data["ClassPlanSource"]["Version"] >= 1
        assert "/get?token=" in man_data["ClassPlanSource"]["Value"]

        # Verify the issued /get?token=... URL works for the matching IP
        parsed_get = urlparse(man_data["SubjectsSource"]["Value"])
        r_dl = await client.get(
            f"{parsed_get.path}?{parsed_get.query}",
            headers={**host_headers, "X-Real-IP": "203.0.113.10"},
        )
        assert r_dl.status_code == 200
        assert "Subjects" in r_dl.json()

        # 3. Manifest for custom profile with empty and missing resource names
        r_man_custom = await client.get(
            "/api/v1/client/uid-empty-profile/manifest",
            headers=host_headers,
        )
        assert r_man_custom.status_code == 200
        assert r_man_custom.json()["ClassPlanSource"]["Version"] == 0
        assert r_man_custom.json()["TimeLayoutSource"]["Version"] == 0
        assert "/get?token=" in r_man_custom.json()["SubjectsSource"]["Value"]

        # 3b. Manifest when max_bandwidth_mb quota is exceeded -> 429
        from app.shared.services.quota import set_quota

        async with AsyncSessionLocal() as db:
            await set_quota("acct-client-test", "max_bandwidth_mb", 0, db)
        r_man_429 = await client.get(
            "/api/v1/client/uid-empty-profile/manifest",
            headers=host_headers,
        )
        assert r_man_429.status_code == 429
        async with AsyncSessionLocal() as db:
            await set_quota("acct-client-test", "max_bandwidth_mb", 100, db)

        # 4. Removed legacy endpoints (/api/v1/client/{resource_type} and /api/v1/management-config) -> 404
        r_removed_res = await client.get(
            "/api/v1/client/Subjects",
            params={"name": "default"},
            headers=host_headers,
        )
        assert r_removed_res.status_code == 404

        r_removed_cfg = await client.get(
            "/api/v1/management-config",
            headers=host_headers,
        )
        assert r_removed_cfg.status_code == 404

        # 5. Embedded fonts endpoint
        r_font_404 = await client.get("/fonts/NotAllowed.ttf")
        assert r_font_404.status_code == 404

        r_font_ok = await client.get("/fonts/GoogleSansFlex-VariableFont.ttf")
        assert r_font_ok.status_code == 200

        with patch("pathlib.Path.exists", return_value=False):
            r_font_missing = await client.get("/fonts/GoogleSansFlex-VariableFont.ttf")
            assert r_font_missing.status_code == 404
