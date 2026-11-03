"""test_api.py"""

from datetime import datetime, timezone
from unittest.mock import patch
import pytest
from fastapi import Request
from httpx import ASGITransport, AsyncClient

from app.client import api
from app.client.app import client_app
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import Account, ClientProfile, PreRegisteredClient
from app.shared.utils.config import BASE_DOMAIN


def test_import():
    """Verify module import."""
    assert api is not None


@pytest.mark.asyncio
async def test_client_app_endpoints():
    """Test client_app root, manifest, resource redirect, management-config, and embedded fonts."""
    async with AsyncSessionLocal() as db:
        acct = Account(
            id="acct-client-test",
            name="Test Client School",
            slug="clientschool",
            api_key="k",
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        pre = PreRegisteredClient(
            id="pre-1",
            account_id="acct-client-test",
            label="Grade 1 Class 1",
            class_identity="G1C1",
            created_at=datetime.now(timezone.utc),
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
            updated_at=datetime.now(timezone.utc),
        )
        db.add_all([acct, pre, prof_empty])
        await db.commit()

    transport = ASGITransport(app=client_app)
    host_headers = {"Host": f"clientschool.{BASE_DOMAIN}"}

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Root health check
        r_root = await client.get("/")
        assert r_root.status_code == 200
        assert r_root.json()["status"] == "ok"

        # 2. Manifest for default profile fallback
        r_man = await client.get(
            "/api/v1/client/some-long-client-uid-12345/manifest",
            headers=host_headers,
        )
        assert r_man.status_code == 200
        man_data = r_man.json()
        assert man_data["OrganizationName"] == "Test Client School"
        assert man_data["ClassPlanSource"]["Version"] >= 1

        # 3. Manifest for custom profile with empty and missing resource names
        r_man_custom = await client.get(
            "/api/v1/client/uid-empty-profile/manifest",
            headers=host_headers,
        )
        assert r_man_custom.status_code == 200
        assert r_man_custom.json()["ClassPlanSource"]["Version"] == 0
        assert r_man_custom.json()["TimeLayoutSource"]["Version"] == 0

        # 4. get_client_resource valid & invalid
        r_res_bad = await client.get(
            "/api/v1/client/InvalidType",
            params={"name": "default"},
            headers=host_headers,
        )
        assert r_res_bad.status_code == 400

        r_res_ok = await client.get(
            "/api/v1/client/Subjects",
            params={"name": "default"},
            headers=host_headers,
            follow_redirects=False,
        )
        assert r_res_ok.status_code == 302
        assert r_res_ok.headers["location"].startswith("/get?token=")

        # 5. management-config with and without pre-registered match
        r_cfg = await client.get(
            "/api/v1/management-config",
            params={"class_identity": "G1C1"},
            headers=host_headers,
        )
        assert r_cfg.status_code == 200
        assert r_cfg.json()["PreRegisteredLabel"] == "Grade 1 Class 1"

        r_cfg_none = await client.get(
            "/api/v1/management-config",
            params={"class_identity": "NO_MATCH"},
            headers=host_headers,
        )
        assert r_cfg_none.status_code == 200
        assert r_cfg_none.json()["PreRegisteredLabel"] == ""

        # 6. Embedded fonts endpoint
        r_font_404 = await client.get("/fonts/NotAllowed.ttf")
        assert r_font_404.status_code == 404

        r_font_ok = await client.get("/fonts/GoogleSansFlex-VariableFont.ttf")
        assert r_font_ok.status_code == 200

        with patch("pathlib.Path.exists", return_value=False):
            r_font_missing = await client.get("/fonts/GoogleSansFlex-VariableFont.ttf")
            assert r_font_missing.status_code == 404


def test_build_manifest_helper():
    """Test _build_manifest helper directly."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "router": client_app.router,
    }
    req = Request(scope)
    m = api._build_manifest(
        req,
        "",
        "default",
        "default",
        "default",
        "default",
        "default",
        "default",
        2,
    )
    assert m.ClassPlanSource["Version"] == 0
    assert m.TimeLayoutSource["Version"] == 2
