"""test_get.py"""

from datetime import datetime, timezone
import pytest
from httpx import ASGITransport, AsyncClient

from app.client import get
from app.client.app import client_app
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import SubFile
from app.shared.security.auth import create_token
from app.shared.security.crypto import ensure_guid_str


def test_import():
    """Verify module import."""
    assert get is not None


@pytest.mark.asyncio
async def test_get_resource_by_token_branches():
    """Test /get endpoint for invalid token, DB hit, default account fallback, DEFAULT_RESOURCES fallback, 404, and corrupted JSON."""
    transport = ASGITransport(app=client_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Invalid token -> 403
        r_bad = await client.get("/get", params={"token": "invalid-token"})
        assert r_bad.status_code == 403

        # 2. Fallback to DEFAULT_RESOURCES when not in DB
        tok_fallback = await create_token("acct-x", "Subjects", "default")
        r_fb = await client.get("/get", params={"token": tok_fallback})
        assert r_fb.status_code == 200
        assert "Subjects" in r_fb.json()

        # 3. Not in DB and not in DEFAULT_RESOURCES -> 404
        tok_404 = await create_token("acct-x", "Subjects", "non_existent_name")
        r_404 = await client.get("/get", params={"token": tok_404})
        assert r_404.status_code == 404

        # 4. Fallback to 'default' account row when specific tenant row is missing
        async with AsyncSessionLocal() as db:
            db.add(
                SubFile(
                    account_id="default",
                    name="shared_sub",
                    content='{"Subjects": {"s1": {"Name": "History"}}}',
                    version=1,
                    updated_at=datetime.now(timezone.utc),
                )
            )
            db.add(
                SubFile(
                    account_id="acct-corrupt",
                    name="corrupt_sub",
                    content="{not-valid-json",
                    version=1,
                    updated_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()

        tok_shared = await create_token("other-tenant", "Subjects", "shared_sub")
        r_shared = await client.get("/get", params={"token": tok_shared})
        assert r_shared.status_code == 200
        assert r_shared.json()["Subjects"][ensure_guid_str("s1")]["Name"] == "History"

        # 5. Corrupted JSON -> 500
        tok_corrupt = await create_token("acct-corrupt", "Subjects", "corrupt_sub")
        r_corrupt = await client.get("/get", params={"token": tok_corrupt})
        assert r_corrupt.status_code == 500

        # 6. Bandwidth quota exceeded on /get -> 429
        from app.shared.services.quota import set_quota

        async with AsyncSessionLocal() as db:
            await set_quota("acct-bw-limit", "max_bandwidth_mb", 0, db)
        tok_bw = await create_token("acct-bw-limit", "Subjects", "default")
        r_bw = await client.get("/get", params={"token": tok_bw})
        assert r_bw.status_code == 429
