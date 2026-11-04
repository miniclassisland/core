"""test_bulk.py"""

from unittest.mock import patch
import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

from app.admin import bulk
from app.admin.app import admin_app
from app.shared.db.session import AsyncSessionLocal
from app.shared.schemas.schemas import BatchRequest, BatchOperation, BatchOpType
from app.shared.security import auth
from app.shared.services.user import ensure_system_roles


def test_import():
    """Verify module import."""
    assert bulk is not None


@pytest.mark.asyncio
async def test_admin_bulk_operations(test_superadmin_user):
    """Test process_batch and /bulk endpoint for create, update, write, delete, Credentials normalization, and error handling."""
    async with AsyncSessionLocal() as db:
        await ensure_system_roles(db)

    sid = await auth.create_session_token(test_superadmin_user)
    headers = {"Authorization": f"Bearer {sid}"}

    transport = ASGITransport(app=admin_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r_bulk = await client.post(
            "/bulk",
            json={
                "operations": [
                    {
                        "action": "create",
                        "resource_type": "Subjects",
                        "name": "sub1",
                        "payload": {"Subjects": {"a": {"Name": "Math"}}},
                    },
                    {
                        "action": "update",
                        "resource_type": "Subjects",
                        "name": "sub1",
                        "payload": {
                            "Subjects": {
                                "a": {"TeacherName": "Mr. Smith"},
                                "b": {"Name": "Physics"},
                            }
                        },
                    },
                    {
                        "action": "write",
                        "resource_type": "Credentials",
                        "name": "cred1",
                        "payload": {"AdminCredential": "SecretPass123"},
                    },
                    {
                        "action": "delete",
                        "resource_type": "Subjects",
                        "name": "sub1",
                    },
                ]
            },
            headers=headers,
        )
        assert r_bulk.status_code == 200
        assert len(r_bulk.json()["results"]) == 4

    # Test skipped unknown resource type and exception rollback branch directly
    async with AsyncSessionLocal() as db:
        op_unknown = BatchOperation.model_construct(
            action=BatchOpType.write,
            resource_type="UnknownType",
            name="x",
            payload={},
        )
        req_skip = BatchRequest.model_construct(operations=[op_unknown])
        res = await bulk.process_batch(req_skip, db, account_id="default")
        assert res["results"][0]["status"] == "skipped"

        # Test HTTPException re-raise on oversized payload (lines 81-83)
        req_huge = BatchRequest(
            operations=[
                BatchOperation(
                    action=BatchOpType.write,
                    resource_type="Subjects",
                    name="huge_sub",
                    payload={"data": "x" * (600 * 1024)},
                )
            ]
        )
        with pytest.raises(HTTPException) as exc_400:
            await bulk.process_batch(req_huge, db, account_id="default")
        assert exc_400.value.status_code == 400

        with patch.object(db, "execute", side_effect=RuntimeError("db failure")):
            req_err = BatchRequest(
                operations=[
                    BatchOperation(
                        action=BatchOpType.write,
                        resource_type="Subjects",
                        name="err_sub",
                        payload={},
                    )
                ]
            )
            with pytest.raises(HTTPException) as exc:
                await bulk.process_batch(req_err, db, account_id="default")
            assert exc.value.status_code == 500
