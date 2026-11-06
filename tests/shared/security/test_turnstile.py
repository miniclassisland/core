"""Tests for Cloudflare Turnstile server-side verification."""

from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app.shared.security import turnstile


def test_turnstile_logger_name():
    """SiteVerify logs should be attributed to the verifier, not httpx."""
    assert turnstile.logger.name == "miniclassisland.turnstile"


class _FakeResponse:
    def __init__(self, status_code: int = 200, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    def json(self) -> dict:
        return self._payload


class _FakeClient:
    def __init__(self, response: _FakeResponse | None = None, error=None):
        self.response = response
        self.error = error
        self.calls: list[tuple[str, dict]] = []

    async def post(self, url: str, data: dict) -> _FakeResponse:
        self.calls.append((url, data))
        if self.error:
            raise self.error
        return self.response


@pytest.mark.asyncio
async def test_verify_turnstile_token_checks_action_and_hostname(monkeypatch):
    monkeypatch.setattr(
        turnstile, "get_turnstile_secret_key", AsyncMock(return_value="secret")
    )
    monkeypatch.setattr(
        turnstile, "get_turnstile_allowed_hostnames", lambda: {"dash.example.com"}
    )
    response = _FakeResponse(
        payload={
            "success": True,
            "action": "login",
            "hostname": "dash.example.com",
        }
    )
    client = _FakeClient(response)
    monkeypatch.setattr(turnstile, "get_turnstile_client", lambda: client)

    assert (
        await turnstile.verify_turnstile_token(
            "token", remote_ip="1.2.3.4", expected_action="login"
        )
        is True
    )
    assert client.calls[-1][1]["remoteip"] == "1.2.3.4"

    assert (
        await turnstile.verify_turnstile_token("token", expected_action="register")
        is False
    )

    response._payload["hostname"] = "evil.example.com"
    assert (
        await turnstile.verify_turnstile_token("token", expected_action="login")
        is False
    )

    assert (
        await turnstile.verify_turnstile_token(
            "token",
            expected_action="login",
            expected_hostnames={"other.example.com"},
        )
        is False
    )


@pytest.mark.asyncio
async def test_verify_turnstile_token_failure_paths(monkeypatch):
    monkeypatch.setattr(
        turnstile, "get_turnstile_secret_key", AsyncMock(return_value="secret")
    )
    monkeypatch.setattr(
        turnstile, "get_turnstile_allowed_hostnames", lambda: {"dash.example.com"}
    )

    for response in (
        _FakeResponse(payload={"success": False}),
        _FakeResponse(status_code=500, payload={}),
    ):
        monkeypatch.setattr(
            turnstile,
            "get_turnstile_client",
            lambda response=response: _FakeClient(response),
        )
        assert await turnstile.verify_turnstile_token("token") is False

    monkeypatch.setattr(
        turnstile,
        "get_turnstile_client",
        lambda: _FakeClient(error=RuntimeError("network")),
    )
    assert await turnstile.verify_turnstile_token("token") is False
    assert await turnstile.verify_turnstile_token("") is False

    monkeypatch.setattr(turnstile, "get_turnstile_allowed_hostnames", lambda: set())
    monkeypatch.setattr(
        turnstile,
        "get_turnstile_client",
        lambda: _FakeClient(
            _FakeResponse(
                payload={
                    "success": True,
                    "action": "login",
                    "hostname": "dash.example.com",
                }
            )
        ),
    )
    assert await turnstile.verify_turnstile_token("token") is False


@pytest.mark.asyncio
async def test_verify_turnstile_token_without_secret(monkeypatch):
    monkeypatch.setattr(
        turnstile, "get_turnstile_secret_key", AsyncMock(return_value="")
    )
    assert await turnstile.verify_turnstile_token("anything") is True
    assert await turnstile.verify_turnstile_token("INVALID_TURNSTILE_TOKEN") is False


def test_get_turnstile_allowed_hostnames(monkeypatch):
    monkeypatch.delenv("TURNSTILE_HOSTNAMES", raising=False)
    monkeypatch.setattr(turnstile, "_load_file_config", lambda: {})
    monkeypatch.setattr(turnstile, "BASE_DOMAIN", "example.com")
    assert turnstile.get_turnstile_allowed_hostnames() == {
        "example.com",
        "dash.example.com",
        "dashboard.example.com",
    }

    monkeypatch.setenv("TURNSTILE_HOSTNAMES", "Dash.Example.com, localhost")
    assert turnstile.get_turnstile_allowed_hostnames() == {
        "dash.example.com",
        "localhost",
    }

    monkeypatch.delenv("TURNSTILE_HOSTNAMES", raising=False)
    monkeypatch.setattr(
        turnstile,
        "_load_file_config",
        lambda: {"turnstile_hostnames": "a.example.com, B.example.com"},
    )
    assert turnstile.get_turnstile_allowed_hostnames() == {
        "a.example.com",
        "b.example.com",
    }


@pytest.mark.asyncio
async def test_turnstile_client_is_reused_and_closed():
    await turnstile.close_turnstile_client()
    first = turnstile.get_turnstile_client()
    second = turnstile.get_turnstile_client()
    assert first is second
    await turnstile.close_turnstile_client()
    assert first.is_closed
    await turnstile.close_turnstile_client()


@pytest.mark.asyncio
async def test_require_turnstile_verification(monkeypatch):
    monkeypatch.setattr(
        turnstile, "verify_turnstile_token", AsyncMock(return_value=False)
    )
    with pytest.raises(HTTPException) as exc:
        await turnstile.require_turnstile_verification("token")
    assert exc.value.status_code == 400

    monkeypatch.setattr(
        turnstile, "verify_turnstile_token", AsyncMock(return_value=True)
    )
    assert (
        await turnstile.require_turnstile_verification("token", expected_action="login")
        is None
    )
