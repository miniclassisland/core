"""Server-Sent Events (SSE) real-time account event bus and stream generator."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
import json
import logging
import time
from typing import Any, AsyncIterator, Callable
import uuid
import weakref

from fastapi import Request
from fastapi.responses import StreamingResponse

from app.shared.utils.config import REDIS_DB_SESSION
from app.shared.utils.redis import get_redis

logger = logging.getLogger(__name__)

_INSTANCE_ID = uuid.uuid4().hex
_CHANNEL_PREFIX = "mci:sse:"
_MAX_QUEUE_SIZE = 256

# Track per-event-loop subscribers and Redis relay tasks to avoid cross-loop leaks in tests.
_SUBSCRIBERS: weakref.WeakKeyDictionary[
    asyncio.AbstractEventLoop, dict[str, set[asyncio.Queue[dict[str, Any]]]]
] = weakref.WeakKeyDictionary()
_RELAY_TASKS: weakref.WeakKeyDictionary[
    asyncio.AbstractEventLoop, asyncio.Task[None]
] = weakref.WeakKeyDictionary()


def format_sse_frame(
    event_name: str, payload: dict[str, Any], *, event_id: str | None = None
) -> bytes:
    """Serialize a structured event payload as an SSE frame."""
    lines: list[str] = []
    if event_id:
        lines.append(f"id: {event_id}")
    lines.append(f"event: {event_name}")
    lines.append(f"data: {json.dumps(payload, ensure_ascii=False, default=str)}")
    return ("\n".join(lines) + "\n\n").encode("utf-8")


def _dispatch_local(
    loop: asyncio.AbstractEventLoop, account_id: str, envelope: dict[str, Any]
) -> None:
    """Push an event envelope to all local SSE queues subscribed to account_id on loop."""
    if not account_id or loop.is_closed():
        return
    acct_map = _SUBSCRIBERS.get(loop)
    if not acct_map:
        return
    queues = list(acct_map.get(account_id, ()))
    for q in queues:
        if q.full():
            with suppress(asyncio.QueueEmpty):
                q.get_nowait()
        with suppress(asyncio.QueueFull):
            q.put_nowait(envelope)


async def _redis_relay_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Subscribe to Redis Pub/Sub SSE channel pattern and forward remote-origin events."""
    while not loop.is_closed():
        pubsub = None
        try:
            rd = get_redis(REDIS_DB_SESSION)
            pubsub = rd.pubsub()
            await pubsub.psubscribe(f"{_CHANNEL_PREFIX}*")
            while not loop.is_closed():
                msg = await pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=1.0
                )
                if not msg:
                    if not _SUBSCRIBERS.get(loop):
                        return
                    continue
                if msg.get("type") != "pmessage":
                    continue
                raw_data = msg.get("data")
                if not isinstance(raw_data, str) or not raw_data:
                    continue
                try:
                    parsed = json.loads(raw_data)
                except Exception:
                    continue
                if not isinstance(parsed, dict):
                    continue
                if parsed.get("_origin") == _INSTANCE_ID:
                    continue
                acct_id = str(
                    parsed.get("channel_key") or parsed.get("account_id") or ""
                )
                if not acct_id:
                    channel = str(msg.get("channel") or "")
                    if channel.startswith(_CHANNEL_PREFIX):
                        acct_id = channel[len(_CHANNEL_PREFIX) :]
                if not acct_id:
                    continue
                clean_env = {
                    k: v
                    for k, v in parsed.items()
                    if k not in ("_origin", "channel_key")
                }
                _dispatch_local(loop, acct_id, clean_env)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("SSE Redis relay inactive or reconnecting: %s", exc)
            await asyncio.sleep(1.0)
        finally:
            if pubsub is not None:
                with suppress(Exception):
                    await pubsub.punsubscribe(f"{_CHANNEL_PREFIX}*")
                with suppress(Exception):
                    await pubsub.aclose()


def _register_subscriber(
    account_id: str,
) -> tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]]]:
    """Register a subscriber queue for account_id and start loop relay if needed."""
    loop = asyncio.get_running_loop()
    acct_map = _SUBSCRIBERS.get(loop)
    if acct_map is None:
        acct_map = {}
        _SUBSCRIBERS[loop] = acct_map
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=_MAX_QUEUE_SIZE)
    acct_map.setdefault(account_id, set()).add(queue)

    existing_task = _RELAY_TASKS.get(loop)
    if existing_task is None or existing_task.done():
        _RELAY_TASKS[loop] = loop.create_task(_redis_relay_loop(loop))
    return loop, queue


async def _unregister_subscriber(
    loop: asyncio.AbstractEventLoop,
    account_id: str,
    queue: asyncio.Queue[dict[str, Any]],
) -> None:
    """Remove a subscriber queue and stop loop relay when no subscribers remain."""
    acct_map = _SUBSCRIBERS.get(loop)
    if acct_map is not None:
        acct_queues = acct_map.get(account_id)
        if acct_queues is not None:
            acct_queues.discard(queue)
            if not acct_queues:
                acct_map.pop(account_id, None)
        if not acct_map:
            _SUBSCRIBERS.pop(loop, None)
            relay_task = _RELAY_TASKS.pop(loop, None)
            if relay_task is not None and not relay_task.done():
                relay_task.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await relay_task


def _build_envelope(
    event_type: str,
    data: dict[str, Any],
    *,
    account_id: str | None = None,
    topic: str | None = None,
) -> dict[str, Any]:
    """Construct a canonical SSE event envelope."""
    ts_iso = datetime.now(timezone.utc).isoformat()
    envelope: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "event": event_type,
        "type": event_type,
        "ts": ts_iso,
        "timestamp": ts_iso,
        "data": data,
    }
    if account_id is not None:
        envelope["account_id"] = account_id
    if topic is not None:
        envelope["topic"] = topic
    return envelope


async def _publish_envelope(
    channel_key: str,
    event_type: str,
    envelope: dict[str, Any],
) -> dict[str, Any]:
    """Dispatch envelope locally on running loop and broadcast via Redis Pub/Sub."""
    with suppress(RuntimeError):
        loop = asyncio.get_running_loop()
        _dispatch_local(loop, channel_key, envelope)

    try:
        rd = get_redis(REDIS_DB_SESSION)
        wire = json.dumps(
            {**envelope, "_origin": _INSTANCE_ID, "channel_key": channel_key},
            ensure_ascii=False,
            default=str,
        )
        await rd.publish(f"{_CHANNEL_PREFIX}{channel_key}", wire)
    except Exception as exc:
        logger.debug("Failed to publish SSE event to Redis (%s): %s", event_type, exc)

    return envelope


async def publish_account_event(
    account_id: str,
    event_type: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    """Publish a real-time account event to local SSE streams and Redis Pub/Sub."""
    envelope = _build_envelope(event_type, data, account_id=account_id)
    if not account_id or account_id == "default":
        return envelope
    return await _publish_envelope(account_id, event_type, envelope)


async def publish_topic_event(
    topic: str,
    event_type: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    """Publish a real-time event scoped to an opaque topic (pairing, qr, admin, user)."""
    envelope = _build_envelope(event_type, data, topic=topic)
    if not topic:
        return envelope
    return await _publish_envelope(f"topic:{topic}", event_type, envelope)


@asynccontextmanager
async def subscribe_account_channel(
    account_id: str,
) -> AsyncIterator[asyncio.Queue[dict[str, Any]]]:
    """Subscribe to local/Redis events for an account channel key while inside the context."""
    loop, queue = _register_subscriber(account_id)
    try:
        yield queue
    finally:
        await _unregister_subscriber(loop, account_id, queue)


@asynccontextmanager
async def subscribe_topic_channel(
    topic: str,
) -> AsyncIterator[asyncio.Queue[dict[str, Any]]]:
    """Subscribe to local/Redis events for an opaque topic while inside the context."""
    async with subscribe_account_channel(f"topic:{topic}") as queue:
        yield queue


async def wait_for_queue_event(
    queue: asyncio.Queue[dict[str, Any]],
    *,
    event_types: tuple[str, ...] | set[str] | None = None,
    predicate: Callable[[dict[str, Any]], bool] | None = None,
    timeout_sec: float = 4.0,
) -> dict[str, Any] | None:
    """Await the next matching envelope from an existing subscriber queue within timeout_sec."""
    deadline = time.monotonic() + max(0.05, timeout_sec)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        try:
            envelope = await asyncio.wait_for(queue.get(), timeout=remaining)
        except asyncio.TimeoutError:
            return None
        if event_types is not None and envelope.get("type") not in event_types:
            continue
        if predicate is not None:
            try:
                if not predicate(envelope):
                    continue
            except Exception:
                continue
        return envelope


async def wait_for_account_event(
    account_id: str,
    *,
    event_types: tuple[str, ...] | set[str] | None = None,
    predicate: Callable[[dict[str, Any]], bool] | None = None,
    timeout_sec: float = 4.0,
) -> dict[str, Any] | None:
    """Subscribe to account_id and wait for the next matching event up to timeout_sec."""
    async with subscribe_account_channel(account_id) as queue:
        return await wait_for_queue_event(
            queue,
            event_types=event_types,
            predicate=predicate,
            timeout_sec=timeout_sec,
        )


async def wait_for_topic_event(
    topic: str,
    *,
    event_types: tuple[str, ...] | set[str] | None = None,
    predicate: Callable[[dict[str, Any]], bool] | None = None,
    timeout_sec: float = 4.0,
) -> dict[str, Any] | None:
    """Subscribe to topic and wait for the next matching event up to timeout_sec."""
    async with subscribe_topic_channel(topic) as queue:
        return await wait_for_queue_event(
            queue,
            event_types=event_types,
            predicate=predicate,
            timeout_sec=timeout_sec,
        )


async def _stream_channel_events(
    channel_key: str,
    connected_payload: dict[str, Any],
    request: Request | None = None,
    *,
    keepalive_seconds: float = 15.0,
    max_events: int | None = None,
    max_duration_seconds: float | None = None,
) -> AsyncIterator[bytes]:
    """Yield SSE frames for channel_key until client disconnects or limits expire."""
    async with subscribe_account_channel(channel_key) as queue:
        started_at = time.monotonic()
        delivered = 0
        yield format_sse_frame(
            "connected",
            {
                **connected_payload,
                "ts": datetime.now(timezone.utc).isoformat(),
            },
        )
        while True:
            if request is not None and await request.is_disconnected():
                break
            if max_events is not None and delivered >= max_events:
                break
            wait_timeout = keepalive_seconds
            if max_duration_seconds is not None:
                elapsed = time.monotonic() - started_at
                remaining = max_duration_seconds - elapsed
                if remaining <= 0:
                    break
                wait_timeout = min(wait_timeout, remaining)
            try:
                envelope = await asyncio.wait_for(queue.get(), timeout=wait_timeout)
            except asyncio.TimeoutError:
                if (
                    max_duration_seconds is not None
                    and (time.monotonic() - started_at) >= max_duration_seconds
                ):
                    break
                yield b": keepalive\n\n"
                continue
            event_name = str(envelope.get("type") or "message")
            event_id = str(envelope.get("id") or "") or None
            yield format_sse_frame(event_name, envelope, event_id=event_id)
            delivered += 1


async def stream_account_events(
    account_id: str,
    request: Request | None = None,
    *,
    keepalive_seconds: float = 15.0,
    max_events: int | None = None,
    max_duration_seconds: float | None = None,
) -> AsyncIterator[bytes]:
    """Yield SSE event frames for account_id until client disconnects or limits expire."""
    async for frame in _stream_channel_events(
        account_id,
        {"account_id": account_id},
        request=request,
        keepalive_seconds=keepalive_seconds,
        max_events=max_events,
        max_duration_seconds=max_duration_seconds,
    ):
        yield frame


async def stream_topic_events(
    topic: str,
    request: Request | None = None,
    *,
    keepalive_seconds: float = 15.0,
    max_events: int | None = None,
    max_duration_seconds: float | None = None,
) -> AsyncIterator[bytes]:
    """Yield SSE event frames for a topic until client disconnects or limits expire."""
    async for frame in _stream_channel_events(
        f"topic:{topic}",
        {"topic": topic},
        request=request,
        keepalive_seconds=keepalive_seconds,
        max_events=max_events,
        max_duration_seconds=max_duration_seconds,
    ):
        yield frame


def create_sse_response(stream: AsyncIterator[bytes]) -> StreamingResponse:
    """Wrap an async SSE byte frame iterator into a properly headed StreamingResponse."""
    return StreamingResponse(
        stream,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
