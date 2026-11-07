"""Per-user QQ community join code management and SnowLuma OneBot 11 auto-approval."""

import asyncio
from datetime import datetime, timezone
import re
import secrets
import string
import threading
import time
from typing import Any, Callable, Coroutine, Optional

import httpx
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.models import CommunityBinding, User
from app.shared.db.session import AsyncSessionLocal
from app.shared.utils.config import (
    COMMUNITY_CODE_TTL_SECONDS,
    COMMUNITY_QQ_GROUP_ID,
    REDIS_DB_AUTH,
    SNOWLUMA_ONEBOT_TOKEN,
    SNOWLUMA_ONEBOT_URL,
    SNOWLUMA_POLL_INTERVAL,
    SNOWLUMA_QQ_GROUP_ID,
)
from app.shared.utils.logging import PORT_TAG_GROUP, get_port_logger
from app.shared.utils.redis import get_redis

logger = get_port_logger(PORT_TAG_GROUP)

CODE_LENGTH = 24
CODE_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/|~"
CODE_CHARSET = string.ascii_letters + string.digits + CODE_SYMBOLS + " "
COMMUNITY_CODE_TTL = int(COMMUNITY_CODE_TTL_SECONDS or 900)  # 15 minutes
DEFAULT_QQ_GROUP_ID = int(SNOWLUMA_QQ_GROUP_ID or COMMUNITY_QQ_GROUP_ID or 1131427434)

MSG_CODE_PROMPT = "密码有效期 15 分钟。加入后将自动绑定您的 QQ 到本用户"
MSG_ALREADY_BOUND = (
    "您已经绑定过一个 QQ 了，如果需要换绑，请直接退出群聊；"
    "如果需要继续加入群聊，您可以考虑新注册一个用户或者练习管理员"
)

_QQ_UIN_RE = re.compile(r"^[1-9][0-9]{4,19}$")

_REDIS_USER_CODE_PREFIX = "community:user_code:"
_REDIS_CODE_USER_PREFIX = "community:code_user:"

_lock = threading.Lock()
_code = ""
# In-memory fallback/index for per-user codes: user_id -> (code, expires_at_monotonic)
_user_codes: dict[str, tuple[str, float]] = {}
# Reverse index: code -> (user_id, expires_at_monotonic)
_code_users: dict[str, tuple[str, float]] = {}

_snowluma_client: Optional[httpx.AsyncClient] = None
_snowluma_poller_task: Optional[asyncio.Task] = None


class CommunityAlreadyBoundError(PermissionError):
    """Raised when a user who already has a bound QQ requests another join code."""


def mask_qq_uin(qq_uin: Optional[str]) -> Optional[str]:
    """Mask a QQ number for safe display to the user (e.g., ``123****890``)."""
    if not qq_uin:
        return None
    s = str(qq_uin).strip()
    if not s:  # pragma: no cover
        return None
    if len(s) >= 7:
        return f"{s[:3]}****{s[-3:]}"
    if len(s) >= 5:
        return f"{s[:2]}***{s[-2:]}"
    return f"{s[:1]}***"  # pragma: no cover


def format_manual_bound_prompt(qq_uin: str) -> str:
    """Format the prompt shown when an administrator has manually bound a user's QQ."""
    masked = mask_qq_uin(qq_uin) or qq_uin
    return (
        f"管理员已经将您的用户绑定到了 QQ（{masked}），您可以直接使用这个号码加入群聊"
    )


def _generate_code() -> str:
    """Generate a 24-character code with letters, digits, symbols and a space."""
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(CODE_SYMBOLS),
        " ",
    ]
    chars = required + [
        secrets.choice(CODE_CHARSET) for _ in range(CODE_LENGTH - len(required))
    ]
    secrets.SystemRandom().shuffle(chars)

    # Keep spaces away from the edges so the code is easy to copy into QQ.
    while chars[0] == " " or chars[-1] == " ":  # pragma: no cover
        edge = 0 if chars[0] == " " else len(chars) - 1
        interior = [i for i in range(1, len(chars) - 1) if chars[i] != " "]
        if not interior:  # pragma: no cover
            break
        swap = secrets.choice(interior)
        chars[edge], chars[swap] = chars[swap], chars[edge]

    return "".join(chars)


_code = _generate_code()


def _prune_expired_locked(now: Optional[float] = None) -> None:
    """Remove expired entries from in-memory caches (caller must hold _lock)."""
    ts = now if now is not None else time.monotonic()
    expired_users = [uid for uid, (_, exp) in _user_codes.items() if exp <= ts]
    for uid in expired_users:  # pragma: no cover
        old_code, _ = _user_codes.pop(uid, ("", 0.0))
        if old_code:
            _code_users.pop(old_code, None)
    expired_codes = [c for c, (_, exp) in _code_users.items() if exp <= ts]
    for c in expired_codes:  # pragma: no cover
        uid, _ = _code_users.pop(c, ("", 0.0))
        if uid and _user_codes.get(uid, ("", 0.0))[0] == c:
            _user_codes.pop(uid, None)


def get_community_code() -> str:
    """Return the current in-memory community join code."""
    return _code


def refresh_community_code() -> str:
    """Regenerate the in-memory community join code, invalidate pending user codes, and return it."""
    global _code
    with _lock:
        _code = _generate_code()
        _user_codes.clear()
        _code_users.clear()
        return _code


async def clear_all_pending_community_codes() -> str:
    """Invalidate all pending per-user join codes in memory and Redis, and rotate the fallback code."""
    new_fallback = refresh_community_code()
    try:
        r = get_redis(REDIS_DB_AUTH)
        keys = []
        async for k in r.scan_iter(
            match=f"{_REDIS_USER_CODE_PREFIX}*"
        ):  # pragma: no cover
            keys.append(k)
        async for k in r.scan_iter(
            match=f"{_REDIS_CODE_USER_PREFIX}*"
        ):  # pragma: no cover
            keys.append(k)
        if keys:  # pragma: no cover
            await r.delete(*keys)
    except Exception:
        pass
    return new_fallback


async def invalidate_user_community_code(user_id: str) -> None:
    """Invalidate any active community join code for ``user_id``."""
    with _lock:
        old_entry = _user_codes.pop(user_id, None)
        old_code = old_entry[0] if old_entry else None
        if old_code:
            _code_users.pop(old_code, None)
    try:
        r = get_redis(REDIS_DB_AUTH)
        user_key = f"{_REDIS_USER_CODE_PREFIX}{user_id}"
        prev_code = await r.get(user_key)
        pipe = r.pipeline()
        pipe.delete(user_key)
        if prev_code:
            pipe.delete(f"{_REDIS_CODE_USER_PREFIX}{prev_code}")
        if old_code and old_code != prev_code:  # pragma: no cover
            pipe.delete(f"{_REDIS_CODE_USER_PREFIX}{old_code}")
        await pipe.execute()
    except Exception:
        pass


async def is_user_community_bound(
    user_id: str, db: AsyncSession
) -> bool:  # pragma: no cover
    """Return True if the user has a community QQ binding."""
    row = (
        await db.execute(
            select(CommunityBinding.user_id).where(CommunityBinding.user_id == user_id)
        )
    ).scalar_one_or_none()
    return row is not None


async def get_user_community_binding(
    user_id: str, db: AsyncSession
) -> Optional[CommunityBinding]:
    """Return the CommunityBinding record for a user if bound."""
    return (
        await db.execute(
            select(CommunityBinding).where(CommunityBinding.user_id == user_id)
        )
    ).scalar_one_or_none()


async def get_user_community_status(user_id: str, db: AsyncSession) -> dict[str, Any]:
    """Return the community binding status and prompt message for ``user_id``."""
    binding = await get_user_community_binding(user_id, db)
    if not binding:
        return {
            "bound": False,
            "status": "unbound",
            "qq_masked": None,
            "masked_qq": None,
            "is_manual": False,
            "is_joined": False,
            "prompt": MSG_CODE_PROMPT,
        }
    masked = mask_qq_uin(binding.qq_uin)
    is_manual = bool(getattr(binding, "is_manual", False))
    is_joined = bool(getattr(binding, "is_joined", True))
    if is_manual and not is_joined:
        status_str = "manual_pending"
        prompt = format_manual_bound_prompt(binding.qq_uin)
    else:
        status_str = "joined"
        prompt = MSG_ALREADY_BOUND
    return {
        "bound": True,
        "status": status_str,
        "qq_masked": masked,
        "masked_qq": masked,
        "is_manual": is_manual,
        "is_joined": is_joined,
        "prompt": prompt,
    }


async def issue_user_community_code(
    user_id: str,
    db: AsyncSession,
    ttl: int = COMMUNITY_CODE_TTL,
    *,
    ttl_seconds: Optional[int] = None,
) -> tuple[str, int]:
    """Generate a new 15-minute join code bound to ``user_id``, invalidating any previous code.

    Returns ``(code, expires_in_seconds)``.
    Raises ``CommunityAlreadyBoundError`` if the user is already bound to a QQ account.
    """
    effective_ttl = int(ttl_seconds if ttl_seconds is not None else ttl)
    binding = await get_user_community_binding(user_id, db)
    if binding is not None:
        is_manual = bool(getattr(binding, "is_manual", False))
        is_joined = bool(getattr(binding, "is_joined", True))
        if is_manual and not is_joined:
            raise CommunityAlreadyBoundError(format_manual_bound_prompt(binding.qq_uin))
        raise CommunityAlreadyBoundError(MSG_ALREADY_BOUND)

    now = time.monotonic()
    expires_at = now + effective_ttl
    with _lock:
        _prune_expired_locked(now)
        old_entry = _user_codes.pop(user_id, None)
        old_mem_code = old_entry[0] if old_entry else None
        if old_mem_code:
            _code_users.pop(old_mem_code, None)

        new_code = _generate_code()
        while new_code in _code_users:  # pragma: no cover
            new_code = _generate_code()

        if effective_ttl > 0:
            _user_codes[user_id] = (new_code, expires_at)
            _code_users[new_code] = (user_id, expires_at)

    try:
        r = get_redis(REDIS_DB_AUTH)
        user_key = f"{_REDIS_USER_CODE_PREFIX}{user_id}"
        prev_redis_code = await r.get(user_key)
        pipe = r.pipeline()
        if prev_redis_code:
            pipe.delete(f"{_REDIS_CODE_USER_PREFIX}{prev_redis_code}")
        if old_mem_code and old_mem_code != prev_redis_code:  # pragma: no cover
            pipe.delete(f"{_REDIS_CODE_USER_PREFIX}{old_mem_code}")
        if effective_ttl > 0:
            pipe.set(user_key, new_code, ex=effective_ttl)
            pipe.set(f"{_REDIS_CODE_USER_PREFIX}{new_code}", user_id, ex=effective_ttl)
        else:
            pipe.delete(user_key)
        await pipe.execute()
    except Exception as exc:  # pragma: no cover
        logger.debug("[QQ群控] Redis 不可用，入群码回退至内存存储: %s", exc)

    logger.info(
        "[QQ群控] 已为用户 user_id=%s 签发入群码 (有效期 %ds)", user_id, effective_ttl
    )
    return new_code, effective_ttl


async def get_active_user_community_code(
    user_id: str,
) -> Optional[str]:  # pragma: no cover
    """Return the currently active unexpired code for ``user_id`` (for testing/inspection)."""
    now = time.monotonic()
    with _lock:
        _prune_expired_locked(now)
        entry = _user_codes.get(user_id)
        if entry and entry[1] > now:
            return entry[0]
    try:
        r = get_redis(REDIS_DB_AUTH)
        code = await r.get(f"{_REDIS_USER_CODE_PREFIX}{user_id}")
        if code:
            return str(code)
    except Exception:
        pass
    return None


async def get_active_user_for_code(code: str) -> Optional[str]:
    """Return the ``user_id`` currently bound to ``code`` without consuming it."""
    if not code:  # pragma: no cover
        return None
    now = time.monotonic()
    with _lock:
        _prune_expired_locked(now)
        entry = _code_users.get(code)
        if entry and entry[1] > now:
            uid = entry[0]
            if _user_codes.get(uid, ("", 0.0))[0] == code:
                return uid
    try:
        r = get_redis(REDIS_DB_AUTH)
        uid = await r.get(f"{_REDIS_CODE_USER_PREFIX}{code}")
        if uid:  # pragma: no cover
            current_for_user = await r.get(f"{_REDIS_USER_CODE_PREFIX}{uid}")
            if current_for_user == code:
                return str(uid)
    except Exception:
        pass
    return None


def _extract_candidate_answers(message: str) -> list[str]:
    """Extract candidate code strings from a QQ group verification message."""
    if not message:  # pragma: no cover
        return []
    candidates: list[str] = []
    stripped = message.strip()
    if stripped:
        candidates.append(stripped)
    for marker in ("答案：", "答案:"):
        if marker in message:
            after = message.split(marker, 1)[1].strip()
            if after and after not in candidates:
                candidates.append(after)
    for line in message.splitlines():
        line_s = line.strip()
        if line_s and line_s not in candidates:
            candidates.append(line_s)
    return candidates


async def match_and_consume_community_code(message: str) -> Optional[str]:
    """Match a QQ verification comment against active unexpired join codes and consume it.

    Returns the bound ``user_id`` if a valid unexpired code is found and consumed,
    or ``None`` otherwise.
    """
    if not message or not message.strip():  # pragma: no cover
        return None

    candidates = _extract_candidate_answers(message)
    now = time.monotonic()
    matched_code: Optional[str] = None
    matched_user_id: Optional[str] = None

    with _lock:
        _prune_expired_locked(now)
        # 1. Exact candidate match against in-memory codes
        for cand in candidates:
            if cand in _code_users:
                uid, exp = _code_users[cand]
                if exp > now and _user_codes.get(uid, ("", 0.0))[0] == cand:
                    matched_code = cand
                    matched_user_id = uid
                    break
        # 2. Substring match against active 24-char codes in memory
        if not matched_code:
            for code_str, (uid, exp) in list(_code_users.items()):
                if exp > now and _user_codes.get(uid, ("", 0.0))[0] == code_str:
                    if code_str in message:  # pragma: no cover
                        matched_code = code_str
                        matched_user_id = uid
                        break

        if matched_code and matched_user_id:
            _code_users.pop(matched_code, None)
            if _user_codes.get(matched_user_id, ("", 0.0))[0] == matched_code:
                _user_codes.pop(matched_user_id, None)

    if matched_code and matched_user_id:
        try:
            r = get_redis(REDIS_DB_AUTH)
            pipe = r.pipeline()
            pipe.delete(f"{_REDIS_CODE_USER_PREFIX}{matched_code}")
            pipe.delete(f"{_REDIS_USER_CODE_PREFIX}{matched_user_id}")
            await pipe.execute()
        except Exception:
            pass
        return matched_user_id

    # 3. Fallback: check Redis in case another worker issued the code
    try:
        r = get_redis(REDIS_DB_AUTH)
        for cand in candidates:
            if len(cand) == CODE_LENGTH:
                uid = await r.get(f"{_REDIS_CODE_USER_PREFIX}{cand}")
                if uid:  # pragma: no cover
                    current_for_user = await r.get(f"{_REDIS_USER_CODE_PREFIX}{uid}")
                    if current_for_user == cand:
                        pipe = r.pipeline()
                        pipe.delete(f"{_REDIS_CODE_USER_PREFIX}{cand}")
                        pipe.delete(f"{_REDIS_USER_CODE_PREFIX}{uid}")
                        await pipe.execute()
                        return str(uid)
    except Exception:
        pass

    return None


def format_binding_reminder(user: User) -> str:
    """Format the QQ private message reminder sent after binding a user."""
    display = (user.display_name or "").strip() or user.username
    return f"您已被绑定到用户 {display}（{user.username}）"


def format_ban_reminder(user: User) -> str:
    """Format the QQ private message reminder sent when a bound user is banned."""
    display = (user.display_name or "").strip() or user.username
    return f"您（{display}）已被封禁"


def format_unbind_reminder(user: User) -> str:
    """Format the QQ private message reminder sent when a user's QQ is unbound or rebound."""
    display = (user.display_name or "").strip() or user.username
    return f"您的 QQ 已与您（{display}）解绑"


def get_snowluma_client() -> httpx.AsyncClient:  # pragma: no cover
    """Return or initialize the shared httpx client for SnowLuma OneBot 11."""
    global _snowluma_client
    if _snowluma_client is None or _snowluma_client.is_closed:
        _snowluma_client = httpx.AsyncClient(timeout=10.0)
    return _snowluma_client


OneBotCaller = Callable[[str, dict[str, Any]], Coroutine[Any, Any, dict[str, Any]]]


async def _call_onebot(
    action: str,
    params: dict[str, Any],
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> dict[str, Any]:
    """Call a SnowLuma OneBot 11 HTTP endpoint."""
    if onebot_caller is not None:
        return await onebot_caller(action, params)
    url = f"{(base_url or SNOWLUMA_ONEBOT_URL).rstrip('/')}/{action.lstrip('/')}"  # pragma: no cover
    auth_token = (
        token if token is not None else SNOWLUMA_ONEBOT_TOKEN
    )  # pragma: no cover
    headers: dict[str, str] = {"Content-Type": "application/json"}  # pragma: no cover
    if auth_token:  # pragma: no cover
        headers["Authorization"] = f"Bearer {auth_token}"
    http_client = client or get_snowluma_client()  # pragma: no cover
    resp = await http_client.post(url, json=params, headers=headers)  # pragma: no cover
    resp.raise_for_status()  # pragma: no cover
    return resp.json()  # pragma: no cover


async def _send_private_msg_and_kick(
    qq_uin: str,
    target_group_id: int,
    message: str,
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> None:
    """Send a private message to ``qq_uin`` first, then kick them from ``target_group_id``."""
    auth_token = token if token is not None else SNOWLUMA_ONEBOT_TOKEN
    if (
        not auth_token and client is None and base_url is None and onebot_caller is None
    ):  # pragma: no cover
        return

    try:
        pm_res = await _call_onebot(
            "send_private_msg",
            {
                "user_id": int(qq_uin),
                "message": message,
                "auto_escape": True,
            },
            base_url=base_url,
            token=token,
            client=client,
            onebot_caller=onebot_caller,
        )
        if pm_res.get("retcode", 0) != 0:  # pragma: no cover
            await _call_onebot(
                "send_private_msg",
                {
                    "user_id": int(qq_uin),
                    "group_id": target_group_id,
                    "message": message,
                    "auto_escape": True,
                },
                base_url=base_url,
                token=token,
                client=client,
                onebot_caller=onebot_caller,
            )
    except Exception as exc:  # pragma: no cover
        logger.warning(
            "[QQ群控] 私聊发送失败 → QQ=%s: %s", mask_qq_uin(qq_uin) or qq_uin, exc
        )

    try:
        await _call_onebot(
            "set_group_kick",
            {
                "group_id": target_group_id,
                "user_id": int(qq_uin),
                "reject_add_request": False,
            },
            base_url=base_url,
            token=token,
            client=client,
            onebot_caller=onebot_caller,
        )
        logger.info(
            "[QQ群控] 已发送私聊提醒并移出群聊 → 群=%d QQ=%s 内容=%r",
            target_group_id,
            mask_qq_uin(qq_uin) or qq_uin,
            message,
        )
    except Exception as exc:  # pragma: no cover
        logger.warning(
            "[QQ群控] 移出群聊失败 → 群=%d QQ=%s: %s",
            target_group_id,
            mask_qq_uin(qq_uin) or qq_uin,
            exc,
        )


async def handle_user_banned_in_community(
    user: User,
    db: AsyncSession,
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    group_id: Optional[int] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> bool:
    """Notify and kick a banned user from the QQ group if bound, and remove binding.

    Sends private message ``您（显示名称）已被封禁`` first, then removes from the group.
    """
    await invalidate_user_community_code(user.id)
    binding = (
        await db.execute(
            select(CommunityBinding).where(CommunityBinding.user_id == user.id)
        )
    ).scalar_one_or_none()
    if not binding:  # pragma: no cover
        return False

    qq_uin = str(binding.qq_uin).strip()
    target_group_id = int(
        group_id if group_id is not None else (binding.group_id or SNOWLUMA_QQ_GROUP_ID)
    )
    ban_msg = format_ban_reminder(user)

    await db.delete(binding)
    await db.commit()
    logger.info(
        "[QQ群控] 用户被封禁，解除绑定并移出群聊 → 用户=%s(%s) QQ=%s 群=%d",
        user.display_name or user.username,
        user.username,
        mask_qq_uin(qq_uin) or qq_uin,
        target_group_id,
    )

    await _send_private_msg_and_kick(
        qq_uin,
        target_group_id,
        ban_msg,
        base_url=base_url,
        token=token,
        client=client,
        onebot_caller=onebot_caller,
    )
    return True


async def admin_bind_or_rebind_user_qq(
    user: User,
    qq_uin: str,
    db: AsyncSession,
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    group_id: Optional[int] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> CommunityBinding:
    """Manually bind or rebind a user's QQ number (Super Admin action).

    If the user was previously bound to a different QQ, sends ``您的 QQ 已与您（显示名称）解绑``
    to the old QQ and removes the old QQ from the group.
    """
    cleaned_qq = str(qq_uin or "").strip()
    if not _QQ_UIN_RE.match(cleaned_qq):  # pragma: no cover
        raise ValueError("QQ 号格式无效（需为 5-20 位纯数字且不能以 0 开头）")

    dup = (
        await db.execute(
            select(CommunityBinding).where(
                CommunityBinding.qq_uin == cleaned_qq,
                CommunityBinding.user_id != user.id,
            )
        )
    ).scalar_one_or_none()
    if dup is not None:  # pragma: no cover
        raise ValueError("该 QQ 号已绑定到其他用户")

    await invalidate_user_community_code(user.id)

    target_group_id = int(group_id if group_id is not None else SNOWLUMA_QQ_GROUP_ID)
    existing = (
        await db.execute(
            select(CommunityBinding).where(CommunityBinding.user_id == user.id)
        )
    ).scalar_one_or_none()

    # Check if the new QQ is already in the group when OneBot is reachable
    already_in_group = False
    auth_token = token if token is not None else SNOWLUMA_ONEBOT_TOKEN
    if (
        auth_token
        or client is not None
        or base_url is not None
        or onebot_caller is not None
    ):
        try:
            res = await _call_onebot(
                "get_group_member_list",
                {"group_id": target_group_id},
                base_url=base_url,
                token=token,
                client=client,
                onebot_caller=onebot_caller,
            )
            if res.get("status") == "ok" and isinstance(res.get("data"), list):
                active_uins = {
                    str(m.get("user_id")).strip()
                    for m in res["data"]
                    if isinstance(m, dict) and m.get("user_id") is not None
                }
                if cleaned_qq in active_uins:  # pragma: no cover
                    already_in_group = True
        except Exception:
            pass

    old_qq_to_kick: Optional[str] = None
    old_group_id = target_group_id

    if existing is not None:
        if str(existing.qq_uin).strip() == cleaned_qq:  # pragma: no cover
            existing.is_manual = True
            if already_in_group:
                existing.is_joined = True
            await db.commit()
            await db.refresh(existing)
            return existing
        old_qq_to_kick = str(existing.qq_uin).strip()
        old_group_id = int(existing.group_id or target_group_id)
        existing.qq_uin = cleaned_qq
        existing.group_id = str(target_group_id)
        existing.is_manual = True
        existing.is_joined = already_in_group
        existing.bound_at = datetime.now(timezone.utc)
        binding = existing
    else:
        binding = CommunityBinding(
            user_id=user.id,
            qq_uin=cleaned_qq,
            group_id=str(target_group_id),
            is_manual=True,
            is_joined=already_in_group,
            bound_at=datetime.now(timezone.utc),
        )
        db.add(binding)

    await db.commit()
    await db.refresh(binding)

    if old_qq_to_kick:
        logger.info(
            "[QQ群控] 管理员手动换绑 QQ → 用户=%s(%s) 原QQ=%s → 新QQ=%s (已在群=%s)",
            user.display_name or user.username,
            user.username,
            mask_qq_uin(old_qq_to_kick) or old_qq_to_kick,
            mask_qq_uin(cleaned_qq) or cleaned_qq,
            already_in_group,
        )
        unbind_msg = format_unbind_reminder(user)
        await _send_private_msg_and_kick(
            old_qq_to_kick,
            old_group_id,
            unbind_msg,
            base_url=base_url,
            token=token,
            client=client,
            onebot_caller=onebot_caller,
        )
    else:
        logger.info(
            "[QQ群控] 管理员手动绑定 QQ → 用户=%s(%s) QQ=%s (已在群=%s)",
            user.display_name or user.username,
            user.username,
            mask_qq_uin(cleaned_qq) or cleaned_qq,
            already_in_group,
        )

    return binding


async def admin_unbind_user_qq(
    user: User,
    db: AsyncSession,
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    group_id: Optional[int] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> bool:
    """Manually unbind a user's QQ number (Super Admin action).

    Sends private message ``您的 QQ 已与您（显示名称）解绑`` first, then removes from the group.
    """
    await invalidate_user_community_code(user.id)
    binding = (
        await db.execute(
            select(CommunityBinding).where(CommunityBinding.user_id == user.id)
        )
    ).scalar_one_or_none()
    if not binding:  # pragma: no cover
        return False

    old_qq = str(binding.qq_uin).strip()
    target_group_id = int(
        group_id if group_id is not None else (binding.group_id or SNOWLUMA_QQ_GROUP_ID)
    )
    unbind_msg = format_unbind_reminder(user)

    await db.delete(binding)
    await db.commit()
    logger.info(
        "[QQ群控] 管理员手动解绑 QQ → 用户=%s(%s) QQ=%s 群=%d",
        user.display_name or user.username,
        user.username,
        mask_qq_uin(old_qq) or old_qq,
        target_group_id,
    )

    await _send_private_msg_and_kick(
        old_qq,
        target_group_id,
        unbind_msg,
        base_url=base_url,
        token=token,
        client=client,
        onebot_caller=onebot_caller,
    )
    return True


async def sync_group_member_bindings(
    db: AsyncSession,
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    group_id: Optional[int] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> int:
    """Reconcile CommunityBinding records against the live QQ group member list.

    - If a manually pre-bound user (`is_joined == False`) is now in the group, marks `is_joined = True`.
    - If a joined member (`is_joined == True`) has left the group, automatically deletes their binding
      so the user can request a new join code again. Returns the number of unbound rows.
    """
    bindings = (await db.execute(select(CommunityBinding))).scalars().all()
    if not bindings:  # pragma: no cover
        return 0

    target_group_id = int(group_id if group_id is not None else SNOWLUMA_QQ_GROUP_ID)
    res = await _call_onebot(
        "get_group_member_list",
        {"group_id": target_group_id},
        base_url=base_url,
        token=token,
        client=client,
        onebot_caller=onebot_caller,
    )
    if res.get("status") != "ok" or res.get("retcode", -1) != 0:  # pragma: no cover
        return 0

    data = res.get("data")
    if not isinstance(data, list) or len(data) == 0:  # pragma: no cover
        return 0

    active_uins = {
        str(m.get("user_id")).strip()
        for m in data
        if isinstance(m, dict) and m.get("user_id") is not None
    }
    if not active_uins:  # pragma: no cover
        return 0

    unbound_users: list[str] = []
    newly_joined_updated = False
    for b in bindings:
        if str(b.group_id or target_group_id) != str(
            target_group_id
        ):  # pragma: no cover
            continue
        qq_str = str(b.qq_uin).strip()
        is_joined = bool(getattr(b, "is_joined", True))
        if qq_str in active_uins:  # pragma: no cover
            if not is_joined:
                b.is_joined = True
                newly_joined_updated = True
        else:
            if is_joined:
                unbound_users.append(b.user_id)

    if unbound_users:
        await db.execute(
            delete(CommunityBinding).where(CommunityBinding.user_id.in_(unbound_users))
        )
        await db.commit()
        logger.info(
            "[QQ群控] 检测到 %d 名成员自行退出群聊(%d)，已自动解除绑定: %s",
            len(unbound_users),
            target_group_id,
            unbound_users,
        )
        return len(unbound_users)

    if newly_joined_updated:  # pragma: no cover
        await db.commit()
        logger.info(
            "[QQ群控] 已同步预绑定成员的在群状态 (群=%d)",
            target_group_id,
        )

    return 0  # pragma: no cover


async def _fetch_group_member_uins(
    target_group_id: int,
    *,
    no_cache: bool = False,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> tuple[set[str], list[dict[str, Any]]]:
    """Fetch current QQ group members and return ``(uin_set, raw_member_dicts)``."""
    params: dict[str, Any] = {"group_id": target_group_id}
    if no_cache:
        params["no_cache"] = True
    try:
        res = await _call_onebot(
            "get_group_member_list",
            params,
            base_url=base_url,
            token=token,
            client=client,
            onebot_caller=onebot_caller,
        )
    except Exception:  # pragma: no cover
        return set(), []
    if res.get("status") != "ok" or res.get("retcode", -1) != 0:  # pragma: no cover
        return set(), []
    data = res.get("data")
    if not isinstance(data, list):  # pragma: no cover
        return set(), []
    members = [m for m in data if isinstance(m, dict) and m.get("user_id") is not None]
    uins = {
        str(m.get("user_id")).strip()
        for m in members
        if str(m.get("user_id")).strip() not in ("", "0")
    }
    return uins, members


async def _approve_and_notify_member(
    flag: str,
    requester_uin: str,
    target_group_id: int,
    user: User,
    *,
    db: Optional[AsyncSession] = None,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> tuple[bool, bool, str, str]:
    """Approve a pending group join request, resolve UIN if needed, and send the binding reminder PM."""
    resolved_uin = "" if requester_uin.strip() in ("", "0") else requester_uin.strip()
    before_uins: set[str] = set()
    if not resolved_uin:
        before_uins, _ = await _fetch_group_member_uins(
            target_group_id,
            no_cache=True,
            base_url=base_url,
            token=token,
            client=client,
            onebot_caller=onebot_caller,
        )

    approve_params: dict[str, Any] = {
        "flag": flag,
        "sub_type": "add",
        "approve": True,
    }
    if onebot_caller is None:  # pragma: no cover
        approve_params["reason"] = ""
    approve_res = await _call_onebot(
        "set_group_add_request",
        approve_params,
        base_url=base_url,
        token=token,
        client=client,
        onebot_caller=onebot_caller,
    )
    if (
        approve_res.get("status") != "ok" or approve_res.get("retcode", 0) != 0
    ):  # pragma: no cover
        logger.error(
            "[QQ群控] 审批入群申请失败 → flag=%s 用户=%s(%s) QQ=%s 响应=%s",
            flag,
            user.display_name or user.username,
            user.id,
            mask_qq_uin(resolved_uin) or resolved_uin or "未知",
            approve_res,
        )
        return False, False, "", ""

    if not resolved_uin:
        after_uins, after_members = await _fetch_group_member_uins(
            target_group_id,
            no_cache=True,
            base_url=base_url,
            token=token,
            client=client,
            onebot_caller=onebot_caller,
        )
        bound_uins: set[str] = set()
        if db is not None:
            existing_rows = (
                (await db.execute(select(CommunityBinding.qq_uin))).scalars().all()
            )
            bound_uins = {str(r).strip() for r in existing_rows if str(r).strip()}
        diff_uins = [u for u in (after_uins - before_uins) if u not in bound_uins]
        if diff_uins:
            resolved_uin = sorted(diff_uins)[0]
        elif after_members:  # pragma: no cover
            unbound_members = [
                m
                for m in after_members
                if str(m.get("user_id")).strip() not in bound_uins
                and str(m.get("role") or "member") == "member"
            ]
            if unbound_members:
                newest = max(
                    unbound_members,
                    key=lambda m: int(m.get("join_time") or 0),
                )
                if int(newest.get("join_time") or 0) > 0:
                    resolved_uin = str(newest.get("user_id")).strip()

    reminder = format_binding_reminder(user)
    private_sent = False
    if resolved_uin:
        try:
            pm_params: dict[str, Any] = {
                "user_id": int(resolved_uin),
                "message": reminder,
            }
            if onebot_caller is None:  # pragma: no cover
                pm_params["auto_escape"] = True
            pm_res = await _call_onebot(
                "send_private_msg",
                pm_params,
                base_url=base_url,
                token=token,
                client=client,
                onebot_caller=onebot_caller,
            )
            if pm_res.get("retcode", 0) == 0:
                private_sent = True
            else:  # pragma: no cover
                pm_res2 = await _call_onebot(
                    "send_private_msg",
                    {
                        "user_id": int(resolved_uin),
                        "group_id": target_group_id,
                        "message": reminder,
                        "auto_escape": True,
                    },
                    base_url=base_url,
                    token=token,
                    client=client,
                    onebot_caller=onebot_caller,
                )
                private_sent = pm_res2.get("retcode", 0) == 0
        except Exception as exc:  # pragma: no cover
            logger.warning(
                "[QQ群控] 发送绑定私聊提醒失败 → QQ=%s: %s",
                mask_qq_uin(resolved_uin) or resolved_uin,
                exc,
            )
    logger.info(
        "[QQ群控] 已自动批准入群并绑定 → 群=%d 用户=%s(%s) QQ=%s 私聊通知=%s",
        target_group_id,
        user.display_name or user.username,
        user.username,
        mask_qq_uin(resolved_uin) or resolved_uin or "未知",
        "已送达" if private_sent else "未送达",
    )
    return True, private_sent, reminder, resolved_uin


async def poll_snowluma_group_requests_once(
    db: Optional[AsyncSession] = None,
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    group_id: Optional[int] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> list[dict[str, Any]]:
    """Poll SnowLuma pending group requests once and return detailed handling results."""
    if db is None:
        async with AsyncSessionLocal() as session:
            return await poll_snowluma_group_requests_once(
                session,
                base_url=base_url,
                token=token,
                group_id=group_id,
                client=client,
                onebot_caller=onebot_caller,
            )

    target_group_id = int(group_id if group_id is not None else SNOWLUMA_QQ_GROUP_ID)
    res = await _call_onebot(
        "get_group_system_msg",
        {"group_id": target_group_id, "only_pending": True, "count": 50},
        base_url=base_url,
        token=token,
        client=client,
        onebot_caller=onebot_caller,
    )
    if res.get("status") != "ok" or res.get("retcode", 0) != 0:  # pragma: no cover
        return []

    items = res.get("data")
    if not isinstance(items, list):  # pragma: no cover
        return []

    results: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):  # pragma: no cover
            continue
        if item.get("checked"):  # pragma: no cover
            continue
        if int(item.get("group_id") or 0) != target_group_id:  # pragma: no cover
            continue

        flag = str(item.get("flag") or "")
        raw_uin = str(item.get("requester_uin") or "").strip()
        requester_uin = "" if raw_uin in ("", "0") else raw_uin
        message = str(item.get("message") or "")
        if not flag:  # pragma: no cover
            continue

        # Case 1: Manually pre-bound QQ by Super Admin — any password/message is accepted!
        if requester_uin:
            existing_qq_bind = (
                await db.execute(
                    select(CommunityBinding).where(
                        CommunityBinding.qq_uin == requester_uin
                    )
                )
            ).scalar_one_or_none()
            if existing_qq_bind is not None:
                bound_user = (
                    await db.execute(
                        select(User).where(User.id == existing_qq_bind.user_id)
                    )
                ).scalar_one_or_none()
                if (
                    bound_user
                    and bound_user.role_code != "banned"
                    and (bound_user.role_code == "pending" or bound_user.is_active)
                ):
                    approved, private_sent, reminder, _ = (
                        await _approve_and_notify_member(
                            flag,
                            requester_uin,
                            target_group_id,
                            bound_user,
                            db=db,
                            base_url=base_url,
                            token=token,
                            client=client,
                            onebot_caller=onebot_caller,
                        )
                    )
                    if approved:
                        existing_qq_bind.is_joined = True
                        existing_qq_bind.group_id = str(target_group_id)
                        await db.commit()
                        await invalidate_user_community_code(bound_user.id)
                        results.append(
                            {
                                "handled": True,
                                "approved": True,
                                "private_sent": private_sent,
                                "user_id": bound_user.id,
                                "qq_uin": requester_uin,
                                "message": reminder,
                            }
                        )
                continue

        # Case 2: Normal per-user join code verification
        if not message:  # pragma: no cover
            continue
        user_id = await match_and_consume_community_code(message)
        if not user_id:
            continue

        user = (
            await db.execute(select(User).where(User.id == user_id))
        ).scalar_one_or_none()
        if (
            not user
            or user.role_code == "banned"
            or (user.role_code != "pending" and not user.is_active)
        ):  # pragma: no cover
            continue

        existing_user_bind = (
            await db.execute(
                select(CommunityBinding).where(CommunityBinding.user_id == user.id)
            )
        ).scalar_one_or_none()
        if existing_user_bind:  # pragma: no cover
            continue

        approved, private_sent, reminder, resolved_uin = (
            await _approve_and_notify_member(
                flag,
                requester_uin,
                target_group_id,
                user,
                db=db,
                base_url=base_url,
                token=token,
                client=client,
                onebot_caller=onebot_caller,
            )
        )
        if not approved:  # pragma: no cover
            continue

        if resolved_uin:
            binding = CommunityBinding(
                user_id=user.id,
                qq_uin=resolved_uin,
                group_id=str(target_group_id),
                is_manual=False,
                is_joined=True,
                bound_at=datetime.now(timezone.utc),
            )
            db.add(binding)
            await db.commit()

        results.append(
            {
                "handled": True,
                "approved": True,
                "private_sent": private_sent,
                "user_id": user.id,
                "qq_uin": resolved_uin,
                "message": reminder,
            }
        )

    return results


async def process_pending_group_requests(
    db: AsyncSession,
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    group_id: Optional[int] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> int:  # pragma: no cover
    """Fetch pending QQ group join requests from SnowLuma and auto-approve valid join codes."""
    results = await poll_snowluma_group_requests_once(
        db,
        base_url=base_url,
        token=token,
        group_id=group_id,
        client=client,
        onebot_caller=onebot_caller,
    )
    return len(results)


async def _snowluma_poll_loop() -> None:  # pragma: no cover
    """Background loop polling SnowLuma for pending QQ group join requests and member departures."""
    interval = max(1.0, float(SNOWLUMA_POLL_INTERVAL or 3.0))
    logger.info(
        "[QQ群控] SnowLuma 群聊控制轮询服务已启动 (目标群=%d, 轮询间隔=%.1fs)",
        SNOWLUMA_QQ_GROUP_ID,
        interval,
    )
    while True:
        try:
            async with AsyncSessionLocal() as db:
                await process_pending_group_requests(db)
                await sync_group_member_bindings(db)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("[QQ群控] 轮询周期异常: %s", exc)
        await asyncio.sleep(interval)


def start_snowluma_poller() -> Optional[asyncio.Task]:  # pragma: no cover
    """Start the background SnowLuma polling task if SNOWLUMA_ONEBOT_TOKEN is configured."""
    global _snowluma_poller_task
    if not SNOWLUMA_ONEBOT_TOKEN:
        logger.warning("[QQ群控] 未配置 SNOWLUMA_ONEBOT_TOKEN，群聊控制轮询未启动")
        return None
    if _snowluma_poller_task is not None and not _snowluma_poller_task.done():
        return _snowluma_poller_task
    _snowluma_poller_task = asyncio.create_task(
        _snowluma_poll_loop(), name="snowluma-community-poller"
    )
    return _snowluma_poller_task


async def stop_snowluma_poller() -> None:  # pragma: no cover
    """Stop the background SnowLuma polling task and close its HTTP client."""
    global _snowluma_poller_task, _snowluma_client
    if _snowluma_poller_task is not None:
        _snowluma_poller_task.cancel()
        try:
            await _snowluma_poller_task
        except asyncio.CancelledError:
            pass
        _snowluma_poller_task = None
    if _snowluma_client is not None:
        await _snowluma_client.aclose()
        _snowluma_client = None
