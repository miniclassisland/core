"""Per-user QQ community join code management and SnowLuma OneBot 11 auto-approval."""

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import secrets
import shutil
import string
import subprocess
import threading
import time
from typing import Any, Callable, Coroutine, Optional

import httpx
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.models import (
    AccountMember,
    AccountQuota,
    CommunityBinding,
    User,
)
from app.shared.db.session import AsyncSessionLocal
from app.shared.utils.config import (
    COMMUNITY_CODE_TTL_SECONDS,
    COMMUNITY_QQ_GROUP_ID,
    CONFIG_DIR,
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
    "如果需要继续加入群聊，您可以考虑新注册一个用户或者联系管理员"
)

_QQ_UIN_RE = re.compile(r"^[1-9][0-9]{4,19}$")

_REDIS_USER_CODE_PREFIX = "community:user_code:"
_REDIS_CODE_USER_PREFIX = "community:code_user:"
_REDIS_REG_MSG_PREFIX = "community:reg_msg:"
_REDIS_LIFECYCLE_MODE_KEY = "community:lifecycle_mode"
_REDIS_PENDING_RESTART_KEY = "community:pending_restart"

MSG_RESTARTING = "集控服务器后端正在重启，服务将马上恢复"
MSG_RESTART_RECOVERED = "服务已恢复"
MSG_SHUTDOWN_MAINTENANCE = "服务器例行维护，服务暂时不可用"
MSG_SHUTDOWN_RECOVERED = "服务器维护已结束，服务已恢复"

_CQ_REPLY_RE = re.compile(r"\[CQ:reply,[^\]]*id=([^\],]+)")
_CQ_TAG_RE = re.compile(r"\[CQ:[^\]]+\]")
_REG_MSG_PARSE_RE = re.compile(r"^新用户\s+.+\(([^,()]+),\s*([^,()]+)\)\s+注册$")
_QR_LOGIN_LINK_RE = re.compile(
    r"miniclassisland://qr-login/([^\s\]\"'<>]+)", re.IGNORECASE
)

_lock = threading.Lock()
_code = ""
# In-memory fallback/index for per-user codes: user_id -> (code, expires_at_monotonic)
_user_codes: dict[str, tuple[str, float]] = {}
# Reverse index: code -> (user_id, expires_at_monotonic)
_code_users: dict[str, tuple[str, float]] = {}
# Registration notification message_id -> user_id
_reg_msg_users: dict[str, str] = {}
# Processed incoming private message IDs to avoid duplicate quote-reply handling
_processed_reply_msg_ids: set[str] = set()
# In-memory lifecycle state fallback
_memory_lifecycle_mode: str = ""
_memory_pending_restart: float = 0.0

_snowluma_client: Optional[httpx.AsyncClient] = None
_snowluma_poller_task: Optional[asyncio.Task] = None


class CommunityAlreadyBoundError(PermissionError):
    """Raised when a user who already has a bound QQ requests another join code."""


def mask_qq_uin(qq_uin: Optional[str]) -> Optional[str]:
    """Mask a QQ number for safe display to the user (e.g., ``123****890``)."""
    if not qq_uin:
        return None
    s = str(qq_uin).strip()
    if not s:
        return None
    if len(s) >= 7:
        return f"{s[:3]}****{s[-3:]}"
    if len(s) >= 5:
        return f"{s[:2]}***{s[-2:]}"
    return f"{s[:1]}***"


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
    while chars[0] == " " or chars[-1] == " ":
        edge = 0 if chars[0] == " " else len(chars) - 1
        interior = [i for i in range(1, len(chars) - 1) if chars[i] != " "]
        if not interior:
            break
        swap = secrets.choice(interior)
        chars[edge], chars[swap] = chars[swap], chars[edge]

    return "".join(chars)


_code = _generate_code()


def _prune_expired_locked(now: Optional[float] = None) -> None:
    """Remove expired entries from in-memory caches (caller must hold _lock)."""
    ts = now if now is not None else time.monotonic()
    expired_users = [uid for uid, (_, exp) in _user_codes.items() if exp <= ts]
    for uid in expired_users:
        old_code, _ = _user_codes.pop(uid, ("", 0.0))
        if old_code:
            _code_users.pop(old_code, None)
    expired_codes = [c for c, (_, exp) in _code_users.items() if exp <= ts]
    for c in expired_codes:
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
        async for k in r.scan_iter(match=f"{_REDIS_USER_CODE_PREFIX}*"):
            keys.append(k)
        async for k in r.scan_iter(match=f"{_REDIS_CODE_USER_PREFIX}*"):
            keys.append(k)
        if keys:
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
        if old_code and old_code != prev_code:
            pipe.delete(f"{_REDIS_CODE_USER_PREFIX}{old_code}")
        await pipe.execute()
    except Exception:
        pass


async def is_user_community_bound(user_id: str, db: AsyncSession) -> bool:
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
    if binding is not None and SNOWLUMA_ONEBOT_TOKEN:
        await sync_group_member_bindings(db)
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
    if binding is not None and SNOWLUMA_ONEBOT_TOKEN:
        await sync_group_member_bindings(db)
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
        while new_code in _code_users:
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
        if old_mem_code and old_mem_code != prev_redis_code:
            pipe.delete(f"{_REDIS_CODE_USER_PREFIX}{old_mem_code}")
        if effective_ttl > 0:
            pipe.set(user_key, new_code, ex=effective_ttl)
            pipe.set(f"{_REDIS_CODE_USER_PREFIX}{new_code}", user_id, ex=effective_ttl)
        else:
            pipe.delete(user_key)
        await pipe.execute()
    except Exception as exc:
        logger.debug("[QQ群控] Redis 不可用，入群码回退至内存存储: %s", exc)

    logger.info(
        "[QQ群控] 已为用户 user_id=%s 签发入群码 (有效期 %ds)", user_id, effective_ttl
    )
    return new_code, effective_ttl


async def get_active_user_community_code(
    user_id: str,
) -> Optional[str]:
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
    if not code:
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
        if uid:
            current_for_user = await r.get(f"{_REDIS_USER_CODE_PREFIX}{uid}")
            if current_for_user == code:
                return str(uid)
    except Exception:
        pass
    return None


def _extract_candidate_answers(message: str) -> list[str]:
    """Extract candidate code strings from a QQ group verification message."""
    if not message:
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
    if not message or not message.strip():
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
                    if code_str in message:
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
                if uid:
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


def format_binding_reminder(user: User, qq_uin: str = "") -> str:
    """Format the QQ message sent when a new member joins the group and is bound."""
    display = (user.display_name or "").strip() or user.username
    qq_part = f" {qq_uin.strip()}" if qq_uin and qq_uin.strip() else ""
    return (
        f"欢迎 {display} ({user.username}) 加入交流群，"
        f"您的 QQ{qq_part} 已自动绑定。如需解绑，请直接退出群聊或者联系运维"
    )


def format_admin_manual_bind_reminder(user: User, qq_uin: str) -> str:
    """Format the QQ message sent when an existing group member is manually bound by an admin."""
    display = (user.display_name or "").strip() or user.username
    return f"管理员已将您的 QQ {qq_uin.strip()} 与 {display} ({user.username}) 绑定"


def format_ban_reminder(user: User) -> str:
    """Format the QQ private message reminder sent when a bound user is banned."""
    display = (user.display_name or "").strip() or user.username
    return f"您（{display}）已被封禁"


def format_unbind_reminder(user: User, qq_uin: str = "") -> str:
    """Format the QQ private message reminder sent when a user's QQ is unbound or rebound."""
    display = (user.display_name or "").strip() or user.username
    qq_part = f" {qq_uin.strip()}" if qq_uin and qq_uin.strip() else ""
    return f"管理员已将您的 QQ{qq_part} 与 {display} ({user.username}) 解绑"


def format_user_identity(user: User) -> str:
    """Format a user identity as ``Display Name(username, email)``."""
    display = (user.display_name or "").strip() or user.username
    return f"{display}({user.username}, {user.email})"


def format_superadmin_registration_report(user: User) -> str:
    """Format the superadmin private report when a new user registers."""
    return f"新用户 {format_user_identity(user)} 注册"


def format_superadmin_ticket_report(user: User, subject: str, content: str) -> str:
    """Format the superadmin private report when a user submits a ticket."""
    return f"用户 {format_user_identity(user)} 发起工单：{subject}\n{content}"


def format_superadmin_group_join_report(
    user: User, qq_uin: str, qq_nick: str = ""
) -> str:
    """Format the superadmin private report when a user joins the group via auto-approval."""
    clean_uin = str(qq_uin or "").strip()
    clean_nick = str(qq_nick or "").strip() or clean_uin
    return (
        f"用户 {format_user_identity(user)} 刚刚使用 QQ "
        f"{clean_uin}({clean_nick}) 加入了交流群"
    )


def format_user_approved_notification(
    user: User, max_clients: Optional[int] = None
) -> str:
    """Format the private notification sent to a user when their registration is approved."""
    display = (user.display_name or "").strip() or user.username
    base = f"您 ({display}) 的注册申请已经被批准，欢迎使用 MINI ClassIsland"
    if max_clients is not None:
        return f"{base}，当前配额最大允许注册 {max_clients} 台设备"
    return base


def format_user_quota_changed_notification(
    user: User, max_clients: int, max_grpc_connections: int
) -> str:
    """Format the private notification sent to account admins/owners when device quotas change."""
    display = (user.display_name or "").strip() or user.username
    return (
        f"您 ({display}) 的配额已经变更为最大允许注册 {max_clients} 台设备，"
        f"最大允许同时保持 {max_grpc_connections} 台设备连接"
    )


def format_group_announcement(title: str, content: str) -> str:
    """Format the group notification sent when a site announcement is published."""
    return f"新的站内公告【{title}】：\n{content}"


def get_snowluma_client() -> httpx.AsyncClient:
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
    url = f"{(base_url or SNOWLUMA_ONEBOT_URL).rstrip('/')}/{action.lstrip('/')}"
    auth_token = token if token is not None else SNOWLUMA_ONEBOT_TOKEN
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    http_client = client or get_snowluma_client()
    resp = await http_client.post(url, json=params, headers=headers)
    resp.raise_for_status()
    return resp.json()


def _extract_message_id(res: dict[str, Any]) -> Optional[str]:
    """Extract OneBot message_id from a send_private_msg/send_group_msg response."""
    if not isinstance(res, dict):
        return None
    data = res.get("data")
    if isinstance(data, dict) and data.get("message_id") is not None:
        return str(data["message_id"]).strip() or None
    if res.get("message_id") is not None:
        return str(res["message_id"]).strip() or None
    return None


async def _send_private_msg_with_id(
    qq_uin: str,
    target_group_id: int,
    message: str,
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> tuple[bool, Optional[str]]:
    """Send a private message to ``qq_uin`` and return ``(sent_ok, message_id)``."""
    auth_token = token if token is not None else SNOWLUMA_ONEBOT_TOKEN
    if not auth_token and client is None and base_url is None and onebot_caller is None:
        return False, None

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
        if pm_res.get("retcode", 0) == 0:
            return True, _extract_message_id(pm_res)
        pm_res2 = await _call_onebot(
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
        if pm_res2.get("retcode", 0) == 0:
            return True, _extract_message_id(pm_res2)
        return False, None
    except Exception as exc:
        logger.warning(
            "[QQ群控] 私聊发送失败 → QQ=%s: %s", mask_qq_uin(qq_uin) or qq_uin, exc
        )
        return False, None


async def _send_private_msg(
    qq_uin: str,
    target_group_id: int,
    message: str,
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> bool:
    """Send a private message to ``qq_uin`` (with temporary session fallback via ``target_group_id``)."""
    ok, _ = await _send_private_msg_with_id(
        qq_uin,
        target_group_id,
        message,
        base_url=base_url,
        token=token,
        client=client,
        onebot_caller=onebot_caller,
    )
    return ok


async def send_group_msg(
    message: str,
    *,
    group_id: Optional[int] = None,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> bool:
    """Send a message to the target QQ group."""
    auth_token = token if token is not None else SNOWLUMA_ONEBOT_TOKEN
    if not auth_token and client is None and base_url is None and onebot_caller is None:
        return False

    target_group_id = int(group_id if group_id is not None else SNOWLUMA_QQ_GROUP_ID)
    try:
        res = await _call_onebot(
            "send_group_msg",
            {
                "group_id": target_group_id,
                "message": message,
                "auto_escape": True,
            },
            base_url=base_url,
            token=token,
            client=client,
            onebot_caller=onebot_caller,
        )
        return res.get("retcode", 0) == 0
    except Exception as exc:
        logger.warning(
            "[QQ群控] 群消息发送失败 → 群=%d: %s",
            target_group_id,
            exc,
        )
        return False


async def get_superadmin_qq_uins(db: AsyncSession) -> list[str]:
    """Return bound QQ UINs of all active platform Super Administrators from the database."""
    rows = (
        (
            await db.execute(
                select(CommunityBinding.qq_uin)
                .join(User, User.id == CommunityBinding.user_id)
                .where(
                    User.role_code == "superadmin",
                    User.is_active.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
    seen: set[str] = set()
    uins: list[str] = []
    for raw in rows:
        uin = str(raw or "").strip()
        if uin and uin not in seen:
            seen.add(uin)
            uins.append(uin)
    return uins


async def _send_private_msg_to_superadmins(
    db: AsyncSession,
    message: str,
    *,
    group_id: Optional[int] = None,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> list[tuple[str, Optional[str]]]:
    """Send a private message to all bound Super Administrators and return ``[(qq_uin, message_id), ...]``."""
    uins = await get_superadmin_qq_uins(db)
    if not uins:
        return []
    target_group_id = int(group_id if group_id is not None else SNOWLUMA_QQ_GROUP_ID)
    delivered: list[tuple[str, Optional[str]]] = []
    for uin in uins:
        ok, msg_id = await _send_private_msg_with_id(
            uin,
            target_group_id,
            message,
            base_url=base_url,
            token=token,
            client=client,
            onebot_caller=onebot_caller,
        )
        if ok:
            delivered.append((uin, msg_id))
    return delivered


async def _store_registration_msg_mapping(message_id: str, user_id: str) -> None:
    """Associate an outbound registration report message_id with the pending user_id."""
    clean_mid = str(message_id or "").strip()
    if not clean_mid or not user_id:
        return
    with _lock:
        _reg_msg_users[clean_mid] = user_id
    try:
        r = get_redis(REDIS_DB_AUTH)
        await r.set(f"{_REDIS_REG_MSG_PREFIX}{clean_mid}", user_id, ex=86400 * 7)
    except Exception:
        pass


async def get_registration_user_for_msg(message_id: str) -> Optional[str]:
    """Resolve the pending ``user_id`` associated with a registration report ``message_id``."""
    clean_mid = str(message_id or "").strip()
    if not clean_mid:
        return None
    with _lock:
        uid = _reg_msg_users.get(clean_mid)
        if uid:
            return uid
    try:
        r = get_redis(REDIS_DB_AUTH)
        val = await r.get(f"{_REDIS_REG_MSG_PREFIX}{clean_mid}")
        if val:
            return str(val)
    except Exception:
        pass
    return None


async def notify_superadmin_new_registration(
    user: User,
    db: AsyncSession,
    *,
    group_id: Optional[int] = None,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> list[tuple[str, Optional[str]]]:
    """Notify bound Super Administrators when a new user registers, and record message_id for quote-reply approval."""
    msg = format_superadmin_registration_report(user)
    delivered = await _send_private_msg_to_superadmins(
        db,
        msg,
        group_id=group_id,
        base_url=base_url,
        token=token,
        client=client,
        onebot_caller=onebot_caller,
    )
    for _, msg_id in delivered:
        if msg_id:
            await _store_registration_msg_mapping(msg_id, user.id)
    return delivered


async def notify_superadmin_new_ticket(
    user: User,
    subject: str,
    content: str,
    db: AsyncSession,
    *,
    group_id: Optional[int] = None,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> bool:
    """Notify bound Super Administrators when a user creates a new support ticket."""
    msg = format_superadmin_ticket_report(user, subject, content)
    delivered = await _send_private_msg_to_superadmins(
        db,
        msg,
        group_id=group_id,
        base_url=base_url,
        token=token,
        client=client,
        onebot_caller=onebot_caller,
    )
    return len(delivered) > 0


async def notify_superadmin_group_join(
    user: User,
    qq_uin: str,
    qq_nick: str,
    db: AsyncSession,
    *,
    group_id: Optional[int] = None,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> bool:
    """Notify bound Super Administrators when a user joins the QQ group via auto-approval."""
    msg = format_superadmin_group_join_report(user, qq_uin, qq_nick)
    delivered = await _send_private_msg_to_superadmins(
        db,
        msg,
        group_id=group_id,
        base_url=base_url,
        token=token,
        client=client,
        onebot_caller=onebot_caller,
    )
    return len(delivered) > 0


async def notify_user_approved(
    user: User,
    db: AsyncSession,
    *,
    max_clients: Optional[int] = None,
    group_id: Optional[int] = None,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> bool:
    """Send a private message to ``user`` if bound when their registration is approved."""
    binding = (
        await db.execute(
            select(CommunityBinding).where(CommunityBinding.user_id == user.id)
        )
    ).scalar_one_or_none()
    if not binding or not str(binding.qq_uin or "").strip():
        return False
    qq_uin = str(binding.qq_uin).strip()
    target_group_id = int(
        group_id if group_id is not None else (binding.group_id or SNOWLUMA_QQ_GROUP_ID)
    )
    resolved_max_clients = max_clients
    if resolved_max_clients is None:
        q_val = (
            await db.execute(
                select(AccountQuota.max_value)
                .join(
                    AccountMember, AccountMember.account_id == AccountQuota.account_id
                )
                .where(
                    AccountMember.user_id == user.id,
                    AccountQuota.quota_key == "max_clients",
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        resolved_max_clients = int(q_val) if q_val is not None else 6
    msg = format_user_approved_notification(user, max_clients=resolved_max_clients)
    return await _send_private_msg(
        qq_uin,
        target_group_id,
        msg,
        base_url=base_url,
        token=token,
        client=client,
        onebot_caller=onebot_caller,
    )


async def notify_account_device_quota_changed(
    account_id: str,
    quota_key: str,
    db: AsyncSession,
    *,
    group_id: Optional[int] = None,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> int:
    """Notify account owners and admins via QQ PM when device count quotas change."""
    if quota_key not in ("max_clients", "max_grpc_connections"):
        return 0

    quota_rows = (
        (
            await db.execute(
                select(AccountQuota).where(
                    AccountQuota.account_id == account_id,
                    AccountQuota.quota_key.in_(("max_clients", "max_grpc_connections")),
                )
            )
        )
        .scalars()
        .all()
    )
    qmap = {q.quota_key: q.max_value for q in quota_rows}
    max_clients = int(qmap.get("max_clients", 6))
    max_grpc = int(qmap.get("max_grpc_connections", 4))

    rows = (
        await db.execute(
            select(User, CommunityBinding)
            .join(AccountMember, AccountMember.user_id == User.id)
            .join(CommunityBinding, CommunityBinding.user_id == User.id)
            .where(
                AccountMember.account_id == account_id,
                AccountMember.role_in_account.in_(("owner", "admin")),
            )
        )
    ).all()

    target_group_id = int(group_id if group_id is not None else SNOWLUMA_QQ_GROUP_ID)
    sent_count = 0
    for user_obj, binding in rows:
        qq_uin = str(binding.qq_uin or "").strip()
        if not qq_uin:
            continue
        grp = int(
            group_id if group_id is not None else (binding.group_id or target_group_id)
        )
        msg = format_user_quota_changed_notification(user_obj, max_clients, max_grpc)
        ok = await _send_private_msg(
            qq_uin,
            grp,
            msg,
            base_url=base_url,
            token=token,
            client=client,
            onebot_caller=onebot_caller,
        )
        if ok:
            sent_count += 1
    return sent_count


async def notify_group_site_announcement(
    title: str,
    content: str,
    *,
    group_id: Optional[int] = None,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> bool:
    """Broadcast a new site announcement to the target QQ group."""
    clean_title = str(title or "").strip()
    clean_content = str(content or "").strip()
    if not clean_title and not clean_content:
        return False
    msg = format_group_announcement(clean_title, clean_content)
    return await send_group_msg(
        msg,
        group_id=group_id,
        base_url=base_url,
        token=token,
        client=client,
        onebot_caller=onebot_caller,
    )


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
    if not auth_token and client is None and base_url is None and onebot_caller is None:
        return

    await _send_private_msg(
        qq_uin,
        target_group_id,
        message,
        base_url=base_url,
        token=token,
        client=client,
        onebot_caller=onebot_caller,
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
    except Exception as exc:
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
    if not binding:
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
    if not _QQ_UIN_RE.match(cleaned_qq):
        raise ValueError("QQ 号格式无效（需为 5-20 位纯数字且不能以 0 开头）")

    dup = (
        await db.execute(
            select(CommunityBinding).where(
                CommunityBinding.qq_uin == cleaned_qq,
                CommunityBinding.user_id != user.id,
            )
        )
    ).scalar_one_or_none()
    if dup is not None:
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
                if cleaned_qq in active_uins:
                    already_in_group = True
        except Exception:
            pass

    old_qq_to_kick: Optional[str] = None
    old_group_id = target_group_id

    if existing is not None:
        if str(existing.qq_uin).strip() == cleaned_qq:
            was_joined = bool(getattr(existing, "is_joined", False))
            existing.is_manual = True
            if already_in_group:
                existing.is_joined = True
            await db.commit()
            await db.refresh(existing)
            if already_in_group and not was_joined:
                await _send_private_msg(
                    cleaned_qq,
                    target_group_id,
                    format_admin_manual_bind_reminder(user, cleaned_qq),
                    base_url=base_url,
                    token=token,
                    client=client,
                    onebot_caller=onebot_caller,
                )
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
        unbind_msg = format_unbind_reminder(user, old_qq_to_kick)
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

    if already_in_group:
        await _send_private_msg(
            cleaned_qq,
            target_group_id,
            format_admin_manual_bind_reminder(user, cleaned_qq),
            base_url=base_url,
            token=token,
            client=client,
            onebot_caller=onebot_caller,
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

    Sends private message ``管理员已将您的 QQ {qq_uin} 与 {display} ({username}) 解绑`` first, then removes from the group.
    """
    await invalidate_user_community_code(user.id)
    binding = (
        await db.execute(
            select(CommunityBinding).where(CommunityBinding.user_id == user.id)
        )
    ).scalar_one_or_none()
    if not binding:
        return False

    old_qq = str(binding.qq_uin).strip()
    target_group_id = int(
        group_id if group_id is not None else (binding.group_id or SNOWLUMA_QQ_GROUP_ID)
    )
    unbind_msg = format_unbind_reminder(user, old_qq)

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
    if not bindings:
        return 0

    target_group_id = int(group_id if group_id is not None else SNOWLUMA_QQ_GROUP_ID)
    member_params: dict[str, Any] = {"group_id": target_group_id}
    if onebot_caller is None:
        member_params["no_cache"] = True
    res = await _call_onebot(
        "get_group_member_list",
        member_params,
        base_url=base_url,
        token=token,
        client=client,
        onebot_caller=onebot_caller,
    )
    if res.get("status") != "ok" or res.get("retcode", -1) != 0:
        return 0

    data = res.get("data")
    if not isinstance(data, list) or len(data) == 0:
        return 0

    active_uins = {
        str(m.get("user_id")).strip()
        for m in data
        if isinstance(m, dict) and m.get("user_id") is not None
    }
    if not active_uins:
        return 0

    unbound_users: list[str] = []
    newly_joined_updated = False
    for b in bindings:
        if str(b.group_id or target_group_id) != str(target_group_id):
            continue
        qq_str = str(b.qq_uin).strip()
        is_joined = bool(getattr(b, "is_joined", True))
        if qq_str in active_uins:
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

    if newly_joined_updated:
        await db.commit()
        logger.info(
            "[QQ群控] 已同步预绑定成员的在群状态 (群=%d)",
            target_group_id,
        )

    return 0


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
    except Exception:
        return set(), []
    if res.get("status") != "ok" or res.get("retcode", -1) != 0:
        return set(), []
    data = res.get("data")
    if not isinstance(data, list):
        return set(), []
    members = [m for m in data if isinstance(m, dict) and m.get("user_id") is not None]
    uins = {
        str(m.get("user_id")).strip()
        for m in members
        if str(m.get("user_id")).strip() not in ("", "0")
    }
    return uins, members


async def _reject_group_request(
    flag: str,
    target_group_id: int,
    requester_uin: str = "",
    reason: str = "无效的验证码",
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> bool:
    """Reject a pending group join request with ``reason``."""
    reject_params: dict[str, Any] = {
        "flag": flag,
        "sub_type": "add",
        "approve": False,
        "reason": reason,
    }
    try:
        res = await _call_onebot(
            "set_group_add_request",
            reject_params,
            base_url=base_url,
            token=token,
            client=client,
            onebot_caller=onebot_caller,
        )
        ok = res.get("status") == "ok" and res.get("retcode", 0) == 0
        if ok:
            logger.info(
                "[QQ群控] 已拒绝入群申请 → 群=%d QQ=%s 原因=%s",
                target_group_id,
                mask_qq_uin(requester_uin) or requester_uin or "未知",
                reason,
            )
        else:
            logger.warning(
                "[QQ群控] 拒绝入群申请失败 → flag=%s 群=%d QQ=%s 响应=%s",
                flag,
                target_group_id,
                mask_qq_uin(requester_uin) or requester_uin or "未知",
                res,
            )
        return ok
    except Exception as exc:
        logger.warning(
            "[QQ群控] 拒绝入群申请异常 → flag=%s 群=%d: %s",
            flag,
            target_group_id,
            exc,
        )
        return False


async def _approve_and_notify_member(
    flag: str,
    requester_uin: str,
    target_group_id: int,
    user: User,
    *,
    requester_nick: str = "",
    db: Optional[AsyncSession] = None,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> tuple[bool, bool, str, str, str]:
    """Approve a pending group join request, resolve UIN if needed, and send the binding reminder PM."""
    resolved_uin = "" if requester_uin.strip() in ("", "0") else requester_uin.strip()
    resolved_nick = str(requester_nick or "").strip()
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
    if onebot_caller is None:
        approve_params["reason"] = ""
    approve_res = await _call_onebot(
        "set_group_add_request",
        approve_params,
        base_url=base_url,
        token=token,
        client=client,
        onebot_caller=onebot_caller,
    )
    if approve_res.get("status") != "ok" or approve_res.get("retcode", 0) != 0:
        logger.error(
            "[QQ群控] 审批入群申请失败 → flag=%s 用户=%s(%s) QQ=%s 响应=%s",
            flag,
            user.display_name or user.username,
            user.id,
            mask_qq_uin(resolved_uin) or resolved_uin or "未知",
            approve_res,
        )
        return False, False, "", "", ""

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
        elif after_members:
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
        if resolved_uin and not resolved_nick and after_members:
            for m in after_members:
                if str(m.get("user_id")).strip() == resolved_uin:
                    resolved_nick = str(
                        m.get("nickname") or m.get("card") or ""
                    ).strip()
                    break

    reminder = format_binding_reminder(user, resolved_uin)
    private_sent = False
    if resolved_uin:
        try:
            pm_params: dict[str, Any] = {
                "user_id": int(resolved_uin),
                "message": reminder,
            }
            if onebot_caller is None:
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
            else:
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
        except Exception as exc:
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
    return True, private_sent, reminder, resolved_uin, (resolved_nick or resolved_uin)


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
    if res.get("status") != "ok" or res.get("retcode", 0) != 0:
        return []

    items = res.get("data")
    if not isinstance(items, list):
        return []

    results: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("checked"):
            continue
        if int(item.get("group_id") or 0) != target_group_id:
            continue

        flag = str(item.get("flag") or "")
        raw_uin = str(item.get("requester_uin") or "").strip()
        requester_uin = "" if raw_uin in ("", "0") else raw_uin
        requester_nick = str(
            item.get("requester_nick") or item.get("nickname") or ""
        ).strip()
        message = str(item.get("message") or "")
        if not flag:
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
                    approved, private_sent, reminder, _, resolved_nick = (
                        await _approve_and_notify_member(
                            flag,
                            requester_uin,
                            target_group_id,
                            bound_user,
                            requester_nick=requester_nick,
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
                        await notify_superadmin_group_join(
                            bound_user,
                            requester_uin,
                            resolved_nick or requester_uin,
                            db,
                            group_id=target_group_id,
                            base_url=base_url,
                            token=token,
                            client=client,
                            onebot_caller=onebot_caller,
                        )
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
                    else:
                        await _reject_group_request(
                            flag,
                            target_group_id,
                            requester_uin,
                            "无效的验证码",
                            base_url=base_url,
                            token=token,
                            client=client,
                            onebot_caller=onebot_caller,
                        )
                continue

        # Case 2: Normal per-user join code verification
        user_id = await match_and_consume_community_code(message) if message else None
        if not user_id:
            await _reject_group_request(
                flag,
                target_group_id,
                requester_uin,
                "无效的验证码",
                base_url=base_url,
                token=token,
                client=client,
                onebot_caller=onebot_caller,
            )
            continue

        user = (
            await db.execute(select(User).where(User.id == user_id))
        ).scalar_one_or_none()
        if (
            not user
            or user.role_code == "banned"
            or (user.role_code != "pending" and not user.is_active)
        ):
            await _reject_group_request(
                flag,
                target_group_id,
                requester_uin,
                "无效的验证码",
                base_url=base_url,
                token=token,
                client=client,
                onebot_caller=onebot_caller,
            )
            continue

        existing_user_bind = (
            await db.execute(
                select(CommunityBinding).where(CommunityBinding.user_id == user.id)
            )
        ).scalar_one_or_none()
        if existing_user_bind:
            await _reject_group_request(
                flag,
                target_group_id,
                requester_uin,
                "无效的验证码",
                base_url=base_url,
                token=token,
                client=client,
                onebot_caller=onebot_caller,
            )
            continue

        approved, private_sent, reminder, resolved_uin, resolved_nick = (
            await _approve_and_notify_member(
                flag,
                requester_uin,
                target_group_id,
                user,
                requester_nick=requester_nick,
                db=db,
                base_url=base_url,
                token=token,
                client=client,
                onebot_caller=onebot_caller,
            )
        )
        if not approved:
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
            if user.role_code != "superadmin":
                await notify_superadmin_group_join(
                    user,
                    resolved_uin,
                    resolved_nick or resolved_uin,
                    db,
                    group_id=target_group_id,
                    base_url=base_url,
                    token=token,
                    client=client,
                    onebot_caller=onebot_caller,
                )

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


def _extract_reply_id_and_text(item: dict[str, Any]) -> tuple[Optional[str], str]:
    """Extract ``(reply_message_id, plain_text)`` from a OneBot 11 message payload."""
    reply_id: Optional[str] = None
    for key in ("reply_id", "reply_message_id"):
        if item.get(key) is not None and str(item[key]).strip():
            reply_id = str(item[key]).strip()
            break
    if not reply_id and isinstance(item.get("reply"), dict):
        rid = item["reply"].get("id") or item["reply"].get("message_id")
        if rid is not None and str(rid).strip():
            reply_id = str(rid).strip()
    if not reply_id and isinstance(item.get("source"), dict):
        rid = item["source"].get("id") or item["source"].get("message_id")
        if rid is not None and str(rid).strip():
            reply_id = str(rid).strip()

    msg = item.get("message")
    raw_msg = str(item.get("raw_message") or "")
    text_parts: list[str] = []

    if isinstance(msg, list):
        for seg in msg:
            if not isinstance(seg, dict):
                continue
            seg_type = str(seg.get("type") or "")
            raw_data = seg.get("data")
            seg_data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
            if seg_type == "reply" and not reply_id:
                rid = seg_data.get("id") or seg_data.get("message_id")
                if rid is not None and str(rid).strip():
                    reply_id = str(rid).strip()
            elif seg_type == "text":
                text_parts.append(str(seg_data.get("text") or ""))
    elif isinstance(msg, str):
        m = _CQ_REPLY_RE.search(msg)
        if m and not reply_id:
            reply_id = m.group(1).strip()
        text_parts.append(_CQ_TAG_RE.sub("", msg))

    if not reply_id and raw_msg:
        m = _CQ_REPLY_RE.search(raw_msg)
        if m:
            reply_id = m.group(1).strip()

    plain_text = "".join(text_parts).strip()
    if not plain_text and raw_msg:
        plain_text = _CQ_TAG_RE.sub("", raw_msg).strip()

    return reply_id, plain_text


def _parse_registration_action(text: str) -> Optional[str]:
    """Return ``'approve'`` for 同意/Approve, ``'refuse'`` for 拒绝/Refuse, else ``None``."""
    cleaned = str(text or "").strip()
    if not cleaned:
        return None
    low = cleaned.lower()
    if cleaned == "同意" or low == "approve":
        return "approve"
    if cleaned == "拒绝" or low == "refuse":
        return "refuse"
    return None


def _extract_quoted_text(res_or_item: dict[str, Any]) -> str:
    """Extract plain text from a ``get_msg`` response or quoted source payload."""
    if not isinstance(res_or_item, dict):
        return ""
    data = (
        res_or_item.get("data")
        if isinstance(res_or_item.get("data"), dict)
        else res_or_item
    )
    msg = data.get("message")
    if isinstance(msg, list):
        return "".join(
            str(s.get("data", {}).get("text") or "")
            for s in msg
            if isinstance(s, dict)
            and s.get("type") == "text"
            and isinstance(s.get("data"), dict)
        ).strip()
    if isinstance(msg, str) and msg.strip():
        return _CQ_TAG_RE.sub("", msg).strip()
    raw = str(data.get("raw_message") or "").strip()
    return _CQ_TAG_RE.sub("", raw).strip()


async def handle_onebot_qr_login_event(
    event: dict[str, Any],
    db: Optional[AsyncSession] = None,
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    group_id: Optional[int] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> Optional[dict[str, Any]]:
    """Process a OneBot message from a bound QQ user containing a ``miniclassisland://qr-login/...`` link."""
    if not isinstance(event, dict):
        return None

    if db is None:
        async with AsyncSessionLocal() as session:
            return await handle_onebot_qr_login_event(
                event,
                session,
                base_url=base_url,
                token=token,
                group_id=group_id,
                client=client,
                onebot_caller=onebot_caller,
            )

    msg_id = str(event.get("message_id") or "").strip()
    if msg_id:
        with _lock:
            if msg_id in _processed_reply_msg_ids:
                return None

    sender_uin = ""
    if event.get("user_id") is not None:
        sender_uin = str(event["user_id"]).strip()
    elif (
        isinstance(event.get("sender"), dict)
        and event["sender"].get("user_id") is not None
    ):
        sender_uin = str(event["sender"]["user_id"]).strip()
    if not sender_uin:
        return None

    _, plain_text = _extract_reply_id_and_text(event)
    raw_msg = str(event.get("raw_message") or "")
    m = _QR_LOGIN_LINK_RE.search(plain_text) or _QR_LOGIN_LINK_RE.search(raw_msg)
    if not m:
        return None

    deeplink = f"miniclassisland://qr-login/{m.group(1).strip()}"

    binding = (
        await db.execute(
            select(CommunityBinding).where(CommunityBinding.qq_uin == sender_uin)
        )
    ).scalar_one_or_none()
    if not binding:
        return None

    user = (
        await db.execute(select(User).where(User.id == binding.user_id))
    ).scalar_one_or_none()
    if not user or user.role_code in ("pending", "banned") or not user.is_active:
        return None

    if msg_id:
        with _lock:
            _processed_reply_msg_ids.add(msg_id)

    from app.shared.security.auth import authorize_qr_login_challenge

    authorized = await authorize_qr_login_challenge(deeplink, user.id)
    target_group_id = int(
        group_id if group_id is not None else (binding.group_id or SNOWLUMA_QQ_GROUP_ID)
    )
    display = (user.display_name or "").strip() or user.username
    reply_msg = (
        f"已为您 ({display}) 确认扫码登录"
        if authorized
        else "登录链接无效或已过期，请刷新二维码后重试"
    )
    await _send_private_msg(
        sender_uin,
        target_group_id,
        reply_msg,
        base_url=base_url,
        token=token,
        client=client,
        onebot_caller=onebot_caller,
    )
    return {
        "handled": True,
        "action": "qr_login",
        "authorized": authorized,
        "user_id": user.id,
        "qq_uin": sender_uin,
        "message": reply_msg,
    }


async def handle_onebot_registration_reply_event(
    event: dict[str, Any],
    db: Optional[AsyncSession] = None,
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    group_id: Optional[int] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> Optional[dict[str, Any]]:
    """Process a single OneBot message event for Super Admin quote-reply registration approval/rejection."""
    if not isinstance(event, dict):
        return None

    if db is None:
        async with AsyncSessionLocal() as session:
            return await handle_onebot_registration_reply_event(
                event,
                session,
                base_url=base_url,
                token=token,
                group_id=group_id,
                client=client,
                onebot_caller=onebot_caller,
            )

    qr_handled = await handle_onebot_qr_login_event(
        event,
        db,
        base_url=base_url,
        token=token,
        group_id=group_id,
        client=client,
        onebot_caller=onebot_caller,
    )
    if qr_handled is not None:
        return qr_handled

    msg_id = str(event.get("message_id") or "").strip()
    if msg_id:
        with _lock:
            if msg_id in _processed_reply_msg_ids:
                return None

    sender_uin = ""
    if event.get("user_id") is not None:
        sender_uin = str(event["user_id"]).strip()
    elif (
        isinstance(event.get("sender"), dict)
        and event["sender"].get("user_id") is not None
    ):
        sender_uin = str(event["sender"]["user_id"]).strip()

    if sender_uin:
        sa_uins = await get_superadmin_qq_uins(db)
        if sender_uin not in sa_uins:
            return None

    reply_id, plain_text = _extract_reply_id_and_text(event)
    if not reply_id:
        return None

    action = _parse_registration_action(plain_text)
    if not action:
        return None

    target_user_id = await get_registration_user_for_msg(reply_id)
    if not target_user_id:
        quoted_text = ""
        if isinstance(event.get("reply"), dict):
            quoted_text = _extract_quoted_text(event["reply"])
        elif isinstance(event.get("source"), dict):
            quoted_text = _extract_quoted_text(event["source"])
        if not quoted_text:
            try:
                msg_res = await _call_onebot(
                    "get_msg",
                    {
                        "message_id": (
                            int(reply_id)
                            if reply_id.lstrip("-").isdigit()
                            else reply_id
                        )
                    },
                    base_url=base_url,
                    token=token,
                    client=client,
                    onebot_caller=onebot_caller,
                )
                quoted_text = _extract_quoted_text(msg_res)
            except Exception:
                quoted_text = ""
        if quoted_text:
            m = _REG_MSG_PARSE_RE.match(quoted_text.strip())
            if m:
                uname, uemail = m.group(1).strip(), m.group(2).strip()
                u_row = (
                    await db.execute(
                        select(User).where(
                            User.username == uname,
                            User.email == uemail,
                        )
                    )
                ).scalar_one_or_none()
                if u_row:
                    target_user_id = u_row.id

    if not target_user_id:
        return None

    if msg_id:
        with _lock:
            _processed_reply_msg_ids.add(msg_id)

    from app.shared.services.user import approve_user, reject_user

    if action == "approve":
        approved_user = await approve_user(
            target_user_id,
            db,
            base_url=base_url,
            token=token,
            group_id=group_id,
            client=client,
            onebot_caller=onebot_caller,
        )
        return {
            "handled": approved_user is not None,
            "action": "approve",
            "user_id": target_user_id,
            "reply_id": reply_id,
        }

    rejected_ok = await reject_user(target_user_id, db)
    return {
        "handled": rejected_ok,
        "action": "refuse",
        "user_id": target_user_id,
        "reply_id": reply_id,
    }


async def poll_snowluma_superadmin_replies_once(
    db: Optional[AsyncSession] = None,
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    group_id: Optional[int] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> list[dict[str, Any]]:
    """Poll SnowLuma private message history for Super Admin quote-reply registration commands."""
    if db is None:
        async with AsyncSessionLocal() as session:
            return await poll_snowluma_superadmin_replies_once(
                session,
                base_url=base_url,
                token=token,
                group_id=group_id,
                client=client,
                onebot_caller=onebot_caller,
            )

    auth_token = token if token is not None else SNOWLUMA_ONEBOT_TOKEN
    if not auth_token and client is None and base_url is None and onebot_caller is None:
        return []

    sa_uins = await get_superadmin_qq_uins(db)
    bound_rows = (
        (
            await db.execute(
                select(CommunityBinding.qq_uin)
                .join(User, User.id == CommunityBinding.user_id)
                .where(
                    User.role_code != "banned",
                    User.role_code != "pending",
                    User.is_active.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
    poll_uins: list[str] = []
    seen_uins: set[str] = set()
    for raw_u in list(sa_uins) + list(bound_rows):
        u_str = str(raw_u or "").strip()
        if u_str and u_str not in seen_uins:
            seen_uins.add(u_str)
            poll_uins.append(u_str)
    if not poll_uins:
        return []

    results: list[dict[str, Any]] = []
    for uin in poll_uins:
        try:
            res = await _call_onebot(
                "get_friend_msg_history",
                {"user_id": int(uin), "count": 20},
                base_url=base_url,
                token=token,
                client=client,
                onebot_caller=onebot_caller,
            )
        except Exception:
            continue
        if res.get("status") != "ok" or res.get("retcode", 0) != 0:
            continue
        data = res.get("data")
        messages: list[Any] = []
        if isinstance(data, dict) and isinstance(data.get("messages"), list):
            messages = data["messages"]
        elif isinstance(data, list):
            messages = data
        for item in messages:
            if not isinstance(item, dict):
                continue
            item_with_sender = dict(item)
            if item_with_sender.get("user_id") is None:
                item_with_sender["user_id"] = int(uin)
            handled = await handle_onebot_registration_reply_event(
                item_with_sender,
                db,
                base_url=base_url,
                token=token,
                group_id=group_id,
                client=client,
                onebot_caller=onebot_caller,
            )
            if handled and handled.get("handled"):
                results.append(handled)
    return results


async def process_pending_group_requests(
    db: AsyncSession,
    *,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    group_id: Optional[int] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> int:
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


def _get_lifecycle_state_file() -> Path:
    """Return path to the local lifecycle state file."""
    return CONFIG_DIR / "lifecycle_state.json"


def _read_local_lifecycle_state() -> dict[str, Any]:
    """Read local lifecycle state JSON if present."""
    path = _get_lifecycle_state_file()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_local_lifecycle_state(data: dict[str, Any]) -> None:
    """Write local lifecycle state JSON."""
    path = _get_lifecycle_state_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def mark_pending_restart() -> None:
    """Mark that a service restart has been explicitly requested (e.g. via CLI)."""
    global _memory_pending_restart
    now = time.time()
    with _lock:
        _memory_pending_restart = now
    state = _read_local_lifecycle_state()
    state["pending_restart_ts"] = now
    _write_local_lifecycle_state(state)


def _consume_pending_restart() -> bool:
    """Return True and clear pending restart marker if set within the last 120 seconds."""
    global _memory_pending_restart
    now = time.time()
    matched = False
    with _lock:
        if _memory_pending_restart and (now - _memory_pending_restart) < 120:
            matched = True
        _memory_pending_restart = 0.0
    state = _read_local_lifecycle_state()
    ts = float(state.pop("pending_restart_ts", 0.0) or 0.0)
    if ts and (now - ts) < 120:
        matched = True
        _write_local_lifecycle_state(state)
    return matched


def detect_is_systemd_restart() -> bool:
    """Detect whether the current shutdown is triggered by ``systemctl restart`` or ``miniclassisland sys restart``."""
    if _consume_pending_restart():
        return True
    if shutil.which("systemctl"):
        try:
            res = subprocess.run(
                ["systemctl", "list-jobs", "--no-legend"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if res.returncode == 0 and res.stdout:
                for line in res.stdout.splitlines():
                    low = line.lower()
                    if "miniclassisland-backend" in low and "restart" in low:
                        return True
        except Exception:
            pass
    return False


async def _set_lifecycle_mode(mode: str) -> None:
    """Persist the shutdown lifecycle mode (``'restart'`` or ``'stop'``) for the next startup."""
    global _memory_lifecycle_mode
    with _lock:
        _memory_lifecycle_mode = mode
    state = _read_local_lifecycle_state()
    if mode:
        state["mode"] = mode
    else:
        state.pop("mode", None)
    _write_local_lifecycle_state(state)
    try:
        r = get_redis(REDIS_DB_AUTH)
        if mode:
            await r.set(_REDIS_LIFECYCLE_MODE_KEY, mode, ex=86400 * 7)
        else:
            await r.delete(_REDIS_LIFECYCLE_MODE_KEY)
    except Exception:
        pass


async def _pop_lifecycle_mode() -> str:
    """Read and clear the persisted shutdown lifecycle mode."""
    global _memory_lifecycle_mode
    mode = ""
    with _lock:
        if _memory_lifecycle_mode:
            mode = _memory_lifecycle_mode
            _memory_lifecycle_mode = ""
    state = _read_local_lifecycle_state()
    file_mode = str(state.pop("mode", "") or "").strip()
    if file_mode:
        if not mode:
            mode = file_mode
        _write_local_lifecycle_state(state)
    try:
        r = get_redis(REDIS_DB_AUTH)
        redis_mode = await r.get(_REDIS_LIFECYCLE_MODE_KEY)
        if redis_mode:
            if not mode:
                mode = str(redis_mode).strip()
            await r.delete(_REDIS_LIFECYCLE_MODE_KEY)
    except Exception:
        pass
    return mode


async def notify_service_shutdown(
    *,
    is_restart: Optional[bool] = None,
    group_id: Optional[int] = None,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> bool:
    """Send group notification on backend restart or maintenance shutdown and record mode for recovery."""
    restarting = is_restart if is_restart is not None else detect_is_systemd_restart()
    mode = "restart" if restarting else "stop"
    await _set_lifecycle_mode(mode)
    msg = MSG_RESTARTING if restarting else MSG_SHUTDOWN_MAINTENANCE
    return await send_group_msg(
        msg,
        group_id=group_id,
        base_url=base_url,
        token=token,
        client=client,
        onebot_caller=onebot_caller,
    )


async def notify_service_startup_recovery(
    *,
    group_id: Optional[int] = None,
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    onebot_caller: Optional[OneBotCaller] = None,
) -> Optional[str]:
    """Send group recovery notification on startup if recovering from a previous restart or shutdown."""
    mode = await _pop_lifecycle_mode()
    if mode == "restart":
        msg = MSG_RESTART_RECOVERED
    elif mode == "stop":
        msg = MSG_SHUTDOWN_RECOVERED
    else:
        return None
    await send_group_msg(
        msg,
        group_id=group_id,
        base_url=base_url,
        token=token,
        client=client,
        onebot_caller=onebot_caller,
    )
    return msg


async def _snowluma_poll_loop() -> None:
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
                await poll_snowluma_superadmin_replies_once(db)
                await sync_group_member_bindings(db)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning(
                "[QQ群控] 轮询周期异常 (%s): %s",
                type(exc).__name__,
                str(exc) or repr(exc),
            )
        await asyncio.sleep(interval)


def start_snowluma_poller() -> Optional[asyncio.Task]:
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


async def stop_snowluma_poller() -> None:
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
