"""MINI ClassIsland shared Pydantic schemas for input/output data validation."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from app.shared.literals import (
    ALLOWED_SETTINGS_KEYS as _ALLOWED_SETTINGS_KEYS,
    PWD_DIGIT,
    PWD_LOWER,
    PWD_UPPER,
    SCHEMA_SLUG_RE,
    SCHEMA_USERNAME_RE,
    TICKET_CATEGORIES,
    TICKET_PRIORITIES,
    TICKET_STATUSES,
)

# Username and password validation regex
_USERNAME_RE = SCHEMA_USERNAME_RE
_SLUG_RE = SCHEMA_SLUG_RE
_PWD_UPPER = PWD_UPPER
_PWD_LOWER = PWD_LOWER
_PWD_DIGIT = PWD_DIGIT

# System settings allowed keys whitelist
ALLOWED_SETTINGS_KEYS = _ALLOWED_SETTINGS_KEYS


# ---- 1. Generic Response Structures ----


class StatusResponse(BaseModel):
    """Generic status response."""

    status: str = Field(max_length=32)
    message: str = Field(max_length=1024)


class MessageResponse(BaseModel):
    """Generic message response."""

    status: str = Field(default="success", max_length=32)
    message: str = Field(default="", max_length=1024)


# ---- 2. User Related Schemas ----


class UserRegisterRequest(BaseModel):
    """User self-registration request schema."""

    email: EmailStr = Field(..., description="Registered email address")
    password: str = Field(..., min_length=12, max_length=128)
    username: Optional[str] = Field(default=None, max_length=64)
    display_name: str = Field(default="", max_length=128)
    role_code: Optional[str] = Field(default=None, max_length=32)
    can_create_account: Optional[bool] = None
    cf_turnstile_response: Optional[str] = Field(default=None, max_length=4096)

    @field_validator("password")
    @classmethod
    def _check_password(cls, v: str) -> str:
        if not _PWD_UPPER.search(v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not _PWD_LOWER.search(v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not _PWD_DIGIT.search(v):
            raise ValueError("Password must contain at least one digit")
        return v

    @field_validator("username")
    @classmethod
    def _check_username(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip().lower()
            if not _USERNAME_RE.match(v):
                raise ValueError(
                    "Username must be 3-64 lowercase alphanumeric characters and underscores"
                )
        return v


class UserLoginRequest(BaseModel):
    """User login request schema."""

    email: EmailStr = Field(..., description="Login email address")
    password: str = Field(..., max_length=128)
    cf_turnstile_response: Optional[str] = Field(default=None, max_length=4096)


class EmailAvailabilityRequest(BaseModel):
    """Email availability check request schema."""

    email: EmailStr = Field(..., description="Email address to check")
    cf_turnstile_response: Optional[str] = Field(default=None, max_length=4096)


class UserOut(BaseModel):
    """User profile output payload."""

    id: str
    username: str
    email: str
    display_name: str
    role_code: str
    is_active: bool
    totp_enabled: bool = False
    can_create_account: bool = False
    created_at: str


class UserUpdateRequest(BaseModel):
    """Super admin update user profile request."""

    username: Optional[str] = Field(None, max_length=64)
    email: Optional[EmailStr] = None
    display_name: Optional[str] = Field(None, max_length=128)
    role_code: Optional[str] = Field(None, max_length=32)
    is_active: Optional[bool] = None
    can_create_account: Optional[bool] = None
    totp_enabled: Optional[bool] = None


# ---- 3. Account (Multi-Tenant) Schemas ----


class AccountCreate(BaseModel):
    """Create tenant account request schema."""

    name: str = Field(..., min_length=1, max_length=128)
    slug: Optional[str] = Field(default=None, min_length=3, max_length=64)
    owner_user_id: Optional[str] = Field(default=None, max_length=64)

    @field_validator("slug")
    @classmethod
    def _check_slug(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _SLUG_RE.match(v):
            raise ValueError(
                "Slug must be 3-64 lowercase alphanumeric characters and hyphens, not starting or ending with a hyphen"
            )
        return v


class AccountUpdate(BaseModel):
    """Update tenant account request schema."""

    new_id: Optional[str] = Field(default=None, min_length=3, max_length=64)
    name: Optional[str] = Field(default=None, max_length=128)
    slug: Optional[str] = Field(default=None, min_length=3, max_length=64)
    is_active: Optional[bool] = None
    registration_mode: Optional[str] = Field(default=None, max_length=32)

    @field_validator("slug")
    @classmethod
    def _check_slug(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _SLUG_RE.match(v):
            raise ValueError("Slug format invalid")
        return v


class AccountIdUpdate(BaseModel):
    """Update tenant account ID request schema."""

    new_id: str = Field(..., min_length=3, max_length=64)


class AccountOut(BaseModel):
    """Tenant account output payload."""

    id: str
    name: str
    slug: str
    api_key: str
    is_active: bool
    registration_mode: str = "pairing"
    created_at: str


# ---- 4. Member & Role Access Schemas (RBAC) ----


class AccessMemberOut(BaseModel):
    """Account member configuration output payload."""

    id: str
    user_id: str
    account_id: str
    role_in_account: str
    joined_at: str
    username: str = ""
    display_name: str = ""
    email: str = ""


class AccessRoleUpdate(BaseModel):
    """Update member role within account request schema."""

    role_in_account: str = Field(
        ..., max_length=32, description="owner / admin / member / viewer"
    )


# ---- 5. Batch Operation Schemas ----


class BatchOpType(str, Enum):
    """Supported batch operation types."""

    create = "create"
    write = "write"
    update = "update"
    delete = "delete"


class BatchOperation(BaseModel):
    """Single batch operation payload."""

    action: BatchOpType
    resource_type: str = Field(..., max_length=64)
    name: str = Field(..., max_length=255)
    payload: Optional[Dict[str, Any]] = None


class BatchRequest(BaseModel):
    """Batch operation collection request."""

    operations: List[BatchOperation] = Field(..., max_length=100)
    target_account_id: Optional[str] = Field(default=None, max_length=64)


# ---- 6. Physical Client & Configuration Manifest ----


class ClientManifest(BaseModel):
    """Integrated resource manifest schema for ClassIsland client."""

    ClassPlanSource: Dict[str, Any]
    TimeLayoutSource: Dict[str, Any]
    SubjectsSource: Dict[str, Any]
    DefaultSettingsSource: Dict[str, Any]
    PolicySource: Dict[str, Any]
    ComponentsSource: Dict[str, Any]
    CredentialSource: Dict[str, Any]
    ServerKind: int = 1
    OrganizationName: str = "MINI ClassIsland Server"
    CoreVersion: str = "2.0.0.0"

    model_config = ConfigDict(populate_by_name=True)


# ---- 7. Invitation & Pre-Registration Schemas ----


class InvitationCreate(BaseModel):
    """Create account invitation link/code request schema."""

    role_in_account: str = Field("member", max_length=32)
    max_uses: int = Field(1, ge=1, le=100)
    expires_at: Optional[datetime] = None


class InvitationOut(BaseModel):
    """Invitation code output payload."""

    id: str
    account_id: str
    inviter_user_id: str
    code: str
    role_in_account: str
    max_uses: int
    used_count: int
    expires_at: Optional[str] = None
    is_active: bool
    created_at: str


class InvitationAcceptRequest(BaseModel):
    """Redeem invitation code request schema."""

    code: str = Field(..., min_length=1, max_length=64)


class PreRegCreate(BaseModel):
    """Create pre-registered client device request schema."""

    label: str = Field(..., max_length=128)
    class_identity: str = Field("", max_length=128)
    mac_address: Optional[str] = Field("", max_length=64)
    preset_profile: Optional[Dict[str, str]] = None


class PreRegBatchCreate(BaseModel):
    """Batch create pre-registered client devices request schema."""

    items: List[PreRegCreate] = Field(..., max_length=500)


class PreRegOut(BaseModel):
    """Pre-registered client device output payload."""

    id: str
    account_id: str
    label: str
    class_identity: str
    mac_address: str = ""
    is_enabled: bool = True
    preset_profile: Dict[str, str] = Field(default_factory=dict)
    bound_client_uid: str = ""
    created_at: str


# ---- 8. Remote Control Command Notification & Pairing ----


class NotificationPayload(BaseModel):
    """Desktop notification push payload."""

    MessageMask: str = Field(default="", max_length=4096)
    MessageContent: str = Field(default="", max_length=4096)
    OverlayIconLeft: int = Field(default=0, ge=0)
    OverlayIconRight: int = Field(default=0, ge=0)
    IsEmergency: bool = False
    IsSpeechEnabled: bool = False
    IsEffectEnabled: bool = False
    IsSoundEnabled: bool = False
    IsTopmost: bool = False
    DurationSeconds: float = Field(default=5.0, ge=0, le=3600)
    RepeatCounts: int = Field(default=1, ge=0, le=100)


class BroadcastNotificationPayload(NotificationPayload):
    """Broadcast or multi-target desktop notification payload."""

    target_uids: Optional[List[str]] = None
    client_uids: Optional[List[str]] = None


class PairingCodeOut(BaseModel):
    """Pairing code output payload."""

    id: str
    code: str
    client_uid: str
    client_id: str = ""
    client_mac: str = ""
    client_ip: str = ""
    status: str = "pending"
    approved: bool
    used: bool
    created_at: str


# ---- 9. Tenant Quota & Role Hierarchy ----


class QuotaSetRequest(BaseModel):
    """Set tenant quota limit request schema."""

    quota_key: str = Field(..., max_length=64)
    max_value: int = Field(..., ge=-1)


class QuotaOut(BaseModel):
    """Tenant quota output payload."""

    id: str
    account_id: str
    quota_key: str
    max_value: int
    current_value: int


# ---- 10. System Settings & 2FA Schemas ----


class SettingsUpdate(BaseModel):
    """Update global system settings request schema."""

    items: dict[str, str] = Field(
        ..., description="Only settings in the whitelist can be updated"
    )

    @field_validator("items")
    @classmethod
    def _check_keys(cls, v: dict[str, str]) -> dict[str, str]:
        bad = set(v.keys()) - ALLOWED_SETTINGS_KEYS
        if bad:
            raise ValueError(f"Disallowed settings keys: {', '.join(bad)}")
        return v


class TotpEnableResponse(BaseModel):
    """2FA enable response showing secret, QR URI, and recovery codes."""

    secret: str
    uri: str
    recovery_codes: list[str]


class TotpConfirmRequest(BaseModel):
    """Confirm 2FA binding request schema."""

    code: str


class TotpVerifyRequest(BaseModel):
    """2FA login verification request schema."""

    temp_token: str
    code: str


class TotpDisableRequest(BaseModel):
    """Disable 2FA request schema.

    Supports any of the following factor combinations:
    1. password + totp_code
    2. password + recovery_code
    3. totp_code + recovery_code
    4. recovery_code + second_recovery_code (or recovery_codes with >= 2 items)
    """

    password: Optional[str] = Field(default=None, max_length=128)
    totp_code: Optional[str] = Field(default=None, max_length=32)
    recovery_code: Optional[str] = Field(default=None, max_length=64)
    second_recovery_code: Optional[str] = Field(default=None, max_length=64)
    recovery_codes: Optional[List[str]] = Field(default=None, max_length=8)


class TotpRecoverRequest(BaseModel):
    """2FA emergency recovery code login request schema."""

    temp_token: str
    recovery_code: str


# ---- 11. Profile Update Schemas ----


class EmailUpdate(BaseModel):
    """Update email request schema."""

    email: EmailStr


class UsernameUpdate(BaseModel):
    """Update username request schema."""

    username: str = Field(..., min_length=3, max_length=64)


class DisplayNameUpdate(BaseModel):
    """Update display name request schema."""

    display_name: str = Field(..., min_length=1, max_length=128)


class PasswordReset(BaseModel):
    """Force password reset request schema."""

    new_password: str = Field(..., min_length=12, max_length=128)

    @field_validator("new_password")
    @classmethod
    def _check_new_password(cls, v: str) -> str:
        return UserRegisterRequest._check_password(v)


class PasswordChange(BaseModel):
    """Change password request schema."""

    old_password: str = Field(..., max_length=128)
    new_password: str = Field(..., min_length=12, max_length=128)

    @field_validator("new_password")
    @classmethod
    def _check_new_password(cls, v: str) -> str:
        return UserRegisterRequest._check_password(v)


class SlugUpdate(BaseModel):
    """Update tenant slug request schema."""

    slug: str = Field(..., min_length=3, max_length=64)


class AccountNameUpdate(BaseModel):
    """Update tenant account name request schema."""

    name: str = Field(..., min_length=1, max_length=128)
    registration_mode: Optional[str] = Field(default=None, max_length=32)


# ---- 11. Support Ticket Schemas ----


def _clean_ticket_text(value: str) -> str:
    """Trim user text and reject NUL/control bytes that break DB storage."""
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("不能为空")
    if any((ord(ch) < 32 and ch not in "\t\n\r") or ord(ch) == 127 for ch in cleaned):
        raise ValueError("包含非法控制字符")
    return cleaned


class TicketCreate(BaseModel):
    """Create a support ticket request schema."""

    subject: str = Field(..., min_length=1, max_length=200)
    content: str = Field(..., min_length=1, max_length=5000)
    category: str = Field(default="other", max_length=32)
    priority: str = Field(default="normal", max_length=16)

    @field_validator("subject", "content")
    @classmethod
    def _strip_required_text(cls, v: str) -> str:
        return _clean_ticket_text(v)

    @field_validator("category")
    @classmethod
    def _check_category(cls, v: str) -> str:
        value = v.strip().lower()
        if value not in TICKET_CATEGORIES:
            raise ValueError("无效的工单分类")
        return value

    @field_validator("priority")
    @classmethod
    def _check_priority(cls, v: str) -> str:
        value = v.strip().lower()
        if value not in TICKET_PRIORITIES:
            raise ValueError("无效的优先级")
        return value


class TicketReplyCreate(BaseModel):
    """Reply to a support ticket request schema."""

    content: str = Field(..., min_length=1, max_length=5000)

    @field_validator("content")
    @classmethod
    def _strip_reply(cls, v: str) -> str:
        return _clean_ticket_text(v)


class TicketAdminUpdate(BaseModel):
    """Super-admin update to a support ticket."""

    status: Optional[str] = Field(default=None, max_length=32)
    priority: Optional[str] = Field(default=None, max_length=16)

    @field_validator("status")
    @classmethod
    def _check_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        value = v.strip().lower()
        if value not in TICKET_STATUSES:
            raise ValueError("无效的工单状态")
        return value

    @field_validator("priority")
    @classmethod
    def _check_priority(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        value = v.strip().lower()
        if value not in TICKET_PRIORITIES:
            raise ValueError("无效的优先级")
        return value


class TicketMessageOut(BaseModel):
    """Serialized ticket reply message."""

    id: int
    author_id: str
    author_role: str
    content: str
    created_at: str


class TicketOut(BaseModel):
    """Serialized support ticket list item."""

    id: str
    user_id: str
    subject: str
    category: str
    priority: str
    status: str
    created_at: str
    updated_at: str
    last_reply_at: Optional[str] = None
    last_reply_by: str = ""
    admin_unread: bool = False
    user_unread: bool = False
    message_count: int = 0
    user: Optional[Dict[str, Any]] = None


class TicketListOut(BaseModel):
    """Paginated support ticket list."""

    total: int
    items: List[TicketOut]


class TicketDetailOut(TicketOut):
    """Support ticket with initial content and replies."""

    content: str
    messages: List[TicketMessageOut] = Field(default_factory=list)
