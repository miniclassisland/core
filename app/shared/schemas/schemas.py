"""CIMS 所有共享的 Pydantic 数据输入输出验证 Schema 定义。

整合了原 legacy/app/api/schemas/ 下 20 个零散小文件，统一维护管理。
"""

import re
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

# 用户名与密码规则正则
_USERNAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{2,63}$")
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,62}[a-z0-9]$")
_PWD_UPPER = re.compile(r"[A-Z]")
_PWD_LOWER = re.compile(r"[a-z]")
_PWD_DIGIT = re.compile(r"[0-9]")

# 系统设置允许的 Key 白名单
ALLOWED_SETTINGS_KEYS = {
    "registration_open",
    "require_approval",
    "max_accounts_per_user",
    "default_role",
    "motd",
}


# ---- 1. 通用响应结构 ----

class StatusResponse(BaseModel):
    """通用状态响应。"""
    status: str = Field(max_length=32)
    message: str = Field(max_length=1024)


class MessageResponse(BaseModel):
    """通用消息指示响应。"""
    status: str = Field(default="success", max_length=32)
    message: str = Field(default="", max_length=1024)


class TokenResponse(BaseModel):
    """认证通过签发的 Session Token。"""
    token: str = Field(max_length=512)
    expires_in: int = 3600
    token_type: str = Field(default="Bearer", max_length=32)


# ---- 2. 用户相关模式 ----

class UserRegisterRequest(BaseModel):
    """用户自主注册请求结构。"""
    email: EmailStr = Field(..., description="注册邮箱")
    password: str = Field(..., min_length=12, max_length=128)
    username: Optional[str] = Field(None, max_length=64)
    display_name: str = Field("", max_length=128)

    @field_validator("password")
    @classmethod
    def _check_password(cls, v: str) -> str:
        if not _PWD_UPPER.search(v):
            raise ValueError("密码需包含至少一个大写字母")
        if not _PWD_LOWER.search(v):
            raise ValueError("密码需包含至少一个小写字母")
        if not _PWD_DIGIT.search(v):
            raise ValueError("密码需包含至少一个数字")
        return v

    @field_validator("username")
    @classmethod
    def _check_username(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _USERNAME_RE.match(v):
            raise ValueError("用户名需 3~64 位，字母开头，仅含字母数字下划线")
        return v


class UserLoginRequest(BaseModel):
    """用户登录请求。"""
    email: EmailStr = Field(..., description="登录邮箱")
    password: str = Field(..., max_length=128)


class UserOut(BaseModel):
    """用户信息输出载荷。"""
    id: str
    username: str
    email: str
    display_name: str
    role_code: str
    is_active: bool
    can_create_account: bool = False
    created_at: str


class UserUpdateRequest(BaseModel):
    """超级管理员更新用户信息请求。"""
    display_name: Optional[str] = Field(None, max_length=128)
    role_code: Optional[str] = Field(None, max_length=32)
    is_active: Optional[bool] = None
    can_create_account: Optional[bool] = None


# ---- 3. 账户 (多租户) 相关模式 ----

class AccountCreate(BaseModel):
    """新建商户组织账户请求。"""
    name: str = Field(..., min_length=1, max_length=128)
    slug: Optional[str] = Field(None, min_length=3, max_length=64)

    @field_validator("slug")
    @classmethod
    def _check_slug(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _SLUG_RE.match(v):
            raise ValueError("Slug 需 3~64 位小写字母数字连字符，不以连字符开头/结尾")
        return v


class AccountUpdate(BaseModel):
    """更新组织账户配置请求。"""
    name: Optional[str] = Field(None, max_length=128)
    slug: Optional[str] = Field(None, min_length=3, max_length=64)
    is_active: Optional[bool] = None

    @field_validator("slug")
    @classmethod
    def _check_slug(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _SLUG_RE.match(v):
            raise ValueError("Slug 格式不合法")
        return v


class AccountOut(BaseModel):
    """商户账户配置输出载荷。"""
    id: str
    name: str
    slug: str
    api_key: str
    is_active: bool
    created_at: str


# ---- 4. 成员与权限隔离 (RBAC) ----

class AccessMemberOut(BaseModel):
    """账户内成员的配置与角色描述。"""
    id: str
    user_id: str
    account_id: str
    role_in_account: str
    joined_at: str


class AccessRoleUpdate(BaseModel):
    """修改指定账户中成员角色的请求。"""
    role_in_account: str = Field(
        ..., max_length=32, description="owner / admin / member / viewer"
    )


class PermissionGrantRequest(BaseModel):
    """对具体用户进行原子权限覆盖授予请求。"""
    member_id: str = Field(..., description="账户成员主键 ID")
    permission_code: str = Field(..., max_length=64)
    granted: bool = Field(True, description="True=授权，False=拒绝")


class PermissionRevokeRequest(BaseModel):
    """撤销某个特许原子权限的请求。"""
    member_id: str = Field(..., description="账户成员主键 ID")
    permission_code: str = Field(..., max_length=64)


class PermissionDefOut(BaseModel):
    """可用细粒度权限列表描述。"""
    code: str
    label: str
    category: str


# ---- 5. 批量操作定义 (Batch) ----

class BatchOpType(str, Enum):
    """批处理中支持的原子动作。"""
    create = "create"
    write = "write"
    update = "update"
    delete = "delete"


class BatchOperation(BaseModel):
    """单条批量更新载荷。"""
    action: BatchOpType
    resource_type: str = Field(..., max_length=64)
    name: str = Field(..., max_length=255)
    payload: Optional[Dict[str, Any]] = None


class BatchRequest(BaseModel):
    """打包多个原子操作的集合。"""
    operations: List[BatchOperation] = Field(..., max_length=100)


# 向后兼容支持
BatchOperationAction = BatchOpType


# ---- 6. 物理客户端与配置清单 ----

class ClientManifest(BaseModel):
    """ClassIsland 终端所需要接收的各类最新资源整合清单。"""
    ClassPlanSource: Dict[str, Any]
    TimeLayoutSource: Dict[str, Any]
    SubjectsSource: Dict[str, Any]
    DefaultSettingsSource: Dict[str, Any]
    PolicySource: Dict[str, Any]
    ComponentsSource: Dict[str, Any]
    CredentialSource: Dict[str, Any]
    ServerKind: int = 1
    OrganizationName: str = "CIMS Server"
    CoreVersion: str = "2.0.0.0"

    model_config = ConfigDict(populate_by_name=True)


# ---- 7. 邀请与预先注册 ----

class InvitationCreate(BaseModel):
    """生成商户账户激活码/邀请链接。"""
    role_in_account: str = Field("member", max_length=32)
    max_uses: int = Field(1, ge=1, le=100)
    expires_at: Optional[datetime] = None


class InvitationOut(BaseModel):
    """激活/邀请数据结构。"""
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


class PreRegCreate(BaseModel):
    """生成待审核预录入设备绑定标识请求。"""
    label: str = Field(..., max_length=128)
    class_identity: str = Field(..., max_length=64)


class PreRegOut(BaseModel):
    """预录入设备信息详情。"""
    id: str
    account_id: str
    label: str
    class_identity: str
    created_at: str


# ---- 8. 远程指令通知与设备配对 ----

class NotificationPayload(BaseModel):
    """广播投射通知设置。"""
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


class PairingCodeOut(BaseModel):
    """配对码详情实体输出。"""
    id: str
    code: str
    client_uid: str
    approved: bool
    used: bool
    created_at: str


# ---- 9. 租户配额与角色层级 ----

class QuotaSetRequest(BaseModel):
    """更新租户某项配额的最大上限。"""
    quota_key: str = Field(..., max_length=64)
    max_value: int = Field(..., ge=-1)


class QuotaOut(BaseModel):
    """租户配额信息载荷。"""
    id: str
    account_id: str
    quota_key: str
    max_value: int
    current_value: int


class RoleCreateRequest(BaseModel):
    """添加全新用户角色的级别定义请求。"""
    code: str = Field(..., min_length=2, max_length=32)
    label: str = Field(..., max_length=64)
    priority: int = Field(..., ge=-100, le=99)


class RoleOut(BaseModel):
    """角色定义。"""
    id: str
    code: str
    label: str
    priority: int
    is_system: bool


# ---- 10. 系统级设置与双因子认证 (2FA) ----

class SettingsUpdate(BaseModel):
    """修改核心全局配置的设置集。"""
    items: dict[str, str] = Field(..., description="只能更新白名单中的设置")

    @field_validator("items")
    @classmethod
    def _check_keys(cls, v: dict[str, str]) -> dict[str, str]:
        bad = set(v.keys()) - ALLOWED_SETTINGS_KEYS
        if bad:
            raise ValueError(f"不允许的配置项: {', '.join(bad)}")
        return v


class TotpEnableResponse(BaseModel):
    """2FA 开启时的回复，展示密钥与扫码的 URI 以及备份恢复码。"""
    secret: str
    uri: str
    recovery_codes: list[str]


class TotpConfirmRequest(BaseModel):
    """确认开通 TOTP 2FA 绑定验证请求。"""
    code: str


class TotpVerifyRequest(BaseModel):
    """多因子认证（输入二级密钥验证码）登录请求。"""
    temp_token: str
    code: str


class TotpDisableRequest(BaseModel):
    """管理员要求或自主关闭 2FA 认证。"""
    password: str


class TotpRecoverRequest(BaseModel):
    """通过恢复码充当 TOTP 丢失后的登录凭据。"""
    temp_token: str
    recovery_code: str


# ---- 11. 个人用户资料更新 ----

class EmailUpdate(BaseModel):
    """更改登录账号邮箱请求。"""
    email: EmailStr


class UsernameUpdate(BaseModel):
    """更改账号自定义用户名。"""
    username: str = Field(..., min_length=3, max_length=64)


class PasswordReset(BaseModel):
    """管理员强制重置用户登录密码请求。"""
    new_password: str = Field(..., min_length=12, max_length=128)


class PasswordChange(BaseModel):
    """登录后修改密码请求。"""
    old_password: str = Field(..., max_length=128)
    new_password: str = Field(..., min_length=12, max_length=128)


class SlugUpdate(BaseModel):
    """更新租户二级域前缀标识 Slug 的请求。"""
    slug: str = Field(..., min_length=3, max_length=64)
