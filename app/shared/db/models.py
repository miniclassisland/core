"""MINI ClassIsland 数据库实体模型合并定义。

本文件整合了系统中所有的 SQLAlchemy 数据模型，避免零散文件，包含全局表与多租户表。
"""

import uuid
import secrets
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """CIMS 所有数据库模型的共有基类。"""
    pass


class User(Base):
    """用户身份与凭据记录。"""
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(512))
    display_name: Mapped[str] = mapped_column(String(128), default="")
    role_code: Mapped[str] = mapped_column(String(32), default="normal")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    totp_secret: Mapped[str | None] = mapped_column(
        String(64), nullable=True, default=None
    )
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    can_create_account: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CustomRole(Base):
    """角色分级记录（含系统内置与自定义）。"""
    __tablename__ = "custom_roles"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    code: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(64))
    priority: Mapped[int] = mapped_column(Integer, default=0)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False)


class Account(Base):
    """账户（组织/租户）身份与配置记录。"""
    __tablename__ = "accounts"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(128))
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    api_key: Mapped[str] = mapped_column(String(256))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AccountMember(Base):
    """用户在账户中的成员关系记录。"""
    __tablename__ = "account_members"
    __table_args__ = (
        UniqueConstraint("user_id", "account_id", name="uq_user_account"),
    )

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(String, index=True)
    account_id: Mapped[str] = mapped_column(String, index=True)
    role_in_account: Mapped[str] = mapped_column(String(32), default="member")
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PermissionDef(Base):
    """原子权限定义记录。"""
    __tablename__ = "permission_defs"

    code: Mapped[str] = mapped_column(String(64), primary_key=True)
    label: Mapped[str] = mapped_column(String(128))
    category: Mapped[str] = mapped_column(String(32), default="general")


class MemberPermission(Base):
    """成员粒度的权限覆盖记录。"""
    __tablename__ = "member_permissions"
    __table_args__ = (
        UniqueConstraint("member_id", "permission_code", name="uq_member_perm"),
    )

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    member_id: Mapped[str] = mapped_column(String, index=True)
    permission_code: Mapped[str] = mapped_column(String(64))
    granted: Mapped[bool] = mapped_column(Boolean, default=True)


class AccountQuota(Base):
    """账户级资源限额记录。"""
    __tablename__ = "account_quotas"
    __table_args__ = (
        UniqueConstraint("account_id", "quota_key", name="uq_acct_quota"),
    )

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    account_id: Mapped[str] = mapped_column(String, index=True)
    quota_key: Mapped[str] = mapped_column(String(64))
    max_value: Mapped[int] = mapped_column(Integer, default=-1)
    current_value: Mapped[int] = mapped_column(Integer, default=0)


class SystemConfig(Base):
    """系统级键值配置记录。"""
    __tablename__ = "system_config"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ReservedName(Base):
    """系统保留名称记录。"""
    __tablename__ = "reserved_names"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    reason: Mapped[str] = mapped_column(String(128), default="system")


class ResourceMixin:
    """资源存储表的模型 Mixin。"""

    name: Mapped[str] = mapped_column(String, primary_key=True)
    content: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CPFile(Base, ResourceMixin):
    """课程计划资源文件表。"""
    __tablename__ = "cp_files"


class TLFile(Base, ResourceMixin):
    """时间布局资源文件表。"""
    __tablename__ = "tl_files"


class SubFile(Base, ResourceMixin):
    """科目资源文件表。"""
    __tablename__ = "sub_files"


class PolicyFile(Base, ResourceMixin):
    """策略资源文件表。"""
    __tablename__ = "policy_files"


class SettingsFile(Base, ResourceMixin):
    """默认设置资源文件表。"""
    __tablename__ = "settings_files"


class ComponentsFile(Base, ResourceMixin):
    """组件资源文件表。"""
    __tablename__ = "components_files"


class CredentialsFile(Base, ResourceMixin):
    """凭据资源文件表。"""
    __tablename__ = "credentials_files"


class ClientRecord(Base):
    """已注册物理客户端设备的数据库记录。"""
    __tablename__ = "clients"

    uid: Mapped[str] = mapped_column(String, primary_key=True)
    client_id: Mapped[str] = mapped_column(String, default="")
    mac: Mapped[str] = mapped_column(String, default="")
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ClientProfile(Base):
    """客户端与特定资源文件之间的关联映射。"""
    __tablename__ = "client_profiles"

    client_id: Mapped[str] = mapped_column(String, primary_key=True)
    class_plan: Mapped[str] = mapped_column(String)
    time_layout: Mapped[str] = mapped_column(String)
    subjects: Mapped[str] = mapped_column(String)
    default_settings: Mapped[str] = mapped_column(String)
    policy: Mapped[str] = mapped_column(String)
    components: Mapped[str] = mapped_column(String, nullable=True)
    credentials: Mapped[str] = mapped_column(String, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    """客户端设备事件日志的持久化存储。"""
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_uid: Mapped[str] = mapped_column(String)
    event: Mapped[int] = mapped_column(Integer)
    payload: Mapped[str] = mapped_column(Text)
    timestamp_utc: Mapped[int] = mapped_column(Integer)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ConfigUploadRecord(Base):
    """已上传客户端配置数据的临时存储。"""
    __tablename__ = "config_uploads"

    request_guid: Mapped[str] = mapped_column(String, primary_key=True)
    client_uid: Mapped[str] = mapped_column(String)
    payload: Mapped[str] = mapped_column(Text)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PairingCode(Base):
    """设备注册配对码记录。"""
    __tablename__ = "pairing_codes"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    code: Mapped[str] = mapped_column(String(8), unique=True, index=True)
    tenant_id: Mapped[str] = mapped_column(String, index=True)
    client_uid: Mapped[str] = mapped_column(String, default="")
    client_id: Mapped[str] = mapped_column(String, default="")
    client_mac: Mapped[str] = mapped_column(String, default="")
    client_ip: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class PreRegisteredClient(Base):
    """预注册客户端记录。"""
    __tablename__ = "pre_registered_clients"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    account_id: Mapped[str] = mapped_column(String, index=True)
    label: Mapped[str] = mapped_column(String(128))
    class_identity: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Invitation(Base):
    """账户邀请码记录。"""
    __tablename__ = "invitations"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    account_id: Mapped[str] = mapped_column(String, index=True)
    inviter_user_id: Mapped[str] = mapped_column(String)
    code: Mapped[str] = mapped_column(
        String(32),
        unique=True,
        index=True,
        default=lambda: secrets.token_urlsafe(12)[:16],
    )
    role_in_account: Mapped[str] = mapped_column(String(32), default="member")
    max_uses: Mapped[int] = mapped_column(Integer, default=1)
    used_count: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RolePermission(Base):
    """角色与原子权限的关联记录。"""
    __tablename__ = "role_permissions"
    __table_args__ = (
        UniqueConstraint("role_code", "permission_code", name="uq_role_perm"),
    )

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    role_code: Mapped[str] = mapped_column(String(32), index=True)
    permission_code: Mapped[str] = mapped_column(String(64))
