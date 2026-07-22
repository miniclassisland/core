"""MINIClassIsland database entity models.

This file consolidates all SQLAlchemy data models in the system, including global tables and multi-tenant tables.
"""

import uuid
import secrets
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all MINIClassIsland database models."""
    pass


class User(Base):
    """User account entity."""
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
    """Role hierarchy record (system built-in and custom)."""
    __tablename__ = "custom_roles"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    code: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(64))
    priority: Mapped[int] = mapped_column(Integer, default=0)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False)


class Account(Base):
    """Account (Organization/Tenant) identity and settings record."""
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
    """User membership relation record in an Account."""
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
    """Atomic permission definition record."""
    __tablename__ = "permission_defs"

    code: Mapped[str] = mapped_column(String(64), primary_key=True)
    label: Mapped[str] = mapped_column(String(128))
    category: Mapped[str] = mapped_column(String(32), default="general")


class MemberPermission(Base):
    """Member-granularity permission override record."""
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
    """Account-level resource quota limit record."""
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
    """System-level key-value configuration record."""
    __tablename__ = "system_config"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ReservedName(Base):
    """System reserved name record."""
    __tablename__ = "reserved_names"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    reason: Mapped[str] = mapped_column(String(128), default="system")


class ResourceMixin:
    """Resource storage table model Mixin."""

    name: Mapped[str] = mapped_column(String, primary_key=True)
    content: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CPFile(Base, ResourceMixin):
    """Class plan resource file table."""
    __tablename__ = "cp_files"


class TLFile(Base, ResourceMixin):
    """Time layout resource file table."""
    __tablename__ = "tl_files"


class SubFile(Base, ResourceMixin):
    """Subjects resource file table."""
    __tablename__ = "sub_files"


class PolicyFile(Base, ResourceMixin):
    """Policy resource file table."""
    __tablename__ = "policy_files"


class SettingsFile(Base, ResourceMixin):
    """Default settings resource file table."""
    __tablename__ = "settings_files"


class ComponentsFile(Base, ResourceMixin):
    """Components resource file table."""
    __tablename__ = "components_files"


class CredentialsFile(Base, ResourceMixin):
    """Credentials resource file table."""
    __tablename__ = "credentials_files"


class ClientRecord(Base):
    """Registered physical client device database record."""
    __tablename__ = "clients"

    uid: Mapped[str] = mapped_column(String, primary_key=True)
    client_id: Mapped[str] = mapped_column(String, default="")
    mac: Mapped[str] = mapped_column(String, default="")
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ClientProfile(Base):
    """Mapping relation between client and specific resource files."""
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
    """Persistent storage for client device event logs."""
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_uid: Mapped[str] = mapped_column(String)
    event: Mapped[int] = mapped_column(Integer)
    payload: Mapped[str] = mapped_column(Text)
    timestamp_utc: Mapped[int] = mapped_column(Integer)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ConfigUploadRecord(Base):
    """Temporary storage for uploaded client configuration data."""
    __tablename__ = "config_uploads"

    request_guid: Mapped[str] = mapped_column(String, primary_key=True)
    client_uid: Mapped[str] = mapped_column(String)
    payload: Mapped[str] = mapped_column(Text)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PairingCode(Base):
    """Device registration pairing code record."""
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
    """Pre-registered client record."""
    __tablename__ = "pre_registered_clients"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    account_id: Mapped[str] = mapped_column(String, index=True)
    label: Mapped[str] = mapped_column(String(128))
    class_identity: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Invitation(Base):
    """Account invitation code record."""
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
    """Relation record between role and atomic permission."""
    __tablename__ = "role_permissions"
    __table_args__ = (
        UniqueConstraint("role_code", "permission_code", name="uq_role_perm"),
    )

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    role_code: Mapped[str] = mapped_column(String(32), index=True)
    permission_code: Mapped[str] = mapped_column(String(64))


# Resource type to database model mapping table
MODEL_MAP = {
    "ClassPlan": CPFile,
    "TimeLayout": TLFile,
    "Subjects": SubFile,
    "Policy": PolicyFile,
    "DefaultSettings": SettingsFile,
    "Components": ComponentsFile,
    "Credentials": CredentialsFile,
}

