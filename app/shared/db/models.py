"""MINI ClassIsland database entity models.

This file consolidates all SQLAlchemy data models in the system, including global tables and multi-tenant tables.
"""

import uuid
import secrets
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _default_account_id() -> str:
    """Resolve current tenant account ID from context var or fallback to 'default'."""
    try:
        from app.shared.utils.tenant import tenant_ctx

        val = tenant_ctx.get()
        return val if val else "default"
    except LookupError:
        return "default"


class Base(DeclarativeBase):
    """Base class for all MINI ClassIsland database models."""

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
    registration_mode: Mapped[str] = mapped_column(String(32), default="open")
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
    """Resource storage table model Mixin (scoped per account_id and resource name)."""

    account_id: Mapped[str] = mapped_column(
        String(64), primary_key=True, index=True, default=_default_account_id
    )
    name: Mapped[str] = mapped_column(String(255), primary_key=True)
    content: Mapped[str] = mapped_column(Text, default="{}")
    version: Mapped[int] = mapped_column(Integer, default=1)
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


class ResourceHistory(Base):
    """Immutable historical version snapshots for tenant configuration resource files."""

    __tablename__ = "resource_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id: Mapped[str] = mapped_column(
        String(64), index=True, default=_default_account_id
    )
    resource_type: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[int] = mapped_column(Integer, index=True, default=1)
    content: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ClientRecord(Base):
    """Registered physical client device database record."""

    __tablename__ = "clients"

    uid: Mapped[str] = mapped_column(String(128), primary_key=True)
    account_id: Mapped[str] = mapped_column(
        String(64), index=True, default=_default_account_id
    )
    client_id: Mapped[str] = mapped_column(String(128), default="")
    display_name: Mapped[str] = mapped_column(String(128), default="")
    mac: Mapped[str] = mapped_column(String(64), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    is_disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )


class ClientProfile(Base):
    """Mapping relation between client (or account '__default__') and specific resource files."""

    __tablename__ = "client_profiles"

    account_id: Mapped[str] = mapped_column(
        String(64), primary_key=True, index=True, default=_default_account_id
    )
    client_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    class_plan: Mapped[str] = mapped_column(String(255), default="default")
    time_layout: Mapped[str] = mapped_column(String(255), default="default")
    subjects: Mapped[str] = mapped_column(String(255), default="default")
    default_settings: Mapped[str] = mapped_column(String(255), default="default")
    policy: Mapped[str] = mapped_column(String(255), default="default")
    components: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, default="default"
    )
    credentials: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, default="default"
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    """Persistent storage for client device event logs."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id: Mapped[str] = mapped_column(
        String(64), index=True, default=_default_account_id
    )
    client_uid: Mapped[str] = mapped_column(String(128), index=True)
    event: Mapped[int] = mapped_column(Integer)
    payload: Mapped[str] = mapped_column(Text, default="")
    decoded_json: Mapped[str] = mapped_column(Text, default="{}")
    timestamp_utc: Mapped[int] = mapped_column(Integer)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ConfigUploadRecord(Base):
    """Storage for uploaded client configuration snapshot data."""

    __tablename__ = "config_uploads"

    request_guid: Mapped[str] = mapped_column(String(128), primary_key=True)
    account_id: Mapped[str] = mapped_column(
        String(64), index=True, default=_default_account_id
    )
    client_uid: Mapped[str] = mapped_column(String(128), index=True)
    config_type: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="completed")
    payload: Mapped[str] = mapped_column(Text, default="")
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PairingCode(Base):
    """Device registration pairing code record."""

    __tablename__ = "pairing_codes"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    code: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="")
    client_uid: Mapped[str] = mapped_column(String(128), default="")
    client_id: Mapped[str] = mapped_column(String(128), default="")
    client_mac: Mapped[str] = mapped_column(String(64), default="")
    client_ip: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(32), default="pending")
    preset_profile_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class PreRegisteredClient(Base):
    """Pre-registered client record."""

    __tablename__ = "pre_registered_clients"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    account_id: Mapped[str] = mapped_column(String(64), index=True)
    label: Mapped[str] = mapped_column(String(128))
    class_identity: Mapped[str] = mapped_column(String(128), index=True)
    mac_address: Mapped[str] = mapped_column(String(64), default="")
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    preset_profile_json: Mapped[str] = mapped_column(Text, default="{}")
    bound_client_uid: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Invitation(Base):
    """Account invitation code record."""

    __tablename__ = "invitations"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: str(uuid.uuid4())
    )
    account_id: Mapped[str] = mapped_column(String(64), index=True)
    inviter_user_id: Mapped[str] = mapped_column(String(64))
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
