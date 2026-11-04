"""test_models.py"""

from app.shared.db import models


def test_models_exist():
    """确认模型元数据注册正确且基类一致。"""
    assert models.Base is not None
    assert models.User.__tablename__ == "users"
    assert models.Account.__tablename__ == "accounts"
    assert models.CustomRole.__tablename__ == "custom_roles"
    assert models.AccountMember.__tablename__ == "account_members"
    assert models.AccountQuota.__tablename__ == "account_quotas"
    assert models.SystemConfig.__tablename__ == "system_config"
    assert models.ReservedName.__tablename__ == "reserved_names"
    assert models.CPFile.__tablename__ == "cp_files"
    assert models.ClientRecord.__tablename__ == "clients"
    assert models.ClientProfile.__tablename__ == "client_profiles"
    assert models.AuditLog.__tablename__ == "audit_logs"
    assert models.ConfigUploadRecord.__tablename__ == "config_uploads"
    assert models.PairingCode.__tablename__ == "pairing_codes"
    assert models.PreRegisteredClient.__tablename__ == "pre_registered_clients"
    assert models.Invitation.__tablename__ == "invitations"
