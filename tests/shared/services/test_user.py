"""test_user.py"""

import pytest
from app.shared.services import user as user_service
from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import ReservedName, Account


@pytest.mark.asyncio
async def test_slug_and_name_reservations():
    """Test slug/username/account_id format validation and reserved name lookup."""
    assert user_service.validate_slug_format("my-school") is True
    assert user_service.validate_slug_format("INVALID_SLUG_FORMAT") is False

    assert user_service.validate_account_id_format("school_2026-01") is True
    assert user_service.validate_account_id_format("list") is False
    assert user_service.validate_account_id_format("ab") is False

    assert user_service.validate_username_format("teacher_1") is True
    assert user_service.validate_username_format("INVALID USERNAME") is False

    async with AsyncSessionLocal() as db:
        db.add(ReservedName(name="reserved_word"))
        await db.commit()

        assert await user_service.is_name_reserved("reserved_word", db) is True
        assert await user_service.is_name_reserved("normal_word", db) is False


@pytest.mark.asyncio
async def test_roles_initialization_and_custom_roles():
    """Test system role initialization."""
    async with AsyncSessionLocal() as db:
        await user_service.ensure_system_roles(db)
        await user_service.ensure_system_roles(db)


@pytest.mark.asyncio
async def test_user_and_account_services():
    """Test user registration, login branches, approval, account creation, and slug updates."""
    async with AsyncSessionLocal() as db:
        # 1. Register user with explicit username and auto-generated username
        owner = await user_service.register_user(
            email="alpha@school.com",
            password="AlphaAdmin123!",
            display_name="Alpha Admin",
            db=db,
            username="alpha_admin",
        )
        assert owner.username == "alpha_admin"

        auto_u = await user_service.register_user(
            email="auto@school.com",
            password="AutoPassword123!",
            display_name="Auto User",
            db=db,
            username=None,
        )
        assert auto_u.username.startswith("user_")

        # Duplicate email & duplicate username
        with pytest.raises(ValueError, match="Email is already registered"):
            await user_service.register_user(
                email="alpha@school.com",
                password="AnotherPassword1!",
                display_name="Dup",
                db=db,
            )
        with pytest.raises(ValueError, match="Username already exists"):
            await user_service.register_user(
                email="unique@school.com",
                password="AnotherPassword1!",
                display_name="Dup U",
                db=db,
                username="alpha_admin",
            )

        with pytest.raises(ValueError, match="Username must be 3-64"):
            await user_service.register_user(
                email="badfmt@school.com",
                password="AnotherPassword1!",
                display_name="Bad Fmt",
                db=db,
                username="bad!username",
            )

        db.add(ReservedName(name="reserved_uname"))
        await db.commit()
        with pytest.raises(ValueError, match="Username is reserved by system"):
            await user_service.register_user(
                email="resuname@school.com",
                password="AnotherPassword1!",
                display_name="Res U",
                db=db,
                username="reserved_uname",
            )

        # 2. Register user and test login error branches (pending, banned, deactivated, 2fa)
        new_user = await user_service.register_user(
            email="beta@school.com",
            password="BetaPassword123!",
            display_name="Beta Teacher",
            db=db,
            username="beta_teacher",
        )

        with pytest.raises(ValueError, match="Account is not active yet"):
            await user_service.login_user("beta@school.com", "BetaPassword123!", db)

        new_user.role_code = "banned"
        await db.commit()
        with pytest.raises(ValueError, match="Account has been banned"):
            await user_service.login_user("beta@school.com", "BetaPassword123!", db)

        new_user.role_code = "normal"
        new_user.is_active = False
        await db.commit()
        with pytest.raises(ValueError, match="Account has been deactivated"):
            await user_service.login_user("beta@school.com", "BetaPassword123!", db)

        # Reset back to pending for approval flow
        new_user.role_code = "pending"
        await db.commit()

        with pytest.raises(ValueError, match="Incorrect email or password"):
            await user_service.login_user("non_existent@school.com", "password", db)

        # Pre-create an account with slug 'beta-teacher' to test slug collision in _create_default_account
        await user_service.create_account(
            name="Pre Existing", user_id="", db=db, slug="beta-teacher"
        )

        # 3. Approval & Rejection
        pending = await user_service.list_pending_users(db)
        assert any(p.username == "beta_teacher" for p in pending)

        approved_user = await user_service.approve_user(new_user.id, db)
        assert approved_user is not None
        assert approved_user.is_active is True

        assert await user_service.approve_user("invalid-uuid", db) is None

        temp_user = await user_service.register_user(
            email="temp@school.com",
            password="TempPassword123!",
            display_name="Temp User",
            db=db,
            username="temp_user",
        )
        assert await user_service.reject_user(temp_user.id, db) is True
        assert await user_service.reject_user("invalid-uuid", db) is False

        # 4. Login active user & 2FA user
        token, logged_in, need_2fa = await user_service.login_user(
            "beta@school.com", "BetaPassword123!", db
        )
        assert logged_in.id == new_user.id
        assert token is not None
        assert need_2fa is False

        new_user.totp_enabled = True
        await db.commit()
        token_2fa, _, need_2fa2 = await user_service.login_user(
            "beta@school.com", "BetaPassword123!", db
        )
        assert token_2fa is None
        assert need_2fa2 is True

        # 5. Account creation (auto slug, custom slug, invalid slug, duplicate slug)
        acc_auto = await user_service.create_account(
            name="Auto Slug School", user_id=owner.id, db=db, slug=None
        )
        assert acc_auto.slug.startswith("org-")
        assert acc_auto.registration_mode == "pairing"

        acc = await user_service.create_account(
            name="Alpha School",
            user_id=owner.id,
            db=db,
            slug="alpha-school",
        )
        assert acc.slug == "alpha-school"
        assert acc.registration_mode == "pairing"

        with pytest.raises(ValueError, match="Slug format invalid"):
            await user_service.create_account(
                name="Bad", user_id=owner.id, db=db, slug="BAD_SLUG!"
            )

        with pytest.raises(ValueError, match="Slug is already taken"):
            await user_service.create_account(
                name="Dup", user_id=owner.id, db=db, slug="alpha-school"
            )

        db.add(ReservedName(name="reserved-create-slug"))
        await db.commit()
        with pytest.raises(ValueError, match="Slug is reserved by system"):
            await user_service.create_account(
                name="Res", user_id=owner.id, db=db, slug="reserved-create-slug"
            )

        # 6. Update account slug branches
        with pytest.raises(ValueError, match="Slug format invalid"):
            await user_service.update_account_slug(acc.id, "BAD_SLUG!", owner.id, db)

        with pytest.raises(ValueError, match="Slug is already taken"):
            await user_service.update_account_slug(acc.id, "beta-teacher", owner.id, db)

        await user_service.update_account_slug(acc.id, "alpha-school-new", owner.id, db)
        acc_updated = await db.get(Account, acc.id)
        assert acc_updated is not None and acc_updated.slug == "alpha-school-new"

        with pytest.raises(PermissionError):
            await user_service.update_account_slug(
                acc.id, "alpha-school-fail", new_user.id, db
            )

        # Superadmin user can update slug even without AccountMember row
        sa_u = await user_service.register_user(
            email="sa_slug@school.com",
            password="SaPassword123!",
            display_name="SA Slug",
            db=db,
            username="sa_slug_user",
            role_code="superadmin",
            is_active=True,
        )
        await user_service.update_account_slug(
            acc.id, "alpha-school-by-sa", sa_u.id, db
        )
        acc_by_sa = await db.get(Account, acc.id)
        assert acc_by_sa is not None and acc_by_sa.slug == "alpha-school-by-sa"

        # Test update_account_info branches (name, new_id, slug reserved, registration_mode, is_active)
        db.add(ReservedName(name="reserved-acct-name"))
        await db.commit()

        with pytest.raises(ValueError, match="Account name cannot be empty"):
            await user_service.update_account_info(acc.id, owner.id, db, name="   ")

        with pytest.raises(ValueError, match="Slug is reserved by system"):
            await user_service.update_account_info(
                acc.id, owner.id, db, slug="reserved-acct-name"
            )

        with pytest.raises(ValueError, match="Account ID format invalid"):
            await user_service.update_account_info(acc.id, owner.id, db, new_id="list")

        with pytest.raises(ValueError, match="Account ID is reserved by system"):
            await user_service.update_account_info(
                acc.id, owner.id, db, new_id="reserved-acct-name"
            )

        with pytest.raises(ValueError, match="Account ID is already taken"):
            await user_service.update_account_info(
                acc.id, owner.id, db, new_id=acc_auto.id
            )

        with pytest.raises(ValueError, match="Invalid registration mode"):
            await user_service.update_account_info(
                acc.id, owner.id, db, registration_mode="invalid_mode"
            )

        updated_acct = await user_service.update_account_info(
            acc.id,
            owner.id,
            db,
            new_id="alpha-custom-id-2026",
            name="Alpha Custom School",
            is_active=True,
            registration_mode="pairing",
        )
        assert updated_acct is not None
        assert updated_acct.id == "alpha-custom-id-2026"
        assert updated_acct.name == "Alpha Custom School"
        assert updated_acct.registration_mode == "pairing"

        # Non-owner admin cannot change new_id or deactivate account (lines 409, 448)
        from app.shared.db.models import AccountMember
        from datetime import datetime, timezone
        from unittest.mock import AsyncMock, MagicMock, patch

        db.add(
            AccountMember(
                id="mem-admin-only",
                user_id=new_user.id,
                account_id="alpha-custom-id-2026",
                role_in_account="admin",
                joined_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()
        with pytest.raises(
            PermissionError,
            match="Only account owner or Super Admin can change Account ID",
        ):
            await user_service.update_account_info(
                "alpha-custom-id-2026",
                new_user.id,
                db,
                new_id="another-id-2026",
            )
        with pytest.raises(
            PermissionError,
            match="Only account owner or Super Admin can deactivate account",
        ):
            await user_service.update_account_info(
                "alpha-custom-id-2026",
                new_user.id,
                db,
                is_active=False,
            )

        # Test disconnect_account_clients when sm and servicer are active (lines 488, 491)
        mock_sm = MagicMock()
        mock_sm.get_all_clients_status = AsyncMock(return_value=[{"uid": "online-c1"}])
        mock_sm.set_client_offline = AsyncMock()
        mock_srv = MagicMock()
        mock_srv.disconnect_client = AsyncMock()
        with (
            patch("app.shared.runtime.get_session_manager", return_value=mock_sm),
            patch("app.shared.runtime.get_command_servicer", return_value=mock_srv),
        ):
            await user_service.disconnect_account_clients("alpha-custom-id-2026", db)
        mock_srv.disconnect_client.assert_awaited_once_with(
            "alpha-custom-id-2026", "online-c1"
        )

        # When AccountMember exists for a deleted Account row -> returns None

        db.add(
            AccountMember(
                id="mem-ghost-acct",
                user_id=owner.id,
                account_id="ghost-acct-id",
                role_in_account="owner",
                joined_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()
        assert (
            await user_service.update_account_slug(
                "ghost-acct-id", "valid-ghost-slug", owner.id, db
            )
            is None
        )
