import asyncio
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional
import typer
from sqlalchemy import select

from app.shared.db.session import AsyncSessionLocal
from app.shared.db.models import Account, AccountMember, User

account_app = typer.Typer(help="账户与租户管理")


@account_app.command("list")
def list_accounts():
    """列出系统所有存在的租户账户。"""
    async def _run():
        async with AsyncSessionLocal() as db:
            r = await db.execute(select(Account))
            rows = r.scalars().all()
            if not rows:
                print("没有找到账户记录")
                return
            for a in rows:
                print(f"  {a.slug} ({a.name}) [active={a.is_active}]")
    asyncio.run(_run())


@account_app.command("create")
def create_account_cmd(
    name: str = typer.Argument(..., help="账户名称"),
    slug: str = typer.Argument(..., help="租户唯一 Slug"),
):
    """创建新的租户账户。"""
    async def _run():
        async with AsyncSessionLocal() as db:
            db.add(
                Account(
                    id=str(uuid.uuid4()),
                    name=name,
                    slug=slug,
                    api_key=secrets.token_urlsafe(32),
                    is_active=True,
                    created_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()
            print(f"✅ 账户 {slug} 已创建")
    asyncio.run(_run())


@account_app.command("delete")
def delete_account_cmd(
    slug: str = typer.Argument(..., help="要删除账户的 Slug"),
):
    """删除指定的账户。"""
    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            if not acct:
                print(f"❌ 账户 {slug} 不存在")
                return
            await db.delete(acct)
            await db.commit()
            print(f"✅ 账户 {slug} 已删除")
    asyncio.run(_run())


@account_app.command("add-member")
def add_member_cmd(
    slug: str = typer.Argument(..., help="账户 Slug"),
    username: str = typer.Argument(..., help="要添加的用户名"),
    role: str = typer.Option("owner", help="成员角色 (owner / admin / member)"),
):
    """向指定租户账户添加成员。"""
    async def _run():
        async with AsyncSessionLocal() as db:
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not acct or not user:
                print("❌ 账户或用户不存在")
                return
            db.add(
                AccountMember(
                    id=str(uuid.uuid4()),
                    user_id=user.id,
                    account_id=acct.id,
                    role_in_account=role,
                    joined_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()
            print(f"✅ {username} 已添加到 {slug}")
    asyncio.run(_run())


@account_app.command("remove-member")
def remove_member_cmd(
    slug: str = typer.Argument(..., help="账户 Slug"),
    username: str = typer.Argument(..., help="要移除的用户名"),
):
    """从指定租户账户中移除成员。"""
    async def _run():
        async with AsyncSessionLocal() as db:
            from sqlalchemy import and_
            acct = (
                await db.execute(select(Account).where(Account.slug == slug))
            ).scalar_one_or_none()
            user = (
                await db.execute(select(User).where(User.username == username))
            ).scalar_one_or_none()
            if not acct or not user:
                print("❌ 账户或用户不存在")
                return
            m = (
                await db.execute(
                    select(AccountMember).where(
                        and_(
                            AccountMember.user_id == user.id,
                            AccountMember.account_id == acct.id,
                        )
                    )
                )
            ).scalar_one_or_none()
            if not m:
                print("❌ 成员关系不存在")
                return
            await db.delete(m)
            await db.commit()
            print(f"✅ {username} 已从 {slug} 移除")
    asyncio.run(_run())
