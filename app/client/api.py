import logging
import time
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.shared.db.session import get_db
from app.shared.db.models import ClientProfile, Account, PreRegisteredClient
from app.shared.schemas.schemas import ClientManifest
from app.shared.utils.logging import get_client_ip_from_request
from app.shared.utils.tenant import get_tenant_id
from app.shared.utils.config import BASE_DOMAIN
from app.shared.security.auth import create_token

router = APIRouter()
logger = logging.getLogger(__name__)

# 已注册的合法资源类型
VALID_RESOURCES = [
    "ClassPlan",
    "TimeLayout",
    "Subjects",
    "Policy",
    "DefaultSettings",
    "Components",
    "Credentials",
]


@router.get("/v1/client/{client_uid}/manifest", response_model=ClientManifest, tags=["Client"])
async def get_client_manifest(
    request: Request, client_uid: str, db: AsyncSession = Depends(get_db)
):
    """为请求的 UID 构建完整的 Manifest JSON 数据。"""
    slug = getattr(request.state, "tenant_slug", "Unknown")
    client_ip = get_client_ip_from_request(request)
    short_uid = (
        f"{client_uid[:8]}...{client_uid[-5:]}" if len(client_uid) > 13 else client_uid
    )
    logger.info(
        "[%s][%s][%s] Client API 详细信息: 请求 Manifest", client_ip, slug, short_uid
    )

    stmt = select(ClientProfile).where(ClientProfile.client_id == client_uid)
    result = await db.execute(stmt)
    p = result.scalar_one_or_none() or ClientProfile()

    # 若配置档案不完整则使用默认值
    cp = p.class_plan or "default_classplan"
    tl = p.time_layout or "default_timelayout"
    sub = getattr(p, "subjects", None) or "default"
    ds = getattr(p, "default_settings", None) or "default"
    pol = getattr(p, "policy", None) or "default"
    comp = getattr(p, "components", None) or "default"
    cred = getattr(p, "credentials", None) or "default"
    cur = int(time.time())

    return _build_manifest(request, cp, tl, sub, ds, pol, comp, cred, cur)


def _build_manifest(request: Request, cp, tl, sub, ds, pol, comp, cred, ver):
    """组装各资源源的 Manifest 结构体。"""

    def _src(rt, n):
        # 使用 request.url_for 生成完整的绝对 URL，并附带 name 参数
        url = request.url_for("get_client_resource", resource_type=rt)
        full_url = str(url.include_query_params(name=n))
        return {"Value": full_url, "Version": ver}

    return ClientManifest(
        ClassPlanSource=_src("ClassPlan", cp),
        TimeLayoutSource=_src("TimeLayout", tl),
        SubjectsSource=_src("Subjects", sub),
        DefaultSettingsSource=_src("DefaultSettings", ds),
        PolicySource=_src("Policy", pol),
        ComponentsSource=_src("Components", comp),
        CredentialSource=_src("Credentials", cred),
        ServerKind=1,
        OrganizationName="MINIClassIsland Server",
        CoreVersion="2.0.0.0",
    )


@router.get("/v1/client/{resource_type}", tags=["Client"])
async def get_client_resource(resource_type: str, name: str, request: Request):
    """根据协议规则重定向到令牌保护的下载端点。"""
    if resource_type not in VALID_RESOURCES:
        raise HTTPException(status_code=400, detail="Invalid resource")

    tenant_id = get_tenant_id()
    client_ip = get_client_ip_from_request(request)

    token = await create_token(tenant_id, resource_type, name, client_ip=client_ip)
    return RedirectResponse(url=f"/get?token={token}", status_code=302)


@router.get("/v1/management-config", tags=["Guide"])
async def get_config(
    class_identity: str = "",
    db: AsyncSession = Depends(get_db),
):
    """根据子域名返回 ManagementPreset.json。

    若传入 class_identity 且匹配到预注册客户端，
    额外返回 PreRegisteredLabel 字段。
    """
    tenant_id = get_tenant_id()
    stmt = select(Account).where(Account.id == tenant_id)
    account = (await db.execute(stmt)).scalar_one_or_none()
    slug = account.slug if account else "unknown"

    # 尝试匹配预注册客户端
    label = ""
    if class_identity and account:
        pre_reg = (
            await db.execute(
                select(PreRegisteredClient).where(
                    PreRegisteredClient.account_id == account.id,
                    PreRegisteredClient.class_identity == class_identity,
                )
            )
        ).scalar_one_or_none()
        if pre_reg:
            label = pre_reg.label

    return {
        "IsManagementEnabled": True,
        "ManagementServerKind": 1,
        "ManagementServer": f"https://{slug}.{BASE_DOMAIN}",
        "ManagementServerGrpc": f"https://{slug}.{BASE_DOMAIN}",
        "ClassIdentity": class_identity,
        "PreRegisteredLabel": label,
        "ManifestUrlTemplate": "",
    }
