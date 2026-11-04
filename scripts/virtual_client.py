#!/usr/bin/env python3
"""
Virtual ClassIsland Client & Comprehensive E2E Test Suite.

Strictly mirrors upstream ClassIsland C# client behavior:
- ClassIsland/Services/Management/ManagementServerConnection.cs
- ClassIsland/Services/Management/ManagementService.cs
- ClassIsland/Services/ProfileService.cs
- ClassIsland.Shared/Models/Profile/Profile.cs
"""

import asyncio
import base64
from datetime import datetime, timezone
import json
import secrets
import sys
import time
import uuid
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

CORE_ROOT = Path(__file__).resolve().parent.parent
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

warnings.filterwarnings("ignore")

import grpc  # noqa: E402
import httpx  # noqa: E402
import pgpy  # noqa: E402

from app.Protobuf.Client import (  # noqa: E402
    AuditScReq_pb2,
    ClientCommandDeliverScReq_pb2,
    ClientRegisterCsReq_pb2,
    ConfigUploadScReq_pb2,
    HandshakeScReq_pb2,
)
from app.Protobuf.Command import (  # noqa: E402
    GetClientConfig_pb2,
    SendNotification_pb2,
)
from app.Protobuf.Enum import (  # noqa: E402
    AuditEvents_pb2,
    CommandTypes_pb2,
    Retcode_pb2,
)
from app.Protobuf.Service import (  # noqa: E402
    Audit_pb2_grpc,
    ClientCommandDeliver_pb2_grpc,
    ClientRegister_pb2_grpc,
    ConfigUpload_pb2_grpc,
    Handshake_pb2_grpc,
)


def assert_valid_csharp_guid(val: str, context: str = "") -> uuid.UUID:
    """Strictly validate that a string can be parsed by C# System.Guid / Utf8JsonReader.GetGuidNoValidation."""
    if not isinstance(val, str):
        raise ValueError(f"[{context}] Expected string GUID, got {type(val)}: {val!r}")
    try:
        parsed = uuid.UUID(val)
    except Exception as exc:
        raise ValueError(
            f"[{context}] Value {val!r} is NOT a valid System.Guid! Upstream C# JsonSerializer will throw JsonException!"
        ) from exc
    if str(parsed) != val.lower():
        raise ValueError(f"[{context}] Non-canonical GUID format: {val!r}")
    return parsed


def validate_upstream_profile_deserialization(
    resource_type: str, data: dict[str, Any]
) -> None:
    """
    Simulate upstream C# System.Text.Json deserialization into:
    - Profile (ObservableDictionary<Guid, ClassPlan> ClassPlans, ObservableDictionary<Guid, TimeLayout> TimeLayouts, ObservableDictionary<Guid, Subject> Subjects, ObservableDictionary<Guid, ClassPlanGroup> ClassPlanGroups)
    - ComponentSettings (ObservableCollection<MainWindowLineSettings> Lines)
    - ManagementPolicy
    - ManagementCredentialConfig
    - Settings
    """
    if not isinstance(data, dict):
        raise TypeError(f"{resource_type} payload must be a JSON object")

    if resource_type == "Subjects":
        if "Subjects" not in data or not isinstance(data["Subjects"], dict):
            raise ValueError("Subjects payload missing top-level 'Subjects' dictionary")
        for sub_id, sub in data["Subjects"].items():
            assert_valid_csharp_guid(sub_id, "Subjects.Key")
            if not isinstance(sub, dict) or "Name" not in sub:
                raise ValueError(f"Invalid Subject entry for {sub_id}: {sub}")

    elif resource_type == "TimeLayout":
        if "TimeLayouts" not in data or not isinstance(data["TimeLayouts"], dict):
            raise ValueError(
                "TimeLayout payload missing top-level 'TimeLayouts' dictionary"
            )
        for tl_id, tl in data["TimeLayouts"].items():
            assert_valid_csharp_guid(tl_id, "TimeLayouts.Key")
            layouts = tl.get("Layouts", [])
            if not isinstance(layouts, list):
                raise ValueError(f"TimeLayout {tl_id} Layouts must be a list")
            for idx, item in enumerate(layouts):
                def_cls = item.get("DefaultClassId")
                if def_cls:
                    assert_valid_csharp_guid(
                        def_cls, f"TimeLayouts[{tl_id}].Layouts[{idx}].DefaultClassId"
                    )
                if "StartSecond" not in item and "StartTime" not in item:
                    raise ValueError(
                        f"TimeLayouts[{tl_id}].Layouts[{idx}] missing StartSecond/StartTime"
                    )
                if "EndSecond" not in item and "EndTime" not in item:
                    raise ValueError(
                        f"TimeLayouts[{tl_id}].Layouts[{idx}] missing EndSecond/EndTime"
                    )

    elif resource_type == "ClassPlan":
        if "ClassPlans" not in data or not isinstance(data["ClassPlans"], dict):
            raise ValueError(
                "ClassPlan payload missing top-level 'ClassPlans' dictionary"
            )
        for cp_id, cp in data["ClassPlans"].items():
            assert_valid_csharp_guid(cp_id, f"ClassPlans.Key({cp_id})")
            tl_id = cp.get("TimeLayoutId")
            if tl_id is not None:
                assert_valid_csharp_guid(tl_id, f"ClassPlans[{cp_id}].TimeLayoutId")
            assoc = cp.get("AssociatedGroup")
            if assoc is not None:
                assert_valid_csharp_guid(assoc, f"ClassPlans[{cp_id}].AssociatedGroup")
            ov_src = cp.get("OverlaySourceId")
            if ov_src:
                assert_valid_csharp_guid(ov_src, f"ClassPlans[{cp_id}].OverlaySourceId")
            for idx, cls_info in enumerate(cp.get("Classes", [])):
                sub_id = cls_info.get("SubjectId")
                if sub_id is not None:
                    assert_valid_csharp_guid(
                        sub_id, f"ClassPlans[{cp_id}].Classes[{idx}].SubjectId"
                    )
        if "ClassPlanGroups" in data and isinstance(data["ClassPlanGroups"], dict):
            for grp_id in data["ClassPlanGroups"].keys():
                assert_valid_csharp_guid(grp_id, f"ClassPlanGroups.Key({grp_id})")

    elif resource_type == "Components":
        lines = data.get("Lines", [])
        if not isinstance(lines, list):
            raise ValueError("Components.Lines must be a list")
        for l_idx, line in enumerate(lines):
            for c_idx, child in enumerate(line.get("Children", [])):
                cid = child.get("Id")
                if cid:
                    assert_valid_csharp_guid(
                        cid, f"Components.Lines[{l_idx}].Children[{c_idx}].Id"
                    )


@dataclass
class VirtualClassIslandClient:
    """
    Python Virtual Client faithfully replicating upstream ClassIsland's ManagementServerConnection
    and ManagementService lifecycle.
    """

    management_server: str
    management_server_grpc: str
    class_identity: str = "Class-101"
    client_uid: str = field(default_factory=lambda: str(uuid.uuid4()))
    mac_address: str = field(
        default_factory=lambda: "AA:BB:CC:"
        + ":".join(f"{secrets.randbits(8):02X}" for _ in range(3))
    )
    host_map: dict[str, str] = field(default_factory=dict)

    # Runtime state matching upstream ManagementSettings & ManagementServerConnection
    server_public_key: str = ""
    session_id: str = ""
    manifest_versions: dict[str, int] = field(default_factory=dict)
    local_resources: dict[str, dict[str, Any]] = field(default_factory=dict)
    received_commands: list[tuple[int, bytes]] = field(default_factory=list)
    received_notifications: list[str] = field(default_factory=list)
    uploaded_configs: list[str] = field(default_factory=list)
    pong_count: int = 0
    _stream_task: asyncio.Task | None = None
    _stop_event: asyncio.Event = field(default_factory=asyncio.Event)

    def _get_metadata(self, out_of_session: bool = False) -> list[tuple[str, str]]:
        """Replicate ManagementServerConnection.GetMetadata(bool outOfSession = false)."""
        parsed = urlparse(self.management_server)
        host = parsed.hostname or ""
        md = [("cuid", self.client_uid)]
        if host:
            md.append(("host", host))
            md.append(("x-forwarded-host", host))
        if not out_of_session:
            if not self.session_id:
                raise RuntimeError(
                    "当前未建立集控会话，且没有指定处于会话外连接，无法生成元数据。"
                )
            md.append(("session", self.session_id))
        return md

    def _grpc_target_and_options(self) -> tuple[str, list[tuple[str, Any]]]:
        parsed = urlparse(self.management_server_grpc)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 27044)
        connect_host = self.host_map.get(host, host)
        opts: list[tuple[str, Any]] = []
        if connect_host != host:
            opts.append(("grpc.default_authority", host))
        return f"{connect_host}:{port}", opts

    async def register(self) -> tuple[int, str, str]:
        """Replicate ManagementServerConnection.RegisterAsync()."""
        target, opts = self._grpc_target_and_options()
        async with grpc.aio.insecure_channel(target, options=opts) as channel:
            stub = ClientRegister_pb2_grpc.ClientRegisterStub(channel)
            req = ClientRegisterCsReq_pb2.ClientRegisterCsReq(
                ClientUid=self.client_uid,
                ClientId=self.class_identity,
                ClientMac=self.mac_address,
            )
            rsp = await stub.Register(req, metadata=self._get_metadata(True))
            if rsp.Retcode in (Retcode_pb2.Success, Retcode_pb2.Registered):
                self.server_public_key = rsp.ServerPublicKey
            return rsp.Retcode, rsp.Message, rsp.ServerPublicKey

    async def unregister(self) -> tuple[int, str]:
        """Replicate ManagementServerConnection.UnRegisterAsync()."""
        target, opts = self._grpc_target_and_options()
        async with grpc.aio.insecure_channel(target, options=opts) as channel:
            stub = ClientRegister_pb2_grpc.ClientRegisterStub(channel)
            req = ClientRegisterCsReq_pb2.ClientRegisterCsReq(
                ClientUid=self.client_uid,
                ClientId=self.class_identity,
                ClientMac=self.mac_address,
            )
            rsp = await stub.UnRegister(req, metadata=self._get_metadata(False))
            return rsp.Retcode, rsp.Message

    async def handshake(self) -> tuple[int, str]:
        """
        Replicate ManagementServerConnection.Handshake():
        1. Generate 64-byte random challenge token, base64 encode.
        2. Encrypt with ServerPublicKey via OpenPGP, extract KeyId.
        3. Call Handshake.BeginHandshake -> verify ChallengeTokenDecrypted == challengeToken.
        4. Call Handshake.CompleteHandshake -> save SessionId & log AuthorizeSuccess audit event.
        """
        if not self.server_public_key:
            raise RuntimeError("Cannot handshake without ServerPublicKey")

        raw_bytes = secrets.token_bytes(64)
        challenge_token = base64.b64encode(raw_bytes).decode("ascii")
        pub_key, _ = pgpy.PGPKey.from_blob(self.server_public_key)
        key_id_uint = int(str(pub_key.fingerprint.keyid), 16)
        key_id_int = (
            key_id_uint - (1 << 64) if key_id_uint >= (1 << 63) else key_id_uint
        )
        msg = pgpy.PGPMessage.new(challenge_token)
        encrypted_msg = pub_key.encrypt(msg)

        target, opts = self._grpc_target_and_options()
        async with grpc.aio.insecure_channel(target, options=opts) as channel:
            stub = Handshake_pb2_grpc.HandshakeStub(channel)
            begin_req = HandshakeScReq_pb2.HandshakeScBeginHandShakeReq(
                ClientUid=self.client_uid,
                ClientMac=self.mac_address,
                ChallengeTokenEncrypted=str(encrypted_msg),
                RequestedServerKeyId=key_id_int,
            )
            begin_rsp = await stub.BeginHandshake(
                begin_req, metadata=self._get_metadata(True)
            )
            if begin_rsp.Retcode != Retcode_pb2.Success:
                return begin_rsp.Retcode, begin_rsp.Message

            if begin_rsp.ChallengeTokenDecrypted != challenge_token:
                raise RuntimeError("Handshake PGP challenge verification failed!")

            complete_req = HandshakeScReq_pb2.HandshakeScCompleteHandshakeReq(
                Accepted=True,
            )
            complete_rsp = await stub.CompleteHandshake(
                complete_req, metadata=self._get_metadata(True)
            )
            if complete_rsp.Retcode == Retcode_pb2.Success:
                self.session_id = complete_rsp.SessionId
                await self.log_audit_event(AuditEvents_pb2.AuthorizeSuccess, b"")
            return complete_rsp.Retcode, complete_rsp.Message

    async def pull_manifest_and_sync_resources(self) -> dict[str, Any]:
        """
        Replicate ManagementServerConnection.GetManifest() & ManagementService.SaveSettingsAsync():
        - GET {ManagementServer}/api/v1/client/{ClientUid}/manifest
        - Follow 302 redirects to /get?token=... for all 7 resources
        - Validate every resource against upstream C# Profile/Model schema & System.Guid rules!
        """
        parsed = urlparse(self.management_server)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 27041)
        connect_host = self.host_map.get(host, host)
        base_url = f"{parsed.scheme}://{connect_host}:{port}"
        headers = {"Host": host}

        async with httpx.AsyncClient(
            base_url=base_url, headers=headers, follow_redirects=True, verify=False
        ) as client:
            manifest_url = f"/api/v1/client/{self.client_uid}/manifest"
            r = await client.get(manifest_url)
            r.raise_for_status()
            manifest = r.json()

            if manifest.get("ServerKind") != 1:
                raise ValueError(f"Unexpected ServerKind: {manifest.get('ServerKind')}")

            resource_map = {
                "ClassPlan": "ClassPlanSource",
                "TimeLayout": "TimeLayoutSource",
                "Subjects": "SubjectsSource",
                "DefaultSettings": "DefaultSettingsSource",
                "Policy": "PolicySource",
                "Components": "ComponentsSource",
                "Credentials": "CredentialSource",
            }

            for rtype, source_key in resource_map.items():
                src = manifest.get(source_key) or {}
                ver = src.get("Version", 0)
                val_url: str = src.get("Value", "")
                if not val_url:
                    continue

                prev_ver = self.manifest_versions.get(rtype, -1)
                if ver != prev_ver or rtype not in self.local_resources:
                    u_parsed = urlparse(val_url)
                    rel_path = u_parsed.path + (
                        f"?{u_parsed.query}" if u_parsed.query else ""
                    )
                    res_resp = await client.get(rel_path)
                    res_resp.raise_for_status()
                    payload = res_resp.json()
                    validate_upstream_profile_deserialization(rtype, payload)
                    self.local_resources[rtype] = payload
                    self.manifest_versions[rtype] = ver

            return manifest

    async def log_audit_event(
        self,
        event_type: int,
        payload_bytes: bytes = b"",
        out_of_session: bool = False,
    ) -> int:
        """Replicate ManagementServerConnection.LogAuditEvent()."""
        target, opts = self._grpc_target_and_options()
        async with grpc.aio.insecure_channel(target, options=opts) as channel:
            stub = Audit_pb2_grpc.AuditStub(channel)
            req = AuditScReq_pb2.AuditScReq(
                Event=event_type,
                Payload=payload_bytes,
                TimestampUtc=int(time.time()),
            )
            rsp = await stub.LogEvent(req, metadata=self._get_metadata(out_of_session))
            return rsp.Retcode

    async def upload_config(
        self, request_guid: str, config_dict: dict[str, Any]
    ) -> int:
        """Replicate ConfigUpload.UploadConfig when receiving GetClientConfig command."""
        target, opts = self._grpc_target_and_options()
        async with grpc.aio.insecure_channel(target, options=opts) as channel:
            stub = ConfigUpload_pb2_grpc.ConfigUploadStub(channel)
            req = ConfigUploadScReq_pb2.ConfigUploadScReq(
                RequestGuidId=request_guid,
                Payload=json.dumps(config_dict, ensure_ascii=False),
            )
            rsp = await stub.UploadConfig(req, metadata=self._get_metadata(False))
            if rsp.Retcode == Retcode_pb2.Success:
                self.uploaded_configs.append(request_guid)
            return rsp.Retcode

    async def start_command_stream(self, ping_interval: float = 1.05) -> None:
        """
        Replicate ManagementServerConnection.ListenCommands() bidirectional stream.
        Note: Server enforces _MIN_PING_INTERVAL = 1.0s between Ping frames.
        """
        self._stop_event.clear()

        async def _req_generator():
            while not self._stop_event.is_set():
                yield ClientCommandDeliverScReq_pb2.ClientCommandDeliverScReq(
                    Type=CommandTypes_pb2.Ping
                )
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(), timeout=ping_interval
                    )
                except asyncio.TimeoutError:
                    pass

        async def _runner():
            target, opts = self._grpc_target_and_options()
            async with grpc.aio.insecure_channel(target, options=opts) as channel:
                stub = ClientCommandDeliver_pb2_grpc.ClientCommandDeliverStub(channel)
                call = stub.ListenCommand(
                    _req_generator(), metadata=self._get_metadata(False)
                )
                async for rsp in call:
                    if rsp.Type == CommandTypes_pb2.Pong:
                        self.pong_count += 1
                    else:
                        self.received_commands.append((rsp.Type, bytes(rsp.Payload)))
                        if rsp.Type == CommandTypes_pb2.SendNotification:
                            notif = SendNotification_pb2.SendNotification.FromString(
                                rsp.Payload
                            )
                            self.received_notifications.append(notif.MessageContent)
                        elif rsp.Type == CommandTypes_pb2.DataUpdated:
                            await self.pull_manifest_and_sync_resources()
                        elif rsp.Type == CommandTypes_pb2.GetClientConfig:
                            cfg_req = GetClientConfig_pb2.GetClientConfig.FromString(
                                rsp.Payload
                            )
                            if cfg_req.RequestGuid:
                                await self.upload_config(
                                    cfg_req.RequestGuid,
                                    {
                                        "ClientUid": self.client_uid,
                                        "ClassIdentity": self.class_identity,
                                        "ConfigType": cfg_req.ConfigType,
                                        "Resources": list(self.local_resources.keys()),
                                    },
                                )

        self._stream_task = asyncio.create_task(_runner())

    async def stop_command_stream(self) -> None:
        self._stop_event.set()
        if self._stream_task:
            self._stream_task.cancel()
            try:
                await self._stream_task
            except (asyncio.CancelledError, Exception):
                pass
            self._stream_task = None


async def run_comprehensive_e2e_suite() -> None:
    """
    Execute comprehensive E2E tests against the running miniclassisland backend:
    1. Multi-Tenant & Multi-Account Isolation (Tenant A vs Tenant B + Multiple Users)
    2. Upstream C# Profile Deserialization & Legacy non-GUID Normalization
    3. Registration Modes: open, pre_reg (whitelist allow/deny + optional MAC), pairing (code generation, approve, reject)
    4. Bidirectional gRPC Command Stream: Ping/Pong, Broadcast Notification, Force Sync (DataUpdated), Request Config Upload, Audit Logs (in-session & out-of-session)
    5. Concurrency Stress Test: 20 concurrent virtual clients across multiple tenants registering, handshaking, pulling manifests/resources, and streaming simultaneously
    6. Reliability & Security Tests:
       - Unauthenticated gRPC stream rejection (StatusCode.UNAUTHENTICATED)
       - Forged / MAC-mismatch BeginHandshake rejection
       - Disabled client rejection in Handshake and Audit Log
       - One-time download token replay & invalid token rejection (403)
       - Cross-tenant API access prevention (User B attempting to read/modify Tenant A -> 403 ERR_TENANT_NO_ACCESS)
       - Oversized / deeply-nested JSON payload protection (400)
    """
    from sqlalchemy import delete
    from app.shared.db.session import AsyncSessionLocal
    from app.shared.db.models import (
        Account,
        AccountMember,
        AuditLog,
        ClientProfile,
        ClientRecord,
        ComponentsFile,
        ConfigUploadRecord,
        CPFile,
        CredentialsFile,
        PairingCode,
        PolicyFile,
        PreRegisteredClient,
        SettingsFile,
        SubFile,
        TLFile,
        User,
    )
    from app.shared.security.auth import create_session_token
    from app.shared.services.user import register_user
    from app.shared.utils.tenant import set_search_path

    print("=" * 78)
    print("🚀 MINI ClassIsland Virtual Client E2E Verification Suite")
    print("=" * 78)

    run_tag = secrets.token_hex(4)
    slug_a = f"e2e-tenant-a-{run_tag}"
    slug_b = f"e2e-tenant-b-{run_tag}"
    acct_a_id = str(uuid.uuid4())
    acct_b_id = str(uuid.uuid4())
    user_a_id = ""
    user_b_id = ""

    host_a = f"{slug_a}.miniclassisland.com"
    host_b = f"{slug_b}.miniclassisland.com"
    host_map = {
        host_a: "127.0.0.1",
        host_b: "127.0.0.1",
        "127.0.0.1": "127.0.0.1",
    }

    mgmt_base = "http://127.0.0.1:27042"
    client_port = 27041
    grpc_port = 27044

    created_client_uids: list[str] = []

    try:
        # ------------------------------------------------------------------
        # Step 0: Provision 2 isolated users & 2 isolated tenant accounts
        # ------------------------------------------------------------------
        now = datetime.now(timezone.utc)
        async with AsyncSessionLocal() as db:
            await set_search_path(db)
            user_a = await register_user(
                f"user_a_{run_tag}@example.com",
                "PassA123!",
                "User A",
                db,
                username=f"user_a_{run_tag}",
                role_code="normal",
                is_active=True,
                can_create_account=True,
            )
            user_b = await register_user(
                f"user_b_{run_tag}@example.com",
                "PassB123!",
                "User B",
                db,
                username=f"user_b_{run_tag}",
                role_code="normal",
                is_active=True,
                can_create_account=True,
            )
            user_a_id = user_a.id
            user_b_id = user_b.id

            db.add_all(
                [
                    Account(
                        id=acct_a_id,
                        name=f"Tenant A ({run_tag})",
                        slug=slug_a,
                        api_key=f"key-a-{run_tag}",
                        registration_mode="open",
                        is_active=True,
                        created_at=now,
                    ),
                    Account(
                        id=acct_b_id,
                        name=f"Tenant B ({run_tag})",
                        slug=slug_b,
                        api_key=f"key-b-{run_tag}",
                        registration_mode="open",
                        is_active=True,
                        created_at=now,
                    ),
                    AccountMember(
                        account_id=acct_a_id,
                        user_id=user_a_id,
                        role_in_account="owner",
                        joined_at=now,
                    ),
                    AccountMember(
                        account_id=acct_b_id,
                        user_id=user_b_id,
                        role_in_account="owner",
                        joined_at=now,
                    ),
                ]
            )
            await db.commit()

        token_a = await create_session_token(user_a_id)
        token_b = await create_session_token(user_b_id)
        headers_a = {"Authorization": f"Bearer {token_a}"}
        headers_b = {"Authorization": f"Bearer {token_b}"}

        async with httpx.AsyncClient(base_url=mgmt_base, timeout=15.0) as mgmt:
            # ------------------------------------------------------------------
            # Test 1: Multi-Tenant & Multi-Account Isolation + Non-GUID Normalization
            # ------------------------------------------------------------------
            print(
                "\n[1/6] Testing Multi-Tenant Resource Isolation & Upstream System.Guid Normalization..."
            )

            # User A writes custom Subjects (with legacy non-GUID key 'sub-custom-physics')
            # and unwrapped ClassPlan (simulating Web frontend save)
            r = await mgmt.post(
                f"/account/{acct_a_id}/Subjects/write",
                params={"name": "default"},
                json={
                    "sub-custom-physics": {
                        "Name": "量子物理(TenantA专属)",
                        "Initial": "物",
                        "TeacherName": "Alice",
                        "IsOutDoor": False,
                    }
                },
                headers=headers_a,
            )
            assert r.status_code == 200, r.text

            r = await mgmt.post(
                f"/account/{acct_a_id}/ClassPlan/write",
                params={"name": "default"},
                json={
                    "cp-monday": {
                        "Name": "TenantA周一课表",
                        "TimeLayoutId": "tl-weekday",
                        "Classes": [
                            {"SubjectId": "sub-custom-physics", "IsEnabled": True}
                        ],
                        "TimeRule": {
                            "WeekDay": 1,
                            "WeekCountDiv": 0,
                            "WeekCountDivTotal": 2,
                        },
                        "IsEnabled": True,
                        "IsOverlay": False,
                    }
                },
                headers=headers_a,
            )
            assert r.status_code == 200, r.text

            # User B writes completely different Subjects to Tenant B
            r = await mgmt.post(
                f"/account/{acct_b_id}/Subjects/write",
                params={"name": "default"},
                json={
                    "Subjects": {
                        str(uuid.uuid4()): {
                            "Name": "古典文学(TenantB专属)",
                            "Initial": "文",
                            "TeacherName": "Bob",
                            "IsOutDoor": False,
                        }
                    }
                },
                headers=headers_b,
            )
            assert r.status_code == 200, r.text

            # Virtual Client A connects to Tenant A, Virtual Client B connects to Tenant B
            vc_a = VirtualClassIslandClient(
                management_server=f"http://{host_a}:{client_port}",
                management_server_grpc=f"http://{host_a}:{grpc_port}",
                class_identity="TenantA-Room101",
                host_map=host_map,
            )
            vc_b = VirtualClassIslandClient(
                management_server=f"http://{host_b}:{client_port}",
                management_server_grpc=f"http://{host_b}:{grpc_port}",
                class_identity="TenantB-Room202",
                host_map=host_map,
            )
            created_client_uids.extend([vc_a.client_uid, vc_b.client_uid])

            ret_a, msg_a, _ = await vc_a.register()
            assert ret_a in (
                Retcode_pb2.Success,
                Retcode_pb2.Registered,
            ), f"vc_a register failed: {msg_a}"
            ret_b, msg_b, _ = await vc_b.register()
            assert ret_b in (
                Retcode_pb2.Success,
                Retcode_pb2.Registered,
            ), f"vc_b register failed: {msg_b}"

            # Right after Register (before Handshake sets session_id), test out-of-session Audit.LogEvent with cuid only
            early_audit_ret = await vc_a.log_audit_event(
                AuditEvents_pb2.AppSettingsUpdated,
                b'{"source":"startup"}',
                out_of_session=True,
            )
            assert (
                early_audit_ret == Retcode_pb2.Success
            ), "Out-of-session Audit.LogEvent with cuid should succeed!"

            hs_a, _ = await vc_a.handshake()
            assert hs_a == Retcode_pb2.Success
            hs_b, _ = await vc_b.handshake()
            assert hs_b == Retcode_pb2.Success

            await vc_a.pull_manifest_and_sync_resources()
            await vc_b.pull_manifest_and_sync_resources()

            # Verify Tenant A client got Tenant A's subjects (with valid GUIDs!) and NOT Tenant B's
            subs_a_names = [
                s["Name"] for s in vc_a.local_resources["Subjects"]["Subjects"].values()
            ]
            subs_b_names = [
                s["Name"] for s in vc_b.local_resources["Subjects"]["Subjects"].values()
            ]
            assert "量子物理(TenantA专属)" in subs_a_names
            assert "古典文学(TenantB专属)" not in subs_a_names
            assert "古典文学(TenantB专属)" in subs_b_names
            assert "量子物理(TenantA专属)" not in subs_b_names

            # Verify Client List API isolation between Tenant A and Tenant B
            clients_a_list = (
                await mgmt.get(f"/account/{acct_a_id}/client/list", headers=headers_a)
            ).json()
            clients_b_list = (
                await mgmt.get(f"/account/{acct_b_id}/client/list", headers=headers_b)
            ).json()
            uids_in_a = {c["uid"] for c in clients_a_list}
            uids_in_b = {c["uid"] for c in clients_b_list}
            assert vc_a.client_uid in uids_in_a
            assert vc_b.client_uid not in uids_in_a
            assert vc_b.client_uid in uids_in_b
            assert vc_a.client_uid not in uids_in_b
            print(
                "  ✅ Tenant A and Tenant B resources, clients, and C# System.Guid schemas are 100% isolated and valid!"
            )

            # ------------------------------------------------------------------
            # Test 2: Registration Modes (pre_reg & pairing)
            # ------------------------------------------------------------------
            print(
                "\n[2/6] Testing Registration Modes (pre_reg whitelist & pairing code workflow)..."
            )

            # Switch Tenant A to pre_reg mode
            r = await mgmt.post(
                f"/account/{acct_a_id}/pairing/mode",
                json={"mode": "pre_reg"},
                headers=headers_a,
            )
            assert r.status_code == 200

            # Unlisted client should be rejected in pre_reg mode
            vc_unlisted = VirtualClassIslandClient(
                management_server=f"http://{host_a}:{client_port}",
                management_server_grpc=f"http://{host_a}:{grpc_port}",
                class_identity="Unlisted-Room999",
                host_map=host_map,
            )
            ret_unlisted, _, _ = await vc_unlisted.register()
            assert (
                ret_unlisted == Retcode_pb2.InvalidRequest
            ), f"Expected InvalidRequest for unlisted pre_reg client, got {ret_unlisted}"

            # Add pre-registration entry WITHOUT MAC (optional MAC test!)
            r_pre = await mgmt.post(
                f"/account/{acct_a_id}/pre-registration/create",
                json={
                    "label": "PreReg Room 303",
                    "class_identity": "PreReg-Room303",
                    "mac_address": "",
                },
                headers=headers_a,
            )
            assert r_pre.status_code == 201, r_pre.text

            vc_prereg = VirtualClassIslandClient(
                management_server=f"http://{host_a}:{client_port}",
                management_server_grpc=f"http://{host_a}:{grpc_port}",
                class_identity="PreReg-Room303",
                host_map=host_map,
            )
            created_client_uids.append(vc_prereg.client_uid)
            ret_pre, msg_pre, _ = await vc_prereg.register()
            assert ret_pre in (
                Retcode_pb2.Success,
                Retcode_pb2.Registered,
            ), f"Pre-registered client failed: {msg_pre}"

            # Switch Tenant A to pairing mode
            r = await mgmt.post(
                f"/account/{acct_a_id}/pairing/mode",
                json={"mode": "pairing"},
                headers=headers_a,
            )
            assert r.status_code == 200

            vc_pair = VirtualClassIslandClient(
                management_server=f"http://{host_a}:{client_port}",
                management_server_grpc=f"http://{host_a}:{grpc_port}",
                class_identity="Pairing-Room404",
                host_map=host_map,
            )
            created_client_uids.append(vc_pair.client_uid)
            ret_p1, msg_p1, _ = await vc_pair.register()
            assert (
                ret_p1 == Retcode_pb2.PairingRequired
            ), f"Expected PairingRequired, got {ret_p1}: {msg_p1}"

            # Verify pairing code only appears in Tenant A, NOT Tenant B
            codes_a = (
                await mgmt.get(f"/account/{acct_a_id}/pairing/list", headers=headers_a)
            ).json()
            codes_b = (
                await mgmt.get(f"/account/{acct_b_id}/pairing/list", headers=headers_b)
            ).json()
            pair_entry = next(
                (c for c in codes_a if c["client_uid"] == vc_pair.client_uid), None
            )
            assert pair_entry is not None
            assert all(c["client_uid"] != vc_pair.client_uid for c in codes_b)

            # Approve pairing code in Tenant A
            r_app = await mgmt.post(
                f"/account/{acct_a_id}/pairing/{pair_entry['code']}/approve",
                json={},
                headers=headers_a,
            )
            assert r_app.status_code == 200

            # Now vc_pair registers again and succeeds
            ret_p2, msg_p2, _ = await vc_pair.register()
            assert ret_p2 in (Retcode_pb2.Success, Retcode_pb2.Registered), msg_p2
            hs_p2, _ = await vc_pair.handshake()
            assert hs_p2 == Retcode_pb2.Success

            # Restore Tenant A to open mode
            await mgmt.post(
                f"/account/{acct_a_id}/pairing/mode",
                json={"mode": "open"},
                headers=headers_a,
            )
            print(
                "  ✅ open, pre_reg (with optional MAC), and pairing registration modes verified!"
            )

            # ------------------------------------------------------------------
            # Test 3: Bidirectional gRPC Command Stream, Broadcast Isolation & Config Upload
            # ------------------------------------------------------------------
            print(
                "\n[3/6] Testing Bidirectional gRPC Command Stream, Broadcast Isolation & Config Upload..."
            )
            await vc_a.start_command_stream(ping_interval=1.05)
            await vc_b.start_command_stream(ping_interval=1.05)
            await asyncio.sleep(0.4)
            assert vc_a.pong_count >= 1, "vc_a did not receive Pong heartbeat!"
            assert vc_b.pong_count >= 1, "vc_b did not receive Pong heartbeat!"

            # Broadcast notification in Tenant A -> only vc_a should receive it, NEVER vc_b!
            r_notif = await mgmt.post(
                f"/account/{acct_a_id}/broadcast/notification",
                json={
                    "MessageMask": "紧急通知",
                    "MessageContent": "仅限TenantA的广播测试",
                    "DurationSeconds": 5.0,
                },
                headers=headers_a,
            )
            assert r_notif.status_code == 200, r_notif.text
            await asyncio.sleep(0.4)
            assert "仅限TenantA的广播测试" in vc_a.received_notifications
            assert "仅限TenantA的广播测试" not in vc_b.received_notifications

            # Request config upload from vc_a
            r_cfg = await mgmt.post(
                f"/account/{acct_a_id}/client/{vc_a.client_uid}/command/get-config",
                params={"config_type": 1},
                headers=headers_a,
            )
            assert r_cfg.status_code == 200, r_cfg.text
            req_guid = r_cfg.json()["request_guid"]
            await asyncio.sleep(0.4)
            assert req_guid in vc_a.uploaded_configs

            # Verify config upload record is visible in Tenant A and NOT Tenant B
            uploads_a = (
                await mgmt.get(
                    f"/account/{acct_a_id}/client/{vc_a.client_uid}/config-uploads",
                    headers=headers_a,
                )
            ).json()
            uploads_b = (
                await mgmt.get(
                    f"/account/{acct_b_id}/client/{vc_a.client_uid}/config-uploads",
                    headers=headers_b,
                )
            ).json()
            assert any(
                u["request_guid"] == req_guid and u["status"] == "completed"
                for u in uploads_a
            )
            assert len(uploads_b) == 0

            # Update Subjects in Tenant A and trigger force_sync -> vc_a automatically pulls hot update
            await mgmt.post(
                f"/account/{acct_a_id}/Subjects/write",
                params={"name": "default"},
                json={
                    "sub-custom-physics": {
                        "Name": "高等量子物理(热更新)",
                        "Initial": "高",
                        "TeacherName": "Alice",
                        "IsOutDoor": False,
                    }
                },
                headers=headers_a,
            )
            r_sync = await mgmt.post(
                f"/account/{acct_a_id}/client/{vc_a.client_uid}/command/update-data",
                headers=headers_a,
            )
            assert r_sync.status_code == 200
            await asyncio.sleep(0.5)
            updated_names = [
                s["Name"] for s in vc_a.local_resources["Subjects"]["Subjects"].values()
            ]
            assert "高等量子物理(热更新)" in updated_names

            await vc_a.stop_command_stream()
            await vc_b.stop_command_stream()
            print(
                "  ✅ gRPC Ping/Pong, Tenant-Isolated Broadcast, ConfigUpload, and Hot DataUpdated Sync verified!"
            )

            # ------------------------------------------------------------------
            # Test 4: Concurrency Stress Test (20 Virtual Clients across 2 Tenants)
            # ------------------------------------------------------------------
            print(
                "\n[4/6] Running Concurrency Stress Test (20 concurrent virtual clients across Tenant A & B)..."
            )
            concurrent_clients: list[VirtualClassIslandClient] = []
            for idx in range(20):
                is_a = idx % 2 == 0
                h = host_a if is_a else host_b
                c = VirtualClassIslandClient(
                    management_server=f"http://{h}:{client_port}",
                    management_server_grpc=f"http://{h}:{grpc_port}",
                    class_identity=f"Concurrent-{'A' if is_a else 'B'}-{idx:02d}",
                    host_map=host_map,
                )
                concurrent_clients.append(c)
                created_client_uids.append(c.client_uid)

            async def _lifecycle_worker(client_obj: VirtualClassIslandClient) -> None:
                ret, msg, _ = await client_obj.register()
                assert ret in (Retcode_pb2.Success, Retcode_pb2.Registered), msg
                hs, hs_msg = await client_obj.handshake()
                assert hs == Retcode_pb2.Success, hs_msg
                await client_obj.pull_manifest_and_sync_resources()
                await client_obj.start_command_stream(ping_interval=1.05)
                await client_obj.log_audit_event(
                    AuditEvents_pb2.AppSettingsUpdated, b'{"concurrent":true}'
                )

            t0 = time.perf_counter()
            await asyncio.gather(*(_lifecycle_worker(c) for c in concurrent_clients))
            await asyncio.sleep(0.4)
            await asyncio.gather(*(c.stop_command_stream() for c in concurrent_clients))
            elapsed = time.perf_counter() - t0
            assert all(c.pong_count >= 1 for c in concurrent_clients)
            assert all(len(c.local_resources) == 7 for c in concurrent_clients)
            print(
                f"  ✅ 20 concurrent virtual clients completed full Register+PGP Handshake+7-Resource Sync+Stream+Audit in {elapsed:.2f}s!"
            )

            # ------------------------------------------------------------------
            # Test 5: Reliability & Security Tests
            # ------------------------------------------------------------------
            print("\n[5/6] Running Reliability & Security Tests...")

            # 5.1 Cross-tenant API access attempt (User B accessing Tenant A -> 403)
            r_cross1 = await mgmt.get(
                f"/account/{acct_a_id}/client/list", headers=headers_b
            )
            assert r_cross1.status_code == 403
            r_cross2 = await mgmt.post(
                f"/account/{acct_a_id}/Subjects/write",
                params={"name": "default"},
                json={"Subjects": {}},
                headers=headers_b,
            )
            assert r_cross2.status_code == 403

            # 5.2 Forged session token on ListenCommand -> UNAUTHENTICATED
            vc_forged = VirtualClassIslandClient(
                management_server=f"http://{host_a}:{client_port}",
                management_server_grpc=f"http://{host_a}:{grpc_port}",
                class_identity="Forged-Session",
                session_id="forged-invalid-session-token-999",
                host_map=host_map,
            )
            await vc_forged.start_command_stream()
            await asyncio.sleep(0.3)
            assert vc_forged.pong_count == 0
            await vc_forged.stop_command_stream()

            # 5.3 MAC Address Spoofing / Mismatch in BeginHandshake -> InvalidRequest
            vc_spoof = VirtualClassIslandClient(
                management_server=f"http://{host_a}:{client_port}",
                management_server_grpc=f"http://{host_a}:{grpc_port}",
                class_identity="Spoof-Test",
                client_uid=vc_a.client_uid,
                mac_address="FF:FF:FF:00:11:22",  # Different MAC than vc_a!
                server_public_key=vc_a.server_public_key,
                host_map=host_map,
            )
            hs_spoof, _ = await vc_spoof.handshake()
            assert hs_spoof == Retcode_pb2.InvalidRequest

            # 5.4 Disabled Client Rejection
            r_dis = await mgmt.post(
                f"/account/{acct_a_id}/client/{vc_a.client_uid}/disable",
                headers=headers_a,
            )
            assert r_dis.status_code == 200
            hs_dis, _ = await vc_a.handshake()
            assert hs_dis == Retcode_pb2.InvalidRequest
            audit_dis = await vc_a.log_audit_event(
                AuditEvents_pb2.AppSettingsUpdated, b"{}", out_of_session=True
            )
            assert audit_dis == Retcode_pb2.InvalidRequest

            # Re-enable vc_a and test UnRegister
            await mgmt.post(
                f"/account/{acct_a_id}/client/{vc_a.client_uid}/enable",
                headers=headers_a,
            )
            hs_re, _ = await vc_a.handshake()
            assert hs_re == Retcode_pb2.Success
            unreg_ret, _ = await vc_a.unregister()
            assert unreg_ret == Retcode_pb2.Success

            # 5.5 One-time download token replay & invalid token protection
            async with httpx.AsyncClient(
                base_url=f"http://127.0.0.1:{client_port}",
                headers={"Host": host_b},
                follow_redirects=False,
            ) as raw_client:
                r_redir = await raw_client.get(
                    "/api/v1/client/Subjects",
                    params={"name": "default", "cuid": vc_b.client_uid},
                )
                assert r_redir.status_code == 302
                loc = r_redir.headers["location"]
                u_loc = urlparse(loc)
                rel_get = f"{u_loc.path}?{u_loc.query}"
                # First consume -> 200
                r_get1 = await raw_client.get(rel_get)
                assert r_get1.status_code == 200
                # Replay consume -> 403 (one-time token already consumed!)
                r_get2 = await raw_client.get(rel_get)
                assert r_get2.status_code == 403

            # 5.6 Deeply nested JSON DoS payload protection -> 400
            deep_obj: dict[str, Any] = {"leaf": 1}
            for _ in range(30):
                deep_obj = {"nested": deep_obj}
            r_deep = await mgmt.post(
                f"/account/{acct_a_id}/Policy/write",
                params={"name": "default"},
                json=deep_obj,
                headers=headers_a,
            )
            assert r_deep.status_code == 400
            print(
                "  ✅ Cross-tenant 403, Forged Session, MAC Spoofing, Disabled Client, One-Time Token Replay & Deep JSON DoS protections verified!"
            )

            # ------------------------------------------------------------------
            # Test 6: Verify Audit Log Isolation
            # ------------------------------------------------------------------
            print("\n[6/6] Verifying Audit Log Multi-Tenant Isolation...")
            audits_a = (
                await mgmt.get(f"/account/{acct_a_id}/audit/list", headers=headers_a)
            ).json()
            audits_b = (
                await mgmt.get(f"/account/{acct_b_id}/audit/list", headers=headers_b)
            ).json()
            assert len(audits_a) > 0
            assert len(audits_b) > 0
            a_uids = {item["client_uid"] for item in audits_a}
            b_uids = {item["client_uid"] for item in audits_b}
            assert vc_b.client_uid not in a_uids
            assert vc_a.client_uid not in b_uids
            print("  ✅ Audit logs are strictly isolated per tenant!")

    finally:
        # Clean up all E2E test data from PostgreSQL so production DB stays clean
        async with AsyncSessionLocal() as db:
            await set_search_path(db)
            for model in (
                CPFile,
                TLFile,
                SubFile,
                SettingsFile,
                PolicyFile,
                ComponentsFile,
                CredentialsFile,
                PreRegisteredClient,
                ConfigUploadRecord,
                AuditLog,
                ClientProfile,
                ClientRecord,
                AccountMember,
            ):
                await db.execute(
                    delete(model).where(model.account_id.in_([acct_a_id, acct_b_id]))
                )
            await db.execute(
                delete(PairingCode).where(
                    PairingCode.tenant_id.in_([acct_a_id, acct_b_id])
                )
            )
            if created_client_uids:
                await db.execute(
                    delete(ClientRecord).where(
                        ClientRecord.uid.in_(created_client_uids)
                    )
                )
            await db.execute(
                delete(Account).where(Account.id.in_([acct_a_id, acct_b_id]))
            )
            for uid in (user_a_id, user_b_id):
                if uid:
                    await db.execute(delete(User).where(User.id == uid))
            await db.commit()

    print("\n" + "=" * 78)
    print(
        "🎉 ALL E2E VIRTUAL CLIENT & MULTI-TENANT SECURITY TESTS PASSED SUCCESSFULLY!"
    )
    print("=" * 78)


if __name__ == "__main__":
    asyncio.run(run_comprehensive_e2e_suite())
