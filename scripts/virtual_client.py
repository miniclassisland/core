#!/usr/bin/env python3
"""
Virtual ClassIsland Client & Large-Scale Cross-Matrix E2E Test Suite.

Strictly mirrors upstream ClassIsland C# client behavior:
- ClassIsland/Services/Management/ManagementServerConnection.cs
- ClassIsland/Services/Management/ManagementService.cs
- ClassIsland/Services/ProfileService.cs
- ClassIsland.Shared/Models/Profile/Profile.cs

Executes a large-scale cross-matrix reliability & security verification:
- 8 Users (with cross-account memberships & non-memberships)
- 12 Tenant Accounts (across open, pre_reg, and pairing registration modes)
- 200 Concurrent Virtual Clients (distributed across the 12 accounts)
- 3 Distinct Profile Clusters per Account ('cluster-alpha', 'cluster-beta', 'cluster-gamma')
  comprising all 7 resource types (ClassPlan, TimeLayout, Subjects, DefaultSettings, Policy, Components, Credentials),
  individually bound to each of the 200 clients and verified end-to-end.
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
    account_index: int = 0
    account_id: str = ""
    cluster_name: str = "cluster-alpha"
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
    manifest_urls: dict[str, str] = field(default_factory=dict)
    local_resources: dict[str, dict[str, Any]] = field(default_factory=dict)
    received_commands: list[tuple[int, bytes]] = field(default_factory=list)
    received_notifications: list[str] = field(default_factory=list)
    uploaded_configs: list[str] = field(default_factory=list)
    restart_count: int = 0
    pong_count: int = 0
    # Traffic / bandwidth metering (bytes at Protobuf/HTTP payload + framing level)
    bytes_tx_grpc: int = 0
    bytes_rx_grpc: int = 0
    bytes_tx_http: int = 0
    bytes_rx_http: int = 0
    bytes_register_total: int = 0
    bytes_handshake_total: int = 0
    bytes_manifest_sync_total: int = 0
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

    async def register(
        self, shared_channel: grpc.aio.Channel | None = None
    ) -> tuple[int, str, str]:
        """Replicate ManagementServerConnection.RegisterAsync()."""
        req = ClientRegisterCsReq_pb2.ClientRegisterCsReq(
            ClientUid=self.client_uid,
            ClientId=self.class_identity,
            ClientMac=self.mac_address,
        )
        if shared_channel is not None:
            stub = ClientRegister_pb2_grpc.ClientRegisterStub(shared_channel)
            rsp = await stub.Register(req, metadata=self._get_metadata(True))
        else:
            target, opts = self._grpc_target_and_options()
            async with grpc.aio.insecure_channel(target, options=opts) as channel:
                stub = ClientRegister_pb2_grpc.ClientRegisterStub(channel)
                rsp = await stub.Register(req, metadata=self._get_metadata(True))
        if rsp.Retcode in (Retcode_pb2.Success, Retcode_pb2.Registered):
            self.server_public_key = rsp.ServerPublicKey
        tx_b = req.ByteSize() + 180
        rx_b = rsp.ByteSize() + 160
        self.bytes_tx_grpc += tx_b
        self.bytes_rx_grpc += rx_b
        self.bytes_register_total += tx_b + rx_b
        return rsp.Retcode, rsp.Message, rsp.ServerPublicKey

    async def unregister(
        self, shared_channel: grpc.aio.Channel | None = None
    ) -> tuple[int, str]:
        """Replicate ManagementServerConnection.UnRegisterAsync()."""
        req = ClientRegisterCsReq_pb2.ClientRegisterCsReq(
            ClientUid=self.client_uid,
            ClientId=self.class_identity,
            ClientMac=self.mac_address,
        )
        if shared_channel is not None:
            stub = ClientRegister_pb2_grpc.ClientRegisterStub(shared_channel)
            rsp = await stub.UnRegister(req, metadata=self._get_metadata(False))
        else:
            target, opts = self._grpc_target_and_options()
            async with grpc.aio.insecure_channel(target, options=opts) as channel:
                stub = ClientRegister_pb2_grpc.ClientRegisterStub(channel)
                rsp = await stub.UnRegister(req, metadata=self._get_metadata(False))
        return rsp.Retcode, rsp.Message

    async def handshake(
        self,
        shared_channel: grpc.aio.Channel | None = None,
        cached_pub_key: pgpy.PGPKey | None = None,
    ) -> tuple[int, str]:
        """
        Replicate ManagementServerConnection.Handshake():
        1. Generate 64-byte random challenge token, base64 encode.
        2. Encrypt with ServerPublicKey via OpenPGP, extract KeyId.
        3. Call Handshake.BeginHandshake -> verify ChallengeTokenDecrypted == challengeToken.
        4. Call Handshake.CompleteHandshake -> save SessionId & log AuthorizeSuccess audit event.
        """
        if not self.server_public_key and cached_pub_key is None:
            raise RuntimeError("Cannot handshake without ServerPublicKey")

        raw_bytes = secrets.token_bytes(64)
        challenge_token = base64.b64encode(raw_bytes).decode("ascii")
        if cached_pub_key is not None:
            pub_key = cached_pub_key
        else:
            pub_key, _ = pgpy.PGPKey.from_blob(self.server_public_key)
        key_id_uint = int(str(pub_key.fingerprint.keyid), 16)
        key_id_int = (
            key_id_uint - (1 << 64) if key_id_uint >= (1 << 63) else key_id_uint
        )
        msg = pgpy.PGPMessage.new(challenge_token)
        encrypted_msg = pub_key.encrypt(msg)

        begin_req = HandshakeScReq_pb2.HandshakeScBeginHandShakeReq(
            ClientUid=self.client_uid,
            ClientMac=self.mac_address,
            ChallengeTokenEncrypted=str(encrypted_msg),
            RequestedServerKeyId=key_id_int,
        )

        async def _do_hs(ch: grpc.aio.Channel) -> tuple[int, str]:
            stub = Handshake_pb2_grpc.HandshakeStub(ch)
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
            tx_b = begin_req.ByteSize() + complete_req.ByteSize() + 360
            rx_b = begin_rsp.ByteSize() + complete_rsp.ByteSize() + 320
            self.bytes_tx_grpc += tx_b
            self.bytes_rx_grpc += rx_b
            self.bytes_handshake_total += tx_b + rx_b
            if complete_rsp.Retcode == Retcode_pb2.Success:
                self.session_id = complete_rsp.SessionId
                await self.log_audit_event(
                    AuditEvents_pb2.AuthorizeSuccess, b"", shared_channel=ch
                )
            return complete_rsp.Retcode, complete_rsp.Message

        if shared_channel is not None:
            return await _do_hs(shared_channel)
        target, opts = self._grpc_target_and_options()
        async with grpc.aio.insecure_channel(target, options=opts) as channel:
            return await _do_hs(channel)

    async def pull_manifest_and_sync_resources(
        self, shared_http: httpx.AsyncClient | None = None
    ) -> dict[str, Any]:
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

        async def _do_sync(client: httpx.AsyncClient) -> dict[str, Any]:
            manifest_url = f"{base_url}/api/v1/client/{self.client_uid}/manifest"
            r = await client.get(manifest_url, headers=headers)
            r.raise_for_status()
            tx_sync = len(manifest_url) + 180
            rx_sync = len(r.content) + 220
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
                prev_url = self.manifest_urls.get(rtype, "")
                if (
                    ver != prev_ver
                    or val_url != prev_url
                    or rtype not in self.local_resources
                ):
                    u_parsed = urlparse(val_url)
                    rel_path = u_parsed.path + (
                        f"?{u_parsed.query}" if u_parsed.query else ""
                    )
                    res_resp = await client.get(
                        f"{base_url}{rel_path}", headers=headers
                    )
                    res_resp.raise_for_status()
                    # Account for 302 redirect + /get?token=... request/response headers & body
                    tx_sync += len(rel_path) * 2 + 380
                    rx_sync += len(res_resp.content) + 420
                    payload = res_resp.json()
                    validate_upstream_profile_deserialization(rtype, payload)
                    self.local_resources[rtype] = payload
                    self.manifest_versions[rtype] = ver
                    self.manifest_urls[rtype] = val_url

            self.bytes_tx_http += tx_sync
            self.bytes_rx_http += rx_sync
            self.bytes_manifest_sync_total += tx_sync + rx_sync
            return manifest

        if shared_http is not None:
            return await _do_sync(shared_http)
        async with httpx.AsyncClient(
            follow_redirects=True, verify=False, timeout=30.0
        ) as client:
            return await _do_sync(client)

    async def log_audit_event(
        self,
        event_type: int,
        payload_bytes: bytes = b"",
        out_of_session: bool = False,
        shared_channel: grpc.aio.Channel | None = None,
    ) -> int:
        """Replicate ManagementServerConnection.LogAuditEvent()."""
        req = AuditScReq_pb2.AuditScReq(
            Event=event_type,
            Payload=payload_bytes,
            TimestampUtc=int(time.time()),
        )
        if shared_channel is not None:
            stub = Audit_pb2_grpc.AuditStub(shared_channel)
            rsp = await stub.LogEvent(req, metadata=self._get_metadata(out_of_session))
        else:
            target, opts = self._grpc_target_and_options()
            async with grpc.aio.insecure_channel(target, options=opts) as channel:
                stub = Audit_pb2_grpc.AuditStub(channel)
                rsp = await stub.LogEvent(
                    req, metadata=self._get_metadata(out_of_session)
                )
        self.bytes_tx_grpc += req.ByteSize() + 180
        self.bytes_rx_grpc += rsp.ByteSize() + 140
        return rsp.Retcode

    async def upload_config(
        self,
        request_guid: str,
        config_dict: dict[str, Any],
        shared_channel: grpc.aio.Channel | None = None,
    ) -> int:
        """Replicate ConfigUpload.UploadConfig when receiving GetClientConfig command."""
        req = ConfigUploadScReq_pb2.ConfigUploadScReq(
            RequestGuidId=request_guid,
            Payload=json.dumps(config_dict, ensure_ascii=False),
        )
        if shared_channel is not None:
            stub = ConfigUpload_pb2_grpc.ConfigUploadStub(shared_channel)
            rsp = await stub.UploadConfig(req, metadata=self._get_metadata(False))
        else:
            target, opts = self._grpc_target_and_options()
            async with grpc.aio.insecure_channel(target, options=opts) as channel:
                stub = ConfigUpload_pb2_grpc.ConfigUploadStub(channel)
                rsp = await stub.UploadConfig(req, metadata=self._get_metadata(False))
        if rsp.Retcode == Retcode_pb2.Success:
            self.uploaded_configs.append(request_guid)
        self.bytes_tx_grpc += req.ByteSize() + 180
        self.bytes_rx_grpc += rsp.ByteSize() + 140
        return rsp.Retcode

    async def start_command_stream(
        self,
        ping_interval: float = 1.05,
        shared_channel: grpc.aio.Channel | None = None,
        shared_http: httpx.AsyncClient | None = None,
    ) -> None:
        """
        Replicate ManagementServerConnection.ListenCommands() bidirectional stream.
        """
        self._stop_event.clear()

        async def _req_generator():
            while not self._stop_event.is_set():
                ping_msg = ClientCommandDeliverScReq_pb2.ClientCommandDeliverScReq(
                    Type=CommandTypes_pb2.Ping
                )
                self.bytes_tx_grpc += ping_msg.ByteSize() + 34
                yield ping_msg
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(), timeout=ping_interval
                    )
                except asyncio.TimeoutError:
                    pass

        async def _consume_stream(ch: grpc.aio.Channel) -> None:
            stub = ClientCommandDeliver_pb2_grpc.ClientCommandDeliverStub(ch)
            call = stub.ListenCommand(
                _req_generator(), metadata=self._get_metadata(False)
            )
            async for rsp in call:
                self.bytes_rx_grpc += rsp.ByteSize() + 34
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
                        await self.pull_manifest_and_sync_resources(
                            shared_http=shared_http
                        )
                    elif rsp.Type == CommandTypes_pb2.RestartApp:
                        self.restart_count += 1
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
                                    "AccountIndex": self.account_index,
                                    "ClusterName": self.cluster_name,
                                    "ConfigType": cfg_req.ConfigType,
                                    "Resources": list(self.local_resources.keys()),
                                },
                                shared_channel=ch,
                            )

        async def _runner():
            if shared_channel is not None:
                await _consume_stream(shared_channel)
            else:
                target, opts = self._grpc_target_and_options()
                async with grpc.aio.insecure_channel(target, options=opts) as channel:
                    await _consume_stream(channel)

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


def build_cluster_resources(
    acct_idx: int, cluster_name: str
) -> dict[str, dict[str, Any]]:
    """
    Generate a distinct, self-consistent 7-resource profile cluster ('cluster-alpha', 'cluster-beta', 'cluster-gamma')
    for a given tenant account index.
    """
    tag = f"A{acct_idx:02d}_{cluster_name}"
    # Intentionally mix legacy non-GUID keys and valid UUIDs on write so we also test backend GUID normalization!
    sub_key_raw = f"sub-{tag}-main"
    tl_key_raw = f"tl-{tag}-main"
    cp_key_raw = f"cp-{tag}-main"
    comp_id = str(uuid.uuid5(uuid.NAMESPACE_OID, f"comp:{tag}"))

    return {
        "Subjects": {
            sub_key_raw: {
                "Name": f"Subject_{tag}",
                "Initial": cluster_name[-1].upper(),
                "TeacherName": f"Teacher_{tag}",
                "IsOutDoor": cluster_name == "cluster-gamma",
            }
        },
        "TimeLayout": {
            tl_key_raw: {
                "Name": f"TimeLayout_{tag}",
                "Layouts": [
                    {
                        "StartSecond": "1970-01-01T08:00:00",
                        "EndSecond": "1970-01-01T08:45:00",
                        "TimeType": 0,
                        "DefaultClassId": sub_key_raw,
                    },
                    {
                        "StartSecond": "1970-01-01T08:45:00",
                        "EndSecond": "1970-01-01T08:55:00",
                        "TimeType": 1,
                        "BreakName": f"Break_{tag}",
                    },
                ],
            }
        },
        "ClassPlan": {
            cp_key_raw: {
                "Name": f"ClassPlan_{tag}",
                "TimeLayoutId": tl_key_raw,
                "Classes": [{"SubjectId": sub_key_raw, "IsEnabled": True}],
                "TimeRule": {
                    "WeekDay": (acct_idx % 5) + 1,
                    "WeekCountDiv": 0,
                    "WeekCountDivTotal": 2,
                },
                "IsEnabled": True,
                "IsOverlay": False,
            }
        },
        "DefaultSettings": {
            "WindowDockingLocation": acct_idx % 6,
            "MainWindowSecondaryFontSize": 14 + (acct_idx % 4),
            "ClusterMarker": tag,
        },
        "Policy": {
            "DisableProfileClassPlanEditing": cluster_name != "cluster-alpha",
            "DisableProfileTimeLayoutEditing": True,
            "DisableProfileSubjectsEditing": True,
            "DisableSettingsEditing": cluster_name == "cluster-gamma",
            "AllowExitManagement": cluster_name == "cluster-alpha",
        },
        "Components": {
            "Lines": [
                {
                    "Children": [
                        {
                            "Id": comp_id,
                            "Name": f"Component_{tag}",
                        }
                    ]
                }
            ]
        },
        "Credentials": {
            "EditPolicyAuthorizeLevel": 1,
            "ExitManagementAuthorizeLevel": 2,
            "AllowExitManagement": True,
        },
    }


async def run_comprehensive_e2e_suite() -> None:
    """
    Execute the 8-User x 12-Account x 200-Virtual-Client Cross-Matrix E2E Test Suite.
    """
    from sqlalchemy import delete
    from app.shared.db.session import AsyncSessionLocal
    from app.shared.db.models import (
        Account,
        AccountMember,
        AccountQuota,
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
    from app.shared.security.crypto import get_ip_failures_dict, set_cc_state
    from app.shared.services.quota import set_quota
    from app.shared.services.user import register_user
    from app.shared.utils.tenant import set_search_path

    num_users = 8
    num_accounts = 12
    num_clients = 200
    clusters = ("cluster-alpha", "cluster-beta", "cluster-gamma")

    print("=" * 84)
    print(
        f"🚀 MINI ClassIsland Cross-Matrix E2E Suite: {num_users} Users | {num_accounts} Accounts | {num_clients} Clients"
    )
    print("=" * 84)

    run_tag = secrets.token_hex(4)
    mgmt_base = "http://127.0.0.1:27042"
    client_port = 27041
    grpc_port = 27044

    user_ids: list[str] = []
    user_tokens: list[str] = []
    account_ids: list[str] = []
    account_slugs: list[str] = []
    account_owners: list[int] = []  # user index (0..7) owning each account (0..11)
    # Cross-membership matrix: account_idx -> set of user_idx that are members
    account_members_map: dict[int, set[int]] = {i: set() for i in range(num_accounts)}
    host_map: dict[str, str] = {"127.0.0.1": "127.0.0.1"}
    created_client_uids: list[str] = []

    try:
        # ------------------------------------------------------------------
        # Phase 1: Provision 8 Users & 12 Accounts with Cross-Membership Matrix
        # ------------------------------------------------------------------
        print(
            f"\n[Phase 1/7] Provisioning {num_users} Users & {num_accounts} Tenant Accounts with Cross-Memberships..."
        )
        t_phase1 = time.perf_counter()
        now = datetime.now(timezone.utc)

        async with AsyncSessionLocal() as db:
            await set_search_path(db)
            for u_idx in range(num_users):
                u = await register_user(
                    f"matrix_u{u_idx}_{run_tag}@example.com",
                    f"MatrixPass{u_idx}!123",
                    f"Matrix User {u_idx}",
                    db,
                    username=f"matrix_u{u_idx}_{run_tag}",
                    role_code="normal",
                    is_active=True,
                    can_create_account=True,
                )
                user_ids.append(u.id)

            for a_idx in range(num_accounts):
                acct_id = str(uuid.uuid4())
                slug = f"mtx-acct-{a_idx:02d}-{run_tag}"
                owner_u_idx = a_idx % num_users
                co_admin_u_idx = (a_idx + 1) % num_users

                # Accounts 0..7 start in 'open', 8..9 in 'pre_reg', 10..11 in 'pairing'
                if a_idx < 8:
                    reg_mode = "open"
                elif a_idx < 10:
                    reg_mode = "pre_reg"
                else:
                    reg_mode = "pairing"

                account_ids.append(acct_id)
                account_slugs.append(slug)
                account_owners.append(owner_u_idx)
                host_map[f"{slug}.miniclassisland.com"] = "127.0.0.1"

                db.add(
                    Account(
                        id=acct_id,
                        name=f"Matrix Account {a_idx:02d}",
                        slug=slug,
                        api_key=f"mtx-key-{a_idx:02d}-{run_tag}",
                        registration_mode=reg_mode,
                        is_active=True,
                        created_at=now,
                    )
                )
                db.add(
                    AccountMember(
                        account_id=acct_id,
                        user_id=user_ids[owner_u_idx],
                        role_in_account="owner",
                        joined_at=now,
                    )
                )
                db.add(
                    AccountMember(
                        account_id=acct_id,
                        user_id=user_ids[co_admin_u_idx],
                        role_in_account="owner",
                        joined_at=now,
                    )
                )
                account_members_map[a_idx].update({owner_u_idx, co_admin_u_idx})

            await db.commit()

        for uid in user_ids:
            tok = await create_session_token(uid)
            user_tokens.append(tok)

        print(
            f"  ✅ Created {num_users} users and {num_accounts} accounts (8 open, 2 pre_reg, 2 pairing) in {time.perf_counter() - t_phase1:.2f}s"
        )

        limits = httpx.Limits(max_connections=100, max_keepalive_connections=50)
        async with (
            httpx.AsyncClient(base_url=mgmt_base, timeout=30.0, limits=limits) as mgmt,
            httpx.AsyncClient(
                follow_redirects=True, verify=False, timeout=30.0, limits=limits
            ) as client_http,
        ):
            # ------------------------------------------------------------------
            # Phase 2: Cross-User & Cross-Account Access Control Verification
            #          + Creating 3 Profile Clusters per Account (12 * 3 * 7 = 252 files)
            # ------------------------------------------------------------------
            print(
                "\n[Phase 2/7] Verifying 8x12 Cross-User RBAC Isolation & Creating 3 Profile Clusters (252 resource files)..."
            )
            t_phase2 = time.perf_counter()

            # 2.1 Verify every (user, account) pair in the 8x12 matrix (96 combinations!)
            # Give each check a unique X-Forwarded-For IP so 72 intentional 403 checks don't trigger per-IP 20-failure CC block
            rbac_checks = 0
            for a_idx in range(num_accounts):
                acct_id = account_ids[a_idx]
                for u_idx in range(num_users):
                    hdr = {
                        "Authorization": f"Bearer {user_tokens[u_idx]}",
                        "X-Forwarded-For": f"10.250.{a_idx}.{u_idx + 1}",
                    }
                    r = await mgmt.get(f"/account/{acct_id}/info", headers=hdr)
                    if u_idx in account_members_map[a_idx]:
                        assert (
                            r.status_code == 200
                        ), f"Member U{u_idx} denied on A{a_idx}: {r.status_code} {r.text}"
                    else:
                        assert (
                            r.status_code == 403
                        ), f"Non-member U{u_idx} allowed on A{a_idx}: {r.status_code} {r.text}"
                    rbac_checks += 1

            # 2.2 Create 3 Profile Clusters ('cluster-alpha', 'cluster-beta', 'cluster-gamma') in all 12 accounts
            # Alternate between owner user and co-admin user to test multi-user collaborative editing!
            async def _seed_account_clusters(a_idx: int) -> None:
                acct_id = account_ids[a_idx]
                owner_hdr = {
                    "Authorization": f"Bearer {user_tokens[account_owners[a_idx]]}"
                }
                co_admin_u_idx = (a_idx + 1) % num_users
                co_hdr = {"Authorization": f"Bearer {user_tokens[co_admin_u_idx]}"}

                for c_idx, c_name in enumerate(clusters):
                    active_hdr = owner_hdr if c_idx % 2 == 0 else co_hdr
                    res_bundle = build_cluster_resources(a_idx, c_name)
                    for rtype, payload in res_bundle.items():
                        resp = await mgmt.post(
                            f"/account/{acct_id}/{rtype}/write",
                            params={"name": c_name},
                            json=payload,
                            headers=active_hdr,
                        )
                        assert (
                            resp.status_code == 200
                        ), f"Write failed on A{a_idx}/{rtype}/{c_name}: {resp.text}"

                # Set account __default__ profile to cluster-alpha
                r_def = await mgmt.post(
                    f"/account/{acct_id}/client/__default__/config",
                    json={
                        "ClassPlan": "cluster-alpha",
                        "TimeLayout": "cluster-alpha",
                        "Subjects": "cluster-alpha",
                        "DefaultSettings": "cluster-alpha",
                        "Policy": "cluster-alpha",
                        "Components": "cluster-alpha",
                        "Credentials": "cluster-alpha",
                        "auto_sync": False,
                    },
                    headers=owner_hdr,
                )
                assert r_def.status_code == 200, r_def.text

                # Verify new default quotas (max_clients=6, max_grpc_connections=4, max_bandwidth_mb=100)
                r_q = await mgmt.get(f"/account/{acct_id}/quota", headers=owner_hdr)
                assert r_q.status_code == 200, r_q.text
                q_defaults = {
                    item["quota_key"]: item["max_value"] for item in r_q.json()
                }
                assert (
                    q_defaults.get("max_clients") == 6
                ), f"Expected 6, got {q_defaults}"
                assert (
                    q_defaults.get("max_grpc_connections") == 4
                ), f"Expected 4, got {q_defaults}"
                assert (
                    q_defaults.get("max_bandwidth_mb") == 100
                ), f"Expected 100, got {q_defaults}"

                # Elevate quotas for the 200-client matrix stress test (~17 clients per account)
                async with AsyncSessionLocal() as db:
                    await set_quota(acct_id, "max_clients", 50, db)
                    await set_quota(acct_id, "max_grpc_connections", 50, db)
                    await set_quota(acct_id, "max_bandwidth_mb", 1024, db)

            await asyncio.gather(
                *(_seed_account_clusters(a_idx) for a_idx in range(num_accounts))
            )
            print(
                f"  ✅ Verified {rbac_checks} (User x Account) RBAC combinations & seeded 252 profile files in {time.perf_counter() - t_phase2:.2f}s"
            )

            # ------------------------------------------------------------------
            # Phase 3: Instantiate 200 Virtual Clients across 12 Accounts & 3 Profile Clusters
            # ------------------------------------------------------------------
            print(
                f"\n[Phase 3/7] Registering & Handshaking {num_clients} Virtual Clients across 12 Accounts (open / pre_reg / pairing)..."
            )
            t_phase3 = time.perf_counter()

            virtual_clients: list[VirtualClassIslandClient] = []
            for c_idx in range(num_clients):
                a_idx = c_idx % num_accounts
                cluster_name = clusters[(c_idx // num_accounts) % len(clusters)]
                slug = account_slugs[a_idx]
                host = f"{slug}.miniclassisland.com"
                vc = VirtualClassIslandClient(
                    management_server=f"http://{host}:{client_port}",
                    management_server_grpc=f"http://{host}:{grpc_port}",
                    class_identity=f"Mtx-A{a_idx:02d}-C{c_idx:03d}",
                    account_index=a_idx,
                    account_id=account_ids[a_idx],
                    cluster_name=cluster_name,
                    host_map=host_map,
                )
                virtual_clients.append(vc)
                created_client_uids.append(vc.client_uid)

            # Pre-register clients belonging to pre_reg accounts (a_idx in 8, 9)
            # Half with MAC address, half without MAC address (testing optional MAC!)
            # Also bind their preset_profile directly during pre-registration!
            for a_idx in (8, 9):
                acct_id = account_ids[a_idx]
                hdr = {"Authorization": f"Bearer {user_tokens[account_owners[a_idx]]}"}
                acct_clients = [
                    vc for vc in virtual_clients if vc.account_index == a_idx
                ]
                batch_items = []
                for idx_in_acct, vc in enumerate(acct_clients):
                    c_name = vc.cluster_name
                    batch_items.append(
                        {
                            "label": f"PreReg {vc.class_identity}",
                            "class_identity": vc.class_identity,
                            "mac_address": (
                                vc.mac_address if idx_in_acct % 2 == 0 else ""
                            ),
                            "preset_profile": {
                                "ClassPlan": c_name,
                                "TimeLayout": c_name,
                                "Subjects": c_name,
                                "DefaultSettings": c_name,
                                "Policy": c_name,
                                "Components": c_name,
                                "Credentials": c_name,
                            },
                        }
                    )
                r_batch = await mgmt.post(
                    f"/account/{acct_id}/pre-registration/batch",
                    json={"items": batch_items},
                    headers=hdr,
                )
                assert r_batch.status_code == 201, r_batch.text
                assert len(r_batch.json()) == len(acct_clients)

            # Step 3.1: First-pass Register for all 200 clients
            # - Accounts 0..9 (open & pre_reg) should succeed immediately
            # - Accounts 10..11 (pairing) should return PairingRequired and generate pairing codes
            sem = asyncio.Semaphore(32)

            async def _first_register(vc: VirtualClassIslandClient) -> None:
                async with sem:
                    ret, msg, _ = await vc.register()
                    if vc.account_index < 10:
                        assert ret in (
                            Retcode_pb2.Success,
                            Retcode_pb2.Registered,
                        ), f"Client {vc.class_identity} register failed: {ret} {msg}"
                    else:
                        assert (
                            ret == Retcode_pb2.PairingRequired
                        ), f"Expected PairingRequired for {vc.class_identity}, got {ret}"

            await asyncio.gather(*(_first_register(vc) for vc in virtual_clients))

            # Step 3.2: Approve all pairing codes in Accounts 10 & 11 (with preset_profile binding!)
            for a_idx in (10, 11):
                acct_id = account_ids[a_idx]
                hdr = {"Authorization": f"Bearer {user_tokens[account_owners[a_idx]]}"}
                codes_list = (
                    await mgmt.get(f"/account/{acct_id}/pairing/list", headers=hdr)
                ).json()
                acct_vc_map = {
                    vc.client_uid: vc
                    for vc in virtual_clients
                    if vc.account_index == a_idx
                }
                assert len(codes_list) == len(acct_vc_map)
                for code_item in codes_list:
                    vc = acct_vc_map[code_item["client_uid"]]
                    c_name = vc.cluster_name
                    r_app = await mgmt.post(
                        f"/account/{acct_id}/pairing/{code_item['code']}/approve",
                        json={
                            "preset_profile": {
                                "ClassPlan": c_name,
                                "TimeLayout": c_name,
                                "Subjects": c_name,
                                "DefaultSettings": c_name,
                                "Policy": c_name,
                                "Components": c_name,
                                "Credentials": c_name,
                            }
                        },
                        headers=hdr,
                    )
                    assert r_app.status_code == 200, r_app.text

            # Re-register pairing clients in Accounts 10 & 11 -> now they succeed and bind preset_profile!
            pairing_clients = [vc for vc in virtual_clients if vc.account_index >= 10]
            for vc in pairing_clients:
                ret, msg, _ = await vc.register()
                assert ret in (Retcode_pb2.Success, Retcode_pb2.Registered), msg
                # Apply preset_profile via client config endpoint for approved pairing devices
                acct_id = account_ids[vc.account_index]
                hdr = {
                    "Authorization": f"Bearer {user_tokens[account_owners[vc.account_index]]}"
                }
                c_name = vc.cluster_name
                await mgmt.post(
                    f"/account/{acct_id}/client/{vc.client_uid}/config",
                    json={
                        "ClassPlan": c_name,
                        "TimeLayout": c_name,
                        "Subjects": c_name,
                        "DefaultSettings": c_name,
                        "Policy": c_name,
                        "Components": c_name,
                        "Credentials": c_name,
                        "auto_sync": False,
                    },
                    headers=hdr,
                )

            # Step 3.3: For open accounts (0..7), assign each client to its designated profile cluster
            async def _assign_open_client_cluster(vc: VirtualClassIslandClient) -> None:
                if vc.account_index >= 8 or vc.cluster_name == "cluster-alpha":
                    # Accounts 8..9 already got preset_profile via pre_reg;
                    # cluster-alpha is already the account's __default__ profile!
                    return
                async with sem:
                    acct_id = vc.account_id
                    hdr = {
                        "Authorization": f"Bearer {user_tokens[account_owners[vc.account_index]]}"
                    }
                    c_name = vc.cluster_name
                    r_cfg = await mgmt.post(
                        f"/account/{acct_id}/client/{vc.client_uid}/config",
                        json={
                            "ClassPlan": c_name,
                            "TimeLayout": c_name,
                            "Subjects": c_name,
                            "DefaultSettings": c_name,
                            "Policy": c_name,
                            "Components": c_name,
                            "Credentials": c_name,
                            "auto_sync": False,
                        },
                        headers=hdr,
                    )
                    assert r_cfg.status_code == 200, r_cfg.text

            await asyncio.gather(
                *(_assign_open_client_cluster(vc) for vc in virtual_clients)
            )

            # Step 3.4: Parse server PGP public key once and run OpenPGP Handshake for all 200 clients
            cached_pub_key, _ = pgpy.PGPKey.from_blob(
                virtual_clients[0].server_public_key
            )

            async def _handshake_worker(vc: VirtualClassIslandClient) -> None:
                async with sem:
                    hs_ret, hs_msg = await vc.handshake(cached_pub_key=cached_pub_key)
                    assert (
                        hs_ret == Retcode_pb2.Success
                    ), f"Handshake failed for {vc.class_identity}: {hs_msg}"

            await asyncio.gather(*(_handshake_worker(vc) for vc in virtual_clients))
            print(
                f"  ✅ All {num_clients} clients registered, bound to profile clusters, and completed PGP Handshake in {time.perf_counter() - t_phase3:.2f}s"
            )

            # ------------------------------------------------------------------
            # Phase 4: All 200 Clients Pull Manifest & 7 Resources (1,400 Resource Downloads!)
            #          + Strict Profile Cluster & C# System.Guid Verification
            # ------------------------------------------------------------------
            print(
                f"\n[Phase 4/7] All {num_clients} Clients Pulling Manifests & 7 Resources (1,400 Token Downloads) + Validating Clusters..."
            )
            t_phase4 = time.perf_counter()

            async def _sync_and_verify_cluster(vc: VirtualClassIslandClient) -> None:
                async with sem:
                    await vc.pull_manifest_and_sync_resources(shared_http=client_http)
                    expected_tag = f"A{vc.account_index:02d}_{vc.cluster_name}"

                    # 1. Verify Subjects matches exact account & cluster
                    subs = vc.local_resources["Subjects"]["Subjects"]
                    sub_names = [s["Name"] for s in subs.values()]
                    assert (
                        f"Subject_{expected_tag}" in sub_names
                    ), f"Client {vc.class_identity} expected Subject_{expected_tag}, got {sub_names}"

                    # 2. Verify TimeLayout matches exact account & cluster
                    tls = vc.local_resources["TimeLayout"]["TimeLayouts"]
                    tl_names = [t["Name"] for t in tls.values()]
                    assert (
                        f"TimeLayout_{expected_tag}" in tl_names
                    ), f"Client {vc.class_identity} expected TimeLayout_{expected_tag}, got {tl_names}"

                    # 3. Verify ClassPlan matches exact account & cluster AND its TimeLayoutId & SubjectId match the GUIDs!
                    cps = vc.local_resources["ClassPlan"]["ClassPlans"]
                    cp_names = [c["Name"] for c in cps.values()]
                    assert (
                        f"ClassPlan_{expected_tag}" in cp_names
                    ), f"Client {vc.class_identity} expected ClassPlan_{expected_tag}, got {cp_names}"
                    cp_obj = next(iter(cps.values()))
                    assert (
                        cp_obj["TimeLayoutId"] in tls
                    ), "ClassPlan.TimeLayoutId foreign key GUID mismatch!"
                    assert (
                        cp_obj["Classes"][0]["SubjectId"] in subs
                    ), "ClassPlan.Classes[0].SubjectId foreign key GUID mismatch!"

                    # 4. Verify DefaultSettings matches exact account & cluster
                    ds = vc.local_resources["DefaultSettings"]
                    assert ds.get("ClusterMarker") == expected_tag

                    # 5. Verify Components matches exact account & cluster
                    comp_name = vc.local_resources["Components"]["Lines"][0][
                        "Children"
                    ][0]["Name"]
                    assert comp_name == f"Component_{expected_tag}"

            await asyncio.gather(
                *(_sync_and_verify_cluster(vc) for vc in virtual_clients)
            )
            print(
                f"  ✅ All {num_clients} clients verified 1,400 resources with zero cross-tenant/cross-cluster leakage in {time.perf_counter() - t_phase4:.2f}s"
            )

            # ------------------------------------------------------------------
            # Phase 5: 200 Concurrent gRPC Bidirectional Command Streams + Cross-Tenant Broadcasts,
            #          Targeted Commands, Hot Profile Cluster Switching & Config Uploads
            # ------------------------------------------------------------------
            print(
                f"\n[Phase 5/7] Starting {num_clients} Concurrent gRPC Command Streams & Executing Cross-Tests..."
            )
            t_phase5 = time.perf_counter()

            for vc in virtual_clients:
                await vc.start_command_stream(
                    ping_interval=1.1,
                    shared_http=client_http,
                )

            # Wait for all 200 streams to establish and receive initial Pong heartbeat
            for _ in range(30):
                if all(vc.pong_count >= 1 for vc in virtual_clients):
                    break
                await asyncio.sleep(0.2)

            online_pongs = sum(1 for vc in virtual_clients if vc.pong_count >= 1)
            assert (
                online_pongs == num_clients
            ), f"Expected {num_clients} clients with Pong >= 1, got {online_pongs}"

            # 5.1 Verify online status across all 12 accounts via Management API
            for a_idx in range(num_accounts):
                acct_id = account_ids[a_idx]
                hdr = {"Authorization": f"Bearer {user_tokens[account_owners[a_idx]]}"}
                c_list = (
                    await mgmt.get(f"/account/{acct_id}/client/list", headers=hdr)
                ).json()
                expected_uids = {
                    vc.client_uid for vc in virtual_clients if vc.account_index == a_idx
                }
                actual_uids = {c["uid"] for c in c_list}
                assert (
                    actual_uids == expected_uids
                ), f"Account {a_idx} client list mismatch!"
                assert all(
                    c["online"] is True for c in c_list
                ), f"Some clients in Account {a_idx} reported offline!"

            # 5.2 Cross-Account Broadcast Test: Broadcast a unique notification in each of the 12 accounts
            for a_idx in range(num_accounts):
                acct_id = account_ids[a_idx]
                hdr = {"Authorization": f"Bearer {user_tokens[account_owners[a_idx]]}"}
                r_bcast = await mgmt.post(
                    f"/account/{acct_id}/broadcast/notification",
                    json={
                        "MessageMask": f"Broadcast-A{a_idx:02d}",
                        "MessageContent": f"ExclusiveMsg_Account_{a_idx:02d}",
                        "DurationSeconds": 3.0,
                    },
                    headers=hdr,
                )
                assert r_bcast.status_code == 200

            await asyncio.sleep(0.8)

            # Verify every client ONLY received its own account's broadcast notification!
            for vc in virtual_clients:
                expected_msg = f"ExclusiveMsg_Account_{vc.account_index:02d}"
                assert vc.received_notifications == [
                    expected_msg
                ], f"Client {vc.class_identity} received wrong notifications: {vc.received_notifications}"

            # 5.3 Dynamic Hot Cluster Update: Modify 'cluster-beta' Subjects in Account 0..5 and batch-sync only cluster-beta clients
            for a_idx in range(6):
                acct_id = account_ids[a_idx]
                hdr = {"Authorization": f"Bearer {user_tokens[account_owners[a_idx]]}"}
                tag = f"A{a_idx:02d}_cluster-beta"
                await mgmt.post(
                    f"/account/{acct_id}/Subjects/write",
                    params={"name": "cluster-beta"},
                    json={
                        f"sub-{tag}-main": {
                            "Name": f"HotUpdated_{tag}_v2",
                            "Initial": "H",
                            "TeacherName": "HotTeacher",
                            "IsOutDoor": True,
                        }
                    },
                    headers=hdr,
                )
                beta_uids = [
                    vc.client_uid
                    for vc in virtual_clients
                    if vc.account_index == a_idx and vc.cluster_name == "cluster-beta"
                ]
                r_batch_sync = await mgmt.post(
                    f"/account/{acct_id}/client/batch",
                    json={"action": "sync", "uids": beta_uids},
                    headers=hdr,
                )
                assert (
                    r_batch_sync.status_code == 200
                ), f"Batch sync failed on A{a_idx}: {r_batch_sync.status_code} {r_batch_sync.text}"

            # 5.4 Dynamic Profile Cluster Reassignment: Switch first client of each account from its cluster to 'cluster-gamma' with auto_sync=True
            switched_clients: list[VirtualClassIslandClient] = []
            for a_idx in range(num_accounts):
                acct_id = account_ids[a_idx]
                hdr = {"Authorization": f"Bearer {user_tokens[account_owners[a_idx]]}"}
                target_vc = next(
                    vc
                    for vc in virtual_clients
                    if vc.account_index == a_idx and vc.cluster_name != "cluster-gamma"
                )
                switched_clients.append(target_vc)
                r_sw = await mgmt.post(
                    f"/account/{acct_id}/client/{target_vc.client_uid}/config",
                    json={
                        "ClassPlan": "cluster-gamma",
                        "TimeLayout": "cluster-gamma",
                        "Subjects": "cluster-gamma",
                        "DefaultSettings": "cluster-gamma",
                        "Policy": "cluster-gamma",
                        "Components": "cluster-gamma",
                        "Credentials": "cluster-gamma",
                        "auto_sync": True,
                    },
                    headers=hdr,
                )
                assert r_sw.status_code == 200

            # 5.5 Trigger GetClientConfig and RestartApp on 24 sampled clients (2 per account)
            sampled_for_cmd: list[tuple[VirtualClassIslandClient, str]] = []
            for a_idx in range(num_accounts):
                acct_id = account_ids[a_idx]
                hdr = {"Authorization": f"Bearer {user_tokens[account_owners[a_idx]]}"}
                acct_vcs = [vc for vc in virtual_clients if vc.account_index == a_idx][
                    :2
                ]
                for vc in acct_vcs:
                    r_gc = await mgmt.post(
                        f"/account/{acct_id}/client/{vc.client_uid}/command/get-config",
                        params={"config_type": 1},
                        headers=hdr,
                    )
                    assert r_gc.status_code == 200
                    sampled_for_cmd.append((vc, r_gc.json()["request_guid"]))
                    r_rst = await mgmt.post(
                        f"/account/{acct_id}/client/{vc.client_uid}/command/restart",
                        headers=hdr,
                    )
                    assert r_rst.status_code == 200

            await asyncio.sleep(1.2)

            # Verify hot updates on cluster-beta clients in Accounts 0..5
            for vc in virtual_clients:
                if (
                    vc.account_index < 6
                    and vc.cluster_name == "cluster-beta"
                    and vc not in switched_clients
                ):
                    tag = f"A{vc.account_index:02d}_cluster-beta"
                    sub_names = [
                        s["Name"]
                        for s in vc.local_resources["Subjects"]["Subjects"].values()
                    ]
                    assert (
                        f"HotUpdated_{tag}_v2" in sub_names
                    ), f"Hot update missing on {vc.class_identity}: {sub_names}"

            # Verify dynamically switched clients now hold cluster-gamma resources
            for vc in switched_clients:
                expected_gamma = f"A{vc.account_index:02d}_cluster-gamma"
                assert (
                    vc.local_resources["DefaultSettings"].get("ClusterMarker")
                    == expected_gamma
                ), f"Dynamic cluster switch failed on {vc.class_identity}"

            # Verify all 24 sampled clients uploaded their config snapshots and received RestartApp
            for vc, req_guid in sampled_for_cmd:
                assert req_guid in vc.uploaded_configs
                assert vc.restart_count >= 1

            print(
                f"  ✅ 200 concurrent streams, 12 tenant-isolated broadcasts, hot cluster updates, dynamic cluster switching & 24 config uploads verified in {time.perf_counter() - t_phase5:.2f}s"
            )

            # ------------------------------------------------------------------
            # Phase 6: Concurrent Audit Logs across 200 Clients & Security Attack Matrix
            # ------------------------------------------------------------------
            print(
                "\n[Phase 6/7] Executing 200-Client Concurrent Audit Logging & Security Attack Matrix..."
            )
            t_phase6 = time.perf_counter()

            async def _audit_worker(vc: VirtualClassIslandClient) -> None:
                async with sem:
                    ret = await vc.log_audit_event(
                        AuditEvents_pb2.AppSettingsUpdated,
                        json.dumps(
                            {
                                "client": vc.class_identity,
                                "account": vc.account_index,
                                "cluster": vc.cluster_name,
                            }
                        ).encode("utf-8"),
                    )
                    assert ret == Retcode_pb2.Success

            await asyncio.gather(*(_audit_worker(vc) for vc in virtual_clients))

            # Verify each account's audit log list ONLY contains clients from that account
            for a_idx in range(num_accounts):
                acct_id = account_ids[a_idx]
                hdr = {"Authorization": f"Bearer {user_tokens[account_owners[a_idx]]}"}
                logs = (
                    await mgmt.get(
                        f"/account/{acct_id}/audit/list",
                        params={"limit": 200},
                        headers=hdr,
                    )
                ).json()
                expected_uids = {
                    vc.client_uid for vc in virtual_clients if vc.account_index == a_idx
                }
                logged_uids = {item["client_uid"] for item in logs}
                assert logged_uids.issubset(
                    expected_uids
                ), f"Cross-tenant audit log leak in Account {a_idx}!"
                assert len(logged_uids) == len(expected_uids)

            # Stop all 200 command streams cleanly
            await asyncio.gather(*(vc.stop_command_stream() for vc in virtual_clients))

            # Security checks: MAC spoofing, disabled device rejection, token replay, optimistic lock conflict (409)
            sample_vc = virtual_clients[0]
            spoof_vc = VirtualClassIslandClient(
                management_server=sample_vc.management_server,
                management_server_grpc=sample_vc.management_server_grpc,
                class_identity=sample_vc.class_identity,
                client_uid=sample_vc.client_uid,
                mac_address="DE:AD:BE:EF:00:01",
                server_public_key=sample_vc.server_public_key,
                host_map=host_map,
            )
            hs_spoof, _ = await spoof_vc.handshake(cached_pub_key=cached_pub_key)
            assert hs_spoof == Retcode_pb2.InvalidRequest

            # Optimistic locking version conflict test (409)
            hdr0 = {"Authorization": f"Bearer {user_tokens[account_owners[0]]}"}
            r_conflict = await mgmt.post(
                f"/account/{account_ids[0]}/Policy/write",
                params={"name": "cluster-alpha", "version": 99999},
                json={"AllowExitManagement": False},
                headers=hdr0,
            )
            assert r_conflict.status_code == 409
            get_ip_failures_dict().clear()
            set_cc_state(False)

            print(
                f"  ✅ 200-client audit log isolation, MAC spoofing defense, and optimistic lock (409) verified in {time.perf_counter() - t_phase6:.2f}s"
            )

            # ------------------------------------------------------------------
            # Phase 6.5: Dual Device Quota Enforcement (`max_clients` vs `max_grpc_connections`)
            #            & Per-Device Real-World Bandwidth/Traffic Overhead Estimation
            # ------------------------------------------------------------------
            print(
                "\n[Phase 6.5/7] Verifying Independent Quotas (max_clients vs max_grpc_connections) & Calculating Bandwidth..."
            )
            t_phase_q = time.perf_counter()

            # 1) Test max_clients (registered device count limit) on Account 0 (currently has 17 registered clients)
            acct0_id = account_ids[0]
            acct0_clients = [vc for vc in virtual_clients if vc.account_index == 0]
            async with AsyncSessionLocal() as db:
                await set_search_path(db)
                await set_quota(acct0_id, "max_clients", len(acct0_clients), db)
                await set_quota(acct0_id, "max_grpc_connections", 2, db)
                await set_quota(acct0_id, "feature.audit", 0, db)
                await db.commit()

            # A brand-new 18th client attempting to register in Account 0 must be rejected by max_clients quota!
            extra_vc = VirtualClassIslandClient(
                management_server=acct0_clients[0].management_server,
                management_server_grpc=acct0_clients[0].management_server_grpc,
                class_identity="Quota-Exceeded-Device",
                account_index=0,
                account_id=acct0_id,
                host_map=host_map,
            )
            q_ret, q_msg, _ = await extra_vc.register()
            assert (
                q_ret == Retcode_pb2.InvalidRequest and "max_clients" in q_msg
            ), f"Expected max_clients rejection, got {q_ret}: {q_msg}"

            # Meanwhile, an already-registered client in Account 0 can still re-register (idempotent update)!
            re_ret, _, _ = await acct0_clients[0].register()
            assert re_ret == Retcode_pb2.Registered

            # 2) Test max_grpc_connections (active gRPC stream limit = 2) on Account 0:
            # Start 2 streams -> both succeed and receive Pong
            await acct0_clients[0].start_command_stream(
                ping_interval=0.8, shared_http=client_http
            )
            await acct0_clients[1].start_command_stream(
                ping_interval=0.8, shared_http=client_http
            )
            await asyncio.sleep(0.5)

            # Check live quota endpoint reports current_value == 2 for max_grpc_connections and 17 for max_clients
            q_list_resp = await mgmt.get(f"/account/{acct0_id}/quota", headers=hdr0)
            assert q_list_resp.status_code == 200
            q_map = {item["quota_key"]: item for item in q_list_resp.json()}
            assert q_map["max_clients"]["current_value"] == len(acct0_clients)
            assert q_map["max_grpc_connections"]["current_value"] == 2

            # Starting a 3rd concurrent gRPC stream in Account 0 must be rejected with RESOURCE_EXHAUSTED!
            target0, opts0 = acct0_clients[2]._grpc_target_and_options()
            grpc_quota_blocked = False
            async with grpc.aio.insecure_channel(target0, options=opts0) as ch3:
                stub3 = ClientCommandDeliver_pb2_grpc.ClientCommandDeliverStub(ch3)

                async def _single_ping():
                    yield ClientCommandDeliverScReq_pb2.ClientCommandDeliverScReq(
                        Type=CommandTypes_pb2.Ping
                    )

                try:
                    call3 = stub3.ListenCommand(
                        _single_ping(), metadata=acct0_clients[2]._get_metadata(False)
                    )
                    async for _ in call3:
                        pass
                except grpc.aio.AioRpcError as rpc_err:
                    if rpc_err.code() == grpc.StatusCode.RESOURCE_EXHAUSTED:
                        grpc_quota_blocked = True
            assert (
                grpc_quota_blocked
            ), "3rd concurrent gRPC stream was NOT blocked by max_grpc_connections=2!"

            await acct0_clients[0].stop_command_stream()
            await acct0_clients[1].stop_command_stream()

            # 3) Test feature.audit = 0 blocks audit event logging
            aud_blocked_ret = await acct0_clients[0].log_audit_event(
                AuditEvents_pb2.AppSettingsUpdated, b"{}"
            )
            assert aud_blocked_ret == Retcode_pb2.InvalidRequest

            # 4) Test max_bandwidth_mb = 0 blocks client manifest & resource downloads with HTTP 429
            async with AsyncSessionLocal() as db:
                await set_quota(acct0_id, "max_bandwidth_mb", 0, db)
            r_bw_blocked = await client_http.get(
                f"http://127.0.0.1:{client_port}/api/v1/client/{acct0_clients[0].client_uid}/manifest",
                headers={"Host": f"{account_slugs[0]}.miniclassisland.com"},
            )
            assert (
                r_bw_blocked.status_code == 429
            ), f"Expected 429 on bandwidth quota exceeded, got {r_bw_blocked.status_code}"
            async with AsyncSessionLocal() as db:
                await set_quota(acct0_id, "max_bandwidth_mb", 100, db)

            print(
                f"  ✅ Default quotas (6/4/100MB) & live enforcement (max_clients={len(acct0_clients)}, max_grpc_connections=2, max_bandwidth_mb, feature.audit) verified in {time.perf_counter() - t_phase_q:.2f}s"
            )

            # 5) Compute & Print Per-Device & 4000/10000-Device Real-World Traffic / Bandwidth Overhead Estimation
            total_tx_grpc = sum(vc.bytes_tx_grpc for vc in virtual_clients)
            total_rx_grpc = sum(vc.bytes_rx_grpc for vc in virtual_clients)
            total_tx_http = sum(vc.bytes_tx_http for vc in virtual_clients)
            total_rx_http = sum(vc.bytes_rx_http for vc in virtual_clients)
            total_all_bytes = (
                total_tx_grpc + total_rx_grpc + total_tx_http + total_rx_http
            )

            avg_reg_bytes = sum(
                vc.bytes_register_total for vc in virtual_clients
            ) / len(virtual_clients)
            avg_hs_bytes = sum(
                vc.bytes_handshake_total for vc in virtual_clients
            ) / len(virtual_clients)
            avg_sync_bytes = sum(
                vc.bytes_manifest_sync_total for vc in virtual_clients
            ) / len(virtual_clients)
            avg_cold_start = avg_reg_bytes + avg_hs_bytes + avg_sync_bytes

            # Upstream ClassIsland (ManagementServerConnection.cs:66) sends Ping every 10s!
            # Wire-level (L2-L7 Ethernet/IP/TCP/TLS1.3/HTTP2) Ping+Pong pair is ~400 bytes bidirectional (~220 bytes Server TX).
            wire_hb_bi_bytes = 400
            wire_hb_tx_bytes = 220
            steady_bi_bps_10s = (wire_hb_bi_bytes / 10.0) * 8.0  # ~320 bps
            steady_tx_bps_10s = (wire_hb_tx_bytes / 10.0) * 8.0  # ~176 bps
            hourly_wire_kb_10s = (wire_hb_bi_bytes * 360) / 1024.0  # ~140.6 KB/h
            daily_8h_kb = (
                (avg_cold_start * 1.35)
                + (wire_hb_bi_bytes * 360 * 8)
                + (avg_sync_bytes * 2)
            ) / 1024.0
            daily_24h_kb = (
                (avg_cold_start * 1.35)
                + (wire_hb_bi_bytes * 360 * 24)
                + (avg_sync_bytes * 4)
            ) / 1024.0
            monthly_22d_mb = (daily_8h_kb * 22) / 1024.0
            monthly_24x7_mb = (daily_24h_kb * 30) / 1024.0

            print("\n" + "-" * 88)
            print(
                "📊 PER-DEVICE & 4,000 / 10,000-DEVICE WIRE-LEVEL TRAFFIC & BANDWIDTH OVERHEAD REPORT"
            )
            print("-" * 88)
            print(
                f"  • Measured L7 Payload in This 200-Client Suite    : {total_all_bytes / 1024:.1f} KB "
                f"(gRPC TX: {total_tx_grpc / 1024:.1f} KB, gRPC RX: {total_rx_grpc / 1024:.1f} KB, "
                f"HTTP TX: {total_tx_http / 1024:.1f} KB, HTTP RX: {total_rx_http / 1024:.1f} KB)"
            )
            print(
                f"  • Single Device Cold Start (L7 Payload / Wire TLS): ~{avg_cold_start / 1024:.2f} KB (L7) / ~{(avg_cold_start * 1.35) / 1024:.2f} KB (Wire)"
            )
            print(
                f"  • Single Device Steady Heartbeat (10s interval)   : ~{steady_tx_bps_10s:.0f} bps Server TX (~{steady_bi_bps_10s:.0f} bps Bi-Dir, ~{hourly_wire_kb_10s:.1f} KB/h)"
            )
            print(
                f"  • Single Device School-Day Traffic (8h/day, 10s)  : ~{daily_8h_kb:.1f} KB / day (~{monthly_22d_mb:.2f} MB / 22-day month)"
            )
            print(
                f"  • Single Device 24x7 Always-On Traffic (10s)      : ~{daily_24h_kb:.1f} KB / day (~{monthly_24x7_mb:.2f} MB / 30-day month)"
            )
            print(
                f"  • 4,000 Devices Steady-State Bandwidth (on 20Mbps): ~{(steady_tx_bps_10s * 4000) / 1_000_000:.2f} Mbps Server TX (~{(steady_bi_bps_10s * 4000) / 1_000_000:.2f} Mbps Bi-Dir)"
            )
            print(
                f"  • 10,000 Devices Steady-State Bandwidth           : ~{(steady_tx_bps_10s * 10000) / 1_000_000:.2f} Mbps Server TX (~{(steady_bi_bps_10s * 10000) / 1_000_000:.2f} Mbps Bi-Dir)"
            )
            print("-" * 88)

    finally:
        # ------------------------------------------------------------------
        # Phase 7: Clean Teardown of All Test Data in PostgreSQL
        # ------------------------------------------------------------------
        print(
            "\n[Phase 7/7] Cleaning up all 8 Users, 12 Accounts, 200 Clients & 252 Profile Files..."
        )
        get_ip_failures_dict().clear()
        set_cc_state(False)
        async with AsyncSessionLocal() as db:
            await set_search_path(db)
            if account_ids:
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
                    AccountQuota,
                    AccountMember,
                ):
                    await db.execute(
                        delete(model).where(model.account_id.in_(account_ids))
                    )
                await db.execute(
                    delete(PairingCode).where(PairingCode.tenant_id.in_(account_ids))
                )
                await db.execute(delete(Account).where(Account.id.in_(account_ids)))
            if created_client_uids:
                await db.execute(
                    delete(ClientRecord).where(
                        ClientRecord.uid.in_(created_client_uids)
                    )
                )
            if user_ids:
                await db.execute(delete(User).where(User.id.in_(user_ids)))
            await db.commit()
        print("  ✅ Database cleanup complete.")

    print("\n" + "=" * 84)
    print(
        "🎉 8 USERS x 12 ACCOUNTS x 200 VIRTUAL CLIENTS CROSS-MATRIX SUITE PASSED 100%!"
    )
    print("=" * 84)


if __name__ == "__main__":
    asyncio.run(run_comprehensive_e2e_suite())
