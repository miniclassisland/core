"""Protobuf AuditEvent payload decoder for MINI ClassIsland."""

import json
from typing import Any
from google.protobuf.json_format import MessageToDict

from app.shared.literals import AUDIT_EVENT_NAMES


def decode_audit_payload(event: int, raw_bytes: bytes) -> dict[str, Any]:
    """Decode binary protobuf AuditEvent payload into a structured dictionary."""
    event_name = AUDIT_EVENT_NAMES.get(event, f"Event_{event}")
    result: dict[str, Any] = {"event": event, "event_name": event_name}
    if not raw_bytes:
        return result

    try:
        msg = None
        if event in (1, 2):
            from app.Protobuf.AuditEvent import AuthorizeEvent_pb2

            msg = AuthorizeEvent_pb2.AuthorizeEvent()
        elif event == 4:
            from app.Protobuf.AuditEvent import AppSettingsUpdated_pb2

            msg = AppSettingsUpdated_pb2.AppSettingsUpdated()
        elif event == 5:
            from app.Protobuf.AuditEvent import ClassChangeCompleted_pb2

            msg = ClassChangeCompleted_pb2.ClassChangeCompleted()
        elif event in (6, 7, 8):
            from app.Protobuf.AuditEvent import ProfileItemUpdated_pb2

            msg = ProfileItemUpdated_pb2.ProfileItemUpdated()
        elif event == 9:
            from app.Protobuf.AuditEvent import AppCrashed_pb2

            msg = AppCrashed_pb2.AppCrashed()
        elif event == 12:
            from app.Protobuf.AuditEvent import PluginInstalled_pb2

            msg = PluginInstalled_pb2.PluginInstalled()
        elif event == 13:
            from app.Protobuf.AuditEvent import PluginUninstalled_pb2

            msg = PluginUninstalled_pb2.PluginUninstalled()

        if msg is not None:
            msg.ParseFromString(raw_bytes)
            result["data"] = MessageToDict(
                msg,
                always_print_fields_with_no_presence=True,
                preserving_proto_field_name=True,
            )
    except Exception as exc:
        result["decode_error"] = str(exc)

    return result


def decode_audit_payload_json(event: int, raw_bytes: bytes) -> str:
    """Decode binary protobuf AuditEvent payload into a JSON string."""
    return json.dumps(decode_audit_payload(event, raw_bytes), ensure_ascii=False)
