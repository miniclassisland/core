"""Normalization helpers for plugin-reported component metadata."""

from typing import Any


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return False


def normalize_plugin_component_item(item: Any) -> dict[str, Any] | None:
    """Normalize a plugin-reported component entry across camelCase, PascalCase, and snake_case."""
    if not isinstance(item, dict):
        return None

    cid = str(
        item.get("id")
        or item.get("Id")
        or item.get("guid")
        or item.get("Guid")
        or ""
    ).strip()
    if not cid:
        return None

    entry = dict(item)
    entry["id"] = cid

    name = (
        item.get("name")
        or item.get("Name")
        or item.get("displayName")
        or item.get("DisplayName")
        or cid
    )
    entry["name"] = str(name)

    if "description" not in entry and "Description" in item:
        entry["description"] = item["Description"]
    if "iconGlyph" not in entry and "IconGlyph" in item:
        entry["iconGlyph"] = item["IconGlyph"]
    if "hasSettingsControl" not in entry and "HasSettingsControl" in item:
        entry["hasSettingsControl"] = _to_bool(item["HasSettingsControl"])
    if "componentTypeName" not in entry and "ComponentTypeName" in item:
        entry["componentTypeName"] = item["ComponentTypeName"]
    if "settingsTypeName" not in entry and "SettingsTypeName" in item:
        entry["settingsTypeName"] = item["SettingsTypeName"]
    if "assemblyName" not in entry and "AssemblyName" in item:
        entry["assemblyName"] = item["AssemblyName"]
    if "isBuiltIn" not in entry and "IsBuiltIn" in item:
        entry["isBuiltIn"] = _to_bool(item["IsBuiltIn"])

    is_container = any(
        _to_bool(item.get(k))
        for k in (
            "isComponentContainer",
            "IsComponentContainer",
            "isContainer",
            "IsContainer",
            "is_component_container",
            "is_container",
        )
    )
    entry["isComponentContainer"] = is_container
    entry["isContainer"] = is_container
    return entry
