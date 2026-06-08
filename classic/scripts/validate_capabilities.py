#!/usr/bin/env python3
"""Validate Atomic Rain capability registries.

Capability registries decouple stable security-testing capabilities from concrete
tool names. This keeps classic and toolPlus documentation from drifting back to
hardcoded, unverified tool assumptions.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_COMMON_IDS = {"http_probe", "asset_recon", "oob_listener"}
REQUIRED_TOOLPLUS_IDS = {
    "project_context",
    "http_fuzz",
    "traffic_history",
    "browser_tabs",
    "browser_evidence",
    "static_dataflow",
    "codec_workflow",
}
REQUIRED_CLASSIC_IDS = {
    "http_probe",
    "directory_fuzz",
    "template_scan",
    "sqli_assist",
    "asset_recon",
    "static_grep",
    "oob_listener",
}

VALID_PROFILES = {"classic", "toolplus"}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def detect_profile() -> str:
    text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    if "atomic-rain-toolplus" in text or "mcp-tools-finder.md" in text:
        return "toolplus"
    return "classic"


def registry_path(profile: str) -> Path:
    name = "mcp-capabilities.json" if profile == "toolplus" else "cli-capabilities.json"
    return ROOT / "capabilities" / name


def check_capability(item: dict[str, Any], idx: int, profile: str, errors: list[str]) -> None:
    prefix = f"capabilities[{idx}]"
    for key in ("id", "provider", "preferred_tools", "required", "required_fields", "fallback"):
        if key not in item:
            errors.append(f"{prefix}: missing {key}")
    cap_id = item.get("id")
    if not isinstance(cap_id, str) or not cap_id:
        errors.append(f"{prefix}: id must be a non-empty string")
    preferred = item.get("preferred_tools")
    if not isinstance(preferred, list) or not preferred or not all(isinstance(tool, str) and tool for tool in preferred):
        errors.append(f"{prefix}: preferred_tools must be a non-empty string list")
    required_fields = item.get("required_fields")
    if not isinstance(required_fields, list) or not required_fields or not all(isinstance(field, str) and field for field in required_fields):
        errors.append(f"{prefix}: required_fields must be a non-empty string list")
    if not isinstance(item.get("required"), bool):
        errors.append(f"{prefix}: required must be boolean")
    if not isinstance(item.get("fallback"), str) or len(item.get("fallback", "")) < 20:
        errors.append(f"{prefix}: fallback must explain operational behavior")

    if profile == "toolplus":
        marker = item.get("degraded_marker")
        if not isinstance(marker, str) or not marker.startswith("DEGRADED:"):
            errors.append(f"{prefix}: toolPlus capabilities must declare DEGRADED:* marker")
        if preferred and any(tool.startswith(("curl", "python", "sqlmap", "nuclei")) for tool in preferred):
            errors.append(f"{prefix}: toolPlus preferred tools should be MCP capabilities, got {preferred}")


def check_registry(profile: str, errors: list[str]) -> None:
    path = registry_path(profile)
    if not path.exists():
        errors.append(f"missing capability registry: {path.relative_to(ROOT).as_posix()}")
        return
    data = load_json(path)
    if data.get("schema_version") != "1.0":
        errors.append(f"{path.name}: schema_version must be 1.0")
    if data.get("profile") != profile:
        errors.append(f"{path.name}: profile should be {profile}, got {data.get('profile')!r}")
    if not isinstance(data.get("runtime_discovery"), dict):
        errors.append(f"{path.name}: missing runtime_discovery object")
    capabilities = data.get("capabilities")
    if not isinstance(capabilities, list) or len(capabilities) < 6:
        errors.append(f"{path.name}: expected at least 6 capabilities")
        return
    seen: set[str] = set()
    for idx, item in enumerate(capabilities):
        if not isinstance(item, dict):
            errors.append(f"capabilities[{idx}]: must be object")
            continue
        cap_id = item.get("id")
        if isinstance(cap_id, str):
            if cap_id in seen:
                errors.append(f"{path.name}: duplicate capability id {cap_id}")
            seen.add(cap_id)
        check_capability(item, idx, profile, errors)

    required = REQUIRED_TOOLPLUS_IDS if profile == "toolplus" else REQUIRED_CLASSIC_IDS
    missing = sorted(required - seen)
    if missing:
        errors.append(f"{path.name}: missing required capabilities {missing}")


def check_docs_reference(profile: str, errors: list[str]) -> None:
    expected_file = "capabilities/mcp-capabilities.json" if profile == "toolplus" else "capabilities/cli-capabilities.json"
    skill_text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    tool_config_text = (ROOT / "references" / "tool-config.md").read_text(encoding="utf-8")
    if expected_file not in skill_text:
        errors.append(f"SKILL.md should reference {expected_file}")
    if expected_file not in tool_config_text:
        errors.append(f"references/tool-config.md should reference {expected_file}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Atomic Rain capability registries.")
    parser.add_argument("--profile", choices=sorted(VALID_PROFILES), default=None)
    args = parser.parse_args()

    profile = args.profile or detect_profile()
    errors: list[str] = []
    check_registry(profile, errors)
    check_docs_reference(profile, errors)

    if errors:
        print("[capabilities] FAIL")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(f"[capabilities] OK profile={profile} registry={registry_path(profile).relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
