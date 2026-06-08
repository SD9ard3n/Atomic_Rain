#!/usr/bin/env python3
"""Conservative single-source scaffold for Atomic Rain variants.

This script does not rewrite the existing repositories. It validates the
declared shared/overlay contract and can export the current repository as a
runtime package according to source/variant-manifest.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "source" / "variant-manifest.json"
TIERS = ROOT / "source" / "runtime-tiers.json"
EXCLUDE_DIRS = {".git", ".omc", "__pycache__", "evals", "source"}
EXCLUDE_FILES = {"README.md"}


def load_manifest() -> dict[str, Any]:
    with MANIFEST.open("r", encoding="utf-8") as f:
        return json.load(f)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def detect_profile() -> str:
    text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    if "atomic-rain-toolplus" in text or "mcp-tools-finder.md" in text:
        return "toolplus"
    return "classic"


def load_tier_excludes(tier: str) -> set[str]:
    if tier == "full":
        return set()
    if not TIERS.exists():
        raise ValueError("source/runtime-tiers.json is required for non-full packaging tiers")
    with TIERS.open("r", encoding="utf-8") as f:
        data = json.load(f)
    tiers = data.get("tiers", {})
    if tier not in tiers:
        available = ", ".join(sorted(tiers))
        raise ValueError(f"unknown runtime tier {tier!r}; available: {available}")
    return {item.rstrip("/") for item in tiers[tier].get("exclude", [])}


def should_skip_runtime(path: Path, tier_excludes: set[str]) -> bool:
    rel_parts = path.relative_to(ROOT).parts
    rel_path = path.relative_to(ROOT).as_posix()
    if any(part in EXCLUDE_DIRS for part in rel_parts):
        return True
    if path.name in EXCLUDE_FILES:
        return True
    if rel_path in tier_excludes or any(rel_path.startswith(item + "/") for item in tier_excludes):
        return True
    if path.suffix in {".pyc", ".pyo"}:
        return True
    return False


def validate_manifest_shape(manifest: dict[str, Any], errors: list[str]) -> None:
    if manifest.get("schema_version") != "1.0":
        errors.append("source/variant-manifest.json: schema_version must be 1.0")
    profiles = manifest.get("profiles")
    if profiles != ["classic", "toolplus"]:
        errors.append("source/variant-manifest.json: profiles must be ['classic', 'toolplus']")
    for key in ("shared_files", "repository_only", "runtime_excluded", "variant_overlays"):
        if key not in manifest:
            errors.append(f"source/variant-manifest.json: missing {key}")


def check_profile_contract(manifest: dict[str, Any], profile: str, errors: list[str]) -> None:
    overlays = manifest.get("variant_overlays", {})
    overlay = overlays.get(profile)
    if not isinstance(overlay, dict):
        errors.append(f"missing variant overlay for {profile}")
        return
    for item in manifest.get("shared_files", []):
        if not (ROOT / item).exists():
            errors.append(f"missing shared file: {item}")
    for item in overlay.get("required_files", []):
        if not (ROOT / item).exists():
            errors.append(f"{profile} missing required overlay file: {item}")
    for item in overlay.get("forbidden_files", []):
        if (ROOT / item).exists():
            errors.append(f"{profile} contains forbidden overlay file: {item}")
    registry = overlay.get("capability_registry")
    if registry and not (ROOT / registry).exists():
        errors.append(f"{profile} missing capability registry: {registry}")


def check_peer_shared_hashes(manifest: dict[str, Any], peer: Path | None, errors: list[str], warnings: list[str]) -> None:
    if peer is None:
        return
    if not peer.exists():
        errors.append(f"peer path does not exist: {peer}")
        return
    for item in manifest.get("shared_files", []):
        here = ROOT / item
        there = peer / item
        if not here.exists() or not there.exists():
            errors.append(f"shared file missing on one side: {item}")
            continue
        if sha256(here) != sha256(there):
            warnings.append(f"shared manifest hash drift: {item}")


def copy_runtime(dest: Path, tier: str) -> None:
    tier_excludes = load_tier_excludes(tier)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for src in ROOT.rglob("*"):
        if should_skip_runtime(src, tier_excludes):
            continue
        target = dest / src.relative_to(ROOT)
        if src.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)


def check_runtime_exclusions(dest: Path, manifest: dict[str, Any], errors: list[str]) -> None:
    for item in manifest.get("runtime_excluded", []):
        clean = item.rstrip("/")
        if (dest / clean).exists():
            errors.append(f"runtime export unexpectedly contains excluded path: {item}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate or export Atomic Rain variant packages.")
    parser.add_argument("command", choices=["check", "export"])
    parser.add_argument("--profile", choices=["classic", "toolplus"], default=None)
    parser.add_argument("--peer", type=Path, default=None, help="Peer variant root for shared manifest hash checks")
    parser.add_argument("--dest", type=Path, default=None, help="Destination directory for export")
    parser.add_argument("--tier", choices=["full", "lean"], default="full", help="Runtime packaging tier for export")
    parser.add_argument("--strict-peer", action="store_true", help="Treat peer shared hash drift warnings as errors")
    args = parser.parse_args()

    profile = args.profile or detect_profile()
    manifest = load_manifest()
    errors: list[str] = []
    warnings: list[str] = []

    validate_manifest_shape(manifest, errors)
    check_profile_contract(manifest, profile, errors)
    check_peer_shared_hashes(manifest, args.peer.resolve() if args.peer else None, errors, warnings)

    if args.command == "export":
        if args.dest is None:
            errors.append("export requires --dest")
        else:
            dest = args.dest.resolve()
            if dest == ROOT or ROOT in dest.parents:
                errors.append("export destination must be outside the source repository")
            elif not errors:
                try:
                    copy_runtime(dest, args.tier)
                except ValueError as exc:
                    errors.append(str(exc))
                else:
                    check_runtime_exclusions(dest, manifest, errors)
                    print(f"[variant] exported {profile} tier={args.tier} runtime to {dest}")

    if warnings:
        print("[variant] WARN")
        for warning in warnings:
            print(f"  - {warning}")
        if args.strict_peer:
            errors.extend(warnings)
    if errors:
        print("[variant] FAIL")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(f"[variant] OK profile={profile} shared={len(manifest.get('shared_files', []))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
