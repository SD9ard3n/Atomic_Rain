#!/usr/bin/env python3
"""Package an Atomic Rain runtime skill directory.

The repository can contain README and project-maintenance material. The runtime
skill package should contain only files Codex needs while executing the skill.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TIERS = ROOT / "source" / "runtime-tiers.json"

EXCLUDE_DIRS = {".git", ".omc", "__pycache__", "evals", "source"}
EXCLUDE_FILES = {"README.md"}


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


def should_skip(path: Path, tier_excludes: set[str]) -> bool:
    rel_parts = path.relative_to(ROOT).parts
    rel = path.relative_to(ROOT).as_posix()
    if any(part in EXCLUDE_DIRS for part in rel_parts):
        return True
    if path.name in EXCLUDE_FILES:
        return True
    if rel in tier_excludes or any(rel.startswith(item + "/") for item in tier_excludes):
        return True
    if path.suffix in {".pyc", ".pyo"}:
        return True
    return False


def copy_runtime(dest: Path, tier: str) -> None:
    tier_excludes = load_tier_excludes(tier)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    for src in ROOT.rglob("*"):
        if should_skip(src, tier_excludes):
            continue
        rel = src.relative_to(ROOT)
        target = dest / rel
        if src.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)


def main() -> int:
    parser = argparse.ArgumentParser(description="Package Atomic Rain runtime skill files.")
    parser.add_argument("--tier", choices=["full", "lean"], default="full", help="Runtime packaging tier")
    parser.add_argument("dest", type=Path, help="Destination directory to create or replace")
    args = parser.parse_args()

    dest = args.dest.resolve()
    if dest == ROOT or ROOT in dest.parents:
        print("[package] destination must be outside the source repository", file=sys.stderr)
        return 1

    try:
        copy_runtime(dest, args.tier)
    except ValueError as exc:
        print(f"[package] {exc}", file=sys.stderr)
        return 1
    print(f"[package] OK tier={args.tier} {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
