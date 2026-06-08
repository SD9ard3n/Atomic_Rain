#!/usr/bin/env python3
"""Semantic health checks for Atomic Rain skill variants.

Complements lint_skill.py by catching drift that remains valid Markdown:
wrong variant files, stale status labels, oversized entrypoints, missing runtime
protocols, and cross-version shared-file divergence.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_SKILL_LINES = 120

CLASSIC_ONLY = {
    "references/tooling/ffuf.md",
    "references/tooling/java-gadget.md",
    "references/tooling/nuclei.md",
    "references/tooling/recon-toolchain.md",
    "references/tooling/sqlmap.md",
    "references/tooling/token-attacks.md",
}

TOOLPLUS_ONLY = {
    "references/mcp-tools-finder.md",
    "references/ssa-vuln-hunting.md",
    "references/project-isolation-workflow.md",
    "references/evidence-pipeline.md",
    "references/cheatsheet/chrome-templates.md",
    "references/cheatsheet/exec-codec.md",
    "references/cheatsheet/fuzztag.md",
    "references/cheatsheet/syntaxflow.md",
    "references/vuln/_TOOLPLUS_OVERLAY.md",
    "scripts/build.py",
}

VARIANT_DIFFERENT = {
    "SKILL.md",
    "README.md",
    "references/tool-config.md",
    "references/tool-usage.md",
    "references/runtime-profile.md",
    "scripts/semantic_check.py",
    "scripts/validate_all.py",
    "scripts/package_runtime.py",
    "assets/third-party-js-blacklist.txt",
    "references/miniapp-workflow.md",
    "references/multi-agent-orchestration.md",
    "references/oob-infrastructure.md",
    "references/phase-guide.md",
    "references/project-workflow.md",
    "references/protocols/agent-protocol.md",
    "references/registerable-site-protocol.md",
    "references/report-template.md",
    "references/vuln/email-spoofing.md",
}

STALE_STATUS_PATTERNS = ("*(待建)*", "*(待加)*", "(待建)", "(待加)")

REQUIRED_SHARED = {
    "capabilities/cli-capabilities.json",
    "capabilities/mcp-capabilities.json",
    "schemas/evidence.schema.json",
    "schemas/report.schema.json",
    "schemas/vulnerability.schema.json",
    "scripts/validate_capabilities.py",
    "scripts/validate_artifacts.py",
    "scripts/build_variant.py",
    "source/variant-manifest.json",
    "source/runtime-tiers.json",
    "references/artifact-quality-gates.md",
    "references/business-flow-checklist.md",
    "references/miniapp-workflow.md",
    "references/vuln/email-spoofing.md",
    "references/scan_modes/quick.md",
    "references/scan_modes/standard.md",
    "references/scan_modes/deep.md",
    "references/multi-agent-orchestration.md",
    "references/protocols/agent-protocol.md",
    "references/runtime-profile.md",
}

REQUIRED_REPOSITORY_SHARED = {
    "evals/evals.json",
}

PATH_RE = re.compile(r"`((?:references|scripts|assets)/[^`]+?)`")


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def iter_markdown(root: Path = ROOT) -> list[Path]:
    return sorted(p for p in root.rglob("*.md") if ".git" not in p.parts)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_frontmatter(path: Path) -> tuple[dict[str, str], list[str]]:
    text = read_text(path)
    lines = text.splitlines()
    errors: list[str] = []
    if not lines or lines[0].strip() != "---":
        return {}, [f"{rel(path)}: missing YAML frontmatter"]
    end = None
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            end = idx
            break
    if end is None:
        return {}, [f"{rel(path)}: unterminated YAML frontmatter"]
    data: dict[str, str] = {}
    for line in lines[1:end]:
        if not line.strip() or line.startswith("  ") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    for required in ("name", "description", "category"):
        if required not in data:
            errors.append(f"{rel(path)}: frontmatter missing {required}")
    return data, errors


def detect_variant(root: Path = ROOT) -> str:
    text = (root / "SKILL.md").read_text(encoding="utf-8") if (root / "SKILL.md").exists() else ""
    if "atomic-rain-toolplus" in text or "mcp-tools-finder.md" in text:
        return "toolplus"
    return "classic"


def check_entrypoint_size(errors: list[str]) -> None:
    lines = read_text(ROOT / "SKILL.md").splitlines()
    if len(lines) > MAX_SKILL_LINES:
        errors.append(f"SKILL.md is too large for a slim entrypoint: {len(lines)} lines > {MAX_SKILL_LINES}")
    protocol = ROOT / "references" / "protocols" / "agent-protocol.md"
    if not protocol.exists():
        errors.append("missing migrated full protocol: references/protocols/agent-protocol.md")
    elif len(read_text(protocol).splitlines()) < 120:
        errors.append("agent-protocol.md looks too small; full protocol may have been truncated")


def check_frontmatter(errors: list[str], profile: str) -> None:
    for path in iter_markdown():
        _, fm_errors = parse_frontmatter(path)
        errors.extend(fm_errors)
    skill_data, _ = parse_frontmatter(ROOT / "SKILL.md")
    expected = "atomic-rain-toolplus" if profile in {"toolplus", "deployed-mixed"} else "atomic-rain"
    actual = skill_data.get("name")
    if actual != expected:
        errors.append(f"SKILL.md: name should be {expected!r}, got {actual!r}")
    desc = skill_data.get("description", "")
    if len(desc) < 120:
        errors.append("SKILL.md: description is too short to trigger reliably")
    if "Use when" not in desc and "Use whenever" not in desc:
        errors.append("SKILL.md: description should include explicit trigger wording")


def check_stale_status(errors: list[str]) -> None:
    for path in iter_markdown():
        text = read_text(path).replace("[待验证-", "")
        for pattern in STALE_STATUS_PATTERNS:
            if pattern in text:
                errors.append(f"{rel(path)}: stale status marker {pattern!r}")


def check_variant_files(errors: list[str], profile: str) -> None:
    present = {rel(path) for path in ROOT.rglob("*") if path.is_file() and ".git" not in path.parts}
    required = set(REQUIRED_SHARED)
    if profile in {"classic", "toolplus"}:
        required |= REQUIRED_REPOSITORY_SHARED
    for item in sorted(required - present):
        errors.append(f"missing required shared file: {item}")
    if profile == "classic":
        for item in sorted(TOOLPLUS_ONLY & present):
            errors.append(f"classic contains toolPlus-only file: {item}")
        for item in sorted(CLASSIC_ONLY - present):
            errors.append(f"classic missing classic-only file: {item}")
    elif profile == "toolplus":
        for item in sorted(CLASSIC_ONLY & present):
            errors.append(f"toolPlus contains classic-only file: {item}")
        for item in sorted(TOOLPLUS_ONLY - present):
            errors.append(f"toolPlus missing toolPlus-only file: {item}")
    elif profile == "deployed-mixed":
        for item in sorted(TOOLPLUS_ONLY - present):
            errors.append(f"deployed-mixed missing toolPlus file: {item}")
        for item in sorted(CLASSIC_ONLY - present):
            errors.append(f"deployed-mixed missing classic tooling file: {item}")


def check_category_counts(warnings: list[str]) -> None:
    counts: dict[str, int] = {}
    for path in iter_markdown():
        data, _ = parse_frontmatter(path)
        category = data.get("category", "<missing>")
        counts[category] = counts.get(category, 0) + 1
    text = read_text(ROOT / "SKILL.md")
    for category, count in sorted(counts.items()):
        if category == "<missing>":
            continue
        match = re.search(rf"`{re.escape(category)}`\s*\|\s*(\d+)", text)
        if match and int(match.group(1)) != count:
            warnings.append(f"SKILL.md category count drift for {category}: table={match.group(1)} actual={count}")


def check_entrypoint_paths(errors: list[str]) -> None:
    text = read_text(ROOT / "SKILL.md")
    for raw in PATH_RE.findall(text):
        clean = raw.split()[0].rstrip(".,;:)")
        if "*" in clean:
            continue
        path = ROOT / clean
        if not path.exists():
            errors.append(f"SKILL.md references missing runtime path: {clean}")


def check_peer_hashes(errors: list[str], warnings: list[str], peer: Path | None) -> None:
    if peer is None:
        return
    if not peer.exists():
        errors.append(f"peer path does not exist: {peer}")
        return
    this_files = {p.relative_to(ROOT).as_posix(): p for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts}
    peer_files = {p.relative_to(peer).as_posix(): p for p in peer.rglob("*") if p.is_file() and ".git" not in p.parts}
    shared = sorted((set(this_files) & set(peer_files)) - VARIANT_DIFFERENT - CLASSIC_ONLY - TOOLPLUS_ONLY)
    for item in shared:
        if sha256(this_files[item]) != sha256(peer_files[item]):
            warnings.append(f"shared file hash drift: {item}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Atomic Rain semantic drift checks.")
    parser.add_argument("--profile", choices=["classic", "toolplus", "deployed-mixed"], default=None)
    parser.add_argument("--root", type=Path, default=None, help="Root directory to validate instead of the script repository")
    parser.add_argument("--peer", type=Path, default=None, help="Peer variant root for shared-file hash drift checks")
    parser.add_argument("--strict-counts", action="store_true", help="treat category count drift as errors")
    parser.add_argument("--strict-peer", action="store_true", help="treat peer hash drift warnings as errors")
    args = parser.parse_args()

    global ROOT
    if args.root:
        ROOT = args.root.resolve()

    profile = args.profile or detect_variant()
    errors: list[str] = []
    warnings: list[str] = []

    check_entrypoint_size(errors)
    check_frontmatter(errors, profile)
    check_stale_status(errors)
    check_variant_files(errors, profile)
    check_category_counts(warnings)
    check_entrypoint_paths(errors)
    check_peer_hashes(errors, warnings, args.peer.resolve() if args.peer else None)

    if warnings:
        print("[semantic] WARN")
        for warning in warnings:
            print(f"  - {warning}")
        if args.strict_counts or args.strict_peer:
            errors.extend(warnings)
    if errors:
        print("[semantic] FAIL")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(f"[semantic] OK profile={profile} md_files={len(iter_markdown())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())


