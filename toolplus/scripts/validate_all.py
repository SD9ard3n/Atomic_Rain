#!/usr/bin/env python3
"""Run all Atomic Rain repository validation checks."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(args: list[str]) -> int:
    print("[validate] " + " ".join(str(a) for a in args))
    proc = subprocess.run(args, cwd=ROOT)
    return proc.returncode


def detect_profile() -> str:
    text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    if "atomic-rain-toolplus" in text or "mcp-tools-finder.md" in text:
        return "toolplus"
    return "classic"


def has_toolplus_build() -> bool:
    return (ROOT / "scripts" / "build.py").exists()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Atomic Rain validation suite.")
    parser.add_argument("--peer", type=Path, default=None, help="Peer variant root for shared-file hash drift checks")
    parser.add_argument("--profile", choices=["classic", "toolplus", "deployed-mixed"], default=None)
    parser.add_argument("--package", action="store_true", help="also test runtime packaging into a temp directory")
    args = parser.parse_args()

    profile = args.profile or detect_profile()
    semantic = [sys.executable, "-u", "scripts/semantic_check.py", "--profile", profile]
    if args.peer:
        semantic.extend(["--peer", str(args.peer)])

    checks = [
        [sys.executable, "scripts/lint_skill.py"],
        semantic,
        [sys.executable, "scripts/validate_artifacts.py"],
        [sys.executable, "scripts/validate_capabilities.py", "--profile", profile],
        [sys.executable, "scripts/build_variant.py", "check", "--profile", profile],
    ]
    if args.peer:
        checks[-1].extend(["--peer", str(args.peer)])
    if has_toolplus_build():
        checks.extend(
            [
                [sys.executable, "scripts/build.py", "selftest"],
                [sys.executable, "scripts/build.py", "validate", "references/vuln/"],
            ]
        )

    failed = 0
    for check in checks:
        if run(check) != 0:
            failed += 1

    if args.package:
        with tempfile.TemporaryDirectory(prefix="atomic-rain-runtime-") as tmp:
            if run([sys.executable, "scripts/package_runtime.py", tmp]) != 0:
                failed += 1
            elif (Path(tmp) / "README.md").exists():
                print("[validate] runtime package unexpectedly contains README.md")
                failed += 1
            else:
                lint = Path(tmp) / "scripts" / "lint_skill.py"
                if run([sys.executable, str(lint)]) != 0:
                    failed += 1
        with tempfile.TemporaryDirectory(prefix="atomic-rain-runtime-lean-") as tmp:
            if run([sys.executable, "scripts/package_runtime.py", "--tier", "lean", tmp]) != 0:
                failed += 1
            elif (Path(tmp) / "README.md").exists():
                print("[validate] lean runtime package unexpectedly contains README.md")
                failed += 1
            else:
                lint = Path(tmp) / "scripts" / "lint_skill.py"
                if run([sys.executable, str(lint)]) != 0:
                    failed += 1

    if failed:
        print(f"[validate] FAIL failed_checks={failed}")
        return 1
    print("[validate] OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
