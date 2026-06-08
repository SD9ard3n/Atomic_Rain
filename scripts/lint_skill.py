#!/usr/bin/env python3
"""
lint_skill.py — blackbox-pentest-master skill 的轻量自检脚本 (v2.8)

校验:
  1. 所有 markdown 内部链接 [text](path) 指向的 .md / .py / .txt 文件是否存在
  2. 所有 grep / Read 命令引用的 references/... .md 文件是否存在

设计原则: 轻量、低误报。只校验明确指向 skill 内文件的引用; 跳过 javascript:/code 块/其它协议链接。
"""
from __future__ import annotations
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXCLUDE_DIRS = {".git", "__pycache__", "node_modules", ".idea", ".vscode"}

LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
# 仅捕获以 references/ 开头, 后跟合法路径片段, 以 .md 结尾的引用
GREP_REF_RE = re.compile(r"\breferences/([A-Za-z0-9_./-]+?\.md)\b")
ANCHOR_RE = re.compile(r"#.*$")
URL_RE = re.compile(r"^(https?:|mailto:|javascript:|data:|ftp:)", re.IGNORECASE)
ALLOWED_EXT = {".md", ".py", ".txt", ".sh", ".json", ".yml", ".yaml", ".png", ".jpg"}


def iter_markdown_files(root: Path):
    for path in root.rglob("*.md"):
        if any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        # 跳过 CHANGELOG: 内含历史/计划路径, 不应作为活引用校验
        if path.name.upper().startswith("CHANGELOG"):
            continue
        yield path


def normalize_target(source: Path, target: str) -> Path | None:
    target = ANCHOR_RE.sub("", target).strip()
    if not target:
        return None
    if URL_RE.match(target):
        return None
    # 跳过明显不是路径的 (空格/引号/反引号/括号 内含)
    if any(ch in target for ch in [" ", "`", "'", "\""]):
        return None
    suffix = Path(target).suffix.lower()
    if suffix and suffix not in ALLOWED_EXT:
        return None
    if not suffix and "/" not in target:
        # 不含路径分隔符且无扩展名, 不当作内部文件链接
        return None
    return (source.parent / target).resolve()


def lint(root: Path, quiet: bool = False) -> int:
    broken = []
    total_links = 0
    total_grep = 0
    files_checked = 0

    for md in iter_markdown_files(root):
        files_checked += 1
        text = md.read_text(encoding="utf-8", errors="ignore")

        # 1. Markdown 链接
        for m in LINK_RE.finditer(text):
            target = m.group(2)
            resolved = normalize_target(md, target)
            if resolved is None:
                continue
            total_links += 1
            if not resolved.exists():
                broken.append(("link", md.relative_to(root), target))

        # 2. references/... 形式的 Grep / Read 引用
        for m in GREP_REF_RE.finditer(text):
            ref = "references/" + m.group(1)
            total_grep += 1
            candidate = (root / ref).resolve()
            if candidate.exists():
                continue
            sibling = (md.parent / Path(ref).name).resolve()
            if sibling.exists():
                continue
            broken.append(("grep", md.relative_to(root), ref))

    if not quiet:
        print(f"[lint] files={files_checked} links={total_links} grep_refs={total_grep}")
        if broken:
            print(f"[lint] broken={len(broken)}")
            for kind, src, target in broken:
                print(f"  {kind:5s} {src} -> {target}")
        else:
            print("[lint] OK no broken references")

    return 1 if broken else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quiet", action="store_true", help="只输出退出码与 summary")
    args = ap.parse_args()
    return lint(ROOT, quiet=args.quiet)


if __name__ == "__main__":
    sys.exit(main())
