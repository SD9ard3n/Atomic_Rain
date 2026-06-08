#!/usr/bin/env python3
"""
add_frontmatter.py — 给 atomic-rain skill 所有 markdown 批量加 YAML frontmatter (v0.1)

设计原则:
  1. idempotent — 已有 frontmatter 的文件原样跳过
  2. dry-run 优先 — 先输出 markdown 形式的 proposal,用户审完再 --apply
  3. 启发式生成 description,允许后续人工 review 改写
  4. 双版本通用 — 通过 --root 参数指定要扫的目录

启发式 description 候选优先级:
  1) 文件首个 ">" 引用块的内容(很多 atomic-rain 文档用 > 写摘要)
  2) 第一个 H1 之后的第一段非空非列表段落
  3) 第一个 H1 标题本身
  4) 文件 stem 兜底说明
"""
from __future__ import annotations
import argparse
import re
import sys
from pathlib import Path
from typing import Iterable


FM_PATTERN = re.compile(r"\A---\s*\n.*?\n---\s*\n", re.DOTALL)
H1_PATTERN = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)
QUOTE_PATTERN = re.compile(r"^>\s*(.+?)\s*$", re.MULTILINE)

EXCLUDE_DIRS = {".git", "__pycache__", "node_modules", ".idea", ".vscode", "assets"}
EXCLUDE_FILES = {"CHANGELOG.md"}
EXCLUDE_PATTERNS = ("frontmatter_proposal", "FRONTMATTER_PROPOSAL")

CATEGORY_OVERRIDES = {
    "SKILL": "skill-entry",
    "README": "meta",
    "_TOOLPLUS_OVERLAY": "meta",
}


def iter_markdown_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*.md")):
        if any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        if path.name in EXCLUDE_FILES:
            continue
        if any(p in path.name for p in EXCLUDE_PATTERNS):
            continue
        yield path


def has_frontmatter(text: str) -> bool:
    return bool(FM_PATTERN.match(text))


def derive_category(root: Path, path: Path) -> str:
    rel = path.relative_to(root)
    stem = path.stem
    if stem in CATEGORY_OVERRIDES:
        return CATEGORY_OVERRIDES[stem]
    parts = rel.parts
    # references/<sub>/file.md → sub
    if len(parts) >= 2 and parts[0] == "references":
        return parts[1] if len(parts) >= 3 else "methodology"
    return parts[0].replace(".md", "")


def derive_name(path: Path) -> str:
    return path.stem.lower().replace("_", "-").lstrip("-")


def first_h1(text: str) -> str | None:
    m = H1_PATTERN.search(text)
    return m.group(1).strip() if m else None


def first_paragraph_after_h1(text: str) -> str | None:
    """取首个 H1 之后的第一段非空非列表非代码块内容"""
    h1 = H1_PATTERN.search(text)
    if not h1:
        return None
    rest = text[h1.end():]
    in_code = False
    buf = []
    for line in rest.splitlines():
        s = line.strip()
        if s.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        if not s:
            if buf:
                break
            continue
        # 跳过列表/引用/标题/分隔线
        if s.startswith(("#", "-", "*", "|", ">", "<!--")) or s.startswith("---"):
            if buf:
                break
            continue
        buf.append(s)
        if sum(len(x) for x in buf) > 250:
            break
    return " ".join(buf) if buf else None


def first_quote_block(text: str) -> str | None:
    """取第一个 > 引用块(连续多行 > 合并)"""
    lines = text.splitlines()
    buf = []
    in_block = False
    for line in lines:
        s = line.strip()
        m = QUOTE_PATTERN.match(line)
        if m:
            buf.append(m.group(1))
            in_block = True
        elif in_block:
            break
    return " ".join(buf) if buf else None


def truncate(s: str, n: int = 140) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    s = re.sub(r"[`*_]", "", s)
    if len(s) <= n:
        return s
    return s[:n - 1].rstrip() + "…"


def derive_description(text: str, stem: str) -> str:
    for fn in (first_quote_block, first_paragraph_after_h1, first_h1):
        v = fn(text)
        if v:
            return truncate(v)
    return f"{stem} 相关知识(待人工补全 description)"


def derive_tags(category: str, stem: str) -> list[str]:
    # tags 不重复 category 名,只放语义标签
    keywords = {
        "java": ["shiro", "spring", "fastjson", "jackson", "log4shell", "jndi", "xstream", "hessian", "dubbo"],
        "deser": ["deserialize", "shiro", "fastjson", "jackson", "log4shell", "xstream"],
        "auth": ["jwt", "oauth", "oidc", "saml"],
        "client": ["xss", "csrf", "prototype-pollution", "dangling-markup", "cors"],
        "server": ["ssrf", "rce", "ssti", "xxe", "smuggling"],
        "logic": ["race", "idor", "bola", "hpp", "mass-assignment"],
        "ai": ["ai-app", "ai-data", "prompt"],
        "middleware": ["shiro", "swagger", "actuator", "druid", "imagetragick"],
        "scenarios": ["-scenarios"],
    }
    sl = stem.lower()
    tags = []
    for tag, hints in keywords.items():
        if any(h in sl for h in hints):
            tags.append(tag)
    return tags


def build_frontmatter(name: str, description: str, category: str, tags: list[str]) -> str:
    lines = [
        "---",
        f"name: {name}",
        f"description: {description}",
        f"category: {category}",
    ]
    if tags:
        lines.append(f"tags: [{', '.join(tags)}]")
    lines.append("---")
    return "\n".join(lines) + "\n"


def process_file(root: Path, path: Path) -> tuple[bool, str, str]:
    """返回 (need_update, frontmatter_str, derived_summary)"""
    text = path.read_text(encoding="utf-8", errors="ignore")
    if has_frontmatter(text):
        return False, "", ""
    name = derive_name(path)
    category = derive_category(root, path)
    description = derive_description(text, path.stem)
    tags = derive_tags(category, path.stem)
    fm = build_frontmatter(name, description, category, tags)
    summary = (
        f"- **name**: `{name}`\n"
        f"- **description**: {description}\n"
        f"- **category**: `{category}`\n"
        f"- **tags**: `{tags}`"
    )
    return True, fm, summary


def write_proposal(root: Path, out_path: Path) -> int:
    pending = []
    for md in iter_markdown_files(root):
        need, fm, summary = process_file(root, md)
        if need:
            pending.append((md, fm, summary))
    lines = [
        f"# Frontmatter Proposal — `{root.name}`",
        "",
        f"扫描 root: `{root}`",
        f"共 **{len(pending)}** 个文件待加 frontmatter。审完后用 `--apply` 真正写入。",
        "",
        "格式:每个文件展示提议的 frontmatter 块,人工审完可在 apply 前先手动改 description / category / tags。",
        "",
        "---",
        "",
    ]
    for md, fm, summary in pending:
        rel = md.relative_to(root).as_posix()
        lines.append(f"## `{rel}`")
        lines.append("")
        lines.append(summary)
        lines.append("")
        lines.append("```yaml")
        lines.append(fm.rstrip())
        lines.append("```")
        lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")
    return len(pending)


def apply(root: Path) -> tuple[int, int]:
    """返回 (applied, skipped)"""
    applied = 0
    skipped = 0
    for md in iter_markdown_files(root):
        text = md.read_text(encoding="utf-8", errors="ignore")
        if has_frontmatter(text):
            skipped += 1
            continue
        need, fm, _ = process_file(root, md)
        if not need:
            skipped += 1
            continue
        new_text = fm + "\n" + text if not text.startswith("\n") else fm + text
        md.write_text(new_text, encoding="utf-8")
        applied += 1
    return applied, skipped


def main() -> int:
    p = argparse.ArgumentParser(description="给 atomic-rain markdown 批量加 frontmatter")
    p.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="skill 根目录(默认脚本所在 scripts/ 的父目录)",
    )
    p.add_argument("--dry-run", action="store_true", help="只生成 proposal 文件,不改任何文件")
    p.add_argument("--apply", action="store_true", help="实际写入 frontmatter")
    p.add_argument(
        "--proposal-out",
        type=Path,
        default=None,
        help="proposal 输出路径(默认 root/frontmatter_proposal.md)",
    )
    args = p.parse_args()

    if not args.dry_run and not args.apply:
        args.dry_run = True

    if args.dry_run:
        out = args.proposal_out or (args.root / "frontmatter_proposal.md")
        n = write_proposal(args.root, out)
        print(f"[dry-run] {n} 个文件待加 frontmatter — proposal 已写入 {out}")
        print(f"          审完后用 --apply 真正写入")
        return 0

    if args.apply:
        applied, skipped = apply(args.root)
        print(f"[apply] 写入 frontmatter 到 {applied} 个文件,跳过(已有) {skipped} 个")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
