#!/usr/bin/env python3
"""
build.py — Atomic Rain 双版本构建工具(toolPlus 独家)

机制:
  vuln/*.md 等共享文件中含 marker 注释:
    <!-- toolPlus -->...<!-- /toolPlus -->   (仅 toolPlus 版生效)
    <!-- classic -->...<!-- /classic -->     (仅 classic 版生效)

  本脚本读取这些标注源文件,生成:
    - atomic-rain/         (剥离 toolPlus,保留 classic + 共享)
    - atomic-rain-toolPlus/(剥离 classic,保留 toolPlus + 共享)

  共享内容(marker 外)两版都保留。

用法:
  python build.py validate <source_dir>
      检查所有 .md 文件的 marker 合法性(配对、不嵌套、不跨节)

  python build.py extract --variant=classic <source_dir> <dest_dir>
      从 source 提取 classic 版到 dest

  python build.py extract --variant=toolplus <source_dir> <dest_dir>
      从 source 提取 toolPlus 版到 dest

  python build.py diff <classic_dir> <toolplus_dir>
      对比两版差异(只算 marker 外是否一致 — 应当完全一致)

退出码:
  0 = 成功
  1 = 参数错误
  2 = marker 语法错误
  3 = 文件系统错误
"""

import argparse
import re
import shutil
import sys
from pathlib import Path

MARKER_PATTERN = re.compile(
    r'<!--\s*(/?)(toolPlus|classic)\s*-->',
    re.IGNORECASE
)

SKIP_PATTERN = re.compile(r'<!--\s*build:skip\s*-->', re.IGNORECASE)

# ANSI 颜色(Windows 终端支持)
class C:
    R = '\033[91m'
    G = '\033[92m'
    Y = '\033[93m'
    B = '\033[94m'
    DIM = '\033[2m'
    BOLD = '\033[1m'
    END = '\033[0m'


def find_markers(text):
    """返回 [(line_no, is_closing, variant), ...] — 1-indexed
    跳过 markdown fenced code block (``` 或 ~~~) 内部的 marker(那是示范文本,不是真 marker)
    """
    markers = []
    in_fence = False
    fence_char = None  # '`' or '~'
    fence_len = 0

    for line_no, line in enumerate(text.splitlines(), start=1):
        # 检测 fence 起止 (行首,允许前导空格)
        stripped = line.lstrip()
        if stripped.startswith('```') or stripped.startswith('~~~'):
            ch = stripped[0]
            run = len(stripped) - len(stripped.lstrip(ch))
            if not in_fence:
                in_fence = True
                fence_char = ch
                fence_len = run
            elif ch == fence_char and run >= fence_len:
                in_fence = False
                fence_char = None
                fence_len = 0
            continue  # fence 起止行本身不查 marker

        if in_fence:
            continue  # 代码块内部一律跳过

        for m in MARKER_PATTERN.finditer(line):
            is_closing = bool(m.group(1))
            variant = m.group(2).lower()
            markers.append((line_no, is_closing, variant))
    return markers


def validate_markers(file_path):
    """验证单个文件的 marker 合法性。返回 (ok, [errors])。
    含 <!-- build:skip --> 的文件直接视为通过(元文档不参与 marker 检查)。
    """
    text = file_path.read_text(encoding='utf-8', errors='replace')
    if SKIP_PATTERN.search(text):
        return True, []
    markers = find_markers(text)
    errors = []

    stack = []  # [(line_no, variant)]
    for line_no, is_closing, variant in markers:
        if not is_closing:
            # 开标签
            if stack:
                errors.append(
                    f"L{line_no}: 嵌套 marker (在 <!-- {stack[-1][1]} --> "
                    f"未闭合时打开 <!-- {variant} -->)"
                )
            stack.append((line_no, variant))
        else:
            # 闭标签
            if not stack:
                errors.append(
                    f"L{line_no}: 孤立闭合 <!-- /{variant} --> (无对应开标签)"
                )
            else:
                open_line, open_variant = stack.pop()
                if open_variant != variant:
                    errors.append(
                        f"L{line_no}: 闭合 <!-- /{variant} --> 不匹配"
                        f"开标签 <!-- {open_variant} --> (L{open_line})"
                    )

    for open_line, open_variant in stack:
        errors.append(
            f"L{open_line}: <!-- {open_variant} --> 未闭合到文件末尾"
        )

    return len(errors) == 0, errors


def extract_variant(text, target_variant):
    """
    从 text 中剥离非 target_variant 的 marker 块。
    例:target_variant='classic' → 删除 toolPlus 块,保留 classic 块和共享内容。
    跳过 markdown 代码块内部的 marker 字面文本。
    """
    lines = text.splitlines(keepends=True)
    output = []
    skip_stack = []  # 当前在哪些 variant 块里(且应被跳过)
    in_fence = False
    fence_char = None
    fence_len = 0

    for line in lines:
        stripped = line.lstrip()
        # 检测 fence 起止
        is_fence_line = False
        if stripped.startswith('```') or stripped.startswith('~~~'):
            ch = stripped[0]
            run = len(stripped) - len(stripped.lstrip(ch))
            if not in_fence:
                in_fence = True
                fence_char = ch
                fence_len = run
                is_fence_line = True
            elif ch == fence_char and run >= fence_len:
                in_fence = False
                fence_char = None
                fence_len = 0
                is_fence_line = True

        # fence 行本身、fence 内部:不解析 marker,根据 skip_stack 决定是否输出
        if in_fence or is_fence_line:
            if not skip_stack:
                output.append(line)
            continue

        # 普通行 — 检查 marker
        markers_in_line = list(MARKER_PATTERN.finditer(line))

        if not markers_in_line:
            if not skip_stack:
                output.append(line)
            continue

        # 有 marker(规范要求 marker 单独成行,marker 行本身不输出)
        for m in markers_in_line:
            is_closing = bool(m.group(1))
            variant = m.group(2).lower()
            if not is_closing:
                if variant != target_variant:
                    skip_stack.append(variant)
            else:
                if skip_stack and skip_stack[-1] == variant:
                    skip_stack.pop()

    return ''.join(output)


def remove_markers_only(text):
    """只删除 marker 行本身,保留所有内容(用于 diff 时归一化)"""
    lines = text.splitlines(keepends=True)
    return ''.join(
        line for line in lines
        if not MARKER_PATTERN.search(line)
    )


def cmd_validate(args):
    src = Path(args.source_dir)
    if not src.is_dir():
        print(f"{C.R}[ERROR]{C.END} {src} 不是目录", file=sys.stderr)
        return 3

    md_files = sorted(src.rglob('*.md'))
    if not md_files:
        print(f"{C.Y}[WARN]{C.END} {src} 下没找到 .md 文件")
        return 0

    total = len(md_files)
    bad = 0
    has_markers = 0

    for md in md_files:
        ok, errors = validate_markers(md)
        rel = md.relative_to(src)
        markers = find_markers(md.read_text(encoding='utf-8', errors='replace'))
        if markers:
            has_markers += 1
        if not ok:
            bad += 1
            print(f"{C.R}[FAIL]{C.END} {rel}")
            for e in errors:
                print(f"  - {e}")
        elif markers and args.verbose:
            print(f"{C.G}[OK]{C.END} {rel} ({len(markers)//2} marker pairs)")

    print()
    print(f"{C.BOLD}总计{C.END}: {total} 文件 / {has_markers} 含 marker / {C.G if bad == 0 else C.R}{bad} 错误{C.END}")
    return 2 if bad > 0 else 0


def cmd_extract(args):
    src = Path(args.source_dir)
    dst = Path(args.dest_dir)
    variant = args.variant.lower()

    if variant not in ('classic', 'toolplus'):
        print(f"{C.R}[ERROR]{C.END} variant 必须是 'classic' 或 'toolplus'", file=sys.stderr)
        return 1
    # 内部规范化:--variant=toolplus 实际匹配 'toolPlus' marker(大小写不敏感)
    target = 'toolplus' if variant == 'toolplus' else 'classic'

    if not src.is_dir():
        print(f"{C.R}[ERROR]{C.END} source {src} 不存在", file=sys.stderr)
        return 3

    if dst.exists() and not args.force:
        print(f"{C.R}[ERROR]{C.END} dest {dst} 已存在,加 --force 覆盖", file=sys.stderr)
        return 3

    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True, exist_ok=True)

    md_count = 0
    other_count = 0
    error_files = []

    for item in sorted(src.rglob('*')):
        rel = item.relative_to(src)
        out_path = dst / rel

        if item.is_dir():
            out_path.mkdir(parents=True, exist_ok=True)
            continue

        if item.suffix.lower() == '.md':
            text = item.read_text(encoding='utf-8', errors='replace')
            ok, errors = validate_markers(item)
            if not ok:
                error_files.append((rel, errors))
                continue
            new_text = extract_variant(text, target)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(new_text, encoding='utf-8')
            md_count += 1
        else:
            # 非 .md 文件直接复制
            out_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, out_path)
            other_count += 1

    print(f"{C.G}[OK]{C.END} 提取 variant={variant} → {dst}")
    print(f"  .md 处理: {md_count}  | 其他文件复制: {other_count}")
    if error_files:
        print(f"{C.R}[ERROR]{C.END} {len(error_files)} 文件 marker 错误,未处理:")
        for rel, errors in error_files:
            print(f"  - {rel}")
            for e in errors:
                print(f"      {e}")
        return 2
    return 0


def cmd_diff(args):
    """
    半分叉报告:对 source 目录中含 marker 的每个文件,
    统计共享骨架 / classic 段 / toolPlus 段的行数占比,展示改造覆盖率。

    诚实说明:
      "骨架一致性"由 extract 算法保证(数学上 skeleton ⊆ classic_view 和
      ⊆ toolplus_view 必然成立),所以这里不做"等价性检测" —
      那是 validate 的工作(它捕获 marker 语法错误)。

      cmd_diff 的真正价值是给人工 review 提供数据:
      - 哪些文件已半分叉改造
      - 每个文件 classic vs toolPlus 段哪个更详细
      - 骨架占比是否合理(过低 = 几乎全靠 marker 撑,可能滥用)
    """
    src = Path(args.source_dir)
    if not src.is_dir():
        print(f"{C.R}[ERROR]{C.END} source {src} 不存在", file=sys.stderr)
        return 3

    md_files = sorted(src.rglob('*.md'))
    rows = []
    skipped = 0
    no_markers = 0

    for md in md_files:
        rel = md.relative_to(src)
        text = md.read_text(encoding='utf-8', errors='replace')

        if SKIP_PATTERN.search(text):
            skipped += 1
            continue
        if not MARKER_PATTERN.search(text):
            no_markers += 1
            continue

        total = len([l for l in text.splitlines() if l.strip()])
        skeleton = _skeleton(text)
        skel_lines = len([l for l in skeleton.splitlines() if l.strip()])

        classic_view = extract_variant(text, 'classic')
        toolplus_view = extract_variant(text, 'toolplus')
        c_lines = len([l for l in classic_view.splitlines() if l.strip()])
        t_lines = len([l for l in toolplus_view.splitlines() if l.strip()])

        # classic 段 = classic_view - skeleton(差集)
        classic_seg = c_lines - skel_lines
        toolplus_seg = t_lines - skel_lines

        rows.append((str(rel), total, skel_lines, classic_seg, toolplus_seg))

    # 表格输出
    print(f"{C.BOLD}半分叉改造报告{C.END}")
    print(f"  含 marker 文件: {C.G}{len(rows)}{C.END}")
    print(f"  无 marker(纯共享): {no_markers}")
    print(f"  跳过(build:skip): {skipped}")
    print(f"  总计: {len(md_files)}")
    if md_files:
        coverage = 100 * len(rows) / (len(md_files) - skipped) if (len(md_files) - skipped) else 0
        print(f"  改造覆盖率: {C.BOLD}{coverage:.1f}%{C.END} ({len(rows)} / {len(md_files) - skipped})")

    if rows:
        print()
        print(f"  {'file':<40} {'total':>6} {'skel':>6} {'classic':>8} {'toolPlus':>9}")
        print(f"  {'-'*40} {'-'*6} {'-'*6} {'-'*8} {'-'*9}")
        for rel, total, skel, c, t in rows:
            # 简短文件名(去 vuln/ 前缀)
            short = rel.replace('vuln/', '').replace('vuln\\', '')
            print(f"  {short[:40]:<40} {total:>6} {skel:>6} {c:>8} {t:>9}")

    if args.verbose and rows:
        print(f"\n{C.DIM}使用 -v 时显示骨架内容(每个文件)— 略,见各文件 source{C.END}")

    return 0


def _skeleton(text):
    """剥离所有 marker 块 + marker 行本身,得到纯共享骨架。
    一次性扫描实现 — 不能用两次 extract_variant(第一次会把 marker 删了,
    第二次看到无 marker 文本会全文保留,导致 classic 段被错误保留)。
    跳过 markdown 代码块内部的 marker 字面文本(与 find_markers 一致)。"""
    lines = text.splitlines(keepends=True)
    output = []
    in_marker = False
    in_fence = False
    fence_char = None
    fence_len = 0

    for line in lines:
        stripped = line.lstrip()
        is_fence_line = False
        if stripped.startswith('```') or stripped.startswith('~~~'):
            ch = stripped[0]
            run = len(stripped) - len(stripped.lstrip(ch))
            if not in_fence:
                in_fence = True
                fence_char = ch
                fence_len = run
                is_fence_line = True
            elif ch == fence_char and run >= fence_len:
                in_fence = False
                fence_char = None
                fence_len = 0
                is_fence_line = True

        # 代码块内部 / fence 行本身:按 in_marker 决定输出,不解析 marker
        if in_fence or is_fence_line:
            if not in_marker:
                output.append(line)
            continue

        # 普通行 — 检查 marker
        m = MARKER_PATTERN.search(line)
        if m:
            is_closing = bool(m.group(1))
            if not is_closing:
                in_marker = True
            else:
                in_marker = False
            continue  # marker 行本身不输出

        if not in_marker:
            output.append(line)

    return ''.join(output)


def _skeleton(text):
    """剥离所有 marker 块 + marker 行本身,得到纯共享骨架。
    一次性扫描实现 — 不能用两次 extract_variant(第一次会把 marker 删了,
    第二次看到无 marker 文本会全文保留,导致 classic 段被错误保留)。
    跳过 markdown 代码块内部的 marker 字面文本(与 find_markers 一致)。"""
    lines = text.splitlines(keepends=True)
    output = []
    in_marker = False
    in_fence = False
    fence_char = None
    fence_len = 0

    for line in lines:
        stripped = line.lstrip()
        is_fence_line = False
        if stripped.startswith('```') or stripped.startswith('~~~'):
            ch = stripped[0]
            run = len(stripped) - len(stripped.lstrip(ch))
            if not in_fence:
                in_fence = True
                fence_char = ch
                fence_len = run
                is_fence_line = True
            elif ch == fence_char and run >= fence_len:
                in_fence = False
                fence_char = None
                fence_len = 0
                is_fence_line = True

        # 代码块内部 / fence 行本身:按 in_marker 决定输出,不解析 marker
        if in_fence or is_fence_line:
            if not in_marker:
                output.append(line)
            continue

        # 普通行 — 检查 marker
        m = MARKER_PATTERN.search(line)
        if m:
            is_closing = bool(m.group(1))
            if not is_closing:
                in_marker = True
            else:
                in_marker = False
            continue  # marker 行本身不输出

        if not in_marker:
            output.append(line)

    return ''.join(output)


def selftest():
    """内置自测:验证 marker 提取逻辑"""
    sample = """# Title

## Section
Shared content.

<!-- classic -->
classic-only content
multiple lines
<!-- /classic -->

<!-- toolPlus -->
toolPlus-only content
also multiple
<!-- /toolPlus -->

## Section 2
More shared.
"""
    classic_out = extract_variant(sample, 'classic')
    toolplus_out = extract_variant(sample, 'toolplus')

    assert 'classic-only content' in classic_out, "classic 应保留 classic 块"
    assert 'toolPlus-only content' not in classic_out, "classic 应删除 toolPlus 块"
    assert 'Shared content' in classic_out, "classic 应保留共享"

    assert 'toolPlus-only content' in toolplus_out, "toolPlus 应保留 toolPlus 块"
    assert 'classic-only content' not in toolplus_out, "toolPlus 应删除 classic 块"
    assert 'More shared' in toolplus_out, "toolPlus 应保留共享"

    # marker 行本身不应出现在输出中
    assert '<!-- classic -->' not in classic_out
    assert '<!-- /classic -->' not in classic_out
    assert '<!-- toolPlus -->' not in toolplus_out
    assert '<!-- /toolPlus -->' not in toolplus_out

    # 验证嵌套检测
    bad = """<!-- toolPlus -->
<!-- classic -->
nested
<!-- /classic -->
<!-- /toolPlus -->"""
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False, encoding='utf-8') as f:
        f.write(bad)
        bad_path = Path(f.name)
    ok, errors = validate_markers(bad_path)
    bad_path.unlink()
    assert not ok, "应检测出嵌套错误"
    assert any('嵌套' in e for e in errors), f"错误信息应提到嵌套: {errors}"

    print(f"{C.G}[OK]{C.END} 所有自测通过")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description=__doc__.split('\n')[1],  # 取第一行说明
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    sub = parser.add_subparsers(dest='cmd', required=True)

    p_val = sub.add_parser('validate', help='验证 marker 合法性')
    p_val.add_argument('source_dir', help='源目录(扫所有 .md)')
    p_val.add_argument('-v', '--verbose', action='store_true', help='显示所有通过的文件')
    p_val.set_defaults(func=cmd_validate)

    p_ext = sub.add_parser('extract', help='提取指定 variant 到目标目录')
    p_ext.add_argument('--variant', required=True, choices=['classic', 'toolplus'])
    p_ext.add_argument('source_dir', help='源目录(含 marker)')
    p_ext.add_argument('dest_dir', help='输出目录(会被清空)')
    p_ext.add_argument('--force', action='store_true', help='强制覆盖 dest')
    p_ext.set_defaults(func=cmd_extract)

    p_diff = sub.add_parser('diff', help='半分叉改造统计报告(列每个含 marker 文件的骨架/classic/toolPlus 段行数)')
    p_diff.add_argument('source_dir', help='含 marker 的源目录')
    p_diff.add_argument('-v', '--verbose', action='store_true', help='展示每个文件的骨架内容')
    p_diff.set_defaults(func=cmd_diff)

    p_test = sub.add_parser('selftest', help='跑内置自测')
    p_test.set_defaults(func=lambda args: selftest())

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == '__main__':
    main()
