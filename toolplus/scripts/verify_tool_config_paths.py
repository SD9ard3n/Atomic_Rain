#!/usr/bin/env python3
"""提取并验证 tool-config.md 中所有路径声明的真实可达性。"""
import re, os, sys

CFG = os.path.join(os.path.dirname(__file__), "..", "references", "tool-config.md")
CFG = os.path.abspath(CFG)

with open(CFG, "r", encoding="utf-8") as f:
    content = f.read()

FIELDS = ("path", "config", "jar", "main", "bin", "entry", "executable",
          "template_dir", "templates", "urls", "targets", "finger",
          "poc_dir", "burp_jre", "batch")
pat = re.compile(r'^\s*(' + '|'.join(FIELDS) + r'):\s*"([^"]+)"', re.MULTILINE)
hits = pat.findall(content)
print(f"[*] 抓到 {len(hits)} 个路径声明")

ok, miss, perm, dirs = [], [], [], []
for field, p in hits:
    wp = p.replace("/", os.sep).lstrip("\\")
    if wp.startswith("\\"):
        wp = wp.lstrip("\\")
    if not os.path.exists(wp):
        miss.append((field, p))
        continue
    if os.path.isdir(wp):
        dirs.append((field, p))
        continue
    if not os.access(wp, os.R_OK):
        perm.append((field, p))
        continue
    ok.append((field, p))

print(f"[OK] 可读: {len(ok)}  [DIR] 目录: {len(dirs)}  [MISS] 不存在: {len(miss)}  [PERM] 拒绝: {len(perm)}")

if miss:
    print("\n=== 路径不存在 (MUST FIX) ===")
    for f, p in miss:
        print(f"  {f}: {p}")

if perm:
    print("\n=== 权限拒绝 (MUST FIX) ===")
    for f, p in perm:
        print(f"  {f}: {p}")

if dirs:
    print(f"\n=== 目录({len(dirs)} 个,未展开)===")
    for f, p in dirs[:5]:
        print(f"  {f}: {p}")
    if len(dirs) > 5:
        print(f"  ... 还有 {len(dirs)-5} 个")

print(f"\n=== 示例可读 (前 15) ===")
for f, p in ok[:15]:
    print(f"  {f}: {p}")
