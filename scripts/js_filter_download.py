#!/usr/bin/env python3
"""
JS 过滤下载器 — 根据第三方 JS 黑名单,仅下载自定义业务 JS。

用法:
    python js_filter_download.py -i js_urls.txt -o ./target/js/
    cat urls.txt | python js_filter_download.py -o ./target/js/

与 blackbox-pentest-master SKILL.md 的 "JS 文件下载规则" 对齐。
黑名单读取 assets/third-party-js-blacklist.txt, 不存在则用内置默认。
"""
import argparse
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

DEFAULT_BLACKLIST = [
    "vue", "vue-router", "react", "react-dom", "react-router",
    "jquery", "bootstrap", "lodash", "moment", "axios",
    "echarts", "element", "antd", "vuetify", "ant-design",
    "polyfill", "regenerator", "core-js", "babel",
    "chunk-vendors", "vendors", "node_modules",
    "three", "d3", "chart", "swiper", "animate",
    "font-awesome", "material-icons",
    "googletagmanager", "google-analytics", "gtag",
    "sentry", "hotjar", "clarity",
]


def load_blacklist(path: Path) -> list:
    if path and path.exists():
        return [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
    return DEFAULT_BLACKLIST


def is_third_party(url: str, blacklist: list) -> bool:
    fname = os.path.basename(urlparse(url).path).lower()
    for kw in blacklist:
        if kw.lower() in fname:
            return True
    return False


def safe_filename(url: str) -> str:
    name = os.path.basename(urlparse(url).path) or "index.js"
    # 替换不安全字符
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


def download(url: str, out_dir: Path, timeout: int = 15) -> bool:
    try:
        req = Request(url, headers={"User-Agent": "Mozilla/5.0 (BlackboxPentest JS Filter)"})
        with urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        dst = out_dir / safe_filename(url)
        dst.write_bytes(data)
        print(f"[+] {url} -> {dst} ({len(data)} bytes)")
        return True
    except Exception as e:
        print(f"[-] {url} FAILED: {e}", file=sys.stderr)
        return False


def main():
    ap = argparse.ArgumentParser(description="Filter and download JS URLs (skip 3rd-party/framework files).")
    ap.add_argument("-i", "--input", help="Input file (one URL per line). Default: stdin.")
    ap.add_argument("-o", "--output", required=True, help="Output directory.")
    ap.add_argument("-b", "--blacklist", help="Path to blacklist file (default: ../assets/third-party-js-blacklist.txt).")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--dry-run", action="store_true", help="Only print which URLs would be downloaded.")
    args = ap.parse_args()

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    bl_path = Path(args.blacklist) if args.blacklist else Path(__file__).parent.parent / "assets" / "third-party-js-blacklist.txt"
    blacklist = load_blacklist(bl_path)

    if args.input:
        urls = Path(args.input).read_text(encoding="utf-8").splitlines()
    else:
        urls = sys.stdin.read().splitlines()
    urls = [u.strip() for u in urls if u.strip() and u.startswith("http")]

    skipped = 0
    downloaded = 0
    for url in urls:
        if is_third_party(url, blacklist):
            skipped += 1
            continue
        if args.dry_run:
            print(f"[would download] {url}")
            downloaded += 1
        else:
            if download(url, out, timeout=args.timeout):
                downloaded += 1

    print(f"\n[summary] downloaded={downloaded} skipped={skipped} total={len(urls)}")


if __name__ == "__main__":
    main()
