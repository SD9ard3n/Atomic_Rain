---
name: ffuf
description: ffuf 实战 playbook — 目录爆破 / 参数 fuzz / vhost 枚举 / 子域名爆破 / 速率与误报过滤。Phase 1-2 主战工具。
category: tooling
tags: [tool, fuzzing, directory, ffuf, classic]
---

# ffuf Playbook (classic only)

> **何时用本文件**: 目录 / 文件 / 参数名 / vhost / 子域名 fuzzing。比 dirsearch / gobuster 都快。
> **toolPlus 替代**: `mcp__yaklang__http_fuzzer` + fuzztag DSL (语法更现代,集成 OOB)。
> **强制约束**: 大字典 (>10k) 必先 HITL 确认速率与范围。

---

## 1. 配置

```yaml
# tool-config.md
ffuf: "/path/to/ffuf/"
seclists: "/path/to/SecLists/"
```

---

## 2. 八大典型 Recipe

### 2.1 目录爆破 (经典)

```bash
ffuf -u "https://target/FUZZ" \
  -w SecLists/Discovery/Web-Content/common.txt \
  -mc 200,301,302,401,403 \
  -fs 0 \
  -t 50 -rate 100
# -mc match code,-fs 过滤 size 0
# -t 线程 -rate 限速
```

### 2.2 多层目录

```bash
ffuf -u "https://target/FUZZ/FUZZ2" \
  -w dirs.txt:FUZZ -w files.txt:FUZZ2 \
  -mc 200
# 两级 wordlist 笛卡尔积
```

### 2.3 参数名 fuzz (发现隐藏参数)

```bash
ffuf -u "https://target/api/users?FUZZ=test" \
  -w SecLists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs <basesize> -mc 200
# -fs 过滤基线长度
```

### 2.4 参数值 fuzz (枚举 ID / 用户名)

```bash
ffuf -u "https://target/api/user/FUZZ" \
  -w numbers.txt \
  -mc 200 -ms <basesize>
# -ms match size,只显特定长度响应
```

### 2.5 vhost 枚举

```bash
ffuf -u "https://target" \
  -w SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.target.com" \
  -fs <basesize>
# 探内部 vhost
```

### 2.6 子域 + IP 探活

```bash
ffuf -u "https://FUZZ.target.com" \
  -w subdomains.txt \
  -mc 200,301,302,403 \
  -t 30 -rate 50
# 比 subfinder + httpx 慢但准
```

### 2.7 POST Body fuzz

```bash
ffuf -u "https://target/login" \
  -X POST \
  -d "username=admin&password=FUZZ" \
  -w SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt \
  -fs <basesize>
# 配合密码字典做爆破
```

### 2.8 配合自定义 Header / Cookie

```bash
ffuf -u "https://target/admin/FUZZ" \
  -w dirs.txt \
  -H "Cookie: session=abc123" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -mc 200,403
```

---

## 3. atomic-rain 协议集成

| 阶段 | 动作 |
| :--- | :--- |
| Phase 1 | 目录爆破 + vhost 枚举 |
| Phase 2 First-pass | 参数 fuzz 找隐藏 endpoint |
| Phase 2 中 | 路径 ID 枚举验证 BOLA |
| Phase 3 | 拼接 payload 字符串多变体测试 |

**OPSEC**:
- 大目标先用 `common.txt` (~4k) 探一遍,有目标再用 `directory-list-medium.txt` (~200k)
- WAF 触发立即降 rate / 改 UA

---

## 4. 字典选择

| 场景 | 推荐字典 |
| :--- | :--- |
| 通用目录 | `Discovery/Web-Content/common.txt` (4.7k) |
| 大字典精扫 | `Discovery/Web-Content/directory-list-2.3-medium.txt` (220k) |
| API endpoint | `Discovery/Web-Content/api/` |
| 配置 / 备份 | `Discovery/Web-Content/Common-PHP-Filenames.txt` + `raft-*.txt` |
| 隐藏参数 | `Discovery/Web-Content/burp-parameter-names.txt` (2.5k) |
| 子域 | `Discovery/DNS/subdomains-top1million-110000.txt` |
| 短字典(快速验证) | `Discovery/Web-Content/quickhits.txt` (~3k) |

---

## 5. False Positives 过滤

ffuf 强大就在过滤选项,误报全靠 `-fs/-fc/-fl/-fw/-fr`:

| 过滤选项 | 用途 |
| :--- | :--- |
| `-mc 200` | 只显特定状态码 |
| `-fc 404,500` | 排除特定状态码 |
| `-fs 1234` | 过滤特定大小响应 |
| `-fw 50` | 过滤特定单词数 |
| `-fl 10` | 过滤特定行数 |
| `-fr "regex"` | 过滤匹配正则的响应 |
| `-ms 100-500` | 大小范围 |
| `-ac` | 自动校准 |

**常见误报场景**:
- WAF 拦截返回 200 + WAF 页 → `-fs <waf 页大小>` 过滤
- 框架默认 404 返 200 → `-fs <404 大小>` 过滤
- CDN 缓存命中 → 不带 cookie 重测

---

## 6. Pro Tips

- **`-ac` 自动校准**: 第一次跑用,会自动找基线长度
- **`-recursion`**: 递归扫描子目录 (`-recursion-depth 2` 控制深度)
- **`-replay-proxy http://127.0.0.1:8080`**: 命中后自动重发到 Burp
- **`-of json -o results.json`**: 保存为 JSON,供脚本消费
- **`-rate 100`**: 远程目标统一限速,WAF 友好
- **加 `-H "User-Agent: Mozilla/5.0..."`**: ffuf 默认 UA 会被部分 WAF 拦
- **`-ignore-body` + `-mc 200`**: 只关注状态码,响应不下载 → 极快
- **`-x http://proxy:8080`** 走代理记录所有请求
- **`-noninteractive`**: CI / 脚本调用时不显进度条
- **`FUZZ` 关键字可以自定义**: `-w wordlist.txt:HOSTNAME`

---

## 7. 相关参考

- 资产侦察整体: [../recon.md](../recon.md)
- API 安全 (隐藏 endpoint): [../api-security.md](../api-security.md)
- WAF 绕过: [../waf-bypass.md](../waf-bypass.md)
- 密码爆破: [../weak-password-generation.md](../weak-password-generation.md)
