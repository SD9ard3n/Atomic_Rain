---
name: tool-config
description: toolPlus 版:绝大多数工具能力已被 MCP 替代,本文件只保留 MCP 真的做不到且能在命令行调用的工具(本机 .py / .exe / .jar CLI)。GUI-only 工具(冰蝎/哥斯拉/蚁剑/CS 等)不在此登记。
category: methodology
---

# 工具路径配置 — toolPlus (CLI-only)

> **范围限定**:本文件只登记**本机已部署、能在命令行调用的工具**(Python 脚本 / 控制台 .exe / 可用 `java -jar` 调用的 jar)。**GUI-only 工具**(冰蝎/哥斯拉/蚁剑/CS/Struts2 GUI 等)不在此处登记。
> **能力注册表**: `../capabilities/mcp-capabilities.json` — toolPlus 稳定 capability ID 到运行时 MCP namespace 的映射契约(必读)
> **主战场**: [mcp-tools-finder.md](mcp-tools-finder.md) — 70 个 MCP 工具按用途分类 + 10 个典型工作流
> **运行时就绪检查**: [mcp-readiness.md](mcp-readiness.md) — Yakit SSE、Chrome streamable HTTP、namespace、分组件降级

## ⚠️ 配置说明

本文件为**示例模板**，请根据你的本地环境修改工具路径。

**配置步骤**:
1. 安装所需的安全测试工具（见下方工具清单）
2. 将本文件中的路径替换为你的实际安装路径
3. 确保 Python/Java/Node.js 等运行时环境已安装
4. 测试工具是否可以通过命令行调用

**路径书写规范**:
- Git Bash 环境使用正斜杠: `/path/to/tool.exe`
- Windows CMD 环境使用反斜杠: `C:\path\to\tool.exe`
- 推荐使用绝对路径避免相对路径问题

---

## 本机 CLI 工具箱根目录

> 以下为示例配置，请根据实际情况修改

| 代号 | 路径（示例） | 备注 |
|---|---|---|
| **TOOLS_ROOT** | `/path/to/security-tools` | 安全工具根目录（自定义） |
| **CTF_TOOLS** | `/path/to/ctf-tools` | CTF 工具目录（可选） |

---

## 1. 主动扫描 (.exe 控制台)

```yaml
# === 示例配置 — 请修改为实际路径 ===

xray:
  path: "/path/to/xray/xray_windows_amd64.exe"
  config: "/path/to/xray/config.yaml"
  usage: "xray_windows_amd64.exe webscan --listen 127.0.0.1:7777 --html-output report.html"
  mcp_alt: "mcp__yaklang__hybrid_scan"
  note: "被动扫描 + 主动爬虫;需先配置 config.yaml"
  install: "https://github.com/chaitin/xray"

nuclei:
  path: "/path/to/nuclei/nuclei.exe"
  templates: "/path/to/nuclei-templates/"
  usage: "nuclei.exe -u http://target -t cves/"
  mcp_alt: "mcp__yaklang__hybrid_scan"
  note: "PoC 扫描器;需下载 nuclei-templates"
  install: "https://github.com/projectdiscovery/nuclei"

httpx:
  path: "/path/to/httpx/httpx.exe"
  usage: "httpx.exe -l url.txt -title -status-code"
  mcp_alt: "mcp__yaklang__http_fuzzer (baseline)"
  note: "快速 HTTP 探测"
  install: "https://github.com/projectdiscovery/httpx"

fscan:
  path: "/path/to/fscan/fscan.exe"
  usage: "fscan.exe -h 192.168.1.0/24"
  mcp_alt: "mcp__yaklang__port_scan + brute"
  note: "内网综合扫描"
  install: "https://github.com/shadow1ng/fscan"
```

---

## 2. 目录 / 子域 / 指纹 (Python CLI)

```yaml
dirsearch:
  path: "/path/to/dirsearch/dirsearch.py"
  python: "python3"
  usage: "python3 dirsearch.py -u http://target -e php,html,js"
  mcp_alt: "mcp__yaklang__web_crawler + payload"
  install: "https://github.com/maurosoria/dirsearch"

GitHack:
  path: "/path/to/GitHack/GitHack.py"
  python: "python3"
  usage: "python3 GitHack.py http://target/.git/"
  note: ".git 目录泄露下载"
  install: "https://github.com/lijiejie/GitHack"

wafw00f:
  python: "python3"
  usage: "python3 -m wafw00f http://target"
  note: "WAF 指纹识别;推荐用 pip install wafw00f"
  install: "pip install wafw00f"
```

---

## 3. SQL 注入 / SSTI / XSS (Python CLI)

```yaml
sqlmap:
  path: "/path/to/sqlmap/sqlmap.py"
  python: "python3"
  usage: "python3 sqlmap.py -u 'http://target/?id=1' --batch --level=3 --risk=2"
  mcp_alt: "mcp__yaklang__http_fuzzer + payload (避免 sqlmap 默认跑全)"
  note: "SQL 注入利用;建议配合 MCP http_fuzzer 做 First-pass"
  install: "https://github.com/sqlmapproject/sqlmap"

Fenjing:
  path: "/path/to/Fenjing"
  python: "python3"
  install: "pip install -r requirements.txt"
  usage: "python3 -m fenjing scan -u 'http://target/?name={{7*7}}'"
  note: "SSTI 注入 + WAF 绕过"
  install_url: "https://github.com/Marven11/Fenjing"

XSStrike:
  path: "/path/to/XSStrike/xsstrike.py"
  python: "python3"
  install: "pip install -r requirements.txt"
  usage: "python3 xsstrike.py -u 'http://target/?q=test' --fuzzer"
  mcp_alt: "mcp__chrome__chrome_navigate + 反射检测"
  install_url: "https://github.com/s0md3v/XSStrike"
```

---

## 4. 中间件 / 框架 / CMS (Python / Jar CLI)

```yaml
# === SpringBoot 专项 ===
SpringBoot-Scan:
  path: "/path/to/SpringBoot-Scan/SpringBoot-Scan.py"
  python: "python3"
  install: "pip install -r requirements.txt"
  usage: "python3 SpringBoot-Scan.py -u http://target"
  mcp_alt: "vuln/spring-vuln.md + http_fuzzer"
  note: "Spring Boot actuator/env/heapdump 信息泄露 + CVE 扫描"
  install_url: "https://github.com/AabyssZG/SpringBoot-Scan"

# === 反序列化 gadget 生成 (jar, java -jar) ===
ysoserial:
  path: "/path/to/ysoserial/ysoserial.jar"
  java: "java"
  usage: "java -jar ysoserial.jar CommonsCollections1 'id' | base64"
  mcp_alt: "mcp__yaklang__exec_codec (Java 序列化模块)"
  note: "Java 反序列化 payload 生成"
  install: "https://github.com/frohoff/ysoserial"

JNDIExploit:
  path: "/path/to/JNDIExploit/JNDIExploit.jar"
  java: "java"
  usage: "java -jar JNDIExploit.jar -i 0.0.0.0"
  note: "JNDI 注入利用 (Fastjson/Log4j 链)"
  install: "https://github.com/WhiteHSBG/JNDIExploit"
```

---

## 5. 内网 / 横向 (CLI)

```yaml
# === Neo-reGeorg 隧道 (Python CLI) ===
Neo-reGeorg:
  path: "/path/to/Neo-reGeorg/neoreg.py"
  python: "python3"
  install: "pip install requests"
  usage: "python3 neoreg.py generate -k password"
  note: "HTTP/SOCKS 隧道代理"
  install_url: "https://github.com/L-codes/Neo-reGeorg"

# === frp 内网穿透 ===
frpc:
  path: "/path/to/frp/frpc"
  config: "/path/to/frp/frpc.toml"
  usage: "frpc -c frpc.toml"
  note: "frp 客户端"
  install: "https://github.com/fatedier/frp/releases"

frps:
  path: "/path/to/frp/frps"
  config: "/path/to/frp/frps.toml"
  usage: "frps -c frps.toml"
  note: "frp 服务端"
```

---

## 6. 通用 CLI 工具 / 协议 (fallback)

```yaml
curl:
  note: "系统内置,**默认禁止用** (走 http_fuzzer);仅 MCP 连接失败时作 backup probe"

jq:
  note: "JSON 解析;用于处理 API 响应"
  install: "https://stedolan.github.io/jq/"
```

---

## 7. 抓包 / 流量分析 (MCP/CLI 兜底,无 GUI-only)

```yaml
# === Yakit 自身 (含 yak 引擎 CLI) ===
yakit:
  note: "Yakit GUI 是 MCP 主战场;yak CLI 通常由 Yakit 自身进程托管,不直接用"
  install: "https://www.yaklang.com/"

# === BurpSuite (jar, java -jar) ===
burpsuite:
  jar: "/path/to/burpsuite/burpsuite_pro.jar"
  java: "java"
  note: "需配置 JRE + 激活;推荐用启动脚本"
  install: "https://portswigger.net/burp"
```

---

## 8. 调用对照表(MCP-first → CLI fallback)

| 测试目标 | MCP-first 顺序 | CLI fallback |
|---|---|---|
| 黑盒 Web 站 | `mcp__yaklang__http_fuzzer` → `query_http_flow` | `httpx` (存活) + `xray` (漏扫) |
| 子域/资产 | `mcp__yaklang__subdomain_collection` | subfinder + amass |
| 主动漏扫 | `mcp__yaklang__hybrid_scan` | `nuclei` + `xray` |
| API 渗透 | `mcp__chrome__chrome_navigate` + network | swagger 手动分析 |
| Spring Boot | `mcp__yaklang__http_fuzzer` + vuln/spring-vuln.md | `SpringBoot-Scan` |
| SQL 注入 | `mcp__yaklang__http_fuzzer` + payload | `sqlmap` |
| SSTI | `mcp__yaklang__http_fuzzer` + ssti payload | `Fenjing` |
| XSS | `mcp__chrome__chrome_navigate` + 反射检测 | `XSStrike` |
| .git 泄露 | `mcp__chrome__chrome_navigate` + curl | `GitHack` |
| WAF 识别 | (无 MCP 替代) | `wafw00f` |
| 反序列化 | `mcp__yaklang__exec_codec` | `ysoserial` + `JNDIExploit` |
| 内网横移 | `mcp__yaklang__brute` + `port_scan` | `fscan` |
| 隧道代理 | (无 MCP 替代) | `Neo-reGeorg` / `frpc` |

---

## 9. 不在本文件登记的工具

- **Webshell 管理** (冰蝎/哥斯拉/蚁剑) — GUI-only,MCP 不可替代
- **C2 框架** (Cobalt Strike / Sliver) — 独立框架,不在此登记
- **OA 综合 GUI** (Struts2 / ThinkPHP GUI) — GUI-only
- **APP Hook** (Frida / Objection) — 物理设备专用
- **红队工具** — 不在此 skill 范围

---

## 10. 环境依赖

```yaml
python:  "python3"         # Python 3.8+ 推荐
java:    "java"            # JDK 11+ 推荐
node:    "node"            # Node.js 16+ (可选)
git:     "git"             # 工具更新

# 通用 Python 依赖（根据使用的工具安装）
py_pkgs:
  - "requests"
  - "click"
  - "dnspython"
  - "urllib3"
  - "beautifulsoup4"
  - "lxml"
```

---

## 11. 故障回退

| 故障 | 处理 |
|---|---|
| Yakit MCP 不可用 | 标 `[DEGRADED:YAKIT_MCP_DOWN]`;**fallback 到 httpx + xray + sqlmap CLI** |
| Chrome MCP 不可用 | 标 `[DEGRADED:CHROME_MCP_DOWN]`;**fallback 到 curl/httpx 手动验证** |
| SSA 不可用 | 标 `[DEGRADED:SSA_UNAVAILABLE]`;**fallback 到 grep** |
| Codec 不可用 | 标 `[DEGRADED:CODEC_UNAVAILABLE]`;**fallback 到 ysoserial + Burp Decoder** |

---

## 12. 配置示例

创建一个 `tool-config.local.md` 文件来存储你的本地配置（该文件已在 `.gitignore` 中）：

```markdown
# 本地工具配置（不提交到 Git）

## 我的工具路径

xray:
  path: "C:/Tools/xray/xray.exe"
  config: "C:/Tools/xray/config.yaml"

sqlmap:
  path: "C:/Tools/sqlmap/sqlmap.py"
  
# ... 其他工具配置
```

---

*toolPlus 工具配置模板 v2.0 — 通用版（上架 GitHub 前请根据本地环境配置实际路径）*
