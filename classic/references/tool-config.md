---
name: tool-config
description: 编辑此文件配置你本地工具的绝对路径。Skill 执行命令时会优先使用此处配置的目录， 在目录下自动寻找对应可执行文件(.exe/.py/.bat/.jar)。
category: methodology
---

# 工具路径配置

> 编辑此文件配置你本地工具的绝对路径。Skill 执行命令时会优先使用此处配置的目录，
> 在目录下自动寻找对应可执行文件(.exe/.py/.bat/.jar)。
>
> 未配置的工具将回退到默认命令（假设在 PATH 中）。
>
> 能力注册表见 [../capabilities/cli-capabilities.json](../capabilities/cli-capabilities.json):先按稳定 capability 选能力,再映射到本地 CLI 工具。

---

## ⚠️ 配置说明

本文件为**示例模板**，所有路径均为占位符。请根据你的本地环境修改。

**配置步骤**:
1. 安装所需的安全测试工具（每个工具下方附官方仓库链接）
2. 把 `/path/to/xxx/` 替换为你的实际安装**目录**
3. 不需要的工具留空 `""` 或删除该行（会回退到 PATH 默认命令）
4. 建议把本地实配存到 `tool-config.local.md`（已在 `.gitignore` 忽略）

**配置格式**: 所有路径均指向工具所在的**目录**，而非具体可执行文件。

```yaml
# 正确（指向目录）
dirsearch: "/path/to/dirsearch/"

# 错误（指向文件）
dirsearch: "/path/to/dirsearch/dirsearch.py"
```

**AI 调用规则**:
- `.exe` 工具 → 直接执行 `目录/工具名.exe`
- Python 工具 → 执行 `python 目录/主入口.py`
- `.bat` 工具 → 直接执行 `目录/工具名.bat`
- `.jar` 工具 → 执行 `java -jar 目录/工具名.jar`

---

## Tier 1 — 核心工具（每次渗透必用）

```yaml
nuclei: "/path/to/nuclei/"
# nuclei.exe 所在目录。模板库默认在 ~/nuclei-templates/
# 安装: https://github.com/projectdiscovery/nuclei

httpx: "/path/to/httpx/"
# httpx.exe 存活探测 + 标题
# 安装: https://github.com/projectdiscovery/httpx

dirsearch: "/path/to/dirsearch/"
# Python CLI 目录扫描。主入口: dirsearch.py
# 安装: https://github.com/maurosoria/dirsearch

sqlmap: "/path/to/sqlmap/"
# Python CLI SQL注入扫描。主入口: sqlmap.py
# 安装: https://github.com/sqlmapproject/sqlmap

xray: "/path/to/xray/"
# xray.exe 高级漏洞扫描器，支持被动/主动模式
# 安装: https://github.com/chaitin/xray
```

## Tier 2 — 信息收集（Phase 1 高频）

```yaml
oneforall: "/path/to/oneforall/"
# Python 子域名收集。主入口: oneforall.py
# 安装: https://github.com/shmilylty/OneForAll

enscan: "/path/to/enscan/"
# 企业信息收集。主入口: enscan.exe
# 安装: https://github.com/wgpsec/ENScan_GO

nmap: "/path/to/nmap/"
# nmap.exe + ncat.exe 端口扫描与网络探测
# 安装: https://nmap.org/download.html

ehole: "/path/to/ehole/"
# EHole 指纹识别
# 安装: https://github.com/EdgeSecurityTeam/EHole

P1finger: "/path/to/P1finger/"
# P1finger 指纹识别
# 安装: https://github.com/P001water/P1finger

sslscan: "/path/to/sslscan/"
# sslscan.exe TLS/SSL 配置检测
# 安装: https://github.com/rbsec/sslscan

wafw00f: "/path/to/wafw00f/"
# Python WAF 识别。主入口: python -m wafw00f
# 安装: pip install wafw00f
```

## Tier 3 — 专项扫描（按需调用）

```yaml
afrog: "/path/to/afrog/"
# afrog.exe 漏洞扫描器
# 安装: https://github.com/zan8in/afrog

fscan: "/path/to/fscan/"
# fscan.exe 内网综合扫描
# 安装: https://github.com/shadow1ng/fscan

nxc: "/path/to/netexec/"
# nxc (NetExec) 内网/AD 渗透
# 安装: https://github.com/Pennyw0rth/NetExec

ysoserial: "/path/to/ysoserial/"
# Java 反序列化利用。主入口: ysoserial.jar
# 安装: https://github.com/frohoff/ysoserial

swagger_hack: "/path/to/swagger-hack/"
# Python Swagger API 扫描。主入口: swagger-hack.py
# 安装: https://github.com/jayus0821/swagger-hack

xsstrike: "/path/to/XSStrike/"
# Python XSS 检测。主入口: xsstrike.py
# 安装: https://github.com/s0md3v/XSStrike

springboot_scan: "/path/to/SpringBoot-Scan/"
# Python SpringBoot 专项扫描。主入口: SpringBoot-Scan.py
# 安装: https://github.com/AabyssZG/SpringBoot-Scan

packerfuzzer: "/path/to/Packer-Fuzzer/"
# Python 前端打包(JS/webpack)分析。主入口: PackerFuzzer.py
# 安装: https://github.com/rtcatc/Packer-Fuzzer
```

## Tier 3.5 — 邮件安全 (SPF / DKIM / DMARC 检测)

> 详见 [vuln/email-spoofing.md](vuln/email-spoofing.md) + [recon.md §1.7](recon.md)
> 发件 PoC 需要 [SKILL.md §1 P3.5](../SKILL.md) 索取接收邮箱

```yaml
spf-master: "/path/to/spf-master/"
# python spf.py target.com 依赖 kitterman.com 第三方 (OPSEC 风险,推荐改用 spoofcheck.py)

spoofcheck: ""
# BishopFox/spoofcheck — python spoofcheck.py target.com (本地解析,推荐)
# 安装: git clone https://github.com/BishopFox/spoofcheck.git

swaks: ""
# swaks --from "fake@target.com" --to user@your.com --server smtp.attacker-vps.com
# Linux: apt install swaks / Win: choco install swaks (或下 perl 脚本)

dig: ""
# 内置工具,Win 11 需要 nslookup 替代或装 BIND9 tools
# 用途: dig TXT target.com _dmarc.target.com default._domainkey.target.com
```

## Tier 4 — 备用/内网扫描器

```yaml
rscan: "/path/to/Rscan/"
# Rscan 漏洞扫描

xscan: "/path/to/xscan/"
# xscan 漏洞扫描

pppscan: "/path/to/pppscan/"
# pppscan 端口扫描

serein: "/path/to/serein/"
# Python 漏洞扫描。主入口: Serein.py
```

## 环境依赖

确保以下命令在 PATH 中可用：

```yaml
python:  "python"          # Python 3.x，用于执行 .py 工具
java:    "java"            # JDK 8+，用于执行 .jar 工具
```

---

*配置更新后无需重启 Claude，下次执行命令时自动生效。*
*本文件为通用模板（上架 GitHub 前请根据本地环境配置实际路径）。*
