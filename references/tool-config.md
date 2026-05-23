# 工具路径配置

> 编辑此文件配置你本地工具的绝对路径。Skill 执行命令时会优先使用此处配置的目录，
> 在目录下自动寻找对应可执行文件(.exe/.py/.bat/.jar)。
>
> 未配置的工具将回退到默认命令（假设在 PATH 中）。

---

## 说明

**配置格式**: 所有路径均指向工具所在的**目录**，而非具体可执行文件。

```yaml
# 正确
dirsearch: "/path/to/dirsearch/"

# 错误
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
# 备注: nuclei.exe 所在目录。模板库默认在 ~/nuclei-templates/

httpx: "/path/to/httpx/"

dirsearch: "/path/to/dirsearch/"
# 备注: Python CLI 目录扫描。主入口: dirsearch.py

sqlmap: "/path/to/sqlmap/"
# 备注: Python CLI SQL注入扫描。主入口: sqlmap.py

xray: "/path/to/xray/"
# 备注: xray.exe 高级漏洞扫描器，支持被动/主动模式
```

## Tier 2 — 信息收集（Phase 1 高频）

```yaml
oneforall: "/path/to/oneforall/"
# 备注: Python 子域名收集。主入口: oneforall.py

enscan: "/path/to/enscan/"
# 备注: 企业信息收集。主入口: enscan.exe

nmap: "/path/to/nmap/"
# 备注: nmap.exe + ncat.exe 端口扫描与网络探测

ehole: "/path/to/ehole/"
# 备注: EHole_windows_amd64.exe 指纹识别

P1finger: "/path/to/P1finger/"
# 备注: P1finger64.exe 指纹识别

sslscan: "/path/to/sslscan/"
# 备注: sslscan.exe TLS/SSL 配置检测

wafw00f: "/path/to/wafw00f/"
# 备注: Python WAF 识别。主入口: wafw00f.py 或 python -m wafw00f
```

## Tier 3 — 专项扫描（按需调用）

```yaml
afrog: "/path/to/afrog/"
# 备注: afrog.exe 漏洞扫描器

fscan: "/path/to/fscan/"
# 备注: fscan.exe 内网综合扫描

nxc: "/path/to/nxc/"
# 备注: nxc.exe (NetExec) 内网/AD 渗透

ysoserial: "/path/to/ysoserial/"
# 备注: Java 反序列化利用。主入口: ysoserial.bat 或 ysoserial.jar

swagger_hack: "/path/to/swagger-hack/"
# 备注: Python Swagger API 扫描。主入口: swagger-hack.py

xsstrike: "/path/to/XSStrike/"
# 备注: Python XSS 检测。主入口: xsstrike.py

springboot_scan: "/path/to/SpringBoot-Scan/"
# 备注: Python SpringBoot 专项扫描。主入口: SpringBoot-Scan.py

packerfuzzer: "/path/to/PackerFuzzer/"
# 备注: Python 前端打包(JS/webpack)分析。主入口: PackerFuzzer.py
```

## Tier 4 — 备用/内网扫描器

```yaml
rscan: "/path/to/Rscan/"
# 备注: Rscan_win64.exe 漏洞扫描

xscan: "/path/to/xscan/"
# 备注: xscan.exe 漏洞扫描

pppscan: "/path/to/pppscan/"
# 备注: pppscan.exe 端口扫描

serein: "/path/to/Serein/"
# 备注: Python 漏洞扫描。主入口: Serein.py
```

## 环境依赖

确保以下命令在 PATH 中可用：

```yaml
python:  "python"          # Python 3.x，用于执行 .py 工具
java:    "java"            # JDK 8+，用于执行 .jar 工具
```

---

*配置更新后无需重启 Claude，下次执行命令时自动生效。*
