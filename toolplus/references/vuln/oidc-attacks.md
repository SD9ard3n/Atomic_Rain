---
name: oidc-attacks
description: CWE: CWE-347 / CWE-345 / CWE-294 | OWASP: WSTG-IDNT-04 / A07:2021 核心: OIDC 在 OAuth 2.0 之上加 idtoken (JWT)、discovery endpoint、nonce、hybrid fl…
category: vuln
tags: [auth]
---

# OpenID Connect (OIDC) 特有攻击深度手册

← 回主入口 [../../SKILL.md](../../SKILL.md)

> **CWE**: CWE-347 / CWE-345 / CWE-294 | **OWASP**: WSTG-IDNT-04 / A07:2021
> **核心**: OIDC 在 OAuth 2.0 之上加 id_token (JWT)、discovery endpoint、nonce、hybrid flow → 多了 4 个攻击面
> **赏金**: 严重 $3000-$20000 (Google / Microsoft / Auth0 / Okta 集成场景)

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| 响应含 `id_token` (JWT 格式) | OIDC | §1 id_token JWT 攻击 |
| `/.well-known/openid-configuration` 200 | Discovery 暴露 | §2 discovery 利用 |
| `jwks_uri` 暴露 | 公钥集可读 | §1.2 算法混淆 / §3 jwks 攻击 |
| id_token Header `alg: none` 被接受 | 严重: 无签名 | §1.1 |
| `nonce` 缺失或可预测 | 重放可能 | §4 nonce |
| Hybrid Flow (`response_type=code id_token`) | 多面攻击 | §5 |
| `iss` 不校验 | issuer 混淆 | §6 |
| 通用 OAuth 流程 | 退到 OAuth | → [oauth-advanced.md](oauth-advanced.md) |

记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。

---

## 0.1 Triage 速查

| 现象 | 可能原因 | 下一步 |
|------|----------|--------|
| id_token 修改后 401 | RP 校验签名 | 试 alg 混淆 / kid 注入 → [jwt-advanced.md](jwt-advanced.md) |
| Discovery 暴露 但 jwks 受限 | 部分泄露 | 仍可读 endpoint 列表,扩大测试 |
| iss 改成攻击者 IdP 被接受 | issuer 不校验 | 严重,直接接管 |
| nonce 不在 id_token | RP 不校验 | code/token 重放可能 |

### Attack Surface

- `id_token` JWT、Discovery、JWKS、`nonce`、`iss`、`aud`、`c_hash`、`at_hash`。
- OIDC login、账号绑定、hybrid flow、front/back-channel logout、userinfo。
- 第三方 IdP、企业 SSO、移动端回调和多租户 issuer 配置。

### Pro Tips

- 重点验证 RP 是否校验 token, 不只验证 IdP 是否签发。
- 改 `iss/aud/nonce/kid/jku/x5u` 后观察最终登录身份和 session 绑定。
- Discovery/JWKS 公开通常是正常行为, 要证明 RP 信任边界被突破。

### Evidence / Rating Boundary

- Discovery 或 JWKS 可读本身通常不构成漏洞。
- 接受伪造 id_token、issuer 混淆、aud 缺失或 nonce 重放可按账号接管定高危。
- 影响证明必须包含原 token、变造点、RP 接受结果和账号身份变化。

### False Positive Gate

- JWT 可解码不代表可伪造。
- JWKS 公钥公开是 OIDC 设计, 不能单独报告。
- IdP 拒绝变造 token 不代表 RP 安全; 需要以 RP 最终会话为准。

---

## 0.2 OIDC 关键概念速记

| 概念 | 描述 |
|------|------|
| `id_token` | JWT, 含用户身份 (sub, email, name) |
| `access_token` | 同 OAuth, 调用 API 用 |
| `nonce` | RP 生成, AS 必须放回 id_token |
| `c_hash` / `at_hash` | id_token 中的 hash, 验证 code/access_token 完整性 |
| Discovery (`.well-known/openid-configuration`) | OIDC 元数据 |
| JWKS (`jwks_uri`) | 公钥集 |
| `iss` (issuer) | 颁发者 URL |
| `aud` (audience) | 目标 client_id |
| Hybrid Flow (`response_type=code id_token`) | 混合流程, 同时返 code + id_token |
| Implicit Flow (`response_type=id_token token`) | 直接返 id_token (废弃但仍见) |

---

## 1. id_token JWT 攻击 (核心)

### 1.1 alg: none

```json
{"alg":"none","typ":"JWT"}
.{"sub":"admin@target.com","aud":"target-client-id"}
.
```

去掉签名, 部分 RP 不校验 → 直接接管.

### 1.2 算法混淆 (HS↔RS)

用目标 AS 的公钥 (在 jwks_uri 公开) 当 HS256 的 HMAC 密钥, 自签 id_token.

详 → [jwt-advanced.md](jwt-advanced.md) §0

### 1.3 jku / x5u / kid 攻击

OIDC id_token 通常 kid 指向 AS 的 JWKS, 但若 RP 盲信 token 中的 jku → 攻击者托管假 JWKS.

详 → [jwt-advanced.md](jwt-advanced.md) §1-§4

### 1.4 iss / aud 不校验

RP 仅校验签名, 不校验 `iss` (谁颁发) 和 `aud` (给谁):

```
攻击者构造 id_token, iss=https://attacker-as.com, aud=victim-rp-client-id
```

若 victim RP 信任所有有效签名 (但实际仅应信特定 issuer), 攻击者用自己的 IdP 颁发的 token 登录 victim.

### 1.5 nonce 不校验

```
RP 生成 nonce_A, AS 应放回 id_token.nonce = nonce_A.
若 RP 不校验 → 旧 token 可重放 / cross-session attack.
```

### 1.6 sub 字段攻击

`sub` 应是 IdP 内唯一用户 ID, 但 RP 错误用 `email` 或 `preferred_username` 当唯一标识 → 第三方 IdP 投放假 email 接管 (见 [oauth-advanced.md](oauth-advanced.md) §7.1).

---

## 2. Discovery Endpoint 攻击

### 2.1 Discovery 篡改

OIDC RP 拉取 `https://idp.com/.well-known/openid-configuration` 获取所有 endpoint URL.

```json
{
  "issuer": "https://idp.com",
  "authorization_endpoint": "https://idp.com/authorize",
  "token_endpoint": "https://idp.com/token",
  "jwks_uri": "https://idp.com/jwks.json",
  "userinfo_endpoint": "https://idp.com/userinfo",
  ...
}
```

**攻击**: 如果 RP 允许动态配置 IdP discovery URL:

```
攻击者提供: https://attacker.com/.well-known/openid-configuration
返回: {"jwks_uri":"https://attacker.com/jwks.json", "issuer":"https://idp.com", ...}
```

RP 用 attacker JWKS 验证 → attacker 私钥可签任意 id_token.

### 2.2 jwks_uri 拉取漏洞

若 RP 周期性刷新 jwks_uri 内容 + URL 可控 → 攻击者切换 JWKS 内容偷偷接管.

### 2.3 issuer 校验绕过

```
攻击者 issuer: "https://idp.com.evil.com"
RP 用 startsWith("https://idp.com") → 通过
RP 实际拉 metadata 从 evil.com → 拿假 JWKS
```

---

## 3. Hybrid Flow 攻击

### 3.1 Hybrid Flow 流程

```
response_type=code id_token
→ AS 同时返 code + id_token (在 fragment)
→ RP 应校验 id_token.c_hash == hash(code)
```

### 3.2 c_hash 不校验 → code injection

攻击者拿到自己的 id_token (含 c_hash), 替换 code 为 victim 的 code:

```
fragment#code=VICTIM_CODE&id_token=ATTACKER_ID_TOKEN
```

若 RP 不校验 c_hash, 用 victim code 兑换 victim token, 但 id_token 显示 attacker 身份 → 复杂混合接管.

### 3.3 at_hash 不校验

同理对 access_token. Hybrid + Implicit 都涉及.

---

## 4. RP-Initiated Logout 攻击

### 4.1 Open Redirect via post_logout_redirect_uri

```
GET /oidc/logout?post_logout_redirect_uri=https://evil.com&id_token_hint=...
```

OIDC 规范允许 logout 后跳转, 但 RP 经常不校验 post_logout_redirect_uri 白名单 → Open Redirect.

### 4.2 ID Token Hint 重放

`id_token_hint` 应表明谁要 logout, 攻击者可拿旧 token 强制 victim logout (DoS).

---

## 5. Front-Channel / Back-Channel Logout

### 5.1 Front-Channel Logout

AS 通过 iframe 通知所有 RP 用户登出. 若 RP 未校验 iframe origin → CSRF 强制登出.

### 5.2 Back-Channel Logout (新)

AS 直接 POST 到 RP 的 logout endpoint, 带 logout_token (JWT).

**攻击**: 若 RP 未校验 logout_token 签名 → 任意 attacker POST → 强制登出.

---

## 6. Userinfo Endpoint 攻击

### 6.1 Token 替换

```
GET /userinfo
Authorization: Bearer <attacker_token>
```

若 RP 仅看 token signature 不看 audience → attacker 可拿任意 token 调.

### 6.2 GET 改 POST

某些 AS 既支持 GET 也支持 POST, 但 CSRF 防御只在 POST 上 → GET 用于绕过.

### 6.3 Scope 越权

token 仅有 `openid` scope, 但 userinfo 返回 email / phone (本应需 `email` / `phone` scope).

---

## 7. CIBA (Client-Initiated Backchannel Authentication)

新流程, 用户在手机上确认而非浏览器跳转. 攻击面:

- `binding_message` 缺失 → 用户不知道在确认什么 (社工)
- `auth_req_id` 重放
- Polling endpoint 被滥用 (DoS)

---

## 8. 工具

### 8.1 OIDC-EXPLORER (CLI)

```bash
# 自动拉 discovery + 测 alg:none / iss / aud / jwks_uri
oidc-explorer scan --idp https://idp.com --rp https://target.com
```

### 8.2 jwt_tool

针对 id_token 的所有 JWT 攻击 (见 [jwt-advanced.md](jwt-advanced.md)).

### 8.3 Burp + 手工

手动改 id_token 的 alg / iss / aud / nonce, 重发到 RP /callback.

---

## 9. Testing Checklist

- [ ] 拿到 id_token 后, decode header, 测所有 JWT 攻击 (见 [jwt-advanced.md](jwt-advanced.md))
- [ ] iss 改成攻击者 issuer → 看 RP 是否校验
- [ ] aud 改成其他 client_id → 看 RP 是否校验
- [ ] nonce 删除 / 改值 → 看 RP 是否校验
- [ ] sub 改成 victim 的 sub → 看 RP 是否信任
- [ ] Discovery URL 可控时, 提供假 metadata
- [ ] jwks_uri 可控时, 提供假 JWKS
- [ ] Hybrid flow: c_hash 不校验测试
- [ ] Logout post_logout_redirect_uri Open Redirect
- [ ] Front-Channel Logout iframe origin
- [ ] Back-Channel Logout token 签名校验
- [ ] Userinfo token 替换 / scope 越权
- [ ] CIBA: binding_message 社工链路

---

## 10. False Positive Traps

| 陷阱 | 真相 |
|------|------|
| alg:none 接受但 RP 拒绝登录 | RP 后续校验 sub 在数据库存在性, 仍是 bypass 但需找有效 sub |
| iss 改成自己但 RP 401 | RP 严格白名单, 非漏洞 |
| aud 不校验, 但 audience 实际相同 | 多 client 共用同 audience 时不算漏洞 |
| nonce 删除 RP 仍登录 | 单次会话内可能不影响, 跨会话才能利用 |
| Discovery 假 metadata 失效 | RP 缓存了 metadata, 不会立刻刷新 |

---

## 11. 影响证明

- **低**: id_token 解析能力, 无伪造
- **中**: nonce / sub / aud 单字段 bypass, 接管同 issuer 内某用户
- **高**: alg:none / HS-RS 混淆完整伪造, 接管任意用户
- **严重**: Discovery / jwks_uri 篡改 → 跨 IdP 接管 / 多 RP 批量接管 / 接管 admin

---

## 12. 相关参考

- 主入口 → [../../SKILL.md](../../SKILL.md)
- **JWT 高级** (核心, OIDC 大部分攻击都依赖 JWT) → [jwt-advanced.md](jwt-advanced.md)
- **OAuth 高级** (基础流程攻击) → [oauth-advanced.md](oauth-advanced.md)
- SAML 攻击 → [saml-attacks.md](saml-attacks.md)
- 子域接管 (jwks_uri 子域接管) → [subdomain-takeover.md](subdomain-takeover.md)
- 认证逻辑 → [../auth-logic.md](../auth-logic.md)
- API 安全 (userinfo / token 端点) → [../api-security.md](../api-security.md)

---

**CWE**: CWE-347 / CWE-345 / CWE-294 | **WSTG**: IDNT-04 | **CVSS 典型**: 9.8 (Discovery 篡改全接管) / 8.1 (alg:none / iss 不校验) / 7.5 (Hybrid c_hash 缺失)
