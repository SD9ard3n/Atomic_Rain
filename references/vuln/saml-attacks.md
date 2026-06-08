# SAML 认证决策卡 (Light Deep Card)

> **CWE**: 295 / 347 | **ROI**: 高 (P1)
> **轻便原则**: 只放 SAML 高 ROI 路由: Signature Wrapping / Comment 注入 / Assertion 伪造。具体 XSW 变体不堆。

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| SAMLRequest/SAMLResponse 在请求中 | SAML 认证流 | §1 抓包分析 |
| `Signature` 在 `Assertion` 外部 | 可能 XSW | §2 |
| Base64 解码后有 `<!-- -->` 注释 | Comment 注入可能 | §3 |
| IdP 返回 Assertion 含 `NameID` / `Role` | 属性可伪造 | §4 |
| SAML 响应无 Signature | 无签名验证,直接伪造 | §4.1 |

记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。

---

## 1. 抓包与解码

```
1. 登录流程抓包 → 找 SAMLResponse 参数
2. Base64 解码 → 检查 Signature 位置与 Assertion 结构
3. 关键检查:
   - Signature 在 Assertion 内还是外?
   - 有几个 Assertion?
   - NameID / Role / email 值是什么?
```

---

## 2. XML Signature Wrapping (XSW)

**核心思想**: 签名验证的是原始 Assertion, 但应用读的是攻击者插入的 Assertion。

### 2.1 First-pass 测试

```xml
<!-- XSW1: 复制已签名 Assertion, 前面插入伪造 Assertion -->
<samlp:Response>
  <Assertion ID="_attack">          <!-- 应用读这个 -->
    <NameID>admin@target.com</NameID>
  </Assertion>
  <Assertion ID="_original" Signature="...">  <!-- 签名验证这个 -->
    <NameID>user@target.com</NameID>
  </Assertion>
</samlp:Response>
```

### 2.2 XSW 变体判断

| 变体 | 方法 | 判断 |
|------|------|------|
| XSW1 | 签名 Assertion 保留,前面插入新 Assertion | 改 NameID 看是否以新值登录 |
| XSW2 | 签名 Assertion 移到 Response 外,内部放伪造 | 同上 |
| XSW3 | 伪造 Assertion 引用签名 Ref URI | 同上 |
| XSW4 | 在签名 Assertion 内注入子元素 | 修改 Role / email |

XSW1 不行就试 XSW2,不行就转 Comment 注入,不要死磕所有变体。

---

## 3. Comment 注入

**原理**: XML 解析器忽略注释,但某些 SAML 库在验证 UID 时不忽略。

```xml
<saml:NameID>user<!-- -->@evil.com</saml:NameID>
```

登录后显示的邮箱/用户名包含注释后的内容 → Comment 注入生效。

---

## 4. Assertion 属性伪造

### 4.1 无签名 (最常见漏洞)

直接修改 NameID / Role / email 为目标值,重新 Base64 编码发送。

### 4.2 有签名但属性未签名

- Signature 只覆盖 Assertion 部分元素
- 修改未签名的属性 (如 Role / group / isAdmin)
- 保持签名部分不变

### 4.3 证书匹配检查

- SP 是否校验 IdP 证书? → 用自签名证书替换试
- 签名算法是否弱? → RSA-SHA1 可能被替换

---

## 5. Triage

| 现象 | 可能原因 | 下一步 |
|------|----------|--------|
| 修改后 500 / Invalid Signature | SP 验证签名,无法绕 | 转 Comment 注入或属性伪造 |
| 修改后登录但身份不变 | SP 只读签名 Assertion | 试 XSW2 / XSW3 |
| 修改 NameID 后登录身份变了 | 无签名 / 签名绕过成功 | Critical,扩大测试 |
| SAML 响应格式错误 | 编码/转义问题 | 检查 Base64 + XML 特殊字符转义 |
| IdP 是知名云服务 (Okta/Azure) | 签名绕过可能性低 | 重点测 SP 端: 属性伪造 / Replay |

---

## 6. 级联

- SAML 伪造成功 → 管理员身份 → BFLA / 管理接口未授权
- NameID 修改 → 账号接管 → [../auth-logic.md](../auth-logic.md)
- SAML Request 的 ACS URL 可控 → SSRF → [ssrf.md](ssrf.md)
- 云 IdP (Azure AD/Okta) → [../cloud-security.md](../cloud-security.md) 租户接管

---

## 7. 相关参考

- 认证逻辑 → [../auth-logic.md](../auth-logic.md)
- OIDC/OAuth 相邻 → [oidc-attacks.md](oidc-attacks.md) / [oauth-advanced.md](oauth-advanced.md)
- OOB → [../oob-infrastructure.md](../oob-infrastructure.md)
