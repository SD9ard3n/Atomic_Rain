---
name: saml-attacks
description: CWE: 295 / 347 | ROI: 高 (P1) 轻便原则: 只放 SAML 高 ROI 路由: Signature Wrapping / Comment 注入 / Assertion 伪造。具体 XSW 变体不堆。
category: vuln
tags: [auth]
---

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

## 7. Attack Surface

| 入口 | 备注 |
| :--- | :--- |
| **SAML SSO 登录端点** | `/saml/login` / `/saml/SSO` / `/Shibboleth.sso/` |
| **ACS URL** (Assertion Consumer Service) | SP 接收 IdP 响应 |
| **SP-initiated SSO** | 业务侧主动跳转 |
| **IdP-initiated SSO** | IdP 直接 POST 到 SP |
| **企业 SSO 集成** | Okta / Azure AD / Auth0 / Keycloak |
| **Single Logout** | SLO endpoint |
| **Metadata 端点** | `/saml/metadata` 含证书与配置 |
| **跨域 IFrame SAML** | 嵌入 SSO 流程 |

---

## 8. High-Value Targets

1. **企业 OA / 内部系统 SAML SSO** — 接管管理员 → 内部全失守 (P0)
2. **多租户 SaaS 用 SAML** — 跨租户接管 (P0)
3. **政府 / 金融 SAML** — 高敏感 + 老系统多漏洞 (P0)
4. **自建 SAML 服务 (Spring Security SAML / OpenSAML)** — 历史 CVE 多 (P0)
5. **OpenSAML / Shibboleth** — 各历史 CVE
6. **混合 IdP (本地 + 云)** — 信任边界混乱 (P1)

---

## 9. False Positives

| 误报 | 真实判断 |
| :--- | :--- |
| XSW 修改后登录成功但身份不变 | SP 只读签名 Assertion,不被攻破 | 试 XSW 其他变体 |
| Comment 注入回显但身份不变 | SP 在 NameID 取值前规范化 | 不是有效漏洞 |
| 修改属性后 200 但权限不变 | 后端不读 SAML 属性 | 不是 BFLA 入口 |
| 无 Signature 直接登录 | 可能是测试环境 / 内部信任网络 | 看是否生产环境 |

---

## 10. Impact / 升级路径

| 链 | 终态 | Impact |
| :--- | :--- | :--- |
| XSW + 管理员 NameID | 管理员接管 | Critical |
| Comment 注入 → 任意账号 | 账号接管 | Critical |
| 无签名 → 伪造任意身份 | 任意账号 | Critical |
| 属性伪造 (role/isAdmin) | 提权 | Critical |
| 弱签名 (RSA-SHA1) → 碰撞 | 长期后门 | Critical |
| ACS URL SSRF | SSRF + 内网横向 | Critical |
| Metadata 泄露 (cert/URL) | 信息泄露 | Medium |

**证据 (P3.5)**:
- 不要拿到管理员身份就猛刷管理 API,只调 1 个 read-only 证明
- 跨租户先 HITL 让用户决定是否真测

---

## 11. Pro Tips

- **抓包先关注是 SP-initiated 还是 IdP-initiated**: 测试方向不同
- **XSW 必须 XML 严格构造**: 缩进 / XML namespace 不对,SP 直接拒
- **Comment 注入是老 SAML 漏洞**: `python-saml` / `pysaml2` 历史漏洞 (CVE-2017-11427)
- **国内企业 SAML**: 政府 / 银行 / 国企 用 OneAccess / 联软等,常无签名验证
- **Metadata 端点泄露 IdP/SP 证书**: 看签名算法弱不弱
- **`pretty print` 改动空白**: XSW 时缩进必须与原签名完全一致
- **`InResponseTo` 字段必查**: SP 应验证,但常忘 → Replay 攻击
- **Replay 时间窗**: 看 `NotOnOrAfter` 是否被严格验证

---

## 12. 工具升级线

**classic 版**:
- 综合: `SAML Raider` (Burp 插件) / `SAMLtool`
- 解码: 手 base64 + 浏览器 XML 查看
- 自建 IdP: 模拟攻击 IdP 测属性伪造

**toolPlus 版**:
- `mcp__yaklang__http_fuzzer` 一次 sweep 多 XSW payload
- `mcp__yaklang__exec_codec` 处理 base64 + URL 编码 SAML
- `mcp__chrome__chrome_inject_script` 自动改 SAML response 重发

---

## 13. 相关参考

- 认证逻辑 → [../auth-logic.md](../auth-logic.md)
- OIDC/OAuth 相邻 → [oidc-attacks.md](oidc-attacks.md) / [oauth-advanced.md](oauth-advanced.md)
- OOB → [../oob-infrastructure.md](../oob-infrastructure.md)
