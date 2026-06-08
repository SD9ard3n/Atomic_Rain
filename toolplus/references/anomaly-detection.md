---
name: anomaly-detection
description: P1 信号预检异常检测门禁 - 响应头/状态码/时间分布/错误泄露/重定向链异常检测与分类
category: protocol
phase: P1
priority: mandatory
dependencies: [mcp-readiness, agent-protocol]
integration: signal-precheck
---

# Anomaly Detection Protocol

> **版本**: toolPlus v2.0  
> **状态**: Production  
> **前置**: P0.4 环境确认完成，MCP http_fuzzer 可用  
> **集成**: P1 信号预检 mandatory gate

---

## 0. Executive Summary

异常行为检测是 P1 信号预检的**强制前置步骤**，在任何漏洞特征匹配前执行。

**核心逻辑**:
```
First-pass HTTP → 记录三要素 (status/length/duration) 
→ 异常检测 (本协议) 
→ 信号分类 → 路由到具体漏洞文件
```

**优先级分层**:
- **P0 (Critical)**: 响应头调试标记、框架 debug 模式、内部路由泄露
- **P1 (High)**: 非标准状态码、错误信息泄露、重定向链异常
- **P2 (Medium)**: 时间分布异常、字符集异常、自定义业务 Header

---

## 1. 异常信号分类表

| 类别 | 优先级 | 检测对象 | 典型触发 | 后续动作 |
|:---|:---:|:---|:---|:---|
| **响应头异常** | P0 | `X-Debug`, `X-Internal-*`, `Server` 详细版本 | 调试模式开启、内部路由泄露 | 立即测试提权/信息泄露 |
| **状态码异常** | P1 | 418/444/499/529/530 等非标准码 | 中间件异常、WAF 特征、框架 bug | 记录指纹 + 边界测试 |
| **时间分布异常** | P1 | P50/P95/P99 响应时间 | 长尾请求、双峰分布、周期性尖峰 | SQL 注入时间盲注前置信号 |
| **错误信息泄露** | P1 | 堆栈追踪、配置路径、SQL 语句 | 异常未处理、debug=true | 提取技术栈 + 路径遍历 |
| **重定向链异常** | P1 | 3+ 跳转、循环重定向、参数篡改 | SSRF、开放重定向、会话固定 | 测试 `url=` 参数控制 |
| **字符集异常** | P2 | `charset` 不一致、BOM 标记 | XSS bypass、编码注入 | UTF-7/UTF-16 Payload |
| **业务 Header** | P2 | `X-RateLimit-*`, `X-Request-ID` | 速率限制、请求追踪 | 竞态条件、IDOR 关联 |

---

## 2. 响应头异常清单 (P0)

### 2.1 调试标记 (Critical)

| Header | 风险 | 测试动作 | 真实案例 |
|:---|:---|:---|:---|
| `X-Debug: true` | 调试模式开启 | 添加 `X-Internal-User: admin`<br/>添加 `X-Original-URL: /admin` | 某 SRC 发现 `X-Debug: 1` → 测试 `X-Admin-Panel: true` → 成功绕过认证进入管理后台 |
| `X-Powered-By: PHP/7.4.3` | 详细版本泄露 | 查询该版本 CVE | 暴露 PHP 7.4.3 → 已知 iconv() RCE (CVE-2024-2961) |
| `X-Laravel-Cache: hit` | Laravel 框架 + 缓存配置 | 测试缓存投毒 `X-Forwarded-Host` | Laravel 应用 → 缓存投毒导致 XSS 持久化 |
| `X-AspNet-Version: 4.0.30319` | .NET 版本泄露 | ViewState 反序列化 | ASP.NET 4.0 → ViewState 加密弱 → 反序列化 RCE |
| `X-Trace-Id: internal-svc-auth` | 内部服务名泄露 | 枚举 `internal-svc-*` 端点 | 发现 `X-Trace-Id: kafka-admin` → 访问 `/kafka-ui` 无认证 |

### 2.2 框架指纹 (High)

| Header | 框架 | 后续路由 |
|:---|:---|:---|
| `Server: Apache-Coyote/1.1` | Tomcat | `references/frameworks/spring-boot.md` (含 Tomcat) |
| `X-Content-Type-Options: nosniff` 缺失 | 可能存在 MIME 嗅探 | XSS Payload 使用 `Content-Type: text/html` |
| `X-Frame-Options` 缺失 | Clickjacking 风险 | 测试 iframe 嵌入 + UI 遮罩攻击 |
| `Server: Kestrel` | .NET Core | 测试 ASP.NET Core 已知 CVE |
| `X-Drupal-Cache: HIT` | Drupal CMS | 已知 CVE 扫描 + 插件枚举 |

### 2.3 自定义业务 Header (Medium)

```
X-User-Role: guest          → 改为 admin/superuser/root
X-Feature-Flag: beta_off    → 改为 beta_on (测试未发布功能)
X-Tenant-ID: 1001           → IDOR 遍历其他租户
X-API-Version: v1           → 改为 v0/internal/debug
X-Request-Source: web       → 改为 internal/cronjob/admin
```

**检测脚本** (基于 http_fuzzer):
```python
# 通过 mcp__yaklang__http_fuzzer 发送请求后，检查响应头
response_headers = fuzzer_result['ResponseHeaders']

# P0: 调试标记
debug_headers = ['X-Debug', 'X-Internal-User', 'X-Admin', 'X-Dev-Mode']
for h in debug_headers:
    if h in response_headers:
        log_anomaly('P0', f'Debug header detected: {h}={response_headers[h]}')
        # 立即测试: 添加 X-Internal-User: admin

# P0: 详细版本泄露
if 'Server' in response_headers:
    server = response_headers['Server']
    if any(ver in server for ver in ['/', 'PHP', 'Apache', 'nginx']):
        log_anomaly('P0', f'Detailed version: {server}')

# P2: 自定义业务 Header
custom_headers = [h for h in response_headers if h.startswith('X-') 
                  and h not in ['X-Content-Type-Options', 'X-Frame-Options']]
for h in custom_headers:
    log_anomaly('P2', f'Custom header: {h}={response_headers[h]}')
```

---

## 3. 状态码异常清单 (P1)

### 3.1 非标准状态码

| 状态码 | 含义 | 常见场景 | 测试动作 |
|:---:|:---|:---|:---|
| **418** | I'm a teapot | 测试/彩蛋接口 | 可能存在隐藏管理接口 |
| **444** | Nginx 关闭连接 | WAF 拦截、恶意请求检测 | 记录 WAF 特征，调整 Payload 编码 |
| **499** | 客户端主动关闭 | 超时/网络问题 | 如果仅特定参数触发 → 可能是 SQL 时间盲注 |
| **520/521/522** | Cloudflare 源站错误 | 源站不可达、SSL 握手失败 | 记录 CDN 指纹 |
| **529** | 站点过载 | 速率限制、DDoS 防护 | 测试竞态条件窗口期 |
| **530** | Cloudflare 1XXX 错误 | CDN 配置错误 | 可能绕过 CDN 直连源站 |
| **598/599** | 网络超时 | 代理层超时 | 时间盲注前置信号 |

### 3.2 真实案例

```
案例 1: 某企业 API 返回 444 状态码
→ 分析: Nginx 检测到 SQL 关键字 (OR 1=1) 后主动断开
→ 绕过: 使用 /*!50000OR*/ 注释绕过 → 注入成功

案例 2: 某支付接口偶现 499 状态码
→ 分析: 仅当 amount=9999999 时触发
→ 验证: 数据库查询超时 (SELECT * FROM orders WHERE amount > 9999999)
→ 利用: 时间盲注提取管理员密码

案例 3: 某 SRC 目标返回 529 (Cloudflare)
→ 分析: 速率限制触发阈值为 100 req/min
→ 利用: 在限流重置窗口 (每分钟第 0 秒) 发起 20 并发竞态 → 成功重复领取优惠券
```

---

## 4. 时间分布异常 (P1)

### 4.1 异常模式

| 模式 | 特征 | 可能原因 | 验证方法 |
|:---|:---|:---|:---|
| **长尾** | P99 >> P50 (如 50ms vs 5000ms) | 数据库慢查询、文件读取、外部 API | 重复请求 20 次，计算标准差 |
| **双峰** | 两个响应时间峰值 (如 50ms, 500ms) | 缓存命中/未命中、条件分支 | 修改参数观察峰值迁移 |
| **周期性尖峰** | 每 N 秒出现一次慢请求 | 定时任务、缓存过期、GC | 可能暴露后台任务执行时间 |
| **线性增长** | 响应时间随输入长度线性增长 | 正则回溯 (ReDoS)、循环处理 | 发送 `a{1000}` 类 Payload |

### 4.2 检测脚本

```python
# 通过 http_fuzzer 发送 20 次相同请求
durations = []
for i in range(20):
    result = mcp__yaklang__http_fuzzer(
        request_template=base_request,
        params={'id': i}
    )
    durations.append(result['Duration'])

# 计算分位数
import numpy as np
p50 = np.percentile(durations, 50)
p95 = np.percentile(durations, 95)
p99 = np.percentile(durations, 99)

# 异常判定
if p99 > p50 * 10:
    log_anomaly('P1', f'Long tail detected: P50={p50}ms, P99={p99}ms')
    # 可能是 SQL 时间盲注前置信号

# 双峰检测 (简化)
unique_durations = set([round(d, -2) for d in durations])  # 四舍五入到百位
if len(unique_durations) >= 2 and max(unique_durations) > min(unique_durations) * 5:
    log_anomaly('P1', f'Bimodal distribution: {unique_durations}')
```

### 4.3 真实案例

```
案例: 某 SRC 用户查询接口
→ 观察: P50=80ms, P99=3200ms (40 倍差异)
→ 验证: 当 username 包含单引号时, P99=3500ms; 包含 ' AND SLEEP(3)-- 时, P99=3080ms
→ 确认: SQL 时间盲注 (MySQL)
→ 利用: 提取数据库名 → information_schema → admin 表 → 密码哈希
```

---

## 5. 错误信息泄露 (P1)

### 5.1 泄露类型

| 泄露内容 | 示例 | 风险等级 | 利用路径 |
|:---|:---|:---:|:---|
| **堆栈追踪** | `at com.example.UserController.getUser(UserController.java:42)` | High | 提取类名/方法名 → 代码审计目标 |
| **SQL 语句** | `ERROR: column "admin" does not exist` | Critical | 确认 SQL 注入 + 数据库结构 |
| **绝对路径** | `/var/www/html/config/database.php on line 23` | High | 路径遍历基准点 |
| **配置信息** | `Redis connection failed: localhost:6379` | Medium | 内部服务发现 + 端口扫描 |
| **框架版本** | `Laravel Framework 8.40.0` | High | CVE 搜索 + 已知漏洞利用 |
| **数据库类型/版本** | `MySQL 5.7.30` | Medium | 针对性 SQL 注入 Payload |
| **用户名/邮箱** | `User 'admin@internal.local' not found` | Medium | 用户枚举 + 社工库 |

### 5.2 检测模式 (正则)

```python
import re

error_patterns = {
    'stack_trace': [
        r'at [a-zA-Z0-9_.$]+\([a-zA-Z0-9_]+\.java:\d+\)',  # Java
        r'File "/.+\.py", line \d+',                        # Python
        r'in /.+\.rb:\d+:in',                               # Ruby
        r'at [a-zA-Z0-9_.$]+\.cs:line \d+',                # C#
    ],
    'sql_error': [
        r'SQL syntax.*MySQL',
        r'Warning.*mysql_.*',
        r'valid PostgreSQL result',
        r'ORA-\d{5}',                                       # Oracle
        r'Microsoft SQL Server.*error',
        r'SQLite3::SQLException',
    ],
    'file_path': [
        r'(?:/var/www|/usr/local|/home|C:\\\\Windows|C:\\\\inetpub)[\\/][^\s<>"]+',
        r'(?:/etc/|C:\\\\ProgramData\\\\)[^\s<>"]+',
    ],
    'config_leak': [
        r'(Redis|MongoDB|Elasticsearch) connection (?:failed|refused)',
        r'(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d{2,5}',
        r'database: \w+, host: [\w.]+',
    ],
}

def detect_error_leak(response_body):
    findings = []
    for category, patterns in error_patterns.items():
        for pattern in patterns:
            matches = re.findall(pattern, response_body, re.IGNORECASE)
            if matches:
                findings.append({
                    'category': category,
                    'matches': matches[:3],  # 限制输出长度
                })
    return findings
```

### 5.3 真实案例

```
案例 1: 某企业 OA 系统
→ 触发: POST /api/user/update?id=1' 
→ 响应: "You have an error in your SQL syntax near 'admin' at line 1"
→ 利用: 确认 SQL 注入点 → 时间盲注 → 提取 user 表 → 22 个管理员账号

案例 2: 某教育 SRC
→ 触发: GET /download?file=../../../../etc/passwd
→ 响应: "Warning: file_get_contents(/var/www/html/uploads/../../../../etc/passwd): 
         failed to open stream in /var/www/html/controllers/DownloadController.php on line 34"
→ 利用: 确认路径遍历 + 泄露 Web 根目录 → 读取 /var/www/html/config/database.php → 数据库密码

案例 3: 某支付平台
→ 触发: GET /api/order/detail?order_id=abc
→ 响应: "Laravel Framework 8.40.0 - Unhandled Exception: 
         SQLSTATE[42S22]: Column not found: 1054 Unknown column 'abc' in 'where clause'"
→ 利用: Laravel 8.40.0 → CVE-2021-3129 (调试模式 RCE) → 测试 /_ignition/execute-solution → RCE 确认
```

---

## 6. 重定向链异常 (P1)

### 6.1 异常模式

| 模式 | 特征 | 风险 | 测试动作 |
|:---|:---|:---|:---|
| **3+ 跳转** | `302 → 302 → 302 → 200` | 逻辑绕过、参数污染 | 每步记录 URL 参数变化 |
| **循环重定向** | `/a → /b → /a` | 服务端逻辑错误 | 可能绕过认证中间件 |
| **参数篡改** | `?user=guest` → `?user=admin` (自动) | IDOR、权限提升 | 拦截并修改中间跳转参数 |
| **域名切换** | `api.example.com` → `internal.example.com` | 内部服务泄露 | 枚举 internal 子域 |
| **协议降级** | `https://` → `http://` | 中间人攻击、敏感信息泄露 | 检查是否传输 token/cookie |

### 6.2 检测脚本

```python
def trace_redirect_chain(url):
    chain = []
    visited = set()
    
    for i in range(10):  # 最多追踪 10 跳
        result = mcp__yaklang__http_fuzzer(
            request_template=f'GET {url} HTTP/1.1\r\nHost: {{{{host}}}}\r\n\r\n',
            follow_redirects=False  # 手动控制跳转
        )
        
        status = result['StatusCode']
        chain.append({
            'step': i + 1,
            'url': url,
            'status': status,
            'location': result['ResponseHeaders'].get('Location', ''),
            'duration': result['Duration'],
        })
        
        # 检测循环
        if url in visited:
            log_anomaly('P1', f'Redirect loop detected: {url}')
            break
        visited.add(url)
        
        # 检测协议降级
        if i > 0 and url.startswith('http://') and chain[i-1]['url'].startswith('https://'):
            log_anomaly('P1', f'Protocol downgrade: HTTPS → HTTP at step {i+1}')
        
        # 检测域名切换
        if i > 0:
            prev_domain = urlparse(chain[i-1]['url']).netloc
            curr_domain = urlparse(url).netloc
            if prev_domain != curr_domain:
                log_anomaly('P1', f'Domain switch: {prev_domain} → {curr_domain}')
        
        if status not in [301, 302, 303, 307, 308]:
            break
        
        location = result['ResponseHeaders'].get('Location')
        if not location:
            break
        
        # 处理相对路径
        url = urljoin(url, location)
    
    # 检测过长重定向链
    if len(chain) >= 4:
        log_anomaly('P1', f'Long redirect chain: {len(chain)} hops')
    
    return chain
```

### 6.3 真实案例

```
案例 1: 某 SRC OAuth 实现
→ 观察: /oauth/authorize → /login → /oauth/callback?code=xxx → /dashboard
→ 异常: 第 2 跳 /login 返回 302, Location 中的 state 参数被篡改
→ 利用: 拦截第 2 跳, 修改 state=victim_csrf_token → CSRF 绕过 → 账号接管

案例 2: 某企业 SSO
→ 观察: sso.example.com → internal-auth.example.com → app.example.com
→ 异常: internal-auth 子域泄露
→ 利用: 枚举 internal-* 子域 → 发现 internal-admin.example.com (无认证)

案例 3: 某支付回调
→ 观察: /pay/callback?order=123 → 302 → /order/detail?order=123&status=paid
→ 异常: 第 2 跳自动添加 status=paid 参数
→ 利用: 直接访问 /order/detail?order=456&status=paid (未支付订单) → 绕过支付验证
```

---

## 7. 完整检测脚本框架

### 7.1 主流程 (集成到 P1 协议)

```python
def anomaly_detection_gate(target_url, scan_mode='standard'):
    """
    P1 信号预检的异常检测门禁
    
    Args:
        target_url: 目标 URL
        scan_mode: quick/standard/deep (控制采样次数)
    
    Returns:
        {
            'anomalies': [...],  # 检测到的异常
            'baseline': {...},   # 基线数据 (用于后续对比)
            'should_escalate': bool,  # 是否需要立即升级调查
        }
    """
    
    # 1. 建立基线 (响应时间/状态码/Header 稳定性)
    baseline = establish_baseline(target_url, samples=20 if scan_mode == 'deep' else 5)
    
    # 2. P0: 响应头异常检测
    header_anomalies = detect_header_anomalies(baseline['headers'])
    
    # 3. P1: 状态码异常
    status_anomalies = detect_status_anomalies(baseline['status_codes'])
    
    # 4. P1: 时间分布异常
    timing_anomalies = detect_timing_anomalies(baseline['durations'])
    
    # 5. P1: 错误信息泄露
    error_anomalies = detect_error_leak(baseline['response_body_sample'])
    
    # 6. P1: 重定向链异常
    redirect_anomalies = []
    if any(s in [301, 302, 303, 307, 308] for s in baseline['status_codes']):
        redirect_chain = trace_redirect_chain(target_url)
        redirect_anomalies = analyze_redirect_chain(redirect_chain)
    
    # 7. 汇总
    all_anomalies = (
        header_anomalies + 
        status_anomalies + 
        timing_anomalies + 
        error_anomalies + 
        redirect_anomalies
    )
    
    # 8. 判定是否需要立即升级
    should_escalate = any(a['priority'] == 'P0' for a in all_anomalies)
    
    return {
        'anomalies': all_anomalies,
        'baseline': baseline,
        'should_escalate': should_escalate,
    }


def establish_baseline(url, samples=5):
    """建立基线数据"""
    results = []
    
    for i in range(samples):
        result = mcp__yaklang__http_fuzzer(
            request_template=f'GET {url} HTTP/1.1\r\nHost: {{{{host}}}}\r\n\r\n',
        )
        results.append({
            'status': result['StatusCode'],
            'duration': result['Duration'],
            'length': result['BodyLength'],
            'headers': result['ResponseHeaders'],
        })
    
    return {
        'status_codes': [r['status'] for r in results],
        'durations': [r['duration'] for r in results],
        'lengths': [r['length'] for r in results],
        'headers': results[0]['headers'],  # 假设 Header 稳定
        'response_body_sample': results[0].get('Body', ''),  # 仅采样一次
    }
```

### 7.2 集成到 agent-protocol.md P1 阶段

**修改点**: `references/protocols/agent-protocol.md` § P1 信号预检

```markdown
## P1 信号预检 (MCP-first)

### 执行序列

1. **异常检测门禁 (Mandatory)** ← 新增
   - 调用 `anomaly_detection_gate(target_url, scan_mode)`
   - 记录所有异常到 `assets.md` § 异常信号
   - 如果 `should_escalate=True` (P0 异常), 立即执行对应测试动作
   
2. First-pass HTTP (统一走 http_fuzzer)
   - 记录三要素: status_code / body_length / duration
   - 对比基线数据 (来自异常检测门禁)
   
3. 信号分类
   - 仅当异常检测 + First-pass 均有异常信号时, 才 Grep 对应漏洞文件
   - 优先处理 P0 异常 (调试标记/版本泄露)
```

---
## 8. assets.md 记录格式

### 8.1 新增章节: 异常信号

在 `assets.md` 中新增 `## 异常信号` 章节:

```markdown
## 异常信号

> 由 P1 异常检测门禁自动生成  
> 更新时间: 2026-06-08 14:32:17

### P0 异常 (Critical - 立即处理)

| 类型 | 详情 | 测试动作 | 状态 |
|:---|:---|:---|:---:|
| 响应头调试标记 | `X-Debug: true` @ `https://target.com/api/user` | 添加 `X-Internal-User: admin` 后重测 | ✅ 已确认提权 |
| 版本泄露 | `Server: Apache/2.4.29 (Ubuntu)` | 查询 CVE-2021-44790 (mod_lua SSRF) | 🔍 待验证 |

### P1 异常 (High)

| 类型 | 详情 | 后续路由 | 状态 |
|:---|:---|:---|:---:|
| 非标准状态码 | `499` @ `/api/query?user=admin'` | 可能是 SQL 时间盲注 → `vuln/sqli.md` | 🔍 待验证 |
| 错误信息泄露 | 堆栈: `UserController.java:42` | 记录类名 + 后续代码审计目标 | 📝 已记录 |
| 重定向链 | 4 跳: `sso.com → internal-auth.com → ...` | 枚举 `internal-*` 子域 | 🔍 进行中 |

### P2 异常 (Medium)

| 类型 | 详情 | 利用方向 |
|:---|:---|:---|
| 自定义 Header | `X-Tenant-ID: 1001` | IDOR 遍历其他租户 |
| 时间分布 | P50=80ms, P99=3200ms (40x) | SQL 时间盲注前置信号 |

### 基线数据

```json
{
  "target": "https://target.com/api/user",
  "samples": 5,
  "status_codes": [200, 200, 200, 200, 200],
  "durations_ms": [78, 82, 79, 81, 3201],
  "body_lengths": [1234, 1234, 1234, 1234, 1234],
  "stable_headers": {
    "Server": "nginx/1.18.0",
    "X-Powered-By": "PHP/7.4.3"
  }
}
```
```

### 8.2 状态标记

- ✅ **已确认**: 漏洞已验证
- 🔍 **待验证**: 需进一步测试
- 📝 **已记录**: 信息已提取, 等待后续利用
- ❌ **误报**: 确认为正常行为
- 🚫 **BLOCKED**: 需 HITL 或外部资源

---

## 9. 集成检查清单

在实施本协议前, 确认以下前置条件:

- [ ] P0.4 环境确认完成 (`mcp-readiness.md`)
- [ ] Yakit MCP `http_fuzzer` 工具可用
- [ ] `assets.md` 已初始化
- [ ] 已选择扫描档位 (`quick`/`standard`/`deep`)
- [ ] `agent-protocol.md` § P1 已更新集成步骤

**执行顺序** (强制):
```
P0.4 环境确认 
→ P0.5 资产侦察 
→ P1 异常检测门禁 (本协议) ← 在这里
→ P1 First-pass HTTP 
→ P1 信号分类
→ P1.5 业务建模
```

---

## 10. 真实案例汇总

### 案例 A: 某 SRC - 响应头调试标记提权

**目标**: 某教育平台管理后台  
**发现**: `X-Debug: 1` + `X-Internal-Routes: /admin,/console`  
**测试**:
1. 添加 `X-Admin-Panel: true` → 403
2. 添加 `X-Internal-User: admin` → 200 (成功进入管理后台)
3. 枚举 `/admin/*` → 发现用户管理/数据导出功能

**影响**: 未授权访问管理后台 → Critical  
**修复**: 移除生产环境调试 Header + 加强权限验证

---

### 案例 B: 某企业 - 状态码 499 + SQL 时间盲注

**目标**: 某 OA 系统用户查询接口  
**发现**: 当 `username=admin'` 时返回 `499` (Nginx 客户端关闭连接)  
**分析**:
- 正常请求: P50=80ms, 499 率 0%
- 恶意请求: `admin' AND SLEEP(3)--` → P99=3200ms, 499 率 85%
- 原因: Nginx `proxy_read_timeout 3s`, 后端 MySQL 执行 SLEEP(3) 超时

**利用**:
1. 确认注入点: `' AND IF(1=1, SLEEP(2), 0)--` → 2s 延迟
2. 提取数据库: `' AND IF(DATABASE()='oa_db', SLEEP(2), 0)--` → 确认
3. 提取表名: 逐字符爆破 → `users` 表
4. 提取管理员: 22 个 `role='admin'` 账号

**时间**: 约 4 小时 (自动化脚本)  
**影响**: SQL 注入 → 敏感信息泄露 → High

---

### 案例 C: 某 SRC - 重定向链参数污染

**目标**: 某支付平台 OAuth 回调  
**发现**: `/oauth/callback` → 4 跳重定向, 第 3 跳自动添加 `&verified=true`  
**流程**:
1. `/oauth/callback?code=xxx&state=yyy`
2. → 302 `/verify/check?code=xxx`
3. → 302 `/order/confirm?order=123&verified=true` ← 参数自动添加
4. → 200 (订单确认页)

**测试**:
- 直接访问 `/order/confirm?order=456&verified=true` (未支付订单)
- → 200 (订单状态变为"已支付")
- → 绕过支付验证

**影响**: 逻辑漏洞 → 任意订单免费购买 → Critical  
**赏金**: $5000

---

## 11. 误报过滤规则

以下情况**不应**标记为异常:

| 场景 | 原因 | 处理方式 |
|:---|:---|:---|
| `X-Request-ID` / `X-Trace-ID` (随机值) | 正常链路追踪 | 忽略 (除非值格式泄露内部服务名) |
| `X-RateLimit-Remaining: 100` | 正常限流响应 | 记录限流阈值, 用于竞态条件测试 |
| CloudFlare/Akamai 自定义 Header | CDN 标准行为 | 记录 CDN 指纹 |
| `Server: cloudflare` (无版本号) | 已隐藏详细版本 | 仅记录 CDN, 不升级 P0 |
| 302 重定向 (1-2 跳, 同域) | 正常路由 | 仅当 ≥3 跳或跨域时标记 |

---

## 12. 参考链接

- P1 信号预检协议: `references/protocols/agent-protocol.md § P1`
- MCP http_fuzzer 用法: `references/mcp-tools-finder.md § HTTP Fuzzing`
- 基线数据记录: `references/evidence-pipeline.md § Baseline`
- 漏洞路由表: `SKILL.md § 信号路由`

---

**版本历史**:
- v2.0 (2026-06-08): toolPlus 初始版本, 集成 MCP http_fuzzer
- v2.1 (TBD): 添加字符集异常检测 (UTF-7/UTF-16 XSS bypass)
