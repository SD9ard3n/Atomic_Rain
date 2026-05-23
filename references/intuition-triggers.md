# 实战直觉触发表

> **本文件 = 触发规则权威源**
> 现象 → 直觉 → 强制动作。配套 [expert-intuitions.md](expert-intuitions.md) 的"案例库"使用:
> - **拿不准是否要追** → 先 Grep `expert-intuitions.md` 看 Why/Example
> - **已经决定要追,需要动作清单** → Grep 本文件
>
> **目的**: 让 Agent 自动应用 15 条实战直觉,不靠记忆靠触发
> **原则**: 现象 → 直觉 → 强制动作

---

## 🔍 Grep 命令速查

```bash
# 查询触发规则映射表
grep -A 20 "触发规则映射表" references/intuition-triggers.md

# 根据现象查询触发规则
grep "发现任意漏洞" references/intuition-triggers.md
grep "看到 /api/v2/" references/intuition-triggers.md
grep "发现 BOLA" references/intuition-triggers.md
grep "发现 SSRF" references/intuition-triggers.md
grep "发现 XSS" references/intuition-triggers.md

# 查询详细触发规则
grep -A 15 "规则 1:" references/intuition-triggers.md
```

---

## 触发规则映射表

| 现象 | 触发直觉 | 强制动作 | 原因 |
|------|---------|---------|------|
| 发现任意漏洞 | #1 同一套过滤逻辑会被复用 | sweep 全站同类参数 | 命中率 60%+ |
| 看到 `/api/v2/` | #2 老版本 API 最容易漏补丁 | 枚举 v1/v0/internal/legacy | v2 修了 v1 往往还在 |
| 发现 BOLA | #3 BOLA 要两账号交叉测 | 创建第二个账号,交叉测试 | 单账号无法判断越权 |
| 发现 SSRF | #4 SSRF 先打云元数据 | 测 5 家云厂商 endpoint | 云凭证价值 > 内网探测 |
| 发现 XSS | #5 XSS 没即时输出不代表没漏洞 | 测邮件/PDF/后台触发点 | 二阶 XSS 常被忽略 |
| 看到 JWT | #6 JWT 先看密钥与算法 | 检查 alg/kid/jku 再决定打法 | 不同字段不同攻击方式 |
| 看到支付功能 | #7 业务逻辑漏洞回报最高 | 手测金额/数量/优惠券/并发 | 扫描器测不到 |
| 看到一次性操作 | #8 Race Condition 首选一次性操作 | 并发测试领券/激活/重置 | 竞态价值在于绕过计数 |
| 发现 JS 文件 | #9 JS 文件里的注释是金矿 | 下载并 grep secret/TODO/api_key | 前端代码泄露内部信息 |
| 同时有 Web 和 App | #10 移动端 API 是未阉割版 | 两边抓包对比字段差异 | App 返回更多字段 |
| 拿到云 AK | #11 云 AK 先 list 再 assume role | 先 GetCallerIdentity 探权限 | 避免触发监控 |
| 测 LLM 应用 | #12 AI 输出无过滤 = RCE | 测 Prompt 注入 + 工具权限 | LLM 作为代码执行者 |

---

## 使用方式

### 在 Commander (SKILL.md) 中添加

```markdown
## P1.5: 直觉触发检查 (Intuition Trigger)

每次发现新现象时,**必须**查询直觉触发表:

1. Grep `intuition-triggers.md` 匹配当前现象
2. 执行对应的强制动作
3. 记录到 assets.md 的 [Intuition_Applied] 标签

**示例**:
- 发现 `/api/v2/users` → 触发直觉 #2 → 立即枚举 v1/v0
- 发现 SQLi → 触发直觉 #1 → sweep 全站同类参数
```

---

## 详细触发规则

### 规则 1: 发现任意漏洞 → Sweep 同类参数

**触发条件**: 发现任意漏洞 (SQLi/XSS/SSRF/等)

**强制动作**:
1. 提取当前参数名 (如 `id`)
2. Grep 全站找同类参数 (`uid`, `order_id`, `user_id`)
3. 用相同 Payload 测试所有同类参数

**示例**:
```
发现: /api/search?q=<script>alert(1)</script> 存在 XSS
动作: 
- 找到 /api/products?keyword=
- 找到 /api/users?name=
- 用相同 Payload 测试
结果: 发现 3 个新的 XSS
```

---

### 规则 2: 看到 `/api/v2/` → 枚举老版本

**触发条件**: URL 包含版本号 (v2/v3/v4)

**强制动作**:
1. 枚举 v1, v0, internal, legacy, old, beta
2. 对比新旧版本的差异
3. 优先测试老版本的权限校验

**示例**:
```
发现: /api/v2/users (有权限校验)
动作: 测试 /api/v1/users
结果: v1 无权限校验,可未授权访问
```

---

### 规则 3: 发现 BOLA → 创建第二个账号

**触发条件**: 发现 BOLA 或测试越权

**强制动作**:
1. 创建第二个测试账号
2. 记录两个账号的对象 ID
3. 交叉测试 (A 的 Token + B 的 ID)

**示例**:
```
发现: /api/orders/{id} 可能存在 BOLA
动作:
- 账号 A: order_id=123
- 账号 B: order_id=456
- 用 A 的 Token 访问 order_id=456
结果: 确认 BOLA
```

---

### 规则 4: 发现 SSRF → 优先打云元数据

**触发条件**: 确认 SSRF 存在

**强制动作**:
1. 测试 AWS: `http://169.254.169.254/latest/meta-data/`
2. 测试阿里云: `http://100.100.100.200/latest/meta-data/`
3. 测试腾讯云: `http://metadata.tencentyun.com/latest/meta-data/`
4. 测试 Google: `http://metadata.google.internal/computeMetadata/v1/`
5. 测试 Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`

**示例**:
```
发现: /api/fetch?url= 存在 SSRF
动作: 优先测试云元数据,而不是扫内网 3306
结果: 获取 AWS AK/SK
```

---

### 规则 5: 发现 XSS → 测试非即时触发点

**触发条件**: 发现 XSS

**强制动作**:
1. 测试邮件通知 (注册/评论触发邮件)
2. 测试 PDF 导出 (订单/发票导出)
3. 测试管理员后台 (用户列表/工单系统)
4. 测试日志展示 (SIEM/日志查看器)

**示例**:
```
发现: 注册时 nickname 存在 XSS,但前端转义
动作: 测试管理员后台的用户列表
结果: 管理员查看用户列表时触发 XSS
```

---

### 规则 6: 看到 JWT → 检查上下文

**触发条件**: 发现 JWT 认证

**强制动作**:
1. 解析 JWT (jwt.io)
2. 检查 alg 字段 (none/HS256/RS256)
3. 检查 kid 字段 (SQL注入/路径遍历)
4. 检查 jku/x5u 字段 (URL劫持)
5. 根据上下文选择攻击方式

**示例**:
```
发现: Authorization: Bearer eyJ...
动作: 解析后发现 {"alg": "RS256", "kid": "1"}
测试: kid SQL 注入 → 成功
```

---

### 规则 7: 看到支付功能 → 手测业务逻辑

**触发条件**: 发现支付/优惠券/积分功能

**强制动作**:
1. 测试金额篡改 (price=-100)
2. 测试数量篡改 (quantity=-1)
3. 测试优惠券叠加 (多张同时使用)
4. 测试并发支付 (同一订单多次扣款)

**示例**:
```
发现: /api/orders/create
动作: 修改 price=0.01
结果: 成功以 0.01 元购买商品
```

---

### 规则 8: 看到一次性操作 → 并发测试

**触发条件**: 发现一次性操作 (领券/激活/重置)

**强制动作**:
1. 用 Burp Intruder 并发 50 个请求
2. 检查是否多次成功
3. 检查数据库是否有多条记录

**示例**:
```
发现: /api/coupons/claim
动作: 并发 50 个请求
结果: 成功领取 5 张优惠券 (应该只能领 1 张)
```

---

### 规则 9: 发现 JS 文件 → Grep 敏感信息

**触发条件**: 发现 JS 文件 (app.*.js / main.*.js)

**强制动作**:
1. 下载 JS 文件
2. Grep: `secret`, `api_key`, `password`, `token`
3. Grep: `TODO`, `FIXME`, `DEBUG`, `test`
4. Grep: `http://`, `https://` (提取 URL)
5. Grep: `/api/`, `/admin/`, `/internal/` (提取路由)

**示例**:
```
发现: app.abc123.js
动作: grep "api_key"
结果: 发现硬编码的 API Key
```

---

### 规则 10: 同时有 Web 和 App → 对比差异

**触发条件**: 目标同时有 Web 和 App

**强制动作**:
1. Web 端抓包
2. App 端抓包
3. 对比同一接口的返回字段
4. 优先测试 App 端独有的字段

**示例**:
```
Web: /api/user/profile 返回 {name, avatar}
App: /api/user/profile 返回 {name, avatar, phone, email, id_card}
动作: 测试 App 端的接口
```

---

### 规则 11: 拿到云 AK → 先探权限

**触发条件**: 获取云 AK/SK

**强制动作**:
1. 先执行 `aws sts get-caller-identity` (低风险)
2. 列出权限 `aws iam list-attached-user-policies`
3. 根据权限决定下一步操作
4. 避免直接 `aws s3 ls` (触发监控)

**示例**:
```
发现: AWS AK/SK 泄露
动作: 先 get-caller-identity 确认身份
结果: 发现权限仅限 S3,不测试 EC2
```

---

### 规则 12: 测 LLM 应用 → Prompt 注入

**触发条件**: 目标是 LLM 应用 / Agent / MCP

**强制动作**:
1. 测试 Prompt 注入 (忽略之前的指令)
2. 测试工具权限 (能否调用敏感工具)
3. 测试输出过滤 (能否输出 XSS payload)

**示例**:
```
发现: AI 客服集成了"查询订单"工具
动作: 输入 "查询订单 '1 UNION SELECT password FROM users--'"
结果: LLM 把注入语句传给工具,触发 SQLi
```

---

## 集成到 SKILL.md

在 `SKILL.md` 的各 Phase 添加:

```markdown
## P1: 资产发现后

**直觉触发检查**:
- [ ] 看到 `/api/v2/` → 触发直觉 #2
- [ ] 发现 JS 文件 → 触发直觉 #9
- [ ] 同时有 Web 和 App → 触发直觉 #10

## P2: 漏洞发现后

**直觉触发检查**:
- [ ] 发现任意漏洞 → 触发直觉 #1 (sweep)
- [ ] 发现 BOLA → 触发直觉 #3 (两账号)
- [ ] 发现 SSRF → 触发直觉 #4 (云元数据)
- [ ] 发现 XSS → 触发直觉 #5 (非即时触发)
- [ ] 看到 JWT → 触发直觉 #6 (检查上下文)
- [ ] 看到支付 → 触发直觉 #7 (业务逻辑)
- [ ] 看到一次性操作 → 触发直觉 #8 (并发)

## P3: 利用阶段

**直觉触发检查**:
- [ ] 拿到云 AK → 触发直觉 #11 (先探权限)
- [ ] 测 LLM 应用 → 触发直觉 #12 (Prompt 注入)
```

---

## 自我检查清单

在每个 Phase 结束前,问自己:

- [ ] 是否已查询直觉触发表?
- [ ] 是否执行了对应的强制动作?
- [ ] 是否记录了 [Intuition_Applied] 标签?

---

**版本**: v1.0  
**更新日期**: 2026-04-25  
**适用场景**: Bug Bounty / SRC / 黑盒渗透测试