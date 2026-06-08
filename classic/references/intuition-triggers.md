---
name: intuition-triggers
description: 本文件 = 触发规则权威源 现象 → 直觉 → 强制动作。配套 [expert-intuitions.md](expert-intuitions.md) 的"案例库"使用: - 拿不准是否要追 → 先 Grep expert-intuitions.md 看 Why/Exampl…
category: methodology
---

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
| 目标公司域名 + 邮件相关 | #13 SPF/DMARC 漏配 → 任意第三方伪造发件 | dig TXT 三件套 → 漏配走 swaks PoC | 钓鱼基础设施漏洞,中高危 |

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

---

## §B 业务建模追问 (P1.5 用,12 问)

> **职责区分**:
> - **§A 现象触发** (上方规则 1-12) = 响应式:**看到 X 现象 → 立刻做 Y 动作**,Phase 2 漏洞挖掘中随时触发
> - **§B 业务建模追问** (本节) = 主动式:**P1.5 业务建模时,对每个业务节点逐一问 12 问**,把 AI 的"模式匹配"升级到"系统化追问"

### 为什么需要 §B

逻辑漏洞的核心是**想象力 / 业务架构联想**,AI 是按敏感度筛选不会业务联想。光靠 §A 现象触发只能"被动响应",P1.5 业务建模阶段需要 AI **主动追问**每个业务节点可能出问题的方向。本表把人挖逻辑漏洞时常用的 12 个追问模式编码,**覆盖 ~70% 常见逻辑漏洞**。

### 12 问触发表

| # | 触发问题 | 对应漏洞模式 |
|---|---|---|
| **B1** | 如果用户**跳过**这一步直接调下一步会怎样? | 流程绕过 / 状态机漏洞 |
| **B2** | 如果用户**回退**到上一步会怎样? | 状态恢复 / 重放 |
| **B3** | 如果用户**既是甲方又是乙方** (自己邀请自己) ? | 自交易 / 自邀请 / 自我推荐 |
| **B4** | 如果**时间倒流 / 时间超长 / 跨时区** ? | 时间篡改 / 优惠永生 / 倒计时绕过 |
| **B5** | 如果**别人的标识被替换成系统标识** (admin/system/0/-1) ? | 权限提升 / 系统账号冒充 |
| **B6** | 如果**前端校验绕过 / 隐藏字段被改** ? | 前端信任漏洞 / 隐藏字段篡改 |
| **B7** | 如果**一个动作能影响别的用户** (消息群发 / 拉黑 / 删除他人订单) ? | CSRF / 横向 IDOR / 拒绝服务 |
| **B8** | 如果**字段是 null / empty / 不传 / 类型不对** ? | 类型混淆 / 空指针绕过 / WAF 绕过 |
| **B9** | 如果**接口被频繁调用** (无速率限制) ? | 短信/邮箱/资源轰炸 → 触发 [SKILL.md P3.5](../SKILL.md) |
| **B10** | 如果**异步回调被人构造** (支付回调 / Webhook) ? | 回调伪造 / 支付 0 元购 |
| **B11** | 如果**导出 / 打印接口拿不属于我的数据** ? | 越权数据泄露 / 报表导出全量 |
| **B12** | 如果**接口预期单次,被重放 / 重入** (非并发场景) ? | 双花 / 重复领取 / 退款双重处理 (扩展 §A #8 并发到非并发场景) |

### §B 使用方式 (P1.5 业务建模强制)

对每个识别出的业务节点 (注册 / 登录 / 找回密码 / 支付 / 邀请 / 实名 / 抽奖 / 签到 / 拼团 / 充值提现 等):

1. 抄 B1-B12 到当前 `vulns-trigger.md`
2. AI 逐条回答 "这个业务节点上,这个问题会发生什么"
3. 任何"会发生 X (漏洞)"的回答 → 转化为测试用例 → 进入 P2 测试
4. 任何"不会,因为 Y (防御)"的回答 → 标记为"**可绕过 Y 吗?**"反向追问一遍
5. 全部跑完 → 写入 `vulns-trigger.md` `[B-Traversed]` 标签 → 准入 Phase 2 参数测试

### §B 与 §A 联动

| §B 追问命中 | 触发 §A 规则 |
|---|---|
| B9 速率限制 → 触发短信轰炸 | + §A #7 (业务逻辑) + [SKILL.md P3.5](../SKILL.md) 索取接收手机号 |
| B7 影响他人订单 → IDOR | + §A #3 BOLA 两账号交叉 |
| B5 系统标识冒充 | + §A #6 JWT 检查 (`{"role":"admin"}`) |
| B12 重放 / 重入 | + §A #8 并发测试 (非并发场景补充) |

### §B 局限性 (诚实说)

- §B 12 问覆盖 **~70% 常见逻辑漏洞**,**剩 30% 仍需人的天马行空**
- AI 跑了 12 问 ≠ 找全了漏洞,只是把"漏掉常见模式"的概率降到很低
- 真正高分逻辑漏洞 (原创联想 / 业务深度理解) 仍需 HITL
- 如果业务节点超过 10 个,**不要全部跑** B1-B12 — 优先跑高价值节点 (注册 / 支付 / 提现 / 权限管理) 的全套,边缘节点 (签到 / 公告) 跑 B5+B7+B9+B11

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