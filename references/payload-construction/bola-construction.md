# BOLA 测试思路

> **原则**: 必须用两个账号交叉测试,不是单账号
> **目标**: A 的 Token + B 的 ID = 越权访问

---

## 思路 1: BOLA 本质理解

**定义**: Broken Object Level Authorization (对象级授权失效)

**核心**: 
- 有认证 (需要 Token)
- 无授权 (不检查对象归属)

**公式**:
```
A 账号的 Token + B 账号的对象 ID = 成功访问 B 的数据
```

**不是**:
- ❌ 删除 Token 能访问 → 这是未授权访问
- ❌ 用 A 的 Token 访问 A 的数据 → 这是正常访问

---

## 思路 2: 测试准备 (必须)

**目标**: 创建两个测试账号

### 2.1 账号准备

```
账号 A:
- user_id: 123
- Token: token_A
- 订单 ID: order_456

账号 B:
- user_id: 789
- Token: token_B
- 订单 ID: order_999
```

### 2.2 记录对象 ID

```
用 A 账号操作,记录:
- 订单 ID: order_456
- 文件 ID: file_123
- 评论 ID: comment_789

用 B 账号操作,记录:
- 订单 ID: order_999
- 文件 ID: file_456
- 评论 ID: comment_111
```

**关键**: 必须有两个账号的对象 ID

---

## 思路 3: 交叉测试

**目标**: A 的 Token + B 的 ID

### 3.1 标准测试流程

```
步骤 1: 用 A 账号访问 A 的订单
GET /api/orders/order_456
Authorization: Bearer token_A
→ 200 OK (正常)

步骤 2: 用 A 账号访问 B 的订单
GET /api/orders/order_999
Authorization: Bearer token_A
→ 200 OK → BOLA 确认 ❌
→ 403 Forbidden → 无 BOLA ✅
```

### 3.2 反向测试 (必须)

```
步骤 3: 用 B 账号访问 A 的订单
GET /api/orders/order_456
Authorization: Bearer token_B
→ 200 OK → BOLA 确认 ❌
```

**关键**: 双向测试,确保不是偶然

---

## 思路 4: ID 参数识别

**目标**: 找到所有可能的 ID 参数

### 4.1 常见 ID 参数名

| 参数名 | 示例 | 位置 |
|--------|------|------|
| `id` | `/api/orders?id=123` | Query |
| `user_id` | `/api/profile?user_id=123` | Query |
| `order_id` | `/api/orders/123` | Path |
| `file_id` | `{"file_id": 123}` | Body |
| `uid` | `/api/users/uid/123` | Path |
| `userId` | `/api/data?userId=123` | Query |

### 4.2 ID 格式识别

| 格式 | 示例 | 测试方法 |
|------|------|---------|
| 数字 | `123` | 递增/递减测试 |
| UUID | `550e8400-e29b-41d4-a716-446655440000` | 枚举困难,但可尝试 |
| Base64 | `MTIz` | 解码后修改再编码 |
| 哈希 | `5f4dcc3b5aa765d61d8327deb882cf99` | 难以枚举 |

**关键**: 优先测试数字 ID

---

## 思路 5: 高价值目标

**目标**: 优先测试敏感功能

### 5.1 优先级排序

| 优先级 | 功能 | 示例 | 危害 |
|--------|------|------|------|
| P0 | 订单/交易 | `/api/orders/{id}` | 财务信息泄露 |
| P0 | 支付方式 | `/api/payment/methods/{id}` | 支付信息泄露 |
| P0 | 个人信息 | `/api/users/{id}` | 隐私泄露 |
| P1 | 文件下载 | `/api/files/{id}/download` | 文件泄露 |
| P1 | 评论/消息 | `/api/comments/{id}` | 内容泄露 |
| P2 | 公开资料 | `/api/profiles/{id}` | 低危 |

**关键**: 先测高价值目标

---

## 思路 6: 操作类型测试

**目标**: 测试所有 CRUD 操作

### 6.1 读取 (Read)

```
GET /api/orders/B_ORDER_ID
Authorization: Bearer A_TOKEN
→ 能读取 B 的订单 → BOLA
```

### 6.2 修改 (Update)

```
PUT /api/orders/B_ORDER_ID
Authorization: Bearer A_TOKEN
Body: {"status": "cancelled"}
→ 能修改 B 的订单 → BOLA (更严重)
```

### 6.3 删除 (Delete)

```
DELETE /api/orders/B_ORDER_ID
Authorization: Bearer A_TOKEN
→ 能删除 B 的订单 → BOLA (最严重)
```

### 6.4 创建 (Create)

```
POST /api/orders
Authorization: Bearer A_TOKEN
Body: {"user_id": B_USER_ID, ...}
→ 能为 B 创建订单 → BOLA
```

**关键**: 删除和修改比读取更严重

---

## 思路 7: 批量操作测试

**目标**: 测试批量接口

### 7.1 批量查询

```
GET /api/orders?ids=A_ORDER_ID,B_ORDER_ID
Authorization: Bearer A_TOKEN
→ 返回 B 的订单 → BOLA
```

### 7.2 批量删除

```
DELETE /api/orders
Authorization: Bearer A_TOKEN
Body: {"ids": [A_ORDER_ID, B_ORDER_ID]}
→ 删除 B 的订单 → BOLA
```

**关键**: 批量接口更容易忽略授权检查

---

## 思路 8: ID 枚举

**目标**: 枚举其他用户的 ID

### 8.1 递增枚举

```
A 的订单 ID: 1000
测试: 999, 1001, 1002, ...
→ 找到其他用户的订单
```

### 8.2 响应差异判断

```
GET /api/orders/999
→ 200 OK → 存在且可访问 (BOLA)
→ 404 Not Found → 不存在
→ 403 Forbidden → 存在但无权限 (正常)
```

**关键**: 200 vs 403 的差异

---

## 自我检查清单

- [ ] 是否创建了两个测试账号?
- [ ] 是否记录了两个账号的对象 ID?
- [ ] 是否用 A 的 Token + B 的 ID 测试?
- [ ] 是否反向测试 (B 的 Token + A 的 ID)?
- [ ] 是否测试了所有 CRUD 操作?
- [ ] 是否优先测试了高价值目标? (订单/支付/个人信息)
- [ ] 是否测试了批量操作?

---

## 常见错误

### 错误 1: 只用一个账号测试

**问题**: 无法判断是否越权

**正确**: 必须用两个账号交叉测试

### 错误 2: 删除 Token 测试

**问题**: 这是测试未授权访问,不是 BOLA

**正确**: 保留 Token,只改 ID

### 错误 3: 只测试读取操作

**问题**: 可能遗漏更严重的修改/删除越权

**正确**: 测试所有 CRUD 操作

### 错误 4: 看到 403 就放弃

**问题**: 可能只是这个 ID 不存在

**正确**: 尝试多个 ID,或用响应差异判断

---

## 报告模板

```markdown
### BOLA 漏洞

**漏洞类型**: Broken Object Level Authorization

**影响接口**: GET /api/orders/{id}

**复现步骤**:
1. 用账号 A (user_id: 123) 登录,获取 Token: token_A
2. 用账号 B (user_id: 789) 登录,创建订单,获取订单 ID: order_999
3. 用 A 的 Token 访问 B 的订单:
   ```
   GET /api/orders/order_999
   Authorization: Bearer token_A
   ```
4. 返回 200 OK,成功获取 B 的订单详情

**危害**: 
- 任意用户可查看其他用户的订单信息
- 包含姓名/地址/手机号等隐私信息

**修复建议**:
- 在查询订单前,检查订单归属: `if (order.user_id != current_user.id) return 403`
```

---

**版本**: v1.0  
**更新日期**: 2026-04-25