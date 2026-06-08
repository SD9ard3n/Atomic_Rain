---
name: websocket-security
description: WebSocket 安全专项。覆盖握手识别、Origin/认证绑定、CSWSH、消息级注入、消息级越权、速率限制和证据要求。
category: vuln
tags: [websocket, csrf, authz]
---

# WebSocket 安全专项

用途: 承接 WebSocket 深测。GraphQL 路由仍见 [graphql-websocket.md](graphql-websocket.md); 证据边界和误判过滤见 [graphql-websocket-evidence-boundaries.md](graphql-websocket-evidence-boundaries.md)。

---

## First-pass Signal

| 信号 | 判断 | 下一步 |
|---|---|---|
| `Upgrade: websocket` / `101 Switching Protocols` | WS 接入点 | 保存握手请求 |
| `/socket.io/` / `/ws` / `/wss` / `/stomp` | 常见 WS 路径 | 检查认证与 Origin |
| 连接不带 Cookie/Token 仍成功 | 未认证候选 | 测消息级权限 |
| 任意 Origin 仍可连接 | CSWSH 候选 | 用自有会话最小验证 |
| 消息含 `userId` / `orderId` / `action` | 消息级越权候选 | A/B 账号对照 |

记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`; 另保留握手、消息样本和连接状态。

---

## 1. 识别

```http
GET /ws HTTP/1.1
Host: target.example
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://target.example
```

浏览器 JS:

```javascript
const ws = new WebSocket("wss://target.example/ws");
```

---

## 2. 攻击面

### 2.1 Origin 校验缺失 / CSWSH

若服务端不校验 Origin, 攻击者页面可能以受害者 Cookie 建立 WS 连接。验证时只能使用自有测试会话和最小字段。

```html
<script>
const ws = new WebSocket("wss://target.example/ws");
ws.onopen = () => ws.send(JSON.stringify({action: "get_profile"}));
ws.onmessage = (e) => console.log(e.data);
</script>
```

有效证据不是“能连上”,而是以跨站 Origin 读取或修改了自有测试账号的敏感消息/状态。

### 2.2 未认证

删除 Cookie / Authorization / query token 后仍能连接,只说明握手可能未认证。必须继续发业务消息,证明能读数据、改状态或订阅敏感频道。

### 2.3 消息级注入与越权

WS 协议本身只是传输层,风险通常在应用消息:

- SQL 注入: 消息字段进入查询条件。
- XSS: 消息被前端 `innerHTML` 渲染。
- 命令注入: 消息参数进入服务端命令。
- 越权: 修改 `userId` / `tenantId` / `orderId` / `roomId`。
- 状态绕过: 修改 `action` / `status` / `role`。

### 2.4 Rate Limit 缺失

WS 长连接容易绕开普通 HTTP 限速。只做低频、低影响样本,不得进行 DoS。

---

## 3. 测试工具

| 工具 | 用途 |
|---|---|
| Burp Suite WebSocket editor | 手工修改消息 |
| websocat | CLI 连接和重放 |
| wsrepl | 交互式 WS 测试 |
| Chrome MCP network debugger | 保存握手和消息证据 |

---

## 4. CSWSH 最小 PoC

```html
<!doctype html>
<script>
const ws = new WebSocket("wss://target.example/ws/chat");
ws.onopen = () => {
  ws.send(JSON.stringify({action: "get_profile"}));
};
ws.onmessage = (e) => {
  console.log("owned-test-account-only", e.data);
};
</script>
```

不要外带真实用户数据;需要外部 Origin 页面或接收端时先走 HITL。

---

## 5. Testing Checklist

- [ ] 保存原始握手请求和 101 响应。
- [ ] 修改 Origin 为自有测试域或 `null`。
- [ ] 删除 Authorization/Cookie/query token 后对比连接状态。
- [ ] 对 A/B 账号分别记录合法消息。
- [ ] 修改消息中的 `userId` / `tenantId` / `orderId` / `roomId`。
- [ ] 检查订阅频道是否泄露跨账号消息。
- [ ] 控制规模测试消息频率和批量操作。
- [ ] 若消息是 Protobuf/binary,先识别 schema 或字段边界。

---

## 6. False Positive

完整误判过滤和评级边界见 [graphql-websocket-evidence-boundaries.md](graphql-websocket-evidence-boundaries.md)。核心提醒: 连接成功、心跳、echo、Origin 宽松或 binary 消息都不是漏洞本身;必须证明敏感消息、跨会话读取、消息级越权或状态变化。

---

## 7. 相关参考

| 内容 | 文件 |
|---|---|
| GraphQL 入口 | [graphql-websocket.md](graphql-websocket.md) |
| 证据边界 | [graphql-websocket-evidence-boundaries.md](graphql-websocket-evidence-boundaries.md) |
| XSS | [xss.md](xss.md) |
| CSRF / Clickjacking | [csrf-clickjacking.md](csrf-clickjacking.md) |
| API 越权 | [../api-security.md](../api-security.md) |
