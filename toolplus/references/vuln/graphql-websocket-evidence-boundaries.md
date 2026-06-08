---
name: graphql-websocket-evidence-boundaries
description: GraphQL 与 WebSocket 的横向证据边界、评级口径、HITL 和误判过滤。用于 graphql-websocket.md 报告前自检。
category: vuln
tags: [graphql, websocket, evidence, rating, false-positive]
---

# GraphQL / WebSocket 证据边界

用途: 只承接 GraphQL 与 WebSocket 的证据、评级、HITL 和误判过滤。端点识别、内省、mutation、CSWSH 和消息测试步骤仍回到 [graphql-websocket.md](graphql-websocket.md)。

---

## 横向判断表

| 入口信号 | 失败现象 | 转向动作 | 关键证据 | 评级边界 | 误判过滤 |
|---|---|---|---|---|---|
| GraphQL 端点 200 / `errors` | 只有协议错误 | 枚举字段建议、schema、auth 差异 | endpoint、请求、错误结构 | 仅攻击面线索 | GraphQL 200+errors 是正常协议行为 |
| Introspection 开启 | 只有 schema | 找 mutation、敏感字段和鉴权差异 | schema 片段、敏感字段、角色要求 | 通常低中,取决于泄露细节 | 公开文档或仅 IDE 不等于高危 |
| BOLA/字段越权 | 返回 null 或空字段 | 用 A/B 账号、多字段、多对象验证 | A/B token、对象 ID、返回字段、当前用户 | 跨账号敏感数据为高危候选 | null 可能是无数据或字段不可见 |
| Mutation 越权 | forbidden 或前端失败 | 低权调用管理 mutation,查最终状态 | mutation、角色、状态变化、审计记录 | 能改状态/权限/资金才高 | 前端报错和后端失败不成立 |
| Alias/Batching | 触发限速或错误 | 控制规模,验证是否绕服务端频控 | 单请求多操作、服务端处理结果 | 绕频控且影响账号/验证码才中高 | 不做高强度爆破或 DoS |
| WS 握手成功 | 只有连接或心跳 | 检查 Origin、Cookie、Token、消息权限 | 握手、Origin、Cookie 状态、消息样本 | 仅连接成功低 | echo/heartbeat 不构成影响 |
| CSWSH | 恶意 Origin 可连 | 证明以受害者会话读/改敏感数据 | Origin、Cookie 自动带上、敏感消息 | 跨站读/改敏感数据高危候选 | Origin 放宽但无敏感消息低 |
| WS 消息越权 | userId/orderId 可改 | A/B 账号对照,查消息和最终状态 | 握手、消息、响应、账号边界 | 跨账号数据/状态变化高危 | 无状态广播或测试频道不高 |

---

## 最小证据包

- GraphQL: endpoint、query/mutation、角色、对象 ID、响应字段和 schema 片段。
- WebSocket: 握手请求、Origin/Cookie/Token、消息样本、响应消息和连接状态。
- A/B 对照: 账号 A、账号 B、匿名/低权/高权差异。
- 影响: 敏感字段、业务状态变更、订阅泄露、权限变化或绕过频控结果。
- 边界: 请求规模、未做 DoS、未做批量数据提取、HITL 授权状态。

---

## 评级口径

- 端点存在、IDE 暴露、`errors` 响应、心跳连接: 线索或低危 candidate。
- Introspection 暴露敏感业务 schema: 低中,需结合可调用接口。
- 跨账号读取、未授权 mutation、CSWSH 读取敏感数据、WS 消息越权: High 候选。
- 资金/权限/账号状态修改、批量敏感订阅泄露: High/Critical 候选。

---

## HITL 边界

- 需要两个测试账号、登录态、验证码、业务对象、外部 Origin 页面或 OOB 接收端时先请求 HITL。
- Alias/Batching、深层嵌套和 WS 高频消息必须控制规模,不得做 DoS。
- 不外带真实用户数据,CSWSH 只用自有测试会话和最小字段。

---

## 报告前误判过滤

- 不把 GraphQL `errors`、字段建议、IDE 页面或 WS echo 当漏洞。
- 不把 introspection 单独夸大为高危,必须说明可利用字段或后续影响。
- 不把 Origin 宽松单独判高,需要证明敏感消息或状态变化。
- 不把单次超时、限速错误或连接关闭当 DoS 证据。
