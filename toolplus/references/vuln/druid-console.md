---
name: druid-console
description: Druid 监控面板安全专项。覆盖 Druid 默认凭据、未授权、SQL 监控、数据源连接串、WebSession 接管和证据边界。
category: vuln
tags: [druid, middleware, java, console]
---

# Druid 监控面板安全专项

用途: 承接 Druid 监控面板深测。Swagger / Actuator 总入口见 [swagger-actuator-druid.md](swagger-actuator-druid.md); 暴露控制台评级与误判过滤见 [exposed-console-evidence-boundaries.md](exposed-console-evidence-boundaries.md)。

---

## First-pass Signal

| 信号 | 判断 | 下一步 |
|---|---|---|
| `/druid/index.html` 200 | Druid 面板候选 | 检查登录态和数据页 |
| `/druid/login.html` 200 | 需要登录 | 在授权下试默认凭据 |
| `/druid/sql.html` 可访问 | SQL 监控暴露 | 只取脱敏片段 |
| `/druid/datasource.html` 可访问 | 数据源信息暴露 | 检查连接串和账号字段 |
| `/druid/websession.html` 可访问 | Session 管理暴露 | HITL,只验证自有会话 |

---

## 1. 默认凭据与未授权

| URL | 内容 |
|---|---|
| `/druid/index.html` | 主页,即使未登录可能能看 |
| `/druid/login.html` | 登录页,常见默认 `admin/admin` 或 `admin/123456` |
| `/druid/sql.html` | SQL 列表和参数 |
| `/druid/datasource.html` | 数据源连接串 |
| `/druid/websession.html` | Web Session 列表 |
| `/druid/weburi.html` | URI 统计,可发现隐藏接口 |
| `/druid/webapp.html` | 应用信息 |

---

## 2. 利用步骤

```bash
# 1. 直接访问
curl https://target.example/druid/index.html

# 2. 若需登录,在授权范围内试默认凭据
curl -X POST https://target.example/druid/submitLogin \
  -d "loginUsername=admin&loginPassword=admin"

# 3. SQL 监控
curl https://target.example/druid/sql.html

# 4. 数据源
curl https://target.example/druid/datasource.html
```

WebSession 接管属于高风险验证,必须 HITL;优先只用自有测试会话证明权限边界。

---

## 3. 证据要求

- 面板 URL、认证状态、角色或默认凭据登录成功证据。
- SQL 监控只截取脱敏字段类型,不批量导出。
- 数据源连接串必须脱敏账号、密码、内网地址。
- WebSession 只验证自有测试会话或由用户确认的测试会话。
- 若要继续链到 DB、云或后台接口,先走 HITL。

---

## 4. 评级边界

- 主页可访问但无数据: 低危或线索。
- SQL 监控含敏感参数、用户信息、业务操作: High 候选。
- 数据源连接串含明文密码: High/Critical 候选,看可用性和数据范围。
- WebSession 可接管高权用户: Critical 候选,必须最小化验证。

---

## 5. 误判过滤

- 空面板、未启用监控或只有静态页面不算高危。
- 默认凭据必须证明登录成功和权限影响。
- 不能输出真实密码、真实 Session、真实内网地址或大批量 SQL。

---

## 6. 相关参考

| 内容 | 文件 |
|---|---|
| 暴露控制台总入口 | [swagger-actuator-druid.md](swagger-actuator-druid.md) |
| 证据边界 | [exposed-console-evidence-boundaries.md](exposed-console-evidence-boundaries.md) |
| Spring Boot | [../frameworks/spring-boot.md](../frameworks/spring-boot.md) |
| 认证逻辑 | [../auth-logic.md](../auth-logic.md) |
