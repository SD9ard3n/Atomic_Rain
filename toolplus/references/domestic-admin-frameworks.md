---
name: domestic-admin-frameworks
description: Domestic admin framework workflow for RuoYi, Blade/Spring-Blade, Nacos, Druid, FineReport, Admin.NET, Swagger, Actuator, and backend capability chains.
category: methodology
---

# Domestic Admin Frameworks

## Applicable Scenarios

Use for domestic backend frameworks, low-code/report platforms, and Spring ecosystem exposure. The path is fingerprint to backend capability, not login-page to vulnerability.

## Entry Signals

| Framework/component | Signal |
|---|---|
| RuoYi | title, favicon, static resources, `RuoYi-Vue`, `RuoYi-Cloud`, API prefix |
| Blade/Spring-Blade | icon, title, copyright, BladeX, static JS, menu/API paths |
| Nacos | console, namespace, configuration center, default path |
| Druid | SQL monitor login, data-source monitor, session clues |
| FineReport | report path, designer, template, file interface |
| Admin.NET | .NET admin title, Swagger, user/tenant/role modules |
| Swagger/Actuator | API docs, mappings, env, heapdump, health/info |

## RuoYi Ecosystem Chain

```text
fingerprint/version/form
-> exposed components: Swagger/Druid/Actuator/Nacos/MinIO/Shiro/Redis/MySQL
-> backend modules: users, roles, departments, export, code generation, scheduled tasks, file download
-> backend capability: data export, permission change, task execution, config read, file access
-> evidence filter: version, permission, interface existence, final impact
```

Progression:

1. Identify form: monolith, front/back separated, Cloud, customized backend, mobile companion.
2. Before login, inspect static resources, API prefixes, Swagger/Druid/Actuator/Nacos exposure with low noise.
3. With an account, prioritize user, role, department, menu, export, code generation, scheduled task, and file download modules.
4. For 1day/nday claims, verify version, interface existence, permission state, and minimal impact.

Evidence: fingerprint/version proof, permission state, concrete API, affected module, and minimal verification result.

False positives: RuoYi login page is not a vulnerability; empty Swagger UI, Druid login page, and Actuator health/info are usually low value; historical issues require version and permission match.

## Blade/Spring-Blade Chain

```text
icon/title/copyright clustering
-> backend login and captcha/weak-password/prompt differences
-> static JS API prefixes
-> menu/API unauthorized access or route leakage
-> backend business modules: user, tenant, device, report, config, export
-> 1day version and permission filtering
```

Progression:

1. Cluster assets by icon, title, copyright, and static resources, then prove scope ownership.
2. Treat login as an entry: test rate, captcha, weak password, account enumeration, and response differences.
3. Search static JS for API prefixes, `menu`, `route`, `permission`, `tenant`, `user`, `role`, `export`.
4. If menu/API returns empty or public menus only, downgrade. Continue only when business data or operation capability appears.
5. Do not assume same icon means same version. Record version, interface, permission requirement, and impact.

Evidence: Blade fingerprint, ownership proof, permission gap, backend module, data/config/business impact.

False positives: accessible backend login is not a vulnerability; empty menu is low value; 1day must pass version and permission filters.

## Spring Component Exposure

| Component | Progression | False-positive filter |
|---|---|---|
| Swagger | API enumeration, auth state, sensitive API | Empty UI or public docs are low value |
| Druid | SQL, data source, session, URI statistics | Login page alone is not enough |
| Actuator | mappings/env/heapdump/logfile | health/info only is usually low value |
| Nacos | namespace, config, users, service discovery | Must prove permission and config sensitivity |
| FineReport | reports, templates, designer, file API | Need data, file, or auth impact |
| Admin.NET | Swagger, tenant, roles, code generation | Need permission or business-data impact |

## Swagger/API Rating Closure

| 入口信号 | 失败现象 | 转向动作 | 关键证据 | 评级边界 | 误判过滤 |
|---|---|---|---|---|---|
| Swagger UI/API docs | UI 可见但接口 401 | 查分组文档、`/v2/api-docs`、静态 JS、历史接口前缀 | 文档来源、鉴权差异、可调接口 | 空文档/公开文档低 | Swagger 存在不是高危证据 |
| API 列表 | 只泄露字段或路径 | 找配置、测试连接、动态查询、导出、后台动作接口 | 脱敏配置字段、接口可调用、最小化影响 | 配置泄露中; 敏感查询/导出/配置动作高 | 接口列表本身不等于后台能力 |
| 内网配置/凭据 | 外部不可达 | 不外连爆破; 找系统自身代理、查询、代码生成、日志接口 | 系统自身可代查或执行的只读证明 | 能通过系统自身能力闭环才升值 | 不做破坏性写入或横向扩展 |

## Admin.NET / Low-Code Backend Chain

```text
miniapp/H5 token
-> backend API reuse
-> code generation / database config / online users / system config
-> password reset / create admin / role binding
-> logs / SQL injection / export capability
```

Failure turns: if there is no backend account, test whether front-end token is accepted by admin APIs; if database external connection is unreachable, look for the system's own query, code-generation, or log interfaces; if super-admin reset fails, test authorized creation of a low-impact admin or role binding only with HITL.

Evidence: token source without exposing token value, management API acceptance, permission scope, configuration type, user-management capability, and minimal read-only proof. Do not write real credentials, tokens, database addresses, or destructive SQL.

Rating boundary: interface names only are low; config/online-user read is medium-high; creating or resetting high-privilege accounts is high; SQL injection needs backend permission and data impact closure.

## Report Value

Value comes from backend capability: user/role/department export, task execution, configuration read, sensitive data query, file download, or tenant management. Component pages, titles, and default paths are entry signals only.
