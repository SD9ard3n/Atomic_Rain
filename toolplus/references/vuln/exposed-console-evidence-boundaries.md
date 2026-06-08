---
name: exposed-console-evidence-boundaries
description: Swagger、Actuator、Druid、H2、Jolokia、Nacos、Eureka 等开发/监控/文档面板暴露的横向证据边界、评级口径和误判过滤。
category: vuln
tags: [swagger, actuator, druid, evidence, rating, false-positive]
---

# 暴露控制台证据边界

用途: 只承接 Swagger / Actuator / Druid / H2 / Jolokia / Nacos / Eureka / Spring Boot Admin 等暴露面的证据、评级、HITL 和误判过滤。endpoint 枚举和利用步骤仍回到 [swagger-actuator-druid.md](swagger-actuator-druid.md)。

---

## 横向判断表

| 入口信号 | 失败现象 | 转向动作 | 关键证据 | 评级边界 | 误判过滤 |
|---|---|---|---|---|---|
| Swagger UI / OpenAPI JSON | UI 可见但无接口 | 直接抓 `/v2/api-docs` / `/v3/api-docs` / 分组文档 | UI、JSON、接口数量、鉴权字段 | 仅 UI 低;可调用敏感 API 才升高 | 静态 UI 残留不是漏洞 |
| Swagger 暴露接口 | 接口 401/403 | 对照匿名/低权/高权,找未授权或 BOLA | endpoint、参数、auth 差异、业务影响 | 按 API 影响定级 | 文档暴露不等于接口可用 |
| Actuator health/info | 只有 up | 找 env、heapdump、mappings、jolokia | endpoint、响应、敏感字段 | health/info 通常低 | 只返回 up 不高危 |
| env/configprops | 字段 masked | 查 heapdump、日志、mappings 或源码线索 | 明文字段、脱敏样例、来源 | 明文凭证/配置中高 | `***` 不算泄露 |
| heapdump | 文件很大或高敏 | HITL,只取证据片段 | 文件大小、少量脱敏命中、字段类型 | 含凭证/Token 高危候选 | 不下载/解析大量生产数据 |
| Jolokia / Gateway / H2 | 可能写文件/RCE | HITL 后做最小化验证 | MBean/route/SQL、最小回显或自有文件 | 可执行/写入 Critical 候选 | 不重启、不持久化、不写真实路径 |
| Druid | 页面可见但无数据 | 看 datasource/sql/websession,对照登录状态 | SQL 片段、连接串、Session 或权限状态 | 敏感 SQL/连接串/Session 高 | 空监控面板低 |
| 默认凭据 | 字典命中或登录页 | 只验证授权样本和角色权限 | 登录成功、角色、可访问模块 | 高权后台中高 | 只列默认密码不算漏洞 |

---

## 最小证据包

- 暴露面: endpoint、状态码、标题/指纹、认证状态。
- 数据: 文档 JSON、配置字段、SQL 监控、heapdump 片段或连接串脱敏样例。
- 可调用性: 匿名/低权/高权差异,实际接口调用或功能访问结果。
- 影响: 敏感数据、凭证、Session、后台功能、写文件、RCE 或级联路径。
- 边界: HITL 授权、未下载大文件、未重启服务、未写真实路径、未批量导出。

---

## 评级口径

- 静态 UI、health/up、登录页、空面板: 低危或攻击面线索。
- OpenAPI JSON 暴露大量内部 API、mappings、beans、非敏感配置: 低中。
- 明文凭证、SQL 参数、Session、连接串、敏感配置: High 候选。
- Jolokia/H2/Gateway/Actuator 写入、命令执行、云/K8s 凭据: Critical 候选。

---

## HITL 边界

- Heapdump、大配置、SQL 监控、Session 接管、默认凭据登录、Jolokia/H2/Gateway 写入或 RCE 都要最小化验证。
- 下载大文件、读取敏感数据、重启/refresh、写文件、创建路由、接管 Session 前必须 HITL。
- 仅取脱敏片段和自有测试对象,不得扩大枚举。

---

## 报告前误判过滤

- 不把 Swagger UI、Actuator health、Druid 首页、登录页或静态资源当高危。
- 不把 masked env、空 Swagger、空 Druid、401/403 端点当敏感泄露。
- 不把默认口令字典写入报告,必须证明登录成功和权限影响。
- 不把可上传脚本到对象存储或静态目录直接当 RCE。
