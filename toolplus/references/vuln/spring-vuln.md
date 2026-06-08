---
name: spring-vuln
description: CWE: 94 / 502 / 22 / 200 | ROI: 极高 (P0) 轻便原则: 只放 Spring 高 ROI 路由: Actuator / Spring4Shell / Cloud Gateway / Function / SpEL。具体 CVE payload…
category: vuln
tags: [java]
---

# Spring 生态决策卡 (Light Deep Card)

> **CWE**: 94 / 502 / 22 / 200 | **ROI**: 极高 (P0)
> **轻便原则**: 只放 Spring 高 ROI 路由: Actuator / Spring4Shell / Cloud Gateway / Function / SpEL。具体 CVE payload 不堆在本文件。

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| `Whitelabel Error Page` | Spring Boot | §1 Actuator |
| `/actuator/health` 200 | Actuator 暴露 | §1 |
| `/actuator/env`, `/heapdump`, `/jolokia` 200 | 高危信息泄露/RCE 链 | §1.2 |
| 请求参数/Header 触发 SpEL 报错 | SpEL 注入可能 | §4 |
| Tomcat + Spring MVC + JDK 9+ | Spring4Shell 条件之一 | §2 |
| Spring Cloud Gateway 指纹 | Gateway RCE/路由操控 | §3 |

记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。禁止未确认指纹就跑全量 CVE。

---

## 1. Actuator 路由

### 1.1 First-pass 端点

```http
/actuator
/actuator/health
/actuator/env
/actuator/configprops
/actuator/heapdump
/actuator/jolokia
/actuator/gateway/routes
```

### 1.2 风险判断

| 端点 | 风险 | 动作 |
|------|------|------|
| `/health` only | 低 | 记录指纹 |
| `/env` / `/configprops` | 高 | 找 AK/DB 密码/JWT secret → 敏感信息三阶段 |
| `/heapdump` | 高 | 只下载最小证明前先 HITL;提取凭证需脱敏 |
| `/jolokia` | 高/严重 | 测 read-only;RCE 前 HITL |
| `/gateway/routes` | 高/严重 | 查 Gateway 版本与路由写权限 |

### 1.3 常见绕过

```http
/actuator;%20/env
/actuator/..;/env
//actuator/env
/actuator/env.json
```

---

## 2. Spring4Shell (CVE-2022-22965) 路由

**必要条件**(不满足则降优先级):
- Spring Framework 5.3.x / 5.2.x 部分版本
- JDK 9+
- Tomcat WAR 部署
- 存在可绑定对象参数

**First-pass**: 只测参数绑定异常/响应差异,不要直接写 WebShell。

```http
POST /path
class.module.classLoader.URLs[0]=test
```

若出现 `class.module` / binding error / 500 差异,再查专门 PoC,并在写文件前 HITL 确认。

---

## 3. Spring Cloud Gateway / Function

### 3.1 Gateway

| 信号 | 动作 |
|------|------|
| `/actuator/gateway/routes` 可读 | 判断是否可写路由 |
| actuator gateway refresh 可调用 | 可能 RCE 链 |
| 版本接近 CVE-2022-22947 | 查 CVE PoC,先 OOB-only |

**禁止**: 未授权确认前写入持久路由;先读 routes + OOB-only。

### 3.2 Spring Cloud Function (CVE-2022-22963)

信号: Header / 参数里出现 function routing,例如 `spring.cloud.function.routing-expression`。

First-pass: 用 harmless 表达式观察响应差异;RCE 前 HITL。

---

## 4. SpEL 注入

### 4.1 常见入口

- 查询参数: `?name=#{7*7}` / `${7*7}`
- Header: `X-...: #{7*7}`
- 模板/邮件/报表字段
- Spring Data REST / error page / validation message

### 4.2 判断

| 响应 | 判断 |
|------|------|
| `49` | 表达式被执行 |
| SpEL parser error | 进入过滤绕过/语法适配 |
| 原样返回 | 可能只是反射,转 XSS/SSTI 判断 |

---

## 5. Triage

| 现象 | 可能原因 | 下一步 |
|------|----------|------|
| `/actuator` 403 | 网关拦截/管理端口分离 | 路径规范化绕过;查 8081/9000 |
| `/heapdump` 很大 | 高风险下载 | HITL 确认,只取证据片段 |
| Spring4Shell payload 无效 | 条件不满足 | 不死磕,转 Actuator/SpEL |
| Gateway routes 可读不可写 | 信息泄露 | 记录架构,不报 RCE |
| SpEL 报错但不执行 | 语法/过滤问题 | 查 SSTI/SpEL 具体构造 |

---

## 6. 级联

- Actuator 泄露凭证 → [../sensitive-info-exploitation.md](../sensitive-info-exploitation.md)
- heapdump 提取 secret → JWT/Shiro/Fastjson 链
- Gateway 可写路由 → SSRF/OOB 验证
- SpEL 命中 → 命令注入/SSTI 影响证明

---

## 7. Attack Surface (摘要)

完整攻击面、CVE 谱系、Spring Cloud Alibaba 国内生态见 [../frameworks/spring-boot.md](../frameworks/spring-boot.md)。

本文件 (vuln/spring-vuln.md) 只是**漏洞决策卡**;框架专项 (frameworks/spring-boot.md) 是**目标栈视角**。两者互补:
- vuln/spring-vuln.md → 单类漏洞 (Actuator / Spring4Shell / Gateway / Function / SpEL)
- frameworks/spring-boot.md → 全栈指纹 + 11 个 CVE + Nacos/Dubbo/Druid/XXL-JOB + 国内 Spring Cloud Alibaba

---

## 8. High-Value Targets

1. **Actuator 暴露 `/env` `/heapdump` `/jolokia`** (P0,国内 SRC 命中率最高)
2. **Nacos 默认凭证 + 未授权 (CVE-2021-29441)** (P0,Spring Cloud Alibaba 黄金入口)
3. **Druid 监控面板** (`/druid/`) — 默认 admin/admin 或未授权 (P0)
4. **XXL-JOB 任务调度** — 默认 admin/123456 → RCE (P0)
5. **Spring Cloud Gateway 可写路由** (P0)
6. **Spring Cloud Function `routing-expression`** (P0)
7. **Spring4Shell** (条件苛但仍存在) (P0)

---

## 9. False Positives

| 误报 | 真实判断 |
| :--- | :--- |
| `/actuator` 404 但 `/management/health` 200 | 端点路径自定义 | 试多种命名 |
| `/heapdump` 下载到一半 | 网络问题 / 大文件超时 | 用 Range Header 取前 1MB |
| Spring4Shell payload 无效 | 不满足条件 (JDK 8 / Jetty / 非 form binding) | 不死磕,转 Actuator |
| Nacos 显示登录页 | 未授权不一定脆弱 | 测 CVE-2021-29441 + 默认凭证 |
| SpEL 报错但不执行 | 语法错误 / 过滤 | 转 SSTI 看是否其他模板引擎 |

---

## 10. Impact / 升级路径

| 链 | 终态 | Impact |
| :--- | :--- | :--- |
| Actuator `/env` → DB 密码 / Redis 密码 | DB 直连 / 横向 | Critical |
| `/heapdump` → JWT secret / session | 接管账户 | Critical |
| `/actuator/jolokia` → MBean 操作 | RCE | Critical |
| Spring Cloud Gateway 写路由 → SSRF / RCE | RCE | Critical |
| Spring Cloud Function SpEL RCE | RCE | Critical |
| Spring4Shell + Tomcat | RCE | Critical |
| Druid + 默认凭证 → SQL 历史 / Session 监控 | 信息泄露 | High |
| 仅泄露版本号 / 错误页 | 信息收集 | Low-Medium |

详细取证模板见 [../frameworks/spring-boot.md §8](../frameworks/spring-boot.md)。

---

## 11. Pro Tips

- **Actuator 路径变体务必扫**: `/actuator` `/manage` `/management` `/admin` `/monitor` `/sys` `/api/actuator`
- **管理端口分离**: 业务 8080 + 管理 8081 (`management.server.port`) — 端口扫描必跑
- **`.json` `.yaml` `.xml` 后缀绕过**: `/env.json` 经常被遗漏
- **路径规范化**: `;jsessionid=xx` / `/..;/env` / `//actuator/env`
- **`heapdump` Range 取证**: `Range: bytes=0-1048576` 取 1MB 证明
- **国内 WAF**: 阿里云 / 腾讯云 拦 `actuator` 字符串 → 试 `%61ctuator` URL 编码
- **Nacos 三步走**: 默认凭证 → 未授权 API → namespace 串户
- **XXL-JOB 任务执行 RCE**: 后台登录后 GLUE 脚本类型直接 RCE
- **Spring Boot Admin (独立项目)** ≠ Actuator,看到 `/applications` 表示有独立监控

---

## 12. 工具升级线

**classic 版**:
- 指纹: `nuclei -t exposed-panels/spring-*`
- Actuator 枚举: `ffuf -w actuator-paths.txt`
- 历史扫: `xray webscan` 含 Spring 模板

**toolPlus 版**:
- `mcp__yaklang__http_fuzzer` 一次发 50 个 actuator 路径候选
- `mcp__yaklang__ssa_compile language="java"` + SyntaxFlow 找 SpEL sink (`SpelExpressionParser.parseExpression`)
- `mcp__yaklang__exec_codec` chained base64+gzip 解 heapdump JWT

---

## 13. 相关参考

- Swagger/Actuator/Druid → [swagger-actuator-druid.md](swagger-actuator-druid.md)
- SSTI/SpEL 相邻 → [ssti.md](ssti.md)
- Shiro → [shiro.md](shiro.md)
- Fastjson/Jackson → [fastjson-jackson.md](fastjson-jackson.md)
- OOB → [../oob-infrastructure.md](../oob-infrastructure.md)
