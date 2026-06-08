---
name: spring-boot
description: Spring Boot / Spring Cloud 目标栈专项 playbook — 指纹识别 / 攻击面地图 / CVE 谱系 / 国内 Spring Cloud Alibaba 生态 / 利用链优先级。配合 vuln/spring-vuln.md 决策卡使用。
category: frameworks
tags: [framework, java, spring, spring-boot, spring-cloud, actuator, china]
---

# Spring Boot / Spring Cloud Playbook

> **何时用本文件**: 通过 Phase 1 指纹识别已确认目标栈是 Spring Boot / Spring Cloud,需要系统化梳理攻击面、按 ROI 排测试顺序。
> **与 [vuln/spring-vuln.md](../vuln/spring-vuln.md) 的关系**: 本文件是**目标栈视角**(横向 — 整个 Spring 攻击面),vuln/spring-vuln.md 是**漏洞视角**(纵向 — 单类漏洞决策卡)。两者互补,本文件不重复 CVE payload 细节。

---

## 1. 指纹识别 (Phase 1 必跑)

### 1.1 强指纹 (单一信号即可确认)

| 信号 | 位置 | 含义 |
| :--- | :--- | :--- |
| `Whitelabel Error Page` | 默认错误页 | Spring Boot 默认错误处理,几乎 100% 命中 |
| `X-Application-Context` Header | 响应头 | Spring Boot 1.x / 2.x 早期默认开启 |
| `/actuator/health` 返回 `{"status":"UP"}` | URL | Actuator 暴露 |
| `org.springframework.web.servlet.NoHandlerFoundException` | 报错栈 | Spring MVC |
| `Spring Framework / [SpringBoot:2.x.x]` | error trace | 版本明文泄露 |
| favicon hash `0xffffffff` 之一 | favicon | spring 默认 favicon |

### 1.2 弱指纹 (需多信号交叉)

- 端口 `8080` + JSON 响应 + `Content-Type: application/json;charset=UTF-8`
- 路径 `/api/v1/` + `Server: ` 不显式
- Set-Cookie `JSESSIONID=...; Path=/` (Tomcat)
- `/swagger-ui.html` / `/v2/api-docs` / `/v3/api-docs` 200
- WebSocket endpoint `/ws/` / `/stomp/`

### 1.3 国内生态额外指纹 (Spring Cloud Alibaba)

| 信号 | 含义 |
| :--- | :--- |
| `/nacos/` `/nacos/v1/auth/users` | Nacos 配置中心 (国内 90%+ 微服务架构) |
| `dubbo`,`/dubbo-admin` | Dubbo RPC 框架 |
| `/sentinel` / `/sentinel-dashboard` | Sentinel 流控/熔断 |
| `Sleuth`,`Zipkin`,`/zipkin/api/v2/` | 链路追踪 |
| `RocketMQ`,`/rocketmq-console-ng` | 消息队列 |
| `XXL-JOB`,`/xxl-job-admin` | 国内常见任务调度 |

确认是 Spring Cloud Alibaba 栈后 → 进入 §6.3。

---

## 2. 攻击面地图 (按 ROI 排序)

### 2.1 Tier 1 — RCE / 严重信息泄露 (优先)

| 攻击面 | 入口 | 概率 | 路由 |
| :--- | :--- | :--- | :--- |
| Actuator 暴露 | `/actuator/env` / `/heapdump` / `/jolokia` | 高 | [vuln/spring-vuln.md §1](../vuln/spring-vuln.md) |
| Spring Cloud Gateway 写路由 | `/actuator/gateway/routes` (POST) | 中 | [vuln/spring-vuln.md §3.1](../vuln/spring-vuln.md) |
| Spring Cloud Function 路由表达式 | Header `spring.cloud.function.routing-expression` | 中 (有版本依赖) | CVE-2022-22963 |
| Spring4Shell 参数绑定 | 任意 form-binding 接口 | 低 (条件苛刻) | CVE-2022-22965 |
| SpEL 注入 | 报错信息 / 模板 / 邮件 | 中 | [vuln/spring-vuln.md §4](../vuln/spring-vuln.md) |
| Nacos 默认凭证 | `nacos/nacos` | 高 | §6.3 |

### 2.2 Tier 2 — 越权 / 中等信息泄露

- Swagger 暴露 → 接口枚举 → BOLA/BFLA → [vuln/swagger-actuator-druid.md](../vuln/swagger-actuator-druid.md)
- Spring Security 配置错误 → 路径规范化绕过 (例: `;jsessionid=xx`, `/api/admin//user`)
- `/error` 信息泄露 (异常栈 / SQL 报错 / 内部地址)
- `/v3/api-docs` 拉接口文档 → 老版本 API (`/api/v0/` / `/api/internal/`)

### 2.3 Tier 3 — 信息收集

- `/actuator/info` `/actuator/metrics` `/actuator/health` (基础)
- `/actuator/mappings` — 完整端点列表
- `/actuator/beans` — 完整 Bean 表 (推断业务)
- `/actuator/loggers` — 日志配置可改 → 注入恶意 logback config

---

## 3. CVE 历史谱系 (按年份 + 影响)

> 不要堆 payload — 只列**触发版本范围**和**优先级**,具体 PoC 在确认版本后查 GitHub。

| CVE | 影响 | 版本范围 | 优先级 |
| :--- | :--- | :--- | :---: |
| CVE-2024-22243 | Spring Web URL 解析 | < 6.1.4 | M |
| CVE-2023-20860 | Spring Security 路径绕过 | 6.0.x / 5.7.x / 5.6.x | M |
| CVE-2022-22965 (**Spring4Shell**) | Param binding RCE | 5.3.0-5.3.17 / 5.2.0-5.2.19 + Tomcat WAR + JDK9+ | H (条件苛) |
| CVE-2022-22963 | Cloud Function SpEL RCE | 3.1.6 / 3.2.2 之前 | H |
| CVE-2022-22947 | Cloud Gateway SpEL RCE | 3.1.0 / 3.0.0-3.0.6 | H |
| CVE-2020-5421 | Spring 反射文件下载 | 5.2.x / 5.1.x / 5.0.x | M |
| CVE-2018-1273 | Spring Data Commons RCE | <2.0.6 / <1.13.11 | M (老但常见) |
| CVE-2017-8046 | Spring Data REST PATCH RCE | <2.5.12 / <2.6.7 | M (老但常见) |
| CVE-2016-4977 | Spring Security OAuth Approval | <2.0.10 | L |

**国内 SRC 实战频率**: Actuator 泄露 > Nacos 默认凭证 > Druid 监控暴露 > Swagger 接口枚举越权 > Spring4Shell > Cloud Gateway/Function。

---

## 4. 系统化 Recon 步骤

```bash
# Step 1: 确认 Spring Boot
curl -s -o /dev/null -w "%{http_code}\n" https://target/actuator/health
curl -sI https://target/ | grep -iE "x-application-context|whitelabel"

# Step 2: Actuator 暴露面 (按 risk 排)
for ep in env configprops heapdump jolokia gateway/routes mappings beans loggers info metrics health; do
  echo "[$ep] $(curl -s -o /dev/null -w '%{http_code} %{size_download}' https://target/actuator/$ep)"
done

# Step 3: 文档/Swagger
for path in swagger-ui.html v2/api-docs v3/api-docs swagger-resources doc.html; do
  curl -s -o /dev/null -w "[$path] %{http_code}\n" https://target/$path
done

# Step 4: 国内 Cloud Alibaba 探测
for path in nacos/ nacos/v1/auth/users dubbo-admin/ sentinel/ xxl-job-admin/ druid/ rocketmq-console-ng/; do
  curl -s -o /dev/null -w "[$path] %{http_code}\n" https://target/$path
done

# Step 5: 老版本 / 管理端口分离
for port in 8080 8081 8082 8090 9000 9001 8888; do
  curl -s -o /dev/null -w "[$port] %{http_code}\n" http://target:$port/actuator/
done
```

---

## 5. 利用链优先级 (Phase 2-3)

### 5.1 已确认 Actuator 暴露

1. **`/actuator/env` 拉 properties** → 找 datasource.password / jwt.secret / aliyun.accessKeyId
2. **`/heapdump`** → HITL 确认,本地 `mat` / `Eclipse Memory Analyzer` / `jhsdb jmap` 提取 secret/JWT/session
3. **`/actuator/jolokia`** (若有) → 测 read-only 操作 (List MBean),写操作前 HITL
4. **`/actuator/loggers`** → POST 修改 logback,如可注入 `JNDI`/`Server` 类指令 → RCE
5. **`/actuator/heapdump.json`** / `.zip` → 老版本绕过

### 5.2 已确认 Nacos

1. 测默认凭证 `nacos/nacos`,`admin/admin`
2. 测未授权 `/nacos/v1/auth/users` (CVE-2021-29441)
3. 看 namespace 是否串户 (`/nacos/v1/console/namespaces`)
4. 配置文件含数据库密码 / API key → 横向

### 5.3 已确认 Swagger/v3 doc

1. 完整接口拉取 → 找 admin/internal/debug 端点
2. 老版本 API path (`/api/v0/` / `/api/v1/internal/`)
3. 接口入参反向推 BOLA (用户 ID/订单 ID/资源 ID 直接传)
4. 接口对比 (Swagger 列出但前端不调用的"幽灵接口")

---

## 6. 国内特化攻击面

### 6.1 Druid 监控

`/druid/index.html` / `/druid/login.html` — 默认 `admin/admin` 或未授权。
泄露: SQL 历史 / Web URI 历史 / Session 监控 → 严重信息泄露。

### 6.2 XXL-JOB 任务调度

`/xxl-job-admin/` — 默认 `admin/123456`。
高危: 任务执行可写脚本 → RCE。

### 6.3 Spring Cloud Alibaba

- **Nacos**: 默认凭证 + 未授权 (CVE-2021-29441) — 国内 SRC 命中率极高
- **Sentinel**: dashboard 无认证 → 流控规则可改 → DoS / 路径劫持
- **Dubbo**: telnet 端口 (默认 20880) 暴露 → 反序列化 RCE (类似 CVE-2020-1948)
- **RocketMQ**: 默认 9876 / console 8088 → 未授权管理 → 消息伪造
- **Seata**: 默认 8091 → 分布式事务可破坏

### 6.4 Apollo / Eureka

- Apollo `/openapi/` → 测 token / 默认 portal
- Eureka `/eureka/apps` — 服务注册表泄露 → 内部服务地址 → SSRF 横向

---

## 7. 验证方法 / False Positives

| 场景 | False Positive | 真实判断 |
| :--- | :--- | :--- |
| `/actuator` 返回 404 | 不是 Spring Boot? | 试 `/actuator/health` / `/management/health` / 老版本 `/health` |
| `/actuator/env` 200 但为空 | 已脱敏 | 试 `.json` `.yaml` 后缀 / POST 方法 |
| `/heapdump` 下载到一半 | 网络? | 试 `Range: bytes=0-1024` 仅取头 |
| Spring4Shell payload 无响应 | 已修复 | 不死磕,转 Actuator |
| `/nacos/` 显示登录页 | 不一定脆弱 | 测默认凭证 + 测 CVE-2021-29441 未授权 |

---

## 8. Impact 证据 (Phase 4 报告用)

| 暴露面 | Impact 等级 | 证据要求 |
| :--- | :--- | :--- |
| Actuator `/env` 含密码 | Critical | 截图脱敏 + 验证密码可登录 DB (HITL) |
| Actuator `/env` 不含密码 | Medium | 截图 + 说明配置项类型 |
| `/heapdump` | Critical | 提取一条 JWT / session 证明,完整 dump 不上传 |
| Nacos 默认凭证 | Critical | 登录截图脱敏 + 配置列表 |
| Spring4Shell RCE | Critical | OOB-only 证明,不写 webshell |
| Swagger 暴露 | Medium-High | 接口列表 + 1-2 个具体越权链 |

---

## 9. Pro Tips

- **Actuator 路径变体不要漏**: `/actuator` `/manage` `/management` `/admin` `/monitor` `/sys` `/api/actuator`
- **管理端口分离**: 业务 8080 + 管理 8081 (`management.server.port`) — 端口扫描必跑
- **`.json` `.yaml` `.xml` 后缀绕过**: `/env.json`,`/env.yaml`
- **路径规范化**: `;jsessionid=xx` / `/..;/env` / `//actuator/env` / `%2e%2e/` 经常绕鉴权
- **Spring Boot Admin** (独立项目,非 Actuator): `/applications` 是它的端点,看到这个表示有独立监控,Actuator 可能开放更多
- **国内反检测**: 阿里云 WAF 默认拦截 `actuator` 字符串,试 URL 编码 `%61ctuator` / `act\x75ator`
- **Nacos 实战流程**: 测默认凭证 → 测未授权 API → 拉 namespace 列表 → 看 prod 命名空间是否串户 → 拉敏感配置文件
- **`heapdump` 不要轻易整个下载**: 用 `Range` Header 只取前 1MB 也能证明可下载

---

## 10. 工具升级线

**classic 版**:
- 指纹: `curl` + `nuclei -t exposed-panels/spring-*`
- Actuator 枚举: `ffuf -w actuator-paths.txt`
- Spring4Shell: 手 payload 或 `nuclei -t CVE-2022-22965`
- heapdump 分析: `mat` (Eclipse Memory Analyzer) / `jhat` / 自写 `jhsdb jmap` script

**toolPlus 版**:
- 指纹: `mcp__yaklang__http_fuzzer` 一次发 50 个候选 actuator 路径
- 静态分析: `mcp__yaklang__ssa_compile language="java"` + SyntaxFlow 数据流找 SpEL sink
- exec_codec: chained base64+gzip 解 heapdump 中的 JWT
- Chrome MCP: 登录 Druid/Nacos 后自动截图归档证据

---

## 11. 相关参考

- 漏洞决策卡: [vuln/spring-vuln.md](../vuln/spring-vuln.md)
- Swagger/Actuator/Druid: [vuln/swagger-actuator-druid.md](../vuln/swagger-actuator-druid.md)
- SSTI/SpEL: [vuln/ssti.md](../vuln/ssti.md)
- Fastjson/Jackson: [vuln/fastjson-jackson.md](../vuln/fastjson-jackson.md)
- Shiro: [vuln/shiro.md](../vuln/shiro.md)
- 敏感信息利用: [sensitive-info-exploitation.md](../sensitive-info-exploitation.md)
- OOB 基础设施: [oob-infrastructure.md](../oob-infrastructure.md)
