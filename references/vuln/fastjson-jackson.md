# Fastjson / Jackson 决策卡 (Light Deep Card)

> **CWE**: 502 | **ROI**: 极高 (P0)
> **轻便原则**: OOB-first,只放版本路由与关键判断;大 gadget 字典交给工具/外部库。

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| 畸形 JSON `{ ""` 返回 `fastjson` / `autoType` / `JSONException` | Fastjson 可能 | §1 |
| 报错含 `com.fasterxml.jackson` / `InvalidTypeIdException` | Jackson 可能 | §2 |
| Java/Spring 指纹 + JSON API | 反序列化高优先 | OOB URLDNS/JNDI 探测 |
| Content-Type JSON + 500 差异稳定 | 可疑 sink | 记录三要素后再查 Decision Card |

**禁止**: 未确认 JSON 反序列化路径前盲发 RCE payload。必须先用 DNS/OOB-only 证明可触发。

---

## 1. Fastjson 路由

### 1.1 版本/行为判断

| 版本/行为 | 特征 | 首测 |
|-----------|------|------|
| ≤1.2.24 | autoType 默认风险高 | `JdbcRowSetImpl` DNS/JNDI |
| 1.2.25-1.2.47 | 黑名单绕过历史多 | DNS-only gadget |
| 1.2.48-1.2.68 | expectClass / 白名单场景 | 先找业务类名/报错 |
| 1.2.80+ | 默认更严 | 只在有 autoType/白名单线索时继续 |
| 版本未知 | 只做 OOB-first | 不直接 RCE |

### 1.2 First-pass Payload 思路

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

### 1.3 常见切换

| OOB 结果 | 动作 |
|----------|------|
| DNS 回调 | 证明触发,进入影响验证/HITL 确认是否升级 |
| LDAP/RMI 被封但 DNS 有 | 只报可触发外连,不强报 RCE |
| 完全无回调 | 换 OOB / 检查出站 / 转 Jackson 或普通 JSON 注入 |
| 500 + 无回调 | 可能类存在但出站失败,记录 Triage |

---

## 2. Jackson 路由

### 2.1 触发前提

Jackson 反序列化通常需要以下任一条件:
- 启用 default typing / polymorphic deserialization
- `@JsonTypeInfo` 接收用户可控 `@type` / `class`
- API 明确接受对象类型字段
- 报错含 `InvalidTypeIdException`, `Could not resolve type id`

### 2.2 First-pass 字段

```json
{"@type":"java.lang.Object"}
{"class":"java.lang.Object"}
{"type":"java.lang.Object"}
```

观察错误差异,不要直接上危险 gadget。

### 2.3 Gadget 方向

| 环境信号 | 方向 |
|----------|------|
| Spring + Hikari/Druid | 数据源类探测 |
| JNDI 可出站 | LDAP/DNS OOB |
| commons-collections 存在 | ysoserial 系列 |
| 无依赖信息 | 仅报 polymorphic type exposure / 继续信息收集 |

---

## 3. Triage

| 现象 | 可能原因 | 下一步 |
|------|----------|------|
| `autoType is not support` | Fastjson 命中但被拦 | 查版本/白名单类/业务类 |
| `ClassNotFoundException` | 类不存在但类型被解析 | 换低风险类名确认 |
| `InvalidTypeIdException` | Jackson polymorphic 入口 | 测 `@type/class/type` 字段 |
| 200 且无回调 | payload 未进入 sink / 出站封锁 | 换字段位置 / 换 OOB |
| 500 稳定 | 解析器 crash | 记录信号,谨慎升级 |

---

## 4. 级联

- 命中 OOB → 进入 [oob-infrastructure.md](../oob-infrastructure.md) 记录证据。
- 发现 Spring 指纹 → 进入 [spring-vuln.md](spring-vuln.md)。
- 发现 Shiro/JWT key 泄露 → 进入 [shiro.md](shiro.md) / [jwt-advanced.md](jwt-advanced.md)。
- 发现数据库连接串 / AK → 进入敏感信息三阶段验证。

---

## 5. 相关参考

- 反序列化通用 → [deserialize.md](deserialize.md)
- Java JNDI / Log4Shell → [jndi-log4shell.md](jndi-log4shell.md)
- Spring 生态 → [spring-vuln.md](spring-vuln.md)
- OOB → [../oob-infrastructure.md](../oob-infrastructure.md)
