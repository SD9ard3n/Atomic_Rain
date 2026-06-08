---
name: syntaxflow
description: 支持语言:java / php / js / golang / yak / c / python (7 种) 本文只放算子 + 规则模板。完整背景 / 增量编译 / 陷阱 → [ssa-vuln-hunting.md](../ssa-vuln-hunting.md)
category: cheatsheet
---

# SyntaxFlow 速查 (toolPlus)

← [mcp-tools-finder.md](../mcp-tools-finder.md) | 完整 SOP:[ssa-vuln-hunting.md](../ssa-vuln-hunting.md)
适用工具:`mcp__yaklang__ssa_compile` + `mcp__yaklang__ssa_query`

> **支持语言**:`java` / `php` / `js` / `golang` / `yak` / `c` / `python` (7 种)
> 本文只放算子 + 规则模板。完整背景 / 增量编译 / 陷阱 → [ssa-vuln-hunting.md](../ssa-vuln-hunting.md)

---

## §1 算子(Operators)

| 算子 | 含义 | 例子 |
|---|---|---|
| `.` | 调用链 | `Runtime.getRuntime().exec()` |
| `#->` | **TopDef**(Use-Def):值**从哪里来** | `$sink #-> * as $source` |
| `-->` | **BottomUse**(Def-Use):值**流到哪里** | `$source --> * as $sink` |
| `?{...}` | 条件过滤 | `?{opcode: call}` / `?{!opcode: param}` |
| `as $var` | 捕获到变量 | `... as $userInput` |
| `check $var then "msg"` | 断言变量非空,空则报错 | `check $sink then "no sink found"` |
| `alert $var` | 标记为**发现**(报告里出) | `alert $userInput` |
| `<slice(start=N)>` | 取参数从第 N 个开始(0-indexed) | `func(<slice(start=1)>)` 跳过第一个参数 |
| `*` | 通配符,匹配任意节点 | `Runtime.exec(*)` |
| `;` | 多条规则分隔 | `rule1; rule2; alert $a` |

---

## §2 节点类型(`?{}` 过滤用)

| opcode | 含义 |
|---|---|
| `call` | 函数调用 |
| `param` | 函数参数 |
| `const` | 常量 |
| `var` | 变量定义 |
| `assign` | 赋值 |
| `binop` | 二元运算 (+, -, *, etc.) |

---

## §3 高频规则模板

### Java

```
// 命令注入
Runtime.getRuntime().exec(*<slice(start=1)> #-> * as $source) as $sink;
alert $sink

// SQL 拼接(StringBuilder)
*sql*.append(*<slice(start=1)> #-> * as $userInput) as $sqliSink;
alert $sqliSink

// Fastjson 反序列化入口
JSON.parseObject(*<slice(start=1)> #-> * as $jsonInput) as $deserSink;
JSON.parse(*<slice(start=1)> #-> * as $jsonInput) as $deserSink;
alert $deserSink
```

### PHP

```
// eval / assert RCE
eval(*<slice(start=1)> #-> * as $codeInput) as $rceSink;
assert(*<slice(start=1)> #-> * as $codeInput) as $rceSink;
alert $rceSink

// 文件包含
include(*<slice(start=1)> #-> ($_GET, $_POST, $_REQUEST, $_FILES) as $lfiSink) as $lfiSink;
require(*<slice(start=1)> #-> ($_GET, $_POST, $_REQUEST, $_FILES) as $lfiSink) as $lfiSink;
alert $lfiSink

// 系统命令
system(*<slice(start=1)> #-> * as $cmdInput) as $cmdSink;
shell_exec(*<slice(start=1)> #-> * as $cmdInput) as $cmdSink;
exec(*<slice(start=1)> #-> * as $cmdInput) as $cmdSink;
passthru(*<slice(start=1)> #-> * as $cmdInput) as $cmdSink;
alert $cmdSink
```

### JavaScript(小程序 / Node.js)

```
// 小程序 wx.request 用户输入(★高产)
wx.request(*<slice(start=1)> #-> * as $userInput) as $sink;
alert $sink

// Node.js child_process
child_process.exec(*<slice(start=1)> #-> * as $cmdInput) as $rceSink;
child_process.execSync(*<slice(start=1)> #-> * as $cmdInput) as $rceSink;
child_process.spawn(*<slice(start=1)> #-> * as $cmdInput) as $rceSink;
alert $rceSink

// DOM XSS
*.innerHTML = *<slice(start=1)> #-> * as $xssInput;
document.write(*<slice(start=1)> #-> * as $xssInput);
alert $xssInput
```

### Golang

```
// SQL 拼接
*.Query(*<slice(start=1)> #-> * as $sqlInput) as $sqliSink;
*.Exec(*<slice(start=1)> #-> * as $sqlInput) as $sqliSink;
alert $sqliSink

// 命令执行
exec.Command(*<slice(start=1)> #-> * as $cmdInput) as $rceSink;
alert $rceSink

// 路径遍历
os.Open(*<slice(start=1)> #-> * as $pathInput) as $lfiSink;
ioutil.ReadFile(*<slice(start=1)> #-> * as $pathInput) as $lfiSink;
alert $lfiSink
```

### Python

```
// Pickle 反序列化(必查!)
pickle.loads(*<slice(start=1)> #-> * as $deserInput) as $deserSink;
alert $deserSink

// 命令执行
os.system(*<slice(start=1)> #-> * as $cmdInput) as $rceSink;
subprocess.call(*<slice(start=1)> #-> * as $cmdInput) as $rceSink;
subprocess.Popen(*<slice(start=1)> #-> * as $cmdInput) as $rceSink;
alert $rceSink

// SQL execute 拼接
*.execute(*<slice(start=1)> #-> * as $sqlInput) as $sqliSink;
alert $sqliSink
```

### C / C++

```
// 危险字符串函数
strcpy(*<slice(start=1)> #-> * as $bufInput) as $bofSink;
strcat(*<slice(start=1)> #-> * as $bufInput) as $bofSink;
sprintf(*<slice(start=1)> #-> * as $bufInput) as $bofSink;
gets(*<slice(start=1)> #-> * as $bufInput) as $bofSink;
alert $bofSink

// 格式化字符串漏洞
printf(*<slice(start=0)> #-> * as $fmtInput) as $fmtSink;
fprintf(*<slice(start=1)> #-> * as $fmtInput) as $fmtSink;
alert $fmtSink
```

### Yak

```
// Yak 命令执行
exec.SystemContext(*<slice(start=1)> #-> * as $cmdInput) as $rceSink;
alert $rceSink

// Yak HTTP 调用(SSRF 隐患)
poc.HTTP(*<slice(start=1)> #-> * as $urlInput) as $ssrfSink;
alert $ssrfSink
```

---

## §4 常见错误

| 错误 | 原因 |
|---|---|
| `ssa_query` 返回空 | 规则太严或方向写反(TopDef vs BottomUse) — 加 `check $var then "..."` 验证 |
| 命中数千条 | 规则太宽,加 `?{opcode: call}` 等过滤 |
| 命中 90% 是误报 | 用户输入经过了过滤函数(SSA 不识别),需人工 Read 验证 |
| program_name not found | 没编译过,先调 `ssa_compile` |

---

*SyntaxFlow cheatsheet v1.0 — 2026-05-24*
