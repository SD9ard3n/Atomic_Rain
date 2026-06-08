---
name: toolplus-overlay
description: 本文件价值:vuln/.md 是 classic 与 toolPlus 共享的漏洞知识库主体,内容相同。差异只在操作工具部分 — classic 用 curl/sqlmap/nuclei,toolPlus 用 mcpyaklang + mcpchrome。 机制:用 marke…
category: meta
---

# toolPlus Overlay Guide — vuln/*.md MCP 改造指南

<!-- build:skip -->

← 主入口 [../../SKILL.md](../../SKILL.md) | 配套 [../mcp-tools-finder.md](../mcp-tools-finder.md)

> **本文件价值**:vuln/*.md 是 classic 与 toolPlus 共享的漏洞知识库主体,内容相同。差异只在**操作工具部分** — classic 用 curl/sqlmap/nuclei,toolPlus 用 `mcp__yaklang__*` + `mcp__chrome__*`。
> **机制**:用 marker 注释分块,classic 看 `<!-- classic -->` 段,toolPlus 看 `<!-- toolPlus -->` 段。
> **目标**:**单一来源 + 双版本输出**(配合未来的 `build.py`)。

---

## §1 marker 规范

### 基本格式

```markdown
<!-- toolPlus -->
(只在 toolPlus 版生效的内容 — 通常是 MCP 工具调用)
<!-- /toolPlus -->

<!-- classic -->
(只在 classic 版生效的内容 — 通常是 CLI 工具命令)
<!-- /classic -->
```

### build.py 行为

```
read source.md →
  保留 toolPlus 块、删除 classic 块 → 输出 atomic-rain-toolPlus/.../source.md
  保留 classic 块、删除 toolPlus 块 → 输出 atomic-rain/.../source.md
共享部分(marker 外):两版都保留
```

### 嵌套规则

- ❌ 不允许嵌套(`<!-- toolPlus -->` 里再放 `<!-- classic -->`)
- ✅ 允许同节多次出现 marker 块(交替排列)
- ✅ marker 块内可以有任意 markdown 语法

---

## §2 常见替换模式(替换前 → 替换后)

### 2.1 HTTP 发包

```markdown
<!-- classic -->
```bash
curl -X POST https://target/api/x -d 'param=PAYLOAD' -H 'Cookie: ...'
```
<!-- /classic -->

<!-- toolPlus -->
```
mcp__yaklang__http_fuzzer {
  request: "POST /api/x HTTP/1.1\r\nHost: target\r\nCookie: ...\r\n\r\nparam=PAYLOAD",
  isHttps: true,
  fuzzTagMode: "standard",
  concurrent: 20
}
```
<!-- /toolPlus -->
```

### 2.2 SQL 注入工具

```markdown
<!-- classic -->
确认信号后用 `sqlmap -r req.txt --batch --random-agent`
<!-- /classic -->

<!-- toolPlus -->
确认信号后用 `mcp__yaklang__http_fuzzer` 配合 fuzztag 批量探测:
- 布尔盲注: `id={{int(1-5)}} AND 1={{int(1,2)}}`
- 时间盲注: `id=1 AND SLEEP({{int(1,3,5)}})` 观察 `duration` 字段
- Union: 用 dict 喂列数 `{{file:union_columns.txt}}`
<!-- /toolPlus -->
```

### 2.3 XSS 触发验证

```markdown
<!-- classic -->
打开浏览器手动访问 URL,看 alert 是否触发,F12 console 看日志(HITL)
<!-- /classic -->

<!-- toolPlus -->
1. `mcp__chrome__chrome_navigate {url: "<触发 URL>"}` 自动加载
2. `mcp__chrome__chrome_console` 抓 console + 异常
3. `mcp__chrome__chrome_screenshot {fullPage: true}` 落地证据
<!-- /toolPlus -->
```

### 2.4 子域名收集

```markdown
<!-- classic -->
```bash
subfinder -d target.com -silent | tee subs.txt
amass enum -passive -d target.com >> subs.txt
sort -u subs.txt
```
<!-- /classic -->

<!-- toolPlus -->
```
mcp__yaklang__subdomain_collection {
  target: "target.com",
  notRecursive: false
}
```
<!-- /toolPlus -->
```

### 2.5 端口扫描

```markdown
<!-- classic -->
```bash
nmap -sV -p- target.com -oN nmap.txt
```
<!-- /classic -->

<!-- toolPlus -->
```
mcp__yaklang__port_scan {
  targets: ["target.com"],
  ports: [1-65535],
  mode: "all",
  proto: ["tcp"],
  active: true,
  fingerprintMode: "all",
  saveToDB: true
}
```
<!-- /toolPlus -->
```

### 2.6 加密 / 解密

```markdown
<!-- classic -->
```bash
echo -n 'plaintext' | openssl enc -aes-128-cbc -K KEY -iv IV -base64
```
<!-- /classic -->

<!-- toolPlus -->
```
mcp__yaklang__exec_codec {
  text: "plaintext",
  workFlow: [{
    codecType: "AESEncrypt",
    params: [
      {key: "key", value: "<KEY>"},
      {key: "iv", value: "<IV>"},
      {key: "mode", value: "CBC"}
    ]
  }, {
    codecType: "Base64Encode",
    params: []
  }]
}
```
<!-- /toolPlus -->
```

### 2.7 暴破

```markdown
<!-- classic -->
```bash
hydra -L user.txt -P pass.txt ssh://target.com -t 4
```
<!-- /classic -->

<!-- toolPlus -->
```
mcp__yaklang__brute {
  type: "ssh",
  target: {targets: ["target.com"]},
  user-dict: {usernameFile: "user.txt"},
  pass-dict: {passwordFile: "pass.txt"},
  concurrent: 4,
  okToStop: true,
  replaceDefaultUsernameDict: true,
  replaceDefaultPasswordDict: true
}
```
<!-- /toolPlus -->
```

### 2.8 OOB / dnslog

```markdown
<!-- classic -->
手动打开浏览器访问 http://dnslog.cn,点 "Get SubDomain" 拿子域,粘贴到 payload。
(HITL: 让用户操作)
<!-- /classic -->

<!-- toolPlus -->
```
mcp__chrome__chrome_navigate {url: "http://dnslog.cn/"}
mcp__chrome__chrome_click_element {selector: "#getDomain"}
mcp__chrome__chrome_get_web_content {selector: "#myDomain"} → 提取子域字符串
```
**注意**:使用 dnslog.cn 等公共 OOB **必须 HITL 确认**(见 [SKILL.md §1 P3.5](../../SKILL.md))。
<!-- /toolPlus -->
```

---

## §3 当前已改造的文件

| 文件 | 状态 | 改造段落 |
|---|---|---|
| `sqli.md` | ✅ | First-pass(sqlmap → http_fuzzer + fuzztag)|
| `xss.md` | ✅ | Decision Card(手动验证 → chrome 自动化三件套)|
| `ssrf.md` | ✅ | OOB 段(dnslog 手动 → chrome 自动化)|

## §4 待改造清单(优先级排序)

| 文件 | 优先级 | 重点段落 |
|---|---|---|
| `cmdi.md` | P0 | First-pass(curl + ; sleep → http_fuzzer + duration)|
| `path-traversal.md` | P0 | 字典遍历(ffuf → http_fuzzer + `{{file:lfi-dict.txt}}`)|
| `upload.md` | P0 | 上传 PoC(curl multipart → http_fuzzer 模板)|
| `ssti.md` | P1 | 模板探测({{7*7}} → http_fuzzer + 引擎指纹)|
| `xxe.md` | P1 | XML PoC(curl XML body → http_fuzzer + OOB chrome)|
| `prototype-pollution.md` | P2 | DOM 触发(chrome_inject_script)|
| `race-condition.md` | P2 | 高并发(http_fuzzer concurrent: 100+ + 微秒级)|
| `jwt-advanced.md` | P2 | JWT 操作(exec_codec JwtParse/JwtSign/JwtReverseSign)|
| `shiro.md` | P3 | Shiro 利用(exec_codec AESEncrypt 国密 / JavaSerialize)|
| `fastjson-jackson.md` | P3 | Fastjson(http_fuzzer + JdbcRowSetImpl payload)|

---

## §5 改造方法论(给贡献者)

### Step 1: 识别改造点

grep 文件里以下关键词,**一律是改造候选**:

- `curl ` / `wget `
- `sqlmap ` / `nuclei ` / `nmap ` / `ffuf ` / `subfinder `
- `hydra ` / `medusa `
- `openssl ` / `python -c "import`
- `HITL` / `让用户` / `手动` / `打开浏览器`
- `dnslog.cn` / `interactsh` (公共 OOB,需配合 chrome 自动化)

### Step 2: 确定 MCP 替代

查 [mcp-tools-finder.md §1](../mcp-tools-finder.md) 工具按用途索引,找最匹配的 MCP 工具。

### Step 3: 包 marker

按 §1 规范,把原 classic 段包 `<!-- classic -->...<!-- /classic -->`,新 toolPlus 段包 `<!-- toolPlus -->...<!-- /toolPlus -->`,**两段并排**(不是替换)。

### Step 4: 验证(build.py 跑后)

```bash
# build.py 运行后,产出两个目录
diff atomic-rain/references/vuln/sqli.md atomic-rain-toolPlus/references/vuln/sqli.md
# 应该只有 marker 块的差异
```

### Step 5: 提交

git commit message 模板:
```
toolPlus: add MCP overlay to <vuln_name>.md

- <段落 1>: <classic 工具> → <toolPlus MCP 工具>
- <段落 2>: ...

Refs: vuln/_TOOLPLUS_OVERLAY.md
```

---

## §6 常见错误

### 错误 1: 忘记包 classic 块

```markdown
❌ 错误:只加 toolPlus 段,把原 classic 段直接覆盖
✅ 正确:并排两段,classic 留给 classic 版

# 错误示范
<!-- toolPlus -->
mcp__yaklang__http_fuzzer { ... }
<!-- /toolPlus -->
(原 curl 命令丢了,classic 版用户看不到工具说明!)

# 正确示范
<!-- classic -->
curl -X POST ...
<!-- /classic -->
<!-- toolPlus -->
mcp__yaklang__http_fuzzer { ... }
<!-- /toolPlus -->
```

### 错误 2: marker 跨段落

```markdown
❌ 不要这样:
<!-- toolPlus -->
## 标题 1
内容...
## 标题 2
<!-- /toolPlus -->

✅ 这样:每个段落独立包 marker,标题在外面共享
## 标题 1
<!-- toolPlus -->
内容...
<!-- /toolPlus -->
## 标题 2
```

### 错误 3: marker 嵌套

```markdown
❌ 不允许:
<!-- toolPlus -->
<!-- classic -->
内容
<!-- /classic -->
<!-- /toolPlus -->

✅ 拆开:
<!-- toolPlus -->...<!-- /toolPlus -->
<!-- classic -->...<!-- /classic -->
```

---

## §7 与 build.py 的契约

(build.py 在 [../../scripts/build.py](../../scripts/build.py) — T7 实现)

build.py 处理逻辑:
1. 输入:`source/` 目录(含 marker 的源文件)
2. 输出:`atomic-rain/` + `atomic-rain-toolPlus/`(两份剥离 marker 的发行版)
3. 错误检测:发现 marker 嵌套 / 不闭合 → 退出非 0,告警
4. 验证:diff 两版,**marker 外内容必须完全一致**

---

## §8 临时状态(过渡期)

当前 toolPlus 目录是 cp 派生(Phase B T1),vuln/*.md 内容与 classic 完全一致,**只在 sqli/xss/ssrf 三个文件做了示范改造**。其余漏洞文件按需在使用中**临时通过本指南 §2 替换模式应急**。

**未来工作流**(待 build.py 落地):
1. 撤回 toolPlus 派生目录里 vuln/ 的硬拷贝
2. 让所有 vuln/*.md 只存在 source/ 一份,带 marker
3. build.py 一键发两版
4. 维护成本砍半

---

## §9 与其他文档的引用关系

| 主题 | 跳转 |
|---|---|
| 主入口 | [../../SKILL.md](../../SKILL.md) |
| MCP 工具速查 | [../mcp-tools-finder.md](../mcp-tools-finder.md) |
| classic 工具配置 | [../tool-config.md](../tool-config.md) |
| build.py 实现 | [../../scripts/build.py](../../scripts/build.py)(T7)|

---

*toolPlus Overlay Guide v1.0 — 2026-05-24*
