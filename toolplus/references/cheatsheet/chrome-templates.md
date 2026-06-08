---
name: chrome-templates
description: 5 个高复用模板:自动登录 / OOB 拉子域 / 漏洞证据 5 连截图 / 加密函数注入 / 滑块前置 HITL
category: cheatsheet
---

# Chrome 自动化模板 (toolPlus)

← [mcp-tools-finder.md](../mcp-tools-finder.md) | 适用工具:`mcp__chrome__*` 全家桶

> 5 个高复用模板:自动登录 / OOB 拉子域 / 漏洞证据 5 连截图 / 加密函数注入 / 滑块前置 HITL

---

## §1 模板 A:自动登录(无滑块)

```
1. mcp__chrome__chrome_navigate {url: "https://target.com/login"}
2. mcp__chrome__chrome_fill_or_select {selector: "input[name=username]", value: "test"}
3. mcp__chrome__chrome_fill_or_select {selector: "input[name=password]", value: "test123"}
4. mcp__chrome__chrome_click_element {selector: "button[type=submit]", waitForNavigation: true}
5. mcp__chrome__chrome_get_web_content {selector: ".user-name"}
   → 验证登录成功(看到用户名)
6. mcp__chrome__chrome_network_request {url: "/api/me"}
   → 拿登录后的 token / cookie
```

**适用**:目标站点没有滑块 / 图形验证码。有的话 → 模板 E。

---

## §2 模板 B:自动 OOB 子域获取(dnslog.cn)

```
1. mcp__chrome__chrome_navigate {url: "http://dnslog.cn/"}
2. mcp__chrome__chrome_click_element {selector: "#getDomain"}
3. mcp__chrome__chrome_get_web_content {selector: "#myDomain"}
   → 提取子域字符串(如 xxxx.dnslog.cn)
4. 把子域写入 assets.md
5. 后续 SSRF/XXE payload 用此子域(配 http_fuzzer 发包)
6. mcp__chrome__chrome_click_element {selector: "#refresh"}
   → 看 DNS 记录是否出现
```

**⚠️ HITL 必须前置**(见 [SKILL.md §1 P3.5](../../SKILL.md)):
- 用 dnslog.cn 这种**公共服务**有 OPSEC 风险(请求日志可能被第三方看见)
- 默认应优先用用户自建 interactsh / Burp Collaborator
- 用户拍板用公共才走本模板

---

## §3 模板 C:漏洞证据 5 连截图

详见 [evidence-pipeline.md §5](../evidence-pipeline.md)。

```
1. http_fuzzer → 拿到漏洞触发的 URL
2. mcp__chrome__chrome_navigate {url: "<URL>"}
3. mcp__chrome__chrome_screenshot {fullPage: true, name: "1-trigger"}
4. mcp__chrome__chrome_console
   → 拿 console 输出 / 异常
5. mcp__chrome__chrome_inject_script
   → 注入证明性 JS(如 `alert(document.cookie)`)
6. mcp__chrome__chrome_screenshot {name: "2-poc"}
7. 写入 vulns.md "影响证明" 段
```

---

## §4 模板 D:加密函数调用(对抗前端加密)

```
1. mcp__chrome__chrome_navigate {url: "<目标页面>"}
2. mcp__chrome__chrome_inject_script {
     type: "ISOLATED",
     jsScript: "
       window.__result = aesEncrypt('plain');
       document.title = window.__result;
     "
   }
3. mcp__chrome__chrome_get_web_content {selector: "title"}
   → 拿到加密结果
4. 加密结果填入 http_fuzzer 的 request → 发包
```

**适用**:页面已加载加密函数(常见于小程序 H5 模式 / web-view 部分),通过浏览器调用比反编译重写省事。

**安全约束**:
- `type: "ISOLATED"` 不污染页面变量(用 `MAIN` 会改用户浏览器状态,**禁止默认用**)
- 注入前告知用户即将注入什么脚本

---

## §5 模板 E:滑块前置(让用户过滑块后继续)

```
1. mcp__chrome__chrome_navigate {url: "<带滑块的页面>"}
2. HITL: "请在浏览器手动过滑块,完成后回我 'done'"
3. 用户回 "done" → mcp__chrome__chrome_network_request {url: "/api/me"}
   → 拿过滑块后的 token
4. 后续用此 token 通过 http_fuzzer 测试
```

**适用**:目标有滑块 / 行为验证码 / 极验 / 阿里云盾等强反爬,**不要硬撑自动化**(对抗成本远超漏洞挖掘价值)。

---

## §6 chrome 工具速查

| 工具 | 用途 |
|---|---|
| `chrome_navigate` | 导航到 URL |
| `chrome_screenshot` | 截图(支持 fullPage / selector) |
| `chrome_console` | 抓 console + 异常 |
| `chrome_inject_script` | 注入 JS(必须 type: "ISOLATED") |
| `chrome_get_web_content` | 抓页面 HTML / selector 内容 |
| `chrome_get_interactive_elements` | 找可点击元素 |
| `chrome_fill_or_select` | 填表单 / 下拉选 |
| `chrome_click_element` | 点击 |
| `chrome_keyboard` | 模拟键盘输入 |
| `chrome_network_request` | 用浏览器登录态发请求(替代 curl 复制 cookie) |
| `chrome_network_debugger_start/stop` | DevTools 级抓包(含 responseBody) |
| `chrome_network_capture_start/stop` | webRequest API 抓包(无 body) |
| `get_windows_and_tabs` | 列出窗口 / tab |
| `chrome_close_tabs` | 关 tab |
| `chrome_go_back_or_forward` | 浏览器前进后退 |

---

## §7 常见错误

| 错误 | 处理 |
|---|---|
| `chrome_click_element` 找不到元素 | 先 `chrome_get_interactive_elements` 看可用 selector |
| 截图保存位置不知道 | `chrome_screenshot {savePng: true}` 默认存 Chrome 用户下载目录;想自定义路径 → `storeBase64: true` 自己写文件 |
| `chrome_inject_script` 不生效 | type 写错(应是 "ISOLATED"),或 CSP 阻断 |
| `chrome_navigate` 卡死 | 目标页有重定向死循环,加 `timeout` 参数 |
| `chrome_network_request` 401 | 当前 chrome 没登录,先跑模板 A 自动登录 |

---

*Chrome templates cheatsheet v1.0 — 2026-05-24*
