---
name: prototype-pollution
description: CWE: 1321 | ROI: 高 (P1) 轻便原则: 只放原型污染高 ROI 路由: 探测信号 / 污染路径 / 级联升级。具体 gadget 链不堆。
category: vuln
tags: [client]
---

# 原型污染决策卡 (Light Deep Card)

> **CWE**: 1321 | **ROI**: 高 (P1)
> **轻便原则**: 只放原型污染高 ROI 路由: 探测信号 / 污染路径 / 级联升级。具体 gadget 链不堆。

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| JSON key 含 `__proto__` / `constructor` / `prototype` | 原型污染入口 | §1 |
| 深度合并/extend/clondeDeep 函数处理用户输入 | 可能触发污染 | §1.2 |
| 服务端 Node.js / Express / Hapi | 后端污染可能 | §2 |
| 前端有 `Object.assign` / `$.extend` / Lodash `merge` | 前端污染可能 | §3 |
| 响应或后续请求中出现注入的键 | 污染生效 | §4 |

记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。

---

## 1. 探测

### 1.1 First-pass

```json
{"__proto__": {"pp_test": "CVE2024"}}
```

发送后,通过另一个接口或同一接口的其它请求检查:
- 响应中是否出现 `pp_test` 键?
- 新创建的对象是否有 `pp_test` 属性?

### 1.2 深度路径污染 (多层对象)

```json
{"constructor": {"prototype": {"pp_test": "CVE2024"}}}
```

很多 WAF 只拦 `__proto__`,不拦 `constructor.prototype`。

---

## 2. 后端污染 (Node.js)

### 2.1 高 ROI 场景

| 污染目标 | 效果 | 级别 |
|----------|------|------|
| `__proto__.isAdmin` | 角色提升 | Critical |
| `__proto__.role` | 权限绕过 | High |
| `__proto__.shell` | RCE (child_process) | Critical |
| `__proto__.env` | 环境变量注入 | High |
| `__proto__.NODE_OPTIONS` | RCE | Critical |

### 2.2 判断

```
1. 污染 isAdmin: true → 访问管理接口 → 200? → Critical
2. 污染 shell: "/bin/sh" → 触发命令执行 → RCE
3. 污染 NODE_OPTIONS: "--require /proc/self/environ" → RCE
```

---

## 3. 前端污染 (DOM)

### 3.1 高 ROI 场景

| 污染目标 | 效果 |
|----------|------|
| `__proto__.src` | XSS (img/iframe src 被注入) |
| `__proto__.innerHTML` | XSS |
| `__proto__.toString` | 逻辑篡改 |
| `__proto__.isAdmin` | 前端权限绕过 (仅 UI 层) |

### 3.2 判断

- 前端污染导致 XSS → High (需交互)
- 前端权限绕过仅限 UI → Low (后端应有校验)
- 前端污染 + 后端无二次校验 → 可升级

---

## 4. 绕过

| 过滤 | 绕过方法 |
|------|----------|
| `__proto__` 被过滤 | `constructor.prototype` / `__proto__[...]` |
| JSON key 过滤 | URL 编码 key / Unicode 转义 |
| 深度合并限制 | 试用数组索引: `["constructor"]` |
| Lodash `_.merge` 已修 | 检查 Lodash 版本;老版本仍可污染 |

---

## 5. Triage

| 现象 | 可能原因 | 下一步 |
|------|----------|--------|
| 污染键未出现在后续响应 | 污染未生效 / 合并函数安全 | 试 `constructor.prototype`;试不同入口点 |
| 污染键出现但无安全影响 | 污染生效但未触发 gadget | 试 `isAdmin` / `role` / `shell` |
| 只有前端生效 | 后端非 JS / 后端有防护 | 评估前端 XSS 影响 |
| WAF 拦截 JSON 中的 `__proto__` | 严格过滤 | `constructor.prototype` / 编码绕过 |
| Lodash 版本 ≥ 4.17.12 | 已修原型污染 | 检查是否有自定义 merge/extend |

---

## 6. 级联

- 原型污染 → RCE (shell/NODE_OPTIONS) → 命令执行 → [cmdi.md](cmdi.md)
- 原型污染 → 权限提升 → [../auth-logic.md](../auth-logic.md)
- 原型污染 → XSS → [xss.md](xss.md) + [xss-scenarios.md](xss-scenarios.md)
- 原型污染 → 环境变量泄露 → [../sensitive-info-exploitation.md](../sensitive-info-exploitation.md)

---

## 7. Attack Surface

| 入口 | 备注 |
| :--- | :--- |
| **POST JSON 接口** | 最常见,后端 / 前端 merge 处理 |
| **GraphQL 输入对象** | 嵌套 JSON 入口 |
| **URL query 解析** (jQuery `$.parseQuery`) | 老前端 SPA |
| **`Object.assign` / `_.merge` / `$.extend`** | 调用点 |
| **YAML / TOML 配置接口** | 配置导入 |
| **`JSON.parse` 后 merge** | 通用 sink |
| **Cookie / Header 解析** | URL-encoded object syntax |
| **multipart/form-data 解析** | bracket notation `a[__proto__]=...` |
| **Express body-parser** | qs library 历史漏洞 |
| **Hapi / Fastify** | 各自的 schema 解析 |

---

## 8. High-Value Targets

1. **Node.js API + 用户输入 → merge** — 最高 ROI (P0)
2. **Express + 老 body-parser** — qs 历史污染 (P0)
3. **客户端 SPA (Vue / React) + jQuery** — 前端 DOM XSS (P1)
4. **配置接口管理后台** — 改 isAdmin (P0)
5. **GraphQL 变量解析** — 嵌套对象多 (P0)
6. **第三方 SDK 配置** — 用户传配置对象 (P1)

---

## 9. False Positives

| 误报 | 真实判断 |
| :--- | :--- |
| 污染 key 出现在响应 | 可能只是 echo,非真污染 | 测另一个新 Object 是否含该 key |
| 污染但后端无 gadget | 触发但无影响 | 报"原型污染存在,影响受限" |
| Lodash 检测命中但版本已修 | 误报 | 看真实版本 |
| 前端污染但后端二次校验 | 仅 UI 层 | 低危,不是 BFLA |

---

## 10. Impact / 升级路径

| 链 | 终态 | Impact |
| :--- | :--- | :--- |
| `__proto__.isAdmin=true` → admin endpoint | 提权 | Critical |
| `__proto__.shell` → child_process | RCE | Critical |
| `__proto__.NODE_OPTIONS` → require malicious | RCE | Critical |
| 前端 `__proto__.src` → XSS | XSS + 升级 | High |
| `__proto__.toString` → 逻辑篡改 | DoS / 业务破坏 | Medium-High |
| 污染但后端无 gadget 利用 | 信息收集 | Medium |

**证据 (P3.5)**:
- isAdmin 提权后只调 1 个 read-only admin API
- RCE 验证用 OOB callback,不写 webshell

---

## 11. Pro Tips

- **`constructor.prototype` 比 `__proto__` 绕过率高**: 大多数 WAF 只拦 `__proto__`
- **数组索引语法**: `a[constructor][prototype][isAdmin]=1` URL 形式
- **嵌套深度多试几层**: `a[__proto__][__proto__]` 看 merge 函数是否递归
- **Node 应用启动 NODE_OPTIONS**: 一旦污染 `NODE_OPTIONS=--require ...` → 下次启动 RCE
- **Lodash 历史链**: `_.merge` / `_.set` 在 4.17.12 前可污染
- **express qs**: `?a[__proto__][b]=c` 一行代码触发
- **JSON.stringify 检测**: 污染后 `JSON.stringify({})` 输出包含 `pp_test` 即生效
- **前端污染检测**: `Object.prototype.pp_test === "X"` console 中验证
- **隐藏 sink**: ejs / handlebars 等模板引擎在某些版本下原型污染可 RCE
- **响应缓存导致难测**: 同一接口多次测,中间 reset 服务可能不现实 → 报告"长效污染"

---

## 12. 工具升级线

**classic 版**:
- 自动化: `ppmap` / `ppfuzz` / Burp Active Scan
- 静态: `eslint-plugin-security` 找 merge 使用点

**toolPlus 版**:
- `mcp__yaklang__http_fuzzer` 一次 sweep `__proto__` + `constructor.prototype` 各位置
- `mcp__yaklang__ssa_compile language="js"` + SyntaxFlow 找 merge / Object.assign sink

---

## 13. 相关参考

- XSS → [xss.md](xss.md)
- 命令注入 → [cmdi.md](cmdi.md)
- 认证逻辑 → [../auth-logic.md](../auth-logic.md)
- API 安全 (批量赋值) → [../api-security.md](../api-security.md)
