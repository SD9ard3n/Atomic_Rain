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

## 7. 相关参考

- XSS → [xss.md](xss.md)
- 命令注入 → [cmdi.md](cmdi.md)
- 认证逻辑 → [../auth-logic.md](../auth-logic.md)
- API 安全 (批量赋值) → [../api-security.md](../api-security.md)
