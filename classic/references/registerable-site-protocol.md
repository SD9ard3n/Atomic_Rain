---
name: registerable-site-protocol
description: 触发条件: 站点支持自助注册 (SaaS / 社区 / 论坛 / 协作平台 / 教育平台) 核心思想: 注册成本是 0,两账号交叉是 BOLA/IDOR/水平越权的最快路径,优先打这条线 与通用 Phase 2 的区别: 通用排序是"按赏金价值",可注册站是"按账号成本最低 →…
category: methodology
---

# 可注册站专用协议 (Registerable-Site Protocol)

← 主入口 [../SKILL.md](../SKILL.md)

> **触发条件**: 站点支持自助注册 (SaaS / 社区 / 论坛 / 协作平台 / 教育平台)
> **核心思想**: 注册成本是 0,**两账号交叉**是 BOLA/IDOR/水平越权的最快路径,优先打这条线
> **与通用 Phase 2 的区别**: 通用排序是"按赏金价值",可注册站是"按账号成本最低 → 出货最快"

---

## 0. 触发判定

| 信号 | 判断 |
|------|------|
| 首页明显有"注册/Register/Sign Up"入口 | ✓ 可注册 |
| 注册页存在但需邀请码/付费 | ✗ 改走通用流程 |
| 注册需企业邮箱审核 | △ 看能否拿到邮箱;审核太久则降级通用流程 |
| 已经有受控账号但来源未知 | ✓ 当作可注册站继续 |

---

## 1. 注册策略 — 必须两账号

### 1.1 标准账号配置

```
账号 A: <邮箱前缀>+a@<可控邮箱域>     角色: 普通用户
账号 B: <邮箱前缀>+b@<可控邮箱域>     角色: 普通用户 (与 A 同角色)

角色不同时再加:
账号 C: <邮箱前缀>+c@<可控邮箱域>     角色: 管理员/付费/VIP (能拿到则拿)
```

### 1.2 注册时记录

每个账号注册完立即记录到 assets.md:

```markdown
## 受控账号
| 账号 | 邮箱 | uid/username | 注册时间戳 | 初始 Cookie/Token | 角色 |
|------|------|-------------|-----------|------------------|------|
| A | foo+a@x.com | 100001 | 2026-05-06 10:00:00 | <token_a> | user |
| B | foo+b@x.com | 100002 | 2026-05-06 10:01:30 | <token_b> | user |
```

**为什么记时间戳**: 后续测时间戳预测 / 注册顺序相关漏洞。
**为什么记 uid**: BOLA 测试时直接 swap。

---

## 2. 测试顺序 (按出货速度排序)

| 顺序 | 漏洞类型 | 为什么排这里 | Decision Card |
|------|---------|-------------|---------------|
| 1 | **越权 (BOLA / IDOR / 水平/垂直)** | 两账号最快出货,API 响应直接对比 | [api-security.md](api-security.md) §BOLA + [auth-logic.md](auth-logic.md) §5 |
| 2 | **未授权访问** | 删 Token / 替换为 B 的 Token / 空 Token,看 200 | [resource-classification.md](resource-classification.md) |
| 3 | **业务逻辑** (支付/优惠券/积分/邀请奖励/签到) | 自助注册场景下逻辑漏洞集中,且通常无 WAF | [auth-logic.md](auth-logic.md) §6 + [vuln/race-condition.md](vuln/race-condition.md) |
| 4 | **敏感信息泄露** | 用 A 账号读 B 的 PII / 后端把别人邮箱/手机号也返回 | [sensitive-info-exploitation.md](sensitive-info-exploitation.md) |
| 5 | **CORS / postMessage** | 前面发现可读敏感数据后,看能否跨域窃取 | [vuln/cors-cache.md](vuln/cors-cache.md) |
| 6 | **XSS** | 用户内容(资料/帖子/评论)是高频 XSS 入口 | [vuln/xss.md](vuln/xss.md) + [vuln/xss-scenarios.md](vuln/xss-scenarios.md) |
| 7 | **SQLi** | 通常 ORM 防护好,排在后面 | [vuln/sqli.md](vuln/sqli.md) |
| 8 | 其它 (上传/SSRF/cmdi/反序列化等) | 退化为通用 Phase 2 | [phase-guide.md](phase-guide.md) §2.1 |

---

## 3. 越权 (排第 1 的核心) — 标准两账号交叉模板

### 3.1 通用对比

```bash
# 用 A 的 Token 访问 A 自己的资源 → 200 (基准)
curl -H "Authorization: Bearer <token_a>" https://target.com/api/orders/<uid_a>

# 用 A 的 Token 访问 B 的资源 → 期望 403/404, 实际 200 = BOLA
curl -H "Authorization: Bearer <token_a>" https://target.com/api/orders/<uid_b>

# 用空 Token 访问 → 期望 401, 实际 200 = 完全未授权
curl https://target.com/api/orders/<uid_b>
```

### 3.2 BOLA 高发字段 (按命中率排)

```
1. 数字 ID:       /api/orders/12345         → 改成 12346/12340
2. UUID:          /api/files/<uuid>          → 改成另一个 uuid
3. 用户名/邮箱:   /api/profile/foo+a         → 改成 foo+b
4. 隐藏字段:      POST body 中的 user_id     → 替换
5. JWT 内 user_id: 不修改 token, 只改 URL    → 测后端是否仅信任 URL
6. 批量操作:      /api/batch?ids=1,2,3       → 加上 B 的 id
7. 导出/打印:     /api/export?orderId=       → 越权导出
```

### 3.3 BFLA (功能级) 测试

```bash
# 用普通账号 A 调管理员接口
curl -H "Authorization: Bearer <token_a>" -X DELETE https://target.com/api/admin/users/<uid_b>
curl -H "Authorization: Bearer <token_a>" https://target.com/api/admin/stats
curl -H "Authorization: Bearer <token_a>" https://target.com/api/admin/config
```

期望 403, 实际 200 = BFLA。

---

## 4. Triage

| 现象 | 可能原因 | 下一步 |
|------|----------|--------|
| 两账号 uid 差距巨大 (10001 vs 99887) | 注册号哈希/混淆 | 试枚举但接受可能失败 |
| 两账号 uid 差距是 1 (100001 vs 100002) | 顺序自增 | 立即向前/向后枚举,可能直接撞老用户 |
| API 响应里 B 账号的字段是 null | 后端有越权检查但返回 200 | 看响应是否完整,可能假 200 |
| 注册需要邀请码 | 半开放 | 邀请码可被枚举/重用? |
| 邮箱验证后才能登录 | 邮箱质量影响测试 | 用 +别名 / catchall 域名 |
| 一个邮箱只能注册一次 | 防重复 | 用 +alias 或不同域名 |

---

## 5. 跨账号污染检测 (高 ROI)

某些 SaaS 实现租户隔离失败,A 账号的操作影响 B 账号。

```
账号 A 操作: 修改自己的 profile / 上传文件 / 创建项目
账号 B 验证: 看是否在自己面板里看到 A 的数据 / 自己的数据被改

特别注意:
- 全局缓存导致的越权 (修改全局配置时影响别人)
- 默认值越权 (注册时默认值取自最近一个用户)
- 团队/组织邀请漏洞 (强制把别人加入自己组)
```

---

## 6. 与其它协议的关系

| 场景 | 走本协议 vs 走通用 |
|------|---------------------|
| 普通可注册 SaaS | ✓ 本协议 |
| 后端站 (无注册入口) | ✗ → [recon.md](recon.md) §9 后端站协议 |
| 仅登录后台 | ✗ → CAWG 弱口令 [weak-password-generation.md](weak-password-generation.md) |
| 已注册并打完 1-8 步还有时间 | 退到 [phase-guide.md](phase-guide.md) §2.1 通用流程 |

---

## 7. 级联

- 步 1 越权 → 步 4 敏感信息泄露 (越权读到的数据本身就是敏感) → [chained-logic-extended.md](chained-logic-extended.md)
- 步 3 业务逻辑 → 步 1 越权 (邀请奖励里强制加别人到自己组) → 跨账号污染
- 步 6 XSS → 偷管理员 Cookie → 升级为接管 → [chained-logic-extended.md](chained-logic-extended.md)

---

## 8. 必须落账

完成本协议后, vulns.md 至少应有:

```markdown
## [Vuln-XXX] BOLA via /api/orders/<id>
- Type: BOLA
- Severity: High
- [Confirmed]
- Discovery-Origin: (必填) 如 "可注册站流程 §3.1 两账号注册后测试 /api/orders/{uid}"
- Repro-Request: <两账号交叉完整请求包,含 Header/Cookie/Body>
- Chain-Steps:
  - Step 1: <请求包> 注册 A、B 两账号 (uid 100001 / 002)
  - Step 2: <请求包> 用 A 的 Token 请求 /api/orders/100002
  - Step 3: 返回 B 的订单数据 (含收货地址/手机号/金额)
  - 实际影响: 任意用户的订单可被遍历 (枚举 uid 1-100002)
- Evidence Chain:
  - HTTP_CODE: 200 (期望 403)
  - RESP_LENGTH_DELTA: 1024 (B 的真实数据,非空响应)
```

---

**版本**: v1.0 | **创建**: 2026-05-06 | **触发**: SKILL.md §2 "站点支持自助注册"
