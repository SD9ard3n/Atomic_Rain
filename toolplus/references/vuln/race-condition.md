---
name: race-condition
description: CWE: 362 / 366 | ROI: 高 (P1-P2) 轻便原则: 只放竞态高 ROI 路由: TOCTOU 信号 / 并发方法 / 判断指纹。具体业务场景 payload 不堆。
category: vuln
tags: [logic]
---

# 竞态漏洞决策卡 (Light Deep Card)

> **CWE**: 362 / 366 | **ROI**: 高 (P1-P2)
> **轻便原则**: 只放竞态高 ROI 路由: TOCTOU 信号 / 并发方法 / 判断指纹。具体业务场景 payload 不堆。

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| 支付/充值/提现流程 | 金额竞态可能 | §1 |
| 激活码/优惠券/积分领取 | 一次性资源竞态 | §2 |
| 密码重置/邮箱修改 | 状态检查竞态 | §3 |
| 转账/提现 | 双花竞态 | §4 |
| 投票/点赞/签到 | 幂等性缺失 | §5 |

记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。

---

## 1. 支付竞态

### 1.1 First-pass

```
1. 正常支付流程抓包, 找到最终扣款请求
2. 同时发送 10+ 个相同的扣款请求
3. 检查: 是否只扣了 1 次钱但到账多次?
```

### 1.2 判断

| 结果 | 判断 |
|------|------|
| 只到账 1 次 | 无竞态,或后端有锁 |
| 到账 2+ 次 | Critical: 双花漏洞 |
| 报错 "重复请求" | 有幂等检查,转其它入口 |

---

## 2. 一次性资源竞态

### 2.1 激活码 / 优惠券

```
1. 获取一个激活码 (如 ABC123)
2. 并发 20 个请求使用同一激活码
3. 检查: 是否被使用了 2+ 次?
```

### 2.2 判断

- 激活码被多次使用 → Critical
- 只能使用 1 次 → 正常,转其它测试

---

## 3. 状态检查竞态

### 3.1 密码重置

```
1. 触发密码重置 → 获得 Token A
2. 用 Token A 重置密码 → 成功
3. 快速用同一 Token A 再次重置 → 是否还能成功?
```

### 3.2 邮箱修改

```
1. 修改邮箱请求: old=a@x.com, new=b@x.com
2. 并发发送: 一半用 old=a, 一半用 old=b
3. 检查: 是否两个都成功了? 是否导致账号状态不一致?
```

---

## 4. 转账双花

```
1. 余额 100, 转账 100 给自己另一个账号
2. 并发 10+ 个转账请求
3. 检查: 总到账是否 > 100?
```

**注意**: 真实转账前 HITL 确认。

---

## 5. 幂等性缺失 (投票/签到)

```
1. 签到请求抓包
2. 并发 50 个签到请求
3. 检查: 积分是否增加了 50 次?
```

---

## 6. 并发方法

| 方法 | 适用 | 命令 |
|------|------|------|
| Burp Intruder | 简单并发 | Payload=1, 线程=20 |
| Python 脚本 | 精确时序 | `threads.ThreadPoolExecutor(max_workers=20)` |
| 单请求多参数 | 部分场景 | 同一请求里参数重复 |

**时序关键**: 竞态窗口极小 (通常 <50ms), 必须真正并发而非顺序发送。

---

## 7. Triage

| 现象 | 可能原因 | 下一步 |
|------|----------|--------|
| 并发请求全部成功 | 无锁/无幂等 | Critical,记录并扩大测试 |
| 部分成功部分 500 | 有部分保护 | 调整并发量,找临界点 |
| 全部返回 "已处理" | 后端有幂等键 | 试修改请求参数绕过幂等键 |
| 只有 1 个成功 | 后端有分布式锁 | 转其它入口;试不同参数组合 |
| 响应时间差异巨大 | 异步处理 | 看异步队列是否有竞态 |

---

## 8. 级联

- 支付竞态 → 双花 → [../auth-logic.md](../auth-logic.md) 支付漏洞
- 激活码竞态 → 批量刷 → [../api-security.md](../api-security.md) 速率限制
- 状态竞态 → 账号接管 → [../auth-logic.md](../auth-logic.md)
- 并发 + IDOR → [../chained-logic-extended.md](../chained-logic-extended.md)

---

## 9. Attack Surface

| 入口 | 备注 |
| :--- | :--- |
| **支付 / 退款 / 退货** | 核心 |
| **转账 / 提现 / 充值** | 双花经典 |
| **优惠券 / 红包 / 抽奖** | 一次性资源 |
| **签到 / 任务 / 积分** | 幂等性测试 |
| **激活码 / 兑换码** | 一次性 |
| **密码重置 / 邮箱修改** | 状态机竞态 |
| **关注 / 投票 / 点赞** | 计数器竞态 |
| **库存扣减** | 超卖 |
| **OAuth code 使用** | 一次性,但有竞态窗口 |
| **API key 创建限制** | 配额内连续创建 |
| **限流绕过** | 突破速率限制 |

---

## 10. High-Value Targets

1. **支付完成回调** — 双花 (P0)
2. **优惠券领取** — 限量资源 (P0)
3. **激活码 / 兑换码** — 一次性资源 (P0)
4. **提现 / 转账** — 直接经济损失 (P0)
5. **签到积分** — 业务损失大 (P1)
6. **密码重置 token** — Token 复用 (P0)
7. **库存扣减** — 超卖 (P0)
8. **多账号同步操作** — 限购绕过 (P1)

---

## 11. False Positives

| 误报 | 真实判断 |
| :--- | :--- |
| 并发请求都成功但只生效 1 次 | 后端有锁 | 不是竞态 |
| 部分成功部分 500 | 部分锁 | 测临界点 |
| 表面成功但实际只 1 次 | 数据库唯一约束 | 看最终 DB 状态 |
| 时间窗内有竞态但实际无业务影响 | 业务幂等键覆盖 | 不算有效漏洞 |
| 测试环境复现但生产无 | 环境差异 (有缓存/锁) | 不报告 |

---

## 12. Impact / 升级路径

| 链 | 终态 | Impact |
| :--- | :--- | :--- |
| 支付双花 | 直接经济损失 | Critical |
| 优惠券多次领取 | 业务损失 | High |
| 激活码批量使用 | 业务损失 | High |
| 密码重置 token 复用 | 账号接管 | Critical |
| 转账双花 | 资金损失 | Critical |
| 签到积分多倍 | 业务损失 | Medium-High |
| OAuth code 复用 | 长期会话 | High |
| 限购绕过 (秒杀场景) | 业务损失 | High |

**证据 (P3.5)**:
- 转账 / 充值 / 退款类**必须 HITL** — 真实金额测试需用户授权
- 优惠券 / 积分类测试用最小金额,完成后 HITL 让用户协助回滚

---

## 13. Pro Tips

- **真正并发是关键**: HTTP/1.1 keep-alive 多请求 + Last-Byte Sync (Burp Turbo Intruder)
- **HTTP/2 单连接多 stream**: 比 HTTP/1.1 时序更准
- **TLS Session Tickets 复用**: 多次 TLS 握手会破坏并发 → keep-alive 必开
- **请求最早一致到达**: 用 `Last-Byte Sync` (Turbo Intruder) 让所有请求 last byte 同时到
- **服务端是否有 nonce/token**: 有些操作每次拿新 token → 并发拿不同 token 也能竞态
- **Burp Turbo Intruder 模板**: 网上有 race condition 专门模板
- **Python aiohttp**: 异步 IO 比 thread pool 更稳
- **测时间窗**: 二分法找窗口大小,大窗口 → 易竞态 / 小窗口 → 难
- **国内电商**: 双 11 类秒杀 = 竞态测试黄金场景 (合法授权下)
- **OAuth code 时间窗**: 5-10 秒理论 single-use,但实际窗内可多次换 token
- **数据库事务隔离级别**: READ COMMITTED 易竞态,REPEATABLE READ 难

---

## 14. 工具升级线

**classic 版**:
- 自动化: Burp `Turbo Intruder` (race-single-packet-attack 模板)
- 脚本: Python `aiohttp` / `asyncio` / Go `goroutine`

**toolPlus 版**:
- `mcp__yaklang__http_fuzzer` concurrent=50 + 同 last-byte sync
- `mcp__yaklang__http_fuzzer` 测多用户 / 多 token 同时并发

---

## 15. 相关参考

- 认证逻辑 → [../auth-logic.md](../auth-logic.md)
- API 安全 → [../api-security.md](../api-security.md)
- HITL (转账等高影响操作) → [../human-in-the-loop.md](../human-in-the-loop.md)
