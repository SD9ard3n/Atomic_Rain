---
name: quick
description: 时间盒 / 赏金冲量档 — 跳过资产穷尽与业务建模,只走高 ROI 漏洞路径,目标产出 1-3 个 P0/P1
category: scan_modes
tags: [scan-mode, time-boxed, bounty]
---

# Quick Scan Mode

> **哲学**: 像时间盒下的赏金猎人 — 宽度优先,深度按需。一击不中立刻换 ROI 路径,绝不在低产出方向纠缠。
> **触发场景**: bug bounty 时间盒 / 客户给 4 小时打一个站 / SRC 排行榜冲量 / 快速预扫确认是否值得深做。
> **预期产出**: 1-3 个可验证的 P0/P1 漏洞 + 最小 PoC。**不追求完整覆盖**。

---

## 1. P 协议执行映射

| P 协议 | 处理 | 备注 |
| :--- | :---: | :--- |
| **P0.4 toolPlus 启动确认** | 必跑 *(仅 toolPlus 版)* | `get_current_database_context` 验环境 |
| **P0.5 启动握手** | 必跑 | 必须明确告知用户当前为 quick 档 |
| **P1 信号预检** | 简化 | 跳过 OAST,只用本地 First-pass payload |
| **P1.5 业务建模 12 问** | **跳过** | quick 档不做业务建模;只识别 auth 边界 + 关键 CRUD |
| **P2 知识脱水** | Decision Card only | 仅 `grep "### [Decision Card]"`,不读 vuln/*.md 全文 |
| **P2.5 敏感度评判** | 必跑 | 任何档位都必跑(决定是否报告) |
| **P2.6 直觉触发表** | 简化 | 命中现象关键词时单次查 intuition-triggers.md;不做完整级联 |
| **P3 级联挖掘** | **单跳** | 发现漏洞 → 只测一次直接级联(如 IDOR → BOLA sweep),不做多跳级联 |
| **P3.5 外部资源 HITL** | 必跑 | OPSEC 红线,任何档位不豁免 |

---

## 2. Phase 路由

| Phase | 处理 |
| :--- | :--- |
| **Phase 1 信息收集** | **大幅简化**。**跳过**:exhaustive 子域爆破 / 全端口扫描 / 目录爆破 / 完整指纹。**只做**:主域+主要子域(`subfinder` 1 次)+ 主入口指纹 + UI 快速点击映射核心功能。耗时上限 **30 分钟**。 |
| **Phase 1.5 业务建模** | **跳过** |
| **Phase 2 漏洞挖掘** | **走 ROI 优先级路径**(见 §3),命中信号 → 立即 P2/P2.5 判断 → 升级利用或换路径 |
| **Phase 3 利用与级联** | **单跳级联**,确认 impact 后立刻收手写报告;**不做**完整业务链路追踪 |
| **Phase 4 报告** | 简化模板:1 段背景 + PoC 步骤 + impact 证据 + 修复建议。耗时上限 **20 分钟**。 |

---

## 3. 漏洞 ROI 优先级路径

按顺序测,命中信号 → 深做;前一项无果 → 立刻换下一项。

```
1. 认证旁路        — 弱口令 / 默认凭证 / JWT alg none / oauth state 缺失
2. 越权 (IDOR/BOLA) — 注册第二账号 → swap id/uuid → 看 cross-account 数据
3. SQL 注入        — login / search / filter 参数 → sqlmap --batch / time-based 信号
4. SSRF            — 任意 URL/webhook/avatar 入口 → cloud metadata / 内网探测
5. 泄露的凭证      — .git / .env / robots / sitemap / JS bundle / source map / __NEXT_DATA__
6. RCE             — 已知组件版本对照 CVE / 反序列化魔术字节(rememberMe / fastjson)
```

**明确跳过**(quick 档不测):
- 业务逻辑漏洞(需要业务建模,代价高)
- 完整级联深挖
- 时序竞争 / TOCTOU(需要 HTTP/2 同步,工具准备成本高)
- 完整级别的 CSRF 链路验证(simple-form / token bypass 可测,深链 token bind 跳过)
- 完整级别的 XSS 上下文枚举(只测明显反射,DOM-based 复杂场景跳过)

---

## 4. 推理强度配置

- **默认**: medium(对位 Strix 的 `reasoning_effort=medium`)
- **触发 ultrathink**: 仅当连续 3 次 ROI 路径无果,启用一次深度思考决定是否升档到 standard

---

## 5. 多 agent 配置

**单 agent 默认**。除非:
- 目标包含多个明显独立子系统(如 web + API + 移动端) → 可 spawn 1 个并行 agent 专做 API
- 否则**禁止过度 spawn**,quick 档要的是单线快推

---

## 6. 终止条件 (Stop Conditions)

满足**任一**即可终止:

1. **时间到** — 用户指定的时间盒到期(默认 4 小时)
2. **产出达标** — 已确认 1-3 个 P0/P1,且 PoC 复现成功
3. **ROI 耗尽** — §3 所有 6 项 ROI 路径都走完无果,且无明显升档线索

---

## 7. 与其他档位的边界

**升档到 standard 的触发条件**(发现以下任一,建议征询用户后升档):

- 目标资产规模 > 10 个有效子域 / 多业务子系统
- 发现 1 个 P0 漏洞且明显存在级联深挖空间(如 SSRF 已能打到内网 metadata)
- 用户明确说"打深一点" / 不再受时间盒约束

**降档到... 不存在**。quick 已是最低档。如果用户预算更紧(< 1 小时),直接按本档执行,只跑 §3 前 3 项 ROI。

---

## 8. Quick 档典型工作流(示例)

```
T+0:00 启动 → P0.5 握手 + 告知用户走 quick 档
T+0:05 Phase 1 简化:subfinder + 主入口指纹 + UI 5 分钟点击
T+0:30 Phase 2 ROI #1 认证旁路 → 无果
T+0:50 Phase 2 ROI #2 IDOR → 命中(注册账号 A/B,/api/orders/{id} 横向)
T+1:30 Phase 3 单跳级联:BOLA sweep 同类 endpoint(列订单/账单/导出),收集证据
T+2:00 Phase 4 报告:1 个 P0(BOLA 跨账号订单查看 + 修改)
T+2:20 收工
```

---

## 9. 反模式(quick 档**禁止**做的事)

- ❌ 跑业务建模 12 问 — 时间不够,且 quick 档不要这种纵深
- ❌ 多 agent spawn 4+ 个并行 — quick 不是覆盖战术
- ❌ 读 vuln/*.md 全文 — 只用 Decision Card 段
- ❌ 完整子域爆破 + 目录爆破 — 时间黑洞
- ❌ 在低 ROI 路径(如 CSRF 完整链验证)纠缠超过 20 分钟
- ❌ 不汇报中间产出 — quick 档应该**每发现一个信号都立即向用户简报**
