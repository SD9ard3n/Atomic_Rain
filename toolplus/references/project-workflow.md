---
name: project-workflow
description: 目的: 解决 Agent 的"认知断层"。通过最小标签集确保 Phase 1 的线索在 Phase 2 被强制级联利用。 核心原则: 必填标签精简到 3 个 ([Linkable] / [Confirmed] / [ChainedFrom]); 其余降级为可选, 防止 LLM…
category: methodology
---

# 项目状态账本协议 (The Ledger Protocol) — v1.0 精简版

> **目的**: 解决 Agent 的"认知断层"。通过最小标签集确保 Phase 1 的线索在 Phase 2 被强制级联利用。
> **核心原则**: 必填标签精简到 3 个 (`[Linkable]` / `[Confirmed]` / `[Chained_From]`); 其余降级为可选, 防止 LLM 在无监督场景下偷工。

---

## 1. 目标账本结构 (Ledger Structure)

Agent 必须创建并维护以下三个核心账本。禁止使用临时内存, 必须落盘以防会话中断。

### 1.1 资产账本 (assets.md) — 最小模板

```markdown
# 资产清单 - <target>

## 攻击面 (按优先级)
| 优先级 | URL / 端点 | 类型 | 必填标签 | 备注 |
|--------|-----------|------|---------|------|
| P0 | https://target.com/admin | 后台 | [Linkable] | 未保护? |
| P0 | https://target.com/api/v1/* | API  |          | BOLA? |

## 线索 (Linkable)
- [Linkable] 发现 .git/config 泄露, 提取仓库地址 ...
- [Linkable] JS 中硬编码 api_key=AKIA... → 待 §敏感信息三阶段验证

## OOB 通道
- 类型 / 子域 / 启动时间 / 记录位置
```

### 1.2 漏洞账本 (vulns.md) — 最小模板

```markdown
# 漏洞列表 - <target>

## [Vuln-001] (一句话标题)
- Type: SQLi / XSS / SSRF / ...
- Severity: Critical / High / Medium / Low / [待验证-High] / [待验证-Critical]
- 必填标签: [Confirmed] (已双信号确认) / [Chained_From: Vuln-XXX] (如有级联)
- Repro-Command:
  ```
  curl -X POST ...
  ```
- Exploitation-Chain:          # 推荐填写,Phase 4 报告时必须有
  - 步骤 1: ...
  - 步骤 2: ...
  - 实际影响: <读到/改到/接管了什么>
- Evidence Chain:
  - 异常信号: 500 + RESP_LENGTH_DELTA=1234 + TIMING=5.2s
  - 证据: <截图/响应片段>
- 修复建议: (三段式见 report-template.md)
```

### 1.3 严重度自检 (Severity Self-Check) — 建议非强制

> **目的**: 给"讨好型人格"一个软刹车,但不卡断挖洞流动性。
> **核心**: 真实挖洞是流动状态,中间记录有合法位置 (`[待验证-Critical/High]`),不强求当下完成态。

**报漏洞或调整等级前,自己反问 3 个问题**:

1. **真复现过吗?** Repro-Command 能否从空环境跑出同样结果?
   - 能 → 维持等级
   - 不能 → 考虑标 `[待验证-Critical/High]`,与 `[Confirmed]` 区分开

2. **真实影响是什么?** 能用一句话说清"读到/改到/接管了什么"?
   - 能 → 写进 Exploitation-Chain,维持等级
   - 不能 → 考虑暂降一级,或保留 `[待验证]` 状态

3. **凭证/敏感类是否走过验证?**
   - 走过 [sensitive-info-exploitation.md](sensitive-info-exploitation.md) 阶段 2 验证 → 维持
   - 没走过 → 暂标 `[待验证]`,不直接 ≥High

**Phase 4 报告收尾时**:
- 仍是 `[待验证-High/Critical]` 且补不上 Exploitation-Chain → 降为 Medium (收尾清理,不是过程中卡断)
- 验证发现失效 (AK expired / JWT 401 / SSRF 不可达) → 降到 Low 或不报,在 assets.md 加 `[Intel_Expired]` 一行避免重复误报

**保留过程中的灰色地带**:
- 看到 AK 但还没空验证 → `[待验证-Critical]` + 继续推进,验证后再确定
- 疑似 BOLA 但还没注册第二账号 → `[待验证-High]` + 继续推进
- 一个 SSRF 入口不可达 ≠ 全部不可达 → 暂留 Medium 等其它入口验证

不要为了凑字段编 Exploitation-Chain,空着就空着、加 `[待验证]` 标签即可。

---

## 2. 三个必填标签 (Required Labels)

只有这三个是 **强制必填**:

| 标签 | 用途 | 必填位置 | 写入时机 |
|------|------|---------|---------|
| `[Linkable]` | 标记可被后续阶段消费的线索 (AK / 路径 / 用户名 / 内网IP) | assets.md | Phase 1 任何发现敏感信息时 |
| `[Confirmed]` | 标记漏洞已经过双信号验证 | vulns.md | Phase 2 漏洞通过 P2→P3 准入检查时 |
| `[Chained_From: <id>]` | 标记当前漏洞从哪个发现级联而来 | vulns.md | 触发 chained-logic 任一策略时 |

**禁止**: 跳过这三个标签直接报漏洞。
**允许**: 其它细粒度标签 (`[BOLA_Likely]` / `[Fastjson_Likely]` / `[WAF_Strict]` / `[Auth_Bypass_Kit]` / `[Intuition_Applied]` / `[Intel_Passive]` / `[CAWG_Round2]` / `[WeakPassword_Progress]` / `[Intel_Expired]` / `[Intel_NotSensitive]`) 按需使用, 不强求全打。

---

## 3. 状态转移协议 (State Transition)

Agent 在各 Phase 切换时必须执行以下自检。

### P1 → P2 准入检查
- **检查项**: 是否已完成 `assets.md` 的攻击面打分 + 至少一个 `[Linkable]` 标签 (若无敏感信息则可空)?
- **强制动作**: 如果存在 `[Linkable]` 标签, Phase 2 的第一步 **必须** 是尝试将该信息带入新发现的端点。

### P2 → P3 利用协议
- **检查项**: 漏洞是否满足"双信号确认"? (至少 2 种独立信号: HTTP_CODE + RESP_LENGTH / TIMING + OOB)
- **强制动作**: 满足 → 标 `[Confirmed]` + 在 `vulns.md` 下方生成对应的 `Repro-Command`。

---

## 4. 级联挖掘算法 (Chain-of-Thought Chaining)

当发现以下任意信号时, 动作转移如下:

1. **发现 .map / JS 注释中的路径** →
   - 动作: 写入 `assets.md` 标记 `[Linkable]` →
   - 决策: 在挖掘其他接口时, 强制使用该路径作为 SSRF 或 LFI 的探针。

2. **发现硬编码 Key** →
   - 动作: 写入 `[Linkable]` (可选附 `[Auth_Bypass_Kit]`) →
   - 决策: 检查所有 Shiro、JWT、Fastjson 接口, 优先使用该 Key 构造 Payload。

---

## 5. 进度恢复协议

恢复会话后, Agent **严禁** 直接 `Read` 全文。
- **动作 1**: `Grep` `assets.md` 里的 `[ ]` 未勾选项。
- **动作 2**: `Grep -n "[Confirmed]" vulns.md` 看已确认漏洞数。
- **动作 3**: `tail -n 20 vulns.md` 查看最后一条漏洞的复现状态。

---

## 6. 级联触发协议 (Auto-Chaining)

### 触发时机

每次在 vulns.md 中记录漏洞时,**必须**执行级联检查:

1. Grep `chained-logic-extended.md` 匹配当前漏洞类型
2. 检查是否有可级联的策略
3. 如果有,**立即**执行级联动作
4. 记录级联结果到 vulns.md 的 `[Chained_From: <id>]` 字段

### 级联示例

**发现 XSS** → 触发策略 #4 (XSS-至-CSRF):
```markdown
### [Vuln-001] Reflected XSS in /search
- Type: XSS
- Severity: Medium
- [Confirmed]
- [Chained_From]: 无 (起源)

**级联检查**:
- 触发策略 #4 → 检查 CSRF Token → 发现无 Token
- 结果: 升级为 XSS+CSRF (High)
- Severity 更新: Medium → High
```

**发现 JWT** → 触发策略 #6 (JWT-至-BOLA):
```markdown
### [Vuln-002] JWT in Authorization Header
- Type: Info → 升级为 BOLA
- [Confirmed]
- [Chained_From]: Vuln-002 (本身)

**级联**:
- 解析 JWT → 提取 user_id → 测试 /api/orders/{id} → BOLA
- 创建新漏洞 [Vuln-003] BOLA via JWT, 标 [Chained_From: Vuln-002]
```

### 级联优先级

- **P0** (立即执行): 文件上传→遍历 / SSRF→Redis RCE / PP→RCE
- **P1** (优先执行): XSS→CSRF / JWT→BOLA / CORS→数据窃取
- **P2** (后续执行): 信息泄露→爆破 / GraphQL→BOLA / 时间盲注→回显

---

## 7. v1.0 关键设计

- **必填标签精简**: 3 个 (`[Linkable]` / `[Confirmed]` / `[Chained_From]`), 防止 Agent 在无人监督时偷工
- **细粒度标签**: 全部降级为可选, 但仍可使用 (向后兼容)
- **assets.md / vulns.md 给最简模板**, < 30 行示例
- **资源索引集中到 grep-recipes.md** (单一 Grep 命令源)
- **Severity Self-Check** 建议非强制, `[待验证-Critical/High]` 中间标签合法化挖洞流动状态
