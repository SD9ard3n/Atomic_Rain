---
name: multi-agent-orchestration
description: 多 agent 协同 SOP — 使用 Claude Code Agent/Team/SendMessage 工具进行多 agent 渗透测试。各 scan_mode 推荐编队 / 通信模式 / 终止协议 / HITL 协调。
category: methodology
tags: [methodology, multi-agent, orchestration, team, scan-mode, agent]
---

# 多 Agent 协同 SOP

> **本文件用途**: 在 `scan_mode=standard` 或 `deep` 时,何时派多 agent / 派几个 / 各自负责什么 / 如何通信 / 如何收尾。
> **关键认知**: Multi-agent **不是默认开**, 单 agent 已经够强;只在 scope 真正大 / 时间不够 / 需要并行验证时启用。
> **不重复**: 单 agent 内部协议见 [SKILL.md](../SKILL.md), 各 scan_mode 内的 agent 分工见 `scan_modes/*.md §5`。

---

## 1. 何时启用多 agent

### 1.1 启用条件 (任一满足)

| 条件 | 示例 |
| :--- | :--- |
| 资产树 > 30 个子域 | 大型企业站 / SRC 大目标 |
| 业务子系统 ≥ 3 | SaaS 多租户 / 集团多 BU |
| 时间盒 ≥ 3 天 + 需穷尽 | 红队评估 / 深度合规 |
| 多角色业务 (≥ 3 个 role) | 商家/买家/平台/审核 |
| 跨技术栈 | Web + APP + 小程序 + 公众号 |
| 必须并行验证 | 竞态条件 / 时序攻击 |

### 1.2 禁用条件 (任一触发)

| 条件 | 原因 |
| :--- | :--- |
| 用户档位是 `quick` | quick 档不需要;协调开销 > 收益 |
| 目标资产 < 10 endpoint | 单 agent 足够 |
| 业务模型简单静态站 | 没有可拆分维度 |
| 用户明确说"不要多 agent" | 尊重 ROEs |
| Phase 1 还没出资产树 | 启用前置:必须先有侦察结果可拆 |

### 1.3 决策树

```
开始 → 启用多 agent?
  ├─ scan_mode == quick? → ❌ 单 agent
  ├─ Phase 1 完成?      → ❌ 等 Phase 1 完
  ├─ 资产 < 10?         → ❌ 单 agent  
  ├─ 业务简单?           → ❌ 单 agent
  └─ 上述都否           → ✅ 进 §2 编队设计
```

---

## 2. 推荐编队 (按 scan_mode)

### 2.1 standard 档 — 1-3 agent 编队

| Agent | 角色 | 主要文件 / 协议 |
| :--- | :--- | :--- |
| **agent 1 (Lead)** | 业务建模 + Phase 2 漏洞主线 + 报告 | `business-flow-checklist.md` + `vuln/` + `report-template.md` |
| **agent 2 (Recon, 可选)** | 资产测绘 + 子域 / takeover / JS 爬 | `recon.md` + `assets.md` 维护 |
| **agent 3 (Evidence, toolPlus 独家)** | 证据自动化 + 截图归档 | `evidence-pipeline.md` (仅 toolPlus) |

**禁止**: agent 同时挂 5+ vuln 类目 — 注意力过度分散。单 agent 应专注一类(如 "AuthZ + IDOR" 或 "Server-Side 反序列化族")。

### 2.2 deep 档 — 4+ agent 编队

| Agent | 角色 | 主要文件 |
| :--- | :--- | :--- |
| **agent 1 (Lead)** | 总协调 + 报告 + 决策仲裁 | SKILL.md / 各 vuln |
| **agent 2 (Recon)** | 全资产侦察 + 历史 CVE 关联 + 子域 takeover | `recon.md` + `intuition-triggers.md` |
| **agent 3 (Business)** | 业务建模 12 问 + Actor×Action×Resource 矩阵 | `business-flow-checklist.md` + `intuition-triggers.md §B` |
| **agent 4 (Vuln-Input)** | SQLi / XSS / SSTI / XXE / SSRF / cmdi / 反序列化 | `vuln/sqli/xss/ssti/xxe/ssrf/cmdi/...md` |
| **agent 5 (Vuln-AuthZ)** | BOLA / BFLA / IDOR / JWT / OAuth / SAML | `auth-logic.md` + `vuln/jwt-advanced.md` 等 |
| **agent 6 (Vuln-Server)** | Spring / Shiro / Fastjson / JNDI / 反序列化族 | `frameworks/spring-boot.md` + `vuln/shiro/fastjson-jackson.md` |
| **agent 7 (Chain)** | 13 条 chained-logic 验证 + 跨服务证据收集 | `chained-logic-extended.md` |
| **agent 8 (Report, toolPlus 独家)** | 截图归档 + Burp flow 标签 + 三段式报告草稿 | `evidence-pipeline.md` |

### 2.3 quick 档

**默认单 agent**。如果时间盒真的紧 + 资产真的大 (例外情况):
- agent 1: 漏洞主线
- agent 2 (可选): Recon
- 不派 evidence / chain agent (quick 不做穷尽级联)

---

## 3. 通信模式 (使用 Claude Code 工具)

### 3.1 工具映射

| Claude Code 工具 | 用途 |
| :--- | :--- |
| `TeamCreate` | 主 agent 创建团队 + task list (1 团队 = 1 task list) |
| `Agent` (subagent_type + team_name + name) | 派子 agent 加入团队 |
| `SendMessage` (to=name) | 主 ↔ 子 agent 通信 |
| `TaskCreate` / `TaskUpdate` / `TaskList` | 任务分配 + 状态同步 |
| `TaskOutput` / `TaskStop` | 跟踪长时任务输出 / 中止 |
| `run_in_background: true` | 子 agent / 长扫描后台运行 |

### 3.2 团队启动流程

```
1. Lead agent: TeamCreate(team_name="srctarget-2026-05", description="...")
   → 自动创建 ~/.claude/teams/srctarget-2026-05/config.json
   → 自动创建对应 task list ~/.claude/tasks/srctarget-2026-05/

2. Lead agent: TaskCreate × N (每个 Phase 1 子任务 1 个)
   → 不要批量创建超过 20 个,先创最早期任务,边推进边补

3. Lead agent: Agent(subagent_type="executor", team_name=..., name="recon", model="sonnet")
   → 子 agent 启动,自动看到团队 config + task list

4. Lead agent: TaskUpdate(taskId=..., owner="recon") 
   → 显式指定该 task 由 recon 完成

5. recon agent 收到任务 → 工作 → 完成时 TaskUpdate(status="completed")
   → idle 时自动通知 Lead

6. Lead 收到 idle notification → 看下一步 → 继续派任务 / 派新 agent
```

### 3.3 关键纪律

- ❌ **禁止** 子 agent 用 plain text 报告状态 — 必须走 TaskUpdate
- ❌ **禁止** 子 agent 用 SendMessage 发结构化 JSON 状态 — 用 TaskUpdate
- ❌ **禁止** 主 agent 反复 TaskList 轮询 — idle notification 是异步推送的
- ✅ **必须** 主 agent 写 task description 时附完整上下文 (子 agent 看不到主对话)
- ✅ **必须** 子 agent 完成任务后看 TaskList 找下一个 — 不要等待

---

## 4. 各阶段编队示例

### 4.1 Phase 1 (Recon)

```
Lead → Recon agent: 
  Task #1: "subfinder + amass 子域全网枚举,结果写 assets.md '子域' 段"
  Task #2: "httpx 探活,只关注 200/301/302/401,写 assets.md '存活' 段"
  Task #3: "katana 爬主站 JS,写 assets.md 'JS' 段"
  Task #4: "Google dork 3 条 (recon.md §1.1)"

Lead → Business agent: (待 recon Task #2 完成后)
  Task #5: "对 Top 10 子域跑 business-flow-checklist 12 问"

Lead: 自己跑 Phase 1.5 业务流程图(收集 Recon + Business 结果总结)
```

### 4.2 Phase 2 (Vuln 主战场, deep 档)

```
Lead 分发任务:
  Vuln-Input agent: 
    Task: "对 P1.5_DONE 标记的所有 endpoint 跑 First-pass SQLi/XSS/SSRF/SSTI/CmdI/XXE"
    Required: 写 vulns.md,只记录有信号三要素异常的端点
  
  Vuln-AuthZ agent:
    Task: "建立两账号(创建 / HITL 提供) → 全量 BOLA/BFLA sweep"
    Required: 写 vulns.md
  
  Vuln-Server agent:
    Task: "Phase 1 指纹中标记 Java/Spring/Tomcat 的端点 → 跑 frameworks/spring-boot.md §4 全步骤"
    Required: 写 vulns.md
```

### 4.3 Phase 3 (Chain, deep 档)

```
Lead 等所有 Vuln agent 至少 1 个 confirm → 派 Chain agent

Chain agent:
  Task: "Grep vulns.md 所有 [Confirmed] 标签 → 对每条跑 chained-logic-extended.md 13 条策略 → 写 chains.md"
  Required: 找到能达到"账号接管 / 跨租户 / RCE"三大终态的链
```

### 4.4 Phase 4 (Report)

```
Lead (或 toolPlus 的 Report agent):
  Task: "用 report-template.md 模板生成三段式报告,evidence 引用 evidence-pipeline.md 归档的截图"
  Required: 每个漏洞 OWASP/CWE 映射 + CVSS 评分 + 复现命令 + impact 证据 + 修复建议
```

---

## 5. HITL 协调 (多 agent 场景的难点)

### 5.1 子 agent 触发 HITL 的传播

子 agent 遇到 P3.5 外部资源需求 (短信号 / OOB / 反弹监听) → **不要** 子 agent 直接和用户说话(可能引起对话混乱) → **必须**:

```
子 agent: SendMessage(to="lead", message="需要 OOB 通道,场景: SSRF 验证 example.com/api/import")
Lead: 暂停所有派任务 → 向用户提问 → 拿到资源 → SendMessage 回传子 agent
子 agent: 收到资源继续
```

### 5.2 数据写 / WebShell / 持久化操作

任何子 agent 想做数据写 (DELETE/UPDATE) / 写 WebShell / 真实利用云 AK / 持久化:
- **必须** SendMessage 给 Lead 请求授权
- Lead **必须** HITL 向用户确认
- 用户拒绝 → Lead SendMessage 回传"否决",子 agent 跳过该步

### 5.3 多 agent 并行时的 HITL 风暴

如果多个子 agent 同时需要 HITL → 用户体验差。规避:
- Lead 先批量收集 HITL 请求 (用 TaskList 看 owner=lead + 含 "HITL" 关键词的任务)
- 一次性向用户列出全部需求
- 用户一次性提供 → Lead 分发

---

## 6. 模型选择 (model 参数)

每个子 agent 启动时显式指定 model:

| 任务复杂度 | model | 示例任务 |
| :--- | :---: | :--- |
| 简单 sweep / 字典扫 | `haiku` | 子域枚举 / 端口扫 / 接口枚举 |
| 标准漏洞测试 | `sonnet` | First-pass 检测 / Decision Card 路由 |
| 复杂级联 / 业务建模 / 决策 | `opus` | 跨业务推理 / 13 条 chained-logic 验证 / 报告 |

**规则**:
- 永远不在 model 中传带 `[1m]` 后缀的字符串 (sub-agent 不能继承 1M context)
- 用 tier alias (`haiku`/`sonnet`/`opus`) 不要用具体 provider ID
- Lead 通常自己跑 `opus`,recon/sweep 用 `haiku` 省成本

---

## 7. 终止协议

### 7.1 子 agent 个体终止

子 agent 完成所有 owner 任务 + TaskList 无可领新任务 → 进入 idle 状态。
- idle ≠ down, idle 子 agent 收到新 SendMessage 仍可唤醒
- 不要因为子 agent idle 就 panic — 这是正常状态

### 7.2 团队整体终止

| 条件 | 动作 |
| :--- | :--- |
| 所有 Phase 完成 + 报告交付 | Lead 向每个子 agent SendMessage shutdown_request |
| 用户中止 | Lead 收到中止信号 → 通知所有子 agent shutdown |
| 时间盒到 | Lead 主动 shutdown,即便有未完成任务,以现有结果出报告 |
| 4h+ 无 ≥High 发现 + 攻击面覆盖 ≥70% | 进入 Phase 4,准备 shutdown |

### 7.3 Shutdown 顺序

```
1. Lead 检查 TaskList — 所有任务都 completed/blocked
2. Lead → 各子 agent: SendMessage(type="shutdown_request")
3. 子 agent 收到 → 处理最后一个任务 → SendMessage(type="shutdown_response", approve=true)
4. 子 agent 进程退出
5. Lead 等所有子 agent shutdown_response 收到
6. Lead 自己进入 Phase 4 报告
7. Lead 调用 TeamDelete 清理团队资源
```

**禁止**: Lead 直接 TeamDelete 不发 shutdown_request — 会留下僵尸进程。

---

## 8. 反模式 (常见错误)

| 错误 | 后果 | 修复 |
| :--- | :--- | :--- |
| 一次性派 8 个 agent 全功能 | 协调开销 > 效率 | 按 §2 编队规模,standard 1-3 / deep 4-8 |
| 子 agent 用 plain text 报状态 | Lead 没看到/混淆 | 用 TaskUpdate |
| 子 agent 之间直接互相 SendMessage | 信息孤岛 / 失去 Lead 决策 | 子 ↔ 子 通信仅在明确分工 (peer DM),所有重大决策走 Lead |
| Lead 反复 TaskList 轮询 | 浪费 token | idle 通知是自动推送的 |
| 多 agent 同时挂 5+ vuln 类 | 注意力过散 | 单 agent 一类 vuln 族 |
| 子 agent 自己 HITL 问用户 | 对话混乱 | 必须通过 Lead 中转 |
| 派 sub-agent 跑 1M context 任务 | model 拒绝 | sub-agent 不能继承 [1m] |
| 跑完忘 TeamDelete | 留下垃圾团队目录 | Lead 在 Phase 4 最后必做 |

---

## 9. 与 OMC 协同

OMC (oh-my-claudecode) 提供专家级 agent (verifier / architect / code-reviewer / writer 等),可在 atomic-rain 工作流中按需调用:

| OMC agent | atomic-rain 场景 |
| :--- | :--- |
| `verifier` | 漏洞确认后二次确认 evidence chain |
| `architect` (opus) | 复杂级联推理 / 跨服务链分析 |
| `writer` | 报告生成 (替代或辅助 Report agent) |
| `tracer` | 信号到根因的因果追踪 (例: 同一参数多个漏洞) |
| `critic` | 报告交付前的多视角审查 |

**调用方式**: 直接 `Agent(subagent_type="oh-my-claudecode:verifier", ...)`,不需要进 team。

---

## 10. 实战范例 (deep 档 8-agent 团队)

```
Day 1 上午:
  Lead 启动 → TeamCreate("acme-srcaudit") → 派 Recon agent (haiku)
  Recon agent: 子域枚举 + 端口 + JS + Google dork (4 个 task,完成约 2h)

Day 1 下午:
  Lead 看 assets.md → 派 Business agent (opus) 跑 P1.5 业务建模 12 问
  Business agent: 输出业务流程图 + Actor×Action×Resource 矩阵

Day 2:
  Lead 派 Vuln-Input (sonnet) + Vuln-AuthZ (sonnet) + Vuln-Server (sonnet) 并行
  3 agent 同时跑 First-pass + Triage,各自维护 vulns.md 不同 section
  Lead 自己整合 vulns.md (定期 TaskList 看进度)

Day 3 上午:
  3 个 Vuln agent 完成 → Lead 派 Chain agent (opus)
  Chain agent: 跑 13 条 chained-logic,产出 chains.md

Day 3 下午:
  Lead 派 Report agent (sonnet, toolPlus only) 生成草稿
  Lead 自己 review chains.md + reports → 决定哪些进最终报告
  Phase 4 收尾 → SendMessage shutdown → TeamDelete
```

---

## 11. 相关参考

- 单 agent 协议: [../SKILL.md](../SKILL.md)
- 各 scan_mode 内的编队定义: 
  - [scan_modes/quick.md §5](scan_modes/quick.md)
  - [scan_modes/standard.md §5](scan_modes/standard.md)
  - [scan_modes/deep.md §5](scan_modes/deep.md)
- 业务建模: [business-flow-checklist.md](business-flow-checklist.md)
- 级联策略: [chained-logic-extended.md](chained-logic-extended.md)
- HITL 协议: [human-in-the-loop.md](human-in-the-loop.md) + [SKILL.md §1 P3.5](../SKILL.md)
- 项目账本: [project-workflow.md](project-workflow.md)
- 证据流水线 (toolPlus only): [evidence-pipeline.md](evidence-pipeline.md)
