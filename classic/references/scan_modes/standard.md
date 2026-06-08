---
name: standard
description: 默认 / 系统化档 — 全 P 协议 + Phase 1-4 完整流程 + 业务建模 12 问 + 标准级联矩阵
category: scan_modes
tags: [scan-mode, default, systematic]
---

# Standard Scan Mode

> **哲学**: 系统化 + 业务感知。先理解目标的业务,再按全攻击面有序测试;每个发现都追问"这能解锁什么"。
> **触发场景**: 默认档 — 用户未明示档位时走这档 / 标准外网 web app 安全评估 / API 安全评估 / SRC 月度复测 / 客户给 2-5 天预算。
> **预期产出**: 全攻击面覆盖报告 + 多个验证过的漏洞链 + 修复建议。

---

## 1. P 协议执行映射

| P 协议 | 处理 | 备注 |
| :--- | :---: | :--- |
| **P0.4 toolPlus 启动确认** | 必跑 *(仅 toolPlus 版)* | `get_current_database_context` |
| **P0.5 启动握手** | 必跑 | 确认目标 / ROEs / 报告交付物 |
| **P1 信号预检** | **完整** | First-pass payload + OAST 准备 + 三要素全记录 |
| **P1.5 业务建模 12 问** | **必跑** | 跑 `references/business-flow-checklist.md` 全 12 问 |
| **P2 知识脱水** | Decision Card + 深度补查 | 命中后 Read 对应 vuln/*.md 的 Triage 段 + payload 段 |
| **P2.5 敏感度评判** | 必跑 | 按 `sensitivity-matrix.md` 完整执行 |
| **P2.6 直觉触发表** | **必跑** | 每次发现新现象都过 intuition-triggers.md;同类参数命中要做 sweep |
| **P3 级联挖掘** | **标准矩阵** | 按 `chained-logic-extended.md` 13 条策略选 ≥3 条与发现匹配的 |
| **P3.5 外部资源 HITL** | 必跑 | OPSEC 红线 |

---

## 2. Phase 路由

| Phase | 处理 |
| :--- | :--- |
| **Phase 1 信息收集** | **完整执行**。subfinder + amass / nmap -sV / 主要目录爆破(中等字典)/ 技术栈指纹 / JS bundle 分析 / OpenAPI/Swagger/GraphQL introspection 拉取 / git/env 等敏感路径探测。 |
| **Phase 1.5 业务建模** | **完整 12 问**。识别角色矩阵(Actor × Action × Resource)+ 关键工作流(支付/导出/邀请/审批)+ 状态机 + 信任边界 + 跨服务调用图。 |
| **Phase 2 漏洞挖掘** | **全攻击面**。Input / Auth / AccessControl / BusinessLogic 四象限,每项跑 §3 列表,所有 vuln/ 决策卡命中信号都要进入 P3 评估。 |
| **Phase 3 利用与级联** | **标准级联**。每个发现都问"这能链到什么 P0/P1?",选 ≥3 条级联策略验证。优先验证能达到 chained-logic-extended.md 的"账号接管 / 跨租户 / RCE"三大终态的链。 |
| **Phase 4 报告** | **完整模板**(`references/report-template.md`)。OWASP/CWE 映射 + CVSS 评分 + 复现步骤 + impact 证据 + 修复建议 + 受影响范围。 |

---

## 3. 漏洞覆盖清单

按 atomic-rain `references/vuln/` 完整测试(标准档下不跳过任何主类):

**Input 类**: sqli / xss(含 scenarios)/ ssti / cmdi / xxe / ssrf(含 scenarios)/ path-traversal / upload / hpp / prototype-pollution / dangling-markup
**Auth 类**: jwt-advanced / oauth-advanced / oidc-attacks / saml-attacks / shiro
**Server 类**: deserialize / fastjson-jackson / xstream-hessian-dubbo / jndi-log4shell / request-smuggling / spring-vuln / swagger-actuator-druid / imagetragick
**Client/Web 类**: csrf-clickjacking / cors-cache / cache-deception / host-header / email-header-injection / email-spoofing
**Logic 类**: race-condition / type-juggling
**鉴权与边界**: 详见 `references/api-security.md` + `auth-logic.md` 的完整 Actor × Action × Resource 矩阵
**特殊场景**: subdomain-takeover(资产侧)/ AI 应用(若目标含 LLM 入口)

---

## 4. 推理强度配置

- **默认**: high
- **触发 ultrathink**: 业务建模 12 问中遇到状态机复杂分支 / 级联到 3 跳以上 / 需要构造跨服务证据时

---

## 5. 多 agent 配置

**1-3 个并行 agent** 推荐分工:

- agent 1 (主): 业务建模 + Phase 2 漏洞挖掘主线
- agent 2 (可选): Recon + 资产测绘 + 子域 takeover 检查
- agent 3 (可选): 报告与证据流水线(`evidence-pipeline.md` *— 仅 toolPlus 提供此能力,classic 跳过该 agent 走手动 Burp 归档*)

**禁止**:每个 agent 同时挂 5+ vuln 类目 — 单 agent 应专注一类(如 "AuthZ + IDOR" 或 "Server-Side 反序列化族")。

---

## 6. 终止条件 (Stop Conditions)

满足**所有**:

1. Phase 1 资产树覆盖率 ≥ 主要子域 + 主要端点 90%
2. 业务建模 12 问全部回答(可以是"无该业务节点"也算回答)
3. Phase 2 §3 所有主类都跑过(命中或排除)
4. 所有发现都做过 §1 的 P2.5 敏感度评判
5. Phase 4 报告交付

---

## 7. 与其他档位的边界

**升档到 deep 的触发**(发现以下任一):
- 资产树 > 50 个子域 / 多业务子系统嵌套
- 发现 1 个 P0 漏洞且明显存在 3+ 跳级联
- 业务建模发现复杂状态机(如多角色审批 / 跨租户 SaaS)
- 用户明确说"打透,不要漏"

**降档到 quick 的触发**:
- 用户中途说"快速看一下就够"
- 目标资产极小(单一 app,< 10 个端点)且业务模型简单

---

## 8. Standard 档典型工作流(示例)

```
Day 1
  Phase 1 信息收集(资产测绘 + 指纹 + JS/swagger 挖掘)
Day 2
  Phase 1.5 业务建模 12 问
  Phase 2 启动:Input 类(sqli/xss/ssrf/ssti) + Auth 类
Day 3
  Phase 2 续:AccessControl 类(IDOR/BOLA 完整矩阵) + Server 类(反序列化族)
Day 4
  Phase 3:每个发现做标准级联(≥3 条策略验证)
  evidence 收集
Day 5
  Phase 4 报告完成 + 与用户复盘
```

---

## 9. 反模式(standard 档**禁止**做的事)

- ❌ 跳过业务建模 12 问 — standard 必须做,跳过等于降级到 quick
- ❌ 单条级联策略就收手 — 标准要求 ≥3 条策略验证
- ❌ 单 agent 挂 5+ vuln 类 — 注意力过度分散
- ❌ 跳过敏感度评判直接报告 — 误报会损害可信度
- ❌ 自动跑公共 OOB 服务(dnslog.cn 等)— 违反 P3.5 HITL 协议
