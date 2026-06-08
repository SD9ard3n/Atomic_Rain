---
name: readme
description: Atomic Rain (toolPlus) — MCP-first 强化版 — 黑盒漏洞挖掘执行引擎,Yakit MCP (47 工具) + Chrome MCP (23 工具) + 4 大 cheatsheet + SyntaxFlow 静态分析
category: meta
---

# Atomic Rain (toolPlus)

> **MCP-first 强化版** — 黑盒漏洞挖掘执行引擎,把 Claude 直接接到 Yakit + Chrome MCP 上
>
> 定位: 漏洞赏金 / SRC / 众测 / 企业安全评估
> 覆盖: Web 应用 · API 安全 · 云环境 · 移动端 APP · AI 应用(LLM/Agent/MCP)
> **明确不做**: 内网横向 / 持久化 / 后渗透 / 红队对抗
> **环境前置**: `/mcp` 必须看到 `yaklang` (47 工具) + `chrome` (23 工具) 都 Connected,**未注册请回退到 [classic 版](../atomic-rain/README.md)**

---

## 为什么用 toolPlus(相对 classic)

classic 版用纯 CLI(curl / sqlmap / nuclei / ffuf / hydra / openssl),适合离线环境。toolPlus 是同源衍生版,假设你本地已起 Yakit + Chrome 插件:

- **HTTP fuzzing 提速 5-10×** — `mcp__yaklang__http_fuzzer` 一次调用拿 `status_code` / `body_length` / `duration` 三要素,`concurrent=20` 直接 sweep
- **fuzztag DSL** — `{{int(1-100)}}` / `{{randstr}}` / `{{file:payload-group}}` 替代手写 wordlist
- **SyntaxFlow 静态分析** — `mcp__yaklang__ssa_compile` + `ssa_query` 替代 grep/semgrep/codeql 的精度问题(7 语言:java / php / js / golang / yak / c / python)
- **浏览器全自动化** — `mcp__chrome__*` 全家桶,自动登录 / 截图 / 注入 / 抓包,告别 HITL "请你帮我截图"
- **exec_codec 链式解码** — `mcp__yaklang__exec_codec` 30+ codec 支持链式调用,替代 openssl + pycryptodome + CyberChef
- **证据自动化流水线** — `set_tag_for_http_flow` + `chrome_screenshot` 自动归档,告别手动截图整理

---

## MCP-first 心法 (取代 classic 的"轻便优先")

```
MCP-first > CLI 兜底       — 凡能用 MCP 的不写 curl
信号驱动 > 手册驱动         — 看信号再去 Grep Decision Card
决策脱水 > 知识堆砌         — 只 Grep 决策段,不读整个 .md
级联优先 > 孤岛挖掘         — 13 条 chained-logic 策略
fuzztag 优先 > 手写 wordlist
SyntaxFlow 优先 > grep      — 数据流而非字符匹配
```

---

## 扫描档位 (Scan Modes) `v2.0+`

启动时根据用户意图选档,自动调整 Phase 路由 / 协议执行强度 / 终止条件:

| 档位 | 触发 | 推理强度 | 路由 |
| :--- | :--- | :---: | :--- |
| **quick** | 时间盒赏金 / < 6h | medium | [`scan_modes/quick.md`](references/scan_modes/quick.md) |
| **standard** ✅ 默认 | 标准外网评估 / 2-5 天预算 | high | [`scan_modes/standard.md`](references/scan_modes/standard.md) |
| **deep** | 红队 / 资产穷尽 / 隐蔽链 | high + ultrathink | [`scan_modes/deep.md`](references/scan_modes/deep.md) |

详见 SKILL.md §0.5 决策规则 + scan_modes/*.md §10 工具升级线(toolPlus 段)。

---

## 双版本架构 (Variant Comparison)

atomic-rain 有两个 variant,**同一项目的两个发行版**:

| | **classic**(`atomic-rain/`) | **toolPlus**(本仓库) |
| :--- | :--- | :--- |
| **工具哲学** | 纯 CLI 兜底 | MCP-first(Yakit + Chrome MCP) |
| **HTTP 发包** | curl / Python urlopen / sqlmap | `mcp__yaklang__http_fuzzer` |
| **浏览器自动化** | (无 / 手动 HITL) | `mcp__chrome__*` 全家桶 |
| **静态分析** | grep / semgrep / codeql | `mcp__yaklang__ssa_compile` + SyntaxFlow |
| **加密解码** | openssl / pycryptodome | `mcp__yaklang__exec_codec` 链式 |
| **抓包** | Burp / mitmproxy | `mcp__chrome__chrome_network_debugger_*` + `query_http_flow` |
| **截图** | (HITL 让用户截) | `mcp__chrome__chrome_screenshot` |
| **环境前置** | 无 — 装好 CLI 工具即可 | `/mcp` 必须有 yaklang + chrome 都 Connected |
| **适用场景** | 离线 / 无 MCP / 内网无外联 / 容器内 / 教学 | 桌面 Yakit + Chrome 插件已就位 |
| **独家文件** | `assets/payload_vaults/` 小型字典 | `mcp-tools-finder.md` / `ssa-vuln-hunting.md` / `cheatsheet/` 4 篇 / `evidence-pipeline.md` / `project-isolation-workflow.md` |
| **半分叉 marker** | 不维护 | 维护(`scripts/build.py` extract) |

**何时用 toolPlus** ↓:
- 你已经装好桌面 Yakit + Chrome MCP 插件
- 要批量 fuzzing / 大规模 sweep
- 要做 SyntaxFlow 静态数据流分析
- 要浏览器全自动化(自动登录 / 截图归档)

**何时用 classic** → 见 `../atomic-rain/README.md`

---

## MCP 工具栈速览

### Yakit MCP (47 工具)

| 工具组 | 用途 | 关键工具 |
| :--- | :--- | :--- |
| **HTTP Fuzzing** | 发包 / fuzzing / sweep | `http_fuzzer` (fuzztag DSL) / `save_payload` |
| **静态分析** | SyntaxFlow / 数据流追踪 | `ssa_compile` / `ssa_query` (7 语言) |
| **侦察** | 资产测绘 | `subdomain_collection` / `port_scan` / `web_crawler` |
| **暴破** | 多协议字典爆破 | `brute` |
| **编解码** | 30+ codec 链式 | `exec_codec` |
| **OOB** | 自建 interactsh 监听 | `query_oob_record` |
| **项目隔离** | 多目标库隔离 | `get_current_database_context` / `switch_current_project_database` |
| **流量查询** | 历史 HTTP flow 查询 | `query_http_flow` / `set_tag_for_http_flow` |

完整 70 工具索引 + 10 个工作流见 [`references/mcp-tools-finder.md`](references/mcp-tools-finder.md)。

### Chrome MCP (23 工具)

| 工具组 | 用途 | 关键工具 |
| :--- | :--- | :--- |
| **导航 / 截图** | 自动化浏览 + 证据归档 | `chrome_navigate` / `chrome_screenshot` |
| **JS 注入** | 自定义脚本 / DOM 操作 | `inject_script` / `evaluate_script` |
| **网络调试** | 抓包 / 修改 / 重放 | `chrome_network_debugger_*` |
| **多标签** | 并行操作 | `get_windows_and_tabs` / `chrome_switch_to_tab` |
| **元素交互** | 自动点击 / 填表 | `chrome_click_element` / `chrome_fill_input` |

### Cheatsheet 速查(toolPlus 独家)

| 文件 | 用途 |
| :--- | :--- |
| [`fuzztag.md`](references/cheatsheet/fuzztag.md) | fuzztag DSL `{{...}}` 占位符语法速查 |
| [`syntaxflow.md`](references/cheatsheet/syntaxflow.md) | SyntaxFlow 查询语法速查 + 数据流模板 |
| [`exec-codec.md`](references/cheatsheet/exec-codec.md) | exec_codec 30+ codec 速查 |
| [`chrome-templates.md`](references/cheatsheet/chrome-templates.md) | Chrome 自动化 5 模板(登录 / OOB / 截图 / 注入 / 网络) |

---

## 内容分层

> 误导防止: 之前几版 (测试期 v2.x) 把 `vuln/*.md` 宣传为"完整深度手册",实际多数是 Decision Card 路由层。v1.0 正式版老实分层标注。

```
L0 Scan Mode         (~150 行/篇) — references/scan_modes/{quick,standard,deep}.md, 档位定义
L1 Master            (~110 行) — SKILL.md, 路由表 + 协议 + 边界 + P0.4 toolPlus 启动确认
L2 Category          (50-520 行) — references/*.md, 项目流程 / 工具 / 协议 / 触发表 / 报告
L3 Decision Card     (80-480 行) — references/vuln/*.md, 信号路由 + Triage + 标准增强段
L4 Scenarios         (80-200 行) — references/vuln/*-scenarios.md, 边角场景与升级链
L5 Construction      (160-320 行) — references/payload-construction/*.md, 构造思路(SQLi/XSS/SSRF/JWT/BOLA/AI Prompt)
L+ Cheatsheet        (40-80 行)  — references/cheatsheet/*.md (toolPlus 独家速查)
```

**当前维护状态**:

| 区域 | 状态 |
| :--- | :--- |
| `SKILL.md` | 主流程保留,只做 toolPlus MCP-first 路由与索引维护 |
| `references/mobile-app.md` | 已瘦身为测试路径 / HITL 边界 / 证据要求;命令移至 `mobile-tool-commands.md` |
| `references/payloads.md` | 已瘦身为 payload first-pass 索引;AI Prompt payload 移至 `payload-construction/ai-prompt-payloads.md` |
| 老 Deep 文件 | First-pass/Triage + Attack Surface / Pro Tips / Evidence / FP 标准增强段已就位 |
| SRC 业务流 | `business-flow-checklist.md` 保留主检查;失败转向、状态机、报告证据分别由 `src-failure-pivots.md` / `src-business-logic-state-machine.md` / `src-report-evidence-standards.md` 承接 |
| 高风险横向证据 | 认证、云安全、反序列化、GraphQL/WebSocket、暴露控制台的评级和误判过滤已抽到 evidence-boundaries 文件 |
| 子专题拆分 | WebSocket 与 Druid 监控已从组合型 Deep 文件迁移到独立 playbook,原文件保留摘要跳转 |

**当前各漏洞文件状态**:

| 漏洞 | Decision Card | Scenarios | Construction |
|------|---|---|---|
| sqli | ✓ Standard | ✓ | ✓ |
| xss | ✓ Standard | ✓ | ✓ |
| ssrf | ✓ Standard | ✓ | ✓ |
| ssti | ✓ Deep | ✓ | — |
| shiro | ✓ Standard | — | — |
| spring-vuln | ✓ Standard | — | — |
| fastjson-jackson | ✓ Standard | — | — |
| jwt-advanced | ✓ Standard | — | ✓ |
| saml-attacks | ✓ Standard | — | — |
| prototype-pollution | ✓ Standard | — | — |
| race-condition | ✓ Standard | — | — |
| cmdi | ✓ Standard | — | — |
| xxe | ✓ Standard | — | — |
| upload | ✓ Standard | — | — |
| path-traversal | ✓ Standard | — | — |
| deserialize | ✓ Deep + 标准增强段 | — | — |
| graphql-websocket | ✓ Deep + 标准增强段 | — | — |
| swagger-actuator-druid | ✓ Deep + 标准增强段 | — | — |
| request-smuggling | ✓ Deep + 标准增强段 | — | — |
| csrf-clickjacking | ✓ Deep + 标准增强段 | — | — |
| oauth-advanced | ✓ Deep + 标准增强段 | — | — |
| oidc-attacks | ✓ Deep + 标准增强段 | — | — |

**已完成**: 老 Deep 文件已补标准增强段 (Attack Surface / Pro Tips / Evidence / FP), First-pass/Triage 路由头也已全部就位。反序列化、GraphQL/WebSocket、暴露控制台的横向证据边界和误判过滤已抽到对应 `*-evidence-boundaries.md` 文件。

---

## 快速开始

### 0. 前置:确认 MCP 环境(一次性)

```bash
# 在 Claude Code 内输入
/mcp
```

期望看到:
- `yaklang` — Connected (47 tools)
- `chrome` — Connected (23 tools)

若没有 → 装 Yakit MCP server 或回退到 classic 版。装法详见 [`mcp-tools-finder.md`](references/mcp-tools-finder.md)。

### 1. 项目库隔离(每次会话首动作)

P0.4 toolPlus 启动确认 — 详见 SKILL.md §1 P0.4 + [`project-isolation-workflow.md`](references/project-isolation-workflow.md):

```
1 个目标 = 1 个 Yakit 项目库,严格切换 HITL 协议,**永远不自动切**
```

### 2. 使用

在 Claude Code 中直接说:

```
/atomic-rain 对 https://example.com 进行黑盒渗透测试
```

可附带档位:

```
/atomic-rain quick 对 https://example.com 时间盒 4 小时
/atomic-rain deep 对 https://target.com 做红队评估
```

AI 会:
1. 走 P0.4 toolPlus 启动确认(Yakit 项目库 + Chrome 状态)
2. 创建 `example.com/` 文件夹 + 维护 `assets.md` / `vulns.md` / `js/` 目录
3. 按 scan_mode 选定的 Phase 路由推进,使用 `mcp__yaklang__http_fuzzer` 做 First-pass
4. 三个必填标签 `[Linkable]` / `[Confirmed]` / `[Chained_From]`
5. 走证据自动化流水线([`evidence-pipeline.md`](references/evidence-pipeline.md))
6. 完成时输出三段式 SRC 报告

### 3. 恢复进度

目标文件夹已存在时,自动 Grep 已有标签和漏洞列表增量推进。

---

## 目录结构

```
atomic-rain-toolPlus/
├── SKILL.md                              Master — 路由表 + 协议 + P0.4 启动确认 + 扫描档位选择
├── README.md                             本文件
├── references/
│   ├── scan_modes/                       ★ v2.0 新增 — quick / standard / deep 档位定义
│   ├── mcp-tools-finder.md               ★★ toolPlus 独家 — 70 MCP 工具索引 + 10 工作流
│   ├── mcp-readiness.md                  ★ toolPlus 启动前 MCP 可用性检查
│   ├── ssa-vuln-hunting.md               ★★ toolPlus 独家 — SyntaxFlow 找数据流漏洞 SOP
│   ├── project-isolation-workflow.md     ★★ toolPlus 独家 — Yakit 多项目库隔离协议
│   ├── evidence-pipeline.md              ★★ toolPlus 独家 — 证据自动化流水线
│   ├── runtime-profile.md                ★ 运行档案与环境边界
│   ├── artifact-quality-gates.md         ★ 输出物质量门禁
│   ├── multi-agent-orchestration.md      ★ 多 agent 协作边界
│   ├── cheatsheet/                       ★★ toolPlus 独家 — 4 篇速查
│   │   ├── fuzztag.md                    fuzztag DSL 占位符语法
│   │   ├── syntaxflow.md                 SyntaxFlow 查询语法
│   │   ├── exec-codec.md                 30+ codec 链式调用
│   │   └── chrome-templates.md           Chrome 自动化 5 模板
│   ├── grep-recipes.md                   ★ Grep 命令中心 (~50 行)
│   ├── phase-guide.md                    Phase 1-4 流程
│   ├── project-workflow.md               账本协议 (3 个必填标签)
│   ├── tool-config.md                    MCP-first 工具配置(只留 4 类 HITL CLI)
│   ├── recon.md / recon-workflow.md      侦察索引与执行工作流
│   ├── api-security.md / auth-logic.md / cloud-security.md / waf-bypass.md
│   ├── auth-evidence-boundaries.md       认证/验证码/弱口令证据边界
│   ├── cloud-evidence-boundaries.md      云线索/对象存储/凭据证据边界
│   ├── mobile-app.md / mobile-tool-commands.md
│   ├── ai-app-security.md / ai-data-security.md
│   ├── domestic-admin-frameworks.md      国内后台框架识别
│   ├── edusrc-workflow.md                教育 SRC 路由
│   ├── miniapp-workflow.md               小程序测试路由
│   ├── qr-code-workflow.md               二维码场景路由
│   ├── intuition-triggers.md             ★ 直觉触发表
│   ├── expert-intuitions.md              ★ 案例库
│   ├── chained-logic-extended.md         13 条级联策略
│   ├── business-flow-checklist.md        SRC 业务流检查清单
│   ├── src-business-logic-state-machine.md 业务逻辑状态机
│   ├── src-failure-pivots.md             失败后转向 / 评级边界横向规则
│   ├── src-report-evidence-standards.md  SRC 报告证据标准
│   ├── sensitive-info-exploitation.md    敏感信息三阶段(SILP)
│   ├── sensitivity-matrix.md             阶段1: 临时评分
│   ├── resource-classification.md        未授权访问公开/敏感判断
│   ├── weak-password-generation.md       CAWG + §3.6 国际站策略
│   ├── oob-infrastructure.md             OOB 通道 + dnslog MCP
│   ├── human-in-the-loop.md              HITL 协议
│   ├── owasp-mapping.md / report-template.md / payloads.md
│   ├── payload-construction/             构造思路 (sqli/xss/ssrf/jwt/bola/ai-prompt)
│   └── vuln/                             Decision Cards + Scenarios
│       ├── deserialization-evidence-boundaries.md 反序列化证据 / 评级 / 误判横向规则
│       ├── graphql-websocket-evidence-boundaries.md GraphQL/WS 证据边界
│       ├── exposed-console-evidence-boundaries.md Swagger/Actuator/Druid 证据边界
│       ├── websocket-security.md         WebSocket 专项
│       ├── druid-console.md              Druid 监控面板专项
│       └── _TOOLPLUS_OVERLAY.md          ★★ marker 改造规范(单 source 双 variant 输出)
├── scripts/                              辅助脚本(toolPlus 时代只留元工具)
│   ├── add_frontmatter.py                ★ v2.0 新增 — frontmatter 批量生成 (idempotent)
│   ├── build.py                          ★★ toolPlus 独家 — 半分叉 marker 验证 / 双 variant 提取
│   ├── build_variant.py                  variant 构建
│   ├── package_runtime.py                运行时打包
│   ├── lint_skill.py                     skill 内部链接 / 引用健康检查
│   ├── semantic_check.py                 语义锚点检查
│   ├── validate_artifacts.py             输出物校验
│   ├── validate_capabilities.py          capabilities 校验
│   └── validate_all.py                   汇总校验入口
└── assets/
    └── third-party-js-blacklist.txt      第三方 JS 黑名单(供 web_crawler / chrome 抓包过滤用)
```

---

## 核心理念

### L1-L4 思维金字塔

```
L4: 防御反推    ← 从 WAF/过滤规则反推绕过点
L3: 组合利用    ← 多漏洞串联 (XSS→CSRF→接管, SSRF→内网→RCE)
L2: 系统验证    ← 基于攻击面逐项验证
L1: 攻击面识别  ← 全面发现入口点 / 数据流 / 信任边界
```

### 漏洞本质公式

```
漏洞 = 边界失控 + 信任假设违背
1. 数据从哪来?  → URL / POST / Header / Cookie / File / JSON / Prompt
2. 数据到哪去?  → 验证→处理→存储→输出→第三方
3. 在哪被信任?  → 前端 / 后端 / DB / 缓存 / LLM / Agent
4. 如何被处理?  → 过滤 / 转义 / 类型检查 / 序列化
5. 处理后去哪?  → HTML / SQL / 命令 / 文件 / HTTP / LLM
```

### 测试优先级 (按赏金价值)

```
P0: RCE / SQL 注入(读数据) / 账号接管 / AK 泄露
P1: SSRF(内网可利用) / 支付漏洞 / 任意文件读写 / BFLA
P2: BOLA(批量数据) / 未授权管理接口 / 信息泄露(凭证)
P3: XSS(需交互) / CSRF / 逻辑漏洞(低影响)
P4: 配置问题 / 低危信息泄露 / 纯前端问题
```

---

## 知识来源 (Knowledge Sources)

蒸馏自以下公开来源, 用于教育和授权安全测试:

| 来源 | 提供的内容 |
|------|-----------|
| WooYun 漏洞库 (8.8 万案例) | Web 漏洞分布 / 检测点模式 / 绕过技巧 |
| PortSwigger Web Academy | 现代 Web 漏洞手法 |
| PayloadsAllTheThings | 64 类漏洞 payload 家族 |
| hacktricks | 渗透测试百科 |
| OWASP WSTG v4.2 / Top 10 2021 / API Top 10 2023 | 测试方法论与风险分类 |
| OWASP LLM Top 10 2025 / Agentic Top 10 2026 | LLM 与 Agent 风险 |
| HackerOne / Bugcrowd 公开报告 | 赏金实战经验 |
| CWE Top 25 2024 | 弱点编号体系 |
| **Yakit / Yaklang** (yaklang.com) | toolPlus 全部 MCP 工具栈基础 |
| **Strix 0.8.3** (usestrix.com) | scan_modes 三档位思路(借鉴框架,内容原创),见 `../Strix学习报告v2-AtomicRain深度对照与改进路线.md` |

**处理原则**:
- 不直接拷贝 payload 字典,而是蒸馏成可路由、可组合、可审查的 skill
- 不含客户特定信息 / 不含可识别的实际案例细节
- 所有内容可追溯到公开安全社区 / 标准框架

---

## 自测靶场

- **Web**: DVWA / OWASP Juice Shop / Hackazon / bWAPP / WebGoat / PortSwigger Labs
- **AI**: Gandalf (Lakera) / Prompt Injection Playground
- **云**: TerraGoat / CloudGoat (仅研究)

---

## CLI 工具(只 HITL 兜底场景保留)

toolPlus 主战场是 MCP,以下 CLI 工具**仅在 MCP 真做不到的 4 类 HITL 场景下用**:

| 用途 | 工具 | 何时退回 CLI |
| :--- | :--- | :--- |
| 小程序解包 HITL | jadx / wxapkg | MCP 无相关工具,纯本地解包 |
| APP Hook | Frida / objection | MCP 无 Hook 能力 |
| 邮件伪造 | swaks | MCP 无 SMTP 发送能力 |
| OOB 自建 | interactsh-server | 用户明确不用公共 dnslog 时 |

**其余工具全部走 MCP**。完整 MCP 工具索引见 [`references/mcp-tools-finder.md`](references/mcp-tools-finder.md)。

---

## 许可 / 免责

- 本 skill 及其引用的所有 payload / 技巧, 仅用于 **授权** 的安全测试、合法研究、赏金猎人项目、SRC 提交、CTF 竞赛
- 使用者对测试行为及其后果负全部责任
- 未授权扫描或攻击计算机系统可能违反《刑法》第 285 条、286 条等相关法律

**使用本工具集即表示你同意以上条款。**

---

## 致谢 (Acknowledgements)

toolPlus 之所以能跑得这么快,基于以下开源项目:

- **[Yaklang / Yakit](https://github.com/yaklang/yakit)** — 提供 47 个 yaklang MCP 工具,本 variant 的核心
- **[Chrome MCP](https://github.com/microsoft/playwright)** 类 — 提供浏览器自动化 23 工具
- **[Anthropic Claude Code](https://claude.com)** — skill 加载层与 agent 执行环境
- **[usestrix/strix 0.8.3](https://github.com/usestrix/strix)** — scan_modes 三档位框架灵感(内容完全原创,见 v2 学习报告)

---

## 版本记录

- **v2.0 (2026-05-26)** — 双版本架构 + 扫描档位 + frontmatter 元数据
  - **2026-05-31 维护状态**:README 索引已同步当前 toolPlus 文件版图;mobile 命令、AI Prompt payload、SRC 失败转向/状态机/报告证据标准已迁移到一级可达 reference;老 Deep 标准增强段已全部就位。
  - **frontmatter 全覆盖**:82 个 .md 全部加 YAML frontmatter(name / description / category / tags),为动态 skill 选择和工具索引打基础。`scripts/add_frontmatter.py` 可 idempotent 重跑
  - **scan_modes 三档**:`references/scan_modes/{quick,standard,deep}.md`,quick(时间盒 4h)/ standard(默认 2-5 天)/ deep(红队穷尽 4+ agent 分工);各档定义 P 协议执行映射 + Phase 路由 + 终止条件 + 工具升级线(toolPlus 段)
  - **SKILL.md §0.5 选档协议**:启动时按用户意图决定档位,强制 Grep 对应 scan_modes 文件
  - **SKILL.md §5 知识包目录**:按 frontmatter category 划分版图,82 个 .md 分 7 类(含 cheatsheet 独家)
  - **README 重写**:对照 classic 写清 MCP-first 心法、70 MCP 工具速览、4 大 cheatsheet 速查、双版本对比、致谢
  - **学习自 Strix 0.8.3**:借鉴 scan_modes 框架(完全原创内容)+ frontmatter 命名规范;反向验证 atomic-rain 在漏洞专题 41 vs 17 / P 协议 / HITL / 业务建模 / 双版本 + 半分叉 / 中文 SRC 场景上的独家优势,详见 `../Strix学习报告v2-AtomicRain深度对照与改进路线.md`

- **v1.0 (2026-05-06)** — 首个正式版本 
  - **设计哲学**: 建议 > 硬指令 / 轻量与功能性并重 / 诚实分层 / 实战优先
  - **12 个 Light Deep Card**: shiro / spring-vuln / fastjson-jackson / jwt-advanced / saml-attacks / cmdi / xxe / race-condition / prototype-pollution / ssrf / upload / path-traversal,每个 ≤172 行
  - **7 个老 Deep 加路由头和标准增强段**: deserialize / graphql-websocket / swagger-actuator-druid / request-smuggling / csrf-clickjacking / oauth-advanced / oidc-attacks 顶部加 First-pass Signal + Triage + Attack Surface / Pro Tips / Evidence / FP,接通协议层
  - **SKILL.md 路由表**: 20 类信号入口,覆盖主流漏洞 + 场景分流 (可注册站 / 后端站 / 仅登录后台)
  - **场景化专用协议**: 可注册站 (两账号交叉, 越权优先) + 后端站 (前端 JS 反向溯源 → 指纹 → 接口) + CAWG 弱口令
  - **严重度自检**: 加 `[待验证-Critical/High]` 中间标签合法化挖洞流动状态;Phase 4 收尾再清理,不卡断主流程
  - **工具配置**: `tool-config.md` 为通用模板，需根据本地环境配置实际路径
  - **诚实分层**: README 与现实严格一致,12 个 Light Deep / 各 Decision Card 行数标注准确
  - **首次实战验证**: 投入实战获赏金 3000+,协议可执行非纸面工程

- **测试期 (v2.0-v2.9, 2026-04-18 ~ 2026-05-05)** — 探索阶段,不再单独保留
  - 漏洞类目扩展 (Web + AI + Java 生态 + 认证流) → 心法入 SKILL.md → 实战驱动协议优化 → 轻便化诚实分层 → 协议闭环 + 实战适配
  - 关键教训: 硬指令会被 LLM 凑字段绕过 / 纸面合规 ≠ 实战有效 / 轻量与功能性并重 / 流程方法论应软于安全边界
