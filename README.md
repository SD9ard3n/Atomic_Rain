# Atomic Rain

> **Atomic Rain — 黑盒漏洞挖掘执行引擎** — 为 Claude Code 打造的结构化渗透测试 Skill
>
> 定位: 漏洞赏金 / SRC / 众测 / 企业安全评估
> 覆盖: Web 应用 · API 安全 · 云环境 · 移动端 APP · AI 应用(LLM/Agent/MCP)

---

## 为什么用它

把一个目标(URL / 域名 / IP)交给 AI 助手时, 普通 AI 需要你一步步引导。本 skill 让 AI 像 **经验丰富的赏金猎人**:

- 自动创建目标文件夹 → 信息收集 → 漏洞挖掘 → 漏洞记录
- 按 **L1-L4 思维金字塔** 组织测试,30+ 现象→协议路由
- 每个漏洞类型有独立 **Decision Card**(信号路由层)+ Scenarios/Construction(深度细节)
- 标注 **OWASP WSTG / CWE / LLM Top 10 / ASI Top 10** 编号
- 漏洞赏金优先级 P0-P4 + CVSS 自动评分
- False Positive 陷阱提示,避免误报
- **轻便优先**: SKILL.md ~100 行入口,Decision Card ~120-150 行,深度细节按需 Grep

---

## 内容分层

```
L1 Master            (~110 行) — SKILL.md, 路由表 + 协议 + 边界
L2 Category          (50-300 行) — references/*.md, 项目流程 / 工具 / 协议 / 触发表 / 报告
L3 Decision Card     (8-150 行)  — references/vuln/*.md, 信号路由 + Triage
L4 Scenarios         (80-200 行) — references/vuln/*-scenarios.md, 边角场景与升级链
L5 Construction      (~250 行)   — references/payload-construction/*.md, 构造思路(SQLi/XSS/SSRF/JWT/BOLA)
```

**当前各漏洞文件状态**:

| 漏洞 | Decision Card | Scenarios | Construction |
|------|---|---|---|
| sqli | ✓ Light (38 行) | ✓ | ✓ |
| xss | 薄 (16 行, 待升 Light) | ✓ | ✓ |
| ssrf | ✓ Light Deep (148 行) | ✓ | ✓ |
| ssti | ✓ Deep (298 行) | ✓ | — |
| shiro | ✓ Light Deep (120 行) | — | — |
| spring-vuln | ✓ Light Deep (143 行) | — | — |
| fastjson-jackson | ✓ Light Deep (116 行) | — | — |
| jwt-advanced | ✓ Light Deep (136 行) | — | — |
| saml-attacks | ✓ Light Deep (122 行) | — | — |
| prototype-pollution | ✓ Light Deep (122 行) | — | — |
| race-condition | ✓ Light Deep (138 行) | — | — |
| cmdi | ✓ Light Deep (125 行) | — | — |
| xxe | ✓ Light Deep (136 行) | — | — |
| upload | ✓ Light Deep (172 行) | — | — |
| path-traversal | ✓ Light Deep (156 行) | — | — |
| oidc-attacks | ✓ Deep (272 行, 老结构) | — | — |
| oauth-advanced | ✓ Deep (317 行, 老结构) | — | — |
| 老 Deep (deserialize/graphql/swagger-actuator/request-smuggling/csrf-clickjacking 等) | Deep, 缺 First-pass/Triage 标准头 | 部分 | — |

**待办**: xss Decision Card 升级为 Light; 老 Deep 文件 (oidc/oauth/deserialize/graphql/swagger-actuator/request-smuggling/csrf-clickjacking) 加 First-pass Signal / Triage 标准头(不删原内容,只加路由层)。

---

## 快速开始

### 1. 配置工具路径 (一次性)

编辑 `references/tool-config.md`, 将各工具目录路径替换为本机绝对路径。

skill 启动时读取 `tool-config.md`;如果不存在会触发 HITL 提示。

### 2. 使用

在 Claude Code 中直接说:

```
/atomic-rain 对 https://example.com 进行黑盒渗透测试
```

AI 会:
1. 创建 `example.com/` 文件夹
2. 维护 `assets.md`(资产+线索)/ `vulns.md`(漏洞)+ `js/` 目录
3. 按 Phase 1-4 推进,使用三个必填标签 `[Linkable]` / `[Confirmed]` / `[Chained_From]`
4. 完成时输出三段式 SRC 报告

### 3. 恢复进度

目标文件夹已存在时,自动 Grep 已有标签和漏洞列表增量推进。

---

## 目录结构

```
atomic-rain/
├── SKILL.md                              Master (~110 行) — 路由表 + 协议
├── README.md                             本文件
├── references/
│   ├── grep-recipes.md                   ★ Grep 命令中心 (~50 行)
│   ├── phase-guide.md                    Phase 1-4 流程
│   ├── project-workflow.md               账本协议 (3 个必填标签)
│   ├── tool-config.md                  工具路径配置(直接 hardcode)
│   ├── tool-usage.md                     工具命令模板
│   ├── recon.md                          信息收集 + §9 后端站协议
│   ├── api-security.md / auth-logic.md / cloud-security.md / mobile-app.md / waf-bypass.md
│   ├── ai-app-security.md / ai-data-security.md
│   ├── intuition-triggers.md             ★ 直觉触发表(权威源)
│   ├── expert-intuitions.md              ★ 案例库(Why/Example, ~70 行)
│   ├── chained-logic-extended.md         13 条级联策略
│   ├── sensitive-info-exploitation.md    敏感信息三阶段(SILP)
│   ├── sensitivity-matrix.md             阶段1: 临时评分
│   ├── resource-classification.md        未授权访问公开/敏感判断
│   ├── weak-password-generation.md       CAWG + §3.6 国际站策略
│   ├── oob-infrastructure.md             OOB 通道 + dnslog MCP
│   ├── human-in-the-loop.md              HITL 协议
│   ├── owasp-mapping.md / report-template.md / payloads.md
│   ├── payload-construction/             构造思路 (sqli/xss/ssrf/jwt/bola)
│   └── vuln/                             Decision Cards + Scenarios
├── scripts/                              辅助脚本 (主流工具补空)
│   ├── js_filter_download.py
│   ├── idor_sweep.py
│   └── prompt_injection_probe.py
└── assets/
    ├── third-party-js-blacklist.txt
    └── payload_vaults/                   小型 payload 字典
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

## 推荐工具

| 用途 | 工具 |
|------|------|
| 子域名 | subfinder / amass / oneforall / ksubdomain |
| 存活 | httpx |
| 端口 | nmap / naabu / masscan |
| 目录 | dirsearch / ffuf / feroxbuster |
| 爬取 | katana / gospider / packerfuzzer |
| 漏洞扫描 | nuclei / xray / afrog |
| 注入 | sqlmap |
| SSTI | tplmap / SSTImap |
| 反序列化 | ysoserial / phpggc / ysoserial.net |
| WAF | wafw00f |
| 子域接管 | subjack / nuclei-takeover 模板 |
| XSS | XSStrike / Dalfox |
| 抓包 | Burp Suite / mitmproxy |
| 移动端 | Frida / objection / jadx |
| 云 | awscli / alibabacloud-cli / tccli / pacu |
| JWT/Hash | jwt_tool / hashcat |

填写 `references/tool-config.md` 中对应路径即可被 Agent 自动调用。

---

## 许可 / 免责

- 本 skill 及其引用的所有 payload / 技巧, 仅用于 **授权** 的安全测试、合法研究、赏金猎人项目、SRC 提交、CTF 竞赛
- 使用者对测试行为及其后果负全部责任
- 未授权扫描或攻击计算机系统可能违反《刑法》第 285 条、286 条等相关法律

**使用本工具集即表示你同意以上条款。**

---

## 版本记录

- **v1.0 (2026-05-06)** — 首个正式版本 
  - **设计哲学**: 建议 > 硬指令 / 轻量与功能性并重 / 诚实分层 / 实战优先
  - **12 个 Light Deep Card**: shiro / spring-vuln / fastjson-jackson / jwt-advanced / saml-attacks / cmdi / xxe / race-condition / prototype-pollution / ssrf / upload / path-traversal,每个 ≤172 行
  - **7 个老 Deep 加路由头**: deserialize / graphql-websocket / swagger-actuator-druid / request-smuggling / csrf-clickjacking / oauth-advanced / oidc-attacks 顶部加 First-pass Signal + Triage,接通协议层
  - **SKILL.md 路由表**: 20 类信号入口,覆盖主流漏洞 + 场景分流 (可注册站 / 后端站 / 仅登录后台)
  - **场景化专用协议**: 可注册站 (两账号交叉, 越权优先) + 后端站 (前端 JS 反向溯源 → 指纹 → 接口) + CAWG 弱口令
  - **严重度自检**: 加 `[待验证-Critical/High]` 中间标签合法化挖洞流动状态;Phase 4 收尾再清理,不卡断主流程
  - **工具配置 hardcode**: 单一 `tool-config.md` (天狐工具箱)
  - **诚实分层**: README 与现实严格一致,12 个 Light Deep / 各 Decision Card 行数标注准确
