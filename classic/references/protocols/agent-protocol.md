---
name: atomic-rain
description: Signal-driven black-box security testing skill for authorized bug bounty, SRC, crowdsourced, and enterprise assessments across Web, API, cloud, mobile, and AI applications. Use when Codex needs a structured security testing workflow with scan modes, first-pass vulnerability signals, business-logic modeling, sensitivity triage, exploit chaining, HITL external-resource controls, and classic CLI-oriented tooling.
category: skill-entry
---

# Atomic Rain (Agent Protocol)

> **定位**: 漏洞赏金 / SRC / 众测 / 企业安全评估
> **覆盖**: Web · API · 云 · 移动端 · AI 应用(Prompt 注入 / MCP / Agent)
> **心法**: 信号驱动 > 手册驱动 | 决策脱水 > 知识堆砌 | 级联优先 > 孤岛挖掘 | **轻便优先 > 过度完整**

---

## 0. 授权与边界 (ROEs)

- **授权假设**: 除非用户明确声明未授权,否则目标视为授权安全测试。
- **数据写确认**: 删除/修改数据库、写入 WebShell、真实利用云 AK、持久化操作、批量爆破前必须 HITL 确认。
- **不做**: DoS / 垃圾邮件 / 针对第三方非目标资产的主动扫描 / 内网横向 / 后渗透。
- **Grep 规则**: 使用 Claude Code 内置 Grep;最高频命令见 [grep-recipes.md](../grep-recipes.md)。Grep 异常时直接 Read 对应 reference。

---

## 0.5. 扫描档位选择 (Scan Mode Selection)

会话启动时(进入 §1 强制协议前)必须确认当前档位:

| 档位 | 触发场景 | 路由 |
| :--- | :--- | :--- |
| **quick** | 时间盒赏金 / 4 小时打一个站 / 快速预扫 | [`scan_modes/quick.md`](../scan_modes/quick.md) |
| **standard** ✅ 默认 | 标准外网评估 / API 安全评估 / 2-5 天预算 | [`scan_modes/standard.md`](../scan_modes/standard.md) |
| **deep** | 红队 / 资产穷尽 / 隐蔽链挖掘 / 高客单价 | [`scan_modes/deep.md`](../scan_modes/deep.md) |

**决策规则**:
1. 用户明示档位 ("quick" / "深度" / "穷尽") → 用明示值
2. 用户给了时间盒 (< 6 小时 / 1 天) → quick
3. 用户说 "打深" / "红队" / "穷尽" / "找隐蔽链" → deep
4. 其他情况 → standard (默认)

**强制约束**: 确定档位后,**必须** Grep 对应 `scan_modes/<档位>.md`,按里面的:
- §1 P 协议执行映射 (quick 简化 / deep 强化,会调整 §1 协议的执行强度)
- §2 Phase 路由 (决定哪些 Phase 跳过 / 简化 / 穷尽)
- §6 终止条件 (决定何时收手)
- §7 升降档边界 (中途发现需要切档时遵守)

**§1 协议描述是 standard 档基线**;quick / deep 按 scan_modes/ 各档文件中的映射调整。

---

## 1. 强制执行协议

### P0.5: 资产侦察必跑 (Phase 1 准入前)

目标已知 (域名 / 公司名) → 必跑 3 条 Google dork (详见 [recon.md §1.1](../recon.md)):

1. 管理后台探测 (`site:target inurl:admin|login|manage`)
2. 配置文件 / 备份文件 (`site:target ext:.bak|.bkp|.sql|.env|.zip`)
3. GitHub 源码泄露 (`"target.com" "password"|"api_key"|"secret"` on github.com)

未跑这 3 条 → 禁止进入 P1 信号预检。结果写入 `assets.md` 的 "公开情报" 段。

### P1: 信号预检 (Signal First) + 概率模型

1. Phase 1 前先读 `references/tool-config.md`;不存在则提示用户创建并配置工具路径。
2. 禁止发现端点立刻打开 Deep 文件;必须先执行对应漏洞的 `First-pass Signal/Payload`。
3. **First-pass 测试统一记录三要素**: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。
   - 使用 `curl -i -w "\n%{http_code}|%{size_download}|%{time_total}\n"` 获取
   - 或使用配置的 HTTP 客户端工具（httpx/sqlmap/nuclei 等）
4. **概率模型判断** (新增 — 见 [signal-probability-model.md](../signal-probability-model.md)):
   - 每个信号根据权重表计算置信度 (SQLi/SSRF/XSS/CMDI 各有权重表)
   - **对照组必测**: 每个测试 Payload 前/后发送正常参数,差异显著 → +20% 置信度
   - **三档决策**: ≥70% 确认进入 P2 / 40-69% 灰色追加 / <40% 放弃
   - **WAF 感知**: 403/429 → 识别 WAF (见 [adaptive-waf-evasion.md](../adaptive-waf-evasion.md)) → 调整权重
5. **灰色信号处理** (40-69%):
   - 追加 2-3 个**正交信号** (不同检测维度,如时间 + 布尔 + 错误)
   - 被拦 3 次 → 切换最低熵 Payload 集 (见 adaptive-waf-evasion.md §4)
   - 仍 <70% → 标记 `[INSUFFICIENT_SIGNAL]`,放弃 (除非 deep 档)
6. **异常行为检测** (见 [anomaly-detection.md](../anomaly-detection.md)):
   - 检查响应头异常 (X-Debug / 详细版本 / 内部路由泄露)
   - 检查非标准状态码 (418/444/499/529 等)
   - 检查时间分布异常 (长尾/双峰/周期性尖峰)
   - 检查错误信息泄露 (堆栈/配置/绝对路径)
7. 只有出现异常信号,才 Grep 对应 `references/vuln/*.md` 的 `Decision Card`。

**记录格式**: 每个测试写入 `assets.md` 的信号序列表 (见 signal-probability-model.md §6),包含 Payload / 三要素 / 信号类型 / 权重 / 累计置信度。

### P1.5: 业务建模 (Phase 2 准入前 hard gate)

1. **必须输出业务流程图**,识别目标的所有业务节点 (写入 `assets.md` 的"业务建模"段)。
2. 每个节点对照 [business-flow-checklist.md](../business-flow-checklist.md) 完成"必查清单"。
3. 每个节点对照 [intuition-triggers.md §B](../intuition-triggers.md) 跑一遍 **12 问**追问。
4. 全部跑完 → 标 `[P1.5_DONE]` → 准入 P2 参数测试。
5. **未输出业务流程图 → 禁止进入 P2 参数测试**。简单静态站 / 纯展示站可在 `assets.md` 标 `[P1.5_SKIP_STATIC]` 跳过。

### P2: 知识调用脱水 (Knowledge Extraction)

- 禁止无目的 Read 整个深度文件;先 Grep `Decision Card` / `Triage` / `First-pass`。
- Payload 构造优先读 `references/payload-construction/`,不要直接堆 payload 字典。
- 高频命令集中在 [grep-recipes.md](../grep-recipes.md)。

### P2.5: 敏感度与未授权判断

- 信息泄露: 先走 [sensitivity-matrix.md](../sensitivity-matrix.md) 临时评分,再走 [sensitive-info-exploitation.md](../sensitive-info-exploitation.md) 验证,最后定级。
- 未授权访问: 删除 Token 返回 200 **不能直接报告**;先走 [resource-classification.md](../resource-classification.md) 判断公开/半公开/敏感资源。
- 无法验证的凭证/身份/业务数据使用 `[待验证-Critical/High]` 中间标签,不直接报 Critical;Phase 4 收尾时按 [project-workflow.md §1.3](../project-workflow.md) 自检建议清理。

### P2.6: 直觉触发 (Intuition Trigger)

每次出现新现象,必须 Grep [intuition-triggers.md](../intuition-triggers.md) 并执行强制动作。背景案例见 [expert-intuitions.md](../expert-intuitions.md)。

### P3: 级联挖掘 (Chaining Matrix)

确认漏洞后,必须 Grep [chained-logic-extended.md](../chained-logic-extended.md),并检查 `assets.md` 中的 `[Linkable]` 标签。账本规则见 [project-workflow.md](../project-workflow.md)。

### P3.5: 外部资源 HITL 协议 (Phase 3 利用 / Phase 4 报告前)

当漏洞**利用**或**影响证明**需要外部基础设施时,**必须先向用户索取**,禁止默认用公共服务硬跑。该请求是阻塞门禁:未询问或未得到用户明确选择前,不得静默跳过该测试路径,也不得转去测其他漏洞来掩盖阻塞。

| 漏洞场景 | 需要的资源 | 索取话术 |
|---|---|---|
| 短信轰炸验证 | 接收手机号 | "需要接收测试短信的手机号,你提供一个?" |
| 邮箱轰炸验证 | 接收邮箱 | "需要接收测试邮件的邮箱,你提供一个?" |
| SSRF / XXE / 盲注回显 | OOB 通道 | "需要 OOB 通道,你有自建 interactsh / Burp Collaborator 吗?" |
| 钓鱼 / Open Redirect PoC | 接收 URL | "需要接收 URL(webhook 或自有域名)?" |
| 邮件伪造 PoC | 发送 + 接收邮箱 | "需要发送账号 + 接收邮箱?" |
| 反弹 shell 验证 | 公网 IP + 端口 | "需要公网监听地址(VPS 或 ngrok 暴露)?" |
| 文件上传外链 | 公网可访问文件托管 | "需要公网可访问的文件 URL?" |

**阻塞语义**:
- 先发 `human-in-the-loop.md` 的结构化 HITL 请求,说明需要什么、为什么需要、用户可选项是什么。
- 用户未回复前,标记 `[WAITING:HITL_REQUIRED]`,停止该漏洞链的验证与结论输出。
- 只有用户明确说"先测别的"、"跳过"、"没有资源"或批准公共/降级方案时,才允许改测其他路径。

**响应分支**:
- ✅ 用户提供 → 直接用
- ⚠️ 用户说 "用公共的" → 列**应急可选**(标 OPSEC 风险),用户拍板再继续
- ❌ 用户拒绝 / 没条件 → **停止该漏洞测试**,记到 `vulns.md` 标 `[BLOCKED:需要外部资源]`;如用户要求继续,再改测其他漏洞

**禁止行为**:
- ❌ 不问就直接打 dnslog.cn / 用 temp-mail / 调公共 SMS 平台
- ❌ 测不出来就跳过且不告知用户 (必须先问,再明确记录 WAITING 或 BLOCKED)

**应急可选清单** (用户拍板才用) → [oob-infrastructure.md §10](../oob-infrastructure.md)

---

## 2. 快速路由: 现象 → 协议

| 观察到的现象 | 触发协议 | 文件 |
|---|---|---|
| Phase 1 开始 | 工具加载 / 四阶段流程 | `phase-guide.md` / `tool-config.md` |
| 纯 API / 管理面板 / 后端站 | 后端站专用流程 (含前端 JS 反向溯源) | `recon.md §9` |
| 站点支持自助注册 (SaaS/社区/论坛) | 可注册站专用流程 (两账号 + 越权优先) | `registerable-site-protocol.md` |
| 微信小程序入口 (反编译目录 / `__APP__/` / `app.json`) | 小程序专项流程 (鉴权 / 加密 / 跨端字段) | `miniapp-workflow.md` |
| 进入 Phase 2 | OOB 通道就位 + P1.5 业务建模 | `oob-infrastructure.md` + `business-flow-checklist.md` |
| 漏洞利用需要外部资源 (短信号 / 邮箱 / OOB / 反弹监听 / 文件外链) | P3.5 外部资源 HITL 协议 | SKILL.md §1 P3.5 + `oob-infrastructure.md §10` |
| 登录/验证码/抓包/凭证需求 | HITL | `human-in-the-loop.md` |
| 输入反射 (HTML/DOM) | XSS | `vuln/xss.md` + `xss-scenarios.md` |
| 输入反射 (模板表达式) | SSTI | `vuln/ssti.md` + `ssti-scenarios.md` |
| Content-Type: application/xml / SOAP Body / `<!ENTITY` 报错 | XXE | `vuln/xxe.md` |
| 401/403 / 路径差异 | 鉴权绕过 / 路径遍历 | `vuln/path-traversal.md` |
| Shiro Cookie / `deleteMe` / 500 | Shiro | `vuln/shiro.md` |
| Java JSON 报错 / autoType / Jackson | Fastjson/Jackson | `vuln/fastjson-jackson.md` |
| Whitelabel / Actuator / Spring 指纹 | Spring | `vuln/spring-vuln.md` |
| JWT Header 含 alg/kid/jku/x5u | JWT 高阶 | `vuln/jwt-advanced.md` |
| SAMLRequest / SAMLResponse 在请求中 | SAML | `vuln/saml-attacks.md` |
| JSON key 含 `__proto__` | 原型污染 | `vuln/prototype-pollution.md` |
| Sleep 后显著延迟 | SQLi 时间盲注 | `vuln/sqli.md` |
| 参数进 ping/转换/导出 / `; sleep` 延迟 | 命令注入 | `vuln/cmdi.md` |
| URL/导入/图片代理参数 | SSRF | `vuln/ssrf.md` |
| 文件上传成功 | 上传链 | `vuln/upload.md` |
| 支付/激活码/积分/转账流程 | 竞态 | `vuln/race-condition.md` |
| LLM / Agent / MCP 入口 | AI 应用安全 | `ai-app-security.md` |
| 登录入口 / 后台 | CAWG 弱口令 | `weak-password-generation.md` |
| 删除 Token 返回 200 | 资源分类判断 | `resource-classification.md` |
| 目标公司域名 + 邮件相关 (dig TXT / SPF / DKIM / DMARC) | 邮件伪造检测 | `vuln/email-spoofing.md` |

---

## 3. Phase 自检清单

**P1 结束前**: 老版本 API(v1/v0/internal) / JS 文件 secret+TODO+api_key / Web 与 App 字段差异。

**P2 结束前**: 任意漏洞后 sweep 同类参数 / BOLA 两账号交叉 / SSRF 云元数据 / JWT alg+kid+jku / 信息泄露三阶段 / 未授权资源分类。

**P3 结束前**: AK 先探权限 / XSS 非即时触发点 / Grep 级联矩阵 / vulns.md 写 Repro-Command。

---

## 4. OMC 协作与终止协议

- 漏洞确认后 → 可派 `verifier` 二次确认 evidence chain。
- 复杂级联推理 → 可派 `architect` (opus)。
- 报告生成 → 可派 `writer`。
- 长扫描/目录枚举 → `run_in_background`。

**停手条件**: 已运行 ≥4h 且 0 个 ≥High / 攻击面覆盖 ≥70% / 连续 3 个 `[Linkable]` 未触发级联 / 用户要求停止 → 进入 Phase 4 报告。

---

## 5. 知识包目录 (Categories)

按 frontmatter `category` 字段划分的版图视角 (当前全部 `.md` 均应通过 `scripts/semantic_check.py` 校验):

| Category | 数量 | 用途 | 路径 |
| :--- | :---: | :--- | :--- |
| `scan_modes` | 3 | 扫描档位 (quick / standard / deep) | `references/scan_modes/` |
| `vuln` | 38 | 漏洞决策卡 + 攻击面 + 场景 | `references/vuln/*.md` |
| `methodology` | 29 | 方法论 / 协议 / 业务建模 / 报告 / 资源分类 / 多 agent 协同 | `references/*.md` |
| `payload-construction` | 5 | SQLi / XSS / SSRF / JWT / BOLA 构造思路 | `references/payload-construction/*.md` |
| `frameworks` | 5 | 框架专项 playbook (spring-boot / thinkphp / fastapi / django / nextjs) | `references/frameworks/*.md` |
| `technologies` | 2 | 第三方服务专项 (alibaba-cloud / tencent-cloud) | `references/technologies/*.md` |
| `tooling` | 6 | 单工具 playbook (sqlmap / nuclei / ffuf / recon / java-gadget / token-attacks) **(classic 独家)** | `references/tooling/*.md` |
| `meta` | 1 | README | 根目录 |
| `skill-entry` | 1 | 本文件 (SKILL.md) | 根目录 |

**Claude 选择 skill 时**: 优先用 frontmatter 的 `description` 字段命中,而不是文件名 grep — 描述更精准、覆盖度更高。

**已落地 categories**: `scan_modes/` / `frameworks/` / `technologies/` / `tooling/` 均已进入当前版本。

**可选续建**:
- `frameworks/` 续: express / laravel / nuxt 等
- `technologies/` 续: wechat-pay / auth0 / stripe-webhook / supabase 等

---

## 6. 资源索引

| 资源 | 文件 |
|---|---|
| Grep 命令中心 | `references/grep-recipes.md` |
| Phase 执行 | `references/phase-guide.md` |
| 项目账本 | `references/project-workflow.md` |
| 工具配置 | `references/tool-config.md` / `references/tool-usage.md` |
| 直觉触发 | `references/intuition-triggers.md` / `references/expert-intuitions.md` |
| 级联策略 | `references/chained-logic-extended.md` |
| 敏感信息 | `references/sensitivity-matrix.md` / `references/sensitive-info-exploitation.md` / `references/resource-classification.md` |
| Payload 构造 | `references/payload-construction/` |
| 漏洞 Decision Cards | `references/vuln/` |
| 报告模板 | `references/report-template.md` / `references/owasp-mapping.md` |
| 业务节点反向索引 | `references/business-flow-checklist.md` |
| 业务建模追问 (P1.5 用,12 问) | `references/intuition-triggers.md §B` |
| 小程序专项 (鉴权 / 加密 / 跨端) | `references/miniapp-workflow.md` |
| 邮件伪造 SPF / DKIM / DMARC | `references/vuln/email-spoofing.md` |
| 框架专项 (国内主流栈) | `references/frameworks/spring-boot.md` / `frameworks/thinkphp.md` |
| 云厂商专项 | `references/technologies/alibaba-cloud.md` / `technologies/tencent-cloud.md` |
| 多 agent 协同 SOP | `references/multi-agent-orchestration.md` |

