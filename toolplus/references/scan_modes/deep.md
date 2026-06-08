---
name: deep
description: 红队 / 穷尽档 — 完整 P 协议双视角 + 资产树穷尽 + 13 条级联完整 + 多 agent 4+ 分工
category: scan_modes
tags: [scan-mode, red-team, exhaustive]
---

# Deep Scan Mode

> **哲学**: 找别人找不到的东西。每个参数、每个端点、每条边界都测;每个发现都当 pivot 点,链到极致。
> **触发场景**: 真实红队评估 / 资产规模大(50+ 子域 / 多业务子系统)/ 找隐蔽链 / 高客单价 SRC 单 / 内部攻防演练。
> **预期产出**: 完整资产树 + 业务建模双视角 + 多漏洞链验证 + 长形深度报告。**不设时间盒**。

---

## 1. P 协议执行映射(双视角强化)

| P 协议 | 处理 | 备注 |
| :--- | :---: | :--- |
| **P0.4 toolPlus 启动确认** | 必跑 *(仅 toolPlus 版)* | `get_current_database_context` |
| **P0.5 启动握手** | 必跑 | 明确告知用户走 deep 档 + 预估周期(通常 ≥1 周) |
| **P1 信号预检** | **完整 + OAST** | First-pass + interactsh 自建 OAST(P3.5 用户确认后)+ 三要素全记录 |
| **P1.5 业务建模 12 问** | **双视角** | 业务视角 + 攻击视角各跑一遍,产出两张 Actor × Action × Resource 矩阵 |
| **P2 知识脱水** | **全文 Read** | 每类漏洞都 Read 对应 vuln/*.md 全文 + payload-construction/ + scenarios |
| **P2.5 敏感度评判** | 必跑 | 严格按 `sensitivity-matrix.md`,**还要标注潜在级联收益** |
| **P2.6 直觉触发表** | **完整 + 自定义** | 完整跑 `intuition-triggers.md` + `expert-intuitions.md` 全部;deep 档允许新增直觉规则到本地副本 |
| **P3 级联挖掘** | **13 条完整** | `chained-logic-extended.md` 13 条全跑;每个发现作 pivot 点直到 dead-end |
| **P3.5 外部资源 HITL** | 必跑 | OPSEC 红线;deep 档**更要严**,因为深度操作产生的外联流量更多 |

---

## 2. Phase 路由

| Phase | 处理 |
| :--- | :--- |
| **Phase 1 信息收集** | **穷尽**。subfinder + amass + oneforall + crt.sh + passive DNS 多源交叉。全端口(`-p-`)。深度目录爆破(多字典叠加,含 SecLists/jhaddix)。JS 全 bundle 分析 + source map 还原 + `__NEXT_DATA__` / `__BUILD_MANIFEST` 全捞。OpenAPI/GraphQL/gRPC reflection 全部尝试。git/env/.bak/.swp/.orig 全套扫。资产关系图绘制。 |
| **Phase 1.5 业务建模** | **双视角双轮**。第一轮:业务视角(怎么挣钱 / 谁付费 / 数据流向)。第二轮:攻击视角(状态机漏洞 / 不变量 / 跨服务假设 / 隐式信任)。**产出**:状态机图 + 信任边界图 + Actor × Action × Resource 完整矩阵。 |
| **Phase 2 漏洞挖掘** | **全攻击面 + 全 vuln/ 41 篇** + 框架/技术栈专项 + AI 应用专项。每个端点 × 每个参数 × 每个角色都进矩阵。 |
| **Phase 3 利用与级联** | **13 条策略全跑**。每个 pivot 点都问"这能链到什么?",直到收敛或撞墙。完整跨服务 / 跨租户 / 跨子系统链验证。 |
| **Phase 3.5 持续测试** | **特有于 deep**。当初版 Phase 2 完成后,**回头复盘**:有什么 finding 暗示存在我们没测的攻击面?有什么 5xx / 异常响应被忽略?有什么 OOB 回调延迟到达?哪些低 sev 发现可以组合成高 sev? |
| **Phase 4 报告** | **完整长形报告**。Executive Summary + 技术细节 + 攻击链时间轴 + 完整证据(请求/响应 + 截图)+ 修复优先级矩阵 + 受影响范围估算 + 复测建议。 |

---

## 3. 漏洞覆盖清单

**全部 41 个 vuln/ 文件**,加上**框架/技术栈/AI 专项**(若目标包含):

- **核心 17 类**(对位 Strix vulnerabilities/):同 standard §3
- **反序列化族深挖**: shiro / fastjson-jackson / jndi-log4shell / xstream-hessian-dubbo / deserialize 全跑,且做版本对照 + gadget 库选择
- **Web 边界深挖**: request-smuggling / cache-deception / host-header / dangling-markup / hpp / cors-cache / csrf-clickjacking
- **认证协议深挖**: jwt-advanced / oauth-advanced / oidc-attacks / saml-attacks(密钥与 audience 边界)
- **中间件**: spring-vuln / swagger-actuator-druid / imagetragick
- **场景类**: sqli-scenarios / xss-scenarios / ssrf-scenarios / ssti-scenarios(deep 档**必读**)
- **AI 应用**(若目标含 LLM): ai-app-security + ai-data-security 完整跑

---

## 4. 推理强度配置

- **默认**: high + **ultrathink 鼓励**
- 在业务建模双轮 / 13 条级联策略选择 / 跨服务边界判断 时,**主动调用** ultrathink

---

## 5. 多 agent 配置

**4+ 并行 agent 推荐分工**:

| Agent | 职责 | 输入 | 输出 |
| :--- | :--- | :--- | :--- |
| **recon-agent** | Phase 1 资产穷尽 + 指纹 + JS 挖掘 | 主域 | 资产树 + 指纹库 + 敏感路径清单 |
| **business-modeling-agent** | Phase 1.5 业务建模双视角 | 主入口 UI + recon 产出 | Actor × Action × Resource 矩阵 + 状态机图 |
| **vuln-input-agent** | Input 类全套(sqli/xss/ssrf/ssti/xxe/cmdi/path/upload) | recon 端点清单 | 漏洞清单 + PoC |
| **vuln-authz-agent** | AccessControl 类(IDOR/BOLA/BFLA/horizontal/vertical) | business-modeling 矩阵 | 越权清单 + PoC |
| **vuln-server-agent** | Server-Side 类(反序列化族 + RCE 链) | recon 指纹 + 版本信息 | 反序列化 / RCE PoC |
| **chain-agent** | Phase 3 级联挖掘(13 条策略) | 上面所有 agent 的发现 | 完整攻击链 |
| **report-agent**(可选) | evidence pipeline + 报告草稿 *(toolPlus only,classic 走手动 Burp 归档)* | 所有发现 | 长形报告 |

**协作约束**:
- 使用 Claude Code 的 `Agent` / `Team` / `SendMessage` 工具
- 各 agent 共享 `.omc/state/` 或临时目录的 `findings.md` 单一信息源
- chain-agent 是后置 agent,等所有 vuln-*-agent 至少有一轮发现后启动

---

## 6. 终止条件 (Stop Conditions)

满足**全部**:

1. **资产树穷尽** — 子域 / 端口 / 目录 / API 端点都已遍历至边界(连续 3 次新扫无新增 = 穷尽)
2. **业务建模双视角完成** — 两张矩阵都画出
3. **13 条级联策略全跑** — `chained-logic-extended.md` 每条策略都对照发现尝试过(命中或不适用)
4. **Phase 3.5 复盘完成** — 至少做过一次完整回头复盘
5. **所有 P0/P1 发现都已验证 + 评估出影响范围**
6. **长形报告交付**

---

## 7. 与其他档位的边界

**降档到 standard 的触发**:
- 中途用户决定 scope 收紧 / 预算受限
- Phase 1 资产树发现规模其实没那么大(< 20 子域,< 5 子系统) → 不需要 deep 的人力代价

**deep 档下不再升档** — 这已是最高强度。

---

## 8. Deep 档典型工作流(示例)

```
Week 1
  Day 1-2  recon-agent + business-modeling-agent 并行
  Day 3-5  vuln-input/authz/server-agent 三路齐进
Week 2
  Day 1-3  chain-agent 启动,13 条级联策略遍历
  Day 4    Phase 3.5 复盘:跳过的低 sev / OOB 延到 / 异常响应
  Day 5-7  长形报告 + evidence 整理 + 与用户复盘
```

实际周期:5 天 ~ 4 周不等,取决于资产规模和发现量。

---

## 9. 反模式(deep 档**禁止**做的事)

- ❌ 单 agent 跑全部 — deep 档必须多 agent 分工
- ❌ 跳过 Phase 3.5 复盘 — 这是 deep 独有的纵深机制
- ❌ 13 条级联策略只跑 3-5 条 — 那是 standard 档
- ❌ 漏洞证据只截一张图 — deep 档要求完整的"请求 + 响应 + 截图 + diff"四件套
- ❌ 报告写 5 页就收 — deep 档报告长形,通常 20-50 页
- ❌ 用公共 OOB 服务做高频探测 — P3.5 不豁免,deep 档反而要更严

---

## 10. Deep 档的工具升级线

**Recon 阶段**:
- classic: subfinder + amass + oneforall + nmap (-p- -sV -sC) + ffuf 多字典叠加 + jadx (移动端)
- toolPlus: `mcp__yaklang__subdomain_collection` + `port_scan` + `web_crawler` + `mcp__chrome__*` 自动化

**漏洞挖掘**:
- classic: sqlmap (--level 5 --risk 3) / nuclei (-as -severity critical,high,medium) / nikto / 自定义 ffuf
- toolPlus: `http_fuzzer` + fuzztag + `ssa_compile` + `ssa_query`(SyntaxFlow 静态)

**级联与证据**:
- classic: Burp / mitmproxy 抓包归档 / 手动截图 / 整理到 evidence/ 目录
- toolPlus: `mcp__chrome__chrome_screenshot` + `query_http_flow` + `evidence-pipeline.md` 自动归档
