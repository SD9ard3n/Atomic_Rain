# Atomic Rain (Agent Protocol)

> **定位**: 漏洞赏金 / SRC / 众测 / 企业安全评估
> **覆盖**: Web · API · 云 · 移动端 · AI 应用(Prompt 注入 / MCP / Agent)
> **心法**: 信号驱动 > 手册驱动 | 决策脱水 > 知识堆砌 | 级联优先 > 孤岛挖掘 | **轻便优先 > 过度完整**

---

## 0. 授权与边界 (ROEs)

- **授权假设**: 除非用户明确声明未授权,否则目标视为授权安全测试。
- **数据写确认**: 删除/修改数据库、写入 WebShell、真实利用云 AK、持久化操作、批量爆破前必须 HITL 确认。
- **不做**: DoS / 垃圾邮件 / 针对第三方非目标资产的主动扫描 / 内网横向 / 后渗透。
- **Grep 规则**: 使用 Claude Code 内置 Grep;最高频命令见 [grep-recipes.md](references/grep-recipes.md)。Grep 异常时直接 Read 对应 reference。

---

## 1. 强制执行协议

### P1: 信号预检 (Signal First)

1. Phase 1 前先读 `references/tool-config.md`;不存在则提示用户创建并配置工具路径。
2. 禁止发现端点立刻打开 Deep 文件;必须先执行对应漏洞的 `First-pass Signal/Payload`。
3. 每次测试记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。
4. 只有出现异常信号,才 Grep 对应 `references/vuln/*.md` 的 `Decision Card`。

### P2: 知识调用脱水 (Knowledge Extraction)

- 禁止无目的 Read 整个深度文件;先 Grep `Decision Card` / `Triage` / `First-pass`。
- Payload 构造优先读 `references/payload-construction/`,不要直接堆 payload 字典。
- 高频命令集中在 [grep-recipes.md](references/grep-recipes.md)。

### P2.5: 敏感度与未授权判断

- 信息泄露: 先走 [sensitivity-matrix.md](references/sensitivity-matrix.md) 临时评分,再走 [sensitive-info-exploitation.md](references/sensitive-info-exploitation.md) 验证,最后定级。
- 未授权访问: 删除 Token 返回 200 **不能直接报告**;先走 [resource-classification.md](references/resource-classification.md) 判断公开/半公开/敏感资源。
- 无法验证的凭证/身份/业务数据使用 `[待验证-Critical/High]` 中间标签,不直接报 Critical;Phase 4 收尾时按 [project-workflow.md §1.3](references/project-workflow.md) 自检建议清理。

### P2.6: 直觉触发 (Intuition Trigger)

每次出现新现象,必须 Grep [intuition-triggers.md](references/intuition-triggers.md) 并执行强制动作。背景案例见 [expert-intuitions.md](references/expert-intuitions.md)。

### P3: 级联挖掘 (Chaining Matrix)

确认漏洞后,必须 Grep [chained-logic-extended.md](references/chained-logic-extended.md),并检查 `assets.md` 中的 `[Linkable]` 标签。账本规则见 [project-workflow.md](references/project-workflow.md)。

---

## 2. 快速路由: 现象 → 协议

| 观察到的现象 | 触发协议 | 文件 |
|---|---|---|
| Phase 1 开始 | 工具加载 / 四阶段流程 | `phase-guide.md` / `tool-config.md` |
| 纯 API / 管理面板 / 后端站 | 后端站专用流程 (含前端 JS 反向溯源) | `recon.md §9` |
| 站点支持自助注册 (SaaS/社区/论坛) | 可注册站专用流程 (两账号 + 越权优先) | `registerable-site-protocol.md` |
| 进入 Phase 2 | OOB 通道就位 | `oob-infrastructure.md` |
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

---

## 3. Phase 自检清单

**P1 结束前**: 老版本 API(v1/v0/internal) / JS 文件 secret+TODO+api_key / Web 与 App 字段差异。

**P2 结束前**: 任意漏洞后 sweep 同类参数 / BOLA 两账号交叉 / SSRF 云元数据 / JWT alg+kid+jku / 信息泄露三阶段 / 未授权资源分类。

**P3 结束前**: AK 先探权限 / XSS 非即时触发点 / Grep 级联矩阵 / vulns.md 写 Repro-Request + Chain-Steps + Discovery-Origin。

---

## 4. OMC 协作与终止协议

- 漏洞确认后 → 可派 `verifier` 二次确认 evidence chain。
- 复杂级联推理 → 可派 `architect` (opus)。
- 报告生成 → 可派 `writer`。
- 长扫描/目录枚举 → `run_in_background`。

**停手条件**: 已运行 ≥4h 且 0 个 ≥High / 攻击面覆盖 ≥70% / 连续 3 个 `[Linkable]` 未触发级联 / 用户要求停止 → 进入 Phase 4 报告。

---

## 5. 资源索引

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
