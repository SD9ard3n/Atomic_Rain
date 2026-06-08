---
name: atomic-rain-toolplus
description: MCP-first black-box security testing skill for authorized bug bounty, SRC, crowdsourced, and enterprise assessments when Yakit MCP and Chrome MCP are available. Use when Codex should run Atomic Rain with MCP-based HTTP fuzzing, traffic querying, browser automation, SyntaxFlow static analysis, exec_codec transformations, scan modes, business-logic modeling, HITL external-resource controls, and evidence automation.
category: skill-entry
---

# Atomic Rain (toolPlus)

> toolPlus variant: MCP-first security testing workflow for Yakit MCP + Chrome MCP environments.
> Core rule: use MCP for HTTP, traffic, browser, SSA, codec, evidence, and brute-force workflows; use HITL only where the protocol requires it.

## Start Here

1. Confirm authorization and scope. If the target is not explicitly unauthorized, treat the task as authorized security testing.
2. Run P0.4 environment confirmation from `references/protocols/agent-protocol.md` and `references/mcp-readiness.md` before active testing.
3. Select scan mode: `quick`, `standard` (default), or `deep`.
4. Read the selected scan mode file first:
   - `references/scan_modes/quick.md`
   - `references/scan_modes/standard.md`
   - `references/scan_modes/deep.md`
5. Read `references/protocols/agent-protocol.md` for the full P0.4-P3.5 execution protocol.
6. Use the route table below to load only the specific reference needed for the observed signal.

## Non-Negotiable Rules

- Do not run destructive actions, data writes, WebShell upload, persistence, real cloud-key exploitation, or bulk brute force without HITL confirmation.
- Do not use public OOB, temporary email, public SMS, webhook, or listener infrastructure without P3.5 user approval.
- When a test path requires user-owned resources such as login accounts, cookies, tokens, captcha/OTP, two test accounts, OOB domain, receiving email/phone, webhook, external file URL, VPS/listener, or cloud-key authorization, stop and issue a structured HITL request before continuing. Do not silently skip that path or pivot to other vulnerabilities unless the user explicitly declines, delays, or authorizes a downgrade.
- Do not fall back to curl/Python requests for first-pass HTTP testing. Use discovered Yakit MCP `http_fuzzer`; if Yakit is down, mark degraded and switch to classic rather than silently using CLI.
- Do not auto-switch Yakit project databases. Ask the user before `switch_current_project_database`.
- Record `status_code`, `body_length`, and `duration` for each first-pass test.

## Context Loading Budget

- Before a first-pass signal, read only MCP readiness, the selected scan mode, the needed `agent-protocol.md` phase section, and immediate routing files.
- Open at most 2-3 reference files per work turn. Exceed this only when the user requests deep mode or confirmed chaining requires it.
- For references over 300 lines, locate the relevant heading or keyword first; do not load the whole file as background context.
- A weak signal may open one focused vulnerability file plus one MCP route or payload-construction file. Do not fan out across multiple deep vuln files.
- toolPlus routing starts from `capabilities/mcp-capabilities.json`, `mcp-readiness.md`, and `mcp-tools-finder.md`; discover namespaces instead of hardcoding MCP tool names.
- Treat `payloads.md`, `report-template.md`, `tool-usage.md`, and `evidence-pipeline.md` as indexes. Jump from them to the smallest specific playbook needed for the signal.

## MCP Tooling

- Read `references/mcp-tools-finder.md` for scenario-to-tool routing, fuzztag, SyntaxFlow, exec_codec, query_http_flow, and Chrome templates.
- Read `capabilities/mcp-capabilities.json` when mapping stable testing capabilities to discovered MCP tool namespaces.
- Read `references/mcp-readiness.md` when confirming MCP endpoints, actual server names, tool namespaces, or degraded-mode decisions.
- Read `references/project-isolation-workflow.md` before multi-target Yakit work.
- Read `references/evidence-pipeline.md` before final evidence capture or report material collection.
- Read `references/ssa-vuln-hunting.md` for source/miniapp/static data-flow analysis.
- Use `references/cheatsheet/` for focused MCP syntax refreshers.

## Signal Routing

| Signal / task | Read next |
|---|---|
| Phase execution | `references/phase-guide.md` |
| P1 anomaly detection (响应头/状态码/时间/错误/重定向异常) | `references/anomaly-detection.md` |
| P1 signal probability calculation / confidence scoring | `references/signal-probability-model.md` |
| WAF evasion / entropy calculation / rate limiting | `references/adaptive-waf-evasion.md` |
| Backend/API/admin surface | `references/recon.md §9` |
| Registerable site | `references/registerable-site-protocol.md` |
| Login/account/captcha/token needed | `references/human-in-the-loop.md` |
| Business logic modeling | `references/business-flow-checklist.md` + `references/intuition-triggers.md §B` |
| false/null/no-parameter interface or failed low-privilege traffic | `references/business-flow-checklist.md` |
| SRC payment/coupon/order state machine | `references/src-business-logic-state-machine.md` + `references/business-flow-checklist.md` |
| EDUSRC / university / certificate / unified auth | `references/edusrc-workflow.md` + `references/auth-logic.md` + `references/auth-evidence-boundaries.md` |
| SRC recon / crowdsourced asset boundary | `references/recon-workflow.md` + `references/src-report-evidence-standards.md` |
| Domestic admin frameworks: RuoYi / Blade / Nacos / Druid / Swagger / Actuator | `references/domestic-admin-frameworks.md` |
| Swagger/API/low-code/Admin.NET backend capability | `references/domestic-admin-frameworks.md` + `references/api-security.md` |
| QR code login/payment/OAuth ticket/verification | `references/qr-code-workflow.md` |
| External resource needed | `references/protocols/agent-protocol.md §P3.5` + `references/oob-infrastructure.md §10` |
| Miniapp artifacts | `references/miniapp-workflow.md` + `references/ssa-vuln-hunting.md` |
| AI / LLM / Agent / MCP surface | `references/ai-app-security.md` |
| Sensitive data / unauth access | `references/sensitivity-matrix.md` + `references/resource-classification.md` |
| Confirmed vulnerability chaining | `references/chained-logic-extended.md` |
| Report/evidence workflow | `references/evidence-pipeline.md` + `references/report-template.md` + `references/artifact-quality-gates.md` |
| SRC report evidence and false-positive filtering | `references/src-report-evidence-standards.md` |

## Vulnerability Routing

| Signal | Read next |
|---|---|
| HTML/DOM reflection | `references/vuln/xss.md` + `references/vuln/xss-scenarios.md` |
| SQL timing or boolean delta | `references/vuln/sqli.md` + `references/payload-construction/sqli-construction.md` |
| URL import/proxy/fetch | `references/vuln/ssrf.md` + `references/payload-construction/ssrf-construction.md` |
| Shell metachar delay or command output | `references/vuln/cmdi.md` |
| Upload accepted | `references/vuln/upload.md` |
| 401/403/path difference | `references/vuln/path-traversal.md` |
| XML/SOAP/entity error | `references/vuln/xxe.md` |
| Template expression reflection | `references/vuln/ssti.md` + `references/vuln/ssti-scenarios.md` |
| JWT `alg`/`kid`/`jku`/`x5u` | `references/vuln/jwt-advanced.md` |
| WebSocket upgrade / socket.io / ws message auth | `references/vuln/websocket-security.md` + `references/vuln/graphql-websocket-evidence-boundaries.md` |
| Serialized object magic / unserialize / pickle / ViewState | `references/vuln/deserialize.md` + `references/vuln/deserialization-evidence-boundaries.md` |
| Paid resource/CDN URL pattern or order cancel/delete/withdraw IDOR | `references/api-security.md` + `references/src-business-logic-state-machine.md` |
| Shiro `rememberMe`/`deleteMe` | `references/vuln/shiro.md` |
| Java JSON autoType/Jackson signals | `references/vuln/fastjson-jackson.md` |
| Spring/Actuator/Druid/Swagger signals | `references/vuln/spring-vuln.md` + `references/frameworks/spring-boot.md` + `references/vuln/swagger-actuator-druid.md` + `references/vuln/exposed-console-evidence-boundaries.md` |
| SAML/OIDC/OAuth flow | `references/vuln/saml-attacks.md`, `oidc-attacks.md`, or `oauth-advanced.md` |
| Race-prone payment/points/order flow | `references/vuln/race-condition.md` |
| Mail SPF/DKIM/DMARC | `references/vuln/email-spoofing.md` |

## Framework / Technology Routing

- For detected stacks, read only the matching playbook under `references/frameworks/`.
- For cloud/vendor signals, read `references/cloud-security.md` first, use `references/cloud-evidence-boundaries.md` for rating/HITL/FP checks, then read `references/technologies/alibaba-cloud.md` or `references/technologies/tencent-cloud.md` when relevant.
- For payload design, prefer `references/payload-construction/` before ad-hoc payload lists.

## Validation

After skill edits, run:

```bash
python scripts/lint_skill.py
python -u scripts/semantic_check.py
python scripts/validate_artifacts.py
python scripts/validate_capabilities.py --profile toolplus
python scripts/build_variant.py check --profile toolplus
python scripts/build.py selftest
python scripts/build.py validate references/vuln/
```

