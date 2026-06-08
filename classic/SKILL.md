---
name: atomic-rain
description: Signal-driven black-box security testing skill for authorized bug bounty, SRC, crowdsourced, and enterprise assessments across Web, API, cloud, mobile, and AI applications. Use when Codex needs a structured security testing workflow with scan modes, first-pass vulnerability signals, business-logic modeling, sensitivity triage, exploit chaining, HITL external-resource controls, and classic CLI-oriented tooling.
category: skill-entry
---

# Atomic Rain (Classic)

> Classic variant: CLI-oriented security testing workflow for environments without Yakit/Chrome MCP.
> Core rule: load only the protocol and reference files needed for the current signal.

## Start Here

1. Confirm authorization and scope. If the target is not explicitly unauthorized, treat the task as authorized security testing.
2. Select scan mode: `quick`, `standard` (default), or `deep`.
3. Read the selected scan mode file first:
   - `references/scan_modes/quick.md`
   - `references/scan_modes/standard.md`
   - `references/scan_modes/deep.md`
4. Read `references/protocols/agent-protocol.md` for the full P0.5-P3.5 execution protocol.
5. Use the route table below to load only the specific reference needed for the observed signal.

## Non-Negotiable Rules

- Do not run destructive actions, data writes, WebShell upload, persistence, real cloud-key exploitation, or bulk brute force without HITL confirmation.
- Do not use public OOB, temporary email, public SMS, webhook, or listener infrastructure without P3.5 user approval.
- When a test path requires user-owned resources such as login accounts, cookies, tokens, captcha/OTP, two test accounts, OOB domain, receiving email/phone, webhook, external file URL, VPS/listener, or cloud-key authorization, stop and issue a structured HITL request before continuing. Do not silently skip that path or pivot to other vulnerabilities unless the user explicitly declines, delays, or authorizes a downgrade.
- Do not open deep vulnerability files before a first-pass signal. Start with `First-pass`, `Decision Card`, or `Triage` sections.
- Record `HTTP_CODE`, `RESP_LENGTH_DELTA`, and `TIMING_DELAY` for each test.
- For sensitive information or unauthenticated access, use `sensitivity-matrix.md`, `sensitive-info-exploitation.md`, and `resource-classification.md` before severity claims.

## Context Loading Budget

- Before a first-pass signal, read only the selected scan mode, the needed `agent-protocol.md` phase section, and routing files required for the immediate action.
- Open at most 2-3 reference files per work turn. Exceed this only when the user requests deep mode or confirmed chaining requires it.
- For references over 300 lines, locate the relevant heading or keyword first; do not load the whole file as background context.
- A weak signal may open one focused vulnerability file plus one payload-construction or tool route. Do not fan out across multiple deep vuln files.
- Classic routing starts from `capabilities/cli-capabilities.json`, `tool-config.md`, and `tool-usage.md`; do not use toolPlus MCP docs as classic execution guidance.
- Treat `payloads.md`, `report-template.md`, and `tool-usage.md` as indexes. Jump from them to the smallest specific playbook needed for the signal.

## Classic Tooling

- Read `capabilities/cli-capabilities.json` before mapping stable testing capabilities to local CLI tools.
- Read `references/tool-config.md` before Phase 1 to confirm local tool paths.
- Use `references/tool-usage.md` for shared command patterns.
- Use `references/tooling/` for per-tool playbooks: `sqlmap`, `nuclei`, `ffuf`, recon toolchain, Java gadget tooling, and token attacks.
- Keep toolPlus-only MCP workflows out of classic. If a document mentions toolPlus, treat it as cross-variant context, not a classic action.

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
| EDUSRC / university / certificate / unified auth | `references/edusrc-workflow.md` + `references/auth-logic.md` |
| SRC recon / crowdsourced asset boundary | `references/recon-workflow.md` + `references/src-report-evidence-standards.md` |
| Domestic admin frameworks: RuoYi / Blade / Nacos / Druid / Swagger / Actuator | `references/domestic-admin-frameworks.md` |
| Swagger/API/low-code/Admin.NET backend capability | `references/domestic-admin-frameworks.md` + `references/api-security.md` |
| QR code login/payment/OAuth ticket/verification | `references/qr-code-workflow.md` |
| External resource needed | `references/protocols/agent-protocol.md §P3.5` + `references/oob-infrastructure.md §10` |
| Miniapp artifacts | `references/miniapp-workflow.md` |
| AI / LLM / Agent / MCP surface | `references/ai-app-security.md` |
| Sensitive data / unauth access | `references/sensitivity-matrix.md` + `references/resource-classification.md` |
| Confirmed vulnerability chaining | `references/chained-logic-extended.md` |
| Report writing | `references/report-template.md` + `references/owasp-mapping.md` + `references/artifact-quality-gates.md` |
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
| Paid resource/CDN URL pattern or order cancel/delete/withdraw IDOR | `references/api-security.md` + `references/src-business-logic-state-machine.md` |
| Shiro `rememberMe`/`deleteMe` | `references/vuln/shiro.md` |
| Java JSON autoType/Jackson signals | `references/vuln/fastjson-jackson.md` |
| Spring/Actuator/Druid/Swagger signals | `references/vuln/spring-vuln.md` + `references/frameworks/spring-boot.md` |
| SAML/OIDC/OAuth flow | `references/vuln/saml-attacks.md`, `oidc-attacks.md`, or `oauth-advanced.md` |
| Race-prone payment/points/order flow | `references/vuln/race-condition.md` |
| Mail SPF/DKIM/DMARC | `references/vuln/email-spoofing.md` |

## Framework / Technology Routing

- For detected stacks, read only the matching playbook under `references/frameworks/`.
- For cloud/vendor signals, read `references/cloud-security.md` first, then `references/technologies/alibaba-cloud.md` or `references/technologies/tencent-cloud.md` when relevant.
- For payload design, prefer `references/payload-construction/` before ad-hoc payload lists.

## Validation

After skill edits, run:

```bash
python scripts/lint_skill.py
python -u scripts/semantic_check.py
python scripts/validate_artifacts.py
python scripts/validate_capabilities.py --profile classic
python scripts/build_variant.py check --profile classic
```

