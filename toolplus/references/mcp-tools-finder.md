---
name: mcp-tools-finder
description: Lightweight MCP capability routing index for Atomic Rain toolPlus. Use this file after mcp-readiness and mcp-capabilities mapping to choose the smallest Yakit/Chrome/SyntaxFlow/codec/evidence route instead of reading a long MCP SOP warehouse.
category: methodology
---

# MCP Tools Finder

This file is a routing index. It is not the source of truth for tool names.

Use [mcp-readiness.md](mcp-readiness.md) and [../capabilities/mcp-capabilities.json](../capabilities/mcp-capabilities.json) first, then use this file to choose the next focused playbook or cheatsheet.

## Operating Rules

- Discover actual MCP namespaces before active testing. Treat examples such as `mcp__yaklang__http_fuzzer` and `mcp__chrome__chrome_navigate` as aliases, not guaranteed names.
- Prefer stable capability IDs from [../capabilities/mcp-capabilities.json](../capabilities/mcp-capabilities.json): `http_fuzz`, `traffic_history`, `browser_evidence`, `static_dataflow`, `codec_workflow`, `asset_recon`, `controlled_bruteforce`.
- Open at most one MCP route file and one domain/security file for a weak signal.
- Do not fall back to curl, Python requests, or classic CLI inside toolPlus first-pass HTTP testing. If Yakit is unavailable, mark `[DEGRADED:YAKIT_MCP_DOWN]` and recommend classic.
- Do not auto-switch project databases. Use [project-isolation-workflow.md](project-isolation-workflow.md) and ask before `switch_current_project_database`.
- OOB, public DNSLog, webhook, temporary email, and listener infrastructure still require P3.5 approval.

## Capability Routes

| Need | Capability | Read next | Preserve |
|---|---|---|---|
| Confirm project and namespaces | `project_context` | [mcp-readiness.md](mcp-readiness.md) | endpoint, server name, namespace map, database |
| First-pass HTTP fuzzing | `http_fuzz` | [cheatsheet/fuzztag.md](cheatsheet/fuzztag.md) | raw request, status_code, body_length, duration |
| Traffic recovery and correlation | `traffic_history` | Section 4 + [project-isolation-workflow.md](project-isolation-workflow.md) | flow_id, URL, method, auth context, tags |
| Browser proof | `browser_evidence` | [cheatsheet/chrome-templates.md](cheatsheet/chrome-templates.md) + [evidence-pipeline.md](evidence-pipeline.md) | screenshot, console, page URL, timestamp |
| Browser network proof | `browser_network` | [evidence-pipeline.md](evidence-pipeline.md) | request/response pair, tab_id, timing |
| Static data-flow | `static_dataflow` | [ssa-vuln-hunting.md](ssa-vuln-hunting.md) + [cheatsheet/syntaxflow.md](cheatsheet/syntaxflow.md) | program_name, rule, hit, confidence |
| Crypto/encoding workflow | `codec_workflow` | [cheatsheet/exec-codec.md](cheatsheet/exec-codec.md) | input, workflow, output, key source |
| Asset recon | `asset_recon` | [recon.md](recon.md) + [tool-usage.md](tool-usage.md) | asset, status, source, scan mode |
| Controlled brute force | `controlled_bruteforce` | [weak-password-generation.md](weak-password-generation.md) | approval, rate, dictionary scope, stop condition |
| Evidence/report automation | `report_artifact` | [evidence-pipeline.md](evidence-pipeline.md) + [artifact-quality-gates.md](artifact-quality-gates.md) | flow IDs, screenshot refs, dedupe key |

## Scenario Routes

| Scenario | Minimal MCP path | Boundary |
|---|---|---|
| BOLA/IDOR from real traffic | `traffic_history` to recover authenticated request, then `http_fuzz` with paired principals. Read [business-flow-checklist.md](business-flow-checklist.md) before broad enumeration. | Do not confirm severity without cross-account evidence. |
| SQLi boolean/time delta | `http_fuzz` paired requests, preserve status/length/duration, then read [vuln/sqli.md](vuln/sqli.md) only after repeatability. | Do not launch heavy fuzzing on one weak delta. |
| XSS browser proof | `http_fuzz` for reflection, then Chrome navigate/console/screenshot through evidence route. | Browser down means mark `[DEGRADED:CHROME_MCP_DOWN]`; HTTP proof can continue. |
| Miniapp static clue | `static_dataflow` via SSA, then [miniapp-workflow.md](miniapp-workflow.md). | SSA down allows grep only as degraded static analysis. |
| Encrypted parameter | `static_dataflow` or source grep for crypto clue, then `codec_workflow`, then `http_fuzz`. | Never hardcode example keys; record key source and mask secrets. |
| Auth/session discovery | `traffic_history` filtered by auth/login/token paths. | Strict URL filters are mandatory in shared/default project databases. |
| File upload candidate | `traffic_history` filter multipart/form-data, then focused upload route. | Upload/RCE/write payloads require HITL before impact proof. |
| OOB SSRF/XXE/blind path | `http_fuzz` only after P3.5-approved OOB. | No public dnslog/webhook by default. |
| Project isolation | `project_context`, list databases, ask before switching. | Never auto-switch. |
| Report package | tag flow, capture screenshot, map to schemas and quality gates. | `set_tag` is an index, not evidence by itself. |

## Query HTTP Flow Filters

Use `query_http_flow` with tight filters. In default or shared databases, never query broad history without `includeInUrl`.

### Baseline Target Traffic

```json
{
  "includeInUrl": ["target.com"],
  "excludeSuffix": [".js", ".css", ".png", ".jpg", ".ico", ".woff", ".svg", ".gif"],
  "excludeKeywords": ["heartbeat", "analytics", "track", "sentry", "cdn"],
  "haveBody": true,
  "pagination": {"page": 1, "limit": 50, "order": "desc", "orderby": "id"}
}
```

### High-Value Filters

| Need | Add filter |
|---|---|
| Auth endpoints | `includePath: ["/login", "/auth", "/oauth", "/sso", "/token"]`, `methods: "POST"` |
| Old/API endpoints | `includePath: ["/api/v0/", "/api/v1/", "/internal/", "/admin/"]` |
| File upload | `searchContentType: "multipart/form-data"`, `methods: "POST"` |
| Crypto/signature clues | `keywordType: "request"`, `keyword: "encrypt|encryptedData|cipher|sign"` |
| Server errors | `statusCode: "500,501,502,503"` |

Preserve returned `id`, `request`, `response`, `url`, `method`, `status_code`, `body_length`, `duration`, `content_type`, and `tags`.

## Focused Workflow Map

| Workflow | Route |
|---|---|
| Real-request BOLA sweep | Section 4 filters + [business-flow-checklist.md](business-flow-checklist.md) + [cheatsheet/fuzztag.md](cheatsheet/fuzztag.md) |
| Miniapp data-flow | [miniapp-workflow.md](miniapp-workflow.md) + [ssa-vuln-hunting.md](ssa-vuln-hunting.md) |
| XSS evidence | [cheatsheet/chrome-templates.md](cheatsheet/chrome-templates.md) + [evidence-pipeline.md](evidence-pipeline.md) |
| Encrypted parameter replay | [cheatsheet/syntaxflow.md](cheatsheet/syntaxflow.md) + [cheatsheet/exec-codec.md](cheatsheet/exec-codec.md) |
| Weak password test | [weak-password-generation.md](weak-password-generation.md) + HITL rate/scope approval |
| OOB proof | [oob-infrastructure.md](oob-infrastructure.md) + P3.5 approval |
| Same-parameter whole-site sweep | [intuition-triggers.md](intuition-triggers.md) + Section 4 filters |
| Evidence archive | [evidence-pipeline.md](evidence-pipeline.md) |
| Multi-SRC database switch | [project-isolation-workflow.md](project-isolation-workflow.md) |
| Page crypto function call | [cheatsheet/chrome-templates.md](cheatsheet/chrome-templates.md) |

## Safety And Degraded Modes

| Condition | Action |
|---|---|
| Yakit HTTP/flow/SSA/codec namespace unavailable | Mark `[DEGRADED:YAKIT_MCP_DOWN]`; stop HTTP fuzz, flow query, SSA, codec, brute, and project DB actions. Recommend classic for HTTP testing. |
| Chrome namespace or tab discovery unavailable | Mark `[DEGRADED:CHROME_MCP_DOWN]`; stop browser automation, screenshots, console, and Chrome network capture. Yakit HTTP work may continue. |
| Only SSA fails | Mark `[DEGRADED:SSA_UNAVAILABLE]`; grep may guide hypotheses but cannot support SSA-level data-flow proof. |
| Codec unavailable | Mark `[DEGRADED:CODEC_UNAVAILABLE]`; continue non-crypto testing and mark encrypted-parameter coverage incomplete. |
| Project DB unknown | Mark `[DEGRADED:DB_CONTEXT_UNKNOWN]`; do not switch databases or rely on history isolation. |

HITL-required actions:

- `switch_current_project_database`
- broad `delete_http_flow` or `deleteAll`
- `delete_payload`
- high-volume brute force
- public OOB/listener use
- write/RCE/upload/delete payload execution
- persistent browser injection

## Related

- MCP readiness and aliases: [mcp-readiness.md](mcp-readiness.md)
- Capability registry: [../capabilities/mcp-capabilities.json](../capabilities/mcp-capabilities.json)
- toolPlus tool routing: [tool-usage.md](tool-usage.md)
- Evidence pipeline: [evidence-pipeline.md](evidence-pipeline.md)
- Project isolation: [project-isolation-workflow.md](project-isolation-workflow.md)
- SSA data-flow: [ssa-vuln-hunting.md](ssa-vuln-hunting.md)
- fuzztag: [cheatsheet/fuzztag.md](cheatsheet/fuzztag.md)
- SyntaxFlow: [cheatsheet/syntaxflow.md](cheatsheet/syntaxflow.md)
- exec_codec: [cheatsheet/exec-codec.md](cheatsheet/exec-codec.md)
- Chrome templates: [cheatsheet/chrome-templates.md](cheatsheet/chrome-templates.md)

## Limits

- This index does not list all MCP tools. Discover actual tools at runtime and map them to stable capabilities.
- Yakit down is not the same as Chrome down. Degrade by component.
- toolPlus remains MCP-first. Classic CLI is a profile switch or explicit degraded recommendation, not a silent substitute.
