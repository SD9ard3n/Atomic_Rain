---
name: tool-usage
description: Lightweight tool routing index for Atomic Rain toolPlus. Use this file to choose the right MCP capability and then jump to mcp-tools-finder, evidence-pipeline, readiness, or capability registries instead of reading a long command warehouse.
category: methodology
---

# Tool Usage Index

This file is a routing layer. It intentionally avoids long command catalogs.

Use it to decide which MCP capability to call, then read the matching operational file:

- `references/mcp-tools-finder.md` for concrete Yakit/Chrome/SyntaxFlow/codec tool discovery and call templates.
- `references/mcp-readiness.md` for namespace detection and degraded-mode decisions.
- `references/evidence-pipeline.md` for screenshots, flows, artifacts, and report evidence.
- `capabilities/mcp-capabilities.json` for stable capability names and required output fields.

## Operating Rules

- Prefer capability names over hardcoded namespaces: decide `http_fuzz`, `traffic_query`, `browser_screenshot`, `ssa_query`, `codec_transform`, etc., then map to discovered MCP tools.
- Do not fall back to curl, Python requests, or classic CLI for first-pass HTTP testing inside toolPlus. If Yakit MCP is unavailable, mark `DEGRADED:YAKIT_MCP_DOWN`.
- Do not auto-switch Yakit project databases. Ask before changing project context.
- Do not start high-volume fuzzing, brute force, write actions, WebShell, cloud-key use, or public OOB without HITL.
- Preserve request, response, status code, body length, duration, flow ID, screenshot path, and degraded marker as evidence.

## Capability Routing

| Task | Capability | Preferred toolPlus doc | Output to preserve |
|---|---|---|---|
| Project context | `project_context` | `mcp-readiness.md` | project/database ID and user approval |
| HTTP first-pass fuzz | `http_fuzz` | `mcp-tools-finder.md` | status code, body length, duration, request hash |
| Traffic history query | `traffic_query` | `mcp-tools-finder.md` | flow ID, endpoint, method, auth context |
| Browser navigation | `browser_navigate` | `mcp-tools-finder.md` | URL, page state, console/network clues |
| Browser screenshot | `browser_screenshot` | `evidence-pipeline.md` | screenshot file, timestamp, target URL |
| Browser network evidence | `browser_network` | `evidence-pipeline.md` | request/response pair, initiator, timing |
| SSA/static trace | `ssa_query` | `ssa-vuln-hunting.md` | source location, trace, confidence, degraded marker |
| Codec transformation | `codec_transform` | `mcp-tools-finder.md` | input, transform chain, output |
| Controlled brute force | `controlled_bruteforce` | `mcp-tools-finder.md` | rate, dictionary scope, stop condition |
| Report artifact | `report_artifact` | `report-template.md` | evidence refs, dedupe key, quality gates |

## Phase Routing

### Phase 0.4: MCP Readiness

Read `mcp-readiness.md` first.

Minimal sequence:

1. Detect available Yakit, Chrome, SyntaxFlow, and codec namespaces.
2. Resolve capability-to-tool mapping through `capabilities/mcp-capabilities.json`.
3. Mark missing capabilities with the declared `DEGRADED:*` marker.
4. Do not silently replace MCP paths with CLI paths.

### Phase 1: Recon

Use MCP traffic/project context first when available.

| Need | First toolPlus route | Gate |
|---|---|---|
| Existing target surface | `traffic_query` | project/database confirmed |
| Live page/API discovery | `browser_navigate` + `browser_network` | in-scope URL |
| Endpoint normalization | `http_fuzz` baseline | stable baseline flow |
| JS/SPA behavior | Chrome network and console | page loaded without auth ambiguity |

### Phase 2: First-Pass Testing

Use focused MCP testing only after a signal or candidate endpoint exists.

| Signal | First MCP escalation | Gate |
|---|---|---|
| SQLi boolean/time delta | `http_fuzz` paired requests | repeatable true/false or timing signal |
| HTML/DOM reflection | `browser_navigate` + screenshot/network | nonce reflected or executed in browser |
| SSRF/XXE blind path | `http_fuzz` + approved OOB | P3.5 approval or mark blocked |
| Auth/BOLA candidate | `traffic_query` + paired principals | two-account context |
| Source/static clue | `ssa_query` | repository/source loaded and confidence recorded |

### Phase 3: Evidence

Read `evidence-pipeline.md` before finalizing.

- Prefer flow IDs, request hashes, screenshots, and exported response snippets over narrative-only proof.
- If browser or SSA is degraded, say so explicitly in the finding.
- If OOB was required but not approved, keep the status `blocked`.

### Phase 4: Report

Use `report-template.md`, `owasp-mapping.md`, and `artifact-quality-gates.md`.

Machine-readable artifacts should satisfy `schemas/evidence.schema.json`, `schemas/vulnerability.schema.json`, and `schemas/report.schema.json`.

## Evidence Format

For every MCP-assisted test, preserve:

```text
capability:
mcp_namespace:
tool_name:
target:
flow_id:
request_hash:
status_code:
body_length:
duration:
evidence_file:
degraded_marker:
false_positive_check:
```

## Common Mistakes

- Hardcoding `mcp__chrome__*` or `mcp__yaklang__*` without checking discovered namespaces.
- Calling classic CLI tools inside toolPlus instead of marking degraded.
- Treating SyntaxFlow grep-like output as proven data flow when SSA is degraded.
- Reporting High/Critical without non-note evidence artifacts.
- Asking HITL for browser work that Chrome MCP can capture directly.

## Related

- Capability registry: `capabilities/mcp-capabilities.json`
- MCP discovery: `references/mcp-tools-finder.md`
- Readiness/degraded mode: `references/mcp-readiness.md`
- Evidence pipeline: `references/evidence-pipeline.md`
- Payload triage: `references/payloads.md`
- Report quality gates: `references/artifact-quality-gates.md`
