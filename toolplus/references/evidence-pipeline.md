---
name: evidence-pipeline
description: Lightweight toolPlus evidence routing index for turning confirmed signals into tagged traffic, browser proof, schema-aligned artifacts, and report-ready evidence without duplicating report templates.
category: methodology
---

# Evidence Pipeline

Use this file after a first-pass signal is repeatable and toolPlus evidence capture is needed.
It is a route map, not a report template or MCP tool inventory.

Primary sources:

- Report wording and human template: [report-template.md](report-template.md)
- Artifact gates: [artifact-quality-gates.md](artifact-quality-gates.md)
- Evidence schema: [../schemas/evidence.schema.json](../schemas/evidence.schema.json)
- Vulnerability schema: [../schemas/vulnerability.schema.json](../schemas/vulnerability.schema.json)
- Report schema: [../schemas/report.schema.json](../schemas/report.schema.json)
- MCP capability mapping: [../capabilities/mcp-capabilities.json](../capabilities/mcp-capabilities.json)
- MCP namespace readiness: [mcp-readiness.md](mcp-readiness.md)

## Operating Rules

- Discover actual MCP namespaces through [mcp-readiness.md](mcp-readiness.md). Treat names such as `query_http_flow`, `set_tag_for_http_flow`, `chrome_screenshot`, and `chrome_console` as capability aliases, not guaranteed tool names.
- Tagging is an index. It never replaces raw request, raw response, screenshot, console, OOB, or static-analysis evidence.
- Keep every evidence item tied to a concrete signal: status code, body length, timing, marker, callback, screenshot, console event, or static hit.
- For sensitive data, redact before capture when possible and mark artifact entries with `redacted: true`.
- If Yakit is down, mark `DEGRADED:YAKIT_MCP_DOWN` and stop traffic query, flow tagging, HTTP fuzzing, SSA, codec, brute, and project DB actions.
- If Chrome is down, mark `DEGRADED:CHROME_MCP_DOWN` and stop screenshot, browser console, browser network, and DOM automation claims. Yakit evidence may continue.
- OOB evidence requires P3.5 approval before public DNSLog, webhook, listener, temporary email, or public SMS use.
- Before final report status, run the quality gates in [artifact-quality-gates.md](artifact-quality-gates.md).

## Evidence Route

| Need | Route | Preserve |
|---|---|---|
| Recover triggering traffic | `traffic_history` capability, tight `query_http_flow` filters | `flow_id`, URL, method, auth context, request, response, status, length, duration |
| Index confirmed flow | `set_tag_for_http_flow` after preserving current tags | vuln type, severity/status, endpoint, dedupe hint |
| Capture browser proof | Chrome navigate, screenshot, console, network capture as available | screenshot path/base64, page URL, timestamp, console event, tab id |
| Capture HTTP proof | Yakit HTTP fuzzer or traffic replay | raw request, raw response, status, body length delta, duration |
| Capture static proof | SSA/SyntaxFlow route | program name, rule, hit location, confidence, degraded marker if grep-only |
| Capture OOB proof | P3.5-approved OOB route | nonce, callback timestamp, controlled infrastructure, request that triggered callback |
| Build artifacts | Schemas + quality gates | `EV-*`, `VULN-*`, `RPT-*`, evidence refs, dedupe key |

## Minimal Workflow

1. Confirm repeatability with the focused vulnerability playbook. Keep the signal data from first pass.
2. Query the smallest traffic slice that can recover the triggering flow. Use URL, method, time window, marker, and target filters.
3. Preserve raw request and raw response before tagging. Do not rely on Yakit database retention as the only evidence.
4. Merge tags client-side: fetch existing tags, append Atomic Rain tags, then write the full tag set back.
5. Capture visual or browser proof only when it adds reviewer value. Do not screenshot sensitive data unless redacted or necessary.
6. Create one or more `EV-*` evidence records, then create or update the `VULN-*` record.
7. Run quality gates before finalizing `confirmed`, `blocked`, or `rejected` status.

## Query Discipline

Use tight filters in shared or default project databases. Prefer `includeInUrl`, `includePath`, `methods`, `statusCode`, content-type filters, time windows, tags, and pagination limits.

Preserve these fields from returned traffic:

- `id` or equivalent flow identity
- URL, method, host, path, query, auth context
- raw request and raw response when available
- `status_code`, `body_length`, `duration`
- request hash or stable replay identity
- existing tags before any tag update

## Tagging Scheme

Use compact, machine-searchable tags. Keep report prose out of tags.

| Tag type | Example | Purpose |
|---|---|---|
| Vulnerability type | `VULN_BOLA`, `VULN_SQLI`, `VULN_XSS_R` | Fast retrieval by class |
| Status | `confirmed`, `candidate`, `blocked`, `rejected` | Workflow state |
| Severity | `Critical`, `High`, `Medium`, `Low`, `Info` | Report queue sorting |
| Endpoint | `endpoint:/api/user` | Recovery filter |
| Evidence id | `EV-20260530-bola-1` | Link to artifact |
| Dedupe hint | `dedupe:bola|api.example.com|/api/user|id|user|missing-owner-check` | Human trace to schema key |

When updating tags, read current tags first. Treat `set_tag_for_http_flow` as replace-oriented unless the discovered tool contract proves it appends.

## Artifact Mapping

| Evidence source | Evidence artifact fields |
|---|---|
| Yakit HTTP flow | `evidence_type: "traffic-flow"`, `source.capability: "traffic_history"`, `source.flow_id`, raw request/response artifacts |
| HTTP fuzzer result | `evidence_type: "http"`, `source.capability: "http_fuzz"`, `signal.status_code`, `signal.body_length`, `signal.duration_ms` |
| Chrome screenshot | `evidence_type: "screenshot"`, `source.capability: "browser_evidence"`, artifact `kind: "screenshot"` or `kind: "path"` |
| Chrome console | `evidence_type: "console"`, `source.capability: "browser_evidence"`, artifact `kind: "note"` with event summary |
| SSA/SyntaxFlow | `evidence_type: "static-analysis"`, `source.capability: "static_dataflow"`, rule and hit location in artifacts or notes |
| OOB callback | `evidence_type: "oob"`, approved infrastructure, nonce, timestamp, triggering request |

Vulnerability records must include:

- `first_pass_signal`
- `evidence_refs`
- `false_positive_checks`
- six-part `dedupe_key`
- `cvss_vector` and `cwe` for confirmed High/Critical findings
- `blocked_reason` when P3.5 approval or required infrastructure is missing
- copied `degraded_markers` from evidence

## Evidence Requirements By Finding

| Finding | Required evidence before `confirmed` |
|---|---|
| BOLA / IDOR | Two principals, owner proof, cross-account request/response pair, negative control |
| SQLi | Boolean/time/error signal tied to one parameter, baseline jitter control, manual reproduction before scanner reliance |
| XSS | Execution context, browser proof or console event, raw payload, non-executing control |
| SSRF / XXE / blind | Approved OOB or self-owned callback, nonce, timestamp, triggering request |
| Upload / RCE / write impact | HITL approval for write/RCE proof, controlled payload, cleanup/rollback note |
| Sensitive info leak | Data class from [sensitivity-matrix.md](sensitivity-matrix.md), resource class from [resource-classification.md](resource-classification.md), redaction state |
| Static-analysis finding | SSA rule/hit path, source-to-sink confidence, runtime confirmation or candidate status |

## Report Handoff

Use this handoff before opening [report-template.md](report-template.md):

```markdown
Finding:
- vuln_id:
- title:
- status:
- severity:
- affected_asset:
- endpoint:
- parameter:
- auth_context:
- first_pass_signal:
- evidence_refs:
- false_positive_checks:
- dedupe_key:
- degraded_markers:
- blocked_reason:
```

Then use [report-template.md](report-template.md) for human wording and [artifact-quality-gates.md](artifact-quality-gates.md) for final checks.

## Related Routes

| Topic | Read next |
|---|---|
| MCP scenario routing | [mcp-tools-finder.md](mcp-tools-finder.md) |
| Chrome templates | [cheatsheet/chrome-templates.md](cheatsheet/chrome-templates.md) |
| Project database isolation | [project-isolation-workflow.md](project-isolation-workflow.md) |
| Report template | [report-template.md](report-template.md) |
| Artifact gates | [artifact-quality-gates.md](artifact-quality-gates.md) |
| Sensitive data | [sensitivity-matrix.md](sensitivity-matrix.md) |
| Resource classification | [resource-classification.md](resource-classification.md) |
| OWASP mapping | [owasp-mapping.md](owasp-mapping.md) |

## Limits

- Screenshot evidence is stateful. Pair it with raw request/response or replay data when possible.
- Browser evidence cannot prove server-side authorization by itself.
- Tags and screenshots are retrieval aids; schema-backed artifacts are the durable evidence layer.
- Degraded evidence can support candidate or blocked status, but must not be described as full proof.
