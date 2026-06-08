---
name: artifact-quality-gates
description: Atomic Rain artifact quality gates for vulnerability dedupe fingerprints, evidence references, High/Critical confirmation requirements, blocked external-resource states, and degraded-mode consistency checks.
category: methodology
---

# Artifact Quality Gates

Use these gates when generating JSON or JSONL artifacts under `artifacts/`. Markdown reports may stay human-readable, but machine-readable evidence must satisfy these contracts.

## Dedupe Fingerprint

Every vulnerability record must use this normalized six-part key:

```text
vuln_type|normalized_asset|endpoint|parameter|auth_context|root_cause
```

Rules:

- Use lowercase values.
- Use `-` for fields that do not apply.
- Keep the same key for the same root cause, even if the evidence becomes stronger.
- Do not submit two non-rejected vulnerability records with the same `dedupe_key`.

## Confirmation Gates

Confirmed findings require:

- At least one `evidence_refs` entry that resolves to an evidence artifact.
- A `first_pass_signal` with at least one concrete signal: status, body length delta, timing, or marker.
- False-positive checks, all marked `passed: true`.
- `confidence >= 0.70`.

High and Critical confirmed findings additionally require:

- `confidence >= 0.80`.
- `cvss_vector` and `cwe`.
- At least one non-note evidence type such as HTTP, traffic-flow, screenshot, OOB, or static-analysis.

## Blocked And External Resources

If exploitation or impact proof needs OOB, DNSLog, webhook, temporary email, public SMS, listener infrastructure, or other external resources, P3.5 approval must be recorded before use.

When approval or infrastructure is unavailable, set `status: blocked` and include `blocked_reason`. Do not mark the finding confirmed.

## Degraded Mode

Any `DEGRADED:*` marker present in evidence must be copied to the vulnerability record. Any report that includes degraded findings must set `quality_gates.degraded_markers_declared: true`.

Common markers:

- `DEGRADED:YAKIT_MCP_DOWN`
- `DEGRADED:CHROME_MCP_DOWN`
- `DEGRADED:SSA_UNAVAILABLE`
- `DEGRADED:CODEC_UNAVAILABLE`
- `DEGRADED:DB_CONTEXT_UNKNOWN`

Run:

```bash
python scripts/validate_artifacts.py --artifact-dir artifacts
```
