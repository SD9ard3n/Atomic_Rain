---
name: report-template
description: Lightweight vulnerability report template aligned with Atomic Rain evidence, vulnerability, and report schemas. Use for SRC, bug bounty, and enterprise reports after quality gates pass.
category: methodology
---

# Report Template

This file is the human-readable report layer. Machine-readable artifacts must use:

- `schemas/evidence.schema.json`
- `schemas/vulnerability.schema.json`
- `schemas/report.schema.json`
- `references/artifact-quality-gates.md`

## Report Gate

Do not finalize a finding unless these are true:

- First-pass signal is present and repeatable.
- False-positive checks are recorded and pass.
- Evidence refs resolve to evidence artifacts or attached files.
- `dedupe_key` is unique for non-rejected findings.
- High/Critical findings have CVSS vector, CWE, confidence >= 0.80, and at least one non-note evidence artifact.
- P3.5 external-resource decisions are documented.
- Degraded markers such as `DEGRADED:YAKIT_MCP_DOWN` are declared where relevant.

## 标准漏洞条目模板

```markdown
## VULN-<ID>: <title>

| Field | Value |
|---|---|
| Severity | Critical / High / Medium / Low / Info |
| Status | confirmed / blocked / rejected / candidate |
| Vulnerability Type | <SQLi / XSS / BOLA / SSRF / ...> |
| CWE | CWE-xxx |
| CVSS Vector | CVSS:3.1/... |
| Affected Asset | <host / endpoint / app / tenant> |
| Endpoint | <method + path> |
| Parameter | <param/header/body field/object id> |
| Auth Context | unauth / user / admin / tenant-a |
| Dedupe Key | vuln_type|normalized_asset|endpoint|parameter|auth_context|root_cause |
| Evidence Refs | EV-... |

### Summary
One paragraph: what is vulnerable, who can exploit it, and what impact is proven.

### Discovery Path
Explain how the endpoint or asset was found. Mention recon source, JS/API schema, traffic history, or business-flow node.

### Reproduction
1. Preconditions and accounts used.
2. Baseline request and response.
3. Modified request or attack step.
4. Observed delta: status, length, timing, data, UI, or callback.
5. Repeatability check.

### Impact
State only the impact proven by evidence. Separate confirmed impact from plausible chained impact.

### False-Positive Checks
- Baseline compared against control input.
- Different account/tenant/object tested where relevant.
- Cache, redirect, WAF block page, and generic error excluded.
- Tool output manually reproduced when scanner-assisted.

### Remediation
Short term: immediate containment.
Long term: root-cause fix.
Verification: exact retest condition.
```

## Artifact Mapping

| Report field | Artifact field |
|---|---|
| Vulnerability Type | `vuln_type` |
| Endpoint | `endpoint` |
| Parameter | `parameter` |
| Request identity | `request_hash` |
| Flow identity | `flow_id` |
| First-pass status | `first_pass_signal.status_code` |
| Response size | `first_pass_signal.body_length` |
| Timing | `first_pass_signal.duration` |
| Confidence | `confidence` |
| False-positive checks | `false_positive_checks` |
| Evidence list | `evidence_refs` |
| CVSS | `cvss_vector` |
| CWE | `cwe` |
| Dedupe | `dedupe_key` |

## Severity Guide

| Severity | Use when |
|---|---|
| Critical | Full account takeover, unauthenticated RCE, mass sensitive data access, cloud credential impact, cross-tenant compromise |
| High | Confirmed privileged action, sensitive data from another user/tenant, file read with secrets, exploitable SSRF to cloud metadata |
| Medium | Limited data exposure, reflected/stored XSS with constrained impact, CSRF on meaningful but recoverable action |
| Low | Low-sensitivity info leak, missing header, weak hardening, non-sensitive behavior difference |
| Info | Useful observation without direct security impact |

Do not inflate severity from theoretical chains. If the chain was not executed because P3.5 approval was missing, mark the finding `blocked` or describe it as potential impact.

## CVSS Notes

Use CVSS v3.1 vector format when possible:

```text
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N
```

Common starting points:

| Finding | Typical vector |
|---|---|
| Unauthenticated RCE | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| SQLi read sensitive data | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| BOLA sensitive object access | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N` |
| Stored XSS admin-triggered | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N` |
| SSRF to cloud metadata | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` |

Adjust for actual privilege, interaction, scope, and confirmed impact.

## False-Positive Checklist

### Universal

- [ ] Control request behaves differently from attack request.
- [ ] Result is repeatable at least twice.
- [ ] Response is not a generic block, captcha, redirect, or error page.
- [ ] Evidence includes exact request/response or equivalent flow reference.
- [ ] Severity matches proven impact.

### BOLA / IDOR

- [ ] At least two principals tested.
- [ ] Object owner is verified.
- [ ] Same request succeeds cross-account and fails/changes with control object.

### SQLi

- [ ] Boolean/time/error signal is tied to the tested parameter.
- [ ] Timing baseline excludes network jitter.
- [ ] Scanner result is manually reproduced.

### SSRF / XXE / Blind

- [ ] OOB resource was approved or self-owned.
- [ ] Callback includes nonce and timestamp.
- [ ] DNS-only proof is not overstated as HTTP/body read proof.

### XSS

- [ ] Execution context is identified.
- [ ] Reflection-only output is not reported as execution.
- [ ] Cookie or sensitive-data exfiltration is not performed without approval.

## Executive Summary Template

```markdown
# Security Assessment Summary

Scope: <assets and dates>
Method: Atomic Rain <classic/toolPlus>, <quick/standard/deep>
Confirmed findings: <n>
Blocked findings: <n>

Key risk:
<2-4 sentences describing the highest confirmed business risk.>

Priority actions:
1. <Fix the highest-risk root cause.>
2. <Reduce exposed attack surface.>
3. <Add validation or monitoring to prevent recurrence.>
```

## Blocked Finding Template

Use this when a proof requires external resources or high-impact action that was not approved.

```markdown
## BLOCKED: <title>

Reason: <P3.5 approval missing / OOB unavailable / write action not approved>
Current evidence: <first-pass signal>
Needed to confirm: <specific user-approved action or resource>
Risk if confirmed: <bounded potential impact>
Status: blocked
```

## Remediation Pattern

Use three layers:

- Short term: disable exposed endpoint, add auth check, rotate leaked token, block dangerous parser path, or rate-limit affected action.
- Long term: fix authorization, parameterization, parser hardening, object ownership checks, secure defaults, or workflow state machine.
- Verification: rerun the exact PoC and one negative-control case; confirm logs and monitoring capture the attempt.

## Final Review

Before delivery:

- [ ] Every confirmed finding has evidence refs.
- [ ] Every High/Critical finding passes quality gates.
- [ ] Blocked items are clearly separated from confirmed findings.
- [ ] Degraded evidence is not described as full proof.
- [ ] Sensitive data is minimized or redacted.
- [ ] Report language states facts, not assumptions.
