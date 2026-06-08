---
name: tool-usage
description: Lightweight tool routing index for Atomic Rain classic. Use this file to choose the right capability and then jump to per-tool playbooks or capability registries instead of reading a long command warehouse.
category: methodology
---

# Tool Usage Index

This file is a routing layer. It intentionally avoids long command catalogs.

Use it to decide which capability to call, then read the matching playbook under `references/tooling/` or the stable registry in `capabilities/cli-capabilities.json`.

## Operating Rules

- Read `references/tool-config.md` before running local CLI tools.
- Prefer capability names over hardcoded tools: decide `dir_fuzz`, `template_scan`, `sqlmap_assist`, `recon_http_probe`, etc., then map to available tools.
- Do not start heavy automation before first-pass evidence exists.
- Do not run destructive, write, bulk brute-force, WebShell, cloud-key, or persistence actions without HITL.
- Keep raw requests, response deltas, tool versions, command line, and output snippets as evidence.

## Capability Routing

| Task | Capability | Preferred classic doc | Output to preserve |
|---|---|---|---|
| Subdomain discovery | `subdomain_enum` | `tooling/recon-toolchain.md` | domain, source, resolver status |
| HTTP probing | `http_probe` | `tooling/recon-toolchain.md` | URL, status, title, tech, length |
| URL crawling | `url_crawl` | `tooling/recon-toolchain.md` | discovered URL, source page, method |
| Directory fuzzing | `dir_fuzz` | `tooling/ffuf.md` | status, length, words, lines |
| Template scanning | `template_scan` | `tooling/nuclei.md` | template ID, matcher, evidence |
| SQLi assist | `sqlmap_assist` | `tooling/sqlmap.md` | exact payload, parameter, DBMS signal |
| Java gadget/OOB | `java_gadget_probe` | `tooling/java-gadget.md` | gadget, callback, target sink |
| JWT/token testing | `token_attack` | `tooling/token-attacks.md` | header, claim diff, verifier behavior |
| WAF fingerprint | `waf_fingerprint` | `waf-bypass.md` | product signal, blocked payload, bypass result |
| Report artifact | `report_artifact` | `report-template.md` | evidence refs, dedupe key, quality gates |

## Phase Routing

### Phase 1: Recon

Read `tooling/recon-toolchain.md` for the concrete chain.

Minimal sequence:

1. Enumerate candidate hosts.
2. Probe alive HTTP services.
3. Preserve status, title, tech, IP, and redirect chain.
4. Send only high-signal surfaces to Phase 2.

Do not run exhaustive subdomain, port, or path fuzzing in quick mode unless the user asks.

### Phase 2: First-Pass Testing

Use focused tools only after a manual signal exists.

| Signal | First tool escalation | Gate |
|---|---|---|
| SQLi boolean/time delta | `tooling/sqlmap.md` | manual true/false or timing signal |
| Hidden path candidate | `tooling/ffuf.md` | stable baseline and scope |
| Known CVE surface | `tooling/nuclei.md` | target tech confirmed |
| JWT `alg`/`kid`/claim issue | `tooling/token-attacks.md` | decoded token and verifier behavior |
| Java deserialization marker | `tooling/java-gadget.md` | OOB channel approved |

### Phase 3: Impact Proof

Stay read-only where possible.

- Prefer OOB callback, harmless command output, or metadata identity proof.
- Do not write WebShell, modify cloud resources, delete data, or execute persistence without HITL.
- Record the exact boundary the user approved.

### Phase 4: Report

Use `report-template.md`, `owasp-mapping.md`, and `artifact-quality-gates.md`.

Machine-readable artifacts should satisfy `schemas/evidence.schema.json`, `schemas/vulnerability.schema.json`, and `schemas/report.schema.json`.

## Per-Tool Playbooks

| Playbook | Use when |
|---|---|
| `tooling/recon-toolchain.md` | building the attack surface from domains, ports, HTTP probes, and crawlers |
| `tooling/ffuf.md` | fuzzing directories, parameters, vhosts, or constrained values |
| `tooling/nuclei.md` | running CVE, exposure, default credential, or custom-template checks |
| `tooling/sqlmap.md` | escalating a confirmed SQLi signal into DBMS-specific verification |
| `tooling/java-gadget.md` | testing Shiro/Fastjson/Jackson/JNDI/deserialization with OOB-first strategy |
| `tooling/token-attacks.md` | testing JWT weak secrets, alg confusion, `kid`, `jku`, `x5u`, and claim tampering |

## Tool Selection Heuristics

- If the target is small or quick mode is selected, prefer manual first-pass plus one focused tool.
- If the target has many hosts, use recon tooling first and postpone deep vulnerability tools.
- If WAF appears, reduce request rate and read `waf-bypass.md` before expanding payloads.
- If a tool output is noisy, require one manual reproduction before reporting.
- If the tool is missing locally, mark degraded and ask whether to configure it or continue manually.

## Evidence Format

For every tool-assisted test, preserve:

```text
tool:
version:
command_or_capability:
target:
input_source:
first_pass_signal:
status_code:
body_length_or_words:
duration:
output_file:
false_positive_check:
```

## Common Mistakes

- Running `sqlmap` before a repeatable SQLi signal exists.
- Running large template scans in quick mode.
- Treating scanner output as confirmed evidence without a manual reproduction.
- Reporting a High/Critical issue without non-note evidence artifacts.
- Using public OOB or external listener infrastructure without P3.5 approval.

## Related

- Capability registry: `capabilities/cli-capabilities.json`
- Local paths: `references/tool-config.md`
- Payload triage: `references/payloads.md`
- Report quality gates: `references/artifact-quality-gates.md`
