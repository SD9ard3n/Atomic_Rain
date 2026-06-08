---
name: ssa-vuln-hunting
description: Lightweight toolPlus SSA and SyntaxFlow workflow index. Use it to decide when static data-flow is worth running, compile/query safely, route rule templates to the SyntaxFlow cheatsheet, and preserve evidence without overstating grep-only results.
category: methodology
---

# SSA Vuln Hunting

Use this file when toolPlus has source, decompiled miniapp code, or backend code and needs static data-flow analysis.
It is the SSA workflow and evidence discipline; rule templates live in [cheatsheet/syntaxflow.md](cheatsheet/syntaxflow.md).

Primary routes:

- MCP capability mapping: [../capabilities/mcp-capabilities.json](../capabilities/mcp-capabilities.json)
- MCP readiness and degraded mode: [mcp-readiness.md](mcp-readiness.md)
- SyntaxFlow operators and rules: [cheatsheet/syntaxflow.md](cheatsheet/syntaxflow.md)
- Miniapp source-to-API handoff: [miniapp-workflow.md](miniapp-workflow.md)
- Evidence capture: [evidence-pipeline.md](evidence-pipeline.md)

## When To Use SSA

| Signal | Use SSA? | Route |
|---|---|---|
| Large source tree, known sink class, or repeated pattern search | Yes | Compile once, run focused SyntaxFlow rules |
| Need source-to-sink trace from user input to dangerous call | Yes | Use `#->` or `-->` rules from [cheatsheet/syntaxflow.md](cheatsheet/syntaxflow.md) |
| Miniapp package with many `wx.request` or crypto helpers | Yes | SSA then [miniapp-workflow.md](miniapp-workflow.md) endpoint handoff |
| Encrypted parameter, signature, or key discovery | Maybe | Grep keywords first, then SSA around call context |
| Business logic flaw, authorization matrix, payment state machine | No | Use [business-flow-checklist.md](business-flow-checklist.md) |
| Tiny single file or obvious direct code path | Usually no | Read the file directly |
| SSA unavailable | Degraded only | Mark `DEGRADED:SSA_UNAVAILABLE`; grep cannot prove data-flow |

Supported languages are `java`, `php`, `js`, `golang`, `yak`, `c`, and `python`.

## Operating Rules

- Discover actual Yakit MCP namespace before calling SSA tools.
- Record `program_name`, target path, language, rules, hit counts, and confidence.
- Use unique `program_name` values such as `<target>_<component>_<version>_<date>`.
- Do not use `re_compile: true` by default. Prefer `base_program_name` for version diffs.
- One rule should answer one question. If a rule returns thousands of hits, narrow it before interpreting.
- Every hit is a lead until manually reviewed or dynamically confirmed. Do not report SSA hits as confirmed vulnerabilities by themselves.
- If only grep was used, mark the result as degraded static analysis and avoid SSA-level claims.

## Minimal Workflow

1. Confirm target source directory, language, size, and whether the user expects static analysis.
2. If the source tree is large, tell the user compile may take time and memory before starting.
3. Compile with a unique `program_name`.
4. Select the smallest rule family from [cheatsheet/syntaxflow.md](cheatsheet/syntaxflow.md).
5. Run focused `ssa_query` rules. Preserve query text and result identifiers.
6. Read only the hit files and nearby functions needed to validate the data flow.
7. Convert validated hits into HTTP/API test candidates, miniapp endpoint handoff, or `candidate` findings.
8. Capture evidence with [evidence-pipeline.md](evidence-pipeline.md). Keep runtime confirmation separate from static proof.

## Compile Parameters

| Parameter | Required | Guidance |
|---|---|---|
| `target` | Yes | Absolute source/decompiled project path |
| `language` | Yes | One of `java`, `php`, `js`, `golang`, `yak`, `c`, `python` |
| `program_name` | Yes | Unique, target-scoped, versioned |
| `base_program_name` | For incremental compile | Use when only part of a known project changed |
| `re_compile` | Rare | Only after a deliberate full rebuild decision |

Example shape, using discovered tool namespace:

```json
{
  "target": "/path/to/decompiled_project",
  "language": "js",
  "program_name": "miniapp_target_v1_20260530"
}
```

## Query Routes

| Goal | Start with |
|---|---|
| Command execution sinks | SyntaxFlow command/RCE templates |
| SQL string construction | SyntaxFlow SQL templates |
| Deserialization entry points | JSON, pickle, Java serialization templates |
| Miniapp request extraction | `wx.request` and upload templates, then [miniapp-workflow.md](miniapp-workflow.md) |
| DOM XSS candidates | DOM sink templates, then browser proof |
| Crypto/key/signature discovery | grep keyword prefilter, then SSA on call context |
| SSRF via internal HTTP helpers | HTTP call templates, then SSRF playbook |

SyntaxFlow syntax, operators, and seven-language rule examples are intentionally kept in [cheatsheet/syntaxflow.md](cheatsheet/syntaxflow.md).

## Hit Triage

For each hit, preserve:

- `program_name`
- rule name or query text
- file path and line/function
- source value and sink value when available
- whether the path is reachable in production
- sanitizer or validation evidence
- runtime endpoint or function that can confirm the issue

Classify hits:

| Class | Meaning | Next step |
|---|---|---|
| `candidate` | Data-flow looks plausible but no runtime proof yet | Read code and build test case |
| `confirmed-static` | Source-to-sink is validated but runtime not tested | Keep as candidate or static finding, depending on scope |
| `confirmed-runtime` | Static hit and runtime behavior align | Create evidence and vulnerability records |
| `rejected` | Test code, dead path, sanitizer, unreachable, or false rule | Record false-positive reason |
| `degraded` | grep-only or SSA incomplete | Mark degraded and avoid proof claims |

## Miniapp Handoff

For miniapp source, SSA should produce an endpoint queue, not a report by itself:

```markdown
| priority | file:line | API/function | parameter clue | next dynamic test |
|---|---|---|---|
| P0 | pages/order/pay.js:88 | wx.request /api/order/pay | orderId, openid | BOLA/payment state check |
```

Then use [miniapp-workflow.md](miniapp-workflow.md) for source-to-traffic correlation and [mcp-tools-finder.md](mcp-tools-finder.md) for `http_fuzz` replay.

## Incremental Compile

Use incremental compile when a known project changes:

```json
{
  "target": "/path/to/miniapp_v2",
  "language": "js",
  "base_program_name": "miniapp_v1",
  "program_name": "miniapp_v2_diff"
}
```

Do not overwrite the old program name unless the user explicitly wants a fresh baseline.

## Evidence Mapping

| SSA output | Artifact mapping |
|---|---|
| Compile metadata | `source.capability: "static_dataflow"`, notes with language and target |
| Query rule and hit | `evidence_type: "static-analysis"`, artifact note or path |
| Validated file path | artifact `kind: "path"` |
| Runtime replay | separate HTTP or traffic-flow evidence |
| SSA unavailable | `degraded_markers: ["DEGRADED:SSA_UNAVAILABLE"]` |

High/Critical findings still need the gates in [artifact-quality-gates.md](artifact-quality-gates.md). Static analysis alone does not satisfy runtime impact unless the assessment scope explicitly accepts static-only findings.

## Failure Handling

| Failure | Action |
|---|---|
| SSA namespace unavailable | Mark `DEGRADED:SSA_UNAVAILABLE`; continue HTTP testing if Yakit HTTP works. |
| `program_name not found` | Re-check compile result and rerun compile if needed. |
| Unsupported language | Use grep/manual review as degraded static analysis or ask for supported decompiled output. |
| Query returns no hits | Add `check` probes, relax rule, or grep for sink/source keywords before retrying. |
| Query returns too many hits | Add call/opcode filters or split into narrower rules. |
| Compile is too slow or memory-heavy | Ask before continuing; split directories or use incremental compile. |

## Related

- SyntaxFlow cheatsheet: [cheatsheet/syntaxflow.md](cheatsheet/syntaxflow.md)
- MCP readiness: [mcp-readiness.md](mcp-readiness.md)
- MCP routes: [mcp-tools-finder.md](mcp-tools-finder.md)
- Miniapp workflow: [miniapp-workflow.md](miniapp-workflow.md)
- Business logic route: [business-flow-checklist.md](business-flow-checklist.md)
- Evidence pipeline: [evidence-pipeline.md](evidence-pipeline.md)

## Limits

- SSA is static. It cannot prove race conditions, payment state-machine flaws, or most business authorization failures alone.
- Obfuscated, incomplete, or partially decompiled code may hide flows or create false paths.
- Dynamic language features such as `eval`, variable functions, reflection, and generated code require manual follow-up.
- Grep is useful for hypotheses, but not a replacement for SSA data-flow proof.
