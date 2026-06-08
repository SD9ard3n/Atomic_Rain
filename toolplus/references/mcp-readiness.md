---
name: mcp-readiness
description: toolPlus MCP readiness checklist for verifying Yakit SSE, Chrome streamable HTTP, actual server names, tool namespaces, database context, browser tab access, and component-level degraded-mode decisions before active testing.
category: methodology
---

# MCP Readiness Checklist

Use this before active toolPlus testing and whenever MCP behavior changes mid-run.

## Required Endpoints

| Component | Expected endpoint | Required capability | If unavailable |
|---|---|---|---|
| Yakit MCP | `http://127.0.0.1:11432/sse` | HTTP fuzzing, flow query, SSA, codec, brute, project DB | Stop Yakit-dependent actions; recommend classic for HTTP/SSA/codec work. |
| Chrome MCP | `http://127.0.0.1:12306/mcp` | Browser automation, tab state, screenshots, console/network capture | Stop browser automation only; Yakit HTTP fuzzing can continue. |

## Startup Checks

1. Inspect the actual MCP server list and record the server names. Do not assume the Chrome server is named `chrome`; streamable HTTP configs may expose names such as `streamable-mcp-server`.
2. Map capabilities to the actual tool namespaces visible in the session. Treat examples like `mcp__chrome__chrome_navigate` as capability aliases until verified.
3. Call Yakit project context with the discovered Yakit namespace: `get_current_database_context` or the equivalent exposed tool.
4. Call Chrome tab discovery with the discovered Chrome namespace: `get_windows_and_tabs` or an equivalent tab/window listing tool.
5. Write the endpoint status, server names, namespace mapping, project database, and Chrome tab status to `assets.md` under `## 环境`.

## Capability Alias Table

| Capability | Preferred tool name when available | Notes |
|---|---|---|
| Current Yakit database | `mcp__yaklang__get_current_database_context` | Never auto-switch databases; ask before `switch_current_project_database`. |
| HTTP fuzzing | `mcp__yaklang__http_fuzzer` | Required for first-pass HTTP tests. |
| Flow history | `mcp__yaklang__query_http_flow` | Use for login-state request recovery and evidence correlation. |
| SSA compile/query | `mcp__yaklang__ssa_compile` + `mcp__yaklang__ssa_query` | If SSA alone fails, grep may be used only as degraded static analysis. |
| Codec workflow | `mcp__yaklang__exec_codec` | Required for MCP-first crypto/encoding workflows. |
| Browser tabs | `mcp__chrome__get_windows_and_tabs` | Equivalent names are acceptable after namespace discovery. |
| Navigate/screenshot/console | `mcp__chrome__chrome_navigate`, `mcp__chrome__chrome_screenshot`, `mcp__chrome__chrome_console` | Browser-only; absence does not block Yakit fuzzing. |

## Degraded-Mode Matrix

| Failure | Allowed continuation | Required marker |
|---|---|---|
| Yakit MCP down | Browser-only observation may continue, but HTTP fuzzing, query_http_flow, SSA, codec, brute, project DB operations stop. Recommend switching to classic for HTTP testing. | `[DEGRADED:YAKIT_MCP_DOWN]` |
| Chrome MCP down | Continue Yakit HTTP fuzzing, flow query, SSA, codec, and project DB workflows. Browser automation, screenshot, console, and Chrome network capture stop. | `[DEGRADED:CHROME_MCP_DOWN]` |
| SSA compile/query down while Yakit HTTP works | Continue HTTP testing. Use grep as temporary static analysis only if the output is marked degraded and no data-flow claim depends solely on grep. | `[DEGRADED:SSA_UNAVAILABLE]` |
| Codec tool down | Continue non-crypto HTTP testing. Do not claim encrypted-parameter coverage until codec or an approved alternative is available. | `[DEGRADED:CODEC_UNAVAILABLE]` |
| Project DB context unavailable | Do not switch databases or rely on Yakit history isolation. Direct HTTP fuzzing may continue only after noting the missing context. | `[DEGRADED:DB_CONTEXT_UNKNOWN]` |

## External Resource Boundary

OOB, DNSLog, webhook, temporary email, public SMS, and listener infrastructure are not MCP readiness items. They require P3.5 approval before use, even when MCP is fully healthy.
