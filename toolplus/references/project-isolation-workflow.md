---
name: project-isolation-workflow
description: Lightweight toolPlus Yakit project isolation protocol. Use it for P0.4 project context checks, HITL database switching, safe query_http_flow filters, and dangerous data-operation boundaries.
category: methodology
---

# Project Isolation Workflow

Use this file when toolPlus needs Yakit project/database context, traffic history, flow tags, or multi-target separation.
It is a runtime protocol, not a Yakit tutorial.

Primary routes:

- MCP readiness and namespace discovery: [mcp-readiness.md](mcp-readiness.md)
- MCP scenario routing and query filters: [mcp-tools-finder.md](mcp-tools-finder.md)
- Evidence tagging and artifact mapping: [evidence-pipeline.md](evidence-pipeline.md)
- Project task ledger: [project-workflow.md](project-workflow.md)

## Operating Rules

- Run project context during P0.4 before relying on Yakit traffic history, flow tags, SSA, codec, brute force, or project database actions.
- Discover actual MCP namespaces first. Treat names such as `get_current_database_context`, `list_project_databases`, `create_project_database`, and `switch_current_project_database` as capability aliases.
- Never auto-switch project databases. Ask before every `switch_current_project_database` call.
- Creating a project database is a write action. Ask before creation, especially when `switchToCurrent` may switch context.
- If project context is unavailable, mark `DEGRADED:DB_CONTEXT_UNKNOWN`; do not switch databases or rely on history isolation.
- In `default` or shared databases, never query broad history without tight target filters.
- Do not delete broad traffic history or payload data unless the user explicitly approves the exact scope.

## P0.4 Context Check

| Step | Action | Preserve |
|---|---|---|
| 1 | Confirm Yakit MCP availability through [mcp-readiness.md](mcp-readiness.md). | endpoint, server name, namespace |
| 2 | Call current database context with the discovered project-context tool. | project name, project id, database path |
| 3 | Compare current project with the target and user intent. | expected target, current project, mismatch |
| 4 | If mismatch exists, list project databases before any switch. | candidate project id/name, last updated, description |
| 5 | Ask before create or switch. | user approval text, target project id/name |
| 6 | Re-check current database after create/switch. | post-action project id/name/path |

Stop Yakit history-dependent work if step 2 or step 6 cannot confirm the expected context.

## Project Decision Table

| Current state | Default action | Boundary |
|---|---|---|
| Current project clearly matches this target | Continue. Record context in notes/assets. | Still use tight `query_http_flow` filters. |
| Current project is `default`, task is quick/one-off | Continue only with strict URL filters. | Recommend dedicated project if evidence/reporting will continue. |
| Current project is `default`, task is SRC/bounty/client or multi-day | Ask to create or choose a dedicated project. | Creation/switch is HITL. |
| Current project belongs to another target | Ask whether to switch, create, or stay degraded. | Never switch automatically. |
| Project DB context unavailable | Mark `DEGRADED:DB_CONTEXT_UNKNOWN`. | No switch or history-isolation claims. |

## Naming Guidance

Use predictable, target-scoped names:

| Scenario | Pattern |
|---|---|
| SRC or bounty target | `<target>_<yyyy-mm>` |
| Long enterprise engagement | `<customer>_<yyyy-q>` |
| Large org with separate surfaces | `<org>_<surface>_<yyyy>` |
| Temporary experiment | stay in `default` with tight filters |

Avoid names such as `test`, `tmp`, `aaa`, or unrelated project nicknames.

## HITL Prompts

Use concise, explicit prompts before write/switch actions.

```text
Current Yakit project is <current_name> (id=<current_id>).
Target is <target>.
I need to switch to <candidate_name> (id=<candidate_id>) before querying or tagging target traffic.
Confirm switch? [Y/N]
```

```text
No dedicated Yakit project was found for <target>.
Create project <project_name> and switch to it after creation?
This changes where query_http_flow, tags, and generated traffic are stored. [Y/N]
```

After approval, re-check context and report the result before continuing.

## Query Discipline

When context is shared, unknown, or `default`, require narrow filters:

```json
{
  "includeInUrl": ["target.example"],
  "excludeSuffix": [".js", ".css", ".png", ".jpg", ".ico", ".woff", ".svg", ".gif"],
  "excludeKeywords": ["heartbeat", "analytics", "track", "sentry", "cdn"],
  "haveBody": true,
  "pagination": {"page": 1, "limit": 50, "order": "desc", "orderby": "id"}
}
```

For auth/session discovery, add path and method filters such as `/login`, `/auth`, `/oauth`, `/sso`, `/token`, and `POST`.
For upload discovery, add `multipart/form-data` and `POST`.
For crypto/signature clues, search request content for `encrypt`, `encryptedData`, `cipher`, or `sign`.

Preserve `id`, URL, method, auth context, request, response, `status_code`, `body_length`, `duration`, and tags before using the flow as evidence.

## Data Operations Boundary

| Operation | Default | Reason |
|---|---|---|
| `get_current_database_context` | Allowed after namespace discovery | Read-only readiness check |
| `list_project_databases` | Allowed when a switch/create decision is needed | Read-only selection |
| `create_project_database` | HITL | Creates persistent project state |
| `switch_current_project_database` | HITL every time | Wrong switch pollutes traffic, tags, payloads, and reports |
| `set_tag_for_http_flow` | Allowed after context and flow are confirmed | Tag is index, not evidence |
| `delete_http_flow` with narrow filter | HITL with exact filter shown | Deletion is irreversible |
| `delete_http_flow` with `deleteAll` or empty filter | Block unless explicitly approved by user for that database | Equivalent to broad destructive cleanup |
| `delete_payload` or dictionary cleanup | HITL | May affect future tests |

Prefer tags over deletion. Use `KEEP`, `VULN_*`, `candidate`, `confirmed`, or `blocked` tags to manage evidence without losing history.

## Failure Handling

| Failure | Action |
|---|---|
| Current database context returns empty | Mark `DEGRADED:DB_CONTEXT_UNKNOWN`; ask user to verify Yakit/MCP. |
| Candidate project id is stale | Re-run list before switching. |
| Switch call succeeds but context does not change | Stop project-dependent actions; ask user to restart/refresh Yakit. |
| Query returns other targets' traffic | Re-check project context, tighten filters, and mark the query result untrusted until corrected. |
| Multiple Yakit instances may share one database | Ask user to confirm active proxy/Yakit instance; avoid writes until clear. |

## Related

- MCP readiness: [mcp-readiness.md](mcp-readiness.md)
- MCP query filters: [mcp-tools-finder.md](mcp-tools-finder.md)
- Evidence workflow: [evidence-pipeline.md](evidence-pipeline.md)
- Project ledger: [project-workflow.md](project-workflow.md)

## Limits

- Yakit does not provide reliable cross-project joins; compare projects by switching with HITL and exporting/recording compact results.
- Project switching is not a security proof. It only protects evidence isolation and query precision.
- `default` is acceptable for quick or local experiments, but not for long-running reportable work without strict filters.
