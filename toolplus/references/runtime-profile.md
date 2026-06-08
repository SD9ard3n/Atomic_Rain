---
name: runtime-profile
description: Atomic Rain repository-vs-runtime packaging profile, deployment profile definitions, and validation policy for classic, toolPlus, and deployed mixed skill copies.
category: methodology
---

# Runtime Profile

Atomic Rain has two layers:

| Layer | Purpose | Included in runtime skill package |
|---|---|---|
| Repository documentation | README, public explanation, roadmap, contribution context | No |
| Behavior evals | `evals/` prompts and assertions for benchmark iterations | No |
| Variant source manifest | `source/variant-manifest.json` shared/overlay governance metadata | No |
| Runtime tier manifest | `source/runtime-tiers.json` optional full/lean packaging policy | No |
| Artifact contracts | `schemas/` evidence, vulnerability, and report schemas | Yes |
| Runtime skill | SKILL.md, references, scripts, assets needed by Codex during execution | Yes |

## Profiles

| Profile | Meaning | Expected use |
|---|---|---|
| `classic` | Pure CLI-oriented runtime package | No Yakit/Chrome MCP available |
| `toolplus` | Pure MCP-first runtime package | Yakit MCP + Chrome MCP available |
| `deployed-mixed` | Local deployment copy that intentionally includes toolPlus plus classic tooling docs | Transitional or personal local deployment only |

## Packaging Rule

`README.md`, `evals/`, and `source/` are repository-maintenance material. They may stay in the repository, but runtime packaging should exclude them unless the user explicitly asks for repository docs, benchmark assets, or variant-governance metadata.

`full` runtime is the default and preserves the complete skill. `lean` runtime is optional and currently link-safe: it keeps the same file graph while the heaviest shared references are compressed in place. Do not enable file-level pruning until the exported package passes `scripts/lint_skill.py`.

`SKILL.md` must not depend on README content. All execution-critical instructions must live in `SKILL.md` or `references/`.

`schemas/` is runtime material. Evidence, vulnerability, and report artifacts should conform to those contracts when generated.

Artifact quality gates are defined in `references/artifact-quality-gates.md`. The validator is non-blocking when no `artifacts/` directory exists, but any JSON/JSONL artifacts that are present must pass dedupe, evidence-reference, severity, blocked-state, and degraded-mode checks.

## Validation Rule

Run `python scripts/validate_all.py` before publishing either runtime profile. This includes lint, semantic checks, and artifact/eval contract validation.

Run `python scripts/build_variant.py check --peer <other-variant-root>` to enforce the single-source manifest. Use `export --dest <dir>` for non-destructive runtime export.

Use `python scripts/package_runtime.py --tier lean <dest>` or `python scripts/build_variant.py export --tier lean --dest <dest>` to create a lightweight runtime package. The default is still `full`; every lean export must pass `python <dest>/scripts/lint_skill.py` before publishing.

When checking a local deployment copy, run semantic checks with an explicit profile once supported by the caller:

```bash
python -u scripts/semantic_check.py --profile deployed-mixed
```
