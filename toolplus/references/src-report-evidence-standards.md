---
name: src-report-evidence-standards
description: SRC report evidence standards and false-positive filters that convert real reports into entry signals, progression paths, key turns, evidence requirements, and rating expectations.
category: methodology
---

# SRC Report Evidence Standards

## Applicable Scenarios

Use before reporting, when filtering false positives, when estimating rating, or when distilling external reports into Atomic Rain rules. Response difference is a lead; final server-side state is evidence.

## Four Report-Learning Elements

| Element | Convert to skill rule |
|---|---|
| Vulnerability origin | Entry signal: which flow node, field, state, or configuration created the opportunity |
| Vulnerability type | Risk class: auth, IDOR, payment, cloud, framework, information leakage, etc. |
| Exploitation method | Progression path: how the lead became impact, including mutation, replay, concurrency, or cross-account checks |
| Obstacle resolution | Key turn: what failed, how the path pivoted, and which false positives were filtered |

Output rules as:

```text
Entry signal -> progression path -> key turn -> evidence requirements -> false-positive filter -> rating expectation
```

## Evidence Matrix

| Area | Weak evidence | Strong evidence |
|---|---|---|
| Auth/captcha | Front-end enters next step | Registration, login, password change, or binding finally succeeds |
| Password recovery | Token/page transition | New password works and final login is proven |
| Payment/exchange | Page shows low price or temporary order success | Abnormal paid amount and stable goods/entitlement/order state |
| Race/replay | Multiple HTTP 200 responses | Account assets, coupons, entitlements, or orders change multiple times |
| IDOR | Changed ID returns data | A session reads/modifies/deletes/exports B object with ownership proof |
| Cloud storage | Object URL or AccessDenied | Minimal proof of list, write, overwrite, or non-public read |
| Framework exposure | Login page, empty UI, health | Version, permission, API, backend capability, and data impact closure |
| Recon | Tool hit | Scope basis, ownership evidence, testable entry, and impact path |

## Skill Rule Fields

### Entry Signal

Name the trigger precisely: login form, recovery flow, order confirmation, payment callback, people picker, SourceMap, upload response, RuoYi page, Blade static JS, QR generation API.

### Progression Path

Record the minimal chain from lead to impact: state nodes, controllable inputs, expected output, actual output, and next pivot. Do not record only a payload.

### Key Turn

Preserve failure-to-pivot knowledge: weak password failed so move to JS/recovery; balance response failed so move to price response; SSO blocked domain so move to original entry/API; single replay failed so move to placeholder creation.

Use this template for every failed path; reusable cross-domain examples live in [src-failure-pivots.md](src-failure-pivots.md):

```text
Failure symptom -> why it is not established -> next pivot -> evidence that would establish it -> rating boundary
```

Keep report evidence here; use [src-failure-pivots.md §报告前过滤](src-failure-pivots.md) when a weak signal needs a next-pivot and false-positive boundary.

### Evidence Requirements

Require normal baseline, modified request, negative control, final state, and masked impact sample. For account, phone, ID number, token, real domain, or IP, store only field type, hash, or partial masking.

### False-Positive Filters

- Response modification that only affects front end is not high severity.
- A `success` response without final object, account, order, or permission state change is not enough.
- Saving content is not XSS impact until a target output point and role are proven.
- Empty Swagger/API docs, interface names, and backend login pages are entry signals only.
- Public static resources, AccessDenied, NoSuchBucket, and suspicious cloud keys require permission-boundary evidence before rating.
- JWT decoding, `alg=none` rejection, or 401 after payload modification shows no JWT vulnerability by itself.
- Entering a page, temporary order success, or tool output cannot be rated high without final server-side impact.
- Temporary order success followed by automatic refund/close is not stable zero-price purchase.
- Login page existence, empty Swagger UI, Druid login page, or Actuator health/info is usually low value.
- AccessDenied only proves a bucket exists or is protected.
- Tool output does not prove asset ownership.
- Client-side bypass is not the vulnerability unless server-side impact follows.

## Current Rating Boundaries

| Signal | Low / not enough | Medium | High candidate |
|---|---|---|---|
| false/null interface | hidden endpoint or success only | non-public object read/write | permission, binding, or business state change |
| XSS | self-trigger or saved only | ordinary cross-user trigger | high-privilege backend with sensitive impact |
| SMS/captcha | front-end timer bypass | server frequency bypass reaching vendor threshold | subject mismatch causing login/register/reset/binding |
| Swagger/API | empty docs or route list | sensitive config | callable backend query/export/config action |
| Coupon/race | multiple 200 responses | stable multiple discounts | fulfillment or asset loss at scale |
| Paid resource | preview URL | single paid resource accessible | predictable/bulk paid resources or long-lived CDN bypass |
| Cloud | clue, AccessDenied, public static file | list/read non-public object | write/overwrite/account capability with HITL |
| JWT | decodable payload | accepted modified low-impact field | identity/role/tenant change with permission impact |
| Cancel/delete IDOR | own object only | one foreign object state change | predictable/bulk state changes or payment/refund impact |
| Weak password | one ordinary account | multiple accounts same rule | high-privilege/default super-admin with scoped same-system proof |

## Rating Expectation

| Evidence closure | Expectation |
|---|---|
| Final account takeover, stable money/entitlement loss, high-privilege backend, non-public sensitive data | High-value/high-severity candidate |
| Limited IDOR read, low-impact write, business config leakage | Medium candidate |
| Ordinary SourceMap code, weak mail policy, public resource bucket, empty component page | Low/info candidate |

## Pre-Report Self Check

```text
1. Is scope and asset ownership proven?
2. Is the entry signal and progression path explicit?
3. Is final server-side state changed or sensitive data exposed?
4. Is there A/B account or normal/abnormal comparison?
5. Are sensitive fields masked?
6. Were front-end illusions, temporary states, tool false positives, and low-value exposures filtered?
```
