---
name: recon-workflow
description: SRC and crowdsourced recon workflow that turns asset collection into testable assets with authorization boundary, ownership confidence, priority scoring, and uncommon low-noise entries.
category: methodology
---

# Recon Workflow

## Applicable Scenarios

Use for SRC, crowdsourced testing, EDUSRC, or large enterprise asset ranges. Recon output is not a subdomain pile; it is a testable-asset table, authorization-boundary table, and next-test routing plan.

## Required Outputs

```text
Asset -> authorization basis -> ownership evidence -> confidence -> service state -> title/fingerprint -> function tags -> required resources -> priority -> next test entry
```

## Authorization Boundary Table

| Field | Requirement |
|---|---|
| Asset source | Program scope, user-provided target, certificate, ICP/registration, page copyright, business redirect, historical DNS |
| Scope basis | Explicit in-scope, same-entity proof, or user confirmation; keep these separate |
| Ownership evidence | Registration, certificate organization, page copyright, brand, business text, redirect chain |
| Confidence | `high`, `medium`, `low`; low confidence means ownership verification only |
| Test constraints | Forbidden actions, account limits, rate limits, data boundary |

Tool results provide leads only. They do not replace ownership proof. If an edge asset is not proven in scope, stop exploitation and strengthen attribution first.

## Priority Scoring

```text
Priority = core importance x function density x freshness x accessibility x role sensitivity
```

| Dimension | High-score signal |
|---|---|
| Core importance | Transaction, auth, backend, data, operations, education core system |
| Function density | Login, query, upload, export, payment, declaration, management modules |
| Freshness | Newly launched, gray release, test environment, recent change, new mobile version |
| Accessibility | 200, login page, API, admin page, registerable, test account available |
| Role sensitivity | Admin, teacher, finance, merchant, support, tenant, operator |

## Uncommon Low-Noise Entries

| Entry | Signal | Progression | False-positive filter |
|---|---|---|---|
| SPF/DMARC/DKIM | Missing or weak mail policy | Prove business-domain relation and policy risk without social engineering | Weak policy is not always high severity; follow program rules |
| SourceMap | `.js.map`, build source maps | Restore APIs, routes, environment config, cloud clues | Ordinary front-end code is low value without sensitive config or API impact |
| JSONP/CORS | callback parameter, cross-origin JSON | Test whether credentialed sensitive data or API results are exposed | Public data or no-credential CORS is low value |
| Captcha helper | Echo, removable field, permanent token, size parameter | Prove bypass of registration, login, SMS, or rate limits | Do not run destructive DoS validation |
| Cloud credential clues | AK/SK-like fields, bucket URL, upload policy | Route to minimum identity and bucket-boundary validation | Suspicious string and public static resource are not enough |

## Progression Path

1. Treat the program asset list as the primary source of truth.
2. Expand domains, IPs, apps, miniapps, and services, then add ownership evidence and confidence before testing.
3. Deduplicate and tag accessible services: login, API, admin, upload, payment, query, static build residue.
4. Use fingerprints for ranking and routing only. Avoid high-frequency POC scans across the whole set.
5. Route high-priority assets into business modeling or framework playbooks. Route low-confidence assets into attribution only.

## Evidence Requirements

- Keep asset attribution evidence separate from vulnerability impact evidence.
- Reports need scope basis, ownership proof, entry service, business impact, and minimal data proof.
- Uncommon entries must show usable impact, not only scanner output.

## Report Value

High-value assets are usually the intersection of core business and high function density. Secondary priority is edge assets with management capability and many APIs. Uncommon entries are useful for stable findings, but rating depends on business impact and vendor acceptance rules.
