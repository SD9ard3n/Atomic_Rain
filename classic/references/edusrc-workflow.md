---
name: edusrc-workflow
description: EDUSRC workflow for university, certificate site, unified auth, academic affairs, logistics, billing, people picker, declaration systems, and upload-to-cloud chains.
category: methodology
---

# EDUSRC Workflow

## Applicable Scenarios

Use for universities, education groups, certificate sites, unified authentication, WebVPN, academic affairs, student affairs, logistics, billing, declaration systems, people pickers, miniapps, and upload systems. Split evidence by step; do not inflate a weak single signal into a high-severity chain.

## Entry Signals

| Signal | Pivot |
|---|---|
| Certificate, ticket, score, payment query | Check whether extra identity fields are returned |
| Unified auth or password recovery | Test whether leaked fields can complete recovery and final login |
| People picker or organization selector | Enumerate names, student IDs, departments, phone/email fields |
| Academic/declaration systems | Test student, teacher, department, declaration object ownership |
| Logistics, recharge, billing | Test query, recharge, refund, bill, and object IDs |
| Upload path or image URL | Extract MinIO/OSS/COS bucket, region, and key |
| Same favicon/title/vendor system | Cluster, then verify scope and authorization before testing |

## Combination Chain

```text
Query API leaks identity fields
-> unified-auth password recovery uses those fields
-> final login to student/business system
-> people picker enumeration or declaration/academic IDOR
-> upload response exposes MinIO/OSS path
-> remove path segments to test ListObject
-> minimally test PUT write, same-name overwrite, and permission boundary
```

## Progression Path

1. Build an asset table: school entity, business system, unified-auth entry, subsystem entry, mobile entry, and authorization basis.
2. Start with query interfaces. Record query parameters and extra response fields; store only field type and masked examples.
3. If fields can be used for recovery, prove the full path with a self-owned or authorized test account through final login.
4. After login, prioritize people picker, academic/declaration objects, logistics/billing, upload, export, and notification functions.
5. For every object ID, use A/B account ownership comparison. Use self-created records for write/delete tests.
6. When upload returns cloud paths, route to [cloud-security.md](cloud-security.md) for minimum-impact permission validation.

## Key Turns

| Initial observation | Turn |
|---|---|
| Query requires only name or number | Check response for extra ID, phone, student ID, email, organization fields |
| Unified auth blocks the subsystem | Find original login, IP, backup domain, or APIs with delayed auth |
| Weak password fails | Pivot to JS, user manual, initial password rule, recovery, query API |
| Empty page after response change | Continue only if APIs return real business data |
| People picker returns names only | Expand pagination, organization, role, keyword, and response fields |
| Upload returns URL | Extract bucket/region/key and test list/write/overwrite minimally |

## Evidence Requirements

| Step | Required evidence |
|---|---|
| Query leakage | Request, masked response, non-public field explanation |
| Account takeover | Self-owned/authorized account, recovery chain, final login, accessible scope |
| People picker | Enumeration parameters, pagination/organization control, masked field types, negative control |
| Declaration/academic IDOR | Object ownership, A/B operation difference, self-created write target |
| Cloud storage | bucket/region/key, list/write/overwrite minimal proof |

## False-Positive Filters

- Public-only query fields are low value.
- Account takeover requires final login; reaching the next recovery step is not enough.
- Front-end response modification is not unified-auth bypass unless back-end APIs return real data.
- People picker data must be judged against public directory exposure.
- Delete, withdraw, overwrite, or destructive operations must use self-created or explicitly authorized records.
- Object storage does not execute uploaded scripts; do not report script upload as RCE.

## Report Value

EDUSRC value often comes from a packaged chain: information leakage, account takeover, IDOR, cloud-storage permission, and backend capability. Keep each step independently evidenced and masked. Single low-risk findings can be chain entries, but severity depends on final authenticated access, sensitive business data, or stable cloud/data permission impact.
