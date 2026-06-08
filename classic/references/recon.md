---
name: recon
description: Recon routing index for Atomic Rain. Use it to classify frontend, backend/API/admin, registerable, miniapp, cloud, and mobile surfaces, then jump to the smallest phase, tool, or vulnerability playbook needed instead of loading a command warehouse.
category: methodology
---

# Recon Routing Index

This file is the Phase 1 entry point, not a long command catalog.

Use it to classify the target, choose the next reference, and preserve the evidence needed for first-pass testing. Tool syntax lives behind [tool-usage.md](tool-usage.md): classic maps to CLI tooling, toolPlus maps to MCP capability routing.

## Operating Rules

- Start from the current scan mode and [phase-guide.md](phase-guide.md) Phase 1.
- Read at most one tool route and one domain route before the first recon signal.
- Do not run high-volume subdomain brute force, mass port scans, credential attacks, or scanner sweeps without scope and rate confirmation.
- Treat scanner and OSINT output as candidate evidence until reproduced with status, length, timing, source, and scope context.
- If the target is a backend/API/admin surface, jump to section 9 before generic frontend enumeration.
- If the site is registerable, load [registerable-site-protocol.md](registerable-site-protocol.md) before business-logic testing.

## Target Classification

| Surface signal | Primary route | Why |
|---|---|---|
| HTML pages, SPA routes, user interaction | Section 5 + [phase-guide.md](phase-guide.md) | Frontend crawling and JS extraction are high ROI. |
| Pure JSON/XML, API host, admin panel, no public UI | Section 9 + [api-security.md](api-security.md) | Backend hosts need JS/source tracing and fingerprint-first testing. |
| User can self-register or create objects | [registerable-site-protocol.md](registerable-site-protocol.md) | Two-account BOLA/BFLA checks outrank generic payload tests. |
| Miniapp package, wx APIs, appid, openid/unionid | [miniapp-workflow.md](miniapp-workflow.md) | Miniapp auth and crypto flows are specialized. |
| Cloud bucket, AK/SK, metadata, vendor console | [cloud-security.md](cloud-security.md) | Impact depends on cloud identity and resource class. |
| Mobile APK/IPA, device traffic, app APIs | [mobile-app.md](mobile-app.md) | Static and dynamic app workflows have device/HITL boundaries. |
| Sensitive data or unauthenticated access | [sensitivity-matrix.md](sensitivity-matrix.md) + [resource-classification.md](resource-classification.md) | Severity must be based on data class and access boundary. |

## Recon Route Table

| Task | Read next | Preserve |
|---|---|---|
| Phase 1 scope planning | [phase-guide.md](phase-guide.md) | scope, scan mode, approved rate, exclusions |
| Tool/capability choice | [tool-usage.md](tool-usage.md) | capability, command/tool, output artifact |
| Passive OSINT | Section 4 | source URL/query, discovered asset, confidence |
| Subdomain and live host mapping | [tool-usage.md](tool-usage.md) | host, IP, status, title, tech, redirect chain |
| Port/service fingerprinting | [tool-usage.md](tool-usage.md) | host, port, protocol, banner, version |
| Directory/API discovery | [tool-usage.md](tool-usage.md) + [api-security.md](api-security.md) | endpoint, method, auth state, response class |
| JS/API extraction | Section 5 | JS URL, endpoint, base URL, secret-like token |
| Registerable workflows | [registerable-site-protocol.md](registerable-site-protocol.md) | account A/B, object IDs, role boundary |
| Miniapp workflows | [miniapp-workflow.md](miniapp-workflow.md) | appid, package source, APIs, auth fields |
| Email auth checks | [vuln/email-spoofing.md](vuln/email-spoofing.md) | SPF, DKIM, DMARC, mail-sending approval |
| Reportable attack surface | Section 10 | asset table, high-priority queue, first-pass signals |

## High-ROI First-Pass Signals

Prioritize these before broad payload testing:

- `admin`, `manage`, `console`, `backend`, `internal`, `api`, `gateway`, `swagger`, `openapi`, `actuator`, `druid`, `nacos`.
- 401/403/404 differences across authenticated, unauthenticated, and second-account requests.
- JS `baseURL`, `apiUrl`, `request(`, `/v1/`, `/v2/`, `openid`, `unionid`, `tenantId`, `orgId`, `userId`, `orderId`.
- Exposed configuration: `.env`, source maps, backup archives, `WEB-INF/web.xml`, `application.yml`, `robots.txt`, `sitemap.xml`.
- Framework fingerprints: Shiro, Spring Boot, Fastjson/Jackson, Druid, Swagger/OpenAPI, Nacos, Tomcat, WebLogic.
- Cloud and infra ports: Redis, MongoDB, Elasticsearch, Docker API, Kubernetes API, Prometheus, RabbitMQ.

Route framework signals to the focused playbook only after the fingerprint is credible:

| Signal | Read next |
|---|---|
| Shiro cookie or `rememberMe` behavior | [vuln/shiro.md](vuln/shiro.md) |
| Spring Boot, Actuator, Gateway, Jolokia | [frameworks/spring-boot.md](frameworks/spring-boot.md) + [vuln/spring-vuln.md](vuln/spring-vuln.md) |
| Fastjson/Jackson autoType or Java JSON errors | [vuln/fastjson-jackson.md](vuln/fastjson-jackson.md) |
| Swagger, Actuator, Druid, Nacos exposure | [vuln/swagger-actuator-druid.md](vuln/swagger-actuator-druid.md) |
| BOLA, BFLA, unauthenticated API | [api-security.md](api-security.md) + [business-flow-checklist.md](business-flow-checklist.md) |
| Weak/default credentials | [weak-password-generation.md](weak-password-generation.md) |

## 4. Passive OSINT Index

Use passive collection when scope is broad or before touching the target.

| Source | Look for | Next route |
|---|---|---|
| Search engines | admin/login pages, config files, backups, public docs, index listings | Section 5 or 9 |
| GitHub/code search | domains, API keys, JDBC strings, `.env`, private package configs | [sensitive-info-exploitation.md](sensitive-info-exploitation.md) |
| Certificate transparency | subdomains, staging/dev hosts, historical names | [tool-usage.md](tool-usage.md) |
| DNS/WHOIS/MX/TXT | mail auth, cloud vendors, NS/SOA, zone-transfer clue | [vuln/email-spoofing.md](vuln/email-spoofing.md) or [cloud-security.md](cloud-security.md) |
| Procurement/recruiting | stack, vendor products, cloud provider, legacy systems | framework-specific route |
| Public documents | usernames, internal paths, software versions, metadata | [sensitivity-matrix.md](sensitivity-matrix.md) |
| School/company identifiers | student ID, employee ID, department code patterns | [registerable-site-protocol.md](registerable-site-protocol.md) |

Minimal dork categories:

```text
site:target.tld admin login manage backend api
site:target.tld filetype:pdf OR filetype:xls OR filetype:doc
site:target.tld ext:env OR ext:yml OR ext:sql OR ext:bak OR ext:log
"target.tld" password OR api_key OR secret OR token OR jdbc
```

## 5. Frontend and SPA Flow

Use this route when the target exposes HTML pages, navigation, or user interaction.

1. Map live pages and redirects through [tool-usage.md](tool-usage.md).
2. Extract JS routes, API base URLs, source maps, and secret-like constants.
3. Normalize endpoints by host, path, method, auth requirement, and object ID shape.
4. If registration is possible, switch to [registerable-site-protocol.md](registerable-site-protocol.md).
5. If endpoints expose user, order, tenant, organization, or file objects, load [business-flow-checklist.md](business-flow-checklist.md) before vuln payload files.
6. Send confirmed API candidates to [api-security.md](api-security.md); do not start with generic payload lists.

Frontend output should be a small queue:

```markdown
| priority | endpoint/page | signal | next test | evidence |
|---|---|---|---|---|
| P0 | /api/v1/users/{id} | object ID + auth | BOLA A/B test | JS route + baseline response |
```

## 9. Backend/API/Admin Protocol

Backend/API/admin surfaces are not generic frontend sites. Their best evidence often comes from where the host was discovered and which framework it runs.

### 9.1 Trigger

Treat the target as backend/API/admin if any signal matches:

- Response is JSON/XML or a narrow login/admin panel with little public UI.
- Hostname includes `api`, `admin`, `backend`, `internal`, `manage`, `gateway`, `console`.
- Domain was found in frontend JS, mobile traffic, miniapp source, CORS, CSP, or response headers.
- Swagger/OpenAPI, Actuator, Druid, Nacos, GraphQL, or framework-specific management endpoints appear.

### 9.2 Flow

| Phase | Action | Route |
|---|---|---|
| 0. Source trace | Record where the backend host came from: JS, headers, CORS/CSP, app traffic, miniapp source. | Section 5 or [miniapp-workflow.md](miniapp-workflow.md) |
| 1. Fingerprint first | Identify framework, middleware, management endpoint, auth style, and error shape. | [tool-usage.md](tool-usage.md) |
| 2. Interface discovery | Check API docs, route lists, versioned paths, GraphQL, Actuator/Druid/Nacos surfaces. | [api-security.md](api-security.md) |
| 3. Auth boundary | Compare unauthenticated, low-privilege, and second-account access. | [registerable-site-protocol.md](registerable-site-protocol.md) |
| 4. Targeted vuln route | Open only the matching framework/vuln file from the table above. | focused vuln playbook |
| 5. Impact triage | Classify data/resource exposure before severity. | [sensitivity-matrix.md](sensitivity-matrix.md) |

### 9.3 Frontend vs Backend Difference

| Step | Frontend/SPa | Backend/API/Admin |
|---|---|---|
| Discovery | subdomains and pages | JS/source/header/app trace |
| First high-ROI action | crawl and JS extraction | fingerprint and interface docs |
| Auth testing | after endpoint normalization | early, with auth/no-auth/A-B comparison |
| Automation | constrained crawler/scanner | focused endpoint and framework checks |
| Deep route | business flow or vuln signal | framework vuln or API auth boundary |

### 9.4 Backend Reminders

- Put JS/source tracing before directory brute force when the backend host was discovered from frontend or app artifacts.
- Do not run generic scanners before fingerprinting management surfaces.
- Swagger/OpenAPI, Actuator, Druid, and Nacos are interface and config sources; treat them as pivots into API auth and sensitive-data triage.
- Weak passwords should be target-context dictionaries from [weak-password-generation.md](weak-password-generation.md), not broad brute force.

## 10. Attack Surface Output

End Phase 1 with a compact artifact, not a transcript.

```markdown
# Attack Surface - target.tld

## Assets
| host | ip | status | tech | auth | source |
|---|---|---|---|---|---|

## Priority Queue
| priority | target | type | signal | next route |
|---|---|---|---|---|

## First-Pass Signals
- [ ] JS route exposes object ID API:
- [ ] Backend management endpoint:
- [ ] Sensitive/config artifact:
- [ ] Registerable two-account flow:
- [ ] Framework-specific route:
```

Use this artifact to decide Phase 2. If no P0/P1 signal exists, stop broadening and ask whether the user wants deeper recon scope, additional credentials, or a slower scan mode.
