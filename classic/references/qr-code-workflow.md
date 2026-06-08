---
name: qr-code-workflow
description: QR-code workflow that treats QR codes as information-transfer channels for URL parameters, Base64 strings, OAuth tickets, scan-login scenes, payment/verification order IDs, and activity entitlement IDs.
category: methodology
---

# QR Code Workflow

## Applicable Scenarios

Use for scan login, QR payment, verification codes, activity QR codes, entitlement claims, OAuth authorization, miniapp/official-account jumps, certificate query, or any QR code carrying business state. The QR code itself is not the issue; the carried fields and state binding are.

## Entry Signals

| Carrier | Fields to inspect |
|---|---|
| URL | path, query, redirect, state, returnUrl |
| Base64/encoded string | decoded parameters, timestamp, signature, business ID |
| OAuth ticket/code | code, ticket, state, redirect_uri, Referer |
| Scan-login scene | scene, uuid, loginToken, pollingId, sessionId |
| Payment/verification | orderId, payId, verifyCode, couponId, shopId |
| Activity/entitlement | activityId, benefitId, userId, inviteCode, campaignId |

## Four-Stage Flow

```text
Generate QR code
-> poll scan status
-> scanner confirms
-> web/app lands in login, binding, payment, verification, or entitlement claim
```

## Progression Path

1. Decode the QR code and classify it as URL, encoded string, ticket, scene, order ID, or activity/entitlement ID.
2. Capture all four stages: generation, polling, scan confirmation, and landing.
3. Verify whether ticket/scene binds to the initiating session, scanner identity, one-time state, and expiry.
4. Run A/B comparison: A generates the code, B scans or confirms, then observe final identity and state.
5. For payment, verification, and entitlement codes, test reuse, cross-account use, order/benefit ID mutation, expiry bypass, and concurrent confirmation.
6. For OAuth code/ticket leakage, prove only with authorized test resources whether it can be exchanged for login state or binding.

## Key Turns

| Initial observation | Turn |
|---|---|
| QR content is encrypted | Classify field source by capturing generation and landing APIs |
| UI only says scanned | Continue until final login or binding is proven |
| OAuth whitelist is strict | Check controllable pages, images, rich text, and Referer leakage inside whitelisted domains |
| Reuse fails | Pivot to concurrent confirmation, stale validity, or status refresh |
| Signed parameter exists | Compare which fields are actually bound by the signature |

## Evidence Requirements

- QR content type and masked fields.
- Generation, polling, confirmation, and landing requests/responses.
- Initiating session identity, scanner identity, and final login/binding/payment/verification identity.
- A/B account comparison and negative control.
- Final server-side state: session, binding relation, order, verification record, or entitlement record.

## False-Positive Filters

- Encrypted QR content is not a vulnerability.
- Seeing "scanned" is not login success.
- Open redirect is not account takeover unless code/ticket can become login state or binding.
- If Referer is stripped or ticket binds to session, the chain is not valid.
- Do not run destructive refresh or polling DoS tests.

## Report Value

High value comes from wrong login, wrong binding, repeated verification, unauthorized payment, entitlement misdelivery, or OAuth credential landing. Visible QR parameters or simple page jump are usually low value.
