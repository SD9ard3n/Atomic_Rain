---
name: src-business-logic-state-machine
description: SRC business logic state-machine workflow for payment, coupon, purchase limit, subscription, trial, refund, verification, points mall, response price trust, and async validation cases.
category: methodology
---

# SRC Business Logic State Machine

## Applicable Scenarios

Use when a flow contains checkout, coupons, purchase limits, subscription, trial, order close, refund, verification, points mall, response price trust, or async delayed validation. The goal is to model state transitions, not list vulnerability names.

## Entry Signals

| Signal | Pivot |
|---|---|
| First-order price, new-user price, purchase limit | Test stale checkout and multi-client placeholders |
| Auto-renewal, subscription, upgrade price difference | Test cancel/reuse and stale payment pages |
| Order close with coupon return | Test coupon rollback and old payment page validity |
| Coupon, voucher, points, balance | Test concurrent replay and atomic deduction |
| Quantity, amount, price, points fields | Test decimal, negative, overflow, and server recalculation |
| Points mall, disabled exchange button | Separate balance response, price response, order submit, fulfillment |
| Refund, verification, shipment, async audit | Wait for final state before rating |

## Generic State Machine

```text
Create operation/placeholder state
-> stay on payment/confirmation/upgrade/verification page
-> external state changes: cancel, close, return coupon, refund, reclaim eligibility
-> submit stale state or submit concurrent states
-> server fails to recalculate eligibility, count, amount, inventory, entitlement, or order state
-> final entitlement, goods, order, balance, points, or verification state remains stable
```

Record every candidate as:

```text
Entry signal -> controllable input -> expected output -> actual output -> next pivot -> key evidence -> false-positive filter
```

## Progression Path

1. Map nodes: detail page, balance/eligibility query, order creation, confirmation, payment page, callback, order list, fulfillment, refund, close.
2. Mark where the server must recheck amount, quantity, coupon state, inventory, purchase count, subscription state, verification state, and refund state.
3. Record controllable fields such as `orderId`, `couponId`, `skuId`, `quantity`, `amount`, `price`, `points`, `userId`, `activityId`, `verifyCode`, `status`.
4. If single-request replay fails, pivot to multi-client placeholders, concurrent placeholder creation, concurrent eligibility consumption, or stale-state reuse after close/refund/coupon return.
5. Use low-value goods, test accounts, self-owned orders, and self-created verification records.

## Key Patterns

失败后的横向转向、评级边界和误判过滤索引见 [src-failure-pivots.md §业务状态机](src-failure-pivots.md); 本节继续保留状态机主流程和专项证据要求。

### Multi-Client Placeholder

Open payment, upgrade, or subscription pages on multiple clients with the same account, keep order IDs or QR codes unpaid, then change subscription/order/eligibility state and pay stale pages. Evidence requires multiple order IDs, stale price, actual payment amount, state-change record, entitlement snapshots, and final stable order state.

False positives: order creation without payment is not enough; price refresh at payment is not enough; one entitlement arrival is not enough; front-end display change is not enough.

### Coupon Rollback and Concurrent Replay

Create an order with a coupon, stay on payment page, close the order or wait for timeout, confirm coupon return, use the returned coupon on another order, then pay the stale checkout or concurrently create/pay shared-coupon orders. Evidence requires coupon state snapshots, discount fields, payment amount, close/return records, and final states of multiple orders.

False positives: multiple HTTP 200 responses with one real coupon/order change are not enough; payment-stage recalculation is not enough; stale payment invalidation is not enough.

### Decimal, Negative, and Overflow Quantity

Test `0`, decimal, negative, very large integer, scientific notation, leading zero, and boundary values before and after order creation. Compare unit price, order total, third-party payment amount, server amount, inventory, entitlement, and points. If recharge is protected, pivot to withdrawal, refund, fees, exchange, or trial conversion.

False positives: front-end bypass with server rejection is not enough; temporary success followed by close/refund is not high severity; high-value tests must remain minimal.

### Response Price Trust and Zero-Price Purchase

State model:

```text
Balance query response -> front-end button state -> product price response -> order confirmation -> submit order -> async delayed validation -> final fulfillment/refund/close
```

Modify balance response only to test front-end unlock. If the server rejects, pivot to product price or confirmation price sources. The finding is high-value only when final order state, goods, entitlement, logistics, or points state remains stable.

False positives: response modification that only affects the front end does not count; temporary order success followed by automatic refund is not high severity; final fulfillment evidence is required.

### Verification, Refund, and Async Validation

Split submit, audit, callback, shipment, verification, and refund. Test out-of-order flows such as unpaid verification, shipping while refunding, paying closed orders, or repeated verification. Wait until async validation finishes before rating.

False positives: success prompt followed by rollback is not enough; page navigation without server-side state change is not enough.

### Activity Registration Double Validation

State model:

```text
registration eligibility -> registration record -> submission eligibility -> submitted material -> review/exposure
```

Entry signal: activity registration, merchant admission, product submission, member restriction, expired/limited activity. If changing activity ID or response status only enters a page, continue to final material/product submission and review record. Evidence requires eligible baseline, restricted activity, response/ID mutation point, final registration/submission record, and negative control. Rating boundary: page access is low; registration without submission is low/medium; final submitted or review-visible record is medium-high.

### Voucher Remaining-Balance Race

Entry signal: voucher can be split, remaining balance deducts orders, points/red-packet balance is partially used. First consume part of the value to create a critical remainder, then concurrently create several orders each covered by the remaining value. Evidence must be final voucher balance, stable orders, payment amount, and resource/entitlement arrival. Multiple HTTP 200 responses are not enough.

### Auth Response Replacement to Final Write

Entry signal: real-name, ticket, order, booking, or third-party verification response controls the next step. Treat response replacement as a lead only; continue to final order, registration, ticket, or booking write. Rating depends on final record validity and whether backend rechecks identity before fulfillment.

### Cancel/Delete/Withdraw as State-Changing IDOR

Deletion, cancellation, refund withdrawal, and declaration withdrawal are high-value state changes. If `sign` errors appear, verify whether business execution still happens. Use only A/B self-created objects. Evidence requires target ownership, signature behavior, final B-object state, and negative control. Single foreign-object cancellation starts at medium; predictable IDs plus scalable cancellation can be high.

## Evidence Requirements

- Normal baseline, modified request, negative control, and final server-side state.
- Payment amount, order state, coupon state, points/balance, entitlement, goods, shipment, refund, or verification record.
- A/B account comparison for ownership-sensitive objects.
- Minimal-impact proof only; do not force real high-value fulfillment.

## Report Value

High value comes from stable server-side impact: real low-price payment, repeated coupon/points deduction, stable entitlement, goods fulfillment, order resurrection, repeated verification, or refund/fulfillment inconsistency. Front-end-only behavior is a low-value clue, not the finding.
