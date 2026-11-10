<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0492 Application admission is independent of initial native staging

Status: accepted
Date: 2026-10-22

## Context

Both pinned versions expose objecter_inflight_ops as a configured logical count
with zero disabling its throttle (pinned-throttle-config-values.md and
pinned-logical-throttle-lifetimes.md). Clamping that count to native initial slots
and stopping mailbox dequeue when native staging is full exposes a second fixed
public limit. Existing completion, cancel and flush ownership must survive queuing.

## Decision

- The compatible async ledger captures the configured application count without
  clamping to its initial map allocation. Zero disables its count limit.
- Initial allocation grows with admitted work; never allocate a configured-count
  array or replace the clamp with a bigger constant.
- The worker drains its bounded mailbox into a FIFO independently of native
  admission. Native NoCredit retains the oldest request and original deadline.
- Each turn bounds dequeue and native-admission work. Map queries and controls
  remain runnable while the FIFO waits for native credits.
- Cancelled/expired queued entries retire without native dispatch. The earliest
  queued deadline bounds sleep; close settles every retained delivery once.
- Existing native staging slots remain a separate recoverable resource. Strict
  test/native constructors keep their explicit count limits.

## Rationale

A finite transport/reactor work queue is useful for fairness but cannot define
public compatibility eligibility. Retained FIFO ownership permits more accepted
application work than fits native staging without losing order, completion cuts,
inputs, deadlines or the C1 resend barrier.

## Consequences

- Disabled/high operation targets can retain more caller-owned work; memory grows
  with actual accepted requests, not the configured maximum.
- Count/byte configuration remains captured at worker creation. This does not
  invent live throttle resizing that the pinned reference does not provide.
- C/C++, sync/async data paths share the deferred owner and existing native
  queue; kernel TCP, io_uring and RDMA use the same worker.

## Alternatives

- Raise native/mailbox constants: retains a second public limit.
- Reject with EAGAIN/E2BIG at native staging capacity: turns temporary pressure
  into a permanent application failure.
- Sleep/retry timers: do not express credit availability and delay other work.
