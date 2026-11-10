<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0512 Redirect resubmission separates logical and wire identity

Status: accepted
Date: 2026-10-21

## Context

Both pinned clients allocate a new wire TID after an authenticated redirect,
retain the logical operation and resubmit with overlay/cache bypass flags
(doc/spec/rados-client/reply-redirect-routing.md). Native tokens currently serve
as both the caller identity and the messenger TID. Changing a token would lose
completion, cancellation, fence and per-object resend ownership.

## Decision

Retain RequestToken as the logical identity. Store the current wire TID in the
pending request and dispatch; allocate replacement TIDs from the same monotonic
counter as admissions. The shared coordinator resolves redirected wire replies
through a sparse alias index and rejects superseded TIDs before decoding replies.

A redirect retains request inputs, snapshot context, byte charge, deadline and
completion. Add sticky redirect/cache/overlay bypass flags, invalidate only the
attempt route, then use the existing per-object resend barrier. No redirect-count
cap is introduced. Wire identity/attempt representability is checked explicitly.

## Rationale

Logical identity must survive wire-level recovery. A sparse alias index adds no
map entry to ordinary flights and preserves the existing cancellation index.
The core owns attempt identity and flags; the coordinator owns authenticated
session routing, ingress and scheduling across kernel TCP/io_uring/RDMA.

## Consequences

- Late replies on a superseded TID cannot complete the current operation.
- C/C++, sync/async retain the same completion and cancellation ownership.
- Native connection drivers must use ReadDispatch::wire_tid for messenger TID.
- Redirect resends preserve the C1 ordering barrier, including fresh admissions.

## Alternatives

- Replace the logical token: breaks fences, cancellation and caller ownership.
- Retain wire TID after redirect: differs from both reference versions and lets
  delayed replies address the replacement attempt without the intended filter.
- Add a second hash entry for every flight: unnecessary ordinary-path overhead.

## Open questions

None for logical/wire identity separation. Watch/notify endpoint binding and
server eligibility are specified in redirect-ownership.md and the source-backed
linger/server companion specs. Native managed controls retain the accepting
endpoint; reference callbacks leave the linger target unchanged (ADR0256).
