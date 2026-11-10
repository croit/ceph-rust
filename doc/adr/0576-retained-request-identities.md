<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0576 Retain immutable request identities across owned dispatches

Status: accepted
Date: 2026-10-25

## Context

The engine retains an accepted request while independently owned dispatches
cross queues and survive retry/remap. Dispatch construction currently copies
object, namespace and locator into a second set of vectors per attempt.
Borrowing the engine across that asynchronous boundary cannot preserve its
existing progress and lifetime contract.

## Decision

- An accepted logical request has one immutable shared owner. Dispatch identity
  views retain that owner; their clones do not copy identity bytes.
- Terminal queue slots reuse empty request-owner shells only after Arc proves
  exclusive ownership. Clear the request immediately; never cache shared owners
  or retain their payloads/callbacks beyond the last dispatch.
- Admission rejects still return original caller-owned requests. Public Target
  inputs and the C/C++ ABI stay unchanged. Native dispatch identity fields use
  an immutable retained byte view; explicit owned construction remains possible.
- The existing MOSDOp/ObjectLocator encoder accepts byte-storage parameters;
  owned server decode remains the default. One encoder defines all wire versions.
- Independent route/attempt headers, operations and snapshot vectors retain their
  current behavior. No C string borrow extends past its synchronous call.
- Adoption requires exact v7/v8/v9 encoding, native/C/EC/compound/control gates,
  deterministic ownership/allocation tests and measured performance.

## Rationale

One shared request owner preserves independent dispatch lifetime without
per-attempt identity allocations/copies. A cold slot or a still-retained old dispatch requires one shared allocation;
exclusive completed slots reuse their cleared owner without allocating. Plain
object-only cold first attempts may not reduce allocation count. Measurements must assess that trade-off, including retries
and nonempty namespace/locator identities.

## Consequences

- + Immutable identities survive engine retirement and stale dispatch rejection.
- + Server-owned decode and C/C++ layouts are unchanged.
- - Native code directly replacing dispatch identity fields must construct the
  retained byte-view type; request input construction stays compatible.
- - Shared ownership retains the request until its last dispatch retires.
- - Payload copies, operation/snapshot clones and GPU qualification are separate.

## Alternatives

- Borrow the pending request into an asynchronous dispatch: constrains engine
  progress or violates the lifetime boundary.
- Copy identities into a reusable vector: retains the avoidable byte copy and
  requires an additional buffer-return protocol.
- Change every public Target field to shared bytes: changes ordinary Rust request
  input construction and does not share one owner across its three identities.
