<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0602 Handle-wide RBD encryption state and internal load fencing

Status: accepted
Date: 2026-10-27

## Context

The pinned C API permits encryption load on read-only handles and selected
snapshots. Snapshot selection preserves the loaded handle's encryption state.
Load must drain previously accepted I/O before reading its header and must
not require writable-owner admission. Key derivation can outlive that drain.

## Decision

An open handle and its immutable selected/refreshed views share one atomic
cryptor slot. Load publishes with compare-and-swap after validation; flat
reformat replaces the slot. Accepted AIO retains its own cryptor through
completion. Size, stat and synchronous/vector/AIO reads use this shared state.

Encryption load retains an activity permit through validation, internal flush,
header reads, key derivation and publication. The internal flush atomically captures accepted read generations and the
write-submission prefix without USER flush or writable-owner admission.
Read counters reuse existing generation entries; only load barriers allocate
new entries. Active read continuations retain their generation, while work
accepted after the barrier does not prolong it.
Pending metadata refresh resolves through the existing generation mechanism;
payload bounds use current HEAD size while header reads use the selected view.
The writer guard protects final shared-slot and writer publication; it is not
held during key derivation. A failed load publishes no candidate cryptor.

## Rationale

Handle-wide state matches the pinned selection contract and avoids stale
cryptors in existing immutable views. Submission fencing shares the existing
activity/close lifetime instead of constructing a writable owner for read-only
work. Reusing generation-aware refresh avoids an unconditional metadata RPC.

## Consequences

- + Flat read-only and selected-view loads use the same handle state as writes.
- + Close waits for an admitted load through final publication.
- + Duplicate load cannot replace an installed cryptor.
- - Parent/ancestor load2, clone formatting, partial EOF units and interior
  sparse extents remain separate implementation/qualification work.
- - Concurrent reformat/selection/refresh and broader fault, provider,
  application and performance qualification remain open.

## Alternatives

- Per-view cryptors: existing selections would retain stale encryption state.
- Writable USER flush: rejects permitted read-only/selected loads and imposes
  unrelated data ownership.

## Open questions

Remaining encryption work is tracked in RBD-043/044/048/049 and the broader
qualification inventory in doc/reviews/librbd-open-issues-20261026.md.
Evidence: doc/perf/librbd-completeness-20261024.md.
