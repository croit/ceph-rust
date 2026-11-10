<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0723 Compact offsets for owned RocksDB scan batches

Status: candidate; qualification pending
Date: 2026-11-08
Amends: 0720-rocksdb-packed-scan-payload

## Motivation

Bounded offline vector replay measures nontrivial finish/drop work when a packed
batch creates two Bytes owners per entry. This is local System-allocator evidence,
not proof of an end-to-end bottleneck or speedup with production mimalloc.

## Decision

Keep one immutable payload owner and a boxed array of key/value end offsets. Owner
slices borrow entries from this envelope; no per-entry Bytes creation/refcount or
destruction. Keep the entire payload-capacity charge through partial consumption.
Shrink offset storage on early termination so unused metadata capacity does not
escape. Preserve the existing conservative64-byte per-entry reservation and every
builder credit check; this candidate changes representation, not credit budgets.

An owner quantum resumes from the batch's offset. Do not publish a per-entry owned
cursor while that batch remains present. At completion or a request cutoff, detach
the needed key before dropping the envelope. Legacy unscoped outputs still copy
individual entries. Shared-answer fallback clones one payload owner and offsets;
the cloned envelope keeps the complete conservative charge.

No iterator/snapshot escapes the worker. Preserve binary selection, overlay and
tombstone precedence, continuation, fairness, cancellation, revision checks,
immutable completed replies, native LSM, format, WAL/sync/ACK and transport policy.

## Qualification

Require independent entry/continuation vectors, partial-consumption full-charge
witnesses, early-prefix metadata bounds, shared-answer fallback, detached terminal
cursor checks, cancellation/revision/expiry and existing Store/adapter regressions.
Reuse test-only offline attribution with equivalent input/timed regions and record
API-only changes to out-of-window validation. Live matched runs remain decisive;
do not predict a production speedup from fewer Rust allocation requests.
