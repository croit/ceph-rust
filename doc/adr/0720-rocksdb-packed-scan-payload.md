<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH -->
# 0720 Packed request-owned RocksDB scan payloads

Status: candidate; offline checks and independent review complete, live qualification pending
Date: 2026-11-07
Amends: 0677, 0719-rocksdb-slice-admission

## Context

The worker allocates separate owned DB keys and values for every returned entry.
Admission batching does not remove this work. This is a structural allocation
opportunity, not an established explanation for end-to-end scan latency.

## Decision

- Copy visible keys/values into one worker-owned packed payload per bounded batch,
  including overlay selections. Publish immutable slices only after the iterator
  walk finishes. No iterator, snapshot or borrowed DB bytes cross the worker.
- Preserve merged selection, tombstone/range precedence, binary bounds, requested
  count, page byte target and oversized-first-entry behavior. A physical-capacity
  credit limit may end an irregular batch earlier; retain the existing first
  unreturned-key/Unknown continuation contract.
- Carry the full payload allocation capacity and entry-vector backing through
  answer cache, shared-answer fallback and request slices. Consuming slices does
  not release this charge. Detach the persisted cursor at batch completion or
  cutoff before releasing the charged batch. Legacy unscoped/truncated outputs
  receive detached copies rather than escaping a hidden large backing allocation.
- Keep existing exclusive admission, growth/encoding checks, fairness yields,
  final writable retry copy, cancellation, expiry and revision invalidation.
- No native LSM, transport, EC/replication, wire, storage format, WAL, sync or ACK
  policy changes. The change is confined to selected RocksDB read materialization.

## Rationale

Per-batch payload allocation removes per-key/value allocation without pretending
that small slices release their physical backing. Existing credit multipliers
also cover temporary construction vectors and shared-copy transitions.

## Consequences

Overlay values now copy into the independent worker payload. Retained backing
can consume more credits than remaining visible lengths. Require exact credit,
binary/overlay, partial consumption, shared-Arc, cursor detachment, cancellation
and retry regressions, then matched source-bound benchmarks. Structural pointer
and capacity assertions alone are not performance qualification.

## Alternatives

- Uncharged Bytes slices: rejected; a one-byte cursor can retain a complete batch.
- Per-entry key/value packing: still allocates per entry and retains value bytes
  through cursor ownership.
- Final immutable encoded reply sharing or fewer fairness yields: separate work.

## Initial qualification

Five added regressions cover contiguous immutable payload ownership, unused
capacity, exact/oversized credits, a real-worker Unknown continuation with held
Arc fallback, and Stage cursor detachment through yields/cutoffs/retries. Existing
backing-charge and truncated-output tests now assert whole-backing retention and
detached legacy entries. Store library393 pass/12 ignored; Rocks integration8,
scan integration8, default Store322/11 ignored, adapter7/2 ignored. All-target
Store Clippy and no-default Rocks Store/adapter/OSD compilation pass. An initial
test-only comparison type mismatch was corrected; failed compile log retained.
No release, live run or performance improvement is established by these checks.

Independent review found no production defect but rejected the original cursor
test's uniqueness-only assertion: a sole small slice can still retain a complete
allocation. The strengthened regression holds the real worker answer, checks
pointer-range independence at completion and cutoff, and exercises shared-Arc
fallback. Removing either cursor-copy path independently makes that test fail
at its backing-independence assertion; restored code and all five new regressions
pass. Final all-target Clippy also passes. This correction changes test-only
observability/validation, not the production detachment algorithm.
