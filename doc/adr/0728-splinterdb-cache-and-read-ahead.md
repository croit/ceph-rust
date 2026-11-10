<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0728 SplinterDB cache layers and bounded scan read-ahead

Status: proposed; implementation/offline validation in progress
Date: 2026-11-05
Extends: 0727-splinterdb-omap-engine
Research: own-words pinned reference (doc not in the source snapshot),
0610 and0645 (our native LSM; unchanged by this decision).

## Context

Reconstructing a foreign iterator for every256-entry page repeats tree seeks and
resets its read-ahead locality. One opportunistic cache for both scans and points
also lets one-pass scans evict point results. Actual pinned BlueStore/RocksDB has
separate logical caches, database blocks, reader buffers and (on its buffered
kernel path) Linux page cache. These layers and their meanings are not identical
to a POSIX SplinterDB file. No upstream code/algorithm is imported.

## Decision

- Keep direct I/O as the default. Offer explicit startup-only `direct|buffered`
  for the optional engine, without silent fallback or runtime descriptor mixing.
  Buffered file I/O affects writes too: both blocking materialization barriers
  and native WAL ACK authority remain unchanged. Kernel file-cache memory is not
  part of the foreign block-cache number; no total-memory or performance parity
  claim follows from equal `cache_size`. No host cache/swap/readahead tuning.
- Preserve SplinterDB's block cache and public extent-prefetch facility. Expose a
  bounded explicit soft byte budget (default pinned local-SSD1MiB); do not build
  another physical block cache, Bloom filter or foreign background pool. The
  library splits this budget across input streams and applies a per-stream
  minimum, so the budget is not a hard bound on physical reads or residency.
- Cache only owned logical scan windows across worker turns, never live foreign
  iterators. Match object, prefix, inclusivity/coverage, projection, overlay
  revisions and session; invalidate on affected materialization and cancellation.
  A fresh seek/projection/generation/session starts with demand only. Consecutive
  full-page continuations enable a small growing window, capped at configured
  pages (default4, maximum16;1 disables Rust look-ahead). Interrupted/unused
  windows reset locality. This is locality-driven batching, not an assertion of
  asynchronous application-level IO overlap or reuse of native lateness metrics.
- Bound additional rows, bytes and worker work. Charge speculative owned pages
  against existing read headroom; oversized demanded values still make progress.
  Yield additional scan work to pending worker requests/mutation pressure and
  stop on cancellation. Bound inspected optional work even when tombstones
  suppress output; session retirement advances a worker-visible request epoch.
  Foreign ranges never start beyond their prefix upper bound; an exhausted base
  still merges newer overlay points. The iterator dies before any same-worker
  mutation. Blocking foreign calls themselves are not preemptible by this policy.
- Keep the latest demanded scan answer available for retry progress separately
  from its optional future pages. Scan windows never populate/evict the general
  point-result cache. Deleting speculative state must not discard the admitted
  demand answer while its request is parked.
- Report Rust window hits, useful/unused whole-page bytes, worker scan/seek work,
  charged residency and actual descriptor mode. Optional pinned cache counters
  describe engine hits/misses/read/write bytes/prefetch requests, not physical
  NVMe IO or Linux page-cache hits. Disabled counters have explicit validity.
  The pinned constructor uses `use_stats`; setting only `cache_use_stats` does
  not activate the actual counters. Statistics remain opt-in to avoid silently
  adding per-read timing overhead.

## Alternatives and consequences

Persistent foreign cursors were rejected: they can block mutations on the same
worker and require self-referential lifetime/retirement machinery. Unconditional
large read-ahead and a global kernel-cache flush were rejected. No cache tuning
changes native B-tree/LSM defaults, formats, PG routing or durability gates.

Direct versus buffered correctness and process-loss tests, bounded-window model
tests and deterministic seek/work counters are offline gates. Real NVMe tail
latency, cache-fitting/exceeding workloads, total RSS+file-cache budgets, physical
power-loss and production admission remain separate unrun qualification. Do not
infer a hardware speedup from seek-count reduction or tmp-filesystem timing.

## Amendment: buffered startup default for the phase1 iteration

2026-11-05, explicit user decision: make buffered IO the optional engine's default
in the binding, store constructor, daemon configuration and offline tool. This
supersedes the initial direct-default choice above; explicit `direct` remains.
No durability barrier, native ACK authority, engine selection/default-off gate or
cache-budget meaning changes. Add default-descriptor and constructor/forwarding
regressions. The requested three-arm campaign is qualification work, not evidence
that buffered IO is already faster or production-qualified.

## Amendment: windows continue across requests of one listing

2026-11-09. The phase1 8Mi run showed 8192 worker scans for 8192 client pages:
each paginated page is a new request with a new session, so the session match
and the clear on retirement prevented any window from reaching the next page,
and growth was limited to 256-row demand. This supersedes the session match and
the clear on request retirement above:

- Match object, prefix, inclusivity/coverage, projection and overlay revisions,
  not the request session. A completed window survives request retirement; the
  retirement epoch still cancels optional in-flight work, and a retired
  request's late answer is still not installed. Idle credit expiry, invalidation
  by materialization of the object and any non-matching worker request drop it.
- Any demand width may grow after consecutive full continuations, in whole
  demand pages, capped by the configured pages and the existing maximum rows.
  Under pressure or point interruption, wide windows keep their demand rows and
  drop rows predicted beyond them.

Charged residency, row/byte bounds and the single in-flight worker read are
unchanged. Model tests cover the cross-request ramp, revision mismatch and
pressure cropping; the effect on scan latency is a measurement, not a claim.

## Amendment 2: continuation by window end; pass-sized copies

2026-11-09. The cross-request window still never grew (phase1 sp4: 8192 worker
scans, 0 prefetched pages): the listing reopens each page inclusively at
`start_after` + 0x00, asks for max+1 rows, and its own 256-row owner slices reset
the continuation streak. Continuation is now decided when a new worker request is
admitted: it continues when it starts exactly at the end of the current window
(exclusive at its last key, or inclusive at that key's immediate successor) and
the window was cut short; how the owner consumed the window in between does not
matter. Growth still needs two continuations in a row and resets on any other
request, pressure or unused predicted page.

A window hit now copies at most the rows the caller's owner pass can consume (the
rest of its 256-entry slice plus the page-ending row), with `more` set; exact
retries still share the admitted answer. A model test drives the cache with the
listing's real pattern (inclusive reopen, max+1, slices, look-ahead).
