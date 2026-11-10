<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Igor Fedotov, croit GmbH -->

# 0644 Foreground omap LSM listing demand batching and bounded chunk look-ahead

Status: accepted
Date: 2026-11-04
Amends: 0610

## Context

Foreground listings reconstruct their merge cursors after a run-cache miss. Returning on the first missing head serializes independent source reads. The cache permits demanded working sets to exceed its soft capacity until an operation finishes, so speculative reads need separate admission and protection rules.

## Decision

- `flashstore_omap_scan_prefetch`, default true, enables batched missing cursor heads and a bounded next-fence window while consuming each current chunk. The startup option reaches the same shard reader on kernel NVMe and SPDK.
- Startup `flashstore_omap_scan_prefetch_chunks` selects 1..=16 logical future chunks per active run, default 1. Malformed, zero and out-of-range values fail store configuration/mount instead of silently changing the window. Four chunks target about 256 KiB per run before shared admission limits.
- Each cursor considers its window once per current chunk, in logical fence order. Hints follow all demanded head reads and range-tombstone skips. Object, prefix and partition bounds limit the next fence; physical adjacency is irrelevant.
- Speculative resident plus outstanding buffers use at most one quarter of the shard run-cache allocation. Outstanding I/O consumes at most half the device slots above the WAL floor and leaves room for one full target demand chunk, including transfer splitting.
- Queued ordinary client data reads take priority over fresh hints until their all-or-nothing read batch is admitted, expired or released; reads and WAL retain their existing admission outside the device data-write FIFO (0643).
- Cached or in-flight overlaps suppress hints. Hints use a separate FIFO index, joining the demand FIFO only on first use. Speculative admissions reclaim old unprotected demand data and retain independent hints within their quarter share; demand insertions evict unused hints first. Current demand data remains protected; speculative completions cannot use its progress exemption. First demanded use promotes a hint.
- Successful listings can leave hint I/O outstanding. Both blocking and nonblocking object APIs keep the shard active until those reads complete, including when no later client request arrives.
- Reader epochs, run-free invalidation and late-completion tokens use the existing shard/cache lifecycle. No persistent encoding changes.
- API behavior and counter units live in `ChunkRead`, `RunCache`, `PrefetchStats` and `Shard::olsm_prefetch_room` Rustdoc.

## Rationale

A configurable fence window overlaps device latency with current-chunk processing while retaining the existing fixed shard memory and queue budgets. The initial one-chunk window bounds startup look-ahead; a wider window permits measurement without changing those shared limits. Reserving demand capacity prevents speculative work from blocking the operation needed for progress. Cold-data reclamation allows admission from a full cache while retaining independently useful next chunks. Separate hint eviction avoids cache-sized scans on point-read misses. Demand insertion priority reduces interference with point reads.

## Consequences

- + Independent run-head misses share one device wait when enabled.
- + Existing perf output reports submitted/useful/unused/throttled chunks, speculative demand waits, resident/in-flight bytes and device slots.
- + Kernel and SPDK share the same admission, cache and lifetime code; transport, replicated/EC and crc/secure paths use the same store reader.
- - Very small caches and shallow queues decline hints; demand reads retain their existing progress behavior.
- - A page can end before its hinted chunk is demanded; unused and throttled counters expose this cost.

## Alternatives

- Adaptive windows: default policy is defined by [adaptive scan prefetch](0645-adaptive-omap-scan-prefetch.md); persistent scan cursors remain outside this change.
- Apply ordinary operation protection to speculative completions: can grow memory without bound across retries.
