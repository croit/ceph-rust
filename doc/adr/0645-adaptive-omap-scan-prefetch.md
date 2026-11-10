<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Igor Fedotov, croit GmbH -->

# 0645 Adaptive foreground omap scan look-ahead

Status: accepted
Date: 2026-11-04
Amends: [0644-omap-scan-prefetch](0644-omap-scan-prefetch.md)

## Context

A fixed fence window cannot respond to late useful hints, abandoned scans or competing demand working sets. Listing cursors are reconstructed after misses, so feedback must outlive a cursor. Cache and device admission already bound all speculative reads together per shard.

## Decision

- Startup `flashstore_omap_scan_prefetch_adaptive`, default true, enables a persistent shard controller when `flashstore_omap_scan_prefetch` is also true.
- Startup `flashstore_omap_scan_prefetch_max_chunks`, default 16, bounds adaptive look-ahead to 1..=16 logical future chunks. Invalid values fail configuration/mount. The controller starts at one chunk. Fixed mode retains `flashstore_omap_scan_prefetch_chunks`, default one, unchanged.
- Feedback resolves each speculative extent once on first demanded use or discard. A first demand while pending is marked once per token and retained until resident promotion. Whole-extent useful, unused and late-useful bytes form matched resolved cohorts; pending reservations are never waste.
- The controller uses byte-cohort policy and hysteresis documented in `AdaptivePrefetch` Rustdoc. Growth requires repeated useful-but-late evidence; waste and demand pressure decrease sooner. These thresholds are policy, not measured device tuning.
- Pressure means an ordinary client data-read batch waits for admission, independent device work leaves insufficient target demand room, or protected demand bytes leave insufficient target hint room. Actual outstanding speculative device parts are discounted when measuring device pressure. The existing conservative queue admission reservation remains held until the complete split chunk lands.
- A continuous pressure episode decreases once; overlap checks and denied admissions cannot rearm it. Recovery discards pressure-period samples. Exhaustion of the speculative memory quarter or queue half alone is ordinary admission and does not decrease the window.
- The shared cache quarter, device half, WAL floor, target demand reserve, reader epochs, invalidation and completion ownership remain authoritative. No persistent format changes, clocks, new per-record allocation or locks.
- Counter units and mode/window aggregation live in `PrefetchStats` and `OlsmStats` Rustdoc. The existing retry-count `demand_waits` remains available separately from distinct first-demand `late` events.

Operator startup options, defaults, validation and fixed/adaptive examples live in `ShardCfg::omap_scan_prefetch` Rustdoc.

## Rationale

Byte feedback gives variable-size extents proportional weight and excludes unresolved speculative buffers from the waste denominator. Per-shard state survives retries and shares one policy across concurrent scans. A separate adaptive ceiling gives adaptive mode useful defaults while preserving fixed configuration semantics. Distinguishing pressure from own admission limits avoids repeated shrinkage caused by a full speculative share.

## Consequences

- + Fixed and disabled behavior remain available; adaptive behavior is the default for kernel NVMe and SPDK through the common shard reader.
- + Deterministic controller/cache tests and both submission styles of the mixed scan/point-read model are included in `scripts/check-omap-scan-prefetch.sh`.
- - A shard combines feedback from concurrent scans. Small scans below the resolved cohort threshold do not independently adjust the window.
- - No performance claim is made without a later controlled measurement. Siblings checked: transport and replicated/EC paths are unaffected because the change is confined to the shared local omap run reader; both storage submission styles use it.

## Alternatives

- Use fixed chunks as the adaptive ceiling: rejected because its compatibility default of one would prevent growth with the new flag alone.
- Per-cursor timing: rejected because retries reconstruct cursors and clocks add work without resolving abandoned-hint usefulness.
