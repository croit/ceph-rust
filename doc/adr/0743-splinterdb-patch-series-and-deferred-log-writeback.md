<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# 0743 SplinterDB patch series and deferred log writeback

Status: proposed; measured candidate pending
Date: 2026-11-09
Extends: 0727-splinterdb-omap-engine

## Context

The pinned library (third_party/splinterdb, 73f89d8, Apache-2.0) is tracked from
its public upstream; we cannot push changes there. Its log graduates each filled
4 KiB per-thread log page by submitting its write immediately: about 7k buffered
single-page submissions per ~80k-update flush, on the inserting threads, while
the log is durable only after an explicit durability wait anyway. Profiles showed
submission dominating traced syscall time; apply threads scale only ~1.8x.

## Decision

- Library changes are carried as an ordered patch series in
  `crates/splinterdb/patches` (`series` lists them). The build copies the pinned
  sources to its output directory and applies the series there; the submodule
  and its revision check are unchanged. Each patch keeps the upstream license,
  is described here in own words and adds only default-off behaviour selected
  through our binding.
- Patch 0001 adds `log_defer_writeback`: a filled log page is enrolled in its
  thread's writeback set as not yet issued. Every log durability wait already
  re-issues incomplete entries before waiting, so the barrier (or checkpoint
  seal) submits the deferred pages and then syncs. Durability, recovery and the
  barrier contract are unchanged; dirty log pages may stay in the cache until
  the wait (the cleaner may still write them earlier).
- Opt-in through `flashstore_store_splinterdb_defer_log_writeback` (store
  `defer_log_writeback`). With the pipelined barrier, the deferred submissions
  run on the durability thread instead of the apply threads.

## Consequences

More dirty log pages are held per flush (bounded by one flush's log, ~30 MB per
80k updates) and the waiting thread does the submissions. Tests: process-loss
prefix crashes with deferral (with and without maintenance, with a large
checkpoint size) and a measurement that the inserting thread no longer writes the
log before the barrier while the barrier still does.
