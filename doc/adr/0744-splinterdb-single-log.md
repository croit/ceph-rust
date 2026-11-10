<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# 0744 SplinterDB single-log images (native WAL only)

Status: proposed; measured candidate pending
Date: 2026-11-10
Extends: 0727-splinterdb-omap-engine, 0742-splinterdb-pipelined-barrier

## Context

Every OMAP update is logged twice: the native WAL acknowledges it, and SplinterDB's
own log records it again when the worker applies it. A binding measurement (three
registered threads, sorted 80k-update batches, 64 B keys, 256 B values) gave
0.82 us/key with the library log, 0.62 with deferred log writeback and 0.31 without
the log: the second log is most of the apply cost. Durability of applied updates
before the watermark never relied on that log alone: native redo above the
watermark is retained until the watermark is durable.

## Decision

- Creation-time image mode `no_log` (tool `--splinterdb-no-log`, store
  `Config::no_log`): the image is provisioned without the library log, and a
  `shard-N.nolog` marker is made durable before the image exists. Every open follows
  the marker, never configuration, so an image is never reopened in another mode (a
  logged image opened without its log could lose logged, uncheckpointed updates).
- In this mode a durable barrier checkpoints the tree. A flush's durability step is
  then the watermark put followed by one checkpoint: the watermark follows all of the
  flush's updates, so one atomic checkpoint covers both. Native publication still
  follows only that completed step. With the pipelined barrier the checkpoint runs on
  the durability thread, off the apply path.
- After a crash the image is at its last checkpoint and native redo replays everything
  above its watermark, as before.

## Consequences

The library log, its per-update work and its automatic checkpoints disappear; each
durability step costs a checkpoint (~60 ms measured per 80k-update batch; it writes
back the cache). Recommended only together with the pipelined barrier. Tests:
process-loss prefix crashes without the log (with and without maintenance), the mode
fixed by the marker and not the configuration, watermark ordering with injected
failures in both modes, pipelined flushes on a no-log image, and a shard crash image
recovered through native replay.
