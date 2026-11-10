<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# 0741 SplinterDB automatic checkpoint size

Status: proposed; measured candidate pending
Date: 2026-11-09
Extends: 0727-splinterdb-omap-engine

## Context

With its log enabled the pinned library arms an automatic checkpoint each time the
log grows by `checkpoint_log_size_bytes`, default one cache size (about 131 MiB per
shard here). At ~370 B of log per update that is ~23 checkpoints per 8.4M-update
phase; each writes back the whole cache and syncs, partly on inserting threads.
Durability between checkpoints comes from the log and our explicit barriers.

## Decision

Expose the size as `flashstore_store_splinterdb_checkpoint_log_bytes` (store
`checkpoint_log_bytes`): 0 keeps the library default; otherwise 64 MiB..=4 GiB and,
when the creation capacity is known, at most a quarter of it. Startup-only; no
format change; barriers, watermark and native publication are unchanged.

## Consequences

Fewer checkpoints mean less writeback and fewer syncs on the apply path, but more
log space in the image and longer log replay at open. A process-loss test writes
about 70 MB of log under a 192 MiB size (no checkpoint) and verifies that every
barrier-covered prefix, the watermark order and ordered redo survive in both I/O
modes.
