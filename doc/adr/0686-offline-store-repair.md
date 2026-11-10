<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0686 Offline allocator and usage-counter repair

Status: accepted
Date: 2026-11-07

## Context

`croit-flashstore-tool repair` only replayed the WAL, checkpointed and healed a superblock copy. `ceph-bluestore-tool
repair` also fixes leaked space, statfs drift, misreferenced extents, false frees and shared-blob refcounts found by
fsck (doc/reviews/2026-11-07-ds-tooling.md item 6). The FlashStore durable state (tree + data bitmap chunks, frozen
together per checkpoint) already lets `fsck` prove bitmap == references on every healthy store.

## Decision

- Repair = `store::obj::Store::repair`, offline, all shards, exclusive device owner, same device/identity checks as
  every offline command.
- Corrected: data blocks allocated but referenced by nothing in the complete fsck census (freed by normal txns,
  published by checkpoint); root usage and meta-page counters (rewritten by checkpoint from allocator and meta
  bitmap; mounts of the offline tool tolerate their drift via `ShardCfg::repair_counters`, the daemon never);
  collection and onode compression counters (rewritten from the object-check recount).
- Ownership findings corrected since am. 1: referenced-but-free data blocks, shared refcount mismatches, exclusive
  aliases (double references, exclusive/shared, exclusive/metadata or exclusive/engine-run overlap).
- Refused, nothing written: every structural or checksum finding and overlaps among metadata, shared and engine
  runs. False-free metadata cells are corrected by repair mounts (am. 2). Guidance: export PGs / recover from replicas.
- Census and object check before any write; second census after a checkpoint drives the frees; every free run lies
  in one allocator segment.
- CLI: full dry pass on the read-only overlay mount first; only a clean dry pass mounts the device writable.
- A store with the RocksDB omap engine (superblock `FEAT_OMAP_ROCKSDB`) is refused from the superblock alone, before
  any mount: repair never opens an external omap engine (exit 3, nothing written).
- No on-disk format change.

## Rationale

The census is the one fsck already requires to match on healthy stores, so a leak is exactly a block fsck would call
leaked. Ordinary txns + checkpoint keep the existing crash contract (replay resumes, no repair journal). A dry pass
on the overlay makes every refusal side-effect free, including the mount's own replay and checkpoint.

## Consequences

- + Leaked space and counter drift are fixed in place, without re-provisioning.
- + False-free metadata cells are recoverable by repair; ordinary mounts still refuse them.
- - The CLI runs the checks twice (dry pass + real pass); `--deep` reads every data block four times.

## Alternatives

- Direct bitmap edits: bypass WAL and checkpoint invariants. Rejected.
- Choose one owner of a double reference without evidence: may hand one object another object's bytes. Rejected.

## Open questions

- doc/90-open-questions.md 154 (resolved by am. 1); 155 (resolved by am. 2).

## Amendment am. 1 (2026-11-07): ownership repairs

Decision:
- The census of the durable state (`fsck::repair_plan`) also plans: `missing` (data blocks referenced, bitmap free),
  `relocate` (exclusive owner keys whose extent overlaps an earlier reference), `refs` (refcount records, only when
  the per-block owner counts disagree; a consistent layout is never rewritten).
- Who keeps the original blocks: metadata cells, then flagged (shared) extents, then omap engine runs, then exclusive
  owners in ascending key order. Every later exclusive owner (`T_EXT`, or a `V_EXT` value of `T_ATTR`/`T_OMAP`/`T_HDR`)
  gets a private copy: allocate (sys class), copy, recompute the address-seeded block crcs, repoint, all in one txn.
  Compression metadata and value length are kept, so every owner reads exactly the bytes it read before.
- Before any write the object check runs with data checksums when a relocation is planned (also without `--deep`):
  an owner whose crcs do not match its bytes refuses the whole repair.
- False frees: reserved before the first txn/checkpoint (and by the repair mounts before WAL replay,
  `ShardCfg::repair_fence`, so the post-replay checkpoint cannot place meta cells on them); then allocated by txns
  that carry them as already-durable extents (the omap run publication path: block crcs of the unchanged bytes, no
  payload write, replay verifies them).
- Refcounts: the records are rebuilt from the flagged extents (one run per stretch between extent boundaries with
  >= 2 owners); only changed records are written; overlapping old/new records go into one txn.
- Old blocks are freed only by the second census (leaks). No on-disk format change; the daemon path is unchanged
  (`repair_fence` is set only by the repair dry pass and the writable repair mount).

Rationale: counts and owners come from the references alone, never from stored counts or a guess which content is
right; every owner keeps its bytes. Ordinary durable txns keep the crash contract: a rerun's census finds what is left.

Consequences: a store with aliases is checked with data checksums (reads every data block once more). A real double
allocation (the second writer overwrote the block) leaves the first owner with a crc mismatch: refused as before.

## Amendment am. 2 (2026-11-07): false-free metadata cells

Decision:
- Only `ShardCfg::repair_fence` mounts (CLI `repair`: overlay dry pass and writable pass) admit metadata-cell blocks
  the data bitmap marks free. Daemon, fsck, export and plain offline mounts refuse them as before.
- Census = the pre-replay ownership walk of am. 1 (`fsck::repair_plan_shard`). Its cell set is the persisted meta
  image's cell list; the walk proves every reachable tree, delta, detached and image page lies in a listed cell (or
  the fixed meta region), cells are disjoint and inside the data region. Root slots and the WAL ring lie outside the
  data region; pages of an unpublished checkpoint belong to no durable state. A census error fences nothing (mount
  refuses on the cell check). Missing bits inside a cell go to `missing_meta`, all others to `missing` (am. 1).
- Before replay and before any allocation: reserve every `missing_meta` range by name and allocate it with
  `State::cell_take`, the existing metadata-growth contract (no WAL record; dirty bitmap chunks and the meta image
  publish together by the copy-on-write checkpoint and its atomic root slot). No WAL data claim, no page CRC.
- The mount forces and awaits that checkpoint also without replayed records (`bg_dirty`), and records the ranges;
  `Store::repair` reports them once (`before`: in use but unallocated, `actions`: allocated by the mount checkpoint).
- Offline raw census reads first drain the shards' in-flight IO (mount-time page prefetches): a synchronous reader
  must not consume another reader's completions (same rule as the lending-table and feature writes).
- No format change, no new record, no daemon-path work. RocksDB refusal and omap internals unchanged.

Crash safety: before the new root lands, a crash selects the old root, image and bitmap: normal mounts still refuse,
the next repair mount reconstructs the same fence (the copy-on-write checkpoint writes only pages the old meta bitmap
marks free). After it lands, the bitmap holds every cell. Nothing allocates data between fence and publication.
A replayed record that frees blocks of a claimed cell is applied as on any mount (the WAL is trusted, am. 1 fence
rule); the published bitmap then misses them again and the repair census refuses: never worse than the refusing mount.

Rationale: metadata allocation is checkpoint-owned, not WAL-owned. Reusing that atomic publication needs no new disk
contract and never validates stale checksums of mutable metadata pages.

Validation: `offline_repair_false_free_meta_and_mixed_crash_matrix`: whole and partial false-free cells, false-free
data, leak, refcount drift, alias and a WAL tail in one store; overlay pass (success and checksum refusal) writes
nothing; mount alone makes the allocation durable; every IO event of mount + repair cut under DROP_ALL, PERSIST_ALL,
MIXED, then repair, fsck, object/attribute bytes and a no-op rerun. Siblings: one offline BlockDev path for SPDK and
kernel tiers; transports, replicated/EC and msgr2 modes not involved.
