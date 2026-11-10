<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0647 Omap removals are blind: no per-object omap counters, removal batches as runs of removals

Status: accepted
Date: 2026-11-04
Amends: 0021 (S8, S9, S11, S15), 0476 (am. 5, 13, 15: counted blind tree ops, range removal; runs of removals), 0611
(quick steps)

## Context

- The store kept exact per-object omap key/byte counters (adr 0021 am. 15): onode format 2, `c` counter-delta records,
  counted WAL ops `DelCounted` / `PutCounted` (tags 6, 7) whose apply reads each removed key's old value, and an executor
  pre-count of every `OmapRmKeyRange` that replicas waited for (`rm_prep`).
- No production code read them: PG `num_omap_keys/bytes` and the OSD `omap_allocated` come from deep scrub (adr 0614),
  the large-omap check lists keys. Classic Ceph v21.2.0 removes omap keys blind (one RocksDB delete per key, no read);
  no client op returns a per-object key count and RMKEYS / RMKEYRANGE do not report whether a key existed.
- Cost (e9455 phase 1, doc/perf/omap-gap-20261104.md): a `c` probe per object and record, the range pre-count
  (2.1 re-runs and 3.7 loads per delete_range in mix-rangedelete), and adr 0476 am. 5 rejected removal tombstones only
  because the counters need each removed key's old value.
- A removal batch was the one omap batch that still worked on the tree at commit: its blind `Op::Del`s load and dirty
  each key's leaf on the commit path (56 device reads per delete op of 64 keys in e9455 phase 1, 431 us OSD latency
  against 81 us for BlueStore) and kill the keys in every run of the object; a put batch of the same size is one run
  (adr 0476).

## Decision

- The store keeps no per-object omap counters. Onodes are written without them (format 1, or 3 / 4 with a zero
  counter slot); format 2 and the counter slots of earlier builds are read and ignored (`F_OCNT` dropped at decode).
- WAL tags 6 / 7 of an earlier build replay as plain `Del` / `Put`; this build writes only the plain tags.
- `OmapRmKeyRange` stages one tree range delete, no pre-count; the commit probes its boundary leaves like any txn.
  Replicas hold a repop only for cold pages (`Pg::held`, `WaitOn::Loads`).
- Omap usage numbers come only from deep scrub (adr 0614); `Store::scrub` recounts one object; tools count by listing.
- Feature `FEAT_OMAP_UNCOUNTED` (`omap_uncounted`, bit 23): incompatible and sticky, set by mkfs and by every mount of
  this build, durable in both superblock copies (`heal_super`) before the mount writes anything else, WAL replay
  included. An earlier build refuses the store (unknown bit) instead of trusting counters nobody maintains.
- In-place upgrade (quick step, at mount): after replay the mount removes all `c` records, one range delete per shard
  that has any. Idempotent: a crash leaves them to the next mount, nothing reads them meanwhile. Onodes of format 2
  stay until their object is written again. No data rewrite, no re-mkfs.

- Runs of removals (D1): an `OmapRmKeys` batch of at least `run_min` (64) distinct keys of an object that may take a
  run (adr 0476: pool object without fragment / data-block values, no run of it staged by the txn, every key fits a
  tree entry, run room) is staged as one run of removal entries: value record empty (`vlen` 0; a value record always
  has its form byte), no tree access and no run kill at commit. Other removals keep the blind tree ops (adr 0476).
  Within the txn the run is newer than its earlier ops (runs are logged after the record's tree ops); a later op of the
  txn on one of its keys turns that entry into a tree removal first, as for put runs.
- The newest entry of a key decides: a removal entry means absent without a tree lookup (point reads, `omap_cmp`,
  GET_VALS_BY_KEYS), scans and listings drop the key; a newer run or a tree op on the key (which kills it in the runs)
  wins. A compaction keeps a removal over the older entries of its key (the tree may still hold it).
- The tree merge deletes a removal's key where its leaf holds it (the merge batch: `Tree::write_sorted_batch`); a leaf
  without the key stays clean, an emptied leaf is pruned, a thinned one merged like after any removal. A removal takes
  no tree bytes in the merge's slice and page sizing; the merge is paced like put runs (adr 0476).
- Durability: removal entries live in the WAL-logged `RunPut` records; replay, re-log and the WAL floor are unchanged.
- Feature `FEAT_OMAP_TOMBS` (`omap_tombs`, bit 24): incompatible and sticky, set by mkfs and by every mount in the
  same superblock write as `FEAT_OMAP_UNCOUNTED`. An earlier build refuses the store (it would read a removal as a
  value). In-place upgrade: the bit only, no data rewrite.
- Counter `run_rms` (part of `run_puts`): removal batches staged as runs.

## Rationale

- Exact per-object counts exist nowhere in Ceph's interface, so removing them changes no app-visible behaviour, and
  every write path loses work: no old-value read per removed key, no `c` record, no range pre-count, no replica wait.
- The bit goes first, ahead of replay (unlike adr 0611's replay-and-checkpoint-first order for steps that reinterpret
  WAL records): this build reads an earlier build's WAL as written (tags 6 / 7 as plain ops, `c` and format-2 onode puts
  as data), and from its first write on the counters on disk are stale, so an earlier build must never mount the store
  again. A crash before the bit is durable leaves the store byte-identical to what the earlier build wrote (superblock
  copies aside).

- Runs of removals: without counters a removal needs no old value, so a removal batch is logged like a put batch and
  the leaf work moves to the merge, which loads each touched leaf once per merge slice in the background instead of on
  the client's commit path. One bit for both changes: a store this build mounted is refused by every earlier build
  anyway (`FEAT_OMAP_UNCOUNTED`), so a separate downgrade window for removal runs would buy nothing.

## Consequences

- + Removal batches no longer need old values: removal batches of `run_min` keys commit without tree access.
- + Range removals and replica repops never wait for a pre-count; `peering` loses the `RmRange` wait state.
- - A store mounted once by this build cannot go back to an earlier build (loud refusal, adr 0611 rule).
- - Per-object omap totals cost a listing or a deep scrub (as in BlueStore).
- - A removal of an absent key costs run memory and a merge leaf probe until merged (BlueStore: a RocksDB tombstone
  until compaction); point reads of an object with unmerged runs see one more run per removal batch (bounded by
  `run_max`, adr 0476).
- Tests: `tests/omap_upgrade.rs` (earlier-build fixture with format-2 onodes, `c` records in the tree and only in the
  WAL, runs with removals; upgrade, content, recount, check, fsck; crash matrix of the upgrade mount at every device
  event, three crash policies; both bits), `wal.rs` tag 6 / 7 replay, `upgrade.rs` refusal of an unknown bit. Runs of
  removals: `runs.rs` (shadowing, compaction, re-log, decode), `page.rs` leaf merge, `tests/runs.rs` (removal runs
  against a model through merge, checkpoint and crash remount; emptied and thinned leaves; crash matrix with 35 % removal
  runs), `tests/obj.rs` (`omap_removal_batches_stage_as_runs`: no loads at commit, in-txn order with puts, clone, range
  removal, object removal, power cut; model and crash matrix with removal batches), format golden.
- Siblings checked: replicated and EC share the store path and the replica hold (EC sub-writes used the same `rm_prep`
  wait); SPDK and kernel NVMe share the store; the LSM engine (adr 0610) never kept counters and writes point tombstones
  already; transports carry the same txns. PG log / pgmeta objects take no runs (tree path, unchanged).

## Alternatives

- Keep the counters and make the pre-count cheaper: still an old-value read per removed key, and no consumer.
- Remove the `c` records lazily (with the next clear or object removal): leftovers forever on untouched objects and a
  check exception; one range delete per shard at mount is bounded and simpler.
- A separate removal entry kind (flag byte) in the run encoding: an empty value record is unused, so the run encoding
  stays; the feature bit guards the meaning.
- Clearing `FEAT_OMAP_TOMBS` on a drained store (`croit-flashstore-tool`): no earlier build mounts the store anyway
  (`FEAT_OMAP_UNCOUNTED`).
- Removal batches below `run_min` as runs: same threshold as put batches; a few keys touch a few leaves, and each run
  costs a bloom, a run slot and compaction work.
