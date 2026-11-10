<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0610 Omap LSM engine: per-shard memtable + immutable sorted runs, omap leaves the CoW tree

Status: proposed
Date: 2026-10-27
Supersedes: 0476 (at phase 3), 0534 job types (protocol kept); replaces the LSM tier spike (branch omap-lsm-20261026, unmerged)
Amends: 0021 (S2 WAL/replay, S5 tree, S8 listings, S9 omap, S11 counters, am. 15/45/59/63; 0491 listing encode); 0534 (credit per owner/helper pair, this ADR am. 3)

Plan, gates, effort, spike numbers: doc/perf/omap-redesign-plan-20261027.md.

## Context

One-object omap populate (rep3, 64 clients QD1): croit-flashstore-osd main is far below BlueStore on keys/s and p99 and saturates the primary PG core (numbers: doc/perf/omap-redesign-plan-20261027.md, "Context numbers"). Cause: omap lives in 4 KiB leaves of the shard's CoW B+tree; the checkpoint rewrites nearly one whole leaf per inserted key (write amplification ~30-40x); 0476 runs only defer the per-key tree merge, they do not remove it; helper compaction (0534) changed 0 %. The LSM tier spike (persisted segments next to the tree, dual paths, per-object flush policy, owner-side merges) reached WA 5-12 and OSDs died on a parked txn; it is not merged. A standalone engine spike (`buffered`: WAL group commit, RAM write buffer, paged sorted runs with fence index + bloom, size-tiered merge on a background thread, global (object, key) keyspace) on raw NVMe met the target and is the reference design.

## Decision

Engine (one per store shard, owned by the shard's core; module `store::olsm`):
- All omap of all objects of a shard (user omap, pgmeta: PG log/info/dups, every object size) lives in one LSM over the
  keyspace `(object id u64 BE, omap key)`. The CoW tree holds no omap key. One path; no size threshold, no conversion,
  no tree fallback, no per-object engine state. The omap header stays a tree record (`Hdr` slot, one value per object).
- Counterless: no per-object omap key/byte counters, no old-value lookup on any write (Ceph keeps none either;
  `num_omap_keys/bytes` come from deep scrub). Every omap write is blind, newest LSN wins.

(1) Write path:
- A txn's omap ops are WAL ops of its one record (atomic with onode, xattrs, data, PG log): `OPut{id, blob}` (sorted,
  validated batch blob as received, adr 0476 rule: borrowed message buffer, normalized once), `ODel{id, keys}`,
  `ORange{id, first, last}` (rm_range), `ORange{id, "", MAX}` (omap_clear, removal of an object with omap: onode flag `F_OMAP`). Commit = WAL durable (group
  commit and `wal_coalesce` unchanged, adr 0021 am. 37).
- Apply (owner core, after the record is staged, visible from apply as today): insert into the shard's active memtable:
  `HashMap<id, ObjMem>`, `ObjMem` = ordered map key -> (lsn, value | tombstone) + sorted range-tombstone list. Keys and
  values are not copied: entries reference the txn's refcounted WAL-unit / batch buffer. A put overwrites, a point delete
  writes a tombstone, a range tombstone also drops the object's memtable entries it covers. Commit and apply never touch
  a run, a leaf or a counter.
- Admission (adr 0175): the active memtable freezes at `mt_soft` = min(1/4 of the shard's memory share, 1/4 of the WAL
  ring). At most one frozen memtable per shard. Active at `mt_soft` while the frozen one still flushes: omap txns of the
  shard park on the flush-done wake (smooth throttle by flush rate, never an error, never a timeout).

(2) Flush:
- Freeze = O(1) swap on the owner at an LSN boundary `flush_lsn` (every omap op <= it is in the frozen memtable or older
  runs). The frozen memtable is immutable and shared read-only with one helper core (0534 lane).
- The helper iterates it in `(id, key)` order and writes one run: chunks (write / allocation unit, target 64 KiB, block
  aligned; an entry larger than the target is one chunk of its own) holding one entry stream that may straddle 4 KiB
  pages; then one meta extent: per chunk a fence entry (first/last key, extent, counts), per page the first entry
  starting in it (key + offset, packed last key, am. 4) and a crc32c per page, the chunk's blocked bloom (12 bits/key, 8 probes, am. 2; per chunk so a chunk can
  move by reference), the run's range tombstones, a trailer with crcs. Reads are page granular (see (5)). Extents are leased by
  the owner (allocator stays owner-only); the owner submits the blocks the helper built (am. 3).
- Commit: owner writes one record-only sys txn: manifest record `T_RUN + run id` -> (tier, lsn range, first/last key,
  extents, entry/byte/tombstone counts) and the shard's `flushed_lsn = flush_lsn`. Then the frozen memtable is dropped
  and the WAL floor may pass `flush_lsn`. A crash before that record leaves the leased blocks unallocated (free at mount).

(3) Merge (compaction):
- Size-tiered with fan `F` (default 8): size classes centred on `n0 * F^t` (bounds at `n0 * F^(t +- 1/2)`, so a flush
  is tier 0 whatever its payload/RAM ratio and a merge of F tier-t runs lands in t+1 after dropping shadowed entries).
  When F age-adjacent runs of one tier exist (smaller runs stuck between them are swept along, a larger run ends the
  window), one k-way merge of them writes one run of tier t+1 (newest wins; point and range tombstones applied; tombstones dropped when
  the merge includes the oldest run of the shard). Write-ahead as the flush (extents leased, written, one record-only
  txn swaps inputs for output; input extents freed through reader epochs).
- Chunk reuse: an input chunk whose key range overlaps no other input's chunk or tombstone moves into the output by
  reference (manifest points at the same extent, no rewrite). Disjoint objects (most of a shard) and append-ordered keys
  cost no rewrite. A chunk fully covered by a newer range tombstone is dropped without a read (object removal and
  omap_clear free space at the next merge that reaches them).
- Merges and flushes run on helper cores (0534 lane: immutable inputs, identity check at return, at most one job of an
  owner per helper, inline on single-core OSDs, same code; am. 3). Per shard: one flush + one merge in flight. Flush
  has priority over merges.
- WA budget: WAL 1 + flush 1 + ceil(log_F(N / n0)) merges, minus chunk reuse; target <= 3 device bytes per user byte for
  N <= F x n0 per shard, <= 4 up to F^2 x n0. A breach is a gate failure. Run organisation below tier 0: partitioned
  tiers (am. 2).

(4) Checkpoint and replay:
- The tree checkpoint persists no omap; the LSM manifest records are small tree records changed only by record-only
  txns. WAL floor = min(tree checkpoint floor, oldest unflushed omap op). Ring pressure (`ckpt_why` 2) starts the
  component holding the floor: a freeze + flush when the memtable holds it, else a checkpoint.
- Mount: read the manifest records, load per run its fence index and bloom (resident, adr 0175 charged), no chunk
  reads. Replay inserts every omap WAL op with lsn > `flushed_lsn` into the memtable (idempotent by lsn); other ops as
  today.

(5) Reads (owner core; same `Store` API):
- Get / by_keys: active memtable, frozen memtable, runs newest first (fence binary search, chunk bloom, page-start
  binary search, one 4 KiB page read + crc; the following pages in the same read only when the key may be the entry
  straddling the page end, am. 4); first hit wins; a newer range tombstone covering the key answers "absent". A page not cached = page `Miss`, parked
  and resumed as today's tree page misses; run pages share the shard's page cache.
- get_vals / list (start_after, filter_prefix, max): per-object merge iterator over memtables and runs, each source
  seeked to `after` through its fence index; reply encoded from the iterator (replaces 0491 leaf encoding). One call
  merges at most 4096 entries, live or deleted (`ListQuery::visits`): a span of tombstones costs one call per 4096.
  A refused run chunk or the end of a CPU slice returns the key position of the merge (`ListPos`, exact across flush
  and merge); the scan memo of adr 0021 am. 63 keeps it with the admitted entries and the retry continues there, never
  at the first key (memo invalidated by any staged omap op of the object). No short page with `more`.
- cls omap ops (cls_rgw, cls_rbd, cmpomap, ...) use these reads; read-modify-write within one op sees the txn's own
  staged ops through the stage overlay (unchanged contract).
- Runs referenced by an iterator or parked op stay alive (reader epochs) across a merge swap.

(6) Other consumers:
- Clone / snapshot clone: copy the source's omap into the new id as one sorted `OPut` batch (as today's key copy; no
  shared runs). PG split / merge: same shard = `MoveRename`, object id unchanged, omap untouched; cross shard = copy by
  scan (as today). Object removal, omap_clear, rm_range = one range tombstone. Snap trim and PG removal = object removals.
- Recovery / backfill push: chunked by a key cursor and byte budget; `num_omap_keys` in `ObjectRecoveryInfo` (nv-internal)
  and `omap_key_count` go; "heavy object" = a push that needs more than one chunk. Migration headroom: shard LSM live
  bytes instead of per-object counters.
- Scrub / deep scrub: digest by iterator scan (1024-key batches, per-PG park slot unchanged); deep scrub sets
  `num_omap_keys/bytes` as Ceph does. Large-omap thresholds from the scrub scan.
- Stats: PG `num_omap_*` from scrub only (Ceph semantics); `statfs` omap bytes = run bytes + memtable bytes per shard.
- Values: inline in entries up to the existing omap limits; no external-value or fragment path for omap; no zstd value
  dictionaries for omap (`FEAT_VAL_COMP` stays for xattrs only if used there).
- Replicated and EC pools, SPDK and kernel NVMe tiers: same store txns, same engine.

(7) One hot object over several cores: not in phases 1-4. Owner work per key is WAL copy + crc + memtable insert
  (estimate in the plan doc). If the gate shows the owner core saturated below target with idle helpers, the next
  step is the "split front" of doc/perf/omap-kv-sota-20261027.md (memtable partitions on other cores), no format change.

(8) Removed at phase 3 (no dual paths): tree omap (`T_OMAP` records, omap frags / external values, omap leaves in
  freeze/checkpoint, 0491 leaf encode), adr 0476 runs (`runs.rs` run set, re-log, floor index, run compaction, tree
  merge, pacing, `RunPut`, `DelCounted`, `PutCounted`, blind tree ops, `run_*` knobs), omap counters
  (`FEAT_OMAP_COUNTERS`, onode counter fields, `c` records, `omap_stats`, `rm_cur` pre-scan, `omap_rm_prep`), omap
  value compression, `warm_omap` leaf warming (becomes chunk prefetch), 0534 run-compaction job types (lane, permit
  and dispatch protocol stay for flush/merge jobs). Format: mkfs feature `FEAT_OMAP_LSM`, required; tree-omap stores
  convert offline (adr 0611 S7, `croit-flashstore-tool upgrade`).

Phase 2a (am. 1, 2026-10-27; branch olsm-p2-20261027): as above, with these concrete choices:
- Format: mkfs `FEAT_OMAP_LSM` (`MkfsParams::omap_lsm`, `croit-flashstore-tool mkfs --omap-lsm`, conf `flashstore_omap_lsm`), not
  required until phase 3; a store without it refuses omap WAL ops. Manifest = tree records `l R <run id be64>` (run
  descriptor) and `l F` (`flushed_lsn`), outside the object key space. The manifest txn is a sys txn whose record
  carries the run's written extents (allocated at apply like data extents; reserved ring unit so it is never refused
  for ring room).
- Memory: a store with the engine gives half of the shard cache share to it; of that, a quarter per memtable
  (`mt_soft`, also <= 1/4 ring) and half for a run block cache owned by the engine (run pages do not enter the tree
  page cache; an extent used since the last completed read is not evicted, so a re-run after a miss progresses).
- Throttle: a txn with omap ops is refused `Busy` (busy reason 10) while active >= `mt_soft` and a frozen memtable
  is flushing; the executor parks it as other `Busy` refusals and the flush completion wakes it.
- Txn overlay: the stage applies its own omap ops to a private memtable, the newest read source of the txn's reads.
- fsck: the shard fsck loads each run's meta and counts its extents as referenced.
- Ring pressure: a `WalFull` refusal of a client record freezes the memtable holding the WAL floor (the half-ring freeze
  reads the floor of the engine being stepped); the client WAL reserve keeps `2 * max_unit_blocks` for the manifest txn
  (its admission needs two units free after the open unit). A refused manifest txn gets its run extents back for the
  resubmit (tests in `tests/olsm.rs`).

Partitioned tiers (am. 2, 2026-10-27; branch olsm-hybrid-20261027; measurements doc/perf/omap-redesign-plan-20261027.md):
- Tier 0 = flush runs, unpartitioned (any key range), newest first. Tier t >= 1 = disjoint key-range partitions
  `[lo, hi)`, each holding < F runs newest first (run id = age order inside tier 0 and inside a partition).
- Policy: F tier-0 runs merge into tier 1; a partition with F runs merges into tier t+1 (push-down). A bottom partition
  merge (no deeper tier holds data in its range) whose output stays below size class 1 (`< cut x sqrt(F)`, cut below;
  mostly shadowed/deleted data) stays in tier t (in-place), so overwrite and append+trim loads do not deepen the tree.
- Merge output is routed by the target tier: one output run per overlapped target partition (keeps its bounds); key
  ranges between target partitions are cut into fresh partitions of `max(n0, chunk target)` bytes each (am. 6; was
  `input / F`, which split partitions geometrically to single keys), guard = first key of the piece (chosen from data
  at merge time, no fixed key constants). Range tombstones are clipped to each output run's
  partition; a tombstone spanning partitions lands in each. Chunk move-by-reference unchanged (a chunk straddling a
  target bound is rewritten).
- Locks: a merge locks (tier, range) of its source and target until its manifest txn installs; disjoint partitions
  merge concurrently.
- Reads: point get = memtables, tier-0 runs, then one partition per deeper tier (binary search on bounds). Scans walk
  segments between consecutive partition bounds, merging only the runs of the partitions covering the segment.
- Manifest record v2 adds `(tier, lo, hi)` per run; v1 records are refused (prototype, re-mkfs). Mount checks bound
  order, disjointness and run containment.
- Bloom 12 bits/key, 8 probes per 512 bit block (was 10/6, failed the 64 x n0 read gates; numbers in the plan doc).
  Per run a packed `(id, 8 key bytes)` array of chunk last keys makes the chunk
  search touch 16 B per step instead of a fence + key pointer.

Helper jobs (am. 3, 2026-10-27; branch olsm-p3a-20261027; measurements doc/perf/omap-redesign-plan-20261027.md):
- A flush or merge is a continuation (`olsm::remote::Task` + `Ctx`: leased extents, written blocks, supplied input
  chunks) that steps in rounds on any core. A round ends when the job finished, its lease cannot hold the next block
  request, or it needs an input chunk it was not given. The helper does the CPU work (entry encoding, page crcs, blooms,
  page index, k-way merge, chunk crc checks); it never touches the allocator, the device or the engine state.
- Owner at a round boundary: queues the written blocks for its device (slices of the helper's buffers, no copy), leases
  `queue depth - WAL data floor` chunk-sized extents (plus one extent for a longer request: a meta, an oversized
  entry), supplies the missed chunk and a read-ahead of `(queue depth - floor) / inputs` chunks per merge input (job
  reads bypass the run cache, a cache hit is used), hands the round out. Manifest txn, installs, frees, WAL floor,
  throttle and ring pressure stay on the owner unchanged; the frozen memtable stays in the engine while its flush is
  away.
- IO: the owner submits (cost per 64 KiB chunk, not per key; helper IO would need a second completion path and
  queue-floor accounting on another core, on both tiers).
- Lane: the 0534 completion-mesh messages carry `HelperJob {Run, Olsm}`; an owner holds one credit per helper core (at
  most one of its jobs on each other core, round robin over free helpers; was one job per owner). Flush rounds of all
  shards are handed out before merge rounds and run compactions.
- Default: on whenever the store has the engine and the OSD has more than one core (no switch). Single core, a dead
  core or stopping: the owner steps the rounds itself (bounded by the free queue slots per poll). Run compaction (0476)
  goes to helpers by default as well (adr 0534 am. 1; `flashstore_store_compact_helpers=false` keeps it inline).
- Memory (adr 0175): a job away holds at most its lease of written blocks plus its read-ahead; both bounded by the
  device queue depth. The memtable throttle and `mt_soft` are unchanged.
- Crash semantics unchanged: leased extents are reservations until the manifest txn (free after a crash); a lost or
  stale job (other mount) is dropped. Counters `olsm_helper_rounds`, `olsm_inline_rounds`.

Point reads (am. 4, 2026-10-27; branch olsm-reads-20261027; measurements doc/perf/omap-redesign-plan-20261027.md):
- Page start index entry also holds the packed key `(id, 8 key bytes)` of the last entry starting in the page (meta
  `OLSMRUN3`, +16 B per page on disk and resident). A get decides before its read: key below it = the page alone; equal
  = the pages up to the next page start in one read; above it = absent in this run, no read. Was: page read, then a
  second read of page + following pages for every key in a straddling entry.
- Run cache remembers per extent which of its first 64 pages passed their crc (`ChunkRead::read_checked` /
  `checked`); a hit on checked pages skips the crc. Extents are found by first block in a hash map (fx hash), a range
  starting inside an extent through an ordered set of first blocks; forget / evict drop the marks with the extent.
- `by_keys` continues past a run block `Miss`: the blocks of all keys are requested in one pass, then `Miss`.

Garbage-driven merge and extent-sized chunks (am. 5, 2026-10-28; design + sim numbers
doc/perf/olsm-oq115-design-20261027.md sections 4, 8):
- Garbage estimate per group (tier 0, each partition) from run meta, kept as additive sums updated at manifest
  install/remove (O(1) per pick, no IO, no allocation): tombstone bytes + tombstones x shard mean put size + older
  chunks wholly covered by a range tombstone (fixed at insert).
- `pick_merge` order: space pressure (free < 3 x flush output, or `alloc_waits` grew) picks GC at `GC_AMP` 11/10;
  else size-tiered; else routine GC at 13/10. GC action and due rule: am. 6.
- Admission: an omap txn waits (Busy, `olsm_space_throttled`) while a merge runs and used > 1.3 x live + slack -
  2 x flush output; the merge install wakes it. Leases are capped at n0 per round.
- Chunks lease 4..16 free blocks and seal on `BlockSink::room()`; no format change. Flush slot unchanged.

Column GC and incremental pick (am. 6, 2026-10-28; branch olsm-pick-20261028; derivation, sim numbers
doc/perf/olsm-pick-20261028.md):
- A tombstone and the put it shadows vanish only in a merge reaching the deepest data of its range. GC action =
  column merge: group G plus every deeper partition overlapping its range, widened tier by tier (closed downwards:
  age order holds), output as fresh partitions at the column's deepest tier; a bottom partition merges in place.
  Middle tiers may be empty.
- Due rule from the space target `used <= (num/den) x live`: column share `g / B >= (num - den) / num`
  (3/13 routine, 1/11 pressure) <=> WA per reclaimed byte `(B - g) / g <= den / (num - den)` (3.3). A merge runs only
  when it pays this price; a push-down that reclaims nothing is never a GC merge.
- Candidates: each partition with own garbage (its column, best share first), then the shard column (tier 0's oldest
  F runs + all partitions; share = shard total minus newer tier-0 runs). Shard due => a candidate is picked, so the
  am. 5 bound holds; a locked best candidate never blocks a due other one.
- Pick cost O(log n): sets `full` (partitions with F runs) and `due` (by share), list `dirty` (gained a run); a
  column is estimated when dirty and re-checked when first in `due`. Counter `olsm_pick_visits`.

## Rationale

- The measured cost is leaf rewrite at checkpoint; any design keeping omap in CoW leaves keeps it (0476, 0534, LSM tier
  dual paths). A memtable + immutable sorted runs writes each key ~2-3 times, sequentially, in large IOs.
- Per-shard keyspace instead of per-object LSMs: one flush unit of n0 bytes regardless of object count (low WA for many
  small objects: pgmeta, RGW index shards, dirfrags); one manifest per shard; no per-object flush policy (the spike's main
  complexity and stall source); removal = range tombstone; the `buffered` spike measured this shape.
- Counterless removes the old-value lookup from every write (largest owner cost in the arch review) and matches Ceph.
- Flush and merge on helpers give the parallelism of a background flush/merge pool (BlueStore spends most of its CPU
  in RocksDB threads), with ~3x fewer rewritten bytes than leveled compaction.
- Point reads (am. 4): IO count and memory traffic set the get cost, not instructions: a cold get is one read, a
  warm get touches the cache map, the bloom lines and the page bytes once.
- Partitioned tiers (am. 2): a partition merge rewrites only its key range (skewed/append loads merge where they
  write); in-place bottom merges keep the depth at log_F of live data; no tier-wide merges at depth >= 2. Probes per get stay ~F per
  tier; the filter rate and the cheap chunk search carry the read gates.
- Trade-off accepted: point gets may probe up to ~F x tiers blooms and read one chunk on a cache miss (rmw-style cls loads
  pay read amplification, as the RAM reference engine).

## Consequences

- + No per-key leaf write; checkpoint size independent of omap load; WA ~2-4 instead of 30-40.
- + Owner core per key: byte work + one ordered insert; background ordering work on idle cores.
- + Object removal / omap_clear / PG removal O(1) on the owner; space returns at the next merge.
- + Deletes 0476 runs, counters, blind ops, omap tree paths.
- - New on-disk structures (runs, manifest records), new WAL op set; fsck must check runs (extents, crcs, manifest).
- - Bloom + fence + page index resident (~1.5 B/key bloom + one key and 10 B per 4 KiB page + 16 B per chunk, am. 2),
  charged to adr 0175.
- - Clone of an object with a large omap copies it (unchanged from today).
- - `num_omap_keys` in PG stats only after deep scrub (Ceph behaviour; nv main is exact today).
- - Helper cores also own PGs: background load lands on their PG latency (gate: p99 of helper-core PGs).

## Alternatives

- Keep omap in the tree, defer leaf writes (0476 runs, sub-page dirty tracking, ckpt fold): WA unchanged at checkpoint;
  0534 helpers 0 %.
- LSM tier next to the tree (branch omap-lsm-20261026): dual paths, per-object segments, WA 5-12, lab deaths; superseded.
- Per-object LSM (manifest per object): tiny flush units for small objects, per-object policies; rejected for KISS.
- Omap index partitions on other cores, CoW format (doc/perf/omap-daos-study-20261027.md): leaf rewrites stay.
- Log-is-data + RAM index (KVell/FASTER): 100+ B RAM per key, random reads in listings.
- Leveled compaction: WA ~10 at our sizes.
- One filter per partition naming the run (Splinter-style routing filter, am. 2): probes O(tiers) instead of
  O(F x tiers); deferred until the spike/G1 shows probe CPU limits point gets (owner CPU at 64 x n0 ~2x that at 8 x n0).
- RocksDB / any LSM library: excluded (user).
- GC estimate from fence overlap (am. 5 draft): O(runs x chunks), misses tombstone-only chunks. GC by one-tier
  push-down (am. 5): reclaims nothing above the bottom, fired on every flush (am. 6). Bottom-only GC: space 8x live.

## Open questions

- Phase 2a: run pages in their own cache (half the engine share) vs the shared page cache of (5): measure hit rates in
  G1/G7 before unifying.

- Memtable index structure: std `BTreeMap` per object with an inline 8 B key prefix (cost per key:
  doc/perf/omap-redesign-plan-20261027.md phase 0). Prefix-compressed or arena structure if shared key prefixes matter
  in G1/G7.
- Run blocks from the builder are heap `Vec`s: the device submit copies them into a DMA buffer when `view_buf` refuses
  the memory (alignment, SPDK). Builder chunks in DMA-capable aligned buffers would remove the copy (inline and helper
  alike).
- Bloom / fence residency for very large shards (20M+ keys per object x many objects): page out per run, or maplets.
- Value separation for large values (>= 64 KiB, WiscKey style): only if measured.
- Chunk compression (LZ4) when OSDs share an NVMe: measure after phase 3.
- Omap key length limit (today 3308 B from the leaf page): keep for now; chunks allow larger keys.
