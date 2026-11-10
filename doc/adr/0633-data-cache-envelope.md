<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->

# 0633 Data cache sized from the memory envelope, in ordinary memory, segmented LRU

Status: accepted, amended (am. 1, am. 2, am. 3)
Date: 2026-10-31
Amends: 0043, 0175

## Context

The store data cache (adr 0043 "Data cache", am. 15) had a fixed capacity: `PF_MAX_BLOCKS` = 8192 blocks = 32 MiB per shard, shared with the prefetch table, held in DMA-arena buffers (kernel tier: the 512 MiB registered `kdev` arena), outside the memory envelope (adr 0175, OQ 98 (2)). Customer-like bench (EPYC 9455P, 1 OSD, kernel-cmd, 6 cores, `osd_memory_target` 12 GiB, caches 10752 MiB): QD1 seqread over a 4 GiB set read once before = 0.54x (4K) / 0.74x (64K) of BlueStore, which serves the re-read from its cache; croit-flashstore-osd re-read it from the device. The tree page cache owned the whole cache share (8 GiB of tree pages for a working set of 1024 onodes).

## Decision

1. Capacity: per shard, data cache + prefetch table hold at most the floor (`ShardCfg::data_floor_blocks`) plus the bytes of the shard's tree page budget (`cache_pages`) the tree has not allocated (`Tree::unallocated_bytes`: the slab grows on demand and keeps every page it allocated). Metadata first: when the tree grows, the data cache gives the memory back (evicted at the next prefetch admission and at the store sweep, `ShardStore::dc_fit`), down to the floor. `perf dump` `data_cache_cap_blocks` reports it. The prefetch table keeps its own IO cap (`PF_MAX_BLOCKS` = 8192 blocks in flight or waiting for their op, unchanged).
2. Envelope: `StoreCfg::for_memory` reserves the floor out of the shard's cache share before sizing the tree units, scaled with the share: floor = min(32 MiB, share / 16, share - 42 MiB), where 42 MiB = the smallest tree (4096 pages + dirty marks + point cache + delta chains). The minimum `osd_memory_target` is unchanged (floor 0 at the minimum); 1/16 is the omap run budget's fraction, so a small share keeps room for its runs (`carve_runs` takes them only from pages above 4096); 32 MiB from a 512 MiB share up. The lent part is inside the tree's share. Data cache + tree pages <= cache share.
3. Bytes live in ordinary process memory: prefetch reads whose runs may stay cached (`pf_retain`) read into a buffer from `BlockDev::alloc_buf_ram_uninit` when `BlockDev::ram_reads()`. Kernel tier: registered cache chunks (am. 1): per thread 2 MiB anonymous mappings registered on demand as fixed buffers of the device ring (sparse table slots 1.., `IORING_REGISTER_BUFFERS_UPDATE`), buffers carved bump-style and reused by exact size, the next chunk mapped in 4 KiB pages (`MADV_NOHUGEPAGE`) and populated two pages per carved page while the current one is carved, so growth registers resident pages (am. 2), a chunk with no live buffer unregistered and unmapped after the cache evicted (`BlockDev::trim_ram`, called from `dc_fit`); never the arena. A read the region cannot take (no sparse table, 8192 chunks = 16 GiB per core used, above 512 KiB, registration error) uses plain heap memory and a block-node read (counter `kcache_heap`). Zero copy stays: the device fills the buffer, the reply and the cache share it (`into_shared`), a hit is a reference. The arena stays for writes, sync / rolling reads, tree pages.
4. A device without RAM reads (SPDK: DMA buffers only from hugepages) lends nothing: its data cache stays at the floor (open question 1).
5. Eviction: segmented LRU with intrusive lists in a slab (`obj/datacache.rs`), replacing CLOCK. A cached run enters probation; a read of it (a re-read; the read that filled it was the first) moves it to the protected list; the protected list holds at most half the capacity, its oldest runs go back to probation. Evictions take the oldest probation run (protected only when probation is empty). A probe (`touch`) moves a run to the newest end of its list without promotion. Every step O(1): insert, hit, eviction, demotion, forget; no ring, no compaction pass, no reference-bit sweep.
6. Lazy growth: nothing is pre-faulted at start; buffers are allocated per prefetch read. Kernel tier: one chunk ahead of the carving is populated (decision 3, am. 2), so growth never faults a chunk in on the op path; a thread's first chunk is faulted in by its registration.

## Rationale

- The working set that fits BlueStore's cache must fit ours (charter: never worse than BlueStore). The tree page budget is mostly idle on data workloads (RBD: one onode per 4 MiB object) and full on omap workloads; lending its unallocated part gives data what metadata does not use, with no ratio to tune and no second knob (adr 0175 one-knob rule). Metadata keeps priority because a metadata miss blocks the op's gate; a data miss is one device read.
- Ordinary memory instead of a bigger arena: the arena is registered (pinned, populated at start, hugepages that may not exist), bump-only and shared with every IO; sizing it to GiBs would pre-fault the whole cache share at start and let cached bytes starve the write path. A copy at insert would add a memory pass per cold read (charter: no avoidable copies). The registered chunks of am. 1 are the middle way: fixed buffers, grown on demand and handed back.
- Scan resistance: CLOCK protects a run only for one hand rotation, so a stream of one cache size wipes the cache; with a GiB cache a CLOCK sweep over all-referenced entries is also one long pass on the PG core. SLRU keeps up to half the cache for runs read twice and is O(1) per step. Half: a hot set up to half the cache survives any stream, and a new working set whose reuse distance is up to half the cache is promoted (accepted trade-off: a stale protected half shrinks the room for a new working set with longer reuse distance until promotions demote it).

## Consequences

- + Re-read of a working set within the cache share is served from memory (zero copy), as BlueStore's buffer cache does.
- + The data cache is inside the envelope; the floor (up to 32 MiB/shard) is now counted (tree pages up to -32 MiB per shard at equal target); the minimum target is unchanged.
- + Eviction cost bounded per step at any capacity; a read-once stream cannot evict runs read twice (up to half the cache).
- - Kernel tier: a cache chunk is pinned when registered (2 MiB per growth step; 16 MiB steps raised QD32 cold p99 by 20 %); the next chunk per thread (2 MiB, outside the block count) is resident ahead of need, populated by one write fault per 4 KiB page while the current one is carved, and its registration still costs ~25-90 us (test runner, tsrv2) of the read that opens it (am. 2); memory of a chunk with one live buffer stays until that buffer goes (fragmentation bounded by 2 MiB per chunk). Chunks use 4 KiB pages also under THP `always`.
- - Per cached run ~100-150 B of bookkeeping (slab node, map entry, crcs, `Bytes` owner) outside the block count: <= ~4 % at 4 KiB runs.
- - RDMA (opt-in): a cache hit is outside the registered arena/heap and is copied into the send arena (the device read it replaces was zero copy).
- - SPDK tier unchanged (floor only).

## Alternatives

- Arena sized from the cache share: rejected (pre-faulted + pinned at start, hugepages, shared with all IO).
- Copy into heap at insert: rejected (one memory pass per cold read on the PG core; large streaming reads).
- Fixed ratio of the cache share for data: rejected (wrong for either RBD or omap workloads; a second tuning point).
- CLOCK with a larger capacity: rejected (no scan resistance; O(n) sweep after a fully referenced pass).
- 2Q / S3-FIFO with a ghost list: rejected for now (more state; SLRU covers the stream case).

## am. 1 (2026-11-01): cache-fill reads into registered chunks

adr 0169 am. 11 made passthrough name only registered buffers (plain user addresses can be truncated to 32 bits in an io-wq worker), so the heap buffers of this ADR's decision 3 turned every cache-filling read into an O_DIRECT block-node read. Measured (zen4a, doc/perf/dc-fill-registered-20261101.md): cold randread 4K -4 % IOPS / p99 +14 %, 64K -2 %, QD32 -2 % vs the plain-passthrough build; with chunks cold fills are +2 % (4K, 64K) / +5 % (QD32) over that main, re-read unchanged. Decision 3 now reads into per-thread registered cache chunks (text above); `KBuf` kind `Cache { slot, ring }` names its fixed-buffer index, `passthrough_ok` accepts arena buffers and the chunks of the command's own ring. Buffers dropped on another core go back through the owner's inbox (`shelf::Returns`, key `CACHE_KEY | slot << 16 | class`), as arena buffers do. Siblings: direct mode (`ReadFixed` with the chunk index) shares the path; SPDK keeps the floor; replicated and EC read through the same store path.

## am. 2 (2026-11-02): populated growth

Registering a fresh anonymous chunk pins it, which faults and zeroes all 512 pages (THP `always`: one 2 MiB huge-page zeroing) inside the read that needed room: 1 of 512 4 KiB cache-filling reads paid 0.6-0.9 ms while the cache grew (tsrv2 r4kj1q1 p99.9 0.85 ms vs BlueStore 0.22 ms; 435 slow traced reads = 435 chunks registered over the cell, doc/perf/r4k-tail-20261102.md). The chunk after the current one is now mapped ahead with `MADV_NOHUGEPAGE` and written one byte per 4 KiB page, two pages per carved page (resident once the current chunk is half carved; a buffer is at most a quarter chunk), so growth registers resident pages: test runner 12-40 us vs 0.3-0.7 ms fresh (`cache_chunk_registration_cost`); tsrv2 r4kj1q1 p99.9 0.84 -> 0.24 ms (BS 0.22), CPU +2.9 %/op while the cache grows (one write fault per 4 KiB page), +2 MiB resident per store thread. 4 KiB pages so the population spreads under THP `always` (a huge page would fault whole at the first write). Siblings: direct mode shares the region; SPDK keeps the floor (DMA pool, no growth); knet / AF_XDP / zcrx buffers and the arena are registered populated at start; replicated and EC read through the same store path.

## am. 3 (2026-11-02): population between ops measured and rejected

Moving the next-chunk population out of the carving allocation into bounded steps of the device `poll` (64 pages per loop iteration) made the first 4 MiB read cell after a prefill worse on tsrv2: r4mj2q2 ops -8.8 %, p99 +19 %, CPU/op +16.5 % vs the inline population of am. 2 (doc/perf/r4m-tail-20261102.md, archive branch `archive/kdev-populate-between-ops`). Decision unchanged: am. 2 populates inline while the current chunk is carved. Open: the first-cell p99 vs BlueStore.

## am. 4 (2026-11-02): operator cache drop

`ceph tell osd.N cache drop` (alias `flush_store_cache`) drops every clean cache of the OSD, as BlueStore's flush does for its onode and buffer caches (spec: doc/spec/ops-observability.md). Per core, between operations: data cache runs (`DataCache::clear`; entries hold no reader pin, so no wait; the prefetch table is request state and stays), decoded compressed chunks, the per-PG object-state cache, the clean omap run cache, and clean tree pages (`Tree::drop_clean`; dirty, in-flight, checkpoint-held (`F_FRZ`/`F_AGAIN`) and pinned pages stay, so changes and leases are never lost) and the page buffers of all free slab slots are released (`Tree::released`, the next page in such a slot allocates), then the device cache memory is trimmed (`trim_ram`). Dirty pages are dropped only after a checkpoint made them clean: `flush_journal` first for a fully cold tree. Reply: exit 0, empty output; `cache status` reports resident gauges and the running totals of drops. Rationale: cold-read benchmark cells need a real drop on both stores; a no-op made croit-flashstore-osd cells warm. Siblings: kernel-cmd and SPDK tiers share the store path (SPDK's floor cache is dropped as well); replicated and EC read through the same store; knet/AF_XDP not affected (no payload cache in the transport).

## am. 5 (2026-11-08, omap hot read): the run block cache borrows the same envelope

Status of the gap: omap-real or-r1a (9 GB omap, 4 GiB target): the LSM engine read 150 GB from the device in 121 s and used 2.3 GiB of the target. A store with the omap engine halves the shard's tree cache for the engine (`mem`: memtables + run block cache = 1/2 of the share, the run cache half of that = 1/4); the tree half holds only onodes and stays unallocated, while the run cache stayed at 1/4.

- Run block cache capacity = its own share (`mem / 2`) + its part of the lendable budget (the tree page budget not allocated, `Shard::lendable`; 0 when the device reads only into a DMA pool, decision 4). Set every driver pass (`olsm_drive`).
- One lendable budget, two borrowers (data cache, run cache): each takes the other's unused part, never less than half (`Shard::lend_share`: max(L/2, L - other's borrowed bytes)). Work conserving: an RBD-only store gives the data cache all of it, an omap-only store gives the run cache all of it. The data cache reports its bytes above the floor (`set_data_cache_held`, in `dc_fit`); the run cache's borrowed bytes are its bytes above `own_cap`.
- Run extents that stay in the cache (demand and listing-prefetch reads of one transfer) are read into ordinary memory (`alloc_buf_ram_uninit`, registered cache chunks on the kernel tier) instead of in-flight IO memory, so the cache can exceed the bounded DMA budget; merge-job input reads and multi-part reads keep the IO path. Evicted extents hand idle chunks back (`trim_ram` after each cached completion).
- Metadata first: the tree growing shrinks the lendable part. Both caches converge without an insertion of their own: a smaller run cache cap evicts at once (`RunCache::set_cap`), the store sweep fits the data cache first and then the run cache from the bytes the data cache holds after its eviction (`olsm_fit_cache`), so an idle read-hot cache gives its borrow back (soft, adr 0175).
- Format: none. Siblings: SPDK tier lends nothing (unchanged); RocksDB engine out of scope; tree-omap (B+tree) has no second cache, its omap leaves are tree pages (measurements doc/perf/omap-hotread-20261108.md).

## Open questions

1. SPDK tier: data cache beyond the floor needs DMA-able ordinary memory (register envelope memory with SPDK on growth) or a copy at promotion; until then SPDK keeps 32 MiB/shard (doc/90-open-questions.md).
2. The tree slab never shrinks: after a metadata-heavy phase the data cache stays at the floor until restart. Partly answered (adr 0062 am. 3): a shard whose tree page budget moves to another shard releases the buffers of its free slots above the new budget; a shard that keeps its budget still keeps its slab.
