# 0059 Per-pool opt-in store compression (Ceph-compatible `compression_mode` pool options), chunked extents

Status: accepted, amended (am. 6); file name kept from the original "no compression" decision, which am. 1 superseded
Date: 2026-10-11
Consolidated 2026-10-19; full pre-consolidation text: git show 60868596d:doc/adr/0059-no-store-compression.md

## Context

BlueStore compresses blobs per pool (`compression_mode` none|passive|aggressive|force, `compression_algorithm`, `required_ratio`, min/max blob size; pool_opts keys 6..10). Our store (adr 0021) maps objects to fixed 4 KiB blocks with a crc per block seeded by the physical address, DMA from network buffers to NVMe, scrub digests over logical bytes. Mandate 2026-10-12: 100 % functional parity with classic except Lua, so compression is implemented as a per-pool opt-in. Targets/budget: adr 0006.

## Decision

Zero-cost rule: a pool with `compression_mode` none (classic default) runs the identical path; one per-op flag test from the cached `PoolCompression`; no extra on-disk bytes; stores without compressed extents unchanged.

Semantics (classic, own words):
- `compression_mode`: passive = only with client alloc hint COMPRESSIBLE, aggressive = unless INCOMPRESSIBLE, force = always. Hint scope = txn (mode x OR of the txn's alloc-hint flags), not object.
- `compression_algorithm` snappy|zlib|zstd|lz4 (pool opt, else OSD default `snappy`; unknown = store uncompressed, log once).
- `compression_required_ratio` (default 0.875): keep the result only if `comp_len <= ratio * raw_len` after rounding up to 4 KiB.
- `compression_min_blob_size` / `compression_max_blob_size` (pool opt, else `bluestore_compression_{min,max}_blob_size[_ssd]`; 0 -> ssd defaults 8 KiB / 64 KiB). Options read from pool_opts keys 6..10; no OSD-side validation. Pools without own `compression_*` follow `bluestore_compression_{mode,algorithm,required_ratio,...}`, re-applied on config change (`pg_reapply_compression`).
- Alloc hints are otherwise stored in oi, never acted on.
- RGW compression is done by the gateway; the OSD only sees stored bytes.

Layout (adr 0021 `e` extents, 4 KiB blocks):
- Chunk = logical range aligned to `max_blob_size` (default 64 KiB = 16 blocks). Full aligned chunks, and each piece between chunk boundaries and the write span edge that is >= `min_blob`, are compressed (`Stage::finish_inner_budget`; `write_chunk` takes any length; extent record carries the logical span). Writes shorter than min_blob are stored raw.
- Extent value: flag byte 1 = COMPRESSED + trailer `alg u8, raw_blks u8, lcrc u32` (`raw_blks` = logical span, <= 64; `len_blks` = physical blocks, payload = u32 comp_len + bytes, zero padded). Onode flag `F_COMP`; onode fmt 3 and `C` fmt 2 carry counters. Per-block crc list covers PHYSICAL blocks (fsck/read/scrub verify before decompress); `lcrc` over the logical chunk gives deep-scrub a post-decompress check.
- Key `(id, 0x03, logical_blk)` of the record's first logical block. Chunk windows (am. 4, store `FORMAT_VERSION` 2, the only overwrite behaviour; compression needs `FEAT_SHARED_EXT`, a legacy store without it stores raw): a mutation inside a compressed chunk writes only its own blocks; `punch` replaces the cut record by up to two window records of the same chunk (flag `EXT_VIEW` = 4, trailer + `skip u8, win u8`: decoded blocks `[skip, skip+win)` = logical `[lblk, lblk+win)`; span = `win`). The windows share the chunk's physical blocks through the refcount records of adr 0021 am. 32 (two parts = one owner more, `EXT_SHARED`; no part = one owner less; the last owner frees the chunk). Nothing is read, decompressed or recompressed: a 4 KiB overwrite costs what it costs on an uncompressed pool (own design: new small window over the old compressed chunk). Counters: a window is charged `len * 4096 * win / raw_blks` physical bytes and `win * 4096` logical bytes (fsck recounts the same). Space rule (own design): when a mutation leaves fewer logical blocks in a chunk's windows (same object) than the chunk's physical blocks, `pull_in` reads those windows into the overlay (one read + decompress) and the chunk is released at flush: a chunk plus its overwrites never occupies more blocks than its logical span; not while a clone shares the chunk; counted in `perf dump` `bluestore.gc_merged` (bytes, as BlueStore). The former whole-chunk path (read, decompress, merge, recompress on every overwrite) is removed; stores of format 1 are refused (re-mkfs). Ranged read of a window decompresses the whole chunk (as before; `DecompCache` key pba + lcrc serves every window of a chunk). Read path (am. 5): decoded chunks are shared buffers (`Bytes`; `DecompCache`, request-retained results). `read_shared` of a range made only of compressed windows (>= 64 KiB) replies with one piece per window by reference to the decoded chunk, crc of a whole chunk = its `lcrc` combined (no pass, no result buffer, no copy); a ready prefetch entry is decoded in place; the copy path also sets `read_crc`. Mixed ranges and small reads copy as before.
- Code map: `store::compress`, `obj::stage` (`pull_in`, `pull_edge`, `write_chunk`, `read_with_comp`, `finish_inner_budget`), `obj::onode`; adapter `set_pool_compression` + per-txn resolve; per-chunk latency ns sums kept per shard in `ObjStats`.
- Clone (`clone_obj`) shares the source's records, compressed chunks and windows included (`EXT_SHARED`, adr 0021 am. 32); `clone_range` never shares compressed data: it copies logical bytes and compresses by its own txn spec. Recovery/backfill/scrub/copy-from work on logical bytes; replicas compress independently (compressed form never on the wire); digests logical; mixed acting sets fine.
- All-zero chunk never stored (hole rule). Sampling fast path `compress::sample_incompressible`: chunks >= 16 KiB first compress one block from the start and one from the middle; both >= max(required_ratio, 0.95) of the block = skip (counted `compress_skipped_count`, not rejected).
- Read cache: per-shard `DecompCache` (4 entries, round-robin, key pba + logical crc); entries overlapping a txn's frees dropped at submit; scrub/fsck bypass.
- Superblock bit `FEAT_COMPRESSION` (512, sticky): while unset, a chunk that would compress is staged raw and flags the shard; `Store::queue` drops that staged txn, drains the shard queue, writes both superblock copies with the bit (durable), then stages the txn again compressed: bit durable before the first compressed extent. Sticky in `read_super`/`heal_super`. Failure = raw until remount. Downgrade unsupported once set.
- Accounting: counters live in the onode (move with `MoveRename`, splits) and sum into the collection record in the same txn (`CollStats::comp/comp_orig`); statfs `data_compressed`, `data_compressed_original`, `data_compressed_allocated` = sum over PGs of every core (`ceph df detail` USED COMPR / UNDER COMPR). `perf dump` `bluestore` logger: `compressed`, `compressed_allocated`, `compressed_original`, `compress_success_count`, `compress_rejected_count`, `compress_skipped_count` (croit-flashstore-osd), `gc_merged` (am. 4), `compress_lat`, `decompress_lat`.
- Compute on the shard core on a per-core scratch arena (no alloc); only compressing pools lose zero-copy DMA (one extra pass).
- Codecs (`store::compress`: Alg, Mode, PoolComp, CompSpec, Codec, SoftCodec), all standard formats so old extents stay readable: lz4 = `lz4` crate (C, FAST(4)), zlib = `flate2` zlib-rs backend raw deflate level 1, zstd level 1 fixed (KISS; `compressor_zstd_level` is accepted and ignored), snappy = `snap`. Algorithm set fixed by Ceph compat; implementations chosen by measured speed (doc/perf/adr-0059-history.md).
- Operator note: when a pool's compression mode is set the control core logs once per (pool, mode) per OSD run (`compress_noted`, pgs.rs); no clog, no health warning.
- Tests: `store/tests/obj.rs` compress*, compressed_chunk_multi_op_txns, decompressed_chunk_cache, model_compression, crash_matrix_objects_compression, perf_compression (ignored); `store/src/compress.rs`; `obj/onode.rs`; `storeadapt/tests/compression.rs`; osd xcore_tests `pool_compression_mode_is_noted_once`; `compression_covers_sub_chunk_pieces`; `compressed_chunks_overwrite_zero_truncate_clone_remove`, `compressed_chunk_windows_overwrite_and_space_rule`, `perf_comp_overwrite_4k` + `soak_compression_windows` (ignored); live A/B `lab/baremetal/comp-ab.sh`.
- Not done: per-object incompressible flag in oi, async offload codec (QAT/IAA, only chunks >= 32 KiB, per doc/hw/offload.md), per-object alloc hints, one crc per compressed extent.

## Rationale

CPU cost (LZ4 ~0.5-0.7 GB/s per core) is paid only by pools that opt in; chunking solves the fixed-block layout; capacity value is real for RGW/CephFS capacity pools. Trade-off accepted: read amplification on compressed pools (a ranged read decodes the whole chunk); complexity confined to the COMPRESSED branch of read/overwrite/free/fsck.

## Consequences

- + parity and capacity savings on capacity pools; space on a 64 KiB chunk at 50 % compressible = 9 of 16 blocks, identical to BlueStore (0.5625).
- + (am. 4) 4 KiB overwrites of compressed data read and code nothing (windows); space bounded by the space rule. - sub-block savings lost (required_ratio effectively needs >= 1 block saved per chunk).
- - compressed pools cost cycles/byte on the write path.
- Reporting caveat: `osd df` `kb_used` (raw) carries shard fill imbalance (`statfs_all` clamps to fullest core/shard, adr 0021 am. 5); compare `kb_used_data` / `ceph df` pool bytes (gate `scoreboard-cells.sh` Cs uses `used_data`, prints `used_meta`, after `bs_compact`); `statfs_all` clamps `available` to the fullest core.
- Siblings: all pool types/backends share `Stage::finish_inner_budget`; the device layer never sees chunk geometry. EC pools compress their shard writes by the pool mode like replicated pools (the adapter resolves `PoolComp` per txn, no pool-type filter), and every EC shard txn of an object carries the client alloc hint (am. 6: `ecback` `wgen`/`owgen` emit one `SetAllocHint` per shard before the data ops, flags kept (ORed over the txn's hint ops), expected sizes scaled `ceil(x / stripe_width) * chunk_size`; spec ec.md write path step 8, ec-optimized-wgen.md 2.4), so `passive` / INCOMPRESSIBLE decide like on replicated pools. The op is a valid Ceph transaction op (spec replication.md op 39) that classic shards apply as a no-op hint; mixed acting sets unaffected. The upstream append-part hint (`SEQUENTIAL_WRITE|APPEND_ONLY`, 0, 0) is not emitted (spec U-W6, advisory). Same store path on SPDK and kernel tier; replicated unchanged.

## Alternatives

- Never compress (original decision): superseded by the parity mandate.
- Silent ignore without note: operators suspect a bug. Clog WARN per pool: noise.
- Offload-only (IAA/QAT) design: not built; software first.
- lz4_flex / miniz_oxide: slower, kept dev-only (tests read old output).

## Open questions

- Space rule only looks at windows of the same object: a chunk shared with a clone stays until the clone lets go of it (BlueStore: same limit for shared blobs). Rewrite on clone removal not done.
- (resolved, am. 6) EC alloc hints (OQ 99): shard txns carry the client hint; tests `ecback` `tests/alloc_hint.rs`, `otests::alloc_hint_reaches_every_member_shard`, `storeadapt/tests/compression.rs::ec_shard_txn_hint_decides_compression`. Not done: a lab check of `ceph df detail` USED COMPR on an EC pool.
- Idle recompaction of cut chunks (rewrite into fewer blocks while the device is idle): adr 0533.

## Amendment map

- (original, 2026-10-11) accept-and-ignore decisions 1, 3, 5 -> removed (superseded by am. 1); decision 2 reporting -> Decision (operator note, wording changed); decision 4 RGW -> Decision
- am. 1 (2026-10-12): per-pool opt-in compression implemented -> Decision (Semantics, Layout)
- am. 1 impl notes (2026-10-12/13): FEAT_COMPRESSION, DecompCache, counters, leftovers -> Decision (Layout); removed: `FEAT_LONG_NAME`-style "set at first write, refuse older builds" wording (now the staged-raw drain protocol), clone-shares-compressed-extent claim (see Open questions), `lz4_flex`/`miniz_oxide` as prod codecs
- am. 2 (2026-10-17): codec choice by speed -> Decision (Codecs); numbers in history
- am. 3 (2026-10-18): sub-chunk pieces compressed; used-raw gap = reporting -> Decision (Layout), Consequences
- am. 5 (2026-10-23): compressed 4M read CPU: decoded chunks by reference with crc from `lcrc`, in-place decode of prefetched chunks, `DecompCache` of shared buffers -> Decision (Layout); measurements doc/perf/comp-read-cpu-20261023.md
- am. 4 (2026-10-22): compressed chunk windows (no RMW on overwrites inside a chunk), space rule, `gc_merged`; open question on clone sharing resolved (clones share) -> Decision (Layout, Accounting, Tests), Rationale, Consequences, Open questions; measurements doc/perf/comp-overwrite-20261022.md
- correction (2026-10-23): EC sibling note ("EC pools passive in v1, set no `CompSpec`") was wrong: EC pools compress by pool mode; alloc hints are lost on shard txns -> Decision (Layout, Siblings), Open questions
- am. 6 (2026-10-24): EC shard txns carry the alloc hint (OQ 99 resolved) -> Decision (Siblings), Open questions
