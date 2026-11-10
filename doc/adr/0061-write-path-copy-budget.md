# 0061 Large write path: copy budget (4 MiB writes)

Status: accepted, amended (am. 11); cut-through forwarding (am. 2/3/8) rejected and removed 2026-10-19
Date: 2026-10-11
Consolidated 2026-10-19; full pre-consolidation text: `git show d5f573777:doc/adr/0061-write-path-copy-budget.md`. Measurements and incidents: doc/perf/adr-0061-history.md (doc not in the source snapshot).

## Context

4M writes trailed BlueStore. Cause: memory traffic on the connection and PG cores, not WAL/NVMe depth. Per 4 MiB payload there were 3 full DRAM passes after the kernel copy (msgr2 segment, txn blob, DMA buffer) plus crc passes, and a rep3 primary built a 4 MiB v9 blob before any repop left. Goal: each payload byte is copied once (kernel/NIC -> final buffer) and checksummed once, on every tier, replicated and EC, without a wire change.

## Decision

Safety unchanged: ack only after data + WAL durable, per-4k crc32c in extent map and WAL, msgr2 crcs verified.

### Primary: local skeleton txn
- `replwire::Transaction::encode_v9_split/decode_split`, `WriteReq::txn_refs`, `StoreOp::ApplyTxnSplit`: write payloads >= 64 KiB stay out of line as the client request's `Bytes`. Skeleton marker `u32::MAX` is invalid in plain v9 (a peer-side decode refuses it). The plain v9 blob exists only when a peer needs it (`WriteReq::wire`); EC primary rebuilds the plain blob first.

### Replica fan-out in parts (am. 1)
- Wire bytes unchanged (plain v9 in DATA, any peer decodes it); only frame assembly is in parts.
- `Transaction::encode_v9_rope(owners)` (adr 0113): inline v9 bytes + spliced payload runs. `WriteReq::wire_rope` = pieces around the client payload `Bytes` + a crc hint per payload.
- `MOSDRepOp::txn_data_more` (local only, never decoded): DATA = `txn_data` ++ parts. `Message::encode` concatenates (copy, safe for any other user); the cluster send path (`pg_send`) moves the parts out -> `xcore::DataX` -> `msgr2::Message::data_more`.
- msgr2 `Encoder::encode_message_parts`: CRC mode rev 2.1 = every part by reference (chunks), segment crc joined from part crcs (`crc32c_combine`, hint only when it views exactly that part); secure / rev 2.0 / small = concatenated, one segment (byte-identical frame either way). Lossless replay re-encodes from the kept `Message`.

### Receive: one copy, block crcs while hot
- Direct receive (knet): data segment >= `direct_min` (128 KiB, `NV_KNET_DIRECT_MIN`, 0 = off) with bytes still to come: multishot recv cancelled, segment buffer lent to the transport (`Decoder::direct_take/put`, `Osd::rx_direct_*`), filled by `recv(MSG_WAITALL)` of 256 KiB pieces, crc32c per piece while hot, buffer handed back; crc checked against the frame trailer. Only between whole receives.
- Block crcs (am. 4): `crc32c(0, block)` per 4 KiB block of every data segment >= 64 KiB (`msgr2::BLOCKS_MIN`; `crc::BlockCrcs`, grid from the segment's first byte or the rx head below), computed by the decoder (DPDK / AF_XDP, per whole block), knet direct receive (`DirectRx::Crc`, per piece) and spread jobs (joined in order). Segment crc = `crc32c_blocks` + combine of the tail: no second pass. `OwnedFrame::data_blocks` -> `CrcHint::with_blocks` (owner-bound like the crc).
- Spread receive copy (am. 5): data-segment bytes go in 256 KiB jobs to helper cores that copy / receive, checksum on the grid and hand back; the connection core joins block crcs in order. DPDK / AF_XDP: `rt::rxcopy`, `NV_RX_SPREAD=<min segment bytes>`, default off (buys single-stream bandwidth with +30..40 % CPU per byte). knet: `NV_KNET_SPREAD`, default on for co-located softirq streams (adr 0053).
- Receive placement (am. 7, am. 11): `msgr2::Decoder::set_rx_place(true)` on every OSD link (public + cluster). The data segment of every MESSAGE frame, any size, is received so that segment byte 0 lies at in-page offset `data_off mod min(align, 4096)` (spec msgr2.md 3.1; `data_off` 0 = Ceph's page-aligned allocation). Senders state their payload: MOSDRepOp `data_off = -14` (`replwire::REPOP_DATA_OFF`), EC sub-write struct v5 `-(first payload in DATA)` (`ECSubWrite::data_segment`). Buffer = shelf class `2^k + PAD_ROOM` (4 KiB room for the pad, `rxpool`); the pad is charged to the frame gate and the dispatch budget (adr 0175). Segment (`Bytes::slice(pad..)`), wire and segment crc unchanged. Grid starts at the first 4 KiB boundary in memory (`with_head`), `OwnedFrame::data_head`, `CrcHint::with_blocks_at`, `Payload::grid` (`blocks_at` checks `(off - grid) % 4096`). Transport contract: a lent buffer holds `pad` junk bytes before the segment; transports only append after `len()`, `BlockCrcs::pos()` counts segment bytes (`pad = len - pos`); `rxcopy` jobs get `at`/`head`. Covered: knet (direct + feed), RDMA (feeds the same decoder), AF_XDP / DPDK (feed path, compile only), crc and secure mode (secure rev 2.1 decrypts the frame's later segments out of place straight into the placed buffer, `Gcm::open_to`: no extra copy; rev 2.0 secure large frames stay in place and only small frames are placed, by the copy they already make). Payload not where `data_off` says (classic primary: RepOp v10 / v4 EC payloads at arbitrary front offsets) = the store copies (counted, below).
- EC sub-write v5 (am. 11): to a peer whose connection features carry SERVER_TENTACLE the primary sends ECSubWrite struct v5 like Ceph (ec.md 6.1.1): unsplit v10 (`data_features` 0), p part in the front, misaligned stream in DATA with the shard payloads by reference (`txn_data_more` -> `DataX::more`). Unknown or older peers: v4 as before (payload inline in the front, arbitrary offset). The features are the cluster link's, whichever side dialed: an accepted link (the peer's dial won, `pg_send` uses it as carrier) records them for the map's incarnation at the address the peer identified with (`link_ready_info`; before, only dialed links did and croit-flashstore-osd peers whose dial won got v4). Conversion from the v4 rope at send (`pg_send`): one small copy of the op records + tables, no payload copy.
- Primary-local writes below `SPLIT_MIN` (am. 11): the plain v9 blob (replicated, `opexec::encode_txn` / fast overwrite) and the EC local shard skeleton without out-of-line payloads (`encode_v9_local`) are encoded by `replwire::Transaction::encode_v9_placed`: the allocation gets up to 4 KiB of zeroed lead so the first write payload of >= one block starts 4 KiB aligned in memory; the bytes (also sent to the peers) are unchanged. The local apply views it (no store copy); cost = one memset of the lead (< 4 KiB) instead of a payload copy. The EC primary hands its shard skeleton to the store as shared `Bytes` (was `copy_from_slice`).
- Aborted frames: a frame whose epilogue says `late_status ABORTED` (segment crcs still checked) is dropped without a fault and without touching `in_seq` (Ceph frames_v2 semantics; decoder `Asm` Late). Wire compat, independent of what croit-flashstore-osd sends.

### Store: write by reference, reuse receive crcs (am. 4, defaults am. 5)
- Client op payload = whole data segment: the hint follows `OsdOp::indata_crc` -> `WriteReq::txn_ref_crcs` -> `StoreOp::ApplyTxnSplit::hints` -> `OTxn::payloads` (`crc::Payload`). Replica: frame hint -> `MOSDRepOp::txn_data_crc` (osd `on_unknown_message`) -> `StoreOp::TxnHint` after `ApplyTxn` (peering `on_repop`) -> `Payload` of the blob (storeadapt `meta.rs`).
- `Stage::data_ref`: a data run inside a payload the device can DMA from (`BlockDev::view_buf`; SPDK: registered hugepage memory via `spdk_vtophys`, dword aligned; kernel NVMe (am. 11): 4 KiB-aligned memory only, `nvme::kdev::VIEW_ALIGN`: dword is all `queue/dma_alignment` asks, but a block-aligned backend (nvmet file namespace, O_DIRECT) failed unaligned views with Status 6) is written BY REFERENCE (`DmaBuf` view holds the `Bytes` until completion; CPU writes / device reads into a view refused). Extent crcs: `reseed_4k(blk_seed, block crc)` on the receive grid (no pass), else one read-only crc pass. Anything else: non-temporal copy+crc into DMA buffers (`crc::crc32c_copy_dma`, AVX-512, sfence: no read-for-ownership).
- Write views are unconditional (the `NV_STORE_ZC` switch is gone); kernel tier payloads in the SPDK env's hugepages by default (`NV_HUGE_ALLOC`, adr 0076 am. 1). Counters `flashstore_staged_bytes`, `flashstore_zc_bytes`, `flashstore_crc_reused_bytes`; `view_copy_bytes` (store perf counters, am. 11) = bytes a device refused to view and the store copied (`Shard::view_buf`: data runs, pre-write pieces, omap LSM runs).
- Deep scrub digest joined from the verified read crc (`Store::read_media_async_crc`). Per-message DMA buffers = the HugeAlloc size-class park; no per-core slab.
- Park budget (am. 9): parked blocks count in the huge budget; an allocation that misses the budget frees parked blocks for its shortfall only (the smallest parked block that covers it, else the largest smaller ones), never the whole park: each `rte_free` zeroes its block on the calling core (a whole-park drain was a 7-14 ms PG-core hold, doc/perf/bmix-tail-20261025.md). Per-thread EAL call counters for stall diagnostics (`NV_PHASE` stall lines `eal_alloc` / `eal_free`), pool counter `parked_bytes`.
- Park capacity (am. 10): one lock-free bounded queue per size class, capacity `budget / class` (set at the first enable): every block the budget admits can be parked, so a burst of frees never overflows into zeroing frees; frees happen only for a budget shortfall. Classes start at an exact 128 KiB class (checkpoint arena chunks = one 128 KiB device write). Budget: kernel NVMe tier (memory-only EAL, serves only this heap) = all of `--mem`; SPDK NVMe (EAL shared with SPDK DMA buffers) = half (adr 0076 am. 3). Run buffers stay on the heap: moving them to 4 KiB pages doubled compaction CPU (doc/perf/payload-heap-20261025.md).

### knet: no zero copy to a same-host peer (am. 8)
- `Conn::local_peer` (peer IP loopback or a local interface address, set at accept / connect): sends never go zero copy. The kernel copies looped zero-copy skbs anyway (deferred copy), and their truesize covers every touched page (payload/truesize 237/256 per 64 KiB vs 252/256 copied); a socket mixing both kinds advertises a window from the last measured ratio that its rcvbuf cannot hold -> prune / `PROTO_MEM` drop -> RTO. Own stack (AF_XDP / DPDK): n/a (no kernel socket accounting; knet towards an own-stack OSD stays zero copy over the NIC).

## Rationale

Bandwidth per core is bounded by DRAM passes; each removed pass showed as MB/s and cycles per byte (history: am. 4 -25..-33 % cyc/B, single stream +19..25 %; am. 7 replica store 1.7 -> 0.87 ms). Wire-unchanged techniques keep mixed acting sets with classic OSDs working without negotiation.

## Consequences

- Tests: replwire/tests/split.rs, opexec/tests/large_write.rs, peering/tests/split_wire.rs, storeadapt/tests/splitwrite.rs (`hinted_payloads_are_written_by_reference_with_reused_block_crcs`, `replica_blob_with_a_payload_grid_reuses_the_block_crcs`), crc `dma_copy_matches_plain_copy_for_every_alignment_and_size`, `blocks::*`, `hint::payload_blocks_only_on_the_grid_and_inside`, `hint::payload_grid_starts_at_the_blob_offset`; msgr2/tests/direct_rx.rs (`plain_feed_block_crcs_for_every_piece_size`), msgr2/tests/rx_head.rs, msgr2/tests/frames.rs `parts_encode_is_byte_identical_to_the_flat_segment`; rt knet::tests::direct_*, `sends_to_a_peer_on_this_host_never_go_zero_copy`, rxcopy grid + head/pad; replwire `first_write_payload_sits_at_the_published_offset`.
- Transports must honour the lent-buffer contract (pad, append only, only between whole receives).
- Siblings: crc reuse and ZC are tier-independent (SPDK / kernel NVMe); receive block crcs on knet, AF_XDP, DPDK; EC sub-writes are encoded on the primary (no unchanged forward).

## Alternatives

Rejected:
- v10 split txn to peers; v10 aligned txn layout per peer (wire change, classic compat risk).
- Rope txn type (a second transaction representation inside the OSD); ring-held segments.
- Non-temporal receive copy (slower for one stream, no gain at 24).
- memmove realign of replica blobs (the copy we remove); pad for every frame (4 KiB waste per small frame).
- **Cut-through forwarding** (am. 2/3/8, prototype default off; removed 2026-10-19, adr 0061 history): a rep3 primary started the repops while the client payload still arrived, finalized each forwarded frame from the client's verified crc, aborted it (`late_status ABORTED`, seq reused) on a bad crc / dead client, undid the PG log entry. Same-process flip gate (05148a2, ice-a, every cell on / off in the same OSD processes): wins w4m1 +15 %, rados bench 4M / 1M +4 %; losses w1mq16 -22 %, w4m8 p99 +9 %, 4k randwrite next to 4M writers p99 +7 % with p99.9 tails up to +40 %; w4mq16, 64K and 4k QD1 equal. Why it loses: a cut write holds shared resources for the client's fill time instead of the wire time: the peer link (msgr2 frames cannot interleave: 19-24 % of repop replies waited 5.7-8 ms behind a filling frame) and the PG (no log append behind an unfinished entry). Structural fixes need either a rate switch (cut only when the client fills at wire speed: a load-based switch, not allowed) or a wire change (interleaved or chunked frames; classic peers cannot). Its cost: TCP_CORK on forwarded frames, a stream receive path on every transport, undo/yield/liveness rules in the PG core. Also rejected inside it: replica stages + explicit commit message (classic replicas cannot), connection reset as abort (lossless replay would resend), no-op replacement entry instead of undo, time-based stall cancel.

## Open questions

- Classic primaries send `data_off` 0: RepOp v10 / EC v5 payloads at DATA offset 4 + earlier items are not placed and get copied by the store (`view_copy_bytes`); live DPDK run of placement.
- Rented 100G verification of single-stream 4 GB/s and of spread's CPU cost at line rate.
- mlx5 LRO needs CX-5+ MPRQ or chain-aware zero-copy rx (`NV_LRO`, `NV_NIC_DEVARGS` knobs exist).

## Amendment map

- am. 1 (2026-10-14): replica fan-out in parts -> Replica fan-out in parts
- am. 2 (2026-10-15): cut-through forwarding prototype -> removed (Alternatives); aborted-frame receive -> Receive
- am. 3 (2026-10-15): cut-through re-entrant start hang fixed -> removed (history)
- am. 4 (2026-10-16): receive block crcs, store by reference, scrub digest -> Receive, Store
- am. 5 (2026-10-16): ZC defaults on, spread receive copy, LRO retry -> Store, Receive, Open questions
- am. 6 (2026-10-16): ZC defaults checked (restart, kill -9) -> superseded (history)
- am. 7 (2026-10-16): replica rx head on the payload grid -> Receive, Store
- am. 8 (2026-10-19): cut-through receive path, stall rules, cork -> removed (Alternatives); no loopback zero copy -> knet: no zero copy to a same-host peer
- am. 9 (2026-10-25): budget miss frees the shortfall only, EAL call counters -> Store
- am. 10 (2026-10-25): budget-sized park per class, 128 KiB class, kernel-tier budget = `--mem` -> Store
- am. 11 (2026-10-31): receive placement by `data_off` for every frame and size (replaces the RepOp rx head), secure out-of-place decrypt, EC sub-write v5 to tentacle peers, placed primary-local blobs, kernel views need 4 KiB-aligned memory + `view_copy_bytes` -> Receive, Store
