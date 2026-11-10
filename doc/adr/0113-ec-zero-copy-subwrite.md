# 0113 Zero-copy legacy EC sub-writes (front rope)

Status: accepted
Date: 2026-10-14
Context: doc/perf/icelake-6330-codex-ab-20261014.md part 2, doc/perf/ec4m-primary-20261014.md. EC k2m1 4M write: ~7 ms CPU per write on the primary PG core. Legacy `MOSDECSubOpWrite` (struct v4) carries the whole v9 shard transaction inline in the FRONT segment (wire fixed by classic peers), so every 2 MiB shard payload was copied: skeleton -> v9 blob + crc at plan (4 MiB), encoded shard -> v9 blob (per shard), blob -> front (`encode_exact`: growth reallocs + exact copy), front -> msgr2 frame (copy + crc). ~26 MiB memcpy per 4 MiB write.

Decision:
- Rope = inline bytes + ascending `(offset, Bytes)` splices. `denc::Encoder::splice`/`splice_at`/`raw_rope`, `encode_exact_rope`: envelope lengths (`versioned`) count spliced runs; `into_vec` with splices = debug assert.
- `replwire::Transaction::encode_v9_rope(owners)`: wire v9 with every plain write payload >= `SPLIT_MIN` lying inside an owner spliced (real length prefix); flattened byte-identical to `encode_v9`. `encode_v9_local(owners)`: local skeleton + refs of the same payloads.
- `ecback::WritePlan::generate_shared` (legacy): per shard rope + skeleton over the encoded shard buffers; `generate` (copied blobs) stays the oracle. `plan_write_split`: plan from the client's local skeleton (no v9 rebuild).
- `ecwire::ECSubWrite::txn_zc` (encode only, struct v4 only) -> `messages::Segments::front_zc` -> `msgr2::Message::front_zc`. `Encoder::encode_message_rope`: in crc mode rev 2.1 runs >= `ZC_MIN` go out by reference (crc only), like a large data segment; secure / rev 2.0 flatten (one copy). Local shard: `StoreOp::ApplyTxnSplit`.
- Receive side unchanged (received segments never have splices); `ecwire::decode_ec` flattens a spliced front (loopback / test capture).
- Mode O (optimized EC) unchanged (plans from the v9 blob).

Compatibility: wire bytes identical (tests: rope flatten == plain frame in all modes, shared generation == copied generation for every model history). No durability change: the shard transactions and ack rules are the same; only buffers are shared (immutable `Bytes`).

Limits: encode_stripes still gathers data chunks (1 copy) and computes parity; frame crc still reads the payload. Replica front copies: am. 1.

## Amendment 1 (2026-10-14): replica receive without front copies
- `messages::decode_with_header_owned` (OSD links): an unknown-type (PG / client) message with a front >= `SHARED_FRONT_MIN` (64 KiB) keeps the received front `Bytes` as the one splice `front_zc = [(0, front)]` (no `to_vec`); `Segments::front_shared` / `front_bytes` (borrowed) give it to every decoder (pgwire, replwire, ecwire, opwire).
- `MOSDECSubOpWrite::decode_owned`: the struct v4 transaction is a slice of that front (was `copy_from_slice`). Two 2 MiB copies less per received EC sub-write; the rx buffer lives until the shard txn is applied (like a shared data segment).

## Amendment 2 (2026-10-14): append encode crc
- `Backend::encode_stripes_crc`: parity encoded in place into its shard buffer; per-shard crc32c (seed 0) fused with the data-chunk gather copy, parity crc while the chunk is in L1; `ec::HashInfo::append_crcs` joins them (`crc32c_combine`), identical hashes (test vs `append`). Removes the second 6 MiB pass of the hash-info append per 4 MiB write.
- Results: doc/perf/ec4m-primary-20261014.md (EC 4M t16 1127 -> 2528 MB/s, QD1 347 -> 495-669 MB/s on icelake-6330).

## Amendment 3 (2026-10-15): mode O zero-copy
- Mode O (`ec_opt()`) now follows legacy: no v9 rebuild of the client skeleton, no per-shard blob.
- `Backend::plan_write_o_txn(pgid, &Transaction, owners, ..)`: plans from the already decoded transaction (skeleton + refs, or the wire blob as the one owner); `plan_write_o(&[u8])` stays as the decode wrapper. `reduce()` keeps write payloads as `Bytes` slices of `owners` in the `Overlay` (`slice_ref`, else one copy); `cut_range` slices.
- `OWritePlan::generate_shared(old, pending, local)`: columns frozen to `Bytes` after compose/encode (no copy), per shard `SharedTxn` (rope via `encode_v9_rope`, skeleton + refs via `encode_v9_local`) over the columns. `local = Some(my shard)`: that shard gets only skeleton + refs (`StoreOp::ApplyTxnSplit`), peers only the rope (`txn_zc`): one encode per shard (small writes: no regression). `None` = both forms everywhere (tests). `OGenerated<T>`; `generate` / `generate_omap` (copied blobs) stay the ORACLE.
- Extent-cache pages still `to_vec` 4 KiB (cache must not pin the 2 MiB columns).
- Tests: ecback otests model harness runs `generate_shared` on every history (all geometries, PDW, degraded, omap, clones): flatten(rope) == oracle blob, skeleton + refs decode == oracle blob, pages / mod_descs equal, `Some(local)` forms equal the `None` forms; `tests/allocation.rs::mode_o_shared_generation_from_the_skeleton_copies_no_payload` (4 MiB write: rope + 1 splice per shard, < 6.5 MiB allocated).
- Wire bytes and local store effect unchanged; no format / PDW change.
- Mac `w4k_bench` (release, EC k2m1 mode O, min of 3, us per op, primary): 4 MiB overwrite: OSD total 1415 -> 557, ec plan 352 -> 38, generate+fanout 503 -> 270, allocs 104 -> 121 (small); 4 MiB new objects: 1543 -> 553, plan 314 -> 28, generate 693 -> 291; 4 KiB: 44.9 -> 44.3 (no regression). Replica "decode" in the harness is higher (loopback flattens the spliced front, same as legacy L1; not a prod cost).

## Amendment 4 (2026-10-15): local-only form only for an unshared shard id
- Defect of am. 3: `generate_shared(.., Some(my shard))` gave the primary's shard id only skeleton + refs; a backfill / async-recovery target of the primary's own position (same shard id, other OSD; pg_temp keeps the primary acting) got an empty `txn_data` + no rope (encode fails, sub-write dropped: write stalls during that backfill; never silently applied).
- Fix: `local = None` (both forms) when any other `acting_recovery_backfill` member has `me.shard`. Test: peering `ec_opt_primary_backfill_target_of_the_primary_shard_gets_writes` (fails before).
