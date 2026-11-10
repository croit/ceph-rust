<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0694 rustyrbd client cache: write-around early acknowledgement with the librbd v21.2.0 guarantees

Status: proposed
Date: 2026-11-08

## Context

- Stock librbd v21.2.0 defaults to `rbd_cache_policy=writearound` with `rbd_cache_writethrough_until_flush=true`: after the first USER flush a write is acknowledged when admitted, before the OSD commit (doc/spec/rustyrbd/client-cache.md 1.1, 2.1). Stock rbd 4K randwrite QD1 with cache on is therefore ~15 us p50 against ~100+ us for an OSD round trip.
- rustyrbd acknowledged every write at the RADOS durable result and ignored the `rbd_cache*` options (spec section 8).
- Goal: the same data guarantees as stock (spec sections 2-4, checklist section 7), and faster. ADR 0256: match application-visible contracts, never reproduce reference bugs, document differences.

## Decision

The client cache is the write-around admission of the spec; there is no object cache.

- Options read at public open (`rbd_open`, `rbd_open_by_id`, `rbd_aio_open*` writable): `rbd_cache`, `rbd_cache_policy`, `rbd_cache_writethrough_until_flush`, `rbd_cache_max_dirty`, from the local config with pool and image (`conf_rbd_cache*`) overrides. Internal handles (copy, group, rename, migration) never acknowledge early. An unreadable configuration leaves early acknowledgement off and prints a WARNING line.
- Policies: `writearound` = the spec. `writeback` is mapped to write-around semantics: the write goes to RADOS at once instead of being kept dirty, so strictly less unwritten data is exposed than by write-back. `writethrough` and `rbd_cache_max_dirty=0` and `rbd_cache=false`: every write completes on its OSD commit. Invalid policy values are rejected by the existing config validation.
- Activation: a one-way latch set by the first USER flush (`rbd_flush`, `rbd_aio_flush`), under the activity lock, when the flush is accepted. Internal drains (resize, snapshot, lock release, close, refresh) use their own paths and never set it. With `writethrough_until_flush=false` the cache is live from open. Before the latch nothing is tracked and the write path is byte-for-byte the previous one (one flag check).
- Admission (`rustyrbd::write_around`, decided in `ImageActivity::reserve_data_write` under the lock that assigns the submission sequence, so decisions follow submission order): a plain write (contiguous or vectored, pipelined path) with no overlapping tracked write and `in_flight_bytes + len <= max_dirty` (or nothing in flight) is tracked and acknowledged early. A write that overlaps a tracked write is held: it takes the serial path, whose turn waits for every earlier write to commit, and it completes on its own commit. A write beyond the budget is tracked too, but not acknowledged early: it is submitted at once on the pipelined path and completes on its own commit (the budget bounds the early-acknowledged exposure, not the sends). FUA (`op_flags & 0x80`, `rbd_write2`, `rbd_aio_write2`, `rbd_aio_write_with_crc32c`) is tracked (later overlapping writes wait for it), waits for overlapping tracked writes like any write, is never acknowledged early and does not consume the byte budget. Extents are tracked in image byte space (the image-to-object map is bijective, so image overlap equals object-extent overlap).
- Early acknowledgement: the object writes are submitted to RADOS first (the provider copies the payload at `rados_aio_write`; this is the one copy, no extra staging), the writer mutex is released, then one arbiter (`WriteFanout::try_early_ack`) decides between the early acknowledgement by the submitter and the settlement by the last RADOS completion. A write that failed at submission, or settled before the acknowledgement, completes through its normal result.
- Retention: an early-acknowledged write keeps its activity permit until the last object write commits. Everything that waits for writes therefore covers it without change: user flush fence, close, serial write tickets (resize, snapshot create/rollback/remove, set_snap/refresh, discard, write_same, compare_and_write), and writer recovery / exclusive-lock release drain (`wait_recovery_write_fence`). Dirty data is durable before another client can acquire the lock.
- Errors: the first failure of an early-acknowledged write is stored with its submission sequence. The first USER flush whose fence covers that sequence returns it and clears it (ADR 0256: the reference delivers it one flush late when nothing was in flight). A later failure while one is pending is logged (WARNING), never silent. Close completes 0 and logs a pending failure (reference: logged only).
- Reads, compare_and_write, discard and write_same need no cache hold: an early-acknowledged write was submitted to RADOS before its acknowledgement, and per-object order is the session FIFO (ADR 0693-rustyrados-data-plane), so a read issued later is ordered after it; discard, write_same and compare_and_write run on the serial path which waits for all earlier writes. No read cache exists (write-around never caches reads).
- `rbd_invalidate_cache` stays a no-op returning 0 (write-around has no invalidate state; spec 4).

## Rationale

- Stock write-around is already a flush-barrier model: the application may lose acknowledged writes only between acknowledgement and a completed flush. Keeping the permit until commit makes the existing sequence fences the barrier, so no second mechanism has to be kept consistent with close, snapshot, resize and lock release.
- Admission under the lock that assigns the submission sequence gives the spec's tid-order decisions with no extra lock and no allocation on the steady state (sorted vector with retained capacity).
- Holding an overlap via the serial path reuses the proven ordering instead of a release queue that would have to submit from a provider callback thread (which must not take the writer mutex).
- The budget must not hold sends: a held write takes the serial path, which waits for every earlier write and blocks later pipelining. With a 24 MiB budget and 4 MiB writes every 7th write drained the whole window (0.19x of stock at queue depth 16 on a 3x replicated pool, 1.6 GB/s). Stock's release queue also caps throughput at the budget per commit round trip; sending at once costs nothing in durability (the write is acknowledged on commit, never earlier than stock) and keeps the pipeline full.
- Mapping write-back to write-around avoids an object cache whose only extra effect is a longer exposure window; the application-visible guarantees (acked data may be lost until a completed flush) are a subset.

## Consequences

- + QD1 acknowledgement latency drops from one OSD round trip to the submission cost after the first flush; later QD scales to the OSD commit rate, bounded by `rbd_cache_max_dirty` (24 MiB).
- + No change before the first flush, with the cache disabled, or for writes that do not qualify: no extra hop, one flag check under the existing lock.
- - A client crash can lose acknowledged writes that had not committed, exactly as stock write-around after the first flush; flushes and the drains above are the barrier.
- Observable differences against stock (ADR 0256):
  - A held write (overlap) and a write beyond the budget are acknowledged on their own commit; stock acknowledges them when released, before their commit. Latency only, durability is stronger. Beyond the budget the writes are also sent earlier than stock sends them (throughput only).
  - Only plain writes are acknowledged early; discard, write_same, compare_and_write and writes that leave the pipelined path complete on commit.
  - `writeback` does not hold data dirty and does not cache reads; `writethrough` does not cache reads either (no read-hit without an OSD round trip). Reads always go to the OSD.
  - A write failure is delivered to the first covering flush, not one flush late; close never reports it.
  - `rbd_cache_size`, `rbd_cache_target_dirty`, `rbd_cache_max_dirty_age`, `rbd_cache_max_dirty_object`, `rbd_cache_block_writes_upfront` and readahead have no effect (they configure the object cache that is not built).
  - Journaled images keep today's behaviour (writes on such images are not supported by rustyrbd).
- Reads are not held behind an overlapping early-acknowledged write (stock holds them): every request of one object travels on the reactor of its primary in submission order and resends keep tid order (crates/rados-ffi/src/owners.rs), so a later read reaches the primary after the write. This depends on reads going to the primary: `rbd_read_from_replica_policy` is validated but not implemented; implementing balance/localize reads requires holding overlapping reads first.
- Siblings checked: rustyrados/rados-ffi (provider) unchanged, the copy-at-submit contract of `rados_aio_write` is the dependency; librados as provider copies at submission too. EC vs replicated and crc vs secure msgr2 are below the RADOS layer and not affected.

## Alternatives

- Object cache (OC clone) for write-back and write-through: rejected, large, adds cache-coherency and flusher machinery for no guarantee the write-around admission does not already give.
- Release queue for held writes: rejected, needs submission from provider callback threads or a worker pool with its own ordering.
- Hold over-budget writes on the serial path (first implementation): rejected, measured 0.19x of stock at queue depth 16 x 4 MiB (cause above).
- Hold reads behind overlapping early writes: rejected, RADOS per-object order already orders them and a hold would block aio callers on callback threads.

## Open questions

- Early acknowledgement for discard and write_same (serial path today): worthwhile only if a workload shows it; the data to own is small.
- Per-image `rbd_cache*` changes after open do not reconfigure a live cache (as stock).
