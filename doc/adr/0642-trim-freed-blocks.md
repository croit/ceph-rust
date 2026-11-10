<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0642 Deallocate whole free windows in device idle gaps, held until the completion

Status: accepted
Status note: implemented; redesign passed the tsrv2 A/B 2026-11-03 (doc/perf/trim-20261102.md).
Date: 2026-11-03
Amends: 0021 (S3 allocator), 0047 (trim-on-free was lab only), 0169 (runtime deallocate paths of the kernel tier)

## Context

The store never overwrites data in place: every overwrite frees the old blocks, which keep a valid mapping in the drive's FTL until the LBA is written again. Neither tier deallocated them, so the FTL treats all LBAs ever written as live. NVMe does not order in-flight commands: a deallocate and a later write of the same LBA may execute in either order.

The first version (every free run of a dirty window, one command per shard in flight beside client IO, an allocation miss answered `Busy` while a command held blocks) failed the tsrv2 A/B (PM9A3, 96 % fill; doc/perf/trim-20261102.md): a 495 s store stall (every retry of a parked txn met a new command), about 0.9 ms of device time per range with about 6 KiB per range (device 100 % busy for minutes after each write phase), steady 4 MiB 0.76x, QD1 4K write -9.3 %.

## Decision

- Granularity: whole free windows only (`alloc::WIN` blocks = 1 MiB, the summary windows of adr 0475). Adjacent windows of one extent join into one range; ranges are cut inward to the device granularity and split at the per-range limit; the held runs stay whole windows. A window with a busy block is never deallocated; its freed blocks go out once the window is free as a whole. Off (`trim=off(...)`) when the device granularity exceeds one window or its limits cannot carry one window per command.
- Trim set (`store::trim`): a window turns dirty when blocks in it become allocatable from held (`Shard::release_held`: a durable checkpoint root passed the free and no reader of an older epoch remains, adr 0021 S3 / adr 0043; meta cells given back after their root is durable), when a borrowed chunk enters the allocator, and for every window at mount (the free map is durable, what was trimmed is not; no format change). A dirty window without a busy block is a candidate; a dirty window turns candidate when its last busy block becomes free (`release_held`, or a reservation given back through `Shard::unreserve`). A walk from a round-robin cursor drops candidates found in use again (they stay dirty), at most 256 per walk; the windows a command takes are clean.
- Ownership: the shard moves the command's windows from free to held (`Alloc::hold_free`) and releases them when the completion is reaped (failed or not). While a deallocate is in flight no allocation can name its blocks; a write to a deallocated block is submitted only after that completion.
- When: only from a poll of an idle shard (the quiescent return of `Shard::poll`: nothing queued, in flight or loading, no checkpoint due or running), and only when every queue of the device, the shard's own included, was quiet for `BG_BUSY_GAP_NS` (device idle table, adr 0533). One shard per device holds the device's deallocate turn (`DevIdle::trim_take`) from the command until a pause after its completion as long as the command took, at least one gap. No client IO of the shard queues behind a deallocate, the device never runs two, and deallocates take at most half of the device time. A device never quiet for one gap gets no deallocate. A checkpoint keeps the shard active until its root is durable (its sliced start, freeze and end, adr 0021 am. 80, need no IO between slices): the core polls it every pass, then a quiet shard at every store sweep, so the deallocate goes out in the same idle gap after it.
- Size: the first command takes one window. A command limited by its window budget that completed within half a gap doubles the budget (up to the device limits); a command slower than one gap scales it by gap / latency (at least one window). A command thus stays about one gap long whatever the drive's cost per range or byte. Each command holds at most half of the allocatable blocks above the user floor and one meta cell (`(n_free - F - cell) / 2`) and at most half of the whole free windows: the reserves under every floor and the window headroom of meta growth, lending and reclaim are never held.
- Allocation: held windows are only excluded from allocation. They count as free for admission, statfs (`data_free`), migration room, `space_low` and the window headroom (`Shard::free_windows`: lending watermark, reclaim room, meta-cell budget, dense-run choice; `Shard::lent_slot` for chunk return and evacuation). Defrag takes no window a command holds as a victim. A data allocation or meta growth that misses while a command holds windows answers `Busy` (`trim_waits`; no forced checkpoint, no growth failure, no `meta_blocked`); no command starts before the next allocation or growth attempt that finds none held (`trim_wait`), so the retry gets the released windows however late it comes. The wait is bounded by that one command.
- Device interface: `BlockDev::dealloc_limits()` and `submit_deallocate(&[(lba, nlba)], tag)` (up to `max_ranges` ranges, one completion; `max_ranges == 0` = no runtime deallocate).
  - Kernel tier, cmd mode with the accepted mkfs DSM verdict (adr 0169 am. 8): one passthrough DSM (AD) carrying every range; limits from sysfs `max_discard_segments`, `discard_max_hw_bytes`, `discard_granularity`.
  - Kernel tier, block node (direct mode, or cmd mode whose device rejects passthrough DSM or whose verdict is unknown): `BLOCK_URING_CMD_DISCARD` in the device ring, one range per command (`max_ranges = 1`, range limit `discard_max_bytes`); probed at open by opcode (`IORING_OP_URING_CMD`) and a zero-length command (EINVAL = the command exists, EOPNOTSUPP/ENOTTY = not). Kernels without it (< 6.12) and devices with sysfs `discard_max_hw_bytes` 0: `off(...)` with `missing=[URING_DISCARD]` in the kernel feature line; no helper thread, no synchronous `BLKDISCARD` on the core.
  - SPDK: one DSM with every range (`spdk_nvme_ns_cmd_dataset_management`, 256 ranges, u32 LBAs per range).
  - Lab FileDev: `fallocate(PUNCH_HOLE)` per range. SimDev: deallocates by default; in-flight deallocates persist, drop or tear at a crash; `SimConfig::dealloc = DeallocLimits::off(..)` = a device without runtime deallocate. CowDev (read-only mount): off.
- No switch: trims run whenever the device can deallocate at runtime. Startup line per device: `store: trim=dsm|uring-discard|punch|off(<why>) ranges=<n> range_max=<bytes> max=<bytes> gran=<bytes>`; `kdev_probe` prints the same limits.
- Errors: a failed command releases its windows unchanged (their contents are undefined either way, nothing refers to them), counts `trim_errors`, one `WARNING` line per shard; its windows are not retried. A command the queue refuses (`QueueFull`) releases its windows and makes them candidates again. `Unsupported` at submit turns trims off for the shard (one line). Nothing ever reads a deallocated block or relies on its contents.
- `perf dump flashstore_store_<core>`: `trim_on` (shards with trims on), `trim_cmds`, `trim_ranges`, `trim_bytes` (device bytes submitted), `trim_lat_ns` (sum of completion latency; / `trim_cmds` = mean), `trim_lat_max_ns`, `trim_errors`, `trim_skipped_bytes` (became allocatable while trims are off), `trim_waits`, gauges `trim_held_bytes`, `trim_dirty_windows` (may hold blocks the device still maps), `trim_cand_windows` (dirty windows that were whole free when marked; a walk drops those in use again; a command takes at most half of the whole free windows).

Crash points (a deallocated block that durable state or replay still names is the failure excluded):
- free applied, before the checkpoint that passes it: block held, never in a command; replay re-frees it.
- checkpoint root write in flight or torn: frees stay in `free_q`, the older root (which may name them) is intact.
- root durable, limbo, release, dirty, command built or in flight: no root from this one on names the block, replay starts past its free; the deallocate may or may not have executed.
- deallocate completed, window reused: the new data write was submitted after the completion; an acked record's data is durable before its ack, a torn tail is judged as before.
- mount: windows marked only after replay, so allocations of replayed records and frees awaiting the first checkpoint are not allocatable.
- process exit or device reset with a deallocate in flight: like an in-flight write to free blocks; the next mount marks every window and trims the whole free ones again.
- borrowed chunk return (adr 0021 am. 49): refused while any block is held, so never during a deallocate; evacuation fences (am. 57) re-fence what a completion releases.
- Tests: `crash_matrix_deallocates` (tests/crash.rs: whole windows released by checkpoints, device idle gaps in the workload, crash points inside deallocates and in the writes that reuse their windows); `near_full_shard_keeps_committing_while_deallocates_run`, `a_miss_waits_for_the_one_deallocate_in_flight`, `freed_blocks_are_deallocated_after_checkpoint`, `mount_deallocates_blocks_freed_without_runtime_deallocate` (tests/wal.rs); `deallocates_go_out_in_idle_gaps_between_sliced_checkpoints` (tests/obj.rs: the store's poll loop, checkpoints requested between writes, idle gaps polled as a core does); unit tests in `store::trim` and `store::devidle`.

## Rationale

- Holding the blocks in the allocator is the only ordering a device without command ordering gives; the alternative (handing them out and deferring writes that overlap an in-flight deallocate) needs a check on every write path (data, pre-write, pages, OLSM).
- Whole windows: the measured cost on PM9A3 is per range, and a fragmented window yields kilobyte ranges; a whole free window is the unit the allocator already tracks in O(1) (`win_busy`), and joined windows give few large ranges.
- Idle gaps only: a deallocate beside client IO delays that IO on the device (QD1 -9.3 % measured). Gating by the shard's own idle state and the device idle table costs one check per idle poll and never touches the op path. The pause after each command bounds the device share without a constant of its own (the gap is the existing background pacing period).
- The bounded wait (`trim_wait`) instead of "a miss is never Busy": a miss can only meet the one command in flight (no new one starts before the retry), and its windows are back within that command's latency; refusing the wait would turn a transient hold into `NoSpace` or a forced checkpoint that frees nothing.
- Dirty and candidate bitsets (2 bits per MiB, 256 KiB per TB) bound the backlog without memory growth and coalesce repeated frees.

## Consequences

- + Freed whole windows are FTL over-provisioning again; a remounted store re-trims its whole free windows.
- + No client IO of the shard waits behind a deallocate; at most one deallocate per device at a time, at most half of its time.
- + Lab FileDev and production share one path (adr 0047's submit-order assumption removed).
- - Blocks freed in windows that stay partly in use keep their mapping until the window empties.
- - Under load without 10 ms device idle gaps nothing is deallocated; the backlog goes out in the next idle period (a gate settle after a write phase includes it).
- - An allocation that meets the command in flight waits up to its latency (`trim_waits`); near the floor an allocation may take a shorter run (`frag_cuts`) while a command holds a window.
- - Offline free-space reports (`free_extents`, expand) count windows a command holds as free; the perf dump free-space shape is allocatable space, the windows in flight are `trim_held_bytes`.
- - Kernels without `BLOCK_URING_CMD_DISCARD` (< 6.12) trim only through passthrough DSM (cmd mode, accepted verdict); direct mode there has no runtime deallocate (as before).

## Alternatives

- Every free run of a dirty window, one command in flight beside client IO (first version): measured stall, per-range cost and QD1 loss (Context).
- Deallocate inside the free txn path (BlueStore `bdev_enable_discard` style, per released extent): one command per extent, no pacing.
- Paced commands under client IO (one per gap): device contention on the client path.
- Persisted trimmed bitmap: format change for a hint that only saves one pass over the free windows per mount.
- `BLKDISCARD` on a helper thread for kernels < 6.12: a thread and eventfd plumbing per device for old kernels only.

## Open questions

- Whether a mount trim of a namespace that was never deallocated moves the drive's write-budget cliff (`w4m.2`): the A/B deallocates the namespace before every arm, and the cliff stays at the same drive volume (doc/perf/trim-20261102.md).
- A device never idle for one gap never trims; whether a sustained-write workload needs trims under load (measure the FTL effect first).
- Free chunks of the elastic pool are not trimmed at mount: chunks returned by a binary without trims keep their mappings until a shard borrows them (a granted chunk is trimmed whole). Candidate: the pool owner deallocates free chunks at mount, a grant waits for the chunk's completion.
- Device-mapped footprint (`nvme id-ns` NUSE) vs live data with trims on large thin namespaces (e9455).
