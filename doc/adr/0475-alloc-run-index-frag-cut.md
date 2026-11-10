# 0475 Allocator: window free-run index, fragmentation gauges, frag_cut and small_dense by default

Status: accepted
Date: 2026-10-20
Amends: 0021

## Context

On an aged store (one pass of 4K random overwrites at ~76 % fill) 4M and 64K overwrites lose most of their IOPS at 15-30x cpu/op with an idle device; small writes and reads are unaffected (doc/perf/vstart-bench.md, Aging). `alloc_upto` halves a data run on `Busy`/`NoSpace`; every failed level scans the whole shard (the `no_fit` memo resets on any free, `scan_words` skips only fully busy windows) and forces a checkpoint while held blocks exist. Next-fit hands long runs to small writes. Fragmentation was not observable.

## Decision

- `Alloc` keeps one `u32` per 1 MiB window (`wruns`): free blocks at its start, at its end, longest free run of the layer union, or `RUNS_DIRTY`. A union change in `update_word` / `take_free` only marks the window dirty; the next reader recomputes (`win_runs`).
- `scan_words` passes a whole window in which no run of `want` can end (`run + pre < want && max < want`) in O(1), carrying the run as the word scan would. `reserve_dense` skips windows whose longest run is too short. Placement is unchanged.
- `Shard::alloc_data` serves `alloc_upto` (data runs and ext values that may be cut), `frag_cut`: a run of `n` blocks the class floor allows but no free run holds is cut to the longest free run of the region, taken whole (`Alloc::reserve_cut`, am. 3); no forced checkpoint, no pool request, no halving. A run never exceeds what the class floor leaves.
- With `small_dense` = N blocks (config `flashstore_store_small_dense`, default 16 = 64 KiB, 0 = kill switch, max `WIN`) data runs of at most N blocks try `reserve_dense` (hole in a partly used window) before next-fit.
- `perf dump flashstore_store_<core>`: counters `alloc_data_runs`, `alloc_data_blocks`, `alloc_small_dense`, `alloc_frag_cuts`; gauges from the index (bounded walk, am. 1) `free_blocks`, `free_whole_win_blocks`, `free_short_blocks` (free blocks in windows without a 16-block = 64 KiB run), `free_longest_run_min` (blocks, worst shard). Fragmented share = `free_short_blocks / free_blocks`.
- vstart-bench `age` records `frag=<short %>:<longest KiB>` per phase.

## Rationale

The scan cost is fixed without touching placement, so the index ships unconditionally and the `DenseAlloc` oracle proves it. `frag_cut` is the default (user decision 2026-10-20): on an aged store it adds +5 % (4M) / +12 % (64K) overwrite IOPS at -15 % cpu/op over the index alone and stops the checkpoint writes the forced path adds (WAF 1.18 -> 1.05). `small_dense` = 16 is the default too (user decision 2026-10-20) although no throughput gain is measured yet: under mixed small + large writes it keeps free space ~3x less fragmented with a growing gap per iteration (doc/perf/vstart-bench.md, Aging). Trade-off accepted: 4 B RAM per window and a recompute of dirty windows by the next scan.

## Consequences

- + A long or failing scan reads one summary per clean window instead of four words.
- + Fragmentation is visible in `perf dump` and in the aging report without a bitmap walk.
- - RAM +4 B per 1 MiB window (32 MiB per 8 TB).
- - `frag_cut`: held blocks that a checkpoint would have joined into a run are used only after the next regular checkpoint; a 4 MiB write on a shard whose free space is short holes takes one extent per hole.
- - `small_dense`: small writes land in holes away from the cursor (less locality per object).

## Alternatives

- Range tree by offset and length (Ceph `Btree2Allocator` style): allocates on the hot path, RAM grows with fragmentation, second free-space structure next to the three bitmap layers.
- Eager summary update on every union change: up to ~128 run iterations per changed word on the write path; lazy marking costs one store.
- Halving the run on a miss (the decision until am. 3): one failed search per level and holes consumed in power-of-two pieces.

## Open questions

- `small_dense`: is 16 the right N? A long mixed-load run (>= 10 iterations) shows whether the free-space gap turns into large-write throughput.

## Amendment 1 (2026-11-01): bounded fragmentation walk

Context: the gauges `free_whole_win_blocks`, `free_short_blocks`, `free_longest_run_min` walked every window of every shard on each call, and the call is not cold: every core builds the store perf counters once a second for the control core (`xcore::local_stats`), and core 0 again per `perf dump`. On an e9455 gate shard (895 k windows, 97 % used) one walk held the core 0.8-2 ms per second, growing with the device (`alloc::frag_cost`, doc/perf/w4m-20261101.md).
Decision: `Alloc::frag` advances a walk by at most `FRAG_STEP` = 16384 windows (16 GiB of device) per call and returns the last complete walk; the first call after mount walks everything once. `Alloc::frag_full` = the whole walk (tests). A shard of n windows refreshes every n / 16384 calls (e9455 shard: ~55 s); shards up to 16 GiB every call as before. Same definitions; a walk spans the allocator changes between its calls.
Rationale: an exact incremental gauge needs O(changed windows x log n) per period (the longest run is a global maximum over joined runs), no cheaper than the walk under random overwrites; a bounded step caps the hold per call (measured median 0.19 ms, max 0.32 ms with 25 k changed windows per call vs 1.5-2 ms for the whole walk) whatever the shard size, and the aging gauges tolerate a minute of lag.

## Amendment 2 (2026-11-02): run-summary tree over the windows

Context: e9455 rep3 4M randwrite fell to 0.30x BlueStore after ~30 s; `perf` on osd.0: `scan_seg` 47 %, `win_runs` 32 %. At ~96.5 % fill the base stays closed (am. 56 reopen needs 10 % free), every `reserve(64)` of `Shard::pre_write` first scans the borrowed space, which holds no 64-block run (4K-aged pieces), then the base. The window skip of this ADR is O(1) per window, so each call walked ~590 k windows: 0.32-0.73 ms per allocation (doc/perf/alloc-scan-20261102.md). `reserve_dense` walked every partly used window whose longest run was too short (same O(windows) per miss).
Decision: `Alloc` keeps a tree over the window summaries, fan-out 16 (`FAN`), node = free blocks at its start, at its end, longest run, longest run inside one partly used window (`dmax`). Runs never join across an extent (chunk) start; full windows (holes) and positions past the region are busy. Lazy like the window summary: a union change marks the window and its ancestors up to the first dirty node (`runs_dirty`, from `win_add`); a read recomputes a dirty node from its 16 children. `scan` walks from the root: a node inside the range in which no run of `want` can end is passed in O(1) carrying the run, a window is always tested, a crossed node is descended without a read; one window of words places the fit. `reserve_dense` finds the first window with `dmax >= want` from its cursor the same way. Removed: `no_fit`, `dense_no_fit`, the base dirty-window memo (`base_no_fit`, `bdirty`), the partly-used bitsets (`win_part`, `win_sum`). Placement is unchanged (next-fit, `DenseAlloc` oracle, brute-force tree tests on plain extents with extent starts inside windows and on chunk tables with holes and growth). `frag` ends runs at extent starts (exact longest run). RAM-only, no format change.
Rationale: a request costs O(FAN x height) node reads (at most 16 per level and side; e9455 shard: 6 levels) instead of one step per window, also when nothing fits; the cost no longer depends on fill, aging or where the fit is. Memos keyed on "the last failure" do not help when every call fails in one area and succeeds in another, which is the e9455 pattern. The lazy marking keeps the write path at one store per changed window plus a short climb.
Consequences: + 4M overwrite allocation at e9455 fill 0.32-0.73 ms -> 0.16-0.41 us (`alloc::age_cost`, perf doc); + the window holding the cursor is scanned first, so a next-fit hit reads no tree node; + no special case for holes, chunk tables or plain extents in the scan. - RAM +32 B per 15 windows (~2 B per 1 MiB window, 17 MiB per 8 TB). - A walk that reads a node above changed windows recomputes them (~30 ns per window; ~0.5 ms once per 4 GiB released at e9455 4M overwrite). - Repeated misses are O(16 x height) each instead of O(1) after the first (memos removed): +100 ns per 4K write while every dense try misses.
Open: the base hysteresis of adr 0021 am. 56 keeps the base closed at e9455 fill (reopen at 10 % free is unreachable); allocation cost no longer depends on it, placement does (doc/90-open-questions.md, "Base hysteresis at high fill").

## Amendment 3 (2026-11-02): cut a data run to the longest free run

Context: tsrv2 (1 OSD, kernel tier + knet, 96 % fill with 4 MiB objects, 4K-aged): the 4 MiB cell after the 64K / 32K cells (`w4m.2`) ran at 0.75x BlueStore (1186 vs 1583 MiB/s, p99 583 vs 154 ms) with ~118 extents and ~300 `alloc_frag_cuts` per 4 MiB write; allocator + `touched_chunks` 28 % of the samples (doc/perf/fill-stall-20261102.md). Free space there is the copy-on-write holes the small cells left (longest run under 64 blocks, no whole window). `alloc_upto` halved a missed run (64, 32, 16, ...): every level one failed next-fit search (`find_lent`: up to 4 scans), and a hole of L blocks went out in power-of-two pieces whose remainders landed in other objects (doc/perf/frag4m-20261102.md).
Decision: `Alloc::reserve_cut(want)` = `reserve(want)` next-fit, else the longest free run of the region (`longest_run` = tree root, am. 2) taken whole in one more walk. `Shard::alloc_data` returns `(block, blocks)` (`alloc_find` with `data`), caps the run at the blocks above the class floor; `Stage::alloc_upto` takes the run as it comes and only waits on `Busy` (nothing allocatable now). Next-fit searches (`find`, `find_base`, `find_borrowed`, `find_lent`) do the wrap / second-area scan only if the root says a run of `want` exists (`may_fit`): a miss = one scan + a root read. `alloc_frag_cuts` = data runs handed out shorter than asked. Placement of every request that fits is unchanged (`DenseAlloc` oracle, brute-force tree tests incl. `longest_run` / `reserve_cut`). RAM-only, no format change.
Rationale: off-lab model of the tsrv2 sequence (`lab/alloc-frag4m.sh`, tsrv2 shard size): w4m.2 extents per 4 MiB write 110-121 -> 78-89, allocator calls 359-404 -> 94-104, allocator time 350-402 -> 69-80 us; first w4m 34-42 -> 27-33 extents; 64K / 32K / 4K writes unchanged within noise. Small-write placement variants (best fit, window classes, immediate release of freed blocks) changed w4m.2 extents by < 15 %: the hole set is the free space; only moving data (a cleaner) makes long runs again.
Consequences: + no failed walk per halving level, no power-of-two remainders; + a pre-write miss costs one scan. - a 4 MiB write on short holes still takes one extent per hole (~80 at tsrv2 w4m.2). - `alloc_frag_cuts` counts runs, not failed levels: values are not comparable with earlier runs.
