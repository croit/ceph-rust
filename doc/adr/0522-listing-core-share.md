<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0522 Listings share the PG core with message work; leaf walks step without descents

Status: accepted, amended (am. 1-3)
Date: 2026-10-22
Amends: 0006 (am. 4, drain slice), 0021 (S8), 0491

## Context

Next to saturating omap listings a hot object of the same PG got about 1/5 of its solo throughput (adr 0491, OQ 92 (3)). Op traces (doc/perf/listing-core-share-20261022.md): ops decoded on another core waited 9 ms mean (p99 16 ms) in the PG core's inbox, ops decoded on the PG core 0. Cause: listing continuations (adr 0021 S8) hand no work units to the drain slice (adr 0006 am. 4), but their time entered the slice's learned cost per unit, so the inbox drain shrank to its first message per loop iteration while continuations of all listings ran each iteration (16 x ~75 us). A time share of continuations alone (a5e4561bd) lost. Store side: a range scan descended from the root for every leaf and stored a tree hint per leaf; a name key decode pushed byte by byte.

## Decision

- Listing continuations are background work of the PG core (`pgs::ListShare`): their time is measured (clock read before / after each continuation) and kept out of the drain slice's learning (`Osd::note_core_busy`: busy ns minus listing ns).
- When the preceding loop iteration accepted non-listing work from local client links or the PG-core inbox (am. 3; `XMsg::is_listing` = `engine::is_listing`: omap_get_vals / omap_get_keys, PGLS / PGNLS (+ filter)), listing passes stop after one drain slice (`SLICE_NS`, the first always runs). The store poll consumes the aggregate demand marker once per iteration; an empty inbox never erases local demand. Deferred passes run in the following iteration (`ListShare::pending`, `poll_store` runs `pg_post`). Otherwise every pass runs (work-conserving). The walk over the PGs with parked ops (`pg_post`) starts after the PG of the latest listing run that got a turn (`ListShare::last`, `pgs::parked_walk`: round robin; am. 2): from the lowest PG every time, the share stayed with the first PGs of a core while they had listings and the last ones starved. A fresh listing request's first pass takes the same turn (`Env::list_turn` in `on_op`; over the share it waits in the gate, ready: `Engine::defer_listing`). Counter: perf `list_deferred`.
- The omap listing walk does not compare the prefix per key (the cursor ends at `omap_prefix_end`); the gate walk's `ordered` tests session and op kind before object names.
- `Tree::scan` goes on in the right sibling under the same level-1 parent without a descent when it is resident and not the parent's last child (`Tree::step_leaf`; fence = the parent's next separator); no tree hint is stored per scanned leaf. A leaf whose fence is at or below the scan end needs no per-key end compare; the leaf prefix is copied once per leaf.
- A listing that holds a later op of its object (am. 1; `Engine::holds_later`: an op `ordered` behind it, gated or waiting for the object: a write, a read of its own session, a PG op behind a PG op) is no background work: it takes its turn unconditionally (`ListShare::turn(held)`, time still counted) and its run lists whole, without the adr 0021 S8 CPU slice (`ObjView::ov_list_whole` -> `Store::list_whole`, per run; cold leaves still refuse it). A listing that holds nothing keeps slice and share.
- Name keys decode run-wise (`keys::unesc`: copies between zero bytes) and move the strings into the hobject (`keys::hobj_of`); PGLS / PGNLS move the listed names into the reply (`pgop`).

## Rationale

- The starvation was a measurement error of the drain slice (background time charged to message units), fixed at its root; the per-iteration bound restores the inbox's turn without slicing listings that run alone (their own requests do not count as pressure).
- Sibling stepping removes a root-to-leaf descent with interior key decoding and a hint store per ~32 entries; it changes no result (test `tree_scan_ranges_step_between_leaves`).

## Consequences

- + Live zen4b vs main (doc/perf/listing-core-share-20261022.md): omap listing alone +69 % keys/s (OSD busy 258-273 -> 167-171 ns/key); hot object next to omap listings 2494-2726 reads/s, p99 7.6-8.3 ms (main 626-2714, 6.7-44.5 ms by session placement), the listing next to it +25 %; next to PGNLS hot +22 %, PGNLS objects/s +12 %.
- + Store bench (build host): omap keys 158 -> 36 ns/key, values 175 -> 42; PGLS 168 -> 118 ns/entry warm, 134 -> 83 cold.
- - The share alone: listings next to point ops list 12 % fewer keys/s (hot +17 % reads/s, p99 -15 %): the point ops get their turn of the core.
- - Two clock reads per listing pass (~75 us of work each).

- + am. 1: hot object A in the omapbench ab mix (zen4, doc/perf/omap-list-scan-20261024.md) 2262 -> 4246 point ops/s (BlueStore 3446), arm spread 11-26 % -> 2 %, A p99 -39 %; B point ops -2.6 %.
- - am. 1: a held listing occupies the core for its whole page (bounded by the request limits: 1024 entries, osd_max_pgls).

## Alternatives

- Time share of continuations against the other work of the last iteration (a5e4561bd): did not touch the drain slice's learning (the inbox stayed starved), cost listings alone 8 %; reverted.
- Yield on any inbox message: listings alone lost 3-5 % (their own requests from other cores cut them into slices; run1).
- Prefetch of leaf entries ahead of the walk: neutral (build host, Mac); removed.
- Checking the inbox for waiting messages before the store poll: one cache line per peer core and lane per loop iteration; the drain already knows what it handed on.

- Slice by time instead of entries (am. 1): a held listing still waits a loop iteration per pass, and the ops it holds with it.
- Let writes of other sessions pass a not yet started listing (am. 1): covers only the deferred fresh pass, not a listing in progress (a staged write drops its memo, the listing restarts).

## Open questions

- 1:1 per loop iteration between listings and other messages; another weight is a decision (OQ 92 (3)). The hot object's own write chain still waits up to a loop iteration per hop (exec ~5 ms next to listings vs ~2 ms alone).

## Amendments

- am. 1 (2026-10-24): listings that hold later ops of their object list whole and outside the share; gates: doc/perf/omap-list-scan-20261024.md.
- am. 2 (2026-10-30): round-robin walk over the parked PGs; gate: doc/perf/omap-scan-p99-20261030.md.
- am. 3 (2026-11-08): local and forwarded demand share the same iteration marker. Root cause: inbox-only pressure left the listing quota disabled for local clients, including every client of a one-core OSD. Regression: `local_reads_bound_listing_work_without_an_inbox` drives a local read, reports an empty inbox, and charges one deterministic continuation quantum; further PG continuation candidates must yield. Listing-only iterations remain work-conserving. Shared OSD layer covers knet/RDMA, replicated/EC, crc/secure and both storage tiers; no wire or storage changes.
