<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0637 Store admission: one space ledger with grants, typed would-block

Status: accepted; implemented in steps: M1 (space rule, parked held cost) in place, M2-M6 pending (doc/perf/admission-ledger-20261101.md)
Date: 2026-11-01
Amends: 0021 (S4 space, S8 non-blocking reads), 0066 (what may still fail-stop)

## Context

Review 2026-11-01 B1/B4 (doc/reviews/2026-11-01-osd-review-simplify.md). Space and store backpressure are decided at many places with different estimates, and a store refusal after the PG logged an entry is fail-stop (adr 0066):

| # | Site (main 2bd060bac) | Decision | Semantics today |
|---|---|---|---|
| 1 | opexec fast.rs:67 | `write_room(admission_cost(wire ops))` | fast path declines, general path decides |
| 2 | opexec engine.rs:1907 | `no_room` = `write_room(wire cost)`, exec input | -ENOSPC after RETURNVEC, before the pool-full rule (exec.rs:1981) |
| 3 | opexec engine.rs:1942 | `write_room(plan.room)` after exec (cls calls) | -ENOSPC, plan dropped |
| 4 | opexec engine/copy.rs:618 | `write_room(chunk)` | copy fails -ENOSPC |
| 5 | peering pg.rs:2516, ecpg.rs:386 | `apply_room` (sys floor) | replica write / EC sub-write held, retried on PG tick |
| 6 | peering recovery.rs:1545, pgset 1335 | statfs failsafe / backfillfull | push refused, backfill revoked (Ceph semantics) |
| 7 | osd ops.rs:887 | statfs failsafe (rule 12) | write-ordered op dropped (Ceph semantics) |
| 8 | store obj/store.rs:4157 `room()` | heuristic: payload/4K + entries + 16 + parked bytes/entries, class floors | the estimate behind 1-5 |
| 9 | store shard.rs:3343-3420 submit | path-probed page estimate vs meta free, class reserve | Busy + forced checkpoint, else NoSpace (PG txn: fail-stop) |
| 10 | store shard.rs:2240 `alloc_find` | data floors per class | Busy (held, reclaim, pool), else NoSpace |
| 11 | storeadapt lib.rs:982/995/470 | deletion txn NoSpace | slice halved, 1 object: 1 s back-off (`REMOVE_RETRY_NS`) |
| 12 | store obj/store.rs:1090/1099 `admission_ready[_for]` | park FIFO count/bytes headroom | callers hold input / park ops |
| 13 | osd pgs.rs:1823/1964, xcore.rs:1173, osd.rs:1505 | #12 per message at ingress | input held (`HoldWhy::Store`) |
| 14 | opexec engine.rs:1076/1242/1304/1547, storeadapt warm/warm_rm/warm_log, peering pg.rs:923/2608, ecpg.rs:383/409, pgset 1756-1780 | #12 per op / per PG tick | op re-gated, replay paused |
| 15 | storeadapt lib.rs:1584 `probe_cold`, osd.rs:1404 | `admission_ready()` + `queued_count()`: walk all shards | per op (`probe_meta`) / per driver pass |

Gaps: #1-#5 judge a heuristic that ignores clone and rename cost and charges parked txns by payload bytes; admitted txns are applied as `sys` and only the user-to-sys band absorbs concurrency and estimate errors, so a burst of admitted writes near the floor can still end in NoSpace (fail-stop); deletion txns can hit NoSpace (#11, a timeout-driven retry).

"Store would block" (B4) is carried by latches: `Store::blocked` (a refused read since the last `take_blocked`), `ShardIo::rm_progress` (set by refused range pre-scans that advanced and also by visibility / data waits, only so the engine does not count them against `MAX_SCAN_TRIES`), `ShardIo::rm_fresh` (pre-scan restarted), plus `cause_begin`/`cause_take` (wake tokens, all shards). Callers take each flag separately (opexec engine.rs:1631/1764/1952, pgop.rs:102/142/272, storeadapt lib.rs:949/1642-1646, view.rs:223); a latch left set by one caller is seen by the next. Waits behind a parked txn, FIFO headroom or space have no wake token: such ops are probed on every wake.

## Decision

Space (B1):
1. `Store::admit(cid, &Ask, Class) -> Admit` is the only space decision for txns. `Admit = Granted(Grant) | Full | Wait(Wait)`. Cost O(1): one shard lookup and integer math; no shard walk.
2. Classes: `User` (client mutation on the primary; refusal = `Full`), `Sys` (replica repop, EC sub-write, recovery push, copy chunk, migration import; refusal = `Wait(Space)`), `Free` (pure shrink: client delete / truncate / omap or xattr removal, PG deletion slices; floor 0; refusal = `Wait(Space)` only).
3. `Ask` = what the caller knows before any log entry: payload bytes, data extents written, tree puts (count, bytes), point deletes, range deletes, objects created, clone / rename sources. The store converts it with its geometry (block size, page size, tree height, txn page budget) into a sound `Cost { blocks, pages }`; clone / rename sources are resolved from their resident onode counters. Callers never estimate pages.
4. Per shard ledger `rsv: Cost` = sum of open grants. `avail(c) = free - rsv - floor(c)`, with `free` and `floor(c)` as `room_view` / `floors` today (held, reclaimable and lendable blocks count; dirty pages are charged). Granted iff `cost <= avail(c)`; then `rsv += cost`.
5. A grant travels with its txn: `WriteReq.grant` -> the PG's txn (`StoreTxn.grant`, summed when the PG merges txns) -> `OTxn.grant` -> parked entry -> staging -> submit. Submit releases it (`rsv -= grant`); data allocations of a granted txn draw from its grant (alloc floor = class floor + the other grants). Every path that does not reach submit releases the grant at one place (adapter `queue_txn`: nothing to write, structural txn, refused = fail-stop; deferred txns keep it until applied); the engine releases a grant whose `submit_write` failed.
6. Ungranted txns (PG bookkeeping: info, log trim, osdmaps; store background: defrag, OLSM merge, reclaim, reformat) are judged against `free - rsv - floor(class)`: they never take granted space.
7. Bound check at submit: a record that needs more data blocks or tree pages (the `validate` estimate) than its grant counts `space_overrun` once (perf dump); the record is then judged by the shard's floors like today. Tests assert `space_overrun == 0`.
8. Primary: one admission per message, after execution (plan known, cls writes included), before `submit_write`; the fast path and copy chunks use the same call. The refusal is the plain -ENOSPC of client-ops 5.8(c)(d): no log entry, nothing applied, also with FULL_TRY / FULL_FORCE; pure shrinks are never refused (they may wait for space). Order: RETURNVEC, pool-full rule (5.7 step 5), store admission.
9. PG deletion sizes each slice by `admit(Free)`: the slice is the objects whose cost fits; none fit = `Wait(Space(shard))`. NoSpace halving, the 1-object back-off and `REMOVE_RETRY_NS` are removed.
10. FIFO headroom stays store backpressure, reported as `Wait(Queue(shard))` by `admit` and by the per-shard probe `admission_ready_for(cid)`; the core-wide `admission_ready()` stays a walk over this core's mounted shards (one or two), not a latched counter that could go stale.
11. Ceph-visible full state is unchanged: OSD full / backfillfull / nearfull and the failsafe ratio come from statfs (real usage, grants not counted; client-ops 5.4 #11/#12, 5.7 step 5, 5.8; osd-lifecycle 4.4); push refusal and backfill revocation above failsafe / backfillfull stay as they are.

Would-block (B4):
12. Non-blocking store reads run in a scope: `nb_begin(cid) -> Scope`, refused reads return `Err(ObjError::WouldBlock)`, `nb_end(scope) -> Option<Refusal>`, `Refusal { why: Wait, tokens: Toks<8>, progressed, fresh }`. The scope is the only carrier: `blocked`, `rm_progress`, `rm_fresh`, `take_blocked`, `take_rm_progress`, `take_rm_fresh`, `cause_begin`, `cause_take` are removed. Nested scopes restore the outer one.
13. `Wait` kinds and their single wake source: `Page(tok)` page load completed; `Data(tok)` prefetch / media read completed; `Slice(tok)` the listing / pre-scan CPU slice ended (next pass); `Parked(shard)` the shard's FIFO head was staged or dropped; `Queue(shard)` the FIFO dropped below headroom; `Space(shard)` a grant was released, a checkpoint released blocks or the free pool grew. Each source pushes its token into the wake set. More than 8 tokens or no token = unknown cause = woken by every wake.
14. The engine counts a refused run against `MAX_SCAN_TRIES` only for `Page` / `Data` without progress (replaces setting `rm_progress` at visibility and data waits).
15. `ObjView` keeps `Result<T, i32>`; the refusal reaches the engine as the value of `ov_nb_end`, never through an errno.
16. Replica held queue (adr 0636): a held head waits on its typed reason only (`WaitOn::Admission` = `Wait(Queue)`, `Space` = `Wait(Space)`, `Loads` = `Page` / `Data` tokens), each woken by its store source. `REPOP_WAIT_MSGS` / `REPOP_WAIT_BYTES` and the forced, core-blocking replay are removed: the per-PG held memory is bounded by the input credits each held message keeps (per OSD), the bound admission and space waits already rely on. Closes OQ 126.
17. Interface types: `Ask`, `Class`, `Admit` and the grant the PG layer carries (`WriteReq.grant` -> `StoreTxn.grant`) are defined next to `PgStoreOps` in `peering::store` (store-agnostic plain data, like `StoreOp`); storeadapt converts them to `store::space` (as it translates `StoreOp` to `TOp`). A txn the adapter does not queue (translated to nothing, orphan PG, dropped on interval change) releases its grant there.

Invariants:
- I1 admitted => never NoSpace: estimate <= grant for every granted txn (bound property), and only grants lower `free - rsv` below a class floor.
- I2 frees always proceed: `Free` has floor 0; `Sys` admissions and ungranted bookkeeping stop at the sys floor; a one-object deletion slice costs less than the free band, which refills when the deletions' checkpoint lands.
- I3 no lost wake: every `Wait` names a token its source pushes, or is unknown (woken by all).
- I4 the ledger closes: with no parked txn and no op between admission and queue, `rsv == 0` (checked in tests and `diag`).
- I5 no on-disk change: grants and the ledger are memory only; replay and the format are untouched (adr 0021 upgrade rule not triggered).

Migration (each step one squash-ready commit, affected-crate tests green):
- M1 store `space` module: `Ask`, `Cost`, one `fits` rule; the parked FIFO keeps its held `Cost` (replaces the parked bytes / entries charge of `room()`); the client op's cold probe asks the PG's shard only (`probe_cold_for`; the all-shard `probe_cold` is removed).
- M2 store: `Class`, `Grant`, `Admit`, `Store::admit` / `release`, per-shard grant ledger charged next to the parked FIFO (also by `write_room` / `apply_room`); `OTxn::grant` consumed once when the queue accepts the txn (parked txns are charged their grant instead of their input bytes); `Txn::grant` reconciled in `validate` (`space_overrun`).
- M2b store: shard allocation floors honour the held cost (ungranted work cannot take granted space).
- M3 callers: `StoreTxn.grant` (store-agnostic plain data through peering), adapter release paths, `PgStoreOps::admit` replaces `write_room` / `apply_room`; engine single post-exec admission (fast path, copy); replica / EC / push admission through `admit`.
- M4 PG deletion slices by `admit(Free)`; halving and back-off removed.
- M5 B4 scope in store; storeadapt view, opexec engine / pgop, peering `rm_prep` consumers; latches removed; token kinds `Parked`, `Queue`, `Space` with their sources.
- M6 `read_session` and cause collection per shard of the PG (no all-shard walk per op).

Test plan:
- store unit: ledger arithmetic, grant / release / leak (I4); property test over random txns (writes incl. fragmented free space, omap puts / deletes, clones with omap, renames, range removals, truncates): `cost(ask) >= prepare estimate` and data blocks (I1); fill test: many granted txns in flight at the user floor all submit without NoSpace; `Free` slices admitted at the sys floor (I2).
- store crash matrix (`cargo test -p store --features lab,elastic`): existing nospace, fullrecover, wal, olsm crash tests plus a remount with granted txns in flight (grants volatile, I5).
- storeadapt: `nospace.rs` (granted txns survive no room), deletion on a full store without back-off, `parked.rs`.
- opexec: ENOSPC order (RETURNVEC, pool full, admission), cls post-exec cost, fast path = general path, copy ENOSPC.
- peering: replica / EC sub-write held on `Wait(Space)` and released by the `Space` token (I3).
- osd `--lib`: xcore full-store fill (primary + replica) without fail-stop.
- B4: scope nesting; one test per `Wait` kind that its source wakes it; engine try counting.

## Rationale

The store is the only place that knows block size, page size, tree height, floors and the counters of a clone source, so it alone converts intent into a bound. Grants make concurrency exact: each in-flight txn is counted once, from admission to submit, instead of a band that absorbs an unknown number of them. A scope returned by value cannot go stale between callers, and naming the wait kind gives every wait a wake source. Accepted trade-off: a bound is above the real cost (whole paths per op, splits per put); near the floor this refuses or holds a little earlier than an exact page count would.

## Consequences

- + one space decision and one estimate (store-owned) instead of five heuristics; admitted txns cannot fail-stop for space while bounds hold, an overrun is visible (`space_overrun`)
- + deletions never back off on a timer; space-freeing work has its own band
- + no all-shard walks per op; parked / queue / space waits get specific wake tokens (fewer probes)
- + no format change
- - a grant field travels through `WriteReq`, `StoreTxn`, `OTxn` and the park queue
- - bounds over-reserve per txn in flight (meta pages scale with tree height): near full, ENOSPC / holds start a little earlier than today's estimate
- - Ceph-visible change in one corner: pool FULL flag set AND store without room AND the write grows: today -ENOSPC (store check first), new: the pool-full rule first (drop, or -ENOSPC / -EDQUOT with FULL_TRY), as a classic OSD (which has no store check) answers

## Alternatives

- Pass-scoped pending reservation (no grant field, reset at end of pass): exact only if every admitted txn is queued in the same pass; held local persists (send-first) and driver order make that fragile.
- Admission inside `Store::queue`: the PG already appended the entry; a refusal there is fail-stop (adr 0066).
- Exact page counts by translating and probing every write before its log entry (`check_write` for all sizes): doubles translation CPU per write.
- Keep halving + timed back-off for deletions: a timeout as a decision.
- `ObjView` error type `Errno | Wait` through every exec call site: same information as the scope value, touches all of exec.

## Open questions

- Removal of one object with very many shared extents (reference decrements) may cost more than the free band: truncate it in slices first, or size the free band by the largest object removal seen?
- Pre-written pieces (adr 0477) are charged in the grant and allocated already: release that part of the grant when the txn claims them (touches the pre-write path)?
- The pool-full vs store-refusal order change (Consequences, last line): decided 2026-11-01 by the lead: pool-full rule first, as classic (app-visible behaviour = Ceph).
- I2 needs removal to be net freeing per checkpoint at the sys floor: open question "Removal at the meta floor" (doc/90-open-questions.md, adr 0021 S4). Until it is fixed in the store, a free slice at the floor can still be refused (`Wait(Space)`, never fatal).
