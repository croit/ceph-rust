# 0050 Executable classic-peer model in the peering Sim
Status: accepted (2026-10-11)

## Context
Mixed clusters abort classic OSDs ("we got a bad state machine event", PeeringState Crashed; asserts) when croit-flashstore-osd sends a message a classic PG state does not handle. Found live, expensively: stray split children (Reset), RELEASE/REQUEST around ungranted reservations, EC from==primary. Live cycles are slow and non-deterministic.

## Decision
1. Spec `spec/classic-peer-model.md` (own words): classic statechart, state x event matrix (H/I/A), admission order, split/merge child lifecycle, reservations, per-role send rules.
2. Model in `services/osd/peering/tests/common/classic*.rs`, on in EVERY Sim by default (`Sim::classic`): checks each delivery to a classic node against the table and panics with state, event, stamps, delivery history. Pieces:
   - `classic_table.rs`: table encoded verbatim from the spec (`verdict(state, event)`), unit-replayed against real logs (`tests/classic_replay.rs`, fixtures from `lab/docker/mixed/capture-classic.sh`).
   - Classic state of a PG copy = the stand-in `Pg` (the Sim node runs croit-flashstore-osd code as the classic peer) plus model overlays where classic differs: split child in Reset until its OSD consumed a map > split epoch; replica reservation substate (RepWaitRecovery ignores RELEASE and stays pending); ToDelete left by the next interval.
   - Admission: drop when `last_peering_reset > epoch_sent|epoch_requested` (map-derived interval start, restart, PG birth, stand-in reset).
   - Realism: classic stand-ins stay silent about a split child until the shard consumed the next map (held sends re-stamped, stale ones dropped); classic stand-ins never gate.
   - Sim has no heartbeat evidence (heartbeat epoch is no evidence, found by the model).
3. Scenarios: randomized split/merge/kill/out/pg_temp/flag storms (`tests/classic_model.rs`, `STORM_N` for bigger hunts, all-classic and mixed), plus every existing Sim test.
4. A model violation is either an croit-flashstore-osd bug (fix + regression seed) or a model gap (fix model, document in the spec section 9).

## Consequences
- Aborts of this class are found in seconds; each fixed hole keeps its storm seed as regression.
- Messages beyond the receiver's map and non-peering ops (do_request path) are counted as `unchecked`, not judged. Create-on-message (spec 3.4) is judged: Notify/Log for a PG the classic peer lacks creates it where the shard map puts it (primary -> GetInfo, else Stray), then the event meets that state (a Notify to a Stray aborts).
- Duplicated-message chaos runs switch the model off (msgr2 never delivers twice).
- Storms settle strictly by default (`STORM_LAX=1` = verdicts only): the pool must end active+clean, no merge/split pending, nothing in flight. Hunting: `STORM_N=<seeds> STORM_ALL=1 cargo test --release -p peering --test classic_model -- --nocapture` lists `FAILSEED n` and goes on; `STORM_ONLY=n` replays one seed (`STORM_N` above n - base), `DUMP_LINES=n` widens the trace. Every fixed seed lives in `storm_regressions`.
- Found with it (messages): heartbeat-epoch gate opening, late-advanced child sends stamped at the split epoch, children created from messages (parent held elsewhere) had no gate (`PgSet::gate_created_child`).
- Found with it (liveness, 25k seeds): (1) `PgSet::trim_maps` kept only maps above the lowest PG epoch: a PG created from a message stamped with a trimmed epoch fell back to a newer map and kept the sender's older interval start, its peers dropped its Pull/Push as old (primary stuck Recovering, objects unfound): maps are now kept `MAP_CACHE` (50, own constant, rationale not recorded) epochs back. (2) the merge placeholder took the SOURCE's history les: no complete copy reached it, every later peering of the merged PG was Incomplete: les/lec now come from the pool's merge meta (classic `merge_from`). (3) recovery data messages (Push/Pull/replies/RecoveryDelete) were dropped when `last_peering_reset > min_epoch`; classic ignores `min_epoch` there (`can_discard_replica_op` = `old_peering_msg(map_epoch, map_epoch)`, `min_epoch` only means "wait for this map"): a stray restarted after the primary's interval began could never serve a Pull. RecoveryDelete(+Reply) decode as peering messages (pgwire first): the rule matches both variants (review fix, test `recovery_delete_gated_by_map_epoch_only`).
- Model gaps fixed on the way: ToDelete left by a new interval becomes GetInfo when the OSD is the new primary (not always Stray); a pg_num change that merges two OTHER PGs is no interval; a GRANT that crosses a RELEASE parked for the map is no new wait state.
- EC shard role: the outbound choke point (`spg_violation`) also checks the sender's own shard (classic asserts `pg_notify_t.from == info.pgid.shard` and keys Notify/Info/Log by it).
- Old start maps (open question 13d, safety): create-on-message from a sender lagging > `MAP_CACHE` epochs no longer falls back to the oldest kept (newer) map: a primary could miss an interval with acked writes. The message is parked (`PgSet::parked_old`, <= 1024 PGs; later messages for a parked PG queue behind it, <= 1024, classic per-PG order), `Action::NeedOldMaps{from,to}` goes to the driver; while asked, maps from `to`+1 on are not trimmed (the answer ends at `to`, a gap would hide intervals), the control core loads the maps from the persisted meta store (single core: same core; worker: `XMsg::OldMapsReq` / `OldMaps`), `PgSet::old_maps` replays the create on the start map and advances through every interval. Start map trimmed (store below oldest_map): message dropped + notice (classic `get_map` asserts; peers retry). Tests: `tests/old_maps.rs` (park, replay of intervals, trimmed, recent, maps arriving while asked, newer message queued behind), `osd` `xcore_tests::worker_creates_pg_from_an_old_message_via_the_control_cores_maps` (worker -> control `OldMapsReq` with 40 epochs arriving meanwhile), `tests/old_maps_sim.rs` (both holders lag past the cache, new primary peers from old-epoch Notifies, acked writes intact; Sim `hold_maps`/`release_maps`/`maps_gone_below`).
- Map memory: the control core decodes every epoch of a MOSDMap once (`pg_decode_chain`), `MapUpdate.chain` shares the `Arc<OsdMap>`s with the workers (CRUSH decoded on the control core before sharing: no worker waits on another's lazy decode; workers keep only the blobs of recent updates, `MapBlobs`, not the decoded maps) (KISS choice over `OSDMap::dedup`: no substructure sharing across epochs, one copy per epoch). Synthetic 5k OSDs/10k upmaps, 16 cores x 50 epochs: 2351 MB (per-core decode) -> 143 MB RSS (`crates/osdmap/tests/mem.rs`, `MEM_MODE=per_core|shared`, ignored).

## Amendment 1 (2026-10-19): what the simulator proves, and what needs real classic OSDs
External review: the model is not an independent compatibility oracle. In the Sim the "classic" node runs croit-flashstore-osd's own peering code (stand-in `Pg`) plus overlays; the table is encoded from our reading of the classic statechart (spec/classic-peer-model.md) and replayed against captured real logs only for the events those logs contain. Consequences, binding for every claim in docs and reports:
- PROVES: internal consistency (no croit-flashstore-osd message the TABLE rejects; liveness/settling of randomized split/merge/kill/out/pg_temp storms; regression seeds). It finds our bugs against our spec.
- DOES NOT PROVE: that the spec/table equals real ceph-osd v21.1.2 behavior (a wrong table cell or a missing overlay passes silently); that classic aborts (asserts, state machine crashes) cannot occur; any path counted `unchecked` (messages beyond the receiver's map, non-peering ops / do_request path, duplicated-delivery chaos with the model off, ordering inside a real msgr2 session, classic admission details outside `last_peering_reset`, EC shard rules beyond `spg_violation`); classic PG log/backfill data semantics (objects, omap, snaps).
- Compatibility claims therefore need real classic ceph-osd peers: mixed lab suite `lab/docker/mixed/` (cases 01-19: baseline, upmap, autoscale split/merge, flags, replace, revoke, resv contention, copy, quick restarts, scrub, release smoke, EC; `repro-split-backfill.sh`, `repro-backfill-classic.sh`, `stress-crash.sh`, `nodown-classic-cmp.sh`) and the new single gate `21-mixed-gate.sh` (one mixed-acting-set pool: PG split + merge, backfill under client load in both directions (crush rule round trip classic-only, flashstore-only, mixed), classic stop and croit-flashstore-osd crash mid-load, md5 of every object, deep-scrub, classic restart-count/abort scan). New model gaps found there become table fixes + fixtures (`capture-classic.sh`, `classic-log-to-fixture.sh`), which is how the table is kept honest.
- Decision point 4 changes: a lab disagreement with the model is a MODEL gap first (fix table + fixture), then an croit-flashstore-osd bug.
- First run 2026-10-19 (lab VM, 3 classic + 3 croit-flashstore-osd, Ceph v21.1.2 image): 35 pass, 0 fail, 266 s; mixed acting sets 25 of 32 PGs after split, 6 of 8 otherwise (note: with the 3+3 lab not every PG mixes).

## Amendment 2 (2026-11-08): immutable CRUSH bytes across incremental epochs

### Context
Checked incremental application clones the previous map. Catch-up and retained
interval history keep several such epochs alive, including unchanged CRUSH blobs.

### Decision
The private raw CRUSH blob uses `Arc<Vec<u8>>`. Incremental clones share its
immutable bytes; either replacement setter installs a new owner and invalidates
or replaces the decoded cache. Other map fields retain their existing ownership.
This supersedes the no-substructure-sharing choice above only for the raw blob.

### Rationale
The public API already exposes the bytes read-only and replaces them as a unit.
Sharing requires no map comparison or deduplication pass. `Arc<Vec<u8>>` takes
ownership of the incoming vector without a second payload copy.

### Consequences
- Unchanged CRUSH storage does not grow with retained incremental epochs.
- Wire encoding, CRC validation and per-epoch placement remain unchanged.
- One reference-count operation replaces each full-blob clone.
- Regression evidence: scale review (doc not in the source snapshot).

### Alternatives
- Copy the raw blob per epoch: avoidable storage and copy cost during catch-up.
- Share every map substructure: broader API/ownership changes are unnecessary here.
