# 0049 EC primary role

Status: accepted, amended (am. 9)
Date: 2026-10-11
Consolidated 2026-10-19; full pre-consolidation text: git show 60868596d:doc/adr/0049-ec-primary-role.md
Supersedes: 0039 point 4

Incident detail: doc/perf/adr-0049-history.md (doc not in the source snapshot).

## Context

adr 0039 phase B: croit-flashstore-osd must lead EC PGs (L0 append-only, L1 overwrites; isa van/cauchy, jerasure van/r6) with classic and/or croit-flashstore-osd shards. Plan + status: doc/ec-phase-b.md. Optimized pools (mode O): adr 0067.

## Decision

Switch and layering
- `ec_enable_primary` (default `true`; applied to PGs created/loaded afterwards): off = adr 0039 behavior bit-for-bit (a PG led here is frozen and silent). On = a supported pool in `ec_enable_pools` is led here. The choke point allows primary-side message types only while on (`ec_primary_may_send`); shard validation unchanged.
- Crate `ecback` (sans-IO: logical txn -> per-shard txns, rollback info, hinfo, post state; read plan/decode; `ec::gf` adr 0048) and `peering::ecprim` / `ecrec` (pipeline, read service, recovery). The op layer keeps its replicated-shape transaction; EC specifics live below `Env::submit_write`.

Writes
- Planned at submit (versions reserved, `Env::next_version` = reserved + 1, object state projected so the engine pipelines writes on one object; EOPNOTSUPP/EFBIG/EINVAL are synchronous errors, nothing logged). Generation strictly in version order; old stripes of an RMW are read only after every earlier write on the object committed on ALL shards (no extent cache).
- Local shard = `ec_append_log` + `ApplyTxn`; peers get `MOSDECSubOpWrite` (v4, txn inline). Client ack only when every member of `acting_recovery_backfill` committed (adr 0008). Idle pipeline with `pg_committed_to > can_rollback_to` sends the dummy roll-forward sub-write.
- Shard txns follow ec.md 11.2 (stash by `CLONE_RANGE2`/`COLL_MOVE_RENAME`, `hinfo_key` last, mod_desc CREATE/DELETE/SETATTRS/ROLLBACK_EXTENTS/APPEND). Truncate(0) of an existing object = move away + create + reapply attrs (WRITEFULL on append-only pools). ZERO/overwrite/truncate on L0 = EOPNOTSUPP. Omap on EC = EOPNOTSUPP except optimized pools with FLAG_OMAP (adr 0067).

Reads
- Op layer `Env::ec_wait` starts a stripe-span read (wanted data shards, or any k + decode) and parks the op; `ov_read` serves decoded bytes from a 64 MiB FIFO cache (`CACHE_CAP`; invalidated at write submit and completion; a read racing a write is discarded). `ov_stat` = logical size from object_info; hinfo hidden from clients. Shard errors retry with the remaining shards; < k left = EIO.
- Read routing per object: `ec_osd_holding(soid, j)` = the `acting_recovery_backfill` member with shard j that holds a current copy (`ec_member_has`, the `ec_avail` predicate); our own shard only when not missing. An acting member and a backfill target share j under pg_temp; shards do not version-check reads.
- Sub-reads in flight (`EcRd::pending`, warm reads, recovery attrs / omap pages `RecState::NeedAttrs/NeedOmap`) carry their target (`Asked{tid, osd, epoch}`) and have NO timer: a slow, partitioned or map-lagging peer is waited for. A same-interval map that shows the target down or restarted (`up_from` > send epoch) gives the shard up (replan / recovery retry from other sources; classic `check_recovery_sources`, spec missing-loc.md 5); a faulted cluster connection loses nothing while the peer stays up (lossless session, adr 0071 am. 2); a new interval clears all (EcPrim reset, writes requeue with EAGAIN). Before: a 10 s timeout turned a held reply into failed shards, no read plan, client write EIO (OQ 28 O14).

Peering, recovery, backfill
- `choose_acting_ec`: positional want with NONE holes, oldest complete member authoritative, up members that cannot catch up from the log become backfill targets, recoverable = k shards, no async recovery; peers identified as `PgShard{osd, acting position}` (`Pg::pshard`); min_present = k in the prior set.
- Recovery per object `RecOp`: attrs (ours, or from a source when we miss it), whole-stripe chunks read from k shards, re-encoded, one `MOSDPGPush` per target (shard offsets, attrs on the first chunk, hinfo copied), local apply for our own shard. Source read failure = object stays unfound (state bit + clog note), retried next interval.
- Backfill reuses the replicated scan/cursor machinery; only the push is the EC rebuild. A backfill target gets writes beyond its cursor log-only (`backfill_or_async_recovery`); a push rebuilt while such writes (incl. `_header` setattr) were queued would carry an older version and leave a stale shard under a current log.
  - `backfill_pump_pushes` defers an object while `ec_write_in_flight` (back to the front of the batch; new writes stay refused by `backfill_blocks`; every write completion runs `backfill_step`), so a push never carries an older version than a queued write.
  - `backfill_on_digest` adds every object of the batch range with a write queued or uncommitted (`ec_writes_in_flight_in`) to the push list (never removes it there); the push is built from committed state, or the target copy is removed (`MOSDPGBackfillRemove`) if the object is gone by then.
- Scrub as primary: done (doc/ec-phase-b.md B8); member key = pg_shard (below).
- Stats: an EC primary sets `stats_invalid` in published stats and `info.stats` (our `num_bytes` = local shard bytes * k, not the logical sum of `oi.size`; classic then replaces it with the scrub count without error). Replicated pools unchanged.

Two instances of one PG on one OSD (pg_temp/upmap/out with few OSDs; acting [a,b,a])
- Classic skips only the exact own pg_shard; any other instance on our OSD is an ordinary peer. Peer skips compare the whole `PgShard` (`query_probe_peers`, `probe_strays`, `stray_search`, `choose_acting_ec` stray candidates). `Pg::pshard(me.osd)` names the OTHER local instance (osd-keyed bookkeeping: reservations unique per OSD like classic `unique_osd_shard_set`; pushes; scrub).
- Loopback in `PgSet::finish`: a send to our own OSD for a PG this core owns (all instances of a pgid share a core, adr 0031) is encoded + decoded with all features and queued; `finish_at(now, store)` delivers FIFO, answers included, up to 4096 per call, rest due at once via `next_deadline`. Never reaches the messenger; classic peers see nothing new.
- Durability unchanged: the second local shard's sub-write is a regular ECSubWrite with its own persist; client ack waits for every `acting_recovery_backfill` member.
- Scrub keys members by pg_shard (EC: acting position; replicated: OSD; `scrubp.rs` `sp_members`): MOSDRepScrub goes to every acting position but ours (other local instance by loopback); MOSDRepScrubMap accepted by `m.from` (osd checked against the connection); `list-inconsistent-obj` maps keys back to `(osd, shard)`. Reservations: one per remote member; the other local instance is not reserved.
- `send_notify` = `!is_primary()` by pg_shard. Acting membership of our own instance (`begin_activate` les/pct stamp, EC `ec_append_log` backfill-target rollforward) = `in_acting(me)` (our OSD at OUR position).

Remote OSD at two positions ([a,b,b])
- Every primary-side wait is keyed by pg_shard; the shard comes from the reply, the OSD from the connection (`from`), never the reverse. `RepOp.waiting: BTreeSet<PgShard>`: EC sub-write reply key `(from, op.from.shard)`; UpdateLogMissingReply `(from, m.from)` (EC) / `ps(from)` (replicated); `peer_lcod` same key; EC push waits `(from, MOSDPGPushReply.from.shard)`; `rec.deletes` = `(PgShard, oid)`.
- Backfill reservations stay one per OSD (`reserve_wait` dedups targets by OSD; `bf.reserved`/`release_owed`/`backfill_peer` by OSD). `scan_wait` by pg_shard; a DIGEST is accepted from `m.from` when it is a target or has a scan outstanding; RELEASE goes out once no scan to that OSD is outstanding; TOOFULL (no shard) clears every scan to the OSD; FINISH_ACK completes the first Finishing target on the OSD.
- Wait keys are pg_shard: EC push waits (`ecrec` `RecState::Pushing`) = `(from, MOSDPGPushReply.from.shard)`; `rec.deletes` = `(PgShard, oid)`, reply key `MOSDPGRecoveryDeleteReply.from.shard`; `ECSubWriteReply.from`, `MOSDPGPushReply.from`, `UpdateLogMissingReply.from` = replier's pg_shard (classic fields, no new traffic). Cause: `osd out` or pg_temp/upmap with few OSDs can put two instances of one PG on one OSD (e.g. acting [a,b,a]); classic skips only the exact own pg_shard, others are peers over loopback.
- EC sub-write reply is accepted only if `op.from.osd` = connection OSD, `op.from != me` and `op.from` is in `acting_recovery_backfill`; else discarded before touching wait/LCOD state.
- Membership at the exact position (classic `is_acting`/`is_up`): `pg_acting_features` from notifies of acting members only; `find_best_info(restrict)` skips `is_stray_shard`; DEGRADED for a backfill target counts only a target acting at its own position. Replicated: OSD-based.
- Read lease renewal goes to every acting pg_shard but ours (`peer_shards_acting`), each with its own spgid shard; acks stay OSD-keyed (MOSDPGLeaseAck has no sender shard); readable_until waits for the ack of every OSD in that set, ours included when it holds another position.
- No new wire traffic: all fields used are classic.

## Rationale

KISS: no extent cache (measure first), shard txns generated below the op layer (replicated path untouched), never block the core on EC reads. Identity by pg_shard because OSD-only keys ack a write one shard early or stall backfill when one OSD holds two positions. `stats_invalid` instead of exact logical accounting (would need per-op deltas incl. rollback/clone rules or a store format change).

## Consequences

+ croit-flashstore-osd leads mixed and all-croit-flashstore-osd EC acting sets.
- Scalar GF kernel (adr 0048), per-op buffer copies, one write in flight per object RMW chain, no async recovery.
- A clean acting set with one OSD twice cannot be built on demand in a lab (mon dedups pg-upmap, CRUSH never repeats); covered by sim only.

## Alternatives

- Extent cache for RMW: rejected, KISS, measure first.
- Async EC reads inside `ObjView` via blocking: rejected, never block the core.
- Generating shard txns in the op layer: rejected, layering.
- Exact logical `num_bytes`: rejected, see Rationale.

## Open questions

- OQ 38 (doc/90-open-questions.md): `num_object_clones` is never filled and clone bytes are full sizes (classic `get_clone_bytes`); pools with snapshot clones may show a v20.2.x stat mismatch after a handover to a classic primary; not seen live.
- (closed) Original decision point 7 (EC scrub as primary disabled) is superseded: scrub as primary is always on (doc/ec-phase-b.md B8); verified 2026-10-20 that no `ec_scrub*` config key or default-off switch exists (only `osd_scrub_*` tunables).

## Amendment map

- am. 1 (2026-10-14): two shards of one PG on one OSD -> Decision (Two instances)
- am. 2 (2026-10-14): scrub + remaining own-OSD checks -> Decision (Two instances)
- am. 3 (2026-10-15): remote OSD at two positions -> Decision (Remote OSD at two positions)
- am. 4 (2026-10-15): review: exact-position identity checks, lease renewal -> Decision (Remote OSD at two positions)
- am. 5 (2026-10-15): EC primary stats_invalid -> Decision (Peering, recovery, backfill: Stats)
- am. 6 (2026-10-15): read routing per object -> Decision (Reads)
- am. 7 (2026-10-16): backfill push vs writes in flight -> Decision (backfill_pump_pushes)
- am. 8 (2026-10-16): backfill batch vs writes in flight -> Decision (backfill_on_digest)
- am. 9 (2026-10-20): sub-reads without timer, dropped on target down/restart, redriven on session loss (redrive replaced by lossless sessions, adr 0071 am. 2) -> Decision (Reads)
