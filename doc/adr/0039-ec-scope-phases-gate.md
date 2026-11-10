# 0039 EC scope, phases, support gate and decline mode

Status: accepted, amended (am. 4)
Date: 2026-10-10
Consolidated 2026-10-19; full pre-consolidation text: git show 60868596d:doc/adr/0039-ec-scope-phases-gate.md

## Context

adr/0010 requires EC (shard + primary roles) eventually; adr/0013 v1 = replicated only. Classic OSDs abort on malformed/misrouted PG messages (prime safety rule), and a silent passive peer stalls classic primaries (GetInfo waits for every probe target, no timeout). Plan: spec/ec-gap.md; wire/algorithms: spec/ec.md; classic model: spec/classic-peer-model.md.

## Decision

### Phases and gate (points 1-7)
1. Phases: 0 = profile parser + per-pool gate (crate `ec`); A = shard role under a classic EC primary (A1 wire+apply+peering-as-replica+push+scrub digests, A2 rollback/roll-forward executor adr 0040, A3 overwrite pools L1 shard side, A4 clay optional); B = EC primary (adr 0049); C = optimized EC (adr 0067). Shard role needs no galois math.
2. Support gate = ALLOW-LIST, default deny (`ec::evaluate`, per pool, re-evaluated on every map change). Supported iff: plugin isa (reed_sol_van | cauchy, k,m <= 32) or jerasure (reed_sol_van w=8 | reed_sol_r6_op w=8 m=2); mode L0 (append-only) or L1 (`allow_ec_overwrites`); no optimized flag unless adr 0067 serves it, no omap flag; profile present and parses (strict decimals, k>=2, m>=1, k+m<=127); pool size == k+m, k <= min_size <= size; stripe_width > 0, multiple of k, chunk = stripe_width/k multiple of 32; `mapping` (if any) has k+m positions with exactly k 'D'. Everything else (lrc, shec, clay, bit-matrix techniques, w != 8, unknown plugin, bad profile) = Unsupported(reason): no state, one clog/notice line naming the reason, listed in `tell status` `ec_pools[]` (pool, profile, supported, reason, mode = serve|decline|passive, decline counters). A pool flipping to unsupported stops serving at once; on-disk data stays untouched.
3. Kill switch `ec_enable_pools` (default `all`; `off` | `all` | comma list of pool ids/names): a supported pool is served only if enabled. `ec_enable_primary` default `true` (adr 0049). Default on: `ec_enable_optimized`, `ec_enable_optimized_primary` (adr 0067 am. 10). Default off: `ec_pdw`, `ec_optimized_direct`. Only an operator opt-out (`off`/`false`) re-creates the silent-passive state (stalls classic PGs). Set via `--set` at start or `tell osd.N config set` (`ceph config set osd.N ec_*` is refused by the mon: unknown key).
4. Optimized pools stay declined unless adr 0067 flags enable them; an croit-flashstore-osd acting primary of a pool it does not serve does nothing and says so loudly (decline 6).
5. Every outbound message goes through choke point `PgSet::finish` with a per (message type, role, pool mode) allow-list for EC (shard role: peering replies, sub-write/read replies, push/scan/backfill/scrub replies only); shard must equal the receiver's acting index; default deny. Check `spg_violation` (`peering/src/pgset/outbound.rs`).
6. Unknown mod_desc record / transaction op / plugin on a supported pool never aborts the process: unparsable rollback info => adr 0040 case 5; a rejected transaction => not acknowledged; an undecodable EC sub-op never closes the link; unknown pool feature => gate says Unsupported. EC `pg_num` changes: shard PGs split/merge like replicas, children/targets keep our shard.
7. Library: crate `ec` (profile, gate, geometry, hinfo codec, mod_desc codec). Own frozen tests; upstream corpus = temporary oracle.

### Decline mode (was am. 1; point numbers kept for references)
Config `ec_decline_unsupported` (default true; false = silent passive; operator opt-out `off`/`false` of it or of `ec_enable_pools` / `ec_enable_primary` re-creates the silent state; set at start with `--set` or at runtime with `tell osd.N config set`, PGs created/loaded afterwards). Classic answers a query for a PG it lacks (`handle_pg_query_nopg`) with an empty `last_backfill = MAX` info = "complete and empty", which would make an empty shard acting (untrimmed log: log-recoverable, real sub-writes/pushes in a format we cannot store). An INCOMPLETE info (`last_backfill = MIN`, last_update 0'0) is never auth (`find_best_info` drops it), never chosen for a position (`calc_ec_acting` candidates need `!is_incomplete`), never asked for log/missing (`GetMissing` skips `is_empty()` / `last_backfill == MIN`): our shard becomes a backfill target, the position NONE; the PG goes active if acting >= min_size, else peered/incomplete.
1. Scope: erasure pools the gate rejects (`EcPoolInfo.supported == false`). NOT pools supported but disabled by `ec_enable_pools` (they may hold shards; a runtime flip would change answers inside an interval). Legacy -> optimized flip starts a new interval (flag in `is_new_interval`).
2. Stateless responder in `PgSet` (no PG object, no store write): Query2 INFO -> Notify2; LOG/FULLLOG/MISSING -> empty Log; both with info {pgid = (pgid, queried shard), last_update 0'0, last_backfill MIN, default history}; Log/Info2 from a primary -> Info2 ack (primary's info with our shard, last_backfill MIN, stats cleared, no lease ack); EC sub-write -> WriteReply committed+applied ONLY if txn empty AND `backfill_or_async_recovery` (else no reply, error notice: never ack data); UpdateLogMissing -> reply; BackfillReserve REQUEST -> REJECT_TOOFULL; everything else dropped and counted. `last_complete` = per-PG high-water mark (in-memory, never decreases within an interval).
3. Epoch stamps = the REQUEST's epochs (never ours), so stale answers are dropped by `old_peering_msg`/`old_peering_evt`. Notify2/Log keep classic nopg stamps (epoch_sent = our map, query_epoch = query.epoch_sent).
4. `spg_violation` has a decline allow-list: exactly the 6 reply types above; reserve only REJECT_TOOFULL; Log with empty log; every carried info last_backfill MIN. Anything else for an unserved pool stays forbidden.
5. Operator signal: clog WRN per pool AND verdict (hourly) naming pool, reason, effect; classic PG states give health warnings; own alert `FLASHSTORE_EC_POOL_NOT_SERVED` (`os_alerts`, HEALTH_WARN, per OSD) for every mapped EC pool not served (kill switch off, unsupported, declined; source `ec_warned`); doc/ops/ec-unsupported.md.
6. croit-flashstore-osd as acting PRIMARY of a declined PG: the control core sends `MOSDPGTemp` (acting with our position NONE, only if another member remains), re-sent on every map while we lead; the next member leads and sees us as the declined backfill target. Passive pools (kill switch off): silent, PGs unknown; operator: primary-affinity 0, CRUSH rule excluding the nvme class.
7. Data safety: never decline a pool this OSD holds or held PG data of (an empty answer from a prior-interval member lets classic activate from a stale shard = implicit `osd lost`). Held = PGs of the pool on any core at boot (`BootInfo.held_pools` plus the core's `list_pgs`) and every pool with a PG in memory before a map / forgotten since (`forget_pg`). Such pools stay silent; operator: `osd lost` or restore support. Test `a_pool_with_data_on_this_osd_is_never_declined`.
8. Backfill block: while a PG has a declined shard, every backfill reservation fails at our REJECT_TOOFULL, so backfill of CLASSIC targets in that PG is blocked too (reduced redundancy persists after a classic remap). Workaround: exclude croit-flashstore-osd from the pool's CRUSH rule, or `pg-upmap-items` the shard to a classic OSD; primary-affinity does not help.
9. Runtime switch: a runtime change of `ec_decline_unsupported`, `ec_enable_pools` or `ec_enable_optimized` queues mon `pg repeer <pgid>` (4 per 1 s tick, control core) for every PG mapped to us as non-primary in a pool whose mode flipped; start-up values do not trigger it. Without it a classic primary in GetInfo is not re-queried.
10. The EC sub-write reply is built with `last_complete = 0'0`; `Pending::EcWriteReply` stamps the shard's real `info.last_complete` at flush after commit (`peering/src/pg.rs`; assertion in ec_shard.rs), so classic `min_last_complete_ondisk` is correct.
11. Shard push verification (am. 4, Ceph tracker 74943): an EC push target (and our own rebuilt local chunk) checks pushed bytes against the pushed `hinfo_key` when it holds cumulative hashes (L0, and L1 before the first overwrite): contiguous bytes from shard offset 0, running crc32c (seed -1), at the last chunk `total_chunk_size` and `hashes[our shard]` must match. Mismatch = chunk refused (no apply, no ack, loud `WARNING EC push ... refused` note + error counter); the object stays missing and the primary's next peering pushes again from the then-current sources. Without hashes (L1 after overwrite, mode O) nothing is verifiable (spec ec.md 4.6, 7.1a). Our own local rebuild failing it goes through `ec_recov_fail` (retry from other sources).
12. Mixed-cluster alert `FLASHSTORE_EC_ISA_DECODE_CACHE` (am. 4, option `flashstore_warn_isa_decode_cache`, default on): map holds >= 2 distinct ISA `(k, m)` shapes, an up/acting set of such a pool holds this OSD, and a classic member reports metadata `ceph_version_short` < 21.1.2 (first known fixed release = pin). Version source: the existing `osd metadata <id>` flavor query (peer_ceph_ver, forgotten on restart). Unknown version = not reported. Also logged + clog WARN once per text change. Our own codec is not affected (decode plans keyed by full geometry).

Tests: `peering/tests/ec_decline.rs` (8 scenarios), `outbound.rs outbound_decline_allow_list`, osd `ec_defaults_legacy_and_optimized_on`. Analysis and live record: doc/perf/adr-0039-history.md.

## Rationale

Allow-list gate + one outbound choke point keep untouched pools risk-free. Decline = answering exactly what a classic primary expects from a backfill target is the way a classic primary makes progress without us storing or claiming anything. Defaults flipped to legacy-EC-on because passive broke the drop-in promise.

## Consequences

- + mixed acting sets with classic EC primaries work; one place decides participation; classic primaries progress (active+undersized+degraded+remapped+backfill_toofull when acting >= min_size); nothing stored or claimed in declined pools.
- - permanent degraded redundancy for declined pools; pg_num decrease (merge) waits forever; backfill reservation retry every 30 s per PG; PG_BACKFILL_FULL "low space" text is misleading (clog explains).
- - lrc/shec/clay users keep non-serving OSDs.

## Alternatives

- Deny-list gate: unknown profile => accidental participation.
- Serve EC primary first: biggest surface, needs math.
- Per-pool flag in the OSDMap: not ours to define.
- pg_temp excluding our shard for classic-led PGs: we stay in `up`, still probed.
- OSD-sent upmap moves: mon policy, balancer fights.
- New DaemonHealthMetric type: fixed classic set (adr 0021).
- Answer as acting primary: needs the primary machine.

## Open questions

- Runtime kill-switch flip for supported-but-disabled pools changes answers inside an interval (decline 1); no behavior beyond pg repeer. doc/90-open-questions.md 30.

## Amendment map

- am. 1 (2026-10-12): decline unsupported EC pools -> Decision (Decline mode, points 1-8; numbers kept)
- am. 2 (2026-10-13): legacy EC on by default -> Decision point 3
- am. 3 (2026-10-13): decline leftovers -> Decision (decline 5, 6, 9, 10)
- am. 4 (2026-10-23): tracker 74943 push verification + ISA mixed-version alert -> Decision 11, 12
