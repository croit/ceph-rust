# 0067 Optimized EC (allow_ec_optimizations) is in scope

Status: accepted, amended (am. 13)
Date: 2026-10-12
Consolidated 2026-10-19; full pre-consolidation text: git show 60868596d:doc/adr/0067-ec-optimized-planned.md
Amends: 0039 (gate point 2)

Incident/derivation detail: doc/perf/adr-0067-history.md (doc not in the source snapshot).

## Context

adr 0039 left optimized pools passive. Upstream tests and newer Ceph defaults use `allow_ec_optimizations`; a classic admin can flip it irreversibly on any EC pool, after which passive croit-flashstore-osd members make PGs degraded/down. Spec: spec/ec-optimized.md, ec-optimized-prim.md, ec-optimized-wgen.md; plan: plan-ec-optimized.md (stages S0-S6).

## Decision

Scope and gate
- Optimized EC (mode O) is in scope: shard role under a classic primary (S0-S1), leading with conventional RMW (S2), recovery/backfill/scrub (S3), omap/cls (S4), direct reads + parity-delta + extent cache (S5), live matrix (S6).
- Pool flag bit 19 is accepted iff: isa (van/cauchy) or jerasure reed_sol_van; chunk % 4096 == 0; pool `nonprimary_shards` == mapped raw 1..k-1. Stretch peering is accepted (shared stretch rules, doc/spec/stretch.md 3, 6, 8). FLAG_OMAP is accepted (shard applies EC_OMAP; primary serves omap/cls).
- Serving needs `ec_enable_pools` AND `ec_enable_optimized` (`all` default | `off` | pool list); one rule `peering::map::ec_not_served`. Otherwise passive/declined like a gate reject (adr 0039 decline mode).
- Leading an optimized PG needs `ec_enable_primary` AND `ec_enable_optimized_primary` (default `true`). Both are latched per primary interval (`Pg::ec_lead_cfg`). Switching off at runtime: a led Active PG requests a new interval like `ceph pg repeer` (pg_temp = only us at our shard position, NONE padded); `primary_start` then refuses the role and clears a pg_temp in force. Not sticky.
- Separate backend module for O; legacy paths unchanged; mode chosen per PG interval from pool flags.
- Nonprimary (NP) shards never lead. Map-elected NP primary requests pg_temp = acting (shard order, NONE padded) if acting holds a primary-capable member, else the up set (`ec_np_primary_escape`); none -> nothing asked. The mon stores it primary-capable-first, so the next map has a capable primary. PG frozen and silent meanwhile.
- Legacy-layout objects after a flip: no conversion (identical geometry); hinfo never written/checked in mode O; scrub accepts a shard with `hinfo_key` at legacy size `ceil(n/S)*C`. Shard rollback uses the current pool mode's shard size.

Shard
- Sub-write order as classic: transaction first, then log + roll-forward (EC_OMAP may target the stash the same txn creates).
- Deep-scrub digest of a shard = crc32c(-1) of the whole shard file; hinfo never read; omap digest -1.
- Every EC_DIRECT_READ on a non-primary is answered `-EAGAIN` unless direct reads are on (below).
- A sub-read is never answered before an earlier sub-write of the same PG is queued: replay yields after a persist (`held::Held` head `Due`, adr 0636), and messages released together (map arrival `waiting_map`, PG creation `waiting_pg`, old-map replay `after`) are routed in order by `PgSet::route_released`; once one queued a persist, later `held_behind` messages of that PG go to `Pg::hold_released` and replay at commit / next retry.
- pwlc: a replica never ends above the authoritative head. `ec_update_peer_pwlc` (MOSDPGInfo in Stray, MOSDPGLog merge): merge primary pwlc, roll every entry back to the primary's last_update (`ecopt::rollback_pwlc`, the `consider_rollback_pwlc` rule), then apply our own entry (the second activation check runs after `update_peer_info`); a legit raise (to == primary lu) stays. The activation refusal `replica behind (needs log)` stays as fail-safe.

Primary
- `post_activate`: roll own pwlc back to own head before any activation message; build and send all peer activation messages; only then roll the primary's log forward to head (`roll_forward`, as classic `activate`); the sent pwlc is the one `pi.last_update` derives from. Without the keep rule a primary-only entry stays authoritative and the object goes `recovery_unfound`.
- Peering with NP logs: merge pwlc from primary-capable peer infos and raise NP peer infos by it (never past our head). GET-LOG pass picks the oldest `last_update` of all shards (`ec_get_log_shard`); falls back to our own log only if the pick's `last_update` < our tail (no overlap). A got log reaching before our tail is cut at our tail (`got_log`; sparse log never extends ours backwards). Keep rule = `ecopt::keep_partial_writes` (consider_adjusting_pwlc, present-shard test, partial_write per kept entry); merge head = last kept entry; stats copied from a peer exactly at the new head, else `stats_invalid`. Our log behind auth with an NP pick: one repeat GetLog via auth per interval.
- Extent cache (`peering/src/ecprim.rs` `XCache`, always on, independent of `ec_pdw`): every generated write puts the post-write 4 KiB shard pages of the stripes it covers partly (`OGenerated::pages`); a write covering a stripe whole drops the object's pages instead of copying them. Invalidated only as wgen 1.4 `invalidates_cache` (clone/rename, delete_first, truncate); a create or a size growth keeps the pages. The front write whose RMW reads are all cached is generated at once (no wait for the commit of the write before it, no shard read). Cleared at every interval start.
- Deep scrub as mode O primary: CRC-linearity (XOR identity of unseeded zero-extended shard digests over raw 0..k); isa reed_sol_van / cauchy m=1 only; object-level error, no repair; skipped unless all data digests and raw k present.

Omap (no in-memory journal)
- Omap ops/cls on an optimized pool need FLAG_OMAP (`EcPoolInfo.omap`, `Backend.omap`); without it omap ops are `EOPNOTSUPP`.
- Emit one `EC_OMAP` mod_desc record per run of omap ops of an object and entry, after ROLLBACK_EXTENTS and before SETATTRS, never in a shard txn. A clear starts a new record; a header set after a clear is its own record; no record carries clear + header (shards apply header before clear). Ops before a `Remove` in the same txn are dropped. Truncate-to-0 keeps an omap object on the normal path.
- Shard generation, stateless across restarts: EC_OMAP of entry E applies, at E's roll-forward/trim on primary-capable shards, to the stash generation of the first LATER logged entry of the object with op DELETE / LOST_DELETE / REPLACE / CLONE-of-head (or mod_desc DELETE), else to the live object; missing generation = no-op. Order per object: header, clear, updates.
- Read overlay (`peering::ecomap::Overlay`): stored omap of our primary-capable shard (records up to `rollback_info_trimmed_to`) under the net effect (final value per key, deleted keys/ranges, clear, header; idempotent) of the object's later log records after the last move-away entry (`ecomap::moved_to`).
- Op-layer gate (`Engine::cold`): omap reads (`OMAP_GET_*`, `OMAP_CMP`, `COPY_GET`) and cls calls wait via `Env::ec_wait` until the object has no queued/uncommitted write; a cls call warms `EC_CLS_WARM` (4 MiB) of object data for `cls_cxx_read`. Omap writes pipeline. `Pg::ec_omap_overlay` answers `EAGAIN` if the gate was bypassed.
- Clone of head: store clone copies the stored omap; clone entry's mod_desc also carries the source's unrolled records (`OWritePlan::generate_omap`). Rollback of the clone entry (`Create`) removes the object. Delete/whiteout: stash rename moves the omap; recreate starts empty.
- Recovery/backfill: omap streams with the push rounds like classic (spec ec-optimized.md 10.1): per round the chunk budget left after the data, at least one entry, header in the first push, entries to primary-capable targets only, NP targets the same rounds without omap; recovered when data and omap are both complete. Source = our shard's store, or a PC shard paged by sub-reads (one page buffered); each batch = source entries under the object's pending EC_OMAP records (`ecomap::Overlay`), cut at the last fetched source key. No per-object omap size limit.
- Limits: open-ended rm range stays literal half-open (empty end removes nothing), same as the store. Omap keys are raw bytes in sub-reads and pushes.

Direct reads
- `ec_optimized_direct` (default `false`): off = every EC_DIRECT_READ (primary or shard) answered `-EAGAIN`. On: `Pg::ec_direct_read` (peering/ecdirect.rs) serves from our own shard file; any doubt = `-EAGAIN` (client redrives through the primary).
- Served: READ (length > 0), SPARSE_READ, GET_INTERNAL_VERSIONS, at head only. READ reply = our shard's contiguous bytes of the logical range after the op layer's size/truncate rule (`extent.length` not rewritten). SPARSE_READ reply = `map<u64,u64>` of LOGICAL extents (one per chunk piece) + bytes; bytes past the shard file end are a hole; dense (no fiemap).
- Checks in order: pool mode O served here and raw chunk is a DATA chunk; role fresh (primary: `is_readable` and no write queued/uncommitted on the object; shard: ReplicaActive and `now < grant - upper clock delta` of the primary incarnation, adr 0683); object not missing, not beyond `last_backfill`, newest log entry <= `pg_committed_to`; `_` readable, not whiteout, head only; shard blocks resident (else warm + EAGAIN); shard bytes cover the whole requested range.
- Torn multi-shard reads are the client's job via GET_INTERNAL_VERSIONS: the primary answers every shard (`oi.version` overridden by `shard_versions`), a shard answers itself.
- GET_INTERNAL_VERSIONS is not public librados (wire op of the umbrella Objecter split reads): served only on this direct-read path; direct off or doubt = `-EAGAIN` (redrive), and the primary op executor answers it `-EOPNOTSUPP` (`opexec/src/exec.rs` default arm). Decision (was OQ 28 O6): keep, no further implementation.
- Op epoch before `same_primary_since`/split (shard: `same_interval_since`): dropped like classic; cephx caps as a normal read (EPERM); passive PG: silent drop. Cold data answers EAGAIN, counted in `eagain_replies`.

Deferred
- Parity-delta writes (PDW, `ec_pdw`, default off): conventional RMW is byte-identical (linearity), no interop impact.

## Rationale

Passive members wedge PGs once a classic admin enables optimizations (irreversible); all-croit-flashstore-osd EC clusters need leading. Log-derived omap state survives restarts without a journal (KISS). Direct reads are optional and always fall back to the primary, so a doubt costs one hop, never wrong data.

## Consequences

- + No wedged PGs when optimization is enabled under us; RBD/CephFS metadata on EC pools possible.
- - Largest correctness surface (pwlc, written_shards, partial writes); ~14.6k LOC; a live classic oracle is needed in every stage.
- - Toward CLASSIC primary-capable shards, a restart between an EC_OMAP entry and the later delete of the object (before roll-forward) is upstream behaviour (UI-4) we do not amplify.
- - Classic shards under our primary: upstream-todos B10 (pwlc coverage of divergent entries).

## Alternatives

- Stay passive, document "do not enable": rejected, admin/default can flip it irreversibly.
- Shard role only: rejected, all-croit-flashstore-osd EC clusters need leading.
- Port upstream omap journal: rejected, in-memory state lost on restart, KISS.

## Open questions

- `ec_pdw` (off|auto|always, default off) is a live switch for parity-delta writes of the mode O primary (S5, `peering/src/ecprim.rs`, test `ec_opt_primary_pdw_and_extent_cache`); the default-flip decision is open (doc/90-open-questions.md 66).
- Live check of the O9 escape (pg_temp reorder by the real mon) was "pending" at am. 1; lab runs hit it (am. 7) but no confirmation recorded.

## Amendment map

- am. 1 (2026-10-12): shard role S0-S1d gate, O2/O9/O1/O3 -> Decision (Scope and gate, Shard, Omap)
- am. 2 (2026-10-12): primary omap S4 -> Decision (Omap)
- am. 3 (2026-10-13): direct reads `ec_optimized_direct` -> Decision (Direct reads)
- am. 4 (2026-10-13): CRC scrub, NP logs, legacy objects, switch-off, direct SPARSE_READ, replay-after-persist -> Decision (Primary, Scope and gate, Direct reads, Shard)
- am. 5 (2026-10-15): pwlc never raises replica over primary head -> Decision (Shard, Primary); incident -> history
- am. 6 (2026-10-15): primary roll-forward after peer messages -> Decision (Primary)
- am. 7 (2026-10-15): NP escape falls back to up set -> Decision (Scope and gate)
- am. 8 (2026-10-16): get-log shard tail before ours -> Decision (Primary)
- am. 9 (2026-10-16): sub-read released with sub-write before it -> Decision (Shard)
- am. 10 (2026-10-20): default on: `ec_enable_optimized=all`, `ec_enable_optimized_primary=true` (owner decision, adr 0013 scope line, go-live C9). `ec_optimized_direct` and `ec_pdw` stay off until their own A/B. Rationale: case-20 kill-loop gate (`lab/docker/mixed/ecbad/default-gate.sh`, no ec_* override, both pools all-croit-flashstore-osd and mixed) green on 21.1.2 (68 bounces, 5 rounds, 2026-10-20); the 20.2.4 RED (client write EIO, 2 of 2 runs) was main's 21.1.2 build on a 20.2.4 cluster (invalid mix, now refused by the gate) exposing an EC sub-read timer, removed (adr 0049 am. 9, OQ 28 O14); with the fix 21.1.2 green again (build 05b6299a, 65 bounces, 4 rounds); 20.2.4 gate due with the v20.2.4 cherry-pick. OQ 28 O4/O5/O7 are spec unknowns without a failing case; O10 resolved by this amendment. Opt-out: `ec_enable_optimized=off` leaves optimized pools silent passive (kill switch of a supported pool, adr 0039 point 3; never declined, classic primaries wait for the shard; lab evidence 2026-10-30); `ec_enable_optimized_primary=false` keeps the shard role only. Branch v20.2.4 keeps its own default until the same change is cherry-picked there.
- am. 11 (2026-10-31): stretch pools accepted (gate O8 off; writeable + past-interval stretch rules shared with replicated) -> Decision (Scope and gate)
- am. 12 (2026-11-03): extent cache always on, kept across creates and size growth, pages of partly covered stripes only -> Decision (Primary, Deferred). Rationale: pipelined appends to one object (QD16 per object) waited for the commit of the write before them plus a shard read per partial-stripe write (e9455 ec22 4K append 0.77x BlueStore IOPS); the reference keeps its extent cache for in-flight writes (spec ec-optimized-wgen.md 1.1, 1.4). Measurements: doc/perf/e9455-tails-20261103.md.
- am. 13 (2026-11-08): omap recovery streams per push round, the 32 MiB per-object cap is gone -> Decision (Omap). Rationale: legitimate objects above the cap could never recover (review NT-mixedcompat-01, doc/reviews/2026-11-08-nt-mixedcompat.md); classic streams.
