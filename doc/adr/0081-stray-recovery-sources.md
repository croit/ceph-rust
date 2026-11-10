# 0081 Recovery sources outside the acting set (strays, missing_loc)
Status: accepted
Date: 2026-10-13
Context: EC recovery read only from acting + backfill members (`ec_avail`). One `osd out` that remaps TWO shard positions of a small pool (lrc k2 m1 l3, shec k3 m2 c1, 6 OSDs) left the new members log-recoverable with the old holders as strays: croit-flashstore-led PGs sat in recovery_unfound, client reads failed; classic primaries stay clean (missing_loc includes strays). Replicated pulls already used strays by info (`holders`), without their missing sets.

Decision (spec/missing-loc.md):
- Probe like classic `discover_all_missing`: FULLLOG query to every up, unpurged `might_have_unfound` peer without known missing (at activation when recovery is needed; in Active on a new notify when degraded, on ActMap while unfound). The answer (Active) runs proc_replica_log; info + missing kept in `peer_info` / `peer_missing` like a member's. Redriven with the other peering queries (adr 0071).
- A stray holding something recovery needs (`last_update >= need`, below last_backfill, not missing) gets MOSDPGInfo2 with its own info (classic asserts on a higher last_update) and is activated: a classic EC stray serves sub-reads only when peered. Only activated strays (`Prim::stray_src`) are EC sources.
- EC reads (recovery, attrs/omap source, clay repair, client reads of a degraded object) take shards members do not serve from such strays: `EcRd::src` maps shard -> stray OSD, the sub-read goes to `spg(pgid, stray shard)`. Writes are blocked on degraded objects, so all sources hold exactly `need`.
- Stray = not a member AT ITS SHARD (EC): an OSD that is a member at another position still has its old instance purged when clean.
- Outbound validation: the acting primary may send MOSDPGInfo2 and MOSDECSubOpRead to a non-holder shard; everything else unchanged.
- lrc (found by the live move test): a layer below the full-cover layer (k2 m1 l3: the global layer) is never encoded (parity stays zero, classic byte-identical); decode, read planning and the recoverability predicate now ignore such layers (classic decodes garbage from them). Stricter than classic: {D0, global c} counts as not recoverable.
Consequences: no new on-disk or wire format. One FULLLOG per stray per interval while degraded (classic does the same). Classic model: Stray + MInfoRec payload assert checked in the Sim. Not done: classic's single-missing-shard shortcut, explicit location map (recomputed on demand).
Validation: peering/tests/stray_sources.rs (RS k2m1 + lrc k2m1l3 every 2-position pair with reads during the move: recovery_unfound without the fix; replicated), crates/ec/tests/lrc_top_layer.rs, lab/docker/mixed/16-ec-recovery.sh MOVE=1.
