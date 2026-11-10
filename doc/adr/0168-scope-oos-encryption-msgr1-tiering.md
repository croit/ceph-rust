# 0168 Parity mandate scope: encryption at rest, msgr1, cache tiering stay OUT
Status: accepted
Date: 2026-10-12
Context: mandate 2026-10-12 = 100 % functional parity with classic except Lua; user scope decisions below. In = per-pool compression (adr 0059 am. 1).
Decision (all OUT, parity.md rows stay oos):
1. Encryption at rest (`ceph-volume --dmcrypt`, LUKS): OUT. SPDK bypasses dm-crypt; in-store crypto not planned. Operators needing it: NVMe SED/Opal drive-side or encrypt above (client/RGW SSE). msgr2 secure mode is unaffected (have).
2. msgr1 (v1 wire protocol): OUT, accepted risk: v1-only clients (kernel < 5.11 rbd/cephfs, pre-Nautilus librados) cannot reach croit-flashstore-osd; we advertise v2 only. Future clients are v2 (classic main still binds both, ms_bind_msgr1 default true). Migration doc lists it. Revisit only on a concrete customer.
3. Cache tiering / hit sets: OUT, deprecated upstream since Reef. Safety floor (days, backlog): a pool with active cache_mode/tier_of = unsupported pool type = passive, logged once (prime safety rule).
4. Lua cls_lua: OUT (unchanged).
Consequences: parity gap list shrinks to compression; hw offload evaluation limited to compression (doc/hw/offload.md).

## am. 1 (implemented)
Point 3 safety floor: `PoolParams.tiered` = any of `tier_of`, `tiers`, `read_tier`, `write_tier`, `cache_mode` set (base AND cache pool, attached or active). `PgSet::pool_entry` `serves` is the single support predicate (not tiered, and for EC gate + kill switch); `is_passive` = !serves for every pool type; the outbound choke point refuses PG messages of non-served replicated pools. One notice per pool. Tests: peering/tests/tiering_passive.rs, realmap.rs.
