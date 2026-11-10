<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Igor Fedotov, croit GmbH -->
# 0593 Dedup pipeline: deep-scrub reformat, dedup info collection, listing, client

Status: accepted, amended (am. 1, am. 2)
Status note: implemented, default off (stages 1-4: services/osd, rustyrados API, search-dups).
Date: 2026-10-22

## Context

croit's Ceph fork (`wip-ifed-dedup`) piggybacks on deep scrub reads to recompress, defragment and record a content digest
per object, lists the records per OSD over a new message and finds duplicate groups client-side (specs:
doc/spec/dedup-reformat.md, dedup-collection.md, dedup-listing.md, dedup-client.md). croit-flashstore-osd pins upstream v21.2.0; the
fork's wire additions (messages 137/138, feature bit 51, pg_history_t v12 (21.1.x fork: v11) / pg_stat_t v32, pool opt
key 26, `*_lazy` compression modes) exist only in the fork. User decisions 2026-10-22: match the fork's formats gated off by default,
digest configurable (MD5 / SHA-256), full pipeline incl. rustyrados API and a Rust `search-dups` tool, pool option plus an
croit-flashstore-osd config fallback for upstream mons, object linking (fork DedupLinking.md) not implemented yet.

## Decision

Stages, each mergeable and default-off: (1) data version + reformat framework (recompress, defragment, lazy modes), (2)
dedup info collection + admin commands, (3) listing request + scrub start stamp, (4) rustyrados API + `search-dups`.

Settings:
- Engines per pool come from pool opt key 26 `deep_scrub_reformat` (fork grammar, dedup-reformat.md 2) when present, else
  from `flashstore_deep_scrub_reformat` = `<pool id>=<engine list>` entries separated by `|` (same engine grammar). Empty =
  off. Unknown engine names are logged and ignored.
- `*_lazy` compression modes are accepted in pool opt `compression_mode` and in `bluestore_compression_mode`.
- `flashstore_dedup_digest` = `md5` (default, fork-compatible) | `sha256`, OSD-wide.
- `flashstore_dedup_zero_objects` = `false` (default) | `true`, OSD-wide: whether objects whose bytes are all zero get a
  dedup record. Off by default (differs from the fork, which records them): every all-zero object of one size shares one
  digest, so linking them would concentrate one huge group on one master; holes / compression already store zeros
  cheaply. The check rides on the digest pass and stops at the first non-zero 64-byte block (counter `zero_skipped`).

Reformat (croit-flashstore-osd mapping of dedup-reformat.md):
- Hook = the deep-scrub data loop of the store adapter (storeadapt/src/scrub.rs): engines run per completed stride read on
  the owning core, synchronously after the read. No collection lock exists (one core owns the PG), so the fork's lock-mode
  rules do not apply; the read result is never affected.
- The adapter knows whether it builds the primary's own map (`primary`); replica and EC-shard maps never collect; the
  modifying engines run on every OSD and shard.
- A rewrite is a store-local op (`Op::Reformat`): same bytes at the same range, forced compression decision or fresh
  allocation, applied only if the object's data version still equals the one captured when the stride read started;
  never bumps the data version, never touches PG metadata, log or replicas. Length = bytes actually read (fork bug
  avoided).
- Span statistics come from the extent records of the range (compressed, shared, extents, merged physical intervals);
  "cached" = the object has a staged, not yet durable txn.
- recompress / defragment follow dedup-reformat.md 7; defragment accepts only an allocation with fewer physical
  intervals than now. A failed compression writes the item uncompressed (fork bug avoided).

Data version:
- The onode carries `data_version` (record format 4, flag `F_DVER`) only for collections with tracking on; tracking is on
  while the collection's pool has ANY reformat engine (a rewrite is guarded by the data version, so `recompress` /
  `defragment` need it as much as `collect_csum`). Each enable increments a per-collection tracking generation (collection
  record format 3); records and rewrites bind (onode id, generation, data_version).
- The store adapter keeps tracking in step with the pool lazily, at the next deep scrub of the PG: an object read while
  tracking was just switched on gets no engine (its state from before proves nothing).
- Bumped by touch, write, zero, truncate, clone / clone_range destination; not by attrs, omap, hints, rename, reformat.
- Sticky superblock bit `FEAT_DEDUP` (262144; 65536 and 131072 are taken on main), made durable before the first tracking txn; a store that never tracked stays
  mountable by older builds.

Reformat details:
- The data state is taken when the object's deep-read session starts, before its first byte is read (the scrub pins a
  physical snapshot for the whole object; a per-stride capture would miss a write between pin and stride).
- `Store::try_reformat` stages the rewrite now or not at all (never parked: a parked txn's staging error is fail-stop);
  busy shard / changed object / no better layout = not applied, counted, retried by the next deep scrub.
- recompress decides with `compress::estimate_blocks`, the staging rule (chunking, incompressibility sample,
  `kept_blocks`) applied to the bytes read; the rewrite compresses again at staging (one extra compression per accepted
  rewrite; the fork hands precompressed blobs over).
- Alloc hints are not stored with objects, so a reformat rewrite resolves the mode with hint flags 0: `passive` /
  `passive_lazy` never compress on reformat.
- Counters (fork names + `skipped`) live in the adapter (`ReformatCounters`); perf dump / asok exposure comes with stage 2.

Collection (stage 2):
- Engine `collect_csum`: only the PG primary's own map (`PgStoreOps::scrub_role`, set by the scrub before each map
  build), replicated PGs only (no EC shards), non-empty objects, data state available. The digest runs in the object's
  scrub session (reads in order from offset 0, one object at a time per PG) instead of the fork's per-collection builder
  with start / continue / abandon rules: interleaving and gaps cannot happen there; it is recorded only if the data state
  at the end equals the one taken before the first byte. Hashed inline on the core within the scrub slice budget.
- Records live in each store shard's KV under tag `D` (`store::obj::dedup`): key = `D` + the fork's key bytes (digest
  length implied by the key length), value = own versioned encoding (algorithm, onode id, generation, data version,
  ghobject). Written with `TOp::DedupKv` through `Store::try_local` (staged now or dropped, never parked, never waits: a page miss or a full queue/WAL drops it, am. 2); fsck validates
  them.
- `flashstore_dedup_digest` = `md5` (default) | `sha256`; listings prune records of the other digest length.
- Listing per core (`StoreAdapter::dedup_list_local`, the fork's take-before-prune rule), merged across cores by
  `peering::store::merge_dedup_parts`: the cursor is the lowest key every incomplete core examined up to (no record skipped),
  the fork's raw key bytes (hex in the admin command). A store read error fails the listing (never an endless partial).
- Admin commands `bluestore dedup stats|clear|list` (scattered tell commands, fork names, arguments, output sections and
  errors).

Wire (stage 3; stage 4 = client):
- `flashstore_dedup_list` (default false) gates everything below; off = upstream v21.2.0 wire and bytes only.
- MOSDDedupList (137) / MOSDDedupListReply (138), fork encodings (crates/messages/src/dedup.rs, golden vectors of
  dedup-listing.md 6.1); feature bit 51 (+57) added to MOSDBoot `osd_features` only when served.
- The receiving core validates in the fork's order (session -EACCES, fsid / arguments -EINVAL, pool -ENOENT, pool-wide caps
  -EPERM, read; write to prune) and answers errors; the control core scatters a valid request as `bluestore dedup list`; the
  merged answer becomes the reply (`now` = OSD wall clock at the request). Flag off: -EOPNOTSUPP.
- Each core's part is bounded by `flashstore_dedup_list_slice_ms` (default 5 ms, <= `osd_dedup_list_max_duration`) and
  never waits for a tree page (non-blocking scan; a miss ends the part early): no request stalls client I/O of a core. The
  fork serves listings on a dedicated thread for up to 1 s; croit-flashstore-osd answers with shorter partial results instead (the
  protocol allows them: `completed` false, the client continues).
- `last_deep_scrub_start_stamp`: wall time of the deep scrub session start (before reservations, `ScrubCfg::
  dedup_start_stamp` = `flashstore_dedup_list`), set at successful deep completion, merged as the fork does, copied to the
  PG stats; pg_history_t v12 (am. 1, adr 0628-pg-history-v12: was v11 before the 21.2.0 pin) / pg_stat_t v32 are
  encoded only while the stamp is set (compat unchanged: upstream decoders
  skip it). A new PG starts without it (the fork uses the creation stamp; clients treat a missing stamp as no cutoff).

Client (stage 4):
- No librados ABI: the fork's API is C++ only (`IoCtx::dedup_candidate_list*` with std containers); rustyrados offers the
  same semantics natively (dedup-client.md 1-3). rustyrados `DedupCursor` / `DedupListArgs` (no I/O: slice, round
  robin, per-call checks, apply); rados-rt `NativeSessions::submit_dedup_list` / `poll_dedup_lists` (`DedupListOwner`,
  forwarded by `ObjectClient`) sends MOSDDedupList with a fixed tid, resends on a new session, and fails a missing / down
  OSD (-ENOENT / -ENXIO) only after the map caught up with the monitors' latest (private pool check). A dedicated engine,
  not the OSD command engine: that one fails on session loss instead of resending.
- `tools/dedup-search` = the fork's `ceph-dedup-tool --op search-dups` (options, output lines, stderr summary, exit codes;
  k-way merger and `--since-last-scrub` cutoffs of dedup-client.md 6). Search "threads" are concurrent shard workers on
  one client event loop. Differences: `--format`, `--osd-op-timeout`, the oldest-scrub line in UTC.
- Interop: lab/dedup-interop.sh runs both tools against a fork mon/mgr + croit-flashstore-osd OSD; same groups and summaries.

## Rationale

The deep-scrub read path already reads every object stride by stride with its own throttling, so the engines cost CPU but
no extra reads. One core per PG removes the lock-mode problem; checking the data version at rewrite time replaces the
exclusive lock. Tracking the data version only where collection is on keeps the 4 KiB write path unchanged elsewhere (the
onode is written only when dirty; a per-write bump would add a KV put per write). The generation closes the gap a
toggled tracking would leave. Matching the fork's formats lets the fork's librados, tool and mon interoperate; gating keeps
v21.2.0 clusters byte-identical to today.

## Consequences

- + No extra media reads; reformat and collection are bounded by the scrub scheduler and slice budget.
- + Default configuration: no behaviour, wire or on-disk change.
- - Onode format 4 and the `D` records are on-disk changes: older croit-flashstore-osd builds cannot open a store that used them
    (feature bit, sticky).
- - Inline hashing costs core CPU during deep scrub of enabled pools (throughput: doc/perf/adr-measurements-moved-20261028.md) within the slice budget.
- - Fork-private values (pool opt 26, op flag 0x200 semantics, message ids 137/138, feature bit 51) may collide with a
    future upstream assignment.

## Alternatives

- Hashing on a helper thread pool: rejected for now (no compute offload facility exists; compression already runs inline);
  revisit with measurements.
- Bumping data_version on every write in every pool: rejected (extra onode write on the 4 KiB hot path).
- Own wire format: not taken in this round (the fork's formats were implemented first); fork compatibility is nice to
  have, not mandatory (user decision 2026-10-23: the feature is not upstream): later changes prefer keeping it but may
  extend or leave the fork formats when that pays off (e.g. per-store-shard listing, doc/backlog.md).

## Open questions

- Record growth policy beyond listing-time prune (fork open item).
- Whether linking (fork DedupLinking.md) will require data_version tracking independent of collection.
- C++ librados ABI of the fork's `dedup_candidate_list*` (only if fork librados users must run on rados-ffi).
