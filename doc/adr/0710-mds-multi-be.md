<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0710 MDS M2 step plan: N BE cores in one process, per-core streams, in-process 2PC

Status: accepted (lead review 2026-11-09). M2.1 landed: per-core ancestry cache
(`be/namespace/ancestry.rs`, one 2-way set-associative table per BE core, no allocation on a lookup) with
the policy generation on the executor; local only (no broadcast before M2.x). A committed
directory CREATE changes nothing (a new ino cannot be cached), while a directory REMOVAL and an
EXISTING directory's ancestry change (owner link incl. any dir rename, layout, quota,
realm/subvolume flag, charmap, pin flags) bump the generation globally (rmdir is rare; the global
bump stops a pre-removal view from re-inserting an ino that client ranges may reuse).
Fills carry the generation of the view they read through, so a pre-bump snapshot never yields a
current entry. Lab counters `ancestry_hit`, `ancestry_miss`, `ancestry_gen_bumps`.
Date: 2026-11-09
Amends: 0669 (M2 row of design/cephfs-mds/plan.md)

## Context

M0 runs every shard on one BE executor (`be::namespace::Executor`, one `Core`, one log stream). The
single-core ceiling and its limits are measured in doc/perf/mds-cpu-per-op.md (wip/mds-scale). M2.0
(`--cores 2`, daemon/split.rs) moved the BE executor to its own thread over the existing FE/BE rings, no
format change. Revision 5 (and 6, adr 0708 B0a: `S` session keys) already encodes per-core ownership
(Owner{be, incarnation, core} in every m.map placement and stream entry), several streams in m.map,
record types 2..9 reserved without bodies, and the O/H outbox keys. Design inputs: transactions.md s1-s5 (2PC, presumed abort), architecture.md
(remote inode reads via the FE), rstat-propagation.md s7 (remote fold edges via O/H), features.md s1
(ancestry cache, policy generations), mds-fe-be-protocol.md s1/s4 (rings and attach per BE core).

## Decision

### 1. Increments (each its own merge, tests green, default behaviour unchanged)

| Step | Scope | Flag | Format |
|---|---|---|---|
| M2.0 | FE thread + BE thread over the M0 rings (done) | `--cores 2` | none |
| M2.1 | ancestry cache + policy generations on the single core (features.md s1); GEN_BUMP local | none | none |
| M2.2 | revision-7 spec (s3), codecs, N-source recovery and 2PC replay join; 2PC + recovery-join sim tests (s8); no writer yet | none | readers only |
| M2.3 | N BE cores as N executors on the ONE BE thread, green sub-commits: (a) ownership, routing, per-core streams, local ops; (b) remote reads; (c) generic 2PC; (d) outbox fold | `--be-cores N` (default 1, lab-only) | rev 6 on first N > 1 |
| M2.4 | one thread per BE core and several FE threads by session hash: per-core rados follower, FE<->BE and BE<->BE rings, wake protocol of split.rs per peer | FE threads + `--be-cores N` | none |
| M2.5 | frag split/merge by size and load, 10M-entry dir; A/Bs: parallel commit, async dirops, dir Fs | per A/B | rev 7 if split needs records |

- Order: M2.1 next (pays on one core), then M2.2, M2.3, M2.4, M2.5.
- The first flagged increment is M2.3. It carries every durability risk of M2 (N streams, 2PC, recovery
  join) without threads: all N executors run round-robin in one thread, messages go through the same
  per-pair rings M2.4 uses across threads (`Peer::Local` vs `Peer::Remote` pattern of M2.0). Crash and sim
  tests are deterministic.
- M2.1 and M2.2 move work off M2.3 that is mergeable alone: M2.1 pays on one core (no O(depth) ancestor
  walk per op, ops.rs `effective_layout`/`prior_path`/path auth); M2.2 is recovery code that also serves
  N = 1 and is proven by the unchanged crash matrix plus synthetic N-stream vectors.
- M2.2 lands the 2PC and recovery-join sim tests (s8, fault after every message and append) before any
  writer exists; M2.3 makes them pass against the real executors.
- `--be-cores N > 1` stays lab-only (`lab` feature) until the crash matrix with the new points (s8) is
  10/10 at N = 1, 2 and 4.

### 2. Shard -> core ownership

- Static within one incarnation. Initial rule: core(s) = (s * N) >> 16 (contiguous blocks; placement
  hashes already spread inodes and frags). The claim writes all 65536 placements with
  Owner{be 0, incarnation, core(s)} in the same guarded m.map update that reserves the streams (M0
  already rewrites all placements per claim).
- FE and every BE core hold the 65536-entry core table (u8 per shard, 64 KiB) loaded from the placements;
  routing is one table read. M3 moves edit the same table.
- N may change between restarts: recovery retires every source stream (s5) before the new assignment
  serves, so no shard state depends on the old N.

### 3. Per-core streams: store revision 7

- Revision 7 = revision 6 (adr 0708 B0a, `S` keys) plus: (a) one incarnation may own N live streams,
  stream i written only by core i and only with images/allocations of shards placed on core i; (b) record
  bodies for type 2 PREPARE, 3 COMMIT, 4 COMMITTED; types 5..9 stay reserved (END is not needed while all
  cores of a BE recover together; M3 decides with QUERY/resend).
- PREPARE: txid (coordinator stream u64, seq u64), Apply (images, allocations of this core's shards).
  COMMIT: seq u64 (stream = own), participants vec<stream u64>, Apply (coordinator images incl. C).
  COMMITTED: txid. Encodings env 1/1 in mds-store-format.md s5; group/segment format unchanged.
- m.map: claim reserves N stream ids (state 2, original core i) and rewrites placements; activate sets
  the N streams live and every source done, one guarded op each (as M0 with N = 1).
- Sources at recovery: every non-done stream with the smallest original incarnation among non-done
  streams (generalizes M0 "earliest replaying stream": interrupted claims only add newer, never-appended
  reservations). Each new head inherits the union bitmap of the sources restricted to its core's shards.
- Upgrade 5|6 -> 7 in place on first use: a claim with N > 1 rewrites m.super 5/5/5 or 6/6/6 -> 7/7/7
  (cmpext-guarded write_full + readback, as 3/4 -> 5 and 5 -> 6) before any revision-7 record or second
  live stream exists. Revision-5 and -6 content is valid revision 7; no data conversion. `--be-cores 1`
  never upgrades to 7 and keeps serving 5 or 6; a 7/7/7 store is served with any N. Revision-5/6 binaries
  refuse 7 (min reader).

### 4. Single-shard and single-core ops stay local

- An op whose claimed keys all sit on shards of one core runs exactly as in M0: one APPLY record in that
  core's stream, early lock release, no internal message. By placement (0669 s2) create, mknod, symlink,
  mkdir, setattr, open/caps, unlink of a file next to its home dentry, and stat of a co-located inode are
  single-shard.
- FE routes ROUTE by the anchor shard (dentry frag, or home(ino) for inode ops) and cap/lease traffic by
  home(ino). Session attach per (session, BE core) on first message; detach/close/evict fan out to all
  cores (mds-fe-be-protocol s1, s5). C receipts stay at the executing core, K at the inode home, N ranges
  per (shard, client), P items at the inode home: all core-local.

### 5. Cross-core reads

- Remote inode in lookup/getattr/readdir: the FE composes (architecture.md): the frag core answers the
  dentry part, the FE asks home(ino) for stat + caps. Cap grant and later revokes of that cap travel the
  same (home core -> FE) ring in order, so no cross-ring cap ordering exists.
- Ancestors (layout, realm, quota/subvolume roots, path auth): per-core ancestry cache from M2.1; a miss
  is one READ to the dir's home core, parked like a store load (`Wait::Loads` analogue).

### 6. Cross-core mutations: generic in-process 2PC (presumed abort)

- Op-agnostic: the coordinator (anchor core) plans as today; claims on foreign shards become LOCK_READ
  to their owners (participant gathers caps, claims shared/exclusive, returns current images); the plan
  runs unchanged on the merged view; after-images split by owner core. No per-op 2PC code paths for
  rename, link, remote unlink, rmdir.
- Participant with images logs PREPARE, keeps its claims, votes YES once durable. Read-only participants
  log nothing and release at the outcome. Coordinator logs COMMIT (own images + C) after all YES; reply
  after COMMIT is durable; then COMMIT to participants, which apply, release and log COMMITTED (lazy,
  next group) and ack once durable.
- Conflicts: try-lock; NO(conflict) aborts and reruns once with ordered acquisition by (core, shard,
  key) where participants wait (transactions.md s3). Cross-parent dir renames take the fs-wide
  dir-rename lock on core(0).
- Checkpoint rules: a participant passes its PREPARE only after the outcome is known and committed images
  are written back (abort: no effects); the coordinator passes a COMMIT only after every participant
  acked COMMITTED durable. Hence a retained PREPARE without COMMITTED always finds its COMMIT if one exists.
- rstat fold across cores is not 2PC: the fold step writes O(seq){shard, dir, delta} and clears its
  source in one record; the receiver applies the delta and H(source shard) = seq in one record and acks;
  O is deleted after all acks (store-format s4 Outbox, rstat-propagation.md s7). Exactly-once, no locks
  held across cores; the conservation identity gains the in-flight O term.
- Policy changes (dir rename, layout, quota, realm, subvolume) broadcast GEN_BUMP to all BE cores and the
  FE, wait for acks, then reply (features.md s1).

### 7. Replay

- All source streams replay (independently; shard sets are disjoint, checked per image against the
  source incarnation's rule: violation = damage, refusal). Join: committed = COMMIT txids in source
  streams + COMMITTED txids; a PREPARE applies at its own LSN position iff its txid is committed, else it
  is dropped (presumed abort). Prepared keys were locked until the outcome, so applying at the PREPARE
  position equals live order.
- O entries replay as images; unacked O is resent by the source core after recovery and deduplicated by H.
- Every source is checkpointed and set done before the new N streams activate: no in-doubt transaction
  and no QUERY survives a restart in M2 (all cores of the process fail together). QUERY/resend is M3.

### 8. Crash matrix and tests

- New lab crash points (process-wide `MDS_CRASH_AT`, any core): `prepare_before_vote`,
  `commit_before_reply`, `commit_before_participants`, `committed_before_ack`, `outbox_before_apply`,
  `claim_before_activate`. Existing 10 points run with `--be-cores 1, 2, 4`.
- New crash workload with cross-core rename (file, dir, over existing), link, remote unlink, rmdir and
  setlayout; checks: every acked reply durable, all-or-nothing across streams, nlink = dentries + B,
  rstat conservation (verify.rs), no claims left after recovery.
- Core-count change matrix: crash at N = 4, restart with 2 and 1; 1 -> 4; interrupted claim with N
  reservations.
- Sim (tests/sim.rs harness, landed in M2.2 before any writer): N executors in one thread, fault
  injection after every 2PC message and append, properties: atomicity, durability of acks, progress after
  ordered rerun, recovery join of N sources.
- Gates per increment: unit gate, clippy both feature sets, crash matrix 10/10 + new points, e2e safe and
  early, pjdfstest full run at `--be-cores 2`; M2.4 adds the scaling curve 1/2/4/8 and CPU/op per core.

### 9. Threads and clients (M2.4)

- Findings of M2.0: rados Client/Rados are !Send (Rc), so every core builds its follower client on its
  own thread; the monitor session stays on the leader (FE thread); `ProxyHub` assign fixes
  (asker, osd) -> owner at first use, one connection per OSD addrvec per process.
- OSD o -> BE core (o mod N): OSD socket I/O spreads over BE cores; FE threads keep the monitor
  session (leader FE) and the m.fe writes. Wake protocol: split.rs Side/marks per peer ring.
- Several FE threads, sessions assigned by session hash: the target is beating stock with stock clients
  (kernel client, ceph-fuse), so one FE thread must not cap the process. Each FE thread holds rings to
  every BE core; session attach per (session, BE core) is unchanged.
- Scaling cells run with >= N OSDs: lab/local/cephfs2-lab.sh gains several OSD daemons per instance
  (memory-backed is acceptable for perf cells).

### 10. Memory

- Each BE core gets `core::Limits` / N (soft targets, adr 0175) until a rebalancer exists (M3).
- A BE core sleeps on its own fd: every time-based condition of a core is an executor timer
  (`Executor::next_timer`). M2.0 found the write-back age trigger evaluated only in passes that the FE's
  monitor wakeups happened to run (perf doc fix 12); every new per-core deadline follows the same rule.

## Rationale

- Static ownership + full checkpoint of all sources at restart makes N streams a recovery join, not a
  distributed protocol: one process fails as a unit, so presumed abort with retained COMMIT is complete
  without QUERY, END or resend.
- One-thread N executors (M2.3) separate correctness from threading; the M2.0 split already proved the ring
  and wake mechanics across threads.
- Generic LOCK_READ 2PC reuses the existing planner, so every op keeps one implementation.
- Outbox for rstat: commutative deltas need exactly-once delivery, not atomic multi-core commit; O/H
  already exist in revision 5.
- Upgrade on first use keeps `--be-cores 1` stores downgradable while M2 is a lab flag.

## Consequences

- \+ Single-shard ops (the create/stat/unlink hot path) pay no 2PC; cross-core ops pay 2 appends + 2 ring
  round trips in-process.
- \+ Format change is additive; revision-5/6 stores stay valid and are upgraded only when N > 1 is used.
- \- `--mds-direct-clients` requires `--cores 1` until direct fronts run on BE cores (adr 0708 B1, M2.3);
  the daemon config refuses the combination.
- \- FE work per op (doc/perf/mds-cpu-per-op.md, scaling section) bounds each FE thread at about
  1 / (FE us per op); M2.4 scales it with FE threads by session hash.
- \- A coordinator COMMIT pins its stream's checkpoint until participants ack COMMITTED (one group
  commit), so log retention grows with cross-core op latency.
- \- The lab needs several OSD daemons per instance for scaling cells (one OSD = one BE core's
  connection under o mod N).
- \- Limits / N per core leaves memory idle on cold cores until M3 rebalances.

## Alternatives

- Cross-core op logged once in the coordinator stream with foreign images: one append, but write-back
  and checkpoint of a shard depend on two streams. Rejected.
- Per-op 2PC handlers (rename, link, rmdir each): more code, same records. Rejected for the generic path.
- Parallel commit (1 append on the critical path): A/B in M2.5 (transactions.md s3).
- rstat fold via 2PC: locks and 2 appends per fold step for a commutative delta. Rejected.
- Live shard moves in M2: belong to M3 (separate processes, rebalancer).

## Open questions

- None (lead review 2026-11-09).
