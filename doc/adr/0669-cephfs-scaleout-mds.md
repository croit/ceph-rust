<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0669 Scale-out transactional CephFS MDS: emulated frontend ranks over internal shard servers

Status: proposed
Date: 2026-11-05
Related: 0041 (CephFS scope, store limits), 0006/0031 (thread-per-core), 0175 (soft memory targets), 0003 (spec first), 0013 (scope), 0306 (client ABI scope)
Specs: doc/spec/mds/mds-client-protocol.md, mds-caps-locks.md, mds-cluster-surface.md, mds-namespace-semantics.md; mds-kernel-client.md pending (items marked [kernel spec])
Design detail: doc/design/cephfs-mds/ architecture, frontend, client, storage, transactions, ownership, features, backtraces, mirror, performance, verification, plan, decisions

## Context

- User requirements (2026-11-05, binding): MDS scales horizontally (more processes, load spreads; no rank-subtree hierarchy, no balancer); transactional metadata; 1e8-1e9 files per fs, 1e5-1e6+ entries per dir; performance first (classic reference: performance.md s1). Full CephFS feature set, verified: POSIX, xattrs incl. Samba (NTACL, DOSATTRIB, charmap dirs), per-dir data pools, snapshots, fcntl/flock, quotas, subvolumes, NFS-Ganesha (reclaim, delegations). Unchanged stock clients: libcephfs v21.2.0 (ceph-fuse, Samba, Ganesha) and kernel 5.14/6.8/6.12/7.2. Unchanged stock mon/mgr. New on-disk format, no classic MDS in the same fs. Metadata pool may require croit-flashstore-osd; data pools any OSD, replicated or EC. Prime safety.
- User decisions (2026-11-05, second round, decisions.md s5): FE model; users move to our client librustycephfs (s9), stock clients stay the compatibility path; backtraces written, high-performance; stock cephfs-mirror plus an own parallel mirror; case-only rename stock by default, case-preserving by option.
- Stock rank model (cluster-surface spec): <= 256 active ranks; +1 rank per 5 s tick and only while no rank is failed or in transition; only the highest rank is removable; failover needs a standby; graceful stop = failure + blocklist.
- Clients route by auth caps and DirStat.auth; every auth change is a cap EXPORT/IMPORT or a forward. Multi-MDS paths are the least-tested client code, worst in old kernels [kernel spec].
- Classic failure modes to avoid (doc/ceph-mds-past-problems.md): replay asserts, hours-long replay, OOM, unfair cap recall, huge dirs, balancer thrash, unbounded journals, stray backlog, dark data.

## Decision

### 1. Roles: emulated frontend ranks over internal shard servers

| Role | Mon-visible | Job |
|---|---|---|
| FE (frontend) | MDS rank: exactly one (rank 0) by default; a few more only when one FE's load requires it | thin thread-per-core session terminator: client sessions and their state; routes each request to the owning BE core, assembles replies, relays cap/lease/snap/quota messages. Clients see it as auth for everything: no forwards, cap EXPORT/IMPORT, split dirs or multi-rank reconnect |
| BE (shard server) | never a rank | authoritative owner of inodes, dentries, caps, leases, locks, per-core logs; any number of processes and cores, no mon tick or highest-rank rule |
| map master | role of FE rank 0 | shard -> core map, BE membership and failover, rebalancer; election and fencing come from the mon's rank 0 |
| librustycephfs (M7) | no | our client: session via its FE; metadata ops and caps directly at BE cores by the shard map (s9) |

- Two client paths: stock clients (kernel, stock libcephfs) = compatibility path through the FE (one active FE + stock standbys), gated never worse than the stock MDS; librustycephfs = primary performance path, where headline numbers are measured.
- One binary (`services/mds`), roles by config; combined FE+BE process for small clusters and M0-M2.
- cephx: FE = stock `mds.<name>` keyring, in the FSMap. BE = `mds.<fs>-be-<id>`, entity type MDS (rotating mds keys to verify librustycephfs tickets; OSD treats its ops as MDS ops; `profile mds` allows blocklist and MRemoveSnaps), never beacons, listed by FE tell `be ls`. No cls, so no osd `x`.

### 2. Shards, inode numbers, placement

- S = 65536 virtual shards fixed at mkfs. Shard = unit of ownership and moves; shard -> (BE, core) is our map.
- ino = bits 63..48 zero | 16-bit place = home shard (bits 47..32) | 32-bit seq. User inos >= 0x1000, < 2^48 (ceph-fuse snapshot tag in bits 63..48), never reused. ino -> shard needs no lookup (LOOKUPINO, NFS handles, cap routing). Inodes never move; whole shards move between cores.
- Contents of dir D live in BE frags; frag f sits at shard `fplace(D, f)` (format hash of dir ino and frag), so every dir's contents land on a pseudo-random shard. Small dir = one frag.
- A new inode (create, mkdir, mknod, symlink) takes its ino from the shard of its dentry's frag: one shard per create and per mkdir. A dir inode lives with its dentry; its contents live elsewhere (HopsFS/InfiniFS pattern).
- Frags split/merge by size or load (hot spots below); dentries move, inodes stay. Rename moves the dentry only. Clients always see one frag per dir.

### 3. Routing and hot ops

FE and librustycephfs route: inode ops and cap messages -> place(ino); name ops and leases -> fplace(D, leaf containing frag_value(hash(name))); readdir -> leaf containing offset_hash, then the next leaf. Stale fragtree or map -> REDIRECT/WRONG_OWNER (internal for stock clients).

| Op | Shards | Sync log appends |
|---|---|---|
| lookup, getattr, open | 1 (+1 if the inode is remote after a rename/split) | 0 (open: 1 if max_size grows) |
| create, mkdir, mknod, symlink, setattr, same-leaf rename, co-located unlink | 1 | 1 |
| link, remote unlink, rmdir, cross-shard rename | 2-4 (2PC) | 2 |
| readdir chunk of a 10M-entry dir (~600-1200 leaves) | 1 leaf (+ batched remote inode stats per BE core) | 0 |

### 4. Storage (metadata pool)

- Objects: `m.super` (format id, S, fs settings), `m.map` (shard map), `m.fe.<rank>` (FE session table), `m.snap` (snap table + snapid counter), `m.ls.<stream>[.<seg>]` (log streams), `m.sm.<shard>` (shard manifest), `m.t.<shard>.<tablet>` (tablets). Objects without the `m.` prefix (e.g. mgr `cephfs_mirror`) are foreign and ignored.
- Log: one stream per BE core; group commit; each append padded to 4 KiB at the next aligned offset of a 16 MiB segment object (no read-modify-write, adr 0041 am. 1); ack only when the contiguous prefix is durable; window W = 64 MiB per stream with smooth admission throttling from 75 %; trim = delete segments. Replay <= ~0.5 s.
- Checkpoint: continuous write-back of dirty records to per-shard omap tablets (<= 64 MiB / 64k keys), coalesced per key and batched per tablet. Keys: I (inode), X (big xattr), B (hardlink backref), D (dentry, ordered as stock readdir: frag_value(hash), name, snapid), F (per-frag stats), C/K (completed requests/flushes), P (purge items), O/H (rstat outbox, applied high-water), V (first change of a key per snapshot interval).
- OSD ops: stock only (aligned write, append, omap get/set/rm/rm_range, xattrs incl. cmpxattr, stat, delete; data pools also pgnls, list-snaps). New croit-flashstore-osd primitives (native log append, guarded tablet apply, readdir projection) only after a measured gap; triggers in storage.md s6.
- Bounds: log <= W per live stream; dead streams deleted after write-back; C/K per client in-flight window; purge backlog streamed with health warning; snapshot versions pruned after RMSNAP. Memory per BE core: dirty <= W (admission), clean cache evictable, caps/leases budget (stop optional grants, then fair recall), in-flight admission. Smooth braking, never OOM, never a failed op. RAM does not grow with fs size.

### 5. Transactions

- One log record in one core's stream is atomic, also across shards of that core. Cross-core ops use 2PC with presumed abort: coordinator = core of the anchor shard (dst dentry for rename/link, dentry for unlink, parent dentry for rmdir); parallel PREPAREs (try-lock), then COMMIT, reply after COMMIT is durable. On lock conflict the op reruns once with ordered (shard, key) locking, which cannot deadlock. Cross-parent dir renames take an fs-wide dir-rename lock (loop check).
- Isolation: per-key locks; early lock release for single-core ops + commit-wait (a reply exposing a key waits for that key's last LSN to be durable); prepared keys stay locked. Success reply = durable; safe replies only in v1.
- Dedup: C(client, tid) in the mutation's record, K(client, flush tid) at the inode's home; retries go to the shard that executed the tid; trimmed by the FE trim vector (~1 s); moved with shards.
- Recovery: successor replays the stream from its checkpoint (no asserts; stop at the first invalid record); in-doubt participants query the coordinator stream's owner; soft state from FE mirrors and librustycephfs clients.
- Fencing: failed BE blocklisted by the master via the mon, successors wait for that osdmap epoch (first touch fences the old writer per PG); BE serves only under a 4 s master lease; live moves ack all writes before export; cmpxattr guards on `m.map`, `m.sm.*`, `m.snap`; FEs fenced by the mon as stock.

Admission and execution: design/cephfs-mds/admission-executor.md.
FE/BE capacities are startup configuration with defaults derived in admission-executor.md s8; refused connections close gracefully (s1.4).

### 6. Ownership changes

- BE join: register with the master, receive shards (count, then load). Drain (upgrade, stop): live moves away, zero client-visible downtime. Live move: freeze shard, finish ops, write back, EXPORT caps/leases/locks/outbox, IMPORT logged, map epoch committed; pause ~5-50 ms per shard.
- BE failure: 5 s missed heartbeats (loud WARNING TIMEOUT) or restart of the same name -> blocklist, wait for epoch, each failed core's stream + shards to one successor core, replay, rebuild caps/leases/locks from FE mirrors (FEs resend un-acked flushes) and librustycephfs clients, resume. ~7-9 s stall for those shards only; no client reconnect, no error. Rebalancer spreads later.
- FE ranks change only through the mon (frontend.md s6, s8) and own no metadata.

### 7. Frontend state model and failover

- Durable: only the session table `m.fe.<rank>` (open sessions, reclaim uuid, metadata), written before OPEN. Needed because reconnect must tell open sessions from unknown ones.
- Volatile: connections, session state, push_seq, request index (tid -> executing shard), relay mirror (caps, leases, locks, un-acked flushes; ~64 B per entry, indexed by shard), push windows per (session, BE core), osd_epoch_barrier. No metadata cache, no log.
- FE failover (frontend.md s6): detect 0 s (restart, graceful stop) or 15 s (host loss) -> REPLAY (< 1 s) -> RECONNECT (stock clients report caps/locks) -> REJOIN -> CLIENTREPLAY -> ACTIVE. Client pause ~2-5 s restart, ~16-20 s host loss. librustycephfs ops continue (BEs keep its caps and session within session_timeout).
- FE capacity/ranks: frontend.md s7-s8. Clients have a home FE (`m.fe.dir`); planned shrink uses cap EXPORT/IMPORT.

### Load distribution and hot spots (performance.md s5)

- Uneven load: the rebalancer moves shards with hysteresis and per-core move limits (ownership.md s5); ~5-50 ms invisible pause per move, no thrash.
- Hot dir: frag split by size or load, 8-way; create stays 1 shard; dir rate ~ leaves x 50-80k creates/s.
- Hot file/prefix: caps, dentry leases (incl. null) and the ancestry cache absorb reads; an uncacheable storm stays <= 1 core (~200k getattr/s).
- rstat/quota: per core one sealed batch per target core per Delta.
- Limits: one frag, inode or name loop <= 1 core until split; cross-parent dir renames ~2-3k/s fs-wide; MKSNAP ~ caps under the subtree.

### 8. Features

- Snapshots: own snapid counter in `m.snap` (above every data pool's snap_seq), removal via MRemoveSnaps per data pool (stock path); table replicated to all BEs/FEs; realms flagged on dirs, membership via ancestry; MKSNAP on a huge subtree = O(1) durable + generation bump + O(caps under it) notifications in parallel; metadata COW as versioned keys, each version with its change seq; V(seq, key) per shard marks the first change of a key per snapshot interval (pruning order, mirror feed).
- Quotas/rstats: per-frag stats in the op's record; async exactly-once outbox to all ancestors every Delta; fresh-RSTAT getattr flushes direct children; quota pushes per root per Delta through FEs; snapshot rstats exact (MKSNAP flush); a cross-parent dir rename flushes pending deltas on its GEN_BUMP round and moves the dir's pre-rename rstat to the new ancestors (rstat barrier). Lag bound (user 2026-11-05): 1-15 s acceptable; Delta 1 s nominal, may stretch under load up to 15 s.
- Layouts/pools: nearest ancestor policy at create via a generation-tagged ancestry cache (also path checks, realms, subvolumes, charmap); policy changes broadcast a generation bump before replying.
- Caps/locks: one authority per inode (home core); no dir Fs/Fx and no async dirops in v1 (leases instead; M2 A/B); fcntl/flock volatile at the home, mirrored by FEs, EDEADLK within a core.
- Case-insensitivity: clients normalise, MDS byte-exact, alternate_name stored. Case-only rename by fs setting `charmap_rename` (`m.super`; tell `fs set|get`, `status`; generation bump): `stock` (default): same inode -> success without change, other inode onto a case/normalization variant -> EINVAL; `preserve`: the dentry takes the new spelling (1 shard, 1 append, leases revoked), other inode -> POSIX replace. Encrypted dirs always stock (features.md s9).
- Hardlinks: inode stays home; B backrefs; owner = smallest backref.
- Strays/purge: no stray dirs; unlinked inode stays home until released; P item in the same record; streaming per-core purge with snapc and old_pools; orphan reconciliation scan (no dark data).
- Backtraces (backtraces.md): a name-relevant change marks the inode in the op's record; per 1 s tick each core appends inode-centric records (all links with alternate_name, type, mode/uid/gid, layout, symlink, inline xattrs, dir policies, snap ops; ~60-100 B) to its stream in the default data pool (one append per ~1k-15k changes); daily per-shard images bound the space; a data pool stall logs a GAP (images heal it), log trim never waits. librustycephfs adds stock-format `parent`/`layout` to its first write of object 0 (zero extra ops). Rebuild tool: total (M1), per shard (M3).
- cephfs-mirror (mirror.md): M4 serves the stock daemon on either end (snapdiff by change seq, blockdiff via `list-snaps`, snapshot metadata, mirror xattrs). Own parallel mirror after M7: per-BE-core FEED of the changes between two snapshots from V (no tree walk, no log retention), workers sharded by target dir (renames by ino, object-level copy, stock peer markers), run by the stock `ceph fs snapshot mirror` commands. Later option: physical replica fs fed per shard.

### 9. librustycephfs and the fast path (client.md)

- Rust library with the libcephfs C ABI in crates/ next to rustyrados and rustyrbd (drop-in: apps, Samba, Ganesha, cephfs-mirror unchanged); mount path = FUSE daemon on it (FUSE over io_uring, passthrough where offered, probed). Own kernel module: deferred to last (below).
- Session with its home FE; requests, caps, leases and locks directly with BE cores by the FE-pushed shard map; data to OSDs. FE failover does not pause it; after a BE failover it re-establishes its caps with the successor.
- cephx: stock mds tickets; BEs verify authorizers, enforce MDSAuthCaps (parser shared with the FE) and serve only sessions their FE announced; eviction = FE blocklist + BE drop.
- Shard map + client<->BE protocol: public versioned contract from M3 (own spec, feature bits, >= one release back/forward, fuzzed decoders); FE<->BE stays private (rolling upgrade N-1).

### 10. Performance model, verification, plan

- Per-op latency, per-core rates, metadata pool load per create (the practical create ceiling) and data pool backtrace bytes: estimates and shortfalls in performance.md.
- Verification and client matrix: design/cephfs-mds/verification.md.
- Milestones and gates: design/cephfs-mds/plan.md.

## Rationale

- FE/BE split: stock clients only ever see single-MDS behaviour, the best-tested client path, on every kernel; BE scaling, moves, splits and failures never reach clients; the mon's rank rules stop limiting capacity; mon rank 0 gives the master election and fencing for free. Price: one extra hop (~25-30 us, +15-20 % on mutations, up to +60 % on cache-miss reads) and FE CPU (~25-50 % of BE CPU per op), and a single front until several FE ranks exist.
- Two client paths: librustycephfs drops the FE hop without kernel changes (FUSE); its libcephfs ABI brings Samba, Ganesha and cephfs-mirror along unchanged; stock clients keep working.
- Inodes never move + ino encodes the home shard: O(1) inode routing for FE, NFS handles and librustycephfs; caps never migrate on namespace ops.
- Dir inode with its dentry, contents hashed: single-shard create and mkdir, natural spread of every subtree without a balancer; the price (no dir Fs caps, 2-shard rmdir) is smaller than a 2PC mkdir, 2-shard dir lookups and readdir fan-out.
- Per-core streams, not per-shard logs: group commit stays effective with >= 64 shards per core; failover replays one stream per failed core.
- Data-segment log: aligned appends on the OSD data path, trim by delete; no dependency on omap speed for the hottest write while omap work is paused.
- Shard as the balancing unit: bounded, cheap, invisible moves with hysteresis; no subtree semantics, so none of the classic balancer's thrash.
- FE durable state = session table only: FE failover needs no replay; BE state + client reconnect rebuild the rest.
- Backtrace journal: ~0.001 RADOS op and ~0.3 us per create instead of one op, ~2-4 us and often an extra object (per-file xattrs); rebuilds exact dir renames, hardlinks, empty dirs and permissions, per shard if needed; no dark-data hazard; MDS availability independent of the data pool. Client hints ride on a write that happens anyway.
- Mirror feed from snapshot versions: snapshot-consistent cuts, retention tied to snapshots, logs stay bounded, enumeration shard-parallel and O(changes).
- `charmap_rename` fs-wide in `m.super`: one consistent switch, no per-dir state, default unchanged.

## Consequences

- \+ Stock clients and mon unchanged and never exposed to multi-MDS behaviour; BE count and placement unconstrained by the mon.
- \+ Failover bounded by small windows: BE ~7-9 s without reconnect, FE restart ~2-5 s for stock clients and none for librustycephfs; replay <= ~0.5 s per stream.
- \+ Hot dirs scale with leaves; creates never serialize on a dir inode; memory independent of fs size.
- \+ Stock RADOS ops only: stock MDS keyring, no OSD changes needed for v1.
- \+ DR: namespace rebuild after metadata pool loss (RPO ~1-2 s of name changes) or per lost shard; mirroring scales with BE cores and workers.
- \- FE hop latency and CPU for stock clients; FE rank 0 is their front until M6 (capacity ~1.4-2M ops/s, failover pause for all of them).
- \- No dir Fs caps, async dirops or early replies in v1: single-client sequential metadata and repeated `ls` from stock clients may trail stock until the M2 A/B.
- \- cephfs-data-scan cannot rebuild this format; stock-format backtraces exist only on files librustycephfs wrote; a rebuild loses snapshot contents and xattrs > 4 KiB.
- \- BEs face clients directly: the shard map and client<->BE protocol need versioning, a compatibility window and fuzzing; BEs enforce MDSAuthCaps.
- \- Cross-shard ops cost 2 appends; cross-parent dir renames serialized fs-wide (~2-3k/s, rstat barrier included).
- \- BE daemons are `mds.*` entities missing from the FSMap; operators need our tell/status for them.
- \- Large scope (80-item checklist, Samba, Ganesha, snapshots, mirror, client library + FUSE): multi-milestone effort.

## Alternatives

- Shards mapped directly onto mon ranks (lead sketch): one hop less, no front bottleneck. Rejected as primary: every move/split is a client-visible cap EXPORT/IMPORT or forward on 5.14..7.2 kernels; the mon rank rules (Context) bound growth and failover; `ls -l` on split dirs needs per-entry auth. librustycephfs recovers the direct path for our client. Numbers: performance.md s4.
- Inodes embedded in their dentries, moving on rename/split, with a locator: one shard for every lookup, but a locator write per move and cap migration on namespace ops. Rejected.
- Dir inode co-located with its contents (2-shard mkdir): enables dir Fs caps; costs 2PC mkdir, 2-shard dir lookups, readdir fan-out for subdirs. Rejected for v1; dir Fs comes back as an M2 A/B.
- Per-shard logs (lead sketch): tiny group commits with >= 64 shards per core. Rejected. Omap-keyed log: depends on omap speed. Rejected for now.
- Mon self-managed snaps for snapids: one pool per MPoolOp, unproven for multi-pool fs.
- Survivor takeover of a failed rank's shards, several ranks per process, own consensus for the master: unnecessary with FE/BE (BEs are not ranks; mon rank 0 elects the master).
- Durable FE cap state: unnecessary.
- New cls methods or multi-object PG transactions: only after a measured gap.
- MDS-written per-file `parent` xattrs (stock style): stock tools read them, but +1 data-pool op per create and rename (3 OSD writes rep 3, up to 6 EC 4+2), an object per data-less file, a purge race; no dirs, links or attributes. Not built (possible second sink, decisions.md s5 j).
- Mirror feed from log streams: needs log retention for lagging peers (unbounded logs) and has no cross-core cut. Rejected.
- Per-dir case policy copied at mkdir like the charmap: cannot be changed for existing subtrees. Rejected; a nearest-ancestor policy is the upgrade if one fs needs both modes.
- Own kernel module now: deferred to the very last milestone (user 2026-11-06; supersedes "rejected" of 2026-11-05). If built: a new filesystem type (working name cephfs2) speaking our native protocol, Rust, upstream into latest mainline only; old kernels use stock fs/ceph through the FE compatibility path, which stays fully functional. Shared no_std codecs dual-licensed GPL-2.0 OR MPL-2.0. Gate: measured gap of the FUSE daemon to a kernel client; prerequisite: Rust VFS/folio/netfs abstractions in mainline (absent 2026-11; out-of-tree first, croit OS kernel). Ask ceph-devel early.

## Open questions

- User and lead questions (a)-(o): all DECIDED (decisions.md s5).
- Spec questions: decided in decisions.md s1-s4; open [kernel spec] items: decisions.md s6.
- Specs: internal protocol and store format written (mds-fe-be-protocol.md, mds-store-format.md); to write: backtrace journal records (M1), public shard map + client<->BE protocol (M3), stock mgr mirroring instance protocol (before the own mirror).
- Create ceiling depends on croit-flashstore-osd omap write-back rate; omap work is paused (no omap changes requested by this ADR).
- Placement-barrier residuals (am. 1): OPEN-impl-questions IMPL-23.
- Ino seq space (2026-11-06, 48-bit client bound): 4.29e9 lifetime creates per home shard; a long-lived small dir with heavy create/unlink churn stays on one frag and can exhaust its shard (ENOSPC). Candidates before the scale review: reuse fully purged seqs (spec s2.2 forbids all reuse today; NFS handle staleness must be checked), or home overflow creates on a sibling shard.

## Amendment map

Current decisions of both amendments (rationale, alternatives and full wording: doc/perf/adr-0669-history.md).

- am. 1 (2026-11-05) placement barrier between classic and our MDS daemons: our daemons advertise, and our fs carries, exactly incompat {7, 63 `ceph-rust mds format v1`}, without base id 1 (cluster-surface s3.3-s3.6). Every stock-mon placement (`fs new`, grow, failed-rank fill, laggy replacement, affinity, standby-replay) uses one selector whose unconditional compat test requires the fs incompat to be a subset of the standby's: ours never enter a classic fs (all carry id 1), classic daemons never enter ours (none has 63), decided before the map changes. Our fs only via our tool: `fs new ... set down true`, add 63, remove the other ids, set refuse_standby_for_another_fs, verify, `fs set down false`. Daemons BOOT and stay standby only while the FSMap offers no other fs and no default_compat they fit (L2, else DNE + wait); placed into a fs with another compat or name: no metadata I/O, DNE, respawn (L3); missing or foreign `m.super`: no write, DAMAGED. No enforceable barrier against operator compat surgery or a future Ceph id 63: contained by L2/L3, docs, tool `check`, scoped OSD caps (lead decision IMPL-23).
- am. 2 (2026-11-05) admission and executor: admission-executor.md is authoritative. Per-session lanes and output reservations; one credited FIFO per direction/core pair; age-ordered BE entries; reserve before atomic append/install; release completions at their dependency's contiguous durable prefix. Replaces ingress batches and private snapshots.
