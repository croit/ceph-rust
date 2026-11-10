<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0702 rustycephfs2: native Rust CephFS client library

Status: accepted (P0-P3a, P4 file data I/O step 1 and the F1 FUSE front end implemented; P4 bench CLI/lab A/B and P5+ open)
Date: 2026-11-08

## Context

The CephFS2 MDS (adr 0669) is measured today only through ceph-fuse and the kernel client.
Both serialize metadata ops per process and per session, so they hide what the MDS can do
and spend most of the latency budget on the client side. rustyrados (MPL-2.0) already
provides mon/cephx/msgr2/OSD access in Rust. The MDS client wire codecs live in
`services/mds/mds/src/proto` (LGPL, daemon crate) and cannot be linked by a client library.

## Decision

- `crates/rustycephfs2` (MPL-2.0) is croit's native CephFS client library; artefact name
  librustycephfs2. It is the librustycephfs of doc/design/cephfs-mds/client.md (user decisions
  2026-11-05): primary performance path, target = our MDS only (stock clusters are not a target).
- Two layers, built in this order:
  - FE path (P0-P4): the standard Ceph v21.2.0 MDS client protocol
    (doc/spec/mds/mds-client-protocol.md, mds-kernel-client.md, mds-caps-locks.md,
    mds-namespace-semantics.md). Sessions (open, renew, close, reclaim, eviction) always use it;
    it is the fallback whenever the fast path is not negotiated. Because it is stock protocol it
    also runs against the stock MDS; that is used as a test oracle, not as a product goal.
  - BE fast path (P5): metadata requests, caps, leases and locks go straight to the BE core of the
    target shard (client.md s2), routed by the shard map; WRONG_OWNER / REDIRECT refresh the map.
    Wire contract = the public shard map + client<->BE spec (plan.md M3, client.md s4), feature
    bit negotiated at connect. No FE hop and no FE CPU per op.
- Client-facing codecs (`proto::{args, caps, client, wire}`) move into
  `crates/cephfs-proto` (MPL-2.0). The MDS uses them through `pub use`; MDS-internal codecs
  (`proto::{internal, ring, owned}`) stay in the daemon (`owned` wraps `internal` types).
  One codec, two users; no duplicate.
- Mon, cephx, msgr2 and OSD data I/O come from rustyrados and its runtime; the client opens
  its MDS sessions on the same runtime (one mon session per client instance).
- Performance model:
  - Many requests in flight per session (tid table, no per-op round trip serialization);
    sends are coalesced into one msgr2 write per runtime pass.
  - Borrowed (zero-copy) reply decode; no allocation or lock per op on the steady-state path.
  - Caps and dentry leases are honoured: stat/lookup served from the local cache while caps allow.
  - Async dirops (MDS feature bit 13 DELEG_INO, spec mds-kernel-client.md s5): create and unlink
    complete locally once the dir caps and delegated inos allow; the MDS reply is awaited for
    durability only.
  - Unsafe/safe replies tracked per tid; replay of unsafe ops on reconnect (spec s3).
- API: async Rust API first (`Client::mount`, `lookup/getattr/mkdir/create/open/unlink/rmdir/
  rename/readdir/setattr`, file read/write via the inode layout on rustyrados). A
  libcephfs-compatible C ABI is out of scope until the Rust API is measured.
- Every phase ships with Rust tests on own vectors and a `rustycephfs2-bench` CLI
  (mdtest-like create/stat/unlink, `--clients`, `--items`, `--format plain|json`) runnable in
  the local lab (lab/local/cephfs2-lab.sh) against both MDS arms.

## Phases (each one mergeable, tests green)

1. P0: extract `crates/cephfs-proto`; MDS unchanged in behaviour (mds-unit-gate.sh green).
2. P1: crate skeleton, mount (FSMap/MDSMap from the mon, session open/renew/close), sync
   request/reply with forward/retry; lookup/getattr/mkdir/create/unlink/rmdir/readdir.
3. P2: caps + leases (cap acks, revoke, release, flush of dirty attrs), local cache.
4. P3: pipelining + async dirops with delegated inos; unsafe reply tracking + replay.
5. P4: file data I/O via rustyrados; bench CLI + lab script; A/B vs ceph-fuse on both MDS arms.
6. P5: BE fast path (client.md s2-s3) once the shard map + client<->BE spec exists (plan.md M3);
   gate: >= FE path in every cell, lookup/getattr latency and BE ops/core.
7. P6: libcephfs C ABI drop-in + FUSE daemon and the client-only features (client.md s5-s6, M7).

## Rationale

A client that pipelines and uses async dirops measures the MDS, not the client. The FE path is
needed anyway (sessions, fallback) and is testable today, before the shard map exists; running it
against the stock MDS checks our protocol code against a reference. The BE fast path then removes
the FE hop. Sharing the codec crate removes the only reason to duplicate wire code.

## Consequences

- + Benchmarks can saturate the MDS from one process; client cost per op is measurable.
- + Same codec on both ends: wire bugs show up in round-trip tests on one crate.
- - The MDS gains a dependency on a new crate; proto changes now touch two users.
- - Async dirops need careful failure semantics (spec s5.6: only genuine faults may fail).

## Alternatives

- Wrap libcephfs via FFI: C++ dependency, inherits its per-session serialization.
- BE fast path first, FE path never: the fast path needs the shard map (M3) and still needs FE
  sessions; nothing would be testable before M3.

## Open questions

- Resolved (2026-11-09): one decoder. The MDS decodes MDSMap/mds_info through `cephfs_proto::maps` (daemon policy on top: state/CompatSet validation, `services/mds/mds/src/mon/maps.rs`); only its placement-input FSMap reader (`PlacementFs`, length-framed foreign state) stays daemon-side.

P1a answer (read 2026-11-08):

- (a) FSMap/MDSMap from the mon needs no monc change. `monc::MonClient` takes arbitrary subscription
  names (`subscribe` / `get_version` / `subscription_got`, crates/monc/src/client.rs) and the
  standing `fsmap` + `mdsmap.<fscid>` pair of doc/spec/mds/mds-cluster-surface.md s2.8. MFSMap (45)
  and MMDSMap (21) have no decoder in crates/messages, so they arrive as `MonEvent::Message` with
  `AnyMessage::Unknown` and the whole payload in the front segment — the same path our MDS uses
  (services/mds/mds/src/mon/mod.rs: mirror `subscribe` + ty 45/21 arms). The decoders exist only in
  the daemon (services/mds/mds/src/mon/maps.rs); P1 moves FSMap/MDSMap decode into
  crates/cephfs-proto (MPL) beside the P0 client codecs.
- (b) A cephx msgr2 session to an MDS rank: monc, msgr2 and rados-rt are already peer-type generic.
  Msgr2: `Connection::client(.., peer_type: u8, peer_addrs, target)` plus the `AuthClientHandler`
  trait and a public `SessionTable` (crates/msgr2/src/conn.rs, src/auth.rs, src/session.rs) take
  ENTITY_MDS; the rank's addrvec comes from the MDSMap mds_info. Cephx: `monc::Config.want |=
  ENTITY_MDS` (public field; our MDS does the same in its `Identity::configure`,
  services/mds/mds/src/mon/mod.rs) makes the mon issue the MDS service ticket that carries the
  client's MDSAuthCaps, and
  `MonClient::with_cephx(|c| c.ticket(service))` hands it out (crates/cephx/src/monclient.rs);
  `cephx::Authorizer::new(gid, service_id, ticket, now)` is generic over the service id
  (crates/cephx/src/authorizer.rs). Transport: `rados_rt::KernelTcp` over the public `TcpOwner`
  trait dials any `EntityAddr` (crates/rados-rt/src/kernel_tcp.rs, src/tcp_owner.rs); Bootstrap's
  impl shows the ~12-method owner pattern.
- (b) gap: the only ready-made cephx handler fixes the service type. `OsdAuth::for_service` is
  private and `Bootstrap::service_auth` accepts only OSD/MGR (crates/rustyrados/src/osd_auth.rs,
  src/bootstrap.rs).

Decision: no monc, msgr2 or rados-rt extension; one small public extension in rustyrados — expose the
cephx MDS service authorizer (`OsdAuth::new_mds`) instead of duplicating that handler in the
client; the client requests the MDS ticket through its own `monc::Config.want`, so the rustyrados
bootstrap want set and `Bootstrap::service_auth` stay unchanged. Plus the P1 codec move above (cephfs-proto, not a rustyrados/monc change).

## P3a decisions (2026-11-08)

- Pipelining is the engine, not an extra API: `RequestTable::reserve` only
  allocates a tid and encodes into the slot's own front buffer, `write` sends
  every reserved request in tid order and the client flushes the transport once,
  so a whole pass is one msgr2 write. `Client::submit_*` / `flush` / `reap` is
  the public pipelined API; every blocking method is that path plus one wait.
- Unsafe/safe replies: the first reply (either kind) completes the caller, the
  slot lives until the safe reply, and `oldest_client_tid` is the oldest tid
  whose unsafe reply has not been answered safe yet (else the next tid). That is
  the only value the MDS may trim its completed table below (client spec s9.3),
  so a tid the client could still replay is never trimmed.
- Reconnect: `Client::reopen_session` keeps the held caps (the cache and leases
  die with the old session), replays unsafe-answered requests with `REPLAY`,
  repeats the unanswered ones in tid order, then sends `MClientReconnect` v5
  with the caps and their realms in the same write pass (client spec s3.2-s3.4).
  The client decodes no `MClientSnap` in P3a, so a cap in a realm other than the
  root realm (parent = global snaprealm 3) or the global realm itself is left out
  of the reconnect and re-requested on next use; a wrong realm parent would get
  the whole reconnect refused.
- Cap state is preallocated (`Config::cap_capacity` slots): a fixed slot array
  with an intrusive LRU list and a tombstone-hashed inode index, plus a
  preallocated release queue. `Config::max_caps` stays the trim bound and must
  not exceed the capacity; `0` disables the bound and the capacity alone bounds
  the table.
- The MDS still answers every request safe; the client's unsafe path is proven
  on own vectors with the fake transport, and the lab's early-reply arm needs an
  MDS-side opt-in that is not part of this phase.

## P3a against our MDS (2026-11-08)

The CephFS2 MDS has `--mds-early-reply true` (default false; design
`doc/design/cephfs-mds/admission-executor.md` I7a, fe-be spec s4): an eligible mutation
gets an UNSAFE reply at apply, before the journal entry is durable, and the SAFE reply
once it is. The `rcfs` lab suite runs the client against our MDS with and without it and
against the stock MDS; the early-reply arm must show the unsafe-then-safe sequence.

## P3b amplification (2026-11-08): the in-flight slot frees at the unsafe reply

Measured on the stock MDS arm (lab instance 4, `rcfs` suite, pipelined create/unlink,
32 requests in flight): 57-95 creates/s and 67-100 unlinks/s, while ceph-fuse reaches
~700 ops/s and the MDS' own `req_create_latency` is 0.54 ms. Client-side timestamps put
13.6 s of a 13.6 s create phase into `submit` (reap 0.04 s), i.e. into `wait_slot`.

Root cause, layer: request engine. P3a kept every tid in its slot until the safe reply
and the table has `Config::max_inflight` (256) slots. A stock MDS answers unsafe at once
but sends the safe reply only when the journal entry is durable, and it batches requests
per journal flush, so a client that stops at 256 unjournaled tids sends one request per
flush. Each flush then costs a full journal commit (13 ms here) instead of amortizing a
whole batch: throughput collapses to one op per commit, and the MDS never sees the queue
depth that would batch. ceph-fuse does not gate submission on safety.

Decision:
- A request leaves its in-flight slot as soon as its caller takes the reply; when the
  safe reply is still outstanding it moves to a replay window (`Config::unsafe_capacity`,
  default 2048 records, preallocated, one `Spec` each). The record is what keeps a
  reconnect replay (client spec s3.2) and `oldest_client_tid` (s9.3) correct, and the
  in-flight window stays a bounded, allocation-free per-op path.
- A full replay window keeps the completion in its slot until the safe reply, so the
  memory a client spends on unjournaled operations stays bounded; nothing spins or waits.
- `oldest_client_tid` is the oldest tid that is not known safe (live slot not safe yet,
  or a replay record), not the oldest tid with an unsafe reply. That is the spec's
  "oldest tid still outstanding" and closes a trim hazard: a tid whose request had no
  reply yet could previously be reported as trimmable while its completed-table entry
  existed, and a later replay would then re-execute it. The cursor only moves forward and
  every tid is probed once (amortized O(1)), so the per-request cost stays flat.
- Siblings: the cap path and the early-reply path are not affected (caps and leases are
  acknowledged in the same pass, independent of request slots); the reconnect path now
  also replays replay-window records in merged tid order before `MClientReconnect`.

Result on the same stock MDS: 31-36k pipelined creates/s and 17-30k unlinks/s (two runs,
1 repeat each); our MDS 6.8k creates/s (7.9k with early reply), the rcfs gate covers all three arms.

## P4 step 1 (file data I/O, 2026-11-09)

- `Client::open(ino, flags)` returns a `File` handle (`read`, `write`,
  `truncate`, `fsync`, `close`). Bytes go straight to the data pool of the
  inode layout; object name `<ino hex>.<objno %08x>`, layout namespace from
  `pool_ns`. The mapped layout is the unstriped osd-surface spec s2.1 rule
  (`objno = off / object_size`); a striped layout is refused instead of writing
  to wrong objects.
- Caps: reads require `Fr`, writes `Fw` below the cap's `max_size`; a write past
  the range asks the MDS for a larger one (caps spec s8.2). Size/mtime stay
  local under `Fw` and are claimed by the dirty cap flush (`dirty = Fw`, client
  flush tid, `SYNC` on fsync), which `fsync`/`close`/`unmount` send only after
  the object writes are durable; a REVOKE that drops `Fw` carries the claim in
  its ack (s5.4, s7). `close` also releases the inode's cap (s8.3, s9.1).
- Shrink = MDS `SETATTR` SIZE (s8.4), then the last kept object is trimmed and
  every object past it is removed; grow changes size only (holes read zeros).
- `DataStore` is the seam: production is a `rados-rt` follower client on the
  mount's monitor session (`real_data.rs`, adr 0467 am. 4: one monitor session
  per client instance); the object ops of one handle stay in flight together;
  unit tests use the fake in-process pool of `test_support`. Concurrency across
  handles needs a client-owned handle table (open). Striped layouts, snapshots and
  write-back caching (`Fb`) remain open.

## F1 (FUSE front end, 2026-11-09)

- `tools/cephfs2-fuse` (LGPL-3.0-only) is the FUSE front end of the BE path only
  (user decision 2026-11-09: no FE session/caps code in the tool). It calls
  `rustycephfs2::fsapi::FsBackend`, a backend-neutral trait of plain types (u64
  inode/handle, POSIX `Attr`, `DirEntry` with a cursor, `FsError` as errno,
  `StatFs`, xattrs); no `cephfs-proto`, session, cap or request type appears in
  its signatures.
- The production backend is `rustycephfs2::fsapi::client::ClientFs`: a
  `Client` mounted in direct mode (`Config::direct`, adr 0708; FE `MAP_GET`
  bootstrap, session/requests/caps on the BE core that owns the session home).
  Open files live in a client-owned handle table (`Client::open_handle`), so
  any number stay open with interleaved calls. The client is not `Send`
  (thread-per-core runtime): it lives in a thread local of the single FUSE
  event-loop thread, mounted at the first kernel request, which `mount` sends
  itself (a `stat` of the mountpoint) so a client that cannot mount fails the
  command. No FE fallback: an MDS without direct clients fails the mount.
- Not implemented by the client yet, answered `EOPNOTSUPP`: setattr other than
  size, mknod, rename, link, symlink, readlink, statfs, xattrs. Non-UTF-8 names
  are `EINVAL`.
- The data-pool RDMA upgrade keeps the librados knob: `Config::rdma` maps to
  `rados_rt::SessionLimits::rdma`, set from the `rustyrados_rdma` key (conf or
  `--rdma`), and needs the cargo feature `rdma` (`rados-rt/rdma`); a request
  without it is refused. Zero-copy registration is a follow-up
  (doc/perf/cephfs2-fuse.md).
