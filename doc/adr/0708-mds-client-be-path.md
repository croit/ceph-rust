<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0708 Our CephFS client talks only to BE cores: stock message bodies, private routing, home-core sessions

Status: accepted
Date: 2026-11-09
Amends: 0669 (client.md s2: sessions no longer at the FE), 0702 (P5 replaces the FE path for our client)
Spec: doc/spec/mds/mds-client-be-protocol.md

## Context

- User decision 2026-11-09: rustycephfs2 and `cephfs2-fuse` (fuser crate) talk only to the BE, never through
  the FE. client.md s2 had sessions at the FE and only metadata ops at BE cores.
- User 2026-11-09: client path RDMA-capable via the adr 0469 infrastructure; CephFS2 uses RDMA wherever it
  pays; KISS but DRY (reuse cephfs-proto, msgr2/cephx/rados-rt, the FE's codecs, the BE executor entry).
- The BE already consumes stock client message bodies at its boundary (ROUTE carries MClientRequest, CAP_IN
  stock MClientCaps/releases, CAP_PUSH emits stock MClientCaps); rustycephfs2 already runs the stock client
  engine (requests, unsafe/safe, caps, leases, reconnect) on cephfs-proto codecs.
- Stock mons know only the FE ranks (MDSMap); BEs never beacon. Client cephx caps have no metadata pool access.

## Decision

### 1. Protocol

- Bodies are the stock client messages (22 session, 23 reconnect, 24 request, 26 reply, 0x310-0x314 caps,
  lease, snap, release, quota) through cephfs-proto. Private kinds only for handshake, map, WRONG_OWNER,
  REDIRECT, MOVED, in one private msgr type with an own magic (spec s2.3).
- Transport: one msgr2 connection per (client, BE core), each core with its own knet listener; no
  per-process multiplexing. cephx with the client's normal keyring; BE verifies mds tickets (MDS-type entity).
- Discovery: ClientMap (from m.map: BE core addresses + shard runs) from any attached BE core; bootstrap
  once at mount from the active FE's MDSMap address with a sessionless MAP_GET. Nothing else at the FE.
- Sessions: session home core H = owner of shard hs(global id); durable record = tablet key `S` in hs
  (store revision 6, store-format s4.3; m.super upgraded in place from 3/4/5 before recovery when an MDS
  opens the store with `--mds-direct-clients`, else the store stays on 5); other cores attach after VERIFY at H; renew only at
  H; close per core with the per-connection push count; eviction at H = blocklist, wait epoch, fan out
  SESSION_DETACH reason 2 (existing semantics).
- Requests go to the anchor core; the BE recomputes the anchor and answers WRONG_OWNER/REDIRECT before
  execution; cross-shard ops run the BE's internal 2PC. Retries/REPLAY dedup through the receipt index.
- Caps/leases/locks of an object live in its owning core's table for FE and direct sessions alike; only the
  egress differs (FE ring vs own connection). Remote-inode stats in replies are capless; caps only from the
  inode's home core connection.
- Data: client -> OSD via rustyrados, unchanged.

### 2. Reuse (DRY)

Normative table: spec s9. Extended or split, never duplicated:
- `crates/cephfs-proto`: + `be` module (private kinds, ClientMap); + the stock reply assembly encoder moved
  from `services/mds/mds/src/fe/reply.rs`.
- `services/mds/mds/src/fe/auth.rs` -> shared MDS auth module for FE and BE listeners.
- `fe/sessions.rs`: lifecycle state machine split from its m.fe storage; H runs it on S-key storage.
- BE: SessionRef gains an origin (FE rank/incarnation | direct); direct ingress builds the existing
  `proto::owned` ROUTE and calls the same executor entry; `be/caps.rs` pushes through an egress trait;
  B0a realization: origin = message header rank (`internal::DIRECT_RANK` for direct sessions), the
  egress = the executor's ring port of that origin (`be/namespace/ports.rs`: FE pair or the core's direct
  pair, static dispatch); the direct pair's consumer is the shared front code on the BE thread;
  `be/receipts.rs`, `be/auth.rs`, CAP_IN mode 4, RECONNECT_END, SESSION_STATE/DETACH handlers unchanged.
- `crates/rustycephfs2`: the existing engine runs per BE-core connection; routing by ClientMap and fragtrees
  is the only new client logic. Its stock FE-path code stays the same code (oracle against the stock MDS).

### 3. Increments

| Step | Scope | Needs | Flag |
|---|---|---|---|
| B0a | one BE core (M0/M2.0 `--cores 2`): BE listener on the BE thread, HELLO/MAP, FE MAP_GET bootstrap, H = the core, S key + store upgrade, open/renew/close/evict (fenced), requests/replies safe-only, caps, leases, releases, file locks; BE restart = all direct sessions fenced-evicted at startup (safe, stock-equal to a missed reconnect); `cephfs2-fuse` mounts | M0 | `--mds-direct-clients` (default off) |
| B0b | reconnect after BE restart (spec s7), REPLAY dedup, EARLY_REPLY, ASYNC_DIROPS | B0a | same |
| B1 | N cores on one thread (M2.3): per-core listeners, VERIFY at H over in-process rings, WRONG_OWNER, fragtrees in replies, remote-inode capless stats | M2.3 | `--be-cores N` |
| B2 | per-core threads (M2.4): each core owns its listener and connections | M2.4 | none new |
| B3 | separate BE processes (M3): BE<->BE wire for VERIFY/DETACH, MOVED + cap migration, per-process reconnect, public spec freeze (N-1/N+1) | M3 | none new |
| R1-R3 | RDMA, s4 order | per row | opt-in |

- B0a is the smallest step that mounts before M2.3: one core means H, anchor and owner are always the same
  core; no VERIFY traffic, no WRONG_OWNER. Gates: pjdfstest via cephfs2-fuse with the ceph-fuse deviation
  list; mixed ceph-fuse + cephfs2-fuse cap conflict tests; crash matrix with direct sessions; rcfs lab suite
  arm "direct" >= FE arm in every cell.
- N cores extend it without protocol change: B1 only turns on routing paths that B0 already encodes.

### 4. RDMA across CephFS2

All RDMA = adr 0469 in-place upgrade of a msgr2 session (F_RDMA, RDMA_UPGRADE after AUTH), opt-in, TCP on
decline, same-host peers TCP. No new RDMA protocol.

| Connection | RDMA | Why | Exists | Missing |
|---|---|---|---|---|
| BE -> OSD (log appends, tablet write-back, purges) | yes, R1 | every mutation waits for the log append; small writes at high rate: latency and CPU/op | rados-rt client upgrade (`sessions.rs` `Config.rdma`, carried by the readiness driver `KernelTcp`), as rustyrados uses it; MDS already uses `rados_rt::NativeSessions` + `KernelTcp` | MDS cargo feature `rdma` -> `rados-rt/rdma`; config key (name: open) setting `Config.rdma` and the payload pool size; per-follower carrier check for M2.4 (one `KernelTcp` per BE thread); MDS status/counters in tell (`RdmaCounters`) |
| client <-> BE | yes, R2 | per-op request/reply latency (lookup, getattr, create), BE CPU per message | server side: rt knet `KRdma` + the `stream::Driver` rdma hooks, msgr2 `Connection` offer/answer; client side: rados-rt upgrade in `KernelTcp` | MDS `kernel_transport.rs` `State` implements no `Driver::rdma_*` hook and the MDS does not build `rt/rdma`; the server glue lives in `services/osd/osd/src/osd.rs` (Osd rdma_prepared/accepted/connected): move it to a shared module (rt) used by OSD and MDS. Client: rados-rt offers only on OSD-type sessions; add a `TcpOwner`-level opt-in for MDS-type peers (rustycephfs2 real.rs). Frame maximum covers reconnect chunks (spec s8.4) |
| client -> OSD data (cephfs2-fuse) | yes, R3 | bandwidth and CPU per byte, same as rustyrados today | rustyrados `rustyrados_rdma`, unchanged | config passthrough in cephfs2-fuse; FUSE zero copy later (below) |
| BE <-> BE (M3 processes: 2PC, VERIFY, outbox, moves) | later, after B3 | cross-process 2PC latency; low volume | knet on both sides | the R2 server glue plus a knet dial side; decided with M3 measurements |
| FE <-> stock clients | no | kernel/ceph-fuse/libcephfs speak plain msgr2 only | — | — |
| MDS <-> mon, mgr | no | control traffic, low rate | — | — |

- Order: R1 (every mutation), R2 (every metadata op of our client), R3 (data via cephfs2-fuse), BE<->BE last.
- FUSE zero copy (after R3, measured): today fuser hands owned buffers and rustyrados copies at submission
  (pool block for >= 64 KiB writes, adr 0469 client). Later: FUSE over io_uring with registered buffers or
  passthrough where the kernel offers it (probed), reads landing in FUSE reply buffers from the RDMA receive
  pool without the extra copy.
- Measurement: lab cells only on the RDMA host (ice-b); A/B TCP vs RDMA per step: create and unlink latency
  (QD1 and pipelined, rustycephfs2-bench), lookup/getattr latency, MDS CPU per op and BE ops/core; 1 repeat
  per arm, 3 interleaved only for a cell inside the noise. Results in doc/perf/.

## Rationale

- Stock bodies: the BE and the client already encode/decode them through one crate; a new op protocol would
  duplicate every op, cap and reconnect encoding. Private kinds cover only what stock cannot express (a core
  instead of a rank, our map).
- Per-core connections keep thread-per-core with no demux hop; cost is connections = clients x cores used,
  in the range the FE already plans for (10k-50k per process).
- Home-core sessions: one renew stream per client, a durable record that is logged, replayed and moved like
  every other key, and eviction that reuses the existing DETACH reason 2 path, so fencing is the FE path's
  guarantee by construction.
- FE bootstrap: the only address stock mons publish is the FE's; one sessionless message at mount keeps the
  FE off every later path. Metadata pool reads need caps clients do not have; a data pool object is writable
  by every client.
- Capless remote stats keep the rule "a cap travels only on its revoking core's connection", so no
  cross-connection cap ordering exists.

## Consequences

- + No FE hop or FE CPU for our client; FE failover does not touch it after mount.
- + One codec, one executor path, one cap table for both client kinds; mixed-client conflicts resolve where
  they resolve today.
- + RDMA on client<->BE needs no protocol work, only shared glue and opt-ins.
- - Store revision 6 (S key), in-place upgrade when an MDS opens the store with `--mds-direct-clients`; a
  revision-5 binary refuses the upgraded store. Per-core addresses in m.map: a later revision (B1).
- - Each BE core is a public endpoint: per-core listener, cephx verify, per-session admission (R credits)
  on the BE.
- - Mount needs a reachable active FE once; BE-only mount without FE is not possible.
- - Public wire contract from M3: versioned private kinds and ClientMap, fuzzed decoders.

## Alternatives

- Stock Ceph MDS wire protocol on BE ports, BEs as extra MDS ranks (forwards, cap EXPORT/IMPORT, MDSMap
  placement): needs BEs in the MDSMap (mon rank rules, <= 256 ranks, beacons), subtree auth semantics and
  per-rank sessions with renew per core; contradicts adr 0669 (BEs are not ranks). Rejected.
- Stock bodies only, no private kinds (map in client metadata, WRONG_OWNER as MClientRequestForward): forward
  names a rank, not a core; no map transport. Rejected.
- New op protocol (own request/reply/cap encodings): second implementation of every op. Rejected (DRY).
- One multiplexed connection per BE process: needs a demux core. Rejected.
- Sessions at the FE (client.md s2 before this ADR): user decision 2026-11-09.
- Map from MDSMap fields: stock mons do not carry them. Map from a RADOS object: metadata pool needs extra
  client caps; data pool object is writable by all clients (map poisoning). Rejected.
- Sessions in an own object `m.cs.<be>` (m.fe format): no shard move, failover takeover per object, extra
  RADOS op per open. Rejected for the S key.
- Remote inode caps relayed by the frag core: two connections carry grant and revoke of one cap. Rejected.

## Open questions

- Private msgr type id P: from the IMPL-3 inventory (shared with the FE<->BE wire transport, M3); before B0a merges (OQ 178).

Lead decisions 2026-11-09 (formerly open):
- RDMA config keys: no new keys. The MDS reuses the daemon key `flashstore_rdma`; cephfs2-fuse and rustycephfs2 reuse the rustyrados client RDMA option unchanged (DRY).
- Reclaim (RESET) for our client: not built; revisit only if Ganesha moves to rustycephfs2.
- Mount without an active FE (configured BE addresses): not planned.
