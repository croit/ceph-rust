<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0469 RDMA transport: in-place msgr2 upgrade to one RC QP per connection

Status: accepted
Date: 2026-10-19
Consolidated 2026-10-21; full pre-consolidation text: `git show 6f786b991:doc/adr/0469-rdma-transport.md`. Measurements and amendment origins: doc/perf/adr-0469-history.md (doc not in the source snapshot).

## Context

The production transports knet (adr 0053) and AF_XDP (adr 0020 am. 4) spend OSD CPU on TCP stack work and socket-buffer copies; DPDK networking is parked (adr 0005 am. 2). RoCE NICs are present in the target fleet (mlx5, bnxt_re). Classic OSDs, mons and mgrs must keep seeing byte-identical msgr2 v2. Spike (ice-b, ConnectX-4): SEND/WRITE/READ reach line rate at path MTU 4096; QP control calls take 0.6-1.2 ms each. Design: doc/design/rdma.md (D1-D21). Perf: doc/perf/rdma-spike-20261019.md.

## Decision

### Wire and upgrade

- Wire identity stays msgr2. RDMA is an in-place upgrade of an authenticated v2/TCP connection, after the last AUTH frame and before CLIENT_IDENT.
- Two BANNER `supported_features` bits: F_RDMA = bit 62 (SEND-only upgrade), F_PLACEMENT = bit 61 (requires F_RDMA, companion 0471-msgr2-payload-placement). Neither bit is ever in `required_features`.
- The RDMA_UPGRADE frame uses a high value of the frame tag enum. It is accepted or emitted only when the peer's authenticated banner carried F_RDMA.
- Upgrade only when `owner(authenticated peer) == landing core` (adr 0054). Handed-off and relayed connections stay TCP for life. Client connections upgrade on the accept core.
- Same-host peers stay TCP (am. 3): `rdma_candidate` (rt knet) never starts an upgrade on a connection whose peer address is an address of this host (`local_peer`: loopback or a local interface address); an OSD dialing such a peer prepares no QP, the server declines an offer from such a peer like any other decline. Reason: a QP pair on one device loops through the NIC and takes receive buffers and PCIe bandwidth from the real inbound traffic of the port, which then drops it (receiver `rx_discards_phy`, go-back-N retransmits), while kernel loopback TCP is a memory copy. A client whose sessions are all same-host runs on TCP.
- A declined or failed handover leaves a normal TCP connection, never an error. A peer whose QP does not come up within the handover deadline stays TCP for that connection; the next connection tries again (no quarantine yet, open question).
- GID binding: the local GID is the RoCEv2 GID of the TCP local IP; the peer GID must match the TCP peer address. The GID table index is confirmed (one query) or looked up again before every RTR (am. 4): an address removed and re-added comes back at another index. While the GID is not on the port, prepares are refused (the connection stays TCP, one log line per change); new sessions upgrade again once it is back.
- The maximum frame size is negotiated in the handover. A larger frame is rejected loudly, never truncated. The negotiated maximum is at least the largest frame the TCP path accepts on that connection (a full `osd_max_object_size` read reply): an op that succeeds over TCP never fails over RDMA.
- hb_front/hb_back messengers, mon and mgr connections never advertise the bits. croit-flashstore-osd never advertises COMPRESSION.
- Default off; enabled per daemon by config (`flashstore_rdma`). RDMA runs next to the kernel TCP tier (knet) only: `flashstore_rdma = true` with `--net afxdp` or `--net dpdk` is refused at startup (`args::rdma_refusal`).
- API: libibverbs (rdma-core, BSD license option), one static copy (adr 0052 am. 5). No rdma_cm, RC QPs only, mlx5 DV only where profiled.
- Fabric: RoCEv2 (GID from a netdev IP) is the default. Lossy and lossless (PFC + ECN) fabrics are both supported; lossless is recommended. Details: 0470-rdma-ops. RoCE path MTU >= 1024 is required (4096 recommended, 0470-rdma-ops am. 1); below 1024 the transport stays TCP for that device and raises a cluster-log warning.

### Handover and liveness socket

- Handover order: quiesce, drain, both QPs RTS, first-frame marker. After the switch point the TCP socket stays open without data for the connection's life (liveness channel; an RC QP tells the passive side nothing when the peer closes, destroys its QP or dies):
  - any byte on it is a protocol fault: the connection closes at once;
  - its end (EOF / reset) = the peer closed or died: the receiver drains its CQ, delivers what arrived, then the connection is dead;
  - graceful close: fence, destroy the QP, close the socket; a fault or abort of this side closes the socket at once;
  - both sides (croit-flashstore-osd knet, rados-rt client) watch it. Cost: one fd and one idle TCP socket per upgraded connection (keepalive as configured on the socket).

### Data path

- All frames then travel as SEND on one RC QP per connection (segmented stream: a frame may span several SENDs), on the owning core, one CQ per core, no cross-core handoff (adr 0006). Header and small segments land in the first receive slot; larger data streams into 4 KiB-aligned arena slots as a by-reference chain (keeps `view_buf`, `reseed_4k`; cut-through was removed, adr 0462).
- Verbs control calls (QP create/modify/destroy, MR registration) never run on a data-path core: a pre-created QP pool and a setup helper thread do them. The control thread's replies wake the owning core through a per-core eventfd of the RDMA plane (in the ring like the CQ channel), independent of the mesh wake and `--knet-wake`; replies never wait for the idle cap.
- Outstanding READs per QP = device limit.
- Send path (no wire change): small output and memory not registered with the device are copied into the per-core send arena (64 KiB slots). An output chunk of at least one slot that lies in registered payload memory goes zero copy: its SENDs point the SGE at the payload (lkey of that registration, segmented to the peer's slot size, no arena slot). Always on (A/B: OSD CPU per byte down, MB/s neutral, 0 misses); a process without a heap copies. Registration: the payload hugepage heap's preallocated segments (never freed by the EAL), once per device at start, local access only (no rkey leaves the process); never per op; heap pages added later are copied (counter `rdma_zc_misses`).
- Lease rule (zero copy): each posting call holds one reference to the posted part of the payload (`Bytes`, immutable, adr 0450) on its last WR in the send queue; that WR is signaled (like an arena-slot holder, so a quiet sender retires it within one round trip) and the reference is dropped when it retires (RC completes in order: every earlier WR is done). On detach (close, fault) the outstanding references move with the QP to the control thread and are dropped after the QP is destroyed; a failed destroy keeps them forever. Never released twice, never before the HCA is done.

### Receive credits and memory

- One SRQ per core. Receive credits equal posted receive buffers; a buffer is re-posted before its credit is returned; the sum of granted credits on a core is at most the SRQ depth.
- Grants are dynamic: every session keeps a minimum window (3: with 2 the reserved credit-only SEND deadlocks, proven by a unit test); a new session starts with a fair share of the free pool (owed extras sent after the peer's first SEND); a credit-blocked session is lent credits on arrival (no timer; the credit-only SEND leaves in the same poll pass, per completion after its slot was re-posted); the 10 ms tick only rebalances and reclaims idle sessions. Active sessions draw from the per-core pool up to the ceiling `DEFAULT_MAX_WINDOW` = 64, at most a quarter of the core's receive slots (`budget::size`: a smaller budget gives smaller windows), and give it back when idle (REVOKE / SURRENDER in the SEND immediate, spec 18). A core holds `receive slots / 3` sessions, bounded by the minimum windows only, never by a per-session reservation. Line rate needs window 8 at 64 KiB slots (`LINE_RATE_WINDOW` 16 = 2x margin); 64 is chosen because the receiver's copy time adds to the round trip.
- `flashstore_rdma_max_sessions` (default 0 = unlimited) caps the sessions of the OSD process; beyond it, or beyond the pool, a connection stays TCP. Credit exhaustion blocks the sender (counter + stall histogram); credit expiry and RNR-retry exhaustion are session faults.
- Memory: the registered (pinned) receive/send arenas are a separate budget `flashstore_rdma_memory` (per OSD process, default 256 MiB), on top of and independent of `osd_memory_target` (the envelope split, adr 0175, is untouched). It is divided equally over cores x devices (one device per distinct OSD address); of a (core, device) part two thirds are receive slots (one SRQ per core), the rest send slots. Memory never scales with peers or connections: sessions share the receive slots through the dynamic grants. Minimum per part: 6 MiB (4 line-rate windows of 16 receive slots, 2 of send slots, 64 KiB slots; the window ceiling follows the part: 32 MiB parts get 64, 16 MiB parts 42); a smaller part, or an `RLIMIT_MEMLOCK` below the budget (without CAP_IPC_LOCK), refuses to start with the fix.

### Close, fault, teardown

- Graceful close (OSD and rados-rt client, same `rdma::fence`): an upgraded connection's QP is destroyed only after a signaled zero-length SEND posted behind the last output completed (RC: acknowledged by the peer HCA), or after a QP fault. Bound: the knet `close_linger` (client: 5 s), then `WARNING TIMEOUT rdma close fence exceeded <n>s (conn <id>)` and teardown (OSD: `osd.rdma_close_fence_timeouts`; client: `RdmaCounters::close_fence_timeouts`). The client closes its liveness socket after the QP. Abortive teardown (fault, dead peer) stays immediate.
- A QP error or timeout is a session fault: msgr2 session reset and reconnect over TCP. In-flight WRs are flushed (QP to ERR) before teardown; buffers are released only after the transport no longer owns them.
- QP teardown on the shared SRQ (am. 1), provider independent (mlx5 drops a destroyed QP's completions still in the CQ, their receive slots would be lost): the control thread moves the QP to ERR, waits for `IBV_EVENT_QP_LAST_WQE_REACHED` (per-device async-event thread), the owning core drains its CQ, then the QP is destroyed; its send slots and receive credits (reserved from detach on, never lent) are released only after that. The event is state (am. 4): a QP raises it once, on entering ERR, often before its teardown (retry exceeded); one nobody waits for is kept per QPN until that QP's quiesce (answered at once) or destroy. The async thread acks after recording, so a returned destroy has all its QP's events recorded (no inheritance by a reused QPN). No event within 10 s (device-local): `WARNING TIMEOUT`, counter `qp_drain_timeouts`, QP and its resources kept (leak, never released blind).

### Client (rados-rt, rados-ffi)

- Client zero copy (rados-rt; default on, `KernelTcpLimits::rdma_zero_copy`; it acts only when the application installed a pool before its first dial: without a pool nothing is registered and nothing counts as a miss): registered memory is a client-owned payload pool (`rados_rt::PayloadPool`): one process-wide region, installed once, never freed, registered whole once per device at the carrier's device setup (local access only). The native API builds write payloads in it (`PayloadPool::alloc` -> `PayloadBuf` -> `freeze` = `Bytes`; the block returns to the pool when the last reference drops). The carrier sends chunks of at least one slot that lie in the pool by reference (`Core::send_bytes`, same lease rule as the OSD); everything else is copied and counted (`zc_misses`). No registration cache over application memory. Counters (`RdmaCounters`): `zc_sends`, `zc_bytes`, `zc_misses`, `zc_registered_bytes`; pool: `PoolStats` (`allocs`, `exhausted`, `in_use_bytes`). Pool size for real applications: `PayloadPool::derived_bytes(RequestLimits::bytes)` = 4 x the request-byte admission (256 MiB at the default 64 MiB: 2 for the payloads in flight, 2 for the buddy rounding), installed by the application before its first dial; a process that may not pin that much falls back to copies (stderr line, `zc_misses`). Secure mode: the ciphertext buffer is heap memory (copied, counted).
- C API (rados-ffi, am. 2): `rustyrados_rdma = true` (ceph.conf, `rados_conf_set`, `CEPH_ARGS`; default false) offers the upgrade on the OSD sessions of that cluster handle; `rustyrados_rdma_memory` (default 256M, minimum 64K, pinned, rounded up to a power of two) sizes the process's payload pool, installed at `rados_connect` before the first dial. The caller buffer is copied at submission (librados contract: the caller may reuse it after the call), so the HCA never reads caller memory and the completion needs no lease hold. The one ownership copy of a write of at least one pool block (64 KiB; scalar and bufferlist paths, fused with the CRC) lands directly in a pool block and goes out by reference; smaller writes and a full pool (`pool_exhausted`) take the heap copy. Reads copy the reply once into the caller buffer. Connect refuses with a stderr line: built without feature `rdma` ENOTSUP, backend other than epoll EINVAL, pool allocation ENOMEM. `rados_conf_get("rustyrados_rdma_status")` returns JSON: `enabled`, `built_in`, the upgrade counters (`upgraded`, `declined`, `capped`, `faulted`, `tcp_peer` = sessions ready over TCP because the OSD offers no RDMA), `zc_*`, `pool_*`. The production client package builds feature `rdma` in (static rdma-core: no rdma DT_NEEDED, no load-time dependency); off at run time unless the option is set. A stock librados ignores the key in a ceph.conf; its `rados_conf_set` answers ENOENT.
- Client receive threading (rados-rt; on wherever the TCP receive helpers are on, adr 0467: same pool, threshold, `RADOS_TRANSPORT_OFFLOAD`): one verbs core (CQ, SRQ, completion channel) stays on the driver thread with CQ polling, re-post, credits, sends, hold/resume, close fence and liveness socket. Only the per-byte receive work (copy + CRC + first-touch faults of the fresh segment buffer) moves to the TCP byte-work helpers through the same job interface.
  - When the owner's receive loan (`take_rx_loan`) has at least the threshold left, the stream's slots are held (not re-posted) and lent to a helper that copies them into the loan. Streaming lend: the job is a stream; the driver settles copied parts (slots re-posted, credits flow back during the copy) and appends newly arrived slots to the running job through a per-connection part ring; the helper ends the job only when no part is left. The wake of a sleeping driver comes once per credit-return unit, not per part. One job per stream, slots in stream order (per-session order holds); no helper idle (the driver copies itself, work-conserving); release (close, fault) waits for the job (at most one credit window). API names, ring and wake mechanics, counters (`rados_rt::offload_helpers()`): doc/perf/adr-0469-history.md.

### Visibility

- Ceph-compatible means only; no own health check codes (an OSD reports health only as the fixed `DaemonHealthMetric` types of the pinned version, and a custom check would need a mgr module): per-session transport counters and a coverage counter (upgraded / eligible per peer class) as OSD perf counters in MMgrReport (`perf dump`, mgr prometheus), asok/tell JSON output, and rate-limited cluster-log (MLog) warnings when RDMA is configured but inactive or capped: one entry per state change, at most one summary per 10 min. No silent fallback.
- Realized: OSD perf counters `rdma_*` (upgraded, declined, faulted, sessions_capped, credit_stalls, queue_stalls, close_fence_timeouts, zc_bytes, zc_misses, gauge sessions; only with `flashstore_rdma`); `rdma status` (`--format plain|json|json-pretty`) per device and core; WARN lines for max_sessions reached / receive pool full, device unusable, configured but nothing upgraded after 600 s, each with at most one "N connections stayed on TCP" summary per 10 min and only if there were new ones; one INFO line when the condition ends. Same lines in the daemon log. Exact names and texts: doc/perf/adr-0469-history.md.

## Rationale

- In-place upgrade reuses the existing listener, auth and session code; fallback is the unchanged TCP path, so classic peers and old croit-flashstore-osd see plain v2 by construction.
- Banner bits are part of the AUTH_SIGNATURE transcript (spec §9), so stripping or adding them faults before the upgrade. Upstream feature bits are allocated from the low end; high bits avoid collision.
- One QP per connection keeps msgr2 stream ordering (RC delivers in order) and keeps the per-core ownership model (adr 0006).
- Control calls are blocking ioctls of 0.6-1.2 ms (~670 QP/s per thread): on a data-path core a reconnect storm would stall I/O.
- Path MTU: at 1024 ConnectX-4 READ throughput collapses; at 4096 READ, WRITE and SEND run at line rate with 0 drops on both fabrics. Lossless class: 0 drops, 0 out-of-sequence; lossy at 4096: 6e-6 out-of-sequence, recovered by RC retransmission at -0.5 % throughput.
- Client zero copy, pool instead of cache: memory whose lifetime the client owns has no invalidation case (the region stays mapped for the process life), works on every provider, one registration. Completion ordering: the OSD reply may be polled before the SEND completion that retires the lease (send and receive completions share one CQ and are not ordered against each other), so the request completes while the HCA may still read; safe because the lease is a reference to immutable, client-owned memory: the block is reusable (`PayloadPool::alloc`) only after the last reference, the lease included, is gone; a request cancelled or timed out drops its reference only.
- Client receive threading: per-completion work (poll, re-post, credit) is small against per-byte work (64 KiB per completion); moving only the latter keeps owner, CQ and credit state single-threaded and reuses the TCP helper model. Streaming lend over closed-batch jobs: closed batches alternated copy and refill on one stream (copied slots not re-posted until the job returned, two wake latencies per job); numbers in the history.
- Trade-off accepted: a new per-core RDMA surface and a msgr2 spec extension, in exchange for removing TCP stack work and socket copies from the data path.

## Consequences

- + Classic clusters unchanged; classic <-> croit-flashstore-osd and old <-> new croit-flashstore-osd stay TCP.
- + Single session, auth and address code path; decline is a normal TCP connection.
- + SEND baseline works on every RoCE provider, including those without memory windows (bnxt_re).
- - msgr2 spec extension: banner bits, upgrade frame, negotiated maximum frame size, credit return channel.
- - The core loop gains a CQ phase; cross-core buffer ownership must be specified (design D18).
- - Deployments need RoCE path MTU >= 1024 (netdev MTU >= 1120); 4096 (netdev MTU >= 4192, switch jumbo) is recommended and `croit-flashstore-osd --check` warns below it.
- - Gate before default-on: RDMA >= knet and AF_XDP on every measured discipline with the added RDMA cycles counted; no silent fallback; zero false down marks.

## Alternatives

- Separate msgr protocol family: duplicates the protocol surface and widens the v21.2.0 compat pin.
- Ceph async+rdma-style byte stream over SEND with chunk copies: two copies per direction, no zero-copy gain.
- Client registration cache over application memory keyed by address range: after free + unmap a new mapping at the same address has new pages and a cache hit sends the old ones (silent corruption); invalidation needs unmap hooks (UCX rcache / MPI-style interposition: misses direct syscalls, `madvise(DONTNEED)`, static binaries) or userfaultfd (asynchronous, racy, privilege-gated): rejected as unsafe.
- Implicit ODP (`IBV_ACCESS_ON_DEMAND`, coherent with munmap): mlx5 only (bnxt_re none; rxe explicit only), HCA page faults stall the QP (published: timeouts, large latency penalties), fresh per-op buffers fault every page; untestable without mlx5 lab time. Recorded option behind the same send path if a measurement shows a gain.
- Client-initiated RMA (pull): the READ target gets no completion; unbounded pinning and no interlock (design D1).
- Pre-granted replica receive windows: remotely writable OSD memory (rkey is PD-wide).
- Streaming lend variants: (a) bound each closed job to part of the window: one handoff gap per job remains; (b) a second in-order job per stream: sequential loan and CRC / AEAD state need a split loan and a chained digest; (c) settle copied parts without growing the job: helper still idles between jobs. Chosen: (c) plus a growing job.
- Client receive threading with one verbs core (own CQ, SRQ, completion channel) per helper, sessions assigned at upgrade, the helper polling and decoding for its sessions: needs cross-thread sends (the core and its QPs are single-threaded), cross-thread hold/resume and fence, a second hand-over path for non-loan bytes to the owner, and N registered receive pools; the TCP helpers do not decode either (the owner stays one thread, adr 0467). Revisit only if the driver's per-completion work becomes the cap.
- Teardown by a marker WR's flush completion instead of the last-WQE event (am. 4): proves only the send queue; for an SRQ QP only the event proves every receive completion is in the CQ (kernel SRQ drain waits for it too). GID index fixed at open, refreshed on `GID table change`: event-dependent; the per-connect check needs none.
- rdma_cm: the in-band upgrade already provides addressing and session setup.
- UC/UD QPs: no hardware retransmission.
- Same-host sessions over NIC loopback (the behavior before am. 3): a gain only while the NIC carries nothing else (size 1, single client on the OSD's host), a large loss as soon as wire traffic shares the port (doc/perf/rdma-size3-20261021.md). A switch on measured port load is excluded (no load-based switches); the neutral rule (same host = TCP) removes the loss at the price of that corner case.
- Close the TCP socket at the switch point: the passive side never learns a close or a dead peer (the msgr2 WAIT loser left the server in its 10 s handshake timeout, whose close fence then hit the destroyed QP: "transport retry counter exceeded"). A QP-level close message or heartbeat would cover a graceful close only, not a dead process.

## Open questions

- Stuck-QP fault time: must stay well below `osd_op_complaint_time` without spurious faults. Local-ACK timeout 14 kept (12 changed nothing on a lossy fabric; doc/perf/rdma-lossy-20261021.md).
- QP scaling knee (1k/4k/16k QPs) and whether DCT/XRC is needed (design 4e).
- Segmented SEND vs chunked READ for large client writes: decided by CPU per op and slot waste (design 4a).
- MPRQ (multi-packet receive queue) on mlx5: decide after the SEND baseline is profiled.
- libfabric as an alternative API for provider portability: lacks a standard MW bind/invalidate.
- Whether ECN becomes mandatory: depends on the incast campaign.
- Zero-copy SEND threshold (start: one slot, 64 KiB); default-on is decided (A/B in the history).
- Client receive threading: ~40 % of the client CPU of 64 MiB reads is first-touch page faults of the fresh read buffer (THP fallbacks of the client VM); recycling large read buffers would remove it for TCP and RDMA alike.
- Client zero copy: whether the library installs the pool itself for the native API (today the application does). Secure mode: allocating the ciphertext buffer in the pool is a follow-up.
- Peer quarantine: a peer whose QP never comes up (broken RoCE path) costs every new connection the handover deadline before it stays TCP; whether to remember such peers (backoff, cluster-log warning) needs a fault test first.
- AF_XDP coexistence: RDMA on the netdev an AF_XDP OSD uses (the XDP program must pass RoCE traffic, the upgrade must run on the own TCP stack's sessions); refused at startup today.

## Amendment map

- am. 1 (2026-10-20): QP teardown on shared SRQ -> Decision "Close, fault, teardown" (QP teardown on the shared SRQ)
- am. 2 (2026-10-21): rados-ffi C API RDMA option -> Decision "Client (rados-rt, rados-ffi)" (C API)
- am. 3 (2026-10-21): same-host peers stay TCP -> Decision "Wire and upgrade" (Same-host peers stay TCP); Alternatives
- am. 4 (2026-10-22): early last-WQE events kept; GID index per connect (faults F1, F2 of doc/perf/rdma-fault-20261022.md) -> Decision "Close, fault, teardown", "Wire and upgrade" (GID binding); Alternatives
- am. 5 (2026-10-25): F_PLACEMENT = bit 61 (code), path MTU floor 1024 -> Decision "Wire and upgrade", Consequences
