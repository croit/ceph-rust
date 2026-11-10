# 0020 TCP stack: own sans-IO Rust TCP (resolves 0005 spike)

Status: superseded by adr/0682-remove-afxdp-dpdk-networking.md (was: accepted)
Date: 2026-10-09
Consolidated 2026-10-28; full pre-consolidation text: git show 6360196331:doc/adr/0020-own-rust-tcp-stack.md
Measurements/history: doc/perf/adr-0020-history.md (doc not in the source snapshot).

## Context

Spike: doc/spikes/tcp-stack.md. No production Rust DPDK TCP exists; F-Stack is process-per-lcore with a copying socket API (breaks 0006 zero-copy); smoltcp has no SACK/TS (~4-15 Gbps). msgr2 needs a datacenter-only TCP the OSD owns: per-core sans-IO (0015), mbuf/payload zero-copy, real loss recovery, congestion control, offloads. References: RFCs, smoltcp (0BSD) as behavior reference; no copying of GPL/BSD code without license review. Dev env: lab/devcontainer (DPDK 26.07, SPDK v26.09, virtual PMDs; no IOMMU in Docker VM -> SPDK NVMe only in Proxmox lab).

## Decision

Own datacenter-only sans-IO TCP in crate `net`: per-core flow ownership, no shared state, static dispatch `Stack<B: RxBuf>` with `RxBuf: Clone` as a cheap handle (mbuf refcount) — no per-packet `Rc<dyn RxBuf>` allocation; production `B = dpdk::NetBuf` (enum `Heap(bytes::Bytes)` | `Rx(RxMbuf)`); the neutral `net::NetBuf` lets backends coexist in one binary.

### Loss recovery and congestion control

- Sender scoreboard: one record per MSS (seq, len, tx time, SACKED/LOST/RETRANS/EVER) from `snd_una`; pipe = flight - sacked - lost + retrans (RFC 6675). No go-back-N: RTO marks all unSACKed lost (SACK info kept), slow start from 1 MSS, ack-clocked retransmit.
- SACK (2018) rx scoreboard + tx blocks (<=3, newest first, with timestamps); D-SACK (2883) generated for every duplicate (below rcv_nxt, inside OOO queue) and consumed: undo of window reduction when all retransmits of an episode were D-SACKed (Linux-like, also late, until snd_una passes the exit point); RACK reordering window widened per D-SACK round.
- RACK-TLP (8985): per-ACK rack state; reo_wnd = min_rtt/4 * mult (0 while no reordering seen and in recovery or >=3 MSS SACKed); reo timer; lost-retransmit detection; TLP PTO 2*srtt, 1.5*srtt+200 ms for one outstanding segment, floor 1 ms; probe = new data else last unSACKed; probe-repaired loss = congestion event unless D-SACKed. `rack=false` -> RFC 6675 DupThresh marking; `sack=false` -> NewReno (3 dupacks, partial ACKs, limited transmit). RTT samples Karn-safe per record (us precision); TS echo (1 ms ticks) only as fallback.
- PRR (6937, SSRB) drives cwnd in recovery; exit cwnd = ssthresh.
- Congestion control: enum `CcKind` per socket (static dispatch; `TcpCfg::cc`, `Stack::listen_cfg/connect_cfg/set_cc`): CUBIC (9438, default; fast convergence, TCP-friendly region, epoch frozen while app-limited) + HyStart++ (9406; RTT_THRESH clamp configurable, default 0.5..4 ms — the RFC's 4..16 ms is WAN-sized and would never trigger at 100 us RTT), DCTCP (8257: alpha g=1/16, reduce once per window, halve on loss, CWR after reduction for classic receivers), Reno.
- ECN (3168): SYN ECE+CWR negotiation, ECT(0) on new data, receiver CE state machine (DCTCP: ACK per CE change; classic: ECE latch until CWR); DCTCP implies ECN, falls back to plain loss behaviour if the peer declines.
- RTO floor 200 ms; lone-segment TLP allowance = fixed WCDelAckT 200 ms (RFC 8985 default = Linux tcp_rto_min / TCP_DELACK_MAX).

### Offloads and receive

- `Config::tso = Off|Hw|Sw`. Hw: `TxFrame` super-frame (<=64 KB, `TxOffload{l2,l3,l4,tso_mss,tcp_csum,ip_csum}`, pseudo-header sum without length) for the NIC (mbuf `tso_segsz`/`ol_flags` set in `Port::build_tx`); Sw: the super-segment split by `gso::segment` (zero-copy payload slices, checksums in SW or flagged) in `poll_tx`. Scoreboard stays per MSS, so retransmits and SACK are TSO-agnostic; `dpdk::Caps::configure` sets csum offload / Hw TSO from port capabilities.
- `Stack::on_rx_frame_ol(frame, now, RxOl{ip,l4: Unknown|Good|Bad})` carries the PMD's per-mbuf verdict (`RX_*_CKSUM_GOOD|NONE` = trusted, `BAD` = drop+count); `Config::rx_csum_offload` / `--rx-csum trust` stays as lab override; `net_af_packet` sets no flags, so lab veth peers need `tx off` or the override.
- Software GRO: `rx_begin()/rx_end()` around the NIC burst merge in-order plain data segments of one flow (<=32) into one run (one `on_segment`, one ACK decision); order preserved per flow (flush on any non-mergeable segment). HW LRO not used (needs chained rx mbufs; GRO covers it).

### Flow table, hashing, tx backpressure, multi-queue

- Maps on the per-packet/per-frame path never use SipHash: msgr2 sessions = slab handle (`SessId`) carried in the connection (key map only for handshakes, foldhash, random per-process seed); flow table keyed by remote-controlled 4-tuples = foldhash seeded from `Config::secret`; maps keyed by own ids (conn ids, `SockId`) = Fx/foldhash.
- NIC tx is backpressured, never dropped: `rt::Nic::tx_backlog()`; the core retries the ring before pulling frames from the stack (frames the ring refuses stay in the NIC's pending list).
- Lab `net_af_packet`: reports frames as sent when `sendto` returns EAGAIN/ENOBUFS and leaves them in the tx ring until the next burst (one RTO with an idle app); needs `net.core.wmem_default` >= 16 MiB (vm-setup.md s12); not an issue for real PMDs.
- Multi-queue: `net::rss` + `Config::steer` + `dpdk::Port::start_mq`; per-core `Stack`, no shared state.

### Copy budget

- rx payload: zero copy to msgr2's byte feed (mbuf refs end there; existing copy in rt). tx: header bytes per frame (<=128 B, built inline); rx-mbuf-backed chunks by reference (indirect mbufs, zero copy); heap buffers (msgr2 output `Vec`) copied into pool mbufs — a real NIC needs DMA-mapped tx memory, i.e. msgr2 serializing into a hugepage arena (open item); virtual PMDs use an external mbuf buffer (one small malloc per attach, lab only). Retransmits re-reference the same chunks. Per-segment `Vec` for the gather list (amortized by TSO). SW checksum (no offload) reads the payload once.
- msgr2 `Decoder` direct assembler (crc, rev 2.1): bytes copied once into owned segments with incremental crc; `Connection` consumes owned frames (removes 2 of 3 payload touches); encoder: blocked copy+crc (`crc::crc32c_extend`).

### Transports

- Production: knet — kernel TCP over io_uring (adr 0053).
- AF_XDP native backend `net::xsk` (feature `xsk`) is DEPRECATED since 2026-10-28 (am. 9): out of the `prod` profile, compile-only, carried only by `prod-full` and derived lab profiles; `croit-flashstore-osd --net afxdp` on a non-xsk build fails at start with an error naming the prod-full build; re-activating AF_XDP in prod = new ADR.
- DPDK networking is parked (adr 0005 am. 2): the own stack does not serve DPDK in prod; the DPDK port layer only keeps compiling (`scripts/check-prod.sh`, features `dpdk,spdk`); shared-layer bugs (TCP FSM, loss recovery, congestion, offloads, msgr2 glue) are fixed and gated on the active transports; re-activating DPDK = new ADR.
- Build profiles: `prod` = knet, mimalloc, rdma; `prod-full` = dpdk, spdk, xsk, mimalloc, knet, rdma (`lab/build-host-build.sh` follows; `scripts/check-prod.sh` keeps the prod-full matrix row that compiles xsk); hwcheck `build.xsk` listed only when compiled in; packages ship `prod` (adr 0589 am. 1).
- CLI unchanged, still accepted on prod-full builds: `--net afxdp --vdev net_af_xdp0,iface=IF[,start_queue=N][,queue_count=N][,busy_budget=N]` (also as `flashstore_eal_args`; other EAL args ignored with a warning).

### AF_XDP backend (net::xsk; deprecated, code facts)

- Raw `socket(AF_XDP)` / `bpf(2)` from the kernel UAPI; no DPDK, libbpf or libxdp. One XSK per rx queue, owned by its core.
- umem chunk = one 4 KiB page (aligned mode, rx data at +256), so frames never cross a page (`net::xdp`).
- Rx frames are refcounted `UmemBuf`s (the stack's `RxBuf`); the last drop on any thread returns the frame to the owning core through a lock-free queue, which refills the fill ring.
- Tx copies head + body into one umem frame with software checksums (`RxOl::SW`), no TSO.
- XDP program: redirect by rx queue index into an XSKMAP, `XDP_PASS` when the queue has no socket; attached with `bpf_link`, which the kernel detaches when the OSD exits or dies.
- Bind flags: `XDP_USE_NEED_WAKEUP`; zero-copy where the kernel grants it, else copy mode (reported at start). Busy polling per queue: `busy_budget` default 64; 0 = IRQ driven.

## Rationale

- AF_XDP kill criterion not met: copy mode ~5x below knet at 1500 MTU, no zero-copy NIC proof (doc/perf/afxdp-native-20261027.md) -> deprecated (am. 9), compile-only.
- DPDK is not in the default build (parked, adr 0005 am. 2); the native xsk backend keeps AF_XDP free of DPDK libraries (no EAL, no PMD patch set, no libxdp/libbpf).
- Sender pacing lost the A/B (MB/s down, p99 up on DPDK and AF_XDP, more retransmits); incast loss is a switch matter.

## Consequences

- + Per-core sans-IO TCP, zero-copy mbufs into msgr2, no locks on the hot path (adr 0006).
- - Deprecated AF_XDP path (host rule, compile-only context): the host must not enable NAPI IRQ deferral (`napi_defer_hard_irqs` / `gro_flush_timeout`) on a busy-polled AF_XDP port; hwcheck `net.<if>.busypoll` warns with `echo 0 > /sys/class/net/<if>/napi_defer_hard_irqs`; `croit-flashstore-tool host-tune` applies it on request; the OSD never writes it.
- - Deprecated AF_XDP path (host rule, compile-only context): the port's queue IRQs belong off the OSD cores; the OSD picks its cores away from the port's IRQ cpus (`choose_cpus`) and warns at start on overlap (hwcheck NIC-IRQ share, with the fix command); it does not move IRQs itself (host setting).
- knet (IRQ-driven NAPI, no busy poll), DPDK PCI ports (user-space poll) and RDMA (CQ poll) are unaffected by the AF_XDP host rules.

## Alternatives

- smoltcp: no SACK/TS, ~4-15 Gbps.
- F-Stack: process-per-lcore, copying socket API, breaks 0006.
- Keep the DPDK PMD in the default build: DPDK libraries (EAL, PMD patch set) in the standard binary for a parked/deprecated transport.
- libxdp/libbpf crates: dependency weight; the XDP program and rings are small.
- Sender pacing: lost the A/B (MB/s down, p99 up, more retransmits); rejected.
- IRQ deferral on busy-polled AF_XDP: masks the tx-completion IRQ the mlx5 PMD relies on (4M read -32 %, doc/perf/afxdp-rx-20261026.md); rejected.
- adaptive-rx off: hot core unchanged, 4k QD16 -14 %; rejected.
- Fixed/signal-driven kick cadence: -64 % kicks gave no 4M write gain, 4M read -7 % (doc/perf/afxdp-kick-20261026.md); rejected.
- busy_budget=0 default: QD1 p50 +10..18 % (doc/perf/afxdp-4m-cores-20261025.md); rejected.
- RX spread on AF_XDP (`NV_RX_SPREAD`): no gain, the rx core was not bound by copy/crc.
- WCDelAckT measured from pure-ACK delays: Linux quickack mode (start, idle, OOO/dup data ACK at once) bounds no sample window for the next delayed ACK; fixed 200 ms kept.

## Open questions

- TX checksum metadata via xsk tx metadata on NICs that support it (mlx5/ice): per-byte tx checksum pass saved; needs xsk support (doc/perf/kernel72-features-20261026.md).
- IRQ suspension (`irq-suspend-timeout`, kernel > 6.12) stays with the AF_XDP rx work.
- No eifel/F-RTO (RTO spuriousness only via D-SACK); no RACK for non-SACK peers; no AccECN.
- Incast/soak N3 gate (netem loss/incast/soak vs Linux peers, cargo-fuzz) not done.
- HW TSO/csum/rx-flag paths untested on real hardware (af_packet has none; the sim emulates the NIC and checks bytes + checksums).

## Tests

`net` unit tests; `tests/sim_n2.rs` (virtual-time sim: deep queue, loss, reorder, ECN, TSO/GSO); `tests/fuzz.rs` (mutated frames, hostile SACK blocks, random API, feature mix per seed); `lab/devcontainer/interop-tcp.sh` (net_af_packet vs Linux kernel TCP, sha256 both ways); `lab/tests/xsk-veth.sh` (xsk veth, copy mode). Performance: doc/design/net-perf.md; measurements: doc/perf/adr-0020-history.md.

## Amendment map

- am. 1 (2026-10-09): N2 loss recovery, congestion control, offloads -> Loss recovery and congestion control, Offloads and receive, Copy budget
- am. 2 (2026-10-09): multi-queue performance -> Flow table, hashing, tx backpressure, multi-queue, Copy budget
- am. 3 (2026-10-10): flow-table hashing, tx backpressure -> Flow table, hashing, tx backpressure, multi-queue
- am. 4 (2026-10-19): DPDK parked -> Transports
- am. 5 (2026-10-25): AF_XDP queue IRQs off OSD cores -> Consequences, Transports
- am. 6 (2026-10-26): no NAPI deferral on busy-polled AF_XDP -> Consequences
- am. 7 (2026-10-26): kernel 7.2 features, no change -> Open questions
- am. 8 (2026-10-27): native AF_XDP backend -> AF_XDP backend, Transports | superseded by am. 9
- am. 9 (2026-10-28): AF_XDP deprecated -> Transports, Consequences
