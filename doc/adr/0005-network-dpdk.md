# 0005 Network: DPDK userspace, no kernel TCP
Status: superseded by adr/0682-remove-afxdp-dpdk-networking.md (was: accepted, amended (am. 2: DPDK networking parked; stack choice resolved by 0020; NIC sharing amended by 0011))
Date: 2026-10-09
Context: Target 100-400 GbE. Clients/mons/peers speak msgr2 over TCP -> need server+client TCP. User: no kernel-TCP phase, full perf from start. Host runs ~20 classic OSDs + ours -> NIC must be SHARED with kernel.
Decision: DPDK poll-mode, one RX/TX queue per core, RSS/flow rules -> core. Single code path everywhere: dev/CI use DPDK virtual PMDs (net_tap, net_af_xdp, net_af_packet), no separate socket backend.
NIC sharing: Nvidia mlx5 bifurcated PMD (flow rules steer our dst ports + reserved src-port range to DPDK, kernel keeps rest, can share host IP) preferred; other vendors (Intel E810, Broadcom): SR-IOV VF per croit-flashstore-osd with own MAC/IP.
Need: TSO + LRO/GRO-equivalent, checksum offload, IPv4+IPv6, ARP/ND, VLAN. Bonding/LACP: DPDK parked (am. 2); knet uses the host kernel bond (adr 0014 moot).
TCP stack spike: (a) own minimal Rust TCP (datacenter-only: SACK, wscale, ts, DCTCP/CUBIC, TSO) vs (b) F-Stack (FreeBSD stack, BSD, C FFI; check multi-core model fit) vs (c) other. Criteria: cycles/msg, 100G single-core throughput, correctness under loss, integration with per-core reactor.
Consequences: big subsystem; must be robust (packet loss, reconnect). msgr2 crc mode first; secure mode (AES-GCM, AES-NI/VAES) later, design frame path for in-place crypto.
Alternatives: kernel TCP + io_uring ZC (rejected by requirement), RDMA (clients don't use it).
RDMA: later opt-in, external branch `rdma` (charter). Candidate if built: OSD<->OSD under the sans-IO msgr2 (adr 0015); saves ~10-30 us/RTT of kernel TCP at QD1, not librados thread handoffs; needs PFC/ECN.

## Amendment (2026-10-12): tx guard (net::txguard)
- TSO chain cap = `nb_seg_max` - 4 (never above it); unreported limits by driver table (bnxt: 31, HW 32 BDs incl. long BD, excess silently dropped = the bnxt TSO stall suspect); virtual PMDs none; `NV_MAXSEG` overrides. Longer chains are cut into whole-MSS TSO pieces (`gso::split_tso`, same wire frames), a piece still too long into MSS frames.
- A head packet the PMD refuses (mlx5: oerrors++, packet stays) is dropped once port `oerrors` rose by at least our own consecutive zero-progress retries over a window (checks at retry 8, 16, 32 ... then every 65536): per-port counter shared by queues cannot trigger it alone, counter reads stay rare.

## Amendment (2026-10-19): DPDK networking parked (am. 2)
User decision 2026-10-19: focus = production-grade OSD on kernel TCP (knet over io_uring, 0053; default) and AF_XDP (own TCP stack, 0020). DPDK networking is PARKED: inactive, not removed.
- Stays: code + cargo feature `dpdk` (net PMD port layer, mlx5 bifurcation, txguard). Must keep compiling: `scripts/check-prod.sh` builds `FEATURES=dpdk,spdk` (default) = the cheap compile check, keep it.
- Stops: no new DPDK-only features, no DPDK lab gates/benchmarks/scoreboard cells, lab defaults switched to knet/afxdp. Existing `NET=dpdk` / `NVNET=dpdk` / `TIERS=` options remain usable by hand.
- Still fixed: bugs in shared code (net TCP stack, msgr2, rt), because AF_XDP runs the same own stack (0020).
- NOT affected: SPDK / NVMe tier (0004) is a separate storage backend. SPDK links DPDK as its env layer (hugepages, memory, PCI); that is not DPDK networking and stays fully active.
- Production transports: knet (default), AF_XDP. Re-activation = new ADR decision.

## Amendment (2026-10-27): DPDK leaves the default production build (am. 3)
Decision: the `prod` profile (`lab/build-host-build.sh`) is knet + native AF_XDP (0020 am. 8) + kernel NVMe + RDMA and links no DPDK/SPDK libraries. `prod-full` = `prod` + `dpdk` + `spdk` (DPDK networking stays parked, SPDK tier stays; SPDK needs DPDK's EAL). Derived lab profiles (prodel, ctrlab, placement, prof, rdma, rdmaprof, cutprobe, rdmafault) build on `prod-full`; their artifacts are named `*.prod-full` where the plain `prod` suffix stood before. `scripts/check-prod.sh` checks both.
Rationale: AF_XDP no longer needs DPDK.
Consequences: SPDK/DPDK lab cells use `prod-full` binaries. Package pipeline (`lab/package-check.sh`, `lab/e2e/image`) still builds the full feature set until the lead decides what ships.

## Amendment (2026-10-28): AF_XDP compile-only (am. 4)
Decision: consistent with the AF_XDP deprecation (0020 am. 9), AF_XDP (feature `xsk`) is compile-only as DPDK networking is: out of the `prod` profile (knet, mimalloc, rdma), built only in `prod-full` (dpdk, spdk, xsk, mimalloc, knet, rdma) and the derived lab profiles.
Consequences: `croit-flashstore-osd --net afxdp` on a prod build fails at start naming the prod-full build; packages ship `prod` (0589 am. 1) and carry no AF_XDP.
