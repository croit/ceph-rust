<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0472 AF_XDP same-port peers: kernel local path, VF per OSD for AF_XDP end to end

Status: superseded by adr/0682-remove-afxdp-dpdk-networking.md (was: accepted)
Status note: Superseded in part by adr 0020 deprecation and CLAUDE.md (AF_XDP deprecated: compile-only, out of the prod build, no new work, no lab cells): kernel TCP over io_uring (adr 0053) is the production transport.
Date: 2026-10-21

## Context

An AF_XDP (and DPDK) OSD sends every frame through its NIC port. On mlx5 the NIC does not loop a frame back to the
port's own MAC: the frames to a peer on the same host behind the same port (another OSD, mon, client) leave on the wire
and do not come back (verified on ice-a, doc/perf/afxdp-same-host-20261021.md). This is also true with a second
transport domain open and with the `loopback` feature off [fixed]. Links to such peers fault with `Io`, so a host with
several AF_XDP OSDs on one port, or a mon on that port, cannot form a cluster (OQ 26, rented 4-host layout).

## Decision

- An own-stack OSD (AF_XDP, DPDK) routes each dial by peer address (`rt::knet::LocalPath`, `rt::OsdNet`):
  - the peer IPv4 sits on a netdev of this host with our port MAC, or is in 127/8: kernel TCP (a small `KNet` io_uring engine per network core, adr 0053);
  - every other peer (another host, a VF, another port): the NIC path as before.
- The OSD listens on its own IP:base..base+3 with kernel sockets too (SO_REUSEPORT, one set per network core), but only when the kernel owns that IP. Wire frames of the OSD's queues still go to the XSK; local connections never touch the NIC, so both listeners coexist.
- The kernel does not own the IP: the local path is off. Same-port peers are unreachable and fail fast (`on_dial_failed`), with one loud WARNING per peer naming the fix.
- Same-port croit-flashstore-osd peers use this kernel path too. There is no user-space same-host transport.
- The recommended topology for AF_XDP end to end is one SR-IOV VF per OSD: each endpoint has its own MAC, and the NIC eSwitch switches VF<->VF and VF<->PF.
  - `croit-flashstore-osd --check` (hwcheck) warns when several AF_XDP OSDs of one conf share a port (`conf.afxdp.<iface>`) and names the exact fix.
  - `host-tune --apply` creates the VFs (`echo N > /sys/class/net/<pf>/device/sriov_numvfs`) only when the PF has none yet. Binding each OSD to its VF (`iface=` of the vdev, `flashstore_ip`) stays manual.
  - The OSD prints `WARNING host: AF_XDP port <iface> is shared with N other endpoint address(es) ...` at start, with the same fix.
- Exit counters: `local: kernel=on accepted= dialed= rx_bytes= tx_bytes=` per core.

## Rationale

- The kernel path is needed anyway: mons, mgrs, classic OSDs and clients on the same host are kernel endpoints, and only kernel TCP reaches them without a NIC hairpin. Using the same path for croit-flashstore-osd peers keeps one mechanism (KISS).
- With failure domain host (the production rule), replication and EC sub-ops never go between OSDs of one host. Same-host traffic is heartbeats, mon/mgr sessions and local clients, not the 100G path.
- The kernel path carries the lab traffic without being the bottleneck: 10-13 GB per OSD in a 2-minute gate, client reads 1.9-2.9 GB/s (doc/perf/afxdp-same-host-20261021.md).
- The peer test is the MAC, not the host: peers behind a VF or another port keep AF_XDP. The VF topology therefore stays AF_XDP end to end without any code switch.

## Consequences

- + Several AF_XDP OSDs per port and a mon on the same port work out of the box when the kernel owns the OSD IPs (the documented AF_XDP setup: per-OSD IPs as kernel addresses).
- + DPDK tier: the code in `rt` is shared, so the same routing applies. It only triggers for same-MAC peers; mlx5 bifurcated DPDK, which loops locally through its own flow rules, does not see such peers in practice.
- + No new process-to-process protocol, no shared-memory lifecycle, no crash-cleanup paths.
- - Same-port traffic pays kernel TCP cost (syscalls, copies) instead of AF_XDP.
- - One more transport in the core loop (static dispatch, polled only when the local path is on).
- - getifaddrs per dial (dials are rare: link setup only).

## Alternatives

- (b) User-space same-host delivery between croit-flashstore-osd processes (shared-memory rings or an abstract unix socket per peer): rejected (user decision 2026-10-21). It needs shm discovery, lifecycle and crash safety across processes, cross-process RSS/core steering and a second rx source in the core loop. The kernel path is needed anyway for non-croit-flashstore-osd endpoints, and same-host OSD traffic is small with failure domain host. The measured kernel path is not the bottleneck.
- (c) NIC hairpin without host config (second transport domain, mlx5 local loopback): measured negative on ice-a. 0 frames reach the kernel; the `loopback` feature is fixed off.
- (a) VF per OSD as the only answer: kept as the recommendation, not as the only answer. It needs SR-IOV, which not every host has (lab VMs with a passed-through PF have none). Mons and clients on the PF still need the PF's kernel stack, which works once each endpoint has its own MAC.
- Switch hairpin / reflective relay: needs switch config outside our control.
- tc / ntuple loopback: XSK tx frames bypass tc ingress.

## Open questions

- mlx5 on kernel 6.12 (ice labs) hashes RSS differently from the stack's Toeplitz model, in both the main table and RSS contexts. The NIC path to remote peers then misses SYN-ACK steering with more than one queue per OSD. This is a separate known issue (doc/perf/afxdp-20261015.md); the same-port gate runs one queue per OSD. Tracked in doc/90-open-questions.md (OQ 82).
