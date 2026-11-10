<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0470 RDMA operations: RoCEv2 on the TCP netdev, path MTU 4096, DSCP 26 lossless class recommended

Status: accepted
Status note: implemented: crates/hwcheck rdma section, fixed RoCE TOS.
Date: 2026-10-19

## Context

0469-rdma-transport upgrades a msgr2/TCP connection to an RC QP and binds the QP's GID to the TCP connection's addresses. Operators need to know which device, addresses, MTU and QoS settings an RDMA deployment requires, and how croit-flashstore-osd reports a wrong setup. adr 0030 forbids ad-hoc IPs, VLAN subinterfaces and promiscuous mode on VFs. Measured on ice-b (ConnectX-4 PF passthrough, doc/perf/rdma-spike-20261019.md sections 4-5) with a switch class PFC prio 3 no-drop, DSCP 26 -> TC3, ECN on queue 3.

## Decision

- RDMA device = the RDMA device whose netdev carries the IP of the msgr2 connection (public or cluster address). croit-flashstore-osd adds no IP, VLAN or GID of its own.
- GID = the RoCEv2 GID of that IP (IPv4-mapped or IPv6). No RoCEv2 GID on the netdev: RDMA stays off for that address, cluster-log warning, connections stay TCP.
- RoCEv1 is not supported.
- RoCE path MTU >= 1024 is required (netdev MTU >= 1120; standard 1500 gives 1024), 4096 is recommended (netdev MTU >= 4192, 9000 jumbo on the whole path); the QP uses the smaller of both ends (am. 1). Below 1024: RDMA stays off for that device, cluster-log warning. 4096 stays required for RDMA READ (adr 0471).
- Recommended fabric class: PFC on one priority (default 3), DSCP trust on NIC and switch, RoCE TOS = DSCP 26 + ECT0 (106), ECN marking on that switch queue, DCQCN on the NIC (mlx5 firmware default). Global pause off on the RDMA netdev when PFC is on.
- Lossy fabric (no PFC) is supported: RoCE TOS must then map to a queue that is not no-drop. Large streams on a lossy fabric need ECN marking on the RoCE queue (DCQCN) or PFC (am. 2).
- RoCE TOS is fixed at 106 (`hwcheck::RDMA_DEFAULT_TOS`, no config option), applied to every QP. TCP traffic (mon, heartbeats, classic peers) keeps its own DSCP; croit-flashstore-osd never puts TCP into the RoCE class.
- croit-flashstore-osd never changes host network state: no MTU, PFC, DSCP trust, pause or DCQCN changes. It reads and reports them.
- PF and VF are both allowed as RDMA device. On a VF the IP must be configured by the operator per adr 0030; croit-flashstore-osd adds none.
- `croit-flashstore-osd --check` (adr 0166) gets an RDMA section; every item reports OK/WARN/FAIL/N/A with value, why and fix:
  - RDMA device present for the configured netdev, port ACTIVE, link layer Ethernet;
  - RoCEv2 GID for the configured IP;
  - port active MTU: OK at 4096 (netdev MTU >= 4192), WARN from 1024 with the fix `ip link set <netdev> mtu 9000`, WARN (RDMA off) below;
  - PFC per priority, global pause, DSCP trust and the DSCP -> priority mapping for the configured TOS (WARN on a lossy setup and on PFC on with global pause on);
  - DCQCN enabled for the RoCE priority (the priority the TOS maps to);
  - RoCE loss: recorded drops (out-of-sequence, sequence errors, ACK timeouts) without ECN marks -> WARN with the lossless-class fix; drops although the switches mark ECN -> WARN (am. 2);
  - type-2 MW allocation (placement possible yes/no);
  - `RLIMIT_MEMLOCK` covers the configured registered memory;
  - PCIe link width/speed at capability.
- Runtime: a transport that cannot upgrade because of these conditions logs one line per device with the failing condition and raises one cluster-log warning; it never retries in a loop.

## Rationale

- Binding to the TCP netdev's IP gives RoCEv2 routing, ECN and DCQCN without extra addressing, and reuses the peer-address check of the transport ADR.
- RoCEv1 has no ECN/DCQCN and needs PFC everywhere; RoCEv2 covers every lab and target layout with an IP.
- Path MTU 4096: READ at 1024 collapses to 1.2-2.5 GB/s lossy or 6.5 GB/s with PFC; at 4096 READ/WRITE/SEND reach 12.2 GB/s with 0 drops (measured).
- Lossless class: 0 drops, 0 out-of-sequence, pause frames only on prio 3, confirmed by switch and NIC counters over a full run (measured). Lossy at 4096: 6e-6 out-of-sequence, -0.5 % throughput (measured).
- DSCP 26 with PFC off on the NIC overflowed the switch no-drop queue (105 tail drops, measured): the TOS and the NIC PFC state must agree, so `--check` verifies them together.
- croit-flashstore-osd changing host network state would affect other tenants of the NIC (adr 0030); reporting keeps the operator in control.

## Consequences

- + One rule for addressing: wherever TCP works with an IP on an RDMA netdev, RDMA can work.
- + Admins get a single read-only check with fixes for every RDMA prerequisite.
- + No new host network mutation by the daemon.
- - Jumbo MTU on the whole RoCE path is mandatory.
- - Layouts whose netdev has no IP (adr 0038 address-less PMD netdev) get no RDMA.
- - The lossless class needs switch configuration the project does not own.

## Alternatives

- RoCEv1 link-local GIDs for address-less netdevs: needs PFC on every hop, no congestion control.
- croit-flashstore-osd configures DCB/MTU itself: mutates shared NIC state, conflicts with adr 0030.
- Path MTU 1024 for small-message latency (4K SEND p50 5.0 us vs 5.7 us): READ collapse outweighs it.

## Amendments

- am. 1 (2026-10-20): path MTU 1024 and 2048 are accepted with a `--check` WARN, 4096 stays the recommendation. Reason: the transport uses SEND only, so the READ collapse at 1024 (Rationale) does not apply, and RDMA must work on standard 1500 networks. The endpoint record carries the sender's active MTU (spec msgr2 RDMA_UPGRADE, 4 optional trailing bytes); the QP path MTU is the minimum of both ends. A record without the field (older version) counts as 4096 and is refused (stays TCP) when the local port is below 4096. Netdev minimum for 1024 is 1120 (path MTU + 96, as 4192 for 4096; to verify per NIC). RDMA READ / placement (adr 0471) keeps requiring 4096. Measurement: doc/perf/rdma-spike-20261019.md "MTU 1500".

- am. 2 (2026-10-21): large streams on a lossy fabric need PFC or ECN marking. A lossy RoCE path drops at the receiving NIC when many sessions stream into one port; every drop costs an RC go-back-N resend of the in-flight window and a DCQCN rate cut (the NIC sends a CNP on a detected drop). The transport does not compensate: no fixed window ceiling is better on a lossy fabric without being worse for a single stream, and a ceiling from the number of active sessions is a load-based switch; the QP ACK timeout does not matter (recovery is NAK-driven). `--check` gets the RoCE loss item above; an OSD with RDMA on logs the fabric WARNs at start. Measurement: doc/perf/rdma-lossy-20261021.md.
- am. 3 (2026-10-25): RoCE TOS is fixed 106 (no `flashstore_rdma_tos` option); `--check` PFC + global pause = WARN (code: `hwcheck/src/rdma.rs`).

## Open questions

- Receiver-driven in-flight bound per RDMA device (sum of all sessions' grants sized from line rate x round trip, IRN's BDP flow control): fixed and load-independent; needs design and A/B (doc/perf/rdma-lossy-20261021.md, Open).
- RDMA with the AF_XDP tier: does the netdev carry the OSD IP in the AF_XDP layout, and does the XDP program pass UDP 4791? (design 1b coexistence)
- RoCEv2 GIDs on bnxt_re VFs and VLAN netdevs: not yet measured two-host.
- PFC watchdog setting on the switch for production.
- ECN threshold for incast (150 KB min on the lab switch never reached with one QP at MTU 4096).
- Config option names: enable flag `flashstore_rdma` and registered memory `flashstore_rdma_memory` are fixed (transport ADR). RoCE TOS has no option (fixed 106).
