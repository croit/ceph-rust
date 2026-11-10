<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0473 AF_XDP multi-queue: replies of own dials steered by port-class ntuple rules, not by an RSS model

Status: superseded by adr/0682-remove-afxdp-dpdk-networking.md (was: accepted, amended (am. 1, am. 2))
Status note: Superseded in part by adr 0020 deprecation and CLAUDE.md (AF_XDP deprecated: compile-only, out of the prod build, no new work, no lab cells): kernel TCP over io_uring (adr 0053) is the production transport.
Date: 2026-10-21

## Context

An own-stack OSD with several queues keeps a connection on one core. Its dials therefore pick a source port whose
replies the NIC delivers to the dialing core's queue. Until now the AF_XDP tier predicted that queue with `net::rss`
(Toeplitz, KEY_MS, equal table), and the operator programmed the kernel driver to match. On mlx5 with kernel 6.12
(ConnectX-4, ice labs), the NIC hashes the symmetric OR-XOR input `(s|d, s^d, sp|dp, sp^dp)` in the main table and in
RSS contexts. Measured: 44/44 and 40/40 probes, against 15/44 and 7/40 for the plain tuple
(doc/perf/afxdp-rss-612-20261021.md). ethtool still reports `symmetric-xor: off` (main) or raw 0xff (context). The
SYN-ACKs of dials land on other cores, the dials time out and I/O hangs (OQ 82). Kernel 7.0 mlx5 (rented CX-5) hashes
the plain tuple. Readback of the transform cannot be trusted, and an empirical hash probe needs a remote responder that
is not always there at start (e.g. the mon on the same port, adr 0472).

## Decision

- AF_XDP with `queues > 1`: the OSD installs one ntuple rule per local port class on its vdev's `iface`:
  TCP/IPv4, dst-ip = OSD IP (exact), dst-port `0xc000 | c` under mask `0xc000 | (P - 1)`, action = queue `start_queue + c % Q`.
  Here `P` = Q rounded up to a power of two (`net::rss::PortClass`, `rt::flowrule`).
- The stack's dials use only ports of their own core's class (`Steer::ports`). The ephemeral range is 49152..65535 and
  every port in it is classed. The RSS model no longer decides any local port.
- Listen ports (< 49152) match no class rule, so passive flows still spread by RSS (the operator's context rule or the main table). Every core accepts.
- The rules are verified by readback (ETHTOOL_GRXCLSRULE equals the installed spec). They go at the lowest free locations
  (highest priority on drivers that order by location; on mlx5, rules with more fields win anyway). They are deleted on exit.
  Rules of ours left by a crashed run (same IP, classed dst-port) are replaced at start.
- Capability is probed, never assumed. The start fails loud with the fix when ntuple is off, the table is full, or the
  NIC refuses masked dst-port rules: `ethtool -K IF ntuple on`, a NIC with masked ntuple rules, or `--queues 1`. There is no kernel or driver gate.
- At start the OSD logs `flow rules: N on IF (tcp4 dst-ip ..., queues a..b, locations [...])`. `steer_syn_miss` counts SYN-ACKs off their class's queue and logs the first 8 misses.
- The RSS model stays for:
  - the guess of a peer's queue in paired opens (a miss costs a relay hop, not correctness);
  - the DPDK PCI tier, where the PMD programs key and table itself (parked, adr 0005 am. 2).
- `--eal-arg --vdev net_af_xdp...,iface=X` feeds NIC-IRQ core placement and the host-net startup warnings the same way `--vdev-iface` does.

## Rationale

- Flow rules are an explicit hardware program that can be read back. A hash model is an assumption about undocumented
  driver behaviour, and readback (input_xfrm) lies on 6.12. Rules make the steering exact on any NIC that accepts
  them, independent of key, table, transform and kernel version.
- Zero per-packet cost: the NIC matches the rules. Rule count = P per OSD (4 or 8 typical; mlx5 has 1024 entries).
- Trade-off accepted: multi-queue AF_XDP now needs ntuple with masked TCP port matching. NICs without it run one queue
  per OSD (fail loud, documented fix) instead of trusting an unverifiable model.

## Consequences

- + ice labs (mlx5, 6.12) run AF_XDP with 4 queues per OSD (gate: lab/baremetal/afxdp-local-gate.sh NQ=4).
- + Kernel 7.0 and future driver hash changes cannot break steering.
- + The operator no longer has to program the KEY_MS key/table for correctness. xdp.sh still does, for the paired-open guess.
- - Paired opens (both ends on the owning core) still guess the peer's queue with the plain model: on 6.12 mlx5 peers
    the guess misses and the peer relays (as before; correctness unaffected).
- - The knet kernel tier models AF_XDP peers the same way (`--knet-peer-cores`, `listen::peer_rss`): an optimisation that misses on 6.12 peers, no stall.
- - The OSD writes ntuple rules on its port, scoped to its own IP and queues. `xdp.sh down` and the OSD exit remove them.
- - Placement from `iface=` (am. of adr 0472 behaviour): the xdp.sh ctx layout pins each OSD's queue IRQs onto its own cores.
    That OSD now logs the NIC-IRQ share warning, and the host-net warnings of that port. Its cpus are unchanged (explicit lcores skip placement); an OSD with a larger affinity mask now avoids the port's IRQ cpus.
- Rule locations (am. 1, 2026-10-21): a driver that announces `RX_CLS_LOC_SPECIAL` (bnxt) places rules itself: the OSD sends `RX_CLS_LOC_ANY`, as `ethtool -N` does. bnxt answers EINVAL to any explicit location; with ANY it accepts the masked dst-port rules but does not steer by the mask (OQ 86: multi-queue AF_XDP on bnxt stays open, the bnxt cells run one queue) (zen4 BCM57508 VF, kernel 6.12: `lab/baremetal/ntuple-probe.sh`); explicit lowest-free locations stay for table drivers (mlx5). Test: `rt::flowrule` `locations_follow_the_driver_announcement`.
- Peer classes (am. 2, 2026-10-25): a relayed inbound peer link lands by RSS on a random queue and, on 4M writes, shares
  that core with a client link 1 of Q times (doc/perf/afxdp-4m-cores-20261025.md). The passive side now installs one
  src-port rule per peer class: value `0xc000 | c << 6`, mask `0xc000 | (P-1) << 6`, queue `c mod Q`
  (`PortClass::peer_rules`, P = classes, `PEER_SHIFT` = 6, P <= 64). Bits 0..5 stay the reply class (dst-port rules
  of the dialer's own host), bits 6.. the peer class, so one dial port satisfies both: the dialer picks a port whose
  reply class is its owner core and whose peer class is the remote owner core (`steer_remote_ok`,
  `PortClass::peer_queue_of`). Peer rules are installed all-or-none after the reply rules; a NIC that refuses them
  logs `WARNING flow rules: no peer classes` and keeps the relay (adr 0054), never fatal. Start line:
  `flow rules: N peer classes`. Client links whose ephemeral source port is >= 0xc000 also land by peer class
  instead of RSS; accepted links stay on their landing core either way, the spread stays uniform. Tests: `net::rss` `peer_classes_are_independent_of_reply_classes`, `rt::flowrule`
  `peer_rules_match_the_source_port`.
- VLAN-tagged port (`--vlan`, rx-vlan-offload off; OQ 84): the rules carry no VLAN match (no FLOW_EXT). mlx5 (kernel source `en_fs_ethtool.c`) parses ip/tcp past the 802.1Q tag and treats cvlan_tag as don't-care without FLOW_EXT, so tagged frames hit the rules; its FLOW_EXT form accepts only a VID-exact match (`vlan_tci` mask 0x0fff, `vlan_etype` mask 0). bnxt refuses every FLOW_EXT rule (EOPNOTSUPP), so a vlan_tci match would break that NIC and gains nothing on a port that carries one VLAN. Hardware proof = rented `bench3.sh afxdp-check` (per-OSD `flow rules:` line, 0 `net: steer miss`, `rx_xsk_packets` > 0): a mismatch shows as steer misses and unreachable peers. Test: `rt::flowrule` `rules_are_vlan_agnostic_and_ext_rules_foreign`. If the hardware check ever fails, the fix is the FLOW_EXT/vlan_tci form (mlx5 only), probed at install.

## Alternatives

- Model the OR-XOR transform when detected: detection needs readback (wrong on 6.12) or a probe against a remote
  responder (none at start when the mon shares the port); a driver quirk table is a version gate.
- Read the real hash via the XDP rx-hash metadata kfunc (`bpf_xdp_metadata_rx_hash`): it gives the hash of received
  frames only. The source port must be chosen before the first reply exists, and it needs a custom XDP program in the PMD.
- Choose ports valid under both models: 1/Q² of the ports qualify and paired opens become impossible. The model set is still a guess.
- One queue per OSD on 6.12: a kernel-specific special case (no workarounds).
- Move dialed peer session sockets off cores with client links (outbound relay pipe, 2026-10-26): no w4m8 gain, slow rounds stay (doc/perf/afxdp-collision-20261026.md).
- Relay misdirected SYN-ACKs between cores: a software dispatcher on the hot path, against adr 0006/0031.

## Open questions

- Answered by am. 2 (peer classes). Open: knet dialers to AF_XDP peers (`listen::peer_rss`) still use the RSS model; they could pick a peer-class port instead.
