<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0464 knet: io_uring zero-copy receive (zcrx) is a supported receive path

Status: accepted; am. 1 (2026-10-26): phase 1 implemented and merged default-off (`--knet-zcrx auto` = opt-in) until a bare-metal A/B (bnxt PF or ConnectX-7, kernel with RECV_ZC) measures a gain: gain -> default `auto`, no gain -> code removed. Fallback gate green on 6.12, nodev tests green on 7.2.9; no lab NIC can register an ifq
Date: 2026-10-19
Amends: 0053

## Context

adr 0053 listed zcrx as "not available" (kernel >= 6.15 plus header/data split NIC). The user decided 2026-10-19: zcrx is not too new and belongs in the knet design. The kernel copy is the largest remaining per-byte cost of the kernel tier (adr 0053 4M receive path). Details, kernel facts and flow: doc/spec/knet-zcrx.md.

## Decision

- knet supports `IORING_OP_RECV_ZC` on a core ring with one ifq per (core, own NIC rx queue). Per queue, with clean fallback to the existing copy receive.
- Support is detected only by probing the capability (io_uring probe, ring flags, real ifq/area registration and its errors, ethtool/netlink queries). Never by kernel version: distros backport. Versions are informational ("mainline since") in docs.
- Baseline is a modern kernel on the OSD host. No legacy engineering; the single fallback is the copy path (needed anyway for NICs without HDS, bonds, VLANs, VMs). Startup line and `hwcheck zcrx` state loudly which capability is missing and print the exact fix command.
- Local socket policy only: nothing changes on the wire. Clients (RHEL-class kernels, krbd, librados, rustyrados on mio/epoll) are never affected and need no modern kernel.
- Data segments >= a start-derived `lease_min` stay in area fragments (crc computed in place, consumed by the store's fused copy+crc into the DMA buffer, then refilled); small frames and anything the memory envelope refuses are copied out and refilled at once. Secure mode decrypts out of place (the decrypt is the copy). Leased bytes are charged to the adr 0175 ingress pools; pressure degrades to copy, never stalls.
- NIC state (HDS, channels, ring sizes, ntuple, RSS exclusion, flow rules, IRQ affinity) is host-owned: warn with exact commands, never changed by the OSD. The OSD owns ring, ifq, area, lease, rcvbuf, accept placement by NAPI id. Phase 1: accepted connections only; dialed links use copy.
- Send side: zero copy (SEND_ZC, MSG_ZEROCOPY) for large payload segments on a real NIC, copy for small frames and loopback/veth; threshold derived at start, not a constant.

## Rationale

- Removes the kernel copy (one DRAM read+write pass per byte) without leaving the kernel stack: no NIC ownership, host kernel keeps routing (adr 0053 rationale).
- Probing is the only reliable signal across backports; a failed probe costs nothing because the copy path is the default.
- Host NIC state is shared with other daemons; AGENTS.md rule: warn, do not change.

## Consequences

- + Receive per byte drops by the kernel copy on zcrx queues (to be measured, doc/perf/); secure mode saves the same.
- - One exclusive rx queue per zcrx core: dense hosts have fewer queues than cores, so only some cores use zcrx.
- - Needs a payload type that can hold a chain of fragments between receive and the DMA copy (adr 0033 `Bytes` stays for everything else, flatten = one counted copy).
- - zcrx cores need `DEFER_TASKRUN` + `CQE_MIXED`; payload on a zcrx queue is unreadable for tcpdump/BPF and plain `recv`.
- - Ifq loss (queue restart) resets the affected connections.

## Alternatives

- Version gate (>= 6.15): rejected, backports and false negatives.
- Copy only: leaves the largest per-byte cost of the kernel tier.
- OSD installs ntuple/RSS rules: rejected as default (shared NIC state); opt-in variant is OQ 77.
- Larger socket rcvbuf/hardware GRO only: no copy removal.

## Open questions

- NIC state (HDS, channels, rings, ntuple, RSS exclusion, IRQ affinity) is host-owned: `hwcheck zcrx` and the startup line print the exact commands; an operator helper (`croit-flashstore-tool host-tune`, separate from the OSD) applies exactly these commands on explicit request (dry run by default, `--apply`, `--revert`); the OSD owns only ring, ifq, area, leases, rcvbuf and accept placement.
- OQ 77: dialed links, lab verification, rope scope (doc/spec/knet-zcrx.md section 11).

## Amendment 1 (2026-10-26): phase 1 implementation

Decision (current state; raw evidence doc/perf/knet-zcrx-20261026.md):
- Separate zcrx ring per core (`SINGLE_ISSUER | DEFER_TASKRUN | TASKRUN_FLAG | CQE32`, own eventfd that the knet ring reads before an idle sleep) next to the unchanged knet ring. The copy path and its ring setup stay byte-for-byte as without zcrx.
- Probe chain at start, first missing piece wins and is printed once (`croit-flashstore-osd: zcrx=off reason=<r> <detail> fix: <command>`): `default-off` (no `--knet-zcrx`: nothing probed, fix names the opt-in `--knet-zcrx auto`), `disabled`, `no-ring-flags`, `no-op`, `virtual-netdev`, `nic-query`, `no-hds`, `no-steering`, `shared-queue`, `queue-busy`; per core at registration: `no-queue-left`, `no-queue-api` (EOPNOTSUPP: VFs, virtio), `no-cap` (EPERM), `memlock`, `area-alloc`, `refused`. A VF is named in the detail, but only the registration decides. Each refusal leaves that core (or the OSD) on the copy receive.
- Steering safety: a queue qualifies only if it is outside the default RSS table and every flow rule reaching it matches exactly the OSD public port (TCP dst, full mask). Accepted connections are placed on the core whose queue has their `SO_INCOMING_NAPI_ID` (placement group, `--knet-balance on`); only those use `RECV_ZC`, all others copy.
- Phase 1 delivery: fragments are copied out of the area (small frames into the decoder, data segments into the lent segment buffer with the crc while cache hot) and refilled in the same loop iteration; one refill tail publish per iteration. This removes `recvmsg`, hardened usercopy and per-piece receive requests, not the payload copy. Leases exist only for throttled input, bounded by a per-core lease budget = area - (NIC rx ring x chunk + `tcp_rmem` max); beyond it fragments are copied out at once; a connection holding its receive queue's worth stops its receive (TCP backpressure, as the copy path).
- Area per queue = 2 x (NIC rx ring x 4 KiB + `tcp_rmem` max), capped at 32768 chunks; transport memory like the buffer ring, not drawn from the ingress pools (phase 1 hands no area bytes to the OSD).
- Runtime faults never cost a connection: data outside the area (queue restart, NIC reset, ifq unbound) is copied into the area by the kernel; `ENOMEM`/`ENOSPC` re-arm after the next refill. A multishot `RECV_ZC` that runs short of chunks or completion space after a partial read posts nothing and waits for the next socket wakeup (none comes once the peer has sent everything; found on 7.2.9 with nodev): the completion queue holds 2 completions per area chunk, and a reap that leaves fewer free chunks than the page pool's share restarts every armed receive (cancel, re-arm) after the refill. Only `EFAULT` (fragment of another ifq = wrong host steering, excluded by the probe) ends a connection, like any socket error. Supersedes the consequence "ifq loss resets the affected connections".
- zcrx connections decline the RDMA upgrade (krdma candidate filter).
- `--knet-zcrx nodev` (lab builds only): device-less ifq on every core (`ZCRX_REG_NODEV`), every accepted connection through `RECV_ZC`, the kernel copies into the area: functional test of the whole path on any zcrx kernel.

Rationale: holding area fragments until the store's DMA copy needs the chain payload type (spec section 3, O4); without it a lease only pins area memory and adds the refill latency, so phase 1 takes the cheap part (no kernel copy path, no per-piece receives) with the fused copy+crc it already has. The separate ring keeps the fallback path untouched and does not depend on the knet ring's taskrun mode.

Open questions: gain unmeasured (no lab NIC registers an ifq: CX-4 has no header split, bnxt VFs have no queue API, build host is virtio); phase 2 (rope payload, O4); host-tune with several OSDs per NIC (one RSS context per public port).
