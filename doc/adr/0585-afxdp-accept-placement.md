<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0585 AF_XDP accepted client links placed by connection count: SYN handoff + frame forwarding by the landing core

Status: superseded by adr/0682-remove-afxdp-dpdk-networking.md (was: proposed)
Status note: Superseded in part by adr 0020 deprecation and CLAUDE.md (AF_XDP deprecated: compile-only, out of the prod build, no new work, no lab cells): kernel TCP over io_uring (adr 0053) is the production transport.
Date: 2026-10-26
Amends: 0054

## Context

An own-stack OSD keeps every TCP flow on the core whose NIC queue receives it. Accepted client links land where the NIC
puts the SYN: RSS, or a peer-class rule when the client's source port is >= 0xc000 (adr 0473 am. 2). With one client
and 4 queues, the client link lands on the core that owns the replica session 1 of 4 times; client rx and replica tx
then share one core and a 4M write runs at ~55-60 % of the uncollided rate (doc/perf/afxdp-4m-cores-20261025.md, OQ 88).
knet already places public links by connection count at accept (`KPlace`).

## Decision

- AF_XDP with `queues > 1`: a SYN to the public port (IPv4) that finds no flow is not answered on the landing core. The
  landing core picks the target core = the network core with the fewest TCP connections (ties stay on the landing core;
  scan starts after it, as `KPlace::pick`).
- Target = landing core: the SYN is processed there; nothing else changes for the flow.
- Target = other core: the landing core records the tuple as handed to the target and sends a copy of the SYN frame to
  it (`rt::place`, connect-time channel). The target answers it and owns the flow.
- Every later frame of a handed tuple still arrives on the landing core (no NIC rule per connection). The landing core
  verifies the IP and TCP checksums, finds the tuple handed, and passes the frame (mbuf reference, no copy) to the
  owner over a per-core-pair SPSC frame ring (`rt::mesh`, `FWD_RING` = 4096 slots); the owner feeds it to its stack as
  checksum-verified. Duplicate SYNs and stray segments are forwarded too: the landing core never answers a handed tuple.
- Ring full: the frame is dropped and counted (`fwd_drop`); TCP retransmits it, as after a full NIC queue.
- Load = TCP connections a network core owns (accepted + dialed: clients, mon, mgr, peers, relay landings) plus SYNs
  handed to it that it has not accepted or dropped yet. One atomic counter per core, read at SYN time only.
- Only the public listener is placed. Cluster / heartbeat links keep their placement (peer-class rules, relay, adr
  0054). IPv6 SYNs and the same-host kernel path (adr 0472) are not placed.
- Tuple lifetime: the owner reports when the flow leaves its stack (closed, reset, TIME_WAIT over, embryo dropped, or no
  flow came of the SYN: backlog full, no cookie for a placed SYN) and the landing core forgets the tuple.
- Always on for AF_XDP with several queues; no knob. Start line `croit-flashstore-osd: place: client links by connection count over N
  network cores (frames forwarded by the landing core)`; exit line per core
  `place: here=.. away=.. adopted=.. owned_now=.. fwd_out=.. fwd_drop=.. fwd_in=..`.

## Rationale

- Per-connection NIC rules were built, measured and rejected (numbers: doc/perf/afxdp-place-20261026.md, "Per-connection rules"): rule install latency and the port's rule table (1024 entries on mlx5, shared by the OSDs on the port) cap placed links far below a restart storm of 1000+ clients. Forwarding has neither limit: placement state is one hash map entry per handed link on each of the two cores.
- No connect latency: the SYN handoff is an in-memory message (microseconds).
- Cost only where it pays: a link is handed only when its landing core is busier than another core; then the landing
  core keeps the per-frame driver work and the checksum (verified once, not again on the owner) and the owner does TCP,
  msgr2, crc and the OSD work. Without forwarding, the collided core does all of it.
- Coarse per-port / per-queue rules plus in-software steering of single flows is how AF_XDP stacks steer
  (DPDK AF_XDP PMD, AF_XDP zero-copy design); per-connection hardware rules are not.
- Connection count is what knet uses (`KPlace`); it removes the dominant effect (two busy links on one core while others
  idle) without a measurement loop. Peer, mon and mgr links count, so a client avoids the replica-session core.

## Consequences

- + One client per OSD no longer shares the replica-session core's whole receive path (OQ 88 item 1).
- + knet and AF_XDP place client links by the same rule; no NIC capacity limit, no connect latency.
- - A handed link costs the landing core the driver receive work, the checksum and one ring push per frame; the owner
    pays a ring pop. Measured in doc/perf/afxdp-place-20261026.md.
- - DPDK PCI tier (parked) and single-queue AF_XDP: placement off (as before).
- - Siblings: knet places by count already (`KPlace`, kernel moves the socket); RDMA upgrades knet sessions; SPDK /
    kernel NVMe, rep / EC, crc / secure: transport only, not affected.

## Alternatives

- Exact 5-tuple ntuple rule per placed link, installed before the SYN-ACK: built and measured, rejected (Rationale).
- The same rule installed asynchronously on a control thread with forwarding until it lands: removes the connect
  latency but keeps the table capacity limit and adds a second steering path; only worth it if the forwarding cost
  shows in a measurement.
- Peer-class rules only, client links by RSS (main before this ADR): bimodal 4M writes with one client (OQ 88).
- Choose the queue by peer-class source port on the client: the client is not ours (librados / kernel rbd).

## Open questions

- Weigh placement by recent bytes instead of connection count (knet has the same open point, OQ 98).
- Forwarding hop cost (doc/perf/afxdp-place-20261026.md, A/B 2): the landing core still saturates on a client landing on the replica-session core, 4M writes stay bimodal; only the NIC steering the frames removes the landing cost. Open: hybrid with an asynchronous exact rule for hot links only.
