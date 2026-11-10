<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->

# 0659 IPv4, IPv6 and dual-stack addressing (croit-flashstore-osd)

Status: accepted
Status note: implemented: ms_bind_ipv4/ipv6/prefer_ipv4, lab/ipv6/dualstack.sh.
Date: 2026-11-05
Supersedes: the address-selection and "OSD core is IPv4-only" sentences of adr 0053
Amends: adr 0171 (source bind, am. 1)

## Context

Spec: doc/spec/ip-addressing.md (doc not in the source snapshot) (Ceph v21.2.0). Gap table with file:line:
doc/perf/ipv6-dual-stack-review-20261105.md (doc not in the source snapshot).

croit-flashstore-osd bound and advertised IPv4 only. In a dual-stack cluster classic Ceph advertises IPv6 entries first
(`ms_bind_prefer_ipv4=false`, spec 2.4), so every classic peer and every client addresses the OSD on IPv6 first. An
IPv4-only croit-flashstore-osd could not dial those peers: the link reconnected silently forever and the heartbeat then reported
healthy classic OSDs as failed (spec 4, review gaps 1/2). That violates prime safety ("never confuses classic OSDs").
IPv6-only clusters could not start the daemon at all.

## Decision

1. Families: `ms_bind_ipv4` (default true), `ms_bind_ipv6` (default false), `ms_bind_prefer_ipv4` (default false) select at
   most one address per family for public and cluster. Both false = startup error (spec 2).
2. Advertised addrvec order is spec 2.4: IPv6 entries first unless `ms_bind_prefer_ipv4`; heartbeat front/back carry the
   same families and order as public/cluster.
3. Address source per role: explicit `public_addr`/`cluster_addr` (any family, `[v6]:port`, `/nonce`), else one address
   per enabled family inside `public_network`/`cluster_network` (mixed v4/v6 CIDR lists, `*_network_interface` filter),
   else the `--ip` / route-towards-mon fallback. An enabled family without a matching network or address fails startup
   (no partial dual-stack, spec 2.2 mirror). A bare network without `/prefix` is a parse error (spec 2.2).
4. An explicit address advertises only its own family (spec 8: do not mirror the malformed second entry); the other
   family is added from a network for it. A role with both families enabled must end up with one address per family:
   otherwise startup fails (no partial dual-stack, spec 2.2).
5. Dial target: the first msgr2 entry of the peer addrvec (spec 4). If that entry is of a family we hold no address of,
   the first msgr2 entry of a family we do hold (dual-stack peers list both). If no advertised entry is reachable for
   us, the OSD does not dial at all and logs `cannot reach <addrvec>: no advertised address of a family we bind` once
   per peer addrvec. A peer is never reported failed for a family we cannot speak.
6. Source bind (adr 0171 am. 1): a dial binds the dialling messenger's own address of the target's family; with no such
   address the socket stays unbound. Never a cross-family source bind.
7. A failed dial is logged at level 0 (`dial <addr> failed (<reason>, <family>)`), once per peer purpose and family.
8. Listeners: one socket per addrvec entry, family = entry family, explicit addresses only. A v6 listener is
   `IPV6_V6ONLY` (no wildcard, no v4-mapped peers, spec 8). All entries of one listener kind share its port: classic
   scans each entry separately and usually lands on two ports; the addrvec with one port on both families is
   wire-equivalent.
9. Text and JSON forms follow spec 6 (compressed IPv6, `TYPE_ANY` without prefix, `TYPE_NONE` = `-`, `cidr:` prefix).
   `mon_host` follows spec 5 (typed/untyped single addresses, bracketed vectors, `/nonce`, hostnames resolved to all A
   and AAAA records; monitors without a msgr2 entry are skipped by the msgr2-only client instead of rejecting the list).
10. The own TCP stack (DPDK parked, AF_XDP deprecated, adr 0020/0005) stays IPv4-only: a v6 public/cluster address is
    refused at startup with a loud line instead of failing dials silently.
11. Out of scope, tracked in doc/90-open-questions.md (doc not in the source snapshot): `public_addrv`, MON-only
    `public_bind_addr` listen semantics, RDMA/RoCEv2 GID choice for v6 sessions, scope-id (link-local) targets.

## Rationale

The safety rule is not negotiable: a classic peer that is up must never be reported down because of a missing local
family. Choosing the peer's other advertised entry keeps Ceph's first-entry rule for every peer we can reach and only
departs where classic itself is broken (cross-family source bind, spec 4/8); the peer advertises that entry, so its
CLIENT_IDENT target check still passes. Binding explicit addresses and `IPV6_V6ONLY` keeps us out of Ceph's v4-mapped
wildcard quirk. Sharing one port per listener kind is the KISS choice: the family split of classic's per-entry port scan
is accidental, not semantic, and it avoids a port table per (kind, family) in the OSD config.

## Consequences

+ Dual-stack clusters (classic peers included) work with default Ceph ordering; IPv6-only clusters start.
+ A peer of a family we cannot speak costs one log line, not a failure report.
- `ms_bind_ipv6=true` with only an IPv4 network now fails startup (Ceph semantics, operator error made visible).
- A dual-stack daemon advertises the same port for both families (spec 3.2 would usually give two).
- The dev/file backend driver (`osd::kdrv`, lab) keeps its single-address path.

## Alternatives

- Stay IPv4-only: prime-safety violation in every default dual-stack cluster (rejected).
- Mirror spec 4 exactly (no family fallback): keeps the prime-safety bug, rejected for the OSD; a pure client keeps it.
- Bind one wildcard `[::]` socket for both families: takes v4-mapped peers (spec 8 says do not mirror), rejected.
- Per-entry port search (two ports per kind): extra state, no wire benefit, rejected.

## Open questions

- Should RDMA/RoCEv2 sessions of a v6 dial pick a GID by peer family (adr 0469)?
- Does any operator rely on `public_addrv` (MON only in v21.2.0)?
