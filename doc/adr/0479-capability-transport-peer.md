<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0479 Capability CIDRs use the transport peer

Status: accepted
Date: 2026-10-21

## Context

Clients choose their CLIENT_IDENT advertised addresses. Capability network grants require the peer socket address (spec/osdcaps.md section 4).

## Decision

croit-flashstore-osd carries the accepted transport source separately from the advertised client identity in ConnInfo and ClientReq, including cross-core forwarding.
Ordinary operation and direct EC read capability checks use only that transport source.
Blocklist and watch identity continue using the advertised address.

## Rationale

Authentication proves client identity and capabilities, not ownership of an advertised IP. Reusing one address for identity and authorization allows CIDR bypass.

## Consequences

- + Forged advertisements cannot widen a network grant.
- + One authorization source across kernel TCP, AF_XDP, CRC/secure, replicated/EC and storage tiers.
- - Internal request constructors carry an additional address; unrestricted internal requests do not consult it.

## Alternatives

- Compare advertised and socket addresses: rejects legitimate identity/transport differences and conflates independent contracts.
