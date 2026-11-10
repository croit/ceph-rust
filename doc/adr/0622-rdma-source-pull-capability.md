<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0622 Negotiate object source-pull separately

Status: accepted
Date: 2026-10-28

## Context

Existing placement and READ-depth offers describe different contracts and do
not authorize a new object source-pull protocol. Unknown control records fault
older peers. Pinned banner evidence is in the source-pull specification.

## Decision

Assign optional MSGR2 supported bit 60 to object source-pull. Advertise it only
when RDMA and the separately configured object capability are enabled; both
peers, READY and a completed RDMA upgrade are required. Default remains off.
A banner does not authorize memory, imply READ depths, install operation
handlers or prove retirement. Rustdoc owns the configuration and connection API.

## Rationale

Separate optional negotiation prevents placement or a QP resource offer from
being mistaken for object-protocol support. Pinned-source inspection shows the
bit is unused in the MSGR2 namespace and unknown supported-only bits pass the
inspected checks; live mixed-peer evidence remains necessary.

## Consequences

- + One-sided, declined and closed connections do not enable the capability.
- - The object protocol, proof routing and provider qualification remain open.
- - Classic-peer runtime and both version compatibility require live evidence.

## Alternatives

- Reinterpret placement or READ depth: neither proves object protocol support.
- Make the bit required: incompatible with peers that lack the extension.

## Open questions

- Which exact authenticated records and provider budgets enable production use?
