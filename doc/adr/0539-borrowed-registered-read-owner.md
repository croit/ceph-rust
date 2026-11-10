<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0539 Registered lease progress borrows the native transport

Status: accepted
Date: 2026-10-25

## Context

RegisteredReadClient owns a native Client and drains its whole logical completion
queue. The C worker also owns one Client and routes its results to ordinary,
watch, notification and listing consumers. Wrapping that client would consume
results intended for those existing consumers.

## Decision

- A bounded RegisteredReadOwner retains registered destinations, attempts and
  pending logical results independently of Client ownership.
- It borrows its original native Client for admission and lease progress; the
  existing unique registration-budget identity rejects a different client.
- Lease progress drains neither provider lease events nor logical application
  completions. The single native dispatcher routes lease events first and then
  logical results; unowned exact tokens/attempts return unchanged.
- RegisteredReadClient remains a convenience wrapper with its existing public
  behavior, using the same lease engine and its own logical queue drain.
- Setup reserves metadata outside READ progress. Moves transfer payload owners;
  no new payload staging, clone, registration or checksum pass is introduced.
- A pre-reserved TID index locates dense lease jobs; matching still requires the
  complete queue-local token and provider attempt identity. Dense removals repair
  both the index and the runnable-position backreferences.
- Progress visits only locally runnable leases. Sent windows wait for provider
  events; returned destinations resume progress so a pending logical retry can
  bind again. Terminal quarantines wait only for result consumption.
- Existing BIND, peer proof, LOCAL_INV, retry, cancellation and quarantine rules
  apply to both dispatch arrangements. GPU memory remains outside host contracts.

## Rationale

The C worker already routes completions from its single native client to several
consumers. A borrowed lease owner fits that boundary without another connection,
reactor or thread. Reusing the existing budget Arc identity detects client mixups
without another identity allocation or a hot-path lock.

## Consequences

- + Ordinary and registered results can share one native progress loop.
- + The qualified destination and provider state machine remains common.
- - The embedding dispatcher must drive lease progress and feed owned logical
  completions; it drains each native result stream once and handles unowned events.
- - Routing cost and bounded metadata behavior require affected tests and
  measurement before the final performance gate.

## Alternatives

- Wrap the C client's transport: its ordinary completions would be stolen.
- A second client/connection/thread: duplicates setup and changes ordering and
  session ownership rather than solving dispatch within the existing client.
- Partition core completion queues by inspecting current flights: flights may
  already have retired before completion consumption.

## Open questions

- Broader C retained-host request/batch fault, shutdown and resource qualification.
- Deep-queue dispatch/refcount/CPU costs and complete fault qualification.
