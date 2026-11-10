<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0572 Exchange completed C READs for new admissions in one worker command

Status: accepted
Date: 2026-10-25

## Context

Measured public C placement submit/release spans total 69–101 us per batch in
configuration medians. Both calls synchronously hand borrowed metadata to the
same owner; the caller has already ended its old CPU accesses before release.
The full measurements and limitations live in the RDMA performance log.

## Decision

- An optional synchronous exchange releases all supplied old requests before
  admitting the supplied new requests in one ordinary FIFO worker command.
- Existing separate calls remain compatible. Exchange does not let new READs
  bypass earlier ordinary commands through the priority control queue.
- Metadata stays borrowed until reply; no new asynchronous pointer lifetime,
  payload copy, worker thread, lock or reply allocation policy is introduced.
- Release and admission have independent per-item results and no rollback.
  Quiescence, exact generations, range leases and shutdown publication remain
  the existing ownership boundary. Rustdoc defines the public contract.
- Adoption requires partial-error/alias/FIFO/ownership gates, independent C ABI,
  connected kernel/SPDK checks and a matched performance comparison.

## Rationale

One combined owner command can avoid a second synchronous round trip while
retaining the existing single-owner state transitions. Running all releases
first permits new admissions to reuse any successfully returned range.

## Consequences

- + No relaxed payload visibility, retirement or lifetime requirement.
- Siblings: the root cause is two synchronous C metadata handoffs. Transport,
  payload/wire, replicated/EC and storage implementations are unchanged. Both
  storage tiers have connected gates; RDMA-free and v20 ABI selections have
  independent build/ownership gates. This does not qualify secure/EC/GPU
  placement or additional networking backends.
- + Old applications keep the existing API and priority release behavior.
- - Exchange releases wait behind earlier ordinary commands as part of preserving
  admission FIFO. It is not an atomic all-or-nothing transaction.
- + Scoped CPU-memory adoption passes independent ABI/ownership/RXE and
  connected kernel/SPDK gates, with lower matched control cost. Evidence and
  configuration limits: performance log (doc not in the source snapshot).
- - End-to-end throughput is workload-dependent; the larger-depth SPDK case
  does not establish a general throughput advantage. GPU and release
  qualification remain separate.

## Alternatives

- Invoke the two public calls internally: retains two handoffs.
- Admit through the priority control queue: bypasses ordinary FIFO.
- New asynchronous borrowed-metadata completion model: expands lifetime/ownership
  contracts beyond the synchronous handoff cost measured here.

## Open questions

- Full post-advertisement C fault/retry/remap/resource qualification.
- Wider size/depth/offset and version/platform performance coverage.
- Dedicated nonproduction GPU import, revocation, visibility and integrity.
