<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0502 EC split reads have one logical completion owner

Status: accepted
Date: 2026-10-22

## Context

The v21 split-read pool flag permits a read to span independent data shards.
Independent successful replies can describe different object versions. A split
must retain application ownership while validating all participating shards
(split-read-contract.md, ec-split-version-contract.md). The v20 client has no
split-read wire op; v21's replicated split implementation is unreachable behind
its explicit non-erasure rejection, not an application feature to reproduce.

## Decision

- The original engine token, deadline, admission charge and completion remain
  the parent owner. Child requests have distinct messenger identities and no
  independent application completion or timeout.
- Capture one placement/geometry proof and canonical acting shard order. Child
  data ops preserve logical offsets/lengths; metadata ops go to the primary
  reference. Append GET_INTERNAL_VERSIONS to each child.
- The engine owns child reply validation and assembly. The shared coordinator
  owns transport admission, session leases and child wire-identity lookup.
- Merge data in ascending logical offset. Keep per-op outputs and status
  separate from internal version metadata; expose no internal op to callers.
- Publish once, after every successful child's version matches the reference's
  recorded version for that shard. Deterministic hard errors precede EAGAIN;
  EAGAIN or a version mismatch returns the whole original read to the primary.
- Interval/session changes invalidate the whole split. Resend preserves the
  original deadline and the C1 barrier; late child replies cannot publish.
- Cancellation, expiry and close release every child alias, reply and lease.
  Child population follows actual shard participation, without a fixed cap.
- Class mutations remain one primary transaction. Conservative mutation
  ownership cannot be split merely because a read-API flag was used.

## Rationale

One parent owner avoids duplicate completions, extended deadlines and partial
caller output. A reference version map prevents mixing shards across object
updates. Canonical shard identities preserve nonidentity chunk mappings and
missing acting slots. Shared coordination covers all native transports and ABI
adapters without allocating additional public operation slots.

## Consequences

- Parent output is a typed logical aggregate of validated replies, not a
  fabricated OSD wire reply. Internal metadata never appears in public results.
- Kernel TCP, io_uring and RDMA use the same fanout and cleanup. C/C++, sync/async
  preserve their existing buffer, version and completion publication contracts.
- Replicated reads retain their reachable balance/localize behavior. No dormant
  replica-split implementation or new enable switch is introduced.

## Alternatives

- Publish as children complete: exposes partial or mixed-version reads.
- Reuse one wire identity across shards: makes stale replies ambiguous.
- Give each child an application slot/completion: breaks ownership and pressure
  semantics, and can deadlock a parent behind its own occupied slot.

## Open questions

None for the ownership decision. Live parity remains a lead-run release gate.
