<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0617 Immutable shared host RDMA READ sources

Status: accepted
Date: 2026-10-27

## Context

Store payloads are immutable shared `Bytes`, including kernel `KBuf::into_shared`
owners. Existing host source windows consume an exclusive writable destination.
Their foreign allocation contract cannot describe simultaneous store/CPU readers.
Copying payloads into exclusive source storage adds avoidable work.

## Decision

Register immutable `Bytes` directly on the control path with MW_BIND only.
Retain the exact original payload owner; never export the parent rkey.
Expose prepared/local/advertised immutable source types without a conversion to
public `HostDestination` or `UnboundWindow`.
Keep a private immutable parent variant in the existing window owner; its typed
wrapper never exposes writable access. Common BIND rejects WRITE on that parent.
Reuse the existing READ-only source BIND/peer-retirement/LOCAL_INV state machine.
Recover or release registration only after successful retirement; provider
uncertainty retains it. Remaining immutable CPU aliases need not end to release
registration because their own `Bytes` ownership preserves the allocation.
Rustdoc in `rdma::verbs::{PreparedReadSource,LocalSharedReadSource,
AdvertisedSharedReadSource}` owns the API behavior.

## Rationale

Immutable sharing matches the store's actual ownership and requires no false
exclusive-memory promise. READ grants cannot mutate bytes observed by aliases.
The existing window owner already implements the required retirement rules;
typed wrappers retain that state machine without broad public generic changes.
The [rdma-core MR contract](https://github.com/linux-rdma/rdma-core/blob/master/libibverbs/man/ibv_reg_mr.3)
defines MW_BIND independently of local/remote writes. Its
[MW contract](https://github.com/linux-rdma/rdma-core/blob/master/libibverbs/man/ibv_bind_mw.3)
requires local write permission for remote WRITE/atomic, not remote READ, and
directs type-2 users to post BIND WRs. Actual provider qualification is separate.

## Consequences

- + Store payload ownership can survive export without a payload copy.
- + Immutable aliases can coexist with peer READs and survive deregistration.
- + Rebinding reuses the registration/window and prepared completion metadata.
- - Registration/window preparation remains a cold operation, not a per-op task.
- - Internal parent storage has an immutable variant; all public transitions must
  preserve the source/destination type barrier.
- - Object/wire integration, pool admission, bounded fault reclamation and GPU
  export/visibility/integrity remain separate requirements.

## Alternatives

- Copy into an exclusive Vec: adds a payload copy and staging ownership.
- Reuse ForeignHostAllocation for shared Bytes: violates its exclusive contract.
- Duplicate BIND/retirement machinery: creates divergent safety rules.
- Generalize every existing public window type: broad unrelated API changes.

## Open questions

- Which cold pool and registration-domain provenance retains store payloads
  without registering each object during request progress?
- What provider proof enables bounded reclaim after a lost peer or CQ?
