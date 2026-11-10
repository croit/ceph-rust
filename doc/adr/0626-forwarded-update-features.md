<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0634 Forwarded update-features execution on retained owners

Status: proposed
Date: 2026-10-28

## Context

`rbd_update_features` validated the requested mask locally and wrote the head
`set_features` class call directly, bypassing the managed exclusive-lock
owner. The pinned contract routes every feature update except JOURNALING
enable through the common administrative invoke to the image's actual owner
(`doc/spec/rustyrbd/admin-owner-forwarding.md`, opcode 15). The wire codec
already carried `AdminOperation::UpdateFeatures`; the owner executor refused
it with `-EOPNOTSUPP`, and the requester had no forwarding path.

## Decision

- The public entry validates the transition against a refreshed head through
  the shared `validate_feature_update`, then acquires the managed owner; a
  peer owner is served by forwarding opcode 15 over the shared administrative
  transport with full-ID correlation, timeout and reselection on
  ERESTART/ETIMEDOUT.
- The owner executor decodes `UpdateFeatures` and executes
  `commit_update_features` under the accepted epoch: refresh, retained
  ownership check, operations-disabled refusal, revalidation against its own
  head, write-admission permit, `set_features` header mutation, observation
  refresh.
- OBJECT_MAP, FAST_DIFF and JOURNALING transitions remain `-EOPNOTSUPP` on
  both sides until their lifecycle is implemented (RBD-040).
- JOURNALING enable follows the pinned local-only exception: it is refused
  before the forwarding decision, so no such request is ever forwarded.
- Requester/receiver share `admin_request_error` and
  `forwarded_result_reselects` in `image_api`; `sparsify_forwarding_resources`
  is the generic `admin_forwarding_resources`.

## Rationale

Forwarding through the retained owner is the pinned routing for all feature
updates except JOURNALING enable; a direct class write would mutate the head
under a live peer lease. Revalidation on the receiver is required because the
requester's head observation can be stale: it computes the actual mutation
and refuses already-applied transitions.

## Consequences

+ `rbd_update_features` honours exclusive ownership for peer-owned images.
+ One validation helper serves requester and receiver; wire format
  unchanged.
- OBJECT_MAP/FAST_DIFF/JOURNALING transitions are still refused (RBD-040).
- Live two-owner qualification of the forwarded path remains open (RBD-013).

## Alternatives

- Direct class write without ownership: rejected, mutates the head under a
  live peer lease.
- Forward the effective (implied-bit) mask: rejected, the receiver must
  re-derive implied bits from its own head state.
