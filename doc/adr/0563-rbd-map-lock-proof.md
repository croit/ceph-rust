<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0563 Object-map leases require proven exclusive ownership

Status: accepted
Date: 2026-10-25

## Context

A previous header owner can leave separate HEAD map lockers behind. The pinned
reference cleans them after header acquisition, but filters some preparation
errors into successful continuation. That continuation is not proof of a held
map lock. Class lock can also return EEXIST before validating exclusive type.
External contracts: spec/rustyrbd/object-map-lock-recovery.md and spec/cls_lock.md.

## Decision

Map lease construction requires matching watched header authority. The first
map contention reads all lockers and removes their exact identities in separate
completed class writes before reattempting acquisition. Map cleanup uses
its own contract, without managed-header cookie/tag validation or blocklisting.
Header authority is checked before map work and before each removal; committed
close prevents further acquisition/cleanup attempts. Disappeared captured entries
are tolerated without skipping the remaining removals.

Class success proves acquisition. EEXIST additionally requires an exclusive
map assertion before becoming a held lease. Preparation/provider errors remain
errors from the lease constructor. Degraded map continuation is a separate
post-acquire state, never a fabricated successful lease. Existing atomic map
assertions continue fencing later map mutations.

## Rationale

Real header authority permits stale map cleanup. Replicated class calls in one
compound can each read the original whole lock xattr; its last replacement can
restore an earlier removed entry. Separate committed removals make each call
observe the preceding update, using standard class operations. A success-only lease
avoids granting metadata write authority from filtered errors or an existing
shared entry. Cancellation checks keep close independent of repeated map
disappearance. Separate header checks do not claim cross-object atomicity.

## Consequences

- + Stale map entries no longer prevent an otherwise valid new map owner.
- + Held leases retain an explicit exclusive-authority meaning.
- + Existing single-method class writes keep their original path.
- - Multiple stale lockers require multiple completed metadata operations.
- - EEXIST needs one additional proof read; ordinary successful acquire does not.
- - Failure/degraded continuation still needs separate representation and tests.

## Alternatives

- Treat reference filtered0 as ownership: rejected because later assertions can fail.
- Reuse managed header break: rejected because map locker admission is different.
- Batch dependent whole-xattr replacements: rejected because the reference
  replicated visibility can leave stale lockers behind; the compound strategy
  is not an external ABI requirement.

## Open questions

- Complete and qualify conservative/degraded map continuation with explicit
  held/unheld map authority, including missing/corrupt/oversized maps and timeout policy.
