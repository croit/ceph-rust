<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0579 Shared image ownership for lifecycle contexts

Status: accepted, amended (am. 1)
Date: 2026-10-26

## Context

TrashMove and Remove require watched ownership without ordinary DATA-writer
admission or parent opening. The current DATA writer embeds actual leases,
failed setup resources and release/cookie cleanup. The recovery coordinator
already has an internal driver boundary. Ordinary writer opening also binds
DATA and rejects features irrelevant to metadata-only preparation.

## Decision

Concrete ImageOwner resources retain prepared header/map leases and failed
setup cleanup. Existing DATA writers consume the same shared resources.
One recovery coordinator binds concrete image drivers and the same managed
owner registry; acquire/request/rewatch/cookie/release orchestration is shared.
Lifecycle metadata contexts use this seam instead of impersonating a DATA
writer or introducing another recovery state machine.

FULL ownership includes required Object Map preparation. Header acquisition,
metadata refresh/admission, map preparation and readiness remain distinct;
only genuine header contention enters peer handoff. Writer-specific DATA and
pool validation remain caller policy. Valid maps require sufficient logical
coverage; conservative invalid-map outcomes still need shared implementation
and explicit DATA adoption.

## Rationale

A separate concrete metadata context preserves DATA admission and hot paths.
Extracting existing production resources first supplies an exercised owner
implementation without optional DATA lanes or a generic image framework.
Actual lease failures remain retained and cannot become fictitious ownership.

## Consequences

- + Existing writers exercise the shared cleanup and ownership resources.
- + Temporary metadata operations can reuse the same recovery lifecycle.
- - Acquisition/map preparation and the metadata context still require work;
  this foundation alone does not implement TrashMove or Remove.

## Alternatives

- Expand DATA WritePurpose with metadata-only optional state: couples metadata
  admission to DATA geometry/pools/features and multiplies internal branches.
- Header-lock-only owner for every image: omits FULL map preparation.
- Duplicate recovery: splits cancellation, watch and close correctness.
- Resize to zero for removal: changes geometry and progress and misses layout.

## Open questions

Implement shared acquisition/map preparation, the concrete metadata context,
full internal mirror/snapshot cleanup, guarded identity removal and the full
TrashMove/Remove state machines. The reference's DISABLING/promotion error-state
ordering needs source/retry verification before changing the documented
implementation deviation. Test evidence (commit hashes, cell results): librbd completeness, ADR evidence (doc not in the source snapshot). Five independent read-only reviews found no high-confidence introduced issue.
This is resource/refactoring evidence; no completed lifecycle or live parity
qualification is inferred.

## Amendment 1: Phased acquisition and sufficient map coverage

HeaderPreparation owns a real provisional header lease and reserves optional
map cleanup storage before acquisition. The separate map phase returns actual
paired leases or an error retaining the actual header; it does not decide
continuation policy or publish readiness. Current writers retain cleanup and
readiness ordering through these shared phases.

A decoded map is usable for a logical image when it covers every required
object; valid physical tails remain unchanged. HEAD acquisition/reload, saved
rollback maps and snapshot-copyup checks use sufficient coverage. Explicit
resize postconditions and exact rollback of a captured map retain physical
length equality. Short/corrupt/missing maps still need conservative preparation;
accepting a long map does not imply that those paths or TrashMove are complete.

Rationale: the pinned refresh contract accepts longer maps; exact logical-size
equality falsely rejected valid ownership and later snapshot operations.

Test evidence (commit hashes, cell results): librbd completeness, ADR evidence (doc not in the source snapshot). Classic-librados evidence for the exercised profiles, not complete conservative-map or lifecycle parity.
