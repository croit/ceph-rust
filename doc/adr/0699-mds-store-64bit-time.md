<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0699 MDS store uses signed 64-bit time

Status: accepted
Date: 2026-11-07

## Context

The experimental MDS format has no existing stores. The owner requires stored
POSIX time beyond 2106 and negative seconds so a future own protocol can expose
it. Stock Ceph wire compatibility remains required.

## Decision

- Store time is i64 signed POSIX seconds plus u32 nanoseconds below 1e9.
- Every persisted timestamp uses the dedicated allocation-free store Time type.
- Ceph UTime and crates/denc remain unchanged. Incoming wire seconds zero-extend;
  the single documented outgoing conversion saturates seconds to 0..=u32::MAX.
- Comparisons and maxima use stored time before wire conversion.
- The experimental store revision is 3. Accept only revision/minimum reader/
  minimum writer 3 with no upgrade target; refuse all other formats loudly at open.
- No upgrade or conversion path is implemented. Recreate older experimental stores.

## Rationale

The owner's future protocol requires the full signed POSIX seconds domain.
Keeping a separate store type preserves shared Ceph wire contracts. Explicit
saturation avoids wrapping stored values when replying to stock clients.
There are no existing stores to migrate; a strict revision boundary keeps the
experimental format and its recovery code simple.

## Consequences

- + Negative and y2106+ timestamps survive storage and recovery.
- + One current encoding; no migration state or conversion/replay machinery.
- - Each stored timestamp grows by four bytes.
- - Stock Ceph clients observe saturated seconds outside their representable range.
- - Older experimental formats require recreation.

## Alternatives

- Widen shared UTime: rejected; changes unrelated OSD/client wire contracts.
- Keep u32 seconds in storage: rejected; loses the required future time range.
- In-place upgrade: rejected; there are no existing stores.

## Open questions

None.
