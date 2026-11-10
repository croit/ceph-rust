<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0521 Compatible clients enforce wire shape independently of soft admission

Status: accepted
Date: 2026-10-22

## Context

The native codec defaults impose a256MiB segment and512MiB frame ceiling.
Both pinned reference frame paths represent up to four u32 segment lengths
without those fixed policy ceilings. Public scalar API bounds can exceed them.

## Decision

Compatible client framing derives its hard shape bounds from u32 segment fields
and MAX_SEGMENTS. Strict native/server codec defaults retain their explicit
policy. Public compatible request and command checks and every client peer use
the same profile. Soft retained/output credit remains independent; checked
padding, aggregate, allocation and platform conversions remain mandatory.

## Rationale

A replacement constant would preserve an arbitrary application failure boundary.
Wire representation supplies an independently verifiable shape bound without
claiming every represented frame is allocatable or supported by every operation.

## Consequences

- + Representable requests no longer fail solely at own default codec ceilings.
- + Shared policy covers monitor, OSD, manager and directed client paths.
- - Large admitted frames can still encounter real allocation or peer rejection.
- + No maximum-sized allocation follows merely from selecting the profile.

## Alternatives

- Increase defaults globally: changes server/strict policy and adds another cap.
- Disable shape validation: permits narrowing and arithmetic corruption.

## Open questions

None for the profile selection; practical peer/resource qualification is distinct
from the representation contract and remains recorded in the gap inventory.
