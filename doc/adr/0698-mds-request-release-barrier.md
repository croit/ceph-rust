<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0698 MDS embedded release barrier excludes receipt GC

Status: accepted
Date: 2026-11-08

## Context

CAP_IN mode 3 settles embedded cap/lease releases before the matching ROUTE
(mds-fe-be-protocol s5). It also deleted older C records and waited for their
journal durability, delaying ROUTE even though the releases were already applied.
The FE already retains request-head watermarks and sends independent TRIM work.

## Decision

Mode 3 acknowledges processed embedded releases without performing C-record GC.
TRIM retains ownership of durable C/K deletion. ROUTE still advances the volatile
receipt watermark; successful mutation replies still require journal durability.

## Rationale

Completed-record deletion is not a dependency of cap/lease settlement. The sim
holds all journal acknowledgements and observes that the next request can be admitted
to the BE without a cap acknowledgement or clock advance.

## Consequences

- + Removes redundant GC storage admission and journal waits before ROUTE.
- + Preserves the sole directory holder's Fs/Fx and existing TRIM durability.
- - Does not remove metadata reads or the mutation's own journal dependency.

## Alternatives

- Retain mode-3 GC: unnecessarily puts maintenance on the request critical path.
