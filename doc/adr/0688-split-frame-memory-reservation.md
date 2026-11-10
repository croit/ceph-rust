<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0688 Reserve split-frame data at the preamble
Status: accepted
Date: 2026-11-08
Amends: 0175 (am. 3)

## Context
Split CRC v2.1 frames reserved only their fronts until the data probe ran.
Clients could pause after their preambles, admitting many large declared
payloads against tiny front charges. All those payloads could subsequently join
without a capacity check. This exceeds the soft target by the sum of their data,
rather than by the last frame admitted below the target.

## Decision
Reserve the whole declared frame at its preamble in every decoder path.
The streaming probe returns the data charge immediately on refusal, before
consuming the refused data without allocation. Accepted data needs no further
reservation. Oversized-frame exclusivity and FIFO admission remain in force.

## Rationale
One complete reservation bounds outstanding declared data and avoids a second
admission that could deadlock behind a waiting exclusive frame. Classic also
takes declared MESSAGE bytes before receiving segments (spec msgr2.md 8.2).

## Consequences
- + Split frames cannot collectively overbook the payload allowance.
- + Refused streaming payloads still allocate no data buffer.
- - A subsequently refused payload briefly occupies credit until its front is parsed.

## Alternatives
- Gate the data separately: held fronts and an exclusive waiter can form a cycle.
- Keep front-only admission: outstanding payload commitments escape accounting.
