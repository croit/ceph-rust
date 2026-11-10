<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0481 Established client watches have independent ownership

Status: accepted
Date: 2026-10-21

## Context

Review M7 found that long-lived registration metadata held the same sixteen
slots used to admit new watches. Native managed and registry slot limits could
independently recreate the same permanent application-visible restriction.

## Decision

The compatible client grows established registration tables on actual demand.
Retained metadata accounting is checked but has no arbitrary count/byte ceiling.
Pending setup holds its own finite reservation until initial completion.
Control operations and notification payloads retain independent admission.
Explicit strict-native constructors preserve their caller-selected limits.

## Rationale

Completing setup must release setup capacity while preserving the watch.
Session leases protect established watch connectivity during peer-cache eviction.

## Consequences

- + Established population can exceed all initial registration reservations.
- + Setup failures and callback lifetime keep explicit cleanup ownership.
- - Memory follows active registrations and callbacks; application cleanup matters.

## Alternatives

- Larger registration constants preserve the compatibility defect.
