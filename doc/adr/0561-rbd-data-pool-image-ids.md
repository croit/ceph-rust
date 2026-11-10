<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0561: Capacity-aware IDs for separate RBD data pools

Status: accepted
Date: 2026-10-24

## Context

Pinned CREATE limits data prefixes to43 bytes. Separate-pool prefixes contain
`rbd_data.<decimal metadata pool ID>.<image ID>`. The class accepts nonempty
ASCII alphanumeric IDs. Existing32-digit hexadecimal IDs exceed the limit
when a metadata pool ID has two or more decimal digits. The pin's generator
retains at most14 hexadecimal digits; its generation algorithm is not a wire
contract. See creation contract (doc not in the source snapshot).

## Decision

Separate-data-pool CREATE generates uniform base62 IDs with rejection sampling
from the operating system random source. ID length is the smaller of22 and
the remaining43-byte prefix capacity. Normal image and group IDs retain their
existing generation. Directory identity checks and exclusive object creation
protect existing resources on collisions; no failed claim permits overwrite
or deletion of another image.

## Rationale

Twenty-two base62 characters provide about131 random bits. Positive signed64
metadata pool IDs leave at least14 characters, about83 bits; this worst-case
entropy reduction is necessary within the fixed prefix and alphabet capacity.
The construction avoids biased modulo selection and preserves the full prefix
budget. Prefix compatibility, not the reference's generator internals, is the
required contract.

## Consequences

- + Every positive signed64 metadata pool ID fits the prefix bound.
- + Typical pool IDs retain at least128 random bits.
- - Large pool IDs reduce the available random space; collisions return an
  error through existing atomic identity checks rather than corrupting data.
- + Existing longer valid IDs remain readable; the generator adds no decoder
  length restriction.

## Alternatives

- Fixed32 hexadecimal characters: cannot fit separate-pool prefixes generally.
- Fixed14 base62 characters: fits, but discards available entropy for small IDs.
