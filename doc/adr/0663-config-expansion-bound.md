<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0663 Bounded client configuration expansion

Status: accepted
Date: 2026-11-06

## Context

`expand` substitutes string configuration references from the config file,
`CEPH_ARGS` and monitor snapshots. Cycle detection stops recursion, but a chain
of doubling references (`k0="$k1$k1"`, `k1="$k2$k2"`, ...) is not a cycle and
grows the expanded value exponentially with the number of schema string options.
A later `rados_conf_get` of the head option then allocates without bound.

## Decision

- One expanded value is limited to 1 MiB; exceeding it fails with `-E2BIG`.
- Every append in the expansion worklist counts toward the same limit, so a
  single oversized literal and a doubling chain hit the same bound.
- Exit codes, cycle handling and byte preservation below the limit are unchanged.

## Rationale

The reference recurses without a size limit; reproducing that would let file or
monitor input exhaust client memory. 1 MiB is far beyond any real configuration
string, so compatible inputs keep identical output. ADR0256 permits this
correctness improvement because no valid application observes the difference.

## Consequences

- + Exponential expansion from configuration or monitor input is bounded.
- + The failure is a defined error, not an allocation abort.
- - A configuration string above 1 MiB is rejected where the reference would
  return it; no such option is known.

## Alternatives

- Copy the unbounded reference recursion: an OOM for attacker-controlled input.
- Cap only the reference depth: doubling chains stay exponential within one level.

## Open questions

- Whether the limit should be lower (64 KiB) or configurable belongs to a later
  operator decision; no current configuration comes near either bound.
