<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0583 Reuse verified source CRCs across a shifted placement grid

Status: accepted
Date: 2026-10-26

## Context

Placement receipts describe seed-0 4096-byte blocks starting at the returned
READ's first byte. The Store shares immutable source pieces but supplies this
sidecar only for aligned READ starts. A public C unaligned short-READ test
therefore receives EOPNOTSUPP after descriptor publication.

## Decision

- Plain shared reads derive receipt CRCs on the requested grid from verified
  immutable source blocks, including shifted starts and short EOF prefixes.
- Aligned full blocks retain the existing exact-CRC reuse path.
- Shifted full blocks hash the shorter source prefix/suffix once per source
  block and combine it with verified seed-0 CRCs using raw CRC linearity.
- Prepare the linear shift map once per READ from one polynomial basis column;
  derive the remaining columns with the inverse bit step. Apply byte tables per
  block instead of evaluating powers repeatedly.
- A final partial receipt block hashes at most one additional block of bytes.
- Report actual newly hashed source bytes separately from the covered range.
- Retain original payload owners; do not flatten or copy source payload.
- Resolved all-hole ranges retain their prior readiness: no unrelated physical
  data durability wait, and no byte hashing for logical zeros.
- Ordinary SEND, non-plain source refusal, destination verification, ordered
  retirement, version/wire formats and the minimum request size are unchanged.
- The host increment is qualified by arithmetic/geometry, Store, PG, transport,
  connected C/native ownership gates and scoped CPU measurements. Physical offset
  performance and broader release/GPU qualification remain open; the existing
  lab-only placement advertisement is unchanged.

## Rationale

A shifted receipt grid differs from the verified device grid. Combining their
linear CRCs with short edges avoids a second full payload pass. Choosing the
shorter edge bounds per-source-block hashing to half a block, while aligned
reads retain their current implementation. Compile-time inverse operators need
no first-use allocation or lock. Existing immutable source ownership is sufficient.

## Consequences

- + Unaligned plain shared READs can supply exact receipt integrity metadata.
- + No new payload staging or copy; common aligned CRC reuse stays intact.
- - Shifted blocks add bounded edge hashing and CRC algebra; a short tail can
  read up to 4095 extra bytes. Measurements must include these costs.
- - Refusal and lifetime/resource qualification beyond plain shared data remains.

## Alternatives

- Hash every returned byte again: adds a full pass over already verified data.
- Reuse checksums from the old grid unchanged: wrong byte ranges.
- Flatten into an aligned buffer: adds a payload allocation/copy.
- Treat the C rejection as success: leaves the requested offset path unsupported.
