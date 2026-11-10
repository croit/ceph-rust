<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0483 EC write: shard crcs come from the encode

Status: accepted
Date: 2026-10-21
Amends: 0061

## Context

An EC 4M write checksummed every shard byte again after the encode: the msgr2 front crc of each sub-write read the shard runs (5.5-6.8 % of each peer-link core, doc/perf/4m-throughput-20261021.md), and the local shard's store recomputed its per-4K block crcs (~1.5 % per core). `encode_stripes_crc` already read every shard byte once (fused with the gather copy / while the parity chunk is in L1).

## Decision

- `Backend::encode_stripes_crc` returns one `crc::BlockCrcs` per shard (grid from byte 0, `crc32c(0, block)` per whole 4 KiB block; fused copy+crc for data shards via `BlockCrcs::update_extend`). Hash-info crcs (`HashInfo::append_crcs`, seed 0) are `BlockCrcs::crc(0)`. Overwrite stripes use the same function (legacy generator only).
- Each shard buffer of a run becomes one `crc::CrcHint::with_blocks` (seed `!0` crc + block crcs). `SharedTxn::hints` carries them per shard.
- Remote shard: `ECSubWrite::txn_hints` -> `Segments::front_hints` -> `msgr2::Message::front_hints` -> `Encoder::encode_message_rope`. A `front_zc` run >= `ZC_MIN` whose bytes are exactly those of a hint contributes `crc32c_append_ones(c, hint, len)` (a join, no read); any other run is hashed. The frame is byte-identical (proved by tests against the flattened plain frame).
- Local shard: `StoreOp::ApplyTxnSplit::hints` gets the same hints; the store takes block crcs through the existing `Payload::blocks_at` / `reseed_4k` path, only for a run that starts on the hint's grid (else one pass).
- A hint is bound to the exact bytes (`CrcHint::of`: address + length, owning reference): a copied, sliced or rebuilt run is never trusted.
- Hints are send-side metadata, not wire content: `crc::CrcHints` has no `PartialEq`; `ECSubWrite` and `Segments` implement equality by hand (exhaustive destructuring) and exclude the hints. `msgr2::Message` is not comparable.
- Secure mode and msgr2 rev 2.0 ignore the hints (flattened frames; the secure path clears them before the plaintext uniqueness check).
- Out of scope: the optimized-EC generator (`owgen`, pool flag `allow_ec_optimizations`) writes slices of column buffers, not whole shard runs; it sends no hints (open question).

## Rationale

The wire frame is unchanged, so classic OSDs in mixed acting sets see identical bytes; only the sender stops reading memory twice. The mechanism is the receive-side `CrcHint` / `BlockCrcs` (adr 0061 am. 4); no parallel one.

## Consequences

- + One crc pass per EC shard byte on the primary (encode) instead of up to three (encode, front crc, store).
- + Wire, on-disk format and crc algorithm unchanged.
- - `ECSubWrite` / `Segments` / `msgr2::Message` carry a hint list; every hint holds a reference to its shard buffer until the frame is built.

## Open questions

- Hints for the optimized-EC generator (slices of columns: needs block crcs per column extent).
