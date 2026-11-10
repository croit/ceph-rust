<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0484 Read reply: the data crc comes from the store's block crcs, also for cut ranges

Status: accepted
Date: 2026-10-21
Amends: 0043, 0061

## Context

doc/perf/rdma-size3-20261021.md measured `crc::x86::k512` at 25-37 % of OSD cycles in 4 MiB reads and read it as "the reply crc is recomputed per read". Call stacks of the same and of a fresh profile (doc/perf/read-crc-20261021.md) show one pass only: every k512 sample sits in the store's block-crc pass (`Sink::whole` / `pf_serve` in the profile base, `pump_at` -> `pf_done` after adr 0043 am. 14), the pass that verifies each 4 KiB block against its stored crc. The reply's msgr2 data crc is already derived from those block crcs without a pass (`read_eff_shared` -> `ObjView::ov_read_shared` -> `OsdOp::set_outdata_parts` -> `CrcHint` -> `Encoder::encode_message_parts`, joined with `crc32c_combine`). One gap: a read that ends or starts inside a block (unaligned offset or length, an object size that is no multiple of 4 KiB) cut its piece and dropped the piece crc, so msgr2 hashed that whole piece again (a piece is one device command, up to 256 KiB).

## Decision

- Every byte a read returns is hashed once, by the store's verification pass; the reply crc is never computed from the payload when the pieces come from `read_eff_shared`.
- A piece cut to the read range keeps its crc: `crc::crc32c_range(data, block, a, b)` joins the crcs of the whole blocks inside `[a, b)` (`crc32c_blocks`, the stored-seed crcs of the verification) and hashes only the partial blocks at its ends (at most two blocks, 8 KiB). A hole piece takes `crc32c_zeros`.
- Wire, hint binding (`CrcHint`, address + length) and the encoder are unchanged; the hint of a cut piece belongs to the cut `Bytes`. Debug builds check every hint against the bytes (`CrcHint::new`, encoder).
- Not covered (crc computed as before): the flat copy path (`read_committed` -> `read_eff_bytes`: ranges below `SHARE_MIN_AVG` on average, compressed chunks, inline objects, txn overlay), where the crc of an unaligned range stays unknown (the pass is over < 64 KiB average pieces); `clip_parts` in opexec (a read clipped there after the store, truncate_seq quirk).

## Rationale

The store must verify every block it returns (bit-rot detection), so one pass per read byte is the floor; deriving everything else from it is already the design (am. 14, adr 0061 am. 4). The cut case is the only place the derivation was lost. Joining block crcs and hashing two partial blocks costs < 1 % of the pass it replaces.

## Consequences

- + Unaligned and size-clamped reads no longer pay a second crc pass over their cut piece.
- + No new type, no new field on the path: only the store function and one crc helper change.
- - The k512 share of 4 MiB reads (15-19 % of OSD samples, all in the store's pass over cold DMA memory) is not reduced by this; it is the verification itself.

## Siblings

- knet, AF_XDP, RDMA SEND: one msgr2 encoder (`encode_message_parts`) and one hint path for all transports; not affected (the same pieces and hints).
- SPDK / kernel NVMe tier: the change is above the device layer (`read_runs_shared` returns the block crcs either way).
- Replicated: primary read, covered. EC: client reads of EC pools come from the decoded stripe cache (`ov_read_bytes`) or shard reads over the flat path; not store-derived, not affected (open question).
- msgr2 crc vs secure: secure ignores hints (AEAD over the flattened data); nothing changes.

## Open questions

- The remaining pass is memory-bound (device DMA buffer, cold cache). Whether it can overlap the device transfer (hash while later commands are in flight, per-command completion on a helper core) is a separate perf question (large-io domain).
- Crc of unaligned ranges on the flat read path and for EC replies.
