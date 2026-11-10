# 0174 Deferred in-place small overwrites on PLP (lever A) — rejected
Status: rejected at design (2026-10-18; never built): 2x write bytes on 4K overwrites vs BlueStore NVMe COW = worse than BlueStore
Date: 2026-10-18

## Context

Stub. Lever A: defer in-place small overwrites of exclusive plain extents through the WAL on PLP, with the home write after the commit.

## Decision

- Rejected at design; not built. Format change (metadata crc needs LBAF 4096+64), kernel-direct tier excluded, 2x data write amplification.
- Cheaper format-free alternative (not built): a punch fast path for a block-aligned overwrite that replaces whole blocks inside one extent, to be measured on op-cpu-gate first.
- Proposal shape, crc placement, replay rules and bounds: doc/perf/adr-0174-history.md (verbatim copy of the ADR at `0ead2ef8f`).

## Rationale

- 2x data bytes on 4K overwrites: worse than BlueStore NVMe COW on bandwidth-bound cells (never worse than BlueStore).
- Removable CPU bound <= about 3 % instr rep, before added costs; expected net 1-2 %.
