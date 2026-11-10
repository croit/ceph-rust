# 0173 Typed client write with a cached onode id (lever B) — rejected
Status: rejected on the measured bound (2026-10-18; never built, do not retry without a new argument)
Date: 2026-10-18

## Context

Stub. Lever B: skip the store name-to-onode lookup and the TOp re-encode for a 4K client write by passing a typed write with a cached onode id.

## Decision

- Rejected. Not built. Bound below the bar (>= 3 % instr AND cycles).
- Cheaper sub-step B0 (store-persistent collection id map, bound about 0.9 % rep / 1.2 % EC instr) moves to the store-trim batch; not built.
- Coherency contract, idea and measured bound: doc/perf/adr-0173-history.md (verbatim copy of the ADR at `0ead2ef8f`).

## Rationale

- Theoretical max about 3.5 % instr rep and 4.5 % EC; the TOp skip applies only to the primary's local apply, realistic about 2-2.5 % rep.
