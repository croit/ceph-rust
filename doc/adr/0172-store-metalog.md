# 0172 Store metadata log: PG log as append chunks (M1) — rejected
Status: rejected (measured 2026-10-18; code removed, do not retry without a new argument)
Date: 2026-10-18

## Context

Stub. A chunked PG log in the store (append chunks, tagged append op) was built as M1 to cut per-op CPU of a replicated 4K write.

## Decision

- Rejected. Chunked PG log in the store is not used; the code was removed. Do not retry without a new argument.
- Measurements, build notes and side findings: doc/perf/adr-0172-history.md (verbatim copy of the ADR at `0ead2ef8f`).

## Rationale

- Store instr saving was -2.08 % rep and about 0 % EC, no cycles gain (lost-A/B rule: < 3 % instr, no cycles gain).
- The pglog put is about one of 4.5 tree mutations of a 4K overwrite; an append still costs a lookup and the checkpoint fold.

## Consequences

- Store levers moved to the typed client write and the COW chain of small overwrites (separate ADRs; see 0173 and 0174).
