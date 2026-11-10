# 0027 Single-IO atomic commit (amends 0021)
Status: rejected (2026-10-09). Benchmark (design doc 'Impl notes (ADR 0027)'): gain only at QD1 (2->1 cmds, equal latency since ring commits in parallel); under load ring already ~1 cmd/txn (meta-only 0.016) and clog needs more bytes, more cmds for meta, extra memcpy, much more complexity. KISS: keep WAL ring. Prototype: added in git de8bf827b8, removed in c6c8dc6655. Multi-record atomic txns (BEGIN..END) to be added to the WAL ring instead.
Date: 2026-10-09

## Context

Stub. Requirement was one device IO per atomic transaction (ZIL-style chained commit units). The ADR 0021 WAL ring needs two IOs per data txn.

## Decision

- Rejected. The WAL ring of 0021 stays. Multi-record atomic transactions (BEGIN..END) go into the WAL ring (0028).
- Full design text and measurements: doc/perf/adr-0027-history.md (verbatim copy of the ADR at `0ead2ef8f`).

## Rationale

- Gain only at QD1; under load the ring already commits about one command per txn.
- The chained-commit design adds metadata commands, an extra memcpy and substantial complexity (KISS).
