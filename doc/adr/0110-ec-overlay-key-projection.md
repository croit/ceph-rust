# 0110 EC overlay key projection

Status: accepted
Date: 2026-10-14

Context: optimized-EC key listings with pending omap log entries construct a value-owning overlay to test whether it is empty, construct it again for the range merge, and copy stored values before discarding them. ADR0100's projected stored-key scan does not benefit this path. The governing constraint is identical Ceph-visible behavior, including existing decoder permissiveness and pagination.

Decision: interpret pending log entries into a typed key-only projection. Validate every existing field and envelope with the shared decoder while borrowing and skipping value/header payloads. Record generation changes, clear, inserts, removals and literal half-open range removals in the same order. Merge surviving overlay keys directly with the store's projected key scan. Preserve strict-after cursors, prefix bounds, count limits, encoded-key byte accounting (`4 + key.len()`), zero-byte results and the exact meaning of `more`. Remove pending insertions only through a bounded tree range, preserving the established range-removal complexity.

Alternatives: retaining the value overlay wastes work proportional to payload size for a key request. Caching a second overlay introduces invalidation and retained-memory costs across writes and generation changes. A per-request projected overlay removes value work without a new cache or persistence contract.

Consequences: keys, update descriptors and merge pages still allocate; pending log metadata is still walked per request. Large payloads remain present in the established log representation, but key listings do not duplicate them. Value listings, recovery/replay, write durability ordering, disk representation and wire encoding continue using the established implementations. This decision is independent of any owner-core budget changes.

Validation: differential projected/full parser validation, mixed stored/pending update pagination, generation resets, disjoint ranges and byte-exact key/cls replies; actual PgEnv/Pg allocation-only and separate bare-System CPU probes. Commands, raw samples and limitations: `../perf/perf4-ec-overlay.md`.

Final verification: normal `ecback`, `opexec`, `peering`, `cls`, `ec` and `osd` suites plus rustdoc passed (1142 tests, 17 ignored). The final regression-only fixture edit was followed by all `osd` tests/rustdoc (175 passed, 10 ignored). Six-crate all-targets Clippy with warnings denied passed, as did osd Clippy for each separate allocation/CPU test feature. Allocation regressions fail the unchanged current-main baseline for direct keys, OMAPGETKEYS and the key-only log.trim primitive; all pass the projection. Independent review found no wire, disk-format or durability-order change.
