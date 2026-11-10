# 0077 Overlap copy fetch with durable staging
Status: accepted
Date: 2026-10-13
Context: finding 8; large copies serialized each source read after the previous staged write completed, despite a two-chunk reservation.
Decision: start the next source read after a staged write is submitted, holding an early answer encoded until that write is durable. Decode/stage only after the barrier; release prior wire/decoded ownership before fetching again. At most one staged write plus one next reply/read, existing two-chunk reservation. Early source errors wait for durability before cleanup. Last stage remains the prerequisite for atomic rename and client completion; reset drops pending replies/tids.
Consequences: overlap one read with one write without concurrent stage writes, no protocol/disk changes. Existing source per-object ordering/version assertions remain. Source omap/xattr overhead and replica/network buffers remain outside the two-data-chunk estimate. Spec: `spec/copy.md`; invariants/tests/numbers: `perf/codex-perf-2026-10-13.md`.
