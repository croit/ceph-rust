# 0075 Pooled external TX lifetime records
Status: accepted
Date: 2026-10-13
Context: finding 9; external TX allocated both a Rust Bytes box and C shared-info per segment.
Decision: one bounded DPDK lifetime-record mempool per port queue, count equal to its mbuf-pool size. Records hold shared-info plus aligned Rust Bytes and an Arc to their pool. Last external reference invokes Rust: move handles off storage, return record, release Bytes/Arc. Multi-thread-safe pool permits callbacks on another core. Exhaustion returns frame-build failure; no malloc fallback or waits.
Consequences: zero steady-state lifetime-record allocations, bounded extra memory, refcount/mempool cost remains. Records outlive the original mbuf and Port when clones survive. Alignment checked at pool creation. No wire/disk change. Tests/numbers: `perf/codex-perf-2026-10-13.md`.
