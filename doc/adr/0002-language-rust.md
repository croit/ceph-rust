# 0002 Language: Rust
Status: accepted
Date: 2026-10-09
Context: Perf parity C/C++/Rust achievable (no GC, zero-cost abstractions, std::arch SIMD, LTO). Storage = correctness-critical; memory-safety bugs = data loss. Green-field anyway (0003), so no C++ reuse benefit.
Decision: Rust (stable), Cargo workspace at the repo root (`crates/`, `services/`, `tools/`). C deps (SPDK, DPDK) via FFI; EC math is own Rust (0048, no ISA-L FFI; SPDK bundles its own ISA-L for its checksums only); static-inline C fns (rte_eth_rx_burst etc.) via thin C shim + cross-language LTO (clang/rustc same LLVM, -Clinker-plugin-lto).
Perf rules: no tokio/work-stealing, no Arc/Mutex on hot path, no heap alloc per IO, bounds checks removed only where profiled, `unsafe` confined to ffi/dma/nvme/net-driver modules with SAFETY comments.
Consequences: + memory safety, + free license (0003). - re-implement Ceph encodings, CRUSH, peering, EC layout, cls subset.
Alternatives: C++20 (reuse Ceph libs but binds LGPL + legacy idioms), C (no safety, no abstraction).
