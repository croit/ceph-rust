# 0073 DMA allocation without eager zeroing
Status: accepted
Date: 2026-10-13
Context: performance finding 11; pool misses requested zeroed SPDK memory even when a device read fills the buffer. Safe Rust byte slices cannot expose truly uninitialized memory.
Decision: allocate with `spdk_dma_malloc`; retain per-buffer initialization state through pooling. Successful reads initialize the full buffer. Safe CPU access lazily initializes a fresh buffer; explicitly zeroed allocation still zeros every byte. Failed/rejected reads never imply initialization. No disk/wire changes.
Consequences: device-read pool misses avoid an explicit zeroing allocator request. CPU writers keep initialization until a separate audited `MaybeUninit` API is available. One state check per safe slice access. Measurement and caller audit: `perf/codex-perf-2026-10-13.md`.
