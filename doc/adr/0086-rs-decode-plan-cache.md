# 0086 Bounded per-thread RS decode plans
Status: accepted
Date: 2026-10-13
Context: performance finding 9. `gf::Codec::decode_into` rebuilt the survivor inverse, coefficients and nibble tables on every RS decode. Codecs are immutable and shared between core-local backends, so a mutable per-codec cache would introduce synchronization.

Decision:
- Cache RS plans in thread-local storage. Key by immutable codec identity, ordered survivor raw indices and ordered wanted raw indices; order determines coefficient and output positions. Codec construction assigns a unique identity, clones retain it. No pointer reuse or hash collision can alias generators.
- Retain inverse-derived coefficients and their nibble tables. Validate lengths, index bounds and duplicate survivors before lookup using stack storage. Preserve zero/one coefficient fast paths, caller-owned output buffers and the existing SIMD kernels. A hit allocates nothing and uses no locks or atomic operations.
- Least-recently-used eviction, at most 32 plans and 4 MiB of retained key/coefficient/table data per thread, plus the fixed entry vector and allocator overhead. Plan construction allocates on a miss. Oversized wanted lists remain valid through the existing uncached path and never enlarge the cache. Codec destruction does not require a global sweep; entries expire under the same bounds.
- Standalone `decode_matrix` remains unchanged. Wide-field, bit-matrix and SHEC planners remain unchanged; LRC/CLAY RS scalar calls share this cache through their existing RS codec. No wire, disk, parity or shard-mapping change.

Validation: before/after stable-pattern 32-byte/4K decode benchmark; allocation regression fails before and passes after warmup; count/byte limits, true LRU eviction, clone identity, Send/Sync and invalid-input checks. All frozen vectors, corpus oracle and EC backend tests must pass before merge. Results: `../perf/codex-perf3-2026-10-13.md`.
