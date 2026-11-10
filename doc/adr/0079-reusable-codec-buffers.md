# 0079 Reusable codec state and decoded-buffer ownership
Status: accepted
Date: 2026-10-13
Context: ADR 0059 software compression allocated LZ4/Snappy state per call and raw-deflate temporary output on encode/decode. A decoded chunk was allocated, copied into the cache, then discarded. Physical/read-result buffers were zeroed before being overwritten.

Decision:
- Lazily retain LZ4's large hash table, Snappy encoder, raw-deflate compressor/decompressor and existing zstd contexts per shard. Reset each independent raw-deflate stream; level 1 and raw format unchanged. Write directly into caller output. Tests compare new raw-deflate bytes and decoding against the existing miniz convenience functions across sizes and failed decodes.
- Reuse physical and decoded scratch per shard. Read physical data into Vec spare capacity, setting length only after a successful complete read. zstd initializes Vec capacity directly; slice-only codecs resize initialized storage when it first grows, then reuse it. Zero only logical holes and failed chunks collected by scrub, instead of every compressed read destination.
- The four-entry decoded cache takes Vec ownership and returns a victim as scratch. A free invalidates its identity (`physical blocks = 0`) before reuse; bounded storage remains available instead of being freed/reallocated. Invalid entries never satisfy a hit. At most four cache buffers plus one decoded scratch (each <=256 KiB for object chunks), one physical scratch and codec state per shard. No allocations for a pool without compression until these paths run.

Consequences: zero steady-state Rust codec allocations, no decoded-cache payload copy, fewer buffer allocations/clears on compressed reads. Result/metadata allocations still exist. First use, buffer growth and native codec context allocations are separate. Slice codecs require initialized fresh storage; no uninitialized Rust byte slice is manufactured. Reader pins, write ordering, CRC validation, media verification and compression formats unchanged.

Validation: unit allocation/ownership/invalidation regressions, sizes/errors/raw-deflate compatibility, object compression model and crash matrix; measurements in `perf/codex-perf-2026-10-13.md`.
