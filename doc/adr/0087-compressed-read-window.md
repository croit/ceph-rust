# 0087 Compressed media read window and request-owned decoded results
Status: accepted
Date: 2026-10-13
Context: performance finding 7. Compressed reads yielded at the first unavailable physical chunk. Large nonblocking reads also cycled their prefix: decoded cache eviction and unused-range pruning discarded earlier chunks before a later miss completed.

Decision:
- Permit at most four unavailable compressed physical runs in a read pass. Submit them through ADR 0078's existing rolling machinery, writer queue reserves and shared 32 MiB DMA limit. Visit ready chunks in the same pass and decompress them while other runs remain outstanding. No wait in a nonblocking caller.
- Retain successfully verified decoded chunk ownership in its pinned rolling request/session until completion or cancellation. Check logical CRC, raw length, physical run and media mode on reuse. This is retry state, not a media-verification cache. Prefix results remain marked used when copied on a retry, so the four-entry client cache cannot cause a large read to cycle.
- A fully prefetched chunk retains its decoded buffer directly; it does not gain an extra physical buffer or copy. Keep the four-request-session admission bound. Decoded result storage scales with the full logical chunks touched by those admitted requests, in addition to retained physical results and caller output. The IO window/DMA caps do not cap total RSS. Existing session release, 200 ms expiry and reader pins govern this additional state.
- On completed direct reads or session release, transfer valid client decoded buffers into the existing four-entry cache and reuse victims as scratch. Media results never enter that cache. Scrub/fsck bypass client prefetch and cache, but may resume their own fresh verified request results.
- Blocking callers drive the same window locally, restoring their original mode on success/error, (superseded, see amendment 1: no deadline). Nonblocking callers yield and let the core poll network, mesh and store. Failed attempts discard partial scrub error lists; final successful verification reports each bad chunk once.
- No store prepare/FIFO budget, durability, ordering, disk/WAL or wire change.

Validation: before/after cold window benchmark; regression fails with only one submitted read; large read finishes with one decompression per chunk; decompression overlaps outstanding media; blocking/sessionless and mixed/full-prefetch callers; cancellation/removal leak check; corruption under cached data; full affected suites, crash matrices and relevant release model/crash checks. Results: `../perf/codex-perf3-2026-10-13.md`.

## Amendment 1 (2026-10-25): no blocking-read deadline
The blocking caller no longer drives the window with a 30 s EIO deadline (5db802be41): it reads each chunk through the synchronous device path, which ends on the completion or the device error, so nothing waits on a timer. Nonblocking callers are unchanged.
