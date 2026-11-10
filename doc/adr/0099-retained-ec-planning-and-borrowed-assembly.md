# 0099 Retained EC planning and borrowed assembly

Status: accepted
Date: 2026-10-14
Context: performance audit F01/F02. Legacy EC planning copied input overlays, composed individual temporary stripes, flattened encoded data for hashing, and cloned append buffers while consuming the plan. Healthy read assembly cloned its complete input columns; degraded assembly cloned available columns again. Immutable codec geometry was also copied with each backend clone.

Decision:
- Add a retained-input legacy planning entrypoint for an owned `Bytes` transaction. Inline decoded write spans retain slices of that owner; noncontiguous data uses the existing copying fallback. The borrowed planning entrypoint remains available and copies only the write payload it needs. Overlay cuts retain prefix/suffix slices. The primary uses the retained entrypoint after its existing validation and wire preparation.
- Encode fully covered consecutive stripe runs straight from their retained overlay. Partial/gapped runs compose into one initialized final run buffer, preserving old-byte retention, zero padding and last-write precedence. There is no temporary owned buffer per stripe.
- Reuse data/parity descriptor vectors through stripe encoding, and feed existing encoded append runs incrementally into hash-info CRCs instead of flattening them. A consumed plan moves pre/post operations and append buffers into output preparation. Final external transaction serialization remains unchanged.
- Share the immutable codec through `Arc`. Keep geometry and chunk mapping behavior unchanged, including thread-local decoder-plan caching.
- Borrow complete/truncated input columns during assembly, allocate padding only for short/missing replies, and move owned padded columns after reconstruction. Allocate missing decoded columns and the logical output as before. Preserve existing zero-padding, interleaving and degraded read-set semantics.

Compatibility: no wire or disk encoding changes, no early acknowledgement, no mutation of shared input, and no change to stripe/chunk mapping, rollback descriptors, hash seeds or object ordering. Plans retain their input until consumed/dropped. Owned cache read replies and optimized-EC native representation remain separate existing paths.

Validation: existing EC codec/frozen oracle suites, legacy/optimized model histories, snapshot rollback, all supported plugin families, peering and executor suites. A retained plan is generated after the caller drops its input handle and compared byte-for-byte with the borrowed path. Allocation ceilings prevent per-stripe allocation/rematerialization and complete-column cloning; short, missing and oversized direct replies preserve previous bytes. The reproducible allocation/CPU probes compare unchanged workloads against the pre-change commit.

Limits: final encoded shard transaction buffers are still allocated; optimized-EC overlays and the initial wire-shaped semantic boundary are not replaced with a universal IR. Compression and arbitrary disjoint stripes still need materialization. Allocation counters are cumulative requested bytes rather than peak retained memory; local CPU benchmarks do not qualify production NVMe/NIC throughput.
