<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0721 Immutable completed RocksDB listing replies

Status: candidate; qualification pending
Date: 2026-11-07
Amends: 0677, 0720-rocksdb-packed-scan-payload

## Context

The selected RocksDB scan keeps a completed mutable encoding for compound retries
and copies it for every writable return. The listing finalizer then changes its
count header and appends `more`. Sharing an unfinished or spare-capacity allocation
would violate retry independence or export backing beyond Store's memory charge.

## Decision

- Add a complete immutable listing-reply path through Store, StoreAdapter and
  ObjView. Finalize count and trailer once, then share an exact boxed allocation
  between the RocksDB memo and returned Bytes. Preserve conservative allocation
  and return reservations; charge the frozen allocation in completed memos and
  re-admit its final shape before publication. An encoding exactly filling its
  allocation grows by the trailer byte; an earlier admission alone is insufficient.
- Distinguish immutable and writable memo identities. Keep existing writable
  listing, CLS, recovery and non-session APIs. Native LSM keeps its old encoding
  and finalization ownership; no native memo field or per-entry dispatch change.
- Keep request-scoped cancellation, expiry, object/revision invalidation, credits,
  worker bounds and every owner fairness yield, including terminal full slices.
  A completed result remains independently owned after any memo or Store release.
- Keep PgEnv's EC overlay-aware listing on its existing path. The new replicated
  route retains the `seen` guard. No wire/storage format, WAL, sync, ACK, queue,
  transport or EC serve/decline policy changes.

## Rationale and consequences

Finalizing before freezing avoids mutable aliasing and extra header/trailer
segments. Exact backing prevents a small visible result from retaining an
unaccounted rounded encoding allocation after cancellation. Shrinking may itself
copy or reallocate; this is not a guaranteed zero-copy or throughput claim.
Retried completed replies share bytes instead of repeatedly copying them.
Allocator rounding/metadata and transport buffers remain outside Store's credits,
as before; this does not establish a global last-owner memory admission guarantee.

## Alternatives and qualification

Three reply segments add metadata and retain the same backing problem. Sharing
rounded storage without a lifetime credit token is rejected. Extending Store
credits into messenger ACK/replay lifetime is separate, broader work.

Require independent wire vectors, writable/immutable separation, completed replay
pointer identity, terminal yields, capacity/credit evidence, cancellation, expiry,
revision invalidation and retained outputs after Store destruction. Check adapter,
executor, EC overlay routing, default native paths and production consumers.
Qualify retained/shared Secure plaintext, CRC and partial-send lifetime paths;
transient shrink/ciphertext allocations are distinct from retained payload size.
Matched source-bound benchmarking remains necessary; no performance result yet.

## Initial offline qualification

Rocks+lab Store396 pass/12 ignored; Store integrations8+8; native Store322/11;
adapter listing3 engines plus Rocks replay1, default adapter2; executor292/2;
OSD listing5, OMAP18 and resend3; messenger59/1; KNet boxed-notification hold1.
Affected all-target Clippy and no-default production-consumer compilation pass.
Independent incremental review found no actionable ownership/credit/EC defect.

Removing exact boxing fails the backing-capacity assertion; removing final
re-admission fails the exact-capacity trailer test. Both mutations were restored.
Initial test fixture exceeded write admission; the corrected256-small-entry
fixture exercises the same final encoding boundary. Two missing qualified Bytes
type names were compile fixes only. Failure logs remain separate from passes.
No workspace-wide, live performance or physical-power-loss qualification yet.
