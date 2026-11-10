<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
# 0677 Request-owned bounded RocksDB scan batches

Status: proposed; offline and single-pass Phase1 checked, statistical qualification open
Date: 2026-11-05
Amends: 0681, 0676

## Motivation

Before this change, a 1024-entry reply performs four iterator constructions/seeks and
four owner/worker round trips. This is independent native work amplification, not
proof of why classic is faster. Pinned BlueStore research is tracked separately
in spec/bluestore-omap-readpath.md; never infer cross-RPC iterator retention.

## Decision

- Distinguish the worker batch bound from the owner CPU slice. A count-bounded
  request can ask for at most1024 entries in one worker operation; byte-only
  unbounded-count scans retain the256-entry worker bound. Existing worker byte
  and remaining-answer credit limits still apply. Batch entry count participates
  in query identity; no cache/buffer/readahead capacity or durability policy change.
- Keep only owned key/value buffers in the request memo, not a Rocks iterator or
  database snapshot. One iterator serves a bounded worker batch, then dies there.
  Consume the batch across existing256-entry/byte owner slices without refetching.
- Transfer a completed batch out of the opportunistic answer cache. The memo owns
  unconsumed entries independently of cache eviction. Charge remaining payload,
  backing vector capacity and continuation, with constant-time incremental charge
  updates as entries are consumed. Existing encoding/return-copy reservations stay.
- Drop the batch on completion, quota refusal, cancellation/expiry and the existing
  session/object/transaction-revision invalidation paths. Preserve merged visible
  ordering, binary prefix/object isolation and first-unreturned continuation.
  No cross-RPC cursor or snapshot is introduced; no native LSM batching change.
- Preserve the independently writable encoded retry memo and return copy. Explicitly
  reserve one extra byte in the returned copy for the listing trailer, as already
  promised by Store::omap_list_enc. Do not replace retry ownership with borrowing.

## Independent regressions and limits

The preceding code fails both reply-sized worker count (four instead of one) and
encoded trailer-capacity fixtures. Require1023/1024/1025/2048-entry reopened-store
scans, forced owner yields, cutoff modes, competing sessions/credit pressure,
mutation during partial consumption, compound replay and unchanged wire bytes.
Worker tests must cover batch identity/cap, binary merged ordering and tight-byte
fallback. Run affected Store checks and review memory/lifecycle behavior.

Fewer iterator setups/round trips and guaranteed trailer capacity are structural
results, not wall-time or CPU improvement claims. No additional live benchmark is
authorized by this decision; retain the previous campaign unchanged.

## Initial qualification

287 Store library tests passed (12 ignored); six Rocks integrations, eight scan
tests and the counter-schema test passed. Matching-feature all-target Clippy,
default Store and production-feature daemon/tool checks passed. Reopened Rocks
fixtures use ceil(entries/1024) worker requests for1023/1024/1025/2048 entries.
Encoded output preserves trailer capacity, independent replay ownership and exact
bytes; mutation/cancellation during partial batch consumption passes. Independent
read-only review found no concrete defect in the batching delta.

Stage tight-credit/Unknown continuation across yields, pre-completion cancellation,
partial-batch expiry and shared-Arc fallback accounting were not individually
established by the new fixtures. Worker credit fallback and existing lifecycle
fixtures pass; these remaining coverage limits are not passes or demonstrated bugs.
Single-pass wall/CPU/tail and slice-count results are recorded below; this is not
statistical, higher-QD or physical-power-loss qualification.

## Single-pass Phase1 evidence

Fresh sequential control/candidate/native LSM/classic, 1c-QD1, 1048576 keys:
36 cells, zero errors, matching corresponding model checkpoints. Worker requests
per full scan: 4096→1024; owner-slice count remains4096. Summed scans:
9.699597→7.438399s (-23.31%). Scan p99: 7.743/8.191/8.319ms→2.239/2.559/2.719ms.
Classic remained faster in each scan.

Observed whole foreground: 135.450257→108.687595s (-19.76%), but only2.261198s of
that26.762662s reduction is in the three full scans. Write cells also varied;
do not attribute the whole-chain delta to batching or claim statistical
significance. Sampled total CPU:120.82→116.82s; namespace writes:13.72→13.78GiB,
still high and not NAND/Rocks-only bytes. No cache, prefetch, buffering or
durability-policy change.

An earlier shared-target build attempt reused the clean Store dependency while
rebuilding the dirty daemon entry crate. Its results are excluded. Qualification
used a private target, forced Store rebuild with exact manifest/fresh=false
compiler evidence, a new-code binary marker, frozen source/binary receipts and
observed live batching counts. Distinct main-binary hashes/dirty versions alone
are not adequate proof that modified dependencies linked. A pre-readiness socket
path-length failure was also preserved/excluded; the successful fresh campaign
used guarded short paths. All owned services stopped and storage preservation
passed. Full records remain in the coordinator's rocksdb-batch-fixed campaign.
