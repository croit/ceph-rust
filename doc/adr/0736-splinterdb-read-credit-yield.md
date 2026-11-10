<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# 0736 Foreign read-credit waits remain yieldable

Status: proposed; regression and fresh live qualification in progress
Date: 2026-11-08
Amends: 0732-splinterdb-throughput-pipeline, ADR0021 fallback assumptions

## Context

Concurrent scans exposed a same-core dependency: SplinterDB retains one request's
read credit across owner slices, but another request's admission refusal was
treated as an independently progressing IO miss. After64 refusals or30s the
executor selected blocking execution. Pumping storage cannot run the suspended
credit owner. The old30s idle expiry could discard that owner's retained work,
but is not a normal way to resolve contention. Baseline cell5 produced60s RPC
timeouts and30s core stalls; exact first escalation was not captured.

## Decision

Classify selected-SplinterDB OMAP credit contention separately from a page miss.
Always return WouldBlock for competing tagged requests, even in blocking fallback. Carry
the classification through the static store adapter/PG view. The executor must
honor blocked reads in fallback too, preserve original operations, and keep a
known local waiter nonblocking on its next run. Local admission waits do not
count as failed page-load attempts or pretend to be progress. An unnamed release
wake retries the waiter. Retain genuine independent-IO fallback, ownership expiry
for abandoned requests, one credit, cache/memory budgets and existing owner slices.

No changes to nativeLSM/RocksDB/B-tree admission, foreign helpers/placement,
barriers, WAL/ACK authority, on-disk format or client workload. The new view hook
defaults tofalse. Apply this correctness repair equally to scale0 and101 before
comparing them; failed pre-repair evidence is not a completed baseline.

## Validation

Independent executor fixtures cross both escalation boundaries and first encounter
local credit after genuine IO fallback; real Store requests compete across32
transaction identities including four per connection. Verify exact scans, owner
retention/release wake, nonblocking admission and unrelated progress. Existing
genuine-stall regression must remain green. No timeout extension, fake progress,
extra worker/cache allocation or changed durability policy is an acceptable fix.

## Sessionless recovery boundary

An unconditional credit refusal is unsafe outside the executor: recovery converts
WouldBlock to an IO failure and can report a healthy object unavailable. A real
StoreAdapter held-scan/build-push regression reproduces that failure. Do not send a
new wire Busy response, discard a pull, mark damage, or block waiting for owner A.

Sessionless reads instead use the existing single pending worker-read slot. A's
completion is consumed/charged before an independent B job can be submitted. Page
answers with no captured session use the ordinary bounded answer cache, without
scan prediction; tagged pages keep their captured owner and stale-page rejection.
Sessionless Keys/Ids do not interrupt A's window. Delivered loan/page answers leave
the ordinary cache. Full query identity and normal flush invalidation still apply.
FIFO children keep their actual mapped session; blocking tagged reads do not become
sessionless just because they have no scan memo.

A synchronous Store read brackets only its sessionless duration so worker polling
cannot expire A while A cannot run. Preserve idle age before the call, restore the
expiry clock on success/error, and retain ordinary abandonment/release wakes. Do
not suspend expiry across nonblocking scheduler turns.

This retains one executor credit, one pending foreign query, the same worker and
cache capacity. It is not a hard peak-byte bound: a first oversized row or complete
by-keys answer can exceed its soft allowance while A remains retained. Charge that
answer, consume it without accumulating loan outputs, and never truncate it. Live
RSS/cache measurements and this oversize exception remain explicit qualifications.
Tests cover actual sliced scans through replicated/EC reads, completion ordering,
expiry, tagged/FIFO ownership, exhausted allowance, oversize replies and read-view
identity/invalidation. No peering-state or wire behavior change is required.

## FIFO visibility barriers

A recovery read can first drain a queued clone/translation that itself waits for
A's credit. Bracketing only the final read is too late. The synchronous queue drain
therefore enters an explicit independent foreign-query scope on selected shards.
Real STAGE/BUILD tags and native retention remain; only foreign pages are one-shot,
without Splinter memos, owner acquisition or window replacement. Only their worker
wait is synchronous. Native page/allocation/admission and elastic-lending waits
remain nonblocking, and existing preparation/submission/durable ACK order remains.

Entering the new policy gives the selected FIFO head one retry. It is not IO or
stall progress; tracked page dependencies and existing deadlines still gate it.
The complete drain pauses idle expiry, nested read scopes cannot end that pause,
and cleanup checks owner identity before restoring idle age. Finishing an
unadmitted tag or independent child must not cancel A's worker epoch/window.

Queue builders translate within their assigned shard, without recursively draining
or running blocking transactions. A recursive drain with queued work is rejected
before polling followers; a nestable foreign-read scope is not a reentrant Store.
Whole-clone output remains an existing soft-memory/latency exception: bounded worker
pages do not bound its accumulated transaction. Tests hold A across an already
credit-blocked Clone and a real foreign-reading QueueBuilder, verify recovery
visibility, FIFO acknowledgements, exact results and A's retained scan.
