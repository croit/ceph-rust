<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0503 Callback domains retain independent progress

Status: accepted
Date: 2026-10-22

## Context

Both pinned clients serialize AIO callbacks separately from watch callbacks;
pool-administration callbacks may execute independently. One adapter callback
thread coupled these domains: an AIO callback waiting for a watch barrier or a
pool callback waiting for an AIO callback prevents the required work progressing.
The configured librados_thread_count had no executor effect; it now sizes the scheduler (`executor.resize`, `callback.rs`).

## Decision

Use one owned callback scheduler per handle with independent AIO and watch
serial domains and an independent pool-administration work domain. Preserve FIFO
within each serial domain and complete-before-safe within each AIO callback.
Apply the positive configured worker capacity before connect and at runtime,
without a fixed ceiling or narrowing to the reference's int16 internal type.
Shrinking affects future dispatch; running callbacks complete normally.
Growing must preserve queued and running ownership if thread creation fails.
Resize and shutdown from callbacks never join the calling thread or wait for
callbacks that depend on the caller. Context observers update every live handle
sharing that context. Avoid holding config, scheduler or completion locks while
calling application code.

A watch barrier completes only after its captured watch prefix. Its async AIO
callback is then delivered through the AIO domain. Synchronous watch flush from
the AIO domain may progress; self-wait on the watch domain returns EDEADLK rather
than hanging. Keep network/control progress independent of application callbacks.

## Rationale

Independent progress is application-visible even without a public thread-ID
promise. Shared scheduling preserves configured concurrency and per-domain
ordering without reproducing the reference pool's self-join hazard.

## Consequences

- + Supported nested callback/wait patterns retain independent progress.
- + Runtime thread-count changes affect actual dispatch capacity.
- + Accepted work retains completion, context and executor until terminal delivery.
- - Scheduler, resize and callback-triggered shutdown need concurrency gates.
- + Out-of-range reference int16 narrowing and self-join bugs are not reproduced.

## Alternatives

- One global callback thread: couples unrelated progress domains.
- One unrestricted pool: breaks serial watch/AIO guarantees.
- Per-operation threads: loses configured resource ownership and scales poorly.

## Open questions

None for the source-grounded domains; exact reference thread IDs and internal
pool/strand topology are not application contracts.
