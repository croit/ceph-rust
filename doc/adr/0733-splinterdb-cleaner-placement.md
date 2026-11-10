<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# 0733 Separate the existing SplinterDB cleaner within the assigned CPU budget

Status: proposed, opt-in experiment; bounded offline/live checks complete, no production qualification
Date: 2026-11-06
Extends: 0732-splinterdb-throughput-pipeline

## Context

Profiling found the hot file worker, its existing LAIO cleaner and a native core
sharing one CPU at roughly94–95% sampled occupancy, despite spare capacity in
the four-core budget. This suggests a placement experiment, not a demonstrated
speedup. No additional maintenance pool or foreground DB writer is needed.

## Decision

Add a startup-only, default-off cleaner-isolation option. The daemon keeps the
file worker on the next entry of its resolved CPU vector and selects the entry
after that for its cleaner. Use vector indices, including sparse mappings; never
guess CPU IDs. Single-core and mounts without a resolved pair retain the legacy
path. PG/native ownership, memory budgets, engine settings and defaults remain.

On the existing file worker: validate/pin its worker CPU, lock the identity-bound
image, temporarily pin only this thread to the cleaner CPU, then open the DB.
Perform one completed asynchronous read of the first superblock page through
the revision-pinned IO interface before restoring the file-worker CPU. Only then
publish startup success and serve requests. No process-wide affinity changes,
thread-name-based pinning, dummy writes or third-party modifications.

The temporary page and request are private cold-start resources. Bound the read
to the effective configured page size, validate readability and alignment, and
retain both until terminal completion and successful result validation. A
callback can mean retry progress rather than completion. Use synchronized
readiness and rerun the request until its terminal status; never free pending
state merely because a callback arrived or an outer timeout fired.

Reported startup errors must close the DB on the owning worker and join that
exact worker. Existing library/open execution is not cancellable: the30s outer
startup timeout may return while the worker retains resources until its blocking
operation finishes, then closes without serving. Do not claim a hard IO-time
bound or force-free outstanding buffers. Library cleaner-thread creation can
assert on failure; this experiment does not make that failure recoverable.

## Pinned IO contract, own words

At SplinterDB73f89d8, register-thread and get-context hooks are unset for LAIO;
synchronous reads and empty async requests do not create the cleaner. A real
nonempty async read creates or reuses its existing per-handle/process context
before submission. Cleaner creation inherits the caller's singleton Linux CPU
mask. Re-pinning the caller does not move that already-created thread.

Use the existing IO-handle accessor, range/read request operations and header-
defined request storage. Read offset0, one effective page; wait for terminal
status, validate short/error results, deinitialize only after completion. Close
joins the existing cleaner and destroys the context. No extra registered thread
ID or additional context is required. Relevant library contracts:
platform_io.h185–255;laio.c449–493,593–722,768–798,866–913;
superblock.c18–23. These are library contracts, not classic Ceph source.

## Invariants / alternatives

Both foreign barriers, watermark/native publication and native-WAL ACK/replay
authority stay unchanged. Both maintenance pools remain0. Buffered IO remains
default; explicit direct IO remains available. No persistent format change.

Merely pinning around open does not prove lazy initialization placement. Moving
threads after discovering their names is rejected. More CPUs, new background
pools, cache growth and IO batching are separate experiments, not bundled here.

## Acceptance

Independent Rust regressions: sparse/single-core CPU mapping, default/offline
fallback, both IO modes, repeated priming with no additional cleaner, data
preservation, close/reopen, startup prime/re-pin failure cleanup and owned join.
Retain existing native-ACK/replay and both-barrier failure coverage. Verify live
worker/cleaner masks, counts and per-thread CPU rather than trusting the option.

Compare fresh sequential unprofiled cells1–4 with identical budgets/settings,
report throughput, CPU-seconds, p99 and settlement. A small single-pass delta is
not a statistically qualified gain; no production promotion is assumed.

Bounded qualification and observed single-pass result:
placement comparison (doc not in the source snapshot).
