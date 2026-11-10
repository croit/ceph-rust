<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# 0734 Bounded SplinterDB normal-maintenance offload

Status: proposed; implementation candidate with scoped offline qualification
Date: 2026-11-06
Extends: 0733-splinterdb-cleaner-placement

## Context

The foreign file worker remains close to one CPU after cleaner separation.
Existing profiles identify packing/merge/cache work but lack sufficient ancestry
to apportion normal versus memtable maintenance. Native LSM demonstrates the
single-authoritative-owner/immutable-helper pattern, not permission for multiple
foreign API writers or unbounded maintenance threads.

## Decision

Prepare one default-off normal-maintenance-pool candidate. Keep memtable workers
zero, foreground assistance enabled, cache/memtable sizes, I/O mode, native WAL,
both foreign barriers and watermark/native publication unchanged. Retain the
cleaner-isolation baseline; do not bundle submission aggregation or bulk ingest.
No performance benefit is claimed before permission to validate.

Only resolved multicore daemon placement may enable the candidate. Require
explicit cleaner isolation, open under that already-assigned CPU so the existing
library worker inherits its mask, prime the cleaner, restore the file worker,
then publish readiness. Single-core/offline/unresolved/equal-CPU paths use no
maintenance worker. No process-wide affinity change or thread-name-based pinning.

Reject concurrent raw cache-counter sampling with the maintenance worker; those
counters do not have a synchronized cross-thread sampling contract. Aggregate
registered-thread admission and stack memory must be bounded before open, with
reservations retained through library close and worker join. Queue scale and
any other necessary pinned scheduler policy require an explicit own-words
contract below, not an assumed upstream default.

The startup option is `flashstore_store_splinterdb_normal_maintenance=false`.
It prepares a normal-pool candidate; it is not a finding that normal tasks
dominate this workload. Dynamic selection remains conditional on attribution.

## Pinned contracts and admission

SplinterDB73f89d8 provides two independently configured task groups. Memtable
callbacks pack finalized memtables, incorporate them and advance eligible
checkpoints; normal callbacks compact immutable branches and build routing
filters. Both can reach packing, so a packing leaf alone cannot select a pool.
Diagnostic markers, classified by the nearest active callback:

- Memtable: `core_memtable_flush_internal_virtual`,
  `core_memtable_flush_internal`, `core_memtable_compact`.
- Normal: `bundle_compaction_task`, `maplet_compaction_task`.
- `core_durable_barrier_task` is asynchronous normal-pool work, not the explicit
  blocking barriers used by our wrapper.

Relevant pinned contracts: core.c1692–1746,4395–4452;
trunk.c5399–5454,5559–5566,5614–5709,5809–5812. No library source is modified.
Keep queue scale0: foreground assistance attempts available work. With one worker,
scale100 would also assist when a task waits, so changing it is unnecessary.
task.c363–427 supplies this policy contract.

Registered IDs are shared across instances. Reserve one credit per distinct API
caller and one per helper before native open, at most63 total with one spare.
Multiple handles on a caller share its credit. Native close alone does not
deregister that caller; explicitly deregister only after its last native handle
has closed/joined, then release its credit. Validate exact registration identity;
if it disappeared unexpectedly, retain the credit and disable that caller rather
than inferring successful cleanup or manipulating private native TLS. Validate
after every native open attempt, including errors while another handle stays
live, and before reusing an existing caller credit. Poisoned database/lookup/
cursor APIs refuse further native access. Unresolved native handles, borrowed
state and helper credits are retained rather than auto-registering to close;
this exceptional failure is not successful cleanup or durability. Runtime
offload admission permits at most31 native shards; the63-shard format limit is
unchanged. Open errors and timeouts must retain any still-owned reservations.
Contracts: platform_threads.c158–245,379–462,486–533.

The library uses default pthread attributes. Query the current default stack and
guard before open; subtract that cost from existing read-retention credit. Keep
foreign cache/memtable sizes and the process memory target unchanged. Refuse an
insufficient read allowance. This accounts for stacks, not a hard bound on task
queues, allocator overhead or all engine memory; the overall target remains soft.

Sample task-busy through the pinned task-system accessor and
`task_system_is_quiescent` (splinterdb.c1613–1617,task.c440–471). It holds both
group locks and observes queued/running work coherently, unlike separate atomic
counter reads during queued→running transfer. Sampling runs on the file worker,
not per foreground operation. Expose configured worker count, task-busy shards
and charged stack bytes with the existing sample-valid/age envelope. This is not
dirty-cache, retained-log or future-overlay debt; require all existing drain and
quiet-window conditions too. A failed/stale sample is not an idle certificate.

## Historical attribution and qualification hold (2026-11-06)

User explicitly forbids tests and test06 use until asked, while another session
tests. This iteration is source-only: no tests, builds, profiling, SSH, deploy or
live runs. Regression code may be authored but must be labelled unrun. Baseline
placement results do not validate this new code.

Before a live comparison, restore diagnostic ancestry without editing library
source (a separate diagnostic build can use compiler unwind/frame-pointer flags),
identify normal/memtable task ancestors, then measure one candidate against
isolation-only SDB and native LSM with fresh sequential cells1–4. Include actual
worker counts/masks, total CPU, p99, memory and settled debt; foreign overlay zero
alone is not proof that a background task queue is idle.

## Alternatives / limits

Adding foreground DB callers, both pools at once, disabling assistance, growing
caches, removing the foreign log or either barrier are not this experiment.
Library workers are not native LSM's cooperatively time-sliced continuations.
Library I/O and close remain noncancellable; do not force-free pending state or
claim a hard completion deadline. Cleaner/worker creation failures may assert.
Stage attribution and performance qualification remain open.

## 2026-11-07 qualification update

The user lifted the test06 hold for a bounded nine-cell8Mi-key comparison using
eight sessions/QD1 and three distinct200GiB LVs: maintenance-off, maintenance-on,
native LSM, fresh sequential clusters. This is authorization to test the normal
pool candidate, not evidence that normal callbacks dominate. No default change.

Focused binding/Store/OSD/tool tests passed with native, Rocks-only, Splinter-only
and combined relevant configurations. Covered both barriers with failure vectors,
placement/stack admission, selected configuration and replay-buffer isolation,
shared golden formats and the separate bit26 serialized header. Abrupt-process
prefix vectors cover off/on, direct/buffered and three prefix phases: all twelve
passed, with added updates/packing in the six maintenance-enabled cases only.
Repeated maintenance samples and independent reopened values pass. These do not
ensure active tasks at the exact exit instant, exercise full
native-ACK crash replay, or qualify physical power loss/native thread failures.
Kernel daemon and no-default-features production tool release builds completed.
The nine-cell comparison (doc not in the source snapshot) completed
27/27 measured cells with zero operation errors and verified sequential cleanup.
Insertion/update rates improved22.3%/10.5% against maintenance-off, while their
p99 increased51.8%/90.0%. Foreground sum fell7.62%; continuous OSD CPU work was
essentially unchanged. Keep default-off: one pass, cache/I/O-policy asymmetry
against native LSM, and open fault/physical-durability qualification prevent a
general performance or production recommendation. No new pool/queue/cache policy.
