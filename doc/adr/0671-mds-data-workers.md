<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0671 M0 completion-driven data-object workers

Status: proposed
Date: 2026-11-05

## Context

M0 namespace APPLY records already retain P intents and unlinked inodes.
Data completion and writer-loss recovery must survive replay without blocking
metadata request admission on the data pool. Contracts: mds-store-format s4,
mds-caps-locks s8.6, mds-namespace-semantics s8, cephfs-osd-surface s2.

## Decision

Use the existing completion stream for data-pool stat, generation-tagged
trimtrunc and delete. Pool/namespace come from the inode layout. One purge
worker and one recovery worker per M0 core each admit at most one data request.
P discovery and head-X retirement use pinned, single-entry tablet pages plus
the durable overlay. Startup seeds a bounded ready queue from validated nonempty
tablet totals and replayed P images. Live P/I submissions and cap releases wake
their shard; skipped open/unlinked P intents become idle after that scan. Wake
generations preserve changes arriving during a scan. Buffer exhaustion parks
selection without advancing its cursor or declaring a prefix swept.

Background metadata retirement runs only outside foreground planning, pending
replies, speculative batches and undurable append dependencies. Storage
completions, split progress and native read-admission wakeups remain shared.
The fixed I/P retirement is one aligned block and fits the last valid segment
block; it cannot cross a segment boundary in this format.

Use trimtrunc on affected objects; skip fully retained objects. Probe trimmed
tails and delete empty objects other than object zero with assert-version in
the same compound. A concurrent write invalidates that deletion. P remains
until all data operations and head-X cleanup finish; final I/P deletion is one
metadata APPLY. Replay repeats the immutable intent, including old pools.
Capture the realm snap context before unlink drops owner_link: own and
prior-parent snaps plus parent-context snaps filtered by parent_since; seq is
the maximum realm seq. Truncate of an open unlinked file reuses its saved unlink
P context. Head-X cleanup never removes frozen snapshot X keys.

Fenced SESSION_DETACH waits for the supplied blocklist epoch in the store's
observed map, gathers remaining file caps and drains only earlier truncate
intents for that inode through the recovery worker, independently of purge I/O.
Recovery results carry a runtime detach-job/ino owner; another job cannot
consume them. Park data waits in bounded control descriptors, and park namespace
requests touching a recovery-pending inode in a bounded per-inode wait queue.
Unrelated inodes continue. Reconcile caps and wake those waiters only after
recovered metadata and range retirement are durable. Queued controls for a
detaching session finish before detach validates its ranges.
Persist size-recovery-pending before probing every candidate object, including
past sparse holes. Commit recovered size/mtime, ancestor accounting and range
retirement together before dedup cleanup/DETACHED. Ranges survive interruptions.
The lifecycle driver supplies blocklisting proof; an epoch alone does not
perform blocklisting. M0's backtrace sink remains disabled as specified;
namespace journal encoding/writer belongs to M1 and client hints to M7.

Data errors never enter metadata-core failure handling. Object ENOENT is an
idempotent success/empty probe. Missing pools (including native NoPool) skip that
pool, retaining the recovery size floor. Local admission capacity waits for
credit. Remote resource, permission, unsupported-operation, I/O and ambiguous
errors emit a health warning and park the durable P/range without retrying
until the observed OSD map changes or replay reconstructs the worker. Native
remote ENOSPC/ENOMEM are preserved as errors, not local admission pressure.

## Rationale

Generation-tagged trimming prevents replay from shrinking writes that already
carry that generation. A version-guarded empty-tail delete closes the subsequent
probe/delete race without locks on the data path or new OSD operations. Metadata
scans pin source tablets so a concurrent split cannot remove an active reader.

## Consequences

Bounded memory and work per tick; no per-object durable progress records.
A crash may repeat already-completed data work. Initial P discovery visits
nonempty owned shard tablets plus the replayed overlay; larger concurrent data
batches remain a measured performance follow-up. Adapter request construction
retains the allocation exception
already recorded in IMPL-9. Native data-pool integration still needs live lab
qualification; memory-store tests do not claim classic/EC qualification.
Siblings checked: memory and native RADOS share worker/error policy; native
compound tests cover pools/namespaces, snapshots, guarded deletes and trim
generations. Replicated/EC use the same data operations (unsupported EC
overwrite replies park). knet/AF_XDP, SPDK/kernel NVMe and crc/secure framing
are not changed: these workers operate above transport and storage tiers.

## Alternatives

- Unconditional tail deletes on replay: can delete concurrent growth.
- Per-object progress keys: more metadata/log traffic and crash states.
- Per-file MDS backtrace xattrs: rejected by the scale-out MDS ADR.

## Open questions

- P.old_pools preserves pool IDs but no prior namespace/layout history. Specify
  how a namespace change purges objects created under an earlier namespace
  (proposed IMPL-16); do not invent an encoding in step 5c.
- FE reconnect adoption (CAP_IN mode 4) remains the FE lane's integration work.
