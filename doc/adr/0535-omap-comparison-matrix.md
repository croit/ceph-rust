<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH -->
# 0535 Reusable single-OSD OMAP comparison matrix
Status: proposed
Date: 2026-10-23

## Context
Hot-object index ownership, object distribution, producer processes/threads and
outstanding depth are independent factors. A private one-off population client
does not provide a mergeable read/write/scan regression suite or fair attribution.

## Decision
Use a shared tracked `oprobe omap-load` client and `lab/omap-matrix/` controllers
against fresh single-OSD classic and croit-flashstore-osd clusters. Fix the total dataset;
partition numeric key ownership across global workers. Compare both fixed total
depth and fixed per-worker depth. Scan tasks are complete independent traversals,
with exact cursor/key/value validation before map decoding can hide duplicates.
One-thread execution runs on main; additional producers are explicitly counted.

Use the kernel TCP/kernel NVMe path, identical four-CPU masks and soft memory
targets, explicitly disposable equal-size devices (croit-flashstore-osd: a whole NVMe namespace, never an LV or partition, adr 0468 superseded; classic BlueStore may use an LV), sequential arms, paired repetitions
and separate warmup/smoke namespaces. Keep daemon implementation unchanged from
the pinned mainline. Store all local identities/secrets/device facts/raw receipts
outside the repository. Require exact owner records and one-shot geometry guards.

## Rationale
Separating client concurrency from object placement makes CPU ownership and
contention effects observable without attributing extra outstanding work to
thread count. One client implementation avoids differences between client stacks.
Fresh object prefixes avoid update/population confusion. Reopened exact scans
detect persistence/readback failures without claiming physical power-loss safety.

## Consequences
Mergeable offline partition/decoder/controller tests and a repeatable live suite.
Validation and client polling costs are included in throughput; report them as
limitations. Resource windows and foreground timing are distinct for mixed scans.
The local same-device, loopback comparison does not qualify SPDK, AF_XDP, EC,
mixed-peer operation, replication or production hardware.

## Alternatives
Private binaries: reject, not maintainable/reviewable. Different native client
per arm: reject for this OSD comparison; client-stack comparison is a separate test.
Concurrent OSD arms on one device: reject, introduces uncontrolled interference.

## Additional unequal-CPU experiment

An explicit `CLASSIC_CPU_MODE=unrestricted` variant keeps croit-flashstore-osd at four CPUs
while launching classic without an affinity wrapper or op-shard/thread overrides.
The unpinned controller's full inherited CPU set is checked, not imposed on classic.
Record thread affinity/effective configuration and label the results separately.
Clients/services retain their masks, so unrestricted classic competes with them;
the available VM CPU set is finite and not a dedicated-core allocation. This
variant answers a different question from the matched-budget experiment.

## Eight-object object-first follow-up

Opt-in `TOTAL_KEYS=800000`, `OBJECT_COUNTS=8`, `PARTITION_POLICY=objects` measures
eight objects with100000keys each. The legacy1M/keys-first defaults remain intact.
Pin cardinality and partition policy before resume skips complete blocks; validate
them before report/readcheck/verification. Smoke remains10000keys total.

Assign object o to global worker o mod W when W<=O. When W>O, worker w owns object
w mod O and splits only that object's key interval with its group. Scan workers
retain object ownership and split complete traversals, never speculate on cursor
continuations. Per-object completed counts are retained and independently checked;
aggregate count alone cannot establish object ownership. Mixed scanner stays an
explicit additional independent producer over all objects.

The requested1/4/8producers with8objects therefore own8/2/1wholeobjects each. This
changes contention as requested; it is not comparable as a thread-only change to
old key-first campaigns. Main/helper daemon and formatter artifacts remain fixed;
one rebuilt client with this opt-in feature serves both arms. Old results stay
separate. No claim of1Mtotal/8Mscan entries applies to this800K/6.4Mvariant.
## Open questions

Cold-cache, larger-than-memory and real-device write amplification need dedicated
qualification. This suite deliberately does not change global cache/IRQ settings.
