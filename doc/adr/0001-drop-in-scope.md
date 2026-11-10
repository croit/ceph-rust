# 0001 Drop-in scope, NVMe-only, no on-disk compat
Status: accepted
Date: 2026-10-09
Context: Classic ceph-osd slow on NVMe due to HDD-era design. Goal: replace daemon, keep clusters.
Decision: Wire-compatible OSD. Fresh unpartitioned NVMe only. Own on-disk format. Migration via add-new/remove-old OSDs. No Python anywhere in project.
Consequences: + freedom in storage engine, threading, I/O path. - must implement full protocol incl. peering/recovery/scrub/cls; native replacement for ceph-volume.
Alternatives: optimize BlueStore in place (rejected: legacy constraints); on-disk BlueStore compat (rejected: no value, migration via rebalance is standard).
