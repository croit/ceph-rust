# How to migrate OSDs to croit-flashstore-osd

croit-flashstore-osd OSDs replace classic OSDs by adding and removing OSDs. Data moves through the cluster's normal backfill. There is no in-place conversion of a BlueStore device.

Two orders work:

1. **Add, then remove.** Deploy croit-flashstore-osd OSDs on new devices, let the cluster backfill onto them, then remove the classic OSDs.
2. **Free, then add.** Remove a classic OSD first to free its NVMe controller, then deploy an croit-flashstore-osd OSD on that device. Use this when the host has no spare slot. While the device is out, PGs that had a copy on it run with one copy less until backfill completes.

Each NVMe controller carries one OSD. A controller that still holds a classic OSD must be freed before croit-flashstore-osd can use it.

## Option 1: add, then remove

1. Deploy the croit-flashstore-osd OSD on a new device. See [how to prepare and activate](prepare-and-activate.md).
2. Wait for `active+clean` on the cluster.
3. Remove the classic OSD. See [replace or remove an OSD](replace-or-remove-osd.md).

Repeat per device. Keep at least one full copy of each PG in the cluster at all times.

## Option 2: free, then add

1. Mark the classic OSD out and wait for `active+clean`: `ceph osd out osd.N`.
2. Stop the classic daemon with your service manager, then purge it: `ceph osd purge osd.N --yes-i-really-mean-it`.
3. Deploy the croit-flashstore-osd OSD on the freed device. The store is new. Run `croit-flashstore-tool prepare` only on the freed device.
4. Wait for `active+clean`.

`prepare` refuses a device that holds a foreign, non-blank store (exit 3). It erases the device only with `--wipe`. Confirm the device before you add it.

## Check before you start

- `ceph health` is `HEALTH_OK`.
- The pools have enough replicas to lose one OSD: `ceph osd pool get <pool> size` and `min_size`.
- The new device passes `croit-flashstore-osd --check` (see [hardware requirements](../reference/hardware-requirements.md)).
- The pools do not use erasure coding on croit-flashstore-osd OSDs. See [how to handle erasure-coded pools](erasure-pools.md).

## Related

- [How to prepare and activate](prepare-and-activate.md)
- [How to replace or remove an OSD](replace-or-remove-osd.md)
- [How to upgrade a cluster](upgrade-rolling.md)
