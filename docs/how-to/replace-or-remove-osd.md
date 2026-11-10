# How to replace or remove an croit-flashstore-osd OSD

Removing an OSD is a cluster operation first and a host operation second. Never wipe the device while the cluster still depends on it.

## Remove a healthy OSD

```
ceph osd out osd.N
ceph osd safe-to-destroy osd.N     # repeat until it reports safe
systemctl stop croit-flashstore-osd@N
ceph osd purge osd.N --yes-i-really-mean-it
```

Wait for `active+clean` and for `safe-to-destroy` to report safe before you stop the OSD. `safe-to-destroy` reports "not safe" while the OSD still holds PGs that would lose their last copy.

The device still holds the old store after the purge; `croit-flashstore-tool objectstore --op list-pgs` lists it and is never empty, so it is not a check. To reuse the device, prepare it again with `croit-flashstore-tool prepare --dev spdk:<pci> --id <new-id> --wipe`. Confirm the flag with `--help` before running; the device is destroyed.

## Replace a failed device

1. Run `ceph osd out osd.N` while the failed OSD is still up, if possible, so backfill starts early.
2. Confirm the cluster no longer needs the OSD before wiping anything: run `ceph osd safe-to-destroy osd.N`. It reports "not safe" while the OSD still holds PGs that would lose their last copy. Repeat the command and wait until it reports safe; do not wipe the device before it does.
3. Stop the OSD: `systemctl stop croit-flashstore-osd@N`.
4. Remove the OSD but keep its id: `ceph osd destroy osd.N --yes-i-really-mean-it`. Use `destroy`, not `purge`, when the id is reused; `purge` removes the id from the map.
5. Replace the drive.
6. Prepare the replacement with the same id: `croit-flashstore-tool prepare --dev spdk:<pci> --id N --wipe`. Confirm the flag with `--help` before running; the device is destroyed.
7. Start the OSD and wait for `active+clean`.

## Verify

```
ceph osd tree
ceph pg stat
```

## Destructive points

- `prepare` deallocates the whole namespace. Run it only on the replacement device.
- `purge` removes the OSD from the map. The data it held is re-replicated from the remaining copies.
- Do not run `purge` while PGs are still degraded on that OSD, unless the loss is accepted.
