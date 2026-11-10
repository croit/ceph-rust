# How to collect a support bundle

When an OSD is corrupt or a store misbehaves, support needs a read-only image of the store's metadata. `support-bundle` collects it into one directory. It writes nothing to the device: stop the OSD first, like for every offline command.

## Collect the bundle

```
croit-flashstore-tool support-bundle --id 0 --out /tmp/osd-0-support
croit-flashstore-tool support-bundle --dev spdk:0000:03:00.0 --out /tmp/osd-0-support
```

`--out` is required and is the only place anything is written. The command refuses to run while the OSD's admin socket answers, or while the device is held (exit 3).

The bundle contains, under `--out`:

- `dump/` — forensic copy of the superblock and each shard's metadata (roots, WAL ring, meta region).
- `fsck.txt`, `inspect.txt`, `free.txt`, `list.txt` — the read-only output of those commands.
- `version.txt` — the tool version.
- `ceph.conf` — the OSD's configuration file.
- `log.txt` — the tail of the OSD log, when `--id` is given and the log is present.

`--format json` prints a machine-readable summary: the collected files with their sizes and each step's exit status.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every step succeeded |
| 1 | A step failed |
| 2 | Usage error |
| 3 | Refused: the OSD runs or holds the device |

## The metadata image: `dump`

`dump` is the BlueStore `bluefs-export` equivalent. It copies everything but the data area, without mounting the store:

```
croit-flashstore-tool dump --dev spdk:0000:03:00.0 --out /tmp/osd-0-meta
```

Output: `super.txt` (superblock and shard directory) and `shard<N>.img` (per-shard roots, WAL ring, meta region; sparse, all-zero 1 MiB chunks are skipped). It reads the device and never writes to it.

## Related

- [How to maintain the store](store-maintenance.md)
- [Reference: croit-flashstore-tool](../reference/croit-flashstore-tool.md)
