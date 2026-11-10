# Reference: croit-flashstore-tool

`croit-flashstore-tool` provisions and maintains an croit-flashstore-osd OSD offline. It refuses to touch a device that a running OSD holds.

## Device selection

Every store command takes one of:

| Form | Meaning |
|---|---|
| `--dev spdk:0000:03:00.0[,ns=N]` | NVMe controller by PCI address; `ns=N` selects a namespace. |
| `--dev file:PATH` | File device (development builds only). |
| `--id N [--cluster C] [--conf F]` | OSD by id; resolves the device from the configuration. |
| `--data-path DIR` | OSD data directory. |

One OSD owns one NVMe controller. A controller with several namespaces still gets one OSD.

## Commands

| Command | Purpose | Modifies device? |
|---|---|---|
| `prepare` | Format a new store for an id. | Yes (destructive) |
| `activate` | Check preconditions before start. | No |
| `list` | List OSDs on the host. | No |
| `inspect` | Superblock, OSD dir, LBA geometry, controller, SMART. | No |
| `fsck [--deep]` | Read-only consistency check. `--deep` checks every data block checksum. | No |
| `repair [--deep]` | Replay WAL, checkpoint, check. | Yes |
| `sizes` | Device vs store size and expandable bytes. | No |
| `expand` | Grow the store into a grown device. | Yes |
| `free [--extents]` | Free space and fragmentation. | No |
| `upgrade [--omap-lsm] [--dry-run]` | Convert the store to the format of this build; resumes an interrupted run. `--omap-lsm`: also convert the omap to the omap LSM engine (optional). See [how-to/store-maintenance.md](../how-to/store-maintenance.md). | Yes (`--dry-run`: no) |
| `objectstore --op ...` | PG export, import, and surgery. See [how-to/recover-pg.md](../how-to/recover-pg.md). | Depends on op |
| `dump --dev SPEC --out DIR` | Read-only forensic copy of the store metadata (superblock, shard roots, WAL rings, meta regions). Never mounts. See [how-to/support-bundle.md](../how-to/support-bundle.md). | No |
| `support-bundle (--id N \| --dev SPEC) --out DIR` | Read-only support collection: `dump`, `fsck`, `inspect`, `free`, `list`, version, config and log tail. See [how-to/support-bundle.md](../how-to/support-bundle.md). | No |
| `asok [--id N] [--timeout S] ...` | Admin socket client (also in the production build). The reply wait has no deadline unless `--timeout` is given (exit 124 when it fires). | No |
| `mkfs --dev SPEC ...` | Create the store and register the OSD with the mon, without the OSD directory; production build too. `prepare` is the operator command (adds the OSD directory and keyring). | Yes |
| `bench*`, `crash` | Benchmarks and crash tests. | Development builds only |

Machine-readable output: `--format json` or `--format json-pretty` (default `plain`, for people); `list`, `raw` and `upgrade` (progress) also offer `--format jsonl` (one record per line). Text-only commands accept only `plain`. `croit-flashstore-osd --check` takes the same option.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | Error or inconsistent store |
| 2 | Usage error |
| 3 | Refused: OSD running, or device held |
| 4 | Already prepared (for `prepare`) |
| 5 | Not enough free space (for `upgrade`); nothing was changed |

For the objectstore subcommand, see its own codes in [how-to/recover-pg.md](../how-to/recover-pg.md).

## Examples

```
croit-flashstore-tool fsck --id 7 --deep
croit-flashstore-tool free --id 7 --format json
croit-flashstore-tool sizes --id 7 --format json
croit-flashstore-tool expand --id 7 --format json
```

## Device lock

Every store command takes the device exclusively, through an SPDK PCI claim, a file lock, or `O_EXCL` for kernel devices. A held device returns exit 3. Stop the OSD first. A store command can still write: a mount may rewrite a differing superblock copy, and `repair` writes a checkpoint.

## Not provided

BlueStore label commands, `quick-fix`, BlueFS and RocksDB commands, and separate DB or WAL devices have no equivalent here. Identity is shown by `inspect`. Keys are stored in `<osd dir>/keyring` and managed with `ceph auth`.
