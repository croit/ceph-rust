# How to maintain the store

The store is the on-device data of one OSD. These commands check, repair, grow and inspect it. All of them run offline: stop the OSD first.

Commands are run with `croit-flashstore-tool`. Each command takes one device selector:

- `--id <n>` (with `--cluster <name>` if not `ceph`): the OSD from its configuration.
- `--dev <spec>`: the device, for example `spdk:<pci>`.
- `--data-path <dir>`: the OSD data directory.

## Before you start

1. Stop the OSD with your service manager (for systemd: `systemctl stop croit-flashstore-osd@<id>`).
2. Confirm it is stopped. The commands refuse to run while the admin socket answers, and exit with code 3.
3. For `repair` and `expand`, take a copy of the device if you can. Neither command has an undo.

## Check the store: `fsck`

```
croit-flashstore-tool fsck --id 0
croit-flashstore-tool fsck --id 0 --deep
```

`fsck` mounts the store read-only, which replays the write-ahead log in memory, and then checks:

- the checkpointed state of each shard,
- the object layer.

`--deep` also verifies the checksum of every block. It reads the whole device and takes longer.

Output: `fsck success` or `fsck found <n> error(s)`. The problems are printed to stderr. Exit code `0` means no problem, `1` means problems were found or an error occurred, `3` means refused.

`fsck` never writes to the device. Unlike `repair`, it does not make the replayed state durable and does not heal a superblock copy. Run `repair` for that.

### Dropped write-ahead log tail: `wal_tail_dropped`

When the replay finds a tail of the write-ahead log that fails validation and no later record proves that it was acknowledged, it drops that tail. This is informational and never an error: the exit code and the error count stay unchanged. BlueStore's RocksDB does the same with its point-in-time recovery.

- Plain output: one line per shard before the verdict, `fsck: WAL tail dropped: shard <n>: lsn <first>..<last> (<k> txns), <reason> at block <b>; dropped as torn tail`.
- JSON output (`--format json`): the field `wal_tail_dropped` is an array, empty when nothing was dropped. Each object has `shard`, `first_lsn`, `last_lsn`, `txns`, `block` and `reason`. `fsck` and `repair` both print it.
- The OSD logs the same event at every mount: `WAL replay stopped at lsn <n> (...): tail from lsn <m> dropped as torn (unacknowledged in-flight writes or media corruption)`.

Meaning: the dropped transactions were in flight at a crash or power loss and were never acknowledged to a client, or, rarely, the media corrupted them. Nothing acknowledged is lost. This differs from `wal_lost` below, where acknowledged transactions are at risk and the mount refuses.

What to do: nothing for pools of size 2 or 3, because peering recovers anything missing from the replicas. If the message repeats without a preceding crash or power loss, check the device health (`croit-flashstore-tool inspect --id N` shows SMART data) and consider replacing the drive.

## Repair the store: `repair`

```
croit-flashstore-tool repair --id 0
```

`repair` first runs the whole repair in memory, without writing to the device. Only when that dry pass finds nothing it must refuse does it mount the store, replay the write-ahead log and write a checkpoint so that the replayed state is durable. Like every mount, it also rewrites a superblock copy that differs from the other copy. It then fixes what `fsck` reports and what can be fixed safely: data blocks that are allocated but used by nothing are freed, data blocks that are in use but marked free are marked allocated again, wrong reference counts of shared (cloned) blocks are recomputed, a block claimed by two objects is copied so that each object has its own (both read exactly what they read before), and the usage counters of the store, of each collection and of compressed objects are recomputed from what is actually stored. It prints the findings before the repair, every action taken and the result of the checks afterwards (`--format json`: fields `before`, `actions`, `after`). If it is interrupted, run it again.

Metadata cells that hold live pages but are marked free are also repairable. Only the repair mount admits them:
it protects their blocks before replay and writes their allocation with a checkpoint. The dry pass includes this
checkpoint in memory. Normal OSD, fsck and export mounts still refuse until repair completes. A power loss during
repair is safe to rerun; no special recovery flag is needed for this allocation correction.

`repair` refuses, and writes nothing (exit code 3), when the tree or a data block is damaged, including a block claimed by two objects whose stored checksum no longer matches. For those, two options remain:

- Export the PGs and recreate the OSD. See [recover a PG](recover-pg.md). The export uses `croit-flashstore-tool objectstore --op export`.
- Let scrub repair the object from its replicas. See the scrub commands in [admin commands](../reference/admin-commands.md).

## Recover from lost write-ahead log entries: `--accept-wal-loss`

When the store refuses to mount with `WalLost` (or `WAL CORRUPT`), do not accept the loss blind. Inspect the ring first, decide, then accept.

### 1. Inspect (read-only)

```
croit-flashstore-tool wal-inspect --id 0
croit-flashstore-tool wal-inspect --id 0 --preview-loss --format json
```

`wal-inspect` decodes each shard's write-ahead log ring without mounting and without writing. It reports, per unit, the lsn, acked_lsn, store_id, epoch and validity (crc ok / torn / foreign); per record, the txn op summary (collection/PG, object, op kind, bytes); and where replay stops and why:

- `end` / `torn` / `foreign` — the log ends at an empty block, a block that holds no valid unit (a torn write or an older ring lap) or a unit that does not continue the chain. No acknowledged transaction is lost; the store mounts normally.
- `data_crc` — a unit names a data block whose checksum does not verify. Without a later witness this is a torn tail.
- `wal_lost` — a unit written after the cut proves transactions `lsn..=acked_lsn` were acknowledged and are now unreadable (media corruption). This is the data-loss case.

`--preview-loss` lists the records the cut would drop: the lsn range, the PGs and the objects. The cut drops every transaction from `lsn` on; the records of the unreadable unit itself cannot be listed. Nothing is written.

### 2. Decide

- No `wal_lost` (or no `--preview-loss` records): the refusal is not a WAL loss. Re-run `fsck` and look elsewhere.
- `wal_lost` with objects that have replicas: accept the loss; peering recovers them.
- `wal_lost` affecting a last-copy PG: export what remains and recover from replicas before accepting (see [recover a PG](recover-pg.md)).

### 3. Accept

```
croit-flashstore-tool repair --id 0 --accept-wal-loss
```

`fsck` and `repair` accept `--accept-wal-loss`. With `fsck`, the flag only shows the store as it would be after the cut: nothing is written, and the next mount still refuses. With `repair`, the cut becomes permanent: the store mounts at the last good log position. Acknowledged transactions after that position are lost. The store is consistent up to that point. Peering then sees the OSD as behind and recovers the missing objects from the other replicas.

Without the flag, the store refuses to mount. Do not use the flag as a routine fix.

## Grow the store after the device grew: `expand`

```
croit-flashstore-tool expand --id 0
croit-flashstore-tool sizes --id 0
```

`sizes` shows the device size, the store size, the data capacity, the shard count and the number of past expansions. It also shows how much a further `expand` would add.

`expand` gives each shard an equal part of the new space. The part is rounded down to a multiple of 16 MiB per shard. If the device did not grow by at least 16 MiB per shard, `expand` does nothing and exits with code `0`.

Limits:

- A store created with the chunked layout cannot be expanded. Recreate the OSD instead.
- A device smaller than the store is refused. The store never shrinks.
- The block size of the device must match the store.

Expansion is recorded in the store. `sizes` shows the count.

## Inspect free space: `free`

```
croit-flashstore-tool free --id 0
croit-flashstore-tool free --id 0 --extents
```

`free` mounts the store and reports the free data space:

- free bytes,
- number of free extents,
- largest extent,
- fragmentation score (0 means one run, 1 means all single blocks),
- fragmentation rating (the share of free space that is not in large runs).

`--extents` adds the list of free extents as byte offsets and lengths.

The OSD answers the same request online with `store free`. See [admin commands](../reference/admin-commands.md).

## Upgrade the store format: `upgrade`

A new croit-flashstore-osd version can need a newer store format. When the format needs a conversion that takes longer than a start
should, the OSD refuses to start, exits with code 78 and prints the command to run, for example:

```
store upgrade needed: ...; with this OSD stopped run: croit-flashstore-tool upgrade --dev <spec>
```

Run the command with the OSD stopped. Set `noout` first so that the cluster does not start to move data while the OSD is
down (`ceph osd set noout`; clear it with `ceph osd unset noout` when the OSD is back). Upgrade one OSD at a time.

```
croit-flashstore-tool upgrade --id 0 --dry-run
croit-flashstore-tool upgrade --id 0
croit-flashstore-tool upgrade --id 0 --format jsonl
```

- `--dry-run` shows the steps that would run. It reads only the superblock and writes nothing.
- Without `--dry-run` the command runs the steps. It prints one progress line per batch and shard. `--format jsonl`
  prints the same as one JSON record per line (`event`: `plan`, `survey`, `mark`, `progress`, `shard_done`,
  `step_done`, and a final `result`). `json` and `json-pretty` print one document at the end.
- `--omap-lsm` converts the omap of the store to the omap LSM engine. This step is optional for now: it runs only when
  you ask for it.
- The command first checks that every shard has the free space the conversion needs. If not, it exits with code 5,
  names the shard and the missing bytes, and changes nothing.
- The conversion is crash safe. If it stops (power loss, crash, Ctrl-C), run the same command again: it continues where
  it stopped. Until it has finished, the OSD refuses to start (exit 78).
- A store that is already in the current format needs nothing: the command reports that it is up to date and writes
  nothing.
- There is no downgrade. After a step has run, an older croit-flashstore-osd version refuses the store (exit 78, "downgrade not
  possible"). Use `--dry-run` to see what would change before you upgrade.

## Output formats

- `--format plain` (default), `json`, `json-pretty`; `upgrade` also `jsonl`.
- `fsck --md5` prints plain lines only and is a lab command.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, or nothing to do |
| 1 | Error, or problems found |
| 2 | Usage error |
| 3 | Refused: the OSD runs or holds the device |
| 5 | `upgrade`: a shard lacks the free space; nothing was changed |

See also [reference: exit codes](../reference/exit-codes.md).

## Related

- [Reference: croit-flashstore-tool](../reference/croit-flashstore-tool.md)
- [How to recover a PG](recover-pg.md)
- [How to replace or remove an OSD](replace-or-remove-osd.md)
- [How to collect a support bundle](support-bundle.md)
