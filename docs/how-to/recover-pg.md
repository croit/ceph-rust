# How to recover a PG with `croit-flashstore-tool objectstore`

This is the operator procedure for an incomplete PG or a PG that lacks enough copies. It uses the classic PG export format, so a PG can move between classic and croit-flashstore-osd OSDs in either direction.

## Rules

1. The OSD must be stopped. The tool refuses (exit 3) while the admin socket answers.
2. Every mutation is a durable transaction and touches only its PG.
3. Export before you change anything. `export-remove` exports first, then deletes.
4. Keep the export file until the cluster is healthy again.
5. Use `--dry-run` to check a plan. It reads and checks everything and prints `dry-run: Nothing changed`.

## Find the best copy

```
ceph pg <pgid> query            # past_intervals, down_osds_we_would_probe
systemctl stop croit-flashstore-osd@N        # for each candidate OSD
croit-flashstore-tool objectstore --id N --op info --pgid <pgid>
```

Compare `last_update`. The highest value is the most complete copy. Do not start an OSD that must not rejoin.

## Export, import, and clean up

```
croit-flashstore-tool objectstore --id N --op export --pgid <pgid> --file /root/<pgid>.export
croit-flashstore-tool objectstore --id M --op import --file /root/<pgid>.export
systemctl start croit-flashstore-osd@M
ceph pg <pgid> query
ceph pg deep-scrub <pgid>
```

`Export successful` means the file is fsynced. `Import successful` confirms the import.

If another, older copy blocks peering, stop that OSD and run `--op remove --pgid <pgid> --force`.

## Move a PG to another OSD

```
ceph osd set noout
systemctl stop ceph-osd@A ceph-osd@B   # FlashStore OSDs: croit-flashstore-osd@N
# export on A (classic tool or croit-flashstore-tool), import on B
systemctl start ceph-osd@A ceph-osd@B  # FlashStore OSDs: croit-flashstore-osd@N
ceph osd pg-upmap-items <pgid> A B
ceph osd unset noout
```

Preconditions: the target store must not already hold the PG (remove it with `--op remove --force` first), the export epoch must be within the target's map range, and both sides must share the cluster fsid.

## Partial interrupted backfill

If the best copy has `last_backfill` not equal to MAX and the PG stays incomplete, run `--op mark-complete --pgid <pgid>` on that copy only. Objects it lacks are lost. Use this only on the best copy and only with a plan.

## Destructive operations

| Operation | Effect | Use when |
|---|---|---|
| `--op remove --pgid P --force` | Deletes the PG on this OSD. Crash safe. | The copy is superseded. |
| `--op reset-last-complete --pgid P --force` | Sets `last_complete` to `last_update`. Data-loss risk. | Only with a recovery plan. |
| `--op mark-complete --pgid P` | Declares the copy complete. Missing objects are lost. | Best copy, interrupted backfill. |
| `--accept-wal-loss` (on `repair` / `fsck`) | Cuts a corrupt WAL at the damage. Acked transactions are lost (`repair`: permanently; `fsck`: only shown, nothing written). | Last resort, with an accepted loss. |

## PG stopped on implausible past intervals

croit-flashstore-osd differs from classic Ceph here. When a PG's stored history and past intervals do not match the
range peering requires, classic `ceph-osd` aborts the whole OSD and crash-loops on every restart. croit-flashstore-osd
stops only that PG: it stays `incomplete`, serves no client I/O, sends nothing to its peers and writes
nothing. The OSD and its other PGs keep running.

Signals:

- Health warning `FLASHSTORE_PG_PAST_INTERVALS` lists every stopped PG with its required and stored range.
- The OSD log and the cluster log carry one line per PG and interval:
  `ERROR <pgid> past interval bounds implausible: required [a,b) past [c,d): <reason>; PG stopped (inactive)`.

The PG resumes by itself when a later interval passes the check. Otherwise recover it from the best
copy with the export/import procedure above. `osd_skip_check_past_interval_bounds = true` (developer
option, same as classic) disables the check and lets the PG peer with the bad state; it risks data loss
and is not a fix. Set at runtime, it releases a stopped PG at once (peering restarts through the normal
Reset path, no OSD restart needed); set it back to `false` only after the pair has been repaired.

A stopped PG is still deleted normally: deleting its pool or a `MOSDPGRemove` from the acting primary
removes the local copy (only the removal is written, the bad pair is never "repaired" in place).

## Unfound objects

If objects stay unfound after recovery:

```
ceph pg <pgid> mark_unfound_lost <revert|delete>
croit-flashstore-tool objectstore --id N --op fix-lost
```

`fix-lost` clears LOST flags in a store.

## One shard damaged (media error in its meta region)

A store is sharded; a PG lives wholly on one shard (`shard_of_spg` = `(pool + pg_seed) mod S`). If one shard's
tree/WAL meta region is damaged, a normal mount reads every shard and fails, so not even the healthy PGs export.

1. Identify the damaged shard: any op fails with `Mount failed with 'shard S: ...'` (the error names shard `S`).
2. Export the healthy PGs read-only, skipping the damaged shard (nothing is written, the device is untouched):
   ```
   croit-flashstore-tool objectstore --id N --skip-shard S --op list-pgs
   croit-flashstore-tool objectstore --id N --skip-shard S --op export --pgid P --file /root/P.export
   ```
   `--shards 0,1,2` selects shards explicitly; `--skip-shard` subtracts from it. The shard report (stderr in plain
   mode, a `{"shards":[...]}` document in json/json-pretty) lists every shard as `mounted`, `skipped` or `failed`.
3. A PG (or object) on the skipped shard is reported as `shard S skipped` (exit 4), never silently missing; every
   op names the skipped shards on stderr. Every write op is refused with exit 4.
   Shard 0 holds the OSD meta collection and cannot be skipped: with shard 0 damaged, recover the PGs from their
   replicas instead. Stores with an omap engine (LSM/RocksDB) are refused.
4. Import the export into a healthy OSD as usual.

## Exit codes

`objectstore` exits 0 on success, 1 on error, 2 on usage, 3 when the OSD is running, 4 when a degraded read-only mount (`--skip-shard`/`--shards`) refuses an operation (a write op, or a read of a PG whose shard is skipped), 10 when the pool of the imported PG no longer exists, and 12 when the pool split or merged since export and a child or merge target already exists.

## Not available

Pool exports, pre-nautilus exports, and mon-store rebuilds from a FlashStore-only cluster are not provided. `get-osdmap` files do not feed `ceph-monstore-tool rebuild` (it reads only the mon RocksDB keys that `update-mon-db` writes). In a mixed cluster, run classic `ceph-objectstore-tool --op update-mon-db` on a classic OSD to feed the rebuild.
