# How to handle erasure-coded pools

croit-flashstore-osd does not store the shards of unsupported erasure-coded pools. If CRUSH maps an croit-flashstore-osd OSD into such a PG, the OSD declines its role and the PG degrades. Choose one of the fixes below.

## What you will see

- Cluster log warnings, one per pool and OSD per hour: `croit-flashstore-osd osd.N mapped into EC pool P ...`. Find them with `ceph log last 100 | grep croit-flashstore-osd`.
- Health: `PG_DEGRADED`, `PG_BACKFILL_FULL`, or `PG_AVAILABILITY`. `PG_BACKFILL_FULL` is misleading here: croit-flashstore-osd refuses backfill on purpose, and disk space is not the cause. Do not add disk space for it.
- `ceph pg ls-by-pool <pool>` shows the croit-flashstore-osd in the up set and `NONE` in the acting set at its position.

## Fix

Pick one:

1. Exclude croit-flashstore-osd from the pool's CRUSH rule. Give croit-flashstore-osd OSDs their own device class (`nvme` by default) and point the pool at a rule for the classic class:
   ```
   ceph osd pool set <pool> crush_rule <rule-without-croit-flashstore-osd>
   ```
   Data moves to classic OSDs and PGs become clean.
2. Do not create a pool with `allow_ec_optimizations` or an unsupported plugin if croit-flashstore-osd OSDs are in its CRUSH root.
3. Never set `allow_ec_optimizations` on an existing pool with croit-flashstore-osd shards. The flag is sticky: every croit-flashstore-osd shard then counts as lost, even though the data stays on disk.
4. As an interim step while croit-flashstore-osd is an acting primary, set primary-affinity to 0:
   ```
   ceph osd primary-affinity osd.N 0
   ```

## Do not

- Do not `pg-temp` or `pg-upmap` croit-flashstore-osd back into an acting set. It holds no data for these pools.
- A `pg_num` decrease on such a pool waits until fix 1 is applied.

## Verify

```
ceph tell osd.N status
```

`ec_pools[]` shows `supported`, `serves`, `mode` (`serve`, `decline`, or `passive`), and `reason` per pool. A declined pool has `mode: decline`.

## Limits

- A PG with a declined croit-flashstore-osd shard rejects every backfill reservation, so backfill of classic targets in the same PG also stalls. Fix 1 or `pg-upmap-items` clears this.
- A pool that already has data on croit-flashstore-osd and is then rejected by a stricter gate is not declined. Its classic primaries wait. Restore support for the pool, or run `ceph osd lost` after moving the PGs away.

## Configuration

| Option | Default | Meaning |
|---|---|---|
| `ec_enable_pools` | `all` | Legacy EC pools served as shard. |
| `ec_enable_primary` | true | Lead supported legacy EC PGs. |
| `ec_decline_unsupported` | true | Decline pools the gate rejects. |
| `ec_enable_optimized` | all | Optimized EC (`off`, `all` or a pool list). Pools with `allow_ec_optimizations` are declined when off. |
| `ec_enable_optimized_primary` | true | Lead optimized EC PGs. |

Set these with `--set k=v` at start, or at runtime with `ceph tell osd.N config set <option> <value>`. The mon rejects unknown keys in `ceph config set`; use `--force` for flashstore-only keys. See [reference/configuration.md](../reference/configuration.md).

## Clay pools

Clay pools are served as a shard for every profile the mon accepts, except a non-identity `mapping`. Only some profiles can lead a PG on croit-flashstore-osd. For the others, set primary-affinity to 0 on croit-flashstore-osd OSDs. Prefer a stripe unit where the sub-chunk size is a multiple of 64.
