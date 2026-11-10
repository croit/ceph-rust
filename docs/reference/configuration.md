# Reference: configuration

Options are read from `/etc/ceph/<cluster>.conf`, in `[osd]` or `[osd.N]` sections. Options can also be set with `--set key=value` on the `croit-flashstore-osd run` command line, and changed in a running daemon with `ceph tell osd.N config set <option> <value>`. Whether a running change takes effect immediately depends on the option.

Defaults are taken from the source. The store options in the "fixed at prepare" section are read when the store is created; changing them later has no effect on an existing store.

## Network and identity

| Option | Default | Values | Notes |
|---|---|---|---|
| `flashstore_rdma` | `false` | `true`, `false` | Upgrade connections to RDMA (RoCEv2) when both peers support it; otherwise they stay on TCP. Needs a binary built with the `rdma` feature; the daemon refuses to start without the feature. The devices of the public and cluster addresses are used; an address without a usable RoCE port (interface MTU below 1120, i.e. RoCE path MTU below 1024; 1500 works with lower throughput, 9000 is best, see [enable RDMA](../how-to/enable-rdma.md#fabric)) stays on TCP, logged once at start. |
| `flashstore_rdma_memory` | 256 MiB | bytes, `K`/`M`/`G` suffix | Pinned (registered) RDMA buffers of the whole OSD process, split evenly over cores x RDMA devices; only with `flashstore_rdma = true`. Separate from, and on top of, `osd_memory_target`. Each (core, device) part needs at least 6 MiB, else the daemon refuses to start (the default 256 MiB covers 8 cores on two devices: 16 MiB per part); `RLIMIT_MEMLOCK` must cover it (`LimitMEMLOCK=infinity`). The memory is per core and never grows with the number of peers: the receive slots are shared by all sessions of a core, each starts with a 3-credit window and borrows more while it is busy (see `flashstore_rdma_max_sessions` for the session limit). A core holds at most `receive slots / 3` sessions (113 at the default 256 MiB over 8 cores and one device: 341 receive slots per core); a connection beyond that stays on TCP and counts in `rdma_sessions_capped`. Large output chunks (>= 64 KiB) in the payload hugepage heap are sent without a copy (always on): the heap is registered once per RDMA device at start and counts against `RLIMIT_MEMLOCK` once per device on top of this budget; without a heap (binary without `spdk`, no `kernel:`/`spdk:` store) everything is copied. Counters `rdma_zc_bytes`, `rdma_zc_misses`. |
| `flashstore_rdma_max_sessions` | 0 (unlimited) | number | Most RDMA sessions of the whole OSD process (all cores and devices). A connection beyond it stays on TCP, a normal connection, never an error; it is counted in `rdma_sessions_capped` and logged to the cluster log as a warning (`rdma: max_sessions N reached, new connections stay on TCP`, then at most one summary per 10 minutes, one line when the session count falls back). Only with `flashstore_rdma = true`. |
| `flashstore_report_objectstore` | `bluestore` | `bluestore`, `flashstore` | Store name the OSD reports to mons, mgrs and CLIs; read at start (restart to change), any other value refuses the start. Classic mons enable some features (for example `allow_ec_overwrites`) only when every OSD reports `bluestore`, so keep the default unless your mons are patched. `flashstore` renames the `osd_objectstore` metadata value and default, the `bluestore_bdev_*` device metadata keys to `flashstore_bdev_*`, the `bluestore` perf logger, the `bluestore ...` tell/admin-socket commands (then only `flashstore ...` is accepted) and the `BLUESTORE_*` health codes to `FLASHSTORE_*`. Ceph config option names such as `bluestore_compression_mode`, `bluestore_log_op_age` and `bluestore_slow_ops_warn_threshold` are never renamed. |
| `flashstore_ip` | none | `addr/prefix` | Address of the OSD on the data network. |
| `flashstore_dev` | none | `spdk:<pci>` (`file:<path>` in development builds) | Store device. `croit-flashstore-prep` binds the PCI function only when this key is in the conf (it never reads the OSD data dir); a `spdk:` OSD therefore needs it. |
| `flashstore_lcores` | none | CPU range, e.g. `8-15` | CPUs the OSD runs on. |
| `flashstore_cores` | length of `flashstore_lcores`, else 8 | number | Core count the OSD runs with. |

## Store (fixed at prepare)

These options are read by `croit-flashstore-tool prepare` and written into the store. Changing them has no effect until the store is re-created.

| Option | Default | Values | Notes |
|---|---|---|---|
| `flashstore_store_shards` | `auto` | `auto` or 1..256 | Store shards. `auto` uses the core count. |
| `flashstore_store_base_pct` | 25 on devices of 256 GiB or more; otherwise plain | 10..90, or 100 | Share of each shard that is fixed. `100` gives the plain static layout. |

## Store (read at start unless noted)

| Option | Default | Values | Notes |
|---|---|---|---|
| `flashstore_omap_delete_range_threshold` | `0` | unsigned 64-bit integer | LSM only. `0` always uses native range tombstones. A resident upper bound on the entries (puts and point tombstones) the removal would visit below a positive threshold selects exact key enumeration and point tombstones; otherwise a range tombstone is used. The threshold also bounds the records enumerated synchronously on the owner core, so keep it to a few chunks of entries (a 64 KiB chunk holds about 200 entries with 256-byte values). Loose bounds can retain range tombstones for short live spans. Changeable at runtime without restart or cache clearing; no reformat. |
| `flashstore_store_lend_auto` | `true` | `true`, `false` | `false` stops shards from borrowing chunks from the shared pool. |
| `flashstore_store_lend_wm_pct` | `25` | percent | A shard asks the pool when its free space drops below this share of a chunk. |
| `flashstore_store_lend_retry_ms` | `100` | milliseconds | Pause after the pool gives no chunk. |
| `flashstore_store_reclaim_mbps` | `64` | MB/s | Evacuation rate; data is moved only while another shard of the OSD waits for space. |
| `flashstore_store_reclaim_hyst_pct` | `10` | percent of base | Headroom kept per shard before chunks are returned. |
| `flashstore_prewrite` | `true` | `true`, `false` | Writes the data of a large write (from 256 KiB, less on drives with a lower transfer limit; block aligned; replicated pool without compression) to free space on the drive while it still arrives; the write becomes visible only after the whole message is verified, as before. Can reduce the latency of large writes at low queue depth. Changeable at runtime. Counters `pre_writes`, `pre_claimed`, `pre_released`, `pre_skipped` and `pre_rx_*` in the `flashstore_store_<core>` sections of `perf dump`. Not used on secure-mode connections and for erasure-coded pools. |

### Changing the OMAP range-delete threshold

```sh
ceph tell osd.N config set flashstore_omap_delete_range_threshold 1024
ceph tell osd.N config set flashstore_omap_delete_range_threshold 32
ceph tell osd.N config get flashstore_omap_delete_range_threshold
ceph tell osd.N config unset flashstore_omap_delete_range_threshold
```

A successful set/unset waits for every OSD core to apply the effective threshold. Invalid or overflowing values
are rejected without changing the running value. Unset restores the configured file/monitor value, or `0`.
Runtime overrides do not survive restart; use the local configuration file for a persistent value.

## Memory

| Option | Default | Notes |
|---|---|---|
| `osd_memory_target` | 4 GiB (4294967296) | Total budget of normal operation. Store caches are sized from it. Pinned RDMA buffers are not part of it (`flashstore_rdma_memory`, on top). |
| `osd_memory_base` | 768 MiB (805306368) | Fixed overhead subtracted from the target. |
| `osd_memory_cache_min` | 128 MiB (134217728) | Floor for the store caches. |
| `flashstore_hugepages_mb` | 2048 | Hugepages (MB, or a K/M/G/T size) the host must reserve for the OSD. Alias `flashstore_mem`; both set must agree. Outside `osd_memory_target`. |

## Erasure coding

| Option | Default | Notes |
|---|---|---|
| `ec_enable_pools` | `all` | Erasure-coded pools served as a shard: `off`, `all`, or pool ids or names. |
| `ec_enable_primary` | `true` | `false` leaves PGs led by this OSD frozen. Use primary-affinity 0 instead. |
| `ec_decline_unsupported` | `true` | Declines pools the support gate rejects. See [how-to/erasure-pools.md](../how-to/erasure-pools.md). |
| `flashstore_warn_isa_decode_cache` | `true` | Health alert `FLASHSTORE_EC_ISA_DECODE_CACHE` when classic OSDs older than ceph 21.1.2 share acting sets with this OSD in ISA erasure pools of several k/m shapes (Ceph tracker 74943: wrong decode table in the classic ISA plugin). |
| `ec_enable_optimized` | `all` | Optimized EC (`off`, `all` or a pool list). Pools with `allow_ec_optimizations` are declined while this is off. |
| `ec_enable_optimized_primary` | `true` | Lead optimized EC PGs. `false`: led optimized PGs stay frozen (the OSD still serves as shard). |
| `ec_optimized_direct`, `ec_pdw` | `false`, `off` | Direct shard reads and parity-delta writes; opt-in. |

## Object classes

| Option | Default | Notes |
|---|---|---|
| `osd_class_load_list` | the 20 classic class names | Classes this OSD serves at all, whitespace-separated (`*` = every class). A `call` to any other class fails with `EPERM` before the caps are checked. `sdk` (a test probe) is not on the list. Changeable at runtime. |
| `osd_class_default_list` | the 20 classic class names | Classes a plain `class-read`/`class-write` cap (`allow rwx`) reaches. A class off this list needs an explicit `allow class NAME` (or `allow *`), as on classic. Changeable at runtime. |

An empty value loads or default-allows nothing. Add a class to both lists only if clients use it.

## Tracing

| Option | Default | Notes |
|---|---|---|
| `flashstore_trace_sample` | `0` (off) | Traces 1 of N client operations. `1` traces every operation. Changeable at runtime. |
| `flashstore_trace_ring` | `16384` | Events kept per core. Rounded up to a power of two. |

## Deletion and scrub pacing

| Option | Default | Notes |
|---|---|---|
| `flashstore_delete_log_s` | `10` | Seconds between PG deletion progress log lines. |
| `flashstore_scrub_slice_bytes` | `1048576` | Bytes scrubbed per slice. |

PG deletion (pool delete, rebalancing) has no pacing option: the OSD runs a deletion step only while no client write is waiting for durability on that core, and at most as often as that keeps client latency close to normal. `osd_delete_sleep` and `osd_delete_sleep_ssd` are accepted and ignored.

The scrub option trades background progress against client latency. Measure client latency before changing it.

## Checking a value

```
ceph tell osd.N config get <option>
ceph tell osd.N config show
```

Verify a change with `config get`. If a change does not show the effect you expect, restart the OSD with `systemctl restart croit-flashstore-osd@N` and check again.
