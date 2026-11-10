# How to monitor the OSD

Use the admin socket for checks on the host and `ceph tell` for checks from anywhere in the cluster. Both return the same data. The command names and their output are listed in [reference: admin commands](../reference/admin-commands.md).

## 1. Check that the OSD is up and active

```
croit-flashstore-tool asok --id 0 status
ceph tell osd.0 status
```

The `status` reply includes these fields:

| Field | Meaning |
|---|---|
| `state` | Daemon state: `initializing`, `preboot`, `booting`, `active`, `waiting_for_healthy`, `stopping`. Expect `active` in normal operation. |
| `whoami` | OSD id. |
| `num_pgs` | PGs hosted by this OSD. |
| `oldest_map`, `newest_map` | OSD map epochs held in the store. |
| `client_ops_parked` | Client operations waiting for a PG or a map right now. |
| `client_ops_parked_total` | Client operations that were parked since start. |
| `client_ops_dropped` | Client operations dropped without a reply, counted per reason. |
| `ignored_options` | Ceph options set with `--set` that croit-flashstore-osd does not use. |

A state other than `active` for more than a few minutes needs a log check (section 4).

## 2. Check performance counters

```
croit-flashstore-tool asok --id 0 perf dump
croit-flashstore-tool asok --id 0 perf schema
```

`perf dump` returns the counter values. `perf schema` returns their definitions. Use `perf reset` to start a new measurement window. It resets the baseline for all counters.

For a stage breakdown of sampled operations, set `flashstore_trace_sample` (see [reference: configuration](../reference/configuration.md)) and run:

```
croit-flashstore-tool asok --id 0 trace_summary
```

It reports p50, p99, p99.9 and max for each stage. `trace_reset` clears the sample.

### Device utilization

`iostat` does not see an SPDK-driven device. The OSD counts device time per core in the `perf dump` logger `flashstore_store_<core>`:

| Counter | Meaning |
|---|---|
| `dev_busy_ns` | Time with at least one command in flight on the core's device queues, in ns. |
| `dev_completions` | Device commands completed. |
| `dev_read_bytes`, `dev_write_bytes` | Bytes of completed device reads and writes. |
| `dev_qpairs` | Device queues (store shards) of the core. |

Read `perf dump` twice and compute the utilization of a core as `Δdev_busy_ns / (Δt × dev_qpairs)`, and the device throughput as `Δdev_read_bytes / Δt` and `Δdev_write_bytes / Δt`. Sum the cores for the OSD. These counters count from daemon start; `perf reset` does not change them. Values of other cores are refreshed every second, so use intervals of 10 s or more.

The value is the share of time the device had work queued, like `%util` in `iostat`. An NVMe device runs many commands in parallel, so 100 % does not mean the device is saturated. Compare `dev_completions` per second with the device's rated IOPS for that.

### Background defrag

The store moves data in the background to keep free space contiguous. Each round ends with a drain: the blocks the data moved out of become free once a checkpoint has passed and no read still uses them. A drain has no time limit. Its state is in the `perf dump` logger `flashstore_store_<core>`:

| Counter | Meaning |
|---|---|
| `defrag_drains_waiting` | Drains waiting now (store shards of the core). |
| `defrag_drains_on_readers` | Waiting drains whose checkpoint has passed: only reads still hold their blocks. |
| `defrag_drain_held_blocks` | Blocks the waiting drains hold. |
| `defrag_drain_wait_max_ms` | How long the longest waiting drain has waited, in ms. |

A drain normally ends shortly after it starts. A `defrag_drain_wait_max_ms` that keeps growing while `defrag_drains_on_readers` is 1 means a read never finished; report it together with the `dump_ops_in_flight` output.

### Core load and receive stalls

Each core's `perf dump` logger `flashstore_core_<core>` also counts:

| Counter | Meaning |
|---|---|
| `busy_ns` | Time the core spent working, in ns (counted with every network tier). |
| `rx_bytes` | Bytes received on the core's connections. |
| `rx_pauses`, `rx_pause_ms` | How often the core stopped reading its sockets because the receive buffer pool was full, and for how long in total. |
| `long_1ms`, `long_10ms`, `long_100ms` | Work loop passes that took at least 1, 10 or 100 ms. During such a pass the core reads none of its sockets. |

Compute per interval as above. A core whose `Δbusy_ns / Δt` is near 1 while other cores are lower limits the OSD. Rising `rx_pause_ms` or `long_100ms` during a load usually shows up as high tail latency at the clients. The counters stay at 0 with other network tiers.

## 3. Check operations in flight

```
ceph tell osd.0 dump_ops_in_flight
ceph tell osd.0 dump_blocked_ops
ceph tell osd.0 dump_historic_slow_ops
```

`dump_blocked_ops` lists operations that have waited longer than `osd_op_complaint_time` (default 30 s). A non-empty list needs the cause: a PG that is not active, a peer that is down, or a full device.

## 4. Read the log

The log is written live. Log entries that matter for monitoring:

| Message | Meaning | Action |
|---|---|---|
| `client op parked (osd <state>, ...)` | A client operation waits because the OSD or the PG is not ready. | Check `state` and the PG state. The OSD runs parked operations once it is `active` and has a map at least as new as the operation's. |
| `client op parked ... pg not here yet` | The PG is not hosted by this OSD yet. | Normal during a map change. Persistent parking needs a PG check. |
| `client op dropped (<reason>)` | An operation was dropped without a reply. | See the reasons below. |
| `slow ops on this core, oldest blocked for <n> s` | Operations wait longer than `osd_op_complaint_time`. | See section 3. |

The reasons for a dropped operation are: `passive pg`, `pg host dead`, `local failsafe full`, `stale epoch`, `object not in this pg`, `no connection info`, `not in acting set`, `not primary`, `osd stopping`, `move park list full`.

The first five occurrences of a reason are logged. After that a message is logged only at powers of two. The `client_ops_dropped` count in `status` is always complete.

After log rotation, reopen the log file with `croit-flashstore-tool asok --id 0 log reopen`. The daemon also reopens it on `SIGHUP`.

## 5. Monitor from the cluster

Classic Ceph tools see the OSD like any other OSD. Check the cluster view with:

```
ceph osd tree
ceph pg stat
ceph health detail
```

A down OSD appears in `ceph osd tree`. A PG that is not active appears in `ceph pg stat`.

## Signals for alerts

| Signal | Source | Meaning |
|---|---|---|
| Blocked operations | `dump_blocked_ops` | Operations older than `osd_op_complaint_time` (default 30 s) |
| Daemon state | `status`, `state` | Any value other than `active` |
| Dropped operations | `status`, `client_ops_dropped` | Counter increases |

The project does not define alert thresholds. Choose them for your cluster.

## Related

- [Reference: admin commands](../reference/admin-commands.md)
- [Reference: configuration](../reference/configuration.md)
- [How to troubleshoot](troubleshoot.md)
