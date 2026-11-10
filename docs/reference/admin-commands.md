# Reference: admin commands

croit-flashstore-osd answers the same admin commands as a classic OSD. This page lists the subset that operators use. Each command can be run in two ways:

- `ceph tell osd.<id> <command>`: through the cluster, from any host with admin access.
- `croit-flashstore-tool asok --id <id> <command>`: on the OSD host, through the admin socket, without the `ceph` CLI.

Both run the same command in the daemon.

## Output format

- `ceph tell` and `croit-flashstore-tool asok` accept `--format plain|json|json-pretty` for commands that return structured data.
- `croit-flashstore-tool asok` passes `jsonl` and plain replies through unchanged. Each JSON line is one record.
- For `croit-flashstore-tool asok` with a JSON format, the request is sent as a JSON command with `format: json`. The output is then re-indented for `json-pretty`.
- The admin socket path is `/var/run/ceph/<cluster>-osd.<id>.asok` unless the `admin_socket` option sets another path.

## Status and version

| Command | Returns | Notes |
|---|---|---|
| `status` | High-level OSD status | Also lists `--set` options that croit-flashstore-osd reads and options it does not use. |
| `version` | Ceph version of the daemon | Same value as `croit-flashstore-osd --version`. |
| `git_version` | Commit of the build | |
| `list_devices` | OSD devices | |
| `cache status` | Cache statistics | |
| `cache drop` | No effect | No-op: nothing to drop. |
| `rdma status` | RDMA sessions, granted credits, held receive slots and counters per device and core | With `flashstore_rdma = true`. `--format plain\|json\|json-pretty`. The same numbers are OSD perf counters (`osd.rdma_*` in `perf dump` and the mgr prometheus module): `rdma_upgraded`, `rdma_declined`, `rdma_faulted`, `rdma_sessions_capped`, `rdma_credit_stalls`, `rdma_queue_stalls`, `rdma_credit_stall_ns` (time sessions were blocked on peer credits, summed over sessions, poll-loop resolution), `rdma_grants_demand` (credit lends to blocked sessions), `rdma_idle_decays` (windows that fell back to the minimum after idling), `rdma_close_fence_timeouts`, `rdma_zc_bytes` (bytes sent zero copy from the registered payload heap; always on), `rdma_zc_misses` (large chunks copied because they lie outside it), `rdma_tx_bytes` / `rdma_tx_sends` / `rdma_tx_chunks` (stream bytes, SEND work requests and output chunks taken; SENDs per chunk below 1 = small chunks packed), `rdma_tx_doorbells` / `rdma_rx_doorbells` (`ibv_post_send` / `ibv_post_srq_recv` calls: one per chained list), `rdma_wakes` (completion channel wake-ups of idle cores), gauge `rdma_sessions`; robustness counters that must stay 0 (nonzero = a broken core or an owner bug, report it): `rdma_rx_post_failures` (receive re-posts that lost slots), `rdma_cq_errors` (CQ poll errors), `rdma_rx_withheld` (receive slots withheld at a detach), and process-wide (not reset by `perf reset`) `rdma_leaked_cores` (cores left allocated when a retire was not confirmed), `rdma_teardown_failures` (refused QP teardown with bound windows or QP/CQ/SRQ/MR teardown failures; uncertain resources retained), `rdma_qp_drain_timeouts` (QPs without a last-WQE event after their move to ERR, kept with their send slots and receive credits). `rdma status` JSON also carries `grants_admission` and `slot_wakeups` per device, the three broken-core counters per device and core, and `leaked_cores` / `teardown_failures` / `qp_drain_timeouts` at the top level. |

The process-wide `rdma_quarantined_windows` and
`rdma_quarantined_write_sources` counters report placement memory retained
after uncertain retirement or WRITE completion. They appear as
`quarantined_windows` and `quarantined_write_sources` in `rdma status` JSON and
must stay zero. They are zero when the placement feature is not built.

## Ops and PGs

| Command | Returns |
|---|---|
| `dump_ops_in_flight` (alias `ops`) | Operations in flight |
| `dump_blocked_ops` | Blocked operations in flight |
| `dump_blocked_ops_count` | Count of blocked operations |
| `dump_historic_ops` | Recent operations |
| `dump_historic_ops_by_duration` | Recent operations, slowest first |
| `dump_historic_slow_ops` | Slowest recent operations |
| `dump_op_traces [last N]` | Sampled per-operation stage traces. Set `flashstore_trace_sample` to sample. |
| `trace_summary` | p50, p99, p99.9 and max for each stage of the sampled traces |
| `trace_reset` | Clears the sampled trace rings |
| `dump_pgs` | PG state of every hosted PG (developer use) |
| `dump_pgstate_history` | Recent PG state history |
| `pg <pgid> query` | Details of one PG |
| `pg <pgid> list_unfound [offset]` | Unfound objects of one PG |
| `dump_osd_pg_stats` | PG statistics |
| `dump_recovery_reservations` | Recovery reservations |
| `dump_scrub_reservations` | Scrub reservations |
| `dump_scrubs` | Scheduled scrubs |

## Scrub and repair

| Command | Effect | Risk |
|---|---|---|
| `scrub [pgid]` | Scrubs one PG, or every PG this OSD is primary for | Read load |
| `deep-scrub [pgid]` | Deep scrub of one PG or all primary PGs | Higher read load |
| `repair [pgid]` | Deep scrub that repairs inconsistencies | Changes data |
| `scrub-abort <pgid>` | Aborts a running scrub | |
| `schedule-scrub <pgid>`, `schedule-deep-scrub <pgid>` | Schedules a scrub now | Developer and test use |
| `pg <pgid> mark_unfound_lost revert\|delete` | Marks all unfound objects of the PG as lost: `revert` restores a prior version if one exists, `delete` removes them. Only the primary runs it; a non-primary returns error -30 (not primary). | Data loss |

Use `repair` only after a scrub reports inconsistent objects. See [how to recover a PG](../how-to/recover-pg.md).

## Configuration

| Command | Effect |
|---|---|
| `config show` | Current settings |
| `config diff` | Current settings that differ from the defaults |
| `config get <name>` | Value of one setting |
| `config set <name> <value>` | Sets a setting in the runtime layer |
| `config unset <name>` | Removes a runtime setting |
| `config help [name]` | Schema and description of a setting |
| `injectargs <args>` | Sets settings given as command-line arguments |

Runtime changes apply until the daemon restarts. For a persistent change, set the option in the configuration file or in the cluster configuration. A setting the daemon only reads at start (for example the key sources `key`, `keyfile` and `keyring`) is refused at runtime with `-EPERM`. See [reference: configuration](configuration.md).

## Performance counters and logs

| Command | Returns |
|---|---|
| `perf dump [logger [counter]]` | Performance counter values |
| `perf schema` | Performance counter schema |
| `perf histogram dump`, `perf histogram schema` | Histogram values and schema |
| `perf reset <name>` | Resets the counter baseline. The argument is accepted and the reset applies to all counters. |
| `counter dump`, `counter schema` | Labeled and unlabeled counters |
| `log flush` | Returns OK. The log file is written live, so no flush is needed. |
| `log reopen` | Reopens the log file. Used after rotation. |
| `log dump` | No effect: log lines are written live |

## Memory and store

| Command | Returns | Notes |
|---|---|---|
| `dump_mempools` | Memory pool statistics | Only the pools croit-flashstore-osd has. Values are measured bytes. |
| `dump_pool_statfs <poolid>` | Store statistics for one pool | |
| `store free [extents=true]` | Free space: bytes, runs, largest run, fragmentation | `extents=true` adds the run list. |
| `bluestore allocator dump|score|fragmentation <name>` | Allocator information | Same as `store free`, under the classic name. |
| `store census [request=true]` | Extent census of the last idle sweep: objects, extent records, compressed chunks, cut chunks; idle recompaction counters | The census runs only while the device is idle. `request=true` includes collections without compressed data in the next sweep; `census_seq` grows when it is done. |
| `flush_pg_stats` | Sends PG statistics to the monitor now | |
| `flush_journal` | Forces a checkpoint of the store | |
| `compact` | No effect | No LSM tree in croit-flashstore-osd. |
| `flush_store_cache` | No effect | |
| `trim stale osdmaps` | Removes stored OSD maps below the lowest epoch still needed: the minimum of the cluster trim bound, the oldest PG epoch and the current epoch. Ignores the batching threshold. | |
| `bluestore bluefs-bdev-expand` | Refused | Grow the device offline with `croit-flashstore-tool expand`. |

## Benchmark and diagnostics

| Command | Effect | Risk |
|---|---|---|
| `bench [count] [size] [object_size] [object_num]` | Writes durable test data to the store. Defaults: count 1 GiB, size 4 MiB. Block size is capped by `osd_bench_max_block_size` (default 64 MiB); larger values are refused with EINVAL. | Uses store space and bandwidth. Do not run on production PGs. |
| `smart [devid]` | SMART data of the OSD device as `{devid: smartctl-style JSON}`; the devid is the classic Ceph form (`MODEL_SERIAL` with the drive's fixed-width padding as `_`), so a drive keeps one entry in `ceph device ls` when it moves between classic OSDs and croit-flashstore-osd. A devid that matches no device returns `{}`. On the kernel tier the data comes from `sudo smartctl` like classic Ceph when the daemon may not read the log page itself: the host needs `smartmontools`, `sudo` and the ceph packages' `/etc/sudoers.d/ceph-smartctl`; the daemon log names the route used. The device is listed as `host:nvme2n1` on the kernel tier and as `host:<PCI address>` on the SPDK tier. After an upgrade from an earlier croit-flashstore-osd the drive appears under its new devid; the old devid and its stored metrics age out (`ceph config get mgr mgr/devicehealth/retention_period`). | |
| `dump_watchers` | Clients with active watches | |
| `dump_blocklist` | Blocklisted clients and times | |
| `dump_osd_network` [value] | Heartbeat ping times | |
| `send_beacon` | Sends a beacon to the monitor now | |
| `get_latest_osdmap` | Requests the latest OSD map from the monitor | |
| `help`, `get_command_descriptions` | Lists the commands | |

## Commands that croit-flashstore-osd refuses or does not support

| Command | Behavior |
|---|---|
| `heap ...` | Refused. Requires a tcmalloc build, which croit-flashstore-osd does not use. |
| `set_recovery_delay`, `debug kick_recovery_wq` | Only `0` is accepted. croit-flashstore-osd does not delay recovery. |
| `bluestore bluefs-bdev-expand` | Refused online. See above. |

## Related

- [Reference: configuration](configuration.md)
- [How to recover a PG](../how-to/recover-pg.md)
