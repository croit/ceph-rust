<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0685 Bench harness: test sets, deploy backends, freshness, workloads, sampler

Status: proposed
Date: 2026-11-07
Part of: 0684-bench-harness.md (daemons, leader, protocol, results, migration)

## Context

`benchrun` jobs (0684-bench-harness) must deploy the cluster and services they
measure (OSD BS/FlashStore, MDS, RGW), reuse that state across jobs instead of
rebuilding per test, and still give fair, comparable numbers. They must attach
to the croit-managed e9455 cluster without fighting croit, run fio wherever it
applies (user 2026-11-07), also cover omap, CephFS and S3, and record server
CPU and other data with equal overhead for every arm.

## Decision

Test sets (desired state):
- A test set is a declarative TOML definition: Ceph build/version, per host
  the OSDs (store `bluestore|flashstore`, tier `kernel|spdk`, transport
  `knet|rdma`, count, devices), pools (type rep/EC, size, EC profile,
  `pg_num`, pool profile), MDS (count, fs), RGW (hosts, port), clients
  (mounts, krbd maps), config overrides. Arms of an A/B are test sets that
  differ in named fields.
- The leader observes the current state through the backend, computes the
  delta to the desired state, and applies minimal actions in dependency order:
  purge removed resources, redeploy changed OSDs/services, restart for changed
  config, create missing pools/fs/buckets. Equal resources are kept.
- Fingerprint: sha256 over the canonical desired state plus observed facts
  (daemon binary sha256, `ceph versions`, OSD metadata objectstore, owned
  config values, pool parameters, device ids). It is stored with every cell
  result; cells compare only within equal fingerprint fields except the arm
  field under test.
- History: per pool and per OSD the leader journals the mutating cells since
  creation (`history` = hash chain of cell ids + targets) and bytes written
  since mkfs. Cells declare `reads` (needs a prefill tag) or `mutates`. Two arms
  compare only with equal history hashes; the leader orders cells so every arm
  runs the same sequence, and refuses an A/B pairing whose histories differ.

Freshness rules (what each scope recreates or resets):

| Resource | Per cell | Per job | Recreated when |
|---|---|---|---|
| mon/mgr | reused | reused | Ceph build changes |
| OSD process | restart (cold) | restart | always per cell |
| OSD store (mkfs) | reused | reused | store/tier/build format changes, `fresh_store=true`, or fill > 80 % |
| pool | reused | reused | parameters change, `fresh_pool=true`, history mismatch |
| primary balance | verified, histogram recorded | applied after pool create | pool recreated |
| prefill data | reused if tag matches | reused | tag mismatch or pool recreated |
| page cache, slab | `sync; drop_caches=3` on OSD + client hosts | same | - |
| krbd map | reused | mapped at job start | image recreated |
| CephFS kernel mount | remounted (caps, dentry cache) | - | always per cell |
| MDS | restarted, wait `up:active` | - | always per cell for metadata cells |
| RGW | restarted | - | always per cell |
| fio processes, clients | new per cell | - | always |

- Prefill is an explicit cell (`kind = prefill`) with a tag (`objects, size,
  pattern`); read cells name the tag they need. A missing or stale tag runs the
  prefill cell first, journaled like any cell.
- Fill level of own pools and raw is checked before each cell; above 80 %
  (project rule) the cell is `harness-fail` unless the job is a declared
  stress job.
- Primary balance: after pool creation and `active+clean`, `ceph osd
  pg-upmap-primary` balances primaries to max-min <= 1 per OSD per pool; the
  histogram is recorded per cell. Same procedure for every arm.
- Cold start per cell, identical for every arm: restart measured OSDs (and
  MDS/RGW for their cells), wait scoped clean, drop caches, record timestamps.

Deploy backends:
- Trait `Backend { observe, apply(action), check, purge(scope) }` for OSD (BS
  and FlashStore), MDS, RGW, pools, fs, RGW users/buckets. One backend per
  test set.
- `attach`: an existing cluster (e9455, croit-managed). Mons, mgrs,
  `ceph.conf` and croit's own daemons are never changed. The inventory lists
  per host the allowlist the tool may manage: OSD ids, devices, MDS/RGW
  instance names, pool/fs/bucket prefix `br-`. Every action outside the
  allowlist is refused before it is sent (`harness-fail`, names the resource).
  The way BS OSDs are restarted on croit hosts is an open question.
- `lab`: lab containers for mon/mgr as today (`lab/lib/common.sh` behaviour),
  OSDs, MDS and RGW as systemd units from the build under test; full deploy
  and purge.
- `croit-api`: optional later, same trait.
- `fake`: in-process cluster for tests (0684-bench-harness Harness CI).

Workload plugins:
- Trait `Workload { render(cell) -> argv + files, progress(dir) -> counter,
  parse(dir) -> Normalized, accounting() -> Bytes|Ops|Runtime }`. Plugins are
  a compiled enum; argv is built without a shell.

| Plugin | Use | Engine / tool |
|---|---|---|
| `fio-rbd` | RBD block | fio `rbd` |
| `fio-rados` | objects | fio `rados` |
| `fio-file` | krbd device, CephFS mount data | fio `libaio` (io_uring option) |
| `fio-fileops` | CephFS metadata | fio `filecreate`, `filestat`, `filedelete`, `dircreate`, `dirstat`, `dirdelete` |
| `fio-s3` | S3 via RGW | fio `http`, `http_mode=s3` |
| `oprobe` | omap | `oprobe omapgate` (jsonl per op class) |
| `custom` | any scalable storage system | own command, see below |

- fio plugins share one job renderer, the `json+` parser and the per-second
  log reader; progress = per-second log growth; accounting from `io_bytes`
  and `total_ios`.
- omap: fio has no omap operations, and an external fio engine binds to fio's
  internal `thread_data`/`io_u` layout without a stable ABI; oprobe stays, with
  the same deadline, progress, rc and evidence rules.
- `custom`: a command (argv, run with the client's per-cell dir as working
  dir) for systems fio cannot drive. The cell declares the output format
  (`json`, `jsonl` or `none`), the accounting target (`bytes`, `ops` or
  `runtime`) read from that output, and an optional progress file whose growth
  is the progress signal. Deadline, rc, evidence and class rules are those of
  the fio cells.
- S3: fio `http` engine with `http_mode=s3` (SigV4: `http_s3_key`,
  `http_s3_keyid`, `http_s3_region`; PUT/GET/DELETE per object). The daemon
  checks `fio --enghelp=http` on the client before the cell (fio needs libcurl
  at build time; else `harness-fail` naming the fix). Multipart, list and
  mixed-op S3 workloads are not covered (open question).
- CephFS metadata: fio file-ops engines for create/stat/delete of files and
  directories; data cells via `fio-file` on the kernel mount. Ops fio lacks
  (rename, setattr, readdir of large dirs, link) get an own Rust probe only
  when a cell needs them, following the oprobe pattern.

fio rules, enforced by the renderer and the evidence check:
- `ramp_time` stops counting ramp I/O in `io_bytes`, so byte/op-bounded jobs
  move fewer measured bytes than the target. Byte/op-bounded cells never set
  `ramp_time`; warm-up is cut from the per-second logs at evaluation; totals
  from `io_bytes` must equal the target. Time-based cells may use `ramp_time`.
- Latency totals and percentiles from `json+` `clat_ns` bins; per-second
  series from `write_{lat,bw,iops}_log`, `log_avg_msec=1000`, `per_job_logs=1`.
- Each fio job has its own librados/librbd client; warm-up runs inside the
  same job, never as a separate fio invocation.
- `rbd` with several jobs on one image contends on the exclusive lock: one
  image per job, or `exclusive-lock` off and recorded in the pool profile.
- Client RX/TX: the job computes client count so the planned aggregate stays
  below the clients' summed line rate with margin; a client above 90 % line
  rate annotates an `ok` cell `client-bound`.
- Multi-client: barrier start; `group_reporting` off.

Server-side sampler:
- Every daemon samples its host during each cell (from barrier - 5 s to cell
  end + 5 s) at a fixed 1 s interval; asok collectors every 5 s. The sampler is
  a thread of the daemon, pinned to the host's housekeeping CPU from the
  inventory (required on server hosts) at `SCHED_IDLE`/nice 19.
- Records:
  - per process and per thread CPU (utime/stime from `/proc/<pid>/task/*/stat`,
    thread `comm` names, so OSD reactor/IO threads are named), context
    switches;
  - memory: RSS per process, host `MemAvailable`; per pool via asok
    `dump_mempools` where the daemon supports it;
  - NIC: `/sys/class/net/*/statistics` per second, `ethtool -S` (drops,
    per-queue) at cell start and end;
  - disk: `/proc/diskstats` for the measured devices;
  - Ceph: asok `perf dump` per measured daemon;
  - IRQ: `/proc/interrupts` at start and end, `/proc/softirqs` per second.
- An asok command a daemon does not support is recorded once as
  `unsupported`, not retried.
- Raw samples are appended locally (`jsonl`, one file per cell) and survive a
  leader outage; the leader converts them to Parquet at collection. Writes are
  batched (memory ring, >= 64 KiB or 30 s, and at cell end; a crash loses at
  most that window), see the footprint rules of the main file.
- Overhead: the sampler records its own CPU time (`getrusage` of its thread)
  per cell into the results; the sampler config is part of the job, identical
  for every arm.
- Time: each daemon records `chronyc tracking` offset at cell start; offset
  above the job limit (default 1 ms) makes the cell `infra-fail` before
  start. All series use `CLOCK_REALTIME` ns.

### Test-set features (0684 am. 6)

What a spec expresses so the e9455 test set (`benchmark/`) runs from one job; details in the Rustdoc of
`tools/benchrun` (`spec`, `compose`, `template`, `pool`, `clusterwait`, `artifact`, `report`).

- Pool profile: EC (`ec` k/m/plugin, `allow_overwrites`, `allow_optimizations`), `min_size`, `failure_domain`,
  `crush_root`, `device_class`, `osds` (subset: own CRUSH root + rule from an edited CRUSH map). `create = true`
  adds a setup cell `setup-<pool>-<arm>` per arm and pool (custom workload `benchrun pool create`, before the arm's
  first cell, every cell of that arm and pool depends on it); autoscale off, size-1 permission, application, wait
  for the pool's PGs `active+clean`. The pool name is run-unique: an existing pool is an error.
- fio object sets (`[cells.fio.objects]`: set, count, size, service, slot, random_map, loops) with `bssplit`; the
  object name is `<set>-<host>-j<NN>-<n>`, so cells of one set address the same objects; fio needs the
  `keep_objects`/`touch_objects` build (`binary`). A mixed-block byte target may overshoot by one block per pass.
- Per-host command lines of omap and custom cells: `{pool}`, `{host_index}`, `{client_base}`, `{total_clients}`,
  `{dir:<cell>}` (manifest hand-off from a dependency with the same clients). oprobe globals (`conf`, `keyring`,
  `entity`, `timeout_s`), `cpus` (taskset), `start_at_s`, `repeat_for_s` (scan loop), `keys_per_op`, `manifest_out`.
- `[defaults]` (pool, clients, deadline, stall, sample, cold_start; `pre` first, `post` last) and `[vars]`
  (placeholders of shared cell files, e.g. the objects per fill slot).
- Cold start `scope = "pool"`: restart and wait only for the acting OSDs of the cell's pool (`benchrun osd-restart
  --pool`), `cache_drop` = `ceph tell osd.N cache drop`; `wait-cluster --pool` judges the pool's PGs and the health
  checks that name the pool, its PGs, its acting OSDs or nothing, so a foreign pool's warning never blocks. A
  restart step is done only when the restarted instance is the one in the osdmap (`up`, a higher `up_from` than
  before the restart, and `ceph tell osd.N version` answers), so the wait and the cache drop never hit a daemon
  that is still going down.
- Coverage: `--skip <cell glob>` (a pattern without a match is an error, as is a dependent of a skipped cell) is
  the only way a planned cell does not run; skipped cells are recorded in the spec (hashed), listed by the plan and
  shown in the status/collect `coverage` table with every planned cell, its class or its reason. Nothing on disk
  outside the job definition changes what runs.
- Optional artifacts: a step with `optional = true` (`benchrun best-effort`) never fails or skips the cell; a
  failing, timed-out or empty one leaves `missing-<name>.txt` and the cell ends `contaminated` with a note.
  `benchrun settle --pool` waits for a quiet window of the pool's local OSDs (their processes' CPU, their data devices, no I/O in flight; limits `max(mean + 3 sd, floor)` of a 60 s idle baseline stored once per run and host in the job dir) and prints one JSON result line; step commands expand the template placeholders. An own OSD is any OSD below the pool's CRUSH rule roots or in an acting set (a down own OSD blocks the health wait).
- Not covered: deploy/purge/blkdiscard, balancer and flags, failure redeploy, drive state, NIC drop and TCP
  retransmit series, steady-state analysis (analysis, not execution).

## Rationale

- Desired state + fingerprint + history makes reuse safe: what is reused is
  recorded and compared, what must be fresh is a table, not habit.
- Allowlist per host is the only way to share a croit-managed cluster without
  ever touching foreign OSDs and pools.
- fio http/S3 and fio file-ops keep one load generator, one parser and one
  evidence path for S3 and CephFS (user: fio wherever it applies).
- warp (AGPL-3.0): running an unmodified external binary would not oblige our
  code, but it is a second result format and brings its own distributed
  client/server mode next to ours; elbencho (GPL-3.0) likewise has its own
  service mode; s3-benchmark is unmaintained. None is needed for PUT/GET
  throughput and latency.
- mdtest/ior need MPI (`mpirun` launches over ssh: cause A again, plus an MPI
  stack on every client); fio file-ops engines cover create/stat/delete.
- Sampler in the daemon, sampling procfs/sysfs directly: no extra tools on the
  hosts, bounded cost (a few file reads per second), measured per cell.

## Consequences

- + Jobs reuse OSDs, pools and services; only deltas cost time.
- + Every number carries the fingerprint and history it was measured on.
- + S3 and CephFS cells use the same fio parser and evidence checks.
- - Store aging across jobs is real state: arms must share histories, which
  can force re-running a prefix or recreating a pool.
- - fio S3 covers single-object PUT/GET/DELETE only.
- - CephFS metadata ops beyond fio's file-ops need an own probe later.
- - Clients need fio built with libcurl for S3 cells.

## Alternatives

- Fresh cluster per job: simplest fairness, but hours per test set change;
  rejected by the user (reuse required).
- warp, elbencho, s3-benchmark for S3: see Rationale.
- mdtest/ior for CephFS metadata: MPI dependency.
- Prometheus node_exporter + ceph-exporter scraping: extra daemons per host,
  scrape interval coupling, no per-thread CPU by name.

## Open questions

- e9455 BS OSDs: restart through croit (API/containers) or systemctl on the
  host? Decides what the `attach` backend may do for cold start.
- S3: are multipart, list or mixed-op workloads needed? Then elbencho (GPL,
  external binary, local mode) or warp (AGPL, external binary) as a second
  S3 plugin.
- CephFS: which metadata ops beyond create/stat/delete are gate-relevant
  (rename, setattr, readdir)?
- Does croit-flashstore-osd's admin socket provide `perf dump` and
  `dump_mempools` with comparable counters?
- Housekeeping CPU per server host: which CPU, given the OSD self-tunes its
  cores and NIC IRQ layout?
