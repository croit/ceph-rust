<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0684 Bench harness: benchrun daemons, designated leader, desired-state test sets

Status: proposed
Date: 2026-11-07
Amends: 0047 (lab reliability: lock, waits, A/B driver move into the harness)
Split: test sets, deploy backends, freshness, workloads, sampler in
0685-bench-harness-testsets.md (same decision).
Consolidated in place (adr 0462): history, incident table, migration log, rejected
alternatives in doc/perf/adr-0684-history.md. Amendment map: am. 1 composition and
dry run, am. 2 bounds, am. 3 host configuration, am. 4 failure events, am. 5 preflight, am. 6 test-set
features (0685).

## Context

Benchmark runs lose cells and hours to harness faults, not to the system under test: the week 2026-11-02..07 of the
private e9455 harness (about 12k lines bash + Python, unversioned) and the repo lab scripts failed for seven
structural causes (incidents: doc/perf/adr-0684-history.md): A. state and liveness held by the controller's ssh
connection; B. no resource namespace, waits judge the whole cluster; C. imperative resume by step number; D. 4-5
levels of sourced bash, rc and timeout owner lost; E. no harness tests; F. private unversioned code; G. evidence and
fairness checked after the run, if at all. Every run also rebuilt the cluster; CephFS/S3 had no harness at all.

## Decision

Tool and roles (user vision 2026-11-07, binding):
- `benchrun` is one static Rust binary in the repo (`tools/benchrun`, LGPL-3.0-only). It runs as a daemon
  (`benchrun agent`, systemd unit) on every benchmark host: servers and clients alike. The same binary is the CLI
  (`submit`, `status`, `hosts`, `collect`, `verify`, `pack`, `cancel`, `setup`, `plan`). Scope: collection and
  packaging only; analysis lives outside the tool, on the data package.
- One daemon is the leader. Jobs are submitted to the leader only.
- A job = (test set, workload cells, collection). The test set is a declarative cluster/service definition the
  leader reconciles to; cells name a workload plugin (fio, oprobe; S3 and CephFS via fio engines) and its
  parameters; collection brings every daemon's raw files, samples and journal to the leader. Test set, workload
  and sampler rules: split file.
- `benchrun` never generates load itself: fio wherever it applies (user 2026-11-07), oprobe for omap (split file).

Leader:
- The leader is designated, not elected: the host that runs `benchrun agent --advertise` (leader and agent in one
  process, so it also runs cells). No election, no quorum, no inventory file.
- Start and discovery: `benchrun agent --leader <ip[:port]>` dials a known leader (routed networks, default port
  47600). Plain `benchrun agent` discovers it by UDP broadcast: "who is the benchmark leader?" is answered by the
  advertiser with "<port> is it"; the requester takes the IP from the datagram source. Broadcast goes only to the
  given (`--iface`) or derived interface broadcast addresses, never multicast. Each round without an answer prints
  `WARNING TIMEOUT leader discovery exceeded <n>s` and retries. Discovery carries no secret.
- Realm: `--cluster <name>` (default `default`) is in request and answer; an advertiser answers only its own realm
  and the join refuses a different one, so several labs on one L2 do not mix.
- Agents dial the leader (star topology) and never listen; they never
  coordinate peer to peer.
- The leader compiles a job into per-host plan parts and sends each daemon its
  part (its cells, sampler config, deploy actions, artifacts to return) before
  the first phase. Each daemon persists its part and every event in its local
  journal before acting.
- Losing the leader or the submitter loses no measurement:
  - A submitter disconnect has no effect; the job lives in the leader journal.
  - A running cell runs to completion on its hosts (autonomous cells, below):
    workload, sampler stop, local evidence check, result packaging, journal.
  - Phase transitions that span hosts (next cell, cold start of servers,
    deploy steps) wait for the leader; a leader outage is a pause between
    cells, never a lost or aborted cell.
  - Daemons reconnect with backoff, each attempt logged.
- Leader (re)start rebuilds state from journals: own journal (job queue, plan,
  phase decisions), then each daemon's `hello` carries its journal tail per
  job; the leader folds both, collects finished cells, and resumes at the first
  phase not done everywhere. If the leader host is lost, another host runs
  `--advertise` and the job is resubmitted with the same job id;
  daemons' journals identify done cells, which are collected, not re-run.
- Done is decided from observed state (journal event + `done` marker with
  sha256 of the result files), never from a remembered flag. There is no
  `--from` and no forced re-run: a cell that must run again is submitted under a new job id.

Transport and protocol:
- Plain TCP, unencrypted (user 2026-11-07: test tool). A frame is one JSON object per line (`serde_json`); a blob
  (artifact, sample file) is announced by a line `{"blob":<len>,"sha256":..}` followed by `len` raw bytes.
  Request/response carry an id. Blocking std I/O, one thread per peer (a few dozen at most); no async runtime.
- Optional pre-shared key: when the lab env sets `LAB_BENCHRUN_PSK`, every daemon connection and every submit
  sends it in `hello`/`submit`; a peer without the matching key is rejected and logged. No TLS, no certificates.
- Handshake `hello{proto, build_sha, cluster, host, labels, info, psk, journal summaries}`. The leader refuses an
  agent with a different protocol version or cluster (the refusal names both values); an agent with a different
  build sha is sent the leader's binary (see Rollout). The CLI (`client` message) carries protocol version and PSK only.
- Host map: `info` = hostname, IPs, CPU count and NUMA nodes, NICs (speed, addresses), block devices, OS, version.
  The leader keeps it in memory (agents re-register on every join); `benchrun hosts` lists it.
- Roles: a job assigns roles to hosts by hostname or label (`--label` on the
  agent, `label:<l>`); the leader resolves them to concrete hosts at submit,
  stores the resolved spec, and refuses an entry that matches no host.

Jobs, journal, resume:
- Job spec (TOML) references a test set and lists cells (workload, params,
  target bytes|ops|runtime, deadline, deps, repeats). `benchrun plan` prints
  the phase graph and the reconcile delta against the current fingerprint.
- Job id names every remote dir and per-job resource. Spec and binary hash are recorded; a resubmit whose spec
  changed is refused unless it only adds cells (`benchrun plan --diff` shows it).
- Journal = append-only `jsonl` per daemon (`/var/lib/benchrun/journal/
  <job>.jsonl`, fsync per event); state = fold of the log (the `state` module
  of the core). A torn last line is ignored and reported.
- A cell depends on setup phases, not on a sibling cell's success; a failed
  cell never fails cells that do not declare it as input.
- Jobs run one at a time per leader, FIFO; a lab lock (below) covers a job.

Autonomous cells:
- A daemon starts each cell process as a transient systemd unit
  (`benchrun-<job>-<cell>`, `RuntimeMaxSec` = deadline + margin) running
  `benchrun cell <dir>`. A daemon restart re-attaches to the unit or the
  `done` marker; starting is idempotent, never a second run.
- The cell runner watches progress locally (plugin progress signal), enforces
  the deadline, writes `rc`, `warnings.jsonl`, results, then `done` (atomic
  rename, last).
- Multi-client start: the leader sends a barrier time; each client waits on
  `CLOCK_REALTIME`. Stall detection runs on the host, never on the leader.

Agent footprint (binding, user 2026-11-07):
- An idle agent costs a heartbeat and a few KiB: no per-measurement disk write.
  Samples and progress points are buffered in memory (fixed ring per cell,
  256 KiB; the oldest lines are dropped and counted when the disk stalls) and
  written in bulk: at 64 KiB or 30 s at the latest, and at cell end. A crash
  loses at most that window; a cell result never depends on it.
- The agent writes only below its own data dir on the root disk, never to a
  device under test.
- Housekeeping: the agent's threads are pinned to one housekeeping CPU (`--housekeeping-cpu`, default the last
  allowed CPU), nice 19, ionice idle. Workloads are started by a launcher thread created before that, so they
  keep default attributes.
- No polling: threads wait on a condition (stop, connection closed) with a timeout of one heartbeat or tick; the
  leader blocks in `accept`, the advertiser in `recv`. An idle leader + agent pair wakes about 5 times per second
  at a 1 s heartbeat (voluntary context switches on a Linux runner, `tests/idle.rs`, bound 15/s).
- The leader never writes to a socket under its state lock: every connection has a writer thread behind a queue,
  so a stalled agent delays only itself (sim test).
- Tests: a fake clock counts writes (batching) and a failing writer checks the ring bound.

Cluster resources and waits:
- Resources the tool creates carry the prefix `br-` plus the test set instance (pools, rules, cephx users, images,
  buckets, fs) or job id (per-job objects); pools also carry `ceph osd pool application set <pool> benchrun owner
  <id>`. Purge acts only on own prefix and owner tag and verifies by listing, not by health.
- Foreign resources are never touched; they are listed in the job's
  `foreign.json` and a cell they can bias is `contaminated`.
- Waits are scoped: own pools' PGs `active+clean`, measured daemons up and
  restarted. Health outside that scope is a warning, never a block.

Lab locks: a lease held by the daemon on the lock host for the job's lifetime (journaled `{owner, job, epoch,
expires}`, renewed while active); a lost submitter or leader connection does not release it, job end or expiry does.
The daemon also holds the `lock.sh` `flock` file, so old and new tools exclude each other during migration. Cells
carry the lease epoch (a stale epoch is refused); hv-isolate apply/revert (adr 0047) run in the lock-host daemon.

Failure classes, evidence, timeouts, output:
- Every cell and phase ends in one class: `ok`, `measure-fail` (workload ran; rc != 0 or numbers out of spec),
  `harness-fail` (precondition, deploy, parse), `infra-fail` (host unreachable past the deadline, lease lost),
  `contaminated`, `interrupted`. Only `ok` cells carry usable numbers; consumers show classes separately.
  `client-bound` is an annotation on `ok`.
- Only a fresh `start` launches a cell unit. A restarted agent re-attaches to a running unit or a `done` marker; a
  started step with neither (unit died while the agent was down) is `interrupted` and never launched again, so no
  second prefill or measurement happens silently. A re-run is a resubmit under a new job id.
- A cell whose workload is spawned later than `barrier_tolerance_ms` (default 1000) after its barrier (late
  `run` after a reconnect, slow delivery) is `contaminated` with the lag in its notes; `result.json` records
  barrier, spawn time and lag. A late client skews a multi-client aggregate, so it is not `ok`.
- Evidence is checked inline on the host before a cell is `ok`: result files
  parse, bytes/ops equal the target, sampler series non-empty, rc of every
  client, warnings count. `benchrun verify <job>` re-runs the same checks.
- Loud timeouts as AGENTS.md: the timer that owns a deadline emits `WARNING TIMEOUT <operation> exceeded <limit>s
  (<context>)` to stderr and the job's `warnings.jsonl` (typed `Expired`, no rc inference); summaries count them.
- Every subcommand takes `--format plain|json|json-pretty` via `outfmt`, record streams also `jsonl`. Exit codes: 0
  ok, 1 measure-fail, 2 usage, 3 harness-fail, 4 infra-fail, 130 interrupted (rustdoc of `class`).

Results (data only, no analysis):
- The leader stores each job under `${LAB_RESULTS:?}/<job>/`: `spec.json`, `leader.jsonl` (journal),
  `warnings.jsonl`, and `raw/<cell>/<arm>/<host>/` per cell x host: every artifact verbatim (fio `json+` and logs,
  stdout/stderr, rc, `series/sampler.jsonl` = raw 1 Hz series, `result.json` with class, notes, start lag, barrier,
  wall times and fio's own parsed numbers, `done` marker with sha256 of every file). No cross-host aggregates,
  no percentile merging, no comparison.
- `benchrun pack <job> [--out FILE] [--cells id,...]` hands the data out at any time, also mid-job: one plain tar
  (`<job>/spec.json`, `leader.jsonl`, `warnings.jsonl`, `raw/...`, `manifest.json` last) with sha256 per file, class
  per cell x host and the pack time; a running cell is listed `state: running` without data (`partial: true`).
  Missing finished files are fetched from the agents first; the tar streams over the blob protocol in two passes
  (measure, then stream; a file changing in between fails the pack), no temp file. Tar is plain (zstd would need a
  C build); Parquet is not built.

Rollout:
- `scp benchrun host:; ssh host ./benchrun setup --role agent --cluster C --psk-file F --labels L` (no flags =
  interactive) writes `/etc/benchrun.toml` and `benchrun.service` (`ExecStart` = the binary's own path), starts it
  and checks within a hard timeout (loud `WARNING TIMEOUT`) that the agent joined / the leader listens;
  `setup --remove [--purge]` undoes it. No musl build, no deploy scripts.
- Update = replace the leader binary: an agent of another build is sent the leader's binary, installs it by atomic
  rename once no cell runs and re-executes itself; the leader starts nothing on such a host. CLI: proto + PSK only.

Composition and dry run (am. 1):
- Reusable definitions live in a repo folder (`benchmark/`): scenarios carry no target and no arm, arms are
  separate files, hosts come only from the leader's host map (roles/labels). `submit DIR|FILE --arms a,b
  [--arms-dir D]` composes on the client: `include` (arrays appended, a scalar conflict is an error), `matrix` on
  cells (id and fio/omap fields), cells without `arm` crossed with the chosen arms (id suffix `-<arm>`). There is
  no override and no `--set`: a different value is a different file or arm. The resolved file list + sha256 is
  part of the spec hash.
- `plan` (= `submit --dry-run`): the leader resolves, every agent compiles its part and answers `DryRunReply`;
  output = per cell and host every command as a shell line in order (`pre` steps, workload + job file, `post`),
  cwd, env, sampler, and per host the host configuration list (below); nothing runs or is journaled.
  `plan --offline` needs no leader.
- `pre`/`post` steps (each with a required `deadline_s`) run on their hosts in list order, step n+1 after step n
  finished on all hosts: pre before the leader chooses the barrier (failure = `harness-fail`, dependents skipped),
  post after all workload hosts are done (failure = `contaminated`). Agents journal each step and keep its output
  in the cell dir (covered by `done`, packed, also for a failed pre step, which seals the cell); a step running
  at an agent restart is `interrupted`, never re-run.
- `cold_start = true` (spec, per cell overridable) expands the arm's `[arms.cold_start]` (restart per OSD,
  drop caches, wait) into leading pre steps. `wait` = `pgs` (default: all PGs `active+clean`), `health`
  (`HEALTH_OK` minus `ignore = [codes]`) or `none`; run by `benchrun wait-cluster` on parsed `ceph -f json`.

Bounds and packaging (am. 2):
- Process groups recorded by a unit (`pid`, `wpgid`, with the boot id) are signalled only when proven ours: another
  boot drops the record, and a live member must carry `BENCHRUN_CELL=<ctl>` in its environment.
- Every wait is bounded and loud: leader reply (`REPLY_S`), file fetch (`FETCH_LIMIT_S`; hosts whose files do not
  arrive end `harness-fail`), `submit --wait` (total job deadline = cells + `CELL_MARGIN_S`).
- A cell without numbers is never `ok`; observer-only (sample) hosts have their own class rules; start lag comes
  from fio's own `job_start`; `idle_seconds > 0` is `contaminated`.
- `pack` writes `<out>.part`, verifies the sha256 and renames; an existing archive is never truncated. Hashes are
  streamed, `done` is fsynced before its rename.

Host configuration (am. 3):
- `[host]` and `[host.<label|role>]` in the spec (all keys optional, composable via include) prescribe the host
  state: `cstate_max`, `governor`, `turbo`, `thp`, `numa_balancing`, `gro`, `gro_hw`, `irq_affinity = "spread"`,
  `rings`, and verify-only `smt`, `mtu`, `irqbalance`, `cmdline`, `bios_version`. NIC keys need `nics = [..]`
  (interface names or CIDRs); no selector = spec error, and the NIC carrying the agent's leader connection is
  never changed (verify-only, with the fix command). Readers and appliers are
  `crates/hwcheck` (`hostcfg`), reusing the `host-tune` plan/apply/revert engine and its state file; benchrun
  adds only the glue (`hostenv`).
- Agent setup flag `allow_host_config` (default false). Without it the agent only verifies: a mismatch ends the
  affected cells `harness-fail` with expected and actual value and the fix command. With it the agent applies
  at plan arrival, reverts at job end (`JobEnd`) and, from its undo log, at the next start after a crash.
- Evidence: the full hwcheck state at job start and job end (`<job>/host/<host>/snapshot-job-*.json`) and before
  every cell (`host-snapshot.json` in the cell dir). A prescribed key whose value differs at cell end from cell
  start makes the cell `contaminated` (`host-drift.json`).
- The dry run lists per host every key with state `ok|apply|verify`, the apply commands, the revert commands
  and, for `verify`, the fix command; an unfixable mismatch makes `plan` exit 3.

Failure events (am. 4):
- Every failure an agent sees is an `Event{id, host, job, step, phase, class, reason, tail}` pushed to the leader at
  once (`Msg::Event`): workload rc, kill, deadline or stall; a pre/post/cold_start step; observer or sampler;
  hostcfg refusal or drift; unit death or start failure; a write error below the data dir (`disk`); the agent's own
  fatal error. The agent journals it first (`events.jsonl`, rewritten to the unacknowledged ones at start) and
  resends after every reconnect until `EventAck`; the leader applies an id once (also across a leader restart).
- The leader appends each to `warnings.jsonl` (`kind: event`), logs `WARNING EVENT host= job= cell= phase=
  class=: reason | stderr: tail`, lists it in `status` and prints new ones in `submit --wait`. A workload, unit
  or hostcfg failure aborts the cell on the other hosts at once (`Msg::Abort`: steps and unit killed, they end
  `interrupted`, not counted against the cell; the failing host carries the class); a failed pre step fails the
  cell without waiting for the other hosts' steps.

Preflight (am. 5, user 2026-11-07):
- An agent checks its host when it receives a plan part, before the ack. Needs are derived from the plan: the first
  word of every command (workload, pre/post, cold_start and arm steps; bare name on `PATH`, else an executable
  path), the programs the `[host]` keys run (`HostWant::required_tools`: `ethtool` for NIC keys, with
  `allow_host_config` also `cpupower`, `sysctl`), the sampler's `/proc/stat`, a writable data dir with free space.
  `fio --version` goes to `host/<host>/preflight.json`. A host with a missing item stores nothing and answers
  `PlanAck{missing}`.
- The leader refuses the whole job before any cell starts: job `harness-fail`, `refused: "preflight: host6: fio: not
  found on PATH (fio cell w4k); host7: /usr/bin/cpupower: missing or not executable (host.governor)"` (status,
  `warnings.jsonl` kind `preflight`); no cell gets a class. It also checks its results dir at submit. `plan` /
  `submit --dry-run` show the same items as problems (exit 3), from live agents.

Targets and names:
- Every host, address, path and credential comes from the private lab env
  (`FLASHSTORE_LAB_ENV`, required keys, no defaults) and the inventory it
  points to; results only below `${LAB_RESULTS:?}`. The repo carries example
  inventories, test sets and jobs with `${LAB_*}` references.
- Product names (binaries, units, keyrings, data dirs, `osd_objectstore`
  values) come from one Rust module; a rename is one change, checked by tests.

Bootstrap and upgrade: one static binary (`x86_64-unknown-linux-musl`, aarch64 alike) plus one systemd unit, installed
by `benchrun setup` (Rollout) or `lab/benchrun/bootstrap.sh`. Upgrade is never mid-job: the leader refuses a job
while daemon versions differ, so a half-done upgrade is visible, not mixed.

Harness CI:
- A `Cluster` backend trait and a `Workload` trait (split file) have fake implementations; an in-process
  multi-daemon cluster (leader + N daemons on loopback TCP, fake units, fake cluster, fake fio writing committed
  fixture output) runs whole jobs in `cargo test -p benchrun` (Mac and Linux, no lab).
- Chaos tests (list: doc/perf/adr-0684-history.md): leader kill and restart, partition, daemon restart, submitter
  disconnect, spec change, handshake mismatches, lease loss, foreign resources, deadline expiry, torn journal,
  failure events (live push, resend once).
- A live smoke job (2 tiny cells, one arm) runs on a lab VM before every block, with one daemon restart and one
  leader kill mid-cell.

## Rationale

- The causes A-G are structural; patching single scripts failed all week and new failures of the same classes
  followed. Daemons on every host remove A at the root: measurement, sampling and locks live on the hosts, the
  leader only sequences and collects; a reconnect is a transport recovery, never a retry of the measurement.
- Designated leader: one operator, one job at a time; election adds split-brain modes for no measurement value.
  A leader outage is a pause between cells; cross-host progress without a leader needs the consensus we reject.
- Plain TCP + JSON lines: no dependencies beyond `serde_json`, debuggable with `nc`; HTTP/2 adds ~60 crates and an
  async runtime for a few dozen connections. Security beyond an optional PSK is out of scope (user 2026-11-07).
- Desired-state test sets with fingerprints reuse deployed state; explicit freshness rules keep numbers fair.
- Parquet over OpenMetrics for series (columnar, typed); `parquet` crate, default features off + zstd.
- Rust: a missing function is a compile error and the whole state machine runs in-process in seconds (C, D, E).
- Trade-off: weeks of harness work and one parity lab block instead of per-incident fixes.

## Consequences

- + A dropped connection, a leader restart or a submitter disconnect loses no cell and no lock.
- + Jobs reuse deployed state; a test set change costs its delta.
- + CephFS and S3 cells share job, sampler and result path.
- + Harness faults are their own class and cannot fail measurement cells.
- + Arms are comparable: same purge, freshness, cold start and primary balance, recorded with the fingerprint.
- + Harness changes are tested without a lab.
- - A daemon and a systemd unit on every benchmark host; on e9455 they run on croit-managed hosts (open question).
- - Plain TCP, unencrypted, at most a PSK: lab and cluster networks only.
- - Balanced primaries and new freshness rules change numbers versus older runs (compare only via the parity block).
- - `pg-upmap-primary` needs `require-min-compat-client` >= reef.

## Migration

Small steps, each merging on its own; old scripts keep working until deleted. Done: core, daemon and protocol,
sampler, `pack`, rollout, composition, dry run, pre/post steps, host configuration, failure events. Open: attach
backend and e9455 parity block (interleaved with the old chain, noise rule adr 0047 am. 1), lab-container backend,
CephFS, S3, deletion of the old scripts (a private chain after its cells pass parity; a repo bench script in the
commit that adds its job; `lab/remote-test.sh` and `lab/e2e` stay). Step log: doc/perf/adr-0684-history.md.

## Alternatives

Rejected (reasons in doc/perf/adr-0684-history.md): an ssh controller (cause A
stays), leader election, HTTP/2 or gRPC, peer-to-peer coordination, OpenMetrics
for series, cleaning the bash, cbt, teuthology, an own load generator, fio
client/server mode, Ansible.

## Open questions

- Does croit-flashstore-osd honour `pg_upmap_primary` (primary selection) for
  v21.2.0 and v20.2.4? Required before `fair_primaries=on`; else a spec fix
  item for the OSD.
- e9455: may a `benchrun` daemon and unit run on the croit-managed servers and
  the croit management node, or only on client hosts with server-side sampling
  via another route?
- Leader host: build host (inside the network) or a client host? Submission
  from the Mac then goes over Tailscale to it.
- Report renderers (PDF/decks): keep private Python, or a Rust renderer later?
- Further questions on test sets, S3 and CephFS: split file.
