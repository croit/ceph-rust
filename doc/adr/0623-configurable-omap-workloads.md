<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH -->
# 0623 Configurable asynchronous OMAP workload benchmarks

Status: accepted
Date: 2026-10-28
Amends: [0535](0535-omap-comparison-matrix.md), opt-in workload runner;
legacy matrix commands, datasets and result schemas remain unchanged.

## Context

Compare compatible cluster configurations using the same configurable workload,
without one-off scripts or mandatory collection of expensive measurements.

## Decision

Use `oprobe omap-workload` with the existing asynchronous client. The optional
`lab/omap-matrix/workload.sh` adapter targets an already-running owned matrix
cluster; neither entry point provisions, formats, tunes or stops a cluster.

### Workload parameters

| Parameter | CLI flag | Default / meaning |
|---|---|---|
| Object count | `--objects N` | `1`; total objects, shared across clients |
| Key size | `--key-bytes N` | `48` bytes per key |
| Value size | `--value-bytes N` | `300` bytes; zero is allowed |
| Prefill | `--prefill N` | `250000` keys **per object**, not per client |
| Batch size | `--batch N` | `256` keys per request |
| Client count | `--clients N` | `8` producer threads, each with its own connection context |
| Queue depth | `--qd N` | `1`; maximum asynchronous requests outstanding **per client** |
| Operation combination | `--operations LIST` | `insert,delete`; ordered, repeating comma-separated list |
| Request limit | `--ops-per-client N` | Exactly N requests per client, not N keys or cycles |
| Duration | `--seconds N` | `60` seconds if no request limit; mutually exclusive with request limit |
| Reporting interval | `--interval N` | `60` seconds per completion/resource window |
| Overall workload limit | `--max-seconds N` | `3600` seconds for foreground plus drain |
| Live-key ceiling | `--max-live-keys N` | `10000000` tracked keys; maximum `32000000` |

### Connection and output parameters

| Purpose | CLI flags | Requirement / default |
|---|---|---|
| Cluster and authentication | `--conf`, `--mon`, `--keyring`, `--entity`, `--mode`, `--timeout` | Existing client options; CRC/Secure supported |
| Pool | `-p POOL` | Required existing pool; never created/deleted by this workload |
| Namespace / locator | `-n NS`, `-k KEY` | Optional; empty by default |
| Object identity | `--prefix NAME` | Required fresh prefix; exclusive object creation |
| Result directory | `--output-dir DIR` | Required fresh directory; parent must exist |
| Dry plan | `--plan` | Validate/print the workload without network IO or output creation |
| Stdout format | `--format FORMAT` | `json`; also `plain` and `json-pretty` |

### Supported operations

| Operation name | Request behavior |
|---|---|
| `insert` | Insert a batch of new, uniquely named keys |
| `update` | Update a batch of acknowledged live keys |
| `delete` | Delete a batch of acknowledged live keys |
| `read` | **Batch read by keys**, validating exact keys and values |

The list is a cyclic submission order, not a compound RPC or random mix. Repeated
names express weights. With `insert,delete` and QD5, the first outstanding requests
are I,D,I,D,I when enough live keys exist. A request limit may end mid-cycle;
there are no hidden operations to rebalance it.

**Range/prefix scanning is not currently a selectable benchmark operation.** Full
paginated scans run only for mandatory verification, outside workload timing.

### Ownership and correctness rules

- Distribute objects round-robin across clients, splitting disjoint key ownership
  when clients outnumber objects. Each client runs one operation cycle per object
  visit. Four objects/eight clients means two clients per object.
- Update/delete/read reserve acknowledged FIFO keys; pending requests never share
  them. Inserts become eligible after durable completion, without random lookups.
  Require QD × batch prefilled keys per owner/object; drain recoverable pressure,
  but fail irrecoverable exhaustion without reordering operations.
- Keys have exact length/unique identities; values are deterministic by key/version.
  Validate key-space/memory limits before IO: pending payload <=1GiB, per-client/
  window histograms <=256MiB, and the configured live-key ceiling.
- Setup/prefill/readback/warmup precede a common start. Count mode measures cohort
  completion; duration mode stops admission at its deadline and separates drain.
  All waits are bounded; failed setup releases workers. Recheck deadlines after
  preparation and undo unadmitted reservations; never mix blocking/async execution.
- Writes require successful overall/per-op status and ACK|ONDISK together
  (contract (doc not in the source snapshot), sections 2.3/3.1). Unknown mutation outcomes
  fail the run. Read validation and exact final paginated key/value verification
  are mandatory; corruption, missing/extra keys or non-progress cannot pass.

### Measurement parameters

`--metrics LIST` selects measurements; default: `throughput` only.

| Metric name | Captured measurement / target |
|---|---|
| `throughput` | Request/key/logical-byte rates, counts and elapsed time |
| `latency` | Pooled request p50/p95/p99/max and raw histogram buckets |
| `client-cpu` | Benchmark-process CPU; 100% means one core |
| `osd-cpu` | CPU of explicit local targets: repeatable `--osd-pid PID` |
| `rss` | Sampled client/selected-OSD RSS, not an exact peak |
| `writes` | Device written sectors: repeatable `--block-stat /sys/.../stat`; 512-byte sectors, not NAND writes |

`--all` selects all six measurements, not additional workloads or traffic; it is
exclusive with `--metrics`. Throughput-only mode allocates no latency histograms
and starts no resource sampler. Required correctness/client overhead remains.

Sample resources read-only over foreground time, recording interval/boundary lag,
PID identity and monotonic counters from bounded kernel sources. Missing remote
metrics are unavailable, never zero. Pool histograms; never average p99s.

### Evidence

Save resolved workload/ownership and sanitized connection settings in
`manifest.json`; counts/windows/selected metrics/drain/errors/verification in
`summary.json`; optional resource samples in `resources.jsonl`. Preserve partial
evidence and reconcile admitted/successful/failed/unknown request outcomes.

Objects and failed attempts remain for inspection; no automatic cleanup/resume.
Usage: suite README (doc not in the source snapshot). Implementation details:
`oprobe::omapworkload` (doc not in the source snapshot).

## Rationale

Disjoint acknowledged key ownership permits real asynchronous depth without
absent-key mutations. Optional instrumentation controls observer cost; existing
client/matrix reuse avoids a parallel framework or changed legacy results.

## Consequences

- + One workload definition supports different compatible cluster configurations.
- + Independent Rust/bash regressions cover scheduling, ownership and failures.
- - Client bookkeeping/validation affect throughput; full verification adds time.
- - Finite key spaces/live sets can exhaust; remote resource targets need explicit
  configuration. Readback is not crash/power-loss or mixed-peer qualification.

## Alternatives

- Change legacy matrix defaults: rejected; breaks result comparability.
- Compound RPCs/QD1 lanes, random lookups or optimistic key ownership: rejected;
  cannot provide the requested independent, known-live asynchronous stream.
- Disable correctness or add traffic with `--all`: rejected; measurement selection
  must not change workload semantics.
