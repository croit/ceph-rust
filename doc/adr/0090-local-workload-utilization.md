# 0090 Local workload utilization
Status: accepted
Date: 2026-10-14
Context: finding 10; fixed PG ownership and connection-count placement cannot detect skew in actual work. ADRs 0006, 0031 and 0035 retain core ownership and local counters.

Decision:
- Add plain cumulative busy_ns, ops and bytes on each core and PG. No placement, admission, scheduling, wire or disk changes. Counter-only PG mutation bypasses deadline/change tracking.
- Core busy_ns uses the runtime's existing previous-work clock sample, including networking and store work, excluding idle spin/sleep. This is work-loop wall time, not process CPU time or device service time. All three runtime loops supply it.
- PG busy_ns measures synchronous engine dispatch, single-PG peer handling, and per-PG timer work/collection, including scrub/recovery executed there. Engine/peer dispatch uses the calibrated store clock (Instant fallback); cold timer dispatch uses Instant. Deferred store polling and connection crypto are unattributed to individual PGs and remain in core busy_ns. Action execution outside those scopes is likewise not charged to a PG. Counters are useful for skew diagnosis, not a complete CPU profiler; PG busy_ns is not expected to sum to core busy_ns.
- Ops counts admitted primary client requests and single-PG peer messages (including control). Bytes counts client input/output payload and replica write/recovery-push input payload using existing lengths; it excludes headers, network retransmits, recovery output and physical IO. A blocked/resubmitted request may count multiple attempts. Multi-PG control messages are unattributed.
- Carry worker snapshots in internal CoreStats, at the existing one-second cadence. Build local admin `perf dump` / `counter dump/schema` groups flashstore_core_<core> and flashstore_pg_<core>_<pool>_<hex-seed>_s<shard>. Leave the canonical mgr counter catalogue and pg_stat_t unchanged.
- `perf reset` stores an admin-only baseline. PG counters restart on PG recreation/migration; if a new value is below its baseline, report the new value. A logger name identifies a PG location rather than a permanent lifetime. Missing/moved worker groups can remain until the next snapshot.

Design options (not implemented): weight newly accepted connections by recent bytes and core work time; offload independent CPU work with bounded results and owner-core completion; migrate PGs only through the existing ordered/durable migration protocol. Connection weights cannot move a single hot PG's work; offload adds ownership/lifetime costs; migration must preserve shard FIFO and metadata ordering. Measure first using the counters above. No claim of improved throughput from this instrumentation.

Validation: before/after empty engine dispatch cost; hot PG write/read counts and payloads; reset; worker snapshots; diagnostics absent from mgr catalogue; counter updates leave touched-PG tracking empty. Native osd/peering/rt and Linux kernel-runtime tests. Measurements and limitations: ../perf/codex-perf3-2026-10-13.md.
