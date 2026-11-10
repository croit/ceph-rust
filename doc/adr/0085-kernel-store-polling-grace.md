# 0085 Kernel store polling grace
Status: accepted
Date: 2026-10-13
Context: performance finding 3. Kernel TCP completions wake the network ring; polled NVMe completions do not. The default 20 us ring wait after 100 idle passes can delay a QD1 media completion.

Decision:
- On the kernel tier, poll a busy store for up to 100 us since the last loop progress before allowing the configured short idle wait. Use the iteration's existing timestamp, with no extra clock read on the active path.
- Keep the existing configured short wait after that bounded grace period. A slow or stalled store cannot force indefinite spinning without progress. Keep pure `--idle spin` available.
- When the store is quiet, preserve existing deep-idle eligibility, mesh wake recheck, connection timer cap and 1 ms maintenance cap. The existing `store_quiet()` hook includes queued work as well as device IO; this conservatively covers polled dependencies without adding a cross-layer IO counter.
- Keep idle defaults at 20 us / 100 passes. The additional wall-clock grace covers short IO independently of core iteration speed. No store scheduling, durability, FIFO, timer scheduling or wire changes.

Validation: deterministic regression fails on the original policy, verifies no wait during the busy grace period, bounded fallback, reset on progress and immediate quiet deep idle. Local kernel TCP QD1 4K benchmark with the existing simulated device measures read/write latency, active CPU and quiet CPU for default and spin. Physical NVMe qualification is outside these local measurements; results and reproduction in `../perf/codex-perf3-2026-10-13.md`.

Consequences: higher active CPU for shorter completion latency; idle CPU saving retained. IO lasting beyond 100 us without progress still incurs the configured short wait. A shared-host scheduler and ring wakeup can add latency even when no wait occurs with media outstanding.

## Amendment 1 (2026-10-25): wake-latency idle replaces the fixed grace
The fixed 20 us wait / 100 passes idle and the 100 us store grace (`STORE_SPIN`) are removed (20f6d00964). An idle core polls until the idle period is as old as one measured wake latency, then sleeps in the ring with a cap derived from it (no fixed re-sleep time); device-wait parking per adr 0162. Current policy: adr 0053 (Idle and busy poll), `crates/rt/src/knet/kcore.rs`.
