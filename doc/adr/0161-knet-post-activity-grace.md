# 0161 Knet post-activity polling grace (default off)
Status: REMOVED 2026-10-17 (lost A/B; see Am. 1)
Date: 2026-10-16

## Context

Stub. A post-activity polling grace on the knet conn core was tested to cut reply_tx latency.

## Decision

- Removed 2026-10-17. The knob `--knet-grace-us` / `NV_KNET_GRACE_US` and its code are gone; no production change.
- A/B tables and the full ADR text: doc/perf/adr-0161-history.md (verbatim copy at `0ead2ef8f`).

## Rationale

- A/B (icelake-6330 VMs, 50 us vs 0): no latency gain, +50-85 % CPU/op at 50 us.
- A window shorter than the PG latency expires before the reply arrives; a window covering it is equivalent to spin (rejected).
