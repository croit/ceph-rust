# 0478 Queued-head cold-page dependency cohorts
Status: proposed
Date: 2026-10-21

## Context
ADR0082 FIFO heads retry on store progress. Bulk OMAP staging can discover many
cold pages, discard its incomplete private overlay, then repeat that work while
only some reads have completed. ADR0092 discovers before materializing data;
it does not retain incomplete metadata discovery. Main's early dirty-hard refusal
(ADR0021 amendment62) addresses a different path and remains unchanged.

## Decision
Capture bounded page addresses missed by a nonblocking FIFO-head preparation or
submission attempt. On a page-miss refusal, wait for that discovered cohort before
another expensive attempt. These are scheduling hints, never a residency proof:
rerun the existing lookup, accounting, validation, admission and durable commit.

- One token owns each shard's hints. Capture at most4096 observations; deduplicate
  after capture. Empty/overflowed/ambiguous capture falls back to ordinary retries.
- Only first successful completions of exact members renew the30s stall bound.
  Unrelated pages, duplicates and unknown wakes do not. Required read failure or
  unknown/stale readiness permits fresh validation. An invalidated cohort still
  observes real member completions after a stopped process resumes.
- Allow one final revalidation of obsolete hints at expiry, consumed only when
  the shared preparation budget permits actual work. Do not renew timeouts forever.
- End capture before blocking/feature-barrier recursion. Clear the owning hints
  on failure/abandonment. Preserve prepared ownership, reservations and read fences.
- Poll completions first; keep other shards, lookahead, output and deferred reads
  running. Never wait for all device/shard IO. Existing per-poll budgets remain.
- Resident tree lookups have no new dependency operation. Unowned Page events
  skip error-list/dependency processing. Address capacity is reused; memory
  reporting includes both fixed embedded tracking and retained vector capacity.
- No disk/WAL/wire/feature/checksum/ACK-format change. No counter disabling,
  provisional-result reuse, relaxed durability or peer-safety bypass.

## Consequences and validation
Later dependency rounds may be needed after eviction or structural invalidation.
Readiness reduces repeated CPU work; it does not reduce required read volume.
Incremental simulator completions can exaggerate the opportunity: validate
coalesced and elapsed-envelope schedules, actual compression, FIFO/errors/deadline
cleanup, crash/recovery and existing safety regressions. Keep baseline and
candidate on the same freshly pinned main, and compare real-client populations
in both orders with full readback outside scoring. No speedup is assumed.

The private benchmark/client tooling and receipts are not repository artifacts.
