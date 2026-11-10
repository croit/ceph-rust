# 0068 Review: expanded transaction admission, scrub errors, aggregate cache budgets

Status: accepted
Date: 2026-10-12

Context: the review at 3eeefc18 reproduced tiny clone transactions exceeding the WAL limit after PG admission, scrub enumeration failures becoming completed partial maps, and per-shard cache floors exceeding the requested process budget. See ../reviews/2026-10-12-osd-review.md for all findings and regressions.

Decision:
- The small-wire admission shortcut applies only to operations with bounded expansion. Borrow the transaction's fixed operation records to detect Clone/CloneRange without decoding/copying payloads; these operations always stage the primary's size preflight. Ordinary writes retain the fast path. Replica fail-stop behavior (0066) is unchanged.
- ScrubPart explicitly carries enumeration errors. A primary aborts its local scrub; a replica returns preemption, which a primary must honor before comparing/repairing. No partial map may update clean stamps.
- Preserve the existing safe per-shard cache floor. StoreCfg::for_memory returns an error if the aggregate configured cache capacity cannot fit the requested budget; mount surfaces that error. Do not silently exceed the budget or shrink the working set below the established floor.
- Keep the existing clone storage format in this patch. Shared-extent cloning requires a separately crash-tested persistent reference-count/format upgrade; it remains outstanding.

Consequences: earlier rejection of unapplyable clones, explicit scrub failure/retry instead of misleading completion, and explicit rejection of previously silently oversubscribed memory configurations. Source-dependent staging still blocks while checking clones. No store-format upgrade is performed.
