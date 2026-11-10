# 0095 Chunked copies into EC pools
Status: accepted
Date: 2026-10-14
Context: ADR 0057 amendment 3(c) refused sources requiring multiple copy-get chunks on EC destinations.
The standard EC sub-write already carries a transaction plus temp_added/temp_removed; version 0
and an empty log can carry temporary work without a client-visible PG-log entry.
Decision: supersede 0057 amendment 3(c) (EOPNOTSUPP for a source of more than one chunk; since this ADR only a stripe width > 4 MiB fails that way, `engine/copy.rs` `copy_stage`). Reuse the bounded copy engine and the L/O EC generators:
- Stage chunks into a negative-pool copy temp, with internal object_info carrying the bytes copied so far.
  Retain <1 stripe between replies and stage complete stripes until the final data chunk; reduce
  source chunk allowance accordingly, preserving append-only hashes and the two-chunk bound.
  Stripe widths >4 MiB remain unsupported by staging. Generate shard data normally; unlogged temps get no rollback stash or log entries.
- Carry temp lifecycle fields to every acting/backfill shard. A temp write is not skipped beyond the
  backfill cursor; the final logged replacement can be skipped there and still discards its temp.
- Consume a committed temp with per-shard TryRename in the final destination transaction.
  Explicitly remove the source afterward even if compound DELETE reduces away the rename. Only
  same-PG copy-temp renames are admitted; ordinary arbitrary object renames remain unsupported.
- Optimized EC temp omap mutations apply directly on primary-capable shards because they have no
  log entry to roll forward. Live-object omap keeps the existing EC_OMAP journal.
- Existing destination data stays visible until the final transaction commits; interval/reset cleanup
  removes orphan temps. Per-copy memory remains two chunks, independent of object size.
Consequences: + large rados cp/cppool and copy-from2 destinations work on EC without whole-object
buffering; + no wire or persistent-format change. Clone-style data operations after a temp rename
remain constrained by the existing generator contract; metadata-only compound tails are supported.
Alternatives: gather the entire source in RAM (breaks the bound); invent a peer protocol (breaks classic parity).
Validation: engine copy tests; L/O peering simulation with 9 MiB + 17 B, unchanged destination/log
during staging, one final version and no remaining temps; live evidence against classic EC peers is not recorded yet (no compat-doc entry).
