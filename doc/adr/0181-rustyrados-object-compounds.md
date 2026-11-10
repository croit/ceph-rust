# 0181 rustyrados object compounds
Status: accepted
Date: 2026-10-14
Context: metadata/class operations and captured snapshots need the same lifecycle engine as data ops.
Decision: owned ordered compound vector, immutable context/access/output budget; one wire request; RETURNVEC with exact statuses/owned output vector. Conservative ReadWrite for arbitrary class calls, no compound retry in this increment (see amendment 1). Validate local supported profile before outbound; retain server validation for binary omap schemas. Contract: RC-COMPOUND (doc not in the source snapshot).
Consequences: RBD metadata/cls_lock can use wire forwarding; server executes class methods, no local plugin code. Caller owns declared output cap and class-access cost. Lifecycle/credit/fence engine shared. Initial metadata encoding allocates; typed wrappers/watch/list/control/automatic retries/production transport remain work.
Alternatives: sequentially send a compound's operations (loses atomicity); infer class read-only from opcode (unsafe); flatten per-op output/status into last errno (loses RETURNVEC/FAILOK semantics).

## Amendment 1 (2026-10-25): compound retry
Read-only compounds (Access::Read) retry within the bounded session-recovery rule of RC-RCOMPRETRY76 (spec 76-read-compound-retry.md, `crates/rustyrados/tests/compound_retry.rs`). Mutation compounds are resent like other writes (adr 0177 am. 1). Class calls of unknown access stay conservative ReadWrite and are not retried as reads.
