# 0182 absolute indexed request deadlines
Status: accepted
Date: 2026-10-14
Context: CLI outer timeout alone cannot provide native logical lifetime/certainty or retry horizon.
Decision: once-set absolute microsecond deadline, existing pre-registered indexed heap, budgeted expiry, explicit sent/unsent Deadline outcome. Clear on terminal; retries never extend. Contract: RC-DEADLINE (doc not in the source snapshot).
Consequences: timer work proportional to expirations, not outstanding table size. Driver time/cadence/default policy remains required; no remote cancellation/rollback claim. Wire TID and immutable context unchanged.
Alternatives: fresh deadline each retry (can wait forever); scan slots each loop (scales with outstanding); map timeout to definitely-failed write (unsafe).
