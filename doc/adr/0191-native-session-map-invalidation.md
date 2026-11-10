# 0191: invalidate native OSD streams on map address/down changes
Status: accepted
Date: 2026-10-14
Context: NativeSessions reused a ready OSD connection across changes to its public address vector. Queued messages could outlive map admission.
Decision: capture each peer's address vector plus cold single-owner validity cell. New map epoch invalidates down/removed/address-changed peers before route or event publication; exact stream closes, Reset loss, fresh ticket/ID on replacement. Queued ready/message events capture the validity cell; stale events release credit in bounded polling. Transport-only loss does not revoke earlier authenticated queued replies.
Consequences: no per-message allocation for validity (Rc clone only); one cold cell/session. Map scan covers the peer slot vector (initial `Limits::osds`, constructor cap 64; `peer_slot()` grows it for a larger active population), only new epochs. TCP stream-validity gate cancels staged suffixes/revoked Dials independently of Close queue budgets. Request remap/retry scheduler remains separate. Already application-owned events or transport-handed bytes cannot be recalled.
Alternatives: reuse old advertised address (stale endpoint); purge whole event FIFO on every map (unrelated reply loss); remember all retired IDs forever (unbounded memory); copy address vectors into every reply (allocation/copy).
