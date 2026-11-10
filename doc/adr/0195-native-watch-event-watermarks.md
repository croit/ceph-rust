# 0195: native watch event delivery watermarks
Status: accepted
Date: 2026-10-15
Context: native event API has no callback executor. Removal clears queued cookie events; callers need a bounded delivery barrier independent of later notifications. Pinned librados flush orders its callback strand, not remote ACK or notification completion.
Decision: add registry-scoped opaque event watermark, captured at accepted event sequence. Query completion when every earlier queued payload has been transferred by poll or discarded by explicit removal/close. Later events do not delay barrier. Reserved watch errors remain separate. No implicit ACK, remote unwatch or callback/application-work completion implied.
Consequences: fixed per-event sequence, no extra allocation/queue or slot tombstones; foreign watermark rejected, sequence exhaustion fail closed. Adapters dispatching work beyond poll must implement their own task barrier. Existing poll event shape remains stable.
Alternatives: wait for empty queue (can starve under later arrivals); assume empty local queue means remote drain (false); add callback executor to reactor (unneeded ownership/thread coupling).
Validation: own tests cover empty/prefix/later events, non-prefix removal holes, foreign registry, close and reserved errors. Native runtime wrappers expose same boundary. Full automatic watch renewal/reconnect still separate required work.
