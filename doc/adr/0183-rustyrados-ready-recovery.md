# 0183 bounded ready recovery
Status: accepted
Date: 2026-10-14
Context: classic OSD may discard a blocked request; releasing table entry alone does not complete it.
Decision: bounded deduplicated ready FIFO, known-range/session UNBLOCK wake, current route/block/deadline/policy validation before original-identity resend. Contract RC-RECOVER (doc not in the source snapshot).
Consequences: raw overload events cannot grow an unbounded retry list; stale requests are ignored. Lab cold prepare remains blocking; production coordinator/fairness and additional retry triggers still required. No fresh mutation identity or fake ACK.
Alternatives: resend every pending request on any UNBLOCK (wrong scope); fresh-TID resubmit (duplicates mutation); immediate unbounded resend loop (starves control work).
