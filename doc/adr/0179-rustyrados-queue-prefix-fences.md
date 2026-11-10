# 0179 rustyrados queue-prefix durable fences
Status: accepted
Date: 2026-10-14
Context: owned writes need an explicit durable barrier, including out-of-order completion and consumed failure results.
Decision: immutable queue-prefix watermark; qualifying writes must all reach terminal state; report earliest admitted failure from bounded sticky prefix ledger. No extra request slots, cross-queue locks or automatic failure forgetting. Initial bounded scan is a prototype cost. Contract: RC-FENCE (doc not in the source snapshot).
Consequences: caller can distinguish durable completion, failure and unknown outcome across a fixed write set. Errors persist for the queue lifetime; range/reset and multi-queue/client fences remain open. This narrows RC-O13 to a single queue and does not establish full RBD FLUSH semantics.
Alternatives: wait latest write only (misses earlier holes); clear errors on completion poll (can falsely report success); retain unbounded failure history (breaks resource cap).
