# 0194: native watch/notify broker integration
Status: accepted
Date: 2026-10-15
Context: native owner handles object replies/backoff but watch/control primitives remain confined to manual lab driver.
Decision: own bounded WatchRegistry inside ObjectClient; expose current-session reservation/rebind, typed handle-bound control submission, activation/initial notify ID, separate notification/error polling/removal. Route WATCH_NOTIFY only through own broker. No implicit ACK/retry or initial-ID-as-final completion.
Consequences: session loss faults matching handles; close clears payload events and reserves disconnect errors until handle removal. Control handoff cannot silently cross its reserved session. Automatic ping/reconnect/watermark lifecycle remains required before full release. Reuse existing registry/queue contracts; no duplicated protocol state machine.
Alternatives: expose raw mutable sessions (breaks lifecycle); silently ACK/drop (false delivery); expose control without matching registry context (lost notification routing).
