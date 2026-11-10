# 0184 typed session-loss recovery
Status: accepted
Date: 2026-10-14
Context: automatic UNBLOCK recovery exists; socket loss still cancels requests. Blindly retrying all messenger faults would also retry corrupted/auth-rejected traffic.
Decision: typed, rejection-dominant failure classification; bounded exact-session wake of original logical requests, immutable deadlines and existing retry policy. Contract RC-SESSION (doc not in the source snapshot).
Consequences: transient socket/session failures can recover without fresh mutation identities; protocol/auth errors remain terminal. Watch disconnect remains explicit. Default-off lab implementation only; production reconnect pacing remains required.
Alternatives: diagnostic-string matching (fragile); retry every fault (unsafe); fresh-ID resubmit (duplicates mutations).
