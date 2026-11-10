# 0192: native bounded request owner
Status: accepted
Date: 2026-10-15
Context: native DPDK object path exists but lab application manually owns routing/replies and cannot provide reusable session recovery.
Decision: ObjectClient<S: ObjectSessions> composes existing ObjectQueue and session owner with bounded slots/TID index/work, absolute deadlines, exact reply/loss association and opt-in finite read recovery. NativeClient aliases NativeSessions specialization; TCP/NIC continue static owner dispatch.
Consequences: no duplicate request state machine; retries preserve queue token/TID/incarnation/deadline and current session placement. Mutation resend was disabled here (enabled by adr 0177 am. 1, amendment 1). Codec/pending-dispatch allocation and backoff/watch/control integration remain required before release; unsupported backoff fails closed initially. Fake own sessions test scheduler without networking/Probe.
Alternatives: put scheduling into examples (not reusable); replace request engine (duplicate completion/retry rules); retry every loss (unsafe mutation/identity behavior).

## Amendment 1 (2026-10-25): mutation resend enabled
`ObjectClient` enables mutation retries at construction (adr 0177 am. 1, 3; `object_client.rs`, `enable_mutation_retries`); writes resend with the same request id within the attempt budget and deadline. Read recovery stays opt-in via attempts.
