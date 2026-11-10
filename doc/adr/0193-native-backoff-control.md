# 0193: native backoff ACK/park/release integration
Status: accepted
Date: 2026-10-15
Context: native request owner still fails closed on OSD backoff; own bounded BackoffTable already defines wire/range rules.
Decision: reuse table in ObjectClient; validate current authenticated replicated session/PG before admission/ACK. Bounded independent ACK queue (64KiB, <=request slots), exact original echo/IO priority, send before more data, 10s local control deadline. Known UNBLOCK reconsiders stored original range; finite read policy only for already-sent requests, parked descriptor keeps attempt.
Consequences: stale sessions/unknown UNBLOCK passive, no live eviction, session reset clears table/ACKs. Output saturation retains control; timeout/overflow closes conservatively. Default mutation retry remains disabled. Cold loss/release scans/codec allocation and stronger output-pool/control fairness remain release work.
Alternatives: fabricate ACK (unsafe peer state); ignore BLOCK (discarded requests hang); resend every operation on release (unsafe mutation policy); unbounded control queue (memory growth).
