# 0180 explicit fence-prefix retirement
Status: accepted
Date: 2026-10-14
Context: sticky queue-lifetime errors prevent useful subsequent fences after caller acknowledges a failed batch.
Decision: epoch-guarded explicit retirement of a ready capture covering all admissions; clear acknowledged failure ledger, invalidate old fence tokens, retain wire TIDs/identity/results. Contract: RC-FRETIRE (doc not in the source snapshot).
Consequences: recover ordering domain without reconnecting or silently erasing failure. Pending/superseded capture cannot reset history. Supersedes ADR 0179's "no reset exposed" restriction only for whole completed-prefix retirement; ranged/global/client fences remain open.
Alternatives: reset on completion poll (silently loses errors); partial retirement with one failure record (may lose later failures); new client per failed fence (unnecessary auth/setup).
