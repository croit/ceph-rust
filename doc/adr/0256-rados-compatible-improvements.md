# 0256 Compatible RADOS improvements
Status: accepted
Date: 2026-10-16
Context: user explicitly allows differences that fix bugs or improve performance provided general compatibility is preserved. the pinned raw async read defects are documented in spec/rados-abi/c-abi-runtime-async.md#adr0255 (no ADR 0255 exists).
Decision: target application/wire compatibility rather than reproducing every pinned implementation defect. Intentional correctness and performance improvements are permitted; document observable changes and verify unchanged consumers plus independent own contracts. Preserve required ABI, ownership, callback/completion, ordering, atomicity and durability semantics. A claimed improvement alone does not justify an incompatible change. Measure performance claims under comparable conditions.
Consequences: retain the bounded output behavior of that spec section; no reference buffer overwrite emulation. Continue complete API/ABI coverage and production qualification. User authorization does not establish untested consumer compatibility or a measured speedup.
Alternatives: exact bug-for-bug reproduction creates known correctness failures; unrestricted API changes would break the requested drop-in profile. Native API evolution remains separately scoped.
