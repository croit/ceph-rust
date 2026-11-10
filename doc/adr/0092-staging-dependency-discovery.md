# 0092 Discover staging dependencies before materialization
Status: accepted
Date: 2026-10-14
Context: finding 5, Wave 2 gate clear. Stage::finish previously punched extents of one object, copied/CRC'd/compressed its data, then discovered a cold extent/refcount dependency of a later object. WouldBlock discarded that materialization and restarted it. ADR 0082 FIFO and amendment 1 remain unchanged.

Decision:
- Finish inline handling and stage all extent/refcount punches before physical data materialization. These mutate only the private Stage overlay; no tree/WAL/data state becomes visible before submission. Failure still drops the overlay and releases every data reservation.
- Compute exactly the punch spans the later materialization uses (the span loop in `Stage::finish_inner_budget`; adjacent data runs merge only when compression is configured), without merging/copying payload or allocating a span vector. Leave data normalization, allocation, compression settings, CRCs, extent encodings and final onode/collection accounting unchanged.
- Discovery can still restart cheap/private metadata work after a miss. It prevents repeated DMA copies, CRC and compression from late metadata IO; it does not retain an allocation-stalled materializer. That continuation and the shared core work budget are the subsequent finding 6 work. No extra device wait or new reservation is introduced by discovery.

Validation: two-object 512 KiB update, second object's middle extent leaf cold while names/onodes and the first object are warm. Initial failed attempt must stage zero physical bytes, final total exactly 512 KiB. Verify both object ranges, full object/model/crash/shared-extent/compression tests and release model/crash soaks. Results/remaining scope: ../perf/codex-perf3-2026-10-13.md.
