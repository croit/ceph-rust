# 0080 Size-only transaction preflight
Status: accepted
Date: 2026-10-13
Context: ADR 0066 admission staged large transactions twice, allocating device buffers and copying/checksumming their payload before repeating that work on submission.

Decision:
- Run the existing object staging logic in planning mode. Retain exact keys, value lengths, physical extent sizes and allocation addresses, but omit device buffers and payload checksums. Raw read-modify-write/clone planning uses initialized placeholder bytes; compression still reads and encodes real data because encoded size determines admission.
- Keep planned address reservations until record/page checking finishes, then return every reservation on success or failure. A checkpoint while loading cold metadata cannot reuse those addresses and alter the plan's footprint.
- Share the record-size, maximum-transfer, WAL-ring and metadata-page checks with prepared transactions. Preserve the half-page-budget replica margin and rolling extent submission from ADR 0066. Planning records are never submitted or applied; normal submission restages real data against current state.

Consequences: raw writes avoid preflight DMA allocation/copy/CRC; copied clones also avoid preflight data IO. Metadata work and compressed size calculation remain. Placeholder values have identical encoded lengths, and metadata preparation depends on key paths and value lengths, not contents. WAL, on-disk and wire formats, replica admission limits and durability ordering are unchanged.

Validation: zero staged payload bytes, copied-clone no-read/real-submission regression, partial-plan reservation cleanup, existing queue/admission page-budget tests and affected store/storeadapt suites. Measurements in `perf/codex-perf-2026-10-13.md`.
