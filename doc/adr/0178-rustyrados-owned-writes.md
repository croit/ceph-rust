# 0178 rustyrados owned data writes
Status: accepted
Date: 2026-10-14
Context: first mutation increment; read-copy/retry prototype works but full W/N remains incomplete.
Decision: reuse request slot/identity/credits for owned Bytes WRITE/WRITEFULL/APPEND. Enforce ONDISK for successful completion; early ACK remains pending. No mutation retries in this increment (enabled later, see amendment 1). Own contract: RC-WRITE (doc not in the source snapshot). Preserve read API while adding `ObjectQueue` alias and native `submit_write`.
Consequences: immutable input can avoid C boundary copy, but encoding/transport may still copy. Unknown outcome after send explicit. Metadata, compound API, snapshots/fences and production driver remain separate work. Previous read-only ADR restrictions superseded only for these data writes.
Alternatives: fresh TID mutation resend (unsafe for append); mark TCP/early ACK as complete (violates durability); separate duplicate write engine (duplicates lifecycle invariants).

## Amendment 1 (2026-10-25): writes are resent
Writes are redriven like reads (same request id, attempt budget, deadline), on session loss and new PG intervals; the dedup/horizon audit is adr 0177 am. 1 and 3 (OSD answers a resent write from its PG log / dup records; finite history). Code: `ObjectClient` `enable_mutation_retries`. Default attempts stays 1 on the native API; the C ABI resends until `rados_osd_op_timeout` (0177 am. 2).
