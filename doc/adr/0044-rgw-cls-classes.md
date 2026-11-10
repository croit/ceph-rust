# 0044 RGW object classes: static registry, stage 1 scope and byte-compat rules
Status: accepted, amended (am. 2)
Date: 2026-10-11
Context: rgw-gap.md R0 needs classes `version`, `refcount`, `queue`, `rgw_gc`, `user`, `rgw` (index core) in the OSD; classic OSDs must read what we write and vice versa (mixed acting sets, adr/0013). adr/0010 fixed the static registry; this records the class list and the cross-cutting rules.
Decision:
- Classes live in `services/osd/cls` as plain generic functions over `ClsCtx`, registered in the static `class_table!` (no dlopen, no dyn). Registered now: lock, rbd, version, refcount, queue, rgw_gc, user, rgw (index core + reshard queue + obj_* helpers). Everything else stays unregistered (but the classes of adr 0060 and stage 2 below): unknown class -> -EPERM, unknown method -> -EOPNOTSUPP, counted per class (`cls::unsupported`, G26).
- Persisted bytes are the contract: same envelope versions/compat as classic, same field order, bug-compat quirks reproduced and marked "bug-compat" (wrapping stats, header ver bump rules, version.inc fresh = 2, packed-int 0x10000 truncation, refcount retired no-op, user stats arithmetic). Legacy pre-envelope decodes classic still accepts are implemented (`wire::legacy`).
- Two upstream bugs are NOT copied (queue multi-entry exact-fill overwrite; usage trim endless loop: advance through filtered pages until a match or range exhaustion, cls_rgw.md s10).
- Output-with-error is a first-class handler result (`Reply`), needed by bucket_list -EFBIG.
- RGW keys are bytes (`ObjKey{Vec<u8>}`): list markers contain 0xFF.
- Oracle: `ceph-dencoder` fixtures generated once from a container (`services/osd/cls/testdata/gen-dencoder.sh`), bytes checked in; tests never need the container. Own hand-derived vectors cover head/entry/header layouts. Differential goldens against a live classic OSD (rgw-gap T0) and the upstream gtests (T1) are the next gate, not part of this ADR.
- Stage order: stage 1 = non-versioned S3 path. Stage 2 (2026-10-11, amendment): G5 (olh/versioning), G6 (bi_*), G7 (lc, usage, legacy gc, bilog, mp_upload_part_info_update) on the same key helpers, plus classes `log`, `timeindex`, `fifo` (G10-G12); every method of cls_rgw_const.h except `set_bucket_resharding2` is registered (so the optional probes bucket_init_index2, bucket_refresh_instance, mp_upload_part_info_update answer like classic). Store G19 (omap key cap) and G21 (cold range scans) remain prerequisites for live s3-tests.
Consequences: + RGW non-versioned PUT/GET/LIST/DELETE/GC/ListBuckets are implementable end to end on croit-flashstore-osd metadata pools; + classes testable without a cluster (MemCtx). + (stage 2) versioned buckets, resharding index ops, lifecycle, usage log, legacy GC, mdlog/datalog/bilog (cls_log, fifo, in-index bilog) are implemented in the cls layer, unverified against classic until the T0/T1 gates; - cmpomap, sem_set, 2pc_queue, otp, numops still unregistered (multisite sync repo, persistent notifications, MFA); - per-message header cache missing (2 header decodes per index write).
Alternatives: opaque passthrough of stored entries (rejected: server re-encodes/decodes anyway); embedding a Lua/C++ class host (rejected: adr/0010).

## Amendment 2 (2026-10-25): registered set
Decision: besides the classes listed under Decision, the table registers `log`, `timeindex`, `fifo` (stage 2) and, since adr 0060, `hello`, `sdk`, `numops`, `cmpomap`, `sem_set`, `cas`, `2pc_queue`, `otp`, `cephfs`. `lua` stays unsupported. Unknown class -> -EPERM, unknown method -> -EOPNOTSUPP as before.

## Amendment 3 (2026-11-08): truthful usage-trim completion
Context: a filtered usage range can contain matching records beyond the former scan cutoff.
Decision: usage trim scans filtered pages with an advancing marker and returns ENODATA only after range exhaustion. Remove the 256-page cutoff that could leave matching records behind while signaling completion.
Rationale: a page budget cannot establish absence of matching records. Classic returns success while more records remain; advancing the scan also avoids its repeated-first-page loop.
Consequences: constant page memory; a sparsely matching range can require scanning the full range in one call. No on-disk or wire change.
Alternatives: false ENODATA (rejected); repeat classic's non-progressing first-page scan (rejected).
Open questions: none.
