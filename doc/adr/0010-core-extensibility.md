# 0010 Core design must accommodate RGW, CephFS, EC (much later)
Status: accepted
Date: 2026-10-09
Context: v0 = replicated RBD data only (0009). RGW + CephFS + EC needed much later; retrofitting core = rewrite. KISS still applies: design seams now, implement later.
Must hold in core from day 1:
- Object model = Ceph's: hobject/ghobject (pool, ns, key, name, hash, snap, gen, shard), bytes + xattrs + omap header + omap (ordered KV). Sort order = Ceph's (needed for pgnls/backfill scan).
- Storage engine: omap = first-class ordered KV per object, range scans, millions of keys per object (RGW bucket index), efficient bulk rm/clear. Not bolted on.
- Multi-op MOSDOp = one atomic transaction (read+write mixes, cmpxattr/assert guards, cls calls inside).
- cls execution: native Rust method registry (class.method -> fn(ctx, in) -> out), ctx exposes object read/write/xattr/omap within op txn. v0 registers cls_rbd subset only. No C++ .so loading.
- Watch/notify, object listing (pgnls), backoff: in op pipeline design even if v0 partial.
- PG backend seam: replicated vs EC behind one interface (op -> per-shard transactions, read path, recovery). EC later needs BOTH roles (primary: encode/fanout/reconstruct; shard: sub-op apply/read) incl. mixed acting sets. Only replicated implemented first.
- Recovery/backfill on object granularity incl. omap+xattrs.
Non-goals still: HDD, cache tiering, FileStore/BlueStore anything.
