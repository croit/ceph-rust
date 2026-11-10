// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `--op import` (classic PG export file -> this store) and `--op dump-export`.
//!
//! Crash safety: the PG collection is created together with the `_remove` marker; `meta::load` / the mount-time
//! removal sweep treat it as garbage until the LAST txn (PG state + marker removal) is durable.
use crate::fmt::{self, SectionReader};
use crate::json::{ghobject_json, log_json, missing_json};
use crate::{Ctx, Fail, R, fail, fail_code};
use denc::types::{CollT, Ghobject, Hobject, SpgT};
use peering::snaps::MapOp;
use peering::{StoreOp, StoreTxn};
use pgwire::PgLog;
use std::io::{Read, Write};
use store::dev::{BlockDev, Clock};
use store::obj::txn::Bytes as TxnBytes;
use store::obj::{OTxn, TOp};
use storeadapt::pgmeta;

/// Commit the open batch when it holds this many payload bytes / ops.
const BATCH_BYTES: usize = 4 << 20;
const BATCH_OPS: usize = 512;
/// Log entries / missing items per PG-state txn (a WAL unit is 256 KiB).
const STATE_CHUNK: usize = 128;
/// Classic `osd_hit_set_namespace`: hit set objects are never filtered by placement.
const HITSET_NSPACE: &[u8] = b".ceph-internal";

/// Does `h` belong to PG `seed` at `pg_num = n` (classic import filter: object, log entry, missing item)?
fn belongs(h: &Hobject, seed: u32, n: u32) -> bool {
    !h.is_temp() && (h.nspace == HITSET_NSPACE || pgwire::pgmath::object_pg(h.hash, n) == seed)
}

/// End of a DATA section: `off` and `off + len` must lie inside one store object, so a corrupt offset cannot wrap
/// into a write or a truncate outside the store's object size limit.
fn data_end(off: u64, len: u64) -> R<u64> {
    match off.checked_add(len) {
        Some(end) if end <= store::MAX_OBJECT_BYTES => Ok(end),
        _ => fail(format!(
            "DATA section {off}+{len} is outside the object size limit {}",
            store::MAX_OBJECT_BYTES
        )),
    }
}

/// Next section of an object group: a future section type (`>= END_OF_TYPES`, spec 3) is skipped, like at the
/// top level.
fn object_section<R2: Read>(rd: &mut SectionReader<R2>, body: &mut Vec<u8>) -> R<u8> {
    loop {
        let t = rd.read_next(body)?;
        if t < fmt::END_OF_TYPES {
            return Ok(t);
        }
    }
}

fn open_input<'b>(o: &crate::Opts, input: Option<Box<dyn Read + 'b>>) -> R<Box<dyn Read + 'b>> {
    match o.file.as_deref() {
        None | Some("-") => {
            if o.stdin_tty {
                return fail("stdin is a tty and no --file filename specified");
            }
            input.ok_or_else(|| Fail::from("stdin already consumed"))
        }
        Some(f) => Ok(Box::new(std::io::BufReader::with_capacity(
            1 << 20,
            std::fs::File::open(f).map_err(|e| format!("file: {f}: {e}"))?,
        ))),
    }
}

/// Omap / attr / header bytes per txn: they travel in the WAL record (a unit is 256 KiB), data goes to extents.
const BATCH_META: usize = 96 << 10;
/// A write op above this many payload bytes is split in half when its txn is too large for one WAL unit.
const SPLIT_DATA: usize = 1 << 20;

struct Batch {
    t: OTxn<'static>,
    /// Data payload bytes / metadata (attrs, omap, header) bytes of the open txn.
    bytes: usize,
    meta: usize,
}

/// Commit `ops` as one txn; a txn too large for one WAL unit / tree budget is split (the PG is invisible until its last
/// txn, so partial application is harmless). A single op is split by omap pair / attr count / write chunk.
fn commit_split<D: BlockDev, C: Clock>(c: &Ctx<'_, D, C>, ops: Vec<TOp<'static>>) -> R {
    let mut t = OTxn::new();
    t.sys = true;
    t.ops = ops;
    let mut ops = match c.ad.with_store(|s| s.commit(&t)) {
        Err(store::obj::ObjError::TooLarge) => std::mem::take(&mut t.ops),
        r => return r.map_err(Fail::from),
    };
    if ops.len() > 1 {
        let tail = ops.split_off(ops.len() / 2);
        commit_split(c, ops)?;
        return commit_split(c, tail);
    }
    match ops.pop() {
        Some(TOp::OmapSetKeys {
            cid,
            oid,
            mut pairs,
        }) if pairs.len() > 1 => {
            let tail = pairs.split_off(pairs.len() / 2);
            commit_split(
                c,
                vec![TOp::OmapSetKeys {
                    cid,
                    oid: oid.clone(),
                    pairs,
                }],
            )?;
            commit_split(
                c,
                vec![TOp::OmapSetKeys {
                    cid,
                    oid,
                    pairs: tail,
                }],
            )
        }
        Some(TOp::SetAttrs {
            cid,
            oid,
            mut attrs,
        }) if attrs.len() > 1 => {
            let tail = attrs.split_off(attrs.len() / 2);
            commit_split(
                c,
                vec![TOp::SetAttrs {
                    cid,
                    oid: oid.clone(),
                    attrs,
                }],
            )?;
            commit_split(
                c,
                vec![TOp::SetAttrs {
                    cid,
                    oid,
                    attrs: tail,
                }],
            )
        }
        Some(TOp::Write {
            cid,
            oid,
            off,
            data,
        }) if data.len() > SPLIT_DATA => {
            // both halves stay block aligned
            let h = data.len() / 2 / store::BLK * store::BLK;
            commit_split(
                c,
                vec![TOp::Write {
                    cid,
                    oid: oid.clone(),
                    off,
                    data: TxnBytes::Owned(data[..h].to_vec()),
                }],
            )?;
            commit_split(
                c,
                vec![TOp::Write {
                    cid,
                    oid,
                    off: off + h as u64,
                    data: TxnBytes::Owned(data[h..].to_vec()),
                }],
            )
        }
        _ => fail(
            "a single attribute / omap value / object chunk is too large for one store transaction",
        ),
    }
}

impl Batch {
    fn new() -> Self {
        // staging only: `commit_split` sets the system class on the txn it commits
        Batch {
            t: OTxn::new(),
            bytes: 0,
            meta: 0,
        }
    }
    fn flush<D: BlockDev, C: Clock>(&mut self, c: &Ctx<'_, D, C>) -> R {
        if self.t.is_empty() {
            return Ok(());
        }
        let t = std::mem::take(&mut self.t);
        self.bytes = 0;
        self.meta = 0;
        if !c.o.dry_run {
            commit_split(c, t.ops)?;
        }
        Ok(())
    }
    fn full(&self) -> bool {
        self.bytes >= BATCH_BYTES || self.meta >= BATCH_META || self.t.ops.len() >= BATCH_OPS
    }
}

pub fn op_import<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    let sb = crate::superblock(c)?;
    let force = c.o.force;
    let dry = c.o.dry_run;
    let user_pg = match c.o.pgid.as_deref() {
        Some(p) => Some(crate::json::spg_of(p)?),
        None => None,
    };
    let ad = c.ad;
    let mut rd = SectionReader::open(open_input(c.o, c.input.take())?)?;
    let mut body = Vec::new();

    // ---- first section: PG_BEGIN
    let t = rd.read_next(&mut body)?;
    if t == fmt::T_POOL_BEGIN {
        return fail("Pool exports cannot be imported into a PG");
    }
    if t != fmt::T_PG_BEGIN {
        return fail(format!("Invalid first section type {t}"));
    }
    let pgb = fmt::dec_pg_begin(&body)?;
    let spg: SpgT = pgb.pgid;
    if let Some(u) = user_pg
        && u != spg
    {
        return fail(format!(
            "specified pgid {u} does not match actual pgid {spg}"
        ));
    }
    let zero = denc::types::Uuid::default();
    if pgb.sb.cluster_fsid != zero && pgb.sb.cluster_fsid != sb.cluster_fsid {
        writeln!(
            c.err,
            "Export came from different cluster with fsid {}",
            pgb.sb.cluster_fsid
        )?;
        if force {
            writeln!(c.err, "Ignoring this problem due to --force")?;
        } else {
            return fail("refusing the import (use --force to ignore the cluster fsid)");
        }
    }
    // ---- the importing OSD's current map: pool must exist
    let cur_blob = crate::pg::map_blob(c, sb.current_epoch)?;
    let curmap =
        osdmap::OsdMap::decode_from(&cur_blob).map_err(|e| format!("current osdmap: {e}"))?;
    let pool_id = spg.pgid.pool as i64;
    let Some(pool) = curmap.pool(pool_id) else {
        return fail_code(10, format!("Pool {} no longer exists", spg.pgid.pool));
    };
    if pool.is_erasure() != (spg.shard.0 >= 0) && !force {
        return fail(format!(
            "pg {spg} does not fit the type of pool {pool_id} ({}); --force to import anyway",
            if pool.is_erasure() {
                "erasure"
            } else {
                "replicated"
            }
        ));
    }
    let cid = CollT::Pg(spg);
    if ad.with_store(|s| s.coll_exists(&cid))? {
        return fail(format!("pgid {spg} already exists"));
    }

    // ---- metadata section
    let t = rd.read_next(&mut body)?;
    if t != fmt::T_PG_METADATA {
        return fail(format!(
            "Missing metadata section (first section is type {t})"
        ));
    }
    let mut ms = fmt::dec_metadata(&body)?;
    ms.info.pgid = spg;
    if ms.osdmap_raw.is_empty() {
        return fail("WARNING: No OSDMap in old export, this is an ancient export. Not supported.");
    }
    let expmap =
        osdmap::OsdMap::decode_from(&ms.osdmap_raw).map_err(|e| format!("export osdmap: {e}"))?;
    if expmap.epoch != ms.map_epoch {
        return fail("FATAL: Invalid OSDMap epoch in export data");
    }
    if ms.map_epoch > sb.current_epoch {
        return fail(format!(
            "ERROR: Export PG's map_epoch {} > OSD's epoch {}\nThe OSD you are using is older than the exported PG\n\
             Either use another OSD or join selected OSD to cluster to update it first",
            ms.map_epoch, sb.current_epoch
        ));
    }
    if ms.divergent_priors > 0 {
        return fail("export carries divergent_priors (pre-nautilus PG): not supported");
    }
    let oldest = sb
        .mapc
        .keys()
        .next()
        .copied()
        .unwrap_or(sb.cluster_osdmap_trim_lower_bound);
    if ms.map_epoch < oldest {
        writeln!(
            c.err,
            "PG export's map {} is older than OSD's oldest_map {oldest}",
            ms.map_epoch
        )?;
        if !force {
            return fail(" pass --force to proceed anyway (with incomplete PastIntervals)");
        }
    }
    // pg_num of the pool at the export (objects, log and missing are filtered against it, like classic; an export
    // map without the pool falls back to the importing pool's pg_num, the filter never switches off) and the
    // split/merge clash check against the PGs this OSD already holds (classic: exit 12, no --force bypass)
    let exp_n = expmap.pool(pool_id).map(|p| p.pg_num);
    let pg_num = exp_n.unwrap_or(pool.pg_num);
    if let Some(n) = exp_n {
        if spg.pgid.seed >= n && !force {
            return fail(format!(
                "pg {spg} is not in pool {pool_id} of the export's own map (pg_num {n}): corrupt export; --force to import anyway"
            ));
        }
        clash_check(c, spg, n, pool.pg_num)?;
    }
    writeln!(c.out, "Importing pgid {spg}")?;
    // ---- create the hidden collection
    let pm = pgmeta(spg);
    if !dry {
        let mut t = OTxn::new();
        t.sys = true;
        t.push(TOp::MkColl {
            cid,
            bits: pgwire::pgmath::split_bits(spg.pgid.seed, pg_num),
            exist_ok: false,
        });
        t.touch(cid, &pm);
        t.push(TOp::OmapSetKeys {
            cid,
            oid: pm.clone(),
            pairs: vec![(
                TxnBytes::Owned(replwire::pgmeta::REMOVE_KEY.as_bytes().to_vec()),
                TxnBytes::Owned(vec![1u8]),
            )],
        });
        ad.with_store(|s| s.commit(&t))?;
    }
    let r = import_objects(c, &mut rd, spg, &pm, pg_num);
    let r = r.and_then(|skipped| {
        filter_state(c, &mut ms, spg.pgid.seed, pg_num, skipped)?;
        finish_pg(c, spg, ms)
    });
    if let Err(e) = r {
        if !dry && let Err(cleanup) = c.ad.remove_pg(spg) {
            // the original error keeps the exit status; the marker stays durable and the next mount sweeps it
            writeln!(c.err, "PG {spg} stays marked for removal: {cleanup}")?;
        }
        return Err(e);
    }
    crate::checkpoint(c)?;
    writeln!(c.out, "Import successful")?;
    Ok(())
}

/// Objects of the stream up to PG_END; returns how many were skipped (placed in another PG).
fn import_objects<D: BlockDev, C: Clock, R2: Read>(
    c: &mut Ctx<'_, D, C>,
    rd: &mut SectionReader<R2>,
    spg: SpgT,
    pm: &Ghobject,
    pg_num: u32,
) -> R<u64> {
    let mut b = Batch::new();
    let mut skipped = 0u64;
    let mut body = Vec::new();
    loop {
        let t = rd.read_next(&mut body)?;
        if t >= fmt::END_OF_TYPES {
            writeln!(c.out, "Skipping unknown section type")?;
            continue;
        }
        match t {
            fmt::T_PG_END => {
                b.flush(c)?;
                return Ok(skipped);
            }
            fmt::T_OBJECT_BEGIN => {
                let ob = fmt::dec_object_begin(&body)?;
                skipped += u64::from(import_one(c, rd, &mut b, spg, ob.hoid, pm, pg_num)?);
            }
            fmt::T_PG_METADATA => return fail("metadata_section out of order"),
            other => return fail(format!("Unknown section type {other}")),
        }
    }
}

/// One object section group; returns whether it was skipped (the export map places it in another PG).
fn import_one<D: BlockDev, C: Clock, R2: Read>(
    c: &mut Ctx<'_, D, C>,
    rd: &mut SectionReader<R2>,
    b: &mut Batch,
    spg: SpgT,
    g: Ghobject,
    pm: &Ghobject,
    pg_num: u32,
) -> R<bool> {
    let cid = CollT::Pg(spg);
    if g.hobj.is_temp() {
        return fail(format!(
            "ERROR: Export contains temporary object '{}'",
            ghobject_json(&g)
        ));
    }
    if g.shard != spg.shard {
        return fail(format!(
            "INTERNAL ERROR: Importing shard {} but object shard is {}",
            spg.shard.0, g.shard.0
        ));
    }
    if g.hobj.pool != spg.pgid.pool as i64 {
        return fail(format!(
            "object {} does not belong to pool {}",
            ghobject_json(&g),
            spg.pgid.pool
        ));
    }
    if g == *pm {
        return fail("export contains the pgmeta object");
    }
    if !belongs(&g.hobj, spg.pgid.seed, pg_num) {
        // classic: an object the export map places in another PG is skipped (stats then invalid)
        writeln!(
            c.err,
            "Skipping object '{}' which belongs in pg {}.{:x}",
            ghobject_json(&g),
            spg.pgid.pool,
            pgwire::pgmath::object_pg(g.hobj.hash, pg_num)
        )?;
        let mut body = Vec::new();
        loop {
            match object_section(rd, &mut body)? {
                fmt::T_OBJECT_END => return Ok(true),
                fmt::T_DATA | fmt::T_ATTRS | fmt::T_OMAP_HDR | fmt::T_OMAP => {}
                other => return fail(format!("Unknown section type {other}")),
            }
        }
    }
    if c.o.debug {
        writeln!(c.out, "Write {}", ghobject_json(&g))?;
    }
    b.t.touch(cid, &g);
    let mut snapset: Option<replwire::SnapSet> = None;
    let mut size_hint = 0u64;
    let mut body = Vec::new();
    loop {
        let t = object_section(rd, &mut body)?;
        match t {
            fmt::T_DATA => {
                let (off, d) = fmt::dec_data(&body)?;
                // bounded before any offset arithmetic: the write offsets below are inside one object
                let end = data_end(off, d.len() as u64)?;
                size_hint = size_hint.max(end);
                for (i, ch) in d.chunks(BATCH_BYTES).enumerate() {
                    let chunk_off = off + (i * BATCH_BYTES) as u64;
                    if ch.iter().all(|&x| x == 0) {
                        // DATA can overlap previous sections. Clear earlier bytes while
                        // preserving holes, rather than treating zeroes as absent input.
                        b.t.zero(cid, &g, chunk_off, ch.len() as u64);
                    } else {
                        b.bytes += ch.len();
                        b.t.push(TOp::Write {
                            cid,
                            oid: g.clone(),
                            off: chunk_off,
                            data: TxnBytes::Owned(ch.to_vec()),
                        });
                    }
                    if b.full() {
                        b.flush(c)?;
                    }
                }
            }
            fmt::T_ATTRS => {
                let m = fmt::dec_map(&body)?;
                if g.hobj.snap == denc::types::SnapId::NOSNAP
                    && let Some(ss) = m.get(b"snapset".as_slice())
                {
                    // a snapset that does not decode leaves the clones without SnapMapper entries: fail
                    snapset = Some(
                        denc::from_slice::<replwire::SnapSet>(ss)
                            .map_err(|e| format!("snapset of {}: {e}", ghobject_json(&g)))?,
                    );
                }
                if !m.is_empty() {
                    b.meta += m.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>();
                    b.t.push(TOp::SetAttrs {
                        cid,
                        oid: g.clone(),
                        attrs: m
                            .into_iter()
                            .map(|(k, v)| (TxnBytes::Owned(k), TxnBytes::Owned(v)))
                            .collect(),
                    });
                }
            }
            fmt::T_OMAP_HDR => {
                let h = fmt::dec_omap_hdr(&body)?;
                if !h.is_empty() {
                    b.meta += h.len();
                    b.t.push(TOp::OmapSetHeader {
                        cid,
                        oid: g.clone(),
                        header: TxnBytes::Owned(h),
                    });
                }
            }
            fmt::T_OMAP => {
                let m = fmt::dec_map(&body)?;
                b.meta += m.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>();
                b.t.push(TOp::OmapSetKeys {
                    cid,
                    oid: g.clone(),
                    pairs: m
                        .into_iter()
                        .map(|(k, v)| (TxnBytes::Owned(k), TxnBytes::Owned(v)))
                        .collect(),
                });
            }
            fmt::T_OBJECT_END => break,
            other => return fail(format!("Unknown section type {other}")),
        }
        if b.full() {
            b.flush(c)?;
        }
    }
    // Object size: restore the greatest DATA end, including sparse tails.
    b.t.push(TOp::Truncate {
        cid,
        oid: g.clone(),
        size: size_hint,
    });
    // clones precede their head in the archive: register the head's clones in the SnapMapper
    if let Some(ss) = snapset
        && !ss.clone_snaps.is_empty()
        && !c.o.dry_run
    {
        b.flush(c)?;
        let mut ops = Vec::new();
        for (cl, snaps) in &ss.clone_snaps {
            let mut ch = g.hobj.clone();
            ch.snap = *cl;
            let exists =
                c.ad.with_store(|s| {
                    s.stat(
                        &cid,
                        &Ghobject::new(ch.clone(), Ghobject::NO_GEN, spg.shard),
                    )
                })?
                .is_some();
            if exists && !snaps.is_empty() {
                ops.push(MapOp::Set {
                    clone: ch,
                    snaps: snaps.iter().map(|s| s.0).collect(),
                });
            }
        }
        if !ops.is_empty() {
            c.ad.try_submit(
                spg,
                &StoreTxn {
                    ops: vec![StoreOp::SnapMap(ops)],
                },
            )?;
        }
    }
    Ok(false)
}

/// Classic `do_import` split/merge check on the net pg_num change export -> now: a split child or the merge target of
/// the PG that already exists here would collide with what the daemon derives from the imported PG (exit 12).
fn clash_check<D: BlockDev, C: Clock>(c: &Ctx<'_, D, C>, spg: SpgT, exp_n: u32, cur_n: u32) -> R {
    use pgwire::pgmath;
    let seed = spg.pgid.seed;
    let exists = |s: u32| {
        let o = SpgT {
            pgid: denc::types::PgT::new(spg.pgid.pool, s),
            shard: spg.shard,
        };
        c.ad.with_store(|st| st.coll_exists(&CollT::Pg(o)))
            .map(|e| e.then_some(o))
    };
    if cur_n > exp_n {
        for ch in pgmath::split_children(seed, exp_n, cur_n) {
            if let Some(o) = exists(ch)? {
                return fail_code(
                    12,
                    format!("pgid {spg} splits (pg_num {exp_n} -> {cur_n}) and {o} exists"),
                );
            }
        }
    } else if pgmath::is_merge_source(seed, exp_n, cur_n)
        && let Some(o) = exists(pgmath::merge_target(seed, cur_n))?
    {
        return fail_code(
            12,
            format!("pgid {spg} merges to target {o} which already exists"),
        );
    }
    Ok(())
}

/// Classic import: drop log entries and missing items of objects that the export map places elsewhere (or temp
/// objects); skipped objects make the stats invalid (like a split).
fn filter_state<D: BlockDev, C: Clock>(
    c: &mut Ctx<'_, D, C>,
    ms: &mut fmt::Metadata,
    seed: u32,
    pg_num: u32,
    skipped: u64,
) -> R {
    let before = ms.log.log.len();
    ms.log.log.retain(|e| belongs(&e.soid, seed, pg_num));
    let dropped = before - ms.log.log.len();
    ms.missing.missing.retain(|h, _| belongs(h, seed, pg_num));
    if dropped > 0 {
        writeln!(c.err, "Skipping {dropped} log entries of other PGs")?;
    }
    if skipped > 0 {
        ms.info.stats.stats_invalid = true;
    }
    Ok(())
}

/// Write the PG state and drop the removal marker in one atomic txn.
fn finish_pg<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>, spg: SpgT, ms: fmt::Metadata) -> R {
    if c.o.dry_run {
        return Ok(());
    }
    let ad = c.ad;
    let PgLog {
        head,
        tail,
        log,
        can_rollback_to,
        rollback_info_trimmed_to,
        dups,
    } = ms.log;
    let ec = spg.shard.0 >= 0;
    // log: header + dups, then entries in chunks, then the real head / rollback cursors
    let base = PgLog {
        head: tail,
        tail,
        log: Default::default(),
        can_rollback_to: tail,
        rollback_info_trimmed_to: tail,
        dups: Default::default(),
    };
    ad.try_submit(
        spg,
        &StoreTxn {
            ops: vec![StoreOp::LogReplace(Box::new(base))],
        },
    )?;
    // dup records (at most `osd_pg_log_dups_tracked`, one small record each): one txn
    if !dups.is_empty() {
        ad.try_submit(
            spg,
            &StoreTxn {
                ops: vec![StoreOp::LogDups(Vec::from(dups))],
            },
        )?;
    }
    let entries: Vec<pgwire::LogEntry> = log.into();
    for ch in entries.chunks(STATE_CHUNK) {
        let op = if ec {
            StoreOp::LogAppendKeep(ch.to_vec())
        } else {
            StoreOp::LogAppend(ch.to_vec())
        };
        ad.try_submit(spg, &StoreTxn { ops: vec![op] })?;
    }
    // The encoded head can be newer than the last retained entry (for example
    // after filtering or mark-complete). Restore it for EC as well, then restore
    // EC's independent rollback bounds in the same transaction.
    let mut ops = vec![StoreOp::LogSetHead(head)];
    if ec {
        ops.push(StoreOp::LogCursors {
            can_rollback_to,
            rollback_info_trimmed_to,
        });
    }
    ad.try_submit(spg, &StoreTxn { ops })?;
    // missing set
    ad.try_submit(
        spg,
        &StoreTxn {
            ops: vec![StoreOp::MissingClear {
                may_include_deletes: ms.missing.may_include_deletes,
            }],
        },
    )?;
    let items: Vec<(Hobject, Option<pgwire::MissingItem>)> = ms
        .missing
        .missing
        .iter()
        .map(|(h, it)| (h.clone(), Some(it.clone())))
        .collect();
    for ch in items.chunks(STATE_CHUNK) {
        ad.try_submit(
            spg,
            &StoreTxn {
                ops: vec![StoreOp::Missing(ch.to_vec())],
            },
        )?;
    }
    // final atomic txn: info, epoch, past intervals, infover, marker removal
    let ops = [
        StoreOp::PutEpoch(ms.map_epoch),
        StoreOp::PutPastIntervals(Box::new(ms.past_intervals)),
        StoreOp::PutInfo(Box::new(ms.info)),
    ];
    let mut t = OTxn::new();
    t.sys = true;
    ad.with_store(|s| {
        let mut tr = storeadapt::meta::Translator::new(s, spg, true);
        ops.iter().try_for_each(|op| tr.op(op, &mut t))
    })?;
    let (cid, pm) = (CollT::Pg(spg), pgmeta(spg));
    t.push(TOp::OmapSetKeys {
        cid,
        oid: pm.clone(),
        pairs: vec![(
            TxnBytes::Owned(replwire::pgmeta::INFOVER_KEY.as_bytes().to_vec()),
            TxnBytes::Owned(vec![replwire::pgmeta::INFOVER]),
        )],
    });
    t.push(TOp::OmapRmKeys {
        cid,
        oid: pm,
        keys: vec![TxnBytes::Owned(
            replwire::pgmeta::REMOVE_KEY.as_bytes().to_vec(),
        )],
    });
    ad.with_store(|s| s.commit(&t)).map_err(Fail::from)
}

// ------------------------------------------------------------------ dump-export

pub fn op_dump_export<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    dump_export(c.o, c.input.take(), c.out)
}

/// `--op dump-export`: needs no store.
pub fn dump_export<'b>(
    o: &crate::Opts,
    input: Option<Box<dyn Read + 'b>>,
    out_w: &mut dyn Write,
) -> R {
    let mut rd = SectionReader::open(open_input(o, input)?)?;
    let mut body = Vec::new();
    let t = rd.read_next(&mut body)?;
    if t == fmt::T_POOL_BEGIN {
        return fail("Dump of pool exports not supported");
    }
    if t != fmt::T_PG_BEGIN {
        return fail(format!("Invalid first section type {t}"));
    }
    let pgb = fmt::dec_pg_begin(&body)?;
    let mut out = serde_json::Map::new();
    out.insert("pgid".into(), pgb.pgid.to_string().into());
    out.insert(
        "cluster_fsid".into(),
        pgb.sb.cluster_fsid.to_string().into(),
    );
    let mut objects: Vec<serde_json::Value> = Vec::new();
    let mut found_meta = false;
    loop {
        let t = rd.read_next(&mut body)?;
        match t {
            fmt::T_OBJECT_BEGIN => {
                let ob = fmt::dec_object_begin(&body)?;
                let (mut size, mut attrs, mut omap_keys) = (0u64, Vec::<String>::new(), 0u64);
                let mut hdr = 0usize;
                loop {
                    let t = object_section(&mut rd, &mut body)?;
                    match t {
                        fmt::T_DATA => {
                            let (off, d) = fmt::dec_data(&body)?;
                            size = size.max(data_end(off, d.len() as u64)?);
                        }
                        fmt::T_ATTRS => {
                            attrs = fmt::dec_map(&body)?
                                .keys()
                                .map(|k| String::from_utf8_lossy(k).into_owned())
                                .collect();
                        }
                        fmt::T_OMAP_HDR => hdr = fmt::dec_omap_hdr(&body)?.len(),
                        fmt::T_OMAP => omap_keys += fmt::dec_map(&body)?.len() as u64,
                        fmt::T_OBJECT_END => break,
                        o => return fail(format!("Unknown section type {o}")),
                    }
                }
                objects.push(serde_json::json!({
                    "oid": crate::json::ghobject_value(&ob.hoid),
                    "size": size, "attrs": attrs, "omap_header_bytes": hdr, "omap_keys": omap_keys,
                }));
            }
            fmt::T_PG_METADATA => {
                let ms = fmt::dec_metadata(&body)?;
                found_meta = true;
                out.insert("pg_disk_version".into(), ms.struct_ver.into());
                out.insert("map_epoch".into(), ms.map_epoch.into());
                out.insert("info".into(), osd::info_json(&ms.info, ms.info.is_empty()));
                out.insert("log".into(), log_json(&ms.log));
                out.insert("pg_missing_t".into(), missing_json(&ms.missing));
            }
            fmt::T_PG_END => break,
            o if o >= fmt::END_OF_TYPES => continue,
            o => return fail(format!("Unknown section type {o}")),
        }
    }
    if !found_meta {
        return fail("Missing metadata section");
    }
    out.insert("objects".into(), objects.into());
    let v = serde_json::Value::Object(out);
    crate::json::emit(out_w, &o.format, &v)
}
