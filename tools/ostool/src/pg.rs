// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PG level commands: list-pgs, info, log, export, remove, mark-complete, reset-last-complete, trim-pg-log(-dups).
use crate::fmt::{self, SectionWriter};
use crate::json::{log_json, missing_json};
use crate::{Ctx, EXIT_DEGRADED, R, fail, fail_code, pg_colls, walk};
use denc::types::{CollT, Eversion, Ghobject, Hobject, SpgT};
use osd::meta::{MapKind, MetaStore};
use peering::{PersistedPg, StoreOp, StoreTxn};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::fd::AsFd;
use store::dev::{BlockDev, Clock};

const OI_ATTR: &[u8] = b"_";

pub fn op_list_pgs<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    for s in pg_colls(c)? {
        writeln!(c.out, "{s}")?;
    }
    Ok(())
}

/// A PG not found in a degraded session: exit [`EXIT_DEGRADED`] naming the skipped shard when it lives there (never a
/// plain "not found"), else `Ok(())`.
pub(crate) fn not_on_skipped_shard<D: BlockDev, C: Clock>(
    c: &Ctx<'_, D, C>,
    spg: SpgT,
    p: &str,
) -> R {
    if !c.o.degraded() {
        return Ok(());
    }
    let shard = c.ad.with_store(|s| s.shard_of(&CollT::Pg(spg))) as u32;
    if c.o.excludes_shard(shard) {
        return fail_code(
            EXIT_DEGRADED,
            format!("shard {shard} skipped (degraded read-only mount); PG '{p}' is on that shard"),
        );
    }
    Ok(())
}

/// The one PG named by `--pgid` (an unqualified id resolves to the single existing shard).
pub(crate) fn pg_one<D: BlockDev, C: Clock>(c: &Ctx<'_, D, C>) -> R<SpgT> {
    let Some(p) = c.o.pgid.as_deref() else {
        return fail("Must provide pgid");
    };
    let want = crate::json::spg_of(p)?;
    let all = pg_colls(c)?;
    if all.contains(&want) {
        return Ok(want);
    }
    if want.shard.0 < 0 {
        let m: Vec<SpgT> = all.into_iter().filter(|s| s.pgid == want.pgid).collect();
        if m.len() == 1 {
            return Ok(m[0]);
        }
        if m.len() > 1 {
            return fail(format!(
                "PG '{p}' is ambiguous: give the shard (e.g. {}s0)",
                p
            ));
        }
    }
    not_on_skipped_shard(c, want, p)?;
    fail(format!("PG '{p}' not found"))
}

pub(crate) fn load_pg<D: BlockDev, C: Clock>(c: &Ctx<'_, D, C>, spg: SpgT) -> R<PersistedPg> {
    if c.ad.pending_removals()?.contains(&spg) {
        return fail(format!(
            "PG {spg} is being removed (deletion was interrupted); finish it with `--op remove --pgid {spg} --force`"
        ));
    }
    match storeadapt::meta::load(c.ad, spg)? {
        Some(p) => Ok(p),
        None => fail(format!(
            "read_info error: PG {spg} has no complete persisted state (incomplete import / removal in progress?)"
        )),
    }
}

pub fn op_info<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    let spg = pg_one(c)?;
    let p = load_pg(c, spg)?;
    let empty = p.info.is_empty();
    crate::json::emit(c.out, &c.o.format, &osd::info_json(&p.info, empty))
}

pub fn op_log<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    let spg = pg_one(c)?;
    let p = load_pg(c, spg)?;
    let v =
        serde_json::json!({"pg_log_t": log_json(&p.log), "pg_missing_t": missing_json(&p.missing)});
    crate::json::emit(c.out, &c.o.format, &v)
}

// ------------------------------------------------------------------ OSDMap blobs

/// Full map blob of `epoch`: stored verbatim, else rebuilt from the newest older full map + incrementals.
pub(crate) fn map_blob<D: BlockDev, C: Clock>(c: &Ctx<'_, D, C>, epoch: u32) -> R<Vec<u8>> {
    let get = |e: u32, k: MapKind| c.meta.get_map(e, k).map_err(|x| format!("{x}"));
    if let Some(b) = get(epoch, MapKind::Full)? {
        return Ok(b);
    }
    // the stored range bounds the search: an epoch outside it is refused instead of being searched down to 0
    let (oldest, newest) = crate::cmds::map_range(&crate::superblock(c)?)?;
    if epoch < oldest || epoch > newest {
        return fail(format!(
            "Can't find OSDMap for pg epoch {epoch}: the stored maps cover {oldest}..{newest}"
        ));
    }
    let mut base = None;
    for e in (oldest..=epoch).rev() {
        if let Some(b) = get(e, MapKind::Full)? {
            base = Some((e, b));
            break;
        }
    }
    let Some((be, bb)) = base else {
        return fail(format!("Can't find OSDMap for pg epoch {epoch}"));
    };
    let mut m = osdmap::OsdMap::decode_from(&bb).map_err(|x| format!("osdmap {be}: {x}"))?;
    for e in be + 1..=epoch {
        let Some(ib) = get(e, MapKind::Inc)? else {
            return fail(format!(
                "Can't find OSDMap for pg epoch {epoch}: incremental {e} missing"
            ));
        };
        let inc = osdmap::Incremental::decode_from(&ib).map_err(|x| format!("inc {e}: {x}"))?;
        m = m
            .apply_incremental_checked(&inc)
            .map_err(|x| format!("apply inc {e}: {x}"))?;
    }
    m.encode_full()
        .map_err(|x| format!("encode osdmap {epoch}: {x}").into())
}

// ------------------------------------------------------------------ export

fn export_object<D: BlockDev, C: Clock, W: Write>(
    c: &Ctx<'_, D, C>,
    w: &mut SectionWriter<W>,
    cid: CollT,
    g: &Ghobject,
    warn: &mut dyn Write,
    trace: &mut dyn Write,
) -> R {
    let force = c.o.force;
    let size = match c.ad.with_store(|s| s.stat(&cid, g))? {
        Some(s) => s.size,
        None => {
            return fail(format!(
                "{}: object vanished",
                crate::json::ghobject_json(g)
            ));
        }
    };
    let oi = c.ad.with_store(|s| s.getattr(&cid, g, OI_ATTR))?;
    if oi.is_none() {
        writeln!(
            warn,
            "getattr failure: No data available at obj:{}{}",
            crate::json::ghobject_json(g),
            if force { " IGNORED" } else { "" }
        )?;
        if !force {
            return fail("export failed (object without object_info; --force exports it anyway)");
        }
    }
    if c.o.debug {
        // per-object trace only with --debug: this buffer lives for the whole export
        writeln!(trace, "Read {}", crate::json::ghobject_json(g))?;
    }
    w.section(
        fmt::T_OBJECT_BEGIN,
        &fmt::enc_object_begin(g, oi.as_deref())?,
    )?;
    let mut off = 0u64;
    while off < size {
        let n = (size - off).min(fmt::MAX_READ);
        let d = match c.ad.with_store(|s| s.read(&cid, g, off, n)) {
            Ok(d) if !d.is_empty() => d,
            r => {
                let why = r
                    .map(|_| "empty read".to_string())
                    .unwrap_or_else(|e| e.to_string());
                writeln!(
                    warn,
                    "read failure: {why} at obj:{} 0x{off:x}~0x{n:x}",
                    crate::json::ghobject_json(g)
                )?;
                if !force {
                    return fail(
                        "export failed (read error; --force replaces unreadable blocks with zeroes)",
                    );
                }
                vec![0u8; n as usize]
            }
        };
        w.data(off, &d)?;
        off += d.len() as u64;
    }
    let attrs: BTreeMap<Vec<u8>, Vec<u8>> = c.ad.with_store(|s| s.getattrs(&cid, g))?;
    w.section(fmt::T_ATTRS, &fmt::enc_map(&attrs)?)?;
    let hdr = c.ad.with_store(|s| s.omap_header(&cid, g))?;
    w.section(fmt::T_OMAP_HDR, &fmt::enc_omap_hdr(&hdr)?)?;
    let mut from: Vec<u8> = Vec::new();
    loop {
        let (kv, more) =
            c.ad.with_store(|s| s.omap_iter(&cid, g, &from, fmt::OMAP_BATCH))?;
        if let Some((k, _)) = kv.last() {
            from = k.clone();
            from.push(0);
        }
        if !kv.is_empty() {
            let m: BTreeMap<Vec<u8>, Vec<u8>> = kv.into_iter().collect();
            w.section(fmt::T_OMAP, &fmt::enc_map(&m)?)?;
        }
        if !more {
            break;
        }
    }
    w.simple(fmt::T_OBJECT_END)?;
    Ok(())
}

pub fn op_export<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>, remove: bool) -> R {
    let spg = pg_one(c)?;
    let sb = crate::superblock(c)?;
    let p = load_pg(c, spg)?;
    let map_epoch = if p.epoch == 0 {
        // no recorded epoch (never processed a map): the export still needs a consistent map
        writeln!(
            c.err,
            "peek_map_epoch: PG has no recorded epoch, using the OSD epoch {}",
            sb.current_epoch
        )?;
        sb.current_epoch
    } else {
        p.epoch
    };
    let map = map_blob(c, map_epoch)?;
    // Keep the actual output descriptor through sync; no pathname reopen for stdout.
    let stdout_file = if remove && !c.o.dry_run && c.o.file.as_deref().is_none_or(|f| f == "-") {
        let file = std::fs::File::from(std::io::stdout().as_fd().try_clone_to_owned()?);
        if !file.metadata()?.is_file() {
            return crate::fail_code(
                2,
                "export-remove requires durable regular-file output; use --file PATH (stdout is a pipe or tty)",
            );
        }
        Some(file)
    } else {
        None
    };
    let mut named_file = None;
    let sink: Box<dyn Write> = if c.o.dry_run {
        Box::new(std::io::sink())
    } else {
        match c.o.file.as_deref() {
            None | Some("-") => {
                if let Some(file) = &stdout_file {
                    Box::new(std::io::BufWriter::with_capacity(
                        1 << 20,
                        file.try_clone()?,
                    )) as Box<dyn Write>
                } else {
                    if c.o.tty {
                        return fail("stdout is a tty and no --file filename specified");
                    }
                    Box::new(std::io::BufWriter::with_capacity(
                        1 << 20,
                        std::io::stdout(),
                    ))
                }
            }
            Some(f) => {
                // export-remove deletes the PG after the export: its target must be a new regular file
                let file = crate::create_output(f, !remove)?;
                named_file = Some(file.try_clone()?);
                Box::new(std::io::BufWriter::with_capacity(1 << 20, file))
            }
        }
    };
    let mut w = SectionWriter::new(sink);
    let mut sb_out = sb.clone();
    if spg.shard.0 < 0 {
        // replicated: the importing OSD need not support the SHARDS feature
        sb_out.compat_features.incompat.mask &= !(1u64 << 11);
        sb_out.compat_features.incompat.names.remove(&11);
    }
    writeln!(c.err, "Exporting {spg} info {}", p.info.last_update)?;
    w.write_super()?;
    w.section(
        fmt::T_PG_BEGIN,
        &fmt::enc_pg_begin(&fmt::PgBegin {
            pgid: spg,
            sb: sb_out,
        })?,
    )?;
    w.section(
        fmt::T_PG_METADATA,
        &fmt::enc_metadata(&fmt::Metadata {
            struct_ver: fmt::PG_STRUCT_V,
            map_epoch,
            info: p.info.clone(),
            log: p.log.clone(),
            past_intervals: p.past_intervals.clone(),
            osdmap_raw: map,
            divergent_priors: 0,
            missing: p.missing.clone(),
        })?,
    )?;
    let cid = CollT::Pg(spg);
    // warnings (what --force papered over) always reach stderr; the per-object trace only with --debug
    let mut warn: Vec<u8> = Vec::new();
    let mut trace: Vec<u8> = Vec::new();
    let mut n = 0u64;
    let r = walk(c.ad, cid, |g| {
        if !crate::objs::user_object(&g) {
            return Ok(true);
        }
        n += 1;
        export_object(c, &mut w, cid, &g, &mut warn, &mut trace)?;
        Ok(true)
    });
    c.err.write_all(&warn)?;
    if c.o.debug {
        c.err.write_all(&trace)?;
    }
    r?;
    w.simple(fmt::T_PG_END)?;
    drop(w.finish()?);
    if let Some(file) = stdout_file {
        sync_stdout(&file).map_err(|e| format!("stdout: sync: {e}"))?;
    } else if let Some(file) = named_file
        && let Some(f) = c.o.file.as_deref()
    {
        // durable before "successful" (and before export-remove deletes the PG: the file may be the only copy)
        sync_file(std::path::Path::new(f), &file).map_err(|e| format!("file: {f}: fsync: {e}"))?;
    }
    writeln!(c.err, "Export successful ({n} objects)")?;
    if remove {
        remove_pg(c, spg)?;
    }
    Ok(())
}

/// Redirected regular-file stdout (`export-remove > F`, as classic allows): the file and its directory entry must be
/// durable before the PG is deleted. The shell created the name and the tool does not know its path, so after the
/// file itself the whole filesystem holding it is synced (`syncfs(2)` commits the directory entry with it).
fn sync_stdout(file: &std::fs::File) -> std::io::Result<()> {
    file.sync_all()?;
    sync_filesystem(file)
}

#[cfg(target_os = "linux")]
fn sync_filesystem(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: `file` is an open descriptor for the whole call; syncfs only reads it.
    if unsafe { libc::syncfs(file.as_raw_fd()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// No `syncfs(2)` outside Linux (dev builds): the directory entry cannot be made durable, fail before removal.
#[cfg(not(target_os = "linux"))]
fn sync_filesystem(_: &std::fs::File) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no syncfs(2) on this platform; use --file PATH",
    ))
}

/// fsync a regular file and its directory entry (pipes, ttys, devices: nothing to do).
fn sync_file(p: &std::path::Path, file: &std::fs::File) -> std::io::Result<()> {
    if !file.metadata()?.is_file() {
        return Ok(());
    }
    file.sync_all()?;
    let dir = match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => std::path::Path::new("."),
    };
    std::fs::File::open(dir)?.sync_all()
}

// ------------------------------------------------------------------ remove

fn remove_pg<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>, spg: SpgT) -> R {
    writeln!(c.out, " marking collection for removal")?;
    if c.o.dry_run {
        return Ok(());
    }
    c.ad.remove_pg(spg)?;
    crate::checkpoint(c)?;
    writeln!(c.out, "Remove successful")?;
    Ok(())
}

pub fn op_remove<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    if !c.o.force && !c.o.dry_run {
        return fail("Please use export-remove or you must use --force option");
    }
    let spg = pg_one(c)?;
    remove_pg(c, spg)
}

// ------------------------------------------------------------------ info edits

fn submit<D: BlockDev, C: Clock>(c: &Ctx<'_, D, C>, spg: SpgT, ops: Vec<StoreOp>) -> R {
    if c.o.dry_run {
        return Ok(());
    }
    c.ad.try_submit(spg, &StoreTxn { ops })?;
    Ok(())
}

pub fn op_mark_complete<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    let spg = pg_one(c)?;
    let sb = crate::superblock(c)?;
    let mut p = load_pg(c, spg)?;
    writeln!(c.out, "Marking complete ")?;
    let cur = sb.current_epoch;
    let version = p
        .info
        .last_update
        .version
        .checked_add(1)
        .ok_or("PG last_update version overflow")?;
    p.info.last_update = Eversion::new(cur, version);
    if p.missing.missing.is_empty() {
        // croit-flashstore-osd keeps the missing set on disk: an empty set means nothing is missing
        p.info.last_complete = p.info.last_update;
    }
    p.info.last_backfill = Hobject::MAX();
    p.info.last_epoch_started = cur;
    p.info.history.last_epoch_started = cur;
    p.info.history.last_epoch_clean = cur;
    let lu = p.info.last_update;
    submit(
        c,
        spg,
        vec![
            StoreOp::PutInfo(Box::new(p.info)),
            StoreOp::PutPastIntervals(Box::default()),
            StoreOp::PutEpoch(p.epoch),
            StoreOp::LogSetHead(lu),
        ],
    )?;
    crate::checkpoint(c)?;
    writeln!(c.out, "Marking complete succeeded")?;
    Ok(())
}

pub fn op_reset_last_complete<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    if !c.o.force {
        return fail(
            "WARNING: reset-last-complete is extremely dangerous and almost certain to lead to permanent data loss \
             unless you know exactly what you are doing. Pass --force to proceed anyway.",
        );
    }
    let spg = pg_one(c)?;
    let mut p = load_pg(c, spg)?;
    writeln!(c.out, "Reseting last_complete ")?;
    p.info.last_complete = p.info.last_update;
    submit(c, spg, vec![StoreOp::PutInfo(Box::new(p.info))])?;
    crate::checkpoint(c)?;
    writeln!(c.out, "Reseting last_complete succeeded")?;
    Ok(())
}

// ------------------------------------------------------------------ log trimming

/// Log entries per `LogTrim` txn.
const TRIM_CHUNK: usize = 512;

pub fn op_trim_log<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    let spg = pg_one(c)?;
    let mut p = load_pg(c, spg)?;
    let max = c.o.max_entries.unwrap_or(10_000);
    writeln!(
        c.err,
        "Log bounds are: ({},{}]",
        p.info.log_tail, p.info.last_update
    )?;
    if p.info
        .last_update
        .version
        .saturating_sub(p.info.log_tail.version)
        <= max
    {
        writeln!(c.err, "Log not larger than osd_max_pg_log_entries {max}")?;
        writeln!(c.out, "Finished trimming pg log")?;
        return Ok(());
    }
    let trim_to = p.info.last_update.version - max;
    let mut new_tail = Eversion::default();
    let mut batch: Vec<Eversion> = Vec::new();
    for e in &p.log.log {
        if e.version.version > trim_to {
            break;
        }
        new_tail = e.version;
        batch.push(e.version);
    }
    // the trimmed entries become dups; every dup already recorded stays
    let dups_from = p
        .log
        .dups
        .front()
        .map(|d| d.version)
        .or_else(|| p.log.log.front().map(|e| e.version));
    for ch in batch.chunks(TRIM_CHUNK) {
        if let (Some(&first), Some(&last)) = (ch.first(), ch.last()) {
            writeln!(c.out, "Removing keys {first} - {last}")?;
            submit(
                c,
                spg,
                vec![StoreOp::LogTrim {
                    to: last,
                    dups_from,
                    tail_up: false,
                }],
            )?;
        }
    }
    if new_tail != Eversion::default() {
        p.info.log_tail = new_tail;
        submit(c, spg, vec![StoreOp::PutInfo(Box::new(p.info))])?;
    }
    crate::checkpoint(c)?;
    writeln!(c.out, "Finished trimming pg log")?;
    Ok(())
}

pub fn op_trim_dups<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    let spg = pg_one(c)?;
    let p = load_pg(c, spg)?;
    let keep = c.o.max_dups.unwrap_or(3000) as usize;
    writeln!(c.out, "max_dup_entries={keep}")?;
    if p.log.dups.len() > keep {
        let drop = p.log.dups.len() - keep;
        writeln!(c.out, "Removing {drop} dup entries")?;
        let kept = p.log.dups.iter().skip(drop).cloned().collect();
        submit(c, spg, vec![StoreOp::LogDups(kept)])?;
        crate::checkpoint(c)?;
    }
    writeln!(c.out, "Finished trimming pg log dups")?;
    Ok(())
}
