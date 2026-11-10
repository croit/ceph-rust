// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Object level commands: `--op list`, `meta-list`, `fix-lost`, and `<object> <cmd>`.
use crate::json::{ghobject_json, ghobject_value, parse_ghobject};
use crate::{Ctx, Opts, R, fail, pg_colls, walk};
use denc::types::{CollT, Ghobject, SnapId, SpgT};
use peering::{StoreOp, StoreTxn};
use std::io::Write;
use store::dev::{BlockDev, Clock};
use store::obj::txn::Bytes as TxnBytes;
use store::obj::{OTxn, TOp};
use storeadapt::StoreAdapter;

pub(crate) const OI_ATTR: &[u8] = b"_";
pub(crate) const SS_ATTR: &[u8] = b"snapset";

pub(crate) fn has_snapset(g: &Ghobject) -> bool {
    g.hobj.snap == SnapId::NOSNAP || g.hobj.snap == SnapId::SNAPDIR
}

/// Not user visible: the per-PG SnapMapper index object.
pub(crate) fn is_mapper(g: &Ghobject) -> bool {
    g.is_pgmeta() && g.hobj.snap == SnapId::SNAPDIR
}

/// `--format json-pretty`: one JSON array per object line; `json`: one array for the whole listing.
pub(crate) fn human(o: &Opts) -> bool {
    o.format == "json-pretty" || o.format == "plain"
}

pub(crate) fn collect<D: BlockDev, C: Clock>(
    c: &Ctx<'_, D, C>,
    colls: &[CollT],
    name: &str,
    ns: Option<&str>,
    head: bool,
) -> R<Vec<(CollT, Ghobject)>> {
    let mut out = Vec::new();
    for cid in colls {
        walk(c.ad, *cid, |g| {
            if is_mapper(&g) || (head && !has_snapset(&g)) {
                return Ok(true);
            }
            if (name.is_empty() || g.hobj.oid == name.as_bytes())
                && ns.is_none_or(|n| g.hobj.nspace == n.as_bytes())
            {
                out.push((*cid, g));
            }
            Ok(true)
        })?;
    }
    Ok(out)
}

/// The PG collections named by `--pgid` (an unqualified pgid also matches every shard), or all of them.
pub(crate) fn pg_selection<D: BlockDev, C: Clock>(c: &Ctx<'_, D, C>) -> R<Vec<CollT>> {
    let all = pg_colls(c)?;
    match c.o.pgid.as_deref() {
        None => Ok(all.into_iter().map(CollT::Pg).collect()),
        Some("meta") => Ok(vec![CollT::Meta]),
        Some(p) => {
            let want = crate::json::spg_of(p)?;
            let v: Vec<CollT> = all
                .into_iter()
                .filter(|s| *s == want || (want.shard.0 < 0 && s.pgid == want.pgid))
                .map(CollT::Pg)
                .collect();
            if v.is_empty() {
                crate::pg::not_on_skipped_shard(c, want, p)?;
                return fail(format!("PG '{p}' not found"));
            }
            Ok(v)
        }
    }
}

/// Listing output buffer: one write per 64 KiB instead of one per line, and the budget a listing may hold.
const LIST_BUF: usize = 64 << 10;

/// The selected objects, written as the walk yields them (one line each, or one JSON array): a listing of a PG
/// with millions of objects never materializes.
fn print_matches<D: BlockDev, C: Clock>(
    ad: &StoreAdapter<D, C>,
    human: bool,
    out: &mut dyn Write,
    colls: &[CollT],
    name: &str,
    ns: Option<&str>,
    head: bool,
) -> R {
    let mut w = std::io::BufWriter::with_capacity(LIST_BUF, out);
    let r = print_lines(&mut w, ad, human, colls, name, ns, head);
    // a flush error is on the same stream as the walk error: report it, then the walk's own error
    w.flush()?;
    r
}

fn print_lines<D: BlockDev, C: Clock>(
    out: &mut dyn Write,
    ad: &StoreAdapter<D, C>,
    human: bool,
    colls: &[CollT],
    name: &str,
    ns: Option<&str>,
    head: bool,
) -> R {
    let mut n = 0usize;
    if !human {
        out.write_all(b"[")?;
    }
    for cid in colls {
        walk(ad, *cid, |g| {
            if is_mapper(&g) || (head && !has_snapset(&g)) {
                return Ok(true);
            }
            if !(name.is_empty() || g.hobj.oid == name.as_bytes())
                || !ns.is_none_or(|n| g.hobj.nspace == n.as_bytes())
            {
                return Ok(true);
            }
            let pg = match cid {
                CollT::Pg(s) => Some(s.to_string()),
                _ => None,
            };
            let lead = match (&pg, human) {
                (Some(p), true) => format!("\"{p}\""),
                (Some(p), false) => format!("\"{p}\",\"{cid}\""),
                (None, _) => format!("\"{cid}\""),
            };
            if human {
                writeln!(out, "[{lead},{}]", ghobject_json(&g))?;
            } else {
                if n > 0 {
                    out.write_all(b",")?;
                }
                write!(out, "[{lead},{}]", ghobject_json(&g))?;
            }
            n += 1;
            Ok(true)
        })?;
    }
    if !human {
        out.write_all(b"]\n")?;
    }
    Ok(())
}

pub fn op_list<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    let colls = pg_selection(c)?;
    print_matches(
        c.ad,
        human(c.o),
        &mut *c.out,
        &colls,
        c.o.object.as_deref().unwrap_or(""),
        c.o.namespace.as_deref(),
        c.o.head,
    )
}

pub fn op_meta_list<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    print_matches(
        c.ad,
        human(c.o),
        &mut *c.out,
        &[CollT::Meta],
        c.o.object.as_deref().unwrap_or(""),
        None,
        false,
    )
}

// ------------------------------------------------------------------ object resolution

/// `(collection, object)` of the object argument: pgmeta (`''` + --pgid), `[pgid, {ghobject}]`, `{ghobject}` +
/// --pgid, or a plain name looked up in the selected PGs (must be unique).
fn resolve<D: BlockDev, C: Clock>(c: &Ctx<'_, D, C>) -> R<(CollT, Ghobject)> {
    let obj = c.o.object.clone().unwrap_or_default();
    let pgid_opt = c.o.pgid.clone();
    if obj.is_empty() {
        let Some(p) = pgid_opt else {
            return fail("The pgmeta object ('') needs --pgid");
        };
        let s = crate::json::spg_of(&p)?;
        return Ok((
            CollT::Pg(s),
            Ghobject::pgmeta(s.pgid.pool as i64, s.pgid.seed, s.shard),
        ));
    }
    if let Ok(v @ (serde_json::Value::Array(_) | serde_json::Value::Object(_))) =
        serde_json::from_str::<serde_json::Value>(&obj)
    {
        let (cid, gv) = match &v {
            serde_json::Value::Array(a) => {
                if !(2..=3).contains(&a.len()) || !a[0].is_string() {
                    return fail(format!(
                        "Object '{obj}' must be a JSON array with 2 or 3 elements, the first a string"
                    ));
                }
                let p = a[0].as_str().unwrap_or_default();
                let cid = if p == "meta" {
                    CollT::Meta
                } else {
                    let s = crate::json::spg_of(p)?;
                    if let Some(q) = &pgid_opt
                        && crate::json::spg_of(q)? != s
                    {
                        return fail(format!(
                            "object '{obj}' has a pgid different from the --pgid={q} option"
                        ));
                    }
                    CollT::Pg(s)
                };
                if a.len() == 3 && a[1].as_str() != Some(cid.to_string().as_str()) {
                    return fail("Object collection and pgid do not match");
                }
                (cid, a[a.len() - 1].clone())
            }
            _ => {
                let Some(p) = &pgid_opt else {
                    return fail(format!(
                        "Without --pgid the object '{obj}' must be a JSON array"
                    ));
                };
                let cid = if p == "meta" {
                    CollT::Meta
                } else {
                    CollT::Pg(crate::json::spg_of(p)?)
                };
                (cid, v.clone())
            }
        };
        let g = parse_ghobject(&gv).map_err(|e| format!("Decode object JSON error: {e}"))?;
        if let CollT::Pg(s) = cid {
            if s.pgid.pool as i64 != g.hobj.pool {
                return fail("Object pool and pgid pool don't match");
            }
            if !c.ad.with_store(|st| st.coll_exists(&cid))? {
                return fail(format!("PG '{s}' not found"));
            }
        }
        return Ok((cid, g));
    }
    // plain name: look it up (head/snapdir only when --head is given, like classic remove-clone-metadata)
    let colls = pg_selection(c)?;
    let head = c.o.head || c.o.objcmd.as_deref() == Some("remove-clone-metadata");
    let mut found = collect(c, &colls, &obj, c.o.namespace.as_deref(), head)?;
    found.retain(|(_, g)| !g.is_pgmeta());
    match found.len() {
        0 => fail(format!(
            "No object id '{obj}' found or invalid JSON specified"
        )),
        1 => Ok(found.remove(0)),
        n => fail(format!(
            "Found {n} objects with id '{obj}', please use a JSON spec from --op list instead"
        )),
    }
}

// ------------------------------------------------------------------ helpers

fn read_all<D: BlockDev, C: Clock>(
    ad: &StoreAdapter<D, C>,
    cid: CollT,
    g: &Ghobject,
    mut sink: impl FnMut(&[u8]) -> R,
) -> R {
    let size = match ad.with_store(|s| s.stat(&cid, g))? {
        Some(s) => s.size,
        None => return fail(format!("{}: No such file or directory", ghobject_json(g))),
    };
    let mut off = 0;
    while off < size {
        let n = (size - off).min(crate::fmt::MAX_READ);
        let d = ad.with_store(|s| s.read(&cid, g, off, n))?;
        if d.is_empty() {
            return fail(format!("read returned no data at offset {off}"));
        }
        sink(&d)?;
        off += d.len() as u64;
    }
    Ok(())
}

fn input<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>, arg: Option<&str>) -> R<Vec<u8>> {
    match arg {
        None | Some("-") => {
            if c.o.stdin_tty {
                return fail("stdin is a tty and no file specified");
            }
            match c.input.as_mut() {
                Some(i) => crate::read_capped(i, crate::MAX_INPUT, "stdin"),
                None => Ok(Vec::new()),
            }
        }
        Some(p) => crate::read_capped_file(p, crate::MAX_INPUT),
    }
}

pub(crate) fn commit<D: BlockDev, C: Clock>(c: &Ctx<'_, D, C>, mut t: OTxn<'_>) -> R {
    if c.o.dry_run || t.is_empty() {
        return Ok(());
    }
    // operator repairs must work on a full device too (same class as PG state txns)
    t.sys = true;
    c.ad.with_store(|s| s.commit(&t))?;
    Ok(())
}

/// Values printed raw; on a terminal non-printable bytes are escaped (`cleanbin`).
fn emit<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>, v: &[u8]) -> R {
    if c.o.tty {
        let mut s = String::new();
        for &b in v {
            if (0x20..0x7f).contains(&b) {
                s.push(b as char);
            } else {
                s += &format!("\\x{b:02x}");
            }
        }
        s.push('\n');
        c.out.write_all(s.as_bytes())?;
    } else {
        c.out.write_all(v)?;
    }
    Ok(())
}

fn need_key<'a>(c: &'a Ctx<'_, impl BlockDev, impl Clock>, cmd: &str) -> R<&'a str> {
    match c.o.arg1.as_deref() {
        Some(k) => Ok(k),
        None => fail(format!("{cmd} needs a key argument")),
    }
}

// ------------------------------------------------------------------ object commands

pub fn object_cmd<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    let cmd = c.o.objcmd.clone().unwrap_or_default();
    let (cid, g) = resolve(c)?;
    match cmd.as_str() {
        "list-attrs" => {
            let a =
                c.ad.with_store(|s| s.getattrs(&cid, &g))
                    .map_err(|e| format!("getattrs: {e}"))?;
            for k in a.keys() {
                emit_line(c, k)?;
            }
        }
        "list-omap" => {
            let m =
                c.ad.with_store(|s| s.omap_all(&cid, &g))
                    .map_err(|e| format!("omap_get_iterator: {e}"))?;
            for k in m.keys() {
                emit_line(c, k)?;
            }
        }
        "get-bytes" => {
            let dest = c.o.arg1.clone();
            match dest.as_deref() {
                None | Some("-") => {
                    // each chunk goes out as it is read: an object bigger than RAM must still be dumpable
                    let out = &mut *c.out;
                    read_all(c.ad, cid, &g, |d| Ok(out.write_all(d)?))?;
                }
                Some(p) => {
                    let mut f = crate::create_output(p, true)?;
                    read_all(c.ad, cid, &g, |d| f.write_all(d).map_err(Into::into))?;
                }
            }
        }
        "set-bytes" => {
            let data = input(c, c.o.arg1.clone().as_deref())?;
            if c.o.dry_run {
                return Ok(());
            }
            let mut t = OTxn::new();
            t.touch(cid, &g);
            t.truncate(cid, &g, 0);
            // Truncation and replacement share one atomic store transaction: an
            // interruption or a rejected transaction must preserve the old object.
            t.write(cid, &g, 0, &data);
            commit(c, t)?;
        }
        "get-attr" => {
            let k = need_key(c, &cmd)?.to_owned();
            match c.ad.with_store(|s| s.getattr(&cid, &g, k.as_bytes()))? {
                Some(v) => emit(c, &v)?,
                None => return fail("getattr: No data available"),
            }
        }
        "set-attr" => {
            let k = need_key(c, &cmd)?.to_owned();
            let v = input(c, c.o.arg2.clone().as_deref())?;
            let mut t = OTxn::new();
            t.touch(cid, &g);
            t.setattr(cid, &g, k.as_bytes(), &v);
            commit(c, t)?;
        }
        "rm-attr" => {
            let k = need_key(c, &cmd)?.to_owned();
            let mut t = OTxn::new();
            t.push(TOp::RmAttr {
                cid,
                oid: g.clone(),
                name: TxnBytes::Owned(k.into_bytes()),
            });
            commit(c, t)?;
        }
        "get-omap" => {
            let k = need_key(c, &cmd)?.to_owned();
            let mut m = c.ad.with_store(|s| s.omap_get(&cid, &g, &[k.as_bytes()]))?;
            match m.remove(k.as_bytes()) {
                Some(v) => emit(c, &v)?,
                None => return fail("Key not found"),
            }
        }
        "set-omap" => {
            let k = need_key(c, &cmd)?.to_owned();
            let v = input(c, c.o.arg2.clone().as_deref())?;
            let mut t = OTxn::new();
            t.touch(cid, &g);
            t.omap_set(cid, &g, k.as_bytes(), &v);
            commit(c, t)?;
        }
        "rm-omap" => {
            let k = need_key(c, &cmd)?.to_owned();
            let mut t = OTxn::new();
            t.push(TOp::OmapRmKeys {
                cid,
                oid: g.clone(),
                keys: vec![TxnBytes::Owned(k.into_bytes())],
            });
            commit(c, t)?;
        }
        "get-omaphdr" => {
            let h =
                c.ad.with_store(|s| s.omap_header(&cid, &g))
                    .map_err(|e| format!("omap_get_header: {e}"))?;
            emit(c, &h)?;
        }
        "set-omaphdr" => {
            let h = input(c, c.o.arg1.clone().as_deref())?;
            let mut t = OTxn::new();
            t.touch(cid, &g);
            t.push(TOp::OmapSetHeader {
                cid,
                oid: g.clone(),
                header: TxnBytes::Owned(h),
            });
            commit(c, t)?;
        }
        "remove" | "removeall" => return remove_object(c, cid, &g, cmd == "removeall"),
        "dump" => return dump_object(c, cid, &g),
        "set-size" | "corrupt-size" => {
            return crate::repair::set_size(c, cid, &g, cmd == "corrupt-size");
        }
        "clear-data-digest" => return crate::repair::clear_data_digest(c, cid, &g),
        "clear-snapset" => return crate::repair::clear_snapset(c, cid, &g),
        "remove-clone-metadata" => return crate::repair::remove_clone_metadata(c, cid, &g),
        other => {
            return fail(format!(
                "Unknown object command '{other}'\n{}",
                crate::USAGE
            ));
        }
    }
    if matches!(
        cmd.as_str(),
        "set-bytes" | "set-attr" | "rm-attr" | "set-omap" | "rm-omap" | "set-omaphdr"
    ) {
        crate::checkpoint(c)?;
    }
    Ok(())
}

/// One name per line (keys are bytes; a terminal shows them lossily).
fn emit_line<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>, k: &[u8]) -> R {
    if c.o.tty {
        let s = String::from_utf8_lossy(k).into_owned() + "\n";
        c.out.write_all(s.as_bytes())?;
    } else {
        let mut v = k.to_vec();
        v.push(b'\n');
        c.out.write_all(&v)?;
    }
    Ok(())
}

pub(crate) fn decode_oi(raw: &[u8]) -> Result<replwire::ObjectInfo, String> {
    denc::from_slice::<replwire::ObjectInfo>(raw).map_err(|e| format!("Error decoding attr: {e}"))
}

pub(crate) fn snapset_of<D: BlockDev, C: Clock>(
    c: &Ctx<'_, D, C>,
    cid: CollT,
    g: &Ghobject,
) -> R<replwire::SnapSet> {
    match c.ad.with_store(|s| s.getattr(&cid, g, SS_ATTR))? {
        Some(b) => denc::from_slice(&b).map_err(|e| format!("Can't get snapset: {e}").into()),
        None => fail("Can't get snapset: missing snapset attr"),
    }
}

fn spg_of_coll(cid: CollT) -> R<SpgT> {
    match cid {
        CollT::Pg(s) => Ok(s),
        _ => fail("object removal needs a PG object"),
    }
}

fn remove_object<D: BlockDev, C: Clock>(
    c: &mut Ctx<'_, D, C>,
    cid: CollT,
    g: &Ghobject,
    all: bool,
) -> R {
    let spg = spg_of_coll(cid)?;
    if (g.is_pgmeta() || is_mapper(g)) && !c.o.force {
        return fail(
            "refusing to remove the pgmeta/SnapMapper object (it holds the PG state); use --op remove to delete the PG, or --force",
        );
    }
    let missing = c.ad.with_store(|s| s.stat(&cid, g))?.is_none();
    if missing && c.o.force && g.generation == Ghobject::NO_GEN && peering::snaps::is_clone(&g.hobj)
    {
        // A `clone_missing` clone (CS-5456 class): the object is gone on every replica, only its
        // SnapMapper entry is left. The object removal itself is already a no-op, so drop just the
        // mapper entry (reverse + forward keys) in one store txn.
        writeln!(
            c.out,
            "remove: clone object missing; removing its SnapMapper entry only"
        )?;
        if c.o.dry_run {
            return Ok(());
        }
        c.ad.try_submit(
            spg,
            &StoreTxn {
                ops: vec![StoreOp::SnapMap(vec![peering::snaps::MapOp::Remove {
                    clone: g.hobj.clone(),
                }])],
            },
        )?;
        return crate::checkpoint(c);
    }
    if missing {
        return fail("remove: No such file or directory");
    }
    let mut clones = Vec::new();
    if has_snapset(g) {
        match snapset_of(c, cid, g) {
            Ok(ss) => {
                clones = ss.clone_snaps.keys().copied().collect::<Vec<_>>();
                if clones.is_empty() {
                    clones = ss.clones.clone();
                }
                if !clones.is_empty() && !all {
                    if c.o.force {
                        writeln!(
                            c.out,
                            "WARNING: only removing {} with clones present",
                            if g.hobj.snap == SnapId::NOSNAP {
                                "head"
                            } else {
                                "snapdir"
                            }
                        )?;
                        clones.clear();
                    } else {
                        return fail("Clones are present, use removeall to delete everything");
                    }
                }
            }
            Err(e) => {
                // --force and a bad snapset: let them remove the head only
                if !(c.o.force && !all) {
                    return Err(e);
                }
            }
        }
    }
    let mut ops = Vec::new();
    let mut generated = OTxn::new();
    for sn in clones {
        let mut ch = g.hobj.clone();
        ch.snap = sn;
        writeln!(
            c.out,
            "remove clone {}",
            ghobject_json(&Ghobject::new(ch.clone(), g.generation, g.shard))
        )?;
        if g.generation == Ghobject::NO_GEN {
            ops.push(StoreOp::RemoveObject(ch));
        } else {
            // Rollback generations are distinct objects, not the live clone
            // named by StoreOp::RemoveObject. Keep the complete identity and
            // remove the selected generation together with its head.
            generated.remove(cid, &Ghobject::new(ch, g.generation, g.shard));
        }
    }
    writeln!(c.out, "remove {}", ghobject_json(g))?;
    if g.generation == Ghobject::NO_GEN && !g.is_pgmeta() {
        ops.push(StoreOp::RemoveObject(g.hobj.clone()));
    } else if !c.o.dry_run {
        generated.remove(cid, g);
        commit(c, generated)?;
    }
    if !c.o.dry_run && !ops.is_empty() {
        c.ad.try_submit(spg, &StoreTxn { ops })?;
    }
    crate::checkpoint(c)
}

fn dump_object<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>, cid: CollT, g: &Ghobject) -> R {
    let st = c.ad.with_store(|s| s.stat(&cid, g))?;
    let Some(st) = st else {
        return fail("dump: No such file or directory");
    };
    let mut o = serde_json::Map::new();
    o.insert("id".into(), ghobject_value(g));
    let mut rc = Ok(());
    match c.ad.with_store(|s| s.getattr(&cid, g, OI_ATTR))? {
        Some(raw) => match decode_oi(&raw) {
            Ok(oi) => {
                o.insert(
                    "info".into(),
                    serde_json::json!({
                        "oid": ghobject_value(&Ghobject::new(oi.soid.clone(), Ghobject::NO_GEN, g.shard)),
                        "version": oi.version.to_string(),
                        "prior_version": oi.prior_version.to_string(),
                        "user_version": oi.user_version,
                        "size": oi.size,
                        "mtime": osd::utime_str(oi.mtime),
                        "local_mtime": osd::utime_str(oi.local_mtime),
                        "lost": u32::from(oi.flags & replwire::oi::flag::LOST != 0),
                        "flags": oi.flags,
                        "truncate_seq": oi.truncate_seq,
                        "truncate_size": oi.truncate_size,
                        "data_digest": format!("0x{:08x}", oi.data_digest),
                        "omap_digest": format!("0x{:08x}", oi.omap_digest),
                    }),
                );
            }
            Err(e) => rc = fail(e),
        },
        None => rc = fail("Error getting attr: No data available"),
    }
    o.insert("stat".into(), serde_json::json!({"size": st.size}));
    if has_snapset(g) {
        match snapset_of(c, cid, g) {
            Ok(ss) => {
                let clones: Vec<_> = ss
                    .clones
                    .iter()
                    .map(|cl| {
                        serde_json::json!({
                            "snap": cl.0,
                            "size": ss.clone_size.get(cl),
                            "snaps": ss.clone_snaps.get(cl).map(|v| v.iter().map(|s| s.0).collect::<Vec<_>>()),
                        })
                    })
                    .collect();
                o.insert(
                    "SnapSet".into(),
                    serde_json::json!({"seq": ss.seq, "clones": clones}),
                );
            }
            Err(e) => rc = Err(e),
        }
    }
    let v = serde_json::Value::Object(o);
    crate::json::emit(c.out, &c.o.format, &v)?;
    rc
}

// ------------------------------------------------------------------ fix-lost

pub fn op_fix_lost<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    let colls = pg_selection(c)?;
    for cid in colls {
        let mut todo: Vec<(Ghobject, replwire::ObjectInfo)> = Vec::new();
        walk(c.ad, cid, |g| {
            if g.is_pgmeta() {
                return Ok(true);
            }
            match c.ad.with_store(|s| s.getattr(&cid, &g, OI_ATTR))? {
                Some(raw) => match decode_oi(&raw) {
                    Ok(oi) if oi.flags & replwire::oi::flag::LOST != 0 => {
                        todo.push((g, oi));
                    }
                    Ok(_) => {}
                    Err(e) => writeln!(c.err, "{cid}/{}: {e}", ghobject_json(&g))?,
                },
                None => writeln!(
                    c.err,
                    "{cid}/{}: Error getting attr: No data available",
                    ghobject_json(&g)
                )?,
            }
            Ok(true)
        })?;
        for (g, mut oi) in todo {
            write!(c.out, "{cid}/{} is lost", ghobject_json(&g))?;
            if c.o.dry_run {
                writeln!(c.out)?;
                continue;
            }
            writeln!(c.out, ", fixing")?;
            oi.flags &= !replwire::oi::flag::LOST;
            let raw = denc::to_vec(&oi).map_err(|e| format!("encode: {e}"))?;
            let mut t = OTxn::new();
            t.setattr(cid, &g, OI_ATTR, &raw);
            commit(c, t)?;
        }
    }
    crate::checkpoint(c)
}

/// Used by export: does the (non-pgmeta) store object belong to the exported set?
pub(crate) fn user_object(g: &Ghobject) -> bool {
    !g.is_pgmeta() && !g.hobj.is_temp() && g.generation == Ghobject::NO_GEN
}
