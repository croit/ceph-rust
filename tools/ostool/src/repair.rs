// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Object metadata surgery and the diagnostic ops of the classic tool (spec doc/spec/objectstore-tool.md 4):
//! `set-size`, `clear-data-digest`, `clear-snapset`, `remove-clone-metadata`, `--op list-slow-omap`,
//! `--op update-mon-db` (refused). Every mutation is ONE store txn (attrs + truncate together), so a crash leaves
//! either the old or the new state; `--dry-run` runs all reads and prints what would change.
use crate::json::ghobject_json;
use crate::objs::{
    OI_ATTR, SS_ATTR, collect, commit, decode_oi, has_snapset, pg_selection, snapset_of,
};
use crate::{Ctx, R, fail};
use denc::types::{CollT, Ghobject, SnapId};
use replwire::oi::flag;
use replwire::{ObjectInfo, SnapSet};
use std::collections::BTreeMap;
use std::time::Instant;
use store::dev::{BlockDev, Clock};
use store::obj::OTxn;

/// Decimal number argument (classic: must start with a digit).
fn num_arg(s: Option<&str>, what: &str) -> R<u64> {
    match s {
        Some(v) if v.as_bytes().first().is_some_and(u8::is_ascii_digit) => v
            .parse::<u64>()
            .map_err(|_| format!("Invalid {what} '{v}' specified").into()),
        Some(v) => fail(format!("Invalid {what} '{v}' specified")),
        None => fail(format!("Missing {what} argument")),
    }
}

fn load_oi<D: BlockDev, C: Clock>(c: &Ctx<'_, D, C>, cid: CollT, g: &Ghobject) -> R<ObjectInfo> {
    match c.ad.with_store(|s| s.getattr(&cid, g, OI_ATTR))? {
        Some(raw) => Ok(decode_oi(&raw)?),
        None => fail(format!(
            "Error getting attr on : {}, No data available",
            ghobject_json(g)
        )),
    }
}

fn store_snapset(ss: &SnapSet) -> R<Vec<u8>> {
    denc::to_vec(ss).map_err(|e| format!("encode snapset: {e}").into())
}

fn with_snap(g: &Ghobject, snap: SnapId) -> Ghobject {
    let mut h = g.hobj.clone();
    h.snap = snap;
    Ghobject::new(h, g.generation, g.shard)
}

fn clear_digest(oi: &mut ObjectInfo) {
    oi.flags &= !flag::DATA_DIGEST;
    oi.data_digest = ObjectInfo::NO_DIGEST;
}

/// Is `g`'s `snapset` attribute present? A missing object (`NoEnt`) or a missing attribute is "absent"; any other
/// store error is reported (a broken read is not an absent SnapSet).
fn snapset_present(
    r: std::result::Result<Option<Vec<u8>>, store::obj::ObjError>,
    g: &Ghobject,
) -> R<bool> {
    match r {
        Ok(Some(_)) => Ok(true),
        Ok(None) | Err(store::obj::ObjError::NoEnt) => Ok(false),
        Err(e) => fail(format!("Can't get snapset of {}: {e}", ghobject_json(g))),
    }
}

/// `<obj> set-size N` (and `corrupt-size N`: only the object_info is changed, the data stays; testing aid). Sets
/// the object data size, `object_info.size` and, for a clone, the `clone_size` entry of its head's (or snapdir's)
/// SnapSet, in one txn. A changed data size drops the data digest (it no longer matches).
pub fn set_size<D: BlockDev, C: Clock>(
    c: &mut Ctx<'_, D, C>,
    cid: CollT,
    g: &Ghobject,
    corrupt: bool,
) -> R {
    if c.o.arg2.is_some() {
        return fail(crate::USAGE);
    }
    let size = num_arg(c.o.arg1.as_deref(), "size")?;
    if g.hobj.snap == SnapId::SNAPDIR {
        return fail("Can't set the size of a snapdir");
    }
    let mut oi = load_oi(c, cid, g)?;
    let Some(st) = c.ad.with_store(|s| s.stat(&cid, g))? else {
        return fail(format!(
            "Error stat on : {}, No such file or directory",
            ghobject_json(g)
        ));
    };
    // a clone: its size is also recorded in the SnapSet of the head (snapdir when there is no head)
    let mut ss_part: Option<(Ghobject, SnapSet, &str)> = None;
    if g.hobj.snap != SnapId::NOSNAP {
        let mut head = with_snap(g, SnapId::NOSNAP);
        let mut which = "head";
        let mut have =
            snapset_present(c.ad.with_store(|s| s.getattr(&cid, &head, SS_ATTR)), &head)?;
        if !have {
            head = with_snap(g, SnapId::SNAPDIR);
            which = "snapdir";
            have = snapset_present(c.ad.with_store(|s| s.getattr(&cid, &head, SS_ATTR)), &head)?;
        }
        if !have {
            return fail("Can't get snapset: no head or snapdir with a snapset");
        }
        let ss = snapset_of(c, cid, &head)?;
        if !ss.clone_size.contains_key(&g.hobj.snap) {
            return fail(format!(
                "SnapSet is missing clone_size for snap {}",
                g.hobj.snap.0
            ));
        }
        ss_part = Some((head, ss, which));
    }
    let clone_size = ss_part
        .as_ref()
        .and_then(|(_, ss, _)| ss.clone_size.get(&g.hobj.snap).copied());
    if st.size == size && oi.size == size && clone_size.is_none_or(|v| v == size) {
        writeln!(c.out, "Size of object is already {size}")?;
        return Ok(());
    }
    write!(
        c.out,
        "Setting size to {size}, stat size {}, obj info size {}",
        st.size, oi.size
    )?;
    if let (Some(v), Some((_, _, which))) = (clone_size, &ss_part) {
        write!(c.out, ", {which} clone_size {v}")?;
    }
    writeln!(c.out)?;
    if c.o.dry_run {
        return Ok(());
    }
    oi.size = size;
    let mut ss_raw = None;
    if let Some((head, mut ss, _)) = ss_part {
        ss.clone_size.insert(g.hobj.snap, size);
        ss_raw = Some((head, store_snapset(&ss)?));
    }
    let mut t = OTxn::new();
    if !corrupt && st.size != size {
        t.truncate(cid, g, size);
        clear_digest(&mut oi);
    }
    let raw = denc::to_vec(&oi).map_err(|e| format!("encode: {e}"))?;
    t.setattr(cid, g, OI_ATTR, &raw);
    if let Some((head, raw)) = &ss_raw {
        t.setattr(cid, head, SS_ATTR, raw);
    }
    commit(c, t)?;
    crate::checkpoint(c)
}

/// `<obj> clear-data-digest`: forget the stored data digest (flag + value), e.g. after it was recorded wrongly.
pub fn clear_data_digest<D: BlockDev, C: Clock>(
    c: &mut Ctx<'_, D, C>,
    cid: CollT,
    g: &Ghobject,
) -> R {
    if c.o.arg1.is_some() {
        return fail(crate::USAGE);
    }
    let mut oi = load_oi(c, cid, g)?;
    if c.o.dry_run {
        return Ok(());
    }
    clear_digest(&mut oi);
    let raw = denc::to_vec(&oi).map_err(|e| format!("encode: {e}"))?;
    let mut t = OTxn::new();
    t.setattr(cid, g, OI_ATTR, &raw);
    commit(c, t)?;
    crate::checkpoint(c)
}

/// `<head|snapdir> clear-snapset [variant]`. No variant: clear `clones`, `clone_overlap`, `clone_size`. `corrupt`:
/// everything incl. `seq` and `clone_snaps`. `seq`, `snaps` (= clone_snaps), `clones`, `clone_size`,
/// `clone_overlap`: only that field. `size`: add 1 to every clone size (breaks them on purpose). Deviation from
/// classic: the variant is optional (classic demands an argument, `''` for the default).
pub fn clear_snapset<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>, cid: CollT, g: &Ghobject) -> R {
    let variant = c.o.arg1.clone().unwrap_or_default();
    if c.o.arg2.is_some()
        || !matches!(
            variant.as_str(),
            "" | "corrupt" | "seq" | "snaps" | "clones" | "clone_size" | "clone_overlap" | "size"
        )
    {
        return fail(format!(
            "bad clear-snapset variant '{variant}'\n{}",
            crate::USAGE
        ));
    }
    if !has_snapset(g) {
        return fail("'clear-snapset' requires a head or snapdir object");
    }
    let mut ss = snapset_of(c, cid, g)?;
    let all = variant == "corrupt";
    if all || variant == "seq" {
        ss.seq = 0;
    }
    if all || variant == "snaps" {
        ss.clone_snaps.clear();
    }
    let dflt = all || variant.is_empty();
    if dflt || variant == "clones" {
        ss.clones.clear();
    }
    if dflt || variant == "clone_overlap" {
        ss.clone_overlap.clear();
    }
    if dflt || variant == "clone_size" {
        ss.clone_size.clear();
    }
    if variant == "size" {
        for v in ss.clone_size.values_mut() {
            *v = v.checked_add(1).ok_or("snapset clone size overflow")?;
        }
    }
    if c.o.dry_run {
        return Ok(());
    }
    let mut t = OTxn::new();
    let sb = store_snapset(&ss)?;
    t.setattr(cid, g, SS_ATTR, &sb);
    commit(c, t)?;
    crate::checkpoint(c)
}

/// Intersection of two interval sets (`start -> len`).
fn intersect(a: &BTreeMap<u64, u64>, b: &BTreeMap<u64, u64>) -> BTreeMap<u64, u64> {
    let mut out = BTreeMap::new();
    for (&s1, &l1) in a {
        for (&s2, &l2) in b.range(..s1.saturating_add(l1)) {
            let lo = s1.max(s2);
            let hi = s1.saturating_add(l1).min(s2.saturating_add(l2));
            if lo < hi {
                out.insert(lo, hi - lo);
            }
        }
    }
    out
}

/// `<head|snapdir> remove-clone-metadata <cloneid>`: drop one clone from the head's SnapSet (`clones`,
/// `clone_overlap`, `clone_size`, and `clone_snaps`, which classic leaves behind), merging its overlap into the
/// next older clone like snap trimming does. The clone OBJECT and its SnapMapper entry are not touched: remove
/// them with `<clone JSON> remove` afterwards (when the clone object is missing, the follow-up is
/// `<clone JSON> remove --force`, which removes only the SnapMapper entry). `--force` ignores a clone missing in one
/// of the maps. Object and PG stats are not corrected (run `ceph pg repair` after the OSD restarted).
pub fn remove_clone_metadata<D: BlockDev, C: Clock>(
    c: &mut Ctx<'_, D, C>,
    cid: CollT,
    g: &Ghobject,
) -> R {
    if c.o.arg2.is_some() {
        return fail(crate::USAGE);
    }
    if !has_snapset(g) {
        return fail("'remove-clone-metadata' requires a head or snapdir object");
    }
    let id = SnapId(num_arg(c.o.arg1.as_deref(), "cloneid")?);
    let mut ss = snapset_of(c, cid, g)?;
    let Some(pos) = ss.clones.iter().position(|x| *x == id) else {
        return fail(format!("Clone {} not present", id.0));
    };
    if pos > 0 {
        // not the oldest: its overlap with the older clone is only what both share
        let prev = ss.clones[pos - 1];
        let mine = ss.clone_overlap.get(&id).cloned().unwrap_or_default();
        let theirs = ss.clone_overlap.entry(prev).or_default();
        *theirs = intersect(theirs, &mine);
    }
    ss.clones.remove(pos);
    let mut miss = Vec::new();
    if ss.clone_overlap.remove(&id).is_none() {
        miss.push("clone_overlap");
    }
    if ss.clone_size.remove(&id).is_none() {
        miss.push("clone_size");
    }
    ss.clone_snaps.remove(&id);
    for m in miss {
        writeln!(c.err, "Clone {} doesn't exist in {m}", id.0)?;
        if !c.o.force {
            return fail("clone metadata incomplete (--force ignores it)");
        }
        writeln!(c.err, "(ignored)")?;
    }
    if c.o.dry_run {
        return Ok(());
    }
    let mut t = OTxn::new();
    let sb = store_snapset(&ss)?;
    t.setattr(cid, g, SS_ATTR, &sb);
    commit(c, t)?;
    crate::checkpoint(c)?;
    writeln!(c.out, "Removal of clone {} complete", id.0)?;
    writeln!(
        c.out,
        "Use pg repair after OSD restarted to correct stat information"
    )?;
    Ok(())
}

/// `--op list-slow-omap [name] [--pgid P] [--slow-omap-threshold S=16]`: objects whose whole omap listing took at
/// least S seconds (classic: RocksDB tombstone pile-ups make listings slow). croit-flashstore-osd's omap is a B-tree without
/// tombstones, so the result is normally empty; the timing is real, so a store that does degrade is still reported.
/// Output: `--format json`: one JSON array; json-pretty: one JSON object per line
/// (`pgid` or `coll`, `ghobject`, `times` in whole seconds; the single listing has no first/last seek, all three
/// values are the total).
pub fn op_list_slow_omap<D: BlockDev, C: Clock>(c: &mut Ctx<'_, D, C>) -> R {
    let human = crate::objs::human(c.o);
    let thr = c.o.slow_omap_threshold.unwrap_or(16);
    let colls = pg_selection(c)?;
    let items = collect(
        c,
        &colls,
        c.o.object.as_deref().unwrap_or(""),
        c.o.namespace.as_deref(),
        false,
    )?;
    let mut slow = Vec::new();
    for (cid, g) in items {
        let t0 = Instant::now();
        let r = c.ad.with_store(|s| s.omap_all(&cid, &g));
        if let Err(e) = r {
            return fail(format!("omap_get_iterator: {e} obj:{}", ghobject_json(&g)));
        }
        let secs = t0.elapsed().as_secs();
        if secs >= thr {
            let mut o = serde_json::Map::new();
            match cid {
                CollT::Pg(s) => {
                    o.insert("pgid".into(), s.to_string().into());
                }
                _ => {
                    o.insert("coll".into(), cid.to_string().into());
                }
            }
            o.insert("ghobject".into(), crate::json::ghobject_value(&g));
            o.insert(
                "times".into(),
                serde_json::json!({"first_seek_time": secs, "last_seek_time": secs, "total_time": secs}),
            );
            slow.push(serde_json::Value::Object(o));
        }
    }
    if human {
        for o in &slow {
            writeln!(c.out, "{o}")?;
        }
    } else {
        writeln!(c.out, "{}", serde_json::Value::Array(slow))?;
    }
    Ok(())
}

/// `--op update-mon-db`: refused. Classic writes the maps and the OSD key of its store into a RocksDB mon store
/// (to rebuild a lost monitor with `ceph-monstore-tool ... rebuild`). croit-flashstore-osd has no mon store writer
/// (adr 0051 am. 1); a mon rebuild from a FlashStore-only cluster is open question 149.
pub fn op_update_mon_db<D: BlockDev, C: Clock>(_c: &mut Ctx<'_, D, C>) -> R {
    fail(
        "--op update-mon-db is not supported on croit-flashstore-osd: it has no writer for a RocksDB monitor store.\n\
         A mon store rebuild from a FlashStore-only cluster is not available yet (get-osdmap files do not feed \
         ceph-monstore-tool rebuild). In a mixed cluster run classic ceph-objectstore-tool --op update-mon-db on a \
         classic OSD, or restore a mon store backup. See doc/ops/objectstore-tool.md",
    )
}

#[cfg(test)]
mod tests {
    use super::snapset_present;
    use denc::types::{Ghobject, Hobject, ShardId, SnapId};
    use store::obj::ObjError;

    fn obj() -> Ghobject {
        Ghobject::new(
            Hobject::new(b"x", SnapId::NOSNAP, 0, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        )
    }

    /// A failed read is not an absent SnapSet (the repair message must name the store error).
    #[test]
    fn snapset_probe_distinguishes_absent_from_failed() {
        let g = obj();
        assert!(!snapset_present(Ok(None), &g).unwrap());
        assert!(!snapset_present(Err(ObjError::NoEnt), &g).unwrap());
        assert!(snapset_present(Ok(Some(vec![1])), &g).unwrap());
        let e = snapset_present(Err(ObjError::Eio("media error".into())), &g).unwrap_err();
        assert!(e.msg.contains("media error"), "{}", e.msg);
    }
}
