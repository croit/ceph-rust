// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cls_rgw versioning (G5): link_olh, unlink_instance, read/trim/clear_olh_log on
//! MemCtx. Key layout and flag transitions per spec/cls_rgw.md s6.
mod common;
use cls::errno::*;
use cls::mem::MemStore;
use cls::rgw::index::ERR_BUSY_RESHARDING;
use cls::rgw::keys;
use cls::rgw::types::*;
use common::*;
use denc::types::UTime;

const O: &str = ".dir.v.0";
const T0: u32 = 1_800_000_000;

fn init() -> MemStore {
    let mut s = MemStore::new();
    s.env.now = UTime::new(T0, 0);
    ok(&mut s, O, "rgw", "bucket_init_index", &[]);
    s
}
/// Advance the OSD clock one second: now-epochs (ns) strictly increase between calls.
fn tick(s: &mut MemStore) {
    s.env.now.sec += 1;
}
fn now_ns(s: &MemStore) -> u64 {
    s.env.now.sec as u64 * 1_000_000_000 + s.env.now.nsec as u64
}
fn meta(size: u64) -> DirEntryMeta {
    DirEntryMeta {
        category: 1,
        size,
        accounted_size: size,
        mtime: UTime::new(100, 0),
        etag: "e".into(),
        owner: "own".into(),
        owner_display_name: "Own".into(),
        ..Default::default()
    }
}
fn hdr(s: &MemStore) -> DirHeader {
    d(&s.obj(O).unwrap().omap_header)
}
fn de(s: &MemStore, k: &[u8]) -> Option<DirEntry> {
    s.obj(O)?.omap.get(k).map(|v| d(v))
}
fn olh(s: &MemStore, name: &str) -> Option<OlhEntry> {
    s.obj(O)?
        .omap
        .get(&keys::olh_key(&ObjKey::new(name, "")))
        .map(|v| d(v))
}
fn inst(s: &MemStore, name: &str, i: &str) -> Option<DirEntry> {
    de(s, &keys::instance_key(&ObjKey::new(name, i), false))
}
fn inst_dm(s: &MemStore, name: &str, i: &str) -> Option<DirEntry> {
    de(s, &keys::instance_key(&ObjKey::new(name, i), true))
}
fn list_copy(s: &MemStore, e: &DirEntry) -> Option<DirEntry> {
    de(s, &keys::list_key(e))
}

fn link_op(name: &str, i: &str, dm: bool, tag: &str) -> LinkOlhOp {
    LinkOlhOp {
        key: ObjKey::new(name, i),
        olh_tag: tag.into(),
        delete_marker: dm,
        op_tag: "ot".into(),
        meta: meta(10),
        ..Default::default()
    }
}
/// The instance entry exists before the link (RGW: prepare+complete of the instance key first).
fn ensure_instance(s: &mut MemStore, name: &str, i: &str) {
    if i.is_empty() || inst(s, name, i).is_some() {
        return;
    }
    let en = DirEntry {
        key: ObjKey::new(name, i),
        exists: true,
        meta: meta(10),
        tag: "pt".into(),
        ..Default::default()
    };
    s.objects
        .get_mut(O)
        .unwrap()
        .omap
        .insert(keys::instance_key(&en.key, false), e(&en));
}
fn link_raw(s: &mut MemStore, op: &LinkOlhOp) -> (i32, Vec<u8>) {
    if !op.delete_marker {
        ensure_instance(
            s,
            &String::from_utf8_lossy(&op.key.name),
            &String::from_utf8_lossy(&op.key.instance),
        );
    }
    let r = call(s, O, "rgw", "bucket_link_olh", &e(op));
    (r.ret, r.out)
}
/// Link and require success (no output, like Ceph 21.2.0); returns the OLH epoch afterwards.
fn link(s: &mut MemStore, name: &str, i: &str, dm: bool, tag: &str) -> u64 {
    let (r, out) = link_raw(s, &link_op(name, i, dm, tag));
    assert_eq!((r, out.len()), (0, 0));
    olh(s, name).unwrap().epoch
}
fn unlink_op(name: &str, i: &str, tag: &str) -> UnlinkInstanceOp {
    UnlinkInstanceOp {
        key: ObjKey::new(name, i),
        op_tag: "ut".into(),
        olh_tag: tag.into(),
        ..Default::default()
    }
}
fn unlink(s: &mut MemStore, name: &str, i: &str, tag: &str) -> (i32, Vec<u8>) {
    let r = call(
        s,
        O,
        "rgw",
        "bucket_unlink_instance",
        &e(&unlink_op(name, i, tag)),
    );
    (r.ret, r.out)
}
fn listing(s: &mut MemStore, versions: bool) -> Vec<(String, bool)> {
    let op = ListOp {
        num_entries: 100,
        list_versions: versions,
        ..Default::default()
    };
    let r = call(s, O, "rgw", "bucket_list", &e(&op));
    assert_eq!(r.ret, 0);
    let l: ListRet = d(&r.out);
    l.dir
        .m
        .values()
        .map(|x| {
            (
                format!(
                    "{}/{}",
                    String::from_utf8_lossy(&x.key.name),
                    String::from_utf8_lossy(&x.key.instance)
                ),
                x.is_delete_marker(),
            )
        })
        .collect()
}
fn log_ops(o: &OlhEntry) -> Vec<(u8, String)> {
    o.pending_log
        .values()
        .flatten()
        .map(|l| {
            (
                l.op,
                format!(
                    "{}/{}",
                    String::from_utf8_lossy(&l.key.name),
                    String::from_utf8_lossy(&l.key.instance)
                ),
            )
        })
        .collect()
}

#[test]
fn registry_flags() {
    use cls::registry::*;
    for (m, f) in [
        ("bucket_link_olh", RW),
        ("bucket_unlink_instance", RW),
        ("bucket_read_olh_log", RD),
        ("bucket_trim_olh_log", RW),
        ("bucket_clear_olh", RW),
    ] {
        assert_eq!(lookup("rgw", m).unwrap().flags, f, "{m}");
    }
    // dev-tree method, not in Ceph 21.2.0: unknown (the message fails with EOPNOTSUPP at classification)
    assert!(lookup("rgw", "bucket_refresh_instance").is_none());
}

#[test]
fn first_link_writes_marker_instance_list_and_olh() {
    let mut s = init();
    let ep = link(&mut s, "k", "v1", false, "tag1");
    assert_eq!(ep, now_ns(&s));
    let marker = de(&s, b"k").unwrap();
    assert_eq!(marker.flags, flag::VER_MARKER);
    let i = inst(&s, "k", "v1").unwrap();
    assert_eq!(i.flags, flag::VER | flag::CURRENT);
    assert_eq!(i.versioned_epoch, ep);
    assert_eq!(list_copy(&s, &i).unwrap(), i);
    let o = olh(&s, "k").unwrap();
    assert_eq!(
        (o.key.clone(), o.epoch, txt(&o.tag), o.exists),
        (ObjKey::new("k", "v1"), ep, "tag1", true)
    );
    assert!(!o.delete_marker && !o.pending_removal);
    assert_eq!(log_ops(&o), vec![(olh_op::LINK_OLH, "k/v1".to_string())]);
    // no header write without log_op
    assert_eq!(hdr(&s).ver, 1);
    // listing: current version visible
    assert_eq!(listing(&mut s, false), vec![("k/v1".to_string(), false)]);
}

#[test]
fn newer_version_promotes_and_demotes_the_old_head() {
    let mut s = init();
    link(&mut s, "k", "v1", false, "t");
    tick(&mut s);
    let ep2 = link(&mut s, "k", "v2", false, "t");
    let v1 = inst(&s, "k", "v1").unwrap();
    let v2 = inst(&s, "k", "v2").unwrap();
    assert_eq!(v1.flags, flag::VER); // demoted: instance AND list copy
    assert_eq!(list_copy(&s, &v1).unwrap().flags, flag::VER);
    assert_eq!(v2.flags, flag::VER | flag::CURRENT);
    let o = olh(&s, "k").unwrap();
    assert_eq!((o.key.instance.as_slice(), o.epoch), (&b"v2"[..], ep2));
    // versions: newest first; plain listing: only the head
    assert_eq!(
        listing(&mut s, true),
        vec![("k/v2".to_string(), false), ("k/v1".to_string(), false)]
    );
    assert_eq!(listing(&mut s, false), vec![("k/v2".to_string(), false)]);
}

#[test]
fn delete_marker_becomes_head_and_hides_the_name() {
    let mut s = init();
    link(&mut s, "k", "v1", false, "t");
    tick(&mut s);
    link(&mut s, "k", "dm1", true, "t");
    let dm = inst(&s, "k", "dm1").unwrap();
    assert_eq!(dm.flags, flag::DELETE_MARKER | flag::VER | flag::CURRENT);
    assert_eq!(txt(&dm.tag), "delete-marker");
    assert_eq!(txt(&dm.meta.owner), "own");
    assert!(olh(&s, "k").unwrap().delete_marker);
    assert_eq!(listing(&mut s, false), Vec::<(String, bool)>::new());
    assert_eq!(
        listing(&mut s, true),
        vec![("k/dm1".to_string(), true), ("k/v1".to_string(), false)]
    );
}

#[test]
fn unlink_head_promotes_next_then_empties_the_olh() {
    let mut s = init();
    let ep1 = link(&mut s, "k", "v1", false, "t");
    tick(&mut s);
    link(&mut s, "k", "v2", false, "t");
    tick(&mut s);
    assert_eq!(unlink(&mut s, "k", "v2", "t"), (0, Vec::new()));
    let o = olh(&s, "k").unwrap();
    assert_eq!(o.key, ObjKey::new("k", "v1"));
    assert_eq!(o.epoch, ep1); // the promoted version's own epoch
    assert!(o.exists && !o.pending_removal);
    assert_eq!(
        inst(&s, "k", "v1").unwrap().flags,
        flag::VER | flag::CURRENT
    );
    let ops = log_ops(&o);
    assert!(ops.contains(&(olh_op::LINK_OLH, "k/v1".to_string())));
    assert!(ops.contains(&(olh_op::REMOVE_INSTANCE, "k/v2".to_string())));
    // list copy gone; the data instance entry of a non-DM stays (removed by the caller's complete_op)
    let v2 = inst(&s, "k", "v2").unwrap();
    assert!(list_copy(&s, &v2).is_none());
    assert_eq!(listing(&mut s, true), vec![("k/v1".to_string(), false)]);

    tick(&mut s);
    assert_eq!(unlink(&mut s, "k", "v1", "t").0, 0);
    let o = olh(&s, "k").unwrap();
    assert!(!o.exists && o.pending_removal);
    assert_eq!(o.key, ObjKey::new("k", ""));
    assert!(log_ops(&o).contains(&(olh_op::UNLINK_OLH, "k/".to_string())));
    assert_eq!(listing(&mut s, true), Vec::<(String, bool)>::new());
}

#[test]
fn olh_tag_generations() {
    let mut s = init();
    link(&mut s, "k", "v1", false, "gen1");
    tick(&mut s);
    // wrong tag while the olh lives: refused, nothing changed
    ensure_instance(&mut s, "k", "v2");
    let before = s.objects.clone();
    let (r, out) = link_raw(&mut s, &link_op("k", "v2", false, "other"));
    assert_eq!((r, out.len()), (ECANCELED, 0));
    assert_eq!(s.objects, before);
    // remove the last version -> pending_removal: a new tag starts a new generation
    assert_eq!(unlink(&mut s, "k", "v1", "gen1").0, 0);
    tick(&mut s);
    link(&mut s, "k", "v3", false, "gen2");
    let o = olh(&s, "k").unwrap();
    assert_eq!(
        (txt(&o.tag), o.pending_removal, o.exists),
        ("gen2", false, true)
    );
    assert_eq!(o.key, ObjKey::new("k", "v3"));
}

#[test]
fn stale_epoch_is_stored_but_not_promoted() {
    let mut s = init();
    let ep = link(&mut s, "k", "v1", false, "t");
    tick(&mut s);
    let mut op = link_op("k", "v2", false, "t");
    op.olh_epoch = ep - 10; // older than the olh epoch (multisite sync case)
    assert_eq!(link_raw(&mut s, &op), (0, Vec::new()));
    let v2 = inst(&s, "k", "v2").unwrap();
    assert_eq!((v2.flags, v2.versioned_epoch), (flag::VER, ep - 10));
    let o = olh(&s, "k").unwrap();
    assert_eq!((o.key.clone(), o.epoch), (ObjKey::new("k", "v1"), ep));
    assert!(log_ops(&o).contains(&(olh_op::STALE, "k/v2".to_string())));
}

#[test]
fn equal_epoch_tie_breaks_on_instance_name() {
    let mut s = init();
    let mut op = link_op("k", "v5", false, "t");
    op.olh_epoch = 500;
    link_raw(&mut s, &op);
    tick(&mut s);
    // same epoch, head instance >= new instance: the smaller instance wins, old head demoted
    let mut op = link_op("k", "v1", false, "t");
    op.olh_epoch = 500;
    assert_eq!(link_raw(&mut s, &op).0, 0);
    assert_eq!(olh(&s, "k").unwrap().key, ObjKey::new("k", "v1"));
    assert_eq!(inst(&s, "k", "v5").unwrap().flags, flag::VER);
    assert_eq!(
        inst(&s, "k", "v1").unwrap().flags,
        flag::VER | flag::CURRENT
    );
    // same epoch, head instance < new instance: stored but not promoted
    let mut op = link_op("k", "v9", false, "t");
    op.olh_epoch = 500;
    assert_eq!(link_raw(&mut s, &op).0, 0);
    assert_eq!(olh(&s, "k").unwrap().key, ObjKey::new("k", "v1"));
    assert_eq!(inst(&s, "k", "v9").unwrap().flags, flag::VER);
}

#[test]
fn unmodified_since_guard() {
    let mut s = init();
    link(&mut s, "k", "v1", false, "t");
    tick(&mut s);
    let h0 = hdr(&s);
    // object mtime (100,0) >= unmod (100,500): precision is seconds -> stale, no output, no header
    let mut op = link_op("k", "v1", false, "t");
    op.unmod_since = UTime::new(100, 500);
    let (r, out) = link_raw(&mut s, &op);
    assert_eq!((r, out.len()), (0, 0));
    assert_eq!(hdr(&s), h0);
    assert!(log_ops(&olh(&s, "k").unwrap()).contains(&(olh_op::STALE, "k/v1".to_string())));
    // high precision: 100.0 < 100.0005 -> proceeds (a new LINK_OLH log entry)
    let links = |s: &MemStore| {
        log_ops(&olh(s, "k").unwrap())
            .iter()
            .filter(|o| o.0 == olh_op::LINK_OLH)
            .count()
    };
    let before = links(&s);
    let mut op = link_op("k", "v1", false, "t");
    op.unmod_since = UTime::new(100, 500);
    op.high_precision_time = true;
    let (r, out) = link_raw(&mut s, &op);
    assert_eq!((r, out.len()), (0, 0));
    assert_eq!(links(&s), before + 1);
}

/// Put a plain (pre-versioning) object through prepare/complete.
fn put_plain(s: &mut MemStore, name: &str) {
    let p = ObjPrepareOp {
        op: op::ADD,
        tag: "t".into(),
        key: ObjKey::new(name, ""),
        ..Default::default()
    };
    ok(s, O, "rgw", "bucket_prepare_op", &e(&p));
    let c = ObjCompleteOp {
        op_tag: "t".into(),
        key: ObjKey::new(name, ""),
        meta: meta(10),
        ..Default::default()
    };
    ok(s, O, "rgw", "bucket_complete_op", &e(&c));
}

#[test]
fn first_version_converts_a_plain_object_to_the_null_version() {
    let mut s = init();
    put_plain(&mut s, "k");
    let stats = hdr(&s).stats.clone();
    tick(&mut s);
    link(&mut s, "k", "v1", false, "t");
    // the old object is now the (non-current) null instance, versioned_epoch = its mtime in ns
    let null = inst(&s, "k", "").unwrap();
    assert_eq!(null.flags, flag::VER);
    assert_eq!(null.versioned_epoch, 100 * 1_000_000_000);
    assert_eq!(list_copy(&s, &null).unwrap(), null);
    assert_eq!(de(&s, b"k").unwrap().flags, flag::VER_MARKER);
    assert_eq!(hdr(&s).stats, stats); // no accounting in link
    assert_eq!(
        listing(&mut s, true),
        vec![("k/v1".to_string(), false), ("k/".to_string(), false)]
    );
    // unlink the head: the null version is promoted
    tick(&mut s);
    assert_eq!(unlink(&mut s, "k", "v1", "t").0, 0);
    assert_eq!(olh(&s, "k").unwrap().key, ObjKey::new("k", ""));
    assert_eq!(inst(&s, "k", "").unwrap().flags, flag::VER | flag::CURRENT);
}

#[test]
fn null_delete_marker_replaces_a_plain_object() {
    let mut s = init();
    put_plain(&mut s, "k");
    tick(&mut s);
    link(&mut s, "k", "", true, "t"); // S3 delete on a versioned bucket: marker with the null instance
    let dm = inst_dm(&s, "k", "").unwrap();
    assert_eq!(dm.flags, flag::DELETE_MARKER | flag::VER | flag::CURRENT);
    let o = olh(&s, "k").unwrap();
    assert!(o.delete_marker && o.exists);
    let ops = log_ops(&o);
    assert!(ops.contains(&(olh_op::LINK_OLH, "k/".to_string())));
    assert!(ops.contains(&(olh_op::REMOVE_INSTANCE, "k/".to_string()))); // the data object goes
    // the old null data entry exists only as instance entry (no list copy): marker is the only version
    assert_eq!(listing(&mut s, true), vec![("k/".to_string(), true)]);
    assert_eq!(listing(&mut s, false), Vec::<(String, bool)>::new());
}

#[test]
fn bilog_entry_and_header_bump_when_log_op() {
    let mut s = init();
    let mut op = link_op("k", "v1", false, "t");
    op.log_op = true;
    op.bilog_flags = BILOG_NULL_VERSION;
    assert_eq!(link_raw(&mut s, &op), (0, Vec::new()));
    let ep = olh(&s, "k").unwrap().epoch;
    let h = hdr(&s);
    assert_eq!(h.ver, 2);
    let (k, v) = s
        .obj(O)
        .unwrap()
        .omap
        .iter()
        .find(|(k, _)| k.starts_with(keys::BILOG))
        .unwrap();
    let b: BiLogEntry = d(v);
    assert_eq!(&k[keys::BILOG.len()..], b.id);
    assert!(b.id.starts_with(b"00000000001."));
    assert_eq!(h.max_marker, b.id);
    assert_eq!(
        (b.op, b.state, b.index_ver),
        (op::LINK_OLH, state::COMPLETE, 1)
    );
    assert_eq!(b.bilog_flags, BILOG_NULL_VERSION | BILOG_VERSIONED_OP);
    assert_eq!((b.ver.epoch, b.ver.pool), (ep, -1));
    assert_eq!(b.object, b"k");
    assert_eq!(b.instance, b"v1");
    assert_eq!(txt(&b.tag), "ot");
    assert!(b.owner.is_empty()); // only delete markers carry the owner
    // delete marker: owner copied; syncstopped suppresses the log (header untouched)
    tick(&mut s);
    let mut op = link_op("k", "dm", true, "t");
    op.log_op = true;
    let (r, _) = link_raw(&mut s, &op);
    assert_eq!(r, 0);
    let last = s
        .obj(O)
        .unwrap()
        .omap
        .iter()
        .rfind(|(k, _)| k.starts_with(keys::BILOG))
        .map(|(_, v)| d::<BiLogEntry>(v))
        .unwrap();
    assert_eq!((last.op, txt(&last.owner)), (op::LINK_OLH_DM, "own"));
    ok(&mut s, O, "rgw", "bi_log_stop", &[]);
    let h = hdr(&s);
    tick(&mut s);
    let mut op = link_op("k", "v3", false, "t");
    op.log_op = true;
    link_raw(&mut s, &op);
    assert_eq!(hdr(&s), h);
}

#[test]
fn unlink_of_an_unknown_instance_and_stale_unlink() {
    let mut s = init();
    link(&mut s, "k", "v1", false, "t");
    tick(&mut s);
    assert_eq!(unlink(&mut s, "k", "nope", "t").0, ENOENT);
    // stale unlink (explicit older epoch): list entry removed, REMOVE_INSTANCE logged, head stays
    link(&mut s, "k", "v2", false, "t");
    tick(&mut s);
    let mut op = unlink_op("k", "v1", "t");
    op.olh_epoch = 1;
    let r = call(&mut s, O, "rgw", "bucket_unlink_instance", &e(&op));
    assert_eq!(r.ret, 0);
    let o = olh(&s, "k").unwrap();
    assert_eq!(o.key, ObjKey::new("k", "v2"));
    assert!(log_ops(&o).contains(&(olh_op::REMOVE_INSTANCE, "k/v1".to_string())));
    assert!(list_copy(&s, &inst(&s, "k", "v1").unwrap()).is_none());
}

#[test]
fn unlink_delete_marker_removes_its_instance_entry() {
    let mut s = init();
    link(&mut s, "k", "v1", false, "t");
    tick(&mut s);
    link(&mut s, "k", "dm1", true, "t");
    tick(&mut s);
    assert_eq!(unlink(&mut s, "k", "dm1", "t").0, 0);
    assert!(inst(&s, "k", "dm1").is_none());
    let o = olh(&s, "k").unwrap();
    assert_eq!(o.key, ObjKey::new("k", "v1"));
    assert!(log_ops(&o).contains(&(olh_op::STALE, "k/dm1".to_string())));
    assert_eq!(listing(&mut s, false), vec![("k/v1".to_string(), false)]);
}

#[test]
fn guard_blocks_while_resharding() {
    let mut s = init();
    let set = SetReshardingOp {
        entry: InstanceEntry {
            reshard_status: reshard::IN_PROGRESS,
        },
    };
    ok(&mut s, O, "rgw", "set_bucket_resharding", &e(&set));
    let (r, _) = link_raw(&mut s, &link_op("k", "v1", false, "t"));
    assert_eq!(r, ERR_BUSY_RESHARDING);
    assert_eq!(unlink(&mut s, "k", "v1", "t").0, ERR_BUSY_RESHARDING);
}

fn read_log(s: &mut MemStore, tag: &str, marker: u64, stales: bool) -> (i32, ReadOlhLogRet) {
    let op = ReadOlhLogOp {
        olh: ObjKey::new("k", ""),
        ver_marker: marker,
        olh_tag: tag.into(),
        get_stales: stales,
    };
    let r = call(s, O, "rgw", "bucket_read_olh_log", &e(&op));
    let ret = if r.ret == 0 {
        d(&r.out)
    } else {
        ReadOlhLogRet::default()
    };
    (r.ret, ret)
}

#[test]
fn read_olh_log_markers_stales_and_tags() {
    let mut s = init();
    link(&mut s, "k", "v1", false, "t");
    tick(&mut s);
    let mut op = link_op("k", "v2", false, "t");
    op.olh_epoch = 5; // stale: logs STALE at now_epoch
    link_raw(&mut s, &op);
    let all = read_log(&mut s, "t", 0, true).1;
    assert_eq!(all.log.len(), 2);
    assert!(!all.is_truncated);
    // stales filtered out (and the emptied epoch dropped)
    let nostale = read_log(&mut s, "t", 0, false).1;
    assert_eq!(nostale.log.len(), 1);
    // strictly greater than the marker
    let first = *all.log.keys().next().unwrap();
    assert_eq!(read_log(&mut s, "t", first, true).1.log.len(), 1);
    assert_eq!(read_log(&mut s, "t", u64::MAX, true).1.log.len(), 0);
    // tag mismatch; non-empty instance
    assert_eq!(read_log(&mut s, "x", 0, true).0, ECANCELED);
    let op = ReadOlhLogOp {
        olh: ObjKey::new("k", "i"),
        olh_tag: "t".into(),
        ..Default::default()
    };
    err(&mut s, O, "rgw", "bucket_read_olh_log", &e(&op), EINVAL);
    // absent olh: empty log for the empty tag, ECANCELED otherwise
    let mut s2 = init();
    assert_eq!(read_log(&mut s2, "", 0, true).0, 0);
    assert_eq!(read_log(&mut s2, "t", 0, true).0, ECANCELED);
}

#[test]
fn read_olh_log_pages_at_1000_epochs() {
    let mut s = init();
    let mut o = OlhEntry {
        key: ObjKey::new("k", "v"),
        tag: "t".into(),
        ..Default::default()
    };
    for ep in 1..=1500u64 {
        o.pending_log.insert(
            ep,
            vec![
                OlhLogEntry {
                    epoch: ep,
                    op: olh_op::LINK_OLH,
                    ..Default::default()
                };
                2 // two entries per epoch: the cap counts epochs, not entries
            ],
        );
    }
    s.objects
        .get_mut(O)
        .unwrap()
        .omap
        .insert(keys::olh_key(&ObjKey::new("k", "")), e(&o));
    let (r, p1) = read_log(&mut s, "t", 0, true);
    assert_eq!(r, 0);
    assert_eq!(p1.log.len(), 1000);
    assert!(p1.is_truncated);
    assert_eq!(p1.log.values().next().unwrap().len(), 2);
    let (_, p2) = read_log(&mut s, "t", 1000, true);
    assert_eq!(p2.log.len(), 500);
    assert!(!p2.is_truncated);
}

#[test]
fn trim_olh_log_drops_up_to_and_including_ver() {
    let mut s = init();
    let e1 = link(&mut s, "k", "v1", false, "t");
    tick(&mut s);
    let e2 = link(&mut s, "k", "v2", false, "t");
    let h = hdr(&s);
    let op = |ver, tag: &str| {
        e(&TrimOlhLogOp {
            olh: ObjKey::new("k", ""),
            ver,
            olh_tag: tag.into(),
        })
    };
    err(
        &mut s,
        O,
        "rgw",
        "bucket_trim_olh_log",
        &op(e1, "zz"),
        ECANCELED,
    );
    ok(&mut s, O, "rgw", "bucket_trim_olh_log", &op(e1, "t"));
    let o = olh(&s, "k").unwrap();
    assert_eq!(o.pending_log.keys().copied().collect::<Vec<_>>(), vec![e2]);
    assert_eq!(hdr(&s), h); // header untouched
    ok(&mut s, O, "rgw", "bucket_trim_olh_log", &op(u64::MAX, "t"));
    assert!(olh(&s, "k").unwrap().pending_log.is_empty());
    let bad = e(&TrimOlhLogOp {
        olh: ObjKey::new("k", "x"),
        ..Default::default()
    });
    err(&mut s, O, "rgw", "bucket_trim_olh_log", &bad, EINVAL);
}

#[test]
fn clear_olh_removes_olh_and_marker_only() {
    let mut s = init();
    link(&mut s, "k", "v1", false, "t");
    let h = hdr(&s);
    let op = |name: &str, tag: &str| {
        e(&ClearOlhOp {
            key: ObjKey::new(name, ""),
            olh_tag: tag.into(),
        })
    };
    err(
        &mut s,
        O,
        "rgw",
        "bucket_clear_olh",
        &op("k", "zz"),
        ECANCELED,
    );
    ok(&mut s, O, "rgw", "bucket_clear_olh", &op("k", "t"));
    assert!(olh(&s, "k").is_none());
    assert!(de(&s, b"k").is_none()); // placeholder gone
    assert!(inst(&s, "k", "v1").is_some()); // instances are the caller's business
    assert_eq!(hdr(&s), h);
    // a real plain object under that name is NOT removed
    let mut s = init();
    put_plain(&mut s, "p");
    ok(&mut s, O, "rgw", "bucket_clear_olh", &op("p", ""));
    assert!(de(&s, b"p").is_some());
}

#[test]
fn in_logrecord_counts_olh_writes_for_the_reshard_log() {
    let mut s = init();
    let set = SetReshardingOp {
        entry: InstanceEntry {
            reshard_status: reshard::IN_LOGRECORD,
        },
    };
    ok(&mut s, O, "rgw", "set_bucket_resharding", &e(&set));
    link(&mut s, "k", "v1", false, "t");
    let h = hdr(&s);
    // marker + instance + list copy + olh = 4 logged writes; the header is written (counter)
    assert_eq!(h.reshardlog_entries, 4);
    assert_eq!(h.ver, 3);
    let n = s
        .obj(O)
        .unwrap()
        .omap
        .keys()
        .filter(|k| k.starts_with(keys::RESHARD_LOG))
        .count();
    assert_eq!(n, 4);
}
