// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
#![expect(clippy::field_reassign_with_default)]
//! set-size, clear-data-digest, clear-snapset, remove-clone-metadata, list-slow-omap, update-mon-db.
mod common;
use common::*;
use denc::types::{CollT, Eversion, SnapId};
use replwire::oi::flag;
use replwire::{ObjectInfo, SnapSet};
use store::obj::OTxn;

/// JSON spec (`--op list` line) of the object with this name and snapid (-2 = head).
fn spec(r: &mut Rig, pg: &str, name: &str, snapid: i64) -> String {
    let o = run(r, &["--op", "list", "--pgid", pg], b"");
    o.text()
        .lines()
        .find(|l| {
            l.contains(&format!("\"oid\":\"{name}\""))
                && l.contains(&format!("\"snapid\":{snapid},"))
        })
        .unwrap_or_else(|| panic!("no {name}@{snapid} in {}", o.text()))
        .to_owned()
}

fn oi_of(r: &Rig, name: &str, snap: SnapId) -> ObjectInfo {
    let s = spg(1, 0);
    let g = gh(s, &hobj(s, name, snap));
    let raw =
        r.ad.with_store(|st| st.getattr(&CollT::Pg(s), &g, b"_"))
            .unwrap()
            .unwrap();
    denc::from_slice(&raw).unwrap()
}
fn ss_of(r: &Rig, name: &str) -> SnapSet {
    let s = spg(1, 0);
    let g = gh(s, &hobj(s, name, SnapId::NOSNAP));
    let raw =
        r.ad.with_store(|st| st.getattr(&CollT::Pg(s), &g, b"snapset"))
            .unwrap()
            .unwrap();
    denc::from_slice(&raw).unwrap()
}
fn size_of(r: &Rig, name: &str, snap: SnapId) -> u64 {
    let s = spg(1, 0);
    let g = gh(s, &hobj(s, name, snap));
    r.ad.with_store(|st| st.stat(&CollT::Pg(s), &g))
        .unwrap()
        .unwrap()
        .size
}
fn put_snapset(r: &Rig, name: &str, ss: &SnapSet) {
    let s = spg(1, 0);
    let g = gh(s, &hobj(s, name, SnapId::NOSNAP));
    let mut t = OTxn::new();
    t.sys = true;
    let raw = denc::to_vec(ss).unwrap();
    t.setattr(CollT::Pg(s), &g, b"snapset", &raw);
    r.ad.with_store(|st| st.commit(&t)).unwrap();
}
fn set_digest(r: &Rig, name: &str) {
    let s = spg(1, 0);
    let h = hobj(s, name, SnapId::NOSNAP);
    let mut oi = oi_of(r, name, SnapId::NOSNAP);
    oi.flags |= flag::DATA_DIGEST;
    oi.data_digest = 0x1234_5678;
    let raw = denc::to_vec(&oi).unwrap();
    let mut t = OTxn::new();
    t.sys = true;
    t.setattr(CollT::Pg(s), &gh(s, &h), b"_", &raw);
    r.ad.with_store(|st| st.commit(&t)).unwrap();
}

#[test]
fn set_size_head_grow_shrink_dry_run_and_noop() {
    let mut r = rig(6);
    make_pg(&r, spg(1, 0), 0);
    set_digest(&r, "small");
    assert_eq!(oi_of(&r, "small", SnapId::NOSNAP).size, 1000);
    // dry-run: prints, changes nothing
    let o = run(
        &mut r,
        &["--pgid", "1.0", "small", "set-size", "2000", "--dry-run"],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    assert!(
        o.text()
            .contains("Setting size to 2000, stat size 1000, obj info size 1000"),
        "{}",
        o.text()
    );
    assert_eq!(size_of(&r, "small", SnapId::NOSNAP), 1000);
    assert_eq!(oi_of(&r, "small", SnapId::NOSNAP).size, 1000);
    // grow: zero filled, digest dropped, object_info consistent
    let o = run(&mut r, &["--pgid", "1.0", "small", "set-size", "2000"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(size_of(&r, "small", SnapId::NOSNAP), 2000);
    let oi = oi_of(&r, "small", SnapId::NOSNAP);
    assert_eq!(oi.size, 2000);
    assert_eq!(oi.flags & flag::DATA_DIGEST, 0);
    assert_eq!(oi.data_digest, ObjectInfo::NO_DIGEST);
    let o = run(&mut r, &["--pgid", "1.0", "small", "get-bytes"], b"");
    let mut want = pattern(1000, 1);
    want.resize(2000, 0);
    assert_eq!(o.out, want);
    // no-op
    let o = run(&mut r, &["--pgid", "1.0", "small", "set-size", "2000"], b"");
    assert_eq!(o.text().trim(), "Size of object is already 2000");
    // shrink survives a remount
    let o = run(&mut r, &["--pgid", "1.0", "small", "set-size", "10"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    let r = remount(r);
    assert_eq!(size_of(&r, "small", SnapId::NOSNAP), 10);
    assert_eq!(oi_of(&r, "small", SnapId::NOSNAP).size, 10);
}

#[test]
fn set_size_argument_errors() {
    let mut r = rig(6);
    make_pg(&r, spg(1, 0), 0);
    for bad in [
        &["--pgid", "1.0", "small", "set-size"][..],
        &["--pgid", "1.0", "small", "set-size", "x"],
        &["--pgid", "1.0", "small", "set-size", "-1"],
    ] {
        let o = run(&mut r, bad, b"");
        assert_ne!(o.code, 0, "{bad:?}");
    }
    let o = run(
        &mut r,
        &["--pgid", "1.0", "nonexistent", "set-size", "5"],
        b"",
    );
    assert_ne!(o.code, 0);
    assert_eq!(size_of(&r, "small", SnapId::NOSNAP), 1000);
}

#[test]
fn set_size_clone_updates_snapset_and_corrupt_size_only_info() {
    let mut r = rig(6);
    make_pg(&r, spg(1, 0), 0);
    let clone = spec(&mut r, "1.0", "snapped", 4);
    assert_eq!(ss_of(&r, "snapped").clone_size[&SnapId(4)], 5000);
    let o = run(&mut r, &["--pgid", "1.0", &clone, "set-size", "4000"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    assert!(o.text().contains("head clone_size 5000"), "{}", o.text());
    assert_eq!(size_of(&r, "snapped", SnapId(4)), 4000);
    assert_eq!(oi_of(&r, "snapped", SnapId(4)).size, 4000);
    assert_eq!(ss_of(&r, "snapped").clone_size[&SnapId(4)], 4000);
    // corrupt-size: object_info + snapset only, data untouched
    let o = run(
        &mut r,
        &["--pgid", "1.0", &clone, "corrupt-size", "77"],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(size_of(&r, "snapped", SnapId(4)), 4000);
    assert_eq!(oi_of(&r, "snapped", SnapId(4)).size, 77);
    assert_eq!(ss_of(&r, "snapped").clone_size[&SnapId(4)], 77);
    // a clone missing in the snapset: refused, nothing changed
    let mut ss = ss_of(&r, "snapped");
    ss.clone_size.clear();
    put_snapset(&r, "snapped", &ss);
    let o = run(&mut r, &["--pgid", "1.0", &clone, "set-size", "1"], b"");
    assert_ne!(o.code, 0);
    assert!(o.err.contains("missing clone_size"), "{}", o.err);
    assert_eq!(size_of(&r, "snapped", SnapId(4)), 4000);
}

#[test]
fn clear_data_digest_roundtrip() {
    let mut r = rig(6);
    make_pg(&r, spg(1, 0), 0);
    set_digest(&r, "small");
    let o = run(
        &mut r,
        &["--pgid", "1.0", "small", "clear-data-digest", "--dry-run"],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(oi_of(&r, "small", SnapId::NOSNAP).data_digest, 0x1234_5678);
    let o = run(
        &mut r,
        &["--pgid", "1.0", "small", "clear-data-digest"],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    let r = remount(r);
    let oi = oi_of(&r, "small", SnapId::NOSNAP);
    assert_eq!(oi.flags & flag::DATA_DIGEST, 0);
    assert_eq!(oi.data_digest, ObjectInfo::NO_DIGEST);
    assert_eq!(oi.size, 1000);
    assert_eq!(oi.user_version, 1);
    assert_eq!(oi.version, Eversion::new(3, 1));
}

fn multi_clone(r: &Rig) {
    let mut ss = SnapSet::default();
    ss.seq = 9;
    ss.clones = vec![SnapId(2), SnapId(5), SnapId(9)];
    for (c, sz) in [(2, 100), (5, 200), (9, 300)] {
        ss.clone_size.insert(SnapId(c), sz);
        ss.clone_snaps.insert(SnapId(c), vec![SnapId(c)]);
    }
    ss.clone_overlap.insert(SnapId(2), [(0, 100)].into());
    ss.clone_overlap
        .insert(SnapId(5), [(0, 50), (60, 40)].into());
    ss.clone_overlap.insert(SnapId(9), [(10, 100)].into());
    put_snapset(r, "snapped", &ss);
}

#[test]
fn clear_snapset_variants() {
    let mut r = rig(6);
    make_pg(&r, spg(1, 0), 0);
    let head = spec(&mut r, "1.0", "snapped", -2);
    // dry-run
    multi_clone(&r);
    let before = ss_of(&r, "snapped");
    let o = run(
        &mut r,
        &["--pgid", "1.0", &head, "clear-snapset", "--dry-run"],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(ss_of(&r, "snapped"), before);
    // default: clones, overlap, size
    let o = run(&mut r, &["--pgid", "1.0", &head, "clear-snapset"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    let ss = ss_of(&r, "snapped");
    assert!(ss.clones.is_empty() && ss.clone_overlap.is_empty() && ss.clone_size.is_empty());
    assert_eq!((ss.seq, ss.clone_snaps.len()), (9, 3));
    // single fields
    for (v, check) in [
        ("seq", 0),
        ("snaps", 1),
        ("clones", 2),
        ("clone_size", 3),
        ("clone_overlap", 4),
    ] {
        multi_clone(&r);
        let o = run(&mut r, &["--pgid", "1.0", &head, "clear-snapset", v], b"");
        assert_eq!(o.code, 0, "{v}: {}", o.err);
        let ss = ss_of(&r, "snapped");
        let empty = [
            ss.seq == 0,
            ss.clone_snaps.is_empty(),
            ss.clones.is_empty(),
            ss.clone_size.is_empty(),
            ss.clone_overlap.is_empty(),
        ];
        for (i, e) in empty.iter().enumerate() {
            assert_eq!(*e, i == check, "variant {v} field {i}");
        }
    }
    // size: +1 on every clone size
    multi_clone(&r);
    let o = run(
        &mut r,
        &["--pgid", "1.0", &head, "clear-snapset", "size"],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    let ss = ss_of(&r, "snapped");
    assert_eq!(
        ss.clone_size.values().copied().collect::<Vec<_>>(),
        [101, 201, 301]
    );
    assert_eq!(ss.clones.len(), 3);
    // corrupt: all
    let o = run(
        &mut r,
        &["--pgid", "1.0", &head, "clear-snapset", "corrupt"],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    let ss = ss_of(&r, "snapped");
    assert_eq!(ss, SnapSet::default());
    // bad variant, clone object, two args: refused
    multi_clone(&r);
    let keep = ss_of(&r, "snapped");
    assert_ne!(
        run(
            &mut r,
            &["--pgid", "1.0", &head, "clear-snapset", "bogus"],
            b""
        )
        .code,
        0
    );
    assert_ne!(
        run(
            &mut r,
            &["--pgid", "1.0", &head, "clear-snapset", "seq", "x"],
            b""
        )
        .code,
        0
    );
    let clone = spec(&mut r, "1.0", "snapped", 4);
    let o = run(&mut r, &["--pgid", "1.0", &clone, "clear-snapset"], b"");
    assert_ne!(o.code, 0);
    assert!(o.err.contains("head or snapdir"), "{}", o.err);
    assert_eq!(ss_of(&r, "snapped"), keep);
}

#[test]
fn remove_clone_metadata_merges_overlap() {
    let mut r = rig(6);
    make_pg(&r, spg(1, 0), 0);
    multi_clone(&r);
    // plain name works (lookup is limited to head/snapdir for this command)
    let o = run(
        &mut r,
        &[
            "--pgid",
            "1.0",
            "snapped",
            "remove-clone-metadata",
            "5",
            "--dry-run",
        ],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(ss_of(&r, "snapped").clones.len(), 3);
    let o = run(
        &mut r,
        &["--pgid", "1.0", "snapped", "remove-clone-metadata", "5"],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    assert!(
        o.text().contains("Removal of clone 5 complete"),
        "{}",
        o.text()
    );
    assert!(o.text().contains("pg repair"));
    let ss = ss_of(&r, "snapped");
    assert_eq!(ss.clones, [SnapId(2), SnapId(9)]);
    assert!(!ss.clone_size.contains_key(&SnapId(5)));
    assert!(!ss.clone_overlap.contains_key(&SnapId(5)));
    assert!(!ss.clone_snaps.contains_key(&SnapId(5)));
    // older clone 2 keeps what it shared with 5: [0,100) n [0,50)+[60,100) = same as 5's
    assert_eq!(ss.clone_overlap[&SnapId(2)], [(0, 50), (60, 40)].into());
    assert_eq!(ss.clone_size[&SnapId(9)], 300);
    // oldest clone: no merge
    let o = run(
        &mut r,
        &["--pgid", "1.0", "snapped", "remove-clone-metadata", "2"],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    let ss = ss_of(&r, "snapped");
    assert_eq!(ss.clones, [SnapId(9)]);
    assert_eq!(ss.clone_overlap[&SnapId(9)], [(10, 100)].into());
    // survives remount; the store objects are not touched
    let r = remount(r);
    assert_eq!(ss_of(&r, "snapped").clones, [SnapId(9)]);
    assert_eq!(size_of(&r, "snapped", SnapId(4)), 5000);
}

#[test]
fn remove_clone_metadata_errors_and_force() {
    let mut r = rig(6);
    make_pg(&r, spg(1, 0), 0);
    multi_clone(&r);
    let keep = ss_of(&r, "snapped");
    for a in [
        &["--pgid", "1.0", "snapped", "remove-clone-metadata"][..],
        &["--pgid", "1.0", "snapped", "remove-clone-metadata", "x"],
        &["--pgid", "1.0", "snapped", "remove-clone-metadata", "7"],
    ] {
        assert_ne!(run(&mut r, a, b"").code, 0, "{a:?}");
    }
    assert_eq!(ss_of(&r, "snapped"), keep);
    // oldest clone, size entry missing: refused, --force ignores
    let mut ss = keep.clone();
    ss.clone_size.remove(&SnapId(2));
    put_snapset(&r, "snapped", &ss);
    let o = run(
        &mut r,
        &["--pgid", "1.0", "snapped", "remove-clone-metadata", "2"],
        b"",
    );
    assert_ne!(o.code, 0);
    assert!(o.err.contains("doesn't exist in clone_size"), "{}", o.err);
    assert_eq!(ss_of(&r, "snapped").clones.len(), 3);
    let o = run(
        &mut r,
        &[
            "--pgid",
            "1.0",
            "snapped",
            "remove-clone-metadata",
            "2",
            "--force",
        ],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(ss_of(&r, "snapped").clones, [SnapId(5), SnapId(9)]);
    // the clone itself can no longer be a target of the metadata command (a clone object is not a head)
    let clone = spec(&mut r, "1.0", "snapped", 4);
    let o = run(
        &mut r,
        &["--pgid", "1.0", &clone, "remove-clone-metadata", "5"],
        b"",
    );
    assert_ne!(o.code, 0);
}

#[test]
fn remove_clone_metadata_missing_overlap_of_non_oldest_clone() {
    let mut r = rig(6);
    make_pg(&r, spg(1, 0), 0);
    multi_clone(&r);
    // clone 5 is not the oldest, so its overlap is merged into clone 2 first: a missing entry must still be
    // reported (the merge must not add an empty entry that hides it)
    let mut ss = ss_of(&r, "snapped");
    ss.clone_overlap.remove(&SnapId(5));
    put_snapset(&r, "snapped", &ss);
    let before = ss_of(&r, "snapped");
    let o = run(
        &mut r,
        &["--pgid", "1.0", "snapped", "remove-clone-metadata", "5"],
        b"",
    );
    assert_ne!(o.code, 0);
    assert!(
        o.err.contains("doesn't exist in clone_overlap"),
        "{}",
        o.err
    );
    assert_eq!(ss_of(&r, "snapped"), before);
    let o = run(
        &mut r,
        &[
            "--pgid",
            "1.0",
            "snapped",
            "remove-clone-metadata",
            "5",
            "--force",
        ],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(ss_of(&r, "snapped").clones, [SnapId(2), SnapId(9)]);
}

#[test]
fn list_slow_omap_and_update_mon_db() {
    let mut r = rig(6);
    make_pg(&r, spg(1, 0), 0);
    // default threshold: nothing is slow
    let o = run(&mut r, &["--op", "list-slow-omap"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(o.text(), "");
    let o = run(&mut r, &["--op", "list-slow-omap", "--format", "json"], b"");
    assert_eq!(o.text().trim(), "[]");
    // threshold 0: everything counts, shape per object
    let o = run(
        &mut r,
        &[
            "--op",
            "list-slow-omap",
            "--slow-omap-threshold",
            "0",
            "--pgid",
            "1.0",
            "omapobj",
        ],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    let lines: Vec<serde_json::Value> = o
        .text()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["pgid"], "1.0");
    assert_eq!(lines[0]["ghobject"]["oid"], "omapobj");
    assert_eq!(lines[0]["times"]["total_time"], 0);
    let o = run(
        &mut r,
        &[
            "--op",
            "list-slow-omap",
            "--slow-omap-threshold",
            "0",
            "--format",
            "json",
        ],
        b"",
    );
    let v: serde_json::Value = serde_json::from_str(&o.text()).unwrap();
    assert!(v.as_array().unwrap().len() >= 4);
    // update-mon-db: clean refusal with the alternatives, nothing opened or written
    let o = run(
        &mut r,
        &["--op", "update-mon-db", "--mon-store-path", "/nonexistent"],
        b"",
    );
    assert_eq!(o.code, 1);
    assert!(
        o.err.contains("not supported") && o.err.contains("get-osdmap"),
        "{}",
        o.err
    );
    assert!(o.out.is_empty());
}

#[test]
fn clear_snapset_size_overflow_preserves_metadata() {
    let mut r = rig(6);
    make_pg(&r, spg(1, 0), 0);
    multi_clone(&r);
    let mut ss = ss_of(&r, "snapped");
    ss.clone_size.insert(SnapId(9), u64::MAX);
    put_snapset(&r, "snapped", &ss);
    let head = spec(&mut r, "1.0", "snapped", -2);
    let o = run(
        &mut r,
        &["--pgid", "1.0", &head, "clear-snapset", "size"],
        b"",
    );
    assert_eq!(o.code, 1, "{}", o.err);
    assert!(o.err.contains("size overflow"), "{}", o.err);
    assert_eq!(ss_of(&r, "snapped"), ss);
}

#[test]
fn slow_omap_reports_failed_reads_with_nonzero_exit() {
    let r = rig(6);
    make_pg(&r, spg(1, 0), 0);
    let cid = CollT::Pg(spg(1, 0));
    let g = gh(spg(1, 0), &hobj(spg(1, 0), "omapobj", SnapId::NOSNAP));
    // Separate omap leaves from collection/onode lookup pages.
    for batch in 0..20 {
        let mut t = OTxn::new();
        t.sys = true;
        let value = vec![0x5a; 2000];
        for i in 0..50 {
            t.push(store::obj::TOp::OmapSetKeys {
                cid,
                oid: g.clone(),
                pairs: vec![(
                    format!("extra{:05}", batch * 50 + i).into_bytes().into(),
                    value.clone().into(),
                )],
            });
        }
        r.ad.with_store(|s| s.commit(&t)).unwrap();
    }
    r.ad.with_store(|s| s.checkpoint()).unwrap();
    let mut r = remount(r);
    // Warm collection/object lookup, leaving the omap tree cold.
    let out = run(&mut r, &["--op", "list", "--pgid", "1.0"], b"");
    assert_eq!(out.code, 0, "{}", out.err);
    r.disk.fail_reads(0, r.disk.config().lba_count);
    let out = run(
        &mut r,
        &["--op", "list-slow-omap", "--pgid", "1.0", "omapobj"],
        b"",
    );
    assert_eq!(out.code, 1, "{}", out.err);
    assert!(out.err.contains("omap_get_iterator"), "{}", out.err);
}
