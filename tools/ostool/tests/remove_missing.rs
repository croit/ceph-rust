// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `remove --force` on a clone whose object is gone drops only its SnapMapper entry (NT-cs-clones-01).
mod common;
use common::*;
use denc::types::{CollT, Eversion, Hobject, SnapId, SpgT};
use peering::snaps::MapOp;
use peering::{StoreOp, StoreTxn};
use replwire::SnapSet;
use store::obj::OTxn;

/// JSON spec (`--op list` line) of the object with this name and snapid (-2 = head).
fn spec(r: &mut Rig, name: &str, snapid: i64) -> String {
    let o = run(r, &["--op", "list", "--pgid", "1.0"], b"");
    o.text()
        .lines()
        .find(|l| {
            l.contains(&format!("\"oid\":\"{name}\""))
                && l.contains(&format!("\"snapid\":{snapid},"))
        })
        .unwrap_or_else(|| panic!("no {name}@{snapid} in {}", o.text()))
        .to_owned()
}

fn ss_of(r: &Rig) -> SnapSet {
    let s = spg(1, 0);
    let g = gh(s, &hobj(s, "snapped", SnapId::NOSNAP));
    let raw =
        r.ad.with_store(|st| st.getattr(&CollT::Pg(s), &g, b"snapset"))
            .unwrap()
            .unwrap();
    denc::from_slice(&raw).unwrap()
}

/// Reverse mapper entries of the PG.
fn map_all(r: &Rig, s: SpgT) -> Vec<(Hobject, Vec<u64>)> {
    r.ad.map_all(s)
}

/// `make_pg` leaves one clone (snap 4); add a second clone (snap 7) with object, SnapSet entry and mapper entry.
fn add_second_clone(r: &Rig) {
    let s = spg(1, 0);
    let cid = CollT::Pg(s);
    let h7 = hobj(s, "snapped", SnapId(7));
    let g7 = gh(s, &h7);
    let data = pattern(3000, 7);
    let oi = oi_bytes(&h7, Eversion::new(3, 2), 3000);
    let mut t = OTxn::new();
    t.sys = true;
    t.touch(cid, &g7);
    t.write(cid, &g7, 0, &data);
    t.setattr(cid, &g7, b"_", &oi);
    r.ad.with_store(|st| st.commit(&t)).unwrap();
    // complete SnapSet for both clones (clone_overlap + clone_size, so remove-clone-metadata needs no --force)
    let head = hobj(s, "snapped", SnapId::NOSNAP);
    let mut ss = SnapSet {
        seq: 7,
        clones: vec![SnapId(4), SnapId(7)],
        ..Default::default()
    };
    for (c, sz) in [(4u64, 5000u64), (7u64, 3000u64)] {
        ss.clone_size.insert(SnapId(c), sz);
        ss.clone_snaps.insert(SnapId(c), vec![SnapId(c)]);
        ss.clone_overlap.insert(SnapId(c), [(0, sz)].into());
    }
    let mut t = OTxn::new();
    t.sys = true;
    t.touch(cid, &gh(s, &head));
    let ssb = denc::to_vec(&ss).unwrap();
    t.setattr(cid, &gh(s, &head), b"snapset", &ssb);
    r.ad.with_store(|st| st.commit(&t)).unwrap();
    r.ad.try_submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::SnapMap(vec![MapOp::Set {
                clone: h7.clone(),
                snaps: vec![7],
            }])],
        },
    )
    .unwrap();
}

#[test]
fn remove_missing_clone_force_drops_only_its_snapmapper_entry() {
    let mut r = rig(6);
    let s = spg(1, 0);
    make_pg(&r, s, 0);
    add_second_clone(&r);

    // step 1 of the documented repair: drop clone 7 from the head SnapSet (object + mapper entry stay)
    let o = run(
        &mut r,
        &["--pgid", "1.0", "snapped", "remove-clone-metadata", "7"],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(ss_of(&r).clones, vec![SnapId(4)]);

    let spec7 = spec(&mut r, "snapped", 7);

    // the clone object goes missing (media error / lost) while its mapper entry remains
    let cid = CollT::Pg(s);
    let g7 = gh(s, &hobj(s, "snapped", SnapId(7)));
    let mut t = OTxn::new();
    t.sys = true;
    t.remove(cid, &g7);
    r.ad.with_store(|st| st.commit(&t)).unwrap();
    assert!(
        map_all(&r, s).iter().any(|(h, _)| h.snap == SnapId(7)),
        "mapper entry for clone 7 should still be present"
    );

    // dry-run: prints and submits nothing
    let o = run(
        &mut r,
        &["--pgid", "1.0", &spec7, "remove", "--force", "--dry-run"],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    assert!(
        o.text()
            .contains("remove: clone object missing; removing its SnapMapper entry only"),
        "{}",
        o.text()
    );
    assert!(map_all(&r, s).iter().any(|(h, _)| h.snap == SnapId(7)));

    // real run: drops only the mapper entry
    let o = run(&mut r, &["--pgid", "1.0", &spec7, "remove", "--force"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    assert!(
        o.text()
            .contains("remove: clone object missing; removing its SnapMapper entry only"),
        "{}",
        o.text()
    );

    let r = remount(r);
    // reverse and forward entries of clone 7 are gone; clone 4 and the head are untouched
    assert!(
        map_all(&r, s).iter().all(|(h, _)| h.snap != SnapId(7)),
        "reverse mapper entry for clone 7 survived: {:?}",
        map_all(&r, s)
    );
    assert!(
        r.ad.map_next(s, 7, 100).unwrap().is_empty(),
        "forward mapper entry for clone 7 survived"
    );
    assert_eq!(
        r.ad.map_snaps(s, &hobj(s, "snapped", SnapId(4))),
        Some(vec![4])
    );
    assert_eq!(ss_of(&r).clones, vec![SnapId(4)]);
}

#[test]
fn remove_missing_non_clone_force_still_fails_and_changes_nothing() {
    let mut r = rig(6);
    let s = spg(1, 0);
    make_pg(&r, s, 0);
    let cid = CollT::Pg(s);

    // a missing head object (snap NOSNAP): the object disappears, everything else stays
    let small = spec(&mut r, "small", -2);
    let g = gh(s, &hobj(s, "small", SnapId::NOSNAP));
    let mut t = OTxn::new();
    t.sys = true;
    t.remove(cid, &g);
    r.ad.with_store(|st| st.commit(&t)).unwrap();

    let before = snapshot(&r, s);
    let o = run(&mut r, &["--pgid", "1.0", &small, "remove", "--force"], b"");
    assert_ne!(o.code, 0);
    assert!(
        o.err.contains("remove: No such file or directory"),
        "{}",
        o.err
    );
    let after = snapshot(&r, s);
    assert_eq!(before, after, "remove --force changed the store state");
}
