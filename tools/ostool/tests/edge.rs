// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
mod common;
use common::*;
use denc::types::{CollT, Eversion, SnapId};
use store::obj::{OTxn, TOp};

#[test]
fn sparse_empty_and_attrless_objects_roundtrip() {
    let mut a = rig(6);
    let s = spg(1, 2);
    make_pg(&a, s, 2);
    let cid = CollT::Pg(s);
    // sparse: data at both ends, a hole of > 4 MiB in between (whole zero chunks are skipped on import)
    let h = hobj(s, "sparse", SnapId::NOSNAP);
    let g = gh(s, &h);
    let (head, tail) = (pattern(4096, 3), pattern(4096, 9));
    let size = 10 * 1024 * 1024u64 + 4096;
    let oi = oi_bytes(&h, Eversion::new(3, 20), size);
    let ss0 = denc::to_vec(&replwire::SnapSet::default()).unwrap();
    let mut t = OTxn::new();
    t.sys = true;
    t.touch(cid, &g);
    t.write(cid, &g, 0, &head);
    t.write(cid, &g, size - 4096, &tail);
    t.setattr(cid, &g, b"_", &oi);
    t.setattr(cid, &g, b"snapset", &ss0);
    // empty object that only has an omap header
    let h2 = hobj(s, "emptyobj", SnapId::NOSNAP);
    let g2 = gh(s, &h2);
    let oi2 = oi_bytes(&h2, Eversion::new(3, 21), 0);
    t.touch(cid, &g2);
    t.setattr(cid, &g2, b"_", &oi2);
    t.setattr(cid, &g2, b"snapset", &ss0);
    t.push(TOp::OmapSetHeader {
        cid,
        oid: g2.clone(),
        header: b"only-a-header".to_vec().into(),
    });
    a.ad.with_store(|st| st.commit(&t)).unwrap();
    let f = std::env::temp_dir().join(format!("ostool-sp-{}.export", std::process::id()));
    let fs = f.to_str().unwrap();
    let o = run(
        &mut a,
        &["--op", "export", "--pgid", "1.2", "--file", fs],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    let mut b = rig(6);
    let o = run(&mut b, &["--op", "import", "--file", fs], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(snapshot(&a, s), snapshot(&b, s));
    // the hole stayed a hole
    let used = b.ad.with_store(|st| st.statfs()).used_bytes;
    assert!(used < 40 << 20, "used {used}");

    std::fs::remove_file(&f).unwrap();
    // an object without object_info: export refuses, --force exports it with a default info
    let g3 = gh(s, &hobj(s, "noinfo", SnapId::NOSNAP));
    let mut t = OTxn::new();
    t.sys = true;
    t.touch(cid, &g3);
    t.write(cid, &g3, 0, b"data");
    a.ad.with_store(|st| st.commit(&t)).unwrap();
    let o = run(
        &mut a,
        &["--op", "export", "--pgid", "1.2", "--file", fs],
        b"",
    );
    assert_ne!(o.code, 0);
    assert!(o.err.contains("object_info"), "{}", o.err);
    std::fs::remove_file(&f).unwrap();
    let o = run(
        &mut a,
        &["--op", "export", "--force", "--pgid", "1.2", "--file", fs],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    // the object shipped with a default object_info: a successful --force export says so
    assert!(o.err.contains("IGNORED"), "{}", o.err);
    let _ = std::fs::remove_file(&f);
}

#[test]
fn big_omap_attrs_and_many_dups_roundtrip() {
    let mut a = rig(6);
    let s = spg(1, 5);
    make_pg(&a, s, 40);
    let cid = CollT::Pg(s);
    // 12k omap keys (~1.5 MB, far more than one WAL unit) and many attrs on one object
    let h = hobj(s, "rgwindex", SnapId::NOSNAP);
    let g = gh(s, &h);
    let oi = oi_bytes(&h, Eversion::new(3, 30), 0);
    let ss0 = denc::to_vec(&replwire::SnapSet::default()).unwrap();
    let mut t = OTxn::new();
    t.sys = true;
    t.touch(cid, &g);
    t.setattr(cid, &g, b"_", &oi);
    t.setattr(cid, &g, b"snapset", &ss0);
    a.ad.with_store(|st| st.commit(&t)).unwrap();
    let vals: Vec<Vec<u8>> = (0..12_000)
        .map(|i| pattern(100 + i % 50, i as u8))
        .collect();
    let keys: Vec<String> = (0..12_000).map(|i| format!("k{i:06}")).collect();
    for lo in (0..12_000).step_by(200) {
        let mut t = OTxn::new();
        t.sys = true;
        for i in lo..lo + 200 {
            t.omap_set(cid, &g, keys[i].as_bytes(), &vals[i]);
        }
        a.ad.with_store(|st| st.commit(&t)).unwrap();
    }
    // 30 fat keys: one export omap section (25 pairs) carries ~500 KB, more than one WAL unit: the import splits it
    for i in 0..30 {
        let mut t = OTxn::new();
        t.sys = true;
        let (k, v) = (format!("zfat{i:03}"), pattern(20_000, i as u8));
        t.omap_set(cid, &g, k.as_bytes(), &v);
        a.ad.with_store(|st| st.commit(&t)).unwrap();
    }
    // 5000 dup records (appended like the daemon's log trim does)
    let dups: Vec<pgwire::LogDup> = (1..=5000u64)
        .map(|v| pgwire::LogDup {
            reqid: denc::types::OsdReqId {
                name: denc::types::EntityName { ty: 8, num: 4100 },
                tid: v,
                inc: 0,
            },
            version: Eversion::new(2, v),
            user_version: v,
            return_code: 0,
            op_returns: vec![],
        })
        .collect();
    a.ad.try_submit(
        s,
        &peering::StoreTxn {
            ops: vec![peering::StoreOp::LogDups(dups.clone())],
        },
    )
    .unwrap();
    assert_eq!(
        storeadapt::meta::load(&a.ad, s)
            .unwrap()
            .unwrap()
            .log
            .dups
            .len(),
        5000
    );
    let f = std::env::temp_dir().join(format!("ostool-big-{}.export", std::process::id()));
    let fs = f.to_str().unwrap();
    let o = run(
        &mut a,
        &["--op", "export", "--pgid", "1.5", "--file", fs],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    let mut b = rig(6);
    let o = run(&mut b, &["--op", "import", "--file", fs], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(snapshot(&a, s), snapshot(&b, s));
    let (pa, pb) = (
        storeadapt::meta::load(&a.ad, s).unwrap().unwrap(),
        storeadapt::meta::load(&b.ad, s).unwrap().unwrap(),
    );
    assert_eq!(pb.log.dups.len(), 5000);
    assert_eq!(pa, pb);
    assert_eq!(run(&mut remount(b), &["--op", "fsck-deep"], b"").code, 0);
    let _ = std::fs::remove_file(&f);
}

#[test]
fn pending_removal_is_reported_and_removal_resumes() {
    let mut r = rig(6);
    let s = spg(1, 0);
    make_pg(&r, s, 1);
    // a crash during PG deletion leaves the marker: info/export refuse, remove finishes it
    let cid = CollT::Pg(s);
    let pm = storeadapt::pgmeta(s);
    let mut t = OTxn::new();
    t.omap_set(cid, &pm, replwire::pgmeta::REMOVE_KEY.as_bytes(), &[1]);
    r.ad.with_store(|st| st.commit(&t)).unwrap();
    let o = run(&mut r, &["--op", "info", "--pgid", "1.0"], b"");
    assert_ne!(o.code, 0);
    assert!(o.err.contains("being removed"), "{}", o.err);
    assert_eq!(
        run(&mut r, &["--op", "remove", "--pgid", "1.0", "--force"], b"").code,
        0
    );
    assert!(list_pgs(&mut r).is_empty());
}

#[test]
fn option_forms_and_errors() {
    let a: Vec<String> = ["--op=list", "--pgid=1.0", "name", "--format=json"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let o = ostool::Opts::parse(&a).unwrap();
    assert_eq!(o.op.as_deref(), Some("list"));
    assert_eq!(o.pgid.as_deref(), Some("1.0"));
    assert_eq!(o.object.as_deref(), Some("name"));
    assert_eq!(o.format, "json");
    assert!(ostool::Opts::parse(&["--bogus".to_string()]).is_err());
    assert!(ostool::Opts::parse(&["--op".to_string()]).is_err());
    let mut r = rig(6);
    assert!(
        ostool::Opts::parse(&["--format".to_string(), "xml".to_string()]).is_err(),
        "unknown format accepted"
    );
    assert_ne!(run(&mut r, &[], b"").code, 0);
}
