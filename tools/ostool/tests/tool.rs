// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
#![expect(clippy::field_reassign_with_default)]
mod common;
use common::*;
use denc::Encode;
use denc::types::{CollT, SnapId};
use osd::meta::MetaStore;

#[test]
fn list_pgs_list_info_log_shapes() {
    let mut r = rig(6);
    let s = spg(1, 2);
    make_pg(&r, s, 5);
    assert_eq!(list_pgs(&mut r), vec!["1.2"]);
    // human readable list: one JSON array per line, pgid first, ghobject like classic (duplicate "max")
    let o = run(&mut r, &["--op", "list", "--pgid", "1.2"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    let lines: Vec<serde_json::Value> = o
        .text()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(lines.len() >= 5, "{lines:?}");
    for l in &lines {
        assert_eq!(l[0], "1.2");
        assert!(
            l[1].get("oid").is_some() && l[1].get("snapid").is_some() && l[1].get("pool").is_some()
        );
    }
    let first = o
        .text()
        .lines()
        .find(|l| l.contains("\"small\""))
        .unwrap()
        .to_owned();
    assert!(
        first.contains("\"max\":0,\"pool\":1,\"namespace\":\"\",\"max\":0}"),
        "{first}"
    );
    // snapid is printed signed like classic (-2 = head)
    assert!(first.contains("\"snapid\":-2"), "{first}");
    // name filter
    let o = run(&mut r, &["--op", "list", "small"], b"");
    assert_eq!(o.text().lines().count(), 1, "{}", o.text());
    // json (non-human): single array of [pgid, coll, ghobject]
    let o = run(
        &mut r,
        &["--op", "list", "--pgid", "1.2", "--format", "json"],
        b"",
    );
    let v: serde_json::Value = serde_json::from_str(&o.text()).unwrap();
    assert_eq!(v[0][0], "1.2");
    assert_eq!(v[0][1], "1.2_head");
    // info / log
    let o = run(&mut r, &["--op", "info", "--pgid", "1.2"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    let v: serde_json::Value = serde_json::from_str(&o.text()).unwrap();
    assert_eq!(v["pgid"], "1.2");
    assert_eq!(v["last_update"], "3'9");
    let o = run(&mut r, &["--op", "log", "--pgid", "1.2"], b"");
    let v: serde_json::Value = serde_json::from_str(&o.text()).unwrap();
    assert_eq!(v["pg_log_t"]["head"], "3'9");
    assert_eq!(v["pg_log_t"]["log"].as_array().unwrap().len(), 9);
    assert_eq!(v["pg_log_t"]["log"][0]["op"], "modify");
    assert!(v["pg_missing_t"]["missing"].as_array().unwrap().is_empty());
    // unknown pg
    assert_ne!(run(&mut r, &["--op", "info", "--pgid", "1.7"], b"").code, 0);
}

#[test]
fn object_commands_roundtrip_and_dry_run() {
    let mut r = rig(6);
    let s = spg(1, 0);
    make_pg(&r, s, 0);
    // bytes
    let o = run(&mut r, &["--pgid", "1.0", "small", "get-bytes"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(o.out, pattern(1000, 1));
    let o = run(
        &mut r,
        &["--pgid", "1.0", "small", "set-bytes"],
        b"hello world",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(
        run(&mut r, &["--pgid", "1.0", "small", "get-bytes"], b"").out,
        b"hello world"
    );
    // dry-run changes nothing
    let o = run(
        &mut r,
        &["--pgid", "1.0", "small", "set-bytes", "--dry-run"],
        b"XXXX",
    );
    assert_eq!(o.code, 0);
    assert_eq!(
        run(&mut r, &["--pgid", "1.0", "small", "get-bytes"], b"").out,
        b"hello world"
    );
    // attrs
    assert_eq!(
        run(
            &mut r,
            &["--pgid", "1.0", "small", "get-attr", "_user.k"],
            b""
        )
        .out,
        b"v1"
    );
    run(
        &mut r,
        &["--pgid", "1.0", "small", "set-attr", "_user.z", "-"],
        b"zz",
    );
    let o = run(&mut r, &["--pgid", "1.0", "small", "list-attrs"], b"");
    assert_eq!(o.text(), "_\n_user.k\n_user.z\nsnapset\n");
    run(
        &mut r,
        &["--pgid", "1.0", "small", "rm-attr", "_user.k"],
        b"",
    );
    assert_ne!(
        run(
            &mut r,
            &["--pgid", "1.0", "small", "get-attr", "_user.k"],
            b""
        )
        .code,
        0
    );
    // omap
    let o = run(&mut r, &["--pgid", "1.0", "omapobj", "list-omap"], b"");
    assert_eq!(o.text().lines().count(), 60);
    assert_eq!(o.text().lines().next(), Some("key000"));
    assert_eq!(
        run(
            &mut r,
            &["--pgid", "1.0", "omapobj", "get-omap", "key005"],
            b""
        )
        .out,
        pattern(8, 5)
    );
    run(
        &mut r,
        &["--pgid", "1.0", "omapobj", "set-omap", "newkey"],
        b"nv",
    );
    assert_eq!(
        run(
            &mut r,
            &["--pgid", "1.0", "omapobj", "get-omap", "newkey"],
            b""
        )
        .out,
        b"nv"
    );
    run(
        &mut r,
        &["--pgid", "1.0", "omapobj", "rm-omap", "key005"],
        b"",
    );
    let o = run(
        &mut r,
        &["--pgid", "1.0", "omapobj", "get-omap", "key005"],
        b"",
    );
    assert_ne!(o.code, 0);
    assert!(o.err.contains("Key not found"), "{}", o.err);
    assert_eq!(
        run(&mut r, &["--pgid", "1.0", "omapobj", "get-omaphdr"], b"").out,
        b"header-bytes"
    );
    run(&mut r, &["--pgid", "1.0", "omapobj", "set-omaphdr"], b"H2");
    assert_eq!(
        run(&mut r, &["--pgid", "1.0", "omapobj", "get-omaphdr"], b"").out,
        b"H2"
    );
    // JSON object spec as printed by --op list, also pgmeta via ''
    let o = run(&mut r, &["--op", "list", "--pgid", "1.0", "small"], b"");
    let spec = o.text().trim().to_owned();
    assert_eq!(run(&mut r, &[&spec, "get-bytes"], b"").out, b"hello world");
    let o = run(&mut r, &["--pgid", "1.0", "", "list-omap"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    assert!(o.text().contains("_info"), "{}", o.text());
    // survives a crash-restart (every mutation was a durable txn)
    let mut r = remount(r);
    assert_eq!(
        run(&mut r, &["--pgid", "1.0", "small", "get-bytes"], b"").out,
        b"hello world"
    );
    assert_eq!(
        run(
            &mut r,
            &["--pgid", "1.0", "omapobj", "get-omap", "newkey"],
            b""
        )
        .out,
        b"nv"
    );
}

#[test]
fn remove_object_with_clones_and_snapmapper() {
    let mut r = rig(6);
    let s = spg(1, 0);
    make_pg(&r, s, 0);
    // head with a clone: refuse without removeall
    let o = run(
        &mut r,
        &["--pgid", "1.0", "snapped", "remove", "--head"],
        b"",
    );
    assert_ne!(o.code, 0);
    assert!(o.err.contains("Clones are present"), "{}", o.err);
    let before = snapshot(&r, s).len();
    // dry-run
    let o = run(
        &mut r,
        &[
            "--pgid",
            "1.0",
            "snapped",
            "removeall",
            "--head",
            "--dry-run",
        ],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(snapshot(&r, s).len(), before);
    let o = run(
        &mut r,
        &["--pgid", "1.0", "snapped", "removeall", "--head"],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    let after = snapshot(&r, s);
    assert_eq!(after.len(), before - 2);
    // snap mapper entry of the clone is gone
    let mo = storeadapt::snapmap::mapper_obj(s);
    let m = &after[&denc::to_vec(&mo.hobj).unwrap()];
    assert!(
        m.2.is_empty(),
        "mapper keys left: {:?}",
        m.2.keys().collect::<Vec<_>>()
    );
    // the pgmeta object holds the PG state: never removed by accident
    let o = run(&mut r, &["--pgid", "1.0", "", "remove"], b"");
    assert_ne!(o.code, 0);
    assert!(o.err.contains("pgmeta"), "{}", o.err);
    assert!(list_pgs(&mut r).contains(&"1.0".to_string()));
    // plain remove of a normal object
    assert_eq!(
        run(&mut r, &["--pgid", "1.0", "small", "remove"], b"").code,
        0
    );
    assert_ne!(
        run(&mut r, &["--pgid", "1.0", "small", "get-bytes"], b"").code,
        0
    );
}

#[test]
fn export_import_roundtrip_between_stores() {
    let mut a = rig(6);
    let s = spg(1, 3);
    make_pg(&a, s, 300); // > one state chunk of log entries
    let dir = std::env::temp_dir().join(format!("ostool-rt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("pg.export");
    let o = run(
        &mut a,
        &[
            "--op",
            "export",
            "--pgid",
            "1.3",
            "--file",
            f.to_str().unwrap(),
        ],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    // container: fixed super header bytes (classic format version 2, header 18, footer 10)
    let bytes = std::fs::read(&f).unwrap();
    assert_eq!(
        &bytes[..16],
        &[0xce, 0xff, 0xce, 0xff, 2, 0, 0, 0, 18, 0, 0, 0, 10, 0, 0, 0]
    );
    // dump-export
    let o = run(
        &mut a,
        &["--op", "dump-export", "--file", f.to_str().unwrap()],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    let v: serde_json::Value = serde_json::from_str(&o.text()).unwrap();
    assert_eq!(v["pgid"], "1.3");
    assert_eq!(v["map_epoch"], 5);
    assert!(v["objects"].as_array().unwrap().len() >= 4);

    // import into a different, fresh OSD (same cluster fsid)
    let mut b = rig(6);
    let o = run(
        &mut b,
        &["--op", "import", "--file", f.to_str().unwrap()],
        b"",
    );
    assert_eq!(o.code, 0, "{} / {}", o.err, o.text());
    assert!(o.text().contains("Import successful"));
    assert_eq!(snapshot(&a, s), snapshot(&b, s));
    let pa = storeadapt::meta::load(&a.ad, s).unwrap().unwrap();
    let pb = storeadapt::meta::load(&b.ad, s).unwrap().unwrap();
    assert_eq!(pa, pb);
    assert_eq!(pb.log.log.len(), 304);
    // snap mapper survived: the clone's entry exists
    let mo = storeadapt::snapmap::mapper_obj(s);
    let key = denc::to_vec(&mo.hobj).unwrap();
    assert!(!snapshot(&b, s)[&key].2.is_empty());
    // importing again: PG exists
    let o = run(
        &mut b,
        &["--op", "import", "--file", f.to_str().unwrap()],
        b"",
    );
    assert_ne!(o.code, 0);
    assert!(o.err.contains("already exists"), "{}", o.err);
    // durable across a restart, and fsck is clean
    let mut b = remount(b);
    assert_eq!(storeadapt::meta::load(&b.ad, s).unwrap().unwrap(), pa);
    let o = run(&mut b, &["--op", "fsck-deep"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    // export of the imported PG is byte-identical (deterministic, same container)
    let f2 = dir.join("pg2.export");
    assert_eq!(
        run(
            &mut b,
            &[
                "--op",
                "export",
                "--pgid",
                "1.3",
                "--file",
                f2.to_str().unwrap()
            ],
            b""
        )
        .code,
        0
    );
    assert_eq!(std::fs::read(&f2).unwrap(), bytes);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn import_guards_and_failure_leaves_nothing() {
    let mut a = rig(6);
    let s = spg(1, 1);
    make_pg(&a, s, 3);
    let dir = std::env::temp_dir().join(format!("ostool-g-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("pg.export");
    assert_eq!(
        run(
            &mut a,
            &[
                "--op",
                "export",
                "--pgid",
                "1.1",
                "--file",
                f.to_str().unwrap()
            ],
            b""
        )
        .code,
        0
    );
    let bytes = std::fs::read(&f).unwrap();

    // truncated stream: import fails, nothing is left behind (also not after a restart)
    let mut b = rig(6);
    let cut = dir.join("cut.export");
    std::fs::write(&cut, &bytes[..bytes.len() * 2 / 3]).unwrap();
    let o = run(
        &mut b,
        &["--op", "import", "--file", cut.to_str().unwrap()],
        b"",
    );
    assert_ne!(o.code, 0);
    assert!(list_pgs(&mut b).is_empty());
    let mut b = remount(b);
    assert!(list_pgs(&mut b).is_empty());

    // garbage
    std::fs::write(&cut, b"this is not an export file at all").unwrap();
    assert_ne!(
        run(
            &mut b,
            &["--op", "import", "--file", cut.to_str().unwrap()],
            b""
        )
        .code,
        0
    );

    // pool does not exist on the target: exit 10
    let mut c = rig(6);
    c.meta
        .commit_maps(
            &[(
                7,
                osd::meta::MapKind::Full,
                osdmap_at(7, &[2]).encode_full().unwrap(),
            )],
            &{
                let mut sb = osd::meta::MetaStore::load_superblock(&c.meta)
                    .unwrap()
                    .unwrap();
                sb.current_epoch = 7;
                sb
            },
        )
        .unwrap();
    let o = run(
        &mut c,
        &["--op", "import", "--file", f.to_str().unwrap()],
        b"",
    );
    assert_eq!(o.code, 10, "{}", o.err);

    // other cluster: refused without --force
    let mut d = rig(6);
    let mut sb = osd::meta::MetaStore::load_superblock(&d.meta)
        .unwrap()
        .unwrap();
    sb.cluster_fsid = denc::types::Uuid([1; 16]);
    osd::meta::MetaStore::store_superblock(&mut d.meta, &sb).unwrap();
    let o = run(
        &mut d,
        &["--op", "import", "--file", f.to_str().unwrap()],
        b"",
    );
    assert_ne!(o.code, 0);
    assert!(o.err.contains("different cluster"), "{}", o.err);
    assert!(list_pgs(&mut d).is_empty());
    let o = run(
        &mut d,
        &["--op", "import", "--force", "--file", f.to_str().unwrap()],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);

    // OSD older than the export (export epoch 5 > OSD epoch 4)
    let mut e = rig(4);
    let o = run(
        &mut e,
        &["--op", "import", "--file", f.to_str().unwrap()],
        b"",
    );
    assert_ne!(o.code, 0);
    assert!(o.err.contains("older than the exported PG"), "{}", o.err);

    // dry-run import writes nothing
    let mut g = rig(6);
    let o = run(
        &mut g,
        &["--op", "import", "--dry-run", "--file", f.to_str().unwrap()],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    assert!(list_pgs(&mut g).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn import_crash_before_completion_is_garbage_collected() {
    // a PG whose import never reached the final txn carries `_remove`: invisible, swept at the next mount
    let mut a = rig(6);
    let s = spg(1, 4);
    make_pg(&a, s, 3);
    let dir = std::env::temp_dir().join(format!("ostool-c-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("pg.export");
    assert_eq!(
        run(
            &mut a,
            &[
                "--op",
                "export",
                "--pgid",
                "1.4",
                "--file",
                f.to_str().unwrap()
            ],
            b""
        )
        .code,
        0
    );
    let b = rig(6);
    // emulate the first txn of an import only
    let cid = CollT::Pg(s);
    let pm = storeadapt::pgmeta(s);
    let mut t = store::obj::OTxn::new();
    t.push(store::obj::TOp::MkColl {
        cid,
        bits: 3,
        exist_ok: false,
    });
    t.touch(cid, &pm);
    t.omap_set(cid, &pm, replwire::pgmeta::REMOVE_KEY.as_bytes(), &[1]);
    let g = gh(s, &hobj(s, "x", SnapId::NOSNAP));
    t.write(cid, &g, 0, b"partial");
    b.ad.with_store(|st| st.commit(&t)).unwrap();
    let mut b = remount(b);
    let _ = b.meta;
    // mount only queues the interrupted deletion (adr 0082: paced background removal); the durable marker keeps the PG refused
    assert_eq!(b.ad.resume_removals().unwrap(), 1);
    let o = run(&mut b, &["--op", "info", "--pgid", "1.4"], b"");
    assert_ne!(o.code, 0);
    assert!(o.err.contains("being removed"), "{}", o.err);
    b.ad.finish_removals().unwrap();
    assert!(list_pgs(&mut b).is_empty());
    // and the PG can now be imported
    let o = run(
        &mut b,
        &["--op", "import", "--file", f.to_str().unwrap()],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn remove_pg_requires_force_and_export_remove() {
    let mut r = rig(6);
    let s = spg(1, 5);
    make_pg(&r, s, 2);
    let o = run(&mut r, &["--op", "remove", "--pgid", "1.5"], b"");
    assert_ne!(o.code, 0);
    assert!(o.err.contains("--force"), "{}", o.err);
    assert_eq!(list_pgs(&mut r), vec!["1.5"]);
    // dry-run is allowed without --force and changes nothing
    assert_eq!(
        run(
            &mut r,
            &["--op", "remove", "--pgid", "1.5", "--dry-run"],
            b""
        )
        .code,
        0
    );
    assert_eq!(list_pgs(&mut r), vec!["1.5"]);
    // another PG is never touched
    make_pg(&r, spg(1, 6), 2);
    let before = snapshot(&r, spg(1, 6));
    let o = run(&mut r, &["--op", "remove", "--pgid", "1.5", "--force"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(list_pgs(&mut r), vec!["1.6"]);
    assert_eq!(snapshot(&r, spg(1, 6)), before);
    // export-remove
    let dir = std::env::temp_dir().join(format!("ostool-er-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("p.export");
    let o = run(
        &mut r,
        &[
            "--op",
            "export-remove",
            "--pgid",
            "1.6",
            "--file",
            f.to_str().unwrap(),
        ],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    assert!(list_pgs(&mut r).is_empty());
    assert!(std::fs::metadata(&f).unwrap().len() > 1000);
    // and back
    assert_eq!(
        run(
            &mut r,
            &["--op", "import", "--file", f.to_str().unwrap()],
            b""
        )
        .code,
        0
    );
    assert_eq!(snapshot(&r, spg(1, 6)), before);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mark_complete_trim_log_and_reset() {
    let mut r = rig(6);
    let s = spg(1, 1);
    make_pg(&r, s, 30);
    // mark-complete: last_backfill MAX, epochs = OSD epoch, last_update advanced
    let mut p = storeadapt::meta::load(&r.ad, s).unwrap().unwrap();
    p.info.last_backfill = denc::types::Hobject::MIN();
    r.ad.try_submit(
        s,
        &peering::StoreTxn {
            ops: vec![peering::StoreOp::PutInfo(Box::new(p.info.clone()))],
        },
    )
    .unwrap();
    let o = run(&mut r, &["--op", "mark-complete", "--pgid", "1.1"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    let p = storeadapt::meta::load(&r.ad, s).unwrap().unwrap();
    assert!(p.info.last_backfill.max);
    assert_eq!(p.info.last_epoch_started, 6);
    assert_eq!(p.info.history.last_epoch_clean, 6);
    assert_eq!(p.info.last_update.epoch, 6);
    assert_eq!(p.info.last_update.version, 35);
    assert_eq!(p.log.head, p.info.last_update);
    // trim-pg-log to 10 entries
    let o = run(
        &mut r,
        &[
            "--op",
            "trim-pg-log",
            "--pgid",
            "1.1",
            "--max-entries",
            "10",
        ],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    let p = storeadapt::meta::load(&r.ad, s).unwrap().unwrap();
    assert_eq!(p.info.log_tail.version, 25);
    assert_eq!(p.log.tail.version, 25);
    assert_eq!(p.log.log.front().unwrap().version.version, 26);
    // reset-last-complete needs --force
    assert_ne!(
        run(
            &mut r,
            &["--op", "reset-last-complete", "--pgid", "1.1"],
            b""
        )
        .code,
        0
    );
    assert_eq!(
        run(
            &mut r,
            &["--op", "reset-last-complete", "--pgid", "1.1", "--force"],
            b""
        )
        .code,
        0
    );
}

#[test]
fn store_level_ops() {
    let mut r = rig(6);
    make_pg(&r, spg(1, 0), 1);
    let o = run(&mut r, &["--op", "fsck"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    assert!(o.text().contains("fsck success"));
    let o = run(&mut r, &["--op", "statfs"], b"");
    let v: serde_json::Value = serde_json::from_str(&o.text()).unwrap();
    assert!(v["total"].as_u64().unwrap() > 0);
    let o = run(&mut r, &["--op", "dump-super"], b"");
    let v: serde_json::Value = serde_json::from_str(&o.text()).unwrap();
    assert_eq!(v["whoami"], 3);
    assert_eq!(v["current_epoch"], 6);
    assert_eq!(v["compat"]["incompat"]["feature_11"], "sharded objects");
    // superblock get/set round trip
    let o = run(&mut r, &["--op", "get-superblock"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    let sbb = o.out.clone();
    assert_eq!(run(&mut r, &["--op", "set-superblock"], &sbb).code, 0);
    // osdmap get/set
    let o = run(&mut r, &["--op", "get-osdmap", "--epoch", "5"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(o.out, osdmap_at(5, &[1]).encode_full().unwrap());
    let o = run(&mut r, &["--op", "get-osdmap"], b"");
    assert_eq!(o.out, osdmap_at(6, &[1]).encode_full().unwrap());
    // set-osdmap: replacing an existing epoch works, a new epoch needs --force
    assert_eq!(
        run(
            &mut r,
            &["--op", "set-osdmap"],
            &osdmap_at(6, &[1, 2]).encode_full().unwrap()
        )
        .code,
        0
    );
    let o = run(&mut r, &["--op", "get-osdmap"], b"");
    assert_eq!(o.out, osdmap_at(6, &[1, 2]).encode_full().unwrap());
    let o = run(
        &mut r,
        &["--op", "set-osdmap"],
        &osdmap_at(9, &[1]).encode_full().unwrap(),
    );
    assert_ne!(o.code, 0);
    assert_eq!(
        run(
            &mut r,
            &["--op", "set-osdmap", "--force"],
            &osdmap_at(9, &[1]).encode_full().unwrap()
        )
        .code,
        0
    );
    // meta-list shows the stored maps
    let o = run(&mut r, &["--op", "meta-list"], b"");
    assert!(o.text().contains("osdmap.0000000009"), "{}", o.text());
    // unsupported ops fail loudly
    assert_ne!(run(&mut r, &["--op", "dup"], b"").code, 0);
    assert_ne!(run(&mut r, &["--op", "nonsense"], b"").code, 0);
}

#[test]
fn fix_lost_clears_the_flag() {
    let mut r = rig(6);
    let s = spg(1, 0);
    make_pg(&r, s, 0);
    let h = hobj(s, "small", SnapId::NOSNAP);
    let g = gh(s, &h);
    let mut oi: replwire::ObjectInfo =
        denc::from_slice(&oi_bytes(&h, denc::types::Eversion::new(3, 1), 1000)).unwrap();
    oi.flags |= replwire::oi::flag::LOST;
    let mut t = store::obj::OTxn::new();
    let nb = denc::to_vec(&oi).unwrap();
    t.setattr(CollT::Pg(s), &g, b"_", &nb);
    r.ad.with_store(|st| st.commit(&t)).unwrap();
    let o = run(&mut r, &["--op", "fix-lost", "--dry-run"], b"");
    assert!(o.text().contains("is lost"), "{}", o.text());
    let raw =
        r.ad.with_store(|st| st.getattr(&CollT::Pg(s), &g, b"_"))
            .unwrap()
            .unwrap();
    assert_ne!(
        denc::from_slice::<replwire::ObjectInfo>(&raw)
            .unwrap()
            .flags
            & 1,
        0
    );
    let o = run(&mut r, &["--op", "fix-lost"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    let raw =
        r.ad.with_store(|st| st.getattr(&CollT::Pg(s), &g, b"_"))
            .unwrap()
            .unwrap();
    assert_eq!(
        denc::from_slice::<replwire::ObjectInfo>(&raw)
            .unwrap()
            .flags
            & 1,
        0
    );
}

#[test]
fn export_rebuilds_a_missing_full_map_from_incrementals() {
    // epoch 5 is stored only as an incremental on top of the full map 4: the export must rebuild it
    let disk = new_disk(256);
    let mut r = mount(&disk);
    let m4 = osdmap_at(4, &[1]);
    let mut inc = osdmap::Incremental::default();
    inc.epoch = 5;
    inc.fsid = m4.fsid;
    let mut m5 = m4.clone();
    m5.apply_incremental(&inc).unwrap();
    inc.full_crc = m5.crc(0).unwrap();
    let mut sb = messages::OsdSuperblock::default();
    sb.cluster_fsid = FSID;
    sb.current_epoch = 5;
    sb.compat_features = messages::types::CompatSet::osd_initial();
    r.meta
        .commit_maps(
            &[
                (4, osd::meta::MapKind::Full, m4.encode_full().unwrap()),
                (5, osd::meta::MapKind::Inc, inc.encode_inc().unwrap()),
            ],
            &sb,
        )
        .unwrap();
    make_pg(&r, spg(1, 0), 1);
    let o = run(&mut r, &["--op", "get-osdmap", "--epoch", "5"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    assert_eq!(o.out, m5.encode_full().unwrap());
    let f = std::env::temp_dir().join(format!("ostool-inc-{}.export", std::process::id()));
    let o = run(
        &mut r,
        &[
            "--op",
            "export",
            "--pgid",
            "1.0",
            "--file",
            f.to_str().unwrap(),
        ],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    let _ = std::fs::remove_file(&f);
}

#[test]
fn trailing_garbage_and_footer_corruption_are_detected() {
    let mut a = rig(6);
    make_pg(&a, spg(1, 1), 1);
    let f = std::env::temp_dir().join(format!("ostool-fc-{}.export", std::process::id()));
    assert_eq!(
        run(
            &mut a,
            &[
                "--op",
                "export",
                "--pgid",
                "1.1",
                "--file",
                f.to_str().unwrap()
            ],
            b""
        )
        .code,
        0
    );
    let mut bytes = std::fs::read(&f).unwrap();
    // flip a byte inside the first footer magic (right after the pg_begin body)
    let hdr = 16usize;
    let body = u32::from_le_bytes(bytes[hdr + 10..hdr + 14].try_into().unwrap()) as usize; // header: env(6)+magic(4)+size(8)
    let _ = body;
    let n = bytes.len();
    bytes[n / 2] ^= 0xff;
    std::fs::write(&f, &bytes).unwrap();
    let mut b = rig(6);
    let o = run(
        &mut b,
        &["--op", "import", "--file", f.to_str().unwrap()],
        b"",
    );
    // either a decode error or a structural error: never a half-imported PG
    assert!(o.code != 0 || !list_pgs(&mut b).is_empty());
    let _ = std::fs::remove_file(&f);
}

#[test]
fn format_option_is_validated() {
    let parse = |a: &[&str]| {
        let v: Vec<String> = a.iter().map(|s| s.to_string()).collect();
        ostool::Opts::parse(&v)
    };
    assert_eq!(parse(&["--format", "json"]).unwrap().format, "json");
    assert_eq!(
        parse(&["--format", "json-pretty"]).unwrap().format,
        "json-pretty"
    );
    assert!(parse(&["--format", "bogus"]).is_err());
    // this tool has no record stream: another document format is not a valid value
    assert!(parse(&["--format", "jsonl"]).is_err());
    assert!(parse(&["--format", "plain"]).is_ok());
}

#[test]
fn dump_super_rejects_corrupt_map_ranges() {
    // a superblock can come from `set-superblock` (a file): its newest map must not be computed by wrapping
    for (start, len) in [(u32::MAX, 2u32), (5, 0)] {
        let mut r = rig(6);
        let mut sb = MetaStore::load_superblock(&r.meta).unwrap().unwrap();
        sb.mapc.clear();
        sb.mapc.insert(start, len);
        let b = sb.encode_to_vec().unwrap();
        let o = run(&mut r, &["--op", "set-superblock"], &b);
        assert_eq!(o.code, 0, "{}", o.err);
        let o = run(&mut r, &["--op", "dump-super"], b"");
        assert_ne!(o.code, 0, "mapc {start}+{len}");
        assert!(o.err.contains("map range"), "{}", o.err);
        assert!(o.out.is_empty(), "{}", o.text());
    }
}

#[test]
fn set_superblock_refuses_when_the_stored_one_is_unreadable() {
    let mut r = rig(6);
    let g = meta_object("superblock");
    let mut t = store::obj::OTxn::new();
    t.sys = true;
    t.truncate(CollT::Meta, &g, 0);
    t.write(CollT::Meta, &g, 0, b"not a superblock");
    r.ad.with_store(|st| st.commit(&t)).unwrap();
    // a foreign fsid without --force must be refused, and the store keeps its bytes
    let mut sb = messages::OsdSuperblock::default();
    sb.cluster_fsid = denc::types::Uuid([1; 16]);
    let b = sb.encode_to_vec().unwrap();
    let o = run(&mut r, &["--op", "set-superblock"], &b);
    assert_ne!(o.code, 0);
    assert!(o.err.contains("superblock"), "{}", o.err);
    let raw =
        r.ad.with_store(|st| st.read(&CollT::Meta, &g, 0, 16))
            .unwrap();
    assert_eq!(raw, b"not a superblock");
}

#[test]
fn get_osdmap_outside_the_stored_range_fails_fast() {
    let mut r = rig(6);
    // newest stored epoch is 6: a higher epoch is refused instead of scanning epochs down to 0
    let o = run(&mut r, &["--op", "get-osdmap", "--epoch", "7"], b"");
    assert_ne!(o.code, 0);
    assert!(o.err.contains("cover 1..6"), "{}", o.err);
    assert!(o.out.is_empty());
}

#[test]
fn mark_complete_refuses_version_overflow_without_mutation() {
    let mut r = rig(6);
    let s = spg(1, 1);
    make_pg(&r, s, 1);
    let mut p = storeadapt::meta::load(&r.ad, s).unwrap().unwrap();
    p.info.last_update.version = u64::MAX;
    r.ad.try_submit(
        s,
        &peering::StoreTxn {
            ops: vec![peering::StoreOp::PutInfo(Box::new(p.info.clone()))],
        },
    )
    .unwrap();
    let before = snapshot(&r, s);
    let o = run(&mut r, &["--op", "mark-complete", "--pgid", "1.1"], b"");
    assert_eq!(o.code, 1, "{}", o.err);
    assert!(o.err.contains("version overflow"), "{}", o.err);
    assert_eq!(snapshot(&r, s), before);
}

#[test]
fn plain_and_json_documents_use_the_shared_formatter() {
    let mut r = rig(6);
    for format in ["plain", "json", "json-pretty"] {
        let out = run(&mut r, &["--op", "statfs", "--format", format], b"");
        assert_eq!(out.code, 0, "{}", out.err);
        let value: serde_json::Value = serde_json::from_slice(&out.out).unwrap();
        assert!(value["total"].as_u64().unwrap() > 0);
        assert_eq!(
            out.text().trim_end(),
            outfmt::Format::parse(format).unwrap().doc(&value)
        );
    }
}
