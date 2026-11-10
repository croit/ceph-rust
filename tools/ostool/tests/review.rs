// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Import split/merge clash (classic exit 12), placement filter of objects/log/missing, export durability.
mod common;
use common::*;
use denc::types::{CollT, Eversion, SnapId};
use osd::meta::{MapKind, MetaStore};
use pgwire::{LogEntry, LogOp};
use store::obj::OTxn;

fn export(r: &mut Rig, pgid: &str, f: &std::path::Path) {
    let o = run(
        r,
        &[
            "--op",
            "export",
            "--pgid",
            pgid,
            "--file",
            f.to_str().unwrap(),
        ],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
}

/// Target OSD whose current map (epoch 7) has pool 1 at `pg_num`.
fn target_with_pg_num(pg_num: u32) -> Rig {
    let mut r = rig(6);
    let mut m = osdmap_at(7, &[1]);
    let p = m.pools.get_mut(&1).unwrap();
    p.pg_num = pg_num;
    p.pgp_num = pg_num;
    let mut sb = MetaStore::load_superblock(&r.meta).unwrap().unwrap();
    sb.current_epoch = 7;
    sb.mapc.insert(1, 7);
    r.meta
        .commit_maps(&[(7, MapKind::Full, m.encode_full().unwrap())], &sb)
        .unwrap();
    r
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("ostool-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn import_refuses_split_child_or_merge_target_already_present() {
    let dir = tmpdir("clash");
    let mut a = rig(6);
    make_pg(&a, spg(1, 1), 2);
    make_pg(&a, spg(1, 5), 2);
    let (f1, f5) = (dir.join("1.1"), dir.join("1.5"));
    export(&mut a, "1.1", &f1);
    export(&mut a, "1.5", &f5);

    // split since the export (8 -> 16): child 1.9 of 1.1 already here -> 12, nothing imported
    let mut b = target_with_pg_num(16);
    make_pg(&b, spg(1, 9), 1);
    let o = run(
        &mut b,
        &["--op", "import", "--file", f1.to_str().unwrap()],
        b"",
    );
    assert_eq!(o.code, 12, "{}", o.err);
    assert!(o.err.contains("1.9 exists"), "{}", o.err);
    assert!(o.err.contains("splits"), "{}", o.err);
    assert_eq!(list_pgs(&mut b), vec!["1.9"]);
    // same split, child absent: imported (the daemon splits it when it advances the maps)
    let mut b = target_with_pg_num(16);
    let o = run(
        &mut b,
        &["--op", "import", "--file", f1.to_str().unwrap()],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);

    // merge since the export (8 -> 4): 1.5 merges into 1.1, which is here -> 12
    let mut c = target_with_pg_num(4);
    make_pg(&c, spg(1, 1), 1);
    let o = run(
        &mut c,
        &["--op", "import", "--file", f5.to_str().unwrap()],
        b"",
    );
    assert_eq!(o.code, 12, "{}", o.err);
    assert!(o.err.contains("merges to target 1.1"), "{}", o.err);
    assert_eq!(list_pgs(&mut c), vec!["1.1"]);
    // --force does not bypass it (classic)
    let o = run(
        &mut c,
        &["--op", "import", "--force", "--file", f5.to_str().unwrap()],
        b"",
    );
    assert_eq!(o.code, 12, "{}", o.err);
    // target absent: imported
    let mut c = target_with_pg_num(4);
    let o = run(
        &mut c,
        &["--op", "import", "--file", f5.to_str().unwrap()],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn import_skips_objects_log_and_missing_of_other_pgs() {
    filter_case(rig(6), "filter");
}

/// An export whose embedded map lacks the pool filters against the importing pool's pg_num (it never imports
/// everything unfiltered with clean-looking stats).
#[test]
fn import_filters_when_the_export_map_lacks_the_pool() {
    let disk = new_disk(256);
    let mut a = mount(&disk);
    seed_maps(&mut a, 6, &[2]);
    filter_case(a, "filter-nopool");
}

fn filter_case(mut a: Rig, tag: &str) {
    let dir = tmpdir(tag);
    let s = spg(1, 2);
    make_pg(&a, s, 1);
    // a stray object placed in PG 1.3 by the map (hash & 7 == 3) inside 1.2's collection, with a log entry and a
    // missing item of its own
    let mut h = hobj(s, "stray", SnapId::NOSNAP);
    h.hash = (h.hash & !7) | 3;
    let g = gh(s, &h);
    let cid = CollT::Pg(s);
    let mut t = OTxn::new();
    t.sys = true;
    t.touch(cid, &g);
    t.write(cid, &g, 0, b"stray data");
    let oi = oi_bytes(&h, Eversion::new(3, 50), 10);
    t.setattr(cid, &g, b"_", &oi);
    a.ad.with_store(|st| st.commit(&t)).unwrap();
    let mut p = storeadapt::meta::load(&a.ad, s).unwrap().unwrap();
    let v = Eversion::new(3, p.info.last_update.version + 1);
    p.info.last_update = v;
    p.info.last_complete = v;
    let item = pgwire::MissingItem::new(v, Eversion::default(), false);
    a.ad.try_submit(
        s,
        &peering::StoreTxn {
            ops: vec![
                peering::StoreOp::LogAppend(vec![LogEntry::new(
                    LogOp::MODIFY,
                    h.clone(),
                    v,
                    Eversion::default(),
                )]),
                peering::StoreOp::Missing(vec![(h.clone(), Some(item))]),
                peering::StoreOp::PutInfo(Box::new(p.info.clone())),
            ],
        },
    )
    .unwrap();
    let f = dir.join("1.2");
    export(&mut a, "1.2", &f);

    let mut b = rig(6);
    let o = run(
        &mut b,
        &["--op", "import", "--file", f.to_str().unwrap()],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
    assert!(o.err.contains("Skipping object"), "{}", o.err);
    assert!(o.err.contains("belongs in pg 1.3"), "{}", o.err);
    assert!(
        b.ad.with_store(|st| st.stat(&cid, &g)).unwrap().is_none(),
        "stray object imported"
    );
    let pb = storeadapt::meta::load(&b.ad, s).unwrap().unwrap();
    assert!(
        pb.log.log.iter().all(|e| e.soid != h),
        "stray log entry kept"
    );
    assert_eq!(pb.log.log.len(), p.log.log.len()); // the others are all there
    assert!(!pb.missing.missing.contains_key(&h));
    assert!(pb.info.stats.stats_invalid);
    // every other object made it
    let (sa, sb) = (snapshot(&a, s), snapshot(&b, s));
    assert_eq!(sa.len(), sb.len() + 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn export_refuses_existing_special_file_but_dry_run_works() {
    // Named output must be new: existing special files cannot alias a store device.
    let mut a = rig(6);
    make_pg(&a, spg(1, 4), 1);
    let o = run(
        &mut a,
        &["--op", "export", "--pgid", "1.4", "--file", "/dev/null"],
        b"",
    );
    assert_eq!(o.code, 1, "{}", o.err);
    let o = run(
        &mut a,
        &[
            "--op",
            "export",
            "--pgid",
            "1.4",
            "--dry-run",
            "--file",
            "/nonexistent/x",
        ],
        b"",
    );
    assert_eq!(o.code, 0, "{}", o.err);
}

// A child process gives the test a real regular-file or pipe stdout without changing
// the process-global descriptors of parallel tests.
#[test]
fn export_remove_stdout_child() {
    let Ok(mode) = std::env::var("OSTOOL_EXPORT_STDOUT_TEST") else {
        return;
    };
    let mut r = rig(6);
    make_pg(&r, spg(1, 4), 1);
    let out = run(&mut r, &["--op", "export-remove", "--pgid", "1.4"], b"");
    if mode == "file" && cfg!(target_os = "linux") {
        assert_eq!(out.code, 0, "{}", out.err);
        assert!(list_pgs(&mut r).is_empty());
    } else if mode == "file" {
        // no syncfs(2): the archive's directory entry cannot be made durable, the PG stays
        assert_ne!(out.code, 0, "{}", out.err);
        assert!(out.err.contains("syncfs"), "{}", out.err);
        assert_eq!(list_pgs(&mut r), vec!["1.4"]);
    } else {
        assert_eq!(out.code, 2, "{}", out.err);
        assert!(out.err.contains("use --file"));
        assert_eq!(list_pgs(&mut r), vec!["1.4"]);
    }
}

#[test]
fn export_remove_syncs_regular_stdout_and_refuses_pipe_or_tty() {
    use std::process::{Command, Stdio};
    let dir = tmpdir("stdout");
    for mode in ["file", "pipe"] {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", "export_remove_stdout_child", "--nocapture"])
            .env("OSTOOL_EXPORT_STDOUT_TEST", mode);
        if mode == "file" {
            child.stdout(std::fs::File::create(dir.join("export.bin")).unwrap());
        } else {
            child.stdout(Stdio::piped());
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    // A tty stdout refuses a binary export (asserted in-process: a pty handed to `output()` blocks the child's
    // harness output and the test never returns).
    let mut r = rig(6);
    make_pg(&r, spg(1, 4), 1);
    let out = run(&mut r, &["--op", "export", "--pgid", "1.4", "--tty"], b"");
    assert_eq!(out.code, 1, "{}", out.err);
    assert!(out.err.contains("tty"), "{}", out.err);
    assert_eq!(list_pgs(&mut r), vec!["1.4"]);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Passes `limit` bytes of `buf` through, then freezes the device and fails the read: an import that fails after
/// its first txn, on a device that cannot take the cleanup either.
struct DyingInput {
    disk: store::dev::SimDisk,
    buf: Vec<u8>,
    off: usize,
    limit: usize,
}

impl std::io::Read for DyingInput {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        if self.off >= self.limit {
            self.disk.crash_now();
            return Err(std::io::Error::other("device went away"));
        }
        let n = b
            .len()
            .min(self.limit - self.off)
            .min(self.buf.len() - self.off);
        b[..n].copy_from_slice(&self.buf[self.off..self.off + n]);
        self.off += n;
        Ok(n)
    }
}

#[test]
fn import_failure_names_a_pg_that_stays_marked_for_removal() {
    let dir = tmpdir("cleanup");
    let mut a = rig(6);
    make_pg(&a, spg(1, 4), 3);
    let f = dir.join("1.4");
    export(&mut a, "1.4", &f);
    let bytes = std::fs::read(&f).unwrap();
    let mut b = rig(6);
    let input = DyingInput {
        disk: b.disk.clone(),
        buf: bytes,
        off: 0,
        limit: 32 << 10,
    };
    let o = run_read(&mut b, &["--op", "import", "--file", "-"], Box::new(input));
    assert_ne!(o.code, 0);
    assert!(o.err.contains("device went away"), "{}", o.err);
    assert!(o.err.contains("stays marked for removal"), "{}", o.err);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn export_remove_refuses_nonregular_named_output_without_removing_pg() {
    let mut r = rig(6);
    make_pg(&r, spg(1, 4), 1);
    let out = run(
        &mut r,
        &[
            "--op",
            "export-remove",
            "--pgid",
            "1.4",
            "--file",
            "/dev/null",
        ],
        b"",
    );
    assert_eq!(out.code, 1, "{}", out.err);
    assert!(out.err.contains("File exists"));
    assert_eq!(list_pgs(&mut r), vec!["1.4"]);
}

#[test]
fn json_listing_empty_and_object_roundtrip() {
    let mut r = rig(6);
    let out = run(&mut r, &["--op", "list", "--format", "json"], b"");
    assert_eq!(out.code, 0, "{}", out.err);
    let empty: serde_json::Value = serde_json::from_slice(&out.out).unwrap();
    assert_eq!(empty, serde_json::json!([]));
    make_pg(&r, spg(1, 0), 1);
    let out = run(&mut r, &["--op", "list", "--format", "json"], b"");
    let objects: Vec<serde_json::Value> = serde_json::from_slice(&out.out).unwrap();
    let object = objects.iter().find(|v| v[2]["oid"] == "small").unwrap();
    let out = run(&mut r, &[&object.to_string(), "get-bytes"], b"");
    assert_eq!(out.code, 0, "{}", out.err);
    assert_eq!(out.out, pattern(1000, 1));
}

#[test]
fn named_exports_refuse_existing_files_and_symlinks() {
    let dir = tmpdir("no-clobber");
    let mut r = rig(6);
    make_pg(&r, spg(1, 0), 1);
    let target = dir.join("existing");
    let link = dir.join("symlink");
    std::fs::write(&target, b"must survive").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    for path in [&target, &link] {
        for op in ["export", "export-remove", "get-superblock", "get-osdmap"] {
            let out = run(
                &mut r,
                &[
                    "--op",
                    op,
                    "--pgid",
                    "1.0",
                    "--file",
                    path.to_str().unwrap(),
                ],
                b"",
            );
            assert_ne!(out.code, 0, "{op} clobbered {}", path.display());
            assert_eq!(std::fs::read(&target).unwrap(), b"must survive");
            assert_eq!(list_pgs(&mut r), vec!["1.0"]);
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn set_bytes_replacement_is_atomic_and_preserves_metadata() {
    use store::dev::{CrashPolicy, SimDisk};
    let r = rig(6);
    make_pg(&r, spg(1, 0), 1);
    let cid = CollT::Pg(spg(1, 0));
    let g = gh(spg(1, 0), &hobj(spg(1, 0), "omapobj", SnapId::NOSNAP));
    r.ad.with_store(|s| s.checkpoint()).unwrap();
    let image = r.disk.image();
    let config = r.disk.config();
    let original_attrs = r.ad.with_store(|s| s.getattrs(&cid, &g)).unwrap();
    let original_omap = r.ad.with_store(|s| s.omap_all(&cid, &g)).unwrap();
    let mut state = 9u64;
    let replacement: Vec<u8> = (0..8 * 1024 * 1024 + 1)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    // Derive an interruption point after the first former 4 MiB batch would be durable.
    let mut baseline = mount(&SimDisk::from_image(&image, config.clone()));
    let start = baseline.disk.events();
    let out = run(
        &mut baseline,
        &["--pgid", "1.0", "omapobj", "set-bytes"],
        &replacement[..4 << 20],
    );
    assert_eq!(out.code, 0, "{}", out.err);
    let cut = baseline.disk.events() - start;
    let mut interrupted = mount(&SimDisk::from_image(&image, config.clone()));
    interrupted.disk.arm_crash(interrupted.disk.events() + cut);
    let out = run(
        &mut interrupted,
        &["--pgid", "1.0", "omapobj", "set-bytes"],
        &replacement,
    );
    assert_ne!(out.code, 0);
    let disk = SimDisk::from_image(&interrupted.disk.crash_image(CrashPolicy::DROP_ALL), config);
    let recovered = mount(&disk);
    assert_eq!(
        recovered
            .ad
            .with_store(|s| s.stat(&cid, &g))
            .unwrap()
            .unwrap()
            .size,
        0
    );
    assert_eq!(
        recovered.ad.with_store(|s| s.getattrs(&cid, &g)).unwrap(),
        original_attrs
    );
    assert_eq!(
        recovered.ad.with_store(|s| s.omap_all(&cid, &g)).unwrap(),
        original_omap
    );
    let mut success = recovered;
    let out = run(
        &mut success,
        &["--pgid", "1.0", "omapobj", "set-bytes"],
        &replacement,
    );
    assert_eq!(out.code, 0, "{}", out.err);
    let success = remount(success);
    assert_eq!(
        success
            .ad
            .with_store(|s| s.read(&cid, &g, 0, replacement.len() as u64))
            .unwrap(),
        replacement
    );
    assert_eq!(
        success.ad.with_store(|s| s.getattrs(&cid, &g)).unwrap(),
        original_attrs
    );
    assert_eq!(
        success.ad.with_store(|s| s.omap_all(&cid, &g)).unwrap(),
        original_omap
    );
    assert_eq!(
        success.ad.with_store(|s| s.omap_header(&cid, &g)).unwrap(),
        b"header-bytes"
    );
}

#[test]
fn set_bytes_accepts_the_object_size_limit() {
    let disk = new_disk(1024);
    let mut r = mount(&disk);
    seed_maps(&mut r, 6, &[1]);
    make_pg(&r, spg(1, 0), 1);
    let data = vec![0x5a; ostool::MAX_INPUT as usize];
    let out = run(&mut r, &["--pgid", "1.0", "small", "set-bytes"], &data);
    assert_eq!(out.code, 0, "{}", out.err);
    let g = gh(spg(1, 0), &hobj(spg(1, 0), "small", SnapId::NOSNAP));
    assert_eq!(
        r.ad.with_store(|s| s.stat(&CollT::Pg(spg(1, 0)), &g))
            .unwrap()
            .unwrap()
            .size,
        data.len() as u64
    );
}

#[test]
fn export_streams_into_an_existing_fifo_but_export_remove_refuses_it() {
    let dir = tmpdir("fifo");
    let fifo = dir.join("pipe");
    let st = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(st.success());
    let mut r = rig(6);
    make_pg(&r, spg(1, 0), 1);
    let path = fifo.to_str().unwrap().to_owned();
    // export-remove refuses before it opens (an open would block without a reader) and keeps the PG
    let out = run(
        &mut r,
        &["--op", "export-remove", "--pgid", "1.0", "--file", &path],
        b"",
    );
    assert_eq!(out.code, 1, "{}", out.err);
    assert!(out.err.contains("File exists"), "{}", out.err);
    assert_eq!(list_pgs(&mut r), vec!["1.0"]);
    // a plain export streams to the FIFO's reader (e.g. `ssh host 'cat > x' < fifo`)
    let reader = {
        let fifo = fifo.clone();
        std::thread::spawn(move || std::fs::read(fifo).unwrap())
    };
    let out = run(
        &mut r,
        &["--op", "export", "--pgid", "1.0", "--file", &path],
        b"",
    );
    assert_eq!(out.code, 0, "{}", out.err);
    let streamed = reader.join().unwrap();
    assert!(!streamed.is_empty());
    let new = dir.join("new.export");
    let out = run(
        &mut r,
        &[
            "--op",
            "export",
            "--pgid",
            "1.0",
            "--file",
            new.to_str().unwrap(),
        ],
        b"",
    );
    assert_eq!(out.code, 0, "{}", out.err);
    assert_eq!(std::fs::read(&new).unwrap(), streamed);
    std::fs::remove_dir_all(dir).unwrap();
}
