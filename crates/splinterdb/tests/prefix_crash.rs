// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
//! Independent durable-prefix vectors; process loss, not physical power loss.
#![cfg(feature = "native")]
use nvmeosd_splinterdb::{Database, IoMode, Options};
use std::path::PathBuf;
const CACHE: u64 = 64 << 20;
const DISK: u64 = 256 << 20;
const MARK: &[u8] = b"watermark";
/// Update rounds before the abrupt exits: with a large checkpoint size the extra
/// rounds (~70MB of log) cross the default checkpoint size without a checkpoint,
/// so recovery must replay the log alone.
fn rounds(checkpoint: u64) -> u8 {
    if checkpoint == 0 { 4 } else { 8 }
}
fn final_effects(db: &mut Database) {
    db.put(b"a", b"new-a").unwrap();
    db.delete(b"b").unwrap();
    db.put(b"c", b"new-c").unwrap();
}
#[test]
fn prefix_crash_child() {
    let Some(path) = std::env::var_os("NVMEOSD_PREFIX_IMAGE") else {
        return;
    };
    let phase = std::env::var("NVMEOSD_PREFIX_PHASE").unwrap();
    let normal_maintenance = std::env::var("NVMEOSD_PREFIX_MAINTENANCE").unwrap() == "true";
    let checkpoint: u64 = std::env::var("NVMEOSD_PREFIX_CHECKPOINT")
        .unwrap()
        .parse()
        .unwrap();
    let defer = std::env::var("NVMEOSD_PREFIX_DEFER").unwrap() == "true";
    let no_log = std::env::var("NVMEOSD_PREFIX_NOLOG").unwrap() == "true";
    let io = std::env::var("NVMEOSD_PREFIX_IO")
        .unwrap()
        .parse::<IoMode>()
        .unwrap();
    let mut db = Database::open_with_options(
        std::path::Path::new(&path),
        CACHE,
        DISK,
        true,
        Options {
            io,
            normal_maintenance,
            checkpoint_log_bytes: checkpoint,
            defer_log_writeback: defer,
            no_log,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(db.read_stats().unwrap().direct, io == IoMode::Direct);
    let maintenance = db.maintenance_stats().unwrap();
    assert_eq!(maintenance.normal_workers, u64::from(normal_maintenance));
    assert_eq!(maintenance.memtable_workers, 0);
    assert_eq!(
        maintenance.queue_scale_percent,
        if normal_maintenance { 101 } else { 0 }
    );
    if normal_maintenance {
        // Exercise updates/packing with the pool live before each abrupt prefix
        // exit. This does not assert that a task is executing at the exit instant.
        for round in 0..rounds(checkpoint) {
            for key in 0..16384u64 {
                db.put(&key.to_be_bytes(), &[round; 512]).unwrap();
                if key % 256 == 0 {
                    assert_eq!(db.maintenance_stats().unwrap().normal_workers, 1);
                }
            }
            db.durable_barrier().unwrap();
        }
    }
    db.put(b"a", b"old-a").unwrap();
    db.put(b"b", b"old-b").unwrap();
    db.put(MARK, &1u64.to_le_bytes()).unwrap();
    db.durable_barrier().unwrap();
    db.put(b"a", b"new-a").unwrap();
    if phase == "partial" {
        // Force a known partial effect to survive while retaining the old mark.
        db.durable_barrier().unwrap();
        unsafe { libc::_exit(0) }
    }
    final_effects(&mut db);
    db.durable_barrier().unwrap();
    if phase == "data" {
        unsafe { libc::_exit(0) }
    }
    db.put(MARK, &2u64.to_le_bytes()).unwrap();
    db.durable_barrier().unwrap();
    unsafe { libc::_exit(0) }
}
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn prefix_crashes_never_publish_mark_before_data_and_ordered_redo_is_idempotent() {
    prefix_crashes(false, 0);
}

#[test]
fn maintenance_prefix_crashes_preserve_barriers_and_ordered_redo() {
    prefix_crashes(true, 0);
}

#[test]
fn large_checkpoint_prefix_crashes_recover_barriers_from_the_log_alone() {
    prefix_crashes(true, 192 << 20);
}

#[test]
fn deferred_log_writeback_prefix_crashes_preserve_barriers() {
    // Filled log pages are issued only by the barrier's wait: every barrier-covered
    // prefix must still survive abrupt exits, with and without checkpoints.
    prefix_crashes_with(true, 0, true);
    prefix_crashes_with(true, 192 << 20, true);
    prefix_crashes_with(false, 0, true);
}

fn prefix_crashes(normal_maintenance: bool, checkpoint: u64) {
    prefix_crashes_with(normal_maintenance, checkpoint, false);
}

fn prefix_crashes_with(normal_maintenance: bool, checkpoint: u64, defer: bool) {
    prefix_crashes_mode(normal_maintenance, checkpoint, defer, false);
}

fn prefix_crashes_mode(normal_maintenance: bool, checkpoint: u64, defer: bool, no_log: bool) {
    for io in ["direct", "buffered"] {
        for phase in ["partial", "data", "watermark"] {
            let path = std::env::temp_dir().join(format!(
                "sdb-prefix-{}-{io}-{phase}-{normal_maintenance}-{checkpoint}-{defer}-{no_log}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            let t = Temp(path);
            let file = t.0.join("db");
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "prefix_crash_child", "--nocapture"])
                .env("NVMEOSD_PREFIX_IMAGE", &file)
                .env("NVMEOSD_PREFIX_PHASE", phase)
                .env("NVMEOSD_PREFIX_IO", io)
                .env("NVMEOSD_PREFIX_MAINTENANCE", normal_maintenance.to_string())
                .env("NVMEOSD_PREFIX_CHECKPOINT", checkpoint.to_string())
                .env("NVMEOSD_PREFIX_DEFER", defer.to_string())
                .env("NVMEOSD_PREFIX_NOLOG", no_log.to_string())
                .status()
                .unwrap();
            assert!(status.success());
            let options = Options {
                io: io.parse().unwrap(),
                normal_maintenance,
                checkpoint_log_bytes: checkpoint,
                defer_log_writeback: defer,
                no_log,
                ..Default::default()
            };
            let mut db = Database::open_with_options(&file, CACHE, 0, false, options).unwrap();
            assert_eq!(
                db.maintenance_stats().unwrap().queue_scale_percent,
                if normal_maintenance { 101 } else { 0 }
            );
            if normal_maintenance {
                for key in 0..16384u64 {
                    assert_eq!(
                        db.get(&key.to_be_bytes(), 512).unwrap(),
                        Some(vec![rounds(checkpoint) - 1; 512])
                    );
                }
            }
            let mark = db.get(MARK, 8).unwrap().unwrap();
            assert_eq!(
                mark,
                if phase == "watermark" { 2u64 } else { 1u64 }.to_le_bytes()
            );
            assert_eq!(db.get(b"a", 32).unwrap().unwrap(), b"new-a");
            if phase == "partial" {
                assert_eq!(db.get(b"b", 32).unwrap().unwrap(), b"old-b");
                assert!(db.get(b"c", 32).unwrap().is_none());
            } else {
                assert!(db.get(b"b", 32).unwrap().is_none());
                assert_eq!(db.get(b"c", 32).unwrap().unwrap(), b"new-c");
            }
            // Native redo would supply this ordered complete transaction above mark1.
            for _ in 0..2 {
                final_effects(&mut db);
                db.durable_barrier().unwrap();
                db.put(MARK, &2u64.to_le_bytes()).unwrap();
                db.durable_barrier().unwrap();
            }
            db.close().unwrap();
            let mut db = Database::open_with_options(&file, CACHE, 0, false, options).unwrap();
            assert_eq!(db.get(b"a", 32).unwrap().unwrap(), b"new-a");
            assert!(db.get(b"b", 32).unwrap().is_none());
            assert_eq!(db.get(b"c", 32).unwrap().unwrap(), b"new-c");
            db.close().unwrap();
        }
    }
}

#[test]
fn no_log_prefix_crashes_recover_every_checkpointed_barrier() {
    // Without the library log a barrier checkpoints the tree: abrupt exits after
    // each barrier must recover exactly the checkpointed prefix and mark order.
    prefix_crashes_mode(true, 0, false, true);
    prefix_crashes_mode(false, 0, false, true);
}
