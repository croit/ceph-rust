// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
#![cfg(feature = "native")]
use nvmeosd_splinterdb::{Database, IoMode, Options};
struct Temp(std::path::PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn default_io_is_buffered_and_direct_remains_explicit() {
    assert_eq!(Options::default().io, IoMode::Buffered);
    assert_eq!("direct".parse::<IoMode>().unwrap(), IoMode::Direct);
    let dir = std::env::temp_dir().join(format!("sdb-default-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let _temp = Temp(dir.clone());
    let mut db = Database::open(&dir.join("db"), 64 << 20, 128 << 20, true).unwrap();
    assert!(!db.read_stats().unwrap().direct);
    db.close().unwrap();
}
#[test]
fn requested_io_mode_matches_descriptor_and_cache_counters_are_explicit() {
    for io in [IoMode::Direct, IoMode::Buffered] {
        let dir = std::env::temp_dir().join(format!("sdb-io-{}-{io:?}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let _temp = Temp(dir.clone());
        let path = dir.join("db");
        let options = Options {
            io,
            prefetch_bytes: 256 << 10,
            cache_stats: true,
            normal_maintenance: false,
            memtable_maintenance: false,
            checkpoint_log_bytes: 0,
            defer_log_writeback: false,
            no_log: false,
        };
        let mut db =
            Database::open_with_options(&path, 64 << 20, 128 << 20, true, options).unwrap();
        let before = db.read_stats().unwrap();
        assert!(before.valid);
        assert_eq!(before.direct, io == IoMode::Direct);
        assert_eq!(before.cache_bytes, 64 << 20);
        assert_eq!(before.prefetch_bytes, 256 << 10);
        for i in 0..500u32 {
            db.put(&i.to_be_bytes(), &i.to_le_bytes()).unwrap();
        }
        db.durable_barrier().unwrap();
        for i in 0..500u32 {
            assert_eq!(
                db.get(&i.to_be_bytes(), 4).unwrap().unwrap(),
                i.to_le_bytes()
            );
        }
        let after = db.read_stats().unwrap();
        assert!(after.hits > before.hits);
        assert!(after.engine_write_bytes >= before.engine_write_bytes);
        db.close().unwrap();
        let mut db = Database::open_with_options(
            &path,
            64 << 20,
            0,
            false,
            Options {
                io,
                ..Default::default()
            },
        )
        .unwrap();
        let sample = db.read_stats().unwrap();
        assert!(!sample.valid);
        assert_eq!(sample.hits, 0);
        assert_eq!(sample.direct, io == IoMode::Direct);
        for i in 0..500u32 {
            assert_eq!(
                db.get(&i.to_be_bytes(), 4).unwrap().unwrap(),
                i.to_le_bytes()
            );
        }
        db.close().unwrap();
        drop(db);
    }
}

#[test]
fn deferred_log_writeback_moves_log_writes_to_the_barrier() {
    // ~3k log pages of updates fit the 64 MiB cache: without deferral the
    // inserting thread writes them as they fill; with it, the barrier does.
    let mut before_barrier = Vec::new();
    for defer in [false, true] {
        let dir = std::env::temp_dir().join(format!("sdb-defer-{}-{defer}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let _temp = Temp(dir.clone());
        let path = dir.join("db");
        let options = Options {
            io: IoMode::Buffered,
            cache_stats: true,
            prefetch_bytes: 256 << 10,
            defer_log_writeback: defer,
            ..Default::default()
        };
        let mut db =
            Database::open_with_options(&path, 64 << 20, 256 << 20, true, options).unwrap();
        let start = db.read_stats().unwrap().engine_write_bytes;
        for i in 0..40_000u32 {
            db.put(&i.to_be_bytes(), &[9; 256]).unwrap();
        }
        let filled = db.read_stats().unwrap().engine_write_bytes - start;
        db.durable_barrier().unwrap();
        let synced = db.read_stats().unwrap().engine_write_bytes - start;
        assert!(
            synced >= 8 << 20,
            "defer={defer}: barrier wrote the log ({synced})"
        );
        before_barrier.push(filled);
        db.close().unwrap();
        let db = Database::open_with_options(&path, 64 << 20, 0, false, options).unwrap();
        for i in (0..40_000u32).step_by(997) {
            assert_eq!(db.get(&i.to_be_bytes(), 256).unwrap(), Some(vec![9; 256]));
        }
    }
    assert!(
        before_barrier[1] * 4 < before_barrier[0],
        "deferred log writes before the barrier: {before_barrier:?}"
    );
}
