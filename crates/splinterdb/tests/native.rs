// SPDX-License-Identifier: LGPL-3.0-only
#![cfg(feature = "native")]
use nvmeosd_splinterdb::Database;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "nvmeosd-splinter-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn file(&self) -> PathBuf {
        self.0.join("image")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
const CACHE: u64 = 64 << 20;
const DISK: u64 = 128 << 20;

#[test]
fn maintenance_rejects_racy_statistics_before_creating_an_image() {
    let tmp = Temp::new();
    let options = nvmeosd_splinterdb::Options {
        normal_maintenance: true,
        cache_stats: true,
        ..Default::default()
    };
    let error = Database::open_with_options(&tmp.file(), CACHE, DISK, true, options).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(!tmp.file().exists());
}

#[test]
fn effective_assistance_policy_is_isolated_to_the_existing_normal_helper() {
    use nvmeosd_splinterdb::{IoMode, Options};
    for normal_maintenance in [false, true] {
        for io in [IoMode::Buffered, IoMode::Direct] {
            let tmp = Temp::new();
            let options = Options {
                io,
                normal_maintenance,
                prefetch_bytes: 1 << 20,
                ..Default::default()
            };
            for create in [true, false] {
                let mut db = Database::open_with_options(
                    &tmp.file(),
                    CACHE,
                    if create { DISK } else { 0 },
                    create,
                    options,
                )
                .unwrap();
                let maintenance = db.maintenance_stats().unwrap();
                assert_eq!(maintenance.normal_workers, u64::from(normal_maintenance));
                assert_eq!(maintenance.memtable_workers, 0, "memtable helper is opt-in");
                // Independent literal expectations, not an exported implementation constant.
                assert_eq!(
                    maintenance.queue_scale_percent,
                    if normal_maintenance { 101 } else { 0 }
                );
                let reads = db.read_stats().unwrap();
                assert!(!reads.valid);
                assert_eq!(reads.cache_bytes, CACHE);
                assert_eq!(reads.prefetch_bytes, 1 << 20);
                assert_eq!(reads.direct, io == IoMode::Direct);
                db.close().unwrap();
            }
        }
    }
}

#[test]
fn normal_maintenance_preserves_updates_and_closes_pending_work_in_both_io_modes() {
    use nvmeosd_splinterdb::{IoMode, Options};
    for io in [IoMode::Buffered, IoMode::Direct] {
        for final_barrier in [false, true] {
            let tmp = Temp::new();
            let options = Options {
                io,
                normal_maintenance: true,
                ..Default::default()
            };
            let mut db =
                Database::open_with_options(&tmp.file(), CACHE, 256 << 20, true, options).unwrap();
            let maintenance = db.maintenance_stats().unwrap();
            assert_eq!(maintenance.normal_workers, 1);
            assert_eq!(maintenance.memtable_workers, 0);
            assert_eq!(maintenance.queue_scale_percent, 101);
            assert!(!db.read_stats().unwrap().valid);
            for round in 0..4u8 {
                for key in 0..16384u64 {
                    db.put(&key.to_be_bytes(), &[round; 512]).unwrap();
                }
                if round != 3 || final_barrier {
                    db.durable_barrier().unwrap();
                }
            }
            // Do not assume the barrier empties every maintenance queue. Close must
            // join the pool and retain all acknowledged data even with work pending.
            db.close().unwrap();
            assert_eq!(
                db.maintenance_stats().unwrap_err().raw_os_error(),
                Some(libc::EBADF)
            );
            let mut reopened =
                Database::open_with_options(&tmp.file(), CACHE, 0, false, options).unwrap();
            for key in 0..16384u64 {
                assert_eq!(
                    reopened.get(&key.to_be_bytes(), 512).unwrap(),
                    Some(vec![3; 512])
                );
            }
            // Exact ordered contents, not just representative point reads. No future
            // writes are needed to drive the final generation through close/reopen.
            let mut cursor = reopened.cursor(b"", false, None).unwrap();
            for key in 0..16384u64 {
                let (actual, value) = cursor.current().unwrap().unwrap();
                assert_eq!(actual, key.to_be_bytes());
                assert_eq!(value, [3; 512]);
                cursor.advance().unwrap();
            }
            assert!(cursor.current().unwrap().is_none());
            drop(cursor);
            reopened.close().unwrap();
        }
    }
}

#[test]
fn multiple_handles_and_repeated_opens_share_then_release_the_caller_registration() {
    let first = Temp::new();
    let second = Temp::new();
    let mut a = Database::open(&first.file(), CACHE, DISK, true).unwrap();
    let mut b = Database::open(&second.file(), CACHE, DISK, true).unwrap();
    a.close().unwrap();
    b.put(b"still-open", b"kept").unwrap();
    b.durable_barrier().unwrap();
    b.close().unwrap();
    // More than the native thread-ID-table size, on the same persistent caller.
    for _ in 0..80 {
        let mut db = Database::open(&second.file(), CACHE, 0, false).unwrap();
        assert_eq!(db.get(b"still-open", 4).unwrap(), Some(b"kept".to_vec()));
        db.close().unwrap();
    }
}

#[test]
fn failed_open_does_not_steal_the_next_callers_registration() {
    let tmp = Temp::new();
    for _ in 0..4 {
        assert!(Database::open(&tmp.0.join("missing-parent/image"), CACHE, DISK, true).is_err());
    }
    let mut db = Database::open(&tmp.file(), CACHE, DISK, true).unwrap();
    db.put(b"ok", b"ok").unwrap();
    db.close().unwrap();
}

#[test]
fn async_io_priming_is_read_only_repeatable_and_works_in_both_modes() {
    use nvmeosd_splinterdb::{IoMode, Options};
    for io in [IoMode::Buffered, IoMode::Direct] {
        let tmp = Temp::new();
        let options = Options {
            io,
            ..Options::default()
        };
        let mut db = Database::open_with_options(&tmp.file(), CACHE, DISK, true, options).unwrap();
        db.prime_io().unwrap();
        db.put(b"binary\0key", b"kept").unwrap();
        db.put(b"", b"").unwrap();
        db.durable_barrier().unwrap();
        for _ in 0..16 {
            db.prime_io().unwrap();
        }
        assert_eq!(db.get(b"binary\0key", 4).unwrap(), Some(b"kept".to_vec()));
        assert_eq!(db.get(b"", 0).unwrap(), Some(Vec::new()));
        db.close().unwrap();
        assert_eq!(db.prime_io().unwrap_err().raw_os_error(), Some(libc::EBADF));
        let mut db = Database::open_with_options(&tmp.file(), CACHE, 0, false, options).unwrap();
        db.prime_io().unwrap();
        assert_eq!(db.get(b"binary\0key", 4).unwrap(), Some(b"kept".to_vec()));
        db.close().unwrap();
    }
}

#[test]
fn binary_empty_and_large_values_survive_close_and_reopen() {
    let tmp = Temp::new();
    let mut db = Database::open(&tmp.file(), CACHE, DISK, true).unwrap();
    let mut expected = std::collections::BTreeMap::new();
    for (k, v) in [
        (vec![], vec![]),
        (vec![0, 255, 1], vec![91; 32768]),
        (vec![255; 9000], vec![13; 8192]),
    ] {
        db.put(&k, &v).unwrap();
        expected.insert(k, v);
    }
    db.durable_barrier().unwrap();
    assert!(db.get(&[0, 255, 1], 16).is_err());
    assert!(Database::open(&tmp.file(), CACHE, DISK, true).is_err());
    db.close().unwrap();
    let mut db = Database::open(&tmp.file(), CACHE, 0, false).unwrap();
    for (k, v) in &expected {
        assert_eq!(db.get(k, usize::MAX).unwrap().as_ref(), Some(v));
    }
    assert!(db.get(b"missing", 1).unwrap().is_none());
    let mut cursor = db.cursor(b"", false, None).unwrap();
    let mut got = std::collections::BTreeMap::new();
    while let Some((k, v)) = cursor.current().unwrap() {
        got.insert(k.to_vec(), v.to_vec());
        cursor.advance().unwrap();
    }
    assert_eq!(got, expected);
    drop(cursor);
    db.delete(&[0, 255, 1]).unwrap();
    db.durable_barrier().unwrap();
    assert!(db.get(&[0, 255, 1], usize::MAX).unwrap().is_none());
    db.close().unwrap();
    assert!(db.get(b"", 1).is_err());
}

#[test]
fn reusable_lookup_owns_results_and_resets_after_missing_empty_and_oversized() {
    let tmp = Temp::new();
    let mut db = Database::open(&tmp.file(), CACHE, DISK, true).unwrap();
    let key = vec![255; 9000];
    let large = vec![19; 32768];
    db.put(b"", b"").unwrap();
    db.put(&key, &large).unwrap();
    db.put(b"binary\0", b"small").unwrap();
    {
        let mut lookup = db.lookup().unwrap();
        for _ in 0..64 {
            assert_eq!(
                lookup.get(&key, 10).unwrap_err().raw_os_error(),
                Some(libc::E2BIG)
            );
            assert_eq!(lookup.get(b"absent", 0).unwrap(), None);
            let owned = lookup.get(&key, usize::MAX).unwrap().unwrap();
            assert_eq!(lookup.get(b"", 0).unwrap(), Some(Vec::new()));
            assert_eq!(lookup.get(b"binary\0", 5).unwrap(), Some(b"small".to_vec()));
            assert_eq!(owned, large, "subsequent reuse must not change owned bytes");
        }
    }
    db.delete(&key).unwrap();
    db.durable_barrier().unwrap();
    assert_eq!(db.lookup().unwrap().get(&key, usize::MAX).unwrap(), None);
    db.close().unwrap();
    assert!(db.lookup().is_err());
}

#[test]
fn iterator_bounds_and_exclusive_resume_match_independent_model() {
    let tmp = Temp::new();
    let mut db = Database::open(&tmp.file(), CACHE, DISK, true).unwrap();
    for i in 0..70u8 {
        db.put(&[0, i], &[i, 255]).unwrap();
    }
    db.put(&[1, 0], b"foreign").unwrap();
    let mut cursor = db.cursor(&[0, 31], true, Some(&[0, 40])).unwrap();
    let mut got = Vec::new();
    while let Some((k, v)) = cursor.current().unwrap() {
        got.push((k.to_vec(), v.to_vec()));
        cursor.advance().unwrap();
    }
    assert_eq!(
        got,
        (32..40u8)
            .map(|i| (vec![0, i], vec![i, 255]))
            .collect::<Vec<_>>()
    );
    drop(cursor);
    db.close().unwrap();
    let missing = tmp.0.join("missing");
    assert!(Database::open(&missing, CACHE, 0, false).is_err());
    assert!(!missing.exists());
}

#[test]
fn durable_child() {
    let Some(path) = std::env::var_os("NVMEOSD_SPLINTER_CRASH_FILE") else {
        return;
    };
    let mut db = Database::open(std::path::Path::new(&path), CACHE, DISK, true).unwrap();
    for i in 0..64u32 {
        db.put(&i.to_be_bytes(), &i.to_le_bytes()).unwrap();
    }
    db.durable_barrier().unwrap();
    // No close, destructor, allocator cleanup or orderly checkpoint.
    unsafe { libc::_exit(0) }
}

#[test]
fn explicit_barrier_survives_abrupt_process_exit_without_close() {
    let tmp = Temp::new();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "durable_child", "--nocapture"])
        .env("NVMEOSD_SPLINTER_CRASH_FILE", tmp.file())
        .status()
        .unwrap();
    assert!(status.success());
    let mut db = Database::open(&tmp.file(), CACHE, 0, false).unwrap();
    for i in 0..64u32 {
        assert_eq!(
            db.get(&i.to_be_bytes(), 4).unwrap(),
            Some(i.to_le_bytes().to_vec())
        );
    }
    db.close().unwrap();
}

#[test]
fn memtable_maintenance_needs_normal_maintenance_and_runs_one_memtable_worker() {
    use nvmeosd_splinterdb::Options;
    let tmp = Temp::new();
    let alone = Options {
        memtable_maintenance: true,
        ..Default::default()
    };
    let error = Database::open_with_options(&tmp.file(), CACHE, DISK, true, alone).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(!tmp.file().exists());
    let both = Options {
        normal_maintenance: true,
        memtable_maintenance: true,
        ..Default::default()
    };
    let mut db = Database::open_with_options(&tmp.file(), CACHE, DISK, true, both).unwrap();
    let m = db.maintenance_stats().unwrap();
    assert_eq!(
        (m.normal_workers, m.memtable_workers, m.queue_scale_percent),
        (1, 1, 101)
    );
    // Enough writes to cycle several memtables through the helper.
    for i in 0..60_000u32 {
        db.put(&i.to_be_bytes(), &[7; 200]).unwrap();
    }
    db.durable_barrier().unwrap();
    db.close().unwrap();
    let db = Database::open_with_options(&tmp.file(), CACHE, 0, false, both).unwrap();
    for i in (0..60_000u32).step_by(997) {
        assert_eq!(db.get(&i.to_be_bytes(), 256).unwrap(), Some(vec![7; 200]));
    }
}

#[test]
fn registered_mutators_apply_disjoint_keys_concurrently() {
    use nvmeosd_splinterdb::{Mutator, Options};
    let tmp = Temp::new();
    let options = Options {
        normal_maintenance: true,
        memtable_maintenance: true,
        ..Default::default()
    };
    let mut db = Database::open_with_options(&tmp.file(), CACHE, DISK, true, options).unwrap();
    let handle = db.shared_handle().unwrap();
    std::thread::scope(|s| {
        for t in 0..3u32 {
            s.spawn(move || {
                // SAFETY: the scope joins every mutator before the database closes.
                let mut m = unsafe { Mutator::attach(handle) }.unwrap();
                for i in 0..20_000u32 {
                    let k = (t * 20_000 + i).to_be_bytes();
                    if i % 5 == 4 {
                        m.put(&k, b"gone").unwrap();
                        m.delete(&k).unwrap();
                    } else {
                        m.put(&k, &t.to_le_bytes()).unwrap();
                    }
                }
            });
        }
        // The owner keeps its own keyspace concurrently.
        for i in 60_000..61_000u32 {
            db.put(&i.to_be_bytes(), b"owner").unwrap();
        }
    });
    db.durable_barrier().unwrap();
    db.close().unwrap();
    let db = Database::open_with_options(&tmp.file(), CACHE, 0, false, options).unwrap();
    for t in 0..3u32 {
        for i in (0..20_000u32).step_by(7) {
            let got = db.get(&(t * 20_000 + i).to_be_bytes(), 16).unwrap();
            let want = (i % 5 != 4).then(|| t.to_le_bytes().to_vec());
            assert_eq!(got, want, "thread {t} key {i}");
        }
    }
    assert_eq!(
        db.get(&60_500u32.to_be_bytes(), 16).unwrap(),
        Some(b"owner".to_vec())
    );
}

/// Measurement, not a gate (`--ignored`): apply time of sorted 80k-key batches
/// (64 B keys, 256 B values, three registered threads on contiguous ranges) with
/// and without the library log, plus the barrier after each batch.
#[test]
#[ignore = "measurement; run explicitly with --ignored --nocapture"]
fn measure_apply_and_barrier_cost_with_and_without_the_library_log() {
    use nvmeosd_splinterdb::{Mutator, Options};
    const BATCH: u32 = 80_000;
    const BATCHES: u32 = 8;
    for no_log in [false, true] {
        for defer in [false, true] {
            if no_log && defer {
                continue;
            }
            let tmp = Temp::new();
            let options = Options {
                normal_maintenance: true,
                memtable_maintenance: true,
                checkpoint_log_bytes: 1 << 30,
                defer_log_writeback: defer,
                no_log,
                ..Default::default()
            };
            let mut db =
                Database::open_with_options(&tmp.file(), 128 << 20, 4 << 30, true, options)
                    .unwrap();
            let handle = db.shared_handle().unwrap();
            let (mut apply, mut barrier) = (std::time::Duration::ZERO, std::time::Duration::ZERO);
            for b in 0..BATCHES {
                let t0 = std::time::Instant::now();
                std::thread::scope(|s| {
                    for t in 0..3u32 {
                        s.spawn(move || {
                            // SAFETY: joined by the scope before the database closes.
                            let mut m = unsafe { Mutator::attach(handle) }.unwrap();
                            let per = BATCH / 3;
                            for i in t * per..(t + 1) * per {
                                // Updates of the same 80k keys after the first batch.
                                let mut k = [7u8; 64];
                                k[..4].copy_from_slice(&i.to_be_bytes());
                                m.put(&k, &[b as u8; 256]).unwrap();
                            }
                        });
                    }
                });
                apply += t0.elapsed();
                let t1 = std::time::Instant::now();
                db.durable_barrier().unwrap();
                barrier += t1.elapsed();
            }
            let keys = f64::from(BATCH * BATCHES);
            eprintln!(
                "no_log={no_log} defer={defer}: apply {:.0} ms ({:.2} us/key wall), barriers {:.0} ms ({:.1} ms each)",
                apply.as_secs_f64() * 1e3,
                apply.as_secs_f64() * 1e6 / keys,
                barrier.as_secs_f64() * 1e3,
                barrier.as_secs_f64() * 1e3 / f64::from(BATCHES)
            );
            db.close().unwrap();
        }
    }
}
