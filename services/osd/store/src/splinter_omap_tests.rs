// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
use super::*;
static NEXT: AtomicU64 = AtomicU64::new(0);
#[test]
fn splinter_default_io_policy_is_buffered() {
    assert_eq!(
        Config::new(PathBuf::from("/unused"), 0).io,
        IoMode::Buffered
    );
    let cfg = Config::new(PathBuf::from("/unused"), 0);
    assert!(!cfg.isolate_cleaner);
    assert!(!cfg.normal_maintenance);
    assert_eq!(cfg.cleaner_cpu, None);
}

#[test]
fn splinter_normal_maintenance_requires_explicit_placement_and_accounts_for_stack() {
    let mut cfg = Config::new(PathBuf::from("/unused"), 0);
    cfg.normal_maintenance = true;
    assert!(cfg.options(64 << 20).is_err());
    cfg.isolate_cleaner = true;
    for pair in [
        (None, None),
        (Some(11), None),
        (None, Some(17)),
        (Some(11), Some(11)),
    ] {
        (cfg.cpu, cfg.cleaner_cpu) = pair;
        assert!(!cfg.options(64 << 20).unwrap().normal_maintenance);
    }
    cfg.cpu = Some(11);
    cfg.cleaner_cpu = Some(17);
    assert!(cfg.options(64 << 20).unwrap().normal_maintenance);
    cfg.cache_stats = true;
    assert!(cfg.options(64 << 20).is_err());
    assert_eq!(maintenance_read_budget(128 << 20, 0).unwrap(), 32 << 20);
    assert_eq!(
        maintenance_read_budget(128 << 20, 8 << 20).unwrap(),
        24 << 20
    );
    assert!(maintenance_read_budget(128 << 20, 32 << 20).is_err());
    assert!(maintenance_read_budget(128 << 20, usize::MAX).is_err());
}

#[test]
fn splinter_cleaner_open_order_and_failure_drop_are_explicit() {
    use std::cell::RefCell;
    struct Opened<'a>(&'a RefCell<Vec<&'static str>>);
    impl Drop for Opened<'_> {
        fn drop(&mut self) {
            self.0.borrow_mut().push("close");
        }
    }
    for failure in [
        None,
        Some("pin-cleaner"),
        Some("open"),
        Some("prime"),
        Some("pin-worker"),
    ] {
        let events = RefCell::new(Vec::new());
        let run = open_with_cleaner(
            (Some(11), Some(17)),
            |cpu| {
                let event = if cpu == Some(17) {
                    "pin-cleaner"
                } else {
                    assert_eq!(cpu, Some(11));
                    "pin-worker"
                };
                events.borrow_mut().push(event);
                if failure == Some(event) {
                    Err(StoreError::Failed)
                } else {
                    Ok(())
                }
            },
            || {
                events.borrow_mut().push("open");
                if failure == Some("open") {
                    Err(StoreError::Failed)
                } else {
                    Ok(Opened(&events))
                }
            },
            |_| {
                events.borrow_mut().push("prime");
                if failure == Some("prime") {
                    Err(StoreError::Failed)
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(run.is_err(), failure.is_some());
        drop(run);
        let expected: &[&str] = match failure {
            Some("pin-cleaner") => &["pin-cleaner"],
            Some("open") => &["pin-cleaner", "open"],
            Some("prime") => &["pin-cleaner", "open", "prime", "close"],
            _ => &["pin-cleaner", "open", "prime", "pin-worker", "close"],
        };
        assert_eq!(&*events.borrow(), expected);
    }
    for cpus in [(Some(11), None), (Some(11), Some(11)), (None, Some(17))] {
        let mut opened = false;
        let db = open_with_cleaner(
            cpus,
            |_| panic!("legacy path must not repin"),
            || {
                opened = true;
                Ok(42)
            },
            |_| panic!("legacy path must not force async IO"),
        )
        .unwrap();
        assert!(opened);
        assert_eq!(db, 42);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn splinter_cleaner_affinity_and_owned_startup_cleanup() {
    // Isolate /proc thread counting from other concurrently running library tests.
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "splinter_omap::tests::splinter_cleaner_affinity_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("NVMEOSD_CLEANER_AFFINITY_CHILD", "1")
        .spawn()
        .unwrap();
    let end = Instant::now() + Duration::from_secs(45);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() >= end {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("WARNING TIMEOUT owned cleaner affinity regression");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn splinter_cleaner_affinity_child() {
    if std::env::var_os("NVMEOSD_CLEANER_AFFINITY_CHILD").as_deref()
        != Some(std::ffi::OsStr::new("1"))
    {
        return;
    }
    fn masks(name: &str) -> Vec<String> {
        std::fs::read_dir("/proc/self/task")
            .unwrap()
            .filter_map(|e| {
                let p = e.unwrap().path();
                if std::fs::read_to_string(p.join("comm")).ok()?.trim() != name {
                    return None;
                }
                let status = std::fs::read_to_string(p.join("status")).ok()?;
                Some(
                    status
                        .lines()
                        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
                        .unwrap()
                        .trim()
                        .to_owned(),
                )
            })
            .collect()
    }
    let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut mask) },
        0
    );
    let allowed: Vec<_> = (0..libc::CPU_SETSIZE as usize)
        .filter(|&c| unsafe { libc::CPU_ISSET(c, &mask) })
        .collect();
    assert!(!allowed.is_empty());
    let worker = allowed[0];
    let cleaner = *allowed.last().unwrap();
    for io in [IoMode::Buffered, IoMode::Direct] {
        let (_t, mut cfg, sb) = setup_io(io);
        cfg.cpu = Some(worker);
        cfg.isolate_cleaner = true;
        cfg.cleaner_cpu = Some(libc::CPU_SETSIZE as usize);
        let space = Space::join(&cfg.root).unwrap();
        assert!(Client::open(&cfg, &sb, 0, 128 << 20, 0, 0).is_err());
        assert!(masks("omap-splinter-0").is_empty());
        assert!(masks("laio_cleaner").is_empty());
        assert_eq!(
            space.reserved.load(Ordering::Acquire),
            0,
            "startup error joins lease/lock teardown"
        );
        for (index, (isolate, selected, normal)) in [
            (true, Some(cleaner), false),
            (true, None, false),
            (false, Some(cleaner), false),
            (true, Some(worker), false),
            (true, Some(cleaner), true),
        ]
        .into_iter()
        .enumerate()
        {
            cfg.isolate_cleaner = isolate;
            cfg.cleaner_cpu = selected;
            cfg.normal_maintenance = normal;
            let mut c = Client::open(&cfg, &sb, 0, 128 << 20, 0, 10).unwrap();
            let offload = normal && selected.is_some_and(|c| c != worker);
            assert_eq!(c.read_gauges()[26], u64::from(offload));
            if offload {
                assert!(c.read_budget < 32 << 20);
                assert!(c.read_gauges()[28] > 0);
            }
            if isolate && selected.is_some_and(|c| c != worker) {
                assert_eq!(
                    masks("laio_cleaner"),
                    vec![cleaner.to_string()],
                    "cleaner must be placed before the first normal request"
                );
            }
            let lsn = index as u64 + 1;
            let mut m = Memtable::new();
            m.put(
                lsn,
                1,
                Bytes::from_static(b"kept"),
                Bytes::from_static(b"value"),
            );
            c.flush(Arc::new(m)).unwrap();
            let end = Instant::now() + Duration::from_secs(10);
            while c.flushed != Some(lsn) {
                assert!(
                    Instant::now() < end,
                    "WARNING TIMEOUT cleaner placement flush"
                );
                c.poll();
                std::thread::yield_now();
            }
            let q = Query::Keys {
                id: 1,
                keys: vec![Bytes::from_static(b"missing")],
            };
            assert!(matches!(&*query(&mut c, q), Answer::Entries(v, _) if v.is_empty()));
            let mut worker_masks = masks("omap-splinter-0");
            let mut expected_workers = vec![worker.to_string()];
            if offload {
                expected_workers.push(cleaner.to_string());
            }
            worker_masks.sort();
            expected_workers.sort();
            assert_eq!(worker_masks, expected_workers);
            let expected = if isolate {
                selected.unwrap_or(worker)
            } else {
                worker
            };
            assert_eq!(masks("laio_cleaner"), vec![expected.to_string()]);
            drop(c);
            assert!(masks("omap-splinter-0").is_empty());
            assert!(masks("laio_cleaner").is_empty());
            assert_eq!(space.reserved.load(Ordering::Acquire), 0);
        }
        // This error is after open/prime, so an enabled pool must also be joined
        // before the reported bootstrap failure releases lock/space ownership.
        assert!(Client::open(&cfg, &sb, 0, 128 << 20, 100, 101).is_err());
        assert!(masks("omap-splinter-0").is_empty());
        assert!(masks("laio_cleaner").is_empty());
        assert_eq!(space.reserved.load(Ordering::Acquire), 0);
    }
}
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn setup() -> (Temp, Config, Superblock) {
    setup_io(IoMode::Direct)
}
fn setup_io(io: IoMode) -> (Temp, Config, Superblock) {
    setup_mode(io, false)
}
/// As [`setup_io`]; `no_log` provisions the image without the library log.
fn setup_mode(io: IoMode, no_log: bool) -> (Temp, Config, Superblock) {
    let p = std::env::temp_dir().join(format!(
        "sdb-store-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&p).unwrap();
    let mut cfg = Config::new(p.clone(), 128 << 20);
    cfg.io = io;
    cfg.allow_non_nvme = true;
    cfg.no_log = no_log;
    let (sb, _) = crate::layout::plan(
        32768,
        &crate::layout::MkfsParams {
            shards: 1,
            wal_blocks: 512,
            align_blocks: 1,
            omap_splinterdb: true,
            ..Default::default()
        },
    )
    .unwrap();
    create(&cfg, &sb, 64 << 20).unwrap();
    (Temp(p), cfg, sb)
}
fn db(cfg: &Config, sb: &Superblock) -> Database {
    Database::open_with_options(
        &cfg.path(sb, 0).unwrap(),
        &identity(sb, 0),
        64 << 20,
        cfg.options(64 << 20).unwrap(),
    )
    .unwrap()
}
#[test]
fn splinter_test_headroom_override_survives_sampler_updates() {
    let (_t, cfg, sb) = setup();
    let c = Client::open(&cfg, &sb, 0, 128 << 20, 0, 0).unwrap();
    let cap = c.capacity();
    c.test_logical_used(cap - cap / 8 - 1234);
    // Deterministically interleave the sampler's atomic publication, without
    // waiting for a thread/timer race or changing production sampling policy.
    c.metrics.db_used.store(0, Ordering::Release);
    assert_eq!(c.logical_available(), 1234);
    c.metrics.db_used.store(cap, Ordering::Release);
    assert_eq!(c.logical_available(), 1234);
    c.logical_used_override.set(None);
}
#[test]
fn splinter_binding_and_read_only_refuse_before_foreign_open() {
    let (_t, mut cfg, sb) = setup();
    let p = cfg.path(&sb, 0).unwrap();
    let before = std::fs::read(&p).unwrap();
    cfg.read_only = true;
    assert!(validate_binding(&cfg, &sb, 0).is_err());
    assert!(Client::open(&cfg, &sb, 0, 128 << 20, 0, 0).is_err());
    cfg.read_only = false;
    let mut other = sb.clone();
    other.mkfs_time += 1;
    assert!(Client::open(&cfg, &other, 0, 128 << 20, 0, 0).is_err());
    assert_eq!(before, std::fs::read(&p).unwrap());
    assert!(create(&cfg, &sb, 64 << 20).is_err());
}
#[test]
fn splinter_flush_key_scratch_preserves_object_prefixes_and_binary_key_lengths() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    let keys = [
        vec![],
        vec![0; 9000],
        vec![0, 255],
        b"b".to_vec(),
        vec![255],
    ];
    let mut expected = std::collections::BTreeMap::new();
    let mut m = Memtable::new();
    for id in [0u64, u64::MAX] {
        for (i, k) in keys.iter().enumerate() {
            let value = vec![i as u8, id as u8];
            m.put(
                1,
                id,
                Bytes::copy_from_slice(k),
                Bytes::copy_from_slice(&value),
            );
            expected.insert((id, k.clone()), value);
        }
    }
    d.flush(&m).unwrap();
    let mut changed = Memtable::new();
    changed.del_range(2, 0, Bytes::new(), Some(Bytes::from_static(b"b")));
    expected.retain(|(id, k), _| *id != 0 || k.as_slice() >= &b"b"[..]);
    for id in [0u64, u64::MAX] {
        changed.put(3, id, Bytes::new(), Bytes::from_static(b"replacement"));
        expected.insert((id, vec![]), b"replacement".to_vec());
        changed.del(3, id, Bytes::from_static(b"b"));
        expected.remove(&(id, b"b".to_vec()));
    }
    d.flush(&changed).unwrap();
    d.db.close().unwrap();
    let d = db(&cfg, &sb);
    assert_eq!(d.watermark, 3);
    for id in [0u64, u64::MAX] {
        for k in &keys {
            // Independent namespace construction, not the production key helper.
            let encoded = [vec![1], id.to_be_bytes().to_vec(), k.clone()].concat();
            assert_eq!(
                d.db.get(&encoded, usize::MAX).unwrap(),
                expected.get(&(id, k.clone())).cloned()
            );
        }
    }
}

#[test]
fn splinter_range_delete_pages_and_overlay_precedence() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    let mut m = Memtable::new();
    for i in 0..800u32 {
        m.put(
            1,
            9,
            Bytes::copy_from_slice(&i.to_be_bytes()),
            Bytes::copy_from_slice(&i.to_le_bytes()),
        );
    }
    m.put(1, 10, Bytes::new(), Bytes::from_static(b"untouched"));
    d.flush(&m).unwrap();
    let mut del = Memtable::new();
    del.del_range(
        2,
        9,
        Bytes::copy_from_slice(&17u32.to_be_bytes()),
        Some(Bytes::copy_from_slice(&710u32.to_be_bytes())),
    );
    del.put(
        2,
        9,
        Bytes::copy_from_slice(&40u32.to_be_bytes()),
        Bytes::from_static(b"new"),
    );
    let view = [del.snapshot(9), None, None];
    let q = Query::Page {
        id: 9,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::new(),
        versions: [(0, 0); 3],
        session: None,
        keys_only: false,
        demand: PAGE,
    };
    let Answer::Entries(v, more) = d.read(&q, &view, 1 << 20).unwrap() else {
        panic!()
    };
    assert!(!more);
    assert_eq!(v.len(), 108);
    assert_eq!(
        v[17],
        (
            Bytes::copy_from_slice(&40u32.to_be_bytes()),
            Bytes::from_static(b"new")
        )
    );
    d.flush(&del).unwrap();
    let Answer::Entries(base, _) = d.read(&q, &[None, None, None], 1 << 20).unwrap() else {
        panic!()
    };
    assert_eq!(base, v);
    let mut clear = Memtable::new();
    clear.del_range(3, 9, Bytes::new(), None);
    d.flush(&clear).unwrap();
    assert_eq!(d.db.get(&key(10, b""), 32).unwrap().unwrap(), b"untouched");
    let Answer::Ids(ids, false) = d
        .read(&Query::Ids { after: None }, &[None, None, None], 1 << 20)
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(ids, vec![10]);
}
#[test]
fn splinter_partial_materialization_old_watermark_replayed_idempotently() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    let mut base = Memtable::new();
    base.put(1, 1, Bytes::from_static(b"a"), Bytes::from_static(b"old"));
    d.flush(&base).unwrap();
    // Simulate surviving effects of a later batch BEFORE its watermark is written.
    d.db.put(&key(1, b"a"), b"partial").unwrap();
    d.db.put(&key(1, b"z"), b"partial").unwrap();
    d.db.durable_barrier().unwrap();
    d.db.close().unwrap();
    let mut d = db(&cfg, &sb);
    assert_eq!(d.watermark, 1);
    let mut replay = Memtable::new();
    replay.del_range(2, 1, Bytes::new(), None);
    replay.put(3, 1, Bytes::from_static(b"b"), Bytes::from_static(b"final"));
    for _ in 0..2 {
        d.flush(&replay).unwrap();
        assert_eq!(d.watermark, 3);
    }
    assert!(d.db.get(&key(1, b"a"), 99).unwrap().is_none());
    assert!(d.db.get(&key(1, b"z"), 99).unwrap().is_none());
    assert_eq!(d.db.get(&key(1, b"b"), 99).unwrap().unwrap(), b"final");
    d.db.close().unwrap();
    assert_eq!(db(&cfg, &sb).watermark, 3);
}
#[test]
fn splinter_watermark_bounds_and_missing_image_are_not_repaired() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    d.db.put(WATERMARK, &9u64.to_le_bytes()).unwrap();
    d.db.durable_barrier().unwrap();
    d.db.close().unwrap();
    assert!(Client::open(&cfg, &sb, 0, 128 << 20, 0, 8).is_err());
    assert!(Client::open(&cfg, &sb, 0, 128 << 20, 10, 12).is_err());
    let p = cfg.path(&sb, 0).unwrap();
    std::fs::remove_file(&p).unwrap();
    assert!(Client::open(&cfg, &sb, 0, 128 << 20, 0, 12).is_err());
    assert!(!p.exists());
}
#[test]
fn splinter_preflight_invalid_size_creates_nothing() {
    let (t, mut cfg, sb) = setup();
    let mut other = sb.clone();
    other.osd_fsid = [22; 16];
    cfg.capacity = 1;
    assert!(create(&cfg, &other, 64 << 20).is_err());
    assert!(!cfg.path(&other, 0).unwrap().parent().unwrap().exists());
    drop(t);
}

fn query(client: &mut Client, q: Query) -> Arc<Answer> {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        client.poll();
        match client.query(q.clone()) {
            Err(StoreError::Miss) => {
                assert!(
                    Instant::now() < end,
                    "WARNING TIMEOUT SplinterDB read regression exceeded 10s"
                );
                std::thread::yield_now();
            }
            r => return r.unwrap(),
        }
    }
}
#[test]
fn splinter_large_aggregate_read_debt_preserves_progress_and_keys_projection() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    let value: Vec<u8> = (0usize..5 << 20)
        .map(|i| ((i * 7919) ^ (i >> 13)) as u8)
        .collect();
    let mut m = Memtable::new();
    for k in [b"a", b"b", b"c"] {
        m.put(
            1,
            1,
            Bytes::copy_from_slice(k),
            Bytes::copy_from_slice(&value),
        );
    }
    d.flush(&m).unwrap();
    d.db.close().unwrap();
    let mut c = Client::open(&cfg, &sb, 0, 128 << 20, 0, 1).unwrap();
    c.read_session(Some((1, 1)), false);
    let q = Query::Keys {
        id: 1,
        keys: vec![
            Bytes::from_static(b"a"),
            Bytes::from_static(b"b"),
            Bytes::from_static(b"c"),
        ],
    };
    let a = query(&mut c, q.clone());
    let Answer::Entries(v, false) = &*a else {
        panic!()
    };
    assert_eq!(v.len(), 3);
    for (_, v) in v {
        assert_eq!(&v[..], &value);
    }
    assert!(c.retained_bytes > c.budget);
    assert_eq!(c.admit_scan((2, 2), 1), Err(StoreError::Miss));
    assert!(c.admit_scan((1, 1), 100 << 20).is_ok()); // soft owner debt, not validity
    c.read_session(None, false);
    assert_eq!(c.retained_bytes, 0);
    assert!(c.owner.is_none());
    let q = Query::Page {
        id: 1,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::new(),
        versions: [(0, 0); 3],
        session: None,
        keys_only: true,
        demand: PAGE,
    };
    let a = query(&mut c, q);
    let Answer::Entries(v, false) = &*a else {
        panic!()
    };
    assert_eq!(v.len(), 3);
    assert!(v.iter().all(|(_, v)| v.is_empty()));
}
#[test]
fn splinter_by_keys_above_worker_page_size_returns_every_requested_key() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    let mut m = Memtable::new();
    for i in 0..1100u32 {
        m.put(
            1,
            1,
            Bytes::copy_from_slice(&i.to_be_bytes()),
            Bytes::copy_from_slice(&i.to_le_bytes()),
        );
    }
    d.flush(&m).unwrap();
    d.db.close().unwrap();
    let mut c = Client::open(&cfg, &sb, 0, 128 << 20, 0, 1).unwrap();
    let q = Query::Keys {
        id: 1,
        keys: (0..1100u32)
            .map(|i| Bytes::copy_from_slice(&i.to_be_bytes()))
            .collect(),
    };
    let a = query(&mut c, q);
    let Answer::Entries(v, false) = &*a else {
        panic!()
    };
    assert_eq!(v.len(), 1100);
    for (i, (k, v)) in v.iter().enumerate() {
        assert_eq!(&k[..], &(i as u32).to_be_bytes());
        assert_eq!(&v[..], &(i as u32).to_le_bytes());
    }
}

fn scan_all(c: &mut Client) -> Vec<(Bytes, Bytes)> {
    let mut from = Bytes::new();
    let mut excl = false;
    let mut all = Vec::new();
    loop {
        let q = Query::Page {
            id: 1,
            from: from.clone(),
            excl,
            prefix: Bytes::new(),
            versions: [(0, 0); 3],
            session: c.session(),
            keys_only: false,
            demand: PAGE,
        };
        let a = query(c, q);
        let Answer::Entries(v, more) = &*a else {
            panic!()
        };
        all.extend(v.iter().cloned());
        if !more {
            break;
        }
        assert!(!v.is_empty());
        from = v.last().unwrap().0.clone();
        excl = true;
    }
    all
}
#[test]
fn splinter_owned_scan_windows_reduce_seeks_and_do_not_evict_hot_points() {
    for io in [IoMode::Direct, IoMode::Buffered] {
        let (_t, mut cfg, sb) = setup_io(io);
        let mut d = db(&cfg, &sb);
        let mut m = Memtable::new();
        let model: Vec<_> = (0..4096u32)
            .map(|i| {
                (
                    Bytes::copy_from_slice(&i.to_be_bytes()),
                    Bytes::copy_from_slice(&i.to_le_bytes()),
                )
            })
            .collect();
        for (k, v) in &model {
            m.put(1, 1, k.clone(), v.clone());
        }
        d.flush(&m).unwrap();
        d.db.close().unwrap();
        let mut seeks = Vec::new();
        for pages in [1, 4] {
            cfg.scan_readahead_pages = pages;
            let mut c = Client::open(&cfg, &sb, 0, 128 << 20, 0, 1).unwrap();
            c.budget = 512;
            let point = Query::Keys {
                id: 1,
                keys: vec![model[0].0.clone()],
            };
            query(&mut c, point.clone());
            c.read_session(Some((1, 1)), false);
            assert_eq!(scan_all(&mut c), model);
            assert!(c.cache.contains_key(&point));
            assert!(c.cache.keys().all(|q| !matches!(q, Query::Page { .. })));
            let counters = c.read_gauges();
            seeks.push(counters[9]);
            if pages == 4 {
                assert!(counters[0] > 0);
                assert!(counters[2] > 0);
                assert!(counters[3] > 0);
            }
        }
        eprintln!(
            "{io:?}: demand-only seeks={}, owned-window seeks={}",
            seeks[0], seeks[1]
        );
        assert!(seeks[1] < seeks[0]);
    }
}
#[test]
fn splinter_request_sized_demand_bounds_errors_pressure_and_large_values() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    let mut m = Memtable::new();
    for i in 0..4100u32 {
        m.put(
            1,
            1,
            Bytes::copy_from_slice(&i.to_be_bytes()),
            Bytes::from_static(b"value"),
        );
    }
    d.flush(&m).unwrap();
    let mut q = Query::Page {
        id: 1,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::new(),
        versions: [(0, 0); 3],
        session: None,
        keys_only: false,
        demand: 1025,
    };
    for width in [0, 1, 2, 255, 256, 257, 1025, MAX_SCAN_ROWS, usize::MAX] {
        if let Query::Page { demand, .. } = &mut q {
            *demand = width;
        }
        let Answer::Entries(v, true) = d.read(&q, &[None, None, None], usize::MAX).unwrap() else {
            panic!()
        };
        assert_eq!(v.len(), width.clamp(1, MAX_SCAN_ROWS));
        assert_eq!(v[0].0[..], 0u32.to_be_bytes());
    }
    if let Query::Page { demand, .. } = &mut q {
        *demand = 1025;
    }
    d.fail_row.set(Some(300));
    assert!(
        d.read(&q, &[None, None, None], usize::MAX).is_err(),
        "row300 is demand, not prediction"
    );
    assert_eq!(d.spec_errors.get(), 0);
    d.fail_row.set(None);
    let Answer::Entries(v, true) = d
        .read_batch(&q, &[None, None, None], usize::MAX, 1025, || true)
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        v.len(),
        PAGE,
        "pressure releases iterator after positive demand progress"
    );
    let Answer::Entries(v, true) = d.read(&q, &[None, None, None], 0).unwrap() else {
        panic!()
    };
    assert_eq!(
        v.len(),
        1,
        "soft allowance still permits a complete oversized demanded entry"
    );
}

#[test]
fn splinter_retired_wide_demand_does_not_retain_worker_result() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    let mut m = Memtable::new();
    for i in 0..1100u32 {
        m.put(
            1,
            1,
            Bytes::copy_from_slice(&i.to_be_bytes()),
            Bytes::from_static(b"value"),
        );
    }
    d.flush(&m).unwrap();
    d.db.close().unwrap();
    let mut c = Client::open(&cfg, &sb, 0, 128 << 20, 0, 1).unwrap();
    c.read_session(Some((9, 1)), false);
    let q = Query::Page {
        id: 1,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::new(),
        versions: [(0, 0); 3],
        session: Some((9, 1)),
        keys_only: false,
        demand: 1025,
    };
    assert!(matches!(c.query(q), Err(StoreError::Miss)));
    c.read_session(None, false);
    let end = Instant::now() + Duration::from_secs(10);
    while !c.pending.is_empty() {
        assert!(Instant::now() < end, "WARNING TIMEOUT retired wide demand");
        c.poll();
        std::thread::yield_now();
    }
    assert!(c.failure.is_none());
    assert!(c.owner.is_none());
    assert_eq!(c.scan.bytes(), 0);
}

#[test]
fn splinter_speculation_yields_and_errors_do_not_invalidate_completed_demand() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    let mut m = Memtable::new();
    for i in 0..700u32 {
        m.put(
            1,
            1,
            Bytes::copy_from_slice(&i.to_be_bytes()),
            Bytes::from_static(b"value"),
        );
    }
    d.flush(&m).unwrap();
    let q = Query::Page {
        id: 1,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::new(),
        versions: [(0, 0); 3],
        session: None,
        keys_only: false,
        demand: PAGE,
    };
    let Answer::Entries(v, true) = d
        .read_batch(&q, &[None, None, None], 1 << 20, PAGE * 4, || true)
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(v.len(), PAGE);
    d.fail_row.set(Some(PAGE + 3));
    let Answer::Entries(v, true) = d
        .read_batch(&q, &[None, None, None], 1 << 20, PAGE * 4, || false)
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(v.len(), PAGE);
    assert_eq!(d.spec_errors.get(), 1);
    d.fail_row.set(Some(0));
    assert!(d.read(&q, &[None, None, None], 1 << 20).is_err());
    d.fail_row.set(None);
    let mut changed = Memtable::new();
    changed.put(2, 1, Bytes::new(), Bytes::from_static(b"after iterator"));
    d.flush(&changed).unwrap();
}
#[test]
fn splinter_window_mutation_and_cancel_drop_reuse_before_new_answers() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    let mut m = Memtable::new();
    for i in 0..1024u32 {
        m.put(
            1,
            1,
            Bytes::copy_from_slice(&i.to_be_bytes()),
            Bytes::from_static(b"old"),
        );
    }
    d.flush(&m).unwrap();
    d.db.close().unwrap();
    let mut c = Client::open(&cfg, &sb, 0, 128 << 20, 0, 2).unwrap();
    c.read_session(Some((7, 1)), false);
    scan_all(&mut c);
    let mut changed = Memtable::new();
    changed.del_range(2, 1, Bytes::new(), None);
    changed.put(
        2,
        1,
        Bytes::from_static(b"new"),
        Bytes::from_static(b"value"),
    );
    c.flush(Arc::new(changed)).unwrap();
    let end = Instant::now() + Duration::from_secs(10);
    while c.flushed.is_none() {
        c.poll();
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT SplinterDB window invalidation exceeded 10s"
        );
        std::thread::yield_now();
    }
    assert_eq!(
        scan_all(&mut c),
        vec![(Bytes::from_static(b"new"), Bytes::from_static(b"value"))]
    );
    c.read_session(None, false);
    c.flushed = None;
    c.set_pressure(false);
    c.read_session(Some((7, 1)), false);
    let q = Query::Page {
        id: 1,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::new(),
        versions: [(0, 0); 3],
        session: Some((7, 1)),
        keys_only: false,
        demand: PAGE,
    };
    // The completed post-invalidation window outlives its request and serves
    // the listing's next request: the matched state has not changed since.
    assert!(matches!(
        &*c.query(q.clone()).unwrap(),
        Answer::Entries(v, false) if v[..] == [(Bytes::from_static(b"new"), Bytes::from_static(b"value"))]
    ));
    // Another projection needs a worker turn; retire it before it completes.
    let mut keys = q;
    if let Query::Page { keys_only, .. } = &mut keys {
        *keys_only = true;
    }
    assert!(matches!(c.query(keys.clone()), Err(StoreError::Miss)));
    let charged = c.scan.bytes();
    c.read_session(None, false);
    while !c.pending.is_empty() {
        c.poll();
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT SplinterDB cancelled window exceeded 10s"
        );
        std::thread::yield_now();
    }
    // The retired request's late answer is never installed.
    assert_eq!(c.scan.bytes(), charged);
    assert!(c.scan.get(&keys).is_none());
}
#[test]
fn splinter_both_io_modes_keep_watermark_unpublished_after_barrier_failure() {
    for io in [IoMode::Direct, IoMode::Buffered] {
        for normal_maintenance in [false, true] {
            for stage in [1, 2] {
                let (_t, cfg, sb) = setup_io(io);
                let options = splinterdb_lib::Options {
                    normal_maintenance,
                    ..cfg.options(64 << 20).unwrap()
                };
                let mut d = Database::open_with_options(
                    &cfg.path(&sb, 0).unwrap(),
                    &identity(&sb, 0),
                    64 << 20,
                    options,
                )
                .unwrap();
                let policy = d.db.maintenance_stats().unwrap();
                assert_eq!(policy.normal_workers, u64::from(normal_maintenance));
                assert_eq!(policy.memtable_workers, 0);
                assert_eq!(
                    policy.queue_scale_percent,
                    if normal_maintenance { 101 } else { 0 }
                );
                let mut m = Memtable::new();
                m.put(1, 1, Bytes::from_static(b"a"), Bytes::from_static(b"value"));
                d.fail_barrier = Some(stage);
                let timings = timing::Timings::default();
                assert!(d.flush_timed(&m, &timings).is_err());
                let counts = timings.snapshot();
                assert_eq!(counts[timing::APPLY * 4], 1);
                assert_eq!(counts[timing::DATA_BARRIER * 4], 1);
                assert_eq!(counts[timing::WATERMARK * 4], u64::from(stage == 2));
                assert_eq!(counts[timing::WATERMARK_BARRIER * 4], u64::from(stage == 2));
                assert_eq!(d.watermark, 0);
                d.db.close().unwrap();
                let mut recovered = Database::open_with_options(
                    &cfg.path(&sb, 0).unwrap(),
                    &identity(&sb, 0),
                    64 << 20,
                    options,
                )
                .unwrap();
                if recovered.watermark == 1 {
                    assert_eq!(
                        recovered.db.get(&key(1, b"a"), 32).unwrap().unwrap(),
                        b"value"
                    );
                }
                recovered.flush(&m).unwrap();
                assert_eq!(recovered.watermark, 1);
            }
        }
    }
}

#[test]
fn splinter_scan_demand_makes_progress_after_idle_credit_expiry() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    let mut m = Memtable::new();
    m.put(
        1,
        1,
        Bytes::from_static(b"key"),
        Bytes::from_static(b"value"),
    );
    d.flush(&m).unwrap();
    d.db.close().unwrap();
    let mut c = Client::open(&cfg, &sb, 0, 128 << 20, 0, 1).unwrap();
    c.touched = Instant::now() - Duration::from_secs(31);
    let q = Query::Page {
        id: 1,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::new(),
        versions: [(0, 0); 3],
        session: None,
        keys_only: false,
        demand: PAGE,
    };
    let a = query(&mut c, q);
    assert!(matches!(&*a,Answer::Entries(v,false) if v.len()==1));
}

#[test]
fn splinter_credit_denial_preserves_owner_and_retired_completion_cannot_claim_successor() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    let mut m = Memtable::new();
    m.put(
        1,
        1,
        Bytes::from_static(b"key"),
        Bytes::from_static(b"value"),
    );
    d.flush(&m).unwrap();
    d.db.close().unwrap();
    let mut c = Client::open(&cfg, &sb, 0, 128 << 20, 0, 1).unwrap();
    let a = (7, 1);
    let b = (7, 2);
    let q = |session| Query::Page {
        id: 1,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::new(),
        versions: [(0, 0); 3],
        session: Some(session),
        keys_only: false,
        demand: 1024,
    };
    c.read_session(Some(a), false);
    c.hold_completions = true;
    assert!(matches!(c.query(q(a)), Err(StoreError::Miss)));
    assert_eq!(c.pending.len(), 1);
    c.read_session(None, true);
    c.read_session(Some(b), false);
    assert!(c.credit_blocked());
    assert!(matches!(c.admit_scan(b, 8192), Err(StoreError::Miss)));
    assert!(matches!(c.query(q(b)), Err(StoreError::Miss)));
    assert_eq!(c.pending.len(), 1, "denial submits no read");
    assert_eq!(c.retained_session(), Some(a));
    c.read_session(None, true);
    c.read_session(Some(a), true);
    assert!(!c.credit_blocked());
    c.read_session(None, false); // Retire A with its old read still pending.
    assert_eq!(c.retained_session(), None);
    c.read_session(Some(b), false);
    c.admit_scan(b, 8192).unwrap();
    c.hold_completions = false;
    let end = Instant::now() + Duration::from_secs(5);
    while !c.pending.is_empty() {
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT retired read completion"
        );
        c.poll();
        std::thread::yield_now();
    }
    assert_eq!(
        c.scan.bytes(),
        0,
        "retired A page not installed in B's scan window"
    );
    assert_eq!(c.retained_session(), Some(b));
    assert!(
        matches!(&*query(&mut c, q(b)), Answer::Entries(v,false) if v==&vec![(Bytes::from_static(b"key"),Bytes::from_static(b"value"))])
    );
    c.read_session(None, false);
    assert_eq!(c.retained_session(), None);
}

#[test]
fn splinter_sessionless_read_orders_completions_and_pauses_only_synchronous_owner_expiry() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    let mut m = Memtable::new();
    for id in [1, 2] {
        for i in 0..1100u32 {
            m.put(
                1,
                id,
                Bytes::copy_from_slice(&i.to_be_bytes()),
                Bytes::copy_from_slice(&i.to_le_bytes()),
            );
        }
    }
    d.flush(&m).unwrap();
    d.db.close().unwrap();
    let mut c = Client::open(&cfg, &sb, 0, 128 << 20, 0, 1).unwrap();
    let owner = (8, 1);
    let page = |id, session| Query::Page {
        id,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::new(),
        versions: [(0, 0); 3],
        session,
        keys_only: false,
        demand: 1024,
    };
    let a = page(1, Some(owner));
    let b = page(2, None);
    c.read_session(Some(owner), false);
    c.hold_completions = true;
    assert!(matches!(c.query(a.clone()), Err(StoreError::Miss)));
    c.read_session(None, true);
    c.begin_blocking_read();
    // Deterministically cross 30s during the synchronous call, without sleeping.
    c.touched -= Duration::from_secs(31);
    c.owner_pause.as_mut().unwrap().1 -= Duration::from_secs(31);
    assert!(!c.poll());
    assert_eq!(c.retained_session(), Some(owner));
    assert!(!c.credit_blocked());
    assert!(matches!(c.query(b.clone()), Err(StoreError::Miss)));
    assert_eq!(
        c.pending.len(),
        1,
        "B must wait for A's completion, not add a worker slot"
    );
    assert!(c.pending.contains(&a));
    c.hold_completions = false;
    let end = Instant::now() + Duration::from_secs(10);
    while !c.pending.is_empty() {
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT installing owner completion"
        );
        c.poll();
        std::thread::yield_now();
    }
    let saved = c.scan.get(&a).unwrap();
    let charge = c.scan.bytes();
    let result = query(&mut c, b);
    assert!(matches!(&*result, Answer::Entries(v,true) if v.len()==1024));
    assert_eq!(c.scan.bytes(), charge);
    assert!(Arc::ptr_eq(&saved, &c.scan.get(&a).unwrap()));
    assert!(
        c.cache.is_empty(),
        "loan result delivered, not retained beside A"
    );
    assert_eq!(c.retained_session(), Some(owner));
    assert!(c.pending.is_empty());
    // Keys and inventory must not interrupt the held scan either.
    query(
        &mut c,
        Query::Keys {
            id: 2,
            keys: vec![Bytes::copy_from_slice(&7u32.to_be_bytes())],
        },
    );
    query(&mut c, Query::Ids { after: None });
    assert!(Arc::ptr_eq(&saved, &c.scan.get(&a).unwrap()));
    assert_eq!(c.scan.bytes(), charge);
    c.end_blocking_read();
    assert!(
        c.touched.elapsed() < Duration::from_secs(10),
        "exclude only service duration"
    );
    // FIFO children share the mapped parent, not a sessionless bypass.
    c.read_session(Some(owner), true);
    c.read_session(Some((8, 99)), true);
    assert!(c.session_admitted((8, 99)) && !c.credit_blocked());
    c.read_session(None, false);
    c.read_session(Some((9, 1)), false);
    assert!(c.credit_blocked());
    assert!(matches!(
        c.query(page(2, Some((9, 1)))),
        Err(StoreError::Miss)
    ));
    c.read_session(None, true);
    c.touched = Instant::now() - Duration::from_secs(31);
    assert!(
        c.poll(),
        "ordinary abandonment/release wake remains enabled"
    );
    assert!(c.retained_session().is_none());
}

#[test]
fn splinter_sessionless_oversize_results_are_complete_charged_and_not_accumulated() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    let mut m = Memtable::new();
    m.put(1, 1, Bytes::from_static(b"a"), Bytes::from_static(b"owner"));
    for i in 0..1100u32 {
        m.put(
            1,
            2,
            Bytes::copy_from_slice(&i.to_be_bytes()),
            Bytes::from(vec![(i % 251) as u8; 4096]),
        );
    }
    d.flush(&m).unwrap();
    d.db.close().unwrap();
    let mut c = Client::open(&cfg, &sb, 0, 128 << 20, 0, 1).unwrap();
    c.read_session(Some((1, 1)), false);
    let a = Query::Keys {
        id: 1,
        keys: vec![Bytes::from_static(b"a")],
    };
    let saved = query(&mut c, a.clone());
    let charge = c.retained_bytes;
    c.read_session(None, true);
    c.budget = 512;
    c.read_budget = 0; // Exhausted soft allowance still permits mandatory progress.
    c.begin_blocking_read();
    for i in 0..8u32 {
        let q = Query::Page {
            id: 2,
            from: Bytes::copy_from_slice(&i.to_be_bytes()),
            excl: false,
            prefix: Bytes::new(),
            versions: [(0, 0); 3],
            session: None,
            keys_only: false,
            demand: 100,
        };
        assert!(matches!(c.query(q.clone()), Err(StoreError::Miss)));
        let end = Instant::now() + Duration::from_secs(10);
        while !c.pending.is_empty() {
            assert!(
                Instant::now() < end,
                "WARNING TIMEOUT oversize sessionless page"
            );
            c.poll();
            std::thread::yield_now();
        }
        assert_eq!(c.cache.len(), 1);
        assert!(
            c.cache_bytes > c.budget,
            "account for the first-oversized-entry exception"
        );
        let answer = c.query(q).unwrap();
        let Answer::Entries(v, true) = &*answer else {
            panic!("not EOF")
        };
        assert_eq!(
            v,
            &vec![(
                Bytes::copy_from_slice(&i.to_be_bytes()),
                Bytes::from(vec![(i % 251) as u8; 4096])
            )]
        );
        assert_eq!(c.cache_bytes, 0);
        assert!(c.cache.is_empty());
        assert_eq!(c.retained_bytes, charge);
        assert!(Arc::ptr_eq(&saved, &c.retained[&a]));
    }
    let q = Query::Keys {
        id: 2,
        keys: (0..1100u32)
            .map(|i| Bytes::copy_from_slice(&i.to_be_bytes()))
            .collect(),
    };
    let answer = query(&mut c, q);
    let Answer::Entries(v, false) = &*answer else {
        panic!("by-keys must not truncate")
    };
    assert_eq!(v.len(), 1100);
    for (i, (k, v)) in v.iter().enumerate() {
        assert_eq!(k.as_ref(), &(i as u32).to_be_bytes());
        assert_eq!(v.as_ref(), &vec![(i % 251) as u8; 4096]);
    }
    assert_eq!(c.cache_bytes, 0);
    assert_eq!(c.retained_bytes, charge);
    assert_eq!(c.retained_session(), Some((1, 1)));
    assert!(Arc::ptr_eq(&saved, &c.retained[&a]));
    c.end_blocking_read();
}

#[test]
fn splinter_barrier_loan_keeps_real_tags_and_nested_scope_preserves_owner_age() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    let mut m = Memtable::new();
    m.put(1, 1, Bytes::from_static(b"a"), Bytes::from_static(b"value"));
    d.flush(&m).unwrap();
    d.db.close().unwrap();
    let mut c = Client::open(&cfg, &sb, 0, 128 << 20, 0, 1).unwrap();
    let owner = (7, 1);
    let q = Query::Page {
        id: 1,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::new(),
        versions: [(0, 0); 3],
        session: Some(owner),
        keys_only: false,
        demand: 1024,
    };
    c.read_session(Some(owner), false);
    let saved = query(&mut c, q.clone());
    let epoch = c.epoch.load(Ordering::Acquire);
    c.read_session(None, true);
    // A metadata-only unrelated tag's retirement did not own or use the window.
    c.read_session(Some((7, 2)), false);
    c.read_session(None, false);
    assert_eq!(c.epoch.load(Ordering::Acquire), epoch);
    assert!(Arc::ptr_eq(&saved, &c.scan.get(&q).unwrap()));
    c.begin_barrier_read();
    c.read_session(Some((u64::MAX, 99)), true);
    assert_eq!(
        c.session(),
        Some((u64::MAX, 99)),
        "keep actual FIFO identity"
    );
    assert_eq!(
        c.query_session(),
        None,
        "only the foreign query is one-shot"
    );
    c.begin_blocking_read();
    c.touched -= Duration::from_secs(31);
    c.owner_pause.as_mut().unwrap().1 -= Duration::from_secs(31);
    c.end_blocking_read();
    c.poll();
    assert_eq!(
        c.owner,
        Some(owner),
        "inner Stage exit must not unpause the outer drain"
    );
    assert_eq!(c.read_scope_depth, 1);
    let key = Query::Keys {
        id: 1,
        keys: vec![Bytes::from_static(b"a")],
    };
    assert!(matches!(&*query(&mut c, key), Answer::Entries(v,false) if v.len()==1));
    c.read_session(None, false);
    assert!(Arc::ptr_eq(&saved, &c.scan.get(&q).unwrap()));
    assert_eq!(c.epoch.load(Ordering::Acquire), epoch);
    c.end_barrier_read();
    assert!(!c.independent_reads() && c.owner_pause.is_none() && c.read_scope_depth == 0);
    assert!(c.touched.elapsed() < Duration::from_secs(10));
    c.read_session(Some((7, 2)), false);
    assert!(
        c.credit_blocked(),
        "ordinary requests gain no barrier privilege"
    );
    c.read_session(None, true);
    c.read_session(Some(owner), true);
    c.read_session(Some((7, 3)), true);
    assert!(
        c.session_admitted((7, 3)),
        "ordinary mapped FIFO child still shares its parent"
    );
    let before = c.epoch.load(Ordering::Acquire);
    c.read_session(None, false);
    assert!(
        c.epoch.load(Ordering::Acquire) > before,
        "ordinary admitted-child retirement still cancels in-flight optional work"
    );
    assert!(
        Arc::ptr_eq(&saved, &c.scan.get(&q).unwrap()),
        "but the completed window survives for the listing's next request"
    );
}

#[test]
fn splinter_sessionless_page_identity_and_flush_invalidation_preserve_read_views() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    let mut base = Memtable::new();
    for id in [1, 2] {
        for key in [b"a", b"b", b"c"] {
            base.put(
                1,
                id,
                Bytes::copy_from_slice(key),
                Bytes::from_static(b"old"),
            );
        }
    }
    d.flush(&base).unwrap();
    d.db.close().unwrap();
    let mut c = Client::open(&cfg, &sb, 0, 128 << 20, 0, 3).unwrap();
    let owner = (1, 1);
    let held = Query::Keys {
        id: 1,
        keys: vec![Bytes::from_static(b"a")],
    };
    c.read_session(Some(owner), false);
    let saved = query(&mut c, held.clone());
    c.read_session(None, true);
    c.begin_blocking_read();
    let page = |versions, from: &'static [u8], excl, prefix: &'static [u8], keys_only, demand| {
        Query::Page {
            id: 2,
            from: Bytes::from_static(from),
            excl,
            prefix: Bytes::from_static(prefix),
            versions,
            session: None,
            keys_only,
            demand,
        }
    };
    let old = page([(0, 0); 3], b"", false, b"", false, 3);
    assert!(matches!(c.query(old.clone()), Err(StoreError::Miss)));
    let end = Instant::now() + Duration::from_secs(10);
    while !c.pending.is_empty() {
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT old read-view completion"
        );
        c.poll();
        std::thread::yield_now();
    }
    assert!(c.cache.contains_key(&old)); // Deliberately leave an old-view answer unread.
    let mut overlay = Memtable::new();
    overlay.put(2, 2, Bytes::from_static(b"b"), Bytes::from_static(b"new"));
    let view = [overlay.snapshot(2), None, None];
    let revisions = view
        .each_ref()
        .map(|m| m.as_ref().map_or((0, 0), |m| m.revision));
    for (from, excl, prefix, keys_only, demand, expected, more) in [
        (
            &b"b"[..],
            false,
            &b""[..],
            false,
            1,
            vec![(b"b".to_vec(), b"new".to_vec())],
            true,
        ),
        (
            &b"b"[..],
            true,
            &b""[..],
            false,
            3,
            vec![(b"c".to_vec(), b"old".to_vec())],
            false,
        ),
        (
            &b""[..],
            false,
            &b"b"[..],
            true,
            3,
            vec![(b"b".to_vec(), vec![])],
            false,
        ),
    ] {
        let q = page(revisions, from, excl, prefix, keys_only, demand);
        let a = loop {
            c.poll();
            match c.query_view(q.clone(), view.clone()) {
                Err(StoreError::Miss) => {
                    assert!(Instant::now() < end, "WARNING TIMEOUT distinct read view");
                    std::thread::yield_now();
                }
                r => break r.unwrap(),
            }
        };
        let Answer::Entries(v, got_more) = &*a else {
            panic!("page answer")
        };
        assert_eq!(
            (
                *got_more,
                v.iter()
                    .map(|(k, v)| (k.to_vec(), v.to_vec()))
                    .collect::<Vec<_>>()
            ),
            (more, expected)
        );
        assert!(Arc::ptr_eq(&saved, &c.retained[&held]));
    }
    c.flush(Arc::new(overlay)).unwrap();
    while c.flushed.is_none() {
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT foreign view publication"
        );
        c.poll();
        std::thread::yield_now();
    }
    assert!(
        !c.cache.contains_key(&old),
        "publication invalidates even an unread old answer"
    );
    assert!(Arc::ptr_eq(&saved, &c.retained[&held]));
    c.flushed = None;
    c.set_pressure(false);
    let mut changed_owner = Memtable::new();
    changed_owner.put(
        3,
        1,
        Bytes::from_static(b"a"),
        Bytes::from_static(b"changed"),
    );
    c.flush(Arc::new(changed_owner)).unwrap();
    while c.flushed.is_none() {
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT held-object invalidation"
        );
        c.poll();
        std::thread::yield_now();
    }
    assert!(
        c.retained.is_empty(),
        "loan isolation must not suppress legitimate mutation invalidation"
    );
    assert_eq!(c.retained_session(), Some(owner));
    c.end_blocking_read();
}

#[test]
fn splinter_masked_suffix_checks_pressure_and_bounds_inspected_work() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    let mut base = Memtable::new();
    let mut deleted = Memtable::new();
    for i in 0..8192u32 {
        let k = Bytes::copy_from_slice(&i.to_be_bytes());
        base.put(1, 1, k.clone(), Bytes::from_static(b"base"));
        if i >= PAGE as u32 {
            deleted.del(2, 1, k);
        }
    }
    d.flush(&base).unwrap();
    let view = [deleted.snapshot(1), None, None];
    let q = Query::Page {
        id: 1,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::new(),
        versions: [(0, 0); 3],
        session: None,
        keys_only: false,
        demand: PAGE,
    };
    let mut checks = 0;
    let a = d
        .read_batch(&q, &view, 1 << 20, PAGE * 4, || {
            checks += 1;
            checks == 3
        })
        .unwrap();
    assert!(matches!(a,Answer::Entries(v,true) if v.len()==PAGE));
    assert_eq!(checks, 3);
    checks = 0;
    let a = d
        .read_batch(&q, &view, 1 << 20, PAGE * 4, || {
            checks += 1;
            false
        })
        .unwrap();
    assert!(matches!(a,Answer::Entries(v,true) if v.len()==PAGE));
    assert!(
        checks <= PAGE * 3 + 1,
        "masked work exceeded inspected-row quantum: {checks}"
    );
    // The optional cutoff is not EOF. A later demanded suffix may walk all
    // tombstones and must discover the real end rather than invent live rows.
    let mut tail = q;
    if let Query::Page { from, excl, .. } = &mut tail {
        *from = Bytes::copy_from_slice(&255u32.to_be_bytes());
        *excl = true;
    }
    assert!(matches!(d.read(&tail,&view,1<<20).unwrap(),Answer::Entries(v,false) if v.is_empty()));
}

#[test]
fn splinter_prefix_ending_inside_tombstone_preserves_new_overlay_points() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    let mut base = Memtable::new();
    for k in [b"ab0", b"ab1", b"ac0"] {
        base.put(1, 1, Bytes::copy_from_slice(k), Bytes::from_static(b"old"));
    }
    d.flush(&base).unwrap();
    let mut overlay = Memtable::new();
    overlay.del_range(
        2,
        1,
        Bytes::from_static(b"aa"),
        Some(Bytes::from_static(b"z")),
    );
    for k in [b"ab2", b"ab5"] {
        overlay.put(3, 1, Bytes::copy_from_slice(k), Bytes::from_static(b"new"));
    }
    let q = Query::Page {
        id: 1,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::from_static(b"ab"),
        versions: [(0, 0); 3],
        session: None,
        keys_only: false,
        demand: PAGE,
    };
    let view = [overlay.snapshot(1), None, None];
    let Answer::Entries(v, false) = d.read(&q, &view, 1 << 20).unwrap() else {
        panic!()
    };
    assert_eq!(
        v,
        vec![
            (Bytes::from_static(b"ab2"), Bytes::from_static(b"new")),
            (Bytes::from_static(b"ab5"), Bytes::from_static(b"new"))
        ]
    );
    let mut outside = q;
    if let Query::Page { from, .. } = &mut outside {
        *from = Bytes::from_static(b"ac");
    }
    assert!(
        matches!(d.read(&outside,&view,1<<20).unwrap(),Answer::Entries(v,false) if v.is_empty())
    );
}

#[test]
fn splinter_running_window_observes_session_retirement_before_next_page() {
    let (_t, cfg, sb) = setup();
    let mut d = db(&cfg, &sb);
    let mut m = Memtable::new();
    for i in 0..2048u32 {
        m.put(
            1,
            1,
            Bytes::copy_from_slice(&i.to_be_bytes()),
            Bytes::from_static(b"v"),
        );
    }
    d.flush(&m).unwrap();
    // A separate client supplies the real session-retirement signal. The read
    // runs synchronously so retirement occurs deterministically while its
    // optional window is executing, with the exact worker yield predicate.
    let (_ct, ccfg, csb) = setup();
    let mut c = Client::open(&ccfg, &csb, 0, 128 << 20, 0, 1).unwrap();
    c.read_session(Some((7, 1)), false);
    // This fixture installs answers directly, so explicitly model their credit
    // admission just as query_view would before sending the worker request.
    c.admit_scan((7, 1), 0).unwrap();
    let page = |from: Bytes, excl| Query::Page {
        id: 1,
        from,
        excl,
        prefix: Bytes::new(),
        versions: [(0, 0); 3],
        session: Some((7, 1)),
        keys_only: false,
        demand: PAGE,
    };
    let mut q = page(Bytes::new(), false);
    for _ in 0..2 {
        let a = Arc::new(d.read(&q, &[None, None, None], 1 << 20).unwrap());
        let Answer::Entries(v, true) = &*a else {
            panic!()
        };
        c.scan.prepare(&q);
        c.scan.insert(q.clone(), a.clone());
        q = page(v.last().unwrap().0.clone(), true);
    }
    let pages = c.scan.prepare(&q);
    assert!(pages > 1);
    let allowance = ReadAllowance {
        bytes: 1 << 20,
        rows: pages * PAGE,
        epoch: c.epoch.load(Ordering::Acquire),
    };
    let hints = WorkerHints {
        stop: c.stop.clone(),
        pressure: c.pressure.clone(),
        epoch: c.epoch.clone(),
        wake: Default::default(),
    };
    let mut checks = 0;
    let a = d
        .read_batch(
            &q,
            &[None, None, None],
            allowance.bytes,
            allowance.rows,
            || {
                checks += 1;
                if checks == 2 {
                    c.read_session(None, false);
                }
                allowance.should_yield(&hints, false)
            },
        )
        .unwrap();
    let Answer::Entries(v, true) = a else {
        panic!()
    };
    assert_eq!(v.len(), PAGE + 1);
    assert_eq!(checks, 2);
    assert!(allowance.retired(&c.epoch));
    // Retirement cancels optional in-flight work, but the completed window stays
    // for the listing's next request; idle expiry drops it.
    assert!(c.scan.bytes() > 0);
    c.release(false);
    assert_eq!(c.scan.bytes(), 0);
    let replacement = ReadAllowance {
        epoch: c.epoch.load(Ordering::Acquire),
        ..allowance
    };
    assert!(!replacement.should_yield(&hints, false));
}

fn encoded(id: u64, k: &[u8]) -> Vec<u8> {
    // Independent namespace construction, not the production key helper.
    [vec![1], id.to_be_bytes().to_vec(), k.to_vec()].concat()
}

#[test]
fn splinter_apply_options_are_bounded_opt_ins() {
    let mut cfg = Config::new(PathBuf::from("/unused"), 0);
    assert_eq!((cfg.apply_threads, cfg.memtable_maintenance), (1, false));
    assert!(cfg.apply_cpus.is_empty());
    for bad in [0, 5] {
        cfg.apply_threads = bad;
        assert!(cfg.options(64 << 20).is_err(), "apply threads {bad}");
    }
    cfg.apply_threads = 3;
    assert!(cfg.options(64 << 20).is_ok());
    // Helpers only with a resolved worker CPU and a multi-CPU service set.
    assert_eq!(cfg.apply_helpers(), 0);
    cfg.cpu = Some(5);
    cfg.apply_cpus = vec![5];
    assert_eq!(cfg.apply_helpers(), 0);
    cfg.apply_cpus = vec![4, 5, 6, 7];
    assert_eq!(cfg.apply_helpers(), 2);
    // The memtable helper is layered on (effective) normal maintenance only.
    cfg.memtable_maintenance = true;
    assert!(cfg.options(64 << 20).is_err());
    cfg.normal_maintenance = true;
    cfg.isolate_cleaner = true;
    cfg.cleaner_cpu = Some(6);
    let o = cfg.options(64 << 20).unwrap();
    assert!(o.normal_maintenance && o.memtable_maintenance);
    cfg.cleaner_cpu = Some(5);
    let o = cfg.options(64 << 20).unwrap();
    assert!(!o.normal_maintenance && !o.memtable_maintenance);
}

#[test]
fn splinter_apply_slices_cover_every_point_once_in_flush_order() {
    let mut m = Memtable::new();
    for (id, n) in [(3u64, 5u32), (4, 0), (9, 7), (u64::MAX, 4)] {
        if n == 0 {
            m.del_range(1, id, Bytes::new(), None); // object with ranges, no points
        }
        for i in 0..n {
            m.put(
                1,
                id,
                Bytes::copy_from_slice(&i.to_be_bytes()),
                Bytes::from_static(b"v"),
            );
        }
    }
    let ids = m.sorted_ids();
    let m = Arc::new(m);
    let mut all = Vec::new();
    let whole = ApplyRound::new(m.clone(), &ids, usize::MAX);
    assert_eq!(whole.chunks.len(), 3, "one chunk per object with points");
    whole
        .drain(|k, _| {
            all.push(k.to_vec());
            Ok(())
        })
        .unwrap();
    assert_eq!(all.len(), 16);
    let mut sorted = all.clone();
    sorted.sort();
    assert_eq!(all, sorted, "flush order is global key order");
    for size in [1usize, 2, 3, 4, 5, 7, 16] {
        let round = ApplyRound::new(m.clone(), &ids, size);
        assert!(round.chunks.iter().all(|c| c.len >= 1 && c.len <= size));
        let mut joined = Vec::new();
        assert_eq!(
            round
                .drain(|k, _| {
                    joined.push(k.to_vec());
                    Ok(())
                })
                .unwrap(),
            round.chunks.len()
        );
        assert_eq!(joined, all, "chunks of {size} in claim order");
        // Concurrent claimers: every point exactly once, each chunk in key order.
        let round = Arc::new(ApplyRound::new(m.clone(), &ids, size));
        let seen = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|s| {
            for _ in 0..3 {
                let (round, seen) = (round.clone(), &seen);
                s.spawn(move || {
                    round
                        .drain(|k, _| {
                            seen.lock().unwrap().push(k.to_vec());
                            Ok(())
                        })
                        .unwrap()
                });
            }
        });
        let mut seen = seen.into_inner().unwrap();
        seen.sort();
        assert_eq!(seen, all, "concurrent chunks of {size}");
    }
    let round = ApplyRound::new(m.clone(), &ids, 4);
    let mut calls = 0;
    let failed = round.drain(|_, _| {
        calls += 1;
        if calls == 10 {
            Err(std::io::Error::from_raw_os_error(libc::EIO))
        } else {
            Ok(())
        }
    });
    assert!(failed.is_err());
    assert_eq!(calls, 10, "the first error stops the chunk");
    assert_eq!(
        round.drain(|_, _| Ok(())).unwrap(),
        0,
        "no claims after a failure"
    );
}

#[test]
fn splinter_parallel_apply_matches_expected_state_and_reopens_at_watermark() {
    let (_t, cfg, sb) = setup_io(IoMode::Buffered);
    let mut d = db(&cfg, &sb);
    let stack = splinterdb_lib::maintenance_stack_bytes().unwrap();
    d.apply_chunk = 256; // many chunks per helper at test sizes
    let pool = ApplyPool::start(&d.db, 0, 3, &[], stack).unwrap();
    assert_eq!(pool.helpers(), 3);
    let mut expected = std::collections::BTreeMap::new();
    // Uneven objects: four slices of one flush cross object boundaries.
    let mut first = Memtable::new();
    for (id, n) in [(0u64, 1500u32), (7, 2600), (u64::MAX, 900)] {
        for i in 0..n {
            let v = [id as u8, i as u8, (i >> 8) as u8];
            first.put(
                1,
                id,
                Bytes::copy_from_slice(&i.to_be_bytes()),
                Bytes::copy_from_slice(&v),
            );
            expected.insert((id, i.to_be_bytes().to_vec()), v.to_vec());
        }
    }
    let first = Arc::new(first);
    assert_eq!(
        d.flush_with(&first, &timing::Timings::default(), Some((&first, &pool)))
            .unwrap(),
        1
    );
    // Range deletion, re-puts inside the deleted range, overwrites and tombstones.
    let mut second = Memtable::new();
    let (lo, hi) = (100u32.to_be_bytes(), 2000u32.to_be_bytes());
    second.del_range(
        2,
        7,
        Bytes::copy_from_slice(&lo),
        Some(Bytes::copy_from_slice(&hi)),
    );
    expected.retain(|(id, k), _| !(*id == 7 && k.as_slice() >= &lo[..] && k.as_slice() < &hi[..]));
    for i in 100..2000u32 {
        second.put(
            3,
            7,
            Bytes::copy_from_slice(&i.to_be_bytes()),
            Bytes::from_static(b"again"),
        );
        expected.insert((7, i.to_be_bytes().to_vec()), b"again".to_vec());
    }
    for i in 0..1500u32 {
        second.put(
            3,
            0,
            Bytes::copy_from_slice(&i.to_be_bytes()),
            Bytes::from_static(b"over"),
        );
        expected.insert((0, i.to_be_bytes().to_vec()), b"over".to_vec());
    }
    for i in (0..900u32).step_by(2) {
        second.del(3, u64::MAX, Bytes::copy_from_slice(&i.to_be_bytes()));
        expected.remove(&(u64::MAX, i.to_be_bytes().to_vec()));
    }
    let second = Arc::new(second);
    assert!(
        ApplyRound::new(second.clone(), &second.sorted_ids(), d.apply_chunk)
            .chunks
            .len()
            >= 8,
        "test must use several chunks per helper"
    );
    assert_eq!(
        d.flush_with(&second, &timing::Timings::default(), Some((&second, &pool)))
            .unwrap(),
        3
    );
    drop(pool);
    d.db.close().unwrap();
    let d = db(&cfg, &sb);
    assert_eq!(d.watermark, 3);
    for (id, n) in [(0u64, 1500u32), (7, 2600), (u64::MAX, 900)] {
        for i in 0..n {
            let k = i.to_be_bytes();
            assert_eq!(
                d.db.get(&encoded(id, &k), usize::MAX).unwrap(),
                expected.get(&(id, k.to_vec())).cloned(),
                "object {id} key {i}"
            );
        }
    }
}

#[test]
fn splinter_parallel_apply_barrier_failure_keeps_the_previous_watermark() {
    let (_t, cfg, sb) = setup_io(IoMode::Buffered);
    let mut d = db(&cfg, &sb);
    let stack = splinterdb_lib::maintenance_stack_bytes().unwrap();
    d.apply_chunk = 256;
    let pool = ApplyPool::start(&d.db, 0, 2, &[], stack).unwrap();
    let mut first = Memtable::new();
    first.put(1, 5, Bytes::from_static(b"k"), Bytes::from_static(b"v"));
    let first = Arc::new(first);
    d.flush_with(&first, &timing::Timings::default(), Some((&first, &pool)))
        .unwrap();
    let mut second = Memtable::new();
    for i in 0..4096u32 {
        second.put(
            2,
            5,
            Bytes::copy_from_slice(&i.to_be_bytes()),
            Bytes::from_static(b"x"),
        );
    }
    let second = Arc::new(second);
    // Data barrier after the parallel apply fails: the watermark is never written.
    d.fail_barrier = Some(1);
    assert!(
        d.flush_with(&second, &timing::Timings::default(), Some((&second, &pool)))
            .is_err()
    );
    assert_eq!(d.watermark, 1);
    d.fail_barrier = None;
    drop(pool);
    d.db.close().unwrap();
    // Points may survive individually; native redo stays pinned to watermark 1.
    assert_eq!(db(&cfg, &sb).watermark, 1);
}

#[test]
fn splinter_worker_wakes_the_owner_after_each_published_completion() {
    let (_t, cfg, sb) = setup();
    let mut c = Client::open(&cfg, &sb, 0, 128 << 20, 0, 1).unwrap();
    let woken = Arc::new(AtomicU64::new(0));
    let counter = woken.clone();
    c.set_owner_wake(OwnerWake(Arc::new(move || {
        counter.fetch_add(1, Ordering::AcqRel);
    })));
    // The first install wins: a core's wake handle never changes.
    c.set_owner_wake(OwnerWake(Arc::new(|| panic!("second wake installed"))));
    assert!(!c.has_completion());
    let mut m = Memtable::new();
    m.put(1, 1, Bytes::from_static(b"k"), Bytes::from_static(b"v"));
    c.flush(Arc::new(m)).unwrap();
    let end = Instant::now() + Duration::from_secs(10);
    while woken.load(Ordering::Acquire) == 0 {
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT SplinterDB owner wake"
        );
        std::thread::yield_now();
    }
    // Publish-then-wake: the completion is visible to the owner's re-check.
    assert!(c.has_completion());
    c.poll();
    assert!(!c.has_completion());
    assert_eq!(c.flushed, Some(1));
    assert_eq!(woken.load(Ordering::Acquire), 1, "one wake per completion");
}

#[test]
fn splinter_durability_thread_writes_the_watermark_only_after_the_data_barrier() {
    for (no_log, fail) in [false, true]
        .into_iter()
        .flat_map(|m| [None, Some(1u8), Some(2)].map(|f| (m, f)))
    {
        let (_t, cfg, sb) = setup_mode(IoMode::Buffered, no_log);
        let mut d = db(&cfg, &sb);
        let mut first = Memtable::new();
        first.put(1, 1, Bytes::from_static(b"a"), Bytes::from_static(b"1"));
        assert_eq!(
            d.flush_timed(&first, &timing::Timings::default()).unwrap(),
            1
        );
        let stack = splinterdb_lib::maintenance_stack_bytes().unwrap();
        let metrics = Arc::new(Metrics::default());
        let mut dur = Durability::start(
            &d.db,
            0,
            &[],
            stack,
            metrics,
            std::thread::current(),
            (fail, d.checkpointed),
        )
        .unwrap();
        assert!(dur.try_finished().is_none() && dur.wait().is_none());
        let mut second = Memtable::new();
        second.put(2, 1, Bytes::from_static(b"b"), Bytes::from_static(b"2"));
        let lsn = d
            .apply_with(&second, &timing::Timings::default(), None)
            .unwrap();
        dur.submit(lsn).unwrap();
        let r = dur.wait().expect("outstanding");
        assert!(dur.wait().is_none(), "one result per submitted flush");
        drop(dur);
        match fail {
            None => assert_eq!(r.unwrap(), 2),
            Some(_) => assert!(r.is_err(), "{fail:?} must fail the flush"),
        }
        d.db.close().unwrap();
        let d = db(&cfg, &sb);
        // A failed data barrier never writes the watermark; after a failed watermark
        // barrier the mark may still reach the image, but only after its data.
        match fail {
            None => assert_eq!(d.watermark, 2),
            Some(1) => assert_eq!(d.watermark, 1),
            _ => assert!(matches!(d.watermark, 1 | 2)),
        }
        assert_eq!(
            d.db.get(b"\x01\0\0\0\0\0\0\0\x01b", 8).unwrap().as_deref(),
            Some(&b"2"[..])
        );
    }
}

#[test]
fn splinter_pipelined_flushes_become_visible_then_durable_in_order() {
    let (_t, mut cfg, sb) = setup();
    cfg.pipelined_barrier = true;
    let mut c = Client::open(&cfg, &sb, 0, 128 << 20, 0, 1).unwrap();
    let (mut applied, mut published) = (Vec::new(), Vec::new());
    let end = Instant::now() + Duration::from_secs(20);
    let mut step = |c: &mut Client| {
        c.poll();
        assert!(c.failure.is_none(), "{:?}", c.failure);
        if let Some(a) = c.take_applied() {
            applied.push(a);
        }
        // The shard publishes `flushed` (here: taken) before the next flush.
        if let Some(f) = c.flushed.take() {
            published.push(f);
        }
        assert!(Instant::now() < end, "WARNING TIMEOUT pipelined flushes");
        std::thread::yield_now();
    };
    for lsn in 1..=6u64 {
        while !c.can_flush() {
            step(&mut c);
        }
        let mut m = Memtable::new();
        m.put(
            lsn,
            1,
            Bytes::copy_from_slice(&lsn.to_be_bytes()),
            Bytes::from_static(b"v"),
        );
        c.flush(Arc::new(m)).unwrap();
    }
    while c.busy() {
        step(&mut c);
    }
    assert_eq!(applied, [1, 2, 3, 4, 5, 6], "visible in order");
    assert_eq!(published, [1, 2, 3, 4, 5, 6], "durable in order");
    assert_eq!(c.watermark, 6);
    drop(c);
    let d = db(&cfg, &sb);
    assert_eq!(d.watermark, 6);
    for lsn in 1..=6u64 {
        let mut k = vec![1];
        k.extend_from_slice(&1u64.to_be_bytes());
        k.extend_from_slice(&lsn.to_be_bytes());
        assert_eq!(d.db.get(&k, 8).unwrap().as_deref(), Some(&b"v"[..]));
    }
}

#[test]
fn splinter_no_log_mode_is_fixed_by_the_image_marker_not_the_config() {
    // A no-log image stays checkpoint-durable even if the config later says otherwise.
    let (_t, mut cfg, sb) = setup_mode(IoMode::Buffered, true);
    assert!(cfg.path(&sb, 0).unwrap().with_extension("nolog").exists());
    cfg.no_log = false;
    let mut d = db(&cfg, &sb);
    assert!(d.checkpointed);
    for lsn in 1..=3u64 {
        let mut m = Memtable::new();
        for i in 0..500u32 {
            m.put(
                lsn,
                1,
                Bytes::copy_from_slice(&i.to_be_bytes()),
                Bytes::copy_from_slice(&lsn.to_le_bytes()),
            );
        }
        assert_eq!(d.flush_timed(&m, &timing::Timings::default()).unwrap(), lsn);
    }
    d.db.close().unwrap();
    let d = db(&cfg, &sb);
    assert_eq!(d.watermark, 3);
    let mut k = vec![1];
    k.extend_from_slice(&1u64.to_be_bytes());
    k.extend_from_slice(&7u32.to_be_bytes());
    assert_eq!(d.db.get(&k, 16).unwrap(), Some(3u64.to_le_bytes().to_vec()));
    // A logged image never switches to checkpoint durability by configuration.
    let (_t2, mut logged, sb2) = setup_mode(IoMode::Buffered, false);
    logged.no_log = true;
    assert!(!db(&logged, &sb2).checkpointed);
}

#[test]
fn splinter_pipelined_flushes_on_a_no_log_image_publish_in_order() {
    let (_t, mut cfg, sb) = setup_mode(IoMode::Buffered, true);
    cfg.pipelined_barrier = true;
    let mut c = Client::open(&cfg, &sb, 0, 128 << 20, 0, 1).unwrap();
    let (mut applied, mut published) = (Vec::new(), Vec::new());
    let end = Instant::now() + Duration::from_secs(30);
    let mut step = |c: &mut Client| {
        c.poll();
        assert!(c.failure.is_none(), "{:?}", c.failure);
        applied.extend(c.take_applied());
        published.extend(c.flushed.take());
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT no-log pipelined flushes"
        );
        std::thread::yield_now();
    };
    for lsn in 1..=5u64 {
        while !c.can_flush() {
            step(&mut c);
        }
        let mut m = Memtable::new();
        m.put(
            lsn,
            1,
            Bytes::copy_from_slice(&lsn.to_be_bytes()),
            Bytes::from_static(b"v"),
        );
        c.flush(Arc::new(m)).unwrap();
    }
    while c.busy() {
        step(&mut c);
    }
    assert_eq!(applied, [1, 2, 3, 4, 5]);
    assert_eq!(published, [1, 2, 3, 4, 5]);
    drop(c);
    let d = db(&cfg, &sb);
    assert!(d.checkpointed);
    assert_eq!(d.watermark, 5);
}
