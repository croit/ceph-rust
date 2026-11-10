// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use super::*;
use crate::dev::{SimClock, SimConfig, SimDisk};
use crate::layout::{MkfsParams, mkfs};
use std::sync::atomic::AtomicU64;

mod attribution;
mod handoff;
mod owner_wake;

const MEM: usize = 8 << 20;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "croit-flashstore-rocks-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn fixture() -> (Temp, Config, Superblock) {
    let temp = Temp::new();
    let disk = SimDisk::new(SimConfig::new(64 << 20));
    let (sb, _) = mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards: 1,
            align_blocks: 1,
            wal_blocks: 128,
            ..Default::default()
        },
    )
    .unwrap();
    let mut cfg = Config::new(temp.0.clone());
    cfg.allow_non_nvme = true;
    create(&cfg, &sb, MEM).unwrap();
    (temp, cfg, sb)
}

fn db(cfg: &Config, sb: &Superblock, ro: bool) -> Database {
    Database::open(&cfg.path(sb, 0).unwrap(), &identity(sb, 0), MEM, ro).unwrap()
}

fn get(d: &Database, id: u64, k: &[u8]) -> Option<Bytes> {
    let Answer::Entries(v, _) = d
        .read(&Query::Keys {
            id,
            keys: vec![Bytes::copy_from_slice(k)],
        })
        .unwrap()
    else {
        panic!("entries");
    };
    v.first().map(|(_, v)| v.clone())
}

#[test]
fn subcompaction_bound_uses_only_the_explicit_service_budget() {
    let mut cfg = Config::new(PathBuf::from("/unused"));
    assert_eq!(cfg.subcompactions(), 1);
    cfg.cpu = Some(7); // A CPU ID, not a CPU count or proof of available capacity.
    assert_eq!(cfg.subcompactions(), 1);
    for (cpus, expected) in [
        (&[7][..], 1),
        (&[3, 7][..], 1),
        (&[3, 7, 11][..], 1),
        (&[3, 7, 11, 19][..], 2),
        (&[1, 3, 5, 7, 9, 11, 13, 15][..], 2),
    ] {
        cfg.set_cpu_budget(0, cpus).unwrap();
        assert_eq!(cfg.subcompactions(), expected);
    }
    assert!(cfg.set_cpu_budget(0, &[3, 3, 7, 11]).is_err());
    assert_eq!(cfg.subcompactions(), 2, "failed configuration is atomic");
    assert!(options(MEM, 0, &Tuning::default()).is_err());
    assert!(options(MEM, 3, &Tuning::default()).is_err());
}

#[test]
fn reusable_point_key_has_exact_binary_encoding_and_retains_only_capacity() {
    let mut scratch = Vec::new();
    key_into(&mut scratch, 7, &[0xaa; 4096]);
    let ptr = scratch.as_ptr();
    let capacity = scratch.capacity();
    for (id, prefix) in [
        (0, [1, 0, 0, 0, 0, 0, 0, 0, 0]),
        (1, [1, 0, 0, 0, 0, 0, 0, 0, 1]),
        (0x0102030405060708, [1, 1, 2, 3, 4, 5, 6, 7, 8]),
        (u64::MAX, [1, 255, 255, 255, 255, 255, 255, 255, 255]),
    ] {
        for suffix in [b"".as_slice(), b"\0\xff\0", b"short", b"x"] {
            let mut expected = prefix.to_vec();
            expected.extend_from_slice(suffix);
            key_into(&mut scratch, id, suffix);
            assert_eq!(scratch, expected);
            assert_eq!(
                scratch.as_ptr(),
                ptr,
                "no per-point allocation after growth"
            );
            assert_eq!(scratch.capacity(), capacity);
        }
    }
}

#[test]
fn materialization_copies_reused_point_keys_before_sync_and_reopen() {
    let (_temp, cfg, sb) = fixture();
    let mut d = db(&cfg, &sb, false);
    let mut long = vec![b'a'; 2048];
    long[1] = 0;
    let keys = [
        Bytes::new(),
        Bytes::from(long),
        Bytes::from_static(b"b"),
        Bytes::from_static(b"\xff"),
    ];
    let mut model = std::collections::BTreeMap::new();
    let mut initial = Memtable::new();
    for id in [0, 9, u64::MAX] {
        for (index, key) in keys.iter().enumerate() {
            let value = Bytes::from(format!("object={id},key={index}"));
            initial.put(1, id, key.clone(), value.clone());
            model.insert((id, key.clone()), value);
        }
    }
    assert_eq!(d.flush(&initial).unwrap(), 1);
    let mut changes = Memtable::new();
    changes.del_range(
        2,
        0,
        Bytes::from_static(b"a"),
        Some(Bytes::from_static(b"c")),
    );
    model.remove(&(0, keys[1].clone()));
    model.remove(&(0, keys[2].clone()));
    changes.put(3, 0, keys[2].clone(), Bytes::from_static(b"reinserted"));
    model.insert((0, keys[2].clone()), Bytes::from_static(b"reinserted"));
    changes.del(4, 9, Bytes::new());
    model.remove(&(9, Bytes::new()));
    changes.put(
        5,
        u64::MAX,
        keys[1].clone(),
        Bytes::from_static(b"overwritten-long"),
    );
    model.insert(
        (u64::MAX, keys[1].clone()),
        Bytes::from_static(b"overwritten-long"),
    );
    assert_eq!(d.flush(&changes).unwrap(), 5);
    drop(d);
    let d = db(&cfg, &sb, false);
    assert_eq!(d.watermark, 5);
    for id in [0, 9, u64::MAX] {
        let Answer::Page(got, end) = d
            .read(&Query::Page {
                id,
                from: Bytes::new(),
                excl: false,
                prefix: Bytes::new(),
                entries: PAGE,
                versions: [(0, 0); 3],
                session: None,
            })
            .unwrap()
        else {
            panic!("page");
        };
        assert_eq!(end, PageEnd::End);
        let expected: Vec<_> = model
            .iter()
            .filter(|((object, _), _)| *object == id)
            .map(|((_, key), value)| (key.clone(), value.clone()))
            .collect();
        assert_eq!(got.to_pairs(), expected, "object={id}");
    }
}

fn saved_options(path: &Path) -> HashMap<String, String> {
    let name = std::fs::read_dir(path)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("OPTIONS-")
        })
        .max()
        .expect("actual persisted RocksDB options");
    std::fs::read_to_string(name)
        .unwrap()
        .lines()
        .filter_map(|line| line.trim().split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

#[test]
fn bounded_subcompaction_is_applied_without_larger_buffers_or_relaxed_stalls() {
    for parallelism in [1, 2] {
        let (_temp, cfg, sb) = fixture();
        let path = cfg.path(&sb, 0).unwrap();
        let _db = Database::open_profiled(&path, &identity(&sb, 0), MEM, false, None, parallelism)
            .unwrap();
        let o = saved_options(&path);
        for (key, value) in [
            ("max_subcompactions", parallelism.to_string()),
            (
                "max_background_jobs",
                Tuning::default().background_jobs.to_string(),
            ),
            ("write_buffer_size", (MEM / 4).to_string()),
            ("max_write_buffer_number", "2".into()),
            ("target_file_size_base", (MEM / 2).to_string()),
            ("level0_file_num_compaction_trigger", "4".into()),
            ("level0_slowdown_writes_trigger", "20".into()),
            ("level0_stop_writes_trigger", "36".into()),
            ("disable_auto_compactions", "false".into()),
        ] {
            assert_eq!(o.get(key), Some(&value), "effective {key}");
        }
    }
}

#[test]
fn two_subcompactions_preserve_overwrites_and_native_watermark_on_reopen() {
    fn value(round: u64, key: u32) -> Bytes {
        // Independently generated incompressible values keep this fixture above
        // the range-splitting threshold even with production LZ4 enabled.
        let mut state = (u64::from(key) + 1) ^ (round << 32);
        let mut out = vec![0; 256];
        for byte in &mut out {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        Bytes::from(out)
    }
    let (_temp, cfg, sb) = fixture();
    let path = cfg.path(&sb, 0).unwrap();
    let mut d = Database::open_profiled(&path, &identity(&sb, 0), MEM, false, None, 2).unwrap();
    // Only this small test forces flush/compaction and small output files to
    // exercise real parallel ranges deterministically, not production policy.
    d.db.set_options(&[
        ("disable_auto_compactions", "true"),
        ("level0_file_num_compaction_trigger", "2"),
        ("target_file_size_base", "524288"),
        ("write_buffer_size", "33554432"),
    ])
    .unwrap();
    for round in 1..=3 {
        let mut m = Memtable::new();
        // Distinct bulk ranges avoid coincident sampled-anchor layouts. Shared
        // even-key sentinels span every range and must resolve to the last round.
        for index in 0u32..65536 {
            let key = 2 * ((round as u32 - 1) * 65536 + index) + 1;
            m.put(
                round,
                7,
                Bytes::copy_from_slice(&key.to_be_bytes()),
                value(round, key),
            );
        }
        for key in [0u32, 131072, 262144, 393216] {
            m.put(
                round,
                7,
                Bytes::copy_from_slice(&key.to_be_bytes()),
                value(round, key),
            );
        }
        assert_eq!(d.flush(&m).unwrap(), round);
        d.db.flush().unwrap();
    }
    d.db.set_options(&[("disable_auto_compactions", "false")])
        .unwrap();
    let mut wait = rocksdb_lib::WaitForCompactOptions::default();
    wait.set_timeout(10_000_000);
    d.db.wait_for_compact(&wait).unwrap();
    drop(d);
    let log = std::fs::read_to_string(path.join("LOG")).unwrap();
    assert!(
        log.contains("\"num_subcompactions\": 2"),
        "fixture must execute two real compaction ranges: {:?}",
        log.lines()
            .filter(|l| l.contains("num_subcompactions"))
            .collect::<Vec<_>>()
    );
    let reopened = db(&cfg, &sb, true);
    assert_eq!(reopened.watermark, 3);
    for round in 1..=3 {
        for index in 0u32..65536 {
            let key = 2 * ((round as u32 - 1) * 65536 + index) + 1;
            assert_eq!(
                get(&reopened, 7, &key.to_be_bytes()),
                Some(value(round, key))
            );
        }
    }
    for key in [0u32, 131072, 262144, 393216] {
        assert_eq!(get(&reopened, 7, &key.to_be_bytes()), Some(value(3, key)));
    }
}

#[test]
fn worker_cpu_budget_uses_selected_ids_and_never_adds_support_cpus() {
    let mut cfg = Config::new(PathBuf::from("/unused"));
    assert_eq!(cfg.cpu, None);
    assert!(cfg.background_cpus.is_empty());
    // Sparse IDs deliberately differ from logical core IDs and cpu + 1.
    let cpus = [2, 7, 11, 19];
    for (owner, expected) in [7, 11, 19, 2].into_iter().enumerate() {
        cfg.set_cpu_budget(owner, &cpus).unwrap();
        assert_eq!(cfg.cpu, Some(expected));
        assert_ne!(cfg.cpu, Some(cpus[owner]));
        assert_eq!(cfg.background_cpus, cpus);
        // More than one shard per owner must not expand its worker budget.
        cfg.set_cpu_budget(owner, &cpus).unwrap();
        assert_eq!(cfg.cpu, Some(expected));
    }
    cfg.set_cpu_budget(0, &[7]).unwrap();
    assert_eq!(cfg.cpu, Some(7));
    assert_eq!(cfg.background_cpus, [7]);
    for (owner, cpus) in [(0, &[][..]), (2, &[2, 7][..]), (0, &[2, 2][..])] {
        assert!(cfg.set_cpu_budget(owner, cpus).is_err());
        assert_eq!(cfg.cpu, Some(7), "invalid selection must be atomic");
        assert_eq!(cfg.background_cpus, [7]);
    }
    #[cfg(target_os = "linux")]
    assert!(
        cfg.set_cpu_budget(0, &[libc::CPU_SETSIZE as usize])
            .is_err()
    );
}

#[test]
fn worker_cpu_placement_option_selects_owner_next_or_whole_budget() {
    let cpus = [2, 7, 11, 19];
    let mut cfg = Config::new(PathBuf::from("/unused"));
    assert_eq!(cfg.worker_cpu, WorkerCpu::Next, "historical default");
    cfg.worker_cpu = WorkerCpu::Owner;
    for owner in 0..cpus.len() {
        cfg.set_cpu_budget(owner, &cpus).unwrap();
        assert_eq!(cfg.cpu, Some(cpus[owner]));
        assert_eq!(cfg.background_cpus, cpus);
    }
    cfg.worker_cpu = WorkerCpu::Float;
    cfg.set_cpu_budget(1, &cpus).unwrap();
    assert_eq!(cfg.cpu, None, "float: no single-CPU pin");
    assert_eq!(cfg.background_cpus, cpus, "float stays inside the budget");
    // Invalid budgets stay atomic for every mode.
    assert!(cfg.set_cpu_budget(0, &[2, 2]).is_err());
    assert_eq!(cfg.cpu, None);
    for (s, v) in [
        ("next", WorkerCpu::Next),
        ("OWNER", WorkerCpu::Owner),
        ("Float", WorkerCpu::Float),
    ] {
        assert_eq!(s.parse::<WorkerCpu>(), Ok(v));
    }
    assert!("spread".parse::<WorkerCpu>().is_err());
}

#[test]
fn tuning_defaults_are_bounded_and_tuned_databases_open() {
    let t = Tuning::default();
    assert_eq!(
        (
            t.low_threads,
            t.high_threads,
            t.background_jobs,
            t.write_buffers,
            t.l0_slowdown,
            t.l0_stop
        ),
        (2, 1, 4, 2, 0, 0),
        "defaults: two compaction threads, four background jobs, library L0 triggers"
    );
    assert_eq!(Config::new(PathBuf::from("/unused")).tuning, t);
    for bad in [
        Tuning {
            low_threads: 0,
            ..t
        },
        Tuning {
            low_threads: 9,
            ..t
        },
        Tuning {
            high_threads: 5,
            ..t
        },
        Tuning {
            background_jobs: 0,
            ..t
        },
        Tuning {
            write_buffers: 1,
            ..t
        },
        Tuning {
            l0_slowdown: 1025,
            ..t
        },
        Tuning {
            l0_slowdown: 20,
            l0_stop: 10,
            ..t
        },
    ] {
        assert!(bad.validate().is_err(), "{bad:?}");
        assert!(options(MEM, 1, &bad).is_err(), "{bad:?}");
    }
    let tuned = Tuning {
        low_threads: 3,
        high_threads: 2,
        background_jobs: 6,
        write_buffers: 4,
        l0_slowdown: 8,
        l0_stop: 16,
    };
    assert!(tuned.validate().is_ok());
    // A tuned database opens and serves the same data (limits only).
    let (_temp, cfg, sb) = fixture();
    let mut d = db(&cfg, &sb, false);
    let mut m = Memtable::new();
    m.put(1, 9, Bytes::from_static(b"k"), Bytes::from_static(b"v"));
    d.flush(&m).unwrap();
    drop(d);
    let d = Database::open_tuned(
        &cfg.path(&sb, 0).unwrap(),
        &identity(&sb, 0),
        MEM,
        false,
        None,
        1,
        &tuned,
    )
    .unwrap();
    assert!(d.watermark >= 1);
}

#[cfg(target_os = "linux")]
#[test]
fn worker_affinity_can_expand_to_service_budget_then_narrow_without_changing_caller() {
    fn affinity() -> Vec<usize> {
        // SAFETY: initialized mask, valid writable output for this thread.
        unsafe {
            let mut mask: libc::cpu_set_t = std::mem::zeroed();
            assert_eq!(
                libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut mask),
                0
            );
            (0..libc::CPU_SETSIZE as usize)
                .filter(|c| libc::CPU_ISSET(*c, &mask))
                .collect()
        }
    }
    let original = affinity();
    let selected: Vec<_> = original.iter().copied().take(2).collect();
    assert!(!selected.is_empty());
    let allowed = selected.clone();
    std::thread::spawn(move || {
        pin(Some(allowed[0])).unwrap(); // owner-like inherited single CPU
        assert_eq!(affinity(), [allowed[0]]);
        pin_cpus(&allowed).unwrap(); // DB pools inherit only admitted CPUs
        assert_eq!(affinity(), allowed);
        pin(allowed.last().copied()).unwrap(); // blocking worker moves away
        assert_eq!(affinity(), [*allowed.last().unwrap()]);
        assert!(pin(Some(libc::CPU_SETSIZE as usize)).is_err());
    })
    .join()
    .unwrap();
    assert_eq!(affinity(), original, "never change the owner's affinity");
}

#[test]
fn worker_metrics_properties_are_supported_by_the_actual_database() {
    let (_temp, cfg, sb) = fixture();
    let d = db(&cfg, &sb, false);
    let metrics = metrics::Metrics::default();
    metrics.observe(&d);
    let sample = metrics.sample();
    assert!(sample.valid, "missing actual RocksDB property: {sample:?}");
    assert_eq!(sample.errors, 0);
    assert!(sample.age_ns < 1_000_000_000);
    assert_eq!(sample.values[5], 0, "fresh DB must not be write-stopped");
}

#[test]
fn profiled_materialization_keeps_synced_restart_and_samples_real_database_counters() {
    let (_temp, cfg, sb) = fixture();
    assert!(!cfg.profile, "profiling is opt-in");
    let metrics = Arc::new(metrics::Metrics::new_profiled(true));
    let path = cfg.path(&sb, 0).unwrap();
    let mut d = Database::open_profiled(
        &path,
        &identity(&sb, 0),
        MEM,
        false,
        Some(metrics.clone()),
        1,
    )
    .unwrap();
    let mut m = Memtable::new();
    m.put(1, 7, Bytes::from_static(b"key"), Bytes::from_static(b"old"));
    m.put(2, 7, Bytes::from_static(b"key"), Bytes::from_static(b"new"));
    m.put(
        3,
        7,
        Bytes::from_static(b"other"),
        Bytes::from_static(b"value"),
    );
    assert_eq!(d.flush(&m).unwrap(), 3);
    metrics.observe(&d);
    let s = metrics.profile.sample();
    assert_eq!(
        s[metrics::profile::VALID],
        1,
        "actual property support: {s:?}"
    );
    assert_eq!(s[metrics::profile::ERRORS], 0);
    assert!(s[7] >= 1, "synchronous DB WAL write must be counted");
    assert!(s[8] > 0, "WAL bytes must be counted");
    assert_eq!(
        s[metrics::profile::POINTS],
        2,
        "collapsed final mutations, not input operations"
    );
    assert_eq!(s[metrics::profile::RANGES], 0);
    assert!(s[metrics::profile::BATCH_BYTES] > 10);
    assert_eq!(&s[38..43], &[1, 0, 0, 0, 0]);
    assert_eq!(s[43], 0);
    assert!(s[metrics::profile::BUILD_NS] > 0);
    assert!(s[metrics::profile::WRITE_NS] > 0);
    #[cfg(target_os = "linux")]
    {
        assert_eq!(s[metrics::profile::CPU_SAMPLES], 1);
        assert_eq!(s[metrics::profile::CPU_ERRORS], 0);
    }
    drop(d);
    let reopened = db(&cfg, &sb, true);
    assert_eq!(reopened.watermark, 3);
    assert_eq!(get(&reopened, 7, b"key"), Some(Bytes::from_static(b"new")));
    assert_eq!(
        get(&reopened, 7, b"other"),
        Some(Bytes::from_static(b"value"))
    );
}

#[test]
fn profiled_worker_counts_queue_completion_and_union_backpressure_without_changing_results() {
    let (_temp, mut cfg, sb) = fixture();
    cfg.profile = true;
    let mut client = Client::open(&cfg, &sb, 0, MEM, 0, 0).unwrap();
    client.blocked_started = Some(Instant::now() - Duration::from_millis(9));
    client.note_blocked(); // repeated refusals do not restart an interval
    assert!(client.profile_metrics()[metrics::profile::BACKPRESSURE_NS] >= 9_000_000);
    client.note_unblocked();
    let closed = client.profile_metrics()[metrics::profile::BACKPRESSURE_NS];
    client.note_unblocked();
    assert_eq!(
        client.profile_metrics()[metrics::profile::BACKPRESSURE_NS],
        closed
    );
    client.note_blocked();
    client.note_blocked();
    assert_eq!(
        client.profile_metrics()[metrics::profile::BACKPRESSURE_INTERVALS],
        1
    );
    client.note_unblocked();

    let mut m = Memtable::new();
    m.put(1, 1, Bytes::from_static(b"k"), Bytes::from_static(b"v"));
    client.flush(Arc::new(m)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while client.flushed != Some(1) {
        client.poll();
        assert!(client.failure.is_none(), "{:?}", client.failure);
        assert!(Instant::now() < deadline, "profiled worker timeout");
        std::thread::yield_now();
    }
    let before = client.profile_metrics();
    assert!(before[metrics::profile::QUEUE_NS] > 0);
    assert!(before[metrics::profile::COMPLETION_NS] > 0);
    client.publication_started = Some(Instant::now() - Duration::from_millis(17));
    client.note_published();
    let published = client.profile_metrics()[metrics::profile::PUBLICATION_NS];
    assert!(published >= 17_000_000);
    client.note_published();
    assert_eq!(
        client.profile_metrics()[metrics::profile::PUBLICATION_NS],
        published
    );
}

#[test]
fn freeze_profile_survives_busy_retry_and_never_fabricates_missing_or_mismatched_waits() {
    let (_temp, mut cfg, sb) = fixture();
    cfg.profile = true;
    let mut client = Client::open(&cfg, &sb, 0, MEM, 0, 0).unwrap();
    let mut m = Memtable::new();
    m.put(1, 1, Bytes::from_static(b"k"), Bytes::from_static(b"v"));
    let m = Arc::new(m);
    client.note_frozen(1, 70000, 0);
    let started = client.freeze_profile.unwrap().1;
    client.flushing = true;
    assert!(matches!(client.flush(m.clone()), Err(StoreError::Busy)));
    assert_eq!(client.freeze_profile, Some((1, started)));
    assert_eq!(client.profile_metrics()[30], 0);
    client.flushing = false;
    client.flush(m).unwrap();
    let s = client.profile_metrics();
    assert_eq!(&s[27..31], &[1, 70000, 1, 1]);
    assert!(s[31] > 0);
    assert_eq!(s[32], 0);
    assert_eq!(&s[33..38], &[0, 0, 1, 0, 0]);
    assert!(client.freeze_profile.is_none());
    client.note_enqueued(1, Instant::now()); // No tag: no invented zero sample.
    assert_eq!(client.profile_metrics()[30], 1);
    client.note_frozen(2, 1, 2);
    client.note_enqueued(3, Instant::now()); // Invalid identity: counted, not timed.
    assert_eq!(client.profile_metrics()[30], 1);
    assert_eq!(client.profile_metrics()[32], 1);
    client.note_frozen(4, 1, 4);
    client.note_frozen(5, 1, 4); // Lost/replaced tag is explicit.
    assert_eq!(client.profile_metrics()[32], 2);
}

#[test]
fn profiled_page_stages_keep_binary_results_and_count_credit_refusal_and_empty_end() {
    let (_temp, cfg, sb) = fixture();
    let metrics = Arc::new(metrics::Metrics::new_profiled(true));
    let path = cfg.path(&sb, 0).unwrap();
    let mut d = Database::open_profiled(
        &path,
        &identity(&sb, 0),
        MEM,
        false,
        Some(metrics.clone()),
        1,
    )
    .unwrap();
    let mut mem = Memtable::new();
    mem.put(
        1,
        7,
        Bytes::from_static(b"\0\xff"),
        Bytes::from_static(b"value"),
    );
    d.flush(&mem).unwrap();
    let q = Query::Page {
        id: 7,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::new(),
        entries: 1024,
        versions: [(0, 0); 3],
        session: None,
    };
    assert!(matches!(
        d.page_limit(&q, &[None, None, None], 1),
        Err(StoreError::TxnTooLarge)
    ));
    let Answer::Page(entries, end) = d.page(&q, &[None, None, None]).unwrap() else {
        panic!("page");
    };
    assert_eq!(
        entries.to_pairs(),
        vec![(Bytes::from_static(b"\0\xff"), Bytes::from_static(b"value"))]
    );
    assert!(matches!(end, PageEnd::End));
    let mut empty = q.clone();
    if let Query::Page { from, excl, .. } = &mut empty {
        *from = Bytes::from_static(b"\0\xff");
        *excl = true;
    }
    assert!(
        matches!(d.page(&empty, &[None, None, None]).unwrap(), Answer::Page(ref v, PageEnd::End) if v.is_empty())
    );
    let s = metrics.profile.sample();
    assert_eq!(&s[44..46], &[3, 1]);
    assert_eq!(s[46] + s[47], 3);
    #[cfg(target_os = "linux")]
    assert_eq!(&s[46..48], &[3, 0]);
    for i in [48, 50, 52, 54] {
        assert!(s[i] > 0, "missing page stage {i}");
    }
    assert!(
        d.page_limit(&Query::Ids { after: None }, &[None, None, None], 1)
            .is_err()
    );
    assert_eq!(
        metrics.profile.sample()[44],
        3,
        "non-page query is not a page attempt"
    );
}

#[test]
fn rapid_materialization_does_not_resample_diagnostics_per_batch() {
    let (_temp, cfg, sb) = fixture();
    let mut client = Client::open(&cfg, &sb, 0, MEM, 0, 0).unwrap();
    let started = Instant::now();
    for lsn in 1..=64 {
        let mut m = Memtable::new();
        m.put(
            lsn,
            1,
            Bytes::from_static(b"key"),
            Bytes::from_static(b"value"),
        );
        client.flush(Arc::new(m)).unwrap();
        while client.flushed != Some(lsn) {
            client.poll();
            assert!(client.failure.is_none(), "{:?}", client.failure);
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "worker test timeout"
            );
            std::thread::yield_now();
        }
        client.flushed = None;
    }
    let elapsed = started.elapsed();
    let sample = client.metrics();
    assert_eq!(sample.work[0], 64);
    assert_eq!(
        client.profile_metrics(),
        [0; metrics::profile::LEN],
        "ordinary materialization does not opt into profiling"
    );
    assert!(sample.work[8] > 0);
    assert_eq!(sample.work[9], MEM as u64 / 2);
    let periodic_bound = elapsed.as_millis() / 250 + 3; // bootstrap plus boundary slack
    assert!(
        u128::from(sample.work[6]) <= periodic_bound,
        "{} diagnostic walks for 64 materializations in {elapsed:?}; bound={periodic_bound}",
        sample.work[6]
    );
}

#[test]
fn credit_expiry_boundary_reports_exactly_the_actual_ownership_transition() {
    let (_temp, cfg, sb) = fixture();
    let mut client = Client::open(&cfg, &sb, 0, MEM, 0, 0).unwrap();
    client.read_session(Some((1, 1)), false);
    client.admit_scan((1, 1), 128).unwrap();
    client.read_session(None, true);
    client.read_session(Some((2, 1)), true);
    assert!(matches!(
        client.admit_scan((2, 1), 128),
        Err(StoreError::Miss)
    ));
    assert!(client.needs_poll());
    assert!(
        !client.busy(),
        "credit waiting is not worker/materialization busy"
    );
    assert!(!client.expire_session_after(Duration::from_secs(30) - Duration::from_nanos(1)));
    assert_eq!(client.retained_session(), Some((1, 1)));
    assert!(client.expire_session_after(Duration::from_secs(30)));
    assert_eq!(client.retained_session(), None);
    assert!(!client.needs_poll());
    assert!(
        !client.expire_session_after(Duration::from_secs(30) + Duration::from_nanos(1)),
        "idle expiry must not create another wake"
    );
    client.admit_scan((2, 1), 128).unwrap();
}

#[test]
fn scan_admission_renews_only_at_slice_boundaries_including_long_preemption() {
    let (_temp, cfg, sb) = fixture();
    let mut client = Client::open(&cfg, &sb, 0, MEM, 0, 0).unwrap();
    let start = Instant::now();
    client.test_credit_clock(start);
    client.read_session(Some((1, 1)), false);
    let before = client.test_credit_clock_reads();
    {
        let mut admission = client.scan_admission((1, 1)).unwrap();
        assert_eq!(admission.client.test_credit_clock_reads() - before, 2);
        // Test-only time injection while the real exclusive permit is live.
        admission
            .client
            .test_credit_clock(start + Duration::from_secs(31));
        for bytes in 1..=256 {
            admission.charge(bytes).unwrap();
        }
        assert_eq!(admission.client.test_credit_clock_reads() - before, 2);
        assert_eq!(admission.client.touched, start);
        assert_eq!(admission.client.retained_session(), Some((1, 1)));
        assert_eq!(admission.client.scan_charge, 256);
    }
    assert_eq!(client.test_credit_clock_reads() - before, 3);
    assert_eq!(client.touched, start + Duration::from_secs(31));
    client.read_session(None, true);
    client.test_credit_clock(start + Duration::from_secs(61) - Duration::from_nanos(1));
    assert!(
        !client.poll(),
        "an active preempted slice restarted its idle lease"
    );
    client.test_credit_clock(start + Duration::from_secs(61));
    assert!(client.poll(), "exactly30s idle releases the owner");
    assert_eq!(client.retained_session(), None);
    assert_eq!(client.scan_charge, 0);
    assert!(!client.poll(), "expiry wakes exactly once");
}

#[test]
fn scan_admission_competitor_cannot_renew_or_change_owner_credits() {
    let (_temp, cfg, sb) = fixture();
    let mut client = Client::open(&cfg, &sb, 0, MEM, 0, 0).unwrap();
    let start = Instant::now();
    client.test_credit_clock(start);
    client.read_session(Some((1, 1)), false);
    client.admit_scan((1, 1), 123).unwrap();
    client.read_session(None, true); // a later request, not a nested preparation
    client.test_credit_clock(start + Duration::from_secs(29));
    client.read_session(Some((2, 1)), true);
    let before = client.test_credit_clock_reads();
    for _ in 0..3 {
        assert!(matches!(
            client.scan_admission((2, 1)),
            Err(StoreError::Miss)
        ));
        assert_eq!(client.touched, start);
        assert_eq!(client.scan_charge, 123);
        assert_eq!(client.retained_session(), Some((1, 1)));
    }
    assert_eq!(client.test_credit_clock_reads() - before, 3);
    assert!(client.needs_poll());
    assert!(!client.busy());
    client.test_credit_clock(start + Duration::from_secs(30));
    client.scan_admission((2, 1)).unwrap().charge(17).unwrap();
    assert_eq!(client.retained_session(), Some((2, 1)));
    assert_eq!(client.scan_charge, 17);
    assert!(!client.waiting_for_credits);
}

#[test]
fn scan_admission_nested_owner_preserves_exact_quota_and_protected_points() {
    let (_temp, cfg, sb) = fixture();
    let mut client = Client::open(&cfg, &sb, 0, MEM, 0, 0).unwrap();
    let q = Query::Keys {
        id: 1,
        keys: vec![Bytes::from_static(b"point")],
    };
    let answer = Arc::new(Answer::Entries(
        vec![(Bytes::from_static(b"point"), Bytes::from_static(b"value"))],
        false,
    ));
    client.cache_bytes = q.bytes() + answer.bytes();
    client.cache.insert(q.clone(), answer.clone());
    client.read_session(Some((1, 1)), false);
    assert!(Arc::ptr_eq(&client.query(q.clone()).unwrap(), &answer));
    let points = client.retained_bytes;
    assert!(points > 0);
    client.read_session(Some((1, 2)), true); // explicit nested scope shares owner
    let available = client.read_budget - points * 4;
    {
        let mut admission = client.scan_admission((1, 2)).unwrap();
        admission.charge(available - 1).unwrap();
        admission.charge(available).unwrap();
        for refused in [available + 1, usize::MAX] {
            assert!(matches!(
                admission.charge(refused),
                Err(StoreError::TxnTooLarge)
            ));
            assert_eq!(admission.client.scan_charge, available);
        }
    }
    assert_eq!(client.retained_bytes, points);
    assert_eq!(client.retained_session(), Some((1, 1)));
    assert!(Arc::ptr_eq(&client.query(q.clone()).unwrap(), &answer));
    client.read_session(None, false); // child finish cannot release its parent
    assert_eq!(client.retained_session(), Some((1, 1)));
    assert!(client.session_parents.is_empty());
    client.read_session(Some((1, 1)), true);
    assert!(Arc::ptr_eq(&client.query(q).unwrap(), &answer));
    client.read_session(None, false);
    assert_eq!(client.retained_session(), None);
    assert_eq!((client.retained_bytes, client.scan_charge), (0, 0));
}

#[test]
fn scan_admission_error_unwind_and_forgotten_guard_preserve_release_safety() {
    let (_temp, cfg, sb) = fixture();
    let mut client = Client::open(&cfg, &sb, 0, MEM, 0, 0).unwrap();
    let start = Instant::now();
    client.test_credit_clock(start);
    client.admit_scan((1, 1), 99).unwrap();
    let result: Result<()> = (|| {
        let mut a = client.scan_admission((1, 1))?;
        a.client.test_credit_clock(start + Duration::from_secs(31));
        a.charge(usize::MAX)?;
        Ok(())
    })();
    assert!(matches!(result, Err(StoreError::TxnTooLarge)));
    assert_eq!(client.touched, start + Duration::from_secs(31));
    assert_eq!(client.scan_charge, 99);
    assert!(!client.poll(), "error drop renews, not releases or wakes");
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut a = client.scan_admission((1, 1)).unwrap();
        a.charge(123).unwrap();
        a.client.test_credit_clock(start + Duration::from_secs(62));
        panic!("test unwind before memo publication");
    }));
    assert!(panic.is_err());
    assert_eq!(client.touched, start + Duration::from_secs(62));
    assert_eq!(client.scan_charge, 123);
    assert!(!client.poll(), "unwind drop is not readiness progress");
    let mut a = client.scan_admission((1, 1)).unwrap();
    a.charge(456).unwrap();
    a.client.test_credit_clock(start + Duration::from_secs(93));
    std::mem::forget(a);
    assert_eq!(client.scan_charge, 456);
    assert_eq!(client.touched, start + Duration::from_secs(62));
    assert!(
        client.poll(),
        "a forgotten guard cannot permanently pin credits"
    );
    assert_eq!(client.retained_session(), None);
    assert_eq!(client.scan_charge, 0);
    assert!(!client.poll());
}

#[test]
fn real_database_binary_keys_objects_and_synced_restart() {
    let (_temp, cfg, sb) = fixture();
    let mut d = db(&cfg, &sb, false);
    let mut m = Memtable::new();
    for (i, (id, k, v)) in [
        (0, &b""[..], &b"empty"[..]),
        (0, &b"\0\xff"[..], &b"binary"[..]),
        (1, &b""[..], &b"next"[..]),
        (u64::MAX, &b"\xff"[..], &b"last"[..]),
    ]
    .into_iter()
    .enumerate()
    {
        m.put(
            i as u64 + 1,
            id,
            Bytes::copy_from_slice(k),
            Bytes::copy_from_slice(v),
        );
    }
    assert_eq!(d.flush(&m).unwrap(), 4);
    assert_eq!(get(&d, 0, b""), Some(Bytes::from_static(b"empty")));
    assert_eq!(get(&d, 0, b"\0\xff"), Some(Bytes::from_static(b"binary")));
    assert_eq!(get(&d, 1, b""), Some(Bytes::from_static(b"next")));
    assert_eq!(
        get(&d, u64::MAX, b"\xff"),
        Some(Bytes::from_static(b"last"))
    );
    drop(d);
    let d = db(&cfg, &sb, false);
    assert_eq!(d.watermark, 4);
    assert_eq!(
        get(&d, u64::MAX, b"\xff"),
        Some(Bytes::from_static(b"last"))
    );
}

#[test]
fn collapsed_ranges_then_points_preserve_clear_put_and_half_open_end() {
    let (_temp, cfg, sb) = fixture();
    let mut d = db(&cfg, &sb, false);
    let mut m = Memtable::new();
    for k in [b"a", b"b", b"c", b"d"] {
        m.put(1, 7, Bytes::copy_from_slice(k), Bytes::copy_from_slice(k));
    }
    m.put(
        1,
        8,
        Bytes::from_static(b"b"),
        Bytes::from_static(b"neighbor"),
    );
    d.flush(&m).unwrap();
    let mut m = Memtable::new();
    m.del_range(
        2,
        7,
        Bytes::from_static(b"b"),
        Some(Bytes::from_static(b"d")),
    );
    m.put(3, 7, Bytes::from_static(b"c"), Bytes::from_static(b"new"));
    m.del(4, 7, Bytes::from_static(b"a"));
    d.flush(&m).unwrap();
    assert_eq!(get(&d, 7, b"a"), None);
    assert_eq!(get(&d, 7, b"b"), None);
    assert_eq!(get(&d, 7, b"c"), Some(Bytes::from_static(b"new")));
    assert_eq!(get(&d, 7, b"d"), Some(Bytes::from_static(b"d")));
    assert_eq!(get(&d, 8, b"b"), Some(Bytes::from_static(b"neighbor")));
    let mut m = Memtable::new();
    m.del_range(5, 7, Bytes::new(), None);
    m.put(6, 7, Bytes::new(), Bytes::from_static(b"recreated"));
    m.del_range(7, u64::MAX, Bytes::new(), None);
    d.flush(&m).unwrap();
    assert_eq!(get(&d, 7, b""), Some(Bytes::from_static(b"recreated")));
    assert_eq!(get(&d, 7, b"c"), None);
    assert_eq!(get(&d, 8, b"b"), Some(Bytes::from_static(b"neighbor")));
}

#[test]
fn scan_prefix_exclusive_cursor_and_global_id_inventory() {
    let (_temp, cfg, sb) = fixture();
    let mut d = db(&cfg, &sb, false);
    let mut m = Memtable::new();
    for id in [0, 9, u64::MAX] {
        for i in 0..(PAGE + 3) {
            m.put(
                1,
                id,
                Bytes::from(format!("p{i:05}")),
                Bytes::from_static(b"v"),
            );
        }
        m.put(
            1,
            id,
            Bytes::from_static(b"q"),
            Bytes::from_static(b"outside"),
        );
    }
    d.flush(&m).unwrap();
    let Answer::Page(v, end) = d
        .read(&Query::Page {
            entries: PAGE,
            versions: [(0, 0); 3],
            session: None,
            id: 9,
            from: Bytes::new(),
            excl: false,
            prefix: Bytes::from_static(b"p"),
        })
        .unwrap()
    else {
        panic!("page");
    };
    assert_eq!(v.len(), PAGE);
    assert!(end.has_more());
    let Answer::Page(rest, end) = d
        .read(&Query::Page {
            entries: PAGE,
            versions: [(0, 0); 3],
            session: None,
            id: 9,
            from: Bytes::copy_from_slice(v.get(v.len() - 1).unwrap().0),
            excl: true,
            prefix: Bytes::from_static(b"p"),
        })
        .unwrap()
    else {
        panic!("page");
    };
    assert_eq!(rest.len(), 3);
    assert_eq!(end, PageEnd::End);
    assert!(rest.get(0).unwrap().0 > v.get(v.len() - 1).unwrap().0);
    let Answer::Ids(ids, more) = d.read(&Query::Ids { after: None }).unwrap() else {
        panic!("ids");
    };
    assert_eq!(ids, [0, 9, u64::MAX]);
    assert!(!more);
}

#[test]
fn page_continuation_is_first_merged_live_binary_key_not_a_hidden_base_key() {
    let (_temp, cfg, sb) = fixture();
    let mut d = db(&cfg, &sb, false);
    let key = |i: usize| {
        let mut k = b"\0\xff/".to_vec();
        k.extend_from_slice(&(i as u32).to_be_bytes());
        Bytes::from(k)
    };
    let mut base = Memtable::new();
    let mut expected = std::collections::BTreeMap::new();
    for i in 0..PAGE + 8 {
        base.put(1, 9, key(i), Bytes::from_static(b"base"));
        expected.insert(key(i), Bytes::from_static(b"base"));
    }
    base.put(
        1,
        9,
        Bytes::from_static(b"z"),
        Bytes::from_static(b"other-prefix"),
    );
    base.put(1, 10, key(0), Bytes::from_static(b"other-object"));
    d.flush(&base).unwrap();
    let mut over = Memtable::new();
    over.del_range(2, 9, key(PAGE), Some(key(PAGE + 4)));
    for i in PAGE..PAGE + 4 {
        expected.remove(&key(i));
    }
    over.put(3, 9, key(PAGE + 2), Bytes::from_static(b"reinsert"));
    expected.insert(key(PAGE + 2), Bytes::from_static(b"reinsert"));
    let mut q = Query::Page {
        entries: PAGE,
        id: 9,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::from_static(b"\0\xff/"),
        versions: [(0, 0); 3],
        session: None,
    };
    let mut got = Vec::new();
    loop {
        let Answer::Page(page, end) = d.page(&q, &[over.snapshot(9), None, None]).unwrap() else {
            panic!("page");
        };
        got.extend(page.to_pairs());
        match end {
            PageEnd::Next(k) => {
                assert_eq!(
                    k,
                    key(PAGE + 2),
                    "lookahead must skip deleted base keys and retain newer reinserts"
                );
                let Query::Page { from, excl, .. } = &mut q else {
                    unreachable!()
                };
                *from = k;
                *excl = false;
            }
            PageEnd::End => break,
            PageEnd::Unknown => panic!("ample credits must preserve lookahead"),
        }
    }
    assert_eq!(got, expected.into_iter().collect::<Vec<_>>());
}

#[test]
fn page_continuation_respects_credits_and_falls_back_without_copying_a_key() {
    let (_temp, cfg, sb) = fixture();
    let mut d = db(&cfg, &sb, false);
    let mut base = Memtable::new();
    base.put(1, 9, Bytes::from_static(b"a"), Bytes::from_static(b"v"));
    base.put(1, 9, Bytes::from_static(b"b"), Bytes::from(vec![7; 8192]));
    d.flush(&base).unwrap();
    let q = Query::Page {
        entries: PAGE,
        id: 9,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::new(),
        versions: [(0, 0); 3],
        session: None,
    };
    let limit = 1 + 1 + 64;
    let answer = d.page_limit(&q, &[None, None, None], limit).unwrap();
    assert_eq!(answer.bytes(), limit);
    assert!(matches!(answer,Answer::Page(v,PageEnd::Unknown) if v.len()==1));
    let answer = d.page_limit(&q, &[None, None, None], limit + 33).unwrap();
    assert_eq!(answer.bytes(), limit + 33);
    assert!(matches!(answer,Answer::Page(v,PageEnd::Next(k)) if v.len()==1 && &k[..]==b"b"));
}

#[test]
fn merged_scan_candidates_preserve_exclusive_starts_and_three_overlay_precedences() {
    let (_temp, cfg, sb) = fixture();
    let mut d = db(&cfg, &sb, false);
    let key = |n: u8| Bytes::from(vec![0, 255, n]);
    let value = |s: &'static [u8]| Bytes::from_static(s);
    let mut base = Memtable::new();
    let mut model = std::collections::BTreeMap::new();
    for n in 0..40 {
        base.put(1, 9, key(n), value(b"base"));
        model.insert(key(n), value(b"base"));
    }
    base.put(1, 9, Bytes::from_static(b"z"), value(b"other-prefix"));
    base.put(1, 10, key(0), value(b"other-object"));
    d.flush(&base).unwrap();
    let mut older = Memtable::new();
    older.del_range(2, 9, key(4), Some(key(14)));
    older.put(3, 9, key(7), value(b"older-seven"));
    for n in 4..14 {
        model.remove(&key(n));
    }
    model.insert(key(7), value(b"older-seven"));
    let mut middle = Memtable::new();
    middle.del(4, 9, key(7));
    middle.put(5, 9, key(6), value(b"middle-six"));
    middle.put(6, 9, key(41), value(b"middle-new"));
    model.remove(&key(7));
    model.insert(key(6), value(b"middle-six"));
    model.insert(key(41), value(b"middle-new"));
    let mut newest = Memtable::new();
    newest.del_range(7, 9, key(18), Some(key(32)));
    newest.put(8, 9, key(22), value(b"newest-reinsert"));
    newest.put(9, 9, key(7), value(b"newest-seven"));
    newest.del(10, 9, key(35));
    for n in 18..32 {
        model.remove(&key(n));
    }
    model.insert(key(22), value(b"newest-reinsert"));
    model.insert(key(7), value(b"newest-seven"));
    model.remove(&key(35));
    let view = [newest.snapshot(9), middle.snapshot(9), older.snapshot(9)];
    for from in [
        Bytes::new(),
        key(0),
        key(3),
        key(7),
        key(20),
        key(35),
        key(41),
        key(50),
    ] {
        for exclusive in [false, true] {
            for entries in [1, 2, 7, SCAN_BATCH] {
                let expected: Vec<_> = model
                    .iter()
                    .filter(|(k, _)| *k > &from || (!exclusive && *k == &from))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                let mut q = Query::Page {
                    id: 9,
                    from: from.clone(),
                    excl: exclusive,
                    prefix: Bytes::from_static(b"\0\xff"),
                    entries,
                    versions: [(0, 0); 3],
                    session: None,
                };
                let mut got = Vec::new();
                for _ in 0..=model.len() {
                    let Answer::Page(page, end) = d.page(&q, &view).unwrap() else {
                        panic!("page")
                    };
                    assert!(page.len() <= entries);
                    got.extend(page.to_pairs());
                    match end {
                        PageEnd::End => break,
                        PageEnd::Next(next) => {
                            assert_eq!(Some(&next), expected.get(got.len()).map(|(k, _)| k));
                            let Query::Page { from, excl, .. } = &mut q else {
                                unreachable!()
                            };
                            *from = next;
                            *excl = false;
                        }
                        PageEnd::Unknown => panic!("ample credits"),
                    }
                }
                assert_eq!(
                    got, expected,
                    "from={from:?},excl={exclusive},entries={entries}"
                );
            }
        }
    }
}

#[test]
fn requested_scan_batch_is_part_of_identity_capped_and_credit_bounded() {
    let (_temp, cfg, sb) = fixture();
    let mut d = db(&cfg, &sb, false);
    let key = |i: usize| Bytes::copy_from_slice(&(i as u32).to_be_bytes());
    let mut base = Memtable::new();
    for i in 0..SCAN_BATCH + 2 {
        base.put(1, 9, key(i), Bytes::from_static(b"xyz"));
    }
    base.put(1, 10, key(0), Bytes::from_static(b"foreign"));
    d.flush(&base).unwrap();
    let query = |entries| Query::Page {
        id: 9,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::new(),
        entries,
        versions: [(0, 0); 3],
        session: Some((53, 1)),
    };
    assert_ne!(query(PAGE), query(SCAN_BATCH));
    for requested in [0, 1, 17, PAGE, 512, SCAN_BATCH, SCAN_BATCH + 500] {
        let Answer::Page(page, end) = d.page(&query(requested), &[None, None, None]).unwrap()
        else {
            panic!("page");
        };
        let n = requested.clamp(1, SCAN_BATCH);
        assert_eq!(page.len(), n);
        for (i, (k, v)) in page.iter().enumerate() {
            assert_eq!(*k, key(i));
            assert_eq!(v, b"xyz");
        }
        assert_eq!(end, PageEnd::Next(key(n)));
    }
    let limit = 17 * (4 + 3 + 64);
    let answer = d
        .page_limit(&query(SCAN_BATCH), &[None, None, None], limit)
        .unwrap();
    assert_eq!(answer.bytes(), limit);
    assert!(matches!(answer, Answer::Page(page, PageEnd::Unknown) if page.len()==17));
}

#[test]
fn current_item_borrow_never_substitutes_base_value_for_overlay_or_survives_range_seek() {
    let (_temp, cfg, sb) = fixture();
    let mut d = db(&cfg, &sb, false);
    let k = |n: u8| Bytes::from(vec![0, n]);
    let v = |n: u8| Bytes::from(vec![n]);
    let mut base = Memtable::new();
    for n in [0x10, 0x20, 0x30, 0x40] {
        base.put(1, 9, k(n), v(n));
    }
    base.put(1, 9, Bytes::from_static(b"\x01\0"), v(0xee));
    base.put(1, 10, k(0x40), v(0xdd));
    d.flush(&base).unwrap();
    drop(d);
    let d = db(&cfg, &sb, true);
    let mut older = Memtable::new();
    older.put(2, 9, k(5), v(0xa5));
    let mut middle = Memtable::new();
    middle.del_range(3, 9, k(0x20), Some(k(0x40)));
    let mut newest = Memtable::new();
    for (key, value) in [(0x0f, 0xaf), (0x10, 0xb0), (0x11, 0xb1), (0x21, 0xc1)] {
        newest.put(4, 9, k(key), v(value));
    }
    let view = [newest.snapshot(9), middle.snapshot(9), older.snapshot(9)];
    newest.put(5, 9, k(0x40), v(0xff)); // Query holds the earlier immutable view.
    let expected = vec![
        (k(5), v(0xa5)),
        (k(0x0f), v(0xaf)),
        (k(0x10), v(0xb0)),
        (k(0x11), v(0xb1)),
        (k(0x21), v(0xc1)),
        (k(0x40), v(0x40)),
    ];
    let mut retained = Vec::new();
    // Literal credits: one 2-byte key/1-byte value costs67; continuation costs34.
    for credit in [67, 101, 10000] {
        let mut q = Query::Page {
            id: 9,
            from: Bytes::new(),
            excl: false,
            prefix: Bytes::from_static(b"\0"),
            entries: 1,
            versions: [(0, 0); 3],
            session: None,
        };
        let mut all = Vec::new();
        for index in 0..expected.len() {
            let Answer::Page(page, end) = d.page_limit(&q, &view, credit).unwrap() else {
                panic!("page");
            };
            assert_eq!(page.to_pairs(), [expected[index].clone()]);
            let last = Bytes::copy_from_slice(page.get(0).unwrap().0);
            all.extend(page.to_pairs());
            let Query::Page { from, excl, .. } = &mut q else {
                unreachable!();
            };
            match end {
                PageEnd::End => assert_eq!(index, expected.len() - 1),
                PageEnd::Unknown => {
                    assert_eq!(credit, 67);
                    *from = last;
                    *excl = true;
                }
                PageEnd::Next(next) => {
                    assert_eq!(next, expected[index + 1].0);
                    *from = next;
                    *excl = false;
                }
            }
        }
        retained.push(all);
    }
    drop(d); // All returned bytes remain owned after every iterator/DB is gone.
    for all in retained {
        assert_eq!(all, expected);
    }
}

#[test]
fn selected_key_origin_is_independent_of_overlay_value_precedence() {
    let (_temp, cfg, sb) = fixture();
    let mut d = db(&cfg, &sb, false);
    let k = |n: u8| Bytes::from(vec![0, n]);
    let v = |n: u8| Bytes::from(vec![n]);
    let mut base = Memtable::new();
    for n in [0x20, 0x40, 0x60, 0x70, 0x80] {
        base.put(1, 9, k(n), v(n));
    }
    base.put(1, 9, Bytes::from_static(b"\x01"), v(0xee));
    base.put(1, 10, k(0), v(0xdd));
    d.flush(&base).unwrap();
    drop(d);
    let d = db(&cfg, &sb, true);
    let mut older = Memtable::new();
    for (key, value) in [(0x10, 0xa1), (0x20, 0xa2), (0x90, 0xa9)] {
        older.put(2, 9, k(key), v(value));
    }
    let mut middle = Memtable::new();
    for (key, value) in [(0x20, 0xb2), (0x30, 0xb3), (0x40, 0xb4)] {
        middle.put(3, 9, k(key), v(value));
    }
    let mut newest = Memtable::new();
    newest.put(4, 9, k(0x20), v(0xc2));
    newest.put(4, 9, k(0x50), v(0xc5));
    newest.del(4, 9, k(0x60));
    newest.del(4, 9, k(0x80));
    let view = [newest.snapshot(9), middle.snapshot(9), older.snapshot(9)];
    // Literal oracle: overlay-only keys must not advance the DB; equal keys
    // must advance it even if another overlay provides the value or deletion.
    let expected = [
        (k(0x10), v(0xa1)),
        (k(0x20), v(0xc2)),
        (k(0x30), v(0xb3)),
        (k(0x40), v(0xb4)),
        (k(0x50), v(0xc5)),
        (k(0x70), v(0x70)),
        (k(0x90), v(0xa9)),
    ];
    for from in [0, 0x10, 0x20, 0x21, 0x40, 0x41, 0x80, 0x90, 0xff] {
        for exclusive in [false, true] {
            let want: Vec<_> = expected
                .iter()
                .filter(|(key, _)| key[1] > from || (!exclusive && key[1] == from))
                .cloned()
                .collect();
            for entries in [1, 2, SCAN_BATCH] {
                let mut query = Query::Page {
                    id: 9,
                    from: k(from),
                    excl: exclusive,
                    prefix: Bytes::from_static(b"\0"),
                    entries,
                    versions: [(0, 0); 3],
                    session: None,
                };
                let mut got = Vec::new();
                for _ in 0..=expected.len() {
                    let Answer::Page(page, end) = d.page(&query, &view).unwrap() else {
                        panic!("page");
                    };
                    assert!(page.len() <= entries);
                    got.extend(page.to_pairs());
                    match end {
                        PageEnd::End => break,
                        PageEnd::Next(next) => {
                            assert_eq!(Some(&next), want.get(got.len()).map(|(key, _)| key));
                            let Query::Page { from, excl, .. } = &mut query else {
                                unreachable!();
                            };
                            *from = next;
                            *excl = false;
                        }
                        PageEnd::Unknown => panic!("ample credits"),
                    }
                }
                assert_eq!(got, want, "from={from},excl={exclusive},entries={entries}");
            }
        }
    }
    // No matching DB prefix: selecting only overlay entries must not invent a
    // base value, and exhaustion must not cross into the adjacent object.
    let query = Query::Page {
        id: 9,
        from: Bytes::new(),
        excl: false,
        prefix: k(0x90),
        entries: SCAN_BATCH,
        versions: [(0, 0); 3],
        session: None,
    };
    let Answer::Page(page, end) = d.page(&query, &view).unwrap() else {
        panic!("page");
    };
    assert_eq!(page.to_pairs(), [(k(0x90), v(0xa9))]);
    assert_eq!(end, PageEnd::End);
}

#[test]
fn empty_prefix_skips_no_binary_keys_and_nonempty_prefixes_still_filter_all_streams() {
    let (_temp, cfg, sb) = fixture();
    let mut d = db(&cfg, &sb, false);
    let key = |k: &[u8]| Bytes::copy_from_slice(k);
    let value = |v: u8| Bytes::from(vec![v]);
    let keys: &[&[u8]] = &[b"", b"\0", b"\0\xff", b"\x01", b"\xff", b"\xff\xff"];
    let mut base = Memtable::new();
    let mut older = Memtable::new();
    let mut middle = Memtable::new();
    let mut newest = Memtable::new();
    for id in [0, 9, u64::MAX] {
        for (i, k) in keys.iter().enumerate() {
            base.put(1, id, key(k), value(i as u8));
        }
        older.put(2, id, key(b"\x02"), value(0xa2));
        middle.del(3, id, key(b"\xff"));
        newest.put(4, id, key(b""), value(0xc0));
    }
    base.put(1, 10, key(b"\0"), value(0xee));
    d.flush(&base).unwrap();
    drop(d);
    let d = db(&cfg, &sb, true);
    let expected = [
        (key(b""), value(0xc0)),
        (key(b"\0"), value(1)),
        (key(b"\0\xff"), value(2)),
        (key(b"\x01"), value(3)),
        (key(b"\x02"), value(0xa2)),
        (key(b"\xff\xff"), value(5)),
    ];
    // Literal subsets, not the production prefix predicate as the oracle.
    let cases: &[(&[u8], &[usize])] = &[
        (b"", &[0, 1, 2, 3, 4, 5]),
        (b"\0", &[1, 2]),
        (b"\0\xff", &[2]),
        (b"\x01", &[3]),
        (b"\x02", &[4]),
        (b"\xff", &[5]),
        (b"\xff\xff", &[5]),
        (b"\xff\0", &[]),
    ];
    for id in [0, 9, u64::MAX] {
        let view = [newest.snapshot(id), middle.snapshot(id), older.snapshot(id)];
        for &(prefix, indices) in cases {
            for entries in [1, 2, SCAN_BATCH] {
                for exclusive in [false, true] {
                    let want: Vec<_> = indices
                        .iter()
                        .filter(|&&i| !exclusive || !expected[i].0.is_empty())
                        .map(|&i| expected[i].clone())
                        .collect();
                    let mut query = Query::Page {
                        id,
                        from: Bytes::new(),
                        excl: exclusive,
                        prefix: key(prefix),
                        entries,
                        versions: [(0, 0); 3],
                        session: None,
                    };
                    let mut got = Vec::new();
                    for _ in 0..=expected.len() {
                        let Answer::Page(page, end) = d.page(&query, &view).unwrap() else {
                            panic!("page");
                        };
                        got.extend(page.to_pairs());
                        match end {
                            PageEnd::End => break,
                            PageEnd::Next(next) => {
                                assert_eq!(Some(&next), want.get(got.len()).map(|(k, _)| k));
                                let Query::Page { from, excl, .. } = &mut query else {
                                    unreachable!();
                                };
                                *from = next;
                                *excl = false;
                            }
                            PageEnd::Unknown => panic!("ample credits"),
                        }
                    }
                    assert_eq!(
                        got, want,
                        "id={id},prefix={prefix:?},entries={entries},excl={exclusive}"
                    );
                }
            }
        }
    }
}

#[test]
fn taken_scan_batch_releases_cache_ownership_and_does_not_change_point_retention() {
    let (_temp, cfg, sb) = fixture();
    let mut d = db(&cfg, &sb, false);
    let mut base = Memtable::new();
    base.put(1, 9, Bytes::from_static(b"a"), Bytes::from_static(b"value"));
    d.flush(&base).unwrap();
    drop(d);
    let mut c = Client::open(&cfg, &sb, 0, 8 << 20, 0, 1).unwrap();
    c.read_session(Some((54, 1)), true);
    let q = Query::Page {
        id: 9,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::new(),
        entries: SCAN_BATCH,
        versions: [(0, 0); 3],
        session: Some((54, 1)),
    };
    let end = Instant::now() + Duration::from_secs(5);
    let (page, continuation) = loop {
        match c.take_page(q.clone(), [None, None, None]) {
            Ok(page) => break page,
            Err(StoreError::Miss) => {}
            Err(e) => panic!("{e:?}"),
        }
        c.poll();
        std::thread::yield_now();
        assert!(Instant::now() < end);
    };
    assert_eq!(
        page.to_pairs(),
        vec![(Bytes::from_static(b"a"), Bytes::from_static(b"value"))]
    );
    assert_eq!(continuation, PageEnd::End);
    assert!(!c.cache.contains_key(&q));
    assert_eq!(c.cache_bytes, 0);
    assert!(c.retained.is_empty());
    assert!(c.session_admitted((54, 1)));
    let q = Query::Keys {
        id: 9,
        keys: vec![Bytes::from_static(b"a")],
    };
    loop {
        match c.query(q.clone()) {
            Ok(_) => break,
            Err(StoreError::Miss) => {}
            Err(e) => panic!("{e:?}"),
        }
        c.poll();
        std::thread::yield_now();
        assert!(Instant::now() < end);
    }
    assert!(c.retained.contains_key(&q));
    assert!(c.retained_bytes > 0);
    c.read_session(None, false);
    assert!(c.retained.is_empty());
}

#[test]
fn packed_worker_tight_credit_unknown_and_shared_answer_keep_full_charge() {
    let (_temp, cfg, sb) = fixture();
    let mut d = db(&cfg, &sb, false);
    let mut base = Memtable::new();
    for n in 0..18u32 {
        base.put(
            1,
            9,
            Bytes::copy_from_slice(&n.to_be_bytes()),
            Bytes::from_static(b"xyz"),
        );
    }
    d.flush(&base).unwrap();
    drop(d);
    let mut c = Client::open(&cfg, &sb, 0, 8 << 20, 0, 1).unwrap();
    c.read_session(Some((84, 1)), true);
    let q = Query::Page {
        id: 9,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::new(),
        entries: SCAN_BATCH,
        versions: [(0, 0); 3],
        session: Some((84, 1)),
    };
    let limit = 17 * (4 + 3 + 64);
    c.test_read_budget((q.bytes() + limit) * 4);
    let deadline = Instant::now() + Duration::from_secs(5);
    let held = loop {
        match c.query(q.clone()) {
            Ok(answer) => break answer,
            Err(StoreError::Miss) => {}
            Err(e) => panic!("{e:?}"),
        }
        c.poll();
        std::thread::yield_now();
        assert!(
            Instant::now() < deadline,
            "WARNING TIMEOUT packed worker credit test exceeded5s"
        );
    };
    let Answer::Page(original, PageEnd::Unknown) = &*held else {
        panic!("credit-bounded page")
    };
    assert_eq!(original.len(), 17);
    assert_eq!(held.bytes(), limit);
    // Holding a genuine worker answer makes try_unwrap fail. The fallback must
    // carry the backing charge, not just copy descriptors or visible lengths.
    let (page, end) = c.take_page(q.clone(), [None, None, None]).unwrap();
    assert_eq!(end, PageEnd::Unknown);
    assert_eq!(page.bytes(), limit);
    assert_eq!(
        page.get(0).unwrap().0.as_ptr(),
        original.get(0).unwrap().0.as_ptr()
    );
    assert_eq!(
        page.get(16).unwrap().1.as_ptr(),
        original.get(16).unwrap().1.as_ptr()
    );
    assert!(!c.cache.contains_key(&q));
    assert_eq!(c.cache_bytes, 0);
    drop(held);
    c.read_session(None, false);
    drop(c);
    assert_eq!(page.bytes(), limit);
    for (n, (k, v)) in page.iter().enumerate() {
        assert_eq!(k, &(n as u32).to_be_bytes());
        assert_eq!(v, b"xyz");
    }
}

#[test]
fn wrong_identity_missing_database_and_nonmonotonic_flush_refuse() {
    let (_temp, cfg, sb) = fixture();
    assert!(create(&cfg, &sb, MEM).is_err());
    assert!(Database::open(&cfg.path(&sb, 0).unwrap(), b"wrong", MEM, false).is_err());
    assert!(Database::open(&cfg.root.join("absent"), &identity(&sb, 0), MEM, false).is_err());
    assert!(!cfg.root.join("absent").exists());
    let mut d = db(&cfg, &sb, false);
    let mut m = Memtable::new();
    m.put(2, 0, Bytes::new(), Bytes::from_static(b"v"));
    d.flush(&m).unwrap();
    assert!(d.flush(&m).is_err());
    drop(d);
    assert!(Client::open(&cfg, &sb, 0, MEM, 3, 10).is_err());
    assert!(Client::open(&cfg, &sb, 0, MEM, 0, 1).is_err());
}

#[test]
fn readonly_open_reads_latest_wal_but_refuses_flush() {
    let (_temp, cfg, sb) = fixture();
    let mut d = db(&cfg, &sb, false);
    let mut m = Memtable::new();
    m.put(1, 42, Bytes::from_static(b"k"), Bytes::from_static(b"v"));
    d.flush(&m).unwrap();
    drop(d);
    let files = |path: &Path| -> std::collections::BTreeMap<std::ffi::OsString, Vec<u8>> {
        std::fs::read_dir(path)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.file_name(), std::fs::read(e.path()).unwrap())
            })
            .collect()
    };
    let before = files(&cfg.path(&sb, 0).unwrap());
    let mut ro = db(&cfg, &sb, true);
    assert_eq!(get(&ro, 42, b"k"), Some(Bytes::from_static(b"v")));
    m.put(2, 42, Bytes::from_static(b"k"), Bytes::from_static(b"new"));
    assert!(ro.flush(&m).is_err());
    drop(ro);
    assert_eq!(
        files(&cfg.path(&sb, 0).unwrap()),
        before,
        "read-only DB open must not modify its directory"
    );
    assert_eq!(
        get(&db(&cfg, &sb, false), 42, b"k"),
        Some(Bytes::from_static(b"v"))
    );
}

#[test]
fn stable_identity_survives_enrollment_but_not_reformat() {
    let (_temp, cfg, mut sb) = fixture();
    sb.osd_id = 19;
    sb.cluster_fsid = [17; 16];
    drop(db(&cfg, &sb, false));
    sb.mkfs_time += 1;
    assert!(Database::open(&cfg.path(&sb, 0).unwrap(), &identity(&sb, 0), MEM, false).is_err());
}

#[test]
fn relative_and_symlink_roots_refuse_before_device_admission() {
    let cfg = Config::new("relative".into());
    assert!(cfg.admit().is_err());
    #[cfg(unix)]
    {
        let temp = Temp::new();
        let link = temp.0.join("link");
        std::os::unix::fs::symlink(&temp.0, &link).unwrap();
        assert!(Config::new(link).admit().is_err());
    }
}

#[test]
fn uuid_parent_symlink_refuses_without_following_or_creating_db() {
    let (_temp, cfg, sb) = fixture();
    let parent = cfg.path(&sb, 0).unwrap().parent().unwrap().to_owned();
    std::fs::remove_dir_all(&parent).unwrap();
    let elsewhere = Temp::new();
    std::os::unix::fs::symlink(&elsewhere.0, &parent).unwrap();
    assert!(create(&cfg, &sb, MEM).is_err());
    assert_eq!(std::fs::read_dir(&elsewhere.0).unwrap().count(), 0);
}

#[test]
fn reservation_is_owned_until_worker_lease_ends() {
    let s = Arc::new(Space::default());
    let lease = SpaceLease::new(s.clone(), 123);
    let (ready, begun) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _lease = lease;
        ready.send(()).unwrap();
        wait.recv().unwrap();
    });
    begun.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(s.reserve.load(Ordering::Acquire), 123);
    assert_eq!(s.users.load(Ordering::Acquire), 1);
    release.send(()).unwrap();
    worker.join().unwrap();
    assert_eq!(s.reserve.load(Ordering::Acquire), 0);
    assert_eq!(s.users.load(Ordering::Acquire), 0);
}

#[test]
fn synced_wal_survives_process_exit_without_database_drop() {
    let (_temp, cfg, sb) = fixture();
    let expected: String = identity(&sb, 0)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "rocks_omap::tests::abrupt_db_child"])
        .env("FLASHSTORE_TEST_ROCKS_PATH", cfg.path(&sb, 0).unwrap())
        .env("FLASHSTORE_TEST_ROCKS_ID", expected)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("owned RocksDB child timeout");
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    assert_eq!(status.code(), Some(71));
    let d = db(&cfg, &sb, false);
    assert_eq!(d.watermark, 7);
    assert_eq!(get(&d, 42, b"abrupt"), Some(Bytes::from_static(b"synced")));
}

#[test]
#[ignore = "subprocess entry point; exercised by synced_wal_survives_process_exit_without_database_drop"]
fn abrupt_db_child() {
    let Ok(path) = std::env::var("FLASHSTORE_TEST_ROCKS_PATH") else {
        return;
    };
    let id = std::env::var("FLASHSTORE_TEST_ROCKS_ID").unwrap();
    let id: Vec<_> = id
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|s| u8::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap())
        .collect();
    let mut d = Database::open(Path::new(&path), &id, MEM, false).unwrap();
    let mut m = Memtable::new();
    m.put(
        7,
        42,
        Bytes::from_static(b"abrupt"),
        Bytes::from_static(b"synced"),
    );
    d.flush(&m).unwrap();
    std::process::exit(71); // no Rust/C++ DB stack destructor or graceful close
}

#[test]
fn compound_point_session_has_completion_credits_independent_of_cache_eviction() {
    let (_temp, cfg, sb) = fixture();
    let mut d = db(&cfg, &sb, false);
    let mut m = Memtable::new();
    for key in [b"a", b"b", b"c"] {
        m.put(
            1,
            42,
            Bytes::copy_from_slice(key),
            Bytes::from(vec![3; 900_000]),
        );
    }
    m.put(
        1,
        43,
        Bytes::from_static(b"large"),
        Bytes::from(vec![7; 3_000_000]),
    );
    d.flush(&m).unwrap();
    drop(d);
    let mut c = Client::open(&cfg, &sb, 0, MEM, 0, 1).unwrap();
    fn answer(c: &mut Client, q: Query) -> Result<Arc<Answer>> {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            match c.query(q.clone()) {
                Err(StoreError::Miss) => {
                    c.poll();
                    std::thread::yield_now();
                }
                r => return r,
            }
            assert!(Instant::now() < until, "point session made no progress");
        }
    }
    let q = |key: &'static [u8]| Query::Keys {
        id: 42,
        keys: vec![Bytes::from_static(key)],
    };
    c.read_session(Some((1, 1)), true);
    assert!(matches!(c.query(q(b"a")), Err(StoreError::Miss)));
    let until = Instant::now() + Duration::from_secs(5);
    while !c.pending.is_empty() {
        c.poll();
        assert!(Instant::now() < until);
        std::thread::yield_now();
    }
    assert!(
        c.retained.contains_key(&q(b"a")),
        "completion must be protected BEFORE first consumption"
    );
    // A large scan page evicts the ordinary answer cache, not request progress.
    answer(
        &mut c,
        Query::Page {
            entries: PAGE,
            id: 43,
            from: Bytes::new(),
            excl: false,
            prefix: Bytes::new(),
            versions: [(0, 0); 3],
            session: Some((1, 1)),
        },
    )
    .unwrap();
    assert!(!c.cache.contains_key(&q(b"a")));
    assert!(c.query(q(b"a")).is_ok());
    c.read_session(None, true);
    c.read_session(Some((1, 2)), true);
    assert!(matches!(c.query(q(b"b")), Err(StoreError::Miss)));
    c.read_session(None, true);
    c.read_session(Some((1, 1)), true);
    answer(&mut c, q(b"b")).unwrap();
    assert!(
        matches!(answer(&mut c, q(b"c")), Err(StoreError::TxnTooLarge)),
        "oversized compound response must fail, not evict/retry forever"
    );
    c.read_session(None, false);
    c.read_session(Some((1, 2)), true);
    answer(&mut c, q(b"b")).unwrap();
    c.read_session(None, false);
    assert!(c.retained.is_empty());
    assert!(c.retained_owner.is_none());
    c.read_session(Some((1, 3)), true);
    answer(&mut c, q(b"a")).unwrap();
    c.read_session(None, true);
    c.touched = Instant::now() - Duration::from_secs(31);
    c.poll();
    assert!(c.retained.is_empty());
    assert!(
        c.retained_owner.is_none(),
        "idle owner must be reclaimed by poll, without a competing query"
    );
}

#[test]
fn page_traverses_point_tombstones_once_and_seeks_over_large_ranges() {
    let (_temp, cfg, sb) = fixture();
    let mut d = db(&cfg, &sb, false);
    let mut m = Memtable::new();
    for i in 0..20_000 {
        m.put(
            1,
            9,
            Bytes::from(format!("k{i:05}")),
            Bytes::from_static(b"base"),
        );
    }
    d.flush(&m).unwrap();
    let mut over = Memtable::new();
    for i in 0..5_000 {
        over.del(0, 9, Bytes::from(format!("z{i:05}")));
    }
    let q = Query::Page {
        entries: PAGE,
        id: 9,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::new(),
        versions: [(0, 0); 3],
        session: None,
    };
    let Answer::Page(v, end) = d.page(&q, &[over.snapshot(9), None, None]).unwrap() else {
        panic!("page");
    };
    assert_eq!(v.len(), PAGE);
    assert!(end.has_more());
    assert!(
        d.page_visits.get() >= 5_000,
        "visit accounting must include tombstone traversal"
    );
    assert!(
        d.page_visits.get() < 5_000 + PAGE + 10,
        "suffix rewalked {} times",
        d.page_visits.get()
    );
    over.del_range(0, 9, Bytes::new(), None);
    over.put(
        0,
        9,
        Bytes::from_static(b"k00001"),
        Bytes::from_static(b"newer"),
    );
    let Answer::Page(v, end) = d.page(&q, &[over.snapshot(9), None, None]).unwrap() else {
        panic!("page");
    };
    assert_eq!(
        v.to_pairs(),
        [(Bytes::from_static(b"k00001"), Bytes::from_static(b"newer"))]
    );
    assert_eq!(end, PageEnd::End);
    assert!(d.page_visits.get() < 10, "range walked persisted keys");
}

#[test]
fn multiget_stops_before_copying_the_whole_oversized_answer() {
    let (_temp, cfg, sb) = fixture();
    let mut d = db(&cfg, &sb, false);
    let value = Bytes::from(vec![5; 64 << 10]);
    let mut m = Memtable::new();
    let keys: Vec<_> = (0..128).map(|i| Bytes::from(format!("k{i:04}"))).collect();
    for k in &keys {
        m.put(1, 12, k.clone(), value.clone());
    }
    d.flush(&m).unwrap();
    let q = Query::Keys {
        id: 12,
        keys: keys.clone(),
    };
    assert!(matches!(
        d.read_limit(&q, 1 << 20),
        Err(StoreError::TxnTooLarge)
    ));
    assert!(d.point_copied.get() <= 1 << 20);
    assert!(
        d.point_copied.get() >= 14 * (64 << 10),
        "accounting must count copied values"
    );
    assert!(
        d.point_visits.get() <= 17,
        "read all keys before refusing: {}",
        d.point_visits.get()
    );
    drop(d);
    let mut c = Client::open(&cfg, &sb, 0, MEM, 0, 1).unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        match c.query(q.clone()) {
            Err(StoreError::Miss) => {
                c.poll();
                std::thread::yield_now();
            }
            Err(StoreError::TxnTooLarge) => break,
            r => panic!("unexpected multi-get outcome: {r:?}"),
        }
        assert!(Instant::now() < until);
    }
    assert!(
        c.failure.is_none(),
        "size refusal is request-local, not fail-stop"
    );
    let one = Query::Keys {
        id: 12,
        keys: vec![keys[0].clone()],
    };
    loop {
        match c.query(one.clone()) {
            Err(StoreError::Miss) => {
                c.poll();
                std::thread::yield_now();
            }
            Ok(a) => {
                let Answer::Entries(v, _) = &*a else {
                    panic!("entries");
                };
                assert_eq!(v[0].1, value);
                break;
            }
            Err(e) => panic!("{e:?}"),
        }
        assert!(Instant::now() < until);
    }
}
