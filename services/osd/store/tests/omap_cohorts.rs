// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Independent cold-tree, FIFO and failure vectors; not a hardware speed oracle.
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use store::dev::{CrashPolicy, SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::txn::Bytes;
use store::obj::{OTxn, ObjError, Store, StoreCfg, TOp};

type St = Store<SimDev, SimClock>;

fn identity() -> (CollT, Ghobject) {
    (
        CollT::Pg(SpgT {
            pgid: PgT::new(1, 0),
            shard: ShardId::NO_SHARD,
        }),
        Ghobject::new(
            Hobject::new(b"cohort-regression", SnapId::NOSNAP, 1, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        ),
    )
}

fn key(i: u32) -> Vec<u8> {
    let mut k = vec![b'x'; 64];
    k[..8].copy_from_slice(format!("{i:08x}").as_bytes());
    k
}

fn value(i: u32, compressed: bool) -> Vec<u8> {
    let mut v = vec![0; 256];
    if compressed {
        let text = b"{independent cohort regression value, repeated body}";
        for (n, b) in v.iter_mut().enumerate() {
            *b = text[n % text.len()];
        }
        v[252..].copy_from_slice(&i.to_le_bytes());
    } else {
        store::rng::Rng::new(u64::from(i) ^ 0x434f_484f_5254).fill(&mut v);
    }
    v
}

fn transaction(ids: &[u32], compressed: bool) -> OTxn<'static> {
    let (cid, oid) = identity();
    let mut t = OTxn::new();
    t.push(TOp::OmapSetKeys {
        cid,
        oid,
        pairs: ids
            .iter()
            .map(|&i| (Bytes::Owned(key(i)), Bytes::Owned(value(i, compressed))))
            .collect(),
    });
    t
}

fn mount(disk: &SimDisk, cfg: &StoreCfg) -> St {
    let d = disk.clone();
    Store::mount(move || d.queue(), SimClock::default(), cfg.clone())
        .unwrap()
        .0
}

fn durable(st: &mut St, t: &OTxn, token: u64, tick_ns: u64) {
    st.queue(t, token).unwrap();
    for _ in 0..20_000 {
        st.clk.t += tick_ns;
        let mut done = Vec::new();
        st.poll(&mut done).unwrap();
        let mut errors = Vec::new();
        st.take_queue_errors(&mut errors);
        assert!(errors.is_empty(), "{errors:?}");
        if done.contains(&token) {
            assert_eq!(done, vec![token]);
            return;
        }
        st.idle();
    }
    panic!("bounded queued transaction did not finish");
}

fn fixture(runs: bool, compressed: bool) -> (SimDisk, StoreCfg, St) {
    let disk = SimDisk::new(SimConfig::new(256 << 20));
    mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards: 1,
            wal_blocks: 8192,
            align_blocks: 1,
            omap_runs: runs,
            val_comp: compressed,
            ..Default::default()
        },
    )
    .unwrap();
    let mut cfg = StoreCfg::default();
    cfg.shard.cache_pages = 4096;
    cfg.shard.dirty_soft_pages = 512;
    cfg.shard.dirty_hard_pages = 1536;
    let mut st = mount(&disk, &cfg);
    let (cid, oid) = identity();
    let mut init = OTxn::new();
    init.mkcoll(cid);
    init.touch(cid, &oid);
    st.commit(&init).unwrap();
    for (n, ids) in (0..8192)
        .map(|i| 2 * i)
        .collect::<Vec<_>>()
        .chunks(1024)
        .enumerate()
    {
        durable(&mut st, &transaction(ids, compressed), 100 + n as u64, 0);
    }
    if compressed {
        assert!(
            st.shards[0].stats.val_comp > 0,
            "must actually compress, not just enable it"
        );
        assert!(st.shards[0].stats.val_comp_saved > 0);
    }
    st.checkpoint().unwrap();
    (disk, cfg, st)
}

/// Also reused by an external unchanged-main control. All correctness checks run
/// before returning work counts; only the candidate regression imposes a bound.
pub fn cold_case(runs: bool, compressed: bool, tick_ns: u64) -> (u64, u64) {
    let (disk, cfg, st) = fixture(runs, compressed);
    let image = disk.image();
    drop(st);
    let disk = SimDisk::from_image(&image, SimConfig::new(256 << 20));
    let mut st = mount(&disk, &cfg);
    let before = st.queue_attempts;
    let loads = st.shards[0].sh.tree_stats().loads;
    let ids: Vec<_> = (0..256).map(|i| 64 * i + 1).collect();
    let start = std::time::Instant::now();
    durable(&mut st, &transaction(&ids, compressed), 900, tick_ns);
    let elapsed = start.elapsed();
    let attempts = st.queue_attempts - before;
    let loads = st.shards[0].sh.tree_stats().loads - loads;
    assert!(loads >= 16, "must exercise genuinely cold metadata");
    if compressed {
        assert!(st.shards[0].stats.val_comp > 0);
        assert!(st.shards[0].stats.val_comp_saved > 0);
    }
    println!(
        "cold_case runs={runs} compressed={compressed} tick_ns={tick_ns} attempts={attempts} loads={loads} elapsed_us={}",
        elapsed.as_micros()
    );
    let (cid, oid) = identity();
    let got = st.omap_all(&cid, &oid).unwrap();
    assert_eq!(got.len(), 8448);
    for id in (0..8192).map(|i| 2 * i).chain(ids) {
        assert_eq!(got.get(&key(id)), Some(&value(id, compressed)));
    }
    let sc = st.scrub(&cid, &oid, 0).unwrap();
    assert_eq!((sc.omap_keys, sc.omap_bytes), (8448, 8448 * 320));
    let image = disk.crash_image(CrashPolicy::DROP_ALL);
    drop(st);
    let disk = SimDisk::from_image(&image, SimConfig::new(256 << 20));
    let mut st = mount(&disk, &cfg);
    assert_eq!(st.omap_all(&cid, &oid).unwrap(), got);
    assert!(st.check(false).unwrap().errors.is_empty());
    (attempts, loads)
}

#[test]
fn cold_batches_wait_for_discovered_pages_instead_of_each_completion() {
    for (runs, compressed) in [(true, false), (false, false), (true, true)] {
        for tick in [0, 1_000_000] {
            let (attempts, _) = cold_case(runs, compressed, tick);
            assert!(
                attempts <= 12,
                "partial completions caused {attempts} preparation/submission attempts"
            );
        }
    }
}

#[test]
fn cold_fifo_and_duplicate_keys_keep_read_fences_exact_counts_and_durable_order() {
    let (disk, cfg, st) = fixture(true, false);
    let image = disk.image();
    drop(st);
    let disk = SimDisk::from_image(&image, SimConfig::new(256 << 20));
    let mut st = mount(&disk, &cfg);
    let ids: Vec<_> = (0..256).map(|i| 64 * i + 1).collect();
    st.queue(&transaction(&ids, false), 777).unwrap();
    let (cid, oid) = identity();
    let mut next = OTxn::new();
    next.push(TOp::OmapSetKeys {
        cid,
        oid: oid.clone(),
        pairs: vec![
            (Bytes::Owned(key(1)), Bytes::Owned(b"wrong".to_vec())),
            (Bytes::Owned(key(1)), Bytes::Owned(b"last".to_vec())),
            (Bytes::Owned(key(0)), Bytes::Owned(Vec::new())),
        ],
    });
    st.queue(&next, 778).unwrap();
    let flags = st.begin_nonblock();
    let read = st.omap_get(&cid, &oid, &[key(1).as_slice()]);
    st.end_nonblock(flags);
    assert!(
        matches!(read, Err(ObjError::WouldBlock)),
        "read crossed the FIFO fence: {read:?}"
    );
    let mut done = Vec::new();
    st.poll(&mut done).unwrap();
    assert!(done.is_empty(), "no durable completion before cold IO");
    for _ in 0..20_000 {
        st.idle();
        st.poll(&mut done).unwrap();
        if done.contains(&778) {
            break;
        }
    }
    assert_eq!(done, vec![777, 778]);
    let mut expected: std::collections::BTreeMap<_, _> = (0..8192)
        .map(|i| 2 * i)
        .chain(ids)
        .map(|i| (key(i), value(i, false)))
        .collect();
    expected.insert(key(1), b"last".to_vec());
    expected.insert(key(0), Vec::new());
    assert_eq!(st.omap_all(&cid, &oid).unwrap(), expected);
    let bytes = expected
        .iter()
        .map(|(k, v)| (k.len() + v.len()) as u64)
        .sum();
    let sc = st.scrub(&cid, &oid, 0).unwrap();
    assert_eq!((sc.omap_keys, sc.omap_bytes), (8448, bytes));
    let crash = disk.crash_image(CrashPolicy::DROP_ALL);
    drop(st);
    let disk = SimDisk::from_image(&crash, SimConfig::new(256 << 20));
    let mut st = mount(&disk, &cfg);
    assert_eq!(st.omap_all(&cid, &oid).unwrap(), expected);
    assert!(st.check(false).unwrap().errors.is_empty());
}

#[test]
fn cold_io_error_is_reported_once_without_ack_or_reserved_leak() {
    let (disk, cfg, st) = fixture(true, false);
    let image = disk.image();
    drop(st);
    let disk = SimDisk::from_image(&image, SimConfig::new(256 << 20));
    let mut st = mount(&disk, &cfg);
    disk.fail_reads(0, u64::MAX / 2);
    let ids: Vec<_> = (0..256).map(|i| 64 * i + 1).collect();
    st.queue(&transaction(&ids, false), 800).unwrap();
    let mut done = Vec::new();
    let mut failed = false;
    for _ in 0..2000 {
        if st.poll(&mut done).is_err() {
            failed = true;
            break;
        }
        st.idle();
    }
    assert!(failed);
    assert!(done.is_empty());
    let mut errors = Vec::new();
    st.take_queue_errors(&mut errors);
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].0, 800);
    assert_eq!(st.queued_count(), 0);
    assert_eq!(st.shards[0].sh.state().alloc.n_reserved(), 0);
}

#[test]
fn completed_dependency_reads_after_a_long_pause_do_not_false_timeout() {
    let (disk, cfg, st) = fixture(true, false);
    let image = disk.image();
    drop(st);
    let disk = SimDisk::from_image(&image, SimConfig::new(256 << 20));
    let mut st = mount(&disk, &cfg);
    let ids: Vec<_> = (0..256).map(|i| 64 * i + 1).collect();
    st.queue(&transaction(&ids, false), 801).unwrap();
    st.clk.t += 60_000_000_000;
    let mut done = Vec::new();
    for _ in 0..20_000 {
        st.poll(&mut done).unwrap();
        if done.contains(&801) {
            break;
        }
        st.idle();
    }
    assert_eq!(done, vec![801]);
    let (cid, oid) = identity();
    assert_eq!(st.omap_all(&cid, &oid).unwrap().len(), 8448);
}
