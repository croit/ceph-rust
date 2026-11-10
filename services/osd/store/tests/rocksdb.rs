// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
#![cfg(all(feature = "rocksdb", feature = "lab"))]
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use store::dev::{CrashPolicy, SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::txn::Bytes as Data;
use store::obj::{OTxn, ObjError, Store, StoreCfg, TOp};
use store::rocks_omap::{Config, create};
type St = Store<SimDev, SimClock>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn oid(name: &[u8]) -> Ghobject {
    Ghobject::new(
        Hobject::new(name, SnapId::NOSNAP, 0, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}
fn collection(seed: u32) -> CollT {
    CollT::Pg(SpgT {
        pgid: PgT::new(1, seed),
        shard: ShardId::NO_SHARD,
    })
}
fn setup() -> (Temp, SimDisk, StoreCfg, St) {
    let root = std::env::temp_dir().join(format!(
        "croit-flashstore-rocks-objects-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    let disk = SimDisk::new(SimConfig::new(128 << 20));
    let (sb, _) = mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards: 2,
            wal_blocks: 512,
            align_blocks: 1,
            omap_rocksdb: true,
            ..Default::default()
        },
    )
    .unwrap();
    let mut rocks = Config::new(root.clone());
    rocks.allow_non_nvme = true;
    create(&rocks, &sb, 8 << 20).unwrap();
    let mut cfg = StoreCfg::default();
    cfg.shard.rocksdb = Some(rocks);
    cfg.shard.cache_pages = 2048; // 4 MiB DB share, 1 MiB result cache.
    let d = disk.clone();
    let st = Store::mount(move || d.queue(), SimClock::default(), cfg.clone())
        .unwrap()
        .0;
    (Temp(root), disk, cfg, st)
}

#[test]
fn checker_finds_orphan_ids_present_only_in_rocks_replay_buffers() {
    let (_temp, disk, mut cfg, st) = setup();
    drop(st);
    // Hold external materialization deterministically, not by racing a worker.
    // Only the DB is read-only here; native writes construct a deliberate orphan.
    cfg.shard.rocksdb.as_mut().unwrap().read_only = true;
    let d = disk.clone();
    let mut st = Store::mount(move || d.queue(), SimClock::default(), cfg)
        .unwrap()
        .0;
    let mut txn = store::shard::Txn::new(777);
    let pairs = [(
        bytes::Bytes::from_static(b"only-in-ram"),
        bytes::Bytes::from_static(b"value"),
    )];
    let (n, blob) = store::olsm::wire::put_blob(&pairs);
    txn.ops
        .push(store::state::Op::Omap(store::olsm::wire::OOp::Put {
            id: 777,
            n,
            blob,
        }));
    st.shards[0].sh.submit(txn).unwrap();
    let lsn = st.shards[0].sh.next_lsn() - 1;
    let deadline = Instant::now() + Duration::from_secs(10);
    while st.shards[0].sh.durable_lsn() < lsn {
        st.poll(&mut Vec::new()).unwrap();
        st.idle();
        assert!(
            Instant::now() < deadline,
            "orphan acknowledgement timed out"
        );
    }
    assert!(
        st.shards[0]
            .sh
            .state()
            .olsm
            .as_ref()
            .unwrap()
            .active
            .is_empty()
    );
    assert!(!st.shards[0].sh.olsm_flushed());
    let report = st.check(true).unwrap();
    assert!(
        report
            .errors
            .iter()
            .any(|e| e == "shard 0: keys of dead onode 777"),
        "{report:?}"
    );
}

#[test]
fn native_range_threshold_never_omits_materialized_rocksdb_keys() {
    let (_temp, mut disk, mut cfg, mut st) = setup();
    let c = collection(0);
    let object = oid(b"persisted-range");
    let keys = [
        Vec::new(),
        vec![0],
        vec![0, 255],
        b"a".to_vec(),
        b"b".to_vec(),
        b"c".to_vec(),
        b"z".to_vec(),
        vec![255],
    ];
    let mut model = BTreeMap::new();
    let mut t = OTxn::new();
    t.mkcoll(c);
    for (i, key) in keys.iter().enumerate() {
        let value = format!("value-{i}").into_bytes();
        t.push(TOp::OmapSetKeys {
            cid: c,
            oid: object.clone(),
            pairs: vec![(Data::Owned(key.clone()), Data::Owned(value.clone()))],
        });
        model.insert(key.clone(), value);
    }
    st.commit(&t).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while st.shards.iter().any(|s| !s.sh.olsm_flushed()) {
        st.poll(&mut Vec::new()).unwrap();
        st.idle();
        assert!(
            Instant::now() < deadline,
            "RocksDB materialization timed out"
        );
    }
    st.checkpoint().unwrap();
    let image = disk.crash_image(CrashPolicy::DROP_ALL);
    drop(st);
    disk = SimDisk::from_image(&image, SimConfig::new(128 << 20));
    cfg.shard.omap_delete_range_threshold = u64::MAX;
    let d = disk.clone();
    st = Store::mount(move || d.queue(), SimClock::default(), cfg.clone())
        .unwrap()
        .0;
    assert_eq!(st.omap_all(&c, &object).unwrap(), model);

    let mut t = OTxn::new();
    t.push(TOp::OmapRmKeyRange {
        cid: c,
        oid: object.clone(),
        first: Data::Borrowed(b"\0"),
        last: Data::Borrowed(b"c"),
    });
    t.omap_set(c, &object, b"a", b"later-put");
    st.commit(&t).unwrap();
    model.retain(|k, _| k.as_slice() < &b"\0"[..] || k.as_slice() >= &b"c"[..]);
    model.insert(b"a".to_vec(), b"later-put".to_vec());
    assert_eq!(st.omap_all(&c, &object).unwrap(), model);

    // Cut after acknowledgement: neither native replay nor the external DB may
    // resurrect removed keys, including the lower boundary and binary keys.
    let image = disk.crash_image(CrashPolicy::DROP_ALL);
    drop(st);
    disk = SimDisk::from_image(&image, SimConfig::new(128 << 20));
    let d = disk.clone();
    st = Store::mount(move || d.queue(), SimClock::default(), cfg)
        .unwrap()
        .0;
    assert_eq!(st.omap_all(&c, &object).unwrap(), model);
    for s in &st.shards {
        assert!(
            s.sh.olsm_stats().is_none(),
            "RocksDB must not use native GC"
        );
        assert_eq!(s.sh.state().olsm.as_ref().unwrap().man.runs().count(), 0);
    }
    assert!(st.check(true).unwrap().errors.is_empty());
}

#[test]
fn mixed_object_omap_clone_remove_and_restart_match_independent_maps() {
    let (_temp, mut disk, cfg, mut st) = setup();
    let object = oid(b"user");
    let clone = oid(b"clone");
    let cols = [collection(0), collection(1)];
    let mut model = [BTreeMap::new(), BTreeMap::new()];
    for c in cols {
        let mut t = OTxn::new();
        t.mkcoll(c);
        t.write(c, &object, 0, b"native-payload");
        t.setattr(c, &object, b"a", b"native-attribute");
        st.commit(&t).unwrap();
    }
    for round in 0..160usize {
        let slot = round % 2;
        let c = cols[slot];
        let key = format!("key-{:03}", (round * 13) % 61).into_bytes();
        let value = format!("value-{round:05}").into_bytes();
        let mut t = OTxn::new();
        match round % 9 {
            0 => {
                t.push(TOp::OmapClear {
                    cid: c,
                    oid: object.clone(),
                });
                model[slot].clear();
                t.omap_set(c, &object, &key, &value);
                model[slot].insert(key.clone(), value.clone());
            }
            1 => {
                t.push(TOp::OmapRmKeyRange {
                    cid: c,
                    oid: object.clone(),
                    first: Data::Borrowed(b"key-010"),
                    last: Data::Borrowed(b"key-035"),
                });
                model[slot].retain(|k, _| {
                    k.as_slice() < &b"key-010"[..] || k.as_slice() >= &b"key-035"[..]
                });
            }
            2 => {
                t.push(TOp::OmapRmKeys {
                    cid: c,
                    oid: object.clone(),
                    keys: vec![Data::Borrowed(&key)],
                });
                model[slot].remove(&key);
            }
            _ => {
                t.omap_set(c, &object, &key, &value);
                t.omap_set(c, &object, &key, b"last-write");
                model[slot].insert(key.clone(), b"last-write".to_vec());
            }
        }
        st.commit(&t).unwrap();
        assert_eq!(st.omap_all(&c, &object).unwrap(), model[slot]);
        assert_eq!(st.read(&c, &object, 0, 99).unwrap(), b"native-payload");
        if round % 31 == 30 {
            assert!(st.check(true).unwrap().errors.is_empty());
            let image = disk.crash_image(CrashPolicy::DROP_ALL);
            drop(st);
            disk = SimDisk::from_image(&image, SimConfig::new(128 << 20));
            let d = disk.clone();
            st = Store::mount(move || d.queue(), SimClock::default(), cfg.clone())
                .unwrap()
                .0;
            for (i, c) in cols.iter().enumerate() {
                assert_eq!(st.omap_all(c, &object).unwrap(), model[i]);
            }
        }
    }
    for (i, c) in cols.iter().enumerate() {
        let mut t = OTxn::new();
        t.push(TOp::Clone {
            cid: *c,
            src: object.clone(),
            dst: clone.clone(),
        });
        t.remove(*c, &object);
        t.write(*c, &object, 0, b"recreated");
        t.omap_set(*c, &object, b"", b"empty-key");
        t.omap_set(*c, &object, b"\0\xff", b"binary-key");
        st.commit(&t).unwrap();
        assert_eq!(st.omap_all(c, &clone).unwrap(), model[i]);
        assert_eq!(
            st.omap_all(c, &object).unwrap(),
            BTreeMap::from([
                (Vec::new(), b"empty-key".to_vec()),
                (b"\0\xff".to_vec(), b"binary-key".to_vec())
            ])
        );
    }
    assert!(st.check(true).unwrap().errors.is_empty());
}

#[test]
fn competing_nonblocking_scans_exceed_cache_and_survive_unrelated_writes() {
    let (_temp, disk, cfg, mut st) = setup();
    let c = collection(0);
    let objects = [oid(b"a"), oid(b"b")];
    let unrelated = oid(b"unrelated");
    let value = vec![23u8; 2048];
    let mut t = OTxn::new();
    t.mkcoll(c);
    st.commit(&t).unwrap();
    for object in &objects {
        for i in 0..600 {
            let key = format!("k{i:04}");
            let mut t = OTxn::new();
            t.omap_set(c, object, key.as_bytes(), &value);
            st.commit(&t).unwrap();
        }
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while st.shards.iter().any(|s| !s.sh.olsm_flushed()) {
        st.poll(&mut Vec::new()).unwrap();
        st.idle();
        assert!(Instant::now() < deadline);
    }
    // Reopen: the entire scan must come from actual RocksDB, not active memory.
    drop(st);
    let d = disk.clone();
    let mut st = Store::mount(move || d.queue(), SimClock::default(), cfg)
        .unwrap()
        .0;
    st.set_nonblock_reads(true);
    let mut done = [false, false];
    for round in 0..20_000 {
        if round == 3 {
            st.clk.t += 1_000_000_000;
        } // active output must survive ordinary 200ms cache TTL
        for i in 0..2 {
            if done[i] {
                continue;
            }
            st.read_session(Some((91, i as u64)), true);
            let before = st.clk.t;
            let result = st.omap_iter(&c, &objects[i], b"", 601);
            assert_eq!(st.clk.t, before, "nonblocking listing waited on owner core");
            let blocked = matches!(result, Err(ObjError::WouldBlock));
            st.read_session(None, blocked);
            match result {
                Ok((v, more)) => {
                    assert!(!more);
                    assert_eq!(v.len(), 600);
                    assert!(v.iter().all(|(_, v)| *v == value));
                    done[i] = true;
                }
                Err(ObjError::WouldBlock) => {}
                Err(e) => panic!("{e:?}"),
            }
        }
        if done == [true, true] {
            return;
        }
        if round % 7 == 0 {
            st.set_nonblock_reads(false);
            let mut t = OTxn::new();
            t.omap_set(c, &unrelated, b"k", b"background");
            st.commit(&t).unwrap();
            st.set_nonblock_reads(true);
        }
        st.poll(&mut Vec::new()).unwrap();
        st.idle();
        std::thread::yield_now();
        assert!(
            Instant::now() < deadline,
            "scans failed to make bounded progress"
        );
    }
    panic!("scan retry bound exceeded");
}

#[test]
fn count_bounded_scan_batches_worker_requests_across_owner_slices() {
    let (_temp, disk, cfg, mut st) = setup();
    let c = collection(0);
    let cases = [1023usize, 1024, 1025, 2048];
    let value = vec![19; 256];
    let mut objects = Vec::new();
    let mut t = OTxn::new();
    t.mkcoll(c);
    st.commit(&t).unwrap();
    for n in cases {
        let object = oid(format!("lookahead-{n}").as_bytes());
        let keys: Vec<_> = (0..n).map(|i| format!("a/{i:05}").into_bytes()).collect();
        for batch in keys.chunks(64) {
            let mut t = OTxn::new();
            for key in batch {
                t.omap_set(c, &object, key, &value);
            }
            st.commit(&t).unwrap();
        }
        objects.push(object);
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while st.shards.iter().any(|s| !s.sh.olsm_flushed()) {
        st.poll(&mut Vec::new()).unwrap();
        st.idle();
        std::thread::yield_now();
        assert!(Instant::now() < deadline);
    }
    drop(st);
    let d = disk.clone();
    let mut st = Store::mount(move || d.queue(), SimClock::default(), cfg)
        .unwrap()
        .0;
    st.set_nonblock_reads(true);
    let requests = |st: &St| {
        st.perf_counters()
            .into_iter()
            .find(|(name, _, _)| *name == "rocks_page_requests")
            .unwrap()
            .2
    };
    let mut session = 0;
    for (n, object) in cases.into_iter().zip(objects) {
        let before = requests(&st);
        let mut after = Vec::new();
        let mut got = Vec::new();
        loop {
            session += 1;
            let (page, more) = loop {
                st.read_session(Some((909, session)), true);
                let result = st.omap_iter(&c, &object, &after, 1024);
                let blocked = matches!(result, Err(ObjError::WouldBlock));
                st.read_session(None, blocked);
                match result {
                    Ok(result) => break result,
                    Err(ObjError::WouldBlock) => {}
                    Err(e) => panic!("{e:?}"),
                }
                st.poll(&mut Vec::new()).unwrap();
                st.idle();
                std::thread::yield_now();
                assert!(Instant::now() < deadline, "scan failed to make progress");
            };
            assert_eq!(more, got.len() + page.len() < n);
            after = page.last().unwrap().0.clone();
            after.push(0); // omap_iter is inclusive: use the strict byte-key successor
            got.extend(page);
            if !more {
                break;
            }
        }
        let expected: Vec<_> = (0..n)
            .map(|i| (format!("a/{i:05}").into_bytes(), value.clone()))
            .collect();
        assert_eq!(got.len(), expected.len(), "n={n}");
        for (index, (actual, want)) in got.iter().zip(&expected).enumerate() {
            assert_eq!(actual.0, want.0, "n={n} index={index}");
            assert!(actual.1 == want.1, "value n={n} index={index}");
        }
        assert_eq!(
            requests(&st) - before,
            n.div_ceil(1024) as u64,
            "a reply-sized worker batch must survive owner slice yields, n={n}"
        );
        // Exercise the Stage byte-cutoff modes across its mandatory slice yield.
        // Recovery's strict cutoff differs from Values/Keys: equality refuses
        // the next entry, while an oversized first entry still makes progress.
        for (mode, max, budget, expected_n, worker_pages) in [
            (0, usize::MAX, 256 * (7 + 256), 256, 1),
            (1, usize::MAX, 256 * (7 + 4), 256, 1),
            (2, 256, usize::MAX, 256, 1),
            (2, usize::MAX, 257 * (7 + 256), 256, 2),
            (2, usize::MAX, 1, 1, 1),
        ] {
            session += 1;
            let before = requests(&st);
            let (page, next) = loop {
                st.read_session(Some((909, session)), true);
                let result = if mode == 2 {
                    st.omap_recovery_range(&c, &object, b"", max, budget as u64)
                } else {
                    st.omap_range(&c, &object, b"", b"a/", max, budget, mode == 0)
                        .map(|(page, more)| {
                            let next = more.then(|| format!("a/{:05}", page.len()).into_bytes());
                            (page, next)
                        })
                };
                let blocked = matches!(result, Err(ObjError::WouldBlock));
                st.read_session(None, blocked);
                match result {
                    Ok(result) => break result,
                    Err(ObjError::WouldBlock) => {}
                    Err(e) => panic!("{e:?}"),
                }
                st.poll(&mut Vec::new()).unwrap();
                st.idle();
                std::thread::yield_now();
                assert!(Instant::now() < deadline, "byte-cutoff scan stalled");
            };
            assert_eq!(page.len(), expected_n, "mode={mode} budget={budget}");
            assert_eq!(next, Some(format!("a/{expected_n:05}").into_bytes()));
            for (i, (key, v)) in page.iter().enumerate() {
                assert_eq!(key, &format!("a/{i:05}").into_bytes());
                assert_eq!(v.as_slice(), if mode == 1 { &[][..] } else { &value[..] });
            }
            assert_eq!(
                requests(&st) - before,
                worker_pages,
                "mode={mode} budget={budget}"
            );
        }
    }
}

#[test]
fn encoded_rocks_listing_reserves_trailer_and_replays_independent_owned_output() {
    let (_temp, disk, cfg, mut st) = setup();
    let c = collection(0);
    let object = oid(b"encoded-retry");
    let keys: Vec<_> = (0..700).map(|i| format!("b/{i:05}").into_bytes()).collect();
    let value = vec![0x91; 256];
    let mut txn = OTxn::new();
    txn.mkcoll(c);
    st.commit(&txn).unwrap();
    for batch in keys.chunks(64) {
        let mut txn = OTxn::new();
        for key in batch {
            txn.omap_set(c, &object, key, &value);
        }
        st.commit(&txn).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while st.shards.iter().any(|s| !s.sh.olsm_flushed()) {
        st.poll(&mut Vec::new()).unwrap();
        st.idle();
        std::thread::yield_now();
        assert!(Instant::now() < deadline);
    }
    drop(st);
    let d = disk.clone();
    let mut st = Store::mount(move || d.queue(), SimClock::default(), cfg)
        .unwrap()
        .0;
    st.set_nonblock_reads(true);
    let mut yielded = 0;
    let (mut first, n, more) = loop {
        st.read_session(Some((938, 1)), true);
        let result = st.omap_list_enc(&c, &object, b"", b"b/", 512, usize::MAX, true, 4);
        st.read_session(None, true); // a later suboperation is still pending
        match result {
            Ok(out) => break out,
            Err(ObjError::WouldBlock) => yielded += 1,
            Err(e) => panic!("{e:?}"),
        }
        st.poll(&mut Vec::new()).unwrap();
        st.idle();
        std::thread::yield_now();
        assert!(Instant::now() < deadline);
    };
    assert!(yielded >= 2, "owner work must remain sliced");
    assert_eq!(n, 512);
    assert!(more);
    assert!(
        first.capacity() > first.len(),
        "encoded API promises spare trailer capacity"
    );
    let mut expected = vec![0; 4];
    for key in &keys[..512] {
        expected.extend_from_slice(&(key.len() as u32).to_le_bytes());
        expected.extend_from_slice(key);
        expected.extend_from_slice(&(value.len() as u32).to_le_bytes());
        expected.extend_from_slice(&value);
    }
    assert_eq!(first, expected);
    let before = st
        .perf_counters()
        .into_iter()
        .find(|(k, _, _)| *k == "rocks_page_requests")
        .unwrap()
        .2;
    first[0] = 255;
    first.push(1); // caller finalization cannot mutate the retained memo
    st.read_session(Some((938, 1)), true);
    let (second, n2, more2) = st
        .omap_list_enc(&c, &object, b"", b"b/", 512, usize::MAX, true, 4)
        .unwrap();
    st.read_session(None, false);
    assert_eq!(second, expected);
    assert!(second.capacity() > second.len());
    assert_eq!((n2, more2), (n, more));
    let after = st
        .perf_counters()
        .into_iter()
        .find(|(k, _, _)| *k == "rocks_page_requests")
        .unwrap()
        .2;
    assert_eq!(
        after, before,
        "compound retry must reuse completed encoded output"
    );

    let slices = |st: &St| {
        st.perf_counters()
            .into_iter()
            .find(|(k, _, _)| *k == "scan_slices")
            .unwrap()
            .2
    };
    let before = slices(&st);
    loop {
        st.read_session(Some((938, 2)), true);
        let result = st.omap_iter(&c, &object, b"", 700);
        st.read_session(None, true);
        assert!(matches!(result, Err(ObjError::WouldBlock)));
        if slices(&st) > before {
            break;
        } // the batch has been only partially consumed
        st.poll(&mut Vec::new()).unwrap();
        st.idle();
        std::thread::yield_now();
        assert!(Instant::now() < deadline);
    }
    let changed = b"changed during owner yield";
    let mut txn = OTxn::new();
    txn.omap_set(c, &object, &keys[100], changed); // invalidate an already encoded entry
    txn.omap_set(c, &object, &keys[600], changed); // invalidate an unconsumed batch entry
    st.commit(&txn).unwrap();
    let page = loop {
        st.read_session(Some((938, 2)), true);
        let result = st.omap_iter(&c, &object, b"", 700);
        let blocked = matches!(result, Err(ObjError::WouldBlock));
        st.read_session(None, blocked);
        match result {
            Ok((page, more)) => {
                assert!(!more);
                break page;
            }
            Err(ObjError::WouldBlock) => {}
            Err(e) => panic!("{e:?}"),
        }
        st.poll(&mut Vec::new()).unwrap();
        st.idle();
        std::thread::yield_now();
        assert!(Instant::now() < deadline);
    };
    assert_eq!(page.len(), keys.len());
    for (i, (k, v)) in page.iter().enumerate() {
        assert_eq!(k, &keys[i]);
        assert_eq!(
            v.as_slice(),
            if i == 100 || i == 600 {
                changed
            } else {
                &value[..]
            }
        );
    }

    // Cancel while most of an admitted worker batch is still unconsumed. A
    // different request must then acquire credits and finish, not wait on it.
    let before = slices(&st);
    loop {
        st.read_session(Some((938, 3)), true);
        let result = st.omap_iter(&c, &object, b"", 700);
        let partial = slices(&st) > before;
        st.read_session(None, !partial);
        assert!(matches!(result, Err(ObjError::WouldBlock)));
        if partial {
            break;
        }
        st.poll(&mut Vec::new()).unwrap();
        st.idle();
        std::thread::yield_now();
        assert!(Instant::now() < deadline);
    }
    loop {
        st.read_session(Some((938, 4)), true);
        let result = st.omap_iter(&c, &object, b"", 700);
        let blocked = matches!(result, Err(ObjError::WouldBlock));
        st.read_session(None, blocked);
        match result {
            Ok((after_cancel, more)) => {
                assert!(!more);
                assert_eq!(after_cancel, page);
                break;
            }
            Err(ObjError::WouldBlock) => {}
            Err(e) => panic!("{e:?}"),
        }
        st.poll(&mut Vec::new()).unwrap();
        st.idle();
        std::thread::yield_now();
        assert!(
            Instant::now() < deadline,
            "cancelled batch retained request credits"
        );
    }
}

#[test]
fn queued_large_clone_preserves_progress_after_staged_source_mutation() {
    let (_temp, _disk, _cfg, mut st) = setup();
    let c = collection(0);
    let source = oid(b"source");
    let destination = oid(b"destination");
    let mut t = OTxn::new();
    t.mkcoll(c);
    for i in 0..700 {
        t.push(TOp::OmapSetKeys {
            cid: c,
            oid: source.clone(),
            pairs: vec![(
                Data::Owned(format!("k{i:04}").into_bytes()),
                Data::Borrowed(b"base"),
            )],
        });
    }
    st.commit(&t).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while st.shards.iter().any(|s| !s.sh.olsm_flushed()) {
        st.poll(&mut Vec::new()).unwrap();
        st.idle();
        assert!(Instant::now() < deadline);
    }
    st.read_session(Some((93, 1)), true);
    assert_eq!(
        st.omap_get(&c, &source, &[b"k0000"])
            .unwrap()
            .get(&b"k0000"[..]),
        Some(&b"base".to_vec())
    );
    // Keep the outer session open while queue() enters nested staging scopes.
    let mut t = OTxn::new();
    t.omap_set(c, &source, b"staged", b"before-clone");
    t.push(TOp::Clone {
        cid: c,
        src: source.clone(),
        dst: destination.clone(),
    });
    let before = st.clk.t;
    st.queue(&t, 991).unwrap();
    assert_eq!(st.clk.t, before);
    let mut acked = Vec::new();
    loop {
        let before = st.clk.t;
        st.poll(&mut acked).unwrap();
        assert_eq!(st.clk.t, before, "queued clone used a blocking fallback");
        let mut errors = Vec::new();
        st.take_queue_errors(&mut errors);
        assert!(errors.is_empty(), "{errors:?}");
        if acked.contains(&991) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "clone repeatedly restarted its first slice"
        );
        st.idle();
        std::thread::yield_now();
    }
    let before = st.clk.t;
    assert_eq!(
        st.omap_get(&c, &source, &[b"k0000"])
            .unwrap()
            .get(&b"k0000"[..]),
        Some(&b"base".to_vec())
    );
    assert_eq!(
        st.clk.t, before,
        "child completion released its parent's protected answer"
    );
    st.read_session(None, false);
    let got = st.omap_all(&c, &destination).unwrap();
    assert_eq!(got.len(), 701);
    assert_eq!(got.get(&b"staged"[..]), Some(&b"before-clone".to_vec()));
    assert_eq!(got, st.omap_all(&c, &source).unwrap());
}

#[test]
fn scan_output_quota_refuses_oversized_request_and_releases_competing_reader() {
    let (_temp, _disk, _cfg, mut st) = setup();
    let c = collection(0);
    let big = oid(b"big");
    let small = oid(b"small");
    let value = vec![31; 2048];
    let mut t = OTxn::new();
    t.mkcoll(c);
    t.omap_set(c, &small, b"one", b"ok");
    st.commit(&t).unwrap();
    for i in 0..1200 {
        let k = format!("k{i:04}");
        let mut t = OTxn::new();
        t.omap_set(c, &big, k.as_bytes(), &value);
        st.commit(&t).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while st.shards.iter().any(|s| !s.sh.olsm_flushed()) {
        st.poll(&mut Vec::new()).unwrap();
        st.idle();
        assert!(Instant::now() < deadline);
    }
    st.set_nonblock_reads(true);
    let mut done = [false, false];
    loop {
        for i in 0..2 {
            if done[i] {
                continue;
            }
            st.read_session(Some((92, i as u64)), true);
            let result = st.omap_iter(&c, if i == 0 { &big } else { &small }, b"", 1201);
            st.read_session(None, matches!(result, Err(ObjError::WouldBlock)));
            match result {
                Err(ObjError::WouldBlock) => {}
                Err(ObjError::TooLarge) if i == 0 => done[0] = true,
                Ok((v, false)) if i == 1 => {
                    assert_eq!(v, vec![(b"one".to_vec(), b"ok".to_vec())]);
                    done[1] = true;
                }
                r => panic!("unexpected admission result for {i}: {r:?}"),
            }
        }
        if done == [true, true] {
            break;
        }
        st.poll(&mut Vec::new()).unwrap();
        st.idle();
        std::thread::yield_now();
        assert!(Instant::now() < deadline);
    }
}
