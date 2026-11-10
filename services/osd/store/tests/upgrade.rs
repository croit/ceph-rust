// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Offline format upgrade (adr 0611), step S7: tree omap -> omap LSM engine. A tree store with omap on many objects,
//! a hot object (adr 0476 runs), large / fragment-sized / compressible values, headers and pgmeta objects is upgraded;
//! afterwards every key, value and header reads back the same in the same order through a service mount, and fsck plus
//! the object check are clean. The crash matrix cuts the upgrade at every `UPGRADE_CRASH_STRIDE`-th device event (default
//! 7; 1 = every event, lab/store-upgrade-test.sh) with each of the three crash policies, resumes and checks the same. The mount gate refuses a marked store
//! and a newer one; a rerun is a no-op.

use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use std::collections::BTreeMap;
use store::dev::{CrashPolicy, SimClock, SimConfig, SimDev, SimDisk, SimImage};
use store::error::StoreError;
use store::layout::{FEAT_OMAP_LSM, FEAT_UPGRADING, MkfsParams, heal_super, mkfs, read_super};
use store::obj::txn::Bytes;
use store::obj::{OTxn, ObjError, Store, StoreCfg, TOp};
use store::upgrade::{Event, Opts, UpgradeError};

/// Omap contents per object: header, keys in order.
type Model = BTreeMap<(CollT, Ghobject), (Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>)>;

fn sim() -> SimConfig {
    SimConfig::new(96 << 20)
}

fn coll(seed: u32) -> CollT {
    CollT::Pg(SpgT {
        pgid: PgT::new(1, seed),
        shard: ShardId::NO_SHARD,
    })
}

fn obj(seed: u32, name: &str) -> Ghobject {
    Ghobject::new(
        Hobject::new(name.as_bytes(), SnapId::NOSNAP, seed, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

/// Value `i` of size class `i % 7`: small, medium, compressible text, near the tree entry limit, data-block sized.
fn value(i: u32) -> Vec<u8> {
    let n = match i % 7 {
        0 | 1 => 24,
        2 => 180,
        3 => 300,
        4 => 1500,
        5 => 2600,
        _ => 9000,
    };
    if i % 7 == 3 {
        let text = b"{\"pool\": 1, \"image\": \"rbd_data.abcdef\", \"state\": \"clean\"} ";
        let mut v: Vec<u8> = text.iter().copied().cycle().take(n).collect();
        v[..4].copy_from_slice(&i.to_le_bytes());
        return v;
    }
    let mut v = vec![0; n];
    store::rng::Rng::new(u64::from(i) ^ 0x5550_4752).fill(&mut v);
    v
}

fn put(m: &mut Model, t: &mut OTxn, c: CollT, o: &Ghobject, kv: Vec<(Vec<u8>, Vec<u8>)>) {
    let e = m.entry((c, o.clone())).or_default();
    for (k, v) in &kv {
        e.1.insert(k.clone(), v.clone());
    }
    t.push(TOp::OmapSetKeys {
        cid: c,
        oid: o.clone(),
        pairs: kv
            .into_iter()
            .map(|(k, v)| (Bytes::Owned(k), Bytes::Owned(v)))
            .collect(),
    });
}

/// A tree-format store (2 shards) with the fixture omap.
fn fixture() -> (SimImage, Model) {
    let disk = SimDisk::new(sim());
    let p = MkfsParams {
        shards: 2,
        wal_blocks: 1024,
        align_blocks: 1,
        meta_pct: 10,
        ..Default::default()
    };
    mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
    let d = disk.clone();
    let (mut st, _) =
        Store::mount(move || d.queue(), SimClock::default(), StoreCfg::default()).unwrap();
    let mut m = Model::new();
    let mut i = 0u32;
    for seed in 0..4 {
        let c = coll(seed);
        let mut t = OTxn::new();
        t.push(TOp::MkColl {
            cid: c,
            bits: 0,
            exist_ok: true,
        });
        // pgmeta: PG log style keys, header
        let pg = Ghobject::pgmeta(1, seed, ShardId::NO_SHARD);
        t.push(TOp::Touch {
            cid: c,
            oid: pg.clone(),
        });
        let kv = (0..40)
            .map(|j| (format!("0000000001.{j:020}").into_bytes(), value(j)))
            .collect();
        put(&mut m, &mut t, c, &pg, kv);
        t.push(TOp::OmapSetHeader {
            cid: c,
            oid: pg.clone(),
            header: Bytes::Owned(b"pginfo".to_vec()),
        });
        m.get_mut(&(c, pg.clone())).unwrap().0 = b"pginfo".to_vec();
        st.commit(&t).unwrap();
        // many small objects, some with a header
        for n in 0..25 {
            let o = obj(seed, &format!("rbd_header.{seed}.{n}"));
            let mut t = OTxn::new();
            t.push(TOp::Touch {
                cid: c,
                oid: o.clone(),
            });
            let kv = (0..12)
                .map(|_| {
                    i += 1;
                    (format!("key_{i:06}").into_bytes(), value(i))
                })
                .collect();
            put(&mut m, &mut t, c, &o, kv);
            if n % 3 == 0 {
                let h = format!("hdr{n}").into_bytes();
                t.push(TOp::OmapSetHeader {
                    cid: c,
                    oid: o.clone(),
                    header: Bytes::Owned(h.clone()),
                });
                m.get_mut(&(c, o.clone())).unwrap().0 = h;
            }
            st.commit(&t).unwrap();
        }
    }
    // hot object: client batches staged as adr 0476 runs (small inline values), then overwrites and removals
    let c = coll(1);
    let hot = obj(1, "rbd_directory");
    for b in 0..6u32 {
        let kv: BTreeMap<Vec<u8>, Vec<u8>> = (0..300)
            .map(|j| {
                let k = format!("name_{:05}", (b * 170 + j) % 1400).into_bytes();
                (
                    k,
                    format!("v{b}.{j}.{}", "x".repeat((j % 40) as usize)).into_bytes(),
                )
            })
            .collect();
        let mut enc = Vec::new();
        denc::SortedKv::encode_into(
            &mut enc,
            kv.len(),
            kv.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
        );
        let e = m.entry((c, hot.clone())).or_default();
        e.1.extend(kv);
        let mut t = OTxn::new();
        t.push(TOp::OmapSetRun {
            cid: c,
            oid: hot.clone(),
            run: store::obj::KvRunData::from_encoding(enc.into()).unwrap(),
        });
        st.queue(&t, 1 + u64::from(b)).unwrap();
        st.sync().unwrap();
        let rm: Vec<Vec<u8>> = (0..20)
            .map(|j| format!("name_{:05}", (b * 97 + j * 13) % 1400).into_bytes())
            .collect();
        for k in &rm {
            e.1.remove(k);
        }
        let mut t = OTxn::new();
        t.push(TOp::OmapRmKeys {
            cid: c,
            oid: hot.clone(),
            keys: rm.into_iter().map(Bytes::Owned).collect(),
        });
        st.commit(&t).unwrap();
    }
    // a cleared object: keys and header gone
    let o = obj(2, "rbd_header.2.0");
    let mut t = OTxn::new();
    t.push(TOp::OmapClear {
        cid: coll(2),
        oid: o.clone(),
    });
    *m.get_mut(&(coll(2), o)).unwrap() = Default::default();
    st.commit(&t).unwrap();
    st.sync().unwrap();
    drop(st);
    (disk.crash_image(CrashPolicy::PERSIST_ALL), m)
}

/// A small cache: the engine's memtable (a quarter of its half of the cache) and so the batch is small, the shards
/// convert in many batches.
fn upgrade_cfg() -> StoreCfg {
    let mut c = StoreCfg::default();
    c.shard.cache_pages = 384;
    c
}

fn opts() -> Opts {
    Opts {
        omap_lsm: true,
        dry_run: false,
    }
}

fn upgrade(disk: &SimDisk, o: Opts) -> Result<(store::upgrade::Report, Vec<Event>), UpgradeError> {
    let d = disk.clone();
    let mut ev = Vec::new();
    let r = store::upgrade::run(
        move || Ok(d.queue()),
        SimClock::default(),
        upgrade_cfg(),
        o,
        &mut |e| ev.push(e.clone()),
    )?;
    Ok((r, ev))
}

fn features(disk: &SimDisk) -> u64 {
    read_super(&mut disk.queue(), &mut SimClock::default())
        .unwrap()
        .0
        .features
}

fn service_mount(disk: &SimDisk) -> Result<Store<SimDev, SimClock>, ObjError> {
    let d = disk.clone();
    Store::mount(move || d.queue(), SimClock::default(), StoreCfg::default()).map(|x| x.0)
}

/// Every object reads back its header and keys, in order; fsck and the object check are clean; the engine holds the
/// omap (format bit set, no mark).
fn verify(disk: &SimDisk, m: &Model, what: &str) {
    let f = features(disk);
    assert!(
        f & FEAT_OMAP_LSM != 0 && f & FEAT_UPGRADING == 0,
        "{what}: features {f:#x}"
    );
    let mut st = service_mount(disk).unwrap_or_else(|e| panic!("{what}: mount: {e}"));
    for ((c, o), (h, kv)) in m {
        let (got, more) = st.omap_iter(c, o, b"", usize::MAX - 1).unwrap();
        assert!(!more, "{what}: {o:?}");
        let want: Vec<(Vec<u8>, Vec<u8>)> =
            kv.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        assert_eq!(got.len(), want.len(), "{what}: {o:?} key count");
        assert!(
            got.iter().zip(&want).all(|(a, b)| a.0 == b.0 && a.1 == b.1),
            "{what}: {o:?} keys/values/order"
        );
        assert_eq!(&st.omap_header(c, o).unwrap(), h, "{what}: {o:?} header");
    }
    let r = st.check(true).unwrap();
    assert!(r.errors.is_empty(), "{what}: check {:?}", r.errors);
    st.checkpoint().unwrap();
    drop(st);
    store::fsck::fsck(
        &mut disk.queue(),
        &mut SimClock::default(),
        Some(&store::obj::onode::fsck_refs),
    )
    .unwrap_or_else(|e| panic!("{what}: fsck {e}"));
}

#[test]
fn unsupported_old_format_refuses_upgrade_before_writes() {
    let disk = SimDisk::new(sim());
    mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards: 2,
            wal_blocks: 1024,
            long_names: false,
            align_blocks: 1,
            meta_pct: 10,
            ..Default::default()
        },
    )
    .unwrap();
    let writes = disk.stats().writes;
    for omap_lsm in [false, true] {
        for dry_run in [false, true] {
            match upgrade(&disk, Opts { omap_lsm, dry_run }) {
                Err(e) => {
                    let msg = e.to_string();
                    assert!(msg.contains("long_name"), "{msg}");
                    assert!(msg.contains("no in-place upgrade"), "{msg}");
                }
                r => panic!("unsupported old format: {r:?}"),
            }
            assert_eq!(disk.stats().writes, writes, "refusal must precede writes");
        }
    }
}

#[test]
fn upgrade_converts_every_omap_entry_and_reruns_as_noop() {
    let (img, m) = fixture();
    let disk = SimDisk::from_image(&img, sim());
    {
        let mut st = service_mount(&disk).unwrap();
        assert!(
            st.shards.iter().any(|s| !s.sh.state().runs.is_empty()),
            "fixture has adr 0476 runs"
        );
        st.checkpoint().unwrap();
    }
    // dry run: plan only, nothing written
    let w0 = disk.stats().writes;
    let (r, ev) = upgrade(
        &disk,
        Opts {
            omap_lsm: true,
            dry_run: true,
        },
    )
    .unwrap();
    assert_eq!(r.steps, vec!["omap_lsm"]);
    assert!(matches!(&ev[..], [Event::Plan { resume: false, .. }]));
    assert_eq!(disk.stats().writes, w0, "dry run writes nothing");
    // without the opt-in nothing is due
    assert!(upgrade(&disk, Opts::default()).unwrap().0.steps.is_empty());
    let (r, ev) = upgrade(&disk, opts()).unwrap();
    assert_eq!(r.steps, vec!["omap_lsm"]);
    assert!(!r.resumed);
    let entries: u64 = ev
        .iter()
        .map(|e| match e {
            Event::Survey { entries, .. } => *entries,
            _ => 0,
        })
        .sum();
    let done: u64 = ev
        .iter()
        .filter_map(|e| match e {
            Event::ShardDone { .. } => Some(0),
            _ => None,
        })
        .count() as u64;
    assert!(entries > 1000, "survey {entries}");
    assert_eq!(done, 2);
    let batches = ev
        .iter()
        .filter(|e| matches!(e, Event::Progress { .. }))
        .count();
    assert!(batches > 4, "converted in {batches} batches");
    verify(&disk, &m, "upgraded");
    // rerun: nothing to do, no write
    let w1 = disk.stats().writes;
    let (r, _) = upgrade(&disk, opts()).unwrap();
    assert!(r.steps.is_empty());
    assert_eq!(disk.stats().writes, w1, "rerun writes nothing");
    verify(&disk, &m, "rerun");
}

/// Set the S7 mark by hand (as a crash right after the mark leaves it).
fn mark(disk: &SimDisk) {
    let mut d = disk.queue();
    let mut clk = SimClock::default();
    let (mut sb, _) = read_super(&mut d, &mut clk).unwrap();
    sb.features |= FEAT_UPGRADING;
    sb.upgrading = 7;
    heal_super(&mut d, &mut clk, &sb).unwrap();
}

#[test]
fn marked_store_is_refused_for_service_and_resumes() {
    let (img, m) = fixture();
    let disk = SimDisk::from_image(&img, sim());
    mark(&disk);
    match service_mount(&disk) {
        Err(ObjError::Store(StoreError::UpgradeNeeded(msg))) => {
            assert!(msg.contains("omap_lsm"), "{msg}")
        }
        r => panic!("marked store mounted: {:?}", r.err()),
    }
    // resume without the opt-in: the marked step continues
    let (r, ev) = upgrade(&disk, Opts::default()).unwrap();
    assert!(r.resumed);
    assert!(matches!(&ev[0], Event::Plan { resume: true, .. }));
    assert!(
        !ev.iter()
            .any(|e| matches!(e, Event::Survey { .. } | Event::Mark { .. }))
    );
    verify(&disk, &m, "resumed");
}

#[test]
fn newer_store_is_refused_untouched() {
    let (img, _) = fixture();
    let disk = SimDisk::from_image(&img, sim());
    let mut d = disk.queue();
    let mut clk = SimClock::default();
    let (mut sb, _) = read_super(&mut d, &mut clk).unwrap();
    sb.features |= 1 << 40;
    heal_super(&mut d, &mut clk, &sb).unwrap();
    let w0 = disk.stats().writes;
    // the exact refusal every path reports (adr 0021 format-change rule): an older build never misreads a newer store
    let want = format!(
        "store format version {} features {:?} is newer than this build (version {}): downgrade not possible after {:?} was enabled",
        store::layout::FORMAT_VERSION,
        store::layout::feature_names(sb.features),
        store::layout::FORMAT_VERSION,
        vec![format!("{:#x}", 1u64 << 40)],
    );
    match upgrade(&disk, opts()) {
        Err(UpgradeError::Obj(ObjError::Store(StoreError::Newer(msg)))) => assert_eq!(msg, want),
        r => panic!("newer store upgraded: {:?}", r.map(|x| x.0)),
    }
    match service_mount(&disk) {
        Err(ObjError::Store(StoreError::Newer(msg))) => assert_eq!(msg, want),
        r => panic!("newer store mounted: {:?}", r.err()),
    }
    // offline check (croit-flashstore-tool fsck) refuses the same way
    match store::fsck::fsck(&mut disk.queue(), &mut SimClock::default(), None) {
        Err(m) => assert_eq!(m, format!("superblock: {want}")),
        Ok(_) => panic!("fsck of a newer store passed"),
    }
    assert_eq!(disk.stats().writes, w0, "refused store untouched");
}

#[test]
fn shortfall_refuses_before_the_mark() {
    let (img, _) = fixture();
    // the same store with more omap in one shard (data-block values) than the system share of its data space, and the
    // rest of the shard filled with object data
    let disk = SimDisk::from_image(&img, sim());
    {
        let mut st = service_mount(&disk).unwrap();
        let c = coll(0);
        for n in 0..40 {
            let mut t = OTxn::new();
            let kv = (0..32)
                .map(|j| {
                    (
                        format!("big_{n:03}.{j:03}").into_bytes(),
                        vec![(n + j) as u8; 9000],
                    )
                })
                .collect();
            put(
                &mut Model::new(),
                &mut t,
                c,
                &obj(0, &format!("big{n}")),
                kv,
            );
            st.commit(&t).unwrap();
        }
        let mut n = 0;
        loop {
            let mut t = OTxn::new();
            for j in 0..8 {
                t.push(TOp::Write {
                    cid: c,
                    oid: obj(0, &format!("fill{n}.{j}")),
                    off: 0,
                    data: Bytes::Owned(vec![(n + j) as u8 | 1; 1 << 20]),
                });
            }
            n += 1;
            if st.commit(&t).is_err() {
                break;
            }
        }
        let _ = st.checkpoint();
    }
    let f0 = features(&disk);
    match upgrade(&disk, opts()) {
        Err(UpgradeError::Space {
            need_bytes,
            avail_bytes,
            ..
        }) => assert!(need_bytes > avail_bytes),
        r => panic!("full store: {:?}", r.map(|x| x.0)),
    }
    assert_eq!(features(&disk), f0, "no mark on refusal");
    service_mount(&disk).expect("store still mounts for service");
}

/// Cut the upgrade at device event `k` with `policy`, resume, verify.
fn crash_case(img: &SimImage, m: &Model, k: u64, policy: CrashPolicy) -> bool {
    let disk = SimDisk::from_image(img, sim());
    disk.arm_crash(k);
    let r = upgrade(&disk, opts());
    if !disk.crashed() {
        assert!(r.is_ok(), "k={k}: {:?}", r.err());
        return false;
    }
    let after = disk.crash_image(policy);
    let disk = SimDisk::from_image(&after, sim());
    let (r, _) = upgrade(&disk, opts()).unwrap_or_else(|e| panic!("k={k} {policy:?}: resume: {e}"));
    assert!(r.features.iter().any(|f| f == "omap_lsm"), "k={k}");
    verify(&disk, m, &format!("k={k} {policy:?}"));
    true
}

/// One slice of the crash matrix: every event `k` with `k % PARTS == part` (of every `UPGRADE_CRASH_STRIDE`-th slot) cut
/// with `policy`. The slices run as separate tests (in parallel).
fn matrix(policy: CrashPolicy, part: u64) {
    const PARTS: u64 = 4;
    let (img, m) = fixture();
    let stride: u64 = std::env::var("UPGRADE_CRASH_STRIDE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(7);
    // the device events of one full run
    let disk = SimDisk::from_image(&img, sim());
    upgrade(&disk, opts()).unwrap();
    let total = disk.events();
    let mut cases = 0;
    let mut k = part * stride;
    while k < total {
        if crash_case(&img, &m, k, policy) {
            cases += 1;
        }
        k += PARTS * stride;
    }
    eprintln!(
        "upgrade crash matrix {policy:?} part {part}/{PARTS}: {total} events, stride {stride}, {cases} crash cases resumed and verified"
    );
    assert!(cases > 0);
}

macro_rules! matrix_tests {
    ($($name:ident: $policy:ident, $part:expr;)*) => {$(
        #[test]
        fn $name() {
            matrix(CrashPolicy::$policy, $part);
        }
    )*};
}

matrix_tests! {
    crash_matrix_drop_all_0: DROP_ALL, 0;
    crash_matrix_drop_all_1: DROP_ALL, 1;
    crash_matrix_drop_all_2: DROP_ALL, 2;
    crash_matrix_drop_all_3: DROP_ALL, 3;
    crash_matrix_persist_all_0: PERSIST_ALL, 0;
    crash_matrix_persist_all_1: PERSIST_ALL, 1;
    crash_matrix_persist_all_2: PERSIST_ALL, 2;
    crash_matrix_persist_all_3: PERSIST_ALL, 3;
    crash_matrix_mixed_0: MIXED, 0;
    crash_matrix_mixed_1: MIXED, 1;
    crash_matrix_mixed_2: MIXED, 2;
    crash_matrix_mixed_3: MIXED, 3;
}
