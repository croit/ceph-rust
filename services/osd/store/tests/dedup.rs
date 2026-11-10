// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! Dedup pipeline store side (adr 0593-dedup-deep-scrub-reformat, doc/spec/dedup-collection.md 5): data version tracking
//! per collection, the bump rules of every op, persistence, generations, the `FEAT_DEDUP` gate and fsck of the new
//! record formats.
#[path = "common/objmodel.rs"]
mod objmodel;

use denc::types::{CollT, Ghobject, Hobject, ShardId, SnapId};
use objmodel::pgc;
use store::dev::{CrashPolicy, SimClock, SimConfig, SimDev, SimDisk, SimImage};
use store::fsck::fsck;
use store::layout::{FEAT_DEDUP, MkfsParams, mkfs, read_super};
use store::obj::onode::fsck_refs;
use store::obj::{DataVersion, OTxn, Store, StoreCfg, TOp};

type St = Store<SimDev, SimClock>;

fn g(oid: &str) -> Ghobject {
    Ghobject::new(
        Hobject::new(oid.as_bytes(), SnapId::NOSNAP, 7, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

fn c1() -> CollT {
    pgc(1, 0)
}

fn sim() -> SimConfig {
    let mut s = SimConfig::new(128 << 20);
    s.seed = 11;
    s
}

fn image() -> SimImage {
    let disk = SimDisk::new(sim());
    let p = MkfsParams {
        shards: 1,
        wal_blocks: 512,
        align_blocks: 1,
        meta_pct: 8,
        node_size: 8192,
        ..Default::default()
    };
    mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
    disk.image()
}

fn open(img: &SimImage) -> (SimDisk, St) {
    let disk = SimDisk::from_image(img, sim());
    let d2 = disk.clone();
    let (st, _) =
        Store::mount(move || d2.queue(), SimClock::default(), StoreCfg::default()).unwrap();
    (disk, st)
}

fn features(img: &SimImage) -> u64 {
    let d = SimDisk::from_image(img, sim());
    read_super(&mut d.queue(), &mut SimClock::default())
        .unwrap()
        .0
        .features
}

fn fsck_ok(img: &SimImage) {
    let d = SimDisk::from_image(img, sim());
    fsck(&mut d.queue(), &mut SimClock::default(), Some(&fsck_refs)).unwrap();
}

fn track(st: &mut St, on: bool) {
    let mut t = OTxn::new();
    t.push(TOp::SetCollDvTrack { cid: c1(), on });
    st.commit(&t).unwrap();
}

fn run(st: &mut St, f: impl FnOnce(&mut OTxn)) {
    let mut t = OTxn::new();
    f(&mut t);
    st.commit(&t).unwrap();
}

fn dv(st: &mut St, o: &str) -> DataVersion {
    st.data_version(&c1(), &g(o)).unwrap().unwrap()
}

/// Close `st` cleanly and return the device image.
fn image_of(mut st: St, disk: &SimDisk) -> SimImage {
    st.sync().unwrap();
    drop(st);
    disk.image()
}

#[test]
fn data_version_bump_rules() {
    let img = image();
    let (disk, mut st) = open(&img);
    run(&mut st, |t| {
        t.mkcoll(c1());
    });
    // no tracking yet: neither the feature bit nor a counter
    let a: &'static [u8] = vec![b'a'; 64 << 10].leak();
    run(&mut st, |t| {
        t.write(c1(), &g("pre"), 0, a);
    });
    assert_eq!(dv(&mut st, "pre").dv, 0);
    assert!(!dv(&mut st, "pre").tracking);
    let img = image_of(st, &disk);
    assert_eq!(
        features(&img) & FEAT_DEDUP,
        0,
        "no tracking, no feature bit"
    );

    let (disk, mut st) = open(&img);
    track(&mut st, true);
    let gen1 = dv(&mut st, "pre").dv_gen;
    assert_eq!(gen1, 1);
    // touch of a new object: created and bumped once
    run(&mut st, |t| {
        t.touch(c1(), &g("obj3"));
    });
    let v3 = dv(&mut st, "obj3").dv;
    assert_eq!(v3, 1);
    run(&mut st, |t| {
        t.write(c1(), &g("obj"), 0, a);
    });
    let mut v = dv(&mut st, "obj").dv;
    assert_eq!(v, 1);
    // attrs and omap leave it unchanged
    run(&mut st, |t| {
        t.setattr(c1(), &g("obj"), b"_", b"x");
        t.omap_set(c1(), &g("obj"), b"k", b"v");
    });
    assert_eq!(dv(&mut st, "obj").dv, v);
    // every data change counts once: touch of an existing object, zero, truncate, write
    let b4: &'static [u8] = vec![b'b'; 4096].leak();
    for step in 0..4 {
        run(&mut st, |t| match step {
            0 => {
                t.touch(c1(), &g("obj"));
            }
            1 => {
                t.zero(c1(), &g("obj"), 0, 4096);
            }
            2 => {
                t.truncate(c1(), &g("obj"), 32 << 10);
            }
            _ => {
                t.write(c1(), &g("obj"), 0, b4);
            }
        });
        let n = dv(&mut st, "obj").dv;
        assert_eq!(n, v + 1, "step {step}");
        v = n;
    }
    // two writes in one txn: two changes
    run(&mut st, |t| {
        t.write(c1(), &g("obj"), 0, b4)
            .write(c1(), &g("obj"), 8192, b4);
    });
    assert_eq!(dv(&mut st, "obj").dv, v + 2);
    v += 2;
    // truncate of a missing object changes nothing
    run(&mut st, |t| {
        t.truncate(c1(), &g("missing"), 0);
    });
    assert!(st.data_version(&c1(), &g("missing")).unwrap().is_none());
    // clone: destination only, a new object with its own counter
    let id_obj = dv(&mut st, "obj").id;
    run(&mut st, |t| {
        t.push(TOp::Clone {
            cid: c1(),
            src: g("obj"),
            dst: g("obj2"),
        });
    });
    assert_eq!(dv(&mut st, "obj").dv, v);
    assert_eq!(dv(&mut st, "obj2").dv, 1);
    assert_ne!(dv(&mut st, "obj2").id, id_obj);
    // clone_range: destination only
    run(&mut st, |t| {
        t.push(TOp::CloneRange {
            cid: c1(),
            src: g("obj"),
            dst: g("obj3"),
            src_off: 0,
            len: 4096,
            dst_off: 0,
        });
    });
    assert_eq!(dv(&mut st, "obj").dv, v);
    assert_eq!(dv(&mut st, "obj3").dv, v3 + 1);
    // rename keeps the counter
    run(&mut st, |t| {
        t.push(TOp::MoveRename {
            cid: c1(),
            oid: g("obj3"),
            dcid: c1(),
            doid: g("obj3r"),
        });
    });
    assert_eq!(dv(&mut st, "obj3r").dv, v3 + 1);
    // recreated object: same counter, new id
    run(&mut st, |t| {
        t.write(c1(), &g("obj4"), 0, a);
    });
    let first = dv(&mut st, "obj4");
    run(&mut st, |t| {
        t.remove(c1(), &g("obj4"));
    });
    run(&mut st, |t| {
        t.write(c1(), &g("obj4"), 0, a);
    });
    let second = dv(&mut st, "obj4");
    assert_eq!(second.dv, first.dv);
    assert_ne!(second.id, first.id);

    // persistence across remount, feature bit durable, records pass fsck
    let before = [
        dv(&mut st, "obj"),
        dv(&mut st, "obj2"),
        dv(&mut st, "obj3r"),
    ];
    let img = image_of(st, &disk);
    assert_ne!(features(&img) & FEAT_DEDUP, 0);
    fsck_ok(&img);
    let (disk, mut st) = open(&img);
    assert_eq!(
        [
            dv(&mut st, "obj"),
            dv(&mut st, "obj2"),
            dv(&mut st, "obj3r")
        ],
        before
    );

    // tracking off: writes leave the counter; switched on again: a new generation
    track(&mut st, false);
    run(&mut st, |t| {
        t.write(c1(), &g("obj"), 0, b4);
    });
    let off = dv(&mut st, "obj");
    assert_eq!((off.dv, off.tracking, off.dv_gen), (v, false, gen1));
    track(&mut st, false);
    assert_eq!(
        dv(&mut st, "obj").dv_gen,
        gen1,
        "repeating the state changes nothing"
    );
    track(&mut st, true);
    let on = dv(&mut st, "obj");
    assert_eq!((on.dv, on.tracking, on.dv_gen), (v, true, gen1 + 1));
    run(&mut st, |t| {
        t.write(c1(), &g("obj"), 0, b4);
    });
    assert_eq!(dv(&mut st, "obj").dv, v + 1);
    let img = image_of(st, &disk);
    fsck_ok(&img);
    let (_disk, mut st) = open(&img);
    assert_eq!(dv(&mut st, "obj").dv_gen, gen1 + 1);
}

fn lz4() -> Option<store::compress::CompSpec> {
    Some(store::compress::CompSpec {
        alg: store::compress::Alg::Lz4,
        ratio_permille: 875,
        min_bytes: 8192,
        chunk_blks: 16,
    })
}

/// Rewrite `[off, off + data.len())` of `o` as the deep-scrub engines do: expect the data state read before.
fn reformat(
    st: &mut St,
    o: &str,
    off: u64,
    data: &[u8],
    expect: DataVersion,
    comp: Option<store::compress::CompSpec>,
    max_frags: u32,
) -> bool {
    let mut t = OTxn::new();
    t.comp = comp;
    t.push(TOp::Reformat {
        cid: c1(),
        oid: g(o),
        off,
        data: store::obj::txn::Bytes::Borrowed(data),
        expect,
        max_frags,
    });
    let r = st.try_local(&t, 1 << 40).unwrap();
    st.sync().unwrap();
    r
}

fn span(st: &mut St, o: &str, off: u64, len: u64) -> store::obj::SpanStats {
    st.span_stats(&c1(), &g(o), off, len).unwrap().unwrap()
}

fn tracked_store() -> (SimDisk, St) {
    let img = image();
    let (disk, mut st) = open(&img);
    run(&mut st, |t| {
        t.mkcoll(c1());
    });
    track(&mut st, true);
    (disk, st)
}

#[test]
fn reformat_recompress_keeps_data_and_version() {
    let (disk, mut st) = tracked_store();
    let d: &'static [u8] = (0..512u32 << 10)
        .map(|i| b"abcdefgh"[(i / 512 % 8) as usize])
        .collect::<Vec<u8>>()
        .leak();
    run(&mut st, |t| {
        t.write(c1(), &g("o"), 0, d);
    });
    let before = span(&mut st, "o", 0, d.len() as u64);
    assert_eq!(
        (
            before.allocated,
            before.allocated_compressed,
            before.extents > 0
        ),
        (512 << 10, 0, true)
    );
    let v = dv(&mut st, "o");
    let est = store::compress::estimate_blocks(
        &mut store::compress::SoftCodec::default(),
        lz4().unwrap(),
        0,
        d,
    );
    assert!(reformat(&mut st, "o", 0, d, v, lz4(), 0));
    let after = span(&mut st, "o", 0, d.len() as u64);
    assert_eq!(
        est,
        (after.allocated + after.allocated_compressed) / 4096,
        "the estimate is what staging stores"
    );
    assert_eq!(after.allocated, 0, "every chunk compressed");
    assert!(after.allocated_compressed > 0 && after.allocated_compressed < 512 << 10);
    assert_eq!(after.stored_compressed, 512 << 10);
    assert_eq!(dv(&mut st, "o"), v, "a reformat is not a data change");
    assert_eq!(st.read(&c1(), &g("o"), 0, d.len() as u64).unwrap(), d);
    let img = image_of(st, &disk);
    fsck_ok(&img);
    let (_disk, mut st) = open(&img);
    assert_eq!(st.read(&c1(), &g("o"), 0, d.len() as u64).unwrap(), d);
}

#[test]
fn reformat_refuses_changed_objects() {
    let (_disk, mut st) = tracked_store();
    let a: &'static [u8] = vec![b'a'; 64 << 10].leak();
    let b: &'static [u8] = vec![b'b'; 4096].leak();
    run(&mut st, |t| {
        t.write(c1(), &g("o"), 0, a);
    });
    let v = dv(&mut st, "o");
    // a client write after the read: the rewrite of the old bytes must not apply
    run(&mut st, |t| {
        t.write(c1(), &g("o"), 4096, b);
    });
    assert!(!reformat(&mut st, "o", 0, a, v, lz4(), 0));
    let got = st.read(&c1(), &g("o"), 0, 8192).unwrap();
    assert_eq!(&got[4096..], b);
    // recreated object: same counter, other id
    let v = dv(&mut st, "o");
    run(&mut st, |t| {
        t.remove(c1(), &g("o"));
    });
    run(&mut st, |t| {
        t.write(c1(), &g("o"), 0, a);
    });
    let v2 = dv(&mut st, "o");
    let stale = DataVersion { dv: v2.dv, ..v };
    assert!(!reformat(&mut st, "o", 0, a, stale, lz4(), 0));
    // past the end, unaligned, empty, missing object
    assert!(!reformat(&mut st, "o", 32 << 10, a, v2, lz4(), 0));
    assert!(!reformat(&mut st, "o", 100, &a[..4096], v2, lz4(), 0));
    assert!(!reformat(&mut st, "o", 0, &[], v2, lz4(), 0));
    assert!(!reformat(&mut st, "missing", 0, a, v2, lz4(), 0));
    // tracking off: no version guard, no rewrite
    track(&mut st, false);
    let v3 = dv(&mut st, "o");
    assert!(!reformat(&mut st, "o", 0, a, v3, lz4(), 0));
    track(&mut st, true);
    let v4 = dv(&mut st, "o");
    assert!(reformat(&mut st, "o", 0, a, v4, lz4(), 0));
    assert_eq!(st.read(&c1(), &g("o"), 0, a.len() as u64).unwrap(), a);
}

#[test]
fn reformat_defragment_only_when_better() {
    let (disk, mut st) = tracked_store();
    let a: &'static [u8] = vec![b'a'; 256 << 10].leak();
    let c: &'static [u8] = vec![b'c'; 4096].leak();
    run(&mut st, |t| {
        t.write(c1(), &g("o"), 0, a);
    });
    // contiguous already: a rewrite is not less fragmented
    let s0 = span(&mut st, "o", 0, a.len() as u64);
    assert_eq!(s0.frags, 1);
    let v = dv(&mut st, "o");
    assert!(!reformat(&mut st, "o", 0, a, v, None, s0.frags as u32));
    // every other block overwritten (copy on write): scattered
    for blk in (0..64).step_by(2) {
        run(&mut st, |t| {
            t.write(c1(), &g("o"), blk * 4096, c);
        });
    }
    let want: Vec<u8> = (0..64)
        .flat_map(|blk| {
            if blk % 2 == 0 {
                c.to_vec()
            } else {
                a[..4096].to_vec()
            }
        })
        .collect();
    let s1 = span(&mut st, "o", 0, a.len() as u64);
    assert!(s1.frags > 1, "{s1:?}");
    let v = dv(&mut st, "o");
    assert!(reformat(&mut st, "o", 0, &want, v, None, s1.frags as u32));
    let s2 = span(&mut st, "o", 0, a.len() as u64);
    assert!(s2.frags < s1.frags, "{s1:?} -> {s2:?}");
    assert_eq!(dv(&mut st, "o"), v);
    assert_eq!(st.read(&c1(), &g("o"), 0, a.len() as u64).unwrap(), want);
    let img = image_of(st, &disk);
    fsck_ok(&img);
}

#[test]
fn span_stats_sees_shared_extents() {
    let (_disk, mut st) = tracked_store();
    let a: &'static [u8] = vec![b'a'; 64 << 10].leak();
    run(&mut st, |t| {
        t.write(c1(), &g("o"), 0, a);
    });
    assert_eq!(span(&mut st, "o", 0, 64 << 10).allocated_shared, 0);
    run(&mut st, |t| {
        t.push(TOp::Clone {
            cid: c1(),
            src: g("o"),
            dst: g("c"),
        });
    });
    let s = span(&mut st, "o", 0, 64 << 10);
    assert_eq!(s.allocated_shared, 64 << 10, "{s:?}");
    // a partial range counts only its blocks
    let p = span(&mut st, "o", 8192, 8192);
    assert_eq!((p.stored, p.allocated), (8192, 8192));
}

#[test]
fn dedup_records_persist_and_pass_fsck() {
    use store::obj::dedup::{DigestAlg, RecordValue, key, shard_range};
    let (disk, mut st) = tracked_store();
    let val = |n: u64| RecordValue {
        alg: DigestAlg::Md5,
        id: n,
        dv_gen: 1,
        dv: n,
        oid: g("o"),
    };
    let recs: Vec<(Vec<u8>, Vec<u8>)> = (0..20u64)
        .map(|i| (key(1, &[i as u8; 16], 1000 + i, i as u32), val(i).encode()))
        .collect();
    let mut t = OTxn::new();
    t.push(TOp::DedupKv {
        shard: 0,
        puts: recs.clone(),
        dels: vec![recs[3].0.clone()],
        del_range: None,
    });
    assert!(st.try_local(&t, 7).unwrap());
    // other keys are refused
    let mut t = OTxn::new();
    t.push(TOp::DedupKv {
        shard: 0,
        puts: vec![(b"Nbogus".to_vec(), vec![])],
        dels: vec![],
        del_range: None,
    });
    assert!(st.try_local(&t, 8).is_err());
    let img = image_of(st, &disk);
    fsck_ok(&img);
    let (disk, mut st) = open(&img);
    let (lo, hi) = shard_range(1, 0, 0, 16);
    let got = st.dedup_scan(&lo, &hi, 100, false).unwrap();
    assert_eq!(got.len(), 19, "the deleted one is gone");
    assert!(got.windows(2).all(|w| w[0].0 < w[1].0));
    assert_eq!(RecordValue::decode(&got[0].1).unwrap(), val(0));
    // range delete of the pool
    let mut t = OTxn::new();
    t.push(TOp::DedupKv {
        shard: 0,
        puts: vec![],
        dels: vec![],
        del_range: Some((lo.clone(), hi.clone())),
    });
    st.commit(&t).unwrap();
    assert!(st.dedup_scan(&lo, &hi, 100, false).unwrap().is_empty());
    fsck_ok(&image_of(st, &disk));
}

// ------------------------------------------------------------------------------------- crash matrix (format change)

/// Script: tracking on, then 24 full overwrites of 4 objects (content byte = write index), a dedup record with every
/// third write in the same txn.
fn crash_script() -> Vec<OTxn<'static>> {
    let mut sc = Vec::new();
    let mut t = OTxn::new();
    t.push(TOp::SetCollDvTrack {
        cid: c1(),
        on: true,
    });
    sc.push(t);
    for i in 0..24u8 {
        let mut t = OTxn::new();
        let d: &'static [u8] = vec![i; 8192].leak();
        t.write(c1(), &g(&format!("o{}", i % 4)), 0, d);
        if i % 3 == 0 {
            t.push(TOp::DedupKv {
                shard: 0,
                puts: vec![(
                    store::obj::dedup::key(1, &[i; 16], i as u64, i as u32),
                    store::obj::dedup::RecordValue {
                        alg: store::obj::dedup::DigestAlg::Md5,
                        id: 0,
                        dv_gen: 1,
                        dv: 0,
                        oid: g("x"),
                    }
                    .encode(),
                )],
                dels: vec![],
                del_range: None,
            });
        }
        sc.push(t);
    }
    sc
}

/// Run the script on `img`, crash at IO event `k` (if any).
fn crash_run(img: &SimImage, seed: u64, k: Option<u64>, sc: &[OTxn<'static>]) -> SimDisk {
    let mut s2 = sim();
    s2.seed = seed;
    let disk = SimDisk::from_image(img, s2);
    let d2 = disk.clone();
    let (mut st, _) =
        Store::mount(move || d2.queue(), SimClock::default(), StoreCfg::default()).unwrap();
    if let Some(k) = k {
        disk.arm_crash(disk.events() + k);
    }
    for (i, t) in sc.iter().enumerate() {
        match st.queue(t, i as u64 + 1) {
            Ok(_) => {}
            Err(_) if disk.crashed() => break,
            Err(e) => panic!("queue: {e:?}"),
        }
        let mut a = Vec::new();
        if st.poll(&mut a).is_err() {
            break;
        }
        if i % 5 == 0 {
            st.shards[0].sh.request_checkpoint();
        }
    }
    if !disk.crashed() {
        let mut a = Vec::new();
        for _ in 0..200 {
            if st.poll(&mut a).is_err() {
                break;
            }
            st.idle();
        }
    }
    disk
}

/// Recovered state invariants: fsck, feature bit before any record that needs it, data version atomic with the data,
/// records only with their write.
fn crash_check(img: &SimImage) -> Result<(), String> {
    let d = SimDisk::from_image(img, sim());
    fsck(&mut d.queue(), &mut SimClock::default(), Some(&fsck_refs))?;
    let feat = features(img) & FEAT_DEDUP != 0;
    let d2 = d.clone();
    let (mut st, _) = Store::mount(move || d2.queue(), SimClock::default(), StoreCfg::default())
        .map_err(|e| format!("mount: {e:?}"))?;
    let (lo, hi) = store::obj::dedup::shard_range(1, 0, 0, 16);
    let recs = if feat {
        st.dedup_scan(&lo, &hi, 100, false)
            .map_err(|e| format!("{e:?}"))?
    } else {
        Vec::new()
    };
    let mut last = [None::<u8>; 4];
    for o in 0..4u8 {
        let Some(v) = st
            .data_version(&c1(), &g(&format!("o{o}")))
            .map_err(|e| format!("{e:?}"))?
        else {
            continue;
        };
        let data = st
            .read(&c1(), &g(&format!("o{o}")), 0, 8192)
            .map_err(|e| format!("{e:?}"))?;
        let i = data[0];
        if data.iter().any(|b| *b != i) || i % 4 != o {
            return Err(format!("o{o}: torn or foreign content {i}"));
        }
        if !feat && v.dv != 0 {
            return Err(format!("o{o}: data version {} without FEAT_DEDUP", v.dv));
        }
        // tracking was on before the first write: the counter is the number of writes the content shows
        if v.tracking && v.dv != (i / 4) as u64 + 1 {
            return Err(format!(
                "o{o}: content of write {i} with data version {}",
                v.dv
            ));
        }
        last[o as usize] = Some(i);
    }
    for (k, _, _) in recs {
        let i = store::obj::dedup::parse_key(&k).unwrap().digest[0];
        if last[(i % 4) as usize].is_none_or(|l| l < i) {
            return Err(format!("record of write {i} without its write"));
        }
    }
    Ok(())
}

#[test]
fn crash_matrix_tracking_and_records() {
    let img0 = image();
    let (d, mut st) = open(&img0);
    run(&mut st, |t| {
        t.mkcoll(c1());
    });
    st.checkpoint().unwrap();
    drop(st);
    let img = d.image();
    let sc = crash_script();
    let events = crash_run(&img, 1, None, &sc).events();
    assert!(crash_check(&crash_run(&img, 1, None, &sc).image()).is_ok());
    let mut n = 0;
    for k in 0..events {
        for (pi, pol) in [
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
            CrashPolicy::MIXED,
        ]
        .into_iter()
        .enumerate()
        {
            let disk = crash_run(&img, k * 7 + pi as u64 + 1, Some(k), &sc);
            disk.crash_now();
            if let Err(e) = crash_check(&disk.crash_image(pol)) {
                panic!("crash at event {k} policy #{pi}: {e}");
            }
            n += 1;
        }
    }
    eprintln!("dedup crash matrix: {events} events, {n} scenarios");
    assert!(n > 30);
}

/// A deep-scrub rewrite never blocks the PG core (review M6): on a cold page cache it is refused (`Ok(false)`, the
/// page loads it started serve the next try), then applies once the pages are in.
#[test]
fn reformat_on_a_cold_cache_never_waits() {
    let (disk, mut st) = tracked_store();
    let a: &'static [u8] = vec![b'a'; 16 << 10].leak();
    run(&mut st, |t| {
        t.write(c1(), &g("target"), 0, a);
    });
    // small inline objects: a tree many times the reopened cache
    let small: &'static [u8] = vec![b's'; 400].leak();
    let objs: Vec<String> = (0..10_000).map(|i| format!("o{i:05}")).collect();
    for chunk in objs.chunks(100) {
        run(&mut st, |t| {
            for o in chunk {
                t.write(c1(), &g(o), 0, small);
            }
        });
    }
    let v = dv(&mut st, "target");
    let img = image_of(st, &disk);
    // a cache far smaller than the tree: the object's pages are not resident after the mount
    let disk = SimDisk::from_image(&img, sim());
    let d2 = disk.clone();
    let mut cfg = StoreCfg::default();
    cfg.shard.cache_pages = 32;
    let (mut st, _) = Store::mount(move || d2.queue(), SimClock::default(), cfg).unwrap();
    let mut t = OTxn::new();
    t.comp = lz4();
    t.push(TOp::Reformat {
        cid: c1(),
        oid: g("target"),
        off: 0,
        data: store::obj::txn::Bytes::Borrowed(a),
        expect: v,
        max_frags: 0,
    });
    assert!(
        !st.try_local(&t, 1 << 40).unwrap(),
        "a page miss must not be waited for"
    );
    let mut tries = 1;
    while !st.try_local(&t, 1 << 40).unwrap() {
        st.idle();
        st.poll(&mut Vec::new()).unwrap();
        tries += 1;
        assert!(tries < 10_000, "the started loads never completed");
    }
    st.sync().unwrap();
    assert_eq!(st.read(&c1(), &g("target"), 0, a.len() as u64).unwrap(), a);
}
