// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Idle recompaction of cut compressed chunks and the extent census (adr 0533): aged compressed objects
//! (4 KiB overwrites cut their chunks into windows, adr 0059 am. 4) are rewritten while the store idles; data, block
//! ownership, compression counters and fsck stay exact; a chunk a clone shares is never rewritten; a power cut at any
//! device event of the idle phase recovers to the same logical data.
//!
//! Matrix size: `RC_CRASH_STRIDE` (default 3); `crash_matrix_recompaction_every_event` (ignored) runs stride 1.

use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use store::compress::{Alg, CompSpec};
use store::dev::{BlockDev, Clock, CrashPolicy, SimClock, SimConfig, SimDev, SimDisk, SimImage};
use store::fsck::fsck;
use store::layout::{MkfsParams, mkfs};
use store::obj::onode::fsck_refs;
use store::obj::{OTxn, Store, StoreCfg, TOp};
use store::rng::Rng;

type St = Store<SimDev, SimClock>;
const BLK: usize = 4096;
/// 4 chunks of 64 KiB per object.
const OBJ: usize = 256 << 10;

fn coll() -> CollT {
    CollT::Pg(SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId::NO_SHARD,
    })
}

fn obj(i: usize) -> Ghobject {
    Ghobject::new(
        Hobject::new(
            format!("rbd_data.{i}").as_bytes(),
            SnapId::NOSNAP,
            i as u32,
            1,
            b"",
        ),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

/// Runs of repeated bytes: compresses well.
fn cdata(n: usize, seed: u64) -> Vec<u8> {
    let mut r = Rng::new(seed);
    let mut v = Vec::with_capacity(n);
    while v.len() < n {
        let run = r.range(8, 300) as usize;
        let b = r.below(256) as u8;
        v.resize((v.len() + run).min(n), b);
    }
    v
}

fn zstd() -> Option<CompSpec> {
    Some(CompSpec {
        alg: Alg::Zstd,
        ratio_permille: 875,
        min_bytes: 8192,
        chunk_blks: 16,
    })
}

fn image(cap_mib: u64, seed: u64) -> (SimConfig, SimImage) {
    let mut sim = SimConfig::new(cap_mib << 20);
    sim.seed = seed;
    let disk = SimDisk::new(sim.clone());
    mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards: 1,
            wal_blocks: 1024,
            align_blocks: 1,
            meta_pct: 8,
            ..Default::default()
        },
    )
    .unwrap();
    (sim, disk.image())
}

fn mount(img: &SimImage, sim: &SimConfig, cfg: &StoreCfg) -> (SimDisk, St) {
    let disk = SimDisk::from_image(img, sim.clone());
    let d2 = disk.clone();
    let (st, _) = Store::mount(move || d2.queue(), SimClock::default(), cfg.clone()).unwrap();
    (disk, st)
}

fn commit(st: &mut St, t: &OTxn) {
    st.commit(t).unwrap_or_else(|e| panic!("commit: {e:?}"));
}

/// `n` objects written compressed, then `per_chunk` single-block overwrites (compressible, stored raw: below the
/// minimum blob) in every chunk: each chunk is cut into windows. Returns the logical content.
fn age(st: &mut St, n: usize, per_chunk: usize, seed: u64) -> Vec<Vec<u8>> {
    let c = coll();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(st, &t);
    let mut model = Vec::new();
    for i in 0..n {
        let d = cdata(OBJ, seed + i as u64);
        let mut t = OTxn::new();
        t.comp = zstd();
        t.write(c, &obj(i), 0, &d);
        commit(st, &t);
        model.push(d);
    }
    let mut r = Rng::new(seed ^ 0x77);
    for (i, m) in model.iter_mut().enumerate() {
        for chunk in 0..OBJ / (64 << 10) {
            for _ in 0..per_chunk {
                let b = chunk * 16 + r.below(16) as usize;
                let d = cdata(BLK, r.below(1 << 30));
                m[b * BLK..(b + 1) * BLK].copy_from_slice(&d);
                let mut t = OTxn::new();
                t.comp = zstd();
                t.write(c, &obj(i), (b * BLK) as u64, &d);
                commit(st, &t);
            }
        }
    }
    model
}

/// Let the store idle for `ns` of simulated time (device completions in between).
fn idle_for(st: &mut St, ns: u64) {
    let end = st.clk.t + ns;
    let mut a = Vec::new();
    while st.clk.t < end {
        st.poll(&mut a).unwrap();
        if st
            .shards
            .iter_mut()
            .any(|s| s.sh.dev().next_deadline().is_some())
        {
            st.idle();
        } else {
            st.clk.t += 100_000;
        }
    }
}

fn verify(st: &mut St, model: &[Vec<u8>]) {
    for (i, m) in model.iter().enumerate() {
        assert_eq!(
            &st.read(&coll(), &obj(i), 0, OBJ as u64).unwrap(),
            m,
            "object {i}"
        );
    }
    let rep = st.check(true).unwrap();
    assert!(rep.errors.is_empty(), "check: {:?}", rep.errors);
}

fn used(st: &St) -> u64 {
    st.shards[0].sh.statfs().data_used
}

#[test]
fn idle_recompaction_reclaims_cut_chunks_and_keeps_data() {
    let (sim, img) = image(64, 1);
    let (_disk, mut st) = mount(&img, &sim, &StoreCfg::default());
    let model = age(&mut st, 4, 3, 10);
    st.checkpoint().unwrap();
    let before = used(&st);
    let cs0 = st.coll_stats(&coll()).unwrap().unwrap();
    assert!(
        cs0.comp_orig < (4 * OBJ) as u64,
        "the overwrites cut the chunks"
    );
    idle_for(&mut st, 3_000_000_000);
    let rc = st.rc_stats();
    assert_eq!(rc.chunks, 16, "every cut chunk rewritten: {rc:?}");
    assert!(rc.freed_blocks > rc.new_blocks, "{rc:?}");
    let (cen, seq) = st.census();
    assert!(seq >= 1);
    assert_eq!(cen.objects, 4);
    assert_eq!(cen.cut_chunks, 16, "census before the rewrites: {cen:?}");
    st.checkpoint().unwrap();
    let after = used(&st);
    assert_eq!(
        before - after,
        rc.freed_blocks - rc.new_blocks,
        "the freed blocks come back after a checkpoint"
    );
    let cs1 = st.coll_stats(&coll()).unwrap().unwrap();
    assert_eq!(
        cs1.comp_orig,
        (4 * OBJ) as u64,
        "all logical bytes compressed again"
    );
    assert!(cs1.comp < cs0.comp + 3 * 16 * BLK as u64);
    verify(&mut st, &model);
    // nothing cut since: no further sweep rewrites anything; a census sweep sees whole chunks only
    st.request_census();
    idle_for(&mut st, 3_000_000_000);
    let (cen, seq2) = st.census();
    assert!(seq2 > seq);
    assert_eq!(
        (cen.windows, cen.cut_chunks, cen.plain_blocks),
        (0, 0, 0),
        "{cen:?}"
    );
    assert_eq!((cen.objects, cen.records, cen.chunks), (4, 16, 16));
    assert_eq!(st.rc_stats().chunks, 16);
    // remount: same data, fsck clean
    drop(st);
    let img2 = _disk.image();
    let disk = SimDisk::from_image(&img2, sim.clone());
    fsck(
        &mut disk.queue(),
        &mut SimClock::default(),
        Some(&fsck_refs),
    )
    .unwrap();
    let (_d, mut st) = mount(&img2, &sim, &StoreCfg::default());
    verify(&mut st, &model);
}

#[test]
fn census_counts_records_chunks_and_windows() {
    let (sim, img) = image(64, 3);
    let (_disk, mut st) = mount(&img, &sim, &StoreCfg::default());
    let c = coll();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut st, &t);
    // 2 chunks of half random, half zero blocks (9 physical blocks each); block 3 of chunk 0 overwritten with the same
    // kind of block: 2 windows + 1 raw record + 1 whole chunk; the cut chunk holds 9 + 1 blocks, rewritten it takes 9
    let half = |seed: u64| {
        let mut b = vec![0u8; BLK];
        Rng::new(seed).fill(&mut b[..BLK / 2]);
        b
    };
    let mut d: Vec<u8> = (0..32).flat_map(|i| half(100 + i)).collect();
    let mut t = OTxn::new();
    t.comp = zstd();
    t.write(c, &obj(0), 0, &d);
    commit(&mut st, &t);
    let x = half(7);
    d[3 * BLK..4 * BLK].copy_from_slice(&x);
    let mut t = OTxn::new();
    t.write(c, &obj(0), 3 * BLK as u64, &x);
    commit(&mut st, &t);
    idle_for(&mut st, 3_000_000_000);
    let (cen, _) = st.census();
    assert_eq!(
        (
            cen.objects,
            cen.records,
            cen.plain_blocks,
            cen.chunks,
            cen.windows
        ),
        (1, 4, 1, 2, 2),
        "{cen:?}"
    );
    assert_eq!(
        (cen.cut_chunks, cen.cut_live, cen.cut_span, cen.comp_logical),
        (1, 15, 16, 31)
    );
    // the cut chunk is rewritten whole (9 blocks instead of 9 + 1)
    assert_eq!(st.rc_stats().chunks, 1, "{:?}", st.rc_stats());
    assert_eq!(&st.read(&c, &obj(0), 0, 128 << 10).unwrap(), &d);
    assert_eq!(
        cen.unc_objects, 0,
        "uncompressed collections are walked on request only"
    );
    // an uncompressed collection: 64 KiB written as 16 single blocks (16 records), counted after a census request
    let u = CollT::Pg(SpgT {
        pgid: PgT::new(1, 1),
        shard: ShardId::NO_SHARD,
    });
    let mut t = OTxn::new();
    t.mkcoll(u);
    commit(&mut st, &t);
    for b in (0..16).rev() {
        let mut t = OTxn::new();
        t.write(u, &obj(1), b * BLK as u64, &x);
        commit(&mut st, &t);
    }
    st.request_census();
    idle_for(&mut st, 3_000_000_000);
    let (cen, _) = st.census();
    assert_eq!(
        (cen.unc_objects, cen.unc_records, cen.unc_blocks),
        (1, 16, 16),
        "{cen:?}"
    );
    assert_eq!(
        (cen.objects, cen.records, cen.windows),
        (1, 2, 0),
        "{cen:?}"
    );
}

/// Put raw tree records (damage the store layer above would never write).
fn put_raw(st: &mut St, recs: Vec<(Vec<u8>, Vec<u8>)>) {
    let mut t: store::shard::Txn<Vec<u8>> = store::shard::Txn::new(7);
    for (k, v) in recs {
        t.put(&k, &v);
    }
    let lsn = loop {
        match st.shards[0].sh.submit(t) {
            Ok(lsn) => break lsn,
            Err((store::StoreError::Busy | store::StoreError::WalFull, back)) => {
                assert!(poll(&mut st.shards[0].sh, &mut st.clk), "no ack");
                t = back;
            }
            Err((e, _)) => panic!("submit: {e:?}"),
        }
    };
    for _ in 0..100_000 {
        if poll(&mut st.shards[0].sh, &mut st.clk) {
            assert!(st.shards[0].sh.durable_lsn() >= lsn);
            return;
        }
    }
    panic!("raw records never acked");
}

/// Poll one shard, advancing the simulated clock to its device deadline.
fn poll(s: &mut store::shard::Shard<SimDev>, clk: &mut SimClock) -> bool {
    let mut ev = Vec::new();
    s.poll(clk.t, &mut ev);
    let mut acked = false;
    for e in ev {
        match e {
            store::shard::Event::Acked(_) => acked = true,
            store::shard::Event::Failed(f) => panic!("shard failed: {f:?}"),
            _ => {}
        }
    }
    let h = s.dev().next_deadline();
    clk.idle(h);
    acked
}

/// A window record whose `skip` reaches back before its own label (crc-valid, cross-checked nowhere) is skipped by the
/// idle recompaction, never subtracted into a wrap: the chunk start would lie below block 0.
#[test]
fn window_starting_before_block_zero_is_skipped() {
    let (sim, img) = image(64, 5);
    let (_disk, mut st) = mount(&img, &sim, &StoreCfg::default());
    let c = coll();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut st, &t);
    let mut t = OTxn::new();
    t.comp = zstd();
    let data = cdata(OBJ, 50);
    t.write(c, &obj(0), 0, &data);
    commit(&mut st, &t);
    // the whole-chunk record of the first 16-block chunk, re-encoded as a window at logical block 4 with `skip` 8
    let kv = st.shards[0].sh.dump_blocking(&mut st.clk).unwrap();
    let (k, v) = kv
        .iter()
        .find(|(k, _)| k[0] == store::obj::keys::T_EXT && k[10..14] == [0, 0, 0, 0])
        .expect("chunk 0 extent record");
    let e = store::obj::onode::ExtRaw::new(v).expect("extent record decodes");
    let m = e.comp().expect("compressed chunk");
    assert_eq!((m.skip, m.win), (0, m.raw_blks));
    let id = u64::from_be_bytes(k[1..9].try_into().unwrap());
    let bogus = e.window_encode(
        store::obj::onode::CompMeta {
            skip: 8,
            win: 2,
            ..m
        },
        false,
    );
    put_raw(&mut st, vec![(store::obj::keys::ext_key(id, 4), bogus)]);
    st.request_census();
    idle_for(&mut st, 3_000_000_000);
    let rc = st.rc_stats();
    assert_eq!(rc.chunks, 0, "the bogus window was staged {rc:?}");
    assert_eq!(rc.skipped, 1, "the cut chunk is skipped {rc:?}");
    let (cen, seq) = st.census();
    assert!(seq >= 1 && cen.cut_chunks == 1, "{cen:?}");
}

#[test]
fn clone_shared_chunk_is_not_rewritten_until_the_clone_is_gone() {
    let (sim, img) = image(64, 4);
    let (_disk, mut st) = mount(&img, &sim, &StoreCfg::default());
    let mut model = age(&mut st, 1, 3, 30);
    let c = coll();
    let mut t = OTxn::new();
    t.push(TOp::Clone {
        cid: c,
        src: obj(0),
        dst: obj(9),
    });
    commit(&mut st, &t);
    idle_for(&mut st, 3_000_000_000);
    let rc = st.rc_stats();
    assert_eq!(
        rc.chunks, 0,
        "shared with the clone: nothing to free {rc:?}"
    );
    assert!(rc.no_gain >= 4, "{rc:?}");
    assert_eq!(&st.read(&c, &obj(9), 0, OBJ as u64).unwrap(), &model[0]);
    verify(&mut st, &model);
    // the clone goes: the next sweep (census request) rewrites the chunks
    let mut t = OTxn::new();
    t.remove(c, &obj(9));
    commit(&mut st, &t);
    st.request_census();
    idle_for(&mut st, 3_000_000_000);
    assert_eq!(st.rc_stats().chunks, 4, "{:?}", st.rc_stats());
    verify(&mut st, &model);
    // a client overwrite after the rewrite cuts a chunk again and triggers the next sweep by itself
    let d = cdata(BLK, 77);
    model[0][5 * BLK..6 * BLK].copy_from_slice(&d);
    let mut t = OTxn::new();
    t.write(c, &obj(0), 5 * BLK as u64, &d);
    commit(&mut st, &t);
    idle_for(&mut st, 3_000_000_000);
    assert_eq!(st.rc_stats().chunks, 5, "{:?}", st.rc_stats());
    verify(&mut st, &model);
}

/// Power cut at device event `k` of the idle phase (`None` = no cut): the recovered store holds the aged logical data,
/// passes fsck and the object check, and finishes the recompaction after recovery.
fn crash_at(
    img: &SimImage,
    sim: &SimConfig,
    model: &[Vec<u8>],
    k: Option<u64>,
    pol: CrashPolicy,
) -> u64 {
    let cfg = StoreCfg::default();
    let (disk, mut st) = mount(img, sim, &cfg);
    st.set_pool_comp(1, zstd());
    let e0 = disk.events();
    if let Some(k) = k {
        disk.arm_crash(e0 + k);
    }
    let end = st.clk.t + 3_000_000_000;
    let mut a = Vec::new();
    while st.clk.t < end && !disk.crashed() {
        if st.poll(&mut a).is_err() {
            break;
        }
        if st.shards[0].sh.dev().next_deadline().is_some() {
            st.idle();
        } else {
            st.clk.t += 100_000;
        }
    }
    let events = disk.events() - e0;
    if k.is_none() {
        assert!(st.rc_stats().chunks > 0, "the idle phase recompacts");
        return events;
    }
    disk.crash_now();
    let cimg = disk.crash_image(pol);
    drop(st);
    let d = SimDisk::from_image(&cimg, sim.clone());
    fsck(&mut d.queue(), &mut SimClock::default(), Some(&fsck_refs))
        .unwrap_or_else(|e| panic!("k={k:?}: fsck of the crash image: {e}"));
    let (disk2, mut st) = mount(&cimg, sim, &cfg);
    st.set_pool_comp(1, zstd());
    verify(&mut st, model);
    idle_for(&mut st, 3_000_000_000);
    verify(&mut st, model);
    st.checkpoint().unwrap();
    drop(st);
    fsck(
        &mut disk2.queue(),
        &mut SimClock::default(),
        Some(&fsck_refs),
    )
    .unwrap_or_else(|e| panic!("k={k:?}: fsck after recovery: {e}"));
    events
}

fn crash_matrix(stride: u64) -> u64 {
    let (sim, img) = image(64, 5);
    let (disk, mut st) = mount(&img, &sim, &StoreCfg::default());
    let mut model = age(&mut st, 2, 3, 40);
    // and one object of single-block plain writes (ranges the pool's compression packs while idle)
    let d = cdata(OBJ, 41);
    for b in 0..OBJ / BLK {
        let mut t = OTxn::new();
        t.write(
            coll(),
            &obj(2),
            (b * BLK) as u64,
            &d[b * BLK..(b + 1) * BLK],
        );
        commit(&mut st, &t);
    }
    model.push(d);
    st.checkpoint().unwrap();
    drop(st);
    let aged = disk.image();
    let events = crash_at(&aged, &sim, &model, None, CrashPolicy::MIXED);
    eprintln!("recompaction crash matrix: idle phase = {events} device events, stride {stride}");
    let mut n = 0;
    let mut k = 0;
    while k < events {
        for pol in [
            CrashPolicy::MIXED,
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
        ] {
            crash_at(&aged, &sim, &model, Some(k), pol);
            n += 1;
        }
        k += stride;
    }
    n
}

#[test]
fn crash_matrix_recompaction() {
    let stride = std::env::var("RC_CRASH_STRIDE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    assert!(crash_matrix(stride) > 30);
}

#[test]
#[ignore = "soak: every device event of the idle phase"]
fn crash_matrix_recompaction_every_event() {
    crash_matrix(1);
}

/// A pool that compresses (`set_pool_comp`): aligned ranges made of small plain records (4 KiB writes are stored raw)
/// are compressed while idle; one written as a single plain record, a range with a hole and an incompressible range stay.
#[test]
fn plain_ranges_of_a_compressing_pool_are_compressed_while_idle() {
    let (sim, img) = image(64, 6);
    let (_disk, mut st) = mount(&img, &sim, &StoreCfg::default());
    let c = coll();
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut st, &t);
    // chunk 0, 1: compressible, 16 single-block writes each; chunk 2: one 64 KiB raw write; chunk 3: 15 blocks (hole);
    // chunk 4: random 4 KiB writes
    let mut d = cdata(5 * 16 * BLK, 60);
    Rng::new(61).fill(&mut d[4 * 16 * BLK..]);
    let put = |st: &mut St, b: usize, n: usize| {
        let mut t = OTxn::new();
        t.write(c, &obj(0), (b * BLK) as u64, &d[b * BLK..(b + n) * BLK]);
        commit(st, &t);
    };
    for b in 0..32 {
        put(&mut st, b, 1);
    }
    put(&mut st, 32, 16);
    for b in 48..63 {
        put(&mut st, b, 1);
    }
    for b in 64..80 {
        put(&mut st, b, 1);
    }
    d[63 * BLK..64 * BLK].fill(0);
    st.checkpoint().unwrap();
    let before = used(&st);
    idle_for(&mut st, 3_000_000_000);
    assert_eq!(
        st.rc_stats().chunks,
        0,
        "no pool compression known: nothing"
    );
    st.set_pool_comp(1, zstd());
    idle_for(&mut st, 3_000_000_000);
    let rc = st.rc_stats();
    assert_eq!(rc.chunks, 2, "{rc:?}");
    assert!(rc.no_gain >= 1, "the random range: {rc:?}");
    st.checkpoint().unwrap();
    assert_eq!(before - used(&st), rc.freed_blocks - rc.new_blocks);
    assert_eq!(
        st.coll_stats(&c).unwrap().unwrap().comp_orig,
        2 * 16 * BLK as u64
    );
    assert_eq!(&st.read(&c, &obj(0), 0, d.len() as u64).unwrap(), &d);
    let rep = st.check(true).unwrap();
    assert!(rep.errors.is_empty(), "check: {:?}", rep.errors);
}

/// EC shard objects (adr 0059 correction: EC pools compress shard writes): a shard collection is walked like a
/// replicated one; plain blocks a stash generation shares (`clone_range`, adr 0021 am. 38) are not freed by a rewrite.
#[test]
fn ec_shard_object_and_its_stash() {
    let (sim, img) = image(64, 7);
    let (_disk, mut st) = mount(&img, &sim, &StoreCfg::default());
    let c = CollT::Pg(SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId(1),
    });
    let shard_obj = |name: &[u8], generation: u64| {
        Ghobject::new(
            Hobject::new(name, SnapId::NOSNAP, 3, 1, b""),
            generation,
            ShardId(1),
        )
    };
    let (o, stash) = (shard_obj(b"ec.0", Ghobject::NO_GEN), shard_obj(b"ec.0", 7));
    let mut t = OTxn::new();
    t.mkcoll(c);
    commit(&mut st, &t);
    // 2 chunks as 32 single-block writes (plain records), the second chunk then stashed by clone_range
    let d = cdata(32 * BLK, 70);
    for b in 0..32 {
        let mut t = OTxn::new();
        t.write(c, &o, (b * BLK) as u64, &d[b * BLK..(b + 1) * BLK]);
        commit(&mut st, &t);
    }
    let mut t = OTxn::new();
    t.push(TOp::CloneRange {
        cid: c,
        src: o.clone(),
        dst: stash.clone(),
        src_off: 16 * BLK as u64,
        len: 16 * BLK as u64,
        dst_off: 16 * BLK as u64,
    });
    commit(&mut st, &t);
    st.set_pool_comp(1, zstd());
    idle_for(&mut st, 3_000_000_000);
    let rc = st.rc_stats();
    assert_eq!(rc.chunks, 1, "the unshared chunk only: {rc:?}");
    assert_eq!(&st.read(&c, &o, 0, d.len() as u64).unwrap(), &d);
    assert_eq!(
        &st.read(&c, &stash, 16 * BLK as u64, 16 * BLK as u64)
            .unwrap(),
        &d[16 * BLK..]
    );
    let rep = st.check(true).unwrap();
    assert!(rep.errors.is_empty(), "check: {:?}", rep.errors);
}
