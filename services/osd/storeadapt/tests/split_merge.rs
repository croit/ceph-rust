// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PG split / merge on the NVMe store (adr 0029): differential against `MemStore` (same semantic), same-shard
//! and cross-shard, with a device crash at every IO boundary of the structural transaction. After a crash the
//! state is either the old (parent at E-1: the PG machinery re-submits the same transaction) or the new one;
//! afterwards every object is in exactly the PG its hash selects, fsck and the object layer check are clean.
mod common;
use common::*;
use denc::types::*;
use peering::store::{MemStore, PersistedPg, PgStoreOps, SplitChild, StoreOp, StoreTxn};
use pgwire::{PastIntervals, PgInfo, PgLog, PgMissing, pgmath};
use replwire::txn::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
use store::dev::{CrashPolicy, SimClock, SimDisk};
use store::fsck::fsck;
use store::obj::{StoreCfg, onode::fsck_refs};
use store::rng::Rng;
use store::shard::ShardCfg;

const OLD_EPOCH: u32 = 7;
const NEW_EPOCH: u32 = 8;

fn cfg() -> StoreCfg {
    let mut c = StoreCfg {
        shard: ShardCfg {
            ckpt_wal_pct: 4,
            ..StoreCfg::default().shard
        },
    };
    if OMAP_LSM.get() {
        // the engine's memtables flush and merge often (adr 0610): the copy crosses runs, not only memtables
        c.shard.cache_pages = 128;
    }
    c
}

struct Obj {
    h: Hobject,
    data: Vec<u8>,
    attrs: Vec<(Vec<u8>, Vec<u8>)>,
    omap: Vec<(Vec<u8>, Vec<u8>)>,
    hdr: Vec<u8>,
}

/// Random objects of a pool (heads, clones sharing the head's hash, namespaces, locator keys, omap, big data).
fn make_objects(pool: i64, n: usize, seed: u64) -> Vec<Obj> {
    let mut r = Rng::new(seed);
    let mut v = Vec::new();
    for i in 0..n {
        let hash = r.next_u64() as u32;
        let nm = format!("rbd_data.{i}.{:08x}", r.next_u64() as u32).into_bytes();
        let ns: &[u8] = if i % 5 == 0 { b"ns" } else { b"" };
        for snap in [SnapId::NOSNAP, SnapId(4)]
            .into_iter()
            .take(1 + (i % 3 == 0) as usize)
        {
            let mut h = Hobject::new(&nm, snap, hash, pool, ns);
            if i % 7 == 3 {
                h.set_key(b"loc");
            }
            let len = match i % 6 {
                0 => 0,
                1 => 100,
                2 => 5000,
                3 => 70_000,
                4 => 9_000,
                _ => 1,
            };
            let mut data = vec![0u8; len];
            r.fill(&mut data);
            if len == 70_000 {
                // holes in the middle and a hole at the end: a cross-shard copy keeps them sparse
                data[8192..40_960].fill(0);
                data[65_536..].fill(0);
            }
            if len == 9_000 && i % 4 == 0 {
                data.fill(0); // nothing but a hole: only the size is copied
            }
            let attrs = vec![
                (b"_".to_vec(), vec![i as u8; 30]),
                (b"user.x".to_vec(), vec![7u8; (i * 13) % 300]),
            ];
            let omap = (0..(i % 5))
                .map(|k| (format!("k{k}").into_bytes(), vec![k as u8; 20 + i]))
                .collect();
            let hdr = if i % 4 == 0 { vec![9u8; 17] } else { vec![] };
            v.push(Obj {
                h,
                data,
                attrs,
                omap,
                hdr,
            });
        }
    }
    v
}

fn put_txn(spg: SpgT, o: &Obj) -> StoreTxn {
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(spg));
    let g = Ghobject::new(o.h.clone(), Ghobject::NO_GEN, spg.shard);
    let ox = t.obj(&g);
    t.push(cx, TxnOp::Touch { oid: ox });
    if !o.data.is_empty() {
        t.push(
            cx,
            TxnOp::Write {
                oid: ox,
                off: 0,
                data: replwire::Data::new(&o.data),
            },
        );
    }
    for (k, v) in &o.attrs {
        t.push(
            cx,
            TxnOp::SetAttr {
                oid: ox,
                name: k,
                value: v,
            },
        );
    }
    if !o.omap.is_empty() {
        let pairs: Vec<(&[u8], &[u8])> = o.omap.iter().map(|(k, v)| (&k[..], &v[..])).collect();
        t.push(
            cx,
            TxnOp::OmapSetKeys {
                oid: ox,
                pairs: pairs.into(),
            },
        );
    }
    if !o.hdr.is_empty() {
        t.push(
            cx,
            TxnOp::OmapSetHeader {
                oid: ox,
                header: &o.hdr,
            },
        );
    }
    StoreTxn {
        ops: vec![StoreOp::ApplyTxn {
            middle: Default::default(),
            data: t.encode_v9().unwrap().into(),
        }],
    }
}

/// SnapMapper entry of a clone object (clones of `make_objects` carry snap 4 and 3).
fn map_txn(o: &Obj) -> Option<StoreTxn> {
    (o.h.snap != SnapId::NOSNAP).then(|| StoreTxn {
        ops: vec![StoreOp::SnapMap(vec![peering::snaps::MapOp::Set {
            clone: o.h.clone(),
            snaps: vec![o.h.snap.0, o.h.snap.0 - 1],
        }])],
    })
}

fn temp_obj(spg: SpgT) -> Obj {
    Obj {
        h: Hobject::new(
            b"temp_recovering",
            SnapId::NOSNAP,
            spg.pgid.seed,
            Hobject::temp_pool(spg.pgid.pool as i64),
            b"",
        ),
        data: vec![5; 50],
        attrs: vec![],
        omap: vec![],
        hdr: vec![],
    }
}

fn pstate(spg: SpgT, epoch: u32, lu: u64) -> PersistedPg {
    let mut info = PgInfo::new(spg);
    info.last_update = Eversion::new(5, lu);
    info.last_complete = info.last_update;
    info.history.epoch_created = 3;
    PersistedPg {
        info,
        log: PgLog::empty_at(Eversion::new(5, lu)),
        missing: PgMissing {
            may_include_deletes: true,
            ..Default::default()
        },
        past_intervals: PastIntervals::default(),
        epoch,
    }
}

fn create_pg(st: &mut impl PgStoreOps, spg: SpgT, lu: u64, epoch: u32) {
    st.submit(
        spg,
        &StoreTxn {
            ops: vec![
                StoreOp::CreatePg,
                StoreOp::PutInfo(Box::new(pstate(spg, epoch, lu).info)),
                StoreOp::PutEpoch(epoch),
            ],
        },
    );
}

/// The split transaction of PG `parent` for `old_n -> new_n` (children by the pgid math).
fn split_txn(parent: SpgT, old_n: u32, new_n: u32) -> (StoreTxn, Vec<SpgT>) {
    let seed = parent.pgid.seed;
    let kids = pgmath::split_children(seed, old_n, new_n);
    let mut spgs = Vec::new();
    let children = kids
        .iter()
        .map(|c| {
            let cs = spg(parent.pgid.pool, *c);
            spgs.push(cs);
            SplitChild {
                spg: cs,
                bits: pgmath::split_bits(*c, new_n),
                state: Box::new(pstate(cs, NEW_EPOCH, 40 + *c as u64)),
            }
        })
        .collect();
    let t = StoreTxn {
        ops: vec![
            StoreOp::SplitOut {
                parent_bits: pgmath::split_bits(seed, new_n),
                children,
            },
            StoreOp::PutInfo(Box::new(pstate(parent, NEW_EPOCH, 50).info)),
            StoreOp::PutEpoch(NEW_EPOCH),
        ],
    };
    (t, spgs)
}

fn merge_txn(target: SpgT, sources: &[SpgT], new_n: u32) -> StoreTxn {
    StoreTxn {
        ops: vec![
            StoreOp::MergeIn {
                sources: sources.to_vec(),
                bits: pgmath::split_bits(target.pgid.seed, new_n),
            },
            StoreOp::PutInfo(Box::new(pstate(target, NEW_EPOCH, 60).info)),
            StoreOp::PutEpoch(NEW_EPOCH),
        ],
    }
}

fn quiet() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |i| {
            let m = i
                .payload()
                .downcast_ref::<String>()
                .cloned()
                .unwrap_or_default();
            if !m.contains(": crash:") && !m.contains("crash: ") {
                prev(i)
            }
        }));
    });
}

/// Compare the adapter with the MemStore model for every PG in `pgs` (state, objects) and list the collections.
fn compare(mem: &MemStore, ad: &Ad, pgs: &[SpgT], gone: &[SpgT], ctx: &str) -> Result<(), String> {
    quiet();
    catch_unwind(AssertUnwindSafe(|| {
        for s in pgs {
            assert_same(mem, ad, *s, ctx);
            assert_same_objects(mem, ad, *s, ctx);
            // the SnapMapper follows its clones: same entries, and none for an object the PG does not hold
            let want = mem.pgs[s].snapmap.all();
            let mut have = ad.map_all(*s);
            have.sort();
            let mut want = want;
            want.sort();
            assert_eq!(have, want, "{ctx}: snap mapper of {s}");
            for (c, _) in &have {
                assert!(
                    mem.objects(*s).contains_key(c),
                    "{ctx}: mapped clone {s} absent"
                );
            }
            // temp objects stay where they were
            assert_eq!(mem.temp_objects(*s), ad.temp_objects(*s), "{ctx}: temp {s}");
            let c = ad
                .with_store(|st| st.coll_stats(&CollT::Pg(*s)))
                .unwrap()
                .unwrap();
            assert_eq!(
                c.nobj as usize,
                mem.objects(*s).len(),
                "{ctx}: collection counter {s}"
            );
        }
        for s in gone {
            assert!(ad.load_pg(*s).is_none(), "{ctx}: {s} should be gone");
            assert!(
                !ad.with_store(|st| st.coll_exists(&CollT::Pg(*s))).unwrap(),
                "{ctx}: collection of {s} left"
            );
        }
        let colls = ad.with_store(|st| st.list_colls()).unwrap();
        for c in colls {
            if let CollT::Pg(s) = c {
                assert!(pgs.contains(&s), "{ctx}: stray collection {s}");
            }
        }
    }))
    .map_err(|e| {
        e.downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    })
}

struct Case {
    shards: u32,
    /// PGs that exist before the structural txn: (pg, objects, epoch).
    pre: Vec<(SpgT, Vec<Obj>)>,
    txn_pg: SpgT,
    txn: StoreTxn,
    /// PGs after (all must exist and equal the model).
    after: Vec<SpgT>,
    /// PGs that must be gone after.
    gone: Vec<SpgT>,
}

fn setup(case: &Case, seed: u64) -> (store::dev::SimConfig, store::dev::SimImage, MemStore) {
    let sim = sim_cfg(64, seed);
    let img = fresh_image(&sim, case.shards, 512);
    let (disk, mut ad) = open(&img, &sim, &cfg());
    let mut mem = MemStore::new();
    for (s, objs) in &case.pre {
        create_pg(&mut ad, *s, 30, OLD_EPOCH);
        create_pg(&mut mem, *s, 30, OLD_EPOCH);
        let mut all: Vec<&Obj> = objs.iter().collect();
        let t = temp_obj(*s);
        all.push(&t);
        for o in all {
            ad.submit(*s, &put_txn(*s, o));
            mem.submit(*s, &put_txn(*s, o));
            if let Some(m) = map_txn(o) {
                ad.submit(*s, &m);
                mem.submit(*s, &m);
            }
        }
    }
    ad.with_store(|st| st.checkpoint().unwrap());
    let base = disk.image();
    drop(ad);
    mem.submit(case.txn_pg, &case.txn);
    (sim, base, mem)
}

/// Crash at device event `k` of the structural txn, remount, finish like the OSD does, compare.
fn scenario(
    case: &Case,
    sim: &store::dev::SimConfig,
    base: &store::dev::SimImage,
    mem: &MemStore,
    k: u64,
    pol: CrashPolicy,
) -> Result<bool, String> {
    let mut s2 = sim.clone();
    s2.seed = 1000 + k;
    let (disk, ad) = open(base, &s2, &cfg());
    disk.arm_crash(disk.events() + k);
    let _ = ad.try_submit(case.txn_pg, &case.txn);
    let crashed = disk.crashed();
    disk.crash_now();
    let cimg = disk.crash_image(pol);
    drop(ad);
    {
        let d = SimDisk::from_image(&cimg, sim.clone());
        let mut dev = d.queue();
        let mut clk = SimClock::default();
        fsck(&mut dev, &mut clk, Some(&fsck_refs)).map_err(|e| format!("fsck crash image: {e}"))?;
    }
    let (_d2, ad2) = open(&cimg, sim, &cfg());
    // mount-time recovery: resume the deletions the durable `_remove` markers stand for and run them to completion,
    // like the OSD's removal slices do (a queued deletion is invisible to every read, `load_pg` included)
    ad2.resume_removals().map_err(|e| format!("resume: {e}"))?;
    ad2.finish_removals()
        .map_err(|e| format!("resumed removals: {e}"))?;
    ad2.recover_structural()
        .map_err(|e| format!("recover: {e}"))?;
    // the PG machinery re-advances a PG whose epoch is still the old one: the same transaction again
    let ep = ad2.load_pg(case.txn_pg).map(|p| p.epoch);
    let redo = ep == Some(OLD_EPOCH);
    if redo {
        ad2.try_submit(case.txn_pg, &case.txn)
            .map_err(|e| format!("redo: {e}"))?;
    }
    if !redo {
        // the merge target committed but a source survived: the PG machinery finds it past the merge epoch and removes it
        for s in &case.gone {
            if ad2.load_pg(*s).is_some() {
                ad2.try_submit(
                    *s,
                    &StoreTxn {
                        ops: vec![StoreOp::RemovePg],
                    },
                )
                .map_err(|e| format!("orphan removal: {e}"))?;
                ad2.finish_removals()
                    .map_err(|e| format!("orphan removal: {e}"))?;
            }
        }
    }
    ad2.gc_orphans().map_err(|e| format!("gc: {e}"))?;
    let rep = ad2
        .with_store(|st| st.check(true))
        .map_err(|e| format!("check: {e}"))?;
    if !rep.errors.is_empty() {
        return Err(format!("object layer check: {:?}", rep.errors));
    }
    let ctx = format!("k={k} {pol:?} crashed={crashed} redo={redo}");
    compare(mem, &ad2, &case.after, &case.gone, &ctx)?;
    Ok(crashed)
}

fn matrix(case: &Case, seed: u64, stride: u64, pols: &[CrashPolicy]) -> (u64, u64) {
    let (sim, base, mem) = setup(case, seed);
    // dry run: no crash, the result must equal the model; count the events
    let (disk, ad) = open(&base, &sim, &cfg());
    let e0 = disk.events();
    ad.try_submit(case.txn_pg, &case.txn).unwrap();
    let events = disk.events() - e0;
    compare(&mem, &ad, &case.after, &case.gone, "no crash").unwrap();
    let rep = ad.with_store(|st| st.check(true)).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    drop(ad);
    assert!(events > 5, "{events}");
    let (mut n, mut c) = (0, 0);
    let mut k = 0;
    while k < events {
        for pol in pols {
            match scenario(case, &sim, &base, &mem, k, *pol) {
                Ok(cr) => {
                    n += 1;
                    c += cr as u64;
                }
                Err(e) => panic!("seed {seed} k={k} {pol:?}: {e}"),
            }
        }
        k += stride;
    }
    eprintln!("split/merge crash matrix seed {seed}: {events} events, {n} scenarios, {c} crashed");
    (n, c)
}

const ALL: [CrashPolicy; 3] = [
    CrashPolicy::DROP_ALL,
    CrashPolicy::PERSIST_ALL,
    CrashPolicy::MIXED,
];

fn split_case(shards: u32, pool: u64, old_n: u32, new_n: u32, seed: u32, nobj: usize) -> Case {
    let parent = spg(pool, seed);
    // only objects the parent owns at old_n (hash & mask(bits) == seed)
    let bits = pgmath::split_bits(seed, old_n);
    let mut objs = make_objects(pool as i64, nobj * 3, 11 + seed as u64);
    objs.retain(|o| pgmath::contains(seed, bits, o.h.hash));
    let (txn, kids) = split_txn(parent, old_n, new_n);
    let mut after = vec![parent];
    after.extend(kids);
    Case {
        shards,
        pre: vec![(parent, objs)],
        txn_pg: parent,
        txn,
        after,
        gone: vec![],
    }
}

#[test]
fn split_same_shard_crash_matrix() {
    // one shard: every child is on the parent's shard (objects are re-keyed, not copied)
    let c = split_case(1, 1, 1, 4, 0, 14);
    let (n, cr) = matrix(&c, 1, 1, &ALL);
    assert!(n > 20 && cr > 0);
}

#[test]
fn split_cross_shard_crash_matrix() {
    // 4 shards, pool 1: parent seed 0 on shard 1; children 1,2,3 on shards 2,3,0 (copied)
    let c = split_case(4, 1, 1, 4, 0, 6);
    let (n, cr) = matrix(
        &c,
        2,
        1,
        &[
            CrashPolicy::MIXED,
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
        ],
    );
    assert!(n > 40 && cr > 0);
}

#[test]
fn split_8_children_mixed_shards() {
    // 1 -> 8 on 4 shards: child 4 shares the parent's shard (moved), the others are copied
    let c = split_case(4, 1, 1, 8, 0, 4);
    let (n, _) = matrix(&c, 3, 3, &[CrashPolicy::MIXED, CrashPolicy::DROP_ALL]);
    assert!(n > 20);
}

#[test]
fn split_non_power_of_two() {
    // 12 -> 32 with seed 4 (three children, 3 bits -> 5 bits)
    let c = split_case(4, 2, 12, 32, 4, 5);
    let (n, _) = matrix(&c, 4, 2, &[CrashPolicy::MIXED, CrashPolicy::DROP_ALL]);
    assert!(n > 10);
}

/// Cross-shard split on the omap LSM engine (adr 0610 phase 2b): the copy takes the source object's engine keys into
/// the child's engine, key for key, under the same per-batch transactions.
#[test]
fn split_cross_shard_omap_lsm() {
    with_omap_lsm(|| {
        let c = split_case(4, 1, 1, 4, 0, 6);
        let (sim, base, mem) = setup(&c, 20);
        let (_disk, ad) = open(&base, &sim, &cfg());
        ad.try_submit(c.txn_pg, &c.txn).unwrap();
        compare(&mem, &ad, &c.after, &c.gone, "omap lsm split").unwrap();
        let rep = ad.with_store(|st| st.check(true)).unwrap();
        assert!(rep.errors.is_empty(), "{:?}", rep.errors);
        assert!(rep.omap_keys > 0, "the fixture has omap");
    });
}

/// The same crash matrix as [`split_cross_shard_crash_matrix`], with the omap in the engine.
#[test]
fn split_cross_shard_omap_lsm_crash_matrix() {
    with_omap_lsm(|| {
        let c = split_case(4, 1, 1, 4, 0, 4);
        let (n, cr) = matrix(&c, 21, 3, &[CrashPolicy::MIXED, CrashPolicy::DROP_ALL]);
        assert!(n > 10 && cr > 0);
    });
}

/// Cross-shard merge on the omap LSM engine: the target's engine receives every source key, then the source goes.
#[test]
fn merge_cross_shard_omap_lsm_crash_matrix() {
    with_omap_lsm(|| {
        let c = merge_case(4, 1, 4, 3, 1, 4);
        let (n, cr) = matrix(&c, 22, 2, &[CrashPolicy::MIXED, CrashPolicy::PERSIST_ALL]);
        assert!(n > 20 && cr > 0);
    });
}

fn merge_case(shards: u32, pool: u64, old_n: u32, new_n: u32, target: u32, nobj: usize) -> Case {
    let t = spg(pool, target);
    let srcs: Vec<SpgT> = pgmath::merge_sources(target, old_n, new_n)
        .into_iter()
        .map(|s| spg(pool, s))
        .collect();
    let mut pre = Vec::new();
    for (i, s) in std::iter::once(&t).chain(srcs.iter()).enumerate() {
        let bits = pgmath::split_bits(s.pgid.seed, old_n);
        let mut objs = make_objects(
            pool as i64,
            nobj * 4,
            77 + i as u64 * 5 + s.pgid.seed as u64,
        );
        objs.retain(|o| pgmath::contains(s.pgid.seed, bits, o.h.hash));
        objs.truncate(nobj);
        pre.push((*s, objs));
    }
    Case {
        shards,
        pre,
        txn_pg: t,
        txn: merge_txn(t, &srcs, new_n),
        after: vec![t],
        gone: srcs,
    }
}

#[test]
fn merge_same_shard_crash_matrix() {
    let c = merge_case(1, 1, 16, 15, 7, 12);
    let (n, cr) = matrix(&c, 5, 1, &ALL);
    assert!(n > 20 && cr > 0);
}

#[test]
fn merge_cross_shard_crash_matrix() {
    // 4 shards: target 1 (shard 2) and source 3 (shard 0) differ
    let c = merge_case(4, 1, 4, 3, 1, 6);
    let (n, cr) = matrix(&c, 6, 1, &ALL);
    assert!(n > 40 && cr > 0);
}

#[test]
fn merge_multi_source_and_missing_source() {
    // 16 -> 4: target 3 absorbs 7, 11, 15; 11 does not exist locally (placeholder case: just skipped)
    let mut c = merge_case(2, 1, 16, 4, 3, 4);
    let missing = spg(1, 11);
    c.pre.retain(|(s, _)| *s != missing);
    let (n, _) = matrix(&c, 7, 4, &[CrashPolicy::MIXED, CrashPolicy::DROP_ALL]);
    assert!(n >= 8);
}

/// Split and merge place mapper entries by the clone hash in the key, never by decoding the value: a damaged
/// reverse entry travels byte for byte with its clone (with its forward entries), where readers and scrub see it.
#[test]
fn split_and_merge_carry_damaged_reverse_snap_mapping() {
    for shards in [1, 2] {
        for merge in [false, true] {
            let (_disk, mut ad, _) = new_adapter(64, shards, 81);
            let target = spg(1, 0);
            let (holder, dest) = if merge {
                (spg(1, 1), target)
            } else {
                (target, spg(1, 1))
            };
            create_pg(&mut ad, target, 30, OLD_EPOCH);
            if merge {
                create_pg(&mut ad, holder, 30, OLD_EPOCH);
            }
            let clone = Hobject::new(b"clone", SnapId(4), 1, 1, b"");
            let object = Obj {
                h: clone.clone(),
                data: b"snapshot-data".to_vec(),
                attrs: vec![],
                omap: vec![],
                hdr: vec![],
            };
            ad.try_submit(holder, &put_txn(holder, &object)).unwrap();
            ad.try_submit(holder, &map_txn(&object).unwrap()).unwrap();
            let key = peering::snaps::rev_key(&clone);
            let fwd = [4, 3].map(|s| peering::snaps::fwd_key(s, &clone));
            let mut damage = store::obj::OTxn::new();
            damage.omap_set(
                CollT::Pg(holder),
                &storeadapt::snapmap::mapper_obj(holder),
                &key,
                &[0xde, 0xad],
            );
            ad.with_store(|st| st.commit(&damage)).unwrap();
            let txn = if merge {
                merge_txn(target, &[holder], 1)
            } else {
                split_txn(target, 1, 2).0
            };
            let ctx = format!("shards={shards} merge={merge}");
            ad.try_submit(target, &txn)
                .unwrap_or_else(|e| panic!("{ctx}: {e:?}"));
            assert_eq!(ad.load_pg(target).unwrap().epoch, NEW_EPOCH, "{ctx}");
            let get = |s: SpgT, k: &[u8]| {
                ad.with_store(|st| {
                    st.omap_get(&CollT::Pg(s), &storeadapt::snapmap::mapper_obj(s), &[k])
                })
                .ok()
                .and_then(|mut m| m.remove(k))
            };
            assert_eq!(get(dest, &key).as_deref(), Some(&[0xde, 0xad][..]), "{ctx}");
            for k in &fwd {
                assert!(get(dest, k).is_some(), "{ctx}: forward entry left behind");
                assert!(
                    get(holder, k).is_none(),
                    "{ctx}: forward entry kept by the source"
                );
            }
            assert!(
                get(holder, &key).is_none(),
                "{ctx}: reverse entry kept by the source"
            );
        }
    }
}

/// A mapper key that names no clone hash cannot be placed: split (and its cross-shard cleanup) leaves it in the
/// parent and notes it, merge carries it; the structural transaction always completes (an error would be redone
/// after every restart and never finish), and a deep scrub's mapper key scan reports the key.
#[test]
fn split_and_merge_complete_with_an_unparseable_snap_mapper_key() {
    let bad = [
        b"c\x00\xff".to_vec(),
        b"s\x00\x00\x00\x00\x00\x00\x00\x04\x07".to_vec(),
    ];
    for shards in [1, 2] {
        for merge in [false, true] {
            let (_disk, mut ad, _) = new_adapter(64, shards, 82);
            let target = spg(1, 0);
            let (holder, dest) = if merge {
                (spg(1, 1), target)
            } else {
                (target, spg(1, 1))
            };
            create_pg(&mut ad, target, 30, OLD_EPOCH);
            if merge {
                create_pg(&mut ad, holder, 30, OLD_EPOCH);
            }
            let mut damage = store::obj::OTxn::new();
            for k in &bad {
                damage.omap_set(
                    CollT::Pg(holder),
                    &storeadapt::snapmap::mapper_obj(holder),
                    k,
                    b"v",
                );
            }
            ad.with_store(|st| st.commit(&damage)).unwrap();
            let txn = if merge {
                merge_txn(target, &[holder], 1)
            } else {
                split_txn(target, 1, 2).0
            };
            let ctx = format!("shards={shards} merge={merge}");
            ad.try_submit(target, &txn)
                .unwrap_or_else(|e| panic!("{ctx}: {e:?}"));
            assert_eq!(ad.load_pg(target).unwrap().epoch, NEW_EPOCH, "{ctx}");
            if !merge {
                ad.finish_split_out(target)
                    .unwrap_or_else(|e| panic!("{ctx}: cleanup {e:?}"));
            }
            let get = |s: SpgT, k: &[u8]| {
                ad.with_store(|st| {
                    st.omap_get(&CollT::Pg(s), &storeadapt::snapmap::mapper_obj(s), &[k])
                })
                .ok()
                .and_then(|mut m| m.remove(k))
            };
            // merge: the target holds the keys; split: they stay in the parent, the child gets none
            let (has, hasnt) = if merge {
                (dest, None)
            } else {
                (holder, Some(dest))
            };
            for k in &bad {
                assert_eq!(get(has, k).as_deref(), Some(&b"v"[..]), "{ctx}: key lost");
                if let Some(h) = hasnt {
                    assert!(get(h, k).is_none(), "{ctx}: key placed without a hash");
                }
            }
            let notes = ad.take_notes();
            assert_eq!(
                notes
                    .iter()
                    .any(|n| n.contains("2 snap mapper keys unparseable")),
                !merge,
                "{ctx}: {notes:?}"
            );
            let (ops, msgs) = ad.snapmap_check(has, &Hobject::MIN(), &Hobject::MAX());
            assert!(ops.is_empty(), "{ctx}: {ops:?}");
            assert!(
                msgs.is_empty(),
                "{ctx}: the per-chunk check never reads the whole mapper: {msgs:?}"
            );
            let msgs = ad.snapmap_key_scan(has);
            assert!(
                msgs.iter()
                    .any(|m| m.starts_with("snap mapper: 2 unparseable keys")),
                "{ctx}: {msgs:?}"
            );
        }
    }
}

#[test]
fn orphan_children_are_collected_but_not_while_a_parent_may_redo() {
    // crash in the middle of a split, then `gc_orphans` BEFORE the redo must keep the half-built children
    let c = split_case(1, 1, 1, 4, 0, 30);
    let (sim, base, mem) = setup(&c, 9);
    let (disk, ad) = open(&base, &sim, &cfg());
    let e0 = disk.events();
    ad.try_submit(c.txn_pg, &c.txn).unwrap();
    let events = disk.events() - e0;
    drop(ad);
    let mut kept = 0;
    for k in (1..events).step_by(7) {
        let (disk, ad) = open(&base, &sim, &cfg());
        disk.arm_crash(disk.events() + k);
        let _ = ad.try_submit(c.txn_pg, &c.txn);
        disk.crash_now();
        let img = disk.crash_image(CrashPolicy::DROP_ALL);
        drop(ad);
        let (_d, ad2) = open(&img, &sim, &cfg());
        let before = ad2.load_pg(c.txn_pg).map(|p| p.epoch);
        ad2.gc_orphans().unwrap();
        if before == Some(OLD_EPOCH) {
            // the parent is still at the old epoch: nothing may have been collected
            ad2.try_submit(c.txn_pg, &c.txn).unwrap();
            kept += 1;
        }
        compare(&mem, &ad2, &c.after, &c.gone, &format!("gc k={k}")).unwrap();
    }
    assert!(kept > 0);
    // a stray collection without any parent is removed
    let (_d, ad) = open(&base, &sim, &cfg());
    ad.with_store(|st| {
        let mut t = store::obj::OTxn::new();
        t.mkcoll(CollT::Pg(spg(9, 5)));
        st.commit(&t).unwrap();
    });
    assert_eq!(ad.gc_orphans().unwrap(), 1);
}

fn names(ad: &Ad, s: SpgT) -> std::collections::BTreeSet<Hobject> {
    ad.all_object_names(s).into_iter().collect()
}

fn queue_removal_started(ad: &mut Ad, s: SpgT) {
    let rm = StoreTxn {
        ops: vec![StoreOp::RemovePg],
    };
    assert!(matches!(
        ad.queue(s, &rm, 1),
        peering::store::Queued::Pending
    ));
    assert!(ad.step_removals_sync().unwrap(), "deletion only started");
}

#[test]
fn split_and_merge_never_reuse_a_pg_whose_deletion_is_queued() {
    // Review regression (sliced PG deletion): a split child / merge source whose deletion was still queued was taken
    // as existing: the split skipped the child (old state + REMOVE marker kept; the deletion then dropped the new
    // child's objects), the merge moved the deleted source's objects into the target (resurrection).
    let objs = make_objects(1, 40, 77);
    let (p, c) = (spg(1, 0), spg(1, 1));
    let half = |s: SpgT| -> std::collections::BTreeSet<Hobject> {
        objs.iter()
            .filter(|o| o.h.hash & 1 == s.pgid.seed)
            .map(|o| o.h.clone())
            .collect()
    };
    // merge 2 -> 1: the deleted source 1.1 stays deleted
    let (_d, mut ad, _) = new_adapter(64, 1, 3);
    ad.remove_batch.set(2);
    create_pg(&mut ad, p, 10, OLD_EPOCH);
    create_pg(&mut ad, c, 10, OLD_EPOCH);
    for o in &objs {
        let s = if o.h.hash & 1 == 0 { p } else { c };
        ad.submit(s, &put_txn(s, o));
    }
    queue_removal_started(&mut ad, c);
    ad.try_submit(p, &merge_txn(p, &[c], 1)).unwrap();
    ad.finish_removals().unwrap();
    assert_eq!(names(&ad, p), half(p), "merge target: own objects only");
    assert!(!ad.list_pgs().contains(&c) && ad.pending_removals().unwrap().is_empty());
    // split 1 -> 2 into a child whose old copy is still being deleted: the child gets exactly its split share
    let (_d, mut ad, _) = new_adapter(64, 1, 4);
    ad.remove_batch.set(2);
    create_pg(&mut ad, p, 10, OLD_EPOCH);
    for o in &objs {
        ad.submit(p, &put_txn(p, o));
    }
    create_pg(&mut ad, c, 5, OLD_EPOCH);
    let stale = make_objects(1, 12, 99);
    for o in stale.iter().filter(|o| o.h.hash & 1 == 1) {
        ad.submit(c, &put_txn(c, o));
    }
    queue_removal_started(&mut ad, c);
    let (t, _) = split_txn(p, 1, 2);
    ad.try_submit(p, &t).unwrap();
    ad.finish_removals().unwrap();
    assert!(ad.list_pgs().contains(&c), "the split child survives");
    assert_eq!(ad.load_pg(c).unwrap().epoch, NEW_EPOCH);
    assert_eq!(
        names(&ad, c),
        half(c),
        "child: its split share, no stale objects"
    );
    assert_eq!(names(&ad, p), half(p));
}
