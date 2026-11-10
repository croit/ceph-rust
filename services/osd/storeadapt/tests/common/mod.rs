// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
#![allow(clippy::allow_attributes, dead_code)]
use denc::types::*;
use peering::store::{MemStore, PgStoreOps};
use pgwire::{LogDup, LogEntry, LogOp, MissingItem, PastIntervals, PgInfo};
use replwire::txn::*;
use replwire::{ObjectInfo, ObjectRecoveryProgress};
use std::collections::BTreeSet;
use store::dev::{SimClock, SimConfig, SimDev, SimDisk, SimImage};
use store::layout::{MkfsParams, mkfs};
use store::obj::{Store, StoreCfg};
use store::rng::Rng;
use storeadapt::StoreAdapter;

pub type Ad = StoreAdapter<SimDev, SimClock>;

pub fn sim_cfg(cap_mib: u64, seed: u64) -> SimConfig {
    let mut s = SimConfig::new(cap_mib << 20);
    s.seed = seed;
    s
}

std::thread_local! {
    /// Format the images of this test thread with the omap LSM engine (`FEAT_OMAP_LSM`, adr 0610); `new_adapter` then
    /// mounts with a small cache so its memtables flush and merge.
    pub static OMAP_LSM: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run `f` with [`OMAP_LSM`] on.
pub fn with_omap_lsm(f: impl FnOnce()) {
    OMAP_LSM.set(true);
    f();
    OMAP_LSM.set(false);
}

pub fn fresh_image(sim: &SimConfig, shards: u32, wal_blocks: u64) -> SimImage {
    fresh_image_pages(sim, shards, wal_blocks, 8192)
}

/// Format an image whose tree pages are `node_size` bytes (the store's meta page size).
pub fn fresh_image_pages(
    sim: &SimConfig,
    shards: u32,
    wal_blocks: u64,
    node_size: u32,
) -> SimImage {
    let disk = SimDisk::new(sim.clone());
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    let p = MkfsParams {
        shards,
        wal_blocks,
        align_blocks: 1,
        meta_pct: 8,
        node_size,
        omap_lsm: OMAP_LSM.get(),
        ..Default::default()
    };
    mkfs(&mut dev, &mut clk, &p).unwrap();
    disk.image()
}

pub fn open(img: &SimImage, sim: &SimConfig, cfg: &StoreCfg) -> (SimDisk, Ad) {
    let disk = SimDisk::from_image(img, sim.clone());
    let d2 = disk.clone();
    let (st, _) = Store::mount(move || d2.queue(), SimClock::default(), cfg.clone()).unwrap();
    (disk, StoreAdapter::new(st))
}

pub fn new_adapter(cap_mib: u64, shards: u32, seed: u64) -> (SimDisk, Ad, SimConfig) {
    let sim = sim_cfg(cap_mib, seed);
    let img = fresh_image(&sim, shards, 1024);
    let mut cfg = StoreCfg::default();
    if OMAP_LSM.get() {
        cfg.shard.cache_pages = 128;
    }
    let (d, a) = open(&img, &sim, &cfg);
    (d, a, sim)
}

/// Incompressible bytes (the store LZ4-compresses omap values, so size-limit tests must not use constant fills).
pub fn incompressible(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut v = Vec::with_capacity(len + 8);
    while v.len() < len {
        v.extend_from_slice(&rng.next_u64().to_le_bytes());
    }
    v.truncate(len);
    v
}

pub fn spg(pool: u64, seed: u32) -> SpgT {
    SpgT {
        pgid: PgT::new(pool, seed),
        shard: ShardId::NO_SHARD,
    }
}

pub fn oi_bytes(h: &Hobject, ver: Eversion, size: u64) -> Vec<u8> {
    let mut oi = ObjectInfo::new(h.clone());
    oi.version = ver;
    oi.prior_version = Eversion::new(ver.epoch, ver.version.saturating_sub(1));
    oi.size = size;
    oi.user_version = ver.version;
    denc::to_vec(&oi).unwrap()
}

/// Random PG-transaction generator over a small object universe of one PG.
pub struct PgGen {
    pub spg: SpgT,
    pub rng: Rng,
    pub names: Vec<Hobject>,
    pub temps: Vec<Hobject>,
    pub ver: u64,
    pub epoch: u32,
}

impl PgGen {
    pub fn new(spg: SpgT, seed: u64) -> PgGen {
        let mut rng = Rng::new(seed);
        let pool = spg.pgid.pool as i64;
        let mut names = Vec::new();
        for i in 0..14 {
            let nm: Vec<u8> = match i % 4 {
                0 => format!("rbd_data.{i}.{:016x}", rng.next_u64()).into_bytes(),
                1 => format!("o\0{i}").into_bytes(),
                2 => format!("obj{i}").into_bytes(),
                _ => vec![b'z'; (i + 1) as usize],
            };
            let mut h = Hobject::new(
                &nm,
                if i % 5 == 0 {
                    SnapId(3)
                } else {
                    SnapId::NOSNAP
                },
                (rng.next_u64() as u32 & !0x7) | spg.pgid.seed & 7,
                pool,
                if i % 6 == 0 { b"ns" } else { b"" },
            );
            if i % 7 == 3 {
                h.set_key(b"loc");
            }
            names.push(h);
        }
        let temps = (0..4)
            .map(|i| {
                Hobject::new(
                    format!("temp_{i}").as_bytes(),
                    SnapId::NOSNAP,
                    spg.pgid.seed,
                    Hobject::temp_pool(pool),
                    b"",
                )
            })
            .collect();
        PgGen {
            spg,
            rng,
            names,
            temps,
            ver: 0,
            epoch: 5,
        }
    }

    pub fn g(&self, h: &Hobject) -> Ghobject {
        Ghobject::new(h.clone(), Ghobject::NO_GEN, self.spg.shard)
    }

    fn pick(&mut self) -> Hobject {
        if self.rng.pct(15) {
            return self.temps[self.rng.below(self.temps.len() as u64) as usize].clone();
        }
        self.names[self.rng.below(self.names.len() as u64) as usize].clone()
    }

    fn data(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.rng.fill(&mut v);
        v
    }

    fn val(&mut self) -> Vec<u8> {
        let n = match self.rng.below(100) {
            0..=69 => self.rng.below(50),
            70..=92 => self.rng.range(100, 2500),
            _ => self.rng.range(3000, 9000),
        } as usize;
        self.data(n)
    }

    /// Encoded transaction (v9) with 1..=5 valid ops; `exist` = hobjects currently present (tracked across calls).
    pub fn object_txn(&mut self, exist: &mut BTreeSet<Hobject>) -> Vec<u8> {
        let n = self.rng.range(1, 5);
        let mut payloads: Vec<Vec<u8>> = Vec::new();
        // build ops into a Vec first (data must outlive the Transaction)
        enum O {
            Touch(Hobject),
            Write(Hobject, u64, Vec<u8>),
            Zero(Hobject, u64, u64),
            Trunc(Hobject, u64),
            Remove(Hobject),
            SetAttrs(Hobject, Vec<(Vec<u8>, Vec<u8>)>),
            RmAttr(Hobject, Vec<u8>),
            RmAttrs(Hobject),
            Clone(Hobject, Hobject),
            CloneRange(Hobject, Hobject, u64, u64, u64),
            Rename(Hobject, Hobject),
            OmapSet(Hobject, Vec<(Vec<u8>, Vec<u8>)>),
            OmapRm(Hobject, Vec<Vec<u8>>),
            OmapRange(Hobject, Vec<u8>, Vec<u8>),
            OmapClear(Hobject),
            Hdr(Hobject, Vec<u8>),
            Hint(Hobject),
        }
        let mut ops = Vec::new();
        for _ in 0..n {
            let o = self.pick();
            match self.rng.below(100) {
                0..=3 => {
                    exist.insert(o.clone());
                    ops.push(O::Touch(o));
                }
                4..=33 => {
                    let off = if self.rng.pct(30) {
                        0
                    } else {
                        self.rng.below(30_000)
                    };
                    let len = if self.rng.pct(50) {
                        self.rng.range(1, 600)
                    } else {
                        self.rng.range(1, 24_000)
                    } as usize;
                    exist.insert(o.clone());
                    let d = self.data(len);
                    ops.push(O::Write(o, off, d));
                }
                34..=38 => {
                    exist.insert(o.clone());
                    ops.push(O::Zero(
                        o,
                        self.rng.below(30_000),
                        self.rng.range(1, 12_000),
                    ));
                }
                39..=43 => {
                    if exist.contains(&o) {
                        ops.push(O::Trunc(o, self.rng.below(35_000)));
                    }
                }
                44..=48 => {
                    exist.remove(&o);
                    ops.push(O::Remove(o));
                }
                49..=57 => {
                    exist.insert(o.clone());
                    let mut at = vec![];
                    if self.rng.pct(60) {
                        let ver = Eversion::new(self.epoch, self.rng.range(1, 1000));
                        at.push((b"_".to_vec(), oi_bytes(&o, ver, 0)));
                    }
                    if self.rng.pct(40) {
                        at.push((
                            b"snapset".to_vec(),
                            denc::to_vec(&replwire::SnapSet::default()).unwrap(),
                        ));
                    }
                    if self.rng.pct(40) {
                        at.push((
                            format!("user.{}", self.rng.below(4)).into_bytes(),
                            self.val(),
                        ));
                    }
                    ops.push(O::SetAttrs(o, at));
                }
                58..=59 => ops.push(O::RmAttr(o, b"user.1".to_vec())),
                60 => ops.push(O::RmAttrs(o)),
                61..=64 => {
                    let src = self.pick();
                    if exist.contains(&src) && src != o {
                        exist.insert(o.clone());
                        ops.push(O::Clone(src, o));
                    }
                }
                65..=66 => {
                    let src = self.pick();
                    if exist.contains(&src) {
                        exist.insert(o.clone());
                        ops.push(O::CloneRange(
                            src,
                            o,
                            0,
                            self.rng.range(1, 9000),
                            self.rng.below(20_000),
                        ));
                    }
                }
                67..=70 => {
                    let src = self.pick();
                    if src != o {
                        if exist.remove(&src) {
                            exist.insert(o.clone());
                        }
                        ops.push(O::Rename(src, o));
                    }
                }
                71..=80 => {
                    exist.insert(o.clone());
                    let k = self.rng.range(0, 4);
                    let kv = (0..k)
                        .map(|_| {
                            (
                                format!("key{:02}", self.rng.below(30)).into_bytes(),
                                self.val(),
                            )
                        })
                        .collect();
                    ops.push(O::OmapSet(o, kv));
                }
                81..=84 => {
                    let ks = (0..self.rng.range(0, 3))
                        .map(|_| format!("key{:02}", self.rng.below(30)).into_bytes())
                        .collect();
                    ops.push(O::OmapRm(o, ks));
                }
                85..=86 => {
                    let a = self.rng.below(30);
                    ops.push(O::OmapRange(
                        o,
                        format!("key{a:02}").into_bytes(),
                        format!("key{:02}", a + self.rng.below(10)).into_bytes(),
                    ));
                }
                87 => ops.push(O::OmapClear(o)),
                88..=90 => {
                    exist.insert(o.clone());
                    let h = if self.rng.pct(30) { vec![] } else { self.val() };
                    ops.push(O::Hdr(o, h));
                }
                _ => ops.push(O::Hint(o)),
            }
        }
        for o in &ops {
            match o {
                O::Write(_, _, d) => payloads.push(d.clone()),
                O::SetAttrs(_, a) => a.iter().for_each(|(k, v)| {
                    payloads.push(k.clone());
                    payloads.push(v.clone())
                }),
                _ => {}
            }
        }
        // encode with borrowed data
        let mut build = Transaction::new();
        let bc = build.coll(&CollT::Pg(self.spg));
        macro_rules! ox {
            ($h:expr) => {
                build.obj(&self.g($h))
            };
        }
        let mut owned_pairs: Vec<Vec<(Vec<u8>, Vec<u8>)>> = Vec::new();
        for o in &ops {
            if let O::OmapSet(_, kv) | O::SetAttrs(_, kv) = o {
                owned_pairs.push(kv.clone());
            }
        }
        let mut pairs_i = 0;
        let rm_store: Vec<Vec<Vec<u8>>> = {
            let mut v = Vec::new();
            for o in &ops {
                if let O::OmapRm(_, k) = o {
                    v.push(k.clone());
                }
            }
            v
        };
        let mut rm_i = 0;
        for o in &ops {
            let op = match o {
                O::Touch(h) => TxnOp::Touch { oid: ox!(h) },
                O::Write(h, off, d) => TxnOp::Write {
                    oid: ox!(h),
                    off: *off,
                    data: Data::new(d),
                },
                O::Zero(h, off, len) => TxnOp::Zero {
                    oid: ox!(h),
                    off: *off,
                    len: *len,
                },
                O::Trunc(h, s) => TxnOp::Truncate {
                    oid: ox!(h),
                    size: *s,
                },
                O::Remove(h) => TxnOp::Remove { oid: ox!(h) },
                O::SetAttrs(h, _) => {
                    let p = &owned_pairs[pairs_i];
                    pairs_i += 1;
                    TxnOp::SetAttrs {
                        oid: ox!(h),
                        attrs: p
                            .iter()
                            .map(|(k, v)| (k.as_slice(), v.as_slice()))
                            .collect(),
                    }
                }
                O::RmAttr(h, n) => TxnOp::RmAttr {
                    oid: ox!(h),
                    name: n,
                },
                O::RmAttrs(h) => TxnOp::RmAttrs { oid: ox!(h) },
                O::Clone(s, d) => TxnOp::Clone {
                    oid: ox!(s),
                    dest_oid: ox!(d),
                },
                O::CloneRange(s, d, so, l, dof) => TxnOp::CloneRange2 {
                    oid: ox!(s),
                    dest_oid: ox!(d),
                    src_off: *so,
                    len: *l,
                    dest_off: *dof,
                },
                O::Rename(s, d) => {
                    if self.rng.pct(50) {
                        TxnOp::CollMoveRename {
                            oid: ox!(s),
                            dest_cid: bc,
                            dest_oid: ox!(d),
                        }
                    } else {
                        TxnOp::TryRename {
                            oid: ox!(s),
                            dest_oid: ox!(d),
                        }
                    }
                }
                O::OmapSet(h, _) => {
                    let p = &owned_pairs[pairs_i];
                    pairs_i += 1;
                    TxnOp::OmapSetKeys {
                        oid: ox!(h),
                        pairs: p
                            .iter()
                            .map(|(k, v)| (k.as_slice(), v.as_slice()))
                            .collect(),
                    }
                }
                O::OmapRm(h, _) => {
                    let k = &rm_store[rm_i];
                    rm_i += 1;
                    TxnOp::OmapRmKeys {
                        oid: ox!(h),
                        keys: k.iter().map(|k| k.as_slice()).collect(),
                    }
                }
                O::OmapRange(h, a, b) => TxnOp::OmapRmKeyRange {
                    oid: ox!(h),
                    first: a,
                    last: b,
                },
                O::OmapClear(h) => TxnOp::OmapClear { oid: ox!(h) },
                O::Hdr(h, d) => TxnOp::OmapSetHeader {
                    oid: ox!(h),
                    header: d,
                },
                O::Hint(h) => TxnOp::SetAllocHint {
                    oid: ox!(h),
                    expected_object_size: 4 << 20,
                    expected_write_size: 4096,
                    flags: 1,
                },
            };
            build.push(bc, op);
        }
        build.encode_v9().unwrap()
    }

    pub fn entry(&mut self, op: LogOp) -> LogEntry {
        self.ver += 1;
        let h = self.names[self.rng.below(self.names.len() as u64) as usize].clone();
        let mut e = LogEntry::new(
            op,
            h,
            Eversion::new(self.epoch, self.ver),
            Eversion::new(self.epoch, self.ver.saturating_sub(1)),
        );
        e.user_version = self.ver;
        e
    }

    pub fn dup_of(&self, e: &LogEntry) -> LogDup {
        LogDup::from_entry(e)
    }

    pub fn info(&mut self) -> PgInfo {
        let mut i = PgInfo::new(self.spg);
        i.last_update = Eversion::new(self.epoch, self.ver);
        i.last_complete = Eversion::new(self.epoch, self.ver.saturating_sub(self.rng.below(3)));
        i.log_tail = Eversion::new(self.epoch, self.ver.saturating_sub(10));
        i.last_epoch_started = self.rng.below(100) as u32;
        i.last_user_version = self.ver;
        i.history.epoch_created = 1 + self.rng.below(5) as u32;
        i.history.same_interval_since = self.epoch;
        i
    }

    pub fn past(&mut self) -> PastIntervals {
        PastIntervals::default()
    }

    pub fn missing_items(&mut self) -> Vec<(Hobject, Option<MissingItem>)> {
        (0..self.rng.range(1, 3))
            .map(|_| {
                let h = self.names[self.rng.below(self.names.len() as u64) as usize].clone();
                let it = self.rng.pct(70).then(|| {
                    MissingItem::new(
                        Eversion::new(self.epoch, self.rng.range(1, 99)),
                        Eversion::new(self.epoch, self.rng.below(50)),
                        self.rng.pct(20),
                    )
                });
                (h, it)
            })
            .collect()
    }
}

pub fn assert_same<A: PgStoreOps, B: PgStoreOps>(mem: &A, ad: &B, spg: SpgT, ctx: &str) {
    let (a, b) = (mem.load_pg(spg), ad.load_pg(spg));
    assert_eq!(a.is_some(), b.is_some(), "{ctx}: pg existence");
    if let (Some(a), Some(b)) = (&a, &b) {
        assert_eq!(a.info, b.info, "{ctx}: info");
        assert_eq!(a.log, b.log, "{ctx}: log");
        assert_eq!(a.missing, b.missing, "{ctx}: missing");
        assert_eq!(a.past_intervals, b.past_intervals, "{ctx}: past intervals");
        assert_eq!(a.epoch, b.epoch, "{ctx}: epoch");
    }
}

pub fn assert_same_objects(mem: &MemStore, ad: &Ad, spg: SpgT, ctx: &str) {
    let (mo, ao) = (mem.objects(spg), ad.objects(spg));
    assert_eq!(
        mo.keys().collect::<Vec<_>>(),
        ao.keys().collect::<Vec<_>>(),
        "{ctx}: object set"
    );
    for (h, m) in &mo {
        let a = &ao[h];
        assert_eq!(
            m.data.len(),
            a.data.len(),
            "{ctx}: {} size",
            String::from_utf8_lossy(&h.oid)
        );
        assert!(
            m.data == a.data,
            "{ctx}: {} data",
            String::from_utf8_lossy(&h.oid)
        );
        assert_eq!(
            m.xattrs,
            a.xattrs,
            "{ctx}: {} xattrs",
            String::from_utf8_lossy(&h.oid)
        );
        assert_eq!(
            m.omap,
            a.omap,
            "{ctx}: {} omap",
            String::from_utf8_lossy(&h.oid)
        );
        assert_eq!(
            m.omap_header,
            a.omap_header,
            "{ctx}: {} header",
            String::from_utf8_lossy(&h.oid)
        );
    }
    assert_eq!(
        mem.temp_objects(spg),
        ad.temp_objects(spg),
        "{ctx}: temp objects"
    );
    assert_eq!(mem.object_stats(spg), ad.object_stats(spg), "{ctx}: stats");
    for (min, max) in [(0, 3), (0, 1000), (5, 5)] {
        assert_eq!(
            mem.list_objects(spg, &Hobject::MIN(), min, max),
            ad.list_objects(spg, &Hobject::MIN(), min, max),
            "{ctx}: list_objects"
        );
    }
    // paged listing from the middle
    if let Some(h) = mo.keys().nth(mo.len() / 2) {
        assert_eq!(
            mem.list_objects(spg, h, 0, 4),
            ad.list_objects(spg, h, 0, 4),
            "{ctx}: list_objects mid"
        );
    }
    for h in mo.keys() {
        assert_eq!(
            mem.object_version(spg, h),
            ad.object_version(spg, h),
            "{ctx}: object_version"
        );
        let (ri_m, ri_a) = (mem.recovery_info(spg, h), ad.recovery_info(spg, h));
        assert_eq!(ri_m, ri_a, "{ctx}: recovery_info");
        if let Some(ri) = ri_m {
            let mut p = ObjectRecoveryProgress::default();
            for chunk in 0..200 {
                let (budget, omapn) = [(1 << 20, 100), (3000, 2), (700, 1)][chunk % 3];
                let (a, b) = (
                    mem.build_push(spg, &ri, &p, budget, omapn),
                    ad.build_push(spg, &ri, &p, budget, omapn),
                );
                assert_eq!(
                    a,
                    b,
                    "{ctx}: build_push chunk {chunk} of {}",
                    String::from_utf8_lossy(&h.oid)
                );
                let Ok(op) = a else { break };
                p = op.after_progress.clone();
                if p.is_complete() {
                    break;
                }
            }
        }
    }
}
