// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
#![allow(
    clippy::allow_attributes,
    dead_code,
    clippy::field_reassign_with_default
)]
use denc::types::{CollT, Eversion, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT, UTime, Uuid};
use messages::OsdSuperblock;
use osd::meta::{MapKind, MetaStore};
use osd::nvmestore::{NvmeMeta, open_nvme};
use ostool::{Ctx, Opts};
use peering::{StoreOp, StoreTxn};
use pgwire::{LogEntry, LogOp, PgInfo};
use replwire::ObjectInfo;
use std::collections::BTreeMap;
use store::dev::{SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::{OTxn, Store, StoreCfg};
use storeadapt::StoreAdapter;

pub const FSID: Uuid = Uuid([7; 16]);

pub struct Rig {
    pub disk: SimDisk,
    pub ad: StoreAdapter<SimDev, SimClock>,
    pub meta: NvmeMeta<SimDev, SimClock>,
}

pub fn new_disk(cap_mib: u64) -> SimDisk {
    new_disk_shards(cap_mib, 2)
}

/// A fresh mkfs'd disk with `shards` shards (the normal [`new_disk`] uses 2).
pub fn new_disk_shards(cap_mib: u64, shards: u32) -> SimDisk {
    let mut sim = SimConfig::new(cap_mib << 20);
    sim.seed = 11;
    let disk = SimDisk::new(sim);
    let p = MkfsParams {
        shards,
        wal_blocks: 1024,
        align_blocks: 1,
        meta_pct: 8,
        node_size: 8192,
        ..Default::default()
    };
    mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
    disk
}

pub fn mount(disk: &SimDisk) -> Rig {
    let d = disk.clone();
    let (st, _) =
        Store::mount(move || d.queue(), SimClock::default(), StoreCfg::default()).unwrap();
    let parts = open_nvme(st).unwrap();
    Rig {
        disk: disk.clone(),
        ad: parts.pgs,
        meta: parts.meta,
    }
}

/// Fresh OSD with a map at `epoch` containing pool 1 (pg_num 8, replicated) and a superblock.
pub fn rig(epoch: u32) -> Rig {
    let disk = new_disk(256);
    let mut r = mount(&disk);
    seed_maps(&mut r, epoch, &[1]);
    r
}

pub fn osdmap_at(epoch: u32, pools: &[i64]) -> osdmap::OsdMap {
    let mut m = osdmap::OsdMap::default();
    m.epoch = epoch;
    for &p in pools {
        let mut pool = osdmap::PgPool::default();
        pool.pg_num = 8;
        pool.pgp_num = 8;
        pool.size = 3;
        pool.min_size = 2;
        m.pools.insert(p, pool);
        m.pool_name.insert(p, format!("pool{p}").into());
        m.pool_max = m.pool_max.max(p as i32);
    }
    m
}

pub fn seed_maps(r: &mut Rig, epoch: u32, pools: &[i64]) {
    let mut blobs = Vec::new();
    for e in 1..=epoch {
        blobs.push((e, MapKind::Full, osdmap_at(e, pools).encode_full().unwrap()));
    }
    let mut sb = OsdSuperblock::default();
    sb.cluster_fsid = FSID;
    sb.whoami = 3;
    sb.current_epoch = epoch;
    sb.osd_fsid = Uuid([9; 16]);
    sb.compat_features = messages::types::CompatSet::osd_initial();
    sb.mapc.insert(1, epoch);
    r.meta.commit_maps(&blobs, &sb).unwrap();
}

pub fn spg(pool: u64, seed: u32) -> SpgT {
    SpgT {
        pgid: PgT::new(pool, seed),
        shard: ShardId::NO_SHARD,
    }
}

pub fn hobj(spg: SpgT, name: &str, snap: SnapId) -> Hobject {
    // hash chosen so that the object belongs to the PG at pg_num 8
    let mut h = 0u32;
    for b in name.bytes() {
        h = h.wrapping_mul(31).wrapping_add(u32::from(b));
    }
    h = (h & !7) | (spg.pgid.seed & 7);
    Hobject::new(name.as_bytes(), snap, h, spg.pgid.pool as i64, b"")
}

pub fn gh(spg: SpgT, h: &Hobject) -> Ghobject {
    Ghobject::new(h.clone(), Ghobject::NO_GEN, spg.shard)
}

pub fn oi_bytes(h: &Hobject, ver: Eversion, size: u64) -> Vec<u8> {
    let mut oi = ObjectInfo::new(h.clone());
    oi.version = ver;
    oi.prior_version = Eversion::new(ver.epoch, ver.version.saturating_sub(1));
    oi.size = size;
    oi.user_version = ver.version;
    oi.mtime = UTime {
        sec: 1_700_000_000,
        nsec: 5,
    };
    denc::to_vec(&oi).unwrap()
}

pub fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed))
        .collect()
}

/// One populated object.
pub struct Obj {
    pub name: &'static str,
    pub snap: SnapId,
    pub data: Vec<u8>,
    pub attrs: Vec<(&'static str, Vec<u8>)>,
    pub omap: Vec<(String, Vec<u8>)>,
    pub hdr: Vec<u8>,
}

/// PG with log, info and objects (incl. a clone with SnapMapper entry).
pub fn make_pg(r: &Rig, s: SpgT, nlog: u64) -> Vec<Obj> {
    let ad = &r.ad;
    ad.try_submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::CreatePg],
        },
    )
    .unwrap();
    let cid = CollT::Pg(s);
    let mut objs = vec![
        Obj {
            name: "small",
            snap: SnapId::NOSNAP,
            data: pattern(1000, 1),
            attrs: vec![("_user.k", b"v1".to_vec())],
            omap: vec![],
            hdr: vec![],
        },
        Obj {
            name: "big",
            snap: SnapId::NOSNAP,
            data: pattern(3 * 1024 * 1024 + 123, 2),
            attrs: vec![("_a", vec![0, 1, 2, 255]), ("_b", vec![])],
            omap: vec![],
            hdr: vec![],
        },
        Obj {
            name: "omapobj",
            snap: SnapId::NOSNAP,
            data: vec![],
            attrs: vec![],
            omap: (0..60)
                .map(|i| (format!("key{i:03}"), pattern(i + 3, i as u8)))
                .collect(),
            hdr: b"header-bytes".to_vec(),
        },
        Obj {
            name: "snapped",
            snap: SnapId(4),
            data: pattern(5000, 4),
            attrs: vec![],
            omap: vec![],
            hdr: vec![],
        },
    ];
    let mut ver = 0u64;
    let mut entries = Vec::new();
    for o in &objs {
        ver += 1;
        let h = hobj(s, o.name, o.snap);
        let g = gh(s, &h);
        let v = Eversion::new(3, ver);
        let mut t = OTxn::new();
        t.sys = true;
        t.touch(cid, &g);
        if !o.data.is_empty() {
            t.write(cid, &g, 0, &o.data);
        }
        let oi = oi_bytes(&h, v, o.data.len() as u64);
        t.setattr(cid, &g, b"_", &oi);
        let ss0 = denc::to_vec(&replwire::SnapSet::default()).unwrap();
        if o.snap == SnapId::NOSNAP {
            t.setattr(cid, &g, b"snapset", &ss0);
        }
        for (k, val) in &o.attrs {
            t.setattr(cid, &g, k.as_bytes(), val);
        }
        for (k, val) in &o.omap {
            t.omap_set(cid, &g, k.as_bytes(), val);
        }
        if !o.hdr.is_empty() {
            t.push(store::obj::TOp::OmapSetHeader {
                cid,
                oid: g.clone(),
                header: o.hdr.clone().into(),
            });
        }
        ad.with_store(|st| st.commit(&t)).unwrap();
        entries.push(LogEntry::new(
            LogOp::MODIFY,
            h,
            v,
            Eversion::new(3, ver - 1),
        ));
    }
    // head "snapped" with a clone-snapset: clone at snap 4 serves snaps [4]
    let head = hobj(s, "snapped", SnapId::NOSNAP);
    let hg = gh(s, &head);
    let mut ss = replwire::SnapSet::default();
    ss.seq = 4;
    ss.clones = vec![SnapId(4)];
    ss.clone_size.insert(SnapId(4), 5000);
    ss.clone_snaps.insert(SnapId(4), vec![SnapId(4)]);
    let ssb = denc::to_vec(&ss).unwrap();
    let mut t = OTxn::new();
    t.sys = true;
    t.touch(cid, &hg);
    let hoi = oi_bytes(&head, Eversion::new(3, 9), 0);
    t.setattr(cid, &hg, b"_", &hoi);
    t.setattr(cid, &hg, b"snapset", &ssb);
    ad.with_store(|st| st.commit(&t)).unwrap();
    ad.try_submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::SnapMap(vec![peering::snaps::MapOp::Set {
                clone: hobj(s, "snapped", SnapId(4)),
                snaps: vec![4],
            }])],
        },
    )
    .unwrap();
    // more log entries to exercise chunking
    for _ in 0..nlog {
        ver += 1;
        let h = hobj(s, "small", SnapId::NOSNAP);
        entries.push(LogEntry::new(
            LogOp::MODIFY,
            h,
            Eversion::new(3, ver),
            Eversion::new(3, ver - 1),
        ));
    }
    let head_v = Eversion::new(3, ver);
    let mut info = PgInfo::new(s);
    info.last_update = head_v;
    info.last_complete = head_v;
    info.log_tail = Eversion::new(0, 0);
    info.history.epoch_created = 1;
    info.history.last_epoch_started = 3;
    info.history.last_epoch_clean = 3;
    info.history.same_interval_since = 2;
    info.last_epoch_started = 3;
    info.last_user_version = ver;
    ad.try_submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::PutInfo(Box::new(info)), StoreOp::PutEpoch(5)],
        },
    )
    .unwrap();
    // log in chunks (a single big append would not fit a WAL unit for large nlog)
    for ch in entries.chunks(100) {
        ad.try_submit(
            s,
            &StoreTxn {
                ops: vec![StoreOp::LogAppend(ch.to_vec())],
            },
        )
        .unwrap();
    }
    objs.push(Obj {
        name: "snapped",
        snap: SnapId::NOSNAP,
        data: vec![],
        attrs: vec![],
        omap: vec![],
        hdr: vec![],
    });
    objs
}

pub struct Out {
    pub code: i32,
    pub out: Vec<u8>,
    pub err: String,
}
impl Out {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.out).into_owned()
    }
}

/// Run the tool on `r` with classic-style arguments.
pub fn run(r: &mut Rig, args: &[&str], stdin: &[u8]) -> Out {
    run_read(r, args, Box::new(std::io::Cursor::new(stdin.to_vec())))
}

/// [`run`] with a caller-supplied stdin: a reader that fails (or crashes the disk) mid-way.
pub fn run_read(r: &mut Rig, args: &[&str], input: Box<dyn std::io::Read + '_>) -> Out {
    let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let o = Opts::parse(&a).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = drive(r, &o, &mut out, &mut err, input);
    Out {
        code,
        out,
        err: String::from_utf8_lossy(&err).into_owned(),
    }
}

/// [`run`] with stdout discarded: measures the command's own buffering, not the collected result.
pub fn run_sink(r: &mut Rig, args: &[&str]) -> Out {
    let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let o = Opts::parse(&a).unwrap();
    let (mut err, mut sink) = (Vec::new(), std::io::sink());
    let code = drive(r, &o, &mut sink, &mut err, Box::new(std::io::empty()));
    Out {
        code,
        out: Vec::new(),
        err: String::from_utf8_lossy(&err).into_owned(),
    }
}

fn drive(
    r: &mut Rig,
    o: &Opts,
    out: &mut dyn std::io::Write,
    err: &mut Vec<u8>,
    input: Box<dyn std::io::Read + '_>,
) -> i32 {
    let mut c = Ctx {
        ad: &r.ad,
        meta: &mut r.meta,
        o,
        out,
        err,
        input: Some(input),
    };
    ostool::run(&mut c)
}

/// Crash-restart: drop the in-memory store and mount again from what is durable.
pub fn remount(r: Rig) -> Rig {
    let disk = r.disk.clone();
    drop(r);
    mount(&disk)
}

/// Ghobject of a meta collection object (the construction `osd::nvmestore` uses for `superblock` and the maps).
pub fn meta_object(name: &str) -> Ghobject {
    Ghobject::new(
        Hobject::new(name.as_bytes(), SnapId(0), 0, Hobject::POOL_META, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

pub type Snap = BTreeMap<
    Vec<u8>,
    (
        Vec<u8>,
        BTreeMap<Vec<u8>, Vec<u8>>,
        BTreeMap<Vec<u8>, Vec<u8>>,
        Vec<u8>,
    ),
>;

/// Everything of the PG's user objects + the snap mapper object, keyed by the encoded ghobject.
pub fn snapshot(r: &Rig, s: denc::types::SpgT) -> Snap {
    let cid = CollT::Pg(s);
    let mut out = Snap::new();
    let mut cur = Ghobject::MIN();
    loop {
        let (objs, next) =
            r.ad.with_store(|st| st.list(&cid, &cur, None, 100))
                .unwrap();
        for g in objs {
            if g == storeadapt::pgmeta(s) {
                continue;
            }
            let (data, attrs, omap, hdr) =
                r.ad.with_store(|st| {
                    let size = st.stat(&cid, &g)?.map_or(0, |x| x.size);
                    Ok::<_, store::obj::ObjError>((
                        st.read(&cid, &g, 0, size)?,
                        st.getattrs(&cid, &g)?,
                        st.omap_all(&cid, &g)?,
                        st.omap_header(&cid, &g)?,
                    ))
                })
                .unwrap();
            out.insert(
                denc::to_vec(&g.hobj).unwrap(),
                (
                    data,
                    attrs.into_iter().collect(),
                    omap.into_iter().collect(),
                    hdr,
                ),
            );
        }
        match next {
            Some(n) => cur = n,
            None => return out,
        }
    }
}

pub fn list_pgs(r: &mut Rig) -> Vec<String> {
    let o = run(r, &["--op", "list-pgs"], b"");
    assert_eq!(o.code, 0, "{}", o.err);
    o.text().lines().map(str::to_owned).collect()
}
