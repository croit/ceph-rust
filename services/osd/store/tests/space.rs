// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Space accounting bench (adr 0021 am. 54, doc/perf/space-vs-bluestore.md): the same datasets as the BlueStore model,
//! device footprint split into data / tree pages / slack / WAL / fixed / held, and the usable fill at ENOSPC.
//! Run: `cargo test --release -p store --test space -- --ignored --nocapture --test-threads=1`
//! (env `SPACE_SCALE` percent of the default dataset sizes, default 100; `SPACE_ONLY` substring of the dataset name).
#![allow(clippy::too_many_arguments)]
#[path = "common/objmodel.rs"]
mod objmodel;

use denc::types::{CollT, Ghobject, Hobject, ShardId, SnapId};
use objmodel::*;
use store::dev::{SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::{OTxn, ObjError, Store, StoreCfg};
use store::rng::Rng;

type St = Store<SimDev, SimClock>;

const BLK: u64 = 4096;
const SHARDS: u32 = 8;
const CAP_MIB: u64 = 20 * 1024;

fn g(oid: &[u8], hash: u32) -> Ghobject {
    Ghobject::new(
        Hobject::new(oid, SnapId::NOSNAP, hash, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

fn scale() -> u64 {
    std::env::var("SPACE_SCALE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
}

fn wanted(name: &str) -> bool {
    std::env::var("SPACE_ONLY").map_or(true, |s| name.contains(&s))
}

struct Rig {
    st: St,
    cap_blocks: u64,
    /// logical bytes (data + attr/omap keys and values) and the BlueStore model of the same objects
    logical: u64,
    bs: Bs,
}

fn rig_p(cap_mib: u64, shards: u32, mut p: MkfsParams, mut cfg: StoreCfg) -> Rig {
    let mut sim = SimConfig::new(cap_mib << 20);
    sim.seed = 7;
    let disk = SimDisk::new(sim.clone());
    p.shards = shards;
    mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
    cfg.shard.cache_pages = 4 << 20; // keep the whole tree resident: shape() sees every page
    let d2 = disk.clone();
    let (st, _) = Store::mount(move || d2.queue(), SimClock::default(), cfg).unwrap();
    Rig {
        st,
        cap_blocks: (cap_mib << 20) / BLK,
        logical: 0,
        bs: Bs::default(),
    }
}

fn rig(cap_mib: u64, shards: u32) -> Rig {
    let p = MkfsParams {
        wal_blocks: store::layout::wal_blocks_for(cap_mib << 20, shards),
        align_blocks: 256,
        meta_pct: 2,
        ..Default::default()
    };
    rig_p(cap_mib, shards, p, StoreCfg::default())
}

fn commit(st: &mut St, t: &OTxn) -> Result<(), ObjError> {
    st.commit(t)
}

// ------------------------------------------------------------------ BlueStore model (doc/perf/space-vs-bluestore.md)

/// Model of what BlueStore (v21, SSD, min_alloc 4 KiB, csum crc32c per 4 KiB, max blob 64 KiB, RocksDB LZ4 default,
/// `max_total_wal_size` 1 GiB) stores for the same objects. All numbers in bytes; see the doc for derivation.
#[derive(Default, Clone, Copy)]
struct Bs {
    /// allocated data (4 KiB units)
    data: u64,
    /// live key-value bytes in RocksDB (onode keys + values incl. extent maps + omap rows)
    kv: u64,
}

impl Bs {
    /// onode key ('O' + shard/pool/hash/name/snap/gen/ghobject framing) for an object name of `n` bytes.
    fn onode_key(n: usize) -> u64 {
        30 + n as u64
    }
    /// An object: name length, attrs (name, value) lengths, extent-map entries, data length.
    fn obj(
        &mut self,
        name: usize,
        attrs: &[(usize, usize)],
        lext: u64,
        blobs: u64,
        csum_blocks: u64,
        data_bytes: u64,
    ) {
        let a: u64 = attrs.iter().map(|(n, v)| 6 + *n as u64 + *v as u64).sum();
        // onode_t header ~48 B; lextent ~6 B; blob ~14 B + pextent 6 B + 4 B csum per 4 KiB; shard key overhead 8 %
        let em = (lext * 6 + blobs * 20 + csum_blocks * 4) as f64 * 1.08;
        self.kv += Self::onode_key(name) + 48 + a + em as u64;
        self.data += data_bytes.div_ceil(BLK) * BLK;
    }
    /// omap rows: BlueStore stores one KV row per omap key: prefix 'M' + 8 B onode nid + 1 + key; value as is.
    fn omap(&mut self, k: usize, v: usize) {
        self.kv += 10 + k as u64 + v as u64;
    }
    /// extra lextents/blobs from `n` aligned 4 KiB overwrites inside already-written objects
    fn overwrite4k(&mut self, n: u64) {
        // +2 lextents (new + split of the old one), +1 blob (4 KiB, 1 csum), +1 pextent split in the old blob
        self.kv += ((n * (2 * 6 + 20 + 6 + 4)) as f64 * 1.08) as u64;
    }
    /// total device bytes: data + RocksDB space amplification (leveled, dynamic level bytes, ~1.25) + WAL average
    /// (bounded by 1 GiB; model 512 MiB) + BlueFS min allocation (1 MiB per file, ~16 files).
    fn total(&self) -> u64 {
        self.data + (self.kv as f64 * 1.25) as u64 + (512 << 20) + (16 << 20)
    }
    /// same without the constant part (comparable with our tree + data without WAL / fixed areas)
    fn net(&self) -> u64 {
        self.data + (self.kv as f64 * 1.25) as u64
    }
}

// ------------------------------------------------------------------ accounting

#[derive(Default, Clone, Copy)]
struct Acct {
    data: u64,
    tree_used: u64,
    tree_leaf_fill: f64,
    cells_slack: u64,
    base_used: u64,
    base_free: u64,
    held: u64,
    reclaim: u64,
    wal: u64,
    other: u64,
    reserve: u64,
    free: u64,
}

fn acct(r: &Rig) -> Acct {
    let mut a = Acct::default();
    let (mut leaf_used, mut leaves) = (0u64, 0u64);
    let mut region_sum = 0u64;
    let page = 8192u64;
    for s in &r.st.shards {
        let f = s.sh.statfs();
        let bpp = f.meta_bpp;
        let cells = f.meta_cell_blocks;
        a.data += (f.data_used - cells.min(f.data_used)) * BLK;
        let cell_used = f.meta_cell_used * bpp;
        a.tree_used += cell_used * BLK;
        a.cells_slack += (cells - cell_used.min(cells)) * BLK;
        let base_used = (f.meta_used - f.meta_cell_used) * bpp;
        a.base_used += base_used * BLK;
        a.base_free += (f.meta_base_pages * bpp - base_used.min(f.meta_base_pages * bpp)) * BLK;
        a.held += f.data_held * BLK;
        a.reclaim += f.data_reclaim * BLK;
        a.wal += f.wal_blocks * BLK;
        a.reserve += (f.data_reserve + f.meta_reserve * bpp) * BLK;
        a.free += f.data_free * BLK;
        region_sum += f.data_blocks + f.meta_base_pages * bpp + f.wal_blocks;
        let sh = s.sh.state().tree.shape();
        leaf_used += sh.leaf_used;
        leaves += sh.leaves;
    }
    a.tree_leaf_fill = leaf_used as f64 / (leaves.max(1) * page) as f64;
    a.other = (r.cap_blocks * BLK).saturating_sub(region_sum * BLK);
    a
}

fn mib(b: u64) -> String {
    format!("{:.1}", b as f64 / (1 << 20) as f64)
}

fn report(name: &str, r: &Rig) {
    let a = acct(r);
    let net = a.data + a.tree_used + a.cells_slack + a.base_used + a.held;
    let gross = net + a.base_free + a.wal + a.other;
    let bsn = r.bs.net();
    eprintln!(
        "== {name}: logical {} MiB, {} shards, device {} MiB",
        mib(r.logical),
        SHARDS,
        mib(r.cap_blocks * BLK)
    );
    eprintln!(
        "   data {} | tree used {} (leaf fill {:.0}%) | cell slack {} | base used {} / free {} | held {} (reclaim {}) | wal {} | fixed/other {} | reserve(unusable floor) {}",
        mib(a.data),
        mib(a.tree_used + a.base_used),
        a.tree_leaf_fill * 100.0,
        mib(a.cells_slack),
        mib(a.base_used),
        mib(a.base_free),
        mib(a.held),
        mib(a.reclaim),
        mib(a.wal),
        mib(a.other),
        mib(a.reserve)
    );
    eprintln!(
        "   NET (data+tree+slack+held) {} MiB = {:.3}x logical | GROSS (+wal+fixed+free base) {} MiB | BS model: data {} + kv {} (x1.25) = net {} MiB ({:.3}x logical), total {} MiB | ours/BS net {:.3}",
        mib(net),
        net as f64 / r.logical.max(1) as f64,
        mib(gross),
        mib(r.bs.data),
        mib(r.bs.kv),
        mib(bsn),
        bsn as f64 / r.logical.max(1) as f64,
        mib(r.bs.total()),
        net as f64 / bsn.max(1) as f64
    );
}

fn md(oid: &[u8]) -> Ghobject {
    g(oid, crc_hash(oid))
}

fn crc_hash(b: &[u8]) -> u32 {
    let mut h = 2166136261u32;
    for x in b {
        h = (h ^ *x as u32).wrapping_mul(16777619);
    }
    h
}

/// PG collection of an object: `pgs` PGs of pool 1.
fn coll_of(o: &Ghobject, pgs: u32) -> CollT {
    pgc(1, crc_hash(&o.hobj.oid) % pgs)
}

fn mkcolls(r: &mut Rig, pgs: u32) {
    for p in 0..pgs {
        let mut t = OTxn::new();
        t.mkcoll(pgc(1, p));
        commit(&mut r.st, &t).unwrap();
    }
}

/// OSD-like object_info (`_`, 260 B for an RBD data object) + snapset (31 B).
fn attrs() -> (Vec<u8>, Vec<u8>) {
    let mut rng = Rng::new(5);
    let mut a = vec![0u8; 260];
    rng.fill(&mut a);
    (a, vec![1u8; 31])
}

const PGS: u32 = 64;

fn data_pattern(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|i| ((i / 4096) as u8).wrapping_add(salt))
        .collect()
}

/// (a) RBD-like: `n` objects of 4 MiB written fully.
fn ds_a(r: &mut Rig, n: u32, base: u32) {
    let (a, s) = attrs();
    let buf = data_pattern(4 << 20, 1);
    for i in 0..n {
        let name = format!("rbd_data.1234abcd5678.{:016x}", base + i);
        let o = md(name.as_bytes());
        let c = coll_of(&o, PGS);
        let mut t = OTxn::new();
        t.write(c, &o, 0, &buf);
        t.setattr(c, &o, b"_", &a);
        t.setattr(c, &o, b"snapset", &s);
        commit(&mut r.st, &t).unwrap();
        r.logical += (4 << 20) + 260 + 31 + 1 + 7;
        r.bs.obj(name.len(), &[(1, 260), (7, 31)], 64, 64, 1024, 4 << 20);
    }
}

/// (b) full 4 MiB objects of an image + `ow` random 4 KiB overwrites (each with an object_info rewrite).
fn ds_b(r: &mut Rig, objs: u32, ow: u64, base: u32) {
    ds_a(r, objs, base);
    let (a, _) = attrs();
    let blk = vec![0xabu8; 4096];
    let mut rng = Rng::new(11);
    for _ in 0..ow {
        let i = base + (rng.next_u64() % objs as u64) as u32;
        let off = (rng.next_u64() % 1024) * 4096;
        let name = format!("rbd_data.1234abcd5678.{:016x}", i);
        let o = md(name.as_bytes());
        let c = coll_of(&o, PGS);
        let mut t = OTxn::new();
        t.write(c, &o, off, &blk);
        t.setattr(c, &o, b"_", &a);
        commit(&mut r.st, &t).unwrap();
    }
    r.bs.overwrite4k(ow);
}

fn ds_small(r: &mut Rig, n: u32, lo: usize, hi: usize, tag: &str) {
    let (a, s) = attrs();
    let extra = vec![7u8; 20];
    let mut rng = Rng::new(21);
    for i in 0..n {
        let name = format!("{tag}_{i:010}");
        let o = md(name.as_bytes());
        let c = coll_of(&o, PGS);
        let len = lo + (rng.next_u64() % (hi - lo + 1) as u64) as usize;
        let buf = data_pattern(len, 3);
        let mut t = OTxn::new();
        t.write(c, &o, 0, &buf);
        t.setattr(c, &o, b"_", &a);
        t.setattr(c, &o, b"snapset", &s);
        t.setattr(c, &o, b"user.x", &extra);
        commit(&mut r.st, &t).unwrap();
        r.logical += len as u64 + 260 + 31 + 20 + 1 + 7 + 6;
        let blobs = (len as u64).div_ceil(65536).max(1);
        r.bs.obj(
            name.len(),
            &[(1, 260), (7, 31), (6, 20)],
            blobs,
            blobs,
            (len as u64).div_ceil(4096),
            len as u64,
        );
    }
}

fn ds_omap(r: &mut Rig, objs: u32, keys: u32, vlen: usize) {
    let (a, s) = attrs();
    // incompressible values: BlueStore's RocksDB uses LZ4 by default, ours has no omap compression (adr 0021 am. 54)
    let mut val = vec![0u8; vlen];
    Rng::new(77).fill(&mut val);
    for i in 0..objs {
        let name = format!("omapobj_{i:08}");
        let o = md(name.as_bytes());
        let c = coll_of(&o, PGS);
        let kv: Vec<String> = (0..keys).map(|k| format!("key_{k:08}")).collect();
        let mut t = OTxn::new();
        t.touch(c, &o);
        t.setattr(c, &o, b"_", &a);
        t.setattr(c, &o, b"snapset", &s);
        for k in &kv {
            t.omap_set(c, &o, k.as_bytes(), &val);
        }
        commit(&mut r.st, &t).unwrap();
        r.logical += (keys as u64) * (12 + vlen as u64) + 260 + 31 + 8;
        r.bs.obj(name.len(), &[(1, 260), (7, 31)], 0, 0, 0, 0);
        for _ in 0..keys {
            r.bs.omap(12, vlen);
        }
    }
}

fn remove_every_other(r: &mut Rig, n_a: u32, base_a: u32, n_b: u32, base_b: u32) {
    for (n, base) in [(n_a, base_a), (n_b, base_b)] {
        for i in (0..n).step_by(2) {
            let name = format!("rbd_data.1234abcd5678.{:016x}", base + i);
            let o = md(name.as_bytes());
            let c = coll_of(&o, PGS);
            let mut t = OTxn::new();
            t.remove(c, &o);
            commit(&mut r.st, &t).unwrap();
        }
    }
}

fn sz(def: u64) -> u64 {
    (def * scale() / 100).max(1)
}

#[test]
#[ignore = "measurement"]
fn space_datasets() {
    // (a) 1 GiB of 4 MiB objects
    if wanted("a") {
        let mut r = rig(CAP_MIB, SHARDS);
        mkcolls(&mut r, PGS);
        ds_a(&mut r, sz(256) as u32, 0);
        r.st.checkpoint().unwrap();
        report("a: 4 MiB RBD objects, written fully", &r);
    }
    // (b) 8 GiB image (2048 objects) + 4 KiB random overwrites
    if wanted("b") {
        let mut r = rig(CAP_MIB, SHARDS);
        mkcolls(&mut r, PGS);
        ds_b(&mut r, sz(2048) as u32, sz(1_000_000), 0);
        r.st.checkpoint().unwrap();
        report("b: 8 GiB RBD image + 4K random overwrites", &r);
    }
    if wanted("c") {
        let mut r = rig(CAP_MIB, SHARDS);
        mkcolls(&mut r, PGS);
        ds_small(&mut r, sz(100_000) as u32, 1024, 4096, "smallobj");
        r.st.checkpoint().unwrap();
        report("c: 100k objects 1-4 KiB + 311 B attrs", &r);
    }
    if wanted("d") {
        let mut r = rig(CAP_MIB, SHARDS);
        mkcolls(&mut r, PGS);
        ds_small(&mut r, sz(40_000) as u32, 5 * 1024, 64 * 1024, "midobj");
        r.st.checkpoint().unwrap();
        report("d: 40k objects 5-64 KiB", &r);
    }
    if wanted("e") {
        let mut r = rig(CAP_MIB, SHARDS);
        mkcolls(&mut r, PGS);
        ds_omap(&mut r, sz(10_000) as u32, 100, 100);
        r.st.checkpoint().unwrap();
        report("e: omap 10k objects x 100 keys x 100 B", &r);
    }
    if wanted("f") {
        let mut r = rig(CAP_MIB, SHARDS);
        mkcolls(&mut r, PGS);
        let (na, nb) = (sz(256) as u32, sz(1024) as u32);
        ds_a(&mut r, na, 0);
        ds_b(&mut r, nb, sz(500_000), 1_000_000);
        r.st.checkpoint().unwrap();
        report("f0: (a)+(b) before delete", &r);
        let before = r.logical;
        let bs_before = r.bs;
        remove_every_other(&mut r, na, 0, nb, 1_000_000);
        // the logical model after the delete: half of each (overwrite share halves too)
        r.logical = before / 2;
        r.bs = Bs {
            data: bs_before.data / 2,
            kv: bs_before.kv / 2,
        };
        report("f1: after deleting 50 %, BEFORE checkpoint (held)", &r);
        r.st.checkpoint().unwrap();
        report("f2: after checkpoint", &r);
        r.st.checkpoint().unwrap();
        report("f3: after 2nd checkpoint", &r);
    }
}

#[test]
#[ignore = "measurement"]
fn space_fixed_areas() {
    eprintln!("== fixed areas of production devices (layout::plan, no data)");
    for (tb, shards) in [(1.92f64, 8u32), (1.92, 32), (7.68, 8), (7.68, 32)] {
        let bytes = (tb * 1e12) as u64;
        let blocks = bytes / BLK;
        let old = MkfsParams {
            shards,
            wal_blocks: store::layout::wal_blocks_for(bytes, shards),
            align_blocks: 262_144,
            ..MkfsParams::default()
        };
        for (tag, p) in [
            ("before", old),
            ("now   ", MkfsParams::for_device(bytes, shards)),
        ] {
            let (_, dirs) = store::layout::plan(blocks, &p).unwrap();
            let wal: u64 = dirs.iter().map(|d| d.wal_blocks).sum();
            let meta: u64 = dirs.iter().map(|d| d.meta_blocks).sum();
            let data: u64 = dirs.iter().map(|d| d.data_blocks).sum();
            let other = blocks - wal - meta - data;
            let pct = |x: u64| x as f64 * 100.0 / blocks as f64;
            let gib = |x: u64| (x * BLK) as f64 / (1u64 << 30) as f64;
            eprintln!(
                "   {tag} {tb} TB, {shards:>2} shards: wal {:.1} GiB ({:.2}%), meta base {:.1} GiB ({:.2}%), align/sb/roots {:.2} GiB ({:.2}%)",
                gib(wal),
                pct(wal),
                gib(meta),
                pct(meta),
                gib(other),
                pct(other)
            );
        }
    }
}

/// Usable fill at the first refused write: objects of `len` bytes spread over `pgs` PGs (fewer PGs than shards or
/// uneven = imbalance), returns (used% of capacity by data+tree at refusal, objects stored, logical payload %).
fn fill_until_full(pgs: u32, len: usize, p: MkfsParams) -> (f64, u64, f64) {
    fill_until_full_cfg(pgs, len, p, StoreCfg::default())
}

fn fill_until_full_cfg(pgs: u32, len: usize, p: MkfsParams, cfg: StoreCfg) -> (f64, u64, f64) {
    let mut r = rig_p(1024, SHARDS, p, cfg);
    mkcolls(&mut r, pgs);
    let (a, s) = attrs();
    let buf = data_pattern(len, 9);
    let mut n = 0u64;
    let mut rng = Rng::new(99);
    loop {
        let name = format!("fill_{n:012}");
        let o = md(name.as_bytes());
        let c = pgc(1, (rng.next_u64() % pgs as u64) as u32);
        let mut t = OTxn::new();
        t.write(c, &o, 0, &buf);
        t.setattr(c, &o, b"_", &a);
        t.setattr(c, &o, b"snapset", &s);
        match commit(&mut r.st, &t) {
            Ok(()) => n += 1,
            Err(_) => break,
        }
    }
    r.st.checkpoint().ok();
    let a = acct(&r);
    let used = a.data + a.tree_used + a.cells_slack + a.base_used;
    let cap = r.cap_blocks * BLK;
    (
        used as f64 * 100.0 / cap as f64,
        n,
        n as f64 * (len as f64 + 291.0) * 100.0 / cap as f64,
    )
}

#[test]
#[ignore = "measurement"]
fn space_stranding() {
    eprintln!(
        "== usable fill at first refused write, 1 GiB device, {SHARDS} shards (net used% | logical payload% of capacity)"
    );
    for (label, pgs) in [
        ("64 PGs (balanced)", 64u32),
        ("12 PGs (2x imbalance)", 12),
        ("5 PGs (3 shards empty)", 5),
        ("1 PG (7 shards empty)", 1),
    ] {
        for len in [4096usize, 65536, 4 << 20] {
            let p = MkfsParams {
                wal_blocks: 2048,
                align_blocks: 256,
                meta_pct: 2,
                ..Default::default()
            };
            let (used, n, logical) = fill_until_full(pgs, len, p);
            eprintln!(
                "   {label:<26} obj {len:>8} B: used {used:5.1}% of device, logical {logical:5.1}%, {n} objects"
            );
        }
    }
}

/// Same fill with the elastic pool (adr 0021 am. 47-53): chunked store, base_pct, lending on (all shards in one store).
#[cfg(feature = "elastic")]
#[test]
#[ignore = "measurement"]
fn space_stranding_elastic() {
    eprintln!(
        "== ELASTIC: usable fill at first refused write, 1 GiB device, {SHARDS} shards, 1 MiB chunks, lend_auto (net used% | logical payload% of capacity)"
    );
    let bases: Vec<u32> = std::env::var("SPACE_BASES")
        .unwrap_or("75,50".into())
        .split(',')
        .map(|s| s.parse().unwrap())
        .collect();
    let wm: Option<u32> = std::env::var("SPACE_WM").ok().map(|s| s.parse().unwrap());
    for base_pct in bases {
        for (label, pgs) in [
            ("64 PGs (balanced)", 64u32),
            ("12 PGs (2x imbalance)", 12),
            ("5 PGs (3 shards empty)", 5),
            ("1 PG (7 shards empty)", 1),
        ] {
            for len in [4096usize, 65536, 4 << 20] {
                let p = MkfsParams {
                    wal_blocks: 2048,
                    align_blocks: 256,
                    meta_pct: 2,
                    chunked: true,
                    chunk_blocks: 256,
                    base_pct,
                    ..Default::default()
                };
                let mut cfg = StoreCfg::default();
                cfg.shard.lend_auto = true;
                cfg.shard.lend_owner = true;
                if let Some(w) = wm {
                    cfg.shard.lend_wm_pct = w;
                }
                let (used, n, logical) = fill_until_full_cfg(pgs, len, p, cfg);
                eprintln!(
                    "   base {base_pct}% {label:<24} obj {len:>8} B: used {used:5.1}% of device, logical {logical:5.1}%, {n} objects"
                );
            }
        }
    }
}
