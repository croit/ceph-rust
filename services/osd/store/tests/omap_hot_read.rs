// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Hot bucket-index read workload against a cache smaller than the omap working set (benchmark omap-real
//! or-r1a-hot-index): random point GETs and listing pages of 1000 entries from a random start, counting device read bytes
//! per operation and the cache hit rate. Scaled down with `HOT_KEYS` (keys per object) and `HOT_SHARE_MIB`.
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use store::dev::{SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::txn::Bytes;
use store::obj::{OTxn, Store, StoreCfg, TOp};

type St = Store<SimDev, SimClock>;

fn cid() -> CollT {
    CollT::Pg(SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId::NO_SHARD,
    })
}
fn oid(i: usize) -> Ghobject {
    Ghobject::new(
        Hobject::new(format!(".dir.{i}").as_bytes(), SnapId::NOSNAP, 1, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}
fn mix(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}
/// S3-like key of index `i` (30..130 B, hash order).
fn key(i: u64) -> Vec<u8> {
    let mut s = i ^ 0x5333_4e41;
    let a = mix(&mut s);
    let len = 30 + (a % 100) as usize;
    let mut k = format!("data/{:04x}/", mix(&mut s) >> 48).into_bytes();
    while k.len() < len {
        k.extend_from_slice(format!("{:016x}", mix(&mut s)).as_bytes());
    }
    k.truncate(len);
    k
}
/// Incompressible 300 B value.
fn value(i: u64, o: usize) -> Vec<u8> {
    let mut s = i ^ ((o as u64) << 40);
    (0..38)
        .flat_map(|_| mix(&mut s).to_le_bytes())
        .take(300)
        .collect()
}
fn env(name: &str, d: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

struct Fix {
    disk: SimDisk,
    st: St,
    cfg: StoreCfg,
    objs: usize,
    keys: u64,
}

fn mount(disk: &SimDisk, cfg: &StoreCfg) -> St {
    let d = disk.clone();
    Store::mount(move || d.queue(), SimClock::default(), cfg.clone())
        .unwrap()
        .0
}

fn populate(lsm: bool) -> Fix {
    let objs = env("HOT_OBJS", 2) as usize;
    let keys = env("HOT_KEYS", 80_000);
    let share = env("HOT_SHARE_MIB", 64) << 20;
    let disk = SimDisk::new(SimConfig::new(2 << 30));
    mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards: 1,
            wal_blocks: 16384,
            align_blocks: 1,
            omap_lsm: lsm,
            ..Default::default()
        },
    )
    .unwrap();
    let mut cfg = StoreCfg::for_memory(share, 1).unwrap();
    cfg.shard.max_unit_blocks = 64;
    let mut st = mount(&disk, &cfg);
    let mut t = OTxn::new();
    t.mkcoll(cid());
    for o in 0..objs {
        t.touch(cid(), &oid(o));
    }
    st.commit(&t).unwrap();
    for o in 0..objs {
        let mut i = 0;
        while i < keys {
            let n = 512.min(keys - i);
            let pairs = (i..i + n)
                .map(|j| (Bytes::Owned(key(j)), Bytes::Owned(value(j, o))))
                .collect();
            let mut t = OTxn::new();
            t.push(TOp::OmapSetKeys {
                cid: cid(),
                oid: oid(o),
                pairs,
            });
            st.commit(&t).unwrap();
            i += n;
        }
    }
    if !lsm {
        let sh = st.shards[0].sh.state().tree.shape();
        eprintln!(
            "  shape: leaves={} entries={} leaf_used={} B/leaf height={} interior={}",
            sh.leaves,
            sh.entries,
            sh.leaf_used / sh.leaves.max(1),
            sh.height,
            sh.interior
        );
    }
    drop(st);
    let img = disk.crash_image(store::dev::CrashPolicy::PERSIST_ALL);
    let disk = SimDisk::from_image(&img, SimConfig::new(2 << 30));
    let st = mount(&disk, &cfg);
    Fix {
        disk,
        st,
        cfg,
        objs,
        keys,
    }
}

/// Returns (device bytes per GET, device bytes per listing page) after a warm-up.
fn run(lsm: bool) -> (u64, u64) {
    let mut f = populate(lsm);
    let _ = (&f.cfg, f.objs);
    let gets = env("HOT_GETS", 8_000);
    let lists = env("HOT_LISTS", 20);
    let pages = lists;
    let mut rng = 12345u64;
    for _ in 0..env("HOT_WARM", 4 * gets) {
        let o = (mix(&mut rng) % f.objs as u64) as usize;
        let k = key(mix(&mut rng) % f.keys);
        f.st.omap_get(&cid(), &oid(o), &[&k]).unwrap();
    }
    let (r0, t0) = (f.disk.stats().read_lbas, f.st.tree_stats());
    let c0 = f.st.cache_status();
    for _ in 0..gets {
        let o = (mix(&mut rng) % f.objs as u64) as usize;
        let k = key(mix(&mut rng) % f.keys);
        let got = f.st.omap_get(&cid(), &oid(o), &[&k]).unwrap();
        assert_eq!(got.len(), 1);
    }
    let (r1, t1) = (f.disk.stats().read_lbas, f.st.tree_stats());
    let mut listed = 0usize;
    let mut npages = 0u64;
    for _ in 0..pages {
        let o = (mix(&mut rng) % f.objs as u64) as usize;
        let mut from = key(mix(&mut rng) % f.keys);
        for _ in 0..10 {
            let (kv, more) =
                f.st.omap_range(&cid(), &oid(o), &from, b"", 1000, 1 << 20, true)
                    .unwrap();
            listed += kv.len();
            npages += 1;
            let Some((last, _)) = kv.last() else { break };
            if !more {
                break;
            }
            from = last.clone();
            from.push(0);
        }
    }
    let pages = npages;
    let (r2, t2) = (f.disk.stats().read_lbas, f.st.tree_stats());
    let c1 = f.st.cache_status();
    if let Some(o) = f.st.shards[0].sh.olsm_stats() {
        eprintln!(
            "  olsm reads={} read_blocks={} live={} MiB runs={} mem={} MiB",
            o.reads,
            o.read_blocks,
            o.space_live_bytes >> 20,
            o.runs,
            o.mem_bytes >> 20
        );
    }
    let ws = f.objs as u64 * f.keys * 400;
    eprintln!(
        "HOTREAD lsm={lsm} working_set~{} MiB share={} MiB",
        ws >> 20,
        env("HOT_SHARE_MIB", 64)
    );
    eprintln!(
        "  GET  n={gets} dev_read={} B/op loads/op={:.3} hint_hits={}",
        (r1 - r0) * 4096 / gets,
        (t1.loads - t0.loads) as f64 / gets as f64,
        t1.hint_hits - t0.hint_hits,
    );
    eprintln!(
        "  LIST n={pages} entries={listed} dev_read={} KB/page loads/page={:.1} scan_loads={} scan_evict={}",
        (r2 - r1) * 4096 / pages / 1024,
        (t2.loads - t1.loads) as f64 / pages as f64,
        t2.scan_loads - t1.scan_loads,
        t2.scan_evictions - t1.scan_evictions,
    );
    for ((n, a), (_, b)) in c0.iter().zip(&c1) {
        eprintln!("  {n}: {a} -> {b}");
    }
    ((r1 - r0) * 4096 / gets, (r2 - r1) * 4096 / pages)
}

/// B+tree omap: the tree page cache is the only cache; a GET misses about as often as the cache is smaller than the tree
/// (about 0.5 page of 8 KiB per GET here), a listing page reads its ~40 leaves.
#[test]
fn hot_read_btree() {
    let (get, list) = run(false);
    assert!(get < 5000 && list < 400 << 10, "{get} {list}");
}

/// LSM omap: the run block cache borrows the tree page budget the tree has not allocated (the tree holds only onodes), so
/// it holds more than its own quarter of the shard share. Before: 4967 B per GET and 403 KB per listing page, no
/// better than the first read of every page.
#[test]
fn hot_read_lsm() {
    let (get, list) = run(true);
    assert!(get < 4000 && list < 330 << 10, "{get} {list}");
}
