// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Local allocator/simulator audit probe. Setup and correctness verification are outside each sample.
//! Copy to the baseline checkout, replacing only query_keys with the old range+projection implementation.
use denc::types::*;
use opexec::ObjView;
use peering::store::PgStoreOps;
use replwire::{ObjectInfo, ObjectRecoveryProgress};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;
use std::time::Instant;
use store::dev::{SimClock, SimConfig, SimDisk, SimImage};
use store::layout::{MkfsParams, mkfs};
use store::obj::{OTxn, Store, StoreCfg, TOp};
use store::sio::Sio;
use storeadapt::StoreAdapter;

type St = Store<store::dev::SimDev, SimClock>;
type Ad = StoreAdapter<store::dev::SimDev, SimClock>;
thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static CALLS: Cell<usize> = const { Cell::new(0) };
    static BYTES: Cell<usize> = const { Cell::new(0) };
}
struct Meter;
fn charge(n: usize) {
    if TRACK.try_with(Cell::get).unwrap_or(false) {
        let _ = CALLS.try_with(|c| c.set(c.get() + 1));
        let _ = BYTES.try_with(|c| c.set(c.get() + n));
    }
}
// SAFETY: delegates every allocation operation to System with the original layout/pointer.
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        charge(l.size());
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        charge(l.size());
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        charge(n);
        unsafe { System.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static ALLOCATOR: Meter = Meter;
fn measure<T>(f: impl FnOnce() -> T) -> (T, usize, usize, u128) {
    CALLS.set(0);
    BYTES.set(0);
    TRACK.set(true);
    let start = Instant::now();
    let result = f();
    let ns = start.elapsed().as_nanos();
    TRACK.set(false);
    (result, CALLS.get(), BYTES.get(), ns)
}
fn pg() -> SpgT {
    SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId::NO_SHARD,
    }
}
fn object(name: &[u8], hash: u32) -> Ghobject {
    Ghobject::new(
        Hobject::new(name, SnapId::NOSNAP, hash, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}
fn fresh(cfg: &StoreCfg) -> (SimDisk, St, SimConfig) {
    fresh_size(cfg, 128)
}
fn fresh_size(cfg: &StoreCfg, mib: u64) -> (SimDisk, St, SimConfig) {
    let sim = SimConfig::new(mib << 20);
    let disk = SimDisk::new(sim.clone());
    mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards: 1,
            wal_blocks: 1024,
            align_blocks: 1,
            meta_pct: 8,
            node_size: 4096,
            ..Default::default()
        },
    )
    .unwrap();
    let (st, _) = Store::mount(|| disk.queue(), SimClock::default(), cfg.clone()).unwrap();
    (disk, st, sim)
}
fn open(image: &SimImage, sim: &SimConfig, cfg: &StoreCfg) -> (SimDisk, St) {
    let disk = SimDisk::from_image(image, sim.clone());
    let (st, _) = Store::mount(|| disk.queue(), SimClock::default(), cfg.clone()).unwrap();
    (disk, st)
}
fn query_keys(ad: &Ad, h: &Hobject) -> (Vec<Vec<u8>>, bool) {
    ad.ov_omap_keys_range(pg(), h, None, b"p/", 1, usize::MAX)
        .unwrap()
}
fn print(name: &str, i: usize, calls: usize, bytes: usize, ns: u128, reads: u64, work: u64) {
    println!(
        "{name} sample={i} allocations={calls} requested_bytes={bytes} ns={ns} read_lbas={reads} work={work}"
    );
}
fn main() {
    let mode = std::env::args().nth(1).unwrap_or("all".into());
    let samples = std::env::var("STORAGE_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5usize);
    let cfg = StoreCfg::default();
    if ["all", "omap", "recovery"].contains(&mode.as_str()) {
        let (disk, mut st, sim) = fresh(&cfg);
        let (c, o) = (CollT::Pg(pg()), object(b"omap", 7));
        let mut t = OTxn::new();
        t.mkcoll(c);
        t.touch(c, &o);
        let mut oi = ObjectInfo::new(o.hobj.clone());
        oi.version = Eversion::new(1, 1);
        let oi = denc::to_vec(&oi).unwrap();
        t.setattr(c, &o, b"_", &oi);
        st.commit(&t).unwrap();
        let value = vec![0x51; 32 << 10];
        for i in 0..128 {
            let mut t = OTxn::new();
            let key = format!("p/{i:04}");
            t.omap_set(c, &o, key.as_bytes(), &value);
            st.commit(&t).unwrap();
        }
        st.checkpoint().unwrap();
        let image = disk.image();
        for i in 0..samples {
            let (disk, st) = open(&image, &sim, &cfg);
            let ad = StoreAdapter::new(st);
            let before = disk.stats().read_lbas;
            let ((keys, more), calls, bytes, ns) = measure(|| black_box(query_keys(&ad, &o.hobj)));
            assert_eq!(keys, vec![b"p/0000".to_vec()]);
            assert!(more);
            print(
                "omap_keys_max1",
                i,
                calls,
                bytes,
                ns,
                disk.stats().read_lbas - before,
                keys.len() as u64,
            );
            let (disk, st) = open(&image, &sim, &cfg);
            let ad = StoreAdapter::new(st);
            let before = disk.stats().read_lbas;
            let ((kv, more), calls, bytes, ns) =
                measure(|| ad.ov_omap_range(pg(), &o.hobj, None, b"p/", 1, 1).unwrap());
            assert_eq!(kv, vec![(b"p/0000".to_vec(), value.clone())]);
            assert!(more);
            print(
                "omap_values_max1",
                i,
                calls,
                bytes,
                ns,
                disk.stats().read_lbas - before,
                kv.len() as u64,
            );
            let (disk, st) = open(&image, &sim, &cfg);
            let ad = StoreAdapter::new(st);
            let ri = ad.recovery_info(pg(), &o.hobj).unwrap();
            let before = disk.stats().read_lbas;
            let (op, calls, bytes, ns) = measure(|| {
                ad.build_push(pg(), &ri, &ObjectRecoveryProgress::default(), 4096, 128)
                    .unwrap()
            });
            assert_eq!(op.omap_entries.len(), 1);
            assert_eq!(op.omap_entries[b"p/0000".as_slice()], value);
            assert_eq!(op.after_progress.omap_recovered_to, b"p/0001");
            print(
                "recovery_omap_4k_budget",
                i,
                calls,
                bytes,
                ns,
                disk.stats().read_lbas - before,
                op.omap_entries.len() as u64,
            );
        }
    }
    if ["all", "clone", "recovery_data"].contains(&mode.as_str()) {
        let (disk, mut st, sim) = fresh(&cfg);
        let (c, src, dst) = (
            CollT::Pg(pg()),
            object(b"source", 4),
            object(b"destination", 5),
        );
        let data = vec![0x37; 4 << 20];
        let mut t = OTxn::new();
        t.mkcoll(c);
        t.write(c, &src, 0, &data);
        let mut oi = ObjectInfo::new(src.hobj.clone());
        oi.version = Eversion::new(1, 1);
        oi.size = data.len() as u64;
        let oi = denc::to_vec(&oi).unwrap();
        t.setattr(c, &src, b"_", &oi);
        st.commit(&t).unwrap();
        st.checkpoint().unwrap();
        let image = disk.image();
        for i in 0..samples {
            for dst_off in [0, 1] {
                let (disk, mut st) = open(&image, &sim, &cfg);
                let mut t = OTxn::new();
                t.push(TOp::CloneRange {
                    cid: c,
                    src: src.clone(),
                    dst: dst.clone(),
                    src_off: 0,
                    len: data.len() as u64,
                    dst_off,
                });
                let before = disk.stats().read_lbas;
                let (_, calls, bytes, ns) = measure(|| st.commit(&t).unwrap());
                let read_lbas = disk.stats().read_lbas - before;
                assert_eq!(st.read(&c, &dst, dst_off, data.len() as u64).unwrap(), data);
                print(
                    if dst_off == 0 {
                        "clone_range_4m"
                    } else {
                        "clone_range_unaligned_4m"
                    },
                    i,
                    calls,
                    bytes,
                    ns,
                    read_lbas,
                    data.len() as u64,
                );
            }
            let (disk, st) = open(&image, &sim, &cfg);
            let ad = StoreAdapter::new(st);
            let ri = ad.recovery_info(pg(), &src.hobj).unwrap();
            let before = disk.stats().read_lbas;
            let (op, calls, bytes, ns) = measure(|| {
                ad.build_push(pg(), &ri, &ObjectRecoveryProgress::default(), 1 << 20, 128)
                    .unwrap()
            });
            assert_eq!(op.data, data[..1 << 20]);
            print(
                "recovery_data_1m",
                i,
                calls,
                bytes,
                ns,
                disk.stats().read_lbas - before,
                op.data.len() as u64,
            );
        }
    }
    if ["all", "sio"].contains(&mode.as_str()) {
        for i in 0..samples {
            let disk = SimDisk::new(SimConfig::new(64 << 20));
            let mut dev = disk.queue();
            let mut clock = SimClock::default();
            let data = vec![0xb5; 1 << 20];
            let mut io = Sio::new(&mut dev, &mut clock);
            let (_, calls, bytes, ns) = measure(|| io.write_one(1000, &data).unwrap());
            assert_eq!(io.read_one(1000, 256).unwrap(), data);
            print("sio_write_1m", i, calls, bytes, ns, 0, data.len() as u64);
        }
    }
    if mode == "defrag" {
        let mut setup = cfg.clone();
        setup.shard.defrag = false;
        setup.shard.bg_compact = false;
        let (disk, mut st, sim) = fresh_size(&setup, 64);
        let c = CollT::Pg(pg());
        let mut t = OTxn::new();
        t.mkcoll(c);
        st.commit(&t).unwrap();
        for i in 0..9000u32 {
            let o = object(format!("obj-{i:06}").as_bytes(), i);
            let d = vec![(i % 251) as u8; 4096];
            let a = vec![(i % 13) as u8; 250];
            let mut t = OTxn::new();
            t.write(c, &o, 0, &d);
            t.setattr(c, &o, b"_", &a);
            st.commit(&t).unwrap();
        }
        for i in (0..9000u32).filter(|i| i % 10 != 3) {
            let mut t = OTxn::new();
            t.remove(c, &object(format!("obj-{i:06}").as_bytes(), i));
            st.commit(&t).unwrap();
        }
        st.checkpoint().unwrap();
        st.checkpoint().unwrap();
        let image = disk.image();
        setup.shard.defrag = true;
        for i in 0..samples {
            let (disk, mut st) = open(&image, &sim, &setup);
            st.clk.t += 2_000_000_000;
            let before = disk.stats().read_lbas;
            let (_, calls, bytes, ns) = measure(|| {
                let mut acked = Vec::new();
                for _ in 0..100000 {
                    acked.clear();
                    st.poll(&mut acked).unwrap();
                    if st.shards[0].defrag_stats().sweeps >= 1 {
                        break;
                    }
                    st.idle();
                }
                assert_eq!(st.shards[0].defrag_stats().sweeps, 1);
                st.checkpoint().unwrap();
            });
            let moved = st.shards[0].defrag_stats().moved_blocks;
            assert!(moved > 0);
            let reads = disk.stats().read_lbas - before;
            assert_eq!(
                st.read(&c, &object(b"obj-000003", 3), 0, 4096).unwrap(),
                vec![3; 4096]
            );
            print("defrag_one_sweep", i, calls, bytes, ns, reads, moved);
        }
    }
}
