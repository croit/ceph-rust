// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Residency leases (adr 0043 am. 18): an op that waits for its store loads (a held replica write, an EC own-shard
//! wait) keeps what its probes loaded resident until it consumes it. Without the lease a completed load could expire
//! (prefetch TTL) or be evicted (tree page CLOCK, data cache envelope) before the op retried: re-load, possibly forever.
#[path = "common/objmodel.rs"]
mod objmodel;

use denc::types::{Ghobject, Hobject, ShardId, SnapId};
use objmodel::pgc;
use store::dev::{SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::{OTxn, Store, StoreCfg};
use store::shard::ShardCfg;

type St = Store<SimDev, SimClock>;

struct Rig {
    disk: SimDisk,
    st: St,
    sim: SimConfig,
    cfg: StoreCfg,
}

impl Rig {
    fn new(cap_mib: u64, cache_pages: usize) -> Rig {
        let mut sim = SimConfig::new(cap_mib << 20);
        sim.seed = 7;
        let disk = SimDisk::new(sim.clone());
        {
            let mut dev = disk.queue();
            let mut clk = SimClock::default();
            let p = MkfsParams {
                shards: 1,
                wal_blocks: 2048,
                align_blocks: 1,
                meta_pct: 12,
                node_size: 8192,
                ..Default::default()
            };
            mkfs(&mut dev, &mut clk, &p).unwrap();
        }
        let mut cfg = StoreCfg {
            shard: ShardCfg {
                cache_pages,
                ..StoreCfg::default().shard
            },
        };
        cfg.shard.val_comp_min = 0;
        let d2 = disk.clone();
        let (st, _) = Store::mount(move || d2.queue(), SimClock::default(), cfg.clone()).unwrap();
        Rig { disk, st, sim, cfg }
    }

    /// Checkpoint, remount on the image: every tree page and data block cold.
    fn remount(&mut self) {
        self.st.checkpoint().unwrap();
        let img = self.disk.image();
        let disk = SimDisk::from_image(&img, self.sim.clone());
        let d2 = disk.clone();
        let (st, _) =
            Store::mount(move || d2.queue(), SimClock::default(), self.cfg.clone()).unwrap();
        self.disk = disk;
        self.st = st;
    }

    fn poll(&mut self) {
        let mut a = vec![];
        self.st.poll(&mut a).unwrap();
        self.st.idle();
    }

    /// Advance the clock by `ns` (prefetch TTL, admission waiter age) and run the store's sweep.
    fn age(&mut self, ns: u64) {
        self.st.clk.t += ns;
        self.poll();
    }
}

fn g(name: &str) -> Ghobject {
    Ghobject::new(
        Hobject::new(name.as_bytes(), SnapId::NOSNAP, 3, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

fn data(i: u8, len: usize) -> Vec<u8> {
    (0..len).map(|j| (j as u8).wrapping_mul(31) ^ i).collect()
}

/// Prefetch completes, then the run outlives the prefetch TTL before the op retries: unleased it is dropped and the op
/// must read it again (the livelock of a held op under pressure); under the lease it stays until released.
#[test]
fn a_leased_prefetch_run_survives_the_ttl_until_released() {
    let mut r = Rig::new(256, 4096);
    let c = pgc(1, 0);
    let len = 1usize << 20;
    let mut t = OTxn::new();
    t.mkcoll(c);
    r.st.commit(&t).unwrap();
    for (i, n) in ["held", "free"].iter().enumerate() {
        let (o, d) = (g(n), data(i as u8, len));
        let mut t = OTxn::new();
        t.write(c, &o, 0, &d);
        t.setattr(c, &o, b"_", b"oi");
        r.st.commit(&t).unwrap();
    }
    r.remount();
    let (held, free) = (g("held"), g("free"));
    let lease = r.st.lease_open(&c).unwrap();
    // both ops prefetch their data; only `held` runs under a lease
    for (o, l) in [(&held, lease), (&free, 0)] {
        r.st.lease_use(l);
        let mut spins = 0;
        while !(r.st.warm(&c, o, 0, len as u64).unwrap()
            && r.st.warm_data(&c, o, 0, len as u64).unwrap())
        {
            r.st.lease_use(0);
            spins += 1;
            assert!(spins < 100_000, "loads never complete");
            r.poll();
            r.st.lease_use(l);
        }
        r.st.lease_use(0);
    }
    assert_eq!(
        r.st.shards[0].pf_leased_usage(),
        (4, 256),
        "the leased runs are held"
    );
    assert_eq!(
        r.st.shards[0].pf_usage(),
        (8, 256),
        "only the unleased runs take admission capacity (a held op never blocks another's admission)"
    );
    // the op's retry comes late (busy core, many held PGs): far past the TTL
    for _ in 0..20 {
        r.age(100_000_000);
    }
    let ios = r.st.shards[0].stats.read_ios;
    r.st.lease_use(lease);
    let ready = r.st.warm(&c, &held, 0, len as u64).unwrap()
        && r.st.warm_data(&c, &held, 0, len as u64).unwrap();
    r.st.lease_use(0);
    assert!(
        ready,
        "the leased run must still be there: the waiting op progresses"
    );
    assert_eq!(
        r.st.shards[0].stats.read_ios, ios,
        "nothing of the leased op was read again"
    );
    assert!(
        !r.st.warm_data(&c, &free, 0, len as u64).unwrap(),
        "control: the unleased run expired and is read again"
    );
    assert!(r.st.shards[0].stats.read_ios > ios);
    assert_eq!(r.st.read(&c, &held, 0, len as u64).unwrap(), data(0, len));
    r.st.lease_release(lease);
    assert_eq!(r.st.leases_open(), 0);
    assert_eq!(r.st.shards[0].pf_leased_usage(), (0, 0));
    assert_eq!(r.st.shards[0].sh.pinned_pages(), 0);
}

/// Warm `o` (tree path only) under `lease` (0 = none) until resident, polling the store for the loads.
fn warm_until(r: &mut Rig, o: &Ghobject, lease: u64) {
    let c = pgc(1, 0);
    for _ in 0..100_000 {
        r.st.lease_use(lease);
        let ok = r.st.warm(&c, o, 0, 4096).unwrap();
        r.st.lease_use(0);
        if ok {
            return;
        }
        r.poll();
    }
    panic!("loads of {o:?} never complete");
}

/// The tree pages a held op's probe loaded stay resident under its lease while other ops churn the page cache; an
/// unleased op's pages are evicted meanwhile (its next probe loads them again: the livelock without the lease).
#[test]
fn leased_tree_pages_stay_resident_under_cache_churn() {
    let mut r = Rig::new(512, 64);
    let c = pgc(1, 0);
    let mut t = OTxn::new();
    t.mkcoll(c);
    r.st.commit(&t).unwrap();
    let names: Vec<Ghobject> = (0..3000).map(|i| g(&format!("obj-{i:05}"))).collect();
    let d = data(1, 4096);
    for chunk in names.chunks(100) {
        let mut t = OTxn::new();
        for o in chunk {
            t.write(c, o, 0, &d);
            t.setattr(c, o, b"_", &[7u8; 200]);
        }
        r.st.commit(&t).unwrap();
    }
    r.remount();
    let (held, free) = (&names[1500], &names[2900]);
    let lease = r.st.lease_open(&c).unwrap();
    warm_until(&mut r, held, lease);
    warm_until(&mut r, free, 0);
    let pinned = r.st.shards[0].sh.pinned_pages();
    assert!(pinned > 0, "the leased probe's misses are pinned");
    // other ops load far more pages than the cache holds
    for _ in 0..2 {
        for o in names[..1400].iter().step_by(3) {
            warm_until(&mut r, o, 0);
        }
    }
    let ev = r.st.shards[0].sh.tree_stats().evictions;
    assert!(ev > 64, "the churn evicted pages ({ev})");
    r.st.lease_use(lease);
    let ok = r.st.warm(&c, held, 0, 4096).unwrap();
    r.st.lease_use(0);
    assert!(ok, "the held op's pages stayed resident: its retry passes");
    assert!(
        !r.st.warm(&c, free, 0, 4096).unwrap(),
        "control: the unleased op's pages were evicted and load again"
    );
    r.st.lease_release(lease);
    assert_eq!(r.st.shards[0].sh.pinned_pages(), 0);
    assert_eq!(r.st.leases_open(), 0);
}

/// A leased op refused prefetch admission keeps its place in the admission queue (a client op's waiter is dropped
/// `PF_WAIT_NS` after its last probe as gone) and is woken when capacity frees: it never depends on a later probe of
/// another op or on a timer to learn that it may run.
#[test]
fn a_refused_leased_admission_is_woken_when_capacity_frees() {
    let mut r = Rig::new(256, 4096);
    let c = pgc(1, 0);
    let mut t = OTxn::new();
    t.mkcoll(c);
    r.st.commit(&t).unwrap();
    let len = 4usize << 20;
    let objs: Vec<Ghobject> = (0..9).map(|i| g(&format!("big-{i}"))).collect();
    for (i, o) in objs.iter().enumerate() {
        let d = data(i as u8, len);
        let mut t = OTxn::new();
        t.write(c, o, 0, &d);
        t.setattr(c, o, b"_", b"oi");
        r.st.commit(&t).unwrap();
    }
    r.remount();
    for o in &objs {
        warm_until(&mut r, o, 0);
    }
    // seven 4 MiB client reads fill the prefetch table (in flight)
    let admitted = 7;
    for o in &objs[..admitted] {
        assert!(!r.st.warm_data(&c, o, 0, len as u64).unwrap());
    }
    assert_eq!(r.st.shards[0].pf_waiters(), 0, "all admitted");
    let (held, other) = (&objs[7], &objs[8]);
    let lease = r.st.lease_open(&c).unwrap();
    r.st.lease_use(lease);
    assert!(
        !r.st.warm_data(&c, held, 0, len as u64).unwrap(),
        "refused: the table is full"
    );
    r.st.lease_use(0);
    assert_eq!(r.st.shards[0].pf_waiters(), 1);
    // the held op does not probe for a while (it waits for the wake); a client op probes and finds the queue
    r.age(100_000_000);
    assert!(!r.st.warm_data(&c, other, 0, len as u64).unwrap());
    assert_eq!(
        r.st.shards[0].pf_waiters(),
        2,
        "the leased waiter keeps its place ahead of the younger client op"
    );
    // the admitted reads complete and are consumed: their capacity frees and must wake the held op
    r.st.take_wake();
    let mut woke = false;
    for o in &objs[..admitted] {
        for _ in 0..100_000 {
            if r.st.warm_data(&c, o, 0, len as u64).unwrap() {
                break;
            }
            r.poll();
        }
        r.st.take_wake();
        r.st.read(&c, o, 0, len as u64).unwrap();
        r.poll();
        woke |= r.st.take_wake();
    }
    assert!(woke, "freed capacity woke the held op");
    // the held op's retry is admitted and completes
    let mut done = false;
    for _ in 0..100_000 {
        r.st.lease_use(lease);
        done = r.st.warm_data(&c, held, 0, len as u64).unwrap();
        r.st.lease_use(0);
        if done {
            break;
        }
        r.poll();
    }
    assert!(done, "the held op progressed once capacity freed");
    let i = objs.iter().position(|o| o == held).unwrap();
    assert_eq!(
        r.st.read(&c, held, 0, len as u64).unwrap(),
        data(i as u8, len)
    );
    r.st.lease_release(lease);
    assert_eq!(r.st.leases_open(), 0);
    assert_eq!(r.st.shards[0].pf_leased_usage(), (0, 0));
}
