// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
//! Object facade parity over real per-shard SplinterDB, with standalone vectors.
#![cfg(all(feature = "splinterdb", feature = "lab"))]
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use std::time::{Duration, Instant};
use store::dev::{Clock, CrashPolicy, SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::{OTxn, Store, StoreCfg, TOp, txn::Bytes as Data};
struct Temp(std::path::PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
#[derive(Debug)]
struct YieldClock {
    sim: SimClock,
    end: Instant,
}
impl Default for YieldClock {
    fn default() -> Self {
        Self {
            sim: SimClock::default(),
            end: Instant::now() + Duration::from_secs(30),
        }
    }
}
impl Clock for YieldClock {
    fn now(&mut self) -> u64 {
        assert!(
            Instant::now() < self.end,
            "WARNING TIMEOUT SplinterDB object regression exceeded 30s"
        );
        self.sim.now()
    }
    fn idle(&mut self, hint: Option<u64>) {
        self.sim.idle(hint);
        std::thread::yield_now();
    }
    fn wall_time(&self) -> bool {
        false
    }
}
fn object(name: &[u8]) -> Ghobject {
    Ghobject::new(
        Hobject::new(name, SnapId::NOSNAP, 1, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}
fn drain(st: &mut Store<SimDev, YieldClock>) {
    st.checkpoint().unwrap();
}
#[test]
fn object_sessions_clone_range_delete_and_restart_keep_independent_contents() {
    let root = std::env::temp_dir().join(format!("sdb-object-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let _temp = Temp(root.clone());
    let disk = SimDisk::new(SimConfig::new(64 << 20));
    let (sb, _) = mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards: 1,
            wal_blocks: 2048,
            align_blocks: 1,
            omap_splinterdb: true,
            ..Default::default()
        },
    )
    .unwrap();
    let mut foreign = store::splinter_omap::Config::new(root, 128 << 20);
    foreign.allow_non_nvme = true;
    store::splinter_omap::create(&foreign, &sb, 64 << 20).unwrap();
    let mut cfg = StoreCfg::default();
    cfg.shard.splinterdb = Some(foreign);
    cfg.shard.cache_pages = 32768;
    let mut st = Store::mount(|| disk.queue(), YieldClock::default(), cfg.clone())
        .unwrap()
        .0;
    let c = CollT::Pg(SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId::NO_SHARD,
    });
    let src = object(b"source");
    let dst = object(b"clone");
    let pairs: Vec<_> = (0..600u32)
        .map(|i| {
            let mut k = b"p/".to_vec();
            k.extend_from_slice(&i.to_be_bytes());
            (k, i.to_le_bytes().to_vec())
        })
        .collect();
    let mut t = OTxn::new();
    t.mkcoll(c);
    for (k, v) in &pairs {
        t.omap_set(c, &src, k, v);
    }
    t.push(TOp::OmapSetHeader {
        cid: c,
        oid: src.clone(),
        header: Data::Borrowed(b"native header"),
    });
    st.commit(&t).unwrap();
    drain(&mut st);
    // Exercise the request memo across several foreign pages and credit release.
    st.read_session(Some((7, 1)), false);
    let (v, more) = st
        .omap_range(&c, &src, b"", b"p/", 400, usize::MAX, true)
        .unwrap();
    assert_eq!(v, pairs[..400]);
    assert!(more);
    st.read_session(None, false);
    st.read_session(Some((7, 2)), false);
    let (v, more) = st.omap_range(&c, &src, b"", b"p/", 600, 10, false).unwrap();
    assert_eq!(v, vec![(pairs[0].0.clone(), Vec::new())]);
    assert!(more);
    st.read_session(None, false);
    let mut t = OTxn::new();
    t.push(TOp::Clone {
        cid: c,
        src: src.clone(),
        dst: dst.clone(),
    });
    st.commit(&t).unwrap();
    drain(&mut st);
    let mut t = OTxn::new();
    t.push(TOp::OmapRmKeyRange {
        cid: c,
        oid: src.clone(),
        first: Data::Borrowed(&pairs[0].0),
        last: Data::Borrowed(&pairs[300].0),
    });
    t.omap_set(c, &src, &pairs[100].0, b"newer");
    st.commit(&t).unwrap();
    drain(&mut st);
    st.checkpoint().unwrap();
    let report = st.check(false).unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    drop(st);
    let disk = SimDisk::from_image(
        &disk.crash_image(CrashPolicy::DROP_ALL),
        SimConfig::new(64 << 20),
    );
    let mut st = Store::mount(|| disk.queue(), YieldClock::default(), cfg)
        .unwrap()
        .0;
    let expected = std::iter::once((pairs[100].0.clone(), b"newer".to_vec()))
        .chain(pairs[300..].iter().cloned())
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(st.omap_all(&c, &src).unwrap(), expected);
    assert_eq!(st.omap_all(&c, &dst).unwrap(), pairs.into_iter().collect());
    assert_eq!(st.omap_header(&c, &src).unwrap(), b"native header");
}
