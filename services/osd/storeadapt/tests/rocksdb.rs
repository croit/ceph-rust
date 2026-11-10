// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
#![cfg(all(feature = "rocksdb", feature = "lab"))]
mod common;
use common::*;
use peering::store::{MemStore, PgStoreOps, StoreOp, StoreTxn};
use pgwire::LogOp;
use std::collections::BTreeSet;
use store::dev::{CrashPolicy, SimClock, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::{Store, StoreCfg};
use store::rocks_omap::{Config, create};
use storeadapt::StoreAdapter;

#[test]
fn pg_metadata_and_objects_match_memstore_through_rocksdb_and_replay() {
    let root = std::env::temp_dir().join(format!(
        "croit-flashstore-rocks-adapter-{}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let sim = sim_cfg(128, 192);
    let mut disk = SimDisk::new(sim.clone());
    let (sb, _) = mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards: 2,
            wal_blocks: 1024,
            align_blocks: 1,
            omap_rocksdb: true,
            ..Default::default()
        },
    )
    .unwrap();
    let mut rocks = Config::new(root.clone());
    rocks.allow_non_nvme = true;
    create(&rocks, &sb, 8 << 20).unwrap();
    let mut cfg = StoreCfg::default();
    cfg.shard.rocksdb = Some(rocks);
    let d = disk.clone();
    let mut ad = StoreAdapter::new(
        Store::mount(move || d.queue(), SimClock::default(), cfg.clone())
            .unwrap()
            .0,
    );
    let mut mem = MemStore::new();
    let pgs = [spg(1, 0), spg(1, 1)];
    let mut gens = [PgGen::new(pgs[0], 193), PgGen::new(pgs[1], 194)];
    let mut exist = [BTreeSet::new(), BTreeSet::new()];
    for pg in pgs {
        let t = StoreTxn {
            ops: vec![StoreOp::CreatePg],
        };
        mem.submit(pg, &t);
        ad.submit(pg, &t);
    }
    for i in 0..80 {
        let slot = i % 2;
        let pg = pgs[slot];
        let g = &mut gens[slot];
        let entry = g.entry(LogOp::MODIFY);
        let mut t = StoreTxn {
            ops: vec![
                StoreOp::LogAppend(vec![entry]),
                StoreOp::PutInfo(Box::new(g.info())),
                StoreOp::PutEpoch(g.epoch),
                StoreOp::ApplyTxn {
                    middle: Default::default(),
                    data: g.object_txn(&mut exist[slot]).into(),
                },
            ],
        };
        if i % 7 == 0 {
            t.push(StoreOp::Missing(g.missing_items()));
        }
        if i % 11 == 0 {
            t.push(StoreOp::PutPastIntervals(Box::new(g.past())));
        }
        mem.submit(pg, &t);
        ad.submit(pg, &t);
        for pg in pgs {
            assert_same(&mem, &ad, pg, "RocksDB PG metadata");
            assert_same_objects(&mem, &ad, pg, "RocksDB object/OMAP");
        }
        if i % 19 == 18 {
            let image = disk.crash_image(CrashPolicy::DROP_ALL);
            drop(ad);
            disk = SimDisk::from_image(&image, sim.clone());
            let d = disk.clone();
            ad = StoreAdapter::new(
                Store::mount(move || d.queue(), SimClock::default(), cfg.clone())
                    .unwrap()
                    .0,
            );
        }
    }
    let rep = ad.with_store(|s| s.check(true)).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    drop(ad);
    std::fs::remove_dir_all(root).unwrap();
}
