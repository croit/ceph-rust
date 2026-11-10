// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Per-core stores (adr 0031): two `Store`s mount disjoint shard subsets of one device and work independently.
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SnapId, SpgT};
use store::dev::{SimClock, SimConfig, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::{OTxn, ObjError, Store, StoreCfg, TOp};

fn spg(pool: u64, seed: u32) -> SpgT {
    SpgT {
        pgid: PgT::new(pool, seed),
        shard: ShardId::NO_SHARD,
    }
}

fn obj(n: &str) -> Ghobject {
    Ghobject::new(
        Hobject::new(n.as_bytes(), SnapId::NOSNAP, 1, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

#[test]
fn subsets_are_independent_and_survive_remount() {
    let disk = SimDisk::new(SimConfig::new(256 << 20));
    let p = MkfsParams {
        shards: 4,
        wal_blocks: 1024,
        align_blocks: 1,
        meta_pct: 8,
        ..Default::default()
    };
    mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
    let mount = |core: u32| {
        let d = disk.clone();
        Store::mount_shards(
            move || d.queue(),
            SimClock::default(),
            StoreCfg::default(),
            move |s| s % 2 == core,
        )
        .unwrap()
        .0
    };
    let mut cores = [mount(0), mount(1)];
    assert!(
        cores
            .iter()
            .all(|s| s.nshards() == 4 && s.shards.len() == 2)
    );
    // pool 1: seeds 0..4 land on shards (1+seed)%4 -> core (1+seed)%4%2
    for seed in 0..4u32 {
        let c = spg(1, seed);
        let core = ((1 + seed) % 4 % 2) as usize;
        let mut t = OTxn::new();
        t.push(TOp::MkColl {
            cid: CollT::Pg(c),
            bits: 0,
            exist_ok: true,
        });
        t.push(TOp::Write {
            cid: CollT::Pg(c),
            oid: obj("o"),
            off: 0,
            data: vec![seed as u8 + 1; 5000].into(),
        });
        cores[core].commit(&t).unwrap();
        // the other core refuses it
        assert!(matches!(
            cores[1 - core].commit(&t),
            Err(ObjError::NotMounted(_))
        ));
    }
    assert_eq!(cores[0].list_colls().unwrap().len(), 2);
    assert_eq!(cores[1].list_colls().unwrap().len(), 2);
    drop(cores);
    let mut cores = [mount(0), mount(1)];
    for seed in 0..4u32 {
        let core = ((1 + seed) % 4 % 2) as usize;
        let d = cores[core]
            .read(&CollT::Pg(spg(1, seed)), &obj("o"), 0, 5000)
            .unwrap();
        assert_eq!(d, vec![seed as u8 + 1; 5000]);
    }
}
