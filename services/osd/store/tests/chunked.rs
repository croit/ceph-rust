// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Chunk-table store (adr 0021 am. 47, elastic shards step 1): mkfs chunked, mount, write more than one chunk per shard,
//! checkpoint, crash-free remount, fsck clean, data intact, capacity = base chunks only.
#![cfg(feature = "elastic")]
#[path = "common/objmodel.rs"]
mod objmodel;

use denc::types::{CollT, Ghobject, Hobject, ShardId, SnapId};
use objmodel::*;
use store::dev::{SimClock, SimConfig, SimDev, SimDisk};
use store::fsck::fsck;
use store::layout::{FEAT_CHUNKED, MkfsParams, mkfs, read_super};
use store::obj::onode::fsck_refs;
use store::obj::{OTxn, Store, StoreCfg};

type St = Store<SimDev, SimClock>;
const PGS: u32 = 16;

fn g(i: u32) -> Ghobject {
    Ghobject::new(
        Hobject::new(format!("o{i}").as_bytes(), SnapId::NOSNAP, i, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}
fn pg_of(i: u32) -> CollT {
    pgc(1, i % PGS)
}
fn pattern(i: u32, len: usize) -> Vec<u8> {
    (0..len).map(|k| (k as u32 * 7 + i * 13) as u8).collect()
}
fn mount(disk: &SimDisk) -> St {
    let d = disk.clone();
    Store::mount(move || d.queue(), SimClock::default(), StoreCfg::default())
        .unwrap()
        .0
}

#[test]
fn chunked_store_roundtrip_and_remount() {
    let disk = SimDisk::new(SimConfig::new(128 << 20));
    let p = MkfsParams {
        shards: 2,
        wal_blocks: 1024,
        align_blocks: 1,
        meta_pct: 4,
        chunked: true,
        chunk_blocks: 1024, // 4 MiB chunks: objects span many chunks
        base_pct: 75,
        ..Default::default()
    };
    mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
    let (sb, dirs) = read_super(&mut disk.queue(), &mut SimClock::default()).unwrap();
    assert!(sb.features & FEAT_CHUNKED != 0);
    let base: u64 = dirs.iter().map(|d| d.data_blocks).sum::<u64>() * store::BLK as u64;
    let mut st = mount(&disk);
    // capacity covers the base chunks only (the tail of every region is the future shared pool)
    assert!(
        st.statfs().total_bytes <= base,
        "{} > {base}",
        st.statfs().total_bytes
    );
    let n = 400u32;
    for i in 0..n {
        let mut t = OTxn::new();
        if i < PGS {
            t.mkcoll(pg_of(i));
        }
        let d = pattern(i, 128 << 10);
        t.write(pg_of(i), &g(i), 0, &d);
        st.commit(&t)
            .unwrap_or_else(|e| panic!("object {i}: {e:?}"));
    }
    // overwrite half (out-of-place: frees and reallocations across chunks)
    for i in (0..n).step_by(2) {
        let mut t = OTxn::new();
        let d = pattern(i + 1000, 128 << 10);
        t.write(pg_of(i), &g(i), 0, &d);
        st.commit(&t).unwrap();
    }
    st.checkpoint().unwrap();
    for i in n..n + 50 {
        let mut t = OTxn::new();
        let d = pattern(i, 64 << 10);
        t.write(pg_of(i), &g(i), 0, &d);
        st.commit(&t).unwrap(); // replayed from the WAL at the next mount
    }
    drop(st);
    let mut st = mount(&disk);
    for i in 0..n + 50 {
        let (seed, len) = if i < n && i % 2 == 0 {
            (i + 1000, 128 << 10)
        } else if i < n {
            (i, 128 << 10)
        } else {
            (i, 64 << 10)
        };
        assert!(
            st.read(&pg_of(i), &g(i), 0, len as u64).unwrap() == pattern(seed, len),
            "object {i}"
        );
    }
    drop(st);
    fsck(
        &mut disk.queue(),
        &mut SimClock::default(),
        Some(&fsck_refs),
    )
    .unwrap();
}
