// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Per-shard capacity snapshot exposed by the store adapter.
mod common;

use common::*;
use denc::types::*;
use peering::store::PgStoreOps;
use store::obj::StoreCfg;

#[test]
fn reports_shard_ids_and_capacity_from_the_shard_statfs() {
    let (_disk, adapter, _sim) = new_adapter(128, 2, 1);
    let shards = adapter.space_shards();
    let raw = adapter.with_store(|st| st.shards.iter().map(|s| s.sh.statfs()).collect::<Vec<_>>());
    assert_eq!(shards.len(), 2);
    assert_eq!(
        shards.iter().map(|s| s.shard).collect::<Vec<_>>(),
        vec![0, 1]
    );
    for (shard, raw) in shards.into_iter().zip(raw) {
        assert!(shard.space.total > 0);
        assert!(shard.space.allocated + shard.space.available <= shard.space.total);
        assert_eq!(
            shard.space.allocated,
            (raw.used_blocks() * store::BLK as u64).saturating_sub(raw.meta_in_data_bytes())
        );
        assert!(shard.meta_usable_pages > 0);
        assert_eq!(shard.data_used_bytes % 4096, 0);
        assert_eq!(
            shard.space.internal_metadata,
            shard.meta_used_pages * shard.meta_blocks_per_page * store::BLK as u64
        );
        assert_eq!(shard.data_held_bytes, raw.data_held * 4096);
        assert_eq!(shard.data_reserved_bytes, raw.data_reserved * 4096);
        assert_eq!(shard.meta_cell_used_pages, raw.meta_cell_used);
        assert_eq!(shard.meta_base_pages, raw.meta_base_pages);
        assert_eq!(shard.meta_cell_blocks, raw.meta_cell_blocks);
        assert_eq!(shard.meta_blocks_per_page, raw.meta_bpp);
    }
}

/// Worker DATA excludes metadata and fullness reserves, including after data is reclaimed.
#[test]
fn physical_data_accounting_after_reclaim() {
    let (_disk, adapter, _) = new_adapter(64, 1, 19);
    let s = spg(1, 0);
    adapter.submit_create(s);
    let g = storeadapt::gh(s, &Hobject::new(b"reclaim", SnapId::NOSNAP, 0x12, 1, b""));
    let data = incompressible(65536, 20);
    let mut before = 0;
    for zero in [false, true] {
        adapter.with_store(|st| {
            let mut t = store::obj::OTxn::new();
            if zero {
                t.zero(CollT::Pg(s), &g, 0, data.len() as u64);
            } else {
                t.write(CollT::Pg(s), &g, 0, &data);
            }
            st.commit(&t).unwrap();
            st.checkpoint().unwrap();
        });
        let raw = adapter.with_store(|st| st.statfs());
        let physical = raw.real_used_bytes.saturating_sub(raw.real_meta_bytes);
        let report = adapter.space().unwrap();
        assert_eq!(
            report.allocated, physical,
            "worker DATA must match control-core physical accounting"
        );
        assert_eq!(
            report.available, raw.avail_bytes,
            "fullness capacity is independent of physical DATA"
        );
        assert_eq!(report.internal_metadata, raw.meta_used_bytes);
        assert_eq!(adapter.space_shards()[0].space.allocated, physical);
        if zero {
            assert_eq!(before - report.allocated, data.len() as u64);
        } else {
            before = report.allocated;
            assert!(before >= data.len() as u64);
        }
    }
}

/// The META bytes are pages × the format's page size (`node_size`), never a fixed 8 KiB: a 4 KiB-page store is
/// reported 2x without it.
#[test]
fn internal_metadata_uses_the_formats_meta_page_size() {
    let sim = sim_cfg(64, 2);
    let img = fresh_image_pages(&sim, 1, 1024, 4096);
    let (_disk, adapter) = open(&img, &sim, &StoreCfg::default());
    let s = spg(1, 0);
    adapter.submit_create(s);
    adapter.with_store(|st| {
        let c = CollT::Pg(s);
        let data = vec![7u8; 4096];
        for i in 0..16u32 {
            let h = Hobject::new(format!("o{i}").as_bytes(), SnapId::NOSNAP, i, 1, b"");
            let mut t = store::obj::OTxn::new();
            t.write(c, &Ghobject::new(h, Ghobject::NO_GEN, s.shard), 0, &data);
            st.commit(&t).unwrap();
        }
        st.checkpoint().unwrap();
    });
    let raw = adapter.with_store(|st| st.shards[0].sh.statfs());
    assert_eq!(raw.meta_bpp, 1, "a 4 KiB page is one block");
    assert!(raw.meta_used > 0, "the fixture holds tree pages");
    let page = raw.meta_bpp * store::BLK as u64;
    let shard = &adapter.space_shards()[0];
    assert_eq!(shard.space.internal_metadata, raw.meta_used * page);
    assert_eq!(
        adapter.space().unwrap().internal_metadata,
        raw.meta_used * page
    );
}
