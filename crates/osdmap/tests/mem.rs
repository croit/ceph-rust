// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Memory of a big osdmap (5k OSDs, 10k PGs of upmap) per core: decoded per core (old) vs decoded once and shared by
//! `Arc` (adr 0050 / open question 13d). Manual: `cargo test --release -p osdmap --test mem -- --ignored --nocapture`.
use denc::types::{EntityAddr, EntityAddrVec, PgT};
use osdmap::*;
use std::sync::Arc;

fn rss_kb() -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

fn big_map(epoch: u32) -> OsdMap {
    let n = 5000usize;
    let mut m = OsdMap::default();
    m.epoch = epoch;
    m.max_osd = n as i32;
    m.osd_state = vec![3; n];
    m.osd_weight = vec![0x10000; n];
    let a = EntityAddrVec::single(EntityAddr::default());
    m.client_addrs = vec![a.clone(); n];
    m.hb_back_addrs = vec![a.clone(); n];
    m.hb_front_addrs = vec![a.clone(); n];
    m.cluster_addrs = vec![a; n];
    m.osd_info = vec![Default::default(); n];
    m.osd_uuid = vec![Default::default(); n];
    m.osd_xinfo = vec![Default::default(); n];
    m.set_crush(vec![7u8; 300_000]);
    for s in 0..10_000u32 {
        m.pg_upmap_items
            .insert(PgT::new(1, s), vec![(1, 2), (3, 4)]);
    }
    m
}

#[test]
#[ignore]
fn per_core_decode_vs_shared() {
    const CORES: usize = 16;
    const EPOCHS: usize = 50;
    let blobs: Vec<Vec<u8>> = (0..EPOCHS)
        .map(|e| big_map(e as u32 + 1).encode_full().expect("encode"))
        .collect();
    println!("encoded map: {} kB", blobs[0].len() / 1024);
    let base = rss_kb();
    // one mode per process (a freed heap keeps its RSS): MEM_MODE=per_core | shared
    if std::env::var("MEM_MODE").as_deref() == Ok("per_core") {
        // before: every core decodes every epoch of the burst
        let held: Vec<Vec<Arc<OsdMap>>> = (0..CORES)
            .map(|_| {
                blobs
                    .iter()
                    .map(|b| Arc::new(OsdMap::decode_from(b).expect("decode")))
                    .collect()
            })
            .collect();
        println!(
            "{CORES} cores x {EPOCHS} epochs, per-core decode: {} MB",
            (rss_kb() - base) / 1024
        );
        drop(held);
    } else {
        // after: decoded once, every core holds Arcs
        let once: Vec<Arc<OsdMap>> = blobs
            .iter()
            .map(|b| Arc::new(OsdMap::decode_from(b).expect("decode")))
            .collect();
        let held: Vec<Vec<Arc<OsdMap>>> = (0..CORES).map(|_| once.clone()).collect();
        println!(
            "{CORES} cores x {EPOCHS} epochs, decoded once + Arc: {} MB",
            (rss_kb() - base) / 1024
        );
        drop(held);
    }
}

/// Catch-up retains epochs for interval reconstruction: unchanged CRUSH bytes
/// must have one owner allocation, independent of the number of epochs.
#[test]
fn unchanged_crush_storage_is_independent_of_epoch_count() {
    for devices in [1_000, 10_000] {
        let mut cm = crush::CrushMap::new();
        let items: Vec<_> = (0..devices).map(|id| (id, 0x10000)).collect();
        cm.add_bucket(crush::Bucket::straw2(-1, 1, &items));
        let mut map = OsdMap::default();
        map.set_crush(cm.encode());
        let state = map.crush_state().unwrap().clone();
        let blob_len = map.crush_blob().len();
        let mut held = vec![map];
        let start = std::time::Instant::now();
        for epoch in 1..=1_000 {
            let inc = Incremental {
                epoch,
                has_crc: false, // Isolate clone/apply storage from full-map CRC encoding.
                ..Incremental::default()
            };
            held.push(
                held.last()
                    .unwrap()
                    .apply_incremental_checked(&inc)
                    .unwrap(),
            );
        }
        let owners: std::collections::BTreeSet<_> =
            held.iter().map(|m| m.crush_blob().as_ptr()).collect();
        println!(
            "devices={devices} epochs={} CRUSH bytes={} unique bytes={} apply={:?}",
            held.len(),
            blob_len,
            owners.len() * blob_len,
            start.elapsed()
        );
        assert_eq!(owners.len(), 1, "unchanged CRUSH copied at each epoch");
        for map in &held {
            assert!(Arc::ptr_eq(map.crush_state().unwrap(), &state));
            assert_eq!(map.crush_blob(), held[0].crush_blob());
        }
    }
}

#[test]
fn replacing_shared_crush_preserves_previous_epochs_and_crc() {
    let raw = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/osdmap/full/0091.bin"),
    )
    .unwrap();
    let old = OsdMap::decode_from(&raw).unwrap();
    let old_state = old.crush_state().unwrap().clone();
    let mut changed = old.clone();
    let replacement = crush::CrushMap::new().encode();
    changed.set_crush(replacement.clone());
    assert_eq!(old.encode_full().unwrap(), raw);
    assert_eq!(changed.crush_blob(), replacement);
    assert!(!Arc::ptr_eq(changed.crush_state().unwrap(), &old_state));

    let inc = Incremental {
        fsid: old.fsid,
        epoch: old.epoch + 1,
        crush: replacement,
        has_crc: false,
        ..Incremental::default()
    };
    let next = old.apply_incremental_checked(&inc).unwrap();
    assert_ne!(old.crush_blob().as_ptr(), next.crush_blob().as_ptr());
    assert!(Arc::ptr_eq(old.crush_state().unwrap(), &old_state));
    assert_eq!(old.encode_full().unwrap(), raw);
    let encoded = next.encode_full().unwrap();
    assert_eq!(OsdMap::decode_from(&encoded).unwrap(), next);
    assert_eq!(
        next.crc(0).unwrap(),
        u32::from_le_bytes(encoded[encoded.len() - 4..].try_into().unwrap())
    );
}
