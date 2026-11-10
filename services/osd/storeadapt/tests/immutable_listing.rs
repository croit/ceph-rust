// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
#![cfg(feature = "lab")]
mod common;
use common::*;
use denc::types::{CollT, Ghobject, Hobject, ShardId, SnapId};
use opexec::ObjView;
use store::obj::OTxn;

fn check_listing(ad: Ad, shared: bool) {
    let pg = spg(1, 0);
    let h = Hobject::new(b"immutable-listing", SnapId::NOSNAP, 0, 1, b"");
    let object = Ghobject::new(h.clone(), Ghobject::NO_GEN, ShardId::NO_SHARD);
    ad.with_store(|st| {
        let mut tx = OTxn::new();
        tx.mkcoll(CollT::Pg(pg));
        tx.omap_set(CollT::Pg(pg), &object, b"\x80\0", b"\xff\0");
        tx.omap_set(CollT::Pg(pg), &object, b"\x80\x01", b"second");
        tx.omap_set(CollT::Pg(pg), &object, b"\x81", b"outside-prefix");
        st.commit(&tx).unwrap();
    });
    // Independent wire vector: one binary pair, with another matching key left.
    let expected = [1, 0, 0, 0, 2, 0, 0, 0, 0x80, 0, 2, 0, 0, 0, 0xff, 0, 1];
    ad.ov_nonblock(true);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let read = || loop {
        ad.ov_read_session(Some((73, 1)), true);
        let result = ad.ov_omap_list_reply(pg, &h, None, b"\x80", 1, usize::MAX, true);
        let blocked = ad.ov_take_blocked();
        ad.ov_read_session(None, true);
        if let Ok(reply) = result {
            assert!(!blocked);
            break reply;
        }
        assert!(blocked, "unexpected listing error: {result:?}");
        ad.with_store(|st| {
            st.poll(&mut Vec::new()).unwrap();
            st.idle();
        });
        assert!(
            std::time::Instant::now() < deadline,
            "WARNING TIMEOUT immutable adapter listing exceeded20s"
        );
        std::thread::yield_now();
    };
    let first = read();
    let replay = read();
    assert_eq!(first.as_ref(), expected);
    assert_eq!(replay, first);
    if shared {
        assert_eq!(
            first.as_ptr(),
            replay.as_ptr(),
            "adapter must preserve the frozen memo owner"
        );
    }
    ad.ov_read_session(Some((73, 1)), true);
    ad.ov_read_session(None, false);
    ad.ov_nonblock(false);
    // Exclusive after-key, binary prefix, keys-only budget and empty prefix end.
    let keys = ad
        .ov_omap_list_reply(pg, &h, Some(b"\x80\0"), b"\x80", 10, usize::MAX, false)
        .unwrap();
    assert_eq!(keys.as_ref(), &[1, 0, 0, 0, 2, 0, 0, 0, 0x80, 1, 0]);
    let empty = ad
        .ov_omap_list_reply(pg, &h, None, b"\xfe", 10, 0, true)
        .unwrap();
    assert_eq!(empty.as_ref(), &[0; 5]);
    drop(ad);
    assert_eq!(first.as_ref(), expected);
    assert_eq!(replay.as_ref(), expected);
}

#[test]
fn immutable_listing_native_tree_preserves_wire_and_lifetime() {
    let (_, ad, _) = new_adapter(64, 1, 771);
    check_listing(ad, false);
}

#[test]
fn immutable_listing_native_lsm_preserves_wire_and_lifetime() {
    with_omap_lsm(|| {
        let (_, ad, _) = new_adapter(64, 1, 772);
        check_listing(ad, false);
    });
}

#[cfg(feature = "rocksdb")]
#[test]
fn immutable_listing_rocks_preserves_wire_and_shared_retry() {
    use store::dev::{SimClock, SimDisk};
    use store::layout::{MkfsParams, mkfs};
    use store::obj::{Store, StoreCfg};
    use store::rocks_omap::{Config, create};
    let root = std::env::temp_dir().join(format!("immutable-listing-rocks-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let disk = SimDisk::new(sim_cfg(64, 773));
    let (sb, _) = mkfs(
        &mut disk.queue(),
        &mut SimClock::default(),
        &MkfsParams {
            shards: 1,
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
    let st = Store::mount(move || disk.queue(), SimClock::default(), cfg)
        .unwrap()
        .0;
    check_listing(storeadapt::StoreAdapter::new(st), true);
    std::fs::remove_dir_all(root).unwrap();
}
