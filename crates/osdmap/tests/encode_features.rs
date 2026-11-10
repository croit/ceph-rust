// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Full-map re-encode for an incremental's `encode_features` (spec osdmap 1.3, 2, 3.3): during an upgrade window
//! (`require_osd_release` below umbrella) the mon encodes pools as v32 / v29, and the `full_crc` check must use the
//! same encoding, else every epoch falls back to a full-map fetch.

use denc::Encoder;
use denc::features::{ALL, SERVER_REEF, SERVER_TENTACLE, SERVER_UMBRELLA};
use osdmap::pool::flags;
use osdmap::{Incremental, OsdMap};

const UMBRELLA_BIT: u64 = 1 << 52;
const TENTACLE_BIT: u64 = 1 << 50;

fn golden() -> OsdMap {
    OsdMap::decode_from(include_bytes!("../../../testdata/osdmap/full/0091.bin")).unwrap()
}

fn pool_bytes(p: &osdmap::PgPool, v: u8) -> Vec<u8> {
    let mut e = Encoder::new();
    p.encode_v(&mut e, v).unwrap();
    e.into_vec()
}

/// Independent byte oracle: a replicated pool's v32 encoding is its v33 encoding without the three v33 tail fields
/// (empty shard_mapping u32 0, two absent options u8 0 each = 6 bytes), with struct_v 32 and the length 6 shorter;
/// v32 also masks CLIENT_SPLIT_READS out of the flags.
#[test]
fn pool_v32_is_v33_without_the_umbrella_tail() {
    let m = golden();
    let (_, p) = m.pools.iter().find(|(_, p)| p.ptype == 1).unwrap();
    let p = p.clone();
    assert_eq!(p.version_for(ALL), 33);
    assert_eq!(p.version_for(ALL & !UMBRELLA_BIT), 32);
    assert_eq!(p.version_for(ALL & !UMBRELLA_BIT & !TENTACLE_BIT), 29);
    // the v21 mon sets the umbrella-only split-reads flag on new replicated pools; v32 masks it out
    assert_ne!(p.flags & flags::CLIENT_SPLIT_READS, 0);
    let mut plain = p.clone();
    plain.flags &= !flags::CLIENT_SPLIT_READS;
    let v33 = pool_bytes(&plain, 33);
    let mut want = v33[..v33.len() - 6].to_vec();
    assert_eq!(&v33[v33.len() - 6..], &[0, 0, 0, 0, 0, 0]);
    want[0] = 32;
    let len = u32::from_le_bytes(want[2..6].try_into().unwrap()) - 6;
    want[2..6].copy_from_slice(&len.to_le_bytes());
    assert_eq!(pool_bytes(&p, 32), want);
    assert_eq!(pool_bytes(&plain, 32), want);
    assert_ne!(pool_bytes(&p, 33), v33);
}

/// C5: an incremental encoded for tentacle (no SERVER_UMBRELLA) applies with its crc instead of failing over to a
/// full-map fetch; the result is identical to the all-features apply.
#[test]
fn tentacle_encoded_incremental_passes_the_full_crc_check() {
    let base = golden();
    let feats = ALL & !UMBRELLA_BIT;
    assert!(
        denc::features::have(feats, SERVER_TENTACLE) && denc::features::have(feats, SERVER_REEF)
    );
    assert!(!denc::features::have(feats, SERVER_UMBRELLA));
    let mut inc = Incremental {
        fsid: base.fsid,
        epoch: base.epoch + 1,
        encode_features: feats,
        has_crc: true,
        ..Default::default()
    };
    let mut applied = base.clone();
    applied.apply_incremental(&inc).unwrap();
    // the mon's bytes: pools v32 (oracle above), client part v10 (reef+)
    let mon_crc = applied.crc(feats).unwrap();
    assert_ne!(
        mon_crc,
        applied.crc(0).unwrap(),
        "v32 pools change the bytes"
    );
    inc.full_crc = mon_crc;
    let got = base.apply_incremental_checked(&inc).unwrap();
    assert_eq!(got.epoch, base.epoch + 1);
    // pre-reef features: client part v9 without pg_upmap_primaries
    let squid = ALL & !UMBRELLA_BIT & !TENTACLE_BIT & !(1 << 31);
    let b = applied.encode_with_features(squid).unwrap();
    assert_eq!(b[6], 9, "client part struct_v");
    let full = applied.encode_with_features(0).unwrap();
    assert_eq!(full[6], 10);
}

/// Synthetic session-fencing maps: a no-op epoch, an IPv4 blocklist insertion
/// (43 wire bytes), then another no-op. Expected maps are built independently
/// of incremental apply, including the retained release-derived flags.
#[test]
fn no_op_epochs_and_blocklist_insertion_preserve_full_crc() {
    use denc::types::{EntityAddr, UTime, Uuid};
    let mut base = OsdMap::default();
    base.fsid = Uuid([7; 16]);
    base.epoch = 10;
    base.set_max_osd(1);
    base.require_osd_release = osdmap::consts::release::NAUTILUS;
    base.flags =
        osdmap::consts::map_flags::PGLOG_HARDLIMIT | osdmap::consts::map_flags::RECOVERY_DELETES;
    let address = EntityAddr::v4(EntityAddr::TYPE_ANY, 123, [192, 0, 2, 1], 40000);
    for epoch in 11..=13 {
        let mut expected = base.clone();
        expected.epoch = epoch;
        expected.modified = UTime {
            sec: epoch,
            nsec: 100,
        };
        let mut inc = Incremental {
            fsid: base.fsid,
            epoch,
            modified: expected.modified,
            ..Default::default()
        };
        if epoch == 12 {
            let expiry = UTime { sec: 1000, nsec: 0 };
            expected.blocklist.insert(address, expiry);
            inc.new_blocklist.insert(address, expiry);
            assert_eq!(
                expected.encode_full().unwrap().len(),
                base.encode_full().unwrap().len() + 43
            );
        }
        inc.full_crc = expected.crc(inc.encode_features).unwrap();
        let inc = Incremental::decode_from(&inc.encode_inc().unwrap()).unwrap();
        let applied = base.apply_incremental_checked(&inc).unwrap();
        assert_eq!(applied, expected);
        let bytes = expected.encode_full().unwrap();
        assert_eq!(
            OsdMap::decode_from(&bytes).unwrap().encode_full().unwrap(),
            bytes
        );
        base = applied;
    }
}

/// Wire addresses retain their connection type. Stored exact-blocklist keys
/// must match the protocol-independent full-map/lookup domain instead.
#[test]
fn typed_blocklist_incrementals_match_normalized_full_maps() {
    use denc::types::{EntityAddr, UTime, Uuid};
    for release in [20, 21] {
        for ty in [EntityAddr::TYPE_LEGACY, EntityAddr::TYPE_MSGR2] {
            let raw_address = EntityAddr::v4(ty, 123, [192, 0, 2, 7], 40000);
            let address = EntityAddr {
                ty: EntityAddr::TYPE_ANY,
                ..raw_address
            };
            let mut base = OsdMap::default();
            base.fsid = Uuid([7; 16]);
            base.epoch = 10;
            base.require_osd_release = release;
            base.flags = osdmap::consts::map_flags::PGLOG_HARDLIMIT
                | osdmap::consts::map_flags::RECOVERY_DELETES;
            base.blocklist.insert(address, UTime { sec: 100, nsec: 0 });
            let mut expected = base.clone();
            expected.epoch = 11;
            let expiry = UTime { sec: 200, nsec: 0 };
            let inc = Incremental {
                fsid: base.fsid,
                epoch: 11,
                new_blocklist: [(raw_address, expiry)].into(),
                full_crc: expected.crc(0).unwrap(),
                ..Default::default()
            };
            let raw = inc.encode_inc().unwrap();
            let decoded = Incremental::decode_from(&raw).unwrap();
            assert_eq!(decoded.encode_inc().unwrap(), raw);
            assert!(decoded.new_blocklist.contains_key(&raw_address));
            let applied = base.apply_incremental_checked(&decoded).unwrap();
            assert_eq!(applied, expected);
            assert_eq!(
                applied.blocklist.len(),
                1,
                "duplicate must retain the canonical key and its expiry"
            );
            assert!(applied.is_blocklisted(&raw_address));
            let remove = Incremental {
                fsid: base.fsid,
                epoch: 12,
                old_blocklist: vec![raw_address],
                ..Default::default()
            };
            let mut removed = applied;
            removed.apply_incremental(&remove).unwrap();
            assert!(removed.blocklist.is_empty());

            // A full map establishes the identical logical key domain, after
            // validating the CRC of its original (typed-address) wire bytes.
            let mut wire_full = expected.clone();
            wire_full.blocklist = [(raw_address, base.blocklist[&address])].into();
            let raw_full = wire_full.encode_full().unwrap();
            assert_eq!(OsdMap::decode_from(&raw_full).unwrap(), expected);
            let mut corrupt = raw_full;
            *corrupt.last_mut().unwrap() ^= 1;
            assert!(matches!(
                OsdMap::decode_from(&corrupt),
                Err(osdmap::Error::BadCrc { .. })
            ));
        }
    }
}

#[test]
fn duplicate_blocklist_additions_retain_existing_expiry_and_full_crc() {
    use denc::types::{EntityAddr, UTime, Uuid};
    for release in [20, 21] {
        let address = EntityAddr::v4(EntityAddr::TYPE_ANY, 42, [192, 0, 2, 9], 0);
        let original = UTime {
            sec: 500,
            nsec: 123,
        };
        let mut base = OsdMap::default();
        base.fsid = Uuid([9; 16]);
        base.epoch = 100;
        base.require_osd_release = release;
        base.blocklist.insert(address, original);
        for expiry in [UTime { sec: 400, nsec: 1 }, UTime { sec: 600, nsec: 2 }] {
            let mut expected = base.clone();
            expected.epoch += 1;
            expected.modified = UTime { sec: 200, nsec: 3 };
            let inc = Incremental {
                fsid: base.fsid,
                epoch: expected.epoch,
                modified: expected.modified,
                new_blocklist: [(address, expiry)].into(),
                full_crc: expected.crc(0).unwrap(),
                ..Default::default()
            };
            let decoded = Incremental::decode_from(&inc.encode_inc().unwrap()).unwrap();
            let applied = base.apply_incremental_checked(&decoded).unwrap();
            assert_eq!(applied, expected);
            assert_eq!(applied.blocklist[&address], original);
        }
    }
}

#[test]
fn release_transition_rekeys_existing_blocklist_before_typed_removal() {
    use denc::types::{EntityAddr, UTime, Uuid};
    let address = EntityAddr::v4(EntityAddr::TYPE_LEGACY, 123, [192, 0, 2, 8], 40000);
    let mut base = OsdMap::default();
    base.fsid = Uuid([7; 16]);
    base.epoch = 10;
    base.require_osd_release = osdmap::consts::release::MIMIC;
    base.blocklist.insert(address, UTime { sec: 100, nsec: 0 });
    let inc = Incremental {
        fsid: base.fsid,
        epoch: 11,
        new_require_osd_release: osdmap::consts::release::NAUTILUS,
        old_blocklist: vec![EntityAddr {
            ty: EntityAddr::TYPE_MSGR2,
            ..address
        }],
        ..Default::default()
    };
    base.apply_incremental(&inc).unwrap();
    assert!(base.blocklist.is_empty());
}
