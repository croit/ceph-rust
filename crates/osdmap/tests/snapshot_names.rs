// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use denc::{
    Encode,
    types::{UTime, Uuid},
};
use osdmap::{OsdMap, PgPool, pool::PoolSnapInfo};
#[test]
fn literal_snapshot_info_preserves_non_utf8_name_without_wire_change() {
    let wire = [
        2, 2, 23, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 123, 0, 0, 0, 200, 1, 0, 0, 3, 0, 0, 0, 255,
        254, 65,
    ];
    let info: PoolSnapInfo = denc::from_slice(&wire).unwrap();
    assert_eq!(info.snapid, 9);
    assert_eq!(info.stamp, UTime::new(123, 456));
    assert_eq!(info.name, [255, 254, 65]);
    assert_eq!(info.encode_to_vec().unwrap(), wire);
    for end in 0..wire.len() {
        assert!(
            denc::from_slice::<PoolSnapInfo>(&wire[..end]).is_err(),
            "prefix {end}"
        );
    }
}
#[test]
fn raw_snapshot_name_survives_whole_map_adoption() {
    let mut map = OsdMap::default();
    map.fsid = Uuid([7; 16]);
    map.epoch = 1;
    let mut pool = PgPool {
        ptype: 1,
        snap_seq: 9,
        ..Default::default()
    };
    pool.flags |= osdmap::pool::flags::POOL_SNAPS;
    pool.snaps.insert(
        9,
        PoolSnapInfo {
            snapid: 9,
            stamp: UTime::new(123, 456),
            name: vec![255, 254, 65],
        },
    );
    map.pools.insert(7, pool);
    let decoded = OsdMap::decode_from(&map.encode_full().unwrap()).unwrap();
    assert_eq!(decoded.pool(7).unwrap().snaps[&9].name, [255, 254, 65]);
}
