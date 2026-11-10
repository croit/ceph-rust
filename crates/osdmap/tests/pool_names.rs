// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use denc::{Encode, types::Uuid};
use osdmap::{Incremental, OsdMap, PgPool, PoolName};
use std::collections::BTreeMap;

#[test]
fn literal_raw_name_record_and_truncated_inputs() {
    let name_wire = [3, 0, 0, 0, 255, 0, 254];
    let name: PoolName = denc::from_slice(&name_wire).unwrap();
    assert_eq!(name.as_bytes(), &[255, 0, 254]);
    assert!(name.as_utf8().is_err());
    assert_eq!(name.encode_to_vec().unwrap(), name_wire);
    for end in 0..name_wire.len() {
        assert!(denc::from_slice::<PoolName>(&name_wire[..end]).is_err());
    }
    let record = [1, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 255, 0, 254];
    let names: BTreeMap<i64, PoolName> = denc::from_slice(&record).unwrap();
    assert_eq!(names[&9], name);
    assert_eq!(names.encode_to_vec().unwrap(), record);
}
#[test]
fn exact_lookup_and_full_incremental_rename_delete_roundtrip() {
    let mut m = OsdMap::default();
    m.fsid = Uuid([7; 16]);
    m.epoch = 1;
    let raw: PoolName = vec![b'p', 0, 255].into();
    for (id, name) in [(1, raw.clone()), (2, "p".into()), (3, "p\0�".into())] {
        m.pools.insert(id, PgPool::default());
        m.pool_name.insert(id, name);
    }
    let bytes = m.encode_full().unwrap();
    let mut decoded = OsdMap::decode_from(&bytes).unwrap();
    assert_eq!(decoded.encode_full().unwrap(), bytes);
    assert_eq!(decoded.pool_id_by_name_bytes(raw.as_bytes()), Some(1));
    assert_eq!(decoded.pool_id_by_name("p"), Some(2));
    assert_eq!(decoded.pool_id_by_name("p\0�"), Some(3));
    assert_eq!(decoded.pool_id_by_name_bytes(b"p\0"), None);
    assert_eq!(decoded.pool_name[&1].as_bytes(), raw.as_bytes());
    let mut inc = Incremental {
        fsid: m.fsid,
        epoch: 2,
        ..Default::default()
    };
    inc.new_pool_names.insert(1, vec![254, b'x', 0].into());
    inc.old_pools.insert(2);
    let mut expected = decoded.clone();
    expected.apply_incremental(&inc).unwrap();
    inc.full_crc = expected.crc(0).unwrap();
    let inc_bytes = inc.encode_inc().unwrap();
    let decoded_inc = Incremental::decode_from(&inc_bytes).unwrap();
    assert_eq!(decoded_inc.encode_inc().unwrap(), inc_bytes);
    decoded = decoded.apply_incremental_checked(&decoded_inc).unwrap();
    assert_eq!(decoded.pool_id_by_name_bytes(raw.as_bytes()), None);
    assert_eq!(decoded.pool_id_by_name_bytes(&[254, b'x', 0]), Some(1));
    assert!(decoded.pool(2).is_none());
    assert!(!decoded.pool_name.contains_key(&2));
    let adopted = OsdMap::decode_from(&decoded.encode_full().unwrap()).unwrap();
    assert_eq!(adopted.pool_name, decoded.pool_name);
}
#[test]
fn diagnostics_are_never_an_identity_projection() {
    let raw: PoolName = vec![255, b'\n', 0, b'\\'].into();
    assert_eq!(raw.to_string(), "\\xff\\n\\x00\\\\");
    let escaped: PoolName = raw.to_string().into();
    assert_ne!(raw, escaped);
    let utf8: PoolName = "pöol\n\0\\".into();
    assert_eq!(utf8.as_utf8().unwrap(), "pöol\n\0\\");
    assert_eq!(utf8.to_string(), "pöol\\n\\u{0}\\\\");
    let empty: PoolName = "".into();
    assert!(empty.as_bytes().is_empty()); // codec does not impose create policy
}
