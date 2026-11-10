// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Golden vectors from ceph-dencoder (testdata/denc, regenerate with gen.sh).

use denc::types::*;
use denc::{Decode, Encode, features, from_slice};
use std::fs;
use std::path::PathBuf;

fn dir(t: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/denc")
        .join(t)
}

fn read_json(t: &str, n: usize) -> String {
    let s = fs::read_to_string(dir(t).join(format!("{n}.json"))).unwrap();
    s.split_whitespace().collect::<String>()
}

/// Decode every `<n><suffix>.bin`, re-encode with `feat`, require identical bytes. Returns count.
fn roundtrip<T>(t: &str, suffix: &str, feat: u64, mut check: impl FnMut(usize, &T)) -> usize
where
    T: for<'a> Decode<'a> + Encode,
{
    let mut n = 1;
    loop {
        let p = dir(t).join(format!("{n}{suffix}.bin"));
        let Ok(bytes) = fs::read(&p) else { break };
        let v: T = from_slice(&bytes).unwrap_or_else(|e| panic!("{t} {n}{suffix}: {e}"));
        let re = v.encode_to_vec_with_features(feat).unwrap();
        assert_eq!(re, bytes, "{t} {n}{suffix} re-encode");
        check(n, &v);
        n += 1;
    }
    assert!(n > 1, "no vectors for {t}");
    n - 1
}

fn plain<T: for<'a> Decode<'a> + Encode>(t: &str) -> usize {
    roundtrip::<T>(t, "", features::ALL, |_, _| {})
}

#[test]
fn simple_types() {
    assert_eq!(plain::<UTime>("utime_t"), 3);
    assert_eq!(plain::<Uuid>("uuid_d"), 4);
    assert_eq!(plain::<EntityName>("entity_name_t"), 4);
    assert_eq!(plain::<Vec<u8>>("object_t"), 2);
    assert_eq!(plain::<SObject>("sobject_t"), 2);
    assert_eq!(plain::<ShardId>("shard_id_t"), 2);
    assert_eq!(plain::<PgT>("pg_t"), 4);
    assert_eq!(plain::<SpgT>("spg_t"), 2);
    assert_eq!(plain::<PgShard>("pg_shard_t"), 3);
    assert_eq!(plain::<CollT>("coll_t"), 6);
    assert_eq!(plain::<Eversion>("eversion_t"), 2);
    assert_eq!(plain::<OsdReqId>("osd_reqid_t"), 2);
}

#[test]
fn json_spot_checks() {
    roundtrip::<PgT>("pg_t", "", features::ALL, |n, v| {
        let j = read_json("pg_t", n);
        assert!(
            j.contains(&format!("\"pool\":{}", v.pool))
                && j.contains(&format!("\"seed\":{}", v.seed))
        );
    });
    roundtrip::<Uuid>("uuid_d", "", features::ALL, |n, v| {
        assert!(read_json("uuid_d", n).contains(&v.to_string()));
    });
    roundtrip::<UTime>("utime_t", "", features::ALL, |n, v| {
        let j = read_json("utime_t", n);
        assert!(
            j.contains(&format!("\"seconds\":{}", v.sec))
                && j.contains(&format!("\"nanoseconds\":{}", v.nsec))
        );
    });
    roundtrip::<ObjectLocator>("object_locator_t", "", features::ALL, |n, v| {
        let j = read_json("object_locator_t", n);
        assert!(j.contains(&format!("\"pool\":{}", v.pool)));
        assert!(j.contains(&format!("\"hash\":{}", v.hash)));
        assert!(j.contains(&format!("\"key\":\"{}\"", String::from_utf8_lossy(&v.key))));
    });
    roundtrip::<Hobject>("hobject_t", "", features::ALL, |n, v| {
        let j = read_json("hobject_t", n);
        assert!(j.contains(&format!("\"oid\":\"{}\"", String::from_utf8_lossy(&v.oid))));
        assert!(j.contains(&format!("\"hash\":{}", v.hash)));
        assert!(j.contains(&format!("\"pool\":{}", v.pool)));
        assert!(j.contains(&format!("\"max\":{}", v.max as u8)));
        assert!(j.contains(&format!("\"snapid\":{}", v.snap.0 as i64)));
    });
    roundtrip::<Ghobject>("ghobject_t", "", features::ALL, |n, v| {
        let j = read_json("ghobject_t", n);
        assert!(j.contains(&format!(
            "\"oid\":\"{}\"",
            String::from_utf8_lossy(&v.hobj.oid)
        )));
        assert!(j.contains(&format!("\"pool\":{}", v.hobj.pool)));
        if v.generation != Ghobject::NO_GEN {
            assert!(j.contains(&format!("\"generation\":{}", v.generation)));
            assert!(j.contains(&format!("\"shard_id\":{}", v.shard.0)));
        }
    });
}

#[test]
fn object_locator_and_hobject_counts() {
    assert_eq!(plain::<ObjectLocator>("object_locator_t"), 6);
    assert_eq!(plain::<Hobject>("hobject_t"), 5);
    assert_eq!(plain::<Ghobject>("ghobject_t"), 11);
}

fn featured<T: for<'a> Decode<'a> + Encode>(t: &str, count: usize) {
    const NO_ADDR2: u64 = !(1u64 << 59);
    const NO_NAUTILUS: u64 = !4u64;
    assert_eq!(roundtrip::<T>(t, "", features::ALL, |_, _| {}), count);
    assert_eq!(roundtrip::<T>(t, ".noaddr2", NO_ADDR2, |_, _| {}), count);
    assert_eq!(
        roundtrip::<T>(t, ".nonautilus", NO_NAUTILUS, |_, _| {}),
        count
    );
}

#[test]
fn addr_types_all_feature_sets() {
    featured::<EntityAddr>("entity_addr_t", 3);
    featured::<EntityAddrVec>("entity_addrvec_t", 3);
    featured::<EntityInst>("entity_inst_t", 2);
}

#[test]
fn addr_json() {
    let b = fs::read(dir("entity_addr_t").join("3.bin")).unwrap();
    let a: EntityAddr = from_slice(&b).unwrap();
    assert_eq!(
        (a.ty, a.nonce, a.ipv4(), a.port()),
        (1, 5, Some([127, 0, 1, 2]), 2)
    );
    // legacy form decodes to the same value
    let b = fs::read(dir("entity_addr_t").join("3.noaddr2.bin")).unwrap();
    assert_eq!(from_slice::<EntityAddr>(&b).unwrap(), a);
}
