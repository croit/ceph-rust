// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Spec sec 11 golden mappings, map built with the in-crate builder.

use crush::*;

fn map() -> CrushMap {
    let mut m = CrushMap::new();
    for (id, a, b) in [(-2, 0, 1), (-3, 2, 3), (-4, 4, 5)] {
        m.add_bucket(Bucket::straw2(id, 1, &[(a, 0x10000), (b, 0x10000)]));
    }
    m.add_bucket(Bucket::straw2(
        -1,
        2,
        &[(-2, 0x20000), (-3, 0x20000), (-4, 0x20000)],
    ));
    m.add_rule(
        0,
        Rule::new(
            RULE_REPLICATED,
            vec![
                Step::new(OP_TAKE, -1, 0),
                Step::new(OP_CHOOSELEAF_FIRSTN, 0, 1),
                Step::new(OP_EMIT, 0, 0),
            ],
        ),
    );
    m.add_rule(
        1,
        Rule::new(
            RULE_ERASURE,
            vec![
                Step::new(OP_SET_CHOOSELEAF_TRIES, 5, 0),
                Step::new(OP_TAKE, -1, 0),
                Step::new(OP_CHOOSELEAF_INDEP, 0, 1),
                Step::new(OP_EMIT, 0, 0),
            ],
        ),
    );
    m
}

fn run(m: &CrushMap, rule: usize, w: &[u32]) -> Vec<[i32; 3]> {
    let mut ws = Workspace::new(m, 3);
    (0..8)
        .map(|x| {
            let mut r = [0; 3];
            assert_eq!(m.do_rule(rule, x, &mut r, w, None, &mut ws), 3);
            r
        })
        .collect()
}

#[test]
fn spec_golden() {
    let m = map();
    let all = [0x10000u32; 6];
    assert_eq!(
        run(&m, 0, &all),
        [
            [4, 0, 3],
            [0, 2, 4],
            [4, 3, 0],
            [4, 2, 1],
            [1, 5, 3],
            [5, 2, 0],
            [5, 3, 1],
            [1, 5, 2]
        ]
    );
    assert_eq!(
        run(&m, 1, &all),
        [
            [4, 1, 3],
            [0, 2, 4],
            [4, 3, 1],
            [4, 1, 3],
            [1, 2, 5],
            [5, 2, 1],
            [5, 0, 3],
            [1, 2, 4]
        ]
    );
    let mut w = all;
    w[2] = 0;
    assert_eq!(
        run(&m, 0, &w),
        [
            [4, 0, 3],
            [0, 4, 3],
            [4, 3, 0],
            [4, 1, 3],
            [1, 5, 3],
            [5, 0, 3],
            [5, 3, 1],
            [1, 5, 3]
        ]
    );
    assert_eq!(
        run(&m, 1, &w),
        [
            [4, 1, 3],
            [0, 3, 4],
            [4, 3, 1],
            [4, 1, 3],
            [1, 3, 5],
            [5, 3, 1],
            [5, 0, 3],
            [1, 3, 4]
        ]
    );
    let mut w = all;
    w[0] = 0x8000;
    w[3] = 0x4000;
    assert_eq!(
        run(&m, 0, &w),
        [
            [4, 0, 2],
            [0, 2, 4],
            [4, 0, 2],
            [4, 2, 1],
            [1, 5, 3],
            [5, 2, 0],
            [5, 1, 2],
            [1, 5, 2]
        ]
    );
    assert_eq!(
        run(&m, 1, &w),
        [
            [4, 1, 2],
            [0, 2, 4],
            [4, 2, 1],
            [4, 1, 2],
            [1, 2, 5],
            [5, 2, 1],
            [5, 0, 2],
            [1, 2, 4]
        ]
    );
}

#[test]
fn encode_roundtrip_and_robustness() {
    let m = map();
    let b = m.encode();
    assert_eq!(CrushMap::decode(&b).unwrap(), m);
    // unknown rule / tiny workspace never panic
    let mut ws = Workspace::new(&m, 3);
    let mut r = [0; 3];
    assert_eq!(m.do_rule(9, 1, &mut r, &[0x10000; 6], None, &mut ws), 0);
    let mut big = [0; 8];
    assert_eq!(m.do_rule(0, 1, &mut big, &[0x10000; 6], None, &mut ws), 0);
    // bad magic / trailing garbage
    let mut bad = b.clone();
    bad[0] = 1;
    assert!(CrushMap::decode(&bad).is_err());
    let mut tr = b.clone();
    tr.push(0);
    assert!(CrushMap::decode(&tr).is_err());
}

#[test]
fn legacy_stage_truncations_roundtrip() {
    // Every optional-stage boundary decodes and re-encodes identically.
    let mut m = map();
    m.name_map.insert(0, "osd.0".into());
    let full = m.encode();
    for st in 0..=9u8 {
        let mut mm = m.clone();
        mm.wire_stages = st;
        let b = mm.encode();
        let d = CrushMap::decode(&b).unwrap();
        assert_eq!(d.wire_stages, st);
        assert_eq!(d.encode(), b);
        assert!(b.len() <= full.len());
    }
}

#[test]
fn name_map_64bit_key_quirk() {
    let mut m = map();
    m.wire_stages = 0;
    let mut b = m.encode();
    // Replace the empty trailing maps (3 x u32 count=0) with a 64-bit-key type map entry.
    b.truncate(b.len() - 12);
    b.extend_from_slice(&1u32.to_le_bytes()); // type_map count
    b.extend_from_slice(&5i32.to_le_bytes()); // key lo
    b.extend_from_slice(&0u32.to_le_bytes()); // key hi (reads as len 0)
    b.extend_from_slice(&3u32.to_le_bytes()); // real len
    b.extend_from_slice(b"rak");
    b.extend_from_slice(&[0; 8]); // name_map, rule_name_map empty
    let d = CrushMap::decode(&b).unwrap();
    assert_eq!(d.type_map.get(&5).map(String::as_str), Some("rak"));
}
