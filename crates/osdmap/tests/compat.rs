// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Own RC-COMPAT57 vectors; literal release IDs deliberately independent of constants.
use crush::*;
use denc::types::PgT;
use osdmap::{OsdMap, PgPool};

fn legacy() -> CrushMap {
    let mut c = CrushMap::new();
    c.tunables = Tunables::legacy();
    c
}
fn map(c: &CrushMap) -> OsdMap {
    let mut m = OsdMap::default();
    m.set_crush(c.encode());
    m
}
fn minimum(c: &CrushMap) -> u8 {
    map(c).derived_min_compat_client().unwrap()
}

#[test]
fn tunable_profiles_and_independent_changes() {
    for (profile, expected) in [
        (Tunables::legacy(), 1),
        (Tunables::bobtail(), 4),
        (Tunables::firefly(), 6),
        (Tunables::hammer(), 6),
        (Tunables::jewel(), 10),
    ] {
        let mut c = legacy();
        c.tunables = profile;
        assert_eq!(minimum(&c), expected);
    }
    for field in 0..9 {
        let mut c = legacy();
        let (value, expected) = match field {
            0 => (&mut c.tunables.choose_local_tries, 1),
            1 => (&mut c.tunables.choose_local_fallback_tries, 1),
            2 => (&mut c.tunables.choose_total_tries, 1),
            3 => (&mut c.tunables.chooseleaf_descend_once, 4),
            4 => (&mut c.tunables.msr_descents, 19),
            5 => (&mut c.tunables.msr_collision_tries, 19),
            6 => (&mut c.tunables.allowed_bucket_algs, 1),
            7 => {
                c.tunables.straw_calc_version = 1;
                assert_eq!(minimum(&c), 1);
                continue;
            }
            _ => {
                c.tunables.chooseleaf_vary_r = 2;
                assert_eq!(minimum(&c), 6);
                continue;
            }
        };
        *value += 1;
        assert_eq!(minimum(&c), expected, "field {field}");
    }
}

#[test]
fn pool_features_affinity_and_raw_policy_are_distinct() {
    let c = legacy();
    let mut m = map(&c);
    m.require_min_compat_client = 255;
    m.require_osd_release = 21;
    assert_eq!(m.derived_min_compat_client(), Some(1));
    let p = PgPool {
        flags: 1,
        ..Default::default()
    };
    m.pools.insert(12, p);
    assert_eq!(m.derived_min_compat_client(), Some(4));
    m.pools.get_mut(&12).unwrap().tier_of = 0;
    assert_eq!(m.derived_min_compat_client(), Some(6));
    m.pools.get_mut(&12).unwrap().tier_of = -1;
    m.pools.get_mut(&12).unwrap().tiers.insert(88);
    assert_eq!(m.derived_min_compat_client(), Some(6));
    m.pools.clear();
    m.max_osd = 2;
    m.osd_primary_affinity = vec![0x10000, 0x10000, 0];
    assert_eq!(m.derived_min_compat_client(), Some(1)); // outside max_osd ignored
    m.osd_primary_affinity[1] = 0xffff;
    assert_eq!(m.derived_min_compat_client(), Some(6));
    m.osd_primary_affinity.clear();
    assert_eq!(m.derived_min_compat_client(), Some(1));
}

#[test]
fn used_rule_steps_but_all_msr_rules_and_buckets() {
    for (op, expected) in [
        (OP_SET_CHOOSELEAF_VARY_R, 6),
        (OP_SET_CHOOSELEAF_STABLE, 10),
        (OP_SET_CHOOSE_TRIES, 1),
        (OP_SET_MSR_DESCENTS, 1),
    ] {
        let mut c = legacy();
        c.rules = vec![
            None,
            Some(Rule::new(RULE_REPLICATED, vec![Step::new(op, 0, 0)])),
        ];
        assert_eq!(minimum(&c), 1, "unused step {op}");
        let mut m = map(&c);
        let p = PgPool {
            crush_rule: 1,
            ..Default::default()
        };
        m.pools.insert(7, p);
        assert_eq!(m.derived_min_compat_client(), Some(expected));
        m.pools.get_mut(&7).unwrap().crush_rule = 0; // hole
        assert_eq!(m.derived_min_compat_client(), Some(1));
        m.pools.get_mut(&7).unwrap().crush_rule = 255;
        assert_eq!(m.derived_min_compat_client(), Some(1));
    }
    for kind in [RULE_MSR_FIRSTN, RULE_MSR_INDEP] {
        let mut c = legacy();
        c.rules = vec![None, Some(Rule::new(kind, vec![]))];
        assert_eq!(minimum(&c), 19); // no pool uses this rule
    }
    let mut c = legacy();
    c.buckets.push(Some(Bucket {
        id: -1,
        btype: 1,
        hash: 0,
        weight: 0,
        items: vec![],
        kind: BucketKind::Straw2 {
            item_weights: vec![],
        },
    }));
    assert_eq!(minimum(&c), 8);
}

#[test]
fn choose_args_compatibility_boundary() {
    let mut c = legacy();
    // A bucket supplies one real choose-arg slot in the CRUSH wire codec.
    c.buckets.push(Some(Bucket {
        id: -1,
        btype: 1,
        hash: 0,
        weight: 1,
        items: vec![0],
        kind: BucketKind::Straw2 {
            item_weights: vec![1],
        },
    }));
    for (key, arg, expected) in [
        (-1, ChooseArg::default(), 8),
        (
            -1,
            ChooseArg {
                ids: vec![],
                weight_set: vec![vec![1]],
            },
            8,
        ),
        (
            -1,
            ChooseArg {
                ids: vec![],
                weight_set: vec![vec![1], vec![1]],
            },
            12,
        ),
        (
            -1,
            ChooseArg {
                ids: vec![0],
                weight_set: vec![],
            },
            12,
        ),
        (7, ChooseArg::default(), 12),
    ] {
        c.choose_args.clear();
        c.choose_args
            .insert(key, [(0u32, arg)].into_iter().collect());
        assert_eq!(minimum(&c), expected, "key {key}");
    }
    c.choose_args
        .insert(-1, [(0u32, ChooseArg::default())].into_iter().collect());
    assert_eq!(minimum(&c), 12);
}

#[test]
fn upmaps_and_highest_feature_precedence_roundtrip() {
    let mut c = legacy();
    c.tunables.chooseleaf_stable = 1;
    let mut m = map(&c);
    let pg = PgT { pool: 1, seed: 0 };
    m.pg_upmap.insert(pg, vec![0, 1]);
    assert_eq!(m.derived_min_compat_client(), Some(12));
    m.pg_upmap.clear();
    m.pg_upmap_items.insert(pg, vec![(0, 1)]);
    assert_eq!(m.derived_min_compat_client(), Some(12));
    m.pg_upmap_primaries.insert(pg, 1);
    assert_eq!(m.derived_min_compat_client(), Some(18));
    c.tunables.msr_descents = 101;
    m.set_crush(c.encode());
    assert_eq!(m.derived_min_compat_client(), Some(19));
    m.require_min_compat_client = 14;
    m.require_osd_release = 21;
    let decoded = OsdMap::decode_from(&m.encode_full().unwrap()).unwrap();
    assert_eq!(decoded.derived_min_compat_client(), Some(19));
    assert_eq!(decoded.require_min_compat_client, 14);
    assert_eq!(decoded.require_osd_release, 21);
}

#[test]
fn missing_or_invalid_crush_is_not_a_release_guess_and_cache_invalidates() {
    let mut m = OsdMap::default();
    assert_eq!(m.derived_min_compat_client(), None);
    m.set_crush(vec![0; 8]);
    assert_eq!(m.derived_min_compat_client(), None);
    m.set_crush(legacy().encode());
    assert_eq!(m.derived_min_compat_client(), Some(1));
    m.set_crush(CrushMap::new().encode());
    assert_eq!(m.derived_min_compat_client(), Some(10));
}
