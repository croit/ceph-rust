// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `CrushMap::subtrees_of_type`: device -> enclosing bucket of a type, shadow buckets skipped.

use crush::*;
use std::collections::BTreeMap;

#[test]
fn devices_map_to_their_host_and_shadow_buckets_are_ignored() {
    let mut m = CrushMap::new();
    m.type_map = BTreeMap::from([
        (0, "osd".into()),
        (1, "host".into()),
        (3, "rack".into()),
        (10, "root".into()),
    ]);
    m.add_bucket(Bucket::straw2(-2, 1, &[(0, 1), (1, 1)]));
    m.add_bucket(Bucket::straw2(-3, 1, &[(2, 1), (3, 1)]));
    m.add_bucket(Bucket::straw2(-4, 3, &[(-2, 2), (-3, 2)]));
    m.add_bucket(Bucket::straw2(-1, 10, &[(-4, 4)]));
    // shadow tree for class 0: host~ssd buckets must not claim the devices
    m.add_bucket(Bucket::straw2(-5, 1, &[(3, 1), (0, 1)]));
    m.class_bucket = BTreeMap::from([(-2, BTreeMap::from([(0, -5)]))]);
    let h = m.subtrees_of_type("host");
    assert_eq!(h, BTreeMap::from([(0, -2), (1, -2), (2, -3), (3, -3)]));
    let r = m.subtrees_of_type("rack");
    assert_eq!(r, BTreeMap::from([(0, -4), (1, -4), (2, -4), (3, -4)]));
    assert!(m.subtrees_of_type("datacenter").is_empty());
}

/// `CrushMap::location_ids`: nearest-first ancestors, shadow buckets skipped, one bucket per type, unnamed item = none.
#[test]
fn location_ids_walk_the_real_hierarchy() {
    let mut m = CrushMap::new();
    m.type_map = BTreeMap::from([
        (0, "osd".into()),
        (1, "host".into()),
        (3, "rack".into()),
        (10, "root".into()),
    ]);
    m.add_bucket(Bucket::straw2(-2, 1, &[(0, 1), (1, 1)]));
    m.add_bucket(Bucket::straw2(-3, 1, &[(2, 1)]));
    m.add_bucket(Bucket::straw2(-4, 3, &[(-2, 2)]));
    m.add_bucket(Bucket::straw2(-1, 10, &[(-4, 2), (-3, 1)]));
    // shadow host~ssd (lower index than nothing real, but must never be taken as the parent)
    m.add_bucket(Bucket::straw2(-5, 1, &[(0, 1)]));
    m.class_bucket = BTreeMap::from([(-2, BTreeMap::from([(0, -5)]))]);
    // a second rack-typed bucket above the first rack: only the nearest rack counts
    m.add_bucket(Bucket::straw2(-6, 3, &[(-1, 1)]));
    for (i, n) in [(0, "osd.0"), (1, "osd.1"), (2, "osd.2")] {
        m.name_map.insert(i, n.into());
    }
    assert_eq!(m.location_ids(0), vec![-2, -4, -1]);
    // osd.2's path has no rack below the root: the rack above the root is its rack
    assert_eq!(m.location_ids(2), vec![-3, -1, -6]);
    assert!(m.location_ids(7).is_empty(), "unnamed item");
    // a cycle ends the walk
    m.add_bucket(Bucket::straw2(-7, 10, &[(-6, 1)]));
    m.buckets[0].as_mut().unwrap().items.push(-7);
    assert_eq!(m.location_ids(2), vec![-3, -1, -6]);
}
