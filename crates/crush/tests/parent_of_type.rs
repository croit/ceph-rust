// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `CrushMap::parent_of_type` within a rule's take roots (doc/spec/stretch.md 2): the barrier bucket stretch
//! peering counts an OSD in.

use crush::*;
use std::collections::BTreeMap;

const HOST: u16 = 1;
const DC: u16 = 8;
const ROOT: u16 = 11;

/// Oracle layout (stretch.md 9): root default -1 = [dc1 -3, dc2 -10]; dc1 = hosts -2 (osd.0), -4 (osd.1); dc2 = hosts
/// -5 (osd.2), -6 (osd.3). Rule 1 = take default / choose 0 datacenter / chooseleaf 2 host / emit.
fn oracle_map() -> CrushMap {
    let mut m = CrushMap::new();
    m.type_map = BTreeMap::from([
        (0, "osd".into()),
        (1, "host".into()),
        (8, "datacenter".into()),
        (11, "root".into()),
    ]);
    m.add_bucket(Bucket::straw2(-2, HOST, &[(0, 1)]));
    m.add_bucket(Bucket::straw2(-4, HOST, &[(1, 1)]));
    m.add_bucket(Bucket::straw2(-5, HOST, &[(2, 1)]));
    m.add_bucket(Bucket::straw2(-6, HOST, &[(3, 1)]));
    m.add_bucket(Bucket::straw2(-3, DC, &[(-2, 1), (-4, 1)]));
    m.add_bucket(Bucket::straw2(-10, DC, &[(-5, 1), (-6, 1)]));
    m.add_bucket(Bucket::straw2(-1, ROOT, &[(-3, 2), (-10, 2)]));
    m.add_rule(
        1,
        Rule::new(
            RULE_REPLICATED,
            vec![
                Step::new(OP_TAKE, -1, 0),
                Step::new(OP_CHOOSE_FIRSTN, 0, 8),
                Step::new(OP_CHOOSELEAF_FIRSTN, 2, 1),
                Step::new(OP_EMIT, 0, 0),
            ],
        ),
    );
    m
}

#[test]
fn osds_map_to_their_site() {
    let m = oracle_map();
    assert_eq!(m.parent_of_type(0, 8, 1), -3);
    assert_eq!(m.parent_of_type(1, 8, 1), -3);
    assert_eq!(m.parent_of_type(2, 8, 1), -10);
    assert_eq!(m.parent_of_type(3, 8, 1), -10);
    // host level works the same way
    assert_eq!(m.parent_of_type(3, 1, 1), -6);
}

#[test]
fn not_found_is_bucket_zero() {
    let mut m = oracle_map();
    // osd outside the take root, NONE hole, unknown rule, negative rule, unknown barrier type
    m.add_bucket(Bucket::straw2(-7, HOST, &[(7, 1)]));
    assert_eq!(m.parent_of_type(7, 8, 1), 0);
    assert_eq!(m.parent_of_type(ITEM_NONE, 8, 1), 0);
    assert_eq!(m.parent_of_type(0, 8, 9), 0);
    assert_eq!(m.parent_of_type(0, 8, -1), 0);
    assert_eq!(m.parent_of_type(0, 9, 1), 0);
    assert_eq!(m.parent_of_type(0, 1 << 20, 1), 0);
}

#[test]
fn lower_type_stops_the_walk() {
    let mut m = oracle_map();
    // a host directly under the root: not inside any datacenter, so its osd has no site even though it is below root
    m.add_bucket(Bucket::straw2(-7, HOST, &[(9, 1)]));
    m.add_bucket(Bucket::straw2(-1, ROOT, &[(-3, 2), (-10, 2), (-7, 1)]));
    assert_eq!(m.parent_of_type(9, 8, 1), 0);
    assert_eq!(m.parent_of_type(9, 1, 1), -7);
}

#[test]
fn placement_steps_are_irrelevant_only_take_roots_count() {
    let mut m = oracle_map();
    // a second rule that takes dc2 only: osd.0 (dc1) is outside its roots
    m.add_rule(
        2,
        Rule::new(
            RULE_REPLICATED,
            vec![
                Step::new(OP_TAKE, -10, 0),
                Step::new(OP_CHOOSELEAF_FIRSTN, 0, 1),
                Step::new(OP_EMIT, 0, 0),
            ],
        ),
    );
    assert_eq!(m.parent_of_type(0, 8, 2), 0);
    // the take root itself is of the barrier type: it is the candidate
    assert_eq!(m.parent_of_type(2, 8, 2), -10);
}

#[test]
fn take_roots_are_visited_most_negative_first() {
    let mut m = oracle_map();
    // osd.0 also sits in dc -42 below root -41; rule takes -1 first, then -41: -41 < -1 wins
    m.add_bucket(Bucket::straw2(-42, DC, &[(-2, 1)]));
    m.add_bucket(Bucket::straw2(-41, ROOT, &[(-42, 1)]));
    m.add_rule(
        3,
        Rule::new(
            RULE_REPLICATED,
            vec![
                Step::new(OP_TAKE, -1, 0),
                Step::new(OP_CHOOSELEAF_FIRSTN, 1, 1),
                Step::new(OP_EMIT, 0, 0),
                Step::new(OP_TAKE, -41, 0),
                Step::new(OP_CHOOSELEAF_FIRSTN, 1, 1),
                Step::new(OP_EMIT, 0, 0),
            ],
        ),
    );
    assert_eq!(m.parent_of_type(0, 8, 3), -42);
    assert_eq!(m.parent_of_type(2, 8, 3), -10);
}

#[test]
fn within_a_root_item_order_decides() {
    let mut m = oracle_map();
    // osd.0 under both sites; root lists dc2 first
    m.add_bucket(Bucket::straw2(-10, DC, &[(-5, 1), (-6, 1), (-2, 1)]));
    m.add_bucket(Bucket::straw2(-1, ROOT, &[(-10, 3), (-3, 2)]));
    assert_eq!(m.parent_of_type(0, 8, 1), -10);
}

#[test]
fn device_class_rule_yields_shadow_buckets() {
    let mut m = oracle_map();
    // shadow tree for class 0 (ssd): -20 = default~ssd, -21 = dc1~ssd, -22 = dc2~ssd, shadow hosts -23..-26
    m.add_bucket(Bucket::straw2(-23, HOST, &[(0, 1)]));
    m.add_bucket(Bucket::straw2(-24, HOST, &[(1, 1)]));
    m.add_bucket(Bucket::straw2(-25, HOST, &[(2, 1)]));
    m.add_bucket(Bucket::straw2(-26, HOST, &[(3, 1)]));
    m.add_bucket(Bucket::straw2(-21, DC, &[(-23, 1), (-24, 1)]));
    m.add_bucket(Bucket::straw2(-22, DC, &[(-25, 1), (-26, 1)]));
    m.add_bucket(Bucket::straw2(-20, ROOT, &[(-21, 2), (-22, 2)]));
    m.class_bucket = BTreeMap::from([
        (-1, BTreeMap::from([(0, -20)])),
        (-3, BTreeMap::from([(0, -21)])),
        (-10, BTreeMap::from([(0, -22)])),
    ]);
    m.add_rule(
        4,
        Rule::new(
            RULE_REPLICATED,
            vec![
                Step::new(OP_TAKE, -20, 0),
                Step::new(OP_CHOOSE_FIRSTN, 0, 8),
                Step::new(OP_CHOOSELEAF_FIRSTN, 2, 1),
                Step::new(OP_EMIT, 0, 0),
            ],
        ),
    );
    assert_eq!(m.parent_of_type(0, 8, 4), -21);
    assert_eq!(m.parent_of_type(3, 8, 4), -22);
}

#[test]
fn cyclic_map_terminates() {
    let mut m = oracle_map();
    // malformed: dc2 contains the root (cycle); lookups must still end
    m.add_bucket(Bucket::straw2(-10, DC, &[(-5, 1), (-6, 1)]));
    m.add_bucket(Bucket::straw2(-6, HOST, &[(3, 1), (-1, 1)]));
    assert_eq!(m.parent_of_type(3, 8, 1), -10);
    assert_eq!(m.parent_of_type(77, 8, 1), 0);
    assert_eq!(m.parent_of_type(77, 0, 1), 0);
}
