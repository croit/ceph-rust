// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `Hobject` identity is the wire order's identity: `a == b` exactly when `a.cmp(b) == Equal`, whatever order the cheap
//! checks run in (the placement hash first, no byte compare of empty names), and equal objects hash alike. The reference
//! is the field-wise comparison of the order's steps (spec encoding.md 8.5).

use denc::Encode;
use denc::types::{Hobject, SnapId};
use std::collections::{BTreeSet, HashSet};
use std::hash::BuildHasher;

/// The order's identity: every step of `cmp` equal, i.e. the effective key (the key, or the oid when the key is empty)
/// rather than the raw key, and no placement hash for the MAX sentinel (its order key is constant).
fn reference(a: &Hobject, b: &Hobject) -> bool {
    fn eff_key(h: &Hobject) -> &[u8] {
        if h.key.is_empty() { &h.oid } else { &h.key }
    }
    a.max == b.max
        && a.pool == b.pool
        && (a.max || a.hash == b.hash)
        && a.nspace == b.nspace
        && eff_key(a) == eff_key(b)
        && a.oid == b.oid
        && a.snap == b.snap
}

/// One object per value of each field (two values per field, three for the names: empty, short, long).
fn grid() -> Vec<Hobject> {
    let names: [&[u8]; 4] = [b"", b"a", b"b", b"rbd_data.1234567890ab.0000000000000001"];
    let mut v = vec![Hobject::MIN(), Hobject::MAX()];
    for key in names {
        for oid in names {
            for nspace in names {
                for snap in [SnapId(0), SnapId(7)] {
                    for hash in [0u32, 0xdead_beef] {
                        for max in [false, true] {
                            for pool in [1i64, -1] {
                                v.push(Hobject {
                                    key: key.to_vec(),
                                    oid: oid.to_vec(),
                                    snap,
                                    hash,
                                    max,
                                    nspace: nspace.to_vec(),
                                    pool,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    v
}

#[test]
fn eq_is_the_order_identity() {
    let g = grid();
    for a in &g {
        for b in &g {
            let same = reference(a, b);
            assert_eq!(a == b, same, "{a:?} vs {b:?}");
            assert_eq!(
                a.cmp(b) == std::cmp::Ordering::Equal,
                same,
                "{a:?} vs {b:?}"
            );
        }
    }
}

#[test]
fn same_placement_hash_different_names_differ() {
    // a collision of the 32-bit placement hash falls back to the full compare
    let mut a = Hobject::new(b"obj-a", SnapId(0), 42, 3, b"");
    let mut b = Hobject::new(b"obj-b", SnapId(0), 42, 3, b"");
    assert_ne!(a, b);
    b.oid = a.oid.clone();
    assert_eq!(a, b);
    a.nspace = b"ns".to_vec();
    assert_ne!(a, b);
}

/// A wire object whose key equals its oid (non-canonical: `set_key` stores empty) is the same object as the canonical
/// form, not a second one that a `BTreeMap` merges and a `HashSet` keeps apart.
#[test]
fn key_equal_to_oid_is_the_same_object() {
    let canonical = Hobject::new(b"obj", SnapId(0), 42, 3, b"");
    let mut raw = canonical.clone();
    raw.key = raw.oid.clone();
    let decoded: Hobject = denc::from_slice(&raw.encode_to_vec().unwrap()).unwrap();
    assert_eq!(decoded.key, b"obj"); // the wire bytes are kept as sent
    for other in [&raw, &decoded] {
        assert_eq!(&canonical, other);
        assert_eq!(canonical.cmp(other), std::cmp::Ordering::Equal);
    }
    let hashed: HashSet<&Hobject> = [&canonical, &raw, &decoded].into_iter().collect();
    let ordered: BTreeSet<&Hobject> = [&canonical, &raw, &decoded].into_iter().collect();
    assert_eq!((hashed.len(), ordered.len()), (1, 1));
}

#[test]
fn equal_objects_hash_alike_and_tables_agree() {
    let g = grid();
    let b = std::collections::hash_map::RandomState::new();
    let set: HashSet<&Hobject> = g.iter().collect();
    let ordered: BTreeSet<&Hobject> = g.iter().collect();
    // both tables hold exactly the grid's distinct identities
    assert_eq!(set.len(), ordered.len());
    for a in &g {
        assert!(set.contains(&a.clone()));
        assert!(ordered.contains(&a.clone()));
        // equal objects hash alike (the hash and the order agree on identity)
        for c in &g {
            if reference(a, c) {
                assert_eq!(b.hash_one(a), b.hash_one(c), "{a:?} vs {c:?}");
            }
        }
    }
    // other placement hashes land elsewhere
    let (x, mut y) = (g[0].clone(), g[0].clone());
    y.hash ^= 1;
    assert_ne!(b.hash_one(&x), b.hash_one(&y));
}
