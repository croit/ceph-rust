// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use super::*;
fn boundary(hash: u32) -> Hobject {
    Hobject::new(b"", SnapId(opwire::NOSNAP), hash, 7, b"")
}
#[test]
fn independent_full_range_boundaries_match_bitwise_thirds_and_quarters() {
    let full = ListRange::full();
    for (parts, interior) in [(3, vec![0xaaaa_aaaa, 0x5555_5555]), (4, vec![2, 1, 3])] {
        let mut points = vec![Hobject::MIN()];
        points.extend(interior.into_iter().map(boundary));
        points.push(Hobject::MAX());
        for n in 0..parts {
            let r = full.slice(7, n, parts, 0).unwrap();
            assert_eq!(r.start(), &points[n as usize]);
            assert_eq!(r.end(), &points[n as usize + 1]);
        }
    }
}
fn verify_parent(parent: &ListRange, parts: u64) {
    let mut previous = parent.start().clone();
    for n in 0..parts {
        let slice = parent.slice(7, n, parts, 4096).unwrap();
        assert_eq!(slice.start(), &previous);
        assert!(slice.start() >= parent.start() && slice.end() <= parent.end());
        assert!(slice.start() <= slice.end());
        previous = slice.end().clone();
    }
    assert_eq!(&previous, parent.end());
}
#[test]
fn same_hash_and_narrow_intervals_never_move_before_named_start_or_outside_parent() {
    let first = Hobject::new(b"a", SnapId(opwire::NOSNAP), 7, 7, b"ns");
    let last = Hobject::new(b"z", SnapId(opwire::NOSNAP), 7, 7, b"ns");
    let same = ListRange::new(first.clone(), last.clone());
    verify_parent(&same, 17);
    for n in 0..16 {
        let s = same.slice(7, n, 17, 4096).unwrap();
        assert_eq!(s.start(), &first);
        assert_eq!(s.end(), &first);
    }
    assert_eq!(same.slice(7, 16, 17, 4096).unwrap().end(), &last);
    let next_hash = (7u32.reverse_bits() + 2).reverse_bits();
    let narrow = ListRange::new(
        first,
        Hobject::new(b"z", SnapId(opwire::NOSNAP), next_hash, 7, b"ns"),
    );
    for parts in [1, 2, 3, 17, 100] {
        verify_parent(&narrow, parts);
    }
    for cut in [Hobject::MIN(), last, Hobject::MAX()] {
        verify_parent(&ListRange::new(cut.clone(), cut), 7);
    }
}
#[test]
fn extreme_counts_are_constant_work_and_do_not_overflow_or_allocate_a_parts_vector() {
    let full = ListRange::full();
    let last = full.slice(7, u64::MAX - 1, u64::MAX, 0).unwrap();
    assert_eq!(last.start(), &boundary(u32::MAX));
    assert_eq!(last.end(), &Hobject::MAX());
    let first = full.slice(7, 0, u64::MAX, 0).unwrap();
    assert_eq!(first.start(), &Hobject::MIN());
    assert_eq!(first.end(), &Hobject::MIN());
    let middle = full.slice(7, u64::MAX / 2, u64::MAX, 0).unwrap();
    assert!(middle.start() <= middle.end());
    for (index, parts) in [(0, 0), (1, 1), (u64::MAX, u64::MAX)] {
        assert_eq!(full.slice(7, index, parts, 0), Err(ListScanError::Range));
    }
}
#[test]
fn slicing_is_passive_on_bad_inputs_and_copies_only_endpoints_under_explicit_byte_cap() {
    let mut start = Hobject::new(b"a", SnapId(opwire::NOSNAP), 0, 7, b"");
    start.oid.reserve_exact(4096);
    let pointer = start.oid.as_ptr();
    let end = Hobject::new(b"z", SnapId(opwire::NOSNAP), u32::MAX, 7, b"");
    let parent = ListRange::new(start, end);
    assert_eq!(parent.slice(7, 0, 3, 0), Err(ListScanError::StateBudget));
    assert_eq!(parent.start().oid.as_ptr(), pointer);
    let interior = parent.slice(7, 1, 3, 0).unwrap();
    assert!(interior.start().oid.is_empty() && interior.end().oid.is_empty());
    assert_eq!(parent.slice(8, 0, 3, 100), Err(ListScanError::Range));
    assert_eq!(parent.slice(-1, 0, 3, 100), Err(ListScanError::Range));
    assert_eq!(
        parent.slice(u32::MAX as i64 + 1, 0, 3, 100),
        Err(ListScanError::Range)
    );
    let malformed = ListRange::new(parent.end().clone(), parent.start().clone());
    assert_eq!(malformed.slice(7, 0, 3, 100), Err(ListScanError::Range));
    let same = ListRange::new(parent.start().clone(), parent.end().clone());
    assert_eq!(same.slice(7, 0, 1, 1), Err(ListScanError::StateBudget));
    assert!(same.slice(7, 0, 1, 2).is_ok());
}
#[test]
fn stable_slice_unions_preserve_binary_identities_and_filters_under_multiple_pg_layouts() {
    let objects = objects();
    let parents = [
        ListRange::full(),
        ListRange::new(objects[7].clone(), objects[60].clone()),
        ListRange::new(objects[11].clone(), objects[12].clone()),
    ];
    for pg_num in [1, 3, 5, 17] {
        let l = layout(pg_num, 1);
        for parent in &parents {
            for parts in [1, 3, 7, 31] {
                let mut actual = vec![];
                let mut q = queue();
                for n in 0..parts {
                    let slice = parent.slice(7, n, parts, 4096).unwrap();
                    let mut s = ranged(l, slice);
                    actual.extend(collect_range(&mut s, l, &mut q, &objects));
                }
                let expected: Vec<_> = objects
                    .iter()
                    .filter(|h| *h >= parent.start() && *h < parent.end())
                    .map(|h| h.oid.clone())
                    .collect();
                assert_eq!(actual, expected);
            }
        }
    }
    // Independently populated namespace-selected model: source page may be empty while advancing.
    let selected: Vec<_> = objects
        .iter()
        .filter(|h| h.nspace == [0, 255])
        .cloned()
        .collect();
    let l = layout(5, 1);
    let mut q = queue();
    let parent = ListRange::full();
    let mut actual = vec![];
    for n in 0..7 {
        let slice = parent.slice(7, n, 7, 4096).unwrap();
        let mut context = query();
        context.namespace = ListNamespace::Exact(vec![0, 255]);
        context.filter = Some(crate::ListFilter::Plain {
            raw_xattr: vec![],
            value: vec![],
        });
        let mut s = ListScan::new_range(
            l,
            context,
            slice,
            ListLimits {
                entries: 3,
                ..Default::default()
            },
            100,
            0,
        )
        .unwrap();
        actual.extend(collect_range(&mut s, l, &mut q, &selected));
    }
    assert_eq!(
        actual,
        selected.iter().map(|h| h.oid.clone()).collect::<Vec<_>>()
    );
}
