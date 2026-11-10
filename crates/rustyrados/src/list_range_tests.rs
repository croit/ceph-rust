// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use super::*;
fn query() -> ListQuery {
    ListQuery {
        pool: 7,
        namespace: ListNamespace::All,
        filter: None,
    }
}
fn ranged(l: ListLayout, range: ListRange) -> ListScan {
    ListScan::new_range(
        l,
        query(),
        range,
        ListLimits {
            entries: 3,
            ..Default::default()
        },
        100,
        0,
    )
    .unwrap()
}
fn collect_range(
    s: &mut ListScan,
    l: ListLayout,
    q: &mut ObjectQueue,
    objects: &[Hobject],
) -> Vec<Vec<u8>> {
    let mut result = vec![];
    while !s.is_done() {
        let (t, r) = admit(s, l, q);
        let candidates: Vec<_> = objects
            .iter()
            .filter(|h| l.pg(h.hash) == r.pg() && *h >= r.cursor())
            .collect();
        let next = if candidates.len() > 3 {
            candidates[3].clone()
        } else {
            end(&r)
        };
        let ListScanStep::Page(page) = s
            .accept(
                Ok(l),
                2,
                done(
                    t,
                    &r,
                    next,
                    candidates.iter().take(3).map(|h| entry(h)).collect(),
                    l.epoch,
                ),
            )
            .unwrap()
        else {
            panic!()
        };
        assert!(page.next_cursor() <= s.range_end());
        result.extend(page.entries().map(|e| e.object.to_vec()));
    }
    result
}
#[test]
fn adjacent_ranges_and_empty_intervals_cover_stable_set_with_exclusive_ends() {
    let objects = objects();
    for n in [1, 3, 5, 17] {
        let l = layout(n, 1);
        let mut q = queue();
        let mut combined = vec![];
        let cuts = [
            Hobject::MIN(),
            objects[7].clone(),
            objects[29].clone(),
            objects[29].clone(),
            Hobject::MAX(),
        ];
        for cut in cuts.windows(2) {
            let mut s = ranged(l, ListRange::new(cut[0].clone(), cut[1].clone()));
            let got = collect_range(&mut s, l, &mut q, &objects);
            let expected: Vec<_> = objects
                .iter()
                .filter(|h| *h >= &cut[0] && *h < &cut[1])
                .map(|h| h.oid.clone())
                .collect();
            assert_eq!(got, expected);
            combined.extend(got);
            assert_eq!(s.position(), s.range_end());
            assert_eq!(
                s.submit_with::<()>(l, 101, |_| panic!("ended range admitted"))
                    .unwrap(),
                None
            );
        }
        assert_eq!(
            combined,
            objects.iter().map(|h| h.oid.clone()).collect::<Vec<_>>()
        );
    }
}
#[test]
fn same_hash_object_cuts_are_inclusive_exclusive_and_clipped_views_keep_payload_loans() {
    let l = layout(1, 1);
    let mut q = queue();
    let objects: Vec<_> = [b"a", b"b", b"c"]
        .iter()
        .map(|name| {
            Hobject::new(
                *name,
                SnapId(opwire::NOSNAP),
                hash_key(l.hash, b"", b"shared"),
                7,
                b"",
            )
        })
        .map(|mut h| {
            h.key = b"shared".to_vec();
            h
        })
        .collect();
    let mut s = ranged(l, ListRange::new(objects[0].clone(), objects[1].clone()));
    let (t, r) = admit(&mut s, l, &mut q);
    let completion = done(
        t,
        &r,
        Hobject::MAX(),
        objects.iter().map(entry).collect(),
        1,
    );
    let ReadOutcome::RemotePgList {
        page: Some(ref raw),
        ..
    } = completion.outcome
    else {
        panic!()
    };
    let original_ptr = raw.entries().next().unwrap().object.as_ptr();
    let wire_len = raw.wire_len();
    let ListScanStep::Page(page) = s.accept(Ok(l), 2, completion).unwrap() else {
        panic!()
    };
    assert_eq!(page.len(), 1);
    assert_eq!(page.entries().next().unwrap().object, b"a");
    assert_eq!(page.entries().next().unwrap().object.as_ptr(), original_ptr);
    assert_eq!(page.next_cursor(), &objects[1]);
    assert!(!page.pg_finished());
    assert!(!page.pool_finished());
    assert_eq!(page.wire_len(), wire_len);
    assert!(s.is_done());
}
#[test]
fn invalid_source_tail_beyond_range_end_rejects_owned_completion_before_projection() {
    let l = layout(1, 1);
    let objects = objects();
    let mut q = queue();
    let mut s = ranged(l, ListRange::new(Hobject::MIN(), objects[1].clone()));
    let (t, r) = admit(&mut s, l, &mut q);
    let c = done(
        t,
        &r,
        Hobject::MAX(),
        vec![entry(&objects[0]), entry(&objects[3]), entry(&objects[3])],
        1,
    );
    let e = s.accept(Ok(l), 2, c).unwrap_err();
    assert_eq!(e.error, ListScanError::Protocol);
    assert_eq!(s.position(), &Hobject::MIN());
    assert!(
        matches!(e.completion.outcome,ReadOutcome::RemotePgList{page:Some(p),..} if p.len()==3)
    );
}
#[test]
fn hash_seek_keeps_requested_global_hash_and_empty_range_never_calls_admission() {
    let l = layout(5, 1);
    let mut q = queue();
    let range = ListRange::from_hash(7, 0x8000_0002);
    let start = range.start().clone();
    let mut s = ranged(l, range);
    let (_, r) = admit(&mut s, l, &mut q);
    assert_eq!(r.pg(), l.pg(start.hash));
    assert_eq!(r.cursor(), &start);
    assert_eq!(start.snap.0, opwire::NOSNAP);
    for cut in [Hobject::MIN(), objects()[3].clone(), Hobject::MAX()] {
        let mut empty = ranged(l, ListRange::new(cut.clone(), cut.clone()));
        assert!(empty.is_done());
        assert_eq!(empty.position(), &cut);
        assert_eq!(empty.submit_with::<()>(l, 0, |_| panic!()).unwrap(), None);
    }
}
#[test]
fn range_rejections_preserve_inputs_and_persistent_end_capacity_is_charged() {
    let l = layout(1, 1);
    let mut start = Hobject::new(b"a", SnapId(opwire::NOSNAP), 7, 7, b"");
    start.oid.reserve_exact(99);
    let start_ptr = start.oid.as_ptr();
    let mut end = Hobject::new(b"z", SnapId(opwire::NOSNAP), 7, 7, b"");
    end.oid.reserve_exact(199);
    let end_ptr = end.oid.as_ptr();
    let err = ListScan::new_range(
        l,
        query(),
        ListRange::new(start, end),
        ListLimits {
            state_bytes: 1,
            ..Default::default()
        },
        100,
        0,
    )
    .unwrap_err();
    assert_eq!(err.reason, ListScanError::StateBudget);
    assert_eq!(err.range.start().oid.as_ptr(), start_ptr);
    assert_eq!(err.range.end().oid.as_ptr(), end_ptr);
    let all = objects();
    for range in [
        ListRange::new(all[4].clone(), all[2].clone()),
        ListRange::from_hash(8, 3),
        ListRange::new(
            Hobject {
                max: true,
                pool: 7,
                ..Hobject::MIN()
            },
            Hobject::MAX(),
        ),
    ] {
        assert_eq!(
            ListScan::new_range(l, query(), range, ListLimits::default(), 100, 0)
                .unwrap_err()
                .reason,
            ListScanError::Range
        );
    }
    let end = Hobject::new(b"large-end", SnapId(opwire::NOSNAP), 7, 7, b"");
    let budget = end.oid.capacity() as u64;
    let mut s = ListScan::new_range(
        l,
        query(),
        ListRange::new(Hobject::MIN(), end),
        ListLimits {
            state_bytes: budget,
            ..Default::default()
        },
        100,
        0,
    )
    .unwrap();
    let mut q = queue();
    let (t, r) = admit(&mut s, l, &mut q);
    assert_eq!(
        s.accept(Ok(l), 2, done(t, &r, Hobject::MAX(), vec![], 1))
            .unwrap_err()
            .error,
        ListScanError::StateBudget
    );
    assert_eq!(s.position(), &Hobject::MIN());
}
#[test]
fn checkpoints_resume_exact_query_and_cut_under_changing_pg_counts_with_explicit_new_budgets() {
    let objects = objects();
    let mut l = layout(3, 1);
    let mut q = queue();
    let mut original = query();
    original.filter = Some(crate::ListFilter::Plain {
        raw_xattr: vec![],
        value: vec![],
    });
    let expected = original.clone();
    let mut s = ListScan::new(
        l,
        original,
        ListLimits {
            entries: 3,
            max_pages: 1,
            ..Default::default()
        },
        100,
        0,
    )
    .unwrap();
    let mut seen = vec![];
    let mut steps = 0;
    while !s.is_done() {
        let (t, r) = admit(&mut s, l, &mut q);
        assert_eq!(q.pg_listing(t).unwrap().filter(), expected.filter.as_ref());
        let candidates: Vec<_> = objects
            .iter()
            .filter(|h| l.pg(h.hash) == r.pg() && *h >= r.cursor())
            .collect();
        let next = if candidates.len() > 3 {
            candidates[3].clone()
        } else {
            end(&r)
        };
        let ListScanStep::Page(page) = s
            .accept(
                Ok(l),
                2,
                done(
                    t,
                    &r,
                    next,
                    candidates.iter().take(3).map(|h| entry(h)).collect(),
                    l.epoch,
                ),
            )
            .unwrap()
        else {
            panic!()
        };
        seen.extend(page.entries().map(|e| e.object.to_vec()));
        let position = s.position().clone();
        if !s.is_done() {
            assert!(matches!(
                s.submit_with::<()>(l, 2, |_| panic!()),
                Err(ListSubmitError::Scan(ListScanError::PageBudget))
            ));
        }
        let cp = s.into_checkpoint().unwrap();
        assert_eq!(cp.query(), &expected);
        let bytes = cp.encode(4096).unwrap();
        let cp = ListCheckpoint::decode(&bytes, 4096).unwrap();
        l = layout(if l.pg_num == 3 { 5 } else { 3 }, l.epoch + 1);
        s = ListScan::resume(
            l,
            cp,
            ListLimits {
                entries: 3,
                max_pages: 1,
                ..Default::default()
            },
            100,
            0,
        )
        .unwrap();
        assert_eq!(s.position(), &position);
        assert_eq!(s.pages_submitted(), 0);
        steps += 1;
        assert!(steps < 100);
    }
    assert_eq!(
        seen,
        objects.iter().map(|h| h.oid.clone()).collect::<Vec<_>>()
    );
}
#[test]
fn busy_checkpoint_returns_original_scan_and_resume_rejection_keeps_owned_identity() {
    let l = layout(1, 7);
    let mut q = queue();
    let mut s = ranged(l, ListRange::full());
    let (t, r) = admit(&mut s, l, &mut q);
    let rejection = s.into_checkpoint().unwrap_err();
    assert_eq!(rejection.reason, ListScanError::Busy);
    let mut s = rejection.scan;
    assert_eq!(s.in_flight(), Some(t));
    s.accept(Ok(l), 2, done(t, &r, Hobject::MAX(), vec![], 7))
        .unwrap();
    let encoded = s.into_checkpoint().unwrap().encode(4096).unwrap();
    for layout in [
        ListLayout {
            fsid: Uuid([8; 16]),
            ..l
        },
        ListLayout { pool: 8, ..l },
        ListLayout {
            hash: STR_HASH_LINUX,
            ..l
        },
        ListLayout { epoch: 6, ..l },
    ] {
        let cp = ListCheckpoint::decode(&encoded, 4096).unwrap();
        let err = ListScan::resume(layout, cp, ListLimits::default(), 100, 0).unwrap_err();
        assert!(matches!(
            err.reason,
            ListScanError::Identity | ListScanError::Layout
        ));
        assert_eq!(err.checkpoint.encode(4096).unwrap(), encoded);
    }
    let mut s = ranged(l, ListRange::full());
    let (t, _) = admit(&mut s, l, &mut q);
    s.accept(
        Ok(l),
        100,
        ReadCompletion::new(
            t,
            ReadOutcome::Deadline {
                possibly_sent: true,
            },
        ),
    )
    .unwrap();
    assert_eq!(s.error(), Some(ListScanError::Deadline));
    let cp = s.into_checkpoint().unwrap();
    let resumed = ListScan::resume(l, cp, ListLimits::default(), 50, 0).unwrap();
    assert_eq!(resumed.position(), &Hobject::MIN());
    assert_eq!(resumed.error(), None);
    assert_eq!(resumed.deadline_us(), 50);
}
fn checksum(bytes: &mut Vec<u8>) {
    let crc = crc::crc32c(0, bytes);
    bytes.extend_from_slice(&crc.to_le_bytes());
}
#[test]
fn checkpoint_codec_is_bounded_strict_and_preserves_binary_namespace_and_class_arguments() {
    for filter in [
        None,
        Some(crate::ListFilter::Plain {
            raw_xattr: vec![0, 255],
            value: vec![1, 0, 255],
        }),
        Some(crate::ListFilter::Class {
            name: b"hello.hello".to_vec(),
            parameters: vec![0, 255, 0, 3],
        }),
    ] {
        let mut q = query();
        q.namespace = ListNamespace::Exact(vec![0, 255]);
        q.filter = filter;
        let expected = q.clone();
        let cp = ListScan::new(layout(3, 1), q, ListLimits::default(), 100, 0)
            .unwrap()
            .into_checkpoint()
            .unwrap();
        let bytes = cp.encode(4096).unwrap();
        assert_eq!(cp.encode(bytes.len() - 1), Err(ListScanError::StateBudget));
        let parsed = ListCheckpoint::decode(&bytes, bytes.len()).unwrap();
        assert_eq!(parsed.query(), &expected);
        assert_eq!(parsed.encode(4096).unwrap(), bytes);
        assert_eq!(
            ListCheckpoint::decode(&bytes, bytes.len() - 1).unwrap_err(),
            ListScanError::StateBudget
        );
        for n in 0..bytes.len() {
            assert!(ListCheckpoint::decode(&bytes[..n], 4096).is_err());
        }
        for i in 0..bytes.len() {
            let mut damaged = bytes.clone();
            damaged[i] ^= 1;
            assert_eq!(
                ListCheckpoint::decode(&damaged, 4096).unwrap_err(),
                ListScanError::Protocol
            );
        }
    }
    let bytes = ranged(layout(1, 1), ListRange::full())
        .into_checkpoint()
        .unwrap()
        .encode(4096)
        .unwrap();
    for (index, value) in [(0, b'X'), (36, 0), (37, 9), (38, 9)] {
        let mut bad = bytes[..bytes.len() - 4].to_vec();
        bad[index] = value;
        checksum(&mut bad);
        assert_eq!(
            ListCheckpoint::decode(&bad, 4096).unwrap_err(),
            ListScanError::Protocol
        );
    }
    let mut bad = bytes[..bytes.len() - 4].to_vec();
    bad.push(0);
    checksum(&mut bad);
    assert_eq!(
        ListCheckpoint::decode(&bad, 4096).unwrap_err(),
        ListScanError::Protocol
    );
}

#[test]
fn independent_checkpoint_literal_fixes_version_field_layout_and_raw_crc_seed() {
    // Own literal fields; trailer independently calculated by bitwise Castagnoli CRC, seed0/no inversion.
    let literal = "5241444f534c433107070707070707070707070707070707010000000700000000000000020000040321000000000000000000000000000000000000000000000000000000000000000000000080040321000000000000000000000000000000000000000000000001000000000000000000000080e700ffa8";
    let bytes: Vec<_> = literal
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect();
    assert_eq!(bytes.len(), 121);
    let cp = ListCheckpoint::decode(&bytes, 121).unwrap();
    assert_eq!(cp.pool(), 7);
    assert_eq!(cp.epoch(), 1);
    assert_eq!(cp.query(), &query());
    assert_eq!(cp.range().start(), &Hobject::MIN());
    assert_eq!(cp.range().end(), &Hobject::MAX());
    let own = ranged(layout(1, 1), ListRange::full())
        .into_checkpoint()
        .unwrap();
    assert_eq!(own.encode(121).unwrap(), bytes);
    for field in [8..24, 24..28] {
        let mut malformed = bytes[..117].to_vec();
        malformed[field].fill(0);
        checksum(&mut malformed);
        assert_eq!(
            ListCheckpoint::decode(&malformed, 121).unwrap_err(),
            ListScanError::Protocol
        );
    }
    let mut malformed = bytes[..117].to_vec();
    malformed[28..36].copy_from_slice(&(-1i64).to_le_bytes());
    checksum(&mut malformed);
    assert_eq!(
        ListCheckpoint::decode(&malformed, 121).unwrap_err(),
        ListScanError::Protocol
    );
}

#[test]
fn semantically_equal_cursor_encodings_still_return_the_captured_exact_end() {
    let l = layout(1, 1);
    let hash = hash_key(l.hash, b"", b"b");
    let canonical = Hobject::new(b"b", SnapId(opwire::NOSNAP), hash, 7, b"");
    let mut bound = canonical.clone();
    bound.key = b"b".to_vec();
    assert_eq!(
        std::cmp::Ord::cmp(&canonical, &bound),
        std::cmp::Ordering::Equal
    );
    // equal as values (Hobject identity follows the wire order), different as encodings: compare the key bytes
    assert_eq!(canonical, bound);
    assert_ne!(canonical.key, bound.key);
    let mut s = ranged(l, ListRange::new(Hobject::MIN(), bound.clone()));
    let mut q = queue();
    let (t, r) = admit(&mut s, l, &mut q);
    let c = done(
        t,
        &r,
        canonical,
        vec![opwire::ListObjEntry {
            nspace: vec![],
            oid: b"a".to_vec(),
            locator: b"b".to_vec(),
        }],
        1,
    );
    let ListScanStep::Page(page) = s.accept(Ok(l), 2, c).unwrap() else {
        panic!()
    };
    assert!(s.is_done());
    assert_eq!(s.position().key, bound.key);
    assert_eq!(page.next_cursor().key, bound.key);
    assert_eq!(page.len(), 1);
}

#[path = "list_slice_tests.rs"]
mod slices;
