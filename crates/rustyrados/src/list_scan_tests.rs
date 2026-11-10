// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use super::*;
use crate::ObjectQueue;
use denc::{Encode, types::SnapId};
use opwire::{ListObjEntry, PgNlsResponse};
#[test]
fn wide_listing_budget_is_captured_and_unlimited_survives_old_clock_horizon() {
    let l = layout(1, 1);
    let now = (1u64 << 32) * 1_000_000;
    for deadline in [
        time::deadline_after(5, 1u64 << 32).unwrap(),
        time::NO_DEADLINE,
    ] {
        let mut s = ListScan::new(
            l,
            ListQuery {
                pool: 7,
                namespace: ListNamespace::All,
                filter: None,
            },
            ListLimits::default(),
            deadline,
            now,
        )
        .unwrap();
        assert_eq!(s.deadline_us(), deadline);
        s.observe(l, now + 1).unwrap();
        let end = time::timer(deadline).unwrap_or(MAX_TIME);
        assert!(matches!(
            s.submit_with(l, end - 1, |_| Err::<RequestToken, _>(())),
            Err(ListSubmitError::Admission(()))
        ));
        if deadline != time::NO_DEADLINE {
            assert!(matches!(
                s.submit_with::<()>(l, end, |_| panic!("expired page must not be admitted")),
                Err(ListSubmitError::Scan(ListScanError::Deadline))
            ));
        }
        assert_eq!(s.observe(l, now), Err(ListScanError::Clock));
    }
    let rejected = ListScan::new(
        l,
        ListQuery {
            pool: 7,
            namespace: ListNamespace::All,
            filter: None,
        },
        ListLimits::default(),
        MAX_TIME + 1,
        0,
    )
    .unwrap_err();
    assert_eq!(rejected.reason, ListScanError::Overflow);
}
#[test]
fn per_page_deadline_can_advance_without_resetting_scan_progress() {
    let l = layout(1, 1);
    let mut s = scan(l, ListNamespace::All);
    let mut q = queue();
    let (token, _) = admit(&mut s, l, &mut q);
    assert_eq!(s.set_deadline_us(200), Err(ListScanError::Busy));
    assert_eq!(s.deadline_us(), 100);
    // A failure completion releases the pending page without changing its cursor.
    let completion = ReadCompletion::new(token, ReadOutcome::CanceledUnsent);
    assert!(matches!(
        s.accept(Ok(l), 99, completion),
        Ok(ListScanStep::Failure(_))
    ));
    s.set_deadline_us(200).unwrap();
    assert_eq!(s.deadline_us(), 200);
    assert_eq!(s.pages_submitted(), 1);
    assert_eq!(
        s.set_deadline_us(MAX_TIME + 1),
        Err(ListScanError::Overflow)
    );
    assert_eq!(s.deadline_us(), 200);
    assert!(s.submit_with::<()>(l, 150, |_| Err(())).is_err());
    assert_eq!(s.error(), None);
}
fn layout(n: u32, epoch: u32) -> ListLayout {
    pool_layout(n, epoch, osdmap::pool::TYPE_REPLICATED)
}
fn pool_layout(n: u32, epoch: u32, ptype: u8) -> ListLayout {
    let mut map = OsdMap::default();
    map.fsid = Uuid([7; 16]);
    map.epoch = epoch;
    map.flags = osdmap::consts::map_flags::SORTBITWISE;
    map.pools.insert(
        7,
        osdmap::PgPool {
            ptype,
            pg_num: n,
            pgp_num: n.div_ceil(2),
            object_hash: STR_HASH_RJENKINS,
            ..Default::default()
        },
    );
    ListLayout::from_map(&map, 7).unwrap()
}
fn scan(l: ListLayout, namespace: ListNamespace) -> ListScan {
    ListScan::new(
        l,
        ListQuery {
            filter: None,
            pool: 7,
            namespace,
        },
        ListLimits {
            entries: 3,
            ..Default::default()
        },
        100,
        0,
    )
    .unwrap()
}
fn queue() -> ObjectQueue {
    ObjectQueue::new(2048, 1 << 30, 9).unwrap()
}
#[expect(
    clippy::result_large_err,
    reason = "Rejected requests return caller-owned input without allocation"
)]
fn admit(s: &mut ListScan, l: ListLayout, q: &mut ObjectQueue) -> (RequestToken, PgListRequest) {
    let mut captured = None;
    let t = s
        .submit_with(l, 2, |r| {
            let duplicate = PgListRequest::new(
                r.pool(),
                ListNamespace::All,
                r.pg(),
                r.pg_num(),
                r.cursor().clone(),
                r.max_entries(),
                r.max_output_bytes(),
            );
            captured = Some(duplicate);
            q.submit_pg_list(r)
        })
        .unwrap()
        .unwrap();
    (t, captured.unwrap())
}
fn done(
    t: RequestToken,
    r: &PgListRequest,
    next: Hobject,
    entries: Vec<ListObjEntry>,
    epoch: u32,
) -> ReadCompletion {
    let data = PgNlsResponse {
        handle: next,
        entries,
    }
    .encode_to_vec()
    .unwrap()
    .into();
    let page = PgListPage::decode(r, 0, epoch, data).unwrap();
    ReadCompletion::new(
        t,
        ReadOutcome::RemotePgList {
            result: 0,
            op_result: 0,
            user_version: 0,
            map_epoch: epoch,
            page: Some(page),
            error_data: bytes::Bytes::new(),
        },
    )
}
fn entry(h: &Hobject) -> ListObjEntry {
    ListObjEntry {
        nspace: h.nspace.clone(),
        oid: h.oid.clone(),
        locator: h.key.clone(),
    }
}
fn end(r: &PgListRequest) -> Hobject {
    let mut pgs: Vec<_> = (0..r.pg_num()).collect();
    pgs.sort_by_key(|p| p.reverse_bits());
    let i = pgs.iter().position(|p| *p == r.pg()).unwrap();
    if i + 1 == pgs.len() {
        Hobject::MAX()
    } else {
        Hobject::new(b"", SnapId(opwire::NOSNAP), pgs[i + 1], 7, b"")
    }
}
fn objects() -> Vec<Hobject> {
    let mut objects = vec![];
    for i in 0..70u8 {
        let oid = vec![i, 255, 0];
        let namespace = if i % 2 == 0 { vec![] } else { vec![0, 255] };
        let key = if i % 3 == 0 { vec![77, i, 0] } else { vec![] };
        let hash = hash_key(
            STR_HASH_RJENKINS,
            &namespace,
            if key.is_empty() { &oid } else { &key },
        );
        let mut h = Hobject::new(&oid, SnapId(opwire::NOSNAP), hash, 7, &namespace);
        h.key = key;
        objects.push(h);
    }
    objects.sort();
    objects
}
#[test]
fn stable_sets_empty_pgs_binary_names_and_non_power_of_two_layouts() {
    for (n, ptype) in [1, 2, 3, 5, 17, 127].into_iter().flat_map(|n| {
        [osdmap::pool::TYPE_REPLICATED, osdmap::pool::TYPE_ERASURE].map(|ptype| (n, ptype))
    }) {
        for namespace in [ListNamespace::All, ListNamespace::Exact(vec![0, 255])] {
            let l = pool_layout(n, 1, ptype);
            let mut s = scan(l, namespace.clone());
            let mut q = queue();
            let objects = objects();
            let mut seen = vec![];
            let expected: Vec<_> = objects
                .iter()
                .filter(|h| {
                    matches!(&namespace, ListNamespace::All)
                        || matches!(&namespace,ListNamespace::Exact(ns) if *ns==h.nspace)
                })
                .collect();
            while !s.is_done() {
                let (token, r) = admit(&mut s, l, &mut q);
                let candidates: Vec<_> = expected
                    .iter()
                    .copied()
                    .filter(|h| l.pg(h.hash) == r.pg() && *h >= r.cursor())
                    .collect();
                let next = if candidates.len() > 3 {
                    candidates[3].clone()
                } else {
                    end(&r)
                };
                let entries = candidates.iter().take(3).map(|h| entry(h)).collect();
                let completion = done(token, &r, next, entries, 1);
                let ListScanStep::Page(page) = s.accept(Ok(l), 2, completion).unwrap() else {
                    panic!()
                };
                seen.extend(
                    page.entries()
                        .map(|e| (e.namespace.to_vec(), e.object.to_vec(), e.locator.to_vec())),
                );
            }
            assert_eq!(
                seen,
                expected
                    .iter()
                    .map(|h| (h.nspace.clone(), h.oid.clone(), h.key.clone()))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                s.submit_with::<()>(l, 101, |_| panic!("MAX must not admit"))
                    .unwrap(),
                None
            );
        }
    }
}
#[test]
fn splits_and_merges_retain_global_position_and_admitted_membership() {
    let mut s = scan(layout(3, 1), ListNamespace::All);
    let mut q = queue();
    let objects = objects();
    let mut seen = vec![];
    let mut iteration = 0;
    while !s.is_done() {
        let n = if iteration % 2 == 0 { 3 } else { 5 };
        let l = layout(n, iteration * 2 + 1);
        let (t, r) = admit(&mut s, l, &mut q);
        let candidates: Vec<_> = objects
            .iter()
            .filter(|h| l.pg(h.hash) == r.pg() && *h >= r.cursor())
            .collect();
        let next = if candidates.len() > 3 {
            candidates[3].clone()
        } else {
            end(&r)
        };
        let c = done(
            t,
            &r,
            next,
            candidates.iter().take(3).map(|h| entry(h)).collect(),
            l.epoch,
        );
        let after = layout(if n == 3 { 5 } else { 3 }, l.epoch + 1);
        let ListScanStep::Page(page) = s.accept(Ok(after), 2, c).unwrap() else {
            panic!()
        };
        seen.extend(page.entries().map(|e| e.object.to_vec()));
        iteration += 1;
        assert!(iteration < 100);
    }
    assert_eq!(
        seen,
        objects.iter().map(|h| h.oid.clone()).collect::<Vec<_>>()
    );
}
#[test]
fn foreign_completion_is_passive_and_failed_admission_preserves_budget() {
    let l = layout(1, 1);
    let mut s = scan(l, ListNamespace::All);
    let mut q = queue();
    assert!(matches!(
        s.submit_with(l, 0, |_| Err(42)),
        Err(ListSubmitError::Admission(42))
    ));
    assert_eq!(s.pages_submitted(), 0);
    let (t, r) = admit(&mut s, l, &mut q);
    let foreign = q
        .submit_pg_list(PgListRequest::new(
            7,
            ListNamespace::All,
            0,
            1,
            Hobject::MIN(),
            3,
            1024,
        ))
        .unwrap();
    let rejected = s
        .accept(
            Err(ListScanError::Identity),
            MAX_TIME + 1,
            ReadCompletion::new(foreign, ReadOutcome::CanceledUnsent),
        )
        .unwrap_err();
    assert_eq!(rejected.error, ListScanError::ForeignCompletion);
    assert_eq!(s.in_flight(), Some(t));
    assert_eq!(s.error(), None);
    assert!(matches!(
        s.submit_with::<()>(l, 1, |_| panic!()),
        Err(ListSubmitError::Scan(ListScanError::Busy))
    ));
    s.accept(Ok(l), 101, done(t, &r, Hobject::MAX(), vec![], 1))
        .unwrap();
    assert!(s.is_done());
}
#[test]
fn malformed_success_keeps_owned_page_and_never_advances() {
    for kind in 0..6 {
        let l = layout(if kind == 3 { 2 } else { 1 }, 1);
        let mut s = scan(l, ListNamespace::All);
        let mut q = queue();
        let (t, r) = admit(&mut s, l, &mut q);
        let all = objects();
        let valid: Vec<_> = all.iter().filter(|h| l.pg(h.hash) == 0).collect();
        let entries = match kind {
            0 => vec![entry(valid[1]), entry(valid[0])],
            1 => vec![entry(valid[0]), entry(valid[0])],
            3 => vec![entry(all.iter().find(|h| l.pg(h.hash) == 1).unwrap())],
            _ => vec![entry(valid[0])],
        };
        let next = if kind == 2 { valid[0].clone() } else { end(&r) };
        let mut c = done(t, &r, next, entries, 1);
        if let ReadOutcome::RemotePgList { page: Some(p), .. } = &mut c.outcome {
            if kind == 4 {
                p.pool = 8;
            }
            if kind == 5 {
                p.pg_num = 2;
            }
        }
        let err = s.accept(Ok(l), 2, c).unwrap_err();
        assert_eq!(err.error, ListScanError::Protocol, "kind={kind}");
        assert_eq!(s.position(), &Hobject::MIN());
        assert!(s.in_flight().is_none());
        assert!(matches!(
            err.completion.outcome,
            ReadOutcome::RemotePgList { page: Some(_), .. }
        ));
    }
}
#[test]
fn recoverable_outcomes_limits_and_terminal_deadline_are_explicit() {
    let l = layout(1, 1);
    let mut s = scan(l, ListNamespace::All);
    let mut q = queue();
    for outcome in [
        ReadOutcome::LocalRejected {
            error: crate::LocalRequestError::FrameLimit,
            possibly_sent: false,
        },
        ReadOutcome::LocalRejected {
            error: crate::LocalRequestError::OutputLimit,
            possibly_sent: true,
        },
        ReadOutcome::ListingChanged { pg_num: Some(3) },
        ReadOutcome::ListingTooLarge { bytes: 99999 },
        ReadOutcome::RemotePgList {
            result: -13,
            op_result: -13,
            user_version: 0,
            map_epoch: 1,
            page: None,
            error_data: bytes::Bytes::from_static(b"denied"),
        },
    ] {
        let (t, _) = admit(&mut s, l, &mut q);
        assert!(matches!(
            s.accept(Ok(l), 2, ReadCompletion::new(t, outcome)).unwrap(),
            ListScanStep::Failure(_)
        ));
        assert_eq!(s.position(), &Hobject::MIN());
        assert_eq!(s.error(), None);
    }
    s.set_page_limits(7, 1000).unwrap();
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
    let mut s = scan(l, ListNamespace::All);
    s.limits.max_pages = 1;
    let (t, _) = admit(&mut s, l, &mut q);
    s.accept(
        Ok(l),
        2,
        ReadCompletion::new(t, ReadOutcome::CanceledUnsent),
    )
    .unwrap();
    assert!(matches!(
        s.submit_with::<()>(l, 2, |_| panic!()),
        Err(ListSubmitError::Scan(ListScanError::PageBudget))
    ));
    let mut s = scan(l, ListNamespace::All);
    assert!(matches!(
        s.submit_with::<()>(l, 100, |_| panic!()),
        Err(ListSubmitError::Scan(ListScanError::Deadline))
    ));
}
#[test]
fn query_rejection_preserves_capacity_and_clock_identity_state_bounds_are_sticky() {
    let l = layout(1, 1);
    let mut ns = Vec::with_capacity(100);
    ns.extend_from_slice(b"raw");
    let err = ListScan::new(
        l,
        ListQuery {
            filter: None,
            pool: 7,
            namespace: ListNamespace::Exact(ns),
        },
        ListLimits {
            state_bytes: 99,
            ..Default::default()
        },
        100,
        0,
    )
    .unwrap_err();
    assert_eq!(err.reason, ListScanError::StateBudget);
    let ListNamespace::Exact(ns) = err.query.namespace else {
        panic!()
    };
    assert_eq!(ns.capacity(), 100);
    for kind in 0..4 {
        let mut s = scan(l, ListNamespace::All);
        let mut q = queue();
        let (t, r) = admit(&mut s, l, &mut q);
        let mut current = l;
        let mut now = 2;
        let expected = match kind {
            0 => {
                current.fsid = Uuid([8; 16]);
                ListScanError::Identity
            }
            1 => {
                now = 0;
                ListScanError::Clock
            }
            2 => {
                current.hash = STR_HASH_LINUX;
                ListScanError::Identity
            }
            _ => {
                s.limits.state_bytes = 1;
                ListScanError::StateBudget
            }
        };
        let next = if kind == 3 {
            objects()[1].clone()
        } else {
            Hobject::MAX()
        };
        let err = s
            .accept(Ok(current), now, done(t, &r, next, vec![], 1))
            .unwrap_err();
        assert_eq!(err.error, expected);
        assert_eq!(s.position(), &Hobject::MIN());
        assert_eq!(s.error(), Some(expected));
    }
}

#[test]
fn admitted_count_output_namespace_and_lower_cut_are_rechecked() {
    for kind in 0..4 {
        let l = layout(1, 1);
        let mut s = scan(
            l,
            if kind == 2 {
                ListNamespace::Exact(vec![])
            } else {
                ListNamespace::All
            },
        );
        let mut q = queue();
        let all = objects();
        if kind == 3 {
            let (t, r) = admit(&mut s, l, &mut q);
            s.accept(
                Ok(l),
                2,
                done(t, &r, all[2].clone(), vec![entry(&all[0])], 1),
            )
            .unwrap();
        }
        let (t, r) = admit(&mut s, l, &mut q);
        let relaxed = PgListRequest::new(7, ListNamespace::All, 0, 1, Hobject::MIN(), 100, 1 << 20);
        let entries = match kind {
            0 => all.iter().take(4).map(entry).collect(),
            2 => vec![entry(all.iter().find(|h| !h.nspace.is_empty()).unwrap())],
            3 => vec![entry(&all[0])],
            _ => vec![],
        };
        let c = done(t, &relaxed, Hobject::MAX(), entries, 1);
        if kind == 1 {
            s.pending.as_mut().unwrap().output = 1;
        }
        let before = s.position().clone();
        assert_eq!(
            s.accept(Ok(l), 2, c).unwrap_err().error,
            ListScanError::Protocol,
            "kind={kind}"
        );
        assert_eq!(s.position(), &before);
        assert_eq!(r.pg(), 0);
    }
}
#[test]
fn empty_pool_finishes_with_no_entries_and_no_extra_admission() {
    let l = layout(5, 1);
    let mut s = scan(l, ListNamespace::All);
    let mut q = queue();
    let mut order = vec![];
    while !s.is_done() {
        let (t, r) = admit(&mut s, l, &mut q);
        order.push(r.pg());
        s.accept(Ok(l), 2, done(t, &r, end(&r), vec![], 1)).unwrap();
    }
    assert_eq!(order, [0, 4, 2, 1, 3]);
    assert_eq!(s.pages_submitted(), 5);
}

#[test]
fn layout_profile_and_epoch_regressions_fail_before_admission() {
    let l = layout(3, 7);
    for changed in [
        ListLayout { epoch: 6, ..l },
        ListLayout {
            pg_num: 5,
            mask: 7,
            ..l
        },
    ] {
        let mut s = scan(l, ListNamespace::All);
        assert!(matches!(
            s.submit_with::<()>(changed, 0, |_| panic!()),
            Err(ListSubmitError::Scan(ListScanError::Layout))
        ));
        assert_eq!(s.pages_submitted(), 0);
        assert_eq!(s.position(), &Hobject::MIN());
    }
    let mut map = OsdMap::default();
    map.fsid = l.fsid;
    map.epoch = 1;
    map.flags = osdmap::consts::map_flags::SORTBITWISE;
    for kind in 0..3 {
        let mut p = osdmap::PgPool {
            ptype: 1,
            pg_num: 3,
            object_hash: 2,
            ..Default::default()
        };
        match kind {
            0 => p.ptype = 0,
            1 => p.pg_num = 0,
            _ => p.object_hash = 0,
        };
        map.pools.insert(7, p);
        assert_eq!(ListLayout::from_map(&map, 7), Err(ListScanError::Layout));
    }
}

#[test]
fn namespace_filtered_backend_pages_can_be_empty_without_finishing_the_pg() {
    let l = layout(1, 1);
    let mut s = scan(l, ListNamespace::Exact(b"absent".to_vec()));
    let mut q = queue();
    for (index, next) in [
        Hobject::new(b"a", SnapId(opwire::NOSNAP), 7, 7, b"other"),
        Hobject::new(b"b", SnapId(opwire::NOSNAP), 7, 7, b"other"),
        Hobject::MAX(),
    ]
    .into_iter()
    .enumerate()
    {
        let (t, r) = admit(&mut s, l, &mut q);
        let ListScanStep::Page(page) = s
            .accept(Ok(l), 2, done(t, &r, next.clone(), vec![], 1))
            .unwrap()
        else {
            panic!()
        };
        assert!(page.is_empty());
        assert_eq!(page.pg_finished(), index == 2);
        assert_eq!(s.is_done(), index == 2);
        assert_eq!(s.position(), &next);
    }
    assert_eq!(s.pages_submitted(), 3);
}

#[test]
#[expect(
    clippy::result_large_err,
    reason = "Rejected requests return caller-owned input without allocation"
)]
fn scan_filter_is_captured_in_each_page_and_persistent_capacity_is_bounded() {
    let l = layout(3, 1);
    let mut raw = Vec::with_capacity(128);
    raw.extend_from_slice(b"_tag");
    let ptr = raw.as_ptr();
    let filter = crate::ListFilter::Plain {
        raw_xattr: raw,
        value: vec![0, 255],
    };
    let query = ListQuery {
        pool: 7,
        namespace: ListNamespace::All,
        filter: Some(filter),
    };
    let err = ListScan::new(
        l,
        query,
        ListLimits {
            state_bytes: 129,
            ..Default::default()
        },
        100,
        0,
    )
    .unwrap_err();
    assert_eq!(err.reason, ListScanError::StateBudget);
    let Some(crate::ListFilter::Plain { raw_xattr, .. }) = &err.query.filter else {
        panic!()
    };
    assert_eq!(raw_xattr.as_ptr(), ptr);
    let mut s = ListScan::new(
        l,
        err.query,
        ListLimits {
            state_bytes: 130,
            ..Default::default()
        },
        100,
        0,
    )
    .unwrap();
    let mut q = queue();
    let mut count = 0;
    while !s.is_done() {
        let mut captured = None;
        let token = s
            .submit_with(l, 2, |r| {
                assert_eq!(r.filter(), safely_expected_filter().as_ref());
                let duplicate = PgListRequest::new(
                    r.pool(),
                    ListNamespace::All,
                    r.pg(),
                    r.pg_num(),
                    r.cursor().clone(),
                    r.max_entries(),
                    r.max_output_bytes(),
                );
                captured = Some(duplicate);
                q.submit_pg_list(r)
            })
            .unwrap()
            .unwrap();
        let r = captured.unwrap();
        s.accept(Ok(l), 2, done(token, &r, end(&r), vec![], 1))
            .unwrap();
        count += 1;
    }
    assert_eq!(count, 3);
    fn safely_expected_filter() -> Option<crate::ListFilter> {
        Some(crate::ListFilter::Plain {
            raw_xattr: b"_tag".to_vec(),
            value: vec![0, 255],
        })
    }
}

#[path = "list_range_tests.rs"]
mod ranges;

#[test]
fn public_layout_hash_respects_locator_namespace_and_non_power_of_two_pg_mapping() {
    let l = layout(12, 1);
    let name = l.hash_object(b"blue", b"object", b"");
    assert_eq!(l.hash_object(b"blue", b"other", b"object"), name);
    assert_eq!(l.hash_object(b"blue", b"object", b"object"), name);
    assert_ne!(l.hash_object(b"red", b"object", b""), name);
    assert_eq!(l.pg_for_hash(13), 5);
    assert_eq!(l.pg_for_hash(5), 5);
    assert_eq!(l.pg_for_hash(u32::MAX), 7);
}
#[test]
fn compatible_scan_has_no_total_page_or_state_profile_ceiling() {
    let layout = layout(1, 1);
    let query = ListQuery {
        pool: 7,
        namespace: ListNamespace::All,
        filter: Some(crate::ListFilter::Plain {
            raw_xattr: b"_filter".to_vec(),
            value: vec![1; 2 * 1024 * 1024 + 1],
        }),
    };
    let mut scan =
        ListScan::new_compatible_range(layout, query.clone(), ListRange::full(), 5000, 100, 0)
            .unwrap();
    // Model a long-running advancing scan without a million-iteration unit test.
    scan.pages = 1_000_000;
    let mut queue = ObjectQueue::with_compatible_admission(1, 1, 0, 9, 1).unwrap();
    let (token, request) = admit(&mut scan, layout, &mut queue);
    assert_eq!(request.max_entries(), 5000);
    assert_eq!(request.max_output_bytes(), u32::MAX);
    let next = Hobject::new(
        &vec![b'x'; 2 * 1024 * 1024 + 1],
        SnapId(opwire::NOSNAP),
        1,
        7,
        b"",
    );
    let completion = done(token, &request, next.clone(), vec![], 1);
    assert!(matches!(
        scan.accept(Ok(layout), 2, completion),
        Ok(ListScanStep::Page(_))
    ));
    assert_eq!(scan.position(), &next);
    assert_eq!(scan.pages_submitted(), 1_000_001);
    queue.cancel(token).unwrap();
    queue.poll_into(&mut [None]);
    scan.pages = u64::MAX;
    let (token, _) = admit(&mut scan, layout, &mut queue);
    assert_eq!(scan.pages_submitted(), u64::MAX);
    queue.cancel(token).unwrap();
    queue.poll_into(&mut [None]);
    assert!(matches!(
        ListScan::new_range(
            layout,
            query,
            ListRange::full(),
            ListLimits {
                entries: 5000,
                output_bytes: 1024,
                state_bytes: 2 * 1024 * 1024,
                max_pages: 1_000_000,
            },
            100,
            0
        ),
        Err(RejectedListRange {
            reason: ListScanError::StateBudget,
            ..
        })
    ));
}
