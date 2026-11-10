// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use bytes::Bytes;
use denc::{
    Encode,
    types::{Hobject, PgT, SnapId},
};
use opwire::{ListObjEntry, MOSDOpReply, PgNlsResponse, flag};
use rustyrados::*;
fn req(ns: ListNamespace) -> PgListRequest {
    PgListRequest::new(7, ns, 0, 2, Hobject::MIN(), 2, 1024)
}
fn route() -> ReadRoute {
    ReadRoute {
        direct_read: false,
        base_pool: 7,
        osd: 2,
        session: 3,
        pg: PgT { pool: 7, seed: 0 },
        hash: 0,
        epoch: 9,
        features: 0,
        generation: 1,
        pool: rustyrados::PoolRoute::Replicated,
    }
}
fn next(hash: u32) -> Hobject {
    Hobject::new(b"", SnapId(opwire::NOSNAP), hash, 7, b"")
}
fn response(
    d: &ReadDispatch,
    result: i32,
    next: Hobject,
    entries: Vec<ListObjEntry>,
) -> MOSDOpReply {
    let mut r = MOSDOpReply::for_request(&d.message, 10);
    r.result = result;
    r.ops[0].outdata = PgNlsResponse {
        handle: next,
        entries,
    }
    .encode_to_vec()
    .unwrap()
    .into();
    r
}
fn take(q: &mut ObjectQueue) -> ReadOutcome {
    let mut out = [None];
    assert_eq!(q.poll_into(&mut out), 1);
    out[0].take().unwrap().outcome
}
#[test]
fn explicit_pg_wire_namespace_cursor_count_epoch_and_credit_are_captured() {
    let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
    let t = q.submit_pg_list(req(ListNamespace::All)).unwrap();
    let charge = q.charged_bytes();
    assert_eq!(charge, 2049);
    let mut wrong = route();
    wrong.hash = 17;
    assert_eq!(q.dispatch(t, wrong).unwrap_err(), DriverError::InvalidRoute);
    let d = q.dispatch(t, route()).unwrap();
    assert!(d.message.oid.is_empty());
    assert_eq!(d.message.oloc.nspace, [1]);
    assert_eq!(
        d.message.flags & (flag::READ | flag::ONDISK | flag::IGNORE_OVERLAY | flag::PGOP),
        flag::READ | flag::ONDISK | flag::IGNORE_OVERLAY
    );
    assert_eq!(d.message.ops[0].pgls().count, 2);
    assert_eq!(d.message.ops[0].pgls().start_epoch, 9);
    let r = response(
        &d,
        0,
        next(2),
        vec![ListObjEntry {
            nspace: vec![255, 0],
            oid: vec![65, 0, 255],
            locator: vec![9, 8],
        }],
    );
    q.reply(t, 2, 3, r).unwrap();
    assert_eq!(q.charged_bytes(), charge);
    let ReadOutcome::RemotePgList {
        page: Some(p),
        result: 0,
        map_epoch: 10,
        ..
    } = take(&mut q)
    else {
        panic!()
    };
    assert_eq!(q.charged_bytes(), 0);
    assert!(!p.pg_finished());
    assert!(!p.pool_finished());
    assert_eq!(p.next_cursor(), &next(2));
    let entries: Vec<_> = p.entries().collect();
    assert_eq!(entries[0].namespace, [255, 0]);
    assert_eq!(entries[0].object, [65, 0, 255]);
    assert_eq!(entries[0].locator, [9, 8]);
}
#[test]
fn ec_plain_and_filtered_pages_keep_primary_shard_namespace_and_server_errors() {
    use denc::types::ShardId;
    for filtered in [false, true] {
        for namespace in [ListNamespace::All, ListNamespace::Exact(vec![0, 255])] {
            let mut request = req(namespace.clone());
            if filtered {
                request = request.with_filter(ListFilter::Plain {
                    raw_xattr: b"_tag".to_vec(),
                    value: b"value".to_vec(),
                });
            }
            let mut q = ObjectQueue::new(1, 8192, 1).unwrap();
            let token = q.submit_pg_list(request).unwrap();
            let d = q
                .dispatch(
                    token,
                    ReadRoute {
                        pool: PoolRoute::Erasure(ShardId(2)),
                        ..route()
                    },
                )
                .unwrap();
            for version in [8, 9] {
                let encoded = d.message.encode_version(version, 0).unwrap();
                let wire =
                    opwire::MOSDOp::decode_shared(version, &encoded.front, &encoded.data).unwrap();
                assert_eq!(wire.pgid.shard, ShardId(2));
                assert_eq!(wire.pgid.pgid, PgT::new(7, 0));
                assert_eq!(wire.hash, 0);
                assert_eq!(wire.flags & flag::PGOP, 0);
                assert_ne!(wire.flags & flag::IGNORE_OVERLAY, 0);
                assert_eq!(
                    wire.oloc.nspace,
                    match &namespace {
                        ListNamespace::All => vec![1],
                        ListNamespace::Exact(ns) => ns.clone(),
                    }
                );
            }
            let mut r = MOSDOpReply::for_request(&d.message, 10);
            r.result = -95;
            r.ops[0].rval = -95;
            q.reply(token, 2, 3, r).unwrap();
            assert!(matches!(
                take(&mut q),
                ReadOutcome::RemotePgList {
                    result: -95,
                    op_result: -95,
                    page: None,
                    ..
                }
            ));
            assert_eq!(q.charged_bytes(), 0);
        }
    }
}
#[test]
fn empty_page_advances_and_pg_end_is_distinct_from_pool_end() {
    for (pg, handle, result, finished, pool_end) in [
        (0, next(2), 0, false, false),
        (0, next(1), 1, true, false),
        (1, Hobject::MAX(), 1, true, true),
    ] {
        let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
        let t = q
            .submit_pg_list(PgListRequest::new(
                7,
                ListNamespace::Exact(vec![]),
                pg,
                2,
                Hobject::MIN(),
                2,
                1024,
            ))
            .unwrap();
        let mut r = route();
        r.pg.seed = pg;
        r.hash = pg;
        let d = q.dispatch(t, r).unwrap();
        q.reply(t, 2, 3, response(&d, result, handle, vec![]))
            .unwrap();
        let ReadOutcome::RemotePgList { page: Some(p), .. } = take(&mut q) else {
            panic!()
        };
        assert!(p.is_empty());
        assert_eq!((p.pg_finished(), p.pool_finished()), (finished, pool_end));
    }
}
#[test]
fn empty_body_race_and_layout_change_never_fabricate_eof() {
    let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
    let t = q.submit_pg_list(req(ListNamespace::All)).unwrap();
    let d = q.dispatch(t, route()).unwrap();
    q.reply(t, 2, 3, MOSDOpReply::for_request(&d.message, 10))
        .unwrap();
    assert_eq!(take(&mut q), ReadOutcome::ListingChanged { pg_num: None });
    let t = q.submit_pg_list(req(ListNamespace::All)).unwrap();
    q.listing_changed(t, Some(3)).unwrap();
    assert_eq!(
        take(&mut q),
        ReadOutcome::ListingChanged { pg_num: Some(3) }
    );
}
#[test]
fn malformed_pages_cannot_publish_data_or_release_credit_as_success() {
    for kind in 0..7 {
        let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
        let t = q
            .submit_pg_list(req(ListNamespace::Exact(b"ns".to_vec())))
            .unwrap();
        let d = q.dispatch(t, route()).unwrap();
        let mut r = response(
            &d,
            0,
            next(2),
            vec![ListObjEntry {
                nspace: b"ns".to_vec(),
                oid: b"a".to_vec(),
                locator: vec![],
            }],
        );
        match kind {
            0 => r.ops[0].outdata = Bytes::from_static(&[1, 1, 255, 255, 255, 255]),
            1 => r = response(&d, 0, Hobject::MIN(), vec![]),
            2 => {
                r = response(
                    &d,
                    0,
                    next(1),
                    vec![ListObjEntry {
                        nspace: b"other".to_vec(),
                        ..Default::default()
                    }],
                )
            }
            3 => r = response(&d, 1, next(2), vec![]),
            4 => {
                r = response(
                    &d,
                    0,
                    next(2),
                    vec![
                        ListObjEntry {
                            nspace: b"ns".to_vec(),
                            ..Default::default()
                        };
                        3
                    ],
                )
            }
            5 => {
                let mut bytes = r.ops[0].outdata.to_vec();
                bytes.push(0);
                r.ops[0].outdata = bytes.into();
            }
            _ => r.ops[0].rval = -5,
        }
        assert_eq!(
            q.reply(t, 2, 3, r),
            Err(DriverError::InvalidReply),
            "case {kind}"
        );
        assert!(q.is_pending(t));
        q.cancel(t).unwrap();
        assert_eq!(take(&mut q), ReadOutcome::PossiblySent);
        assert_eq!(q.charged_bytes(), 0);
    }
}
#[test]
fn oversized_reply_is_per_request_failure_and_remote_error_keeps_bounded_bytes() {
    let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
    let t = q
        .submit_pg_list(PgListRequest::new(
            7,
            ListNamespace::All,
            0,
            2,
            Hobject::MIN(),
            1,
            8,
        ))
        .unwrap();
    let d = q.dispatch(t, route()).unwrap();
    let r = response(&d, 1, next(1), vec![]);
    let len = r.ops[0].outdata.len() as u64;
    q.reply(t, 2, 3, r).unwrap();
    assert_eq!(take(&mut q), ReadOutcome::ListingTooLarge { bytes: len });
    let t = q.submit_pg_list(req(ListNamespace::All)).unwrap();
    let d = q.dispatch(t, route()).unwrap();
    let mut r = MOSDOpReply::for_request(&d.message, 10);
    r.result = -13;
    r.ops[0].outdata = Bytes::from_static(b"denied");
    q.reply(t, 2, 3, r).unwrap();
    assert!(
        matches!(take(&mut q),ReadOutcome::RemotePgList {result:-13,page:None,error_data,..} if error_data==b"denied"[..])
    );
}
#[test]
fn admission_bounds_retry_deadline_and_foreign_session_preserve_request_identity() {
    let mut q = ObjectQueue::with_retry_limit(1, 4096, 1, 2).unwrap();
    assert_eq!(
        q.submit_pg_list(req(ListNamespace::Exact(vec![1])))
            .unwrap_err()
            .reason,
        AdmissionError::InvalidOperation
    );
    let t = q.submit_pg_list(req(ListNamespace::All)).unwrap();
    q.set_deadline_us(t, 100, 100).unwrap();
    let d = q.dispatch(t, route()).unwrap();
    let r = response(&d, 0, next(2), vec![]);
    assert_eq!(q.reply(t, 2, 9, r), Err(DriverError::Stale));
    q.retry(t).unwrap();
    let d = q.dispatch(t, route()).unwrap();
    assert_eq!(d.token, t);
    assert_eq!(d.message.retry_attempt, 1);
    assert!(d.message.flags & flag::RETRY != 0);
    assert_eq!(q.retry(t), Err(DriverError::RetryExhausted));
    q.expire_us(100, 1);
    assert_eq!(
        take(&mut q),
        ReadOutcome::Deadline {
            possibly_sent: true
        }
    );
}

#[test]
fn owned_cursor_capacity_is_charged_and_rejected_without_cloning() {
    let mut cursor = Hobject::MIN();
    cursor.oid = Vec::with_capacity(4096);
    let ptr = cursor.oid.as_ptr();
    let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
    let rejected = q
        .submit_pg_list(PgListRequest::new(
            7,
            ListNamespace::All,
            0,
            2,
            cursor,
            2,
            1024,
        ))
        .unwrap_err();
    assert_eq!(rejected.reason, AdmissionError::NoCredit);
    assert_eq!(rejected.request.cursor().oid.as_ptr(), ptr);
    assert_eq!(q.outstanding(), 0);
    assert_eq!(q.charged_bytes(), 0);
}

#[test]
fn filtered_literal_wire_reply_opcode_retry_and_credit_are_bound_to_request() {
    let mut q = ObjectQueue::with_retry_limit(1, 4096, 1, 2).unwrap();
    let t = q
        .submit_pg_list(req(ListNamespace::All).with_filter(ListFilter::Plain {
            raw_xattr: vec![b'_', 0, 255],
            value: vec![b'A', 0, 255],
        }))
        .unwrap();
    assert_eq!(q.charged_bytes(), 2049 + 6 + 39);
    q.set_deadline_us(t, 100, 100).unwrap();
    let d = q.dispatch(t, route()).unwrap();
    assert_eq!(d.message.ops[0].op, opwire::op::PGNLS_FILTER);
    let prefix = [
        2, 0, 0, 0, b'p', b'g', 6, 0, 0, 0, b'f', b'i', b'l', b't', b'e', b'r', 5, 0, 0, 0, b'p',
        b'l', b'a', b'i', b'n', 3, 0, 0, 0, b'_', 0, 255, 3, 0, 0, 0, b'A', 0, 255,
    ];
    assert_eq!(&d.message.ops[0].indata[..39], prefix);
    assert_eq!(
        &d.message.ops[0].indata[39..],
        Hobject::MIN().encode_to_vec().unwrap()
    );
    let filter: denc::Result<opwire::PgFilterIn> = denc::from_slice(&d.message.ops[0].indata);
    assert!(
        matches!(filter.unwrap().filter,Some(opwire::PgFilter::Xattr{xattr,val}) if xattr==[b'_',0,255]&&val==[b'A',0,255])
    );
    q.retry(t).unwrap();
    let retried = q.dispatch(t, route()).unwrap();
    assert_eq!(retried.token, t);
    assert_eq!(retried.message.ops[0].indata, d.message.ops[0].indata);
    assert_eq!(retried.message.retry_attempt, 1);
    let mut wrong = response(&retried, 1, next(1), vec![]);
    wrong.ops[0].op = opwire::op::PGNLS;
    assert_eq!(q.reply(t, 2, 3, wrong), Err(DriverError::InvalidReply));
    assert_eq!(q.outstanding(), 1);
    q.reply(t, 2, 3, response(&retried, 1, next(1), vec![]))
        .unwrap();
    assert!(matches!(take(&mut q),ReadOutcome::RemotePgList{page:Some(p),..} if p.pg_finished()));
    assert_eq!(q.charged_bytes(), 0);
}
#[test]
fn class_filter_parameters_are_opaque_and_plain_empty_fields_are_encoded_explicitly() {
    for filter in [
        ListFilter::Class {
            name: b"custom.filter".to_vec(),
            parameters: vec![255, 0, 3, 9],
        },
        ListFilter::Plain {
            raw_xattr: vec![],
            value: vec![],
        },
    ] {
        let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
        let t = q
            .submit_pg_list(req(ListNamespace::All).with_filter(filter.clone()))
            .unwrap();
        assert_eq!(q.pg_listing(t).unwrap().filter(), Some(&filter));
        let d = q.dispatch(t, route()).unwrap();
        let mut decoder = denc::Decoder::new(&d.message.ops[0].indata);
        assert_eq!(decoder.bytes().unwrap(), b"pg");
        assert_eq!(decoder.bytes().unwrap(), b"filter");
        match filter {
            ListFilter::Class { name, parameters } => {
                assert_eq!(decoder.bytes().unwrap(), name);
                let begin = decoder.position();
                assert_eq!(
                    &d.message.ops[0].indata[begin..begin + parameters.len()],
                    parameters
                );
                assert_eq!(
                    &d.message.ops[0].indata[begin + parameters.len()..],
                    Hobject::MIN().encode_to_vec().unwrap()
                );
            }
            ListFilter::Plain { .. } => {
                assert_eq!(decoder.bytes().unwrap(), b"plain");
                assert!(decoder.bytes().unwrap().is_empty());
                assert!(decoder.bytes().unwrap().is_empty());
            }
        }
        let mut reply = MOSDOpReply::for_request(&d.message, 10);
        reply.result = -22;
        reply.ops[0].rval = -22;
        reply.ops[0].outdata = Bytes::from_static(b"bad-filter");
        q.reply(t, 2, 3, reply).unwrap();
        assert!(
            matches!(take(&mut q),ReadOutcome::RemotePgList{result:-22,page:None,error_data,..} if error_data==b"bad-filter"[..])
        );
    }
}
#[test]
fn filter_admission_retains_spare_capacities_and_invalid_classes_are_passive() {
    let mut raw = Vec::with_capacity(5000);
    raw.extend_from_slice(b"_tag");
    let pointer = raw.as_ptr();
    let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
    let error = q
        .submit_pg_list(req(ListNamespace::All).with_filter(ListFilter::Plain {
            raw_xattr: raw,
            value: vec![],
        }))
        .unwrap_err();
    assert_eq!(error.reason, AdmissionError::NoCredit);
    let Some(ListFilter::Plain { raw_xattr, .. }) = error.request.filter() else {
        panic!()
    };
    assert_eq!(raw_xattr.as_ptr(), pointer);
    assert_eq!(raw_xattr.capacity(), 5000);
    for name in [b"plain".as_slice(), b".filter", b"class.", b""] {
        let e = q
            .submit_pg_list(req(ListNamespace::All).with_filter(ListFilter::Class {
                name: name.to_vec(),
                parameters: vec![255],
            }))
            .unwrap_err();
        assert_eq!(e.reason, AdmissionError::InvalidOperation);
        assert_eq!(q.outstanding(), 0);
        assert_eq!(q.charged_bytes(), 0);
    }
}

#[test]
fn filtered_size_and_empty_body_races_preserve_failure_instead_of_false_eof() {
    for oversized in [false, true] {
        let mut q = ObjectQueue::new(1, 4096, 1).unwrap();
        let r = PgListRequest::new(
            7,
            ListNamespace::All,
            0,
            2,
            Hobject::MIN(),
            2,
            if oversized { 8 } else { 1024 },
        )
        .with_filter(ListFilter::Plain {
            raw_xattr: b"_tag".to_vec(),
            value: vec![],
        });
        let t = q.submit_pg_list(r).unwrap();
        let d = q.dispatch(t, route()).unwrap();
        let reply = if oversized {
            response(&d, 1, next(1), vec![])
        } else {
            MOSDOpReply::for_request(&d.message, 10)
        };
        q.reply(t, 2, 3, reply).unwrap();
        if oversized {
            assert!(matches!(take(&mut q), ReadOutcome::ListingTooLarge { .. }));
        } else {
            assert_eq!(take(&mut q), ReadOutcome::ListingChanged { pg_num: None });
        }
        assert_eq!(q.charged_bytes(), 0);
    }
}
