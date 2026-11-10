// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Independent queue/accounting witnesses, not timing-performance assertions.
use super::*;
use metrics::profile as p;

fn page() -> Query {
    Query::Page {
        id: 9,
        from: Bytes::new(),
        excl: false,
        prefix: Bytes::new(),
        entries: 4,
        versions: [(0, 0); 3],
        session: None,
    }
}

fn client(enabled: bool) -> (Temp, Client) {
    let (temp, mut cfg, sb) = fixture();
    let mut db = db(&cfg, &sb, false);
    let mut data = Memtable::new();
    data.put(
        1,
        9,
        Bytes::from_static(b"key"),
        Bytes::from_static(b"value"),
    );
    db.flush(&data).unwrap();
    drop(db);
    cfg.profile = enabled;
    let client = Client::open(&cfg, &sb, 0, MEM, 0, 1).unwrap();
    (temp, client)
}

fn wait_counter(client: &Client, index: usize, count: u64) {
    let end = Instant::now() + Duration::from_secs(5);
    while client.profile_metrics()[index] < count {
        assert!(
            Instant::now() < end,
            "WARNING TIMEOUT handoff counter {index}"
        );
        std::thread::yield_now();
    }
}

#[test]
fn rejected_page_pushes_are_not_accepted_and_disabled_or_point_pushes_read_no_clock() {
    let on = metrics::Profile::new(true);
    let off = metrics::Profile::default();
    let (mut tx, mut rx) = RingBuffer::new(1);
    let at = Instant::now();
    let point = || {
        Request::Read(
            Query::Keys {
                id: 9,
                keys: vec![],
            },
            None,
            0,
        )
    };
    push_request_with(&mut tx, point(), &on, || panic!("point clock")).unwrap();
    let mut request = Request::Page(page(), [None, None, None], 1000, None, None);
    for n in 1..=2 {
        request = match push_request_with(&mut tx, request, &on, || at + Duration::from_nanos(n)) {
            Err(rtrb::PushError::Full(request)) => request,
            Ok(()) => panic!("full request ring accepted a page"),
        };
        assert_eq!(on.sample()[p::HANDOFF_ACCEPTED], 0);
    }
    drop(rx.pop().unwrap());
    push_request_with(&mut tx, request, &on, || at + Duration::from_nanos(3)).unwrap();
    let Request::Page(_, _, _, _, queued) = rx.pop().unwrap() else {
        panic!("page")
    };
    assert_eq!(queued, Some(at + Duration::from_nanos(3)));
    assert_eq!(on.sample()[p::HANDOFF_ACCEPTED], 1);
    push_request_with(
        &mut tx,
        Request::Page(page(), [None, None, None], 1000, None, None),
        &off,
        || panic!("disabled page clock"),
    )
    .unwrap();
    let Request::Page(_, _, _, _, queued) = rx.pop().unwrap() else {
        panic!("page")
    };
    assert!(queued.is_none());
    let (mut tx, _rx) = RingBuffer::new(1);
    push_response_with(
        &mut tx,
        Response::unprofiled(Completion::Failed(err("unprofiled"))),
        &off,
        || panic!("disabled response clock"),
    )
    .unwrap();
    assert_eq!(off.sample(), [0; p::LEN]);
}

#[test]
fn worker_hold_precedes_execution_owner_hold_precedes_consumption_and_cache_is_not_a_page() {
    let (_temp, mut c) = client(true);
    c.test_hold_worker(true);
    let q = page();
    assert!(matches!(c.query(q.clone()), Err(StoreError::Miss)));
    wait_counter(&c, p::HANDOFF_DEQUEUED, 1);
    for _ in 0..8 {
        assert!(matches!(c.query(q.clone()), Err(StoreError::Miss)));
    }
    let s = c.profile_metrics();
    assert_eq!(&s[56..61], &[1, 1, 0, 0, 0]);
    c.test_hold_worker(false);
    // Deliberately do not poll the owner until publication has completed.
    wait_counter(&c, p::HANDOFF_PUBLISHED, 1);
    assert_eq!(c.profile_metrics()[p::HANDOFF_CONSUMED], 0);
    assert!(c.poll());
    let first = c.query(q.clone()).unwrap();
    let Answer::Page(entries, PageEnd::End) = &*first else {
        panic!("owned page")
    };
    assert_eq!(
        entries.to_pairs(),
        vec![(Bytes::from_static(b"key"), Bytes::from_static(b"value"))]
    );
    for _ in 0..8 {
        assert!(Arc::ptr_eq(&first, &c.query(q.clone()).unwrap()));
    }
    let s = c.profile_metrics();
    assert_eq!(&s[56..67], &[1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0]);
    assert_eq!(s[67..71].iter().sum::<u64>(), s[71]);
}

#[test]
fn profiled_page_refusal_and_request_failure_keep_original_outcomes() {
    let (_temp, mut c) = client(true);
    c.test_read_budget(0);
    let q = page();
    assert!(matches!(c.query(q.clone()), Err(StoreError::Miss)));
    wait_counter(&c, p::HANDOFF_PUBLISHED, 1);
    c.poll();
    assert!(matches!(c.query(q), Err(StoreError::TxnTooLarge)));
    assert_eq!(&c.profile_metrics()[60..66], &[1, 0, 1, 0, 1, 0]);

    let (_temp, mut c) = client(true);
    // A deliberately invalid internal page envelope exercises the existing
    // page-error→Failed conversion; public routing never sends this mismatch.
    let bad = Request::Page(
        Query::Keys {
            id: 9,
            keys: vec![],
        },
        [None, None, None],
        1000,
        None,
        None,
    );
    push_request_with(&mut c.tx, bad, &c.metrics.profile, Instant::now).unwrap();
    c.thread.unpark();
    wait_counter(&c, p::HANDOFF_PUBLISHED, 1);
    c.poll();
    assert!(matches!(
        c.failure,
        Some(StoreError::Invalid("non-page RocksDB overlay query"))
    ));
    assert_eq!(&c.profile_metrics()[60..66], &[1, 0, 0, 1, 1, 0]);
}

#[test]
fn cancellation_and_full_response_owner_drop_leave_explicit_incomplete_windows() {
    let (_temp, mut c) = client(true);
    c.test_hold_worker(true);
    assert!(matches!(c.query(page()), Err(StoreError::Miss)));
    wait_counter(&c, p::HANDOFF_DEQUEUED, 1);
    let metrics = c.metrics.clone();
    c.test_stop_worker();
    drop(c);
    assert_eq!(
        &metrics.profile.sample()[56..67],
        &[1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );

    let (_temp, mut c) = client(true);
    let end = Instant::now() + Duration::from_secs(5);
    for _ in 0..=QUEUE {
        let mut request = Request::Page(page(), [None, None, None], 4096, None, None);
        loop {
            match push_request_with(&mut c.tx, request, &c.metrics.profile, Instant::now) {
                Ok(()) => break,
                Err(rtrb::PushError::Full(value)) => request = value,
            }
            assert!(
                Instant::now() < end,
                "WARNING TIMEOUT filling completion ring"
            );
            c.thread.unpark();
            std::thread::yield_now();
        }
        c.thread.unpark();
    }
    wait_counter(&c, p::HANDOFF_FULL_RETRIES, 1);
    let metrics = c.metrics.clone();
    drop(c);
    let s = metrics.profile.sample();
    assert_eq!(
        &s[56..61],
        &[
            (QUEUE + 1) as u64,
            (QUEUE + 1) as u64,
            (QUEUE + 1) as u64,
            QUEUE as u64,
            0
        ]
    );
    assert_eq!(
        s[p::HANDOFF_SAMPLES],
        0,
        "abandoned work is not a zero-time sample"
    );
    assert_eq!(s[p::HANDOFF_ERRORS], 0);
}

#[test]
fn disabled_profile_returns_identical_owned_content_without_handoff_samples() {
    let (_temp, mut c) = client(false);
    let end = Instant::now() + Duration::from_secs(5);
    let answer = loop {
        match c.query(page()) {
            Ok(answer) => break answer,
            Err(StoreError::Miss) => {}
            Err(e) => panic!("{e:?}"),
        }
        c.poll();
        assert!(Instant::now() < end, "WARNING TIMEOUT disabled page");
        std::thread::yield_now();
    };
    let Answer::Page(entries, PageEnd::End) = &*answer else {
        panic!("page")
    };
    assert_eq!(
        entries.to_pairs(),
        vec![(Bytes::from_static(b"key"), Bytes::from_static(b"value"))]
    );
    assert_eq!(c.profile_metrics(), [0; p::LEN]);
}

#[test]
fn handoff_queue_layout_is_fixed_and_reported_not_claimed_free_when_disabled() {
    use std::mem::size_of;
    // Independent before-layout witness: no values are constructed or exported.
    #[allow(dead_code)]
    enum BeforeRequest {
        Flush(Arc<Memtable>, Option<Instant>),
        Read(Query, Option<(u64, u64)>, usize),
        Page(Query, [Option<Arc<ObjMem>>; 3], usize, Option<(u64, u64)>),
    }
    let request_delta = size_of::<Request>() - size_of::<BeforeRequest>();
    let response_delta = size_of::<Response>() - size_of::<Completion>();
    assert!(request_delta <= size_of::<Option<Instant>>());
    assert!(response_delta <= size_of::<Option<metrics::Handoff>>());
    println!(
        "HANDOFF_LAYOUT request_before={} request_after={} response_before={} response_after={} slots_per_ring={} added_ring_bytes={}",
        size_of::<BeforeRequest>(),
        size_of::<Request>(),
        size_of::<Completion>(),
        size_of::<Response>(),
        QUEUE,
        QUEUE * (request_delta + response_delta)
    );
}
