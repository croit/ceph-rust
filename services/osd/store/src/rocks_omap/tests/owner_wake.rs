// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Owner wake after worker publication: ordering witnesses, not timing assertions.
use super::*;

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

fn client() -> (Temp, Client) {
    let (temp, cfg, sb) = fixture();
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
    let client = Client::open(&cfg, &sb, 0, MEM, 0, 1).unwrap();
    (temp, client)
}

/// Counts wakes (Release). A reader that acquires the count and then finds no
/// completion in [`Client::has_completion`] would witness a wake issued before
/// publication: the publish-then-wake order the owner's re-check relies on.
fn counting(c: &Client) -> Arc<AtomicU64> {
    let wakes = Arc::new(AtomicU64::new(0));
    let w = wakes.clone();
    c.set_owner_wake(OwnerWake(Arc::new(move || {
        w.fetch_add(1, Ordering::Release);
    })));
    wakes
}

fn wait_wakes(wakes: &AtomicU64, n: u64) {
    let end = Instant::now() + Duration::from_secs(5);
    while wakes.load(Ordering::Acquire) < n {
        assert!(Instant::now() < end, "WARNING TIMEOUT owner wake {n}");
        std::thread::yield_now();
    }
}

#[test]
fn page_completion_wakes_owner_after_publication_and_stays_visible_until_poll() {
    let (_temp, mut c) = client();
    let wakes = counting(&c);
    c.test_hold_worker(true);
    assert!(matches!(c.query(page()), Err(StoreError::Miss)));
    assert!(
        !c.has_completion(),
        "nothing published while the worker holds"
    );
    assert_eq!(wakes.load(Ordering::Acquire), 0);
    c.test_hold_worker(false);
    wait_wakes(&wakes, 1);
    // Wake observed, owner not polled: the re-check must already see the completion.
    assert!(
        c.has_completion(),
        "wake issued before the completion was published"
    );
    assert!(c.poll());
    assert!(!c.has_completion());
    assert!(matches!(&*c.query(page()).unwrap(), Answer::Page(..)));
}

#[test]
fn flush_completion_wakes_owner() {
    let (_temp, mut c) = client();
    let wakes = counting(&c);
    let mut m = Memtable::new();
    m.put(2, 9, Bytes::from_static(b"k2"), Bytes::from_static(b"v2"));
    c.flush(Arc::new(m)).unwrap();
    wait_wakes(&wakes, 1);
    assert!(c.has_completion());
    c.poll();
    assert!(!c.has_completion());
}

#[test]
fn first_installed_wake_wins_and_no_wake_keeps_previous_behavior() {
    let (_temp, mut c) = client();
    // Without a wake: completion is still published and consumed by polling.
    assert!(matches!(c.query(page()), Err(StoreError::Miss)));
    let end = Instant::now() + Duration::from_secs(5);
    while !c.has_completion() {
        assert!(Instant::now() < end, "WARNING TIMEOUT unwoken completion");
        std::thread::yield_now();
    }
    assert!(c.poll());
    let first = counting(&c);
    let second = Arc::new(AtomicU64::new(0));
    let s = second.clone();
    c.set_owner_wake(OwnerWake(Arc::new(move || {
        s.fetch_add(1, Ordering::AcqRel);
    })));
    let mut m = Memtable::new();
    m.put(3, 9, Bytes::from_static(b"k3"), Bytes::from_static(b"v3"));
    c.flush(Arc::new(m)).unwrap();
    wait_wakes(&first, 1);
    assert_eq!(second.load(Ordering::Acquire), 0);
}
