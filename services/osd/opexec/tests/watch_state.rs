// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Volatile watch registry (`opexec::watch::Watches`): reconnect semantics and the timer index.
use denc::types::{EntityAddr, EntityName, Hobject};
use opexec::Out;
use opexec::watch::Watches;
use opwire::consts::notify as nop;

const NS: u64 = 1_000_000_000;

fn head(n: u32) -> Hobject {
    Hobject {
        oid: format!("o{n}").into_bytes(),
        ..Default::default()
    }
}

fn notify_opcodes(out: &[Out]) -> Vec<u8> {
    out.iter()
        .filter_map(|o| match o {
            Out::Notify { msg, .. } => Some(msg.opcode),
            _ => None,
        })
        .collect()
}

/// A repeated registration on the connection the watcher is already bound to is a no-op (classic: "already
/// connected"). It neither re-delivers the notifies still waiting for this watcher's ack (a second callback for
/// the same notify id) nor restarts the ping lease.
#[test]
fn reconnect_on_the_same_connection_does_not_redeliver_pending_notifies() {
    let h = head(1);
    let key = (7u64, EntityName::client(100));
    let mut w = Watches::default();
    let mut out = Vec::new();
    w.connect(
        &h,
        key,
        Some(1),
        EntityAddr::default(),
        30,
        true,
        0,
        &mut out,
    );
    w.notify(5, &h, &[key], 2, 9, 0x77, b"p".to_vec(), 30, 1, 0, &mut out);
    assert_eq!(notify_opcodes(&out), [nop::NOTIFY]);
    out.clear();
    // same connection again (a RECONNECT/WATCH resend): nothing is delivered twice
    w.connect(
        &h,
        key,
        Some(1),
        EntityAddr::default(),
        30,
        true,
        10 * NS,
        &mut out,
    );
    assert!(notify_opcodes(&out).is_empty(), "duplicate NOTIFY delivery");
    // a new connection after a disconnect does get the pending notify (classic: send_notify on connect)
    w.conn_closed(1, 11 * NS);
    w.connect(
        &h,
        key,
        Some(3),
        EntityAddr::default(),
        30,
        true,
        12 * NS,
        &mut out,
    );
    assert_eq!(notify_opcodes(&out), [nop::NOTIFY]);
}

/// A legacy (non-ping) WATCH that completes after its connection closed: `conn_closed` already ran, so `connect`
/// itself starts the timeout and binds no connection; the watcher then expires instead of living forever.
#[test]
fn legacy_watch_on_an_already_closed_connection_expires() {
    let h = head(1);
    let key = (7u64, EntityName::client(100));
    let mut w = Watches::default();
    let mut out = Vec::new();
    w.connect(
        &h,
        key,
        None,
        EntityAddr::default(),
        30,
        false,
        5 * NS,
        &mut out,
    );
    assert!(w.connected_keys(&h).is_empty());
    assert_eq!(w.next_deadline(), Some(35 * NS));
    // an open connection keeps a legacy watcher without a deadline until the connection closes
    let other = (8u64, EntityName::client(100));
    w.connect(
        &h,
        other,
        Some(2),
        EntityAddr::default(),
        30,
        false,
        5 * NS,
        &mut out,
    );
    assert_eq!(w.connected_keys(&h), [other]);
    assert_eq!(w.next_deadline(), Some(35 * NS));
}

/// `next_deadline` is read after every op of a PG: it must not scan every watcher of the PG. Run with
/// `cargo test --release -p opexec --test watch_state -- --ignored --nocapture`.
#[test]
#[ignore = "benchmark"]
fn next_deadline_cost_with_many_watchers() {
    let mut w = Watches::default();
    let mut out = Vec::new();
    for i in 0..20_000u32 {
        w.connect(
            &head(i),
            (u64::from(i), EntityName::client(1)),
            Some(1),
            EntityAddr::default(),
            30,
            true,
            u64::from(i) * 1000,
            &mut out,
        );
    }
    let t = std::time::Instant::now();
    let mut acc = 0u64;
    for _ in 0..2_000 {
        acc ^= w.next_deadline().unwrap_or(0);
    }
    let per = t.elapsed().as_nanos() / 2_000;
    println!("next_deadline with 20000 watchers: {per} ns/call (acc {acc})");
}

/// NT-watchnotify-06: one connection close scans every watcher of every PG engine of the core
/// (`Engine::conn_closed` per engine). 100000 watchers over 100 PGs, one watcher per connection.
/// `cargo test --release -p opexec --test watch_state -- --ignored --nocapture`.
#[test]
#[ignore = "benchmark"]
fn conn_closed_cost_with_many_watchers() {
    let mut pgs: Vec<Watches> = (0..100).map(|_| Watches::default()).collect();
    let mut out = Vec::new();
    for i in 0..100_000u32 {
        pgs[(i % 100) as usize].connect(
            &head(i),
            (u64::from(i), EntityName::client(1)),
            Some(u64::from(i)),
            EntityAddr::default(),
            30,
            true,
            u64::from(i) * 1000,
            &mut out,
        );
    }
    let t = std::time::Instant::now();
    let mut acc = 0u32;
    for k in 0..200u64 {
        for w in &mut pgs {
            acc += u32::from(w.conn_closed(k, 1 << 40));
        }
    }
    let per = t.elapsed().as_nanos() / 200;
    println!("conn_closed with 100000 watchers over 100 PGs: {per} ns/close (acc {acc})");
}

/// NT-watchnotify-06: the per-connection index follows rebind, removal, notify completion, clear and a close of an
/// unknown connection (`conn_closed` cross-checks it against a scan in debug builds).
#[test]
fn conn_closed_index_tracks_every_binding_change() {
    let (a, b) = (head(1), head(2));
    let (ka, kb) = ((1u64, EntityName::client(1)), (2u64, EntityName::client(2)));
    let mut w = Watches::default();
    let mut out = Vec::new();
    let c = |w: &mut Watches, h: &Hobject, k, conn: Option<u64>, ping: bool, out: &mut Vec<Out>| {
        w.connect(h, k, conn, EntityAddr::default(), 30, ping, 0, out);
    };
    c(&mut w, &a, ka, Some(1), true, &mut out);
    c(&mut w, &b, kb, Some(1), false, &mut out);
    // rebind ka to conn 2: closing conn 1 must not touch it
    c(&mut w, &a, ka, Some(2), true, &mut out);
    assert!(w.conn_closed(1, 100)); // legacy kb starts its timeout
    assert!(!w.conn_closed(1, 100));
    assert!(!w.conn_closed(99, 100));
    // removal drops the binding, a later close of its old connection is a no-op
    c(&mut w, &a, ka, Some(3), true, &mut out);
    w.remove(&a, &ka, false, &mut out);
    assert!(!w.conn_closed(3, 100));
    // notify owner index: completion drops it, a fresh notify on conn 4 loses its notifier on close
    c(&mut w, &a, ka, Some(2), true, &mut out);
    let id = w.notify(1, &a, &[ka], 4, 7, 9, Vec::new(), 30, 0, 0, &mut out);
    w.check_complete(id, &mut out);
    assert!(!w.conn_closed(4, 100));
    w.clear();
    assert!(!w.conn_closed(2, 100));
    assert!(w.is_empty());
}

/// The index agrees with the deadlines through ping, close, removal, notify completion and expiry.
#[test]
fn next_deadline_tracks_every_deadline_change() {
    let a = head(1);
    let b = head(2);
    let ka = (1u64, EntityName::client(1));
    let kb = (2u64, EntityName::client(2));
    let mut w = Watches::default();
    let mut out = Vec::new();
    assert_eq!(w.next_deadline(), None);
    w.connect(
        &a,
        ka,
        Some(1),
        EntityAddr::default(),
        30,
        true,
        0,
        &mut out,
    );
    w.connect(
        &b,
        kb,
        Some(2),
        EntityAddr::default(),
        10,
        true,
        0,
        &mut out,
    );
    assert_eq!(w.next_deadline(), Some(10 * NS));
    w.ping(&b, &kb, 5 * NS);
    assert_eq!(w.next_deadline(), Some(15 * NS));
    w.remove(&b, &kb, false, &mut out);
    assert_eq!(w.next_deadline(), Some(30 * NS));
    // a notify's deadline counts until it completes
    w.notify(1, &a, &[ka], 9, 9, 3, Vec::new(), 2, 0, 0, &mut out);
    assert_eq!(w.next_deadline(), Some(2 * NS));
    let id = (1u64 << 32) | 1;
    w.ack(&a, ka.1, id, ka.0, false, Vec::new(), &mut out);
    assert_eq!(w.next_deadline(), Some(30 * NS));
    // legacy watcher: no deadline while connected, one once its connection closed
    w.connect(
        &b,
        kb,
        Some(2),
        EntityAddr::default(),
        10,
        false,
        0,
        &mut out,
    );
    assert_eq!(w.next_deadline(), Some(30 * NS));
    w.conn_closed(2, 20 * NS);
    assert_eq!(w.next_deadline(), Some(30 * NS));
    // an expired notify leaves the index with the tick
    w.notify(1, &a, &[ka], 9, 9, 4, Vec::new(), 1, 0, 25 * NS, &mut out);
    assert_eq!(w.next_deadline(), Some(26 * NS));
    let dead = w.tick(26 * NS, &mut out);
    assert!(dead.is_empty());
    assert_eq!(w.next_deadline(), Some(30 * NS));
    w.clear();
    assert_eq!(w.next_deadline(), None);
}
