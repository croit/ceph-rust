// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! A single-shot transport owns the decoder allocation until every requested byte arrived.
mod common;
use common::*;
use denc::types::EntityName;
use msgr2::auth::*;
use msgr2::*;

fn secret() -> ConnSecret {
    ConnSecret::new(&(0..64u8).collect::<Vec<_>>()).unwrap()
}

fn pair(rev: Revision) -> (Encoder, Decoder) {
    let mut e = Encoder::new(rev);
    let mut d = Decoder::new(rev);
    e.set_secure(&secret(), Role::Client).unwrap();
    d.set_secure(&secret(), Role::Server).unwrap();
    (e, d)
}

fn frame(e: &mut Encoder, byte: u8) -> Vec<u8> {
    frame_header(e, byte, 41)
}

fn frame_header(e: &mut Encoder, byte: u8, header_len: usize) -> Vec<u8> {
    let mut w = Vec::new();
    e.encode_message(
        &vec![1; header_len],
        &[2; 103],
        &[3; 7],
        &vec![byte; 1 << 20],
        &mut w,
    )
    .unwrap();
    w
}

fn fill(loan: &mut SecureRxBuffer, wire: &[u8]) {
    assert_eq!(wire.len(), loan.remaining());
    for (i, chunk) in wire.chunks(4093).enumerate() {
        if i % 2 == 0 {
            for (slot, byte) in loan.spare_capacity_mut().iter_mut().zip(chunk) {
                slot.write(*byte);
            }
            // SAFETY: the complete next chunk was initialized above; no writer remains.
            unsafe { loan.commit_initialized(chunk.len()) };
        } else {
            loan.recv_buf()[..chunk.len()].copy_from_slice(chunk);
            loan.commit(chunk.len());
        }
    }
    assert_eq!(loan.remaining(), 0);
}

#[test]
fn secure_transport_loan_preserves_allocation_authentication_and_following_nonces() {
    fn is_send<T: Send>() {}
    is_send::<SecureRxBuffer>();
    for (rev, header_len) in [Revision::V20, Revision::V21]
        .into_iter()
        .flat_map(|rev| [41, 200].map(|len| (rev, len)))
    {
        let (mut e, mut d) = pair(rev);
        let first = frame_header(&mut e, 0x5a, header_len);
        let second = frame_header(&mut e, 0x6b, header_len);
        let prefix = 2111;
        assert_eq!(d.secure_want(), 0);
        d.feed(&first[..prefix]);
        assert!(d.poll_owned().unwrap().is_none());
        assert_eq!(d.secure_want(), first.len() - prefix);
        let expected_append = d.recv_buf(1).as_ptr();
        let mut loan = d.secure_take().unwrap();
        assert_eq!(loan.recv_buf().as_ptr(), expected_append);
        let allocation = expected_append as usize - prefix;
        assert_eq!(d.secure_want(), 0);
        assert!(d.secure_take().is_none());
        assert!(matches!(d.poll_owned(), Err(Error::Busy)));
        assert!(matches!(d.poll(), Err(Error::Busy)));
        assert!(matches!(
            d.set_secure(&secret(), Role::Server),
            Err(Error::Busy)
        ));
        fill(&mut loan, &first[prefix..]);
        d.secure_put(loan).unwrap();
        let f = d.poll_owned().unwrap().unwrap();
        assert_eq!(f.segs[0].as_ref(), vec![1; header_len]);
        assert_eq!(f.segs[1].as_ref(), &[2; 103]);
        assert_eq!(f.segs[2].as_ref(), &[3; 7]);
        assert!(f.segs[3].iter().all(|&b| b == 0x5a));
        assert!((allocation..allocation + first.len()).contains(&(f.segs[3].as_ptr() as usize)));
        // Holding the first authenticated frame must not let reuse mutate its plaintext.
        d.feed(&second);
        let next = d.poll_owned().unwrap().unwrap();
        assert!(next.segs[3].iter().all(|&b| b == 0x6b));
        assert!(f.segs[3].iter().all(|&b| b == 0x5a));
        assert!(d.poll_owned().unwrap().is_none());
    }
}

#[test]
fn secure_transport_loan_rejects_bad_tags_partial_and_foreign_loans() {
    for rev in [Revision::V20, Revision::V21] {
        for kind in 0..4 {
            let (mut e, mut d) = pair(rev);
            let mut w = frame(&mut e, 0x5a);
            d.feed(&w[..2111]);
            assert!(d.poll_owned().unwrap().is_none());
            let mut loan = d.secure_take().unwrap();
            match kind {
                0 => {
                    *w.last_mut().unwrap() ^= 1;
                    fill(&mut loan, &w[2111..]);
                    d.secure_put(loan).unwrap();
                    assert!(matches!(d.poll_owned(), Err(Error::AuthFailed)));
                }
                1 => {
                    assert!(matches!(d.secure_put(loan), Err(Error::Busy)));
                }
                2 => {
                    d.feed(&[1]); // Illegal concurrent input must never parse the placeholder buffer.
                    fill(&mut loan, &w[2111..]);
                    assert!(matches!(d.secure_put(loan), Err(Error::Failed)));
                }
                _ => {
                    let (_, mut replacement) = pair(rev);
                    replacement.feed(&w[..2111]);
                    assert!(replacement.poll_owned().unwrap().is_none());
                    let _replacement_loan = replacement.secure_take().unwrap();
                    fill(&mut loan, &w[2111..]);
                    assert!(matches!(replacement.secure_put(loan), Err(Error::Busy)));
                    assert!(matches!(replacement.poll_owned(), Err(Error::Failed)));
                    continue;
                }
            }
            assert!(matches!(d.poll_owned(), Err(Error::Failed)));
        }
    }
}

#[test]
fn a_faulted_connection_discards_its_late_secure_receive_loan() {
    let mut a = Node::new(EntityName::OSD, 1, 1, PolicyTable::osd_cluster());
    let mut b = Node::new(EntityName::OSD, 2, 2, PolicyTable::osd_cluster());
    let raw: Vec<u8> = (0..64u8).collect();
    let mut c = a.dial_with(
        &b,
        Box::new(KeyedClient {
            key: vec![9; 16],
            secret: raw.clone(),
            modes: vec![MODE_SECURE],
            method: AUTH_METHOD_CEPHX,
        }),
        t(0),
    );
    let mut s = b.accept_with(
        1,
        Box::new(KeyedServer {
            peer_name: None,
            key: vec![9; 16],
            secret: raw,
            rounds: 0,
            done: 0,
            methods: vec![AUTH_METHOD_CEPHX],
            modes: vec![MODE_SECURE],
        }),
        t(0),
    );
    exchange(&mut c, &mut s, t(1), &mut Rng(123), 4096);
    events(&mut c);
    events(&mut s);
    c.send_message(msg(77, 42, 1 << 16));
    let w = c.poll_output();
    s.on_bytes(&w[..2111], t(2));
    assert!(s.rx_secure_want() > 0);
    let mut loan = s.rx_secure_take().unwrap();
    fill(&mut loan, &w[2111..]);
    s.on_closed(t(3));
    s.rx_secure_put(loan, t(4));
    let ev = events(&mut s);
    assert!(ev.iter().any(|e| matches!(e, Event::Fault(_))));
    assert!(msgs(&ev).is_empty());
}

#[test]
fn positive_loan_receive_progress_refreshes_idle_timeout_without_early_delivery() {
    for mode in [MODE_CRC, MODE_SECURE] {
        let mut a = Node::new(EntityName::OSD, 1, 1, PolicyTable::osd_cluster());
        let mut b = Node::new(EntityName::OSD, 2, 2, PolicyTable::osd_cluster());
        b.cfg.idle_timeout = std::time::Duration::from_millis(5);
        let raw: Vec<u8> = (0..64u8).collect();
        let mut c = a.dial_with(
            &b,
            Box::new(KeyedClient {
                key: vec![9; 16],
                secret: raw.clone(),
                modes: vec![mode],
                method: AUTH_METHOD_CEPHX,
            }),
            t(0),
        );
        let mut s = b.accept_with(
            1,
            Box::new(KeyedServer {
                peer_name: None,
                key: vec![9; 16],
                secret: raw,
                rounds: 0,
                done: 0,
                methods: vec![AUTH_METHOD_CEPHX],
                modes: vec![mode],
            }),
            t(0),
        );
        exchange(&mut c, &mut s, t(1), &mut Rng(123), 4096);
        events(&mut c);
        events(&mut s);
        c.send_message(msg(77, 42, 1 << 16));
        let wire = c.poll_output();
        let mut pos = 2111;
        s.on_bytes(&wire[..pos], t(2));
        let mut left = if mode == MODE_SECURE {
            s.rx_secure_want()
        } else {
            s.rx_direct_want()
        };
        let mut secure = if mode == MODE_SECURE {
            s.rx_secure_take()
        } else {
            None
        };
        let mut crc = if mode == MODE_CRC {
            s.rx_direct_take()
        } else {
            None
        };
        for (progress, timer) in [(t(6), t(8)), (t(10), t(13))] {
            let n = 4093;
            if let Some(loan) = secure.as_mut() {
                loan.recv_buf()[..n].copy_from_slice(&wire[pos..pos + n]);
                loan.commit(n);
            } else {
                let (v, sum) = crc.as_mut().unwrap();
                v.extend_from_slice(&wire[pos..pos + n]);
                sum.update(&wire[pos..pos + n]);
            }
            pos += n;
            left -= n;
            s.rx_progress(progress);
            assert!(
                !s.has_events(),
                "progress must not deliver unauthenticated data"
            );
            s.on_timer(timer);
            assert_eq!(
                s.state(),
                ConnState::Ready,
                "positive receive was mistaken for idle"
            );
        }
        if let Some(mut loan) = secure {
            fill(&mut loan, &wire[pos..]);
            s.rx_secure_put(loan, t(14));
        } else {
            let (mut v, mut sum) = crc.unwrap();
            v.extend_from_slice(&wire[pos..pos + left]);
            sum.update(&wire[pos..pos + left]);
            pos += left;
            s.rx_direct_put(v, sum, t(14));
            s.on_bytes(&wire[pos..], t(14));
        }
        let received = events(&mut s);
        assert_eq!(msgs(&received).len(), 1);
        assert_eq!(msgs(&received)[0].header.tid, 77);
        assert!(msgs(&received)[0].data.iter().all(|&b| b == 7));
        c.send_message(msg(78, 42, 17));
        s.on_bytes(&c.poll_output(), t(15));
        let received = events(&mut s);
        assert_eq!(msgs(&received).len(), 1, "progress advanced secure nonces");
        assert_eq!(msgs(&received)[0].header.tid, 78);
        // No positive bytes now: the configured idle timeout still closes the stream.
        s.on_timer(t(21));
        assert_ne!(s.state(), ConnState::Ready);
        assert!(events(&mut s).iter().any(|e| matches!(e, Event::Fault(_))));
    }
}

#[test]
fn idle_notice_names_the_peer_type_and_address_and_is_no_timeout_warning() {
    let mut a = Node::new(EntityName::OSD, 1, 1, PolicyTable::osd_cluster());
    let b = Node::new(EntityName::OSD, 2, 2, PolicyTable::osd_cluster());
    a.cfg.idle_timeout = std::time::Duration::from_secs(900);
    let c = a.dial_with(
        &b,
        Box::new(KeyedClient {
            key: vec![9; 16],
            secret: vec![1; 16],
            modes: vec![MODE_CRC],
            method: AUTH_METHOD_CEPHX,
        }),
        t(0),
    );
    let w = c.idle_notice();
    // an idle close is Ceph's silent fault, not an operation that timed out
    assert!(!w.contains("WARNING"), "{w}");
    assert!(w.starts_with("msgr2 idle for 900s (conn "), "{w}");
    assert!(w.contains("peer osd"), "{w}");
    assert!(w.contains(&c.target().to_string()), "{w}");
    assert!(w.ends_with(", closing)"), "{w}");
}

/// A session that only sends (stats reports to the mgr, the peer never answers) is not idle: output resets the timer.
#[test]
fn sending_resets_the_idle_timer() {
    let mut a = Node::new(EntityName::OSD, 1, 1, PolicyTable::osd_cluster());
    let mut b = Node::new(EntityName::OSD, 2, 2, PolicyTable::osd_cluster());
    a.cfg.idle_timeout = std::time::Duration::from_millis(10);
    b.cfg.idle_timeout = std::time::Duration::from_millis(10);
    let raw: Vec<u8> = (0..64u8).collect();
    let mut c = a.dial_with(
        &b,
        Box::new(KeyedClient {
            key: vec![9; 16],
            secret: raw.clone(),
            modes: vec![MODE_CRC],
            method: AUTH_METHOD_CEPHX,
        }),
        t(0),
    );
    let mut s = b.accept_with(
        1,
        Box::new(KeyedServer {
            peer_name: None,
            key: vec![9; 16],
            secret: raw,
            rounds: 0,
            done: 0,
            methods: vec![AUTH_METHOD_CEPHX],
            modes: vec![MODE_CRC],
        }),
        t(0),
    );
    exchange(&mut c, &mut s, t(1), &mut Rng(123), 4096);
    events(&mut c);
    events(&mut s);
    // 3x the timeout with one message per 6 ms; the output calls carry no clock and the peer sends nothing back
    // (the connection clock only advances through timers and received bytes)
    for (i, now) in [7u64, 13, 19, 25, 31].into_iter().enumerate() {
        c.send_message(msg(100 + i as u64, 42, 17));
        let _ = c.poll_output();
        if now % 12 == 7 {
            c.on_timer(t(now + 4));
            assert_eq!(
                c.state(),
                ConnState::Ready,
                "sender faulted idle at {now} ms"
            );
        }
    }
    // no output any more: the timeout closes it
    c.on_timer(t(44));
    assert_eq!(
        c.state(),
        ConnState::Ready,
        "idle timer restarts at the check that saw output"
    );
    c.on_timer(t(46));
    assert_ne!(c.state(), ConnState::Ready);
}
