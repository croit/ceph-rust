// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Send-slot progress on a real verbs device (soft-RoCE in lab/rdma-spike/rxe-teardown-test.sh): `rdma::tx` invariants I1
//! (every slot back within a round trip once a sender is quiet) and I2 (a connection refused for slots is woken through
//! the core's wait queue). Two connections on one sender core whose send pool (8 slots) is smaller than one window (16):
//! A posts a 6-slot burst and goes quiet, B streams 256 MiB and offers bytes only after `Event::Writable`, as the knet and
//! rados-rt drivers do. Once the grants have grown B's window past the pool, B runs into slot refusals (asserted).
#![cfg(all(feature = "verbs", target_os = "linux"))]

use rdma::grant::SessionCap;
use rdma::verbs::{Core, CoreCfg, Device, Event, Qp};
use std::net::IpAddr;
use std::time::{Duration, Instant};

const SLOT: usize = 64 * 1024;
const BURST: usize = 6 * SLOT;
const TOTAL: usize = 256 << 20;
/// Stream bytes are `i % 251`; offers are windows into one periodic buffer.
const PERIOD: usize = 251;
const OFFER: usize = 4 << 20;
const DEADLINE: Duration = Duration::from_secs(120);

fn cfg() -> CoreCfg {
    CoreCfg {
        srq_depth: 64,
        tx_slots: 8,
        max_window: 16,
        ..CoreCfg::default()
    }
}

/// Connect `s` (on `sc`) and `r` (on `rc`) to each other and attach both.
fn link(sc: &mut Core, rc: &mut Core, s: Qp, r: Qp) -> (u32, u32) {
    let (hs, hr) = (sc.handles(), rc.handles());
    let (es, er) = (s.endpoint(&hs), r.endpoint(&hr));
    s.connect(&hs, &er).expect("connect sender QP");
    r.connect(&hr, &es).expect("connect receiver QP");
    let (qs, qr) = (s.qpn(), r.qpn());
    let cap = SessionCap::new(0);
    sc.attach(s, &er, cap.acquire().unwrap())
        .expect("attach sender QP");
    rc.attach(r, &es, cap.acquire().unwrap())
        .expect("attach receiver QP");
    (qs, qr)
}

#[test]
#[ignore = "needs a RoCEv2 device: FLASHSTORE_TEST_RDMA_ADDR"]
fn quiet_burst_does_not_stall_a_large_transfer_on_the_same_core() {
    let ip: IpAddr = std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
        .expect("FLASHSTORE_TEST_RDMA_ADDR (local IP of a RoCEv2 device)")
        .parse()
        .expect("FLASHSTORE_TEST_RDMA_ADDR is an IP address");
    let dev = Device::open(rdma::gid_of(ip)).expect("device");
    let mut sc = Core::new(&dev, cfg()).expect("sender core");
    let mut rc = Core::new(&dev, cfg()).expect("receiver core");
    let qp = |c: &Core, psn| Qp::create(&dev, c.handles(), psn).expect("create QP");
    let (sa, ra) = (qp(&sc, 1), qp(&rc, 2));
    let (sb, rb) = (qp(&sc, 3), qp(&rc, 4));
    let (qa, qra) = link(&mut sc, &mut rc, sa, ra);
    let (qb, qrb) = link(&mut sc, &mut rc, sb, rb);

    let buf: Vec<u8> = (0..OFFER + PERIOD).map(|i| (i % PERIOD) as u8).collect();
    let at = |off: usize, len: usize| &buf[off % PERIOD..][..len.min(OFFER)];
    let (mut sent_a, mut sent_b) = (0usize, 0usize);
    let (mut got_a, mut got_b) = (0usize, 0usize);
    let (mut wr_a, mut wr_b) = (true, true);
    let mut bad = None;
    let t = Instant::now();
    let mut quiet = None;
    loop {
        let now = t.elapsed();
        assert!(
            now < DEADLINE,
            "WARNING TIMEOUT rxe_tx_pool exceeded {:.3}s (A {sent_a}/{BURST} sent {got_a} got, B {sent_b}/{TOTAL} sent \
             {got_b} got, free tx slots {}, queue stalls {})",
            DEADLINE.as_secs_f64(),
            sc.free_tx_slots(),
            sc.stats.queue_stalls
        );
        if std::mem::take(&mut wr_a) && sent_a < BURST {
            sent_a += sc.send(qa, at(sent_a, BURST - sent_a));
        }
        // offer until refused: the core takes nothing more before it reports Writable
        while std::mem::take(&mut wr_b) && sent_b < TOTAL {
            let n = sc.send(qb, at(sent_b, TOTAL - sent_b));
            sent_b += n;
            wr_b = n == OFFER;
        }
        sc.tick(now.as_nanos() as u64);
        rc.tick(now.as_nanos() as u64);
        sc.poll(|q, e| match e {
            Event::Writable if q == qa => wr_a = true,
            Event::Writable if q == qb => wr_b = true,
            Event::Writable | Event::Data(_) => {}
            Event::RemoteInvalidated(_) => panic!("unexpected remote invalidation"),
            Event::Fault(m) => panic!("sender qp {q}: {m}"),
        });
        rc.poll(|q, e| match e {
            Event::Data(d) if q == qra => got_a += d.len(),
            Event::Data(d) if q == qrb => {
                if bad.is_none() && d != at(got_b, d.len()) {
                    bad = Some(got_b);
                }
                got_b += d.len();
            }
            Event::Fault(m) => panic!("receiver qp {q}: {m}"),
            _ => {}
        });
        if got_a == BURST && got_b == TOTAL {
            // both quiet: every send slot must come back within a round trip (I1); the deadline bounds the wait
            let since = *quiet.get_or_insert(now);
            if sc.free_tx_slots() == cfg().tx_slots as usize {
                eprintln!(
                    "rxe_tx_pool: 256 MiB in {now:?}, all send slots back {:?} after the last byte arrived, sends {}, \
                     queue stalls {}, credit stalls {}",
                    now - since,
                    sc.stats.tx_sends,
                    sc.stats.queue_stalls,
                    sc.stats.credit_stalls
                );
                assert!(now - since < Duration::from_secs(1), "slots came back late");
                break;
            }
        }
    }
    assert_eq!(bad, None, "B's stream intact");
    assert!(
        sc.stats.queue_stalls > 0,
        "the window never outgrew the send pool: slot refusals not exercised"
    );
    // QPs go before their cores
    for q in [qa, qb] {
        drop(sc.detach(q).expect("attached").qp);
    }
    for q in [qra, qrb] {
        drop(rc.detach(q).expect("attached").qp);
    }
}
