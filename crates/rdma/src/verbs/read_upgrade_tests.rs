// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Real control-thread pool and Upgrader exchange, then an actual READ or
//! default/mixed-peer refusal. No manually supplied peer device caps.
use super::*;
use crate::control::{Control, ControlCfg, CoreLink, start_verbs, start_verbs_for_reads};
use crate::upgrade::{Done, Upgrader};
use std::{io::Write, time::Instant};

type Upgrade = Upgrader<Qp, CoreLink<Qp>>;

fn before(start: Instant, operation: &str) {
    if start.elapsed() < std::time::Duration::from_secs(10) {
        return;
    }
    let message = format!("WARNING TIMEOUT {operation} exceeded 10s (owned RXE READ upgrade)");
    diag::diag!("{message}");
    if let Ok(path) = std::env::var("WARNINGS_FILE") {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        writeln!(f, "{message}").unwrap();
    }
    panic!("{message}");
}
fn done(upgrade: &mut Upgrade) -> Done<Qp> {
    let start = Instant::now();
    loop {
        before(start, "control upgrade");
        if let Some(done) = upgrade.poll() {
            return done;
        }
        std::thread::yield_now();
    }
}
fn control(dev: &Arc<Device>, core: &Core, reads: bool) -> (Control, Upgrade) {
    let handles = vec![core.handles()];
    let cfg = ControlCfg {
        pool_depth: 1,
        queue_depth: 8,
    };
    // The public entry points the transport uses, not the backend directly.
    let (control, mut links) = if reads {
        start_verbs_for_reads(dev.clone(), handles, cfg, |_| {}).unwrap()
    } else {
        start_verbs(dev.clone(), handles, cfg, |_| {}).unwrap()
    };
    let upgrade = Upgrader::new(links.remove(0), 2, crate::grant::SessionCap::new(0));
    (control, upgrade)
}
fn poll(core: &mut Core) {
    core.poll(|_, event| assert!(!matches!(event, Event::Fault(_)), "{event:?}"));
}

#[test]
#[ignore = "needs owned software RDMA device: FLASHSTORE_TEST_RDMA_ADDR"]
fn rxe_read_upgrade_real_control_and_peer_wire_caps_enable_only_mutual_reads() {
    let ip: std::net::IpAddr = std::env::var("FLASHSTORE_TEST_RDMA_ADDR")
        .unwrap()
        .parse()
        .unwrap();
    let dev = Device::open(crate::gid_of(ip)).unwrap();
    for (reader_on, source_on) in [(true, true), (true, false), (false, true), (false, false)] {
        let config = CoreCfg {
            srq_depth: 64,
            tx_slots: 8,
            sq_depth: 8,
            max_window: 16,
            ..CoreCfg::default()
        };
        let (mut reader, mut source) = (
            Core::new(&dev, config).unwrap(),
            Core::new(
                &dev,
                CoreCfg {
                    sq_depth: 4,
                    ..config
                },
            )
            .unwrap(),
        );
        let (reader_control, mut reader_up) = control(&dev, &reader, reader_on);
        let (source_control, mut source_up) = control(&dev, &source, source_on);
        reader_up.prepare(1, 0).unwrap();
        let Done::Prepared {
            endpoint: Some(offer),
            ..
        } = done(&mut reader_up)
        else {
            panic!("READ prepare refused");
        };
        assert_eq!(offer.reads.is_some(), reader_on);
        source_up.accept(2, &offer.encode(), ip, 0).unwrap();
        let Done::Accepted {
            accepted: Some(accepted),
            ..
        } = done(&mut source_up)
        else {
            panic!("READ accept refused");
        };
        assert_eq!(accepted.peer, offer);
        assert_eq!(accepted.ours.reads.is_some(), source_on);
        reader_up.connect(1, &accepted.ours.encode(), ip).unwrap();
        let Done::Connected {
            qp, peer, permit, ..
        } = done(&mut reader_up)
        else {
            panic!("READ connect refused");
        };
        assert_eq!(peer, accepted.ours);
        let (qr, qs) = (qp.qpn(), accepted.qp.qpn());
        let (rd, sd) = (qp.read_depths(), accepted.qp.read_depths());
        assert_eq!(rd.outgoing(), sd.incoming());
        assert_eq!(rd.incoming(), sd.outgoing());
        if reader_on && source_on {
            let (a, b) = (offer.reads.unwrap(), accepted.ours.reads.unwrap());
            assert_eq!(a.initiator, a.initiator.min(8));
            assert_eq!(b.initiator, b.initiator.min(4));
            assert_eq!(rd.outgoing(), a.initiator.min(b.responder));
            assert_eq!(rd.incoming(), a.responder.min(b.initiator));
            assert!(rd.outgoing() > 0 && rd.incoming() > 0);
        } else {
            assert_eq!(rd, ReadDepths::default());
            assert_eq!(sd, ReadDepths::default());
        }
        reader.attach(qp, &peer, permit).unwrap();
        source
            .attach(accepted.qp, &accepted.peer, accepted.permit)
            .unwrap();
        let prepared = PreparedReadSource::register(&dev, Bytes::from(vec![0x5a; 4096])).unwrap();
        let range = prepared.range();
        if reader_on && source_on {
            let local = source.bind_shared_read_source(qs, prepared, range).unwrap();
            let start = Instant::now();
            while local.state() == WindowState::Binding {
                before(start, "upgrade source BIND");
                poll(&mut source);
            }
            let mut published = local
                .advertise(
                    &source,
                    WindowAttempt {
                        connection: 1,
                        tid: 1,
                        retry: 0,
                    },
                )
                .unwrap();
            let descriptor = published.descriptor();
            let target = PreparedReadBuffer::prepare(&dev, 4096).unwrap();
            // SAFETY: exact live grant on this fixture's authenticated upgrade
            // pair; all accepted READs retire before peer admission closes.
            let grant = unsafe { descriptor.remote_source().unwrap() };
            let pending = reader.read_buffer(qr, target, grant).unwrap();
            let start = Instant::now();
            while pending.state() == ReadState::Pending {
                before(start, "upgraded READ");
                poll(&mut reader);
            }
            let shared = pending.try_finish().unwrap();
            assert!(shared.bytes().iter().all(|b| *b == 0x5a));
            // SAFETY: every accepted READ completed; no further admission.
            assert!(unsafe {
                published.confirm_peer_retired_unchecked(descriptor.attempt, descriptor.rkey)
            });
            published.invalidate(&mut source).unwrap();
            let start = Instant::now();
            while published.state() == WindowState::Invalidating {
                before(start, "upgraded source LOCAL_INV");
                poll(&mut source);
            }
            published.try_recover().unwrap().into_bytes().unwrap();
        } else {
            let rejected = source
                .bind_shared_read_source(qs, prepared, range)
                .unwrap_err();
            assert_eq!(rejected.error.kind(), io::ErrorKind::Unsupported);
            rejected.source.into_bytes().unwrap();
        }
        // Pooled INIT QPs must leave their SRQ/CQ before those core owners drop.
        drop((reader_up, source_up, reader_control, source_control));
        drop((reader, source));
    }
}
