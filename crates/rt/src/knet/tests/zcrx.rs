// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! zcrx receive (adr 0464): a refused plan leaves the copy receive unchanged (every kernel); the device-less mode
//! (`ZCRX_REG_NODEV`, the kernel copies into the area) drives the whole `RECV_ZC` path of knet where the kernel offers
//! it and the test runs with `CAP_NET_ADMIN`; elsewhere those tests report why and pass without running.
use super::*;
use crate::knet::zcrx::{Plan, Reason, ZStats};
use std::sync::mpsc;

type Done = (KStats, Option<ZStats>);

/// Both immediate and held-input FINs preserve the writable half and report
/// EOF once, after every preceding byte. Requires device-less zcrx support.
#[test]
fn nodev_fin_preserves_write_half_and_orders_eof_after_held_input() {
    for paused in [false, true] {
        let plan = Arc::new(Plan::nodev(0, 256 << 10));
        if let Some(reason) = &plan.off {
            eprintln!(
                "zcrx nodev not available: {} (test not run)",
                reason.as_str()
            );
            return;
        }
        let (ports, mut fds) = bind_free(1, &Steer::Hash, 8);
        let mut net = KNet::new(KCfg::default(), fds.remove(0)).unwrap();
        if let Err(reason) = net.set_zcrx(plan, 0) {
            eprintln!(
                "zcrx nodev registration refused: {} (test not run)",
                reason.as_str()
            );
            return;
        }
        let mut driver = Shared::default();
        {
            let mut m = driver.0.lock().unwrap();
            m.half_open = true;
            m.paused = paused;
        }
        let mut peer = client(ports[0]);
        peer.write_all(b"request before FIN").unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        let start = Instant::now();
        loop {
            net.poll(&mut driver, start.elapsed());
            net.submit();
            let finished = net.slots.iter().flatten().any(|c| matches!(c.rx, Rx::Eof))
                || !driver.0.lock().unwrap().closed.is_empty();
            if finished {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "WARNING TIMEOUT zcrx FIN exceeded 5s (paused={paused})"
            );
        }
        assert!(driver.0.lock().unwrap().closed.is_empty());
        let id = driver.0.lock().unwrap().accepted[0].0;
        if paused {
            assert!(driver.0.lock().unwrap().eof.is_empty());
            driver.0.lock().unwrap().paused = false;
        }
        while driver.0.lock().unwrap().eof.is_empty() {
            net.poll(&mut driver, start.elapsed());
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "WARNING TIMEOUT zcrx EOF delivery exceeded 5s (paused={paused})"
            );
        }
        net.poll(&mut driver, start.elapsed());
        assert_eq!(driver.0.lock().unwrap().rx[&id], b"request before FIN");
        assert_eq!(driver.0.lock().unwrap().eof, [(id, 18)]);
        assert!(!net.slots[net.by_id[&id] as usize].as_ref().unwrap().zarmed);
        {
            let mut m = driver.0.lock().unwrap();
            m.out
                .entry(id)
                .or_default()
                .push_back(Bytes::from_static(b"reply"));
            m.notified.insert(id);
        }
        net.flush_one(&mut driver, id);
        net.submit();
        while driver.0.lock().unwrap().written.is_empty() {
            net.poll(&mut driver, start.elapsed());
            net.submit();
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "WARNING TIMEOUT zcrx reply after FIN exceeded 5s (paused={paused})"
            );
        }
        let mut reply = [0; 5];
        peer.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"reply");
    }
}

/// One core with `plan` applied; returns the ports, the `set_zcrx` answer and the core thread.
fn spawn_z(
    cfg: KCfg,
    plan: Arc<Plan>,
    mock: Shared,
    stop: Arc<AtomicBool>,
) -> ([u16; 4], Result<String, Reason>, JoinHandle<Done>) {
    let (ports, mut fds) = bind_free(1, &Steer::Hash, 128);
    let fds = fds.remove(0);
    let (tx, rx) = mpsc::channel();
    let th = std::thread::spawn(move || {
        let mut n = KNet::new(cfg, fds).expect("ring");
        tx.send(n.set_zcrx(plan, 0)).unwrap();
        let mut d = Local::new(mock);
        let t0 = Instant::now();
        while !stop.load(Ordering::Relaxed) {
            let now = t0.elapsed();
            let work = n.poll(&mut d, now);
            n.pump_io(&mut d, now);
            n.flush_out(&mut d);
            n.submit();
            if !work {
                n.wait(Duration::from_micros(200));
            }
        }
        (n.stats, n.zcrx_stats())
    });
    (ports, rx.recv().unwrap(), th)
}

/// A device-less core, or `None` (printed) where this kernel or this process cannot register one.
fn nodev(
    cfg: KCfg,
    rmem: usize,
    mock: &Shared,
) -> Option<([u16; 4], Arc<AtomicBool>, JoinHandle<Done>)> {
    let plan = Plan::nodev(0, rmem);
    if let Some(r) = &plan.off {
        eprintln!("zcrx nodev not available: {} (test not run)", r.as_str());
        return None;
    }
    let stop = Arc::new(AtomicBool::new(false));
    let (ports, set, th) = spawn_z(cfg, Arc::new(plan), mock.clone(), stop.clone());
    match set {
        Ok(_) => Some((ports, stop, th)),
        Err(r) => {
            stop.store(true, Ordering::Relaxed);
            th.join().unwrap();
            eprintln!(
                "zcrx nodev registration refused: {} (test not run)",
                r.as_str()
            );
            None
        }
    }
}

/// Wait up to 20 s for `f`; on timeout stop the core and fail with the mock's and the core's counters.
fn wait_z(
    what: &str,
    mock: &Shared,
    stop: &AtomicBool,
    th: &mut Option<JoinHandle<Done>>,
    f: impl Fn(&Mock) -> bool,
) {
    let end = Instant::now() + Duration::from_secs(20);
    while !f(&mock.0.lock().unwrap()) {
        if Instant::now() > end {
            stop.store(true, Ordering::Relaxed);
            let (st, z) = th.take().unwrap().join().unwrap();
            let m = mock.0.lock().unwrap();
            let d: Vec<_> = m
                .dst
                .values()
                .map(|s| (s.in_payload, s.len, s.got))
                .collect();
            let rx: Vec<_> = m.rx.values().map(Vec::len).collect();
            panic!(
                "timeout: {what}: msgs {} takes {} puts {} decoder {d:?} rx {rx:?} closed {}; {:?}; {st:?}",
                m.msgs.len(),
                m.direct_takes,
                m.direct_puts,
                m.closed.len(),
                z.map(|z| z.line())
            );
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn refused_plan_keeps_the_copy_receive() {
    let off = Plan::probe(Ipv4Addr::LOCALHOST, 1, false);
    assert_eq!(off.off, Some(Reason::Disabled));
    assert!(off.line().starts_with("zcrx=off reason=disabled"));
    let def = Plan::default_off(1).line();
    assert!(
        def.starts_with("zcrx=off reason=default-off")
            && def.contains("disabled by default until validated (adr 0464)")
            && def.contains("--knet-zcrx auto"),
        "{def}"
    );
    // loopback never qualifies: the kernel lacks zcrx, or the address has no NIC queue
    let plan = Plan::probe(Ipv4Addr::LOCALHOST, 1, true);
    let r = plan.off.clone().expect("loopback refused");
    assert!(
        matches!(
            r,
            Reason::NoRingFlags | Reason::NoOp | Reason::VirtualNetdev
        ),
        "{r:?}"
    );
    let line = plan.line();
    assert!(
        line.contains(r.as_str()) && line.contains("fix: "),
        "{line}"
    );
    let mock = Shared::default();
    mock.0.lock().unwrap().echo = true;
    let stop = Arc::new(AtomicBool::new(false));
    let (ports, set, th) = spawn_z(KCfg::default(), Arc::new(plan), mock, stop.clone());
    assert_eq!(set, Err(r));
    for (i, n) in [1usize, 4096, 3 << 20].into_iter().enumerate() {
        echo_roundtrip(ports[0], pattern(n, i as u8));
    }
    stop.store(true, Ordering::Relaxed);
    let (st, z) = th.join().unwrap();
    assert!(z.is_none(), "copy receive only");
    assert!(st.rx_bytes >= (3 << 20) + 4097);
}

#[test]
fn nodev_echo_and_direct_segments() {
    let mock = Shared::default();
    mock.0.lock().unwrap().direct = true;
    let cfg = KCfg {
        direct_min: 64 << 10,
        ..KCfg::default()
    };
    let Some((ports, stop, th)) = nodev(cfg, 4 << 20, &mock) else {
        return;
    };
    let sizes = [1 << 20, 5 << 20, 200_000, 64, 3 << 20, 0, 70_000];
    let w = direct_msgs(&sizes, 11);
    let total = w.len() as u64;
    let mut c = client(ports[0]);
    for ch in w.chunks(300_017) {
        c.write_all(ch).unwrap();
    }
    let mut th = Some(th);
    wait_z("all messages", &mock, &stop, &mut th, |m| {
        m.msgs.len() == sizes.len()
    });
    let s = Srv {
        mock: mock.clone(),
        ports,
        stop: stop.clone(),
        th: None,
    };
    check_msgs(&s, 1, &sizes, &[11]);
    assert!(
        mock.0.lock().unwrap().direct_puts >= 4,
        "big segments went into lent buffers"
    );
    drop(c);
    wait_z("close reported", &mock, &stop, &mut th, |m| {
        m.closed.len() == 1
    });
    stop.store(true, Ordering::Relaxed);
    let (st, z) = th.unwrap().join().unwrap();
    let z = z.expect("zcrx core");
    assert_eq!(z.bytes, total);
    assert_eq!(
        z.copied, total,
        "every byte left the area into the decoder or a segment buffer"
    );
    assert!(z.conns == 1 && z.cqes > 0 && z.refill_entries > 0);
    assert!(st.direct_starts >= 4);
}

#[test]
fn nodev_paused_input_holds_converts_and_resumes_in_order() {
    let mock = Shared::default();
    mock.0.lock().unwrap().paused = true;
    // area = 2 x 256 KiB reserve, lease budget 256 KiB; the rest of a held stream is copied out
    let Some((ports, stop, th)) = nodev(KCfg::default(), 256 << 10, &mock) else {
        return;
    };
    let data = pattern(3 << 20, 5);
    let d2 = data.clone();
    let w = std::thread::spawn(move || {
        let mut c = client(ports[0]);
        c.write_all(&d2).unwrap();
        c
    });
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        mock.0.lock().unwrap().rx.is_empty(),
        "no application bytes while throttled"
    );
    mock.0.lock().unwrap().paused = false;
    let mut th = Some(th);
    wait_z("all bytes", &mock, &stop, &mut th, |m| {
        m.rx.values().map(Vec::len).sum::<usize>() == data.len()
    });
    assert_eq!(mock.0.lock().unwrap().rx.values().next().unwrap(), &data);
    let c = w.join().unwrap();
    drop(c);
    stop.store(true, Ordering::Relaxed);
    let (_, z) = th.unwrap().join().unwrap();
    let z = z.expect("zcrx core");
    assert!(z.leased > 0, "held fragments stayed in the area");
    assert!(
        z.converted > 0,
        "beyond the lease budget fragments were copied out"
    );
    assert!(z.held_max <= 256 << 10, "lease budget kept: {}", z.held_max);
}

#[test]
fn nodev_many_connections_and_peer_close() {
    let mock = Shared::default();
    let Some((ports, stop, th)) = nodev(KCfg::default(), 512 << 10, &mock) else {
        return;
    };
    let total = 200_000usize;
    let th_c: Vec<_> = (0..16u8)
        .map(|i| {
            std::thread::spawn(move || {
                let mut c = client(ports[0]);
                c.write_all(&pattern(total, i)).unwrap();
                c
            })
        })
        .collect();
    let keep: Vec<TcpStream> = th_c.into_iter().map(|t| t.join().unwrap()).collect();
    let mut th = Some(th);
    wait_z("all bytes", &mock, &stop, &mut th, |m| {
        m.rx.len() == 16 && m.rx.values().all(|v| v.len() == total)
    });
    {
        let m = mock.0.lock().unwrap();
        let sent: Vec<Vec<u8>> = (0..16u8).map(|i| pattern(total, i)).collect();
        for v in m.rx.values() {
            assert!(sent.contains(v), "corrupted stream");
        }
    }
    drop(keep);
    wait_z("closes reported", &mock, &stop, &mut th, |m| {
        m.closed.len() == 16
    });
    stop.store(true, Ordering::Relaxed);
    let (_, z) = th.unwrap().join().unwrap();
    let z = z.expect("zcrx core");
    assert_eq!(z.conns, 16);
    assert_eq!(z.bytes, 16 * total as u64);
}
