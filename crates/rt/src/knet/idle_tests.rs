// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Local QD1 scheduling benchmark: kernel TCP plus simulated, polled block IO; no physical NVMe.
use super::*;
use crate::knet::{Binds, Driver, KCfg, Steer, bind_all};
use crate::stream::IoCmd;
use bytes::Bytes;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::AtomicBool;
use store::dev::{BlockDev, Completion, SimConfig, SimDev, SimDisk};

struct DeviceDriver {
    dev: SimDev,
    rx: Vec<u8>,
    output: Option<Bytes>,
    notified: bool,
    pending: bool,
    done: Vec<Completion<Vec<u8>>>,
}

impl DeviceDriver {
    fn new() -> Self {
        let mut cfg = SimConfig::new(4096);
        cfg.read_ns = 50_000;
        cfg.write_ns = 50_000;
        cfg.xfer_ns_per_lba = 0;
        cfg.jitter_ns = 0;
        Self {
            dev: SimDisk::new(cfg).queue(),
            rx: Vec::with_capacity(4096),
            output: None,
            notified: false,
            pending: false,
            done: Vec::with_capacity(1),
        }
    }

    fn poll(&mut self, now: Duration) -> bool {
        self.dev.poll(now.as_nanos() as u64, &mut self.done);
        let Some(c) = self.done.pop() else {
            return false;
        };
        c.result.unwrap();
        self.output = Some(Bytes::from(c.buf.unwrap()));
        self.pending = false;
        true
    }
}

impl Driver for DeviceDriver {
    fn on_accept(&mut self, _: usize, _: SocketAddr, _: Duration) -> Option<u64> {
        Some(1)
    }
    fn on_connected(&mut self, _: u64, _: Duration) {}
    fn on_dial_failed(&mut self, _: u64, _: bool, _: Duration) {}
    fn on_closed(&mut self, _: u64, _: Duration) {}
    fn on_bytes(&mut self, _: u64, data: &[u8], _: Duration) {
        self.rx.extend_from_slice(data);
        if self.rx.len() == 4096 {
            assert!(!self.pending);
            let mut b = self.dev.alloc_buf(4096);
            b.copy_from_slice(&self.rx);
            if b[0] == 0 {
                self.dev.submit_read(0, b, 1).unwrap();
            } else {
                self.dev.submit_write(0, b, 1).unwrap();
            }
            self.rx.clear();
            self.pending = true;
        }
        assert!(self.rx.len() < 4096);
    }
    fn poll_io(&mut self) -> Option<IoCmd> {
        None
    }
    fn poll_output_chunks(&mut self, _: u64) -> Vec<Bytes> {
        self.notified = false;
        self.output.take().into_iter().collect()
    }
    fn poll_output_ready(&mut self) -> Option<u64> {
        if self.output.is_some() && !self.notified {
            self.notified = true;
            Some(1)
        } else {
            None
        }
    }
}

fn cpu_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid timespec output pointer, calling thread's CPU clock.
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) },
        0
    );
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

const WAKE: Wake = Wake {
    typ: Duration::from_micros(40),
    late: Duration::from_micros(40),
};

#[test]
fn idle_period_polls_for_one_wake_latency_then_sleeps() {
    let idle = Idle::Sleep;
    let us = Duration::from_micros;
    let mut state = IdleState {
        park_pct: 10,
        ..IdleState::default()
    };
    assert_eq!(
        state.cap(idle, us(1000), true, StoreWait::Busy(None), true, WAKE),
        None
    );
    // the idle period starts at the first idle iteration after the work: poll until it is as old as a wake costs
    for t in [1000, 1010, 1039] {
        assert_eq!(
            state.cap(idle, us(t), false, StoreWait::Busy(None), true, WAKE),
            None,
            "poll while a sleep would cost more than the wait"
        );
    }
    // store IO in flight (polled completions): sleep a fraction of the period's age, at least one wake latency
    assert_eq!(
        state.cap(idle, us(1040), false, StoreWait::Busy(None), true, WAKE),
        Some(WAKE.typ)
    );
    assert_eq!(
        state.cap(idle, us(1500), false, StoreWait::Busy(None), true, WAKE),
        Some(us(50)),
        "10 % of the 500 us the period is old: the completion is late by at most that"
    );
    assert_eq!(
        state.cap(idle, us(100_000), false, StoreWait::Busy(None), true, WAKE),
        Some(DEEP_IDLE),
        "a stalled store is looked at every deep-idle cap"
    );
    // nothing in flight and wakeable: sleep up to the deep-idle cap; the period is older than a wake, no new polling
    assert_eq!(
        state.cap(idle, us(100_001), false, StoreWait::Quiet, true, WAKE),
        Some(DEEP_IDLE)
    );
    // quiet and wakeable: no polling at all (see above); quiet, but a message source without wake handle: sleep one wake latency at a time
    assert_eq!(
        state.cap(idle, us(100_002), false, StoreWait::Quiet, false, WAKE),
        Some(WAKE.typ)
    );
    // work restarts the period
    assert_eq!(
        state.cap(idle, us(100_003), true, StoreWait::Busy(None), true, WAKE),
        None
    );
    assert_eq!(
        state.cap(idle, us(100_010), false, StoreWait::Busy(None), true, WAKE),
        None,
        "new period: poll again for one wake latency"
    );
    assert_eq!(
        state.cap(Idle::Spin, us(200_000), false, StoreWait::Quiet, true, WAKE),
        None
    );
}

#[test]
#[ignore = "local kernel TCP + simulated media benchmark"]
fn perf_qd1_idle_read_write() {
    for idle in [Idle::Sleep, Idle::Spin] {
        let guards: Vec<_> = (0..4)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let ports: [u16; 4] = std::array::from_fn(|i| guards[i].local_addr().unwrap().port());
        drop(guards);
        let fds = bind_all(
            &Binds(ports.map(|p| vec![std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, p))])),
            1,
            &Steer::Hash,
            16,
        )
        .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let cpus = crate::affinity_cpus();
            crate::pin_current_thread(cpus[0]).unwrap();
            let cfg = KCfg {
                bufs: 16,
                buf_size: 4096,
                ..Default::default()
            };
            let mut n = KNet::new(cfg, fds.into_iter().next().unwrap()).unwrap();
            n.set_wake(crate::wake::Wake::new().unwrap());
            let mut d = DeviceDriver::new();
            let quiet_origin = Instant::now();
            let quiet_cpu = cpu_ns();
            let mut quiet_policy = IdleState::default();
            while quiet_origin.elapsed() < Duration::from_millis(100) {
                let now = quiet_origin.elapsed();
                let work = n.poll(&mut d, now);
                n.submit();
                if let Some(cap) = quiet_policy.cap(idle, now, work, StoreWait::Quiet, true, WAKE) {
                    n.wait(cap);
                } else {
                    std::hint::spin_loop();
                }
            }
            let quiet_cpu_pct =
                (cpu_ns() - quiet_cpu) as f64 * 100.0 / quiet_origin.elapsed().as_nanos() as f64;
            let origin = Instant::now();
            let cpu = cpu_ns();
            let mut policy = IdleState::default();
            tx.send(()).unwrap();
            while !stopped.load(Ordering::Relaxed) && origin.elapsed() < Duration::from_secs(10) {
                let now = origin.elapsed();
                let media_work = d.poll(now);
                let work = n.poll(&mut d, now) || media_work;
                if work {
                    n.flush_out(&mut d);
                }
                n.submit();
                if let Some(cap) = policy.cap(
                    idle,
                    now,
                    work,
                    if !d.pending {
                        StoreWait::Quiet
                    } else {
                        StoreWait::Busy(None)
                    },
                    true,
                    WAKE,
                ) {
                    n.wait(cap);
                } else {
                    std::hint::spin_loop();
                }
            }
            let cpu = cpu_ns() - cpu;
            let wall = origin.elapsed().as_nanos() as u64;
            (cpu, wall, quiet_cpu_pct)
        });
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut socket = TcpStream::connect((Ipv4Addr::LOCALHOST, ports[0])).unwrap();
        socket.set_nodelay(true).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        for op in [0u8, 1] {
            let buf = [op; 4096];
            let mut response = [0u8; 4096];
            let mut samples = Vec::with_capacity(3000);
            for _ in 0..3000 {
                let start = Instant::now();
                socket.write_all(&buf).unwrap();
                socket.read_exact(&mut response).unwrap();
                assert_eq!(response, buf);
                samples.push(start.elapsed().as_nanos() as u64);
            }
            samples.sort_unstable();
            println!(
                "idle={idle:?} op={op} qd=1 bytes=4096 simulated_media_us=50 p50_ns={} p99_ns={}",
                samples[1500], samples[2970]
            );
        }
        stop.store(true, Ordering::Relaxed);
        let (cpu, wall, quiet_cpu_pct) = server.join().unwrap();
        println!(
            "idle={idle:?} workload_cpu_pct={:.2}",
            cpu as f64 * 100.0 / wall as f64
        );
        println!("idle={idle:?} quiet_cpu_pct={quiet_cpu_pct:.2}");
    }
}

#[test]
fn store_span_parks_until_a_fraction_of_the_learned_latency_then_polls() {
    let idle = Idle::Sleep;
    let us = Duration::from_micros;
    let mut s = IdleState {
        park_pct: 50,
        ..IdleState::default()
    };
    // first span: nothing learned, no park; completion at +80 us teaches the latency
    s.io_note(false, us(5), true);
    assert_eq!(s.park_until, Duration::ZERO);
    assert_eq!(
        s.cap(idle, us(10), false, StoreWait::Busy(None), true, WAKE),
        None,
        "poll within one wake latency"
    );
    s.io_note(true, us(85), true);
    assert_eq!(s.io_est_ns, 80_000);
    // next span: park half (40 us) after the submit seen at loop time 1005
    s.io_note(false, us(1005), true);
    assert_eq!(s.park_until, us(1045));
    assert_eq!(
        s.cap(idle, us(1010), false, StoreWait::Busy(None), true, WAKE),
        Some(us(35))
    );
    assert_eq!(
        s.cap(idle, us(1050), false, StoreWait::Busy(None), true, WAKE),
        Some(us(525)),
        "past the park: the period is old, sleep a share of its age"
    );
    // a quiet store ends the span; a shorter latency pulls the estimate down fast, a longer one up slowly
    s.io_note(true, us(1020), true);
    assert_eq!(s.io_est_ns, 63_750);
}

#[test]
fn park_off_never_tracks_or_parks() {
    let idle = Idle::Sleep;
    let mut s = IdleState::default();
    s.io_note(false, Duration::ZERO, true);
    assert!(s.io_since.is_none());
    assert_eq!(
        s.cap(
            idle,
            Duration::from_micros(5),
            false,
            StoreWait::Busy(None),
            true,
            WAKE
        ),
        None
    );
}

#[test]
fn waking_store_sleeps_at_once_while_io_is_in_flight() {
    // adr 0169: completions of a `kernel:` device wake the ring; an idle core with IO in flight sleeps on the first idle
    // pass (no STORE_SPIN polling, no timer park), capped; a quiet store keeps the normal idle policy; spin stays spin
    let idle = Idle::Sleep;
    let us = Duration::from_micros;
    let mut s = IdleState {
        irq_full: true,
        ..IdleState::default()
    };
    assert_eq!(
        s.cap(idle, us(10), false, StoreWait::Busy(None), false, WAKE),
        Some(IRQ_PARK)
    );
    assert_eq!(s.parks, 1);
    assert_eq!(
        s.cap(idle, us(100), false, StoreWait::Quiet, false, WAKE),
        Some(WAKE.typ),
        "quiet: normal policy"
    );
    assert_eq!(
        s.cap(
            Idle::Spin,
            us(12),
            false,
            StoreWait::Busy(None),
            false,
            WAKE
        ),
        None
    );
    assert_eq!(
        s.cap(idle, us(13), true, StoreWait::Busy(None), false, WAKE),
        None,
        "work: no sleep"
    );
}

#[test]
fn device_hint_parks_until_one_late_wake_before_the_expected_completion() {
    // adr 0004 am. 1: a polled device that knows when its earliest in-flight command may complete lets the idle core
    // sleep until one late wake latency (~p80 overshoot) before it, so it is awake before the completion; inside two late
    // wake latencies it polls; inside the window the age rule runs from the window start; without a hint the old rules apply
    const W: Wake = Wake {
        typ: Duration::from_micros(40),
        late: Duration::from_micros(60),
    };
    let idle = Idle::Sleep;
    let us = Duration::from_micros;
    let busy = |h| StoreWait::Busy(Some(h));
    let mut s = IdleState {
        park_pct: 10,
        ..IdleState::default()
    };
    assert_eq!(
        s.cap(idle, us(0), true, StoreWait::Busy(None), true, W),
        None
    );
    assert_eq!(
        s.cap(idle, us(1), false, busy(us(200)), true, W),
        Some(us(140)),
        "park ends one late wake before the expected completion"
    );
    assert_eq!(s.parks, 1);
    assert_eq!(
        s.cap(idle, us(55), false, busy(us(119)), true, W),
        None,
        "due within two late wake latencies: poll"
    );
    // the window starts at 55 + 119 = 174 us: inside it the age rule (typical wake) runs from there
    assert_eq!(
        s.cap(idle, us(190), false, busy(Duration::ZERO), true, W),
        None,
        "window entered less than a wake latency ago: poll"
    );
    assert_eq!(
        s.cap(idle, us(800), false, busy(Duration::ZERO), true, W),
        Some(us(626) * 10 / 100),
        "long window: park a share of the age since the window start"
    );
    assert_eq!(
        s.cap(idle, us(1000), false, StoreWait::Busy(None), true, W),
        Some(us(999) * 10 / 100),
        "past every learned bound: age rule"
    );
    assert_eq!(
        s.cap(idle, us(1001), false, StoreWait::Quiet, true, W),
        Some(DEEP_IDLE),
        "quiet store: the hint is not asked"
    );
}
