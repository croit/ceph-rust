// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Microbench of the kernel tier transport (adr 0053): an echo server on [`rt::knet`] and a client that measures it (the
//! client also works against any other echo server).
//!   knet_bench server IP PORT CORES SECS [--idle spin|sleep] [--zc-min BYTES] [--bufs N] [--buf-kb N]
//!   knet_bench client IP:PORT pingpong|stream SIZE CONNS SECS
//! Server prints per-core stats and process CPU seconds at the end (wall = SECS); client prints ops/s, latency
//! percentiles (pingpong) or Gbit/s (stream: echoed payload one way; wire = twice that) and its own CPU seconds.
#[cfg(not(all(feature = "knet", target_os = "linux")))]
fn main() {
    eprintln!("needs --features knet on Linux");
}

#[cfg(all(feature = "knet", target_os = "linux"))]
fn main() {
    imp::main()
}

#[cfg(all(feature = "knet", target_os = "linux"))]
mod imp {
    use bytes::Bytes;
    use rt::Idle;
    use rt::knet::{Binds, Driver, KCfg, KNet, Steer, bind_all};
    use rt::stream::IoCmd;
    use std::collections::{HashMap, VecDeque};
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    fn cpu_secs() -> f64 {
        // SAFETY: getrusage fills a zeroed struct.
        unsafe {
            let mut r: libc::rusage = std::mem::zeroed();
            libc::getrusage(libc::RUSAGE_SELF, &mut r);
            let t = |x: libc::timeval| x.tv_sec as f64 + x.tv_usec as f64 / 1e6;
            t(r.ru_utime) + t(r.ru_stime)
        }
    }

    #[derive(Default)]
    struct Echo {
        next: u64,
        out: HashMap<u64, VecDeque<Bytes>>,
        notified: std::collections::BTreeSet<u64>,
    }

    impl Driver for Echo {
        fn on_accept(&mut self, _l: usize, _peer: SocketAddr, _n: Duration) -> Option<u64> {
            self.next += 1;
            self.out.insert(self.next, VecDeque::new());
            Some(self.next)
        }
        fn on_connected(&mut self, _c: u64, _n: Duration) {}
        fn on_dial_failed(&mut self, c: u64, _r: bool, _n: Duration) {
            self.out.remove(&c);
        }
        fn on_closed(&mut self, c: u64, _n: Duration) {
            self.out.remove(&c);
        }
        fn on_bytes(&mut self, c: u64, d: &[u8], _n: Duration) {
            // what the OSD does too: one copy out of the rx buffer, output as shared runs
            if let Some(q) = self.out.get_mut(&c) {
                q.push_back(Bytes::copy_from_slice(d));
            }
        }
        fn poll_io(&mut self) -> Option<IoCmd> {
            None
        }
        fn poll_output_chunks(&mut self, c: u64) -> Vec<Bytes> {
            self.notified.remove(&c);
            self.out
                .get_mut(&c)
                .map_or_else(Vec::new, |q| q.drain(..).collect())
        }
        fn poll_output_ready(&mut self) -> Option<u64> {
            let id = self
                .out
                .iter()
                .find(|(id, q)| !q.is_empty() && !self.notified.contains(id))
                .map(|(id, _)| *id)?;
            self.notified.insert(id);
            Some(id)
        }
    }

    fn flag<'a>(a: &'a [String], k: &str) -> Option<&'a str> {
        a.iter()
            .position(|x| x == k)
            .and_then(|i| a.get(i + 1))
            .map(String::as_str)
    }

    fn server(a: &[String]) {
        let ip: Ipv4Addr = a[0].parse().expect("ip");
        let port: u16 = a[1].parse().expect("port");
        let cores: usize = a[2].parse().expect("cores");
        let secs: u64 = a[3].parse().expect("secs");
        let mut cfg = KCfg::default();
        if let Some(v) = flag(a, "--zc-min") {
            cfg.zc_min = v.parse().unwrap();
        }
        if let Some(v) = flag(a, "--bufs") {
            cfg.bufs = v.parse().unwrap();
        }
        if let Some(v) = flag(a, "--buf-kb") {
            cfg.buf_size = v.parse::<u32>().unwrap() * 1024;
        }
        let spin = flag(a, "--idle") == Some("spin");
        let ports = [port, port + 1, port + 2, port + 3];
        let binds = Binds(ports.map(|p| vec![SocketAddr::new(IpAddr::V4(ip), p)]));
        let steer = if flag(a, "--steer") == Some("cpu") {
            Steer::Cpu(rt::affinity_cpus().into_iter().take(cores).collect())
        } else {
            Steer::Hash
        };
        let fds = bind_all(&binds, cores, &steer, 1024).expect("bind");
        let stop = Arc::new(AtomicBool::new(false));
        let cpus = rt::affinity_cpus();
        let c0 = cpu_secs();
        let t0 = Instant::now();
        let th: Vec<_> = fds
            .into_iter()
            .enumerate()
            .map(|(i, f)| {
                let (cfg, stop, cpu) = (cfg.clone(), stop.clone(), cpus[i % cpus.len()]);
                std::thread::spawn(move || {
                    let _ = rt::pin_current_thread(cpu);
                    let mut n = KNet::new(cfg, f).expect("ring");
                    let mut d = Echo::default();
                    let t0 = Instant::now();
                    let mut idle_run = 0u32;
                    let mut idle_iters = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        let now = t0.elapsed();
                        let work = n.poll(&mut d, now);
                        if work {
                            n.flush_out(&mut d);
                        }
                        n.submit();
                        if work {
                            idle_run = 0;
                        } else {
                            idle_iters += 1;
                            idle_run = idle_run.saturating_add(1);
                            if !spin && idle_run > 2000 {
                                n.wait(Duration::from_micros(50));
                            }
                        }
                    }
                    (i, n.describe(), idle_iters)
                })
            })
            .collect();
        std::thread::sleep(Duration::from_secs(secs));
        stop.store(true, Ordering::Relaxed);
        for t in th {
            let (i, d, idle) = t.join().unwrap();
            println!("core {i}: idle_iters={idle} {d}");
        }
        let wall = t0.elapsed().as_secs_f64();
        let cpu = cpu_secs() - c0;
        println!(
            "server: wall {wall:.1}s cpu {cpu:.2}s = {:.2} cores busy",
            cpu / wall
        );
    }

    fn client(a: &[String]) {
        let (ip, port) = a[0].rsplit_once(':').expect("ip:port");
        let addr = SocketAddrV4::new(ip.parse().expect("ip"), port.parse().expect("port"));
        let mode = a[1].as_str();
        let size: usize = a[2].parse().expect("size");
        let conns: usize = a[3].parse().expect("conns");
        let secs: u64 = a[4].parse().expect("secs");
        let stop = Arc::new(AtomicBool::new(false));
        let bytes = Arc::new(AtomicU64::new(0));
        let c0 = cpu_secs();
        let t0 = Instant::now();
        let th: Vec<_> = (0..conns)
            .map(|i| {
                let (stop, bytes) = (stop.clone(), bytes.clone());
                let mode = mode.to_owned();
                std::thread::spawn(move || {
                    let s = TcpStream::connect(addr).expect("connect");
                    s.set_nodelay(true).unwrap();
                    let mut lat: Vec<u32> = Vec::new();
                    let buf = vec![(i as u8) ^ 0x5a; size];
                    if mode == "pingpong" {
                        let (mut r, mut w) = (&s, &s);
                        let mut rb = vec![0u8; size];
                        while !stop.load(Ordering::Relaxed) {
                            let t = Instant::now();
                            if w.write_all(&buf).is_err() || r.read_exact(&mut rb).is_err() {
                                break;
                            }
                            lat.push(t.elapsed().as_nanos() as u32);
                            bytes.fetch_add(size as u64, Ordering::Relaxed);
                        }
                    } else {
                        let mut w = s.try_clone().unwrap();
                        let stop2 = stop.clone();
                        let echoed = Arc::new(AtomicU64::new(0));
                        let echoed2 = echoed.clone();
                        let wt = std::thread::spawn(move || {
                            // bounded in flight (4 MiB): the echo server must not be asked to buffer the whole stream
                            let big = vec![7u8; size];
                            let mut sent = 0u64;
                            while !stop2.load(Ordering::Relaxed) {
                                if sent.saturating_sub(echoed2.load(Ordering::Relaxed)) > (4 << 20)
                                {
                                    std::thread::yield_now();
                                    continue;
                                }
                                if w.write_all(&big).is_err() {
                                    break;
                                }
                                sent += big.len() as u64;
                            }
                            let _ = w.shutdown(std::net::Shutdown::Both);
                        });
                        let mut r = &s;
                        let mut rb = vec![0u8; 1 << 20];
                        while let Ok(n) = r.read(&mut rb) {
                            if n == 0 {
                                break;
                            }
                            bytes.fetch_add(n as u64, Ordering::Relaxed);
                            echoed.fetch_add(n as u64, Ordering::Relaxed);
                        }
                        wt.join().unwrap();
                    }
                    lat
                })
            })
            .collect();
        std::thread::sleep(Duration::from_secs(secs));
        stop.store(true, Ordering::Relaxed);
        let mut lat: Vec<u32> = Vec::new();
        for t in th {
            lat.extend(t.join().unwrap());
        }
        let wall = t0.elapsed().as_secs_f64();
        let b = bytes.load(Ordering::Relaxed) as f64;
        let cpu = cpu_secs() - c0;
        if mode == "pingpong" {
            lat.sort_unstable();
            let p =
                |q: f64| lat[((lat.len() as f64 * q) as usize).min(lat.len() - 1)] as f64 / 1000.0;
            println!(
                "pingpong size={size} conns={conns}: {:.0} ops/s  lat us p50 {:.1} p99 {:.1} p99.9 {:.1}  client cpu {:.2}s",
                lat.len() as f64 / wall,
                p(0.5),
                p(0.99),
                p(0.999),
                cpu
            );
        } else {
            println!(
                "stream conns={conns}: {:.2} Gbit/s echoed ({:.2} Gbit/s on the wire both ways)  client cpu {:.2}s",
                b * 8.0 / wall / 1e9,
                b * 16.0 / wall / 1e9,
                cpu
            );
        }
    }

    pub fn main() {
        let a: Vec<String> = std::env::args().skip(1).collect();
        match a.first().map(String::as_str) {
            Some("server") => server(&a[1..]),
            Some("client") => client(&a[1..]),
            _ => eprintln!(
                "usage: knet_bench server IP PORT CORES SECS [..] | client IP:PORT pingpong|stream SIZE CONNS SECS"
            ),
        }
        let _ = Idle::Spin;
    }
}
