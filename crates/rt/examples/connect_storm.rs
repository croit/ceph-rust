// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! LAB: connect storm against one listener (adr 0585: connect latency of placed links). `N` TCP
//! connects, `C` at a time (one thread each), every connect timed until `connect()` returns (SYN-ACK received); each link
//! is held `HOLD_MS` and then closed, so up to `C` links are open at once. Reports connect latency percentiles, the
//! wall time of the storm and failures. A connect that exceeds `TIMEOUT_MS` is loud (`WARNING TIMEOUT`) and counts as
//! failed.
//! usage: `connect_storm IP:PORT N C [HOLD_MS=0] [TIMEOUT_MS=10000] [--format plain|json]`
//! exit: 0 all connected, 1 any failure, 2 usage.
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let json = a
        .windows(2)
        .any(|w| w[0] == "--format" && w[1].starts_with("json"));
    let pos: Vec<&String> = a
        .iter()
        .skip(1)
        .filter(|s| !s.starts_with("--") && !s.starts_with("json") && *s != "plain")
        .collect();
    if pos.len() < 3 {
        eprintln!("usage: connect_storm IP:PORT N C [HOLD_MS] [TIMEOUT_MS] [--format plain|json]");
        std::process::exit(2);
    }
    let to: SocketAddr = pos[0].parse().expect("IP:PORT");
    let n: usize = pos[1].parse().expect("N");
    let c: usize = pos[2].parse::<usize>().expect("C").max(1);
    let hold = Duration::from_millis(pos.get(3).map_or(0, |v| v.parse().expect("HOLD_MS")));
    let tmo_ms: u64 = pos
        .get(4)
        .map_or(10_000, |v| v.parse().expect("TIMEOUT_MS"));
    let next = Arc::new(AtomicUsize::new(0));
    let lat = Arc::new(Mutex::new(Vec::with_capacity(n)));
    let errs = Arc::new(Mutex::new(Vec::new()));
    let t0 = Instant::now();
    let th: Vec<_> = (0..c)
        .map(|_| {
            let (next, lat, errs) = (next.clone(), lat.clone(), errs.clone());
            std::thread::spawn(move || {
                while next.fetch_add(1, Ordering::Relaxed) < n {
                    let s = Instant::now();
                    match TcpStream::connect_timeout(&to, Duration::from_millis(tmo_ms)) {
                        Ok(sock) => {
                            lat.lock().unwrap().push(s.elapsed().as_secs_f64() * 1e6);
                            std::thread::sleep(hold);
                            drop(sock);
                        }
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::TimedOut {
                                eprintln!(
                                    "WARNING TIMEOUT connect exceeded {}s ({to})",
                                    tmo_ms as f64 / 1e3
                                );
                            }
                            errs.lock().unwrap().push(e.to_string());
                        }
                    }
                }
            })
        })
        .collect();
    for t in th {
        t.join().unwrap();
    }
    let wall = t0.elapsed().as_secs_f64();
    let mut v = std::mem::take(&mut *lat.lock().unwrap());
    let errs = std::mem::take(&mut *errs.lock().unwrap());
    v.sort_by(f64::total_cmp);
    let p = |q: f64| {
        if v.is_empty() {
            0.0
        } else {
            v[((v.len() - 1) as f64 * q).round() as usize]
        }
    };
    let (p50, p90, p99, max) = (p(0.5), p(0.9), p(0.99), p(1.0));
    let ok = v.len();
    if json {
        println!(
            "{{\"to\":\"{to}\",\"n\":{n},\"concurrency\":{c},\"ok\":{ok},\"failed\":{},\"wall_s\":{wall:.3},\"connects_per_s\":{:.1},\"p50_us\":{p50:.0},\"p90_us\":{p90:.0},\"p99_us\":{p99:.0},\"max_us\":{max:.0},\"first_error\":{}}}",
            errs.len(),
            ok as f64 / wall.max(1e-9),
            errs.first().map_or("null".into(), |e| format!("{e:?}"))
        );
    } else {
        println!(
            "connect_storm {to}: {ok}/{n} ok, {} failed, C={c}, wall {wall:.3}s, {:.1} connects/s, latency us p50 {p50:.0} p90 {p90:.0} p99 {p99:.0} max {max:.0}",
            errs.len(),
            ok as f64 / wall.max(1e-9)
        );
        if let Some(e) = errs.first() {
            println!("first error: {e}");
        }
    }
    std::process::exit(if errs.is_empty() { 0 } else { 1 });
}
