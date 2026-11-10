// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `kernel:` device probe (adr 0169, lab/baremetal/kvnme-func.sh): geometry, a destructive write/read/zero/deallocate verify over an LBA
//! window, and a QD1 4 KiB read latency + CPU comparison of polling the device ring vs sleeping on it.
//!
//! usage: kdev_probe kernel:/dev/NODE [--verify START_LBA COUNT] [--lat N] [--format plain|json]
//! DESTROYS the data in the verify window. Exit 0 = every check passed.

#[cfg(target_os = "linux")]
mod imp {
    use nvme::any::{AnyCtrl, DevSpec};
    use nvme::{BlockDev, Completion, IoBuf};
    use std::time::Instant;

    fn arg(a: &[String], k: &str) -> Option<String> {
        a.iter()
            .position(|x| x == k)
            .and_then(|i| a.get(i + 1).cloned())
    }

    /// Per-thread CPU time; `RUSAGE_THREAD` exists on Linux only, and the `kernel:` tier needs Linux.
    #[cfg(target_os = "linux")]
    fn cpu_ns() -> u64 {
        // SAFETY: plain syscall into a local struct.
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe { libc::getrusage(libc::RUSAGE_THREAD, &mut ru) };
        let us = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
        (us(ru.ru_utime) + us(ru.ru_stime)) * 1000
    }

    fn wait<D: BlockDev>(
        d: &mut D,
        out: &mut Vec<Completion<D::Buf>>,
        n: usize,
        sleep_fd: Option<i32>,
    ) {
        let t = Instant::now();
        while out.len() < n {
            if d.poll(0, out) == 0
                && let Some(fd) = sleep_fd
            {
                let mut p = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one valid pollfd.
                unsafe { libc::poll(&mut p, 1, 100) };
            }
            if t.elapsed().as_secs() >= 30 {
                eprintln!(
                    "WARNING TIMEOUT kdev_probe IO exceeded 30s ({} of {n} completions)",
                    out.len()
                );
                std::process::exit(1);
            }
        }
    }

    fn pct(v: &mut [u64], p: f64) -> u64 {
        v.sort_unstable();
        v[((v.len() as f64 - 1.0) * p) as usize]
    }

    pub fn main() {
        let a: Vec<String> = std::env::args().collect();
        let json = arg(&a, "--format").is_some_and(|f| f.starts_with("json"));
        let spec = DevSpec::parse(a.get(1).map(String::as_str).unwrap_or("")).unwrap_or_else(|e| {
            eprintln!("kdev_probe: {e}");
            std::process::exit(2)
        });
        let ctrl = AnyCtrl::open_exclusive(&spec).unwrap_or_else(|e| {
            eprintln!("kdev_probe: {e}");
            std::process::exit(1)
        });
        let g = ctrl.geometry();
        let mut d = ctrl.open_queue().expect("queue");
        let dl = d.dealloc_limits();
        let mut res: Vec<(String, String)> = vec![
            ("backend".into(), format!("\"{}\"", spec.backend_name())),
            ("lba_size".into(), g.lba_size.to_string()),
            ("lba_count".into(), g.lba_count.to_string()),
            ("awupf_lbas".into(), g.awupf_lbas.to_string()),
            ("vwc".into(), g.vwc.to_string()),
            ("max_xfer_lbas".into(), g.max_xfer_lbas.to_string()),
            ("dealloc".into(), g.dealloc.to_string()),
            ("trim".into(), format!("\"{}\"", dl.via)),
            ("trim_ranges".into(), dl.max_ranges.to_string()),
            ("trim_max_lbas".into(), dl.max_lbas.to_string()),
            ("trim_gran_lbas".into(), dl.gran_lbas.to_string()),
            ("write_zeroes".into(), g.write_zeroes.to_string()),
            (
                "arena".into(),
                nvme::kdev::arena_info().map_or("\"off\"".into(), |(mb, huge, _)| {
                    format!("\"{mb} MiB{}\"", if huge { " hugepages" } else { "" })
                }),
            ),
        ];
        let mut ok = true;
        let mut out = Vec::new();
        if let Some(start) = arg(&a, "--verify").and_then(|s| s.parse::<u64>().ok()) {
            let count: u64 = a
                .iter()
                .position(|x| x == "--verify")
                .and_then(|i| a.get(i + 2))
                .and_then(|s| s.parse().ok())
                .unwrap_or(4096);
            let ls = g.lba_size as usize;
            let sizes = [1u64, 2, 8, 32, u64::from(g.max_xfer_lbas)];
            // write the window in pieces of varying size (QD up to 32), every LBA stamped with its number
            let (mut lba, mut k, mut inflight) = (start, 0usize, 0usize);
            while lba < start + count || inflight > 0 {
                while lba < start + count && inflight < 32 {
                    let n = sizes[k % sizes.len()].min(start + count - lba);
                    k += 1;
                    let mut b = d.alloc_buf_uninit(n as usize * ls);
                    let s = b.as_mut_slice();
                    for i in 0..n {
                        let o = i as usize * ls;
                        s[o..o + ls].fill(((lba + i) % 251) as u8);
                        s[o..o + 8].copy_from_slice(&(lba + i).to_le_bytes());
                    }
                    d.submit_write(lba, b, lba).expect("submit write");
                    lba += n;
                    inflight += 1;
                }
                out.clear();
                wait(&mut d, &mut out, 1, None);
                for c in out.drain(..) {
                    inflight -= 1;
                    ok &= c.result.is_ok();
                }
            }
            // read back in different pieces
            let mut bad = 0u64;
            let mut lba = start;
            while lba < start + count {
                let n = 16u64
                    .min(u64::from(g.max_xfer_lbas))
                    .min(start + count - lba);
                let b = d.alloc_buf_uninit(n as usize * ls);
                d.submit_read(lba, b, lba).expect("submit read");
                out.clear();
                wait(&mut d, &mut out, 1, None);
                let c = out.pop().expect("completion");
                ok &= c.result.is_ok();
                let s = c.buf.expect("buf");
                for i in 0..n {
                    let o = i as usize * ls;
                    let blk = &s.as_slice()[o..o + ls];
                    if blk[..8] != (lba + i).to_le_bytes()
                        || blk[8..].iter().any(|x| *x != ((lba + i) % 251) as u8)
                    {
                        bad += 1;
                    }
                }
                lba += n;
            }
            // write zeroes on the first 8 LBAs (when supported), read back
            let mut zero_ok = true;
            if g.write_zeroes {
                d.submit_write_zeroes(start, 8, 1).expect("submit zeroes");
                out.clear();
                wait(&mut d, &mut out, 1, None);
                zero_ok = out[0].result.is_ok();
                let b = d.alloc_buf_uninit(8 * ls);
                d.submit_read(start, b, 2).expect("read");
                out.clear();
                wait(&mut d, &mut out, 1, None);
                zero_ok &= out[0]
                    .buf
                    .as_ref()
                    .is_some_and(|b| b.as_slice().iter().all(|x| *x == 0));
            }
            // runtime deallocate after the zeroed LBAs (cmd mode with a verdict: one DSM, range list in an arena buffer; else
            // the block node's discard command): 8 LBAs, 256 LBAs at a 1 MiB aligned start (devices may reject small or
            // unaligned ranges: every result is reported), two ranges in one command where the path takes several
            let mut dealloc_ok = true;
            if dl.is_on() {
                let a = (start + 256).next_multiple_of(256);
                let cases: [(&str, &[(u64, u32)]); 3] = [
                    ("8", &[(start + 8, 8)]),
                    ("256a", &[(a, 256)]),
                    ("2r", &[(start + 16, 8), (start + 32, 8)]),
                ];
                for (name, ranges) in cases {
                    if ranges.len() > dl.max_ranges as usize
                        || ranges
                            .iter()
                            .any(|&(l, n)| l + u64::from(n) > start + count)
                    {
                        continue;
                    }
                    d.submit_deallocate(ranges, 3).expect("submit deallocate");
                    out.clear();
                    wait(&mut d, &mut out, 1, None);
                    dealloc_ok &= out[0].result.is_ok();
                    let r = out[0]
                        .result
                        .map_or_else(|e| format!("{e:?}"), |()| "ok".into());
                    res.push((format!("verify_dealloc_{name}"), format!("\"{r}\"")));
                }
            }
            ok &= bad == 0 && zero_ok && dealloc_ok;
            res.push(("verify_lbas".into(), count.to_string()));
            res.push(("verify_bad_lbas".into(), bad.to_string()));
            res.push(("verify_zeroes_ok".into(), zero_ok.to_string()));
            res.push(("verify_dealloc_ok".into(), dealloc_ok.to_string()));
        }
        if let Some(n) = arg(&a, "--lat").and_then(|s| s.parse::<usize>().ok()) {
            let span = g.lba_count.min(1 << 24);
            let fd = nvme::kdev::thread_ring_fd().ok();
            for (name, sleep) in [("poll", None), ("sleep", fd)] {
                let mut lat = Vec::with_capacity(n);
                let (c0, t0) = (cpu_ns(), Instant::now());
                let mut x = 0x9e37_79b9_7f4a_7c15u64;
                for _ in 0..n {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    let b = d.alloc_buf_uninit(g.lba_size as usize);
                    let t = Instant::now();
                    d.submit_read(x % span, b, 0).expect("read");
                    nvme::kdev::flush();
                    out.clear();
                    wait(&mut d, &mut out, 1, sleep);
                    lat.push(t.elapsed().as_nanos() as u64);
                    ok &= out[0].result.is_ok();
                }
                let wall = t0.elapsed().as_nanos() as u64;
                let cpu = cpu_ns() - c0;
                res.push((
                    format!("{name}_p50_us"),
                    format!("{:.1}", pct(&mut lat, 0.5) as f64 / 1e3),
                ));
                res.push((
                    format!("{name}_p99_us"),
                    format!("{:.1}", pct(&mut lat, 0.99) as f64 / 1e3),
                ));
                res.push((
                    format!("{name}_cpu_us_op"),
                    format!("{:.1}", cpu as f64 / n as f64 / 1e3),
                ));
                res.push((
                    format!("{name}_wall_us_op"),
                    format!("{:.1}", wall as f64 / n as f64 / 1e3),
                ));
            }
        }
        // 4 MiB reads as max_xfer pieces submitted together (what the store does for one 4M object read)
        if let Some(n) = arg(&a, "--big").and_then(|s| s.parse::<usize>().ok()) {
            let piece = g.max_xfer_lbas as usize * g.lba_size as usize;
            let pieces = (4usize << 20).div_ceil(piece);
            let span = g.lba_count.min(1 << 24) / (4 << 20 >> 12) * (4 << 20 >> 12);
            let fd = nvme::kdev::thread_ring_fd().ok();
            for (name, sleep) in [("big_poll", None), ("big_sleep", fd)] {
                let mut lat = Vec::with_capacity(n);
                let (c0, t0) = (cpu_ns(), Instant::now());
                for i in 0..n {
                    let base = (i as u64 * 1031 * 1024) % span.max(1024);
                    let t = Instant::now();
                    for p in 0..pieces {
                        let b = d.alloc_buf_uninit(piece);
                        d.submit_read(base + (p * piece / g.lba_size as usize) as u64, b, p as u64)
                            .expect("read");
                    }
                    nvme::kdev::flush();
                    out.clear();
                    wait(&mut d, &mut out, pieces, sleep);
                    lat.push(t.elapsed().as_nanos() as u64);
                    ok &= out.iter().all(|c| c.result.is_ok());
                }
                let cpu = cpu_ns() - c0;
                let wall = t0.elapsed().as_nanos() as u64;
                res.push((
                    format!("{name}_p50_us"),
                    format!("{:.1}", pct(&mut lat, 0.5) as f64 / 1e3),
                ));
                res.push((
                    format!("{name}_MBps"),
                    format!(
                        "{:.0}",
                        (n as f64 * 4.0 * 1048576.0) / (wall as f64 / 1e9) / 1e6
                    ),
                ));
                res.push((
                    format!("{name}_cpu_us_op"),
                    format!("{:.1}", cpu as f64 / n as f64 / 1e3),
                ));
            }
        }
        res.push(("ok".into(), ok.to_string()));
        if json {
            let body: Vec<String> = res.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
            println!("{{{}}}", body.join(","));
        } else {
            for (k, v) in &res {
                println!("{k}: {}", v.trim_matches('"'));
            }
        }
        std::process::exit(if ok { 0 } else { 1 });
    }
}

#[cfg(target_os = "linux")]
fn main() {
    imp::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("kdev_probe: kernel: devices need Linux (adr 0169)");
    std::process::exit(2);
}
