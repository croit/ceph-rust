// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Two-host check of the SEND-baseline stream (crate rdma, feature verbs). A TCP connection exchanges the handover
//! records (the device is found by the TCP local address = RoCEv2 GID binding), then the byte stream runs over the RC QP.
//! usage: rdma_pipe [--format plain|json|json-pretty] [SIZING] serve PORT
//!        rdma_pipe [--format ...] [SIZING] stream HOST:PORT MIB CHUNK [--no-verify]   one-way stream; receiver verifies every byte
//!                                                   (--no-verify: receiver only counts, transport cost only)
//!        rdma_pipe [--format ...] [SIZING] pingpong HOST:PORT SIZE COUNT  echo round trips (p50/p99 us)
//! SIZING (each side takes its own; give both sides the same values; defaults = `CoreCfg::default()`):
//!   --window N     grant ceiling: the largest receive window the dynamic grants ever give this session (sessions start at
//!                  the minimum window 3 and are lent credits up to N while they use them); 3 <= N <= SRQ depth
//!   --slot BYTES   receive and send slot size = largest SEND (power of two >= 4096)
//!   --srq N        receive slots (SRQ depth); --tx-slots N  send slots
//! Record fields: mode, device, bytes, secs, gbytes_per_s, sends, credit_only, credit_stalls, queue_stalls, verified,
//! rtt_p50_us, rtt_p99_us, plus the effective window, slot, srq, tx_slots. Exit: 0 ok, 1 data mismatch or fault, 2 usage/setup error.
use rdma::grant::SessionCap;
use rdma::verbs::{Core, CoreCfg, Device, Event, Qp};
use rdma::{Endpoint, gid_of};
use serde_json::json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

fn die(m: &str) -> ! {
    eprintln!("rdma_pipe: {m}");
    std::process::exit(2)
}

/// Stream byte at offset `i`: period 251 (prime, so a lost, duplicated or reordered SEND of any size shows up).
fn pat(i: u64) -> u8 {
    (i % 251) as u8
}

struct Link {
    core: Core,
    qpn: u32,
    dev: String,
    cfg: CoreCfg,
    _tcp: TcpStream,
}

impl Link {
    /// The sizing in effect, for the record.
    fn sizing(&self) -> serde_json::Value {
        json!({"window": self.cfg.max_window, "slot": self.cfg.slot, "srq": self.cfg.srq_depth,
            "tx_slots": self.cfg.tx_slots})
    }
}

/// Merge the effective sizing of `l` into the record `r`.
fn with_sizing(l: &Link, mut r: serde_json::Value) -> serde_json::Value {
    if let (Some(m), Some(s)) = (r.as_object_mut(), l.sizing().as_object()) {
        m.extend(s.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
    r
}

/// Leading sizing options of `a` (see the usage) applied to the defaults; returns the rest.
fn parse_sizing<'a>(mut a: &'a [&'a str]) -> (CoreCfg, &'a [&'a str]) {
    let mut cfg = CoreCfg::default();
    while let [opt, v, rest @ ..] = a {
        let n: u32 = match *opt {
            "--window" | "--slot" | "--srq" | "--tx-slots" => v
                .parse()
                .unwrap_or_else(|_| die(&format!("{opt}: not a number: {v}"))),
            _ => break,
        };
        match *opt {
            "--window" => cfg.max_window = n,
            "--slot" => cfg.slot = n,
            "--srq" => cfg.srq_depth = n,
            _ => cfg.tx_slots = n,
        }
        a = rest;
    }
    if !cfg.slot.is_power_of_two() || cfg.slot < 4096 {
        die("--slot: a power of two >= 4096");
    }
    if cfg.max_window < rdma::credit::MIN_WINDOW || cfg.max_window > cfg.srq_depth {
        die(&format!(
            "--window: {}..=SRQ depth ({})",
            rdma::credit::MIN_WINDOW,
            cfg.srq_depth
        ));
    }
    if cfg.tx_slots < cfg.max_window {
        die("--tx-slots: at least the window");
    }
    (cfg, a)
}

/// Handover over `tcp`: our record out, the peer's in, connect, attach. Mode byte + 3 u64 params ride along.
fn handover(mut tcp: TcpStream, cfg: CoreCfg, hdr: Option<[u64; 4]>) -> (Link, [u64; 4]) {
    let ip = tcp
        .local_addr()
        .unwrap_or_else(|e| die(&format!("{e}")))
        .ip();
    let dev = Device::open(gid_of(ip)).unwrap_or_else(|e| die(&format!("device for {ip}: {e}")));
    let mut core = Core::new(&dev, cfg).unwrap_or_else(|e| die(&format!("core: {e}")));
    let h = core.handles();
    let qp = Qp::create(&dev, h, std::process::id()).unwrap_or_else(|e| die(&format!("{e}")));
    let mut out = qp.endpoint(&h).encode();
    let mut params = [0u64; 4];
    if let Some(p) = hdr {
        p.iter().for_each(|v| out.extend(v.to_le_bytes()));
        params = p;
    }
    tcp.write_all(&out).unwrap_or_else(|e| die(&format!("{e}")));
    let mut b = [0u8; Endpoint::LEN + 32];
    let n = if hdr.is_some() {
        Endpoint::LEN
    } else {
        b.len()
    };
    tcp.read_exact(&mut b[..n])
        .unwrap_or_else(|e| die(&format!("{e}")));
    let peer = Endpoint::decode(&b).unwrap_or_else(|| die("bad endpoint record"));
    if hdr.is_none() {
        for (i, p) in params.iter_mut().enumerate() {
            *p = u64::from_le_bytes(
                b[Endpoint::LEN + 8 * i..][..8]
                    .try_into()
                    .unwrap_or_default(),
            );
        }
    }
    if peer.gid
        != gid_of(
            tcp.peer_addr()
                .unwrap_or_else(|e| die(&format!("{e}")))
                .ip(),
        )
    {
        die("peer GID does not match the TCP peer address");
    }
    qp.connect(&h, &peer)
        .unwrap_or_else(|e| die(&format!("connect: {e}")));
    // both sides RTS before the first SEND (RNR otherwise): one byte each way over TCP
    tcp.write_all(&[1]).unwrap_or_else(|e| die(&format!("{e}")));
    tcp.read_exact(&mut [0u8])
        .unwrap_or_else(|e| die(&format!("{e}")));
    let qpn = qp.qpn();
    core.attach(qp, &peer, SessionCap::new(0).acquire().expect("unlimited"))
        .unwrap_or_else(|_| die("attach refused"));
    (
        Link {
            core,
            qpn,
            dev: dev.name(),
            cfg,
            _tcp: tcp,
        },
        params,
    )
}

const DEADLINE: Duration = Duration::from_secs(60);

/// Poll until `step` returns true. `step(core, qpn, rx)` gets the bytes received since the last call (empty if none);
/// faults and the deadline end the process loudly.
fn pump<S>(l: &mut Link, st: &mut S, mut step: impl FnMut(&mut S, &mut Core, u32, &[u8]) -> bool) {
    let t = Instant::now();
    let qpn = l.qpn;
    let mut rx = Vec::new();
    while !step(st, &mut l.core, qpn, &rx) {
        rx.clear();
        l.core.tick(t.elapsed().as_nanos() as u64);
        l.core.poll(|_, e| match e {
            Event::Data(d) => rx.extend_from_slice(d),
            Event::Writable => {}
            Event::RemoteInvalidated(_) => die("unexpected remote invalidation"),
            Event::Fault(m) => {
                eprintln!("rdma_pipe: fault: {m}");
                std::process::exit(1)
            }
        });
        if t.elapsed() > DEADLINE {
            eprintln!(
                "WARNING TIMEOUT rdma_pipe exceeded {:.3}s (qpn {qpn})",
                DEADLINE.as_secs_f64()
            );
            std::process::exit(1)
        }
    }
}

/// Print one record: the JSON formats via `outfmt`, plain as `key=value` pairs (a plain-mode user never sees JSON).
fn emit(fmt: outfmt::Format, rec: &serde_json::Value) {
    if fmt.is_json() {
        println!("{}", fmt.doc(rec));
    } else {
        let o = rec.as_object().map(|m| {
            m.iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" ")
        });
        println!("{}", o.unwrap_or_default());
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (fmt, a) = outfmt::extract(&args, false).unwrap_or_else(|e| die(&e));
    let a: Vec<&str> = a.iter().map(String::as_str).collect();
    let (cfg, a) = parse_sizing(&a);
    let rec = match a {
        ["serve", port] => {
            let l = TcpListener::bind(format!("[::]:{port}"))
                .or_else(|_| TcpListener::bind(format!("0.0.0.0:{port}")))
                .unwrap_or_else(|e| die(&format!("{e}")));
            let (s, _) = l.accept().unwrap_or_else(|e| die(&format!("{e}")));
            let (mut l, p) = handover(s, cfg, None);
            let r = match p[0] {
                1 => serve_stream(&mut l, p[1], p[2] == 0),
                2 => serve_echo(&mut l, p[1] as usize, p[2]),
                m => die(&format!("unknown mode {m}")),
            };
            with_sizing(&l, r)
        }
        ["stream", hp, mib, chunk, rest @ ..] => {
            let verify = match rest {
                [] => true,
                ["--no-verify"] => false,
                _ => die("stream: unknown flag"),
            };
            let total = mib.parse::<u64>().unwrap_or_else(|_| die("MIB")) << 20;
            let chunk: usize = chunk.parse().unwrap_or_else(|_| die("CHUNK"));
            let s = TcpStream::connect(hp).unwrap_or_else(|e| die(&format!("{hp}: {e}")));
            let (mut l, _) = handover(s, cfg, Some([1, total, (!verify) as u64, 0]));
            let r = stream(&mut l, total, chunk);
            let r = with_sizing(&l, r);
            if r["verified"] != true {
                emit(fmt, &r);
                std::process::exit(1);
            }
            r
        }
        ["pingpong", hp, size, count] => {
            let size: usize = size.parse().unwrap_or_else(|_| die("SIZE"));
            let count: u64 = count.parse().unwrap_or_else(|_| die("COUNT"));
            let s = TcpStream::connect(hp).unwrap_or_else(|e| die(&format!("{hp}: {e}")));
            let (mut l, _) = handover(s, cfg, Some([2, size as u64, count, 0]));
            let r = pingpong(&mut l, size, count);
            with_sizing(&l, r)
        }
        _ => die(
            "usage: rdma_pipe [--format F] [--window N] [--slot BYTES] [--srq N] [--tx-slots N] serve PORT | stream HOST:PORT MIB CHUNK [--no-verify] | pingpong HOST:PORT SIZE COUNT",
        ),
    };
    emit(fmt, &rec);
}

/// Receiver of `stream --no-verify`: counts bytes straight from the receive slots (transport cost only).
fn serve_sink(l: &mut Link, total: u64) -> serde_json::Value {
    let t = Instant::now();
    let mut got = 0u64;
    while got < total {
        l.core.tick(t.elapsed().as_nanos() as u64);
        l.core.poll(|_, e| match e {
            Event::Data(d) => got += d.len() as u64,
            Event::Writable => {}
            Event::RemoteInvalidated(_) => die("unexpected remote invalidation"),
            Event::Fault(m) => die(&format!("fault: {m}")),
        });
        if t.elapsed() > DEADLINE {
            eprintln!(
                "WARNING TIMEOUT rdma_pipe sink exceeded {:.3}s",
                DEADLINE.as_secs_f64()
            );
            std::process::exit(1)
        }
    }
    let secs = t.elapsed().as_secs_f64();
    pump(l, &mut (), |_, c, q, _| c.send(q, &[1]) == 1);
    std::thread::sleep(Duration::from_millis(100));
    json!({"mode": "stream-sink", "device": l.dev, "bytes": got, "secs": secs,
        "gbytes_per_s": got as f64 / secs / 1e9, "verified": null,
        "credit_only": l.core.stats.credit_only, "sends": l.core.stats.rx_sends})
}

/// Receiver of `stream`: verifies every byte, then sends the verdict byte back.
fn serve_stream(l: &mut Link, total: u64, verify: bool) -> serde_json::Value {
    if !verify {
        return serve_sink(l, total);
    }
    let want: Vec<u8> = (0..rdma::DEFAULT_SLOT as u64 * 2 + 251).map(pat).collect();
    let t = Instant::now();
    let mut s = (0u64, 0u64);
    pump(l, &mut s, |(got, bad), _, _, rx| {
        for c in rx.chunks(rdma::DEFAULT_SLOT as usize) {
            let o = (*got % 251) as usize;
            if c != &want[o..o + c.len()] {
                *bad += c
                    .iter()
                    .enumerate()
                    .filter(|(i, x)| **x != pat(*got + *i as u64))
                    .count() as u64;
            }
            *got += c.len() as u64;
        }
        *got >= total
    });
    let secs = t.elapsed().as_secs_f64();
    let (got, bad) = s;
    pump(l, &mut (), |_, c, q, _| c.send(q, &[(bad == 0) as u8]) == 1);
    // let the verdict SEND complete before the QP goes away
    std::thread::sleep(Duration::from_millis(100));
    json!({"mode": "stream-recv", "device": l.dev, "bytes": got, "secs": secs,
        "gbytes_per_s": got as f64 / secs / 1e9, "verified": bad == 0, "mismatches": bad,
        "credit_only": l.core.stats.credit_only, "sends": l.core.stats.rx_sends})
}

fn serve_echo(l: &mut Link, size: usize, count: u64) -> serde_json::Value {
    let mut buf = Vec::with_capacity(size * 2);
    for _ in 0..count {
        pump(l, &mut buf, |b, _, _, rx| {
            b.extend_from_slice(rx);
            b.len() >= size
        });
        let mut off = 0;
        pump(l, &mut off, |o, c, q, _| {
            *o += c.send(q, &buf[*o..size]);
            *o == size
        });
        buf.drain(..size);
    }
    std::thread::sleep(Duration::from_millis(100));
    json!({"mode": "pingpong-echo", "device": l.dev, "count": count})
}

fn stream(l: &mut Link, total: u64, chunk: usize) -> serde_json::Value {
    let src: Vec<u8> = (0..chunk as u64 + 251).map(pat).collect();
    let t = Instant::now();
    pump(l, &mut 0u64, |o, c, q, _| {
        let s = (*o % 251) as usize;
        let n = chunk.min((total - *o) as usize);
        *o += c.send(q, &src[s..s + n]) as u64;
        *o >= total
    });
    let secs = t.elapsed().as_secs_f64();
    let mut verdict = None;
    pump(l, &mut verdict, |v, _, _, rx| {
        if let Some(&b) = rx.first() {
            *v = Some(b);
        }
        v.is_some()
    });
    let st = l.core.stats;
    json!({"mode": "stream", "device": l.dev, "bytes": total, "secs": secs,
        "gbytes_per_s": total as f64 / secs / 1e9, "verified": verdict == Some(1), "sends": st.tx_sends,
        "credit_only": st.credit_only, "credit_stalls": st.credit_stalls, "queue_stalls": st.queue_stalls})
}

fn pingpong(l: &mut Link, size: usize, count: u64) -> serde_json::Value {
    let msg: Vec<u8> = (0..size as u64).map(pat).collect();
    let mut rtt = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let t = Instant::now();
        pump(l, &mut 0usize, |o, c, q, _| {
            *o += c.send(q, &msg[*o..]);
            *o == size
        });
        pump(l, &mut 0usize, |g, _, _, rx| {
            *g += rx.len();
            *g >= size
        });
        rtt.push(t.elapsed().as_nanos() as u64);
    }
    rtt.sort_unstable();
    let q = |p: f64| rtt[((rtt.len() - 1) as f64 * p) as usize] as f64 / 1e3;
    json!({"mode": "pingpong", "device": l.dev, "bytes": size, "count": count,
        "rtt_p50_us": q(0.5), "rtt_p99_us": q(0.99), "credit_only": l.core.stats.credit_only})
}
