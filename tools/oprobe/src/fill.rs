// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `oprobe fill`: count-bounded object filler for space measurements (one compound op per object:
//! writefull + xattrs + omap keys). Values are incompressible (random) or compressible (repeating
//! 64 B text block), reproducible from `--seed`. Prints one summary line with the logical byte counts.

use crate::client::{Opts, Probe};
use crate::omapbench::{
    MAX_CLIENTS, MAX_QD, Rng, flag, num, num_max, secs, splitmix, take, target,
};
use crate::script::ScriptMsg;
use opwire::{KvMap, OsdOp};
use std::process::ExitCode;
use std::time::{Duration, Instant};

pub const HELP: &str = "\
fill -p POOL --objects N [options]   write N objects (name <prefix><index>), each 1 compound op
  --prefix S (fill-)  --data B (0: writefull B bytes)  --keys K (0: omap keys per object)  --val-min B (100)  --val-max B (100)
  --xattrs X (0)  --xattr-len B (32)  --compressible (default: random)  --cpct P (P % of every 4 KiB repeating text, rest random; 50 ~ 2:1)  --structured (RGW-index-like omap entries: long hierarchical keys, ~270 B values that repeat the key and share strings; ignores --val-min/max)  --seed N  --clients N (4)  --qd N (32)  --op-timeout S (60)
  --format plain|json|json-pretty
output plain: 'fill objects=N errs=E data_B=.. omap_key_B=.. omap_val_B=.. xattr_B=.. secs=.. lat_avg_ms= lat_p50_ms= lat_p99_ms= lat_max_ms=' (op latency of the successful writes); json: the same fields as one object. rc 0 ok, 1 errors.
";

#[derive(Clone)]
struct Cfg {
    pool: String,
    prefix: String,
    data: usize,
    keys: usize,
    vmin: usize,
    vmax: usize,
    xattrs: usize,
    xlen: usize,
    compressible: bool,
    structured: bool,
    cpct: usize,
    seed: u64,
    qd: usize,
    timeout: Duration,
}

/// 64 B text block of the compressible payload.
const TEXT: &[u8] = b"the quick brown fox jumps over the lazy dog 0123456789 ABCDEFGH ";

fn payload(rng: &mut Rng, n: usize, compressible: bool, cpct: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n + 8);
    if cpct > 0 {
        // every 4 KiB: (100-cpct) % random bytes, then repeating text (realistic ~2:1 at 50)
        while v.len() < n {
            let blk = v.len();
            let rnd = 4096 * (100 - cpct.min(100)) / 100 / 8 * 8;
            for _ in 0..rnd / 8 {
                v.extend_from_slice(&rng.next_u64().to_le_bytes());
            }
            while v.len() < blk + 4096 {
                let k = (blk + 4096 - v.len()).min(TEXT.len());
                v.extend_from_slice(&TEXT[..k]);
            }
        }
    } else if compressible {
        while v.len() < n {
            v.extend_from_slice(TEXT);
        }
    } else {
        while v.len() < n {
            v.extend_from_slice(&rng.next_u64().to_le_bytes());
        }
    }
    v.truncate(n);
    v
}

/// RGW-bucket-index-shaped entry: hierarchical key with long shared prefixes, value = encoded directory entry (key again, random
/// etag / size / tag, constant owner / content type / class strings).
fn structured_entry(rng: &mut Rng, idx: u64, i: usize) -> (Vec<u8>, Vec<u8>) {
    let key = format!(
        "backups/2026/{:02}/host-{:03}/snapshots/volume-{:05}/chunk-{:010}.bin",
        1 + idx % 12,
        idx / 12 % 100,
        idx / 7 % 1000,
        idx * 1000 + i as u64
    )
    .into_bytes();
    let hex = |rng: &mut Rng, n: usize| -> Vec<u8> {
        (0..n)
            .map(|_| b"0123456789abcdef"[(rng.next_u64() & 15) as usize])
            .collect()
    };
    let lp = |v: &mut Vec<u8>, s: &[u8]| {
        v.extend_from_slice(&(s.len() as u32).to_le_bytes());
        v.extend_from_slice(s);
    };
    let mut v = vec![8u8, 3, 0, 0, 0, 0];
    lp(&mut v, &key);
    lp(&mut v, b"");
    v.extend_from_slice(&(1 + (i as u64) % 7).to_le_bytes());
    v.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0]);
    v.extend_from_slice(&(1_700_000_000u32 + (idx as u32) / 3).to_le_bytes());
    v.extend_from_slice(&((rng.next_u64() as u32) % 1_000_000_000).to_le_bytes());
    let etag = hex(rng, 32);
    lp(&mut v, &etag);
    v.extend_from_slice(&(rng.next_u64() % (64 << 20)).to_le_bytes());
    lp(&mut v, b"testuser-0001");
    lp(&mut v, b"Test User Display Name");
    lp(&mut v, b"application/octet-stream");
    v.extend_from_slice(&(rng.next_u64() % (64 << 20)).to_le_bytes());
    v.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]);
    lp(&mut v, b"STANDARD");
    let tag = hex(rng, 28);
    lp(&mut v, &[b"tag.".as_slice(), &tag].concat());
    v.extend_from_slice(&[0u8; 24]);
    (key, v)
}

/// (message, logical bytes [data, key, val, xattr])
fn build(c: &Cfg, idx: u64) -> (ScriptMsg, [u64; 4]) {
    let mut s = idx ^ c.seed.wrapping_mul(0x9E37_79B9);
    let mut rng = Rng::new(splitmix(&mut s));
    let mut ops = Vec::new();
    let mut b = [0u64; 4];
    if c.data > 0 {
        ops.push(OsdOp::writefull(payload(
            &mut rng,
            c.data,
            c.compressible,
            c.cpct,
        )));
        b[0] = c.data as u64;
    }
    for i in 0..c.xattrs {
        let k = format!("user.x{i}");
        let v = payload(&mut rng, c.xlen, c.compressible, c.cpct);
        b[3] += (k.len() + v.len()) as u64;
        ops.push(OsdOp::setxattr(k.as_bytes(), &v));
    }
    if c.keys > 0 {
        let mut m = KvMap::new();
        for i in 0..c.keys {
            if c.structured {
                let (k, v) = structured_entry(&mut rng, idx, i);
                b[1] += k.len() as u64;
                b[2] += v.len() as u64;
                m.insert(k, v);
                continue;
            }
            let k = format!("key{i:06}").into_bytes();
            let n = c.vmin + rng.below((c.vmax - c.vmin + 1) as u64) as usize;
            b[1] += k.len() as u64;
            b[2] += n as u64;
            m.insert(k, payload(&mut rng, n, c.compressible, c.cpct));
        }
        ops.push(OsdOp::omap_set_vals(&m));
    }
    (
        ScriptMsg {
            ops,
            ..Default::default()
        },
        b,
    )
}

/// (done, errs, logical bytes submitted, op latencies in microseconds)
type Worked = (u64, u64, [u64; 4], Vec<u64>);

/// one client: returns [`Worked`]
fn worker(o: Opts, c: Cfg, lo: u64, hi: u64) -> Result<Worked, String> {
    let mut o = o;
    o.timeout = c.timeout;
    let mut p = Probe::connect(o)?;
    p.idle_sleep = Duration::from_micros(100);
    let pool = p
        .osdmap()
        .pool_id_by_name(&c.pool)
        .ok_or_else(|| format!("no pool '{}'", c.pool))?;
    let (mut next, mut done, mut errs, mut tot) = (lo, 0u64, 0u64, [0u64; 4]);
    let mut lat: Vec<u64> = Vec::with_capacity((hi - lo) as usize);
    while done + errs < hi - lo {
        while next < hi && p.in_flight() < c.qd {
            let (m, b) = build(&c, next);
            let t = target(pool, &format!("{}{next}", c.prefix));
            if p.submit(t, m, next).is_err() {
                errs += 1;
            } else {
                for (t, x) in tot.iter_mut().zip(b) {
                    *t += x;
                }
            }
            next += 1;
        }
        for d in p.poll() {
            match d.reply {
                Some(r) if r.result >= 0 => {
                    done += 1;
                    lat.push(d.finished.duration_since(d.submitted).as_micros() as u64);
                }
                other => {
                    errs += 1;
                    if errs <= 2 {
                        eprintln!(
                            "fill: op error after {:.1} s: err={:?} result={:?}",
                            d.finished.duration_since(d.submitted).as_secs_f64(),
                            d.err,
                            other.map(|r| r.result)
                        );
                    }
                }
            }
        }
    }
    Ok((done, errs, tot, lat))
}

pub fn cli(a: Vec<String>, o: Opts, pool: Option<String>) -> Result<ExitCode, String> {
    let (fmt, mut a) = outfmt::extract(&a, false)?;
    let objects: u64 = num(&mut a, "--objects", 0u64)?;
    let clients: u64 = num_max(&mut a, "--clients", MAX_CLIENTS, 4u64)?.max(1);
    let vmin: usize = num(&mut a, "--val-min", 100usize)?;
    let c = Cfg {
        pool: pool.ok_or("fill: -p POOL required")?,
        prefix: take(&mut a, "--prefix")?.unwrap_or_else(|| "fill-".into()),
        data: num(&mut a, "--data", 0usize)?,
        keys: num(&mut a, "--keys", 0usize)?,
        vmin,
        vmax: num(&mut a, "--val-max", vmin)?.max(vmin),
        xattrs: num(&mut a, "--xattrs", 0usize)?,
        xlen: num(&mut a, "--xattr-len", 32usize)?,
        compressible: flag(&mut a, "--compressible"),
        structured: flag(&mut a, "--structured"),
        cpct: num(&mut a, "--cpct", 0usize)?,
        seed: num(&mut a, "--seed", 1u64)?,
        qd: num_max(&mut a, "--qd", MAX_QD, 32usize)?.max(1),
        timeout: secs(&mut a, "--op-timeout", 60.0)?,
    };
    if objects == 0 || !a.is_empty() {
        return Err(format!(
            "fill: --objects N required / unknown args {a:?}\n{HELP}"
        ));
    }
    let t0 = Instant::now();
    let per = objects.div_ceil(clients);
    let hs: Vec<_> = (0..clients)
        .map(|i| {
            let (o, c) = (o.clone(), c.clone());
            let (lo, hi) = ((i * per).min(objects), ((i + 1) * per).min(objects));
            std::thread::spawn(move || worker(o, c, lo, hi))
        })
        .collect();
    let (mut done, mut errs, mut tot) = (0u64, 0u64, [0u64; 4]);
    let mut lat: Vec<u64> = Vec::new();
    for h in hs {
        let (d, e, b, l) = h.join().map_err(|_| "fill: worker panicked")??;
        lat.extend(l);
        done += d;
        errs += e;
        for (t, x) in tot.iter_mut().zip(b) {
            *t += x;
        }
    }
    lat.sort_unstable();
    let elapsed_s = t0.elapsed().as_secs_f64();
    let (avg, p50, p99, max) = (
        pct(&lat, -1.0),
        pct(&lat, 0.5),
        pct(&lat, 0.99),
        pct(&lat, 1.0),
    );
    if fmt == outfmt::Format::Plain {
        println!(
            "fill objects={done} errs={errs} data_B={} omap_key_B={} omap_val_B={} xattr_B={} secs={elapsed_s:.1} lat_avg_ms={avg:.1} lat_p50_ms={p50:.1} lat_p99_ms={p99:.1} lat_max_ms={max:.1}",
            tot[0], tot[1], tot[2], tot[3]
        );
    } else {
        println!(
            "{}",
            fmt.doc(&serde_json::json!({
                "objects": done, "errs": errs, "data_B": tot[0], "omap_key_B": tot[1],
                "omap_val_B": tot[2], "xattr_B": tot[3], "secs": elapsed_s,
                "lat_avg_ms": avg, "lat_p50_ms": p50, "lat_p99_ms": p99, "lat_max_ms": max,
            }))
        );
    }
    Ok(if errs == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

/// Latency statistic in ms of the sorted microsecond samples: `q` in 0..=1, or -1 for the mean.
fn pct(lat: &[u64], q: f64) -> f64 {
    if lat.is_empty() {
        return 0.0;
    }
    if q < 0.0 {
        return lat.iter().sum::<u64>() as f64 / lat.len() as f64 / 1000.0;
    }
    lat[((lat.len() - 1) as f64 * q).round() as usize] as f64 / 1000.0
}
