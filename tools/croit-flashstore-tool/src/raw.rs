// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `raw`: device line rate / IOPS ceiling below the store (no store, no mkfs), the reference for "fraction of line rate".
//!
//!   croit-flashstore-tool raw --dev spdk:PCI [--bs 128k,1m] [--qd 1,4,32] [--secs 5] [--region-mib 512] [--offset-mib 0]
//!                    [--write] [--rand] [--qdepth 1024] [--format plain|json|json-pretty|jsonl]   (pin with taskset)
//! One thread, one qpair. Per (bs, qd) point: `qd` IOs of `bs` in flight over `[offset, offset+region)`. Sequential (default):
//! IOs in order (wrapping); an IO above the device max transfer is split into max-transfer commands (counted as one IO).
//! `--rand`: every IO at a uniformly random `bs`-aligned slot of the region (a slot still in flight is skipped), one command
//! per IO (bs <= max transfer); the IOPS ceiling of the backend at small blocks (e.g. `--rand --bs 4k --qd 1,16,64,128
//! --region-mib 64`; one DMA buffer per slot = region bytes of hugepage memory).
//! Reads always run. `--write` NEVER changes the device contents: the region is read once into DMA buffers (one per
//! slot) and every write puts the very bytes back at the LBAs they came from, so a crash or a torn write leaves
//! identical data. Exclusive open: refused while an OSD holds the device. MB/s are decimal. Latency = submit to
//! completion of the whole IO (p50/p99/p99.9/max over every IO of the point); `cmd_*` = the same per device command
//! (split IOs: one sample per command), `slow5ms` = IOs of at least 5 ms. jsonl/json fields: op bs qd rand
//! cmds_per_io mbps iops avg_us p50_us p99_us p999_us max_us cmd_p50_us cmd_p99_us cmd_p999_us cmd_max_us slow5ms.
use crate::{arg, flag, fnum, mib, num};
use nvme::any::{AnyBuf, AnyDev, DevSpec};
use nvme::{BlockDev, Completion};
use outfmt::Format;
use serde_json::{Value, json};
use std::time::Instant;

pub fn run(a: &[String], f: Format) -> i32 {
    let args = match parse(a) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("raw: {e}");
            return 2;
        }
    };
    match inner(a, args, f) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("raw: {e}");
            crate::devopen::exit_code(&e)
        }
    }
}

fn size(s: &str) -> Result<u64, String> {
    nvme::any::parse_size(s).ok_or_else(|| format!("bad size {s}"))
}

/// MiB option in bytes (see [`mib`]).
fn mib_at(a: &[String], k: &str, d: u64) -> Result<u64, String> {
    mib(k, num(a, k, d)?)
}

/// One measured point (a table row / json record).
struct Row {
    write: bool,
    bs: u64,
    qd: usize,
    per: usize,
    mbps: f64,
    iops: f64,
    avg_us: f64,
    p50_us: f64,
    p99_us: f64,
    p999_us: f64,
    max_us: f64,
    cmd_p50_us: f64,
    cmd_p99_us: f64,
    cmd_p999_us: f64,
    cmd_max_us: f64,
    slow5ms: usize,
}

/// Usage-level arguments (exit 2 when bad): block sizes, queue depths, device spec.
fn parse(a: &[String]) -> Result<(Vec<u64>, Vec<usize>, DevSpec), String> {
    let bss: Vec<u64> = arg(a, "--bs")
        .unwrap_or_else(|| "128k,1m".into())
        .split(',')
        .map(size)
        .collect::<Result<_, _>>()?;
    let qds: Vec<usize> = arg(a, "--qd")
        .unwrap_or_else(|| "1,4,32".into())
        .split(',')
        .map(|s| s.parse().map_err(|_| format!("bad qd {s}")))
        .collect::<Result<_, _>>()?;
    let spec = DevSpec::parse(&arg(a, "--dev").ok_or("--dev required")?)?;
    Ok((bss, qds, spec))
}

fn inner(
    a: &[String],
    (bss, qds, spec): (Vec<u64>, Vec<usize>, DevSpec),
    fmt: Format,
) -> Result<(), String> {
    let rand = flag(a, "--rand");
    let secs = fnum(a, "--secs", 5.0)?;
    let region = mib_at(a, "--region-mib", 512)?;
    let offset = mib_at(a, "--offset-mib", 0)?;
    let ctrl = crate::devopen::open(&spec, false, 0)?;
    let g = ctrl.geometry();
    let lba = g.lba_size as u64;
    let cmd = g.max_xfer_lbas as u64 * lba;
    offset
        .checked_add(region)
        .filter(|&e| e <= g.capacity_bytes())
        .ok_or_else(|| {
            format!(
                "region {region} B at offset {offset} B is not inside the {} B device",
                g.capacity_bytes()
            )
        })?;
    if region == 0 || !region.is_multiple_of(cmd) || !offset.is_multiple_of(lba) {
        return Err(format!(
            "region must be a nonzero multiple of the max transfer {cmd} B inside the device"
        ));
    }
    for &bs in &bss {
        let bad = if rand {
            bs % lba != 0 || bs > cmd || !region.is_multiple_of(bs)
        } else {
            bs % lba != 0 || !region.is_multiple_of(bs) || bs < cmd || bs % cmd != 0
        };
        if bad {
            return Err(format!(
                "bs {bs}: must divide the region and be a multiple of the lba; sequential: a multiple of the max transfer {cmd} B; --rand: at most the max transfer"
            ));
        }
    }
    nvme::any::set_queue_depth(num(a, "--qdepth", 1024)?.min(u64::from(u32::MAX)) as u32);
    let mut dev = ctrl.open_queue()?;
    eprintln!(
        "raw: lba {lba} B, max transfer {cmd} B, qpair depth {}, region {} MiB at {} MiB, {} GiB device, {}",
        dev.queue_depth(),
        region >> 20,
        offset >> 20,
        g.capacity_bytes() >> 30,
        if rand { "random" } else { "sequential" }
    );
    let ops: &[bool] = if flag(a, "--write") {
        &[false, true]
    } else {
        &[false]
    };
    let mut out: Vec<Completion<AnyBuf>> = Vec::new();
    let mut rows = Vec::new();
    // slot = one DMA buffer of the region (max transfer sequential, bs random); writes put a slot back where it came from
    let mut bufs: Vec<Option<AnyBuf>> = Vec::new();
    let mut unit = 0;
    for &w in ops {
        for &bs in &bss {
            let u = if rand { bs } else { cmd };
            if u != unit {
                bufs = load(&mut dev, &mut out, offset / lba, region, u, lba)?;
                unit = u;
            }
            for &qd in &qds {
                let p = Point {
                    write: w,
                    bs,
                    qd,
                    secs,
                    flba: offset / lba,
                    ulbas: u / lba,
                    unit: u,
                    rand,
                };
                if let Some(r) = p.run(&mut dev, &mut bufs, &mut out)? {
                    if fmt == Format::Plain && rows.is_empty() {
                        println!(
                            "| op | bs | qd | cmds/io | MB/s | IOPS | avg us | p50 us | p99 us | p99.9 us | max us | cmd p99 us | cmd p99.9 us | cmd max us | slow5ms |"
                        );
                        println!("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|");
                    }
                    emit(fmt, rand, &r);
                    rows.push(r);
                }
            }
        }
    }
    if matches!(fmt, Format::Json | Format::JsonPretty) {
        let recs: Vec<Value> = rows.iter().map(|r| json(rand, r)).collect();
        println!("{}", fmt.records(&recs));
    }
    Ok(())
}

/// Read the region into `region / unit` DMA buffers (QD 32).
fn load(
    dev: &mut AnyDev,
    out: &mut Vec<Completion<AnyBuf>>,
    flba: u64,
    region: u64,
    unit: u64,
    lba: u64,
) -> Result<Vec<Option<AnyBuf>>, String> {
    let slots = (region / unit) as usize;
    let ulbas = unit / lba;
    let mut bufs: Vec<Option<AnyBuf>> = (0..slots)
        .map(|_| Some(dev.alloc_buf_uninit(unit as usize)))
        .collect();
    let (mut next, mut done, mut infl) = (0usize, 0usize, 0usize);
    while done < slots {
        while next < slots && infl < 32 {
            let b = bufs[next].take().expect("buf");
            dev.submit_read(flba + next as u64 * ulbas, b, next as u64)
                .map_err(|e| format!("read submit: {:?}", e.err))?;
            next += 1;
            infl += 1;
        }
        out.clear();
        dev.poll(0, out);
        for c in out.drain(..) {
            c.result.map_err(|e| format!("read: {e:?}"))?;
            bufs[c.tag as usize] = c.buf;
            done += 1;
            infl -= 1;
        }
    }
    Ok(bufs)
}

struct Point {
    write: bool,
    bs: u64,
    qd: usize,
    secs: f64,
    flba: u64,
    /// LBAs of one slot
    ulbas: u64,
    /// bytes of one slot
    unit: u64,
    rand: bool,
}

impl Point {
    fn run(
        &self,
        dev: &mut AnyDev,
        bufs: &mut [Option<AnyBuf>],
        out: &mut Vec<Completion<AnyBuf>>,
    ) -> Result<Option<Row>, String> {
        let (qd, write) = (self.qd, self.write);
        // IO = `per` consecutive slots; IO k covers slots [k*per, (k+1)*per) of the region
        let per = (self.bs / self.unit).max(1) as usize;
        let ios = bufs.len() / per;
        if qd * per > dev.queue_depth() {
            eprintln!(
                "raw: {} {}K qd {qd} skipped: {} commands > qpair depth {}",
                if write { "write" } else { "read" },
                self.bs >> 10,
                qd * per,
                dev.queue_depth()
            );
            return Ok(None);
        }
        if qd > ios {
            return Err(format!("qd {qd} exceeds the {ios} IOs of the region"));
        }
        let mut rng = store::rng::Rng::new(0x5eed ^ (self.bs << 8) ^ qd as u64);
        let mut left = vec![0usize; ios]; // commands of IO k still in flight
        let (mut next, mut infl) = (0usize, 0usize);
        let mut lat_ns: Vec<u64> = Vec::with_capacity(1 << 20);
        let mut t_sub = vec![Instant::now(); ios];
        let mut t_cmd = vec![Instant::now(); bufs.len()];
        let mut cmd_ns: Vec<u64> = Vec::with_capacity(1 << 20);
        let t0 = Instant::now();
        let dur = std::time::Duration::from_secs_f64(self.secs);
        let mut stop = false;
        loop {
            while !stop && infl < qd {
                let k = if self.rand {
                    rng.below(ios as u64) as usize
                } else {
                    next % ios
                };
                if left[k] != 0 {
                    if self.rand {
                        continue; // random slot still in flight: draw again (qd << ios)
                    }
                    break; // wrapped onto an IO still in flight (qd close to ios)
                }
                t_sub[k] = Instant::now();
                for j in 0..per {
                    let c = k * per + j;
                    let b = bufs[c].take().expect("slot buffer free");
                    let l = self.flba + c as u64 * self.ulbas;
                    t_cmd[c] = Instant::now();
                    let r = if write {
                        dev.submit_write(l, b, c as u64)
                    } else {
                        dev.submit_read(l, b, c as u64)
                    };
                    if let Err(e) = r {
                        return Err(format!("submit: {:?}", e.err));
                    }
                }
                left[k] = per;
                next += 1;
                infl += 1;
            }
            out.clear();
            dev.poll(0, out);
            for c in out.drain(..) {
                c.result.map_err(|e| format!("io: {e:?}"))?;
                let ch = c.tag as usize;
                cmd_ns.push(t_cmd[ch].elapsed().as_nanos() as u64);
                bufs[ch] = c.buf;
                let k = ch / per;
                left[k] -= 1;
                if left[k] == 0 {
                    infl -= 1;
                    lat_ns.push(t_sub[k].elapsed().as_nanos() as u64);
                }
            }
            if !stop && t0.elapsed() >= dur {
                stop = true;
            }
            if stop && infl == 0 {
                break;
            }
        }
        let s = t0.elapsed().as_secs_f64();
        let n = lat_ns.len().max(1) as f64;
        let avg = lat_ns.iter().sum::<u64>() as f64 / n / 1e3;
        lat_ns.sort_unstable();
        cmd_ns.sort_unstable();
        let pct = |v: &[u64], p: f64| {
            v.get(((v.len() as f64 * p) as usize).min(v.len().saturating_sub(1)))
                .map_or(0.0, |x| *x as f64 / 1e3)
        };
        let slow5ms = lat_ns.iter().filter(|x| **x >= 5_000_000).count();
        Ok(Some(Row {
            write,
            bs: self.bs,
            qd,
            per,
            mbps: lat_ns.len() as f64 * self.bs as f64 / s / 1e6,
            iops: lat_ns.len() as f64 / s,
            avg_us: avg,
            p50_us: pct(&lat_ns, 0.50),
            p99_us: pct(&lat_ns, 0.99),
            p999_us: pct(&lat_ns, 0.999),
            max_us: pct(&lat_ns, 1.0),
            cmd_p50_us: pct(&cmd_ns, 0.50),
            cmd_p99_us: pct(&cmd_ns, 0.99),
            cmd_p999_us: pct(&cmd_ns, 0.999),
            cmd_max_us: pct(&cmd_ns, 1.0),
            slow5ms,
        }))
    }
}

fn json(rand: bool, r: &Row) -> Value {
    let round = |x: f64, d: i32| (x * 10f64.powi(d)).round() / 10f64.powi(d);
    json!({"op": if r.write { "write" } else { "read" }, "bs": r.bs, "qd": r.qd, "rand": rand, "cmds_per_io": r.per,
        "mbps": round(r.mbps, 1), "iops": round(r.iops, 0), "avg_us": round(r.avg_us, 1),
        "p50_us": round(r.p50_us, 1), "p99_us": round(r.p99_us, 1), "p999_us": round(r.p999_us, 1), "max_us": round(r.max_us, 1),
        "cmd_p50_us": round(r.cmd_p50_us, 1), "cmd_p99_us": round(r.cmd_p99_us, 1), "cmd_p999_us": round(r.cmd_p999_us, 1),
        "cmd_max_us": round(r.cmd_max_us, 1), "slow5ms": r.slow5ms})
}

fn emit(fmt: Format, rand: bool, r: &Row) {
    match fmt {
        Format::Plain => println!(
            "| {}{} | {}K | {} | {} | {:.0} | {:.0} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} | {} |",
            if r.write { "write" } else { "read" },
            if rand { " rand" } else { "" },
            r.bs >> 10,
            r.qd,
            r.per,
            r.mbps,
            r.iops,
            r.avg_us,
            r.p50_us,
            r.p99_us,
            r.p999_us,
            r.max_us,
            r.cmd_p99_us,
            r.cmd_p999_us,
            r.cmd_max_us,
            r.slow5ms
        ),
        Format::Jsonl => println!("{}", json(rand, r)),
        Format::Json | Format::JsonPretty => {}
    }
}
