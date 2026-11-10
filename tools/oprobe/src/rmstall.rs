// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `oprobe rmstall`: foreground 4 KiB read/write latency on one pool while another pool is deleted (PG removal on every
//! OSD). Every op is timestamped (offset from the start of the run), so the report shows the latency per window
//! (before / during / after the delete) and the slowest ops with their offset from the delete command, to correlate with
//! OSD-side counters. See `HELP` and doc/perf/pg-remove-stall-20261023.md.

use crate::client::{Opts, Probe};
use crate::omapbench::{Hist, MAX_CLIENTS, MAX_QD, Rng, flag, num, num_max, secs, take, target};
use crate::script::ScriptMsg;
use opwire::OsdOp;
use std::fmt::Write as _;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::time::{Duration, Instant};

pub const HELP: &str = "\
rmstall -p FGPOOL --delete POOL [options]   4 KiB mixed IO on FGPOOL while POOL is deleted
  --prefix S        object name prefix (default rmstall-<time>)   --objs N (20000) objects   --size B (4096)
  --clients N (2)   --qd N (8)   --write-pct N (50)
  --warm S (3)      writes only, objects are created      --at S (5) after the warm-up: send the pool delete
  --during S (10)   length of the `during` window after the delete command   --after S (10)   tail after `during`
  (output also: `timeline`, one row per second after the delete: ops, p50/p99/max us)
  --top N (12)      slowest ops listed (offset from the delete command)       --keep  leave the objects
  --format plain|json|json-pretty
windows: before (warm-up excluded) | during | after; per window ops/s, p50/p99/p99.9/max us, errors.
output also: delete command round trip (ms), slowest ops (window, offset ms from the delete command, class, latency us).
exit: 0 ok, 1 errors counted or delete failed, 2 usage / setup failure.
";

#[derive(Clone)]
struct Cfg {
    pool: String,
    prefix: String,
    objs: u64,
    size: usize,
    qd: usize,
    write_pct: u64,
    /// Writes only until this offset (objects get created).
    warm: Duration,
}

/// One finished op: submit offset us, latency us, class (0 read, 1 write), failed.
type Samp = (u64, u64, u8, bool);

fn worker(
    o: Opts,
    c: Arc<Cfg>,
    id: u64,
    t0: Instant,
    stop: Arc<AtomicBool>,
) -> Result<Vec<Samp>, String> {
    let mut p = Probe::connect(o)?;
    p.idle_sleep = Duration::from_micros(100);
    let pid = p
        .osdmap()
        .pool_id_by_name(&c.pool)
        .ok_or_else(|| format!("no pool '{}'", c.pool))?;
    let mut rng = Rng::new(0xD31E ^ (id << 32));
    let data: Vec<u8> = (0..c.size).map(|i| (i * 7 + id as usize) as u8).collect();
    let mut out = Vec::new();
    let mut written = vec![false; c.objs as usize];
    loop {
        let stopping = stop.load(Relaxed);
        if stopping && p.in_flight() == 0 {
            break;
        }
        while !stopping && p.in_flight() < c.qd {
            let i = rng.below(c.objs) as usize;
            let warm = t0.elapsed() < c.warm;
            let write = warm || !written[i] || rng.below(100) < c.write_pct;
            written[i] = true;
            let op = if write {
                OsdOp::writefull(data.clone())
            } else {
                OsdOp::read(0, c.size as u64)
            };
            let m = ScriptMsg {
                ops: vec![op],
                ..Default::default()
            };
            p.submit(
                target(pid, &format!("{}-{i}", c.prefix)),
                m,
                u64::from(write),
            )?;
        }
        for d in p.poll() {
            let bad = d
                .reply
                .as_ref()
                .is_none_or(|r| r.result < 0 || r.ops.iter().any(|x| x.rval < 0));
            out.push((
                d.submitted.duration_since(t0).as_micros() as u64,
                d.finished.duration_since(d.submitted).as_micros() as u64,
                (d.tag & 1) as u8,
                bad,
            ));
        }
    }
    Ok(out)
}

struct Win {
    name: &'static str,
    secs: f64,
    h: Hist,
    errs: u64,
}

type Top = (&'static str, i64, u8, u64);

fn render(wins: &[Win], del_rtt_ms: f64, top: &[Top], tl: &[Hist], fmt: outfmt::Format) -> String {
    let cls = |c: u8| if c == 1 { "write" } else { "read" };
    if fmt == outfmt::Format::Plain {
        let mut s = String::new();
        let _ = writeln!(s, "window secs ops_s p50_us p99_us p999_us max_us errs");
        for w in wins {
            let _ = writeln!(
                s,
                "{} {:.1} {:.0} {} {} {} {} {}",
                w.name,
                w.secs,
                w.h.n as f64 / w.secs.max(1e-9),
                w.h.pct(0.5),
                w.h.pct(0.99),
                w.h.pct(0.999),
                w.h.max,
                w.errs
            );
        }
        let _ = writeln!(s, "delete_rtt_ms {del_rtt_ms:.1}");
        let _ = writeln!(s, "timeline: second_after_delete ops p50_us p99_us max_us");
        for (i, h) in tl.iter().enumerate() {
            let _ = writeln!(s, "{i} {} {} {} {}", h.n, h.pct(0.5), h.pct(0.99), h.max);
        }
        let _ = writeln!(s, "slowest: window offset_ms class lat_us");
        for (w, off, c, l) in top {
            let _ = writeln!(s, "{w} {off} {} {l}", cls(*c));
        }
        return s;
    }
    let doc = serde_json::json!({
        "delete_rtt_ms": del_rtt_ms,
        "windows": wins.iter().map(|w| serde_json::json!({
            "window": w.name, "secs": w.secs, "n": w.h.n,
            "ops_s": w.h.n as f64 / w.secs.max(1e-9),
            "p50_us": w.h.pct(0.5), "p99_us": w.h.pct(0.99), "p999_us": w.h.pct(0.999),
            "max_us": w.h.max, "errs": w.errs,
        })).collect::<Vec<_>>(),
        "timeline": tl.iter().enumerate().map(|(i, h)| serde_json::json!({
            "s": i, "ops": h.n, "p50_us": h.pct(0.5), "p99_us": h.pct(0.99), "max_us": h.max,
        })).collect::<Vec<_>>(),
        "slowest": top.iter().map(|(w, off, c, l)| serde_json::json!({
            "window": w, "offset_ms": off, "class": cls(*c), "lat_us": l,
        })).collect::<Vec<_>>(),
    });
    let mut s = fmt.doc(&doc);
    s.push('\n');
    s
}

/// Entry point of `oprobe rmstall ...` (`a` = remaining args, `pool` = the global -p).
pub fn cli(a: Vec<String>, o: Opts, pool: Option<String>) -> Result<ExitCode, String> {
    let (fmt, mut a) = outfmt::extract(&a, false)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let prefix = take(&mut a, "--prefix")?.unwrap_or_else(|| format!("rmstall-{now:x}"));
    let victim = take(&mut a, "--delete")?.ok_or("rmstall: --delete POOL required")?;
    let c = Cfg {
        pool: pool.ok_or("rmstall: -p FGPOOL required")?,
        prefix,
        objs: num(&mut a, "--objs", 20_000)?,
        size: num(&mut a, "--size", 4096)?,
        qd: num_max(&mut a, "--qd", MAX_QD, 8)?,
        write_pct: num(&mut a, "--write-pct", 50)?,
        warm: secs(&mut a, "--warm", 3.0)?,
    };
    let clients: u64 = num_max(&mut a, "--clients", MAX_CLIENTS, 2)?;
    let at = secs(&mut a, "--at", 5.0)?;
    let during = secs(&mut a, "--during", 10.0)?;
    let after = secs(&mut a, "--after", 10.0)?;
    let ntop: usize = num(&mut a, "--top", 12)?;
    let keep = flag(&mut a, "--keep");
    if let Some(x) = a.first() {
        return Err(format!("rmstall: unknown argument '{x}'"));
    }
    if c.objs == 0 || c.qd == 0 || clients == 0 || c.write_pct > 100 || c.size == 0 {
        return Err(
            "rmstall: --objs, --qd, --clients, --size must be > 0, --write-pct <= 100".into(),
        );
    }
    let c = Arc::new(c);
    let mut mon = Probe::connect(o.clone())?;
    let t0 = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let hs: Vec<_> = (0..clients)
        .map(|i| {
            let (o, c, st) = (o.clone(), c.clone(), stop.clone());
            std::thread::spawn(move || worker(o, c, i, t0, st))
        })
        .collect();
    while t0.elapsed() < c.warm + at {
        mon.pump_for(Duration::from_millis(5));
    }
    let d0 = t0.elapsed();
    let del = mon.mon_command(&format!(
        r#"{{"prefix":"osd pool rm","pool":"{victim}","pool2":"{victim}","yes_i_really_really_mean_it":true}}"#
    ));
    let rtt = t0.elapsed().saturating_sub(d0).as_secs_f64() * 1e3;
    let del_ok = matches!(&del, Ok((0, _, _)));
    if !del_ok {
        eprintln!("rmstall: pool delete failed: {del:?}");
    }
    while t0.elapsed() < d0 + during + after {
        mon.pump_for(Duration::from_millis(5));
    }
    stop.store(true, Relaxed);
    let mut all: Vec<Samp> = Vec::new();
    let mut fatal = Vec::new();
    for h in hs {
        match h.join() {
            Ok(Ok(v)) => all.extend(v),
            Ok(Err(e)) => fatal.push(e),
            Err(_) => fatal.push("worker panicked".into()),
        }
    }
    if !keep && let Some(pid) = mon.osdmap().pool_id_by_name(&c.pool) {
        for i in 0..c.objs {
            let m = ScriptMsg {
                ops: vec![OsdOp::delete()],
                ..Default::default()
            };
            let _ = mon.exec(&target(pid, &format!("{}-{i}", c.prefix)), &m);
        }
    }
    let (w0, w1, w2) = (
        c.warm.as_micros() as u64,
        d0.as_micros() as u64,
        (d0 + during).as_micros() as u64,
    );
    let mk = |name, secs| Win {
        name,
        secs,
        h: Hist::new(),
        errs: 0,
    };
    let mut wins = [
        mk("before", (w1 - w0) as f64 / 1e6),
        mk("during", during.as_secs_f64()),
        mk("after", after.as_secs_f64()),
    ];
    let mut slow: Vec<(u64, u64, u8, usize)> = Vec::new();
    // one histogram per second after the delete command
    let mut tl: Vec<Hist> = (0..(during + after).as_secs() + 1)
        .map(|_| Hist::new())
        .collect();
    for (off, lat, cl, bad) in &all {
        if *off < w0 {
            continue;
        }
        if !*bad
            && *off >= w1
            && let Some(h) = tl.get_mut(((*off - w1) / 1_000_000) as usize)
        {
            h.rec(*lat);
        }
        let w = if *off < w1 {
            0
        } else if *off < w2 {
            1
        } else {
            2
        };
        if *bad {
            wins[w].errs += 1;
        } else {
            wins[w].h.rec(*lat);
            slow.push((*lat, *off, *cl, w));
        }
    }
    slow.sort_unstable_by_key(|x| std::cmp::Reverse(x.0));
    let top: Vec<Top> = slow
        .iter()
        .take(ntop)
        .map(|(l, off, cl, w)| (wins[*w].name, (*off as i64 - w1 as i64) / 1000, *cl, *l))
        .collect();
    print!("{}", render(&wins, rtt, &top, &tl, fmt));
    for f in &fatal {
        eprintln!("rmstall: fatal: {f}");
    }
    let errs: u64 = wins.iter().map(|w| w.errs).sum();
    Ok(if !fatal.is_empty() || errs > 0 || !del_ok {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_render_is_one_document() {
        let wins = [
            Win {
                name: "before",
                secs: 1.0,
                h: Hist::new(),
                errs: 0,
            },
            Win {
                name: "during",
                secs: 2.0,
                h: Hist::new(),
                errs: 1,
            },
            Win {
                name: "after",
                secs: 3.0,
                h: Hist::new(),
                errs: 0,
            },
        ];
        let s = render(
            &wins,
            4.5,
            &[("during", -3, 1, 9)],
            &[Hist::new()],
            outfmt::Format::Json,
        );
        let v: serde_json::Value = serde_json::from_str(&s).expect("valid JSON");
        assert_eq!(v["windows"][1]["window"], "during");
        assert_eq!(v["windows"][1]["errs"], 1);
        assert_eq!(v["slowest"][0]["class"], "write");
        assert_eq!(v["delete_rtt_ms"], 4.5);
    }
}
