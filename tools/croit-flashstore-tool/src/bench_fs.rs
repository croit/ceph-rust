// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! CephFS-shaped store benchmarks (doc/spec/cephfs-gap.md G3/G4), engine level, real device:
//!
//!   croit-flashstore-tool bench --dev spdk:PCI --fs jrnl4k:1,jrnl4k:8,jrnl64k:1,jrnlmix:4,dirfrag [--cpu N] [--secs 5] [--keys 10000]
//!                      [--format-lba4k]     DESTROYS the device (fresh mkfs), like `bench`
//!   `jrnlSZ:QD`  MDS journal: byte-granular (unaligned) appends of SZ (4k = 4000 B, 64k = 65000 B, mix = 1 KiB..64 KiB
//!                log-uniform) to consecutive 4 MiB objects, QD appends in flight, OSD-like txn (object_info attr + pg-log
//!                key + trim), old journal objects removed (trim) as the writer moves on. Reports append latency; the
//!                size seen by `stat` after the run must equal the acked end.
//!   `dirfrag`    dirfrag omap objects (`<name>_head` keys, 0.5-5 KB values): build by 10 MiB batches, commit churn
//!                (rm-keys + set + header, 1/16/256 dirty dentries, QD1 and QD8 over 4 objects), paged fetch (1024 keys
//!                per page), delete of the whole object (the longest single store call = core stall).
use crate::bench::*;
use std::rc::Rc;
use std::time::Instant;
use store::obj::{OTxn, TOp};
use store::rng::Rng;

const MIB: usize = 1 << 20;

/// A whole-dirfrag delete is the longest store call of the churn phase; a store that does not ack it cannot be measured
/// (the numbers would be of a stuck core).
const DELETE_ACK_LIMIT_S: u64 = 60;

/// In-flight window (and token ring size) of a journal mode: one issued store op per slot, as `bench` itself caps it.
const QD_MAX: usize = 4096;

struct Lat(Vec<u32>);
impl Lat {
    fn line(&mut self, name: &str, secs: f64, bytes: u64) {
        self.0.sort_unstable();
        let n = self.0.len().max(1) as f64;
        println!(
            "{:<22} n={:<8} {:>9.0}/s {:>8.1} MB/s  p50={:>6}us p90={:>6}us p99={:>6}us p99.9={:>6}us max={:>7}us",
            name,
            self.0.len(),
            n / secs,
            bytes as f64 / secs / 1e6,
            pct(&self.0, 0.5),
            pct(&self.0, 0.9),
            pct(&self.0, 0.99),
            pct(&self.0, 0.999),
            self.0.last().copied().unwrap_or(0),
        );
    }
}

/// A journal mode with `qd == 0` issues nothing and waits for appends that never come; `secs == 0` ends the run before
/// the first append (then there is no object to stat). Both are usage errors, not measurements, as is a `qd` above the
/// in-flight window (the run cannot hold that many tokens: the latency of a token would be another token's).
fn check_journal_args(qd: usize, secs: f64, m: &str) -> Result<(), String> {
    if qd == 0 {
        return Err(format!("--fs {m}: qd 0 never issues an append"));
    }
    if qd > QD_MAX {
        return Err(format!(
            "--fs {m}: qd {qd} is above the {QD_MAX}-slot in-flight window"
        ));
    }
    if secs <= 0.0 {
        return Err(format!("--fs {m}: --secs {secs} runs no append"));
    }
    Ok(())
}

pub fn run(a: &[String], modes: &str) -> Result<(), String> {
    let ctrl = open_ctrl(a, true)?;
    let cn = Rc::new(Counters::default());
    let (_ctrl, mut st) = make_store(a, ctrl, &cn)?;
    let secs = fnum(a, "--secs", 5.0)?;
    let keys = num(a, "--keys", 10_000)? as usize;
    let mut data = vec![0u8; 8 * MIB];
    fill_pattern(&mut data, 42);
    let pgs = 4u32;
    for pg in 0..pgs {
        let mut t = OTxn::new();
        t.push(TOp::MkColl {
            cid: pgc(pg),
            bits: 0,
            exist_ok: true,
        });
        t.touch(pgc(pg), &pgmeta(pg));
        st.commit(&t).map_err(|e| e.to_string())?;
    }
    for m in modes.split(',') {
        let (n, qd) = m.split_once(':').unwrap_or((m, "1"));
        let qd: usize = qd.parse().map_err(|_| format!("bad mode {m}"))?;
        match n {
            "jrnl4k" => {
                check_journal_args(qd, secs, m)?;
                journal(&mut st, &cn, &data, m, Sz::Fixed(4000), qd, secs)?;
            }
            "jrnl64k" => {
                check_journal_args(qd, secs, m)?;
                journal(&mut st, &cn, &data, m, Sz::Fixed(65_000), qd, secs)?;
            }
            "jrnlmix" => {
                check_journal_args(qd, secs, m)?;
                journal(&mut st, &cn, &data, m, Sz::LogUniform, qd, secs)?;
            }
            "dirfrag" => dirfrag(&mut st, &cn, &data, keys, secs)?,
            _ => return Err(format!("bad --fs mode {m}")),
        }
    }
    let rep = st.check(true).map_err(|e| e.to_string())?;
    println!(
        "check after bench: errors={} {:?}",
        rep.errors.len(),
        st.statfs()
    );
    Ok(())
}

#[derive(Clone, Copy)]
enum Sz {
    Fixed(usize),
    LogUniform,
}

fn jname(i: u64) -> denc::types::Ghobject {
    obj(&format!("200.{i:08x}"), 0)
}

/// One MDS journal: appends at consecutive byte positions, never crossing a 4 MiB object (the tail is its own
/// smaller append, as the Journaler splits a flush at the object boundary).
fn journal(
    st: &mut St,
    cn: &Counters,
    data: &[u8],
    name: &str,
    sz: Sz,
    qd: usize,
    secs: f64,
) -> Result<(), String> {
    let mut rng = Rng::new(11);
    let c = pgc(0);
    let pgm = pgmeta(0);
    let (w0, r0) = (cn.wr.get(), cn.rd.get());
    let t0 = Instant::now();
    let (mut pos, mut seq) = (0u64, 0u64);
    let mut inflight = 0usize;
    // token -> (issue ns, bytes), indexed `tok % qd`: at most `qd` tokens are in flight and token ids are consecutive,
    // so two live tokens never share a slot whatever `qd` the mode names
    let mut issue: Vec<(u64, u64)> = vec![(0, 0); qd];
    let mut tok = 0u64;
    let mut lat = Lat(Vec::new());
    let (mut bytes, mut removes, mut last_obj) = (0u64, 0u64, 0u64);
    let mut rm_tokens = std::collections::BTreeSet::new();
    let mut acked = Vec::new();
    let mut max_call = 0u128;
    let end_ns = (secs * 1e9) as u64;
    let mut stopped = false;
    loop {
        let now = t0.elapsed().as_nanos() as u64;
        // the run always issues its first append: the stat check at the end needs an object to measure
        if now >= end_ns && seq > 0 {
            stopped = true;
        }
        while !stopped && inflight < qd {
            let io = match sz {
                Sz::Fixed(n) => n,
                Sz::LogUniform => {
                    let l = (rng.below(1000) as f64 / 1000.0 * (65536f64 / 1024.0).ln()).exp();
                    (1024.0 * l) as usize
                }
            };
            let in_obj = pos % OBJ_BYTES as u64;
            let len = io.min(OBJ_BYTES - in_obj as usize);
            let (oi, off) = (pos / OBJ_BYTES as u64, in_obj);
            let o = jname(oi);
            let shift = (rng.next_u64() as usize & 0xffff) & !7usize;
            let mut t = OTxn::new();
            t.write(c, &o, off, &data[shift..shift + len]);
            seq += 1;
            let (mut k1, mut k2) = ([0u8; 24], [0u8; 24]);
            log_key(&mut k1, seq);
            log_key(&mut k2, seq.saturating_sub(300));
            t.push(TOp::SetAttrs {
                cid: c,
                oid: o.clone(),
                attrs: vec![
                    (b"_".as_slice().into(), data[..250].into()),
                    (b"snapset".as_slice().into(), data[250..282].into()),
                ],
            });
            t.push(TOp::OmapSetKeys {
                cid: c,
                oid: pgm.clone(),
                pairs: vec![(k1.as_slice().into(), data[256..436].into())],
            });
            t.push(TOp::OmapRmKeys {
                cid: c,
                oid: pgm.clone(),
                keys: vec![k2.as_slice().into()],
            });
            tok += 1;
            let tq = Instant::now();
            let ti = t0.elapsed().as_nanos() as u64;
            st.queue(&t, tok).map_err(|e| format!("queue: {e}"))?;
            max_call = max_call.max(tq.elapsed().as_micros());
            issue[tok as usize % qd] = (ti, len as u64);
            inflight += 1;
            pos += len as u64;
            // writer entered a new object: trim the one 4 objects behind (Filer::purge_range)
            if oi > last_obj {
                last_obj = oi;
                if oi >= 4 {
                    let mut t = OTxn::new();
                    t.push(TOp::Remove {
                        cid: c,
                        oid: jname(oi - 4),
                    });
                    tok += 1;
                    let tq = Instant::now();
                    let ti = t0.elapsed().as_nanos() as u64;
                    st.queue(&t, tok).map_err(|e| format!("queue rm: {e}"))?;
                    max_call = max_call.max(tq.elapsed().as_micros());
                    issue[tok as usize % qd] = (ti, 0);
                    rm_tokens.insert(tok);
                    inflight += 1;
                    removes += 1;
                }
            }
        }
        loop_pause();
        acked.clear();
        st.poll(&mut acked).map_err(|e| format!("poll: {e}"))?;
        let now = t0.elapsed().as_nanos() as u64;
        for &tk in &acked {
            let (ti, b) = issue[tk as usize % qd];
            inflight -= 1;
            if !rm_tokens.remove(&tk) {
                lat.0.push(((now - ti) / 1000) as u32);
                bytes += b;
            }
        }
        if stopped && inflight == 0 {
            break;
        }
    }
    let secs = t0.elapsed().as_secs_f64();
    let n = lat.0.len().max(1) as f64;
    lat.line(name, secs, bytes);
    println!(
        "    wr_cmd/append={:.2} rd_cmd/append={:.2} removes={removes} longest store call={}us",
        (cn.wr.get() - w0) as f64 / n,
        (cn.rd.get() - r0) as f64 / n,
        max_call
    );
    // stat size after the run = exact end of the last object (acked == issued here)
    let last = (pos - 1) / OBJ_BYTES as u64;
    let want = pos - last * OBJ_BYTES as u64;
    let got = st
        .stat(&c, &jname(last))
        .map_err(|e| e.to_string())?
        .map(|s| s.size);
    println!(
        "    stat size of newest journal object = {got:?}, acked end = {want}: {}",
        if got == Some(want) {
            "EXACT"
        } else {
            "MISMATCH"
        }
    );
    if got != Some(want) {
        return Err("stat size != acked end".into());
    }
    // cleanup: remove every journal object so the next mode starts empty
    let mut t = OTxn::new();
    for i in last.saturating_sub(4)..=last {
        t.push(TOp::Remove {
            cid: c,
            oid: jname(i),
        });
    }
    st.commit(&t).map_err(|e| e.to_string())?;
    Ok(())
}

fn dname(i: usize) -> denc::types::Ghobject {
    obj(&format!("1000000{i:04x}.00000000"), 1)
}

fn dkey(rng: &mut Rng, i: usize) -> Vec<u8> {
    // `<name>_head`, names 12-60 bytes, unique by the index prefix
    let extra = rng.range(0, 48) as usize;
    let mut k = format!("f{i:07}-").into_bytes();
    k.extend(std::iter::repeat_n(b'x', 4 + extra));
    k.extend_from_slice(b"_head");
    k
}

fn dirfrag(st: &mut St, cn: &Counters, data: &[u8], keys: usize, secs: f64) -> Result<(), String> {
    let c = pgc(1);
    let mut t = OTxn::new();
    t.push(TOp::MkColl {
        cid: c,
        bits: 0,
        exist_ok: true,
    });
    st.commit(&t).map_err(|e| e.to_string())?;
    let mut rng = Rng::new(5);
    let nobj = 4usize;
    // ---- build: nobj dirfrags, keys in ~10 MiB batches (one txn each)
    let mut all: Vec<Vec<Vec<u8>>> = Vec::new();
    let tb = Instant::now();
    let mut built_bytes = 0u64;
    let mut lat = Lat(Vec::new());
    for oi in 0..nobj {
        let o = dname(oi);
        let mut t = OTxn::new();
        t.touch(c, &o);
        st.commit(&t).map_err(|e| e.to_string())?;
        let mut ks: Vec<Vec<u8>> = (0..keys).map(|i| dkey(&mut rng, i)).collect();
        ks.sort();
        for chunk in ks.chunks(4000) {
            let mut pairs = Vec::new();
            let mut b = 0usize;
            for k in chunk {
                let vl = rng.range(500, 5000) as usize;
                let off = rng.below((data.len() - vl) as u64) as usize;
                b += k.len() + vl;
                pairs.push((k.clone().into(), data[off..off + vl].into()));
            }
            let mut t = OTxn::new();
            t.push(TOp::OmapSetKeys {
                cid: c,
                oid: o.clone(),
                pairs,
            });
            let t1 = Instant::now();
            st.commit(&t).map_err(|e| format!("build batch: {e}"))?;
            lat.0.push(t1.elapsed().as_micros() as u32);
            built_bytes += b as u64;
        }
        all.push(ks);
    }
    lat.line(
        &format!("dirfrag build {keys}k x{nobj}"),
        tb.elapsed().as_secs_f64(),
        built_bytes,
    );
    st.sync().map_err(|e| e.to_string())?;
    // ---- commit churn: dirty dentries per commit
    for (dirty, qd) in [(1usize, 1usize), (16, 1), (256, 1), (16, 8), (256, 8)] {
        let mut lat = Lat(Vec::new());
        let t0 = Instant::now();
        let mut inflight = 0;
        // token -> issue ns, `tok % qd` (at most `qd` in flight, consecutive ids: no live slot is overwritten)
        let mut issue = vec![0u64; qd];
        let mut tok = 0u64;
        let mut bytes = 0u64;
        let mut acked = Vec::new();
        let mut hdr = 1u8;
        loop {
            let now = t0.elapsed().as_nanos() as u64;
            let stop = now as f64 >= secs * 1e9;
            while !stop && inflight < qd {
                let oi = rng.below(nobj as u64) as usize;
                let o = dname(oi);
                let ks = &all[oi];
                let mut t = OTxn::new();
                let mut rm = Vec::new();
                let mut pairs = Vec::new();
                for j in 0..dirty {
                    let k = ks[rng.below(ks.len() as u64) as usize].clone();
                    if j % 4 == 3 {
                        rm.push(k.into());
                    } else {
                        let vl = rng.range(500, 5000) as usize;
                        let off = rng.below((data.len() - vl) as u64) as usize;
                        bytes += (k.len() + vl) as u64;
                        pairs.push((k.into(), data[off..off + vl].into()));
                    }
                }
                if !rm.is_empty() {
                    t.push(TOp::OmapRmKeys {
                        cid: c,
                        oid: o.clone(),
                        keys: rm,
                    });
                }
                t.push(TOp::OmapSetKeys {
                    cid: c,
                    oid: o.clone(),
                    pairs,
                });
                hdr = hdr.wrapping_add(1);
                t.push(TOp::OmapSetHeader {
                    cid: c,
                    oid: o.clone(),
                    header: vec![hdr; 350].into(),
                });
                tok += 1;
                let ti = t0.elapsed().as_nanos() as u64;
                st.queue(&t, tok).map_err(|e| format!("churn queue: {e}"))?;
                issue[tok as usize % qd] = ti;
                inflight += 1;
            }
            loop_pause();
            acked.clear();
            st.poll(&mut acked).map_err(|e| format!("poll: {e}"))?;
            let now = t0.elapsed().as_nanos() as u64;
            for &tk in &acked {
                lat.0.push(((now - issue[tk as usize % qd]) / 1000) as u32);
                inflight -= 1;
            }
            if stop && inflight == 0 {
                break;
            }
        }
        lat.line(
            &format!("dirfrag commit d={dirty} QD{qd}"),
            t0.elapsed().as_secs_f64(),
            bytes,
        );
    }
    // ---- paged fetch like CDir::fetch: header + 1024 keys per request
    for round in 0..2 {
        let o = dname(0);
        let mut lat = Lat(Vec::new());
        let (mut n, mut b) = (0usize, 0u64);
        let t0 = Instant::now();
        let mut from = Vec::new();
        let mut rd0 = cn.rd.get();
        loop {
            let t1 = Instant::now();
            let _ = st.omap_header(&c, &o).map_err(|e| e.to_string())?;
            let (kv, more) = st
                .omap_iter(&c, &o, &from, 1024)
                .map_err(|e| e.to_string())?;
            lat.0.push(t1.elapsed().as_micros() as u32);
            n += kv.len();
            b += kv
                .iter()
                .map(|(k, v)| (k.len() + v.len()) as u64)
                .sum::<u64>();
            if let Some((k, _)) = kv.last() {
                from = [k.as_slice(), &[0]].concat();
            }
            if !more {
                break;
            }
        }
        lat.line(
            &format!("dirfrag fetch pass{round} ({n} keys)"),
            t0.elapsed().as_secs_f64(),
            b,
        );
        rd0 = cn.rd.get() - rd0;
        println!("    device reads this pass: {rd0}");
    }
    // ---- delete of a whole dirfrag: the longest store call is the stall of the owning core
    for (oi, obj_keys) in all.iter().enumerate().take(nobj) {
        let o = dname(oi);
        let mut t = OTxn::new();
        t.remove(c, &o);
        let tq = Instant::now();
        st.queue(&t, 1).map_err(|e| format!("delete queue: {e}"))?;
        let qus = tq.elapsed().as_micros();
        let mut acked = Vec::new();
        let (mut polls, mut maxpoll) = (0u32, 0u128);
        while acked.is_empty() {
            let tp = Instant::now();
            st.poll(&mut acked).map_err(|e| e.to_string())?;
            maxpoll = maxpoll.max(tp.elapsed().as_micros());
            polls += 1;
            if tq.elapsed().as_secs() >= DELETE_ACK_LIMIT_S {
                eprintln!(
                    "WARNING TIMEOUT dirfrag delete ack exceeded {DELETE_ACK_LIMIT_S}s ({} keys of {}, {polls} polls)",
                    obj_keys.len(),
                    oi
                );
                return Err(format!(
                    "dirfrag delete of {} ({} keys) got no ack within {DELETE_ACK_LIMIT_S}s",
                    oi,
                    obj_keys.len()
                ));
            }
        }
        println!(
            "dirfrag delete {} keys: queue call {qus} us, ack after {} us, {polls} polls (longest {maxpoll} us)",
            obj_keys.len(),
            tq.elapsed().as_micros()
        );
    }
    Ok(())
}
