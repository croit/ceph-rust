// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `bench --omapchurn N`: the omap removal shapes of the omapx recheck (doc/perf/omapx-recheck-20261024.md) at store
//! level, on one core, without network and replicas:
//!
//! * `churn`: CephFS dirfrag commits on ONE object of N dentries (cell `b-dir`): QD1 txns
//!   [omap_set_header, omap_set_vals(B new dentries) as a run, omap_rm_keys(B oldest dentries)], `--churn-ops` (200)
//!   per batch size of `--churn-batches` (16,256,1024).
//! * `rm`: a second object of N keys, removed as the omapx `b-rm-keys` / `b-rm-range` cells do: the lower half by
//!   listing pages of 1000 keys and removing each page with omap_rm_keys (QD1), the upper half by ONE
//!   omap_rm_key_range.
//!
//! Keys: dentry-like names (16 hex digits + `_head`, uniformly spread), values 400-600 B; populated by 1024-key batches
//! (`OmapSetRun`, QD4) like the OSD hands client batches to the store. Prints per phase: ops/s, keys/s, txn latency
//! p50 / p99 / max (queue -> ack) and the time of the bench thread per op in `queue` (stage + apply: the PG core's
//! share of a txn) and in `poll` (completion, maintenance, device). `--churn-phases churn,rm` selects phases. Ends with fsck.
use crate::bench::{St, arg, pgc, pgmeta};
use denc::types::{Ghobject, Hobject, ShardId, SnapId};
use std::time::Instant;
use store::obj::{OTxn, ObjError, TOp};

fn obj(name: &[u8]) -> Ghobject {
    Ghobject::new(
        Hobject::new(name, SnapId::NOSNAP, 0x4d49_5244, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// Dentry `i` of a directory: 16 hex digits + `_head` (key order unrelated to `i`).
fn key(i: u64) -> Vec<u8> {
    format!("{:016x}_head", mix(i)).into_bytes()
}

fn val(i: u64) -> Vec<u8> {
    let n = 400 + (mix(i ^ 0x5555) % 201) as usize;
    (0..n).map(|j| (mix(i + j as u64) & 0xff) as u8).collect()
}

fn run_of(keys: impl Iterator<Item = u64>) -> store::obj::KvRunData<'static> {
    let mut kv: Vec<(Vec<u8>, Vec<u8>)> = keys.map(|i| (key(i), val(i))).collect();
    kv.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let mut enc = Vec::new();
    denc::SortedKv::encode_into(
        &mut enc,
        kv.len(),
        kv.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
    );
    store::obj::KvRunData::from_encoding(enc.into()).expect("sorted batch")
}

/// Queue `t` and poll until it is acked: (latency us, ns in `queue` = stage + apply, ns in `poll` = completion,
/// maintenance and the device).
pub(crate) fn commit1(st: &mut St, t: &OTxn, tok: u64) -> Result<(u64, u64, u64), String> {
    let t0 = Instant::now();
    let (mut qns, mut pns) = (0u64, 0u64);
    let mut acked = Vec::new();
    loop {
        let tq = Instant::now();
        let r = st.queue(t, tok);
        qns += tq.elapsed().as_nanos() as u64;
        match r {
            Ok(_) => break,
            Err(ObjError::WouldBlock) => {
                let tp = Instant::now();
                st.poll(&mut acked).map_err(|e| e.to_string())?;
                pns += tp.elapsed().as_nanos() as u64;
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    loop {
        acked.clear();
        let tp = Instant::now();
        st.poll(&mut acked).map_err(|e| e.to_string())?;
        pns += tp.elapsed().as_nanos() as u64;
        if acked.contains(&tok) {
            return Ok((t0.elapsed().as_micros() as u64, qns, pns));
        }
    }
}

/// Populate `o` with keys `0..n` in 1024-key runs, 4 txns in flight.
fn populate(st: &mut St, o: &Ghobject, n: u64, tok: &mut u64) -> Result<(), String> {
    let c = pgc(0);
    let (mut issued, mut inflight) = (0u64, 0usize);
    let mut acked = Vec::new();
    while issued < n || inflight > 0 {
        while inflight < 4 && issued < n {
            let hi = (issued + 1024).min(n);
            let mut t = OTxn::new();
            t.push(TOp::OmapSetRun {
                cid: c,
                oid: o.clone(),
                run: run_of(issued..hi),
            });
            *tok += 1;
            match st.queue(&t, *tok) {
                Ok(_) => {
                    issued = hi;
                    inflight += 1;
                }
                Err(ObjError::WouldBlock) => break,
                Err(e) => return Err(format!("populate: {e}")),
            }
        }
        acked.clear();
        st.poll(&mut acked).map_err(|e| e.to_string())?;
        inflight -= acked.len();
    }
    Ok(())
}

struct Ph {
    lat: Vec<u64>,
    qns: u64,
    pns: u64,
    keys: u64,
    t0: Instant,
}

impl Ph {
    fn new() -> Ph {
        Ph {
            lat: Vec::new(),
            qns: 0,
            pns: 0,
            keys: 0,
            t0: Instant::now(),
        }
    }
    fn add(&mut self, (l, q, p): (u64, u64, u64), keys: u64) {
        self.lat.push(l);
        self.qns += q;
        self.pns += p;
        self.keys += keys;
    }
    fn line(mut self, name: &str) {
        let el = self.t0.elapsed().as_secs_f64();
        self.lat.sort_unstable();
        let n = self.lat.len().max(1);
        let p = |q: f64| self.lat[((n as f64 * q) as usize).min(n - 1)];
        println!(
            "omapchurn {name:<13} ops={:<5} ops/s={:<7.0} keys/s={:<8.0} p50={}us p99={}us max={}us queue={:.1}us/op poll={:.1}us/op queue/key={:.3}us",
            self.lat.len(),
            self.lat.len() as f64 / el,
            self.keys as f64 / el,
            p(0.5),
            p(0.99),
            self.lat.last().copied().unwrap_or(0),
            self.qns as f64 / 1e3 / n as f64,
            self.pns as f64 / 1e3 / n as f64,
            self.qns as f64 / 1e3 / self.keys.max(1) as f64,
        );
    }
}

pub(crate) fn run(st: &mut St, a: &[String]) -> Result<(), String> {
    let n: u64 = arg(a, "--omapchurn")
        .and_then(|s| s.parse().ok())
        .unwrap_or(250_000);
    let ops: u64 = arg(a, "--churn-ops")
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let batches: Vec<u64> = arg(a, "--churn-batches")
        .unwrap_or_else(|| "16,256,1024".into())
        .split(',')
        .map(|s| s.parse().map_err(|_| format!("bad batch {s}")))
        .collect::<Result<_, _>>()?;
    let phases = arg(a, "--churn-phases").unwrap_or_else(|| "churn,rm".into());
    let c = pgc(0);
    let (d, r) = (obj(b"omapchurn_dir"), obj(b"omapchurn_rm"));
    let mut t = OTxn::new();
    t.push(TOp::MkColl {
        cid: c,
        bits: 0,
        exist_ok: true,
    });
    t.touch(c, &pgmeta(0));
    t.touch(c, &d);
    t.touch(c, &r);
    st.commit(&t).map_err(|e| e.to_string())?;
    let mut tok = 0u64;
    if phases.split(',').any(|p| p == "churn") {
        let t0 = Instant::now();
        populate(st, &d, n, &mut tok)?;
        println!(
            "omapchurn populate {n} keys in {:.2}s",
            t0.elapsed().as_secs_f64()
        );
        // FIFO: dentries `del..ins` are live
        let (mut ins, mut del) = (n, 0u64);
        for &b in &batches {
            let mut ph = Ph::new();
            for hdr in 0..ops {
                let mut rm: Vec<Vec<u8>> = (del..del + b).map(key).collect();
                rm.sort_unstable();
                let mut t = OTxn::new();
                t.push(TOp::OmapSetHeader {
                    cid: c,
                    oid: d.clone(),
                    header: vec![hdr as u8; 232].into(),
                });
                t.push(TOp::OmapSetRun {
                    cid: c,
                    oid: d.clone(),
                    run: run_of(ins..ins + b),
                });
                t.push(TOp::OmapRmKeys {
                    cid: c,
                    oid: d.clone(),
                    keys: rm.into_iter().map(Into::into).collect(),
                });
                tok += 1;
                ph.add(commit1(st, &t, tok)?, b);
                ins += b;
                del += b;
            }
            ph.line(&format!("commit-b{b}"));
        }
        let got = st.scrub(&c, &d, 0).map_err(|e| e.to_string())?.omap_keys;
        if got != ins - del {
            return Err(format!("dir omap keys {got}, expected {}", ins - del));
        }
    }
    if phases.split(',').any(|p| p == "rm") {
        populate(st, &r, n, &mut tok)?;
        // lower half: list pages of 1000 and remove each page (omapx b-rm-keys)
        let mut ph = Ph::new();
        let mut from = Vec::new();
        loop {
            let (kv, more) = st
                .omap_iter(&c, &r, &from, 1000)
                .map_err(|e| e.to_string())?;
            let ks: Vec<Vec<u8>> = kv
                .iter()
                .map(|(k, _)| k.to_vec())
                .filter(|k| k.as_slice() < b"8".as_slice())
                .collect();
            if ks.is_empty() {
                break;
            }
            let nk = ks.len() as u64;
            from = ks.last().unwrap().clone();
            from.push(0);
            let mut t = OTxn::new();
            t.push(TOp::OmapRmKeys {
                cid: c,
                oid: r.clone(),
                keys: ks.into_iter().map(Into::into).collect(),
            });
            tok += 1;
            ph.add(commit1(st, &t, tok)?, nk);
            if !more || (nk as usize) < kv.len() {
                break;
            }
        }
        let gone = ph.keys;
        ph.line("rm-keys");
        // upper half: one range removal (omapx b-rm-range)
        let runs: usize = st.shards.iter().map(|s| s.sh.state().runs.entries()).sum();
        let mut ph = Ph::new();
        let mut t = OTxn::new();
        t.push(TOp::OmapRmKeyRange {
            cid: c,
            oid: r.clone(),
            first: b"8".to_vec().into(),
            last: b"g".to_vec().into(),
        });
        tok += 1;
        ph.add(commit1(st, &t, tok)?, n - gone);
        ph.line("rm-range");
        println!("omapchurn rm-range run_entries_before={runs}");
        let left = st.scrub(&c, &r, 0).map_err(|e| e.to_string())?;
        if (left.omap_keys, left.omap_bytes) != (0, 0) {
            return Err(format!(
                "rm object omap (keys, bytes) {:?} after removing every key",
                (left.omap_keys, left.omap_bytes)
            ));
        }
    }
    let rep = st.check(true).map_err(|e| e.to_string())?;
    println!("omapchurn fsck: errors={}", rep.errors.len());
    if rep.errors.is_empty() {
        Ok(())
    } else {
        Err(format!("fsck: {:?}", rep.errors))
    }
}
