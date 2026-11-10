// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `bench --omapfill N`: populate ONE object's omap with N random keys (omapbench group A, open question 44): batches of
//! `--omap-batch` (1024) random 64 B hex keys with incompressible 256 B values per txn (the oprobe omapbench shape), `--qd` (4) txns in flight, each with an OSD-like pg log
//! entry on the pgmeta object. Prints per interval: keys, keys/s, store used bytes and bytes per key, dirty pages,
//! checkpoints, held bytes, and per key of the interval: device bytes written / read, checkpoint pages, WAL bytes,
//! `queue` (stage + apply) and checkpoint-start CPU on the core, dirty-hard refusals; at the end fsck + the used bytes
//! after a final checkpoint. `--cache-pages N` (bench.rs) sets the tree cache per shard and the run budget the daemon gives that cache; `--store-mem MiB` sizes the
//! store like the daemon from that budget (cache, dirty marks, run budget; e.g. 722 = one shard of a zen4 gate OSD).
//! Txn latency (queue -> ack): the worst of each interval (`lat_max`) and p50 / p99 / max at the end (the OSD gate's
//! per-batch latency without network and replicas); `NV_DIAG=1` adds the longest store sections per interval
//! (`store::diag`). Store-only latency repro of the single-object populate: `--every 0.005` (doc/perf/omap-merge-pacing-20261024.md).
//! `--omap-ranks R`: oprobe omapgate insert keys instead of random ones (ascending blocks per rank, batches round-robin
//! over R ranks: R = 1 = benchmark cell s2's key order, R = 8 = s3's).
//! `--idle-drain`: after the populate no drain request: the shards' own idle-object merges must take every run (interval lines
//! go on until they did).
//! `--helpers`: the store dispatches run compactions as helper jobs (adr 0534, as on an OSD with more than one core and
//! `flashstore_store_compact_helpers`); the bench steps the one job in flight on the same thread after each poll (the
//! helper core's quantum: 8 steps of 256 input entries) and prints the time spent in it apart (`helper_ms`): owner and
//! helper CPU per key without cross-core effects.
//! `--omap-vals rgw`: values shaped like RGW bucket index entries (~250 B, compressible with a value dictionary) instead of
//! random bytes, and before the populate `DICT_SAMPLES + 2` single-key puts of such values on the object (tree path), so the
//! store trains and installs the class dictionary as on an OSD: tree merges then compress the merged values (adr 0476
//! "Merged values"), which random values never trigger. Keys are the same as without it.
use crate::bench::{Counters, St, arg, flag, log_key, pgc, pgmeta};
use denc::types::{Ghobject, Hobject, ShardId, SnapId};
use std::time::Instant;
use store::obj::{OTxn, TOp};
use store::rng::Rng;

pub(crate) fn run(st: &mut St, cn: &Counters, a: &[String]) -> Result<(), String> {
    let n: u64 = arg(a, "--omapfill")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);
    let batch: usize = arg(a, "--omap-batch")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1024);
    let qd: usize = arg(a, "--qd").and_then(|s| s.parse().ok()).unwrap_or(4);
    let vlen: usize = arg(a, "--omap-vlen")
        .and_then(|s| s.parse().ok())
        .unwrap_or(256);
    let every: f64 = arg(a, "--every")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1.0);
    // `--omap-ranks R`: the oprobe omapgate insert shape instead of random keys: key = 64 hex digits of
    // `(rank << 40) | local`, each batch the next `batch` locals of one rank, batches round-robin over the R ranks
    // (R = 1: one client's ascending inserts, gate cell s2; R = 8: eight clients on one object, s3)
    let ranks: Option<u64> = match arg(a, "--omap-ranks") {
        None => None,
        Some(r) => Some(
            r.parse()
                .ok()
                .filter(|&r| r > 0)
                .ok_or("--omap-ranks: positive integer")?,
        ),
    };
    let mut next_local = vec![0u64; ranks.unwrap_or(0) as usize];
    let mut next_rank = 0usize;
    let rgw = match arg(a, "--omap-vals").as_deref() {
        None | Some("random") => false,
        Some("rgw") => true,
        Some(x) => return Err(format!("--omap-vals {x}: random | rgw")),
    };
    let c = pgc(0);
    let mut t = OTxn::new();
    t.push(TOp::MkColl {
        cid: c,
        bits: 0,
        exist_ok: true,
    });
    t.touch(c, &pgmeta(0));
    let o = Ghobject::new(
        Hobject::new(b"omapbench_A_0", SnapId::NOSNAP, 0x1234_5678, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    );
    t.touch(c, &o);
    st.commit(&t).map_err(|e| e.to_string())?;
    let mut vr = Rng::new(45);
    if rgw {
        // the class dictionary: trained at the DICT_SAMPLES-th tree-path value, installed by the next one
        for i in 0..store::obj::onode::DICT_SAMPLES as u64 + 2 {
            let mut t = OTxn::new();
            t.push(TOp::OmapSetKeys {
                cid: c,
                oid: o.clone(),
                pairs: vec![(
                    format!("!dict-{i:04}").into_bytes().into(),
                    rgw_entry(&mut vr, i).into(),
                )],
            });
            st.commit(&t).map_err(|e| e.to_string())?;
        }
    }
    st.sync().map_err(|e| e.to_string())?;
    let base = st.statfs().used_bytes;
    let wr_base = cn.wr_lbas.get();
    let mut rng = Rng::new(44);
    let val = vec![0x5au8; vlen];
    let (mut issued, mut done_keys, mut inflight, mut tok, mut log) =
        (0u64, 0u64, 0usize, 0u64, 0u64);
    let mut keys_of = std::collections::HashMap::new();
    let mut acked = Vec::new();
    let t0 = Instant::now();
    let mut next = every;
    let mut last = (0u64, 0.0f64);
    let mut peak = 0u64;
    // txn latency queue -> ack (us): all, and the worst one of the current interval
    let (mut lats, mut lat_max) = (Vec::with_capacity((n as usize).div_ceil(batch)), 0u64);
    let helpers = flag(a, "--helpers");
    let mut job: Option<store::shard::HelperJob> = None;
    let mut hns = 0u64;
    // one poll of the helper core (`Osd::poll_compaction`): take the dispatched job, one quantum, return it when done
    let pump = |st: &mut St, job: &mut Option<store::shard::HelperJob>, hns: &mut u64| {
        if job.is_none() {
            *job = st.take_compaction();
        }
        let Some(j) = job else {
            return;
        };
        let t = Instant::now();
        let done = (0..8).any(|_| j.step(256));
        *hns += t.elapsed().as_nanos() as u64;
        if done {
            st.return_compaction(job.take().unwrap(), true);
        }
    };
    // cumulative counters at the last report: device write / read LBAs, ckpt pages, WAL bytes, queue ns, ckpt sync ns,
    // dirty-hard refusals
    #[derive(Default, Clone, Copy)]
    struct Cum {
        wr: u64,
        rd: u64,
        ckp: u64,
        wal: u64,
        qns: u64,
        cks: u64,
        hard: u64,
        /// meta space refusals, of those while a freeze held back the meta growth
        meta: u64,
        mrun: u64,
        mck: u64,
        /// omap runs (adr 0476): merge slices, entries merged, refused merge / re-log txns, merges that waited for a
        /// checkpoint, queued txns that waited for run room, re-logs
        mg: u64,
        mge: u64,
        mgr: u64,
        mgw: u64,
        rwait: u64,
        rl: u64,
        /// run compactions (adr 0476 step 4) and their output entries
        cp: u64,
        cpe: u64,
        /// tree merges started by trigger: drain, soft size, ring floor, idle
        why: [u64; 4],
        miss: u64,
        missp: u64,
    }
    let lba = 4096f64;
    let cum = |st: &St, qns: u64| {
        let mut c = Cum {
            wr: cn.wr_lbas.get(),
            rd: cn.rd_lbas.get(),
            qns,
            ..Cum::default()
        };
        for s in &st.shards {
            let x = &s.sh.stats;
            c.ckp += x.ckpt_pages;
            c.wal += x.wal_bytes;
            c.cks += x.ckpt_sync_ns;
            c.hard += x.busy[2];
            c.meta += x.busy[3];
            c.mrun += x.busy_meta_run;
            c.mck += x.busy_meta_ckpt;
            c.mg += x.run_merges;
            c.mge += x.run_merged_ents;
            c.mgr += x.run_txn_refused;
            c.mgw += x.run_merge_waits;
            c.rl += x.run_relogs;
            c.cp += x.run_compactions;
            c.cpe += x.run_compacted_ents;
            for i in 0..4 {
                c.why[i] += x.run_merge_starts[i];
            }
            c.miss += x.run_merge_miss;
            c.missp += x.run_merge_miss_pages;
            c.rwait += s.stats.run_waits;
        }
        c
    };
    let mut qns = 0u64;
    let mut prev = cum(st, 0);
    let report = |st: &St,
                  lat_max: &mut u64,
                  done_keys: u64,
                  el: f64,
                  last: &mut (u64, f64),
                  peak: &mut u64,
                  prev: &mut Cum,
                  qns: u64| {
        let f = st.statfs();
        let used = f.used_bytes.saturating_sub(base);
        *peak = (*peak).max(used);
        let (dirty, ck) = st.shards.iter().fold((0u64, 0u64), |a, s| {
            (
                a.0 + s.sh.gauges().dirty_pages,
                a.1 + s.sh.stats.checkpoints,
            )
        });
        let c = cum(st, qns);
        let dk = (done_keys - last.0).max(1) as f64;
        println!(
            "omapfill t={el:.3}s keys={done_keys} keys/s={:.0} lat_max={}us used={:.0}MiB B/key={:.0} held={:.0}MiB meta_pages={} dirty={dirty} ckpts={ck} | per key: wr={:.0}B rd={:.0}B ckpt_pages={:.3} wal={:.0}B queue={:.2}us ckpt_sync={:.2}us | hard_busy={} meta_busy={} (run {} ckpt {}) | runs: live={} slices={} merged={} refused={} (miss {} pages {}) ckpt_waits={} run_waits={} relogs={} runs_n={} compactions={} compacted={} merge_starts(drain/soft/floor/idle)={:?}",
            (done_keys - last.0) as f64 / (el - last.1).max(1e-9),
            std::mem::take(lat_max),
            used as f64 / 1048576.0,
            used as f64 / done_keys.max(1) as f64,
            f.held_bytes as f64 / 1048576.0,
            f.meta_used_pages,
            (c.wr - prev.wr) as f64 * lba / dk,
            (c.rd - prev.rd) as f64 * lba / dk,
            (c.ckp - prev.ckp) as f64 / dk,
            (c.wal - prev.wal) as f64 / dk,
            (c.qns - prev.qns) as f64 / 1e3 / dk,
            (c.cks - prev.cks) as f64 / 1e3 / dk,
            c.hard - prev.hard,
            c.meta - prev.meta,
            c.mrun - prev.mrun,
            c.mck - prev.mck,
            st.shards
                .iter()
                .map(|s| s.sh.state().runs.entries())
                .sum::<usize>(),
            c.mg - prev.mg,
            c.mge - prev.mge,
            c.mgr - prev.mgr,
            c.miss - prev.miss,
            c.missp - prev.missp,
            c.mgw - prev.mgw,
            c.rwait - prev.rwait,
            c.rl - prev.rl,
            st.shards
                .iter()
                .map(|s| s.sh.state().runs.n_runs())
                .sum::<usize>(),
            c.cp - prev.cp,
            c.cpe - prev.cpe,
            c.why,
        );
        if store::diag::on() {
            println!("omapfill diag t={el:.3}s {}", store::diag::take_all());
        }
        *prev = c;
        *last = (done_keys, el);
    };
    while done_keys < n {
        while inflight < qd && issued < n {
            let k = (batch as u64).min(n - issued);
            let mut t = OTxn::new();
            let seq = (!next_local.is_empty()).then(|| {
                let r = next_rank;
                next_rank = (next_rank + 1) % next_local.len();
                let l = next_local[r];
                next_local[r] += k;
                ((r as u64) << 40) | l
            });
            let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..k)
                .map(|j| {
                    // omapbench shape: 64 random hex digits, incompressible value
                    const H: &[u8; 16] = b"0123456789abcdef";
                    let mut key = Vec::with_capacity(64);
                    if let Some(id0) = seq {
                        key = format!("{:064x}", id0 + j).into_bytes();
                    } else {
                        for _ in 0..4 {
                            let w = rng.next_u64();
                            key.extend((0..16).map(|i| H[(w >> (i * 4) & 15) as usize]));
                        }
                    }
                    let mut v = vec![0u8; vlen];
                    for ch in v.chunks_mut(8) {
                        let w = rng.next_u64().to_le_bytes();
                        ch.copy_from_slice(&w[..ch.len()]);
                    }
                    if rgw {
                        v = rgw_entry(&mut vr, issued + j);
                    }
                    (key, v)
                })
                .collect();
            // a client batch is a map: sorted, unique keys, one buffer (the OSD hands the store a run)
            pairs.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            pairs.dedup_by(|a, b| a.0 == b.0);
            let mut enc = Vec::new();
            denc::SortedKv::encode_into(
                &mut enc,
                pairs.len(),
                pairs.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
            );
            t.push(TOp::OmapSetRun {
                cid: c,
                oid: o.clone(),
                run: store::obj::KvRunData::from_encoding(enc.into()).expect("sorted batch"),
            });
            log += 1;
            let mut lk = [0u8; 24];
            log_key(&mut lk, log);
            let mut ok = [0u8; 24];
            log_key(&mut ok, log.saturating_sub(300));
            t.push(TOp::OmapSetKeys {
                cid: c,
                oid: pgmeta(0),
                pairs: vec![(lk.as_slice().into(), val[..180.min(vlen)].into())],
            });
            t.push(TOp::OmapRmKeys {
                cid: c,
                oid: pgmeta(0),
                keys: vec![ok.as_slice().into()],
            });
            tok += 1;
            let tq = Instant::now();
            let r = st.queue(&t, tok);
            qns += tq.elapsed().as_nanos() as u64;
            match r {
                Err(store::obj::ObjError::WouldBlock) => {
                    tok -= 1;
                    log -= 1;
                    break;
                }
                r => {
                    r.map_err(|e| format!("queue at {done_keys} keys: {e}"))?;
                }
            }
            keys_of.insert(tok, (k, Instant::now()));
            issued += k;
            inflight += 1;
        }
        acked.clear();
        st.compaction_helpers(helpers, usize::from(job.is_none()));
        st.poll(&mut acked)
            .map_err(|e| format!("poll at {done_keys} keys: {e}"))?;
        if helpers {
            pump(st, &mut job, &mut hns);
        }
        for tk in &acked {
            if let Some((k, at)) = keys_of.remove(tk) {
                done_keys += k;
                let l = at.elapsed().as_micros() as u64;
                lat_max = lat_max.max(l);
                lats.push(l);
            }
            inflight -= 1;
        }
        let el = t0.elapsed().as_secs_f64();
        if el >= next {
            next = el + every;
            report(
                st,
                &mut lat_max,
                done_keys,
                el,
                &mut last,
                &mut peak,
                &mut prev,
                qns,
            );
        }
    }
    let el = t0.elapsed().as_secs_f64();
    report(
        st,
        &mut lat_max,
        done_keys,
        el,
        &mut last,
        &mut peak,
        &mut prev,
        qns,
    );
    st.sync().map_err(|e| e.to_string())?;
    // omap runs (adr 0476): the merges still owed run now; the sustained rate includes them (the space below is the
    // merged tree, not the runs' page charge)
    // `--idle-drain`: no drain request; the shards' own idle-object merges must take every run (adr 0476)
    let idle_drain = flag(a, "--idle-drain");
    if !idle_drain {
        for s in st.shards.iter_mut() {
            s.sh.drain_runs();
        }
    }
    let runs_left =
        |st: &St| -> usize { st.shards.iter().map(|s| s.sh.state().runs.entries()).sum() };
    let (left, td) = (runs_left(st), Instant::now());
    const DRAIN_MAX_S: u64 = 600;
    while runs_left(st) > 0 {
        if td.elapsed().as_secs() >= DRAIN_MAX_S {
            eprintln!(
                "WARNING TIMEOUT omapfill run drain exceeded {DRAIN_MAX_S}s ({} run entries left)",
                runs_left(st)
            );
            break;
        }
        st.idle();
        acked.clear();
        st.compaction_helpers(helpers, usize::from(job.is_none()));
        st.poll(&mut acked).map_err(|e| e.to_string())?;
        if helpers {
            pump(st, &mut job, &mut hns);
        }
        let el = t0.elapsed().as_secs_f64();
        if idle_drain && el >= next {
            next = el + every;
            report(
                st,
                &mut lat_max,
                done_keys,
                el,
                &mut last,
                &mut peak,
                &mut prev,
                qns,
            );
        }
    }
    let dr = td.elapsed().as_secs_f64();
    let lmax = lats.iter().copied().max().unwrap_or(0);
    println!(
        "omapfill latency: txns={} p50={:.0}us p99={:.0}us max={lmax}us",
        lats.len(),
        pct(&mut lats, 0.5) * 1e3,
        pct(&mut lats, 0.99) * 1e3,
    );
    println!(
        "omapfill drain: {left} run entries merged in {dr:.1}s; with the drain {:.0} keys/s",
        n as f64 / (el + dr)
    );
    // populate + drain on one thread: owner = the rest of the wall time
    println!(
        "omapfill cpu: populate+drain {:.0}ms = owner {:.0}ms + helper_ms {:.0}ms; {:.3}us/key total, owner {:.3}us/key",
        (el + dr) * 1e3,
        (el + dr) * 1e3 - hns as f64 / 1e6,
        hns as f64 / 1e6,
        (el + dr) * 1e6 / n as f64,
        ((el + dr) * 1e9 - hns as f64) / 1e3 / n as f64
    );
    st.checkpoint().map_err(|e| e.to_string())?;
    st.checkpoint().map_err(|e| e.to_string())?;
    let used = st.statfs().used_bytes.saturating_sub(base);
    let ts = st.tree_stats();
    println!(
        "omapfill done: {n} keys in {el:.1}s ({:.0} keys/s), used after checkpoint {:.0}MiB = {:.0} B/key (logical {} B/key), peak {:.0}MiB, splits {} delta pages {}",
        n as f64 / el,
        used as f64 / 1048576.0,
        used as f64 / n as f64,
        64 + vlen,
        peak as f64 / 1048576.0,
        ts.splits,
        ts.delta_pages
    );
    println!(
        "omapfill wa: device writes {:.0}MiB for {:.0}MiB logical keys+values = {:.2}x",
        (cn.wr_lbas.get() - wr_base) as f64 * lba / 1048576.0,
        (n * (64 + vlen as u64)) as f64 / 1048576.0,
        (cn.wr_lbas.get() - wr_base) as f64 * lba / (n * (64 + vlen as u64)) as f64
    );
    let rep = st.check(true).map_err(|e| e.to_string())?;
    println!("fsck: errors={} {:?}", rep.errors.len(), st.statfs());
    Ok(())
}

/// A value shaped like an RGW bucket index entry (`--omap-vals rgw`): fixed header and owner / content type / storage class
/// strings, an object name, varying size / mtime, a random 32-digit etag and tag (~250 B; a trained dictionary codes it to
/// about a third).
fn rgw_entry(rng: &mut Rng, i: u64) -> Vec<u8> {
    fn s(v: &mut Vec<u8>, b: &[u8]) {
        v.extend_from_slice(&(b.len() as u32).to_le_bytes());
        v.extend_from_slice(b);
    }
    fn hexs(rng: &mut Rng, n: usize) -> Vec<u8> {
        const H: &[u8; 16] = b"0123456789abcdef";
        (0..n).map(|_| H[(rng.next_u64() & 15) as usize]).collect()
    }
    let mut v = vec![8, 3, 0, 0, 0, 0];
    s(&mut v, format!("data/obj-{i:010}.bin").as_bytes());
    s(&mut v, b"");
    v.extend_from_slice(&(i % 5 + 1).to_le_bytes());
    v.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0]);
    v.extend_from_slice(&(1_760_000_000 + i / 4).to_le_bytes());
    v.extend_from_slice(&(rng.next_u64() % (16 << 20)).to_le_bytes());
    let etag = hexs(rng, 32);
    s(&mut v, &etag);
    s(&mut v, b"bench-user");
    s(&mut v, b"Bench User");
    s(&mut v, b"binary/octet-stream");
    v.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
    s(&mut v, b"STANDARD");
    let tag = [b"tag.".as_slice(), &hexs(rng, 24)].concat();
    s(&mut v, &tag);
    v.extend_from_slice(&[0u8; 20]);
    v
}

/// Process CPU seconds (user + system) from /proc/self/stat.
fn cpu_s() -> f64 {
    let s = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let f: Vec<&str> = s
        .rsplit_once(')')
        .map_or("", |x| x.1)
        .split_whitespace()
        .collect();
    let t = |i: usize| f.get(i).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
    (t(11) + t(12)) / 100.0
}

fn pct(v: &mut [u64], p: f64) -> f64 {
    v.sort_unstable();
    v.get(((v.len() as f64 * p) as usize).min(v.len().saturating_sub(1)))
        .copied()
        .unwrap_or(0) as f64
        / 1e3
}

/// `--omap-reads` after `--omapfill` (spike surrealkv, doc/perf/spike-surrealkv-*.md): on the freshly remounted store
/// (cold cache): `--omap-gets` random point gets of populated keys (cold pass, then the same keys warm), ordered 1000-key
/// listings from random keys, then `OmapRmKeyRange` over the lower half of the key space (hex first digit 0-7), a
/// checkpoint and the space left. Per-op p50/p99 in us and process CPU us per op.
pub(crate) fn reads(st: &mut St, cn: &Counters, a: &[String]) -> Result<(), String> {
    let n: u64 = arg(a, "--omapfill")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);
    let gets: u64 = arg(a, "--omap-gets")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000)
        .min(n);
    let lists: u64 = arg(a, "--omap-lists")
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000);
    let vlen: usize = arg(a, "--omap-vlen")
        .and_then(|s| s.parse().ok())
        .unwrap_or(256);
    let c = pgc(0);
    let o = Ghobject::new(
        Hobject::new(b"omapbench_A_0", SnapId::NOSNAP, 0x1234_5678, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    );
    // replay the populate generator: every (n/gets)-th key
    let mut rng = Rng::new(44);
    let step = (n / gets).max(1);
    let mut sample: Vec<Vec<u8>> = Vec::with_capacity(gets as usize);
    for i in 0..n {
        const H: &[u8; 16] = b"0123456789abcdef";
        let mut key = Vec::with_capacity(64);
        for _ in 0..4 {
            let w = rng.next_u64();
            key.extend((0..16).map(|j| H[(w >> (j * 4) & 15) as usize]));
        }
        for _ in 0..vlen.div_ceil(8) {
            rng.next_u64();
        }
        if i % step == 0 {
            sample.push(key);
        }
    }
    let mut r2 = Rng::new(7);
    for i in (1..sample.len()).rev() {
        sample.swap(i, (r2.next_u64() % (i as u64 + 1)) as usize);
    }
    for pass in ["cold", "warm"] {
        let (mut lat, mut miss) = (Vec::with_capacity(sample.len()), 0u64);
        let (rd0, c0, t0) = (cn.rd_lbas.get(), cpu_s(), Instant::now());
        for k in &sample {
            let t = Instant::now();
            let m = st
                .omap_get(&c, &o, &[k.as_slice()])
                .map_err(|e| e.to_string())?;
            lat.push(t.elapsed().as_nanos() as u64);
            miss += m.is_empty() as u64;
        }
        let el = t0.elapsed().as_secs_f64();
        println!(
            "omapreads get-{pass}: {} gets {:.0}/s p50={:.1}us p99={:.1}us cpu={:.2}us/op dev_rd={:.0}B/op miss={miss}",
            sample.len(),
            sample.len() as f64 / el,
            pct(&mut lat, 0.5),
            pct(&mut lat, 0.99),
            (cpu_s() - c0) * 1e6 / sample.len() as f64,
            (cn.rd_lbas.get() - rd0) as f64 * 4096.0 / sample.len() as f64
        );
    }
    let (mut lat, mut got) = (Vec::new(), 0u64);
    let (c0, t0) = (cpu_s(), Instant::now());
    for i in 0..lists as usize {
        let t = Instant::now();
        let (l, _more) = st
            .omap_iter(&c, &o, &sample[i % sample.len()], 1000)
            .map_err(|e| e.to_string())?;
        lat.push(t.elapsed().as_nanos() as u64);
        got += l.len() as u64;
    }
    let el = t0.elapsed().as_secs_f64();
    println!(
        "omapreads list1000: {lists} lists {:.0}/s ({:.0} keys/s) p50={:.1}us p99={:.1}us cpu={:.2}us/key keys={got}",
        lists as f64 / el,
        got as f64 / el,
        pct(&mut lat, 0.5),
        pct(&mut lat, 0.99),
        (cpu_s() - c0) * 1e6 / got.max(1) as f64
    );
    let before = st.statfs().used_bytes;
    let (wr0, c0, t0) = (cn.wr_lbas.get(), cpu_s(), Instant::now());
    let mut t = OTxn::new();
    t.push(TOp::OmapRmKeyRange {
        cid: c,
        oid: o.clone(),
        first: b"0".as_slice().into(),
        last: b"8".as_slice().into(),
    });
    st.commit(&t).map_err(|e| e.to_string())?;
    st.sync().map_err(|e| e.to_string())?;
    let el_ack = t0.elapsed().as_secs_f64();
    st.checkpoint().map_err(|e| e.to_string())?;
    st.checkpoint().map_err(|e| e.to_string())?;
    let el = t0.elapsed().as_secs_f64();
    let (l, _) = st.omap_iter(&c, &o, b"0", 1).map_err(|e| e.to_string())?;
    println!(
        "omapreads delrange [0,8): txn durable {:.1}ms, +checkpoint {:.1}ms, cpu={:.1}ms dev_wr={:.1}MiB used {:.0}MiB -> {:.0}MiB first_left={:?}",
        el_ack * 1e3,
        el * 1e3,
        (cpu_s() - c0) * 1e3,
        (cn.wr_lbas.get() - wr0) as f64 * 4096.0 / 1048576.0,
        before as f64 / 1048576.0,
        st.statfs().used_bytes as f64 / 1048576.0,
        l.first()
            .map(|e| String::from_utf8_lossy(&e.0[..2]).into_owned())
    );
    Ok(())
}
