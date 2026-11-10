// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `bench --omapmix N`: the omapgate mix cells (tools/oprobe `omapgate mix-delete` / `mix-range`, e9455 OMAP phase 1) at
//! store level on one core, without network and replicas: ONE object prefilled with N keys (64-byte hex ids, values of
//! `--mix-vlen` B, `--mix-keys` keys per op as client runs, 4 txns in flight), then `--mix-ops` ops per kind, QD1, round
//! robin insert (new ids above the prefill) / update (scattered live keys) / delete (`--mix-shape delete`: omap_rm_keys
//! of scattered live keys; `range`: omap_rm_key_range over a run of live keys) /
//! point_read (omap_get_vals_by_keys of scattered live keys), then a full listing in pages of `--mix-page` (1000).
//! `--mix-delhalf`: before the mix, the omapgate `delete` + `scan-del` cells: half of the prefill removed by scattered
//! `--mix-keys` batches (QD1), a full listing right after (`scan-del`: the background merge of the removals runs
//! between the pages, as on the PG core), the runs drained, the listing again (`scan-settled`).
//! Listings poll the store once before each page (the PG core's loop between client ops) and print per page latency
//! p50 / p99, the time in the listing itself (`iter`) and in the polls (`bg`: merges, checkpoints, completions), tree
//! page loads, merged run entries and checkpoint pages per page.
//! Key choice as oprobe: a uniform point in the id span, the next live key at or above it.
//!
//! Reads run as the OSD executor runs them: non-blocking, a miss refuses the op (`WouldBlock`), the op repeats once
//! every queued page load is in. `passes` = executions per read op (1 = served from the cache).
//!
//! Prints per kind: ops, latency p50 / p99 (queue -> ack; reads: first try -> result), tree page loads per op, read
//! passes per op; per phase the tree shape (meta pages in use, resident pages, resident leaf fill), merges, page loads.
//! Ends with the recount of the omap entries (scrub) and fsck.
use crate::bench::{St, arg, pgc, pgmeta};
use crate::bench_omaprm::commit1;
use denc::types::{Ghobject, Hobject, ShardId, SnapId};
use std::collections::BTreeMap;
use std::time::Instant;
use store::obj::{OTxn, ObjError, TOp};

fn splitmix(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *s;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// oprobe omapgate key of id `i`: 64 lowercase hex digits.
fn key(i: u64) -> Vec<u8> {
    format!("{i:064x}").into_bytes()
}

/// Incompressible value of `len` bytes for (`i`, generation `g`).
fn val(i: u64, g: u64, len: usize) -> Vec<u8> {
    let mut s = i ^ (g << 48) ^ 0x5eed;
    let mut v = Vec::with_capacity(len + 8);
    while v.len() < len {
        v.extend_from_slice(&splitmix(&mut s).to_le_bytes());
    }
    v.truncate(len);
    v
}

fn run_of(ids: &[u64], g: u64, vlen: usize) -> store::obj::KvRunData<'static> {
    let kv: Vec<(Vec<u8>, Vec<u8>)> = ids.iter().map(|&i| (key(i), val(i, g, vlen))).collect();
    let mut enc = Vec::new();
    denc::SortedKv::encode_into(
        &mut enc,
        kv.len(),
        kv.iter().map(|(k, v)| (k.as_slice(), v.as_slice())),
    );
    store::obj::KvRunData::from_encoding(enc.into()).expect("sorted batch")
}

#[derive(Default)]
struct Kind {
    lat: Vec<u64>,
    loads: u64,
    passes: u64,
    /// Most passes of one op, and ops refused more than the executor's `MAX_SCAN_TRIES` (64) times: on the PG core
    /// those run blocking (the core waits for each page load).
    pmax: u64,
    over: u64,
    /// Background work that ran inside this kind's ops (store polls): merged run entries, pages the merge asked to load,
    /// checkpoint pages.
    bg: (u64, u64, u64),
}

impl Kind {
    fn line(&mut self, name: &str, el: f64) {
        self.lat.sort_unstable();
        let n = self.lat.len().max(1);
        let p = |q: f64| self.lat[((n as f64 * q) as usize).min(n - 1)];
        println!(
            "omapmix {name:<12} ops={:<6} ops/s={:<7.0} p50={}us p99={}us max={}us loads/op={:.2} passes/op={:.2} passes_max={} over64={} bg_merged/op={:.1} bg_merge_loads/op={:.1} bg_ckpt_pages/op={:.1}",
            self.lat.len(),
            self.lat.len() as f64 / el,
            p(0.5),
            p(0.99),
            self.lat.last().copied().unwrap_or(0),
            self.loads as f64 / n as f64,
            self.passes as f64 / n as f64,
            self.pmax,
            self.over,
            self.bg.0 as f64 / n as f64,
            self.bg.1 as f64 / n as f64,
            self.bg.2 as f64 / n as f64,
        );
    }
}

fn loads(st: &St) -> u64 {
    st.tree_stats().loads
}

/// Tree shape line: meta pages in use, resident pages and the fill of the resident leaves, merges, page loads.
fn shape(st: &mut St, at: &str) {
    let fs = st.statfs();
    let ts = st.tree_stats();
    let (mut starts, mut marks) = ([0u64; 4], 0u64);
    for s in &st.shards {
        for (a, b) in starts.iter_mut().zip(s.sh.stats.run_merge_starts) {
            *a += b;
        }
        marks += s.sh.stats.run_idle_marks;
    }
    let (mut leaves, mut used, mut ents, mut res) = (0u64, 0u64, 0u64, 0u64);
    for s in &st.shards {
        let t = &s.sh.state().tree;
        let sh = t.shape();
        leaves += sh.leaves;
        used += sh.leaf_used;
        ents += sh.entries;
        res += t.mem().pages;
    }
    println!(
        "omapmix shape {at:<10} meta_pages={} resident={res} res_leaves={leaves} res_leaf_fill={:.2} ents/leaf={:.1} merged={} compacted={} loads={} evictions={} merge_starts(want,over,ring,idle)={starts:?} idle_marks={marks}",
        fs.meta_used_pages,
        used as f64 / (leaves.max(1) * 8192) as f64,
        ents as f64 / leaves.max(1) as f64,
        ts.merged,
        ts.compacted,
        ts.loads,
        ts.evictions,
    );
}

/// Up to `n` scattered live ids (oprobe `take_scattered`): a uniform point below `span`, the next live id at or above
/// it (wrapping). Removed from `live`.
fn scattered(live: &mut BTreeMap<u64, ()>, span: u64, n: usize, rng: &mut u64) -> Vec<u64> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n && !live.is_empty() {
        let r = splitmix(rng) % span.max(1);
        let id = *live
            .range(r..)
            .next()
            .or_else(|| live.iter().next())
            .expect("non-empty")
            .0;
        live.remove(&id);
        out.push(id);
    }
    out.sort_unstable();
    out
}

/// A run of `n` live ids from a uniform point (oprobe `take_run`). Removed from `live`.
fn run_ids(live: &mut BTreeMap<u64, ()>, span: u64, n: usize, rng: &mut u64) -> Vec<u64> {
    let r = splitmix(rng) % span.max(1);
    let mut ids: Vec<u64> = live.range(r..).take(n).map(|(k, _)| *k).collect();
    if ids.len() < n {
        ids = live.iter().rev().take(n).map(|(k, _)| *k).collect();
        ids.reverse();
    }
    for k in &ids {
        live.remove(k);
    }
    ids
}

/// Longest wait for the runs to drain after `--mix-delhalf` (loud when it fires).
const SETTLE_S: u64 = 600;

/// Summed over the shards: merged run entries, checkpoint pages, run entries held, pages merges asked to load.
fn bg_counts(st: &St) -> (u64, u64, u64, u64) {
    st.shards.iter().fold((0, 0, 0, 0), |(e, p, r, m), s| {
        (
            e + s.sh.stats.run_merged_ents,
            p + s.sh.stats.ckpt_pages,
            r + s.sh.state().runs.entries() as u64,
            m + s.sh.stats.run_merge_miss_pages,
        )
    })
}

fn bg_add(k: &mut Kind, a: (u64, u64, u64, u64), b: (u64, u64, u64, u64)) {
    k.bg.0 += b.0 - a.0;
    k.bg.1 += b.3 - a.3;
    k.bg.2 += b.1 - a.1;
}

/// Full listing of `o` in pages of `page` keys, one store poll before each page; prints the `name` line, returns the
/// keys listed.
fn listing(
    st: &mut St,
    c: &denc::types::CollT,
    o: &Ghobject,
    page: usize,
    name: &str,
) -> Result<u64, String> {
    let (l0, (e0, p0, r0, _)) = (loads(st), bg_counts(st));
    let (mut from, mut seen, mut pages) = (Vec::new(), 0u64, 0u64);
    let (mut lat, mut iter_ns, mut bg_ns) = (Vec::new(), 0u64, 0u64);
    let mut acked = Vec::new();
    let ts = Instant::now();
    loop {
        let t0 = Instant::now();
        acked.clear();
        st.poll(&mut acked).map_err(|e| e.to_string())?;
        let t1 = Instant::now();
        let (kv, more) = st.omap_iter(c, o, &from, page).map_err(|e| e.to_string())?;
        let t2 = Instant::now();
        bg_ns += (t1 - t0).as_nanos() as u64;
        iter_ns += (t2 - t1).as_nanos() as u64;
        lat.push((t2 - t0).as_micros() as u64);
        pages += 1;
        seen += kv.len() as u64;
        let Some((last, _)) = kv.last() else { break };
        from = last.to_vec();
        from.push(0);
        if !more {
            break;
        }
    }
    let el = ts.elapsed().as_secs_f64();
    let (e1, p1, _, _) = bg_counts(st);
    lat.sort_unstable();
    let q = |x: f64| lat[((lat.len() as f64 * x) as usize).min(lat.len() - 1)];
    let pg = pages.max(1) as f64;
    println!(
        "omapmix {name} pages={pages} keys={seen} pages/s={:.0} p50={}us p99={}us iter_us/page={:.1} bg_us/page={:.1} \
         loads/page={:.2} merged_ents/page={:.1} ckpt_pages/page={:.2} run_ents_at_start={r0}",
        pg / el,
        q(0.5),
        q(0.99),
        iter_ns as f64 / pg / 1e3,
        bg_ns as f64 / pg / 1e3,
        (loads(st) - l0) as f64 / pg,
        (e1 - e0) as f64 / pg,
        (p1 - p0) as f64 / pg,
    );
    Ok(seen)
}

pub(crate) fn run(st: &mut St, a: &[String]) -> Result<(), String> {
    let num = |k: &str, d: u64| -> Result<u64, String> {
        arg(a, k).map_or(Ok(d), |s| s.parse().map_err(|_| format!("bad {k} {s}")))
    };
    let n = num("--omapmix", 1 << 20)?;
    let ops = num("--mix-ops", 16384)?;
    let kpo = num("--mix-keys", 64)? as usize;
    let vlen = num("--mix-vlen", 256)? as usize;
    let page = num("--mix-page", 1000)? as usize;
    let shape_range = match arg(a, "--mix-shape").as_deref().unwrap_or("delete") {
        "delete" => false,
        "range" => true,
        s => return Err(format!("--mix-shape delete|range, not {s}")),
    };
    let c = pgc(0);
    let o = Ghobject::new(
        Hobject::new(b"omapmix", SnapId::NOSNAP, 0x4d49_5845, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    );
    let mut t = OTxn::new();
    t.push(TOp::MkColl {
        cid: c,
        bits: 0,
        exist_ok: true,
    });
    t.touch(c, &pgmeta(0));
    t.touch(c, &o);
    st.commit(&t).map_err(|e| e.to_string())?;
    let mut tok = 0u64;
    // prefill: N keys in kpo-key runs, 4 txns in flight
    let t0 = Instant::now();
    let (mut issued, mut inflight) = (0u64, 0usize);
    let mut acked = Vec::new();
    while issued < n || inflight > 0 {
        while inflight < 4 && issued < n {
            let hi = (issued + kpo as u64).min(n);
            let ids: Vec<u64> = (issued..hi).collect();
            let mut t = OTxn::new();
            t.push(TOp::OmapSetRun {
                cid: c,
                oid: o.clone(),
                run: run_of(&ids, 0, vlen),
            });
            tok += 1;
            match st.queue(&t, tok) {
                Ok(_) => {
                    issued = hi;
                    inflight += 1;
                }
                Err(ObjError::WouldBlock) => break,
                Err(e) => return Err(format!("prefill: {e}")),
            }
        }
        acked.clear();
        st.poll(&mut acked).map_err(|e| e.to_string())?;
        inflight -= acked.len();
    }
    println!(
        "omapmix prefill {n} keys in {:.2}s",
        t0.elapsed().as_secs_f64()
    );
    shape(st, "prefill");
    let mut live: BTreeMap<u64, ()> = (0..n).map(|i| (i, ())).collect();
    let mut next = n;
    let mut rng = 0x6d69_785f_7365_6564u64;
    if a.iter().any(|x| x == "--mix-delhalf") {
        let mut d = Kind::default();
        let td = Instant::now();
        while live.len() as u64 > n / 2 {
            let want = kpo.min(live.len() - (n / 2) as usize);
            let ids = scattered(&mut live, next, want, &mut rng);
            let mut t = OTxn::new();
            t.push(TOp::OmapRmKeys {
                cid: c,
                oid: o.clone(),
                keys: ids.iter().map(|&i| key(i).into()).collect(),
            });
            tok += 1;
            let (l0, b0) = (loads(st), bg_counts(st));
            d.lat.push(commit1(st, &t, tok)?.0);
            d.loads += loads(st) - l0;
            bg_add(&mut d, b0, bg_counts(st));
        }
        d.line("delete-half", td.elapsed().as_secs_f64());
        shape(st, "delete");
        listing(st, &c, &o, page, "scan-del")?;
        let ts = Instant::now();
        let mut acked = Vec::new();
        while st.shards.iter().any(|s| !s.sh.state().runs.is_empty()) {
            if ts.elapsed().as_secs() >= SETTLE_S {
                eprintln!("WARNING TIMEOUT omapmix settle exceeded {SETTLE_S}s (runs not drained)");
                break;
            }
            acked.clear();
            st.poll(&mut acked).map_err(|e| e.to_string())?;
            st.idle();
        }
        println!("omapmix settle {:.2}s", ts.elapsed().as_secs_f64());
        listing(st, &c, &o, page, "scan-settled")?;
    }
    let mut g = 0u64;
    let names = [
        "insert",
        "update",
        if shape_range {
            "delete_range"
        } else {
            "delete"
        },
        "point_read",
    ];
    let mut k: [Kind; 4] = Default::default();
    let tm = Instant::now();
    for i in 0..ops * 4 {
        let kind = (i % 4) as usize;
        let (l0, b0) = (loads(st), bg_counts(st));
        match kind {
            0 | 1 => {
                let ids = if kind == 0 {
                    let ids: Vec<u64> = (next..next + kpo as u64).collect();
                    next += kpo as u64;
                    ids
                } else {
                    scattered(&mut live, next, kpo, &mut rng)
                };
                g += 1;
                let mut t = OTxn::new();
                t.push(TOp::OmapSetRun {
                    cid: c,
                    oid: o.clone(),
                    run: run_of(&ids, g, vlen),
                });
                tok += 1;
                k[kind].lat.push(commit1(st, &t, tok)?.0);
                live.extend(ids.into_iter().map(|i| (i, ())));
            }
            2 if shape_range => {
                let ids = run_ids(&mut live, next, kpo, &mut rng);
                let (lo, hi) = (key(ids[0]), key(ids[ids.len() - 1] + 1));
                let mut t = OTxn::new();
                t.push(TOp::OmapRmKeyRange {
                    cid: c,
                    oid: o.clone(),
                    first: lo.into(),
                    last: hi.into(),
                });
                tok += 1;
                k[kind].lat.push(commit1(st, &t, tok)?.0);
            }
            2 => {
                let ids = scattered(&mut live, next, kpo, &mut rng);
                let mut t = OTxn::new();
                t.push(TOp::OmapRmKeys {
                    cid: c,
                    oid: o.clone(),
                    keys: ids.iter().map(|&i| key(i).into()).collect(),
                });
                tok += 1;
                k[kind].lat.push(commit1(st, &t, tok)?.0);
            }
            _ => {
                let ids = scattered(&mut live, next, kpo, &mut rng);
                let keys: Vec<Vec<u8>> = ids.iter().map(|&i| key(i)).collect();
                let ks: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
                let tr = Instant::now();
                st.set_nonblock_reads(true);
                let mut passes = 0u64;
                let got = loop {
                    passes += 1;
                    match st.omap_get(&c, &o, &ks) {
                        Err(ObjError::WouldBlock) => {
                            st.take_blocked();
                            st.wait_loads().map_err(|e| e.to_string())?;
                        }
                        r => break r.map_err(|e| e.to_string())?,
                    }
                };
                st.set_nonblock_reads(false);
                k[kind].lat.push(tr.elapsed().as_micros() as u64);
                k[kind].passes += passes;
                k[kind].pmax = k[kind].pmax.max(passes);
                k[kind].over += u64::from(passes - 1 > 64);
                if got.len() != ids.len() {
                    return Err(format!("point read: {} of {} keys", got.len(), ids.len()));
                }
                live.extend(ids.into_iter().map(|i| (i, ())));
            }
        }
        k[kind].loads += loads(st) - l0;
        bg_add(&mut k[kind], b0, bg_counts(st));
        if (i + 1) % (ops) == 0 {
            shape(st, &format!("mix@{}", (i + 1) / 4));
        }
    }
    let el = tm.elapsed().as_secs_f64();
    for (kk, name) in k.iter_mut().zip(names) {
        kk.line(name, el);
    }
    println!(
        "omapmix mix total ops={} ops/s={:.0} live={}",
        ops * 4,
        (ops * 4) as f64 / el,
        live.len()
    );
    let seen = listing(st, &c, &o, page, "scan")?;
    shape(st, "end");
    let got = st.scrub(&c, &o, 0).map_err(|e| e.to_string())?.omap_keys;
    if got != live.len() as u64 || seen != live.len() as u64 {
        return Err(format!(
            "omap keys {got} / listed {seen}, expected {}",
            live.len()
        ));
    }
    let rep = st.check(true).map_err(|e| e.to_string())?;
    println!("omapmix fsck: errors={}", rep.errors.len());
    if !rep.errors.is_empty() {
        return Err(format!(
            "fsck: {:?}",
            &rep.errors[..rep.errors.len().min(5)]
        ));
    }
    Ok(())
}
