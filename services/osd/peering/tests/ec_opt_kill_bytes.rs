// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Optimized EC (mode O) durability under kill -9 / restart cycles with writes in flight, BYTE-LEVEL: every shard of
//! every object must equal the encoding of one content the client may observe (all acked writes applied, any subset of
//! the unacked ones), and the primary's read must return that content (case 20 of the mixed lab, all-croit-flashstore-osd here).
mod common;
use common::*;
use ecback::{Backend, Geo};

const POOL: u64 = 1;

fn opt_cluster(seed: u64, osds: &[i32], k: u32, m: u32, chunk: u32, rf_defer: Option<u64>) -> Sim {
    let mut s = Sim::new(seed);
    // the real store: queued txns are visible to reads at once (OQ 41 window reads rely on this model)
    s.read_after_queue = true;
    for o in osds {
        s.add_osd_cfg(*o, |c| {
            c.ec_enable = ec::EcEnable::All;
            c.ec_enable_optimized = ec::EcEnable::All;
            c.ec_primary = true;
            c.ec_opt_primary = true;
            c.ec_trace = std::env::var("OQ41_TRACE").is_ok();
            if let Some(d) = rf_defer {
                c.ec_rf_defer_ns = d;
            }
        });
    }
    s.run_for(50 * MS);
    s.create_pool_ec_opt(POOL, k, m, chunk, true, 1);
    s.run_for(2000 * MS);
    s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
    s
}

fn backend(k: u32, m: u32, chunk: u32) -> Backend {
    Backend::from_parts(
        "isa",
        "reed_sol_van",
        (k, m),
        (k * chunk, chunk),
        (0..k + m).collect(),
        true,
    )
    .unwrap()
}

/// Expected O shard files of `data` (index = shard = raw, identity mapping).
fn o_shards(be: &Backend, data: &[u8]) -> Vec<Vec<u8>> {
    let g = Geo {
        k: be.k as u64,
        c: be.c,
    };
    let n = data.len() as u64;
    let plen = g.shard_size(n, 0) as usize;
    let mut cols: Vec<Vec<u8>> = (0..be.k)
        .map(|r| {
            (0..plen)
                .map(|so| {
                    data.get(g.shard_to_ro(r, so as u64) as usize)
                        .copied()
                        .unwrap_or(0)
                })
                .collect()
        })
        .collect();
    let mut padded = data.to_vec();
    padded.resize(plen.div_ceil(be.c as usize) * be.s as usize, 0);
    let enc = be.encode_stripes(&padded);
    for j in 0..be.m {
        cols.push(enc[be.k + j][..plen].to_vec());
    }
    for (r, c) in cols.iter_mut().enumerate() {
        c.truncate(g.shard_size(n, r) as usize);
    }
    cols
}

fn fill(tag: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|j| ((tag.wrapping_mul(2654435761) as usize + j * 7) % 251) as u8 | 1)
        .collect()
}

/// One client op on an object (the shapes ceph_test_rados uses: stride writes, appends, write_excl, delete, attrs).
#[derive(Clone)]
enum Op {
    Write(u64, Vec<u8>),
    Zero(u64, u64),
    Append(Vec<u8>),
    Trunc(u64),
    Create(Vec<u8>),
    Remove,
    Attr,
}

impl Op {
    fn sizes(&self) -> bool {
        !matches!(self, Op::Write(..) | Op::Zero(..) | Op::Attr)
    }
    fn apply(&self, v: &mut Option<Vec<u8>>) {
        match self {
            Op::Write(off, d) => {
                let b = v.as_mut().expect("write on an absent object");
                b[*off as usize..*off as usize + d.len()].copy_from_slice(d);
            }
            Op::Zero(off, len) => {
                let b = v.as_mut().expect("zero on an absent object");
                b[*off as usize..(*off + *len) as usize].fill(0);
            }
            Op::Append(d) => v
                .as_mut()
                .expect("append on an absent object")
                .extend_from_slice(d),
            Op::Trunc(sz) => v
                .as_mut()
                .expect("trunc on an absent object")
                .resize(*sz as usize, 0),
            Op::Create(d) => *v = Some(d.clone()),
            Op::Remove => *v = None,
            Op::Attr => {}
        }
    }
}

struct W {
    tid: u64,
    spg: denc::types::SpgT,
    ver: denc::types::Eversion,
    op: Op,
}

/// Every state the client may observe: base + acked ops + any subset of the unacked ones, in submission order.
fn candidates(s: &Sim, base: &Option<Vec<u8>>, ws: &[W]) -> Vec<Option<Vec<u8>>> {
    let unacked: Vec<usize> = (0..ws.len()).filter(|i| !acked(s, &ws[*i])).collect();
    assert!(unacked.len() <= 12, "too many unacked writes on one object");
    let mut out = Vec::new();
    for mask in 0u32..(1 << unacked.len()) {
        let mut v = base.clone();
        for (i, w) in ws.iter().enumerate() {
            if let Some(p) = unacked.iter().position(|u| *u == i)
                && mask & (1 << p) == 0
            {
                continue;
            }
            w.op.apply(&mut v);
        }
        if !out.contains(&v) {
            out.push(v);
        }
    }
    out
}

fn read_ec(s: &mut Sim, name: &str, len: u64) -> Result<Vec<u8>, i32> {
    let lead = s.lead_spg(POOL, 0);
    let osd = s.primary_of(lead.pgid);
    let h = hobj(POOL, name);
    for _ in 0..8000 {
        let mut ready = false;
        s.call(osd, |set, now, store| {
            let (r, acts) = set
                .with_pg(now, lead, store, |pg| {
                    pg.ec_wait(&h, 0, len, store).is_none()
                })
                .expect("pg");
            ready = r;
            acts
        });
        if ready {
            break;
        }
        s.run_for(2 * MS);
    }
    let pg = s.pg(osd, lead).unwrap();
    let size = pg.ec_obj_size(&h, &s.nodes[&osd].store).unwrap().ok_or(2)?;
    let r = pg.ec_cache_read(&h, 0, len, size);
    s.ec_ops_ran(osd);
    r
}

/// OQ 41: client reads in the window right after a restart (peering, rollback of divergent entries, recovery). Every
/// object is read through the current primary as the op layer would (active PG, own shard not missing, ec_wait until
/// ready); a completed read must be one of the object's candidate contents. `steps` x 2..20 ms of sim time.
fn window_reads(
    s: &mut Sim,
    rng: &mut Rng,
    base: &[Option<Vec<u8>>],
    hist: &[Vec<W>],
    steps: u64,
    ctx: &str,
) -> u64 {
    let mut done = 0;
    let mut pending: Vec<bool> = vec![true; base.len()];
    for _ in 0..steps {
        s.run_for(rng.range(2, 20) * MS);
        let lead = s.lead_spg(POOL, 0);
        let osd = s.primary_of(lead.pgid);
        if osd == pgwire::NONE_OSD || !s.nodes.contains_key(&osd) {
            continue;
        }
        let Some(pg) = s.pg(osd, lead) else { continue };
        if pg.state_bits() & pgwire::state::ACTIVE == 0
            || !pg.is_primary()
            || pg.map_epoch() != s.epoch()
        {
            continue;
        }
        for (i, b) in base.iter().enumerate() {
            if !pending[i] {
                continue;
            }
            let name = format!("o{i}");
            let h = hobj(POOL, &name);
            let cands = candidates(s, b, &hist[i]);
            let len = cands
                .iter()
                .flatten()
                .map(|c| c.len())
                .max()
                .unwrap_or(0)
                .max(1) as u64;
            if s.pg(osd, lead).is_some_and(|p| p.read_blocked(&h)) {
                continue;
            }
            let mut ready = false;
            s.call(osd, |set, now, store| {
                let (r, acts) = set
                    .with_pg(now, lead, store, |pg| {
                        pg.ec_wait(&h, 0, len, store).is_none()
                    })
                    .expect("pg");
                ready = r;
                acts
            });
            if !ready {
                continue;
            }
            let pg = s.pg(osd, lead).unwrap();
            let got = match pg.ec_obj_size(&h, &s.nodes[&osd].store) {
                Ok(None) => Ok(None),
                Ok(Some(size)) => pg.ec_cache_read(&h, 0, len, size).map(Some),
                Err(e) => Err(e),
            };
            s.ec_ops_ran(osd);
            let Ok(got) = got else { continue }; // EIO: the op layer retries / errors, never wrong bytes
            if !cands.contains(&got) {
                for w in &hist[i] {
                    let what = match &w.op {
                        Op::Write(o, d) => format!("write {o}..{}", o + d.len() as u64),
                        Op::Zero(o, l) => format!("zero {o}..{}", o + l),
                        Op::Append(d) => format!("append {}", d.len()),
                        Op::Trunc(n) => format!("trunc {n}"),
                        Op::Create(d) => format!("create {}", d.len()),
                        Op::Remove => "remove".into(),
                        Op::Attr => "attr".into(),
                    };
                    eprintln!("  tid {} v {:?} {what} acked {}", w.tid, w.ver, acked(s, w));
                }
                for (ci, c) in cands.iter().enumerate() {
                    if let (Some(c), Some(g)) = (c, &got) {
                        let d = c.iter().zip(g).position(|(a, b)| a != b);
                        eprintln!(
                            "  cand {ci}: len {} vs got {}, first diff {d:?}",
                            c.len(),
                            g.len()
                        );
                    }
                }
                if std::env::var("OQ41_TRACE").is_ok() {
                    let ids: Vec<i32> = s.nodes.keys().copied().collect();
                    for o in ids {
                        let mut notes = Vec::new();
                        s.call(o, |set, _, _| {
                            notes.extend(set.take_notices());
                            vec![]
                        });
                        for n in notes.iter().filter(|n| n.contains("ectrace")) {
                            eprintln!("osd.{o} {n}");
                        }
                    }
                }
                panic!(
                    "{ctx}: window read of {name} on osd.{osd} matches none of {} candidates\n{}",
                    cands.len(),
                    s.object_report(POOL, &name)
                );
            }
            pending[i] = false;
            done += 1;
        }
    }
    done
}

/// Settle, then check shards + read of every object against its candidates; returns the observed contents (new base).
fn check(
    s: &mut Sim,
    be: &Backend,
    base: &[Option<Vec<u8>>],
    hist: &[Vec<W>],
    ctx: &str,
) -> Vec<Option<Vec<u8>>> {
    s.run_until(180_000 * MS, &format!("{ctx}: clean"), |s| {
        s.pool_clean(POOL)
    });
    s.run_for(3000 * MS);
    let acting = s.acting_of(denc::types::PgT::new(POOL, 0));
    let mut now = Vec::new();
    for (i, b) in base.iter().enumerate() {
        let name = format!("o{i}");
        let cands = candidates(s, b, &hist[i]);
        // the content the primary returns must be one of the candidates, and every shard must encode exactly it
        let len = cands
            .iter()
            .flatten()
            .map(|c| c.len())
            .max()
            .unwrap_or(0)
            .max(1) as u64;
        let got = match read_ec(s, &name, len) {
            Ok(v) => Some(v),
            Err(2) => None,
            Err(e) => panic!("{ctx}: {name} read err {e}"),
        };
        let hit = cands.iter().position(|c| *c == got).unwrap_or_else(|| {
            for w in &hist[i] {
                let what = match &w.op {
                    Op::Write(o, d) => format!("write {o}..{}", o + d.len() as u64),
                    Op::Zero(o, l) => format!("zero {o}..{}", o + l),
                    Op::Append(d) => format!("append {}", d.len()),
                    Op::Trunc(n) => format!("trunc {n}"),
                    Op::Create(d) => format!("create {}", d.len()),
                    Op::Remove => "remove".into(),
                    Op::Attr => "attr".into(),
                };
                eprintln!("  tid {} v {:?} {what} acked {}", w.tid, w.ver, acked(s, w));
            }
            for (ci, c) in cands.iter().enumerate() {
                match (c, &got) {
                    (Some(c), Some(g)) => {
                        let d: Vec<usize> = c
                            .iter()
                            .zip(g)
                            .enumerate()
                            .filter(|(_, (a, b))| a != b)
                            .map(|(j, _)| j)
                            .collect();
                        eprintln!(
                            "  cand {ci}: len {} vs got {}, {} diffs, first {:?} last {:?}",
                            c.len(),
                            g.len(),
                            d.len(),
                            d.first(),
                            d.last()
                        );
                    }
                    _ => eprintln!(
                        "  cand {ci}: exists {} vs got exists {}",
                        c.is_some(),
                        got.is_some()
                    ),
                }
            }
            panic!(
                "{ctx}: {name} read matches none of {} candidates\n{}",
                cands.len(),
                s.object_report(POOL, &name)
            )
        });
        let Some(data) = &cands[hit] else {
            for osd in acting.iter().filter(|o| **o != pgwire::NONE_OSD) {
                let objs = s.nodes[osd].store.objects(s.spg_on(*osd, POOL, 0));
                assert!(
                    !objs.contains_key(&hobj(POOL, &name)),
                    "{ctx}: {name} removed but on osd.{osd}"
                );
            }
            now.push(None);
            continue;
        };
        let want = o_shards(be, data);
        for (sh, osd) in acting.iter().enumerate() {
            if *osd == pgwire::NONE_OSD {
                continue;
            }
            let objs = s.nodes[osd].store.objects(s.spg_on(*osd, POOL, 0));
            let o = objs.get(&hobj(POOL, &name)).unwrap_or_else(|| {
                panic!("{ctx}: {name}: shard {sh} on osd.{osd} lacks the object")
            });
            if o.data != want[sh] {
                let at = o.data.iter().zip(&want[sh]).position(|(a, b)| a != b);
                panic!(
                    "{ctx}: {name}: shard {sh} on osd.{osd} differs (len {} want {}, first diff {at:?})\n{}",
                    o.data.len(),
                    want[sh].len(),
                    s.object_report(POOL, &name)
                );
            }
        }
        now.push(cands[hit].clone());
    }
    now
}

fn ec_ops(op: &Op, size: Option<u64>) -> (Vec<EcOp>, Option<u64>) {
    let sz = size.unwrap_or(0);
    match op {
        Op::Write(off, d) => (vec![EcOp::Write(*off, d.clone())], Some(sz)),
        Op::Zero(off, len) => (vec![EcOp::Zero(*off, *len)], Some(sz)),
        Op::Append(d) => (vec![EcOp::Write(sz, d.clone())], Some(sz + d.len() as u64)),
        Op::Trunc(n) => (vec![EcOp::Trunc(*n)], Some(*n)),
        Op::Create(d) => (
            vec![EcOp::Touch, EcOp::Write(0, d.clone())],
            Some(d.len() as u64),
        ),
        Op::Remove => (vec![EcOp::Remove], None),
        Op::Attr => (vec![EcOp::Attr("_u", vec![7; 33])], Some(sz)),
    }
}

/// Next op for an object whose size is known (`cur`: every candidate has this size / absence).
fn pick(
    rng: &mut Rng,
    cur: &Option<Vec<u8>>,
    tag: u64,
    chunk: u64,
    stripe: u64,
    max: u64,
    sure: bool,
) -> Option<Op> {
    let Some(b) = cur else {
        return sure.then(|| Op::Create(fill(tag, rng.range(1, max / 2) as usize)));
    };
    let n = b.len() as u64;
    let r = rng.range(0, 99);
    if sure && r < 10 {
        return Some(Op::Append(fill(
            tag,
            rng.range(1, 3 * stripe).min(max.saturating_sub(n).max(1)) as usize,
        )));
    }
    if sure && r < 14 {
        return Some(Op::Trunc(rng.range(0, n + stripe)));
    }
    if sure && r < 17 {
        return Some(Op::Remove);
    }
    if r < 22 {
        return Some(Op::Attr);
    }
    if n == 0 {
        return None;
    }
    if r < 27 {
        let off = rng.range(0, n - 1);
        return Some(Op::Zero(off, rng.range(1, n - off)));
    }
    let len = if r < 60 {
        rng.range(1, 3 * chunk)
    } else {
        rng.range(chunk, 5 * stripe)
    }
    .min(n);
    let off = rng.range(0, n - len);
    Some(Op::Write(off, fill(tag, len as usize)))
}

fn run(seed: u64, k: u32, m: u32, chunk: u32, rf_defer: Option<u64>, rounds: u32) {
    run_x(seed, k, m, chunk, rf_defer, rounds, false);
}

/// `reads`: client reads of every object in the window after each restart (`window_reads`).
fn run_x(seed: u64, k: u32, m: u32, chunk: u32, rf_defer: Option<u64>, rounds: u32, reads: bool) {
    let mut nreads = 0u64;
    let osds: Vec<i32> = (0..(k + m + 1) as i32).collect();
    let mut s = opt_cluster(9100 + seed, &osds, k, m, chunk, rf_defer);
    let be = backend(k, m, chunk);
    let mut rng = Rng::new(seed);
    let objs = 4usize;
    let stripe = (k * chunk) as u64;
    let max = 24 * stripe + 1234;
    let mut base: Vec<Option<Vec<u8>>> = Vec::new();
    for i in 0..objs {
        let d = fill(1000 + i as u64, (12 * stripe + 1234) as usize);
        let tid = s
            .write_ops(
                POOL,
                0,
                &format!("o{i}"),
                &[EcOp::Touch, EcOp::Write(0, d.clone())],
                Some(d.len() as u64),
            )
            .expect("accepted");
        let l = s.lead_spg(POOL, 0);
        s.wait_writes(&[tid], l);
        base.push(Some(d));
    }
    let mut tag = 0u64;
    for round in 0..rounds {
        let mut hist: Vec<Vec<W>> = (0..objs).map(|_| Vec::new()).collect();
        for _ in 0..rng.range(1, 4) {
            // a burst of pipelined ops (ceph_test_rados strides: several in flight per object), then a kill
            for _ in 0..rng.range(1, 6) {
                let o = rng.range(0, objs as u64 - 1) as usize;
                // size-changing ops only while no size-changing op of the object is unacked (the client model needs one
                // known size for object_info); size-neutral ops may pile up unacked
                if hist[o].iter().any(|w| w.op.sizes() && !acked(&s, w)) {
                    continue;
                }
                let sure = hist[o].iter().all(|w| acked(&s, w));
                let mut cur = base[o].clone();
                for w in &hist[o] {
                    if w.op.sizes() {
                        w.op.apply(&mut cur);
                    }
                }
                if let Some(c) = &mut cur {
                    // sizes are known; bytes are not needed for the choice
                    c.truncate(c.len());
                }
                tag += 1;
                let Some(op) = pick(&mut rng, &cur, tag, chunk as u64, stripe, max, sure) else {
                    continue;
                };
                let (ops, size) = ec_ops(&op, cur.as_ref().map(|c| c.len() as u64));
                let l = s.lead_spg(POOL, 0);
                if let Ok(tid) = s.write_ops(POOL, 0, &format!("o{o}"), &ops, size) {
                    hist[o].push(W {
                        tid,
                        spg: l,
                        ver: s.last_version,
                        op,
                    });
                }
                s.run_for(rng.range(0, 3) * MS);
            }
            s.run_for(rng.range(0, 20) * MS);
            let v = osds[rng.range(0, osds.len() as u64 - 1) as usize];
            s.kill(v);
            s.run_for(rng.range(0, 300) * MS);
            if rng.range(0, 3) == 0 {
                // a second victim while the first is down (another member)
                let v2 = osds[rng.range(0, osds.len() as u64 - 1) as usize];
                if v2 != v {
                    s.kill(v2);
                    s.run_for(rng.range(0, 100) * MS);
                    s.restart(v2);
                }
            }
            s.restart(v);
            if reads {
                let ctx = format!("seed {seed} round {round} after restart of osd.{v}");
                let steps = rng.range(5, 40);
                nreads += window_reads(&mut s, &mut rng, &base, &hist, steps, &ctx);
            } else {
                s.run_for(rng.range(20, 400) * MS);
            }
        }
        base = check(
            &mut s,
            &be,
            &base,
            &hist,
            &format!("seed {seed} round {round}"),
        );
    }
    // the window reads must really run (a harness that never reads would pass silently)
    assert!(
        !reads || nreads > 0,
        "seed {seed}: no window read completed"
    );
}

#[test]
fn ec_opt_kill_restart_bytes_k2m1() {
    for seed in 0..seeds(24) {
        run(seed, 2, 1, 4096, None, 6);
    }
}

#[test]
fn ec_opt_kill_restart_bytes_k2m1_immediate_rollforward() {
    for seed in 0..seeds(12) {
        run(100 + seed, 2, 1, 4096, Some(0), 6);
    }
}

#[test]
fn ec_opt_kill_restart_bytes_k4m2() {
    for seed in 0..seeds(8) {
        run(200 + seed, 4, 2, 4096, None, 4);
    }
}

/// tids are per primary: the (spg, tid, version) triple names one write
fn acked(s: &Sim, w: &W) -> bool {
    s.acked
        .iter()
        .any(|(sp, t, v)| *sp == w.spg && *t == w.tid && *v == w.ver)
}

/// `EC_KILL_SEEDS=n` widens the sweep (local soak); default = the CI count.
fn seeds(default: u64) -> u64 {
    std::env::var("EC_KILL_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// OQ 41 diagnostics: with `ec_trace` on, a client read leaves the plan, the sub-read asks / replies and the shards'
/// sub-read and sub-write notes (one per op).
#[test]
fn ec_trace_notes_cover_a_client_read() {
    let mut s = Sim::new(4100);
    let osds = [0, 1, 2];
    for o in osds {
        s.add_osd_cfg(o, |c| {
            c.ec_enable = ec::EcEnable::All;
            c.ec_enable_optimized = ec::EcEnable::All;
            c.ec_primary = true;
            c.ec_opt_primary = true;
            c.ec_trace = true;
        });
    }
    s.run_for(50 * MS);
    s.create_pool_ec_opt(POOL, 2, 1, 4096, true, 1);
    s.run_for(2000 * MS);
    s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
    let d = fill(7, 3 * 8192 + 100);
    let tid = s
        .write_ops(
            POOL,
            0,
            "t",
            &[EcOp::Touch, EcOp::Write(0, d.clone())],
            Some(d.len() as u64),
        )
        .expect("accepted");
    let l = s.lead_spg(POOL, 0);
    s.wait_writes(&[tid], l);
    s.run_for(500 * MS);
    assert_eq!(read_ec(&mut s, "t", d.len() as u64).unwrap(), d);
    let mut notes = Vec::new();
    for o in osds {
        s.call(o, |set, _, _| {
            notes.extend(set.take_notices());
            vec![]
        });
    }
    let all = notes.join("\n");
    for want in [
        "rd#",
        "Client t [0,",
        "ask osd.",
        "reply osd.",
        "done Client",
        "subread from osd.",
        "subwrite from osd.",
    ] {
        assert!(all.contains(want), "no '{want}' in trace:\n{all}");
    }
}

/// OQ 41: the kill loop with client reads in the window after every restart (rollback / peering / recovery).
#[test]
fn ec_opt_kill_restart_window_reads_k2m1() {
    for seed in 0..seeds(24) {
        if let Ok(only) = std::env::var("EC_KILL_SEED_ONLY")
            && only.parse::<u64>().ok() != Some(300 + seed)
        {
            continue;
        }
        run_x(300 + seed, 2, 1, 4096, None, 6, true);
    }
}

/// OQ 41 root cause (lab-a 2026-10-15, capture fail-eba-4): a backfill target of shard j gets the writes of an object
/// beyond its cursor as log-only sub-writes. When the backfill push of that object starts while such writes are still in
/// flight, the push is rebuilt from shards that do not hold them yet: the target ends at an older version of the object
/// while its log says current (silently stale shard; a read from it, e.g. after it became primary, returns old data).
/// Writes stream into every object (several in flight per object) while the backfill runs; afterwards every shard must
/// encode the model and the read must return it.
#[test]
fn ec_opt_backfill_push_waits_for_writes_in_flight() {
    let (k, m, chunk) = (2u32, 1u32, 4096u32);
    let be = backend(k, m, chunk);
    let stripe = (k * chunk) as u64;
    for seed in 0..seeds(6) {
        // target shard: 0 = the primary's own shard id (the lab case), 1 = a data shard, 2 = parity
        let pos = (seed % 3) as usize;
        // short logs: the new member is backfilled (pg_temp keeps the old set acting), not log-recovered
        let mut s = Sim::new(9300 + seed);
        s.read_after_queue = true;
        for o in 0..5 {
            s.add_osd_cfg(o, |c| {
                c.ec_enable = ec::EcEnable::All;
                c.ec_enable_optimized = ec::EcEnable::All;
                c.ec_primary = true;
                c.ec_opt_primary = true;
                c.ec_trace = std::env::var("OQ41_TRACE").is_ok();
                c.min_pg_log_entries = 4;
                c.pg_log_trim_min = 1;
                c.pg_log_trim_max = 30;
            });
        }
        s.run_for(50 * MS);
        s.create_pool_ec_opt(POOL, k, m, chunk, true, 1);
        s.run_for(2000 * MS);
        s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
        let pg = denc::types::PgT::new(POOL, 0);
        let before = vec![3, 1, 2];
        s.set_up_override(pg, before.clone());
        s.run_until(60_000 * MS, "clean on the start set", |s| {
            s.pool_clean(POOL) && s.acting_of(pg) == before
        });
        let objs = 24usize;
        let mut model: Vec<Vec<u8>> = Vec::new();
        for i in 0..objs {
            let d = fill(500 + i as u64, (6 * stripe + 777) as usize);
            let tid = s
                .write_ops(
                    POOL,
                    0,
                    &format!("o{i}"),
                    &[EcOp::Touch, EcOp::Write(0, d.clone())],
                    Some(d.len() as u64),
                )
                .expect("accepted");
            let l = s.lead_spg(POOL, 0);
            s.wait_writes(&[tid], l);
            model.push(d);
        }
        // trim the logs past what the new member could recover from
        for r in 0..3u64 {
            for (i, cur) in model.iter_mut().enumerate() {
                let d = fill(700 + r * 100 + i as u64, cur.len());
                let tid = s
                    .write_ops(
                        POOL,
                        0,
                        &format!("o{i}"),
                        &[EcOp::Write(0, d.clone())],
                        Some(d.len() as u64),
                    )
                    .expect("accepted");
                let l = s.lead_spg(POOL, 0);
                s.wait_writes(&[tid], l);
                *cur = d;
            }
        }
        s.run_for(500 * MS);
        // shard `pos` moves to osd.4: osd.4 is backfilled while the old member keeps serving (pg_temp)
        let mut after = before.clone();
        after[pos] = 4;
        s.set_up_override(pg, after.clone());
        let mut bf_seen = false;
        let mut rng = Rng::new(seed);
        let mut tag = 10_000u64;
        let mut sent: Vec<(usize, denc::types::SpgT, u64)> = Vec::new();
        for _ in 0..4000 {
            if s.pool_clean(POOL) && s.acting_of(pg) == after {
                break;
            }
            {
                let l = s.lead_spg(POOL, 0);
                let p = s.primary_of(pg);
                let now = s
                    .pg(p, l)
                    .is_some_and(|g| g.state_string().contains("backfill"));
                if bf_seen && !now {
                    break; // backfill done: no writes into the acting change that follows
                }
                bf_seen |= now;
            }
            for _ in 0..rng.range(1, 4) {
                let i = rng.range(0, objs as u64 - 1) as usize;
                let n = model[i].len() as u64;
                tag += 1;
                let (ops, new) = if rng.range(0, 9) < 2 {
                    let d = fill(tag, rng.range(1, 2 * stripe) as usize);
                    let mut v = model[i].clone();
                    v.extend_from_slice(&d);
                    (vec![EcOp::Write(n, d)], v)
                } else {
                    let len = rng.range(1, 3 * chunk as u64).min(n);
                    let off = rng.range(0, n - len);
                    let d = fill(tag, len as usize);
                    let mut v = model[i].clone();
                    v[off as usize..(off + len) as usize].copy_from_slice(&d);
                    (vec![EcOp::Write(off, d)], v)
                };
                let size = new.len() as u64;
                if let Ok(tid) = s.write_ops(POOL, 0, &format!("o{i}"), &ops, Some(size)) {
                    sent.push((i, s.lead_spg(POOL, 0), tid));
                    model[i] = new;
                }
            }
            s.run_for(rng.range(0, 2) * MS);
        }
        assert!(bf_seen, "seed {seed}: no backfill happened");
        s.run_until(180_000 * MS, "clean after the backfill", |s| {
            s.pool_clean(POOL) && s.acting_of(pg) == after
        });
        s.run_for(2000 * MS);
        // a write in flight at the acting change (backfill done) may fail: its object has no single model, skip it
        let unsure: std::collections::BTreeSet<usize> = sent
            .iter()
            .filter(|(_, l, t)| !s.is_acked(*l, *t))
            .map(|x| x.0)
            .collect();
        assert!(
            unsure.len() < objs,
            "seed {seed}: {} objects with failed writes",
            unsure.len()
        );
        let acting = s.acting_of(pg);
        for (i, data) in model.iter().enumerate() {
            if unsure.contains(&i) {
                continue;
            }
            let name = format!("o{i}");
            let want = o_shards(&be, data);
            for (sh, osd) in acting.iter().enumerate() {
                let objs = s.nodes[osd].store.objects(s.spg_on(*osd, POOL, 0));
                let o = objs.get(&hobj(POOL, &name)).expect("object on every shard");
                if o.data != want[sh] {
                    dump_trace(&mut s, &format!(" {name} "));
                }
                assert!(
                    o.data == want[sh],
                    "seed {seed} (target shard {pos}): {name} shard {sh} on osd.{osd} differs (len {} want {}, first diff {:?})",
                    o.data.len(),
                    want[sh].len(),
                    o.data.iter().zip(&want[sh]).position(|(a, b)| a != b)
                );
            }
            assert_eq!(
                read_ec(&mut s, &name, data.len() as u64).ok().as_ref(),
                Some(data),
                "seed {seed}: {name} read"
            );
        }
    }
}

/// OQ 46 (lab-c 2026-10-16, PG 16.e, classic osd.2 backfill target of the croit-flashstore-osd primary's shard 0): a create
/// (here also re-create after a delete) accepted before the backfill scan but planned after it (queued behind an RMW
/// read) is not in the local listing of the batch and reaches the target log-only (beyond its cursor): it was never
/// pushed, the batch and FINISH set last_backfill MAX, the target lacked the object under a log that has it
/// (classic primary next interval: ENOENT, scrub "missing"). Deletes in flight left a stale copy on the target the same
/// way. Every object of the batch range with a write in flight must be pushed (or removed) once that write committed.
#[test]
fn ec_opt_backfill_covers_objects_created_by_writes_in_flight() {
    let (k, m, chunk) = (2u32, 1u32, 4096u32);
    let be = backend(k, m, chunk);
    let stripe = (k * chunk) as u64;
    for seed in 0..seeds(9) {
        let pos = (seed % 3) as usize;
        let mut s = Sim::new(9700 + seed);
        s.read_after_queue = true;
        for o in 0..5 {
            s.add_osd_cfg(o, |c| {
                c.ec_enable = ec::EcEnable::All;
                c.ec_enable_optimized = ec::EcEnable::All;
                c.ec_primary = true;
                c.ec_opt_primary = true;
                c.ec_trace = std::env::var("OQ41_TRACE").is_ok();
                c.min_pg_log_entries = 4;
                c.pg_log_trim_min = 1;
                c.pg_log_trim_max = 30;
            });
        }
        s.run_for(50 * MS);
        s.create_pool_ec_opt(POOL, k, m, chunk, true, 1);
        s.run_for(2000 * MS);
        s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
        let pg = denc::types::PgT::new(POOL, 0);
        let before = vec![3, 1, 2];
        s.set_up_override(pg, before.clone());
        s.run_until(60_000 * MS, "clean on the start set", |s| {
            s.pool_clean(POOL) && s.acting_of(pg) == before
        });
        let objs = 16usize;
        let mut model: Vec<Option<Vec<u8>>> = Vec::new();
        for i in 0..objs {
            let d = fill(500 + i as u64, (3 * stripe + 777) as usize);
            let tid = s
                .write_ops(
                    POOL,
                    0,
                    &format!("o{i}"),
                    &[EcOp::Touch, EcOp::Write(0, d.clone())],
                    Some(d.len() as u64),
                )
                .expect("accepted");
            let l = s.lead_spg(POOL, 0);
            s.wait_writes(&[tid], l);
            model.push(Some(d));
        }
        // trim the logs past what the new member could recover from
        for r in 0..3u64 {
            for (i, cur) in model.iter_mut().enumerate() {
                let d = fill(700 + r * 100 + i as u64, cur.as_ref().unwrap().len());
                let tid = s
                    .write_ops(
                        POOL,
                        0,
                        &format!("o{i}"),
                        &[EcOp::Write(0, d.clone())],
                        Some(d.len() as u64),
                    )
                    .expect("accepted");
                let l = s.lead_spg(POOL, 0);
                s.wait_writes(&[tid], l);
                *cur = Some(d);
            }
        }
        s.run_for(500 * MS);
        let mut after = before.clone();
        after[pos] = 4;
        s.set_up_override(pg, after.clone());
        let mut bf_seen = false;
        let mut rng = Rng::new(seed);
        let mut tag = 10_000u64;
        let mut sent: Vec<(usize, denc::types::SpgT, u64)> = Vec::new();
        for _ in 0..4000 {
            if s.pool_clean(POOL) && s.acting_of(pg) == after {
                break;
            }
            {
                let l = s.lead_spg(POOL, 0);
                let p = s.primary_of(pg);
                let now = s
                    .pg(p, l)
                    .is_some_and(|g| g.state_string().contains("backfill"));
                if bf_seen && !now {
                    break;
                }
                bf_seen |= now;
            }
            // bursts: RMW overwrites (remote sub-reads) ahead of creates / deletes of other objects
            for _ in 0..rng.range(1, 5) {
                let i = rng.range(0, objs as u64 - 1) as usize;
                tag += 1;
                let (ops, new) = match &model[i] {
                    None => {
                        let d = fill(tag, rng.range(1, 3 * stripe) as usize);
                        (vec![EcOp::Touch, EcOp::Write(0, d.clone())], Some(d))
                    }
                    Some(_) if rng.range(0, 9) < 3 => (vec![EcOp::Remove], None),
                    Some(cur) => {
                        let n = cur.len() as u64;
                        let len = rng.range(1, chunk as u64).min(n);
                        let off = rng.range(0, n - len);
                        let d = fill(tag, len as usize);
                        let mut v = cur.clone();
                        v[off as usize..(off + len) as usize].copy_from_slice(&d);
                        (vec![EcOp::Write(off, d)], Some(v))
                    }
                };
                let size = new.as_ref().map(|v| v.len() as u64);
                if let Ok(tid) = s.write_ops(POOL, 0, &format!("o{i}"), &ops, size) {
                    sent.push((i, s.lead_spg(POOL, 0), tid));
                    model[i] = new;
                }
            }
            s.run_for(rng.range(0, 2) * MS);
        }
        assert!(bf_seen, "seed {seed}: no backfill happened");
        s.run_until(180_000 * MS, "clean after the backfill", |s| {
            s.pool_clean(POOL) && s.acting_of(pg) == after
        });
        s.run_for(2000 * MS);
        let unsure: std::collections::BTreeSet<usize> = sent
            .iter()
            .filter(|(_, l, t)| !s.is_acked(*l, *t))
            .map(|x| x.0)
            .collect();
        assert!(
            unsure.len() < objs,
            "seed {seed}: {} objects with failed writes",
            unsure.len()
        );
        let acting = s.acting_of(pg);
        for (i, data) in model.iter().enumerate() {
            if unsure.contains(&i) {
                continue;
            }
            let name = format!("o{i}");
            for (sh, osd) in acting.iter().enumerate() {
                let objs = s.nodes[osd].store.objects(s.spg_on(*osd, POOL, 0));
                let have = objs.get(&hobj(POOL, &name)).map(|o| o.data.clone());
                let want = data.as_ref().map(|d| o_shards(&be, d)[sh].clone());
                if have != want {
                    dump_trace(&mut s, &format!(" {name} "));
                }
                assert!(
                    have == want,
                    "seed {seed} (target shard {pos}): {name} shard {sh} on osd.{osd}: present {} want present {} (len {:?} want {:?})",
                    have.is_some(),
                    want.is_some(),
                    have.as_ref().map(|v| v.len()),
                    want.as_ref().map(|v| v.len())
                );
            }
            if let Some(d) = data {
                assert_eq!(
                    read_ec(&mut s, &name, d.len() as u64).ok().as_ref(),
                    Some(d),
                    "seed {seed}: {name} read"
                );
            }
        }
    }
}

/// OQ 46, the lab order made deterministic: during the backfill reservation an RMW overwrite of `a` (its sub-read reply
/// held back) and the create of `b` queued behind it are accepted; the scan + digest run while both wait; then the
/// reply arrives, `b` is created (log-only to the target, beyond its cursor). The target must still get `b`.
#[test]
fn ec_opt_backfill_pushes_object_created_after_the_scan() {
    let (k, m, chunk) = (2u32, 1u32, 4096u32);
    let be = backend(k, m, chunk);
    for seed in 0..seeds(3) {
        let mut s = Sim::new(9800 + seed);
        s.read_after_queue = true;
        for o in 0..5 {
            s.add_osd_cfg(o, |c| {
                c.ec_enable = ec::EcEnable::All;
                c.ec_enable_optimized = ec::EcEnable::All;
                c.ec_primary = true;
                c.ec_opt_primary = true;
                c.ec_trace = std::env::var("OQ41_TRACE").is_ok();
                c.min_pg_log_entries = 4;
                c.pg_log_trim_min = 1;
                c.pg_log_trim_max = 30;
            });
        }
        s.run_for(50 * MS);
        s.create_pool_ec_opt(POOL, k, m, chunk, true, 1);
        s.run_for(2000 * MS);
        s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
        let pg = denc::types::PgT::new(POOL, 0);
        let before = vec![3, 1, 2];
        s.set_up_override(pg, before.clone());
        s.run_until(60_000 * MS, "clean on the start set", |s| {
            s.pool_clean(POOL) && s.acting_of(pg) == before
        });
        let mut model: std::collections::BTreeMap<String, Vec<u8>> = Default::default();
        for i in 0..40u64 {
            let name = format!("f{i}");
            let d = fill(300 + i, 3 * 8192 + 100);
            let tid = s
                .write_ops(
                    POOL,
                    0,
                    &name,
                    &[EcOp::Touch, EcOp::Write(0, d.clone())],
                    Some(d.len() as u64),
                )
                .expect("accepted");
            let l = s.lead_spg(POOL, 0);
            s.wait_writes(&[tid], l);
            model.insert(name, d);
        }
        // the new member of shard 0 (the primary's own shard id: the lab case) is backfilled, osd.3 stays primary
        let mut after = before.clone();
        after[0] = 4;
        s.set_up_override(pg, after.clone());
        let lead = s.lead_spg(POOL, 0);
        s.run_until(60_000 * MS, "backfill reservation", |s| {
            s.pg(3, lead)
                .is_some_and(|g| g.is_primary() && g.state_string().contains("backfill_wait"))
        });
        // shard 1's replies to the primary are held: the RMW of `a` waits, the create of `b` waits behind it
        s.blocked.insert((1, 3));
        let a = "f7".to_string();
        let mut va = model[&a].clone();
        let pd = fill(9001, 300);
        va[5000..5300].copy_from_slice(&pd);
        let ta = s
            .write_ops(POOL, 0, &a, &[EcOp::Write(5000, pd)], Some(va.len() as u64))
            .expect("rmw accepted");
        let vb = fill(9002, 2 * 8192 + 33);
        let tb = s
            .write_ops(
                POOL,
                0,
                "b",
                &[EcOp::Touch, EcOp::Write(0, vb.clone())],
                Some(vb.len() as u64),
            )
            .expect("create accepted");
        s.run_until(60_000 * MS, "backfilling", |s| {
            s.pg(3, lead)
                .is_some_and(|g| g.state_string().contains("backfilling"))
        });
        s.run_for(50 * MS); // scan + digest of the (only) batch
        s.heal();
        s.wait_writes(&[ta, tb], lead);
        model.insert(a, va);
        model.insert("b".into(), vb);
        s.run_until(180_000 * MS, "clean after the backfill", |s| {
            s.pool_clean(POOL) && s.acting_of(pg) == after
        });
        s.run_for(2000 * MS);
        for (name, data) in &model {
            let want = o_shards(&be, data);
            for (sh, osd) in after.iter().enumerate() {
                let objs = s.nodes[osd].store.objects(s.spg_on(*osd, POOL, 0));
                let have = objs.get(&hobj(POOL, name)).map(|o| o.data.clone());
                if have.as_ref() != Some(&want[sh]) {
                    dump_trace(&mut s, &format!(" {name} "));
                }
                assert!(
                    have.as_ref() == Some(&want[sh]),
                    "seed {seed}: {name} shard {sh} on osd.{osd}: present {}",
                    have.is_some()
                );
            }
            assert_eq!(
                read_ec(&mut s, name, data.len() as u64).ok().as_ref(),
                Some(data).cloned().as_ref(),
                "seed {seed}: {name} read"
            );
        }
    }
}

/// `OQ41_TRACE`: print every `ectrace` note of every OSD that mentions `needle` (diagnostics of a failing seed).
fn dump_trace(s: &mut Sim, needle: &str) {
    if std::env::var("OQ41_TRACE").is_err() {
        return;
    }
    let ids: Vec<i32> = s.nodes.keys().copied().collect();
    for o in ids {
        let mut notes = Vec::new();
        s.call(o, |set, _, _| {
            notes.extend(set.take_notices());
            vec![]
        });
        for n in notes.iter().filter(|n| n.contains(needle)) {
            eprintln!("osd.{o} {n}");
        }
    }
}

/// OQ 45: a write applied only on the primary (parity killed before it applied, the nonprimary shard got the sub-write
/// only after its interval change: discarded) must be rolled back at the next peering (the nonprimary's shorter log is
/// the get-log shard, prim spec C.2/C.3), never kept as authoritative with one shard holding it.
#[test]
fn ec_opt_write_only_on_primary_is_rolled_back() {
    only_on_primary(false);
}

/// OQ 45 lab trigger (lab-c 2026-10-16, PG 15.4): partial writes that skip the nonprimary shard leave its log tail older
/// than the primary's; the get-log pass picked it, but its older tail made the primary fall back to its own log: the
/// keep rule never ran, the primary-only entry stayed authoritative -> unfound object, client EIO.
#[test]
fn ec_opt_write_only_on_primary_is_rolled_back_np_tail_behind() {
    only_on_primary(true);
}

fn only_on_primary(np_tail_behind: bool) {
    let (k, m, chunk) = (2u32, 1u32, 4096u32);
    for seed in 0..seeds(6) {
        let mut s = Sim::new(9500 + seed);
        s.read_after_queue = true;
        for o in 0..4 {
            s.add_osd_cfg(o, |c| {
                c.ec_enable = ec::EcEnable::All;
                c.ec_enable_optimized = ec::EcEnable::All;
                c.ec_primary = true;
                c.ec_opt_primary = true;
                c.ec_trace = std::env::var("OQ41_TRACE").is_ok();
                if np_tail_behind {
                    c.min_pg_log_entries = 4;
                    c.pg_log_trim_min = 1;
                    c.pg_log_trim_max = 30;
                }
            });
        }
        s.run_for(50 * MS);
        s.create_pool_ec_opt(POOL, k, m, chunk, true, 1);
        s.run_for(2000 * MS);
        s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
        let pg = denc::types::PgT::new(POOL, 0);
        let set = vec![3, 1, 2];
        s.set_up_override(pg, set.clone());
        s.run_until(60_000 * MS, "clean on the set", |s| {
            s.pool_clean(POOL) && s.acting_of(pg) == set
        });
        let stripe = (k * chunk) as u64;
        if np_tail_behind {
            // partial writes (chunk 0 only: shards 0 + parity) trim the primary's log past the nonprimary's tail
            let p = fill(9, (2 * stripe) as usize);
            let tid = s
                .write_ops(
                    POOL,
                    0,
                    "p",
                    &[EcOp::Touch, EcOp::Write(0, p.clone())],
                    Some(p.len() as u64),
                )
                .expect("accepted");
            let l = s.lead_spg(POOL, 0);
            s.wait_writes(&[tid], l);
            for i in 0..60u64 {
                let tid = s
                    .write_ops(
                        POOL,
                        0,
                        "p",
                        &[EcOp::Write(0, fill(100 + i, 64))],
                        Some(p.len() as u64),
                    )
                    .expect("accepted");
                let l = s.lead_spg(POOL, 0);
                s.wait_writes(&[tid], l);
            }
            s.run_for(500 * MS);
        }
        let base = fill(1, (4 * stripe + 300) as usize);
        let tid = s
            .write_ops(
                POOL,
                0,
                "o",
                &[EcOp::Touch, EcOp::Write(0, base.clone())],
                Some(base.len() as u64),
            )
            .expect("accepted");
        let l = s.lead_spg(POOL, 0);
        s.wait_writes(&[tid], l);
        s.run_for(500 * MS);
        // the nonprimary shard's link held, the write goes out, parity dies before it arrives
        s.partition(3, 1);
        let add = fill(2, (3 * stripe + 77) as usize);
        let mut grown = base.clone();
        grown.extend_from_slice(&add);
        let w = s.write_ops(
            POOL,
            0,
            "o",
            &[EcOp::Write(base.len() as u64, add)],
            Some(grown.len() as u64),
        );
        assert!(w.is_ok(), "seed {seed}: write refused {w:?}");
        s.run_for(seed * 100_000);
        s.kill(2);
        let e0 = s.epoch();
        s.run_until(30_000 * MS, "parity marked down", |s| s.epoch() > e0);
        s.run_for(50 * MS);
        s.heal();
        s.run_for(2000 * MS);
        s.restart(2);
        s.run_until(120_000 * MS, "clean again", |s| s.pool_clean(POOL));
        s.run_for(1000 * MS);
        let got = read_ec(&mut s, "o", grown.len() as u64);
        assert!(
            got.as_ref().is_ok_and(|g| *g == base || *g == grown),
            "seed {seed}: read {:?} (len) want base {} or grown {}",
            got.as_ref().map(|g| g.len()),
            base.len(),
            grown.len()
        );
    }
}
