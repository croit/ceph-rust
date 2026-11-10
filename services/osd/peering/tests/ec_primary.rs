// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! EC primary role (adr 0049): peering, write pipeline, sub-writes, rollback info, on the deterministic simulator.
mod common;
use common::*;
use ecback::Backend;
use peering::PgStoreOps;
use std::collections::BTreeMap;

const POOL: u64 = 1;

fn payload(i: usize, len: usize) -> Vec<u8> {
    (0..len).map(|j| ((i * 131 + j * 7) % 251) as u8).collect()
}

fn ec_cluster(seed: u64, osds: &[i32], k: u32, m: u32, chunk: u32, ow: bool, pg_num: u32) -> Sim {
    ec_cluster_with(seed, osds, k, m, chunk, ow, pg_num, |_| {})
}

#[expect(clippy::too_many_arguments)]
fn ec_cluster_with(
    seed: u64,
    osds: &[i32],
    k: u32,
    m: u32,
    chunk: u32,
    ow: bool,
    pg_num: u32,
    f: impl Fn(&mut peering::Config),
) -> Sim {
    let mut s = Sim::new(seed);
    for o in osds {
        s.add_osd_cfg(*o, |c| {
            c.ec_enable = ec::EcEnable::All;
            c.ec_primary = true;
            f(c);
        });
    }
    s.run_for(50 * MS);
    s.create_pool_ec(POOL, k, m, chunk, ow, pg_num);
    s.run_for(2000 * MS);
    if !s.pool_clean(POOL) {
        eprintln!("{:?}", s.stats);
        for (o, n) in s.nodes.iter_mut() {
            eprintln!("osd.{o}: {:?}", n.set.take_notices());
        }
    }
    s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
    s
}

fn backend(k: u32, m: u32, chunk: u32, ow: bool) -> Backend {
    Backend::from_parts(
        "isa",
        "reed_sol_van",
        (k, m),
        (k * chunk, chunk),
        (0..k + m).collect(),
        ow,
    )
    .unwrap()
}

/// Every shard of every object equals the encoding of the model (the write path is the oracle's reference).
fn assert_shards(s: &Sim, be: &Backend, seed: u32, model: &BTreeMap<String, Vec<u8>>) {
    let acting = s.acting_of(denc::types::PgT::new(POOL, seed));
    for (name, data) in model {
        let mut padded = data.clone();
        padded.resize(data.len().div_ceil(be.s as usize) * be.s as usize, 0);
        let want = be.encode_stripes(&padded);
        let h = hobj(POOL, name);
        for (sh, osd) in acting.iter().enumerate() {
            let objs = s.nodes[osd].store.objects(s.spg_on(*osd, POOL, seed));
            let o = objs
                .get(&h)
                .unwrap_or_else(|| panic!("{name}: shard {sh} on osd.{osd} lacks the object"));
            assert_eq!(o.data, want[sh], "{name}: shard {sh} on osd.{osd}");
        }
    }
    s.assert_ec_persisted_consistent();
}

/// Apply store ops to the plain model (clamped zero, gap fill, as the store would).
fn model_apply(m: &mut Option<Vec<u8>>, ops: &[EcOp]) {
    for op in ops {
        match op {
            EcOp::Touch => {
                m.get_or_insert_with(Vec::new);
            }
            EcOp::Write(off, d) => {
                let v = m.get_or_insert_with(Vec::new);
                let end = *off as usize + d.len();
                if v.len() < end {
                    v.resize(end, 0);
                }
                v[*off as usize..end].copy_from_slice(d);
            }
            EcOp::Zero(off, len) => {
                if let Some(v) = m {
                    let end = (*off + *len).min(v.len() as u64) as usize;
                    if (*off as usize) < end {
                        v[*off as usize..end].fill(0);
                    }
                }
            }
            EcOp::Trunc(sz) => m.get_or_insert_with(Vec::new).resize(*sz as usize, 0),
            EcOp::Remove => *m = None,
            EcOp::Attr(..) | EcOp::OmapSet(_) | EcOp::OmapRmRange(..) => {
                m.get_or_insert_with(Vec::new);
            }
        }
    }
}

/// One logical write, acked, then every shard checked against the model.
fn step(
    s: &mut Sim,
    be: &Backend,
    model: &mut BTreeMap<String, Vec<u8>>,
    name: &str,
    ops: Vec<EcOp>,
) {
    let mut m = model.get(name).cloned();
    model_apply(&mut m, &ops);
    let lead = s.lead_spg(POOL, 0);
    let tid = s
        .write_ops(POOL, 0, name, &ops, m.as_ref().map(|v| v.len() as u64))
        .expect("accepted");
    s.wait_writes(&[tid], lead);
    s.run_for(60 * MS);
    match m {
        Some(v) => {
            model.insert(name.to_string(), v);
        }
        None => {
            model.remove(name);
        }
    }
    assert_shards(s, be, 0, model);
}

#[test]
fn ec_primary_overwrites_rmw_and_truncates() {
    let (k, m, chunk) = (2, 1, 32);
    let mut s = ec_cluster(22, &[0, 1, 2], k, m, chunk, true, 1);
    let be = backend(k, m, chunk, true);
    let mut model = BTreeMap::new();
    let st = be.s as usize;
    step(
        &mut s,
        &be,
        &mut model,
        "a",
        vec![EcOp::Touch, EcOp::Write(0, payload(1, st * 3 + 5))],
    );
    step(
        &mut s,
        &be,
        &mut model,
        "a",
        vec![EcOp::Write(st as u64 / 2, payload(2, st * 2))],
    );
    step(
        &mut s,
        &be,
        &mut model,
        "a",
        vec![EcOp::Write(3, payload(3, 7))],
    );
    step(
        &mut s,
        &be,
        &mut model,
        "a",
        vec![EcOp::Zero(st as u64 - 4, 9)],
    );
    let sz = model["a"].len() as u64;
    step(
        &mut s,
        &be,
        &mut model,
        "a",
        vec![EcOp::Write(sz, payload(4, st + 3))],
    );
    step(
        &mut s,
        &be,
        &mut model,
        "a",
        vec![EcOp::Trunc(st as u64 + 3)],
    );
    step(
        &mut s,
        &be,
        &mut model,
        "a",
        vec![EcOp::Trunc(st as u64 * 2 + 10)],
    );
    step(
        &mut s,
        &be,
        &mut model,
        "a",
        vec![EcOp::Trunc(0), EcOp::Write(0, payload(5, 77))],
    );
    step(
        &mut s,
        &be,
        &mut model,
        "b",
        vec![EcOp::Touch, EcOp::Write(0, payload(6, 30))],
    );
    step(&mut s, &be, &mut model, "a", vec![EcOp::Remove]);
    s.assert_no_roundtrip_mismatch();
    for o in s.acting_of(s.lead_spg(POOL, 0).pgid) {
        let sp = s.spg_on(o, POOL, 0);
        let pg = s.pg(o, sp).unwrap();
        assert_eq!(pg.log().log.can_rollback_to, pg.log().head(), "osd.{o} crt");
        assert!(s.nodes[&o].store.stash(sp).is_empty(), "osd.{o} stash");
    }
}

#[test]
fn ec_primary_pipelined_writes_to_one_object() {
    let (k, m, chunk) = (2, 1, 32);
    let mut s = ec_cluster(23, &[0, 1, 2], k, m, chunk, true, 1);
    let be = backend(k, m, chunk, true);
    let lead = s.lead_spg(POOL, 0);
    let st = be.s as usize;
    let mut model: Option<Vec<u8>> = None;
    let mut tids = vec![];
    // submitted back to back: later writes depend on the projected state of earlier ones
    for i in 0..10 {
        let off = (i * 17 % 90) as u64;
        let ops = vec![EcOp::Write(off, payload(i, st / 2 + i))];
        model_apply(&mut model, &ops);
        let sz = model.as_ref().unwrap().len() as u64;
        tids.push(s.write_ops(POOL, 0, "p", &ops, Some(sz)).expect("accepted"));
    }
    s.wait_writes(&tids, lead);
    s.run_for(300 * MS);
    let mut want = BTreeMap::new();
    want.insert("p".to_string(), model.unwrap());
    assert_shards(&s, &be, 0, &want);
}

/// Shards on the live acting members only (a down member has no current copy).
fn assert_live_shards(s: &Sim, be: &Backend, model: &BTreeMap<String, Vec<u8>>) {
    let acting = s.acting_of(denc::types::PgT::new(POOL, 0));
    for (name, data) in model {
        let mut padded = data.clone();
        padded.resize(data.len().div_ceil(be.s as usize) * be.s as usize, 0);
        let want = be.encode_stripes(&padded);
        for (sh, osd) in acting.iter().enumerate() {
            if *osd == pgwire::NONE_OSD {
                continue;
            }
            let objs = s.nodes[osd].store.objects(s.spg_on(*osd, POOL, 0));
            let o = objs
                .get(&hobj(POOL, name))
                .unwrap_or_else(|| panic!("{name}: shard {sh} on osd.{osd} lacks the object"));
            assert_eq!(o.data, want[sh], "{name}: shard {sh} on osd.{osd}");
        }
    }
}

/// Client read through the op-layer interface: `ec_wait` until ready, then the cache.
fn read_ec(s: &mut Sim, name: &str, off: u64, len: u64) -> Result<Vec<u8>, i32> {
    let lead = s.lead_spg(POOL, 0);
    let osd = s.primary_of(lead.pgid);
    let h = hobj(POOL, name);
    for _ in 0..8000 {
        let mut ready = false;
        s.call(osd, |set, now, store| {
            let (r, acts) = set
                .with_pg(now, lead, store, |pg| {
                    pg.ec_wait(&h, off, len, store).is_none()
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
    let r = pg.ec_cache_read(&h, off, len, size);
    s.ec_ops_ran(osd);
    let pg = s.pg(osd, lead).unwrap();
    if r.is_err() {
        eprintln!(
            "read {name} {off}+{len} size {size}: {r:?}\ndisc {:?}\nerr {:?}\n{}",
            pg.counters().discards,
            pg.counters().errors,
            s.dump()
        );
    }
    r
}

#[test]
fn ec_primary_reads_and_degraded_reads() {
    let (k, m, chunk) = (3, 2, 32);
    let mut s = ec_cluster(25, &[0, 1, 2, 3, 4], k, m, chunk, true, 1);
    let be = backend(k, m, chunk, true);
    let mut model = BTreeMap::new();
    for i in 0..4 {
        let name = format!("r{i}");
        step(
            &mut s,
            &be,
            &mut model,
            &name,
            vec![EcOp::Touch, EcOp::Write(0, payload(i, 20 + i * 150))],
        );
    }
    let check = |s: &mut Sim, model: &BTreeMap<String, Vec<u8>>| {
        for (n, d) in model {
            assert_eq!(&read_ec(s, n, 0, d.len() as u64).unwrap(), d, "{n} whole");
            if d.len() > 40 {
                assert_eq!(
                    read_ec(s, n, 7, 30).unwrap(),
                    d[7..37].to_vec(),
                    "{n} slice"
                );
            }
            // past the end clamps; absent object
            assert_eq!(
                read_ec(s, n, d.len() as u64 + 5, 10).unwrap(),
                Vec::<u8>::new()
            );
        }
        assert_eq!(read_ec(s, "absent", 0, 10), Err(2));
    };
    check(&mut s, &model);
    // lose one shard OSD: reads decode around it
    let lead = s.lead_spg(POOL, 0);
    let prim = s.primary_of(lead.pgid);
    let victim = *s.acting_of(lead.pgid).iter().find(|o| **o != prim).unwrap();
    s.kill(victim);
    s.mark_down(victim);
    s.run_until(30_000 * MS, "active again", |s| {
        let p = s.primary_of(lead.pgid);
        s.pg(p, lead).is_some_and(|pg| {
            pg.acting().contains(&pgwire::NONE_OSD)
                && pg.map_epoch() == s.epoch()
                && pg.state_bits() & pgwire::state::ACTIVE != 0
        })
    });
    check(&mut s, &model);
    // a second one: still k=3 of 5
    let victim2 = *s
        .acting_of(lead.pgid)
        .iter()
        .find(|o| **o != prim && **o != pgwire::NONE_OSD)
        .unwrap();
    s.kill(victim2);
    s.mark_down(victim2);
    s.run_until(30_000 * MS, "active again 2", |s| {
        let p = s.primary_of(lead.pgid);
        s.pg(p, lead).is_some_and(|pg| {
            pg.acting()
                .iter()
                .filter(|o| **o == pgwire::NONE_OSD)
                .count()
                == 2
                && pg.map_epoch() == s.epoch()
                && pg.state_bits() & pgwire::state::PEERED != 0
        })
    });
    // min_size = k+1 = 4: with k = 3 shards the PG is peered but not active (no client io); the decode itself works
    let p = s.primary_of(lead.pgid);
    assert_eq!(
        s.pg(p, lead).unwrap().state_bits() & pgwire::state::ACTIVE,
        0
    );
    check(&mut s, &model);
}

#[test]
fn ec_primary_degraded_writes_with_a_shard_down() {
    let (k, m, chunk) = (3, 2, 32);
    let osds = [0, 1, 2, 3, 4];
    let mut s = ec_cluster(24, &osds, k, m, chunk, true, 1);
    let be = backend(k, m, chunk, true);
    let lead = s.lead_spg(POOL, 0);
    let prim = s.primary_of(lead.pgid);
    let acting = s.acting_of(lead.pgid);
    let victim = *acting.iter().find(|o| **o != prim).unwrap();
    let mut model = BTreeMap::new();
    step(
        &mut s,
        &be,
        &mut model,
        "pre",
        vec![EcOp::Touch, EcOp::Write(0, payload(1, 200))],
    );
    s.kill(victim);
    s.mark_down(victim);
    s.run_until(30_000 * MS, "active again", |s| {
        let p = s.primary_of(lead.pgid);
        s.pg(p, lead).is_some_and(|pg| {
            pg.acting().contains(&pgwire::NONE_OSD)
                && pg.map_epoch() == s.epoch()
                && pg.state_bits() & pgwire::state::ACTIVE != 0
        })
    });
    let mut tids = vec![];
    for i in 0..8 {
        let name = format!("d{i}");
        let d = payload(i + 7, 50 + i * 40);
        tids.push(s.write_obj(POOL, 0, &name, &d).expect("accepted"));
        model.insert(name, d);
    }
    // overwrite of an old object while degraded: the stripe read decodes around the missing shard
    let mut pre = model["pre"].clone();
    pre[10..60].copy_from_slice(&payload(9, 50));
    let t = s
        .write_ops(
            POOL,
            0,
            "pre",
            &[EcOp::Write(10, payload(9, 50))],
            Some(200),
        )
        .expect("accepted");
    model.insert("pre".into(), pre);
    tids.push(t);
    s.wait_writes(&tids, lead);
    s.run_for(300 * MS);
    assert_live_shards(&s, &be, &model);
}

/// The primary dies with writes in flight: a surviving shard leads, acked writes are intact, in-flight ones are
/// either complete or gone on every live shard (rolled back), never torn.
#[test]
fn ec_primary_failover_keeps_acked_writes_and_rolls_back_the_rest() {
    for seed in 0..16u64 {
        let (k, m, chunk) = (3, 2, 32);
        let osds = [0, 1, 2, 3, 4];
        let mut s = ec_cluster(30 + seed, &osds, k, m, chunk, true, 1);
        let be = backend(k, m, chunk, true);
        let lead = s.lead_spg(POOL, 0);
        let prim = s.primary_of(lead.pgid);
        let mut model = BTreeMap::new();
        for i in 0..6 {
            let name = format!("a{i}");
            let d = payload(i, 60 + i * 30);
            let t = s.write_obj(POOL, 0, &name, &d).unwrap();
            s.wait_writes(&[t], lead);
            model.insert(name, d);
        }
        // in flight when the primary dies (some shards have them, some do not)
        let mut flight: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for i in 0..5 {
            let name = format!("f{i}");
            let d = payload(i + 20, 90 + i * 20);
            s.write_obj(POOL, 0, &name, &d).unwrap();
            flight.insert(name, d);
            let dt = (s.rng.range(0, 3) * MS) / 2;
            s.run_for(dt);
        }
        s.kill(prim);
        s.mark_down(prim);
        s.run_until(60_000 * MS, "new primary active", |s| {
            let l = s.lead_spg(POOL, 0);
            let p = s.primary_of(l.pgid);
            p != prim
                && s.pg(p, l).is_some_and(|pg| {
                    pg.map_epoch() == s.epoch() && pg.state_bits() & pgwire::state::ACTIVE != 0
                })
        });
        s.run_for(500 * MS);
        // acked writes intact on every live shard
        assert_live_shards(&s, &be, &model);
        // in-flight ones: present everywhere with the exact content, or nowhere
        let acting = s.acting_of(lead.pgid);
        for (name, d) in &flight {
            let mut padded = d.clone();
            padded.resize(d.len().div_ceil(be.s as usize) * be.s as usize, 0);
            let want = be.encode_stripes(&padded);
            let mut seen = vec![];
            for (sh, osd) in acting.iter().enumerate() {
                if *osd == pgwire::NONE_OSD {
                    continue;
                }
                let objs = s.nodes[osd].store.objects(s.spg_on(*osd, POOL, 0));
                seen.push(objs.get(&hobj(POOL, name)).map(|o| o.data == want[sh]));
            }
            assert!(
                seen.iter().all(|x| *x == Some(true)) || seen.iter().all(|x| x.is_none()),
                "seed {seed}: {name} is torn across shards: {seen:?}"
            );
        }
        // the new primary serves new writes
        let l2 = s.lead_spg(POOL, 0);
        let d = payload(99, 150);
        let t = s.write_obj(POOL, 0, "after", &d).unwrap();
        s.wait_writes(&[t], l2);
        model.insert("after".into(), d);
        s.run_for(300 * MS);
        assert_live_shards(&s, &be, &model);
        // the old primary comes back (its divergent entries roll back) and the PG recovers completely: no object
        // stays unfound / missing on any shard
        s.restart(prim);
        s.run_until(60_000 * MS, "old primary back, pool clean", |s| {
            s.pool_clean(POOL)
        });
        s.run_for(500 * MS);
        for (name, d) in &flight {
            // in-flight writes were unacked: either everywhere or nowhere; if everywhere they must be the exact data
            if s.nodes[&s.acting_of(lead.pgid)[0]]
                .store
                .objects(s.spg_on(s.acting_of(lead.pgid)[0], POOL, 0))
                .contains_key(&hobj(POOL, name))
            {
                model.insert(name.clone(), d.clone());
            }
        }
        assert_shards(&s, &be, 0, &model);
        for o in s.acting_of(lead.pgid) {
            let pg = s.pg(o, s.spg_on(o, POOL, 0)).unwrap();
            assert!(
                pg.missing().is_empty(),
                "seed {seed}: osd.{o} still misses objects"
            );
        }
    }
}

/// A shard OSD is away while writes (new objects, overwrites, deletes) continue; when it returns it is recovered
/// from the other shards (decode + push) and the PG gets clean with every shard byte-exact.
#[test]
fn ec_primary_recovers_a_returning_shard() {
    for (k, m, nosd, victim_pos) in [(2, 1, 3, 1usize), (3, 2, 5, 2), (3, 2, 5, 4), (2, 2, 4, 0)] {
        let chunk = 32;
        let osds: Vec<i32> = (0..nosd).collect();
        let mut s = ec_cluster(40 + victim_pos as u64, &osds, k, m, chunk, true, 1);
        let be = backend(k, m, chunk, true);
        let lead = s.lead_spg(POOL, 0);
        let acting = s.acting_of(lead.pgid);
        let victim = acting[victim_pos];
        let mut model = BTreeMap::new();
        for i in 0..4 {
            step(
                &mut s,
                &be,
                &mut model,
                &format!("o{i}"),
                vec![EcOp::Touch, EcOp::Write(0, payload(i, 70 + i * 50))],
            );
        }
        let prim = s.primary_of(lead.pgid);
        if victim == prim {
            continue; // the primary's own death is the failover test
        }
        s.kill(victim);
        s.run_until(30_000 * MS, "degraded active", |s| {
            let p = s.primary_of(lead.pgid);
            s.pg(p, lead).is_some_and(|pg| {
                pg.acting().contains(&pgwire::NONE_OSD)
                    && pg.map_epoch() == s.epoch()
                    && pg.state_bits() & pgwire::state::ACTIVE != 0
            })
        });
        // writes while it is away
        let live =
            |s: &mut Sim, model: &mut BTreeMap<String, Vec<u8>>, name: &str, ops: Vec<EcOp>| {
                let mut mm = model.get(name).cloned();
                model_apply(&mut mm, &ops);
                let tid = s
                    .write_ops(POOL, 0, name, &ops, mm.as_ref().map(|v| v.len() as u64))
                    .expect("accepted");
                let l = s.lead_spg(POOL, 0);
                s.wait_writes(&[tid], l);
                match mm {
                    Some(v) => model.insert(name.to_string(), v),
                    None => model.remove(name),
                };
            };
        for i in 4..9 {
            live(
                &mut s,
                &mut model,
                &format!("o{i}"),
                vec![EcOp::Touch, EcOp::Write(0, payload(i, 40 + i * 30))],
            );
        }
        live(
            &mut s,
            &mut model,
            "o0",
            vec![EcOp::Write(5, payload(77, 90))],
        );
        live(
            &mut s,
            &mut model,
            "o1",
            vec![EcOp::Trunc(0), EcOp::Write(0, payload(78, 33))],
        );
        live(&mut s, &mut model, "o2", vec![EcOp::Remove]);
        s.run_for(200 * MS);
        s.restart(victim);
        s.run_until(60_000 * MS, "recovered and clean", |s| s.pool_clean(POOL));
        s.run_for(300 * MS);
        assert_shards(&s, &be, 0, &model);
        // recovery counters (spec pg-io-stats.md 2): o0, o1, o4..o8 rebuilt on the returning shard
        let p = s.primary_of(lead.pgid);
        let sum = &s
            .pg(p, s.lead_spg(POOL, 0))
            .expect("primary pg")
            .info()
            .stats
            .stats
            .sum;
        assert!(
            sum.num_objects_recovered >= 7 && sum.num_bytes_recovered > 0,
            "ec recovery counted ({}, {})",
            sum.num_objects_recovered,
            sum.num_bytes_recovered
        );
        // a recovered object is readable through the decode path too
        for (n, d) in model.clone() {
            assert_eq!(read_ec(&mut s, &n, 0, d.len() as u64).unwrap(), d, "{n}");
        }
        // and the removed one is gone from every shard
        for (sh, o) in s.acting_of(lead.pgid).iter().enumerate() {
            let objs = s.nodes[o].store.objects(s.spg_on(*o, POOL, 0));
            assert!(!objs.contains_key(&hobj(POOL, "o2")), "o2 on shard {sh}");
        }
    }
}

/// Deep scrub of an append-only EC PG led here: a bit flip in ANY shard (data or parity, ours or a peer's) is found by the
/// shard hash check and repaired by rebuilding that shard from the others.
#[test]
fn ec_primary_deep_scrub_finds_and_repairs_a_flipped_shard() {
    let (k, m, chunk) = (3, 2, 32);
    for victim_pos in 0..5usize {
        let mut s = ec_cluster(
            60 + victim_pos as u64,
            &[0, 1, 2, 3, 4],
            k,
            m,
            chunk,
            false,
            1,
        );
        let be = backend(k, m, chunk, false);
        let lead = s.lead_spg(POOL, 0);
        let prim = s.primary_of(lead.pgid);
        let mut model = BTreeMap::new();
        for i in 0..6 {
            let name = format!("s{i}");
            let d = payload(i, 30 + i * 70);
            let ss = denc::to_vec(&replwire::SnapSet::default()).unwrap();
            let t = s
                .write_ops(
                    POOL,
                    0,
                    &name,
                    &[
                        EcOp::Touch,
                        EcOp::Write(0, d.clone()),
                        EcOp::Attr("snapset", ss),
                    ],
                    Some(d.len() as u64),
                )
                .unwrap();
            s.wait_writes(&[t], lead);
            model.insert(name, d);
        }
        s.run_for(300 * MS);
        // a clean PG scrubs clean
        let scrub = |s: &mut Sim, repair: bool| {
            s.call(prim, |set, now, st| {
                set.request_scrub(now, lead, true, repair, st)
            });
            let before = s.pg(prim, lead).unwrap().scrub_counts().0;
            s.run_until(60_000 * MS, "scrub finished", move |s| {
                let p = s.pg(prim, lead).unwrap();
                p.scrub_counts().0 > before && !p.scrub_running() && p.is_clean()
            });
            s.run_for(300 * MS);
        };
        scrub(&mut s, false);
        let errs = |s: &Sim| {
            s.pg(prim, lead)
                .unwrap()
                .info()
                .stats
                .stats
                .sum
                .num_scrub_errors
        };
        assert_eq!(errs(&s), 0, "pos {victim_pos}: clean pg reports errors");
        // flip a byte of one shard of one object
        let osd = s.acting_of(lead.pgid)[victim_pos];
        let sp = s.spg_on(osd, POOL, 0);
        s.nodes
            .get_mut(&osd)
            .unwrap()
            .store
            .pgs
            .get_mut(&sp)
            .unwrap()
            .objects
            .get_mut(&hobj(POOL, "s3"))
            .unwrap()
            .data[5] ^= 0xFF;
        scrub(&mut s, false);
        assert!(errs(&s) > 0, "pos {victim_pos}: flipped shard not found");
        // repair
        scrub(&mut s, true);
        s.run_until(60_000 * MS, "repaired and clean", |s| s.pool_clean(POOL));
        s.run_for(500 * MS);
        assert_shards(&s, &be, 0, &model);
        scrub(&mut s, false);
        assert_eq!(errs(&s), 0, "pos {victim_pos}: errors remain after repair");
    }
}

/// A shard OSD comes back with an EMPTY store (disk replaced): backfill rebuilds its shard of every object.
#[test]
fn ec_primary_backfills_a_wiped_shard() {
    for (k, m, nosd, victim_pos) in [(2, 1, 3, 2usize), (3, 2, 5, 1), (3, 2, 5, 3)] {
        let chunk = 32;
        let osds: Vec<i32> = (0..nosd).collect();
        let mut s = ec_cluster(50 + victim_pos as u64, &osds, k, m, chunk, true, 1);
        let be = backend(k, m, chunk, true);
        let lead = s.lead_spg(POOL, 0);
        let victim = s.acting_of(lead.pgid)[victim_pos];
        if victim == s.primary_of(lead.pgid) {
            continue;
        }
        let mut model = BTreeMap::new();
        for i in 0..10 {
            step(
                &mut s,
                &be,
                &mut model,
                &format!("b{i}"),
                vec![EcOp::Touch, EcOp::Write(0, payload(i, 30 + i * 61))],
            );
        }
        s.kill(victim);
        s.run_until(30_000 * MS, "degraded active", |s| {
            let p = s.primary_of(lead.pgid);
            s.pg(p, lead).is_some_and(|pg| {
                pg.acting().contains(&pgwire::NONE_OSD)
                    && pg.map_epoch() == s.epoch()
                    && pg.state_bits() & pgwire::state::ACTIVE != 0
            })
        });
        // changes while it is away, then the disk is replaced
        step_degraded(
            &mut s,
            &mut model,
            "b3",
            vec![EcOp::Write(4, payload(90, 70))],
        );
        step_degraded(
            &mut s,
            &mut model,
            "new",
            vec![EcOp::Touch, EcOp::Write(0, payload(91, 150))],
        );
        step_degraded(&mut s, &mut model, "b5", vec![EcOp::Remove]);
        s.nodes.get_mut(&victim).unwrap().store = peering::MemStore::new();
        s.restart(victim);
        s.run_until(60_000 * MS, "backfilled and clean", |s| s.pool_clean(POOL));
        s.run_for(300 * MS);
        assert_shards(&s, &be, 0, &model);
        for (n, d) in model.clone() {
            assert_eq!(read_ec(&mut s, &n, 0, d.len() as u64).unwrap(), d, "{n}");
        }
    }
}

/// Backfill destinations can overlap another acting shard on the same OSD.
#[test]
fn ec_backfill_target_can_also_hold_an_old_acting_shard() {
    let (k, m, chunk) = (2, 1, 32);
    let mut s = ec_cluster(507, &[0, 1, 2, 3], k, m, chunk, true, 1);
    let be = backend(k, m, chunk, true);
    let pg = denc::types::PgT::new(POOL, 0);
    let before = s.acting_of(pg);
    let spare = (0..4).find(|o| !before.contains(o)).unwrap();
    let mut model = BTreeMap::new();
    for i in 0..6 {
        step(
            &mut s,
            &be,
            &mut model,
            &format!("overlap{i}"),
            vec![EcOp::Touch, EcOp::Write(0, payload(i, 500 + i * 31))],
        );
    }
    // The old parity holder is now the data-shard backfill target, while its old
    // parity shard remains a recovery source until the spare has caught up.
    let up = vec![before[0], before[2], spare];
    s.set_up_override(pg, up.clone());
    s.run_until(60_000 * MS, "overlapping shard backfill clean", |s| {
        s.pool_clean(POOL)
    });
    assert_eq!(s.acting_of(pg), up);
    assert_shards(&s, &be, 0, &model);
    for (name, data) in model {
        assert_eq!(read_ec(&mut s, &name, 0, data.len() as u64).unwrap(), data);
    }
}

#[test]
fn ec_copy_temp_chunks_are_unlogged_and_final_rename_is_atomic() {
    use denc::types::{CollT, Ghobject, Hobject};
    use peering::{WriteEntry, WriteReq};
    use replwire::{ObjectInfo, Transaction, TxnOp};
    for (optimized, k, overwrites) in [
        (false, 2, true),
        (true, 2, true),
        (false, 3, false),
        (true, 3, false),
    ] {
        let mut s = Sim::new(808 + optimized as u64);
        for osd in 0..k + 1 {
            s.add_osd_cfg(osd, |c| {
                c.ec_enable = ec::EcEnable::All;
                c.ec_enable_optimized = ec::EcEnable::All;
                c.ec_primary = true;
                c.ec_opt_primary = true;
            });
        }
        s.run_for(50 * MS);
        if optimized {
            s.create_pool_ec_opt(POOL, k as u32, 1, 8192, overwrites, 1);
        } else {
            s.create_pool_ec(POOL, k as u32, 1, 8192, overwrites, 1);
        }
        s.run_until(60_000 * MS, "copy pool clean", |s| s.pool_clean(POOL));
        let lead = s.lead_spg(POOL, 0);
        let tid = s.write_obj(POOL, 0, "dest", b"original").unwrap();
        s.wait_writes(&[tid], lead);
        let dest = hobj(POOL, "dest");
        let primary = s.primary_of(lead.pgid);
        let before = s.pg(primary, lead).unwrap().log().head();
        let mut temp = dest.clone();
        temp.pool = Hobject::temp_pool(dest.pool);
        temp.oid = b"copy-tmp-test".to_vec();
        let data = payload(45, (9 << 20) + 17);
        let chunk = (4 << 20) / (k as usize * 8192) * (k as usize * 8192);
        for (part, bytes) in data.chunks(chunk).enumerate() {
            let mut t = Transaction::new();
            let cx = t.coll(&CollT::Pg(lead));
            let ox = t.obj(&Ghobject::head(temp.clone(), lead.shard));
            if part == 0 {
                t.push(cx, TxnOp::Create { oid: ox });
            }
            t.push(
                cx,
                TxnOp::Write {
                    oid: ox,
                    off: (part * chunk) as u64,
                    data: replwire::Data::new(bytes),
                },
            );
            let mut oi = ObjectInfo::new(temp.clone());
            oi.size = ((part * chunk) + bytes.len()) as u64;
            let encoded = denc::to_vec(&oi).unwrap();
            t.push(
                cx,
                TxnOp::SetAttr {
                    oid: ox,
                    name: b"_",
                    value: &encoded,
                },
            );
            let tid = s
                .submit_raw(
                    POOL,
                    0,
                    WriteReq {
                        txn_data: t.encode_v9().unwrap().into(),
                        new_temp: (part == 0).then(|| temp.clone()),
                        ..Default::default()
                    },
                )
                .unwrap();
            s.wait_writes(&[tid], lead);
            assert_eq!(s.pg(primary, lead).unwrap().log().head(), before);
            assert_eq!(read_ec(&mut s, "dest", 0, 8).unwrap(), b"original");
        }
        let version = s.pg(primary, lead).unwrap().next_version();
        let mut t = Transaction::new();
        let cx = t.coll(&CollT::Pg(lead));
        let src = t.obj(&Ghobject::head(temp.clone(), lead.shard));
        let dst = t.obj(&Ghobject::head(dest.clone(), lead.shard));
        t.push(cx, TxnOp::Remove { oid: dst });
        t.push(
            cx,
            TxnOp::TryRename {
                oid: src,
                dest_oid: dst,
            },
        );
        let mut oi = ObjectInfo::new(dest.clone());
        oi.version = version;
        oi.size = data.len() as u64;
        let encoded = denc::to_vec(&oi).unwrap();
        t.push(
            cx,
            TxnOp::SetAttr {
                oid: dst,
                name: b"_",
                value: &encoded,
            },
        );
        let tid = s
            .submit_raw(
                POOL,
                0,
                WriteReq {
                    txn_data: t.encode_v9().unwrap().into(),
                    discard_temp: Some(temp.clone()),
                    entries: vec![WriteEntry {
                        op: pgwire::LogOp::MODIFY,
                        soid: dest.clone(),
                        user_version: 1,
                        mtime: Default::default(),
                        snaps: vec![],
                        return_code: 0,
                        op_returns: vec![],
                        prior: None,
                    }],
                    ..Default::default()
                },
            )
            .unwrap();
        s.wait_writes(&[tid], lead);
        assert_eq!(read_ec(&mut s, "dest", 0, data.len() as u64).unwrap(), data);
        assert_eq!(s.pg(primary, lead).unwrap().log().head(), version);
        for osd in s.acting_of(lead.pgid) {
            assert_eq!(s.nodes[&osd].store.temp_objects(s.spg_on(osd, POOL, 0)), 0);
        }
        // COPY_FROM followed by DELETE reduces away the rename, but must still remove its source.
        let mut t = Transaction::new();
        let cx = t.coll(&CollT::Pg(lead));
        let ox = t.obj(&Ghobject::head(temp.clone(), lead.shard));
        t.push(cx, TxnOp::Create { oid: ox });
        let encoded = denc::to_vec(&ObjectInfo::new(temp.clone())).unwrap();
        t.push(
            cx,
            TxnOp::SetAttr {
                oid: ox,
                name: b"_",
                value: &encoded,
            },
        );
        let tid = s
            .submit_raw(
                POOL,
                0,
                WriteReq {
                    txn_data: t.encode_v9().unwrap().into(),
                    new_temp: Some(temp.clone()),
                    ..Default::default()
                },
            )
            .unwrap();
        s.wait_writes(&[tid], lead);
        let mut t = Transaction::new();
        let cx = t.coll(&CollT::Pg(lead));
        let src = t.obj(&Ghobject::head(temp.clone(), lead.shard));
        let dst = t.obj(&Ghobject::head(dest.clone(), lead.shard));
        t.push(cx, TxnOp::Remove { oid: dst });
        t.push(
            cx,
            TxnOp::TryRename {
                oid: src,
                dest_oid: dst,
            },
        );
        t.push(cx, TxnOp::Remove { oid: dst });
        let tid = s
            .submit_raw(
                POOL,
                0,
                WriteReq {
                    txn_data: t.encode_v9().unwrap().into(),
                    discard_temp: Some(temp.clone()),
                    entries: vec![WriteEntry {
                        op: pgwire::LogOp::DELETE,
                        soid: dest,
                        user_version: 2,
                        mtime: Default::default(),
                        snaps: vec![],
                        return_code: 0,
                        op_returns: vec![],
                        prior: None,
                    }],
                    ..Default::default()
                },
            )
            .unwrap();
        s.wait_writes(&[tid], lead);
        for osd in s.acting_of(lead.pgid) {
            assert_eq!(s.nodes[&osd].store.temp_objects(s.spg_on(osd, POOL, 0)), 0);
        }
        assert_eq!(read_ec(&mut s, "dest", 0, 1), Err(opwire::errno::ENOENT));
    }
}

/// A logical write while the PG runs degraded (no shard check).
fn step_degraded(s: &mut Sim, model: &mut BTreeMap<String, Vec<u8>>, name: &str, ops: Vec<EcOp>) {
    let mut mm = model.get(name).cloned();
    model_apply(&mut mm, &ops);
    let tid = s
        .write_ops(POOL, 0, name, &ops, mm.as_ref().map(|v| v.len() as u64))
        .expect("accepted");
    let l = s.lead_spg(POOL, 0);
    s.wait_writes(&[tid], l);
    match mm {
        Some(v) => model.insert(name.to_string(), v),
        None => model.remove(name),
    };
}

/// CRUSH moves OSDs to other shard positions of live PGs (a remap, e.g. OSDs added to the rule's root): an OSD keeps the PG
/// instance of its OLD shard next to the new one. The old instance must stay a stray: it must not lead (its queries would
/// name a shard the OSD no longer holds and classic peers assert on that), nothing it sends may reach another OSD, data
/// stays intact and the PG gets clean on the new positions.
#[test]
fn ec_primary_remap_to_other_shard_positions_leaves_no_stale_primary() {
    let (k, m, chunk) = (2, 1, 32);
    let mut s = ec_cluster(70, &[0, 1, 2, 3], k, m, chunk, true, 1);
    let be = backend(k, m, chunk, true);
    let pg = denc::types::PgT::new(POOL, 0);
    let lead = s.lead_spg(POOL, 0);
    let before = s.acting_of(pg);
    let mut model = BTreeMap::new();
    for i in 0..5 {
        step(
            &mut s,
            &be,
            &mut model,
            &format!("m{i}"),
            vec![EcOp::Touch, EcOp::Write(0, payload(i, 40 + i * 20))],
        );
    }
    let _ = lead;
    for o in 0..4 {
        s.nodes.get_mut(&o).unwrap().set.take_notices();
    }
    // CRUSH shifts the first two members one position up and drops the last: the old primary is now shard 1, shard 0 is a hole
    let up = vec![pgwire::NONE_OSD, before[0], before[1]];
    s.set_up_override(pg, up);
    s.run_for(15_000 * MS);
    // the PG serves again (it reverts to the members that hold the data by pg_temp) and takes writes
    let lead2 = s.lead_spg(POOL, 0);
    let t = s
        .write_obj(POOL, 0, "post", &payload(7, 100))
        .expect("accepted");
    s.wait_writes(&[t], lead2);
    model.insert("post".into(), payload(7, 100));
    for o in 0..4 {
        let notes = s.nodes.get_mut(&o).unwrap().set.take_notices();
        assert!(
            !notes.iter().any(|n| n.contains("claims a shard")),
            "osd.{o}: a stale instance sent as its old shard: {notes:?}"
        );
        // only the instance at the OSD's current shard may lead
        if let Some(sp) = (0..3)
            .map(|sh| denc::types::SpgT {
                pgid: pg,
                shard: denc::types::ShardId(sh),
            })
            .find(|sp| s.pg(o, *sp).is_some_and(|p| p.is_primary()))
        {
            assert_eq!(
                sp,
                s.lead_spg(POOL, 0),
                "osd.{o} leads with the wrong instance"
            );
        }
    }
}

/// Shards whose replies are held (peers behind on maps, a slow link) park a read; it is never given up on a timer
/// (classic has no sub-read timeout: a source is dropped only when a map shows its OSD down, spec missing-loc.md 5).
/// The held replies arrive -> the read completes with the right bytes. Before: a 10 s timeout failed both peer shards,
/// no read plan was left -> EIO (OQ 28 O14: client write EIO in the 20.2.4 kill loop).
#[test]
fn ec_primary_read_waits_for_held_shards() {
    let (k, m, chunk) = (2, 1, 32);
    let mut s = ec_cluster(80, &[0, 1, 2], k, m, chunk, true, 1);
    let be = backend(k, m, chunk, true);
    let mut model = BTreeMap::new();
    step(
        &mut s,
        &be,
        &mut model,
        "q",
        vec![EcOp::Touch, EcOp::Write(0, payload(3, 500))],
    );
    let lead = s.lead_spg(POOL, 0);
    let prim = s.primary_of(lead.pgid);
    for o in s.acting_of(lead.pgid) {
        if o != prim {
            s.partition(prim, o);
        }
    }
    let h = hobj(POOL, "q");
    let warm = |s: &mut Sim| {
        let mut ready = false;
        s.call(prim, |set, now, store| {
            let (r, acts) = set
                .with_pg(now, lead, store, |pg| {
                    pg.ec_wait(&h, 0, 500, store).is_none()
                })
                .expect("pg");
            ready = r;
            acts
        });
        ready
    };
    for _ in 0..300 {
        assert!(!warm(&mut s), "a read with every peer shard held finished");
        s.run_for(100 * MS);
    }
    s.heal();
    let mut got = None;
    for _ in 0..2000 {
        if warm(&mut s) {
            let pg = s.pg(prim, lead).unwrap();
            let size = pg.ec_obj_size(&h, &s.nodes[&prim].store).unwrap().unwrap();
            got = Some(pg.ec_cache_read(&h, 0, 500, size));
            break;
        }
        s.run_for(5 * MS);
    }
    assert_eq!(got.expect("read finished"), Ok(model["q"].clone()));
}

/// RMW write while every peer shard is held for 30 s: the old-stripe read waits, the write is never failed (no
/// WriteDone with an error); after the heal it is acked and every shard matches the model.
#[test]
fn ec_primary_rmw_write_waits_for_held_shards() {
    let (k, m, chunk) = (2, 1, 32);
    let mut s = ec_cluster(82, &[0, 1, 2], k, m, chunk, true, 1);
    let be = backend(k, m, chunk, true);
    let mut model = BTreeMap::new();
    step(
        &mut s,
        &be,
        &mut model,
        "w",
        vec![EcOp::Touch, EcOp::Write(0, payload(5, 500))],
    );
    let lead = s.lead_spg(POOL, 0);
    let prim = s.primary_of(lead.pgid);
    for o in s.acting_of(lead.pgid) {
        if o != prim {
            s.partition(prim, o);
        }
    }
    let ops = vec![EcOp::Write(40, payload(6, 30))];
    let mut m2 = model.get("w").cloned();
    model_apply(&mut m2, &ops);
    let tid = s
        .write_ops(POOL, 0, "w", &ops, m2.as_ref().map(|v| v.len() as u64))
        .expect("accepted");
    s.run_for(30_000 * MS);
    assert!(s.failed.is_empty(), "write failed: {:?}", s.failed);
    assert!(!s.is_acked(lead, tid), "acked without its shards");
    s.heal();
    s.wait_writes(&[tid], lead);
    s.run_for(60 * MS);
    model.insert("w".into(), m2.unwrap());
    assert_shards(&s, &be, 0, &model);
}

#[test]
fn ec_primary_peers_and_writes_full_objects() {
    let (k, m, chunk) = (2, 1, 64);
    let mut s = ec_cluster(21, &[0, 1, 2], k, m, chunk, false, 1);
    let lead = s.lead_spg(POOL, 0);
    assert!(s.pg(s.primary_of(lead.pgid), lead).unwrap().is_clean());
    let be = backend(k, m, chunk, false);
    let mut model = BTreeMap::new();
    let mut tids = vec![];
    for i in 0..12 {
        let name = format!("o{i}");
        let d = payload(i, 20 + i * 37);
        tids.push(s.write_obj(POOL, 0, &name, &d).expect("accepted"));
        model.insert(name, d);
        s.run_for(MS / 2);
    }
    s.wait_writes(&tids, lead);
    s.run_for(300 * MS);
    assert_shards(&s, &be, 0, &model);
    s.assert_no_roundtrip_mismatch();
    // every shard rolled forward: no stash, crt == head everywhere
    for o in s.acting_of(lead.pgid) {
        let pg = s.pg(o, s.spg_on(o, POOL, 0)).unwrap();
        assert_eq!(pg.log().log.can_rollback_to, pg.log().head(), "osd.{o} crt");
        assert!(s.nodes[&o].store.stash(s.spg_on(o, POOL, 0)).is_empty());
    }
}

/// Overwrites of objects whose entries already left the log carry the stored version as prior_version (0'0 would
/// make every divergent shard REMOVE its chunk instead of rolling back: PGLog case 2, the "unfound after the
/// primary was SIGKILLed" failure). The primary dies with such overwrites in flight: every object survives intact,
/// old or new content on all shards, and the PG gets clean when the old primary returns.
#[test]
fn ec_primary_failover_of_overwrites_outside_the_log_keeps_objects() {
    for seed in 0..8u64 {
        let (k, m, chunk) = (3, 2, 32);
        let osds = [0, 1, 2, 3, 4];
        let mut s = Sim::new(70 + seed);
        for o in osds {
            s.add_osd_cfg(o, |c| {
                c.ec_enable = ec::EcEnable::All;
                c.ec_primary = true;
                c.min_pg_log_entries = 4;
                c.pg_log_trim_min = 1;
                c.pg_log_trim_max = 30;
            });
        }
        s.run_for(50 * MS);
        s.create_pool_ec(POOL, k, m, chunk, true, 1);
        s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
        let be = backend(k, m, chunk, true);
        let lead = s.lead_spg(POOL, 0);
        let prim = s.primary_of(lead.pgid);
        let mut model = BTreeMap::new();
        for i in 0..4 {
            let name = format!("o{i}");
            let d = payload(i, 100 + i * 10);
            let t = s.write_obj(POOL, 0, &name, &d).unwrap();
            s.wait_writes(&[t], lead);
            model.insert(name, d);
        }
        // push the originals out of the log
        for i in 0..20 {
            let t = s
                .write_obj(POOL, 0, &format!("fill{i}"), &payload(50 + i, 40))
                .unwrap();
            s.wait_writes(&[t], lead);
            model.insert(format!("fill{i}"), payload(50 + i, 40));
        }
        s.run_for(100 * MS);
        let olds: BTreeMap<String, denc::types::Eversion> = (0..4)
            .map(|i| {
                let n = format!("o{i}");
                let pg = s.pg(prim, lead).unwrap();
                assert!(
                    pg.log().newest_for(&hobj(POOL, &n)).is_none(),
                    "{n} still logged"
                );
                let v = s.nodes[&prim]
                    .store
                    .object_version(lead, &hobj(POOL, &n))
                    .unwrap();
                (n, v)
            })
            .collect();
        // one overwrite acked: its prior_version is the stored version
        let t = s.write_obj(POOL, 0, "o0", &payload(80, 130)).unwrap();
        s.wait_writes(&[t], lead);
        model.insert("o0".into(), payload(80, 130));
        {
            let pg = s.pg(prim, lead).unwrap();
            let e = pg
                .log()
                .log
                .log
                .iter()
                .rev()
                .find(|e| e.soid == hobj(POOL, "o0"))
                .unwrap();
            assert_eq!(
                e.prior_version, olds["o0"],
                "seed {seed}: prior_version of an overwrite outside the log"
            );
        }
        // overwrites in flight when the primary dies
        let mut flight: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for i in 1..4 {
            let name = format!("o{i}");
            let d = payload(i + 90, 70 + i * 25);
            s.write_obj(POOL, 0, &name, &d).unwrap();
            flight.insert(name, d);
            let dt = (s.rng.range(0, 3) * MS) / 2;
            s.run_for(dt);
        }
        s.kill(prim);
        s.mark_down(prim);
        s.run_until(60_000 * MS, "new primary active", |s| {
            let l = s.lead_spg(POOL, 0);
            let p = s.primary_of(l.pgid);
            p != prim
                && s.pg(p, l).is_some_and(|pg| {
                    pg.map_epoch() == s.epoch() && pg.state_bits() & pgwire::state::ACTIVE != 0
                })
        });
        s.run_for(500 * MS);
        let acting = s.acting_of(lead.pgid);
        for (name, new) in &flight {
            let old = &model[name];
            let enc = |d: &Vec<u8>| {
                let mut p = d.clone();
                p.resize(d.len().div_ceil(be.s as usize) * be.s as usize, 0);
                be.encode_stripes(&p)
            };
            let (wo, wn) = (enc(old), enc(new));
            let mut seen = vec![];
            for (sh, osd) in acting.iter().enumerate() {
                if *osd == pgwire::NONE_OSD {
                    continue;
                }
                let objs = s.nodes[osd].store.objects(s.spg_on(*osd, POOL, 0));
                let o = objs.get(&hobj(POOL, name)).unwrap_or_else(|| {
                    panic!("seed {seed}: {name} removed from shard {sh} (osd.{osd})")
                });
                seen.push(if o.data == wn[sh] {
                    1
                } else if o.data == wo[sh] {
                    0
                } else {
                    2
                });
            }
            assert!(
                seen.iter().all(|x| *x == 0) || seen.iter().all(|x| *x == 1),
                "seed {seed}: {name} torn: {seen:?}"
            );
            if seen[0] == 1 {
                model.insert(name.clone(), new.clone());
            }
        }
        s.restart(prim);
        s.run_until(60_000 * MS, "old primary back, pool clean", |s| {
            s.pool_clean(POOL)
        });
        s.run_for(500 * MS);
        assert_shards(&s, &be, 0, &model);
    }
}

/// A client read of an object with a write in flight waits for the write (its shards would mix old and new stripes,
/// and a warm done now is dropped at the completion: the op would then hit an empty cache = EIO); afterwards it reads
/// the new content.
#[test]
fn ec_primary_read_waits_for_write_in_flight() {
    let (k, m, chunk) = (3, 2, 32);
    let mut s = ec_cluster(26, &[0, 1, 2, 3, 4], k, m, chunk, true, 1);
    let lead = s.lead_spg(POOL, 0);
    let osd = s.primary_of(lead.pgid);
    let old = payload(1, 300);
    let t = s.write_obj(POOL, 0, "r", &old).unwrap();
    s.wait_writes(&[t], lead);
    assert_eq!(read_ec(&mut s, "r", 0, 300).unwrap(), old);
    let new = payload(2, 300);
    let t = s.write_obj(POOL, 0, "r", &new).unwrap();
    let h = hobj(POOL, "r");
    let mut ready = true;
    s.call(osd, |set, now, store| {
        let (r, acts) = set
            .with_pg(now, lead, store, |pg| {
                pg.ec_wait(&h, 0, 300, store).is_none()
            })
            .expect("pg");
        ready = r;
        acts
    });
    assert!(
        !ready,
        "a read must not be served / started while the write is in flight"
    );
    assert_eq!(
        s.pg(osd, lead).unwrap().ec_client_reads(),
        0,
        "no shard read while the write is in flight"
    );
    s.wait_writes(&[t], lead);
    let mut woke = Vec::new();
    s.nodes.get_mut(&osd).unwrap().set.take_ec_wake(&mut woke);
    assert!(
        woke.iter()
            .any(|(p, w)| *p == lead && w.tokens().contains(&peering::wake::ec_tok(&h))),
        "write completion wakes the reads parked on its object (only its token): {woke:?}"
    );
    assert_eq!(read_ec(&mut s, "r", 0, 300).unwrap(), new);
}

/// Client reads of different ranges of one object each wait for their own shard read: each names its read's token, a
/// read the one in flight covers names that read, and a finished read wakes only its own token (a sequential reader's
/// queue of reads of one object is not probed as a whole on every completion).
#[test]
fn ec_primary_client_reads_wake_per_read() {
    let (k, m, chunk) = (3, 2, 32);
    let mut s = ec_cluster(27, &[0, 1, 2, 3, 4], k, m, chunk, true, 1);
    let lead = s.lead_spg(POOL, 0);
    let osd = s.primary_of(lead.pgid);
    let stripe = u64::from(k * chunk);
    let data = payload(4, 4 * stripe as usize);
    let t = s.write_obj(POOL, 0, "w", &data).unwrap();
    s.wait_writes(&[t], lead);
    let h = hobj(POOL, "w");
    let wait = |s: &mut Sim, off: u64, len: u64| {
        let mut w = None;
        s.call(osd, |set, now, store| {
            let (r, acts) = set
                .with_pg(now, lead, store, |pg| pg.ec_wait(&h, off, len, store))
                .expect("pg");
            w = r;
            acts
        });
        w
    };
    s.nodes
        .get_mut(&osd)
        .unwrap()
        .set
        .take_ec_wake(&mut Vec::new());
    let a = wait(&mut s, 0, stripe).expect("first stripe: shard read started");
    let b = wait(&mut s, 2 * stripe, stripe).expect("third stripe: shard read started");
    assert_ne!(a, b, "two reads, one token");
    assert_ne!(a, peering::wake::ec_tok(&h));
    assert_eq!(
        wait(&mut s, 0, chunk.into()),
        Some(a),
        "a read the one in flight covers waits for that read"
    );
    s.run_for(200 * MS);
    let mut woke = Vec::new();
    s.nodes.get_mut(&osd).unwrap().set.take_ec_wake(&mut woke);
    let toks: Vec<u64> = woke
        .iter()
        .filter(|(p, _)| *p == lead)
        .flat_map(|(_, w)| w.tokens().to_vec())
        .collect();
    assert!(toks.contains(&a) && toks.contains(&b), "{toks:x?}");
    assert!(!toks.contains(&peering::wake::ec_tok(&h)), "{toks:x?}");
    assert_eq!(wait(&mut s, 0, stripe), None);
    assert_eq!(wait(&mut s, 2 * stripe, stripe), None);
    assert_eq!(read_ec(&mut s, "w", 0, 4 * stripe).unwrap(), data);
}

/// Reads around a write see one object version (spec client-ops 5.12, ec.md s10). Reads A in flight when a write W
/// arrives: the op layer holds W behind them (opexec `ordered`, wake test
/// `ec_reads_of_one_session_pass_each_other_and_a_write_keeps_its_place`), so they answer the old data whole. A read B
/// that arrives after W started its shard read at arrival (op-layer probe before the order check); W is submitted while
/// that read is in flight and lands on one shard while the other still holds the old stripe: B never gets the old or a
/// mixed stripe (nothing of it is cached), it waits for W and reads the shards again only once W is durable on all.
#[test]
fn ec_primary_reads_around_a_write_see_one_version() {
    let (k, m, chunk) = (2, 1, 32);
    let mut s = ec_cluster(28, &[0, 1, 2], k, m, chunk, true, 1);
    let be = backend(k, m, chunk, true);
    let lead = s.lead_spg(POOL, 0);
    let prim = s.primary_of(lead.pgid);
    let acting = s.acting_of(lead.pgid);
    assert!(
        acting[..k as usize].contains(&prim),
        "seed: the primary holds a data shard"
    );
    let peers: Vec<i32> = acting.iter().copied().filter(|o| *o != prim).collect();
    let data_peer = acting[..k as usize]
        .iter()
        .copied()
        .find(|o| *o != prim)
        .unwrap();
    let stripe = u64::from(k * chunk);
    let (old, new) = (
        payload(7, 4 * stripe as usize),
        payload(8, 4 * stripe as usize),
    );
    let t = s.write_obj(POOL, 0, "o", &old).unwrap();
    s.wait_writes(&[t], lead);
    let h = hobj(POOL, "o");
    let wait = |s: &mut Sim, off: u64| {
        let mut w = None;
        s.call(prim, |set, now, store| {
            let (r, acts) = set
                .with_pg(now, lead, store, |pg| pg.ec_wait(&h, off, stripe, store))
                .expect("pg");
            w = r;
            acts
        });
        w
    };
    let cached = |s: &Sim, off: u64| {
        let pg = s.pg(prim, lead).unwrap();
        let size = pg.ec_obj_size(&h, &s.nodes[&prim].store).unwrap().unwrap();
        pg.ec_cache_read(&h, off, stripe, size)
    };
    let part = |s: &mut Sim| peers.iter().for_each(|o| s.partition(prim, *o));

    // A: three stripe reads in flight (peer shards held); W arrives and waits behind them in the op layer
    part(&mut s);
    let a: Vec<u64> = (0..3)
        .map(|i| wait(&mut s, i * stripe).expect("A read started"))
        .collect();
    s.heal();
    let mut got = Vec::new();
    for i in 0..3 {
        let mut n = 0;
        while wait(&mut s, i * stripe).is_some() {
            n += 1;
            assert!(
                n < 2000,
                "A read {i} (token {:x}) never finished",
                a[i as usize]
            );
            s.run_for(5 * MS);
        }
        got.extend(cached(&s, i * stripe).expect("A read cached"));
    }
    assert_eq!(
        got,
        old[..3 * stripe as usize],
        "reads in flight before the write answer the old version whole"
    );

    // B arrives after W: its probe starts a shard read; then (A answered) W is submitted while B's read is in flight
    s.ec_ops_ran(prim);
    part(&mut s);
    let b_off = 3 * stripe;
    let b = wait(&mut s, b_off).expect("B read started");
    assert!(!a.contains(&b));
    let w = s.write_obj(POOL, 0, "o", &new).unwrap();
    assert_eq!(
        wait(&mut s, b_off),
        Some(peering::wake::ec_tok(&h)),
        "B waits for the write, not for its own shard read"
    );
    // the other data shard gets B's sub-read and W's sub-write (in that order) and answers both, the parity shard stays
    // held: B's read finishes with old data while W is durable on a subset of the shards
    s.heal_link(prim, data_peer);
    for _ in 0..20 {
        s.run_for(100 * MS);
        assert!(!s.is_acked(lead, w), "write acked with a shard held");
        assert_eq!(
            wait(&mut s, b_off),
            Some(peering::wake::ec_tok(&h)),
            "B may read while the write is not durable on every shard"
        );
        assert!(
            cached(&s, b_off).is_err(),
            "old or mixed stripe data of B's read in flight was kept"
        );
    }
    assert_eq!(
        s.pg(prim, lead).unwrap().ec_client_reads(),
        0,
        "B's shard read finished during the hold"
    );
    s.heal();
    let mut n = 0;
    while wait(&mut s, b_off) == Some(peering::wake::ec_tok(&h)) {
        n += 1;
        assert!(n < 20_000, "write never completed");
        s.run_for(MS);
    }
    assert!(
        s.is_acked(lead, w),
        "B read the shards before the write was acked"
    );
    assert_shards(
        &s,
        &be,
        0,
        &BTreeMap::from([("o".to_string(), new.clone())]),
    );
    let mut n = 0;
    while wait(&mut s, b_off).is_some() {
        n += 1;
        assert!(n < 2000, "B read never finished");
        s.run_for(5 * MS);
    }
    assert_eq!(
        cached(&s, b_off).unwrap(),
        new[b_off as usize..],
        "B after the write reads the new data"
    );
    assert_eq!(read_ec(&mut s, "o", 0, 4 * stripe).unwrap(), new);
}

/// A client read that failed (fewer than k shards answered) answers EIO to the ops parked on it, but does not stick:
/// the next op reads the shards again at once (no error hold, no write needed to clear it; classic evaluates each op).
#[test]
fn ec_primary_failed_read_is_retried_later() {
    let (k, m, chunk) = (2, 2, 32);
    let mut s = ec_cluster(81, &[0, 1, 2, 3], k, m, chunk, true, 1);
    let be = backend(k, m, chunk, true);
    let mut model = BTreeMap::new();
    step(
        &mut s,
        &be,
        &mut model,
        "z",
        vec![EcOp::Touch, EcOp::Write(0, payload(4, 400))],
    );
    let lead = s.lead_spg(POOL, 0);
    let prim = s.primary_of(lead.pgid);
    let others: Vec<i32> = s
        .acting_of(lead.pgid)
        .into_iter()
        .filter(|o| *o != prim)
        .collect();
    // the peers' shard files vanish for a moment (they answer ENOENT): fewer than k shards = EIO
    let h = hobj(POOL, "z");
    let mut saved = Vec::new();
    for o in &others {
        let spg = s.spg_on(*o, POOL, 0);
        let pg = s.nodes.get_mut(o).unwrap().store.pgs.get_mut(&spg).unwrap();
        saved.push((*o, spg, pg.objects.remove(&h).unwrap()));
    }
    assert_eq!(
        read_ec(&mut s, "z", 0, 400),
        Err(5),
        "only our shard answers: EIO"
    );
    for (o, spg, obj) in saved {
        s.nodes
            .get_mut(&o)
            .unwrap()
            .store
            .pgs
            .get_mut(&spg)
            .unwrap()
            .objects
            .insert(h.clone(), obj);
    }
    assert_eq!(read_ec(&mut s, "z", 0, 400), Ok(model["z"].clone()));
}

/// Data shard `pos < k` held by an OSD other than the primary: `(pos, osd)`.
fn peer_data_shard(s: &Sim, k: u32) -> (usize, i32) {
    let lead = s.lead_spg(POOL, 0);
    let prim = s.primary_of(lead.pgid);
    s.acting_of(lead.pgid)
        .into_iter()
        .enumerate()
        .find(|(p, o)| *p < k as usize && *o != prim)
        .expect("a peer data shard")
}

/// Legacy (L1) shards hold whole chunks: a peer whose shard object is shorter than the formula size (damaged) must
/// count as a failed shard. Its missing bytes are never zero padded into the client data, and an RMW never re-encodes
/// parity from those zeros (the read decodes around the shard instead).
#[test]
fn ec_primary_short_legacy_shard_reply_is_a_failed_shard() {
    let (k, m, chunk) = (2, 2, 32);
    let mut s = ec_cluster(83, &[0, 1, 2, 3], k, m, chunk, true, 1);
    let be = backend(k, m, chunk, true);
    let mut model = BTreeMap::new();
    step(
        &mut s,
        &be,
        &mut model,
        "t",
        vec![EcOp::Touch, EcOp::Write(0, payload(6, 400))],
    );
    let (pos, victim) = peer_data_shard(&s, k);
    let h = hobj(POOL, "t");
    let spg = s.spg_on(victim, POOL, 0);
    let obj = s
        .nodes
        .get_mut(&victim)
        .unwrap()
        .store
        .pgs
        .get_mut(&spg)
        .unwrap()
        .objects
        .get_mut(&h)
        .unwrap();
    assert_eq!(obj.data.len(), 224, "7 stripes of 32 byte chunks");
    obj.data.truncate(100);
    assert_eq!(
        read_ec(&mut s, "t", 0, 400),
        Ok(model["t"].clone()),
        "short shard {pos} on osd.{victim}: decoded around, never zero padded"
    );
    // RMW of stripe 5 (bytes [320, 330) of chunk 0): the untouched chunk 1 is read as old data; shard `pos` is short
    // there, so parity must come from the decoded chunk, not from zeros
    let ops = vec![EcOp::Write(5 * 64, vec![0xa5; 10])];
    let mut m2 = model.get("t").cloned();
    model_apply(&mut m2, &ops);
    let lead = s.lead_spg(POOL, 0);
    let tid = s
        .write_ops(POOL, 0, "t", &ops, Some(400))
        .expect("accepted");
    s.wait_writes(&[tid], lead);
    s.run_for(60 * MS);
    model.insert("t".into(), m2.unwrap());
    let mut padded = model["t"].clone();
    padded.resize(448, 0);
    let want = be.encode_stripes(&padded);
    let acting = s.acting_of(lead.pgid);
    for (sh, osd) in acting.iter().enumerate() {
        let d = &s.nodes[osd].store.objects(s.spg_on(*osd, POOL, 0))[&h].data;
        if sh == pos {
            // the damaged shard: the RMW wrote its stripe-5 chunk (decoded old bytes) again
            assert_eq!(
                d[160..192],
                want[sh][160..192],
                "rewritten chunk of shard {sh}"
            );
        } else {
            assert_eq!(*d, want[sh], "shard {sh} on osd.{osd} after the RMW");
        }
    }
}

/// A sub-read reply is matched by tid AND the OSD that was asked: a reply with the right tid from another OSD (a
/// misrouted or duplicated message) neither fills nor fails the shard.
#[test]
fn ec_read_reply_from_an_osd_not_asked_is_ignored() {
    let (k, m, chunk) = (2, 2, 32);
    let mut s = ec_cluster(84, &[0, 1, 2, 3], k, m, chunk, true, 1);
    let be = backend(k, m, chunk, true);
    let mut model = BTreeMap::new();
    step(
        &mut s,
        &be,
        &mut model,
        "u",
        vec![EcOp::Touch, EcOp::Write(0, payload(7, 400))],
    );
    let lead = s.lead_spg(POOL, 0);
    let prim = s.primary_of(lead.pgid);
    let (pos, asked) = peer_data_shard(&s, k);
    let (other_pos, other) = s
        .acting_of(lead.pgid)
        .into_iter()
        .enumerate()
        .find(|(_, o)| *o != prim && *o != asked)
        .unwrap();
    s.partition(prim, asked);
    s.capture = true;
    let h = hobj(POOL, "u");
    s.call(prim, |set, now, store| {
        let (r, acts) = set
            .with_pg(now, lead, store, |pg| {
                pg.ec_wait(&h, 0, 400, store).is_none()
            })
            .expect("pg");
        assert!(!r, "the read goes to the shards");
        acts
    });
    let (tid, off, len) = s
        .captured
        .iter()
        .find_map(|(f, t, b)| match b {
            peering::Body::Ec(ecwire::EcMsg::Read(r)) if *f == prim && *t == asked => {
                let (o, l, _) = r.op.to_read[&h][0];
                Some((r.op.tid, o, l))
            }
            _ => None,
        })
        .expect("sub-read to the partitioned shard");
    // a well-formed reply of `other` for its own shard, carrying the tid of the read asked from `asked`
    let mut op = ecwire::ECSubReadReply {
        from: denc::types::PgShard {
            osd: other,
            shard: denc::types::ShardId(other_pos as i8),
        },
        tid,
        ..Default::default()
    };
    op.buffers_read.insert(
        h.clone(),
        vec![(off, bytes::Bytes::from(vec![0xee; len as usize]))],
    );
    let reply = ecwire::MOSDECSubOpReadReply {
        pgid: lead,
        map_epoch: s.epoch(),
        op,
        min_epoch: s.epoch(),
        trace: [0; 3],
    };
    s.inject(other, prim, peering::Body::Ec(ecwire::EcMsg::from(reply)));
    s.run_for(50 * MS);
    assert!(
        s.pg(prim, lead).unwrap().ec_client_reads() > 0,
        "the read still waits for shard {pos} on osd.{asked}"
    );
    s.heal();
    assert_eq!(read_ec(&mut s, "u", 0, 400), Ok(model["u"].clone()));
}

/// Scrub chunk vs. EC writes accepted BEFORE the chunk but still in the RMW pipeline (reads of old stripes pending):
/// the chunk must not start over their objects until their sub-writes went out (classic: the scrubber waits for the
/// newest log entry of the range to be applied). Else the sub-writes land on the shards while they build their maps
/// (mixed versions = false inconsistency). Invariant on the wire: between a RepScrub to a shard and that shard's map,
/// no sub-write for an object of the chunk is sent to it.
#[test]
fn ec_scrub_chunk_waits_for_queued_writes_of_its_range() {
    let (k, m, chunk) = (2, 1, 32);
    let mut s = ec_cluster(91, &[0, 1, 2], k, m, chunk, true, 1);
    let be = backend(k, m, chunk, true);
    let st = be.s as usize;
    let lead = s.lead_spg(POOL, 0);
    let prim = s.primary_of(lead.pgid);
    let mut model = BTreeMap::new();
    step(
        &mut s,
        &be,
        &mut model,
        "x",
        vec![
            EcOp::Touch,
            EcOp::Write(0, payload(1, st * 4)),
            EcOp::Attr(
                "snapset",
                denc::to_vec(&replwire::SnapSet::default()).unwrap(),
            ),
        ],
    );
    s.run_for(300 * MS);
    s.capture = true;
    s.call(prim, |set, now, store| {
        set.request_scrub(now, lead, true, false, store)
    });
    // a chain of partial overwrites of `x` (each one reads the old stripe after the previous one committed)
    let mut tids = vec![];
    for i in 0..40 {
        match s.write_ops(
            POOL,
            0,
            "x",
            &[EcOp::Write(3 + i as u64, payload(10 + i, 5))],
            Some(st as u64 * 4),
        ) {
            Ok(t) => tids.push(t),
            Err(_) => break,
        }
    }
    assert!(tids.len() > 5, "writes queued before the chunk");
    s.run_until(60_000 * MS, "scrub finished", move |s| {
        let p = s.pg(prim, lead).unwrap();
        p.scrub_counts().0 > 0 && !p.scrub_running()
    });
    s.wait_writes(&tids, lead);
    let mut open: BTreeMap<i32, (denc::types::Hobject, denc::types::Hobject)> = BTreeMap::new();
    for (from, to, b) in &s.captured {
        match b {
            peering::Body::Repl(replwire::ReplMsg::RepScrub(m)) if *from == prim => {
                open.insert(*to, (m.start.clone(), m.end.clone()));
            }
            peering::Body::Repl(replwire::ReplMsg::RepScrubMap(_)) if *to == prim => {
                open.remove(from);
            }
            peering::Body::Ec(ecwire::EcMsg::Write(w)) if *from == prim => {
                if let Some((a, e)) = open.get(to) {
                    assert!(
                        !(w.op.soid >= *a && (e.max || w.op.soid < *e)),
                        "sub-write of {:?} to osd.{to} inside its scrub chunk",
                        w.op.soid
                    );
                }
            }
            _ => {}
        }
    }
    let errs = s
        .pg(prim, lead)
        .unwrap()
        .info()
        .stats
        .stats
        .sum
        .num_scrub_errors;
    assert_eq!(errs, 0, "scrub of a PG under writes reports errors");
}

/// Sibling of the replicated `chunk_waits_for_unacked_repops_into_its_range`: an EC write whose sub-write to one shard
/// is held in a faulted carrier while a new link carries the scrub request. The chunk waits for the write to commit on
/// every shard (not only until its sub-writes went out); the scrub stays clean.
#[test]
fn ec_scrub_chunk_waits_for_unacked_sub_writes_of_its_range() {
    let (k, m, chunk) = (2, 1, 32);
    let mut s = ec_cluster(93, &[0, 1, 2], k, m, chunk, true, 1);
    let be = backend(k, m, chunk, true);
    let st = be.s as usize;
    let lead = s.lead_spg(POOL, 0);
    let prim = s.primary_of(lead.pgid);
    let mut model = BTreeMap::new();
    let snapset = || {
        EcOp::Attr(
            "snapset",
            denc::to_vec(&replwire::SnapSet::default()).unwrap(),
        )
    };
    step(
        &mut s,
        &be,
        &mut model,
        "x",
        vec![EcOp::Touch, EcOp::Write(0, payload(1, st * 2)), snapset()],
    );
    s.run_for(300 * MS);
    let peer = *s.acting_of(lead.pgid).iter().find(|o| **o != prim).unwrap();
    s.partition(prim, peer);
    let t = s
        .write_ops(
            POOL,
            0,
            "x",
            &[EcOp::Write(0, payload(7, st * 2))],
            Some(st as u64 * 2),
        )
        .unwrap();
    s.run_for(50 * MS);
    s.blocked.clear();
    s.call(prim, |set, now, store| {
        set.request_scrub(now, lead, true, false, store)
    });
    s.run_for(5_000 * MS);
    let errs = |s: &Sim| {
        s.pg(prim, lead)
            .unwrap()
            .info()
            .stats
            .stats
            .sum
            .num_scrub_errors
    };
    assert_eq!(
        errs(&s),
        0,
        "an EC write in flight was reported as an inconsistency"
    );
    assert_eq!(
        s.pg(prim, lead).unwrap().scrub_counts().0,
        0,
        "the chunk compared before the sub-write was acked"
    );
    s.heal();
    s.wait_writes(&[t], lead);
    s.run_until(60_000 * MS, "scrub finished", move |s| {
        let p = s.pg(prim, lead).unwrap();
        p.scrub_counts().0 > 0 && !p.scrub_running()
    });
    assert_eq!(errs(&s), 0);
}

#[test]
fn ec_primary_pipelined_unaligned_appends_k4m2() {
    let (k, m, chunk) = (4, 2, 4096);
    let mut s = ec_cluster(31, &[0, 1, 2, 3, 4, 5], k, m, chunk, true, 1);
    let be = backend(k, m, chunk, true);
    let lead = s.lead_spg(POOL, 0);
    let mut model: Option<Vec<u8>> = None;
    let mut rng = 12345u64;
    let mut next = |lo: u64, hi: u64| {
        rng = rng
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        lo + (rng >> 33) % (hi - lo)
    };
    for round in 0..6 {
        let mut tids = vec![];
        for i in 0..3 {
            let off = model.as_ref().map_or(0, |v| v.len() as u64);
            let len = next(100_000, 200_000) as usize;
            let ops = vec![EcOp::Write(off, payload(round * 10 + i, len))];
            model_apply(&mut model, &ops);
            let sz = model.as_ref().unwrap().len() as u64;
            tids.push(s.write_ops(POOL, 0, "a", &ops, Some(sz)).expect("accepted"));
        }
        let sz = model.as_ref().unwrap().len() as u64;
        let ops = vec![EcOp::Attr("_header", vec![round as u8; 40])];
        tids.push(s.write_ops(POOL, 0, "a", &ops, Some(sz)).expect("accepted"));
        s.run_until(30_000 * MS, "done", |s| {
            tids.iter()
                .all(|t| s.is_acked(lead, *t) || s.failed.iter().any(|f| f.0 == lead && f.1 == *t))
        });
        assert!(s.failed.is_empty(), "round {round}: failed {:?}", s.failed);
    }
    s.run_for(300 * MS);
    let mut want = BTreeMap::new();
    want.insert("a".to_string(), model.unwrap());
    assert_shards(&s, &be, 0, &want);
}

/// Live bug (ceph_test_rados on an overwrite pool, EIO on the racing read(0, 1) of a new object): a write that creates
/// an object queues behind an RMW write of another object (generation in version order), so the object is not in the
/// local store yet. `ec_wait` must park on the queued write, not answer "ready" from the absent local object (the op
/// then ran after the write without a warmed cache: EIO).
#[test]
fn ec_primary_read_of_object_created_by_queued_write_waits() {
    let (k, m, chunk) = (2, 1, 32);
    let mut s = ec_cluster(27, &[0, 1, 2], k, m, chunk, true, 1);
    let lead = s.lead_spg(POOL, 0);
    let osd = s.primary_of(lead.pgid);
    let st = backend(k, m, chunk, true).s as usize;
    let x = payload(1, st + 5);
    let t = s.write_obj(POOL, 0, "x", &x).unwrap();
    s.wait_writes(&[t], lead);
    // unaligned append to x: RMW read of its last stripe, the write waits at the front of the queue
    let ops = vec![EcOp::Write(x.len() as u64, payload(2, 7))];
    let t1 = s
        .write_ops(POOL, 0, "x", &ops, Some(x.len() as u64 + 7))
        .unwrap();
    // new object y: planned, queued behind x's write, not generated
    let y = payload(3, 100);
    let ops = vec![EcOp::Touch, EcOp::Write(0, y.clone())];
    let t2 = s.write_ops(POOL, 0, "y", &ops, Some(100)).unwrap();
    let h = hobj(POOL, "y");
    let mut ready = true;
    s.call(osd, |set, now, store| {
        let (r, acts) = set
            .with_pg(now, lead, store, |pg| pg.ec_wait(&h, 0, 1, store).is_none())
            .expect("pg");
        ready = r;
        acts
    });
    assert!(!ready, "read of an object with a queued write must park");
    // the op layer sees the projected object (attrs, size) although the local shard does not have it yet
    let pg = s.pg(osd, lead).unwrap();
    assert!(
        pg.ec_obj_size(&h, &s.nodes[&osd].store).unwrap().is_none(),
        "not generated yet"
    );
    let (size, attrs) = pg.ec_projected(&h).expect("projected").expect("exists");
    assert_eq!(size, 100);
    assert!(attrs.contains_key(b"_".as_slice()));
    s.wait_writes(&[t1, t2], lead);
    assert!(
        s.pg(osd, lead).unwrap().ec_projected(&h).is_none(),
        "committed: the local shard is current"
    );
    assert_eq!(read_ec(&mut s, "y", 0, 1).unwrap(), y[..1].to_vec());
}

/// Shard-only pool (clay profile the primary role refuses, `primary_ok == false`, ec-clay.md 0.6): no croit-flashstore-osd leads,
/// the pool never gets active and writes are not accepted.
#[test]
fn ec_primary_never_leads_a_shard_only_pool() {
    let mut s = Sim::new(31);
    for o in [0, 1, 2] {
        s.add_osd_cfg(o, |c| {
            c.ec_enable = ec::EcEnable::All;
            c.ec_primary = true;
        });
    }
    s.run_for(50 * MS);
    s.create_pool_ec(POOL, 2, 1, 64, true, 1);
    s.new_epoch(|mp| {
        std::sync::Arc::make_mut(mp.pools.get_mut(&POOL).unwrap().ec.as_mut().unwrap())
            .primary_ok = false;
    });
    s.run_for(3000 * MS);
    assert!(!s.pool_clean(POOL));
    assert!(s.write_obj(POOL, 0, "o", &payload(1, 100)).is_err());
}

/// clay pool: a returning shard is rebuilt from the sub-chunks of d helpers (spec ec-clay.md 6, recovery repair path):
/// byte-exact shards, readable through the decode path, and the repair path really ran.
#[test]
fn ec_primary_clay_repairs_a_returning_shard() {
    let mut ran = 0;
    for (k, m, d, nosd, victim_pos) in [
        (2u32, 2u32, "3", 4, 1usize),
        (2, 2, "3", 4, 3),
        (3, 2, "4", 5, 2),
    ] {
        let chunk = if k == 2 { 256 } else { 512 };
        let osds: Vec<i32> = (0..nosd).collect();
        let prof: BTreeMap<String, String> = [
            ("plugin", "clay".to_string()),
            ("k", k.to_string()),
            ("m", m.to_string()),
            ("d", d.to_string()),
        ]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b))
        .collect();
        let sub = if k == 2 { 4 } else { 8 };
        let be =
            Backend::from_profile(&prof, (k * chunk, chunk), (0..k + m).collect(), false).unwrap();
        let mut s = Sim::new(90 + victim_pos as u64);
        s.ec_profile = Some((prof, sub));
        for o in &osds {
            s.add_osd_cfg(*o, |c| {
                c.ec_enable = ec::EcEnable::All;
                c.ec_primary = true;
            });
        }
        s.run_for(50 * MS);
        s.create_pool_ec(POOL, k, m, chunk, false, 1);
        s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
        let lead = s.lead_spg(POOL, 0);
        let acting = s.acting_of(lead.pgid);
        let victim = acting[victim_pos];
        let prim = s.primary_of(lead.pgid);
        if victim == prim {
            continue;
        }
        let mut model = BTreeMap::new();
        for i in 0..3 {
            let d = payload(i, 300 + i * 900);
            let t = s
                .write_ops(
                    POOL,
                    0,
                    &format!("o{i}"),
                    &[EcOp::Touch, EcOp::Write(0, d.clone())],
                    Some(d.len() as u64),
                )
                .unwrap();
            s.wait_writes(&[t], lead);
            model.insert(format!("o{i}"), d);
        }
        s.kill(victim);
        s.run_until(30_000 * MS, "degraded active", |s| {
            let p = s.primary_of(lead.pgid);
            s.pg(p, lead).is_some_and(|pg| {
                pg.acting().contains(&pgwire::NONE_OSD)
                    && pg.map_epoch() == s.epoch()
                    && pg.state_bits() & pgwire::state::ACTIVE != 0
            })
        });
        for i in 3..6 {
            let d = payload(i, 200 + i * 700);
            let t = s
                .write_ops(
                    POOL,
                    0,
                    &format!("o{i}"),
                    &[EcOp::Touch, EcOp::Write(0, d.clone())],
                    Some(d.len() as u64),
                )
                .unwrap();
            let l = s.lead_spg(POOL, 0);
            s.wait_writes(&[t], l);
            model.insert(format!("o{i}"), d);
        }
        s.restart(victim);
        s.run_until(60_000 * MS, "recovered and clean", |s| s.pool_clean(POOL));
        s.run_for(300 * MS);
        assert_shards(&s, &be, 0, &model);
        for (n, d) in model.clone() {
            assert_eq!(read_ec(&mut s, &n, 0, d.len() as u64).unwrap(), d, "{n}");
        }
        let p = s.primary_of(lead.pgid);
        let repairs = s.pg(p, s.lead_spg(POOL, 0)).unwrap().ec_repair_reads();
        assert!(
            repairs > 0,
            "({k},{m},{d}) victim {victim_pos}: no repair read ran"
        );
        ran += 1;
    }
    assert!(ran >= 2, "only {ran} cases ran");
}

/// shec (4,3,2): k shards are necessary, not sufficient. Losing shards {0,1,4} leaves 4 = k shards that cannot rebuild
/// everything (spec ec-shec.md 5.4): the PG must not go active (classic ECRecPred says incomplete). Losing {0,1} leaves a
/// recoverable set: active.
#[test]
fn ec_primary_shec_needs_its_own_recoverability_predicate() {
    for (dead, active) in [(vec![0usize, 1], true), (vec![0, 1, 4], false)] {
        let (k, m, chunk) = (4u32, 3u32, 32u32);
        let prof: BTreeMap<String, String> = [
            ("plugin", "shec"),
            ("k", "4"),
            ("m", "3"),
            ("c", "2"),
            ("technique", "multiple"),
        ]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        let mut s = Sim::new(120 + dead.len() as u64);
        s.ec_profile = Some((prof, 1));
        for o in 0..7 {
            s.add_osd_cfg(o, |c| {
                c.ec_enable = ec::EcEnable::All;
                c.ec_primary = true;
            });
        }
        s.run_for(50 * MS);
        s.create_pool_ec(POOL, k, m, chunk, false, 1);
        s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
        // admin sets min_size = k (allowed range [k, size]): the count rule alone would activate with k shards
        s.new_epoch(|mp| {
            mp.pools.get_mut(&POOL).unwrap().min_size = k;
        });
        s.run_until(60_000 * MS, "clean after min_size change", |s| {
            s.pool_clean(POOL)
        });
        let lead = s.lead_spg(POOL, 0);
        let acting = s.acting_of(lead.pgid);
        for d in &dead {
            s.kill(acting[*d]);
        }
        s.run_for(40_000 * MS);
        let any_active = acting.iter().enumerate().any(|(i, o)| {
            !dead.contains(&i)
                && s.pg(*o, s.spg_on(*o, POOL, 0))
                    .is_some_and(|pg| pg.state_bits() & pgwire::state::ACTIVE != 0)
        });
        assert_eq!(any_active, active, "dead shards {dead:?}");
    }
}

/// adr 0043 am. 5: with every peer known as croit-flashstore-osd, partial overwrites send warm sub-reads to the
/// unread (parity) shard; the shards stay exact. Without the peer set (classic peers) nothing extra is sent.
#[test]
fn ec_primary_rmw_warms_unread_shards_of_flashstore_peers_only() {
    for nv in [true, false] {
        let (k, m, chunk) = (2, 1, 32);
        let mut s = ec_cluster(23, &[0, 1, 2], k, m, chunk, true, 1);
        if nv {
            for n in s.nodes.values_mut() {
                let _ = n.set.set_flashstore_peers([0, 1, 2].into_iter().collect());
            }
        }
        let be = backend(k, m, chunk, true);
        let mut model = BTreeMap::new();
        let st = be.s as usize;
        step(
            &mut s,
            &be,
            &mut model,
            "a",
            vec![EcOp::Touch, EcOp::Write(0, payload(1, st * 4))],
        );
        for i in 0..6 {
            let off = (i * 13 % (st * 3)) as u64;
            step(
                &mut s,
                &be,
                &mut model,
                "a",
                vec![EcOp::Write(off, payload(10 + i, 9))],
            );
        }
        let lead = s.lead_spg(POOL, 0);
        let osd = s
            .acting_of(lead.pgid)
            .into_iter()
            .find(|o| s.spg_on(*o, POOL, 0) == lead)
            .unwrap();
        let warm = s.pg(osd, lead).unwrap().ec_warm_reads();
        if nv {
            assert!(warm >= 6, "warm reads {warm}");
        } else {
            assert_eq!(warm, 0, "warm read to a classic peer");
        }
        s.assert_no_roundtrip_mismatch();
    }
}

/// The primary comes back with objects missing on its own shard (written while it was down; recovery held): a client
/// read of such an object starts no shard read (the local object_info, so the size the read is clipped to, is stale)
/// and parks on the missing object instead; after the recovery the read returns the whole new object. Live (20.2.4
/// release smoke, croit-flashstore-osd primary restart under ceph_test_rados): the cache filled from the stale size outlived the
/// recovery and the parked read answered EIO.
#[test]
fn ec_primary_read_of_object_missing_on_own_shard_waits_for_recovery() {
    let (k, m, chunk) = (2, 1, 32);
    let mut s = ec_cluster(61, &[0, 1, 2], k, m, chunk, true, 1);
    let be = backend(k, m, chunk, true);
    let lead = s.lead_spg(POOL, 0);
    let mut model = BTreeMap::new();
    step(
        &mut s,
        &be,
        &mut model,
        "g",
        vec![EcOp::Touch, EcOp::Write(0, payload(1, 70))],
    );
    let prim = s.primary_of(lead.pgid);
    s.kill(prim);
    s.mark_down(prim);
    s.run_until(30_000 * MS, "degraded active elsewhere", |s| {
        let l = s.lead_spg(POOL, 0);
        let p = s.primary_of(l.pgid);
        p != prim
            && s.pg(p, l).is_some_and(|pg| {
                pg.map_epoch() == s.epoch() && pg.state_bits() & pgwire::state::ACTIVE != 0
            })
    });
    s.new_epoch(|m| m.rb.norecover = true);
    // the object grows while the old primary is away
    let mut mm = model.get("g").cloned();
    let ops = vec![EcOp::Write(70, payload(2, 150))];
    model_apply(&mut mm, &ops);
    let tid = s
        .write_ops(POOL, 0, "g", &ops, mm.as_ref().map(|v| v.len() as u64))
        .expect("accepted");
    let l = s.lead_spg(POOL, 0);
    s.wait_writes(&[tid], l);
    let new = mm.unwrap();
    s.restart(prim);
    let h = hobj(POOL, "g");
    s.run_until(
        30_000 * MS,
        "old primary active, own shard missing g",
        |s| {
            s.primary_of(lead.pgid) == prim
                && s.pg(prim, lead).is_some_and(|pg| {
                    pg.state_bits() & pgwire::state::ACTIVE != 0 && pg.missing().contains(&h)
                })
        },
    );
    let mut ready = false;
    s.call(prim, |set, now, store| {
        let (r, acts) = set
            .with_pg(now, lead, store, |pg| {
                pg.ec_wait(&h, 0, new.len() as u64, store).is_none()
            })
            .expect("pg");
        ready = r;
        acts
    });
    assert!(
        ready,
        "nothing to warm while missing: the op parks on the object"
    );
    assert_eq!(
        s.pg(prim, lead).unwrap().ec_client_reads(),
        0,
        "no read from the stale size"
    );
    s.new_epoch(|m| m.rb.norecover = false);
    s.run_until(60_000 * MS, "recovered and clean", |s| s.pool_clean(POOL));
    assert_eq!(read_ec(&mut s, "g", 0, new.len() as u64).unwrap(), new);
}

/// adr 0043 am. 6: legacy RMW reads skip the data chunks a plain write overwrites whole; the
/// shards stay exact for whole-chunk, multi-chunk, stripe-crossing, partial and truncate+write overwrites, also with a
/// shard down (whole stripes, decoded).
#[test]
fn ec_primary_rmw_skips_whole_overwritten_chunks() {
    for (k, m, osds) in [(2u32, 1u32, vec![0, 1, 2]), (3, 2, vec![0, 1, 2, 3, 4])] {
        let chunk = 32u32;
        let mut s = ec_cluster(25, &osds, k, m, chunk, true, 1);
        let be = backend(k, m, chunk, true);
        let (c, st) = (chunk as usize, be.s as usize);
        let mut model = BTreeMap::new();
        step(
            &mut s,
            &be,
            &mut model,
            "a",
            vec![EcOp::Touch, EcOp::Write(0, payload(1, st * 5))],
        );
        let mut i = 10;
        for r in 0..k as usize {
            for stripe in [0usize, 2, 4] {
                i += 1;
                step(
                    &mut s,
                    &be,
                    &mut model,
                    "a",
                    vec![EcOp::Write((stripe * st + r * c) as u64, payload(i, c))],
                );
            }
        }
        // two chunks of one stripe, a run crossing a stripe boundary, partial chunks, write + truncate
        step(
            &mut s,
            &be,
            &mut model,
            "a",
            vec![EcOp::Write(st as u64, payload(40, 2 * c))],
        );
        step(
            &mut s,
            &be,
            &mut model,
            "a",
            vec![EcOp::Write(
                (st + (k as usize - 1) * c) as u64,
                payload(41, 2 * c),
            )],
        );
        step(
            &mut s,
            &be,
            &mut model,
            "a",
            vec![EcOp::Write((2 * st + 3) as u64, payload(42, c))],
        );
        step(
            &mut s,
            &be,
            &mut model,
            "a",
            vec![
                EcOp::Write(c as u64, payload(43, c)),
                EcOp::Write(0, payload(44, c - 5)),
            ],
        );
        step(
            &mut s,
            &be,
            &mut model,
            "a",
            vec![
                EcOp::Write((3 * st) as u64, payload(45, c)),
                EcOp::Trunc((4 * st + 7) as u64),
            ],
        );
        let lead = s.lead_spg(POOL, 0);
        let osd = s
            .acting_of(lead.pgid)
            .into_iter()
            .find(|o| s.spg_on(*o, POOL, 0) == lead)
            .unwrap();
        let (all, partial) = s.pg(osd, lead).unwrap().ec_rmw_stats();
        assert!(
            partial >= 3 * k as u64,
            "k{k}: partial RMW reads {partial} of {all}"
        );
        assert!(partial < all, "k{k}: every RMW read partial");
        s.assert_no_roundtrip_mismatch();
        // a shard down: whole stripes again (decoded around the missing shard), still exact
        let prim = s.primary_of(lead.pgid);
        let victim = *s.acting_of(lead.pgid).iter().find(|o| **o != prim).unwrap();
        s.kill(victim);
        s.mark_down(victim);
        s.run_until(30_000 * MS, "active again", |s| {
            let p = s.primary_of(lead.pgid);
            s.pg(p, lead).is_some_and(|pg| {
                pg.acting().contains(&pgwire::NONE_OSD)
                    && pg.map_epoch() == s.epoch()
                    && pg.state_bits() & pgwire::state::ACTIVE != 0
            })
        });
        for r in 0..k as usize {
            i += 1;
            step_degraded(
                &mut s,
                &mut model,
                "a",
                vec![EcOp::Write((st + r * c) as u64, payload(i, c))],
            );
        }
        s.run_for(300 * MS);
        assert_live_shards(&s, &be, &model);
    }
}

/// adr 0160 am. 3: adaptive idle roll-forward. Writes 2 ms apart (bound 20 ms) carry the roll-forward of the previous one
/// (no dummy round in between); once idle, the dummy goes after at most 2 gaps and every shard rolls forward. Bound 0 =
/// classic: a dummy round after every write.
#[test]
fn ec_primary_idle_rollforward_rides_on_the_next_write() {
    for defer in [20 * MS, 0] {
        let (k, m, chunk) = (2, 1, 32);
        let mut s = ec_cluster_with(29, &[0, 1, 2], k, m, chunk, true, 1, |c| {
            c.ec_rf_defer_ns = defer
        });
        let be = backend(k, m, chunk, true);
        let lead = s.lead_spg(POOL, 0);
        let osd = s
            .acting_of(lead.pgid)
            .into_iter()
            .find(|o| s.spg_on(*o, POOL, 0) == lead)
            .unwrap();
        let mut model = BTreeMap::new();
        let n = 12u64;
        let (d0, p0) = s.pg(osd, lead).unwrap().ec_rf_stats();
        for i in 0..n as usize {
            let ops = vec![EcOp::Write((i * 7) as u64, payload(i, 40))];
            let mut v = model.get("a").cloned();
            model_apply(&mut v, &ops);
            let tid = s
                .write_ops(POOL, 0, "a", &ops, v.as_ref().map(|x| x.len() as u64))
                .expect("accepted");
            s.wait_writes(&[tid], lead);
            model.insert("a".to_string(), v.unwrap());
            s.run_for(2 * MS);
        }
        let (d1, p1) = s.pg(osd, lead).unwrap().ec_rf_stats();
        if defer > 0 {
            assert!(p1 - p0 >= n - 4, "piggybacked {}", p1 - p0);
            assert!(d1 - d0 <= 3, "dummies {}", d1 - d0);
        } else {
            assert_eq!(p1, p0);
            assert!(d1 - d0 >= n - 1, "dummies {}", d1 - d0);
        }
        // idle: the deferred dummy goes, every member rolls forward to the head
        s.run_for(200 * MS);
        for o in s.acting_of(lead.pgid) {
            let spg = s.spg_on(o, POOL, 0);
            let l = &s.pg(o, spg).unwrap().log().log;
            assert_eq!(l.can_rollback_to, l.head, "osd.{o} rolled forward");
        }
        assert_shards(&s, &be, 0, &model);
        s.assert_no_roundtrip_mismatch();
    }
}

/// adr 0049 am. 5: our EC `num_bytes` (shard bytes x k, stripe padded) is not the logical sum of `oi.size` a classic
/// primary keeps; classic shards copy the primary's stats from every sub-write and keep them when they lead. v20.2.x deep
/// scrub reports a num_bytes mismatch of VALID stats as an error (PG inconsistent, lab case 20), so an EC primary flags its
/// stats invalid (classic then takes the scrub count silently). Replicated pools keep exact, valid stats.
#[test]
fn ec_primary_flags_its_approximate_stats_invalid() {
    let (k, m, chunk) = (2, 1, 4096);
    let mut s = ec_cluster(23, &[0, 1, 2], k, m, chunk, true, 1);
    let be = backend(k, m, chunk, true);
    let mut model = BTreeMap::new();
    step(
        &mut s,
        &be,
        &mut model,
        "a",
        vec![EcOp::Write(0, payload(1, 5000))],
    );
    let lead = s.lead_spg(POOL, 0);
    let prim =
        peering::PgMapView::pg_mapping(&*s.map(), denc::types::PgT::new(POOL, 0)).acting_primary;
    let n = s.nodes.get_mut(&prim).unwrap();
    let st = n.store.clone();
    let pg = n.set.pg_mut(lead).unwrap();
    let ps = pg.build_pg_stat(&st);
    assert_ne!(
        ps.stats.sum.num_bytes, 5000,
        "padded approximation (else the flag could go)"
    );
    assert!(ps.stats_invalid, "published stats");
    assert!(
        pg.info().stats.stats_invalid,
        "info stats (sent with sub-writes and peering infos)"
    );

    let mut r = cluster(24, &[0, 1, 2], POOL, 3, 2, 1);
    let rp =
        peering::PgMapView::pg_mapping(&*r.map(), denc::types::PgT::new(POOL, 0)).acting_primary;
    let spg = r.lead_spg(POOL, 0);
    let n = r.nodes.get_mut(&rp).unwrap();
    let st = n.store.clone();
    assert!(
        !n.set.pg_mut(spg).unwrap().build_pg_stat(&st).stats_invalid,
        "replicated stats stay valid"
    );
}

/// OQ 28 O19: replica scrub reservations go out in ascending (osd, shard) order like classic's sorted acting set, so EC
/// PGs whose acting sets are rotations of each other cannot each hold one replica slot while waiting for the next
/// (with shard order: PG [0,1,2] holds osd.1 and waits for osd.2, [1,2,0] holds osd.2 and waits for osd.0, [2,0,1] holds
/// osd.0 and waits for osd.1: a cycle that only the reservation timeout broke). One slot per OSD, every PG deep-scrubbed
/// at once: all finish without a reservation timeout or abort.
#[test]
fn operator_scrubs_of_rotated_ec_pgs_never_wait_on_each_other() {
    const PGS: u32 = 16;
    let mut s = ec_cluster_with(29, &[0, 1, 2], 2, 1, 4096, true, PGS, |c| {
        c.max_scrubs = 1;
    });
    let leads: Vec<(i32, denc::types::SpgT)> = (0..PGS)
        .map(|seed| {
            let lead = s.lead_spg(POOL, seed);
            (s.primary_of(lead.pgid), lead)
        })
        .collect();
    let mut firsts = std::collections::BTreeSet::new();
    for (prim, lead) in &leads {
        let acting = s.acting_of(lead.pgid);
        firsts.insert((acting[0], acting[1]));
        s.call(*prim, |set, now, st| {
            set.request_scrub(now, *lead, true, false, st)
        });
    }
    // the mapping has rotations (else the test proves nothing)
    assert!(
        firsts.iter().any(|(p, n)| n < p) && firsts.iter().any(|(p, n)| n > p),
        "acting sets {firsts:?}"
    );
    let all_done = |s: &Sim| {
        leads.iter().all(|(prim, lead)| {
            let p = s.pg(*prim, *lead).unwrap();
            p.scrub_counts().0 >= 1 && !p.scrub_running()
        })
    };
    // well below the 120 s reservation timeout
    s.run_until(60_000 * MS, "every pg deep-scrubbed", |s| all_done(s));
    for (prim, lead) in &leads {
        let p = s.pg(*prim, *lead).unwrap();
        assert_eq!(p.scrub_counts().1, 0, "{lead}: scrub aborted");
    }
}

/// An object missing on a peer shard only (the shard was down while it was written, recovery held): a write to it is
/// refused before anything is planned (`WriteErr::Degraded`, a write-only gate: the op layer parks it and lets later pure
/// reads pass it, client-ops 5.4 #16, 5.5 (6)), while the object is readable here (`read_blocked` false) and a client
/// read is served at once from the other shards with the current data. After the recovery the write is accepted.
/// Replicated sibling: `degraded_gate::object_degraded_on_a_replica_blocks_writes_not_reads`.
#[test]
fn ec_primary_object_degraded_on_a_peer_shard_blocks_writes_not_reads() {
    let (k, m, chunk) = (2, 1, 32);
    let mut s = ec_cluster(62, &[0, 1, 2], k, m, chunk, true, 1);
    let be = backend(k, m, chunk, true);
    let lead = s.lead_spg(POOL, 0);
    let mut model = BTreeMap::new();
    step(
        &mut s,
        &be,
        &mut model,
        "g",
        vec![EcOp::Touch, EcOp::Write(0, payload(1, 70))],
    );
    let prim = s.primary_of(lead.pgid);
    let victim = *s.acting_of(lead.pgid).iter().find(|o| **o != prim).unwrap();
    s.kill(victim);
    s.run_until(30_000 * MS, "degraded active", |s| {
        s.pg(prim, lead).is_some_and(|pg| {
            pg.acting().contains(&pgwire::NONE_OSD)
                && pg.map_epoch() == s.epoch()
                && pg.state_bits() & pgwire::state::ACTIVE != 0
        })
    });
    s.new_epoch(|m| m.rb.norecover = true);
    // g changes while the shard is away
    let ops = vec![EcOp::Write(10, payload(2, 40))];
    let mut mm = model.get("g").cloned();
    model_apply(&mut mm, &ops);
    let tid = s
        .write_ops(POOL, 0, "g", &ops, mm.as_ref().map(|v| v.len() as u64))
        .expect("accepted");
    s.wait_writes(&[tid], lead);
    let cur = mm.unwrap();
    s.restart(victim);
    let h = hobj(POOL, "g");
    s.run_until(30_000 * MS, "shard back, g degraded on it", |s| {
        s.pg(prim, lead).is_some_and(|pg| {
            !pg.acting().contains(&pgwire::NONE_OSD)
                && pg.map_epoch() == s.epoch()
                && pg.state_bits() & pgwire::state::ACTIVE != 0
                && pg.obj_degraded(&h)
        })
    });
    assert!(
        !s.pg(prim, lead).unwrap().read_blocked(&h),
        "g is readable here: reads are not held"
    );
    let ops = vec![EcOp::Write(0, payload(3, 10))];
    match s.write_ops(POOL, 0, "g", &ops, Some(cur.len() as u64)) {
        Err(peering::WriteErr::Degraded(o)) => assert_eq!(o, h),
        r => panic!("write to a degraded object: {r:?}"),
    }
    assert_eq!(
        read_ec(&mut s, "g", 0, cur.len() as u64).unwrap(),
        cur,
        "read served while the write waits: the current data, decoded around the stale shard"
    );
    s.new_epoch(|m| m.rb.norecover = false);
    s.run_until(60_000 * MS, "recovered and clean", |s| s.pool_clean(POOL));
    let mut mm = Some(cur);
    model_apply(&mut mm, &ops);
    let tid = s
        .write_ops(POOL, 0, "g", &ops, mm.as_ref().map(|v| v.len() as u64))
        .expect("accepted after the recovery");
    s.wait_writes(&[tid], lead);
    let new = mm.unwrap();
    assert_eq!(read_ec(&mut s, "g", 0, new.len() as u64).unwrap(), new);
}

/// EC async recovery (ec.md 9.5): the CRUSH primary returns more than `osd_async_recovery_min_cost` writes behind. It
/// leaves the acting set as an async-recovery target (pg_temp with a hole at its position), the next shard leads and
/// serves writes, also to objects the returning shard misses (log-only sub-writes to it), and the end of recovery clears
/// the pg_temp. Every primary of the PG must make the same choice: the returning one (a classic OSD in the ec-migrate way
/// back, 2026-11-05) requests the hole, the acting one must keep it; otherwise each undoes the other's pg_temp every
/// epoch and the PG never activates (doc/perf/ec-async-recovery-20261105.md).
#[test]
fn ec_async_recovery_of_the_returning_up_primary() {
    let (k, m, chunk) = (2, 2, 32);
    let osds: Vec<i32> = (0..4).collect();
    let mut s = ec_cluster_with(61, &osds, k, m, chunk, true, 1, |c| {
        c.async_recovery_min_cost = 5;
        c.recovery_max_active = 1;
    });
    let be = backend(k, m, chunk, true);
    let pg = s.lead_spg(POOL, 0).pgid;
    let up = s.up_of(pg);
    let victim = up[0];
    assert_eq!(s.primary_of(pg), victim);
    let mut model = BTreeMap::new();
    for i in 0..3 {
        step(
            &mut s,
            &be,
            &mut model,
            &format!("o{i}"),
            vec![EcOp::Touch, EcOp::Write(0, payload(i, 70 + i * 40))],
        );
    }
    s.kill(victim);
    s.run_until(30_000 * MS, "degraded active", |s| {
        let p = s.primary_of(pg);
        p != victim
            && s.pg(p, s.lead_spg(POOL, 0)).is_some_and(|x| {
                x.map_epoch() == s.epoch() && x.state_bits() & pgwire::state::ACTIVE != 0
            })
    });
    // more than min_cost writes it misses: new objects and overwrites
    for i in 0..10 {
        step_degraded(
            &mut s,
            &mut model,
            &format!("n{i}"),
            vec![EcOp::Touch, EcOp::Write(0, payload(10 + i, 50 + i * 20))],
        );
    }
    step_degraded(
        &mut s,
        &mut model,
        "o0",
        vec![EcOp::Write(5, payload(77, 90))],
    );
    s.run_for(200 * MS);
    let e0 = s.epoch();
    s.restart(victim);
    // pg_temp history of the PG from the restart on, and writes while the returning shard is out of acting
    let mut temps: Vec<Vec<i32>> = vec![Vec::new()];
    let mut wrote = false;
    let end = s.now + 60_000 * MS;
    while s.now < end && !s.pool_clean(POOL) {
        s.run_for(5 * MS);
        let t = s.map().pg_temp.get(&pg).cloned().unwrap_or_default();
        if temps.last() != Some(&t) {
            temps.push(t.clone());
        }
        let p = s.primary_of(pg);
        let async_active = !t.is_empty()
            && !s.acting_of(pg).contains(&victim)
            && s.pg(p, s.lead_spg(POOL, 0)).is_some_and(|x| {
                x.map_epoch() == s.epoch() && x.state_bits() & pgwire::state::ACTIVE != 0
            });
        if async_active && !wrote {
            wrote = true;
            // objects the returning shard misses (n3, o0) and one it holds (o1): none waits for its recovery
            for (name, ops) in [
                ("n3", vec![EcOp::Write(7, payload(80, 60))]),
                ("o0", vec![EcOp::Write(0, payload(81, 30))]),
                ("o1", vec![EcOp::Write(9, payload(82, 40))]),
            ] {
                step_degraded(&mut s, &mut model, name, ops);
            }
        }
    }
    assert!(s.pool_clean(POOL), "{}", s.dump());
    assert!(
        wrote,
        "the PG never ran active with the returning shard as async target"
    );
    s.run_for(300 * MS);
    let hole: Vec<i32> = std::iter::once(pgwire::NONE_OSD)
        .chain(up[1..].iter().copied())
        .collect();
    assert_eq!(
        temps,
        vec![Vec::new(), hole, Vec::new()],
        "pg_temp set once by the returning primary, kept by the acting one, cleared once at Recovered"
    );
    assert_eq!(s.acting_of(pg), up);
    assert_eq!(s.stats.pg_temp_from_tick, 0, "pg_temp decided by the tick");
    assert!(
        s.epoch() - e0 <= 10,
        "osdmap churn: {} epochs since the restart",
        s.epoch() - e0
    );
    assert_shards(&s, &be, 0, &model);
    for (n, d) in model.clone() {
        assert_eq!(read_ec(&mut s, &n, 0, d.len() as u64).unwrap(), d, "{n}");
    }
}

/// A checksum-valid store read still has to satisfy L0's independent shard hash. The primary's own shard
/// must take the same checks and reconstruction path as a remote shard (spec ec.md 7.2).
#[test]
fn ec_primary_l0_checks_local_and_remote_shards() {
    let (k, m, chunk) = (2, 1, 32);
    let mut s = ec_cluster(8731, &[0, 1, 2], k, m, chunk, false, 1);
    let lead = s.lead_spg(POOL, 0);
    let primary = s.primary_of(lead.pgid);
    let remote = s.acting_of(lead.pgid)[1];
    assert_ne!(primary, remote);
    for victim in [remote, primary] {
        for fault in ["bytes", "missing", "malformed", "size", "hash-entry"] {
            let name = format!("hash-{victim}-{fault}");
            let data = payload(9, (k * chunk) as usize);
            let tid = s
                .write_ops(
                    POOL,
                    0,
                    &name,
                    &[EcOp::Touch, EcOp::Write(0, data.clone())],
                    Some(data.len() as u64),
                )
                .unwrap();
            s.wait_writes(&[tid], lead);
            let spg = s.spg_on(victim, POOL, 0);
            let obj = s
                .nodes
                .get_mut(&victim)
                .unwrap()
                .store
                .pgs
                .get_mut(&spg)
                .unwrap()
                .objects
                .get_mut(&hobj(POOL, &name))
                .unwrap();
            // Model a wrong shard admitted with valid device checksums (e.g. a bad historical repair),
            // or damaged hinfo metadata. Both are rejected independently of device checksums on L0.
            let expected_error = match fault {
                "bytes" => {
                    obj.data[5] ^= 0xff;
                    "ec read: bad shard hash"
                }
                "missing" => {
                    obj.xattrs.remove(ec::HINFO_KEY.as_bytes());
                    "ec read: missing hinfo"
                }
                "malformed" => {
                    obj.xattrs
                        .insert(ec::HINFO_KEY.as_bytes().to_vec(), vec![0xff]);
                    "ec read: undecodable hinfo"
                }
                "size" => {
                    obj.data.resize(obj.data.len() + chunk as usize, 0);
                    "ec read: hinfo size mismatch"
                }
                "hash-entry" => {
                    let key = ec::HINFO_KEY.as_bytes();
                    let mut hi = ec::HashInfo::decode(obj.xattrs.get(key).unwrap()).unwrap();
                    hi.hashes.truncate(spg.shard.0 as usize);
                    obj.xattrs.insert(key.to_vec(), hi.encode());
                    obj.data[5] ^= 0xff;
                    "ec read: missing shard hash"
                }
                _ => unreachable!(),
            };
            let before = s
                .pg(victim, spg)
                .unwrap()
                .counters()
                .errors
                .get(expected_error)
                .copied()
                .unwrap_or_default();
            assert_eq!(
                read_ec(&mut s, &name, 0, data.len() as u64),
                Ok(data),
                "damaged shard on osd.{victim} must be excluded and reconstructed ({fault})"
            );
            assert_eq!(
                s.pg(victim, spg)
                    .unwrap()
                    .counters()
                    .errors
                    .get(expected_error),
                Some(&(before + 1)),
                "local and remote sources must both reject {fault}"
            );
        }
    }
}

/// A locally rolled-back snapshot trim must restore the index as well as the clone.
/// Otherwise a subsequent trim cannot discover the restored snapshot contents.
/// Clone creation carries no mapper record (a divergent CLONE is removed, which clears it), and
/// no record ever holds an empty set: a classic shard's rollback refuses one.
#[test]
fn ec_snapshot_entries_restore_the_mapper_on_rollback() {
    use denc::types::{CollT, Ghobject, SnapId};
    use peering::snaps::MapOp;
    use peering::{WriteEntry, WriteReq};
    use replwire::{ObjectInfo, Transaction, TxnOp};

    for optimized in [false, true] {
        let mut s = Sim::new(1450 + u64::from(optimized));
        for osd in 0..3 {
            s.add_osd_cfg(osd, |c| {
                c.ec_enable = ec::EcEnable::All;
                c.ec_enable_optimized = ec::EcEnable::All;
                c.ec_primary = true;
                c.ec_opt_primary = true;
            });
        }
        s.run_for(50 * MS);
        if optimized {
            s.create_pool_ec_opt(POOL, 2, 1, 8192, true, 1);
        } else {
            s.create_pool_ec(POOL, 2, 1, 8192, true, 1);
        }
        s.run_until(60_000 * MS, "snapshot pool clean", |s| s.pool_clean(POOL));
        let lead = s.lead_spg(POOL, 0);
        let primary = s.primary_of(lead.pgid);
        let tid = s
            .write_obj(POOL, 0, "snap-source", b"snapshot bytes")
            .unwrap();
        s.wait_writes(&[tid], lead);
        let head = hobj(POOL, "snap-source");
        let mut clone = head.clone();
        clone.snap = SnapId(5);
        for (op, old_snaps, new_snaps) in [
            (pgwire::LogOp::CLONE, vec![], vec![4, 5]),
            (pgwire::LogOp::MODIFY, vec![4, 5], vec![5]),
            (pgwire::LogOp::DELETE, vec![5], vec![]),
        ] {
            let before = s.nodes[&primary].store.pgs[&lead].snapmap.clone();
            let mut t = Transaction::new();
            let cx = t.coll(&CollT::Pg(lead));
            let dst = t.obj(&Ghobject::head(clone.clone(), lead.shard));
            if op == pgwire::LogOp::CLONE {
                let src = t.obj(&Ghobject::head(head.clone(), lead.shard));
                t.push(
                    cx,
                    TxnOp::Clone {
                        oid: src,
                        dest_oid: dst,
                    },
                );
            }
            let mut oi = ObjectInfo::new(clone.clone());
            oi.size = b"snapshot bytes".len() as u64;
            let oi_bytes = denc::to_vec(&oi).unwrap();
            if op == pgwire::LogOp::DELETE {
                t.push(cx, TxnOp::Remove { oid: dst });
            } else {
                t.push(
                    cx,
                    TxnOp::SetAttr {
                        oid: dst,
                        name: b"_",
                        value: &oi_bytes,
                    },
                );
            }
            let tid = s
                .submit_raw(
                    POOL,
                    0,
                    WriteReq {
                        entries: vec![WriteEntry {
                            op,
                            soid: clone.clone(),
                            user_version: 1,
                            snaps: peering::snaps::encode_snaps(&new_snaps),
                            mtime: Default::default(),
                            return_code: 0,
                            op_returns: vec![],
                            prior: None,
                        }],
                        txn_data: t.encode_v9().unwrap().into(),
                        ..Default::default()
                    },
                )
                .unwrap();
            s.wait_writes(&[tid], lead);
            let pg = s.pg(primary, lead).unwrap();
            let entry = pg.log().entry_for(&clone).unwrap();
            let records = ec::moddesc::parse(&entry.mod_desc.bl).unwrap();
            let ctx = peering::ecroll::EcCtx {
                stripe_width: 16384,
                chunk: 8192,
                k: 2,
                raw: 0,
                shard: lead.shard.0 as u32,
                opt: optimized,
                np: false,
                ..Default::default()
            };
            let rollback = peering::ecroll::rollback_entry(&ctx, entry).unwrap();
            if op == pgwire::LogOp::CLONE {
                assert!(
                    !records
                        .iter()
                        .any(|r| matches!(r, ec::moddesc::ModOp::UpdateSnaps(_))),
                    "optimized={optimized}: clone creation has no mapper record"
                );
                assert!(rollback.snap_ops.is_empty());
                continue;
            }
            let mut restored = s.nodes[&primary].store.pgs[&lead].snapmap.clone();
            assert_ne!(restored, before, "the write changes its snapshot mapping");
            for op in rollback.snap_ops {
                assert!(matches!(op, MapOp::Set { .. } | MapOp::Remove { .. }));
                restored.apply(&op);
            }
            assert_eq!(restored, before, "optimized={optimized}, op={op:?}");
            assert_eq!(
                records.first(),
                Some(&ec::moddesc::ModOp::UpdateSnaps(old_snaps)),
                "optimized={optimized}, op={op:?}"
            );
        }
        // No earlier indexed entry for this clone: a failed old-map read must refuse generation,
        // without logging a new mapping or acknowledging the trim.
        clone.snap = SnapId(6);
        let mut t = Transaction::new();
        let cx = t.coll(&CollT::Pg(lead));
        let dst = t.obj(&Ghobject::head(clone.clone(), lead.shard));
        let mut oi = ObjectInfo::new(clone.clone());
        oi.size = 1;
        let oi_bytes = denc::to_vec(&oi).unwrap();
        t.push(
            cx,
            TxnOp::SetAttr {
                oid: dst,
                name: b"_",
                value: &oi_bytes,
            },
        );
        let before = s.pg(primary, lead).unwrap().log().head();
        s.nodes.get_mut(&primary).unwrap().store.snapmap_error = true;
        let tid = s
            .submit_raw(
                POOL,
                0,
                WriteReq {
                    entries: vec![WriteEntry {
                        op: pgwire::LogOp::MODIFY,
                        soid: clone.clone(),
                        user_version: 1,
                        snaps: peering::snaps::encode_snaps(&[6]),
                        mtime: Default::default(),
                        return_code: 0,
                        op_returns: vec![],
                        prior: None,
                    }],
                    txn_data: t.encode_v9().unwrap().into(),
                    ..Default::default()
                },
            )
            .unwrap();
        s.run_until(30_000 * MS, "snapshot mapping read refused", |s| {
            s.failed.iter().any(|(sp, t, _)| *sp == lead && *t == tid)
        });
        assert!(!s.acked.iter().any(|(sp, t, _)| *sp == lead && *t == tid));
        let pg = s.pg(primary, lead).unwrap();
        assert_eq!(pg.log().head(), before);
        assert_eq!(
            pg.counters()
                .errors
                .get("ec write: old snapshot mapping unreadable, refused"),
            Some(&1)
        );
        assert!(
            !s.nodes[&primary].store.pgs[&lead]
                .objects
                .contains_key(&clone)
        );
    }
}
