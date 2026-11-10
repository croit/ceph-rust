// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Optimized EC (mode O, adr 0067) PRIMARY role on the deterministic simulator (all croit-flashstore-osd): write pipeline with
//! partial writes (sparse logs on nonprimary shards, no sub-write for skipped shards), O shard layout, reads.
mod common;
use common::*;
use ecback::{Backend, Geo};
use std::collections::BTreeMap;

const POOL: u64 = 1;

fn payload(i: usize, len: usize) -> Vec<u8> {
    (0..len)
        .map(|j| ((i * 131 + j * 7) % 251) as u8 | 1)
        .collect()
}

fn opt_cluster(seed: u64, osds: &[i32], k: u32, m: u32, chunk: u32) -> Sim {
    opt_cluster_pdw(seed, osds, k, m, chunk, "off")
}

fn opt_cluster_pdw(seed: u64, osds: &[i32], k: u32, m: u32, chunk: u32, pdw: &str) -> Sim {
    opt_cluster_with(seed, osds, (k, m, chunk), |c| {
        c.ec_pdw = ecback::PdwMode::parse(pdw).unwrap_or_default()
    })
}

fn opt_cluster_with(
    seed: u64,
    osds: &[i32],
    (k, m, chunk): (u32, u32, u32),
    f: impl Fn(&mut peering::Config),
) -> Sim {
    let mut s = Sim::new(seed);
    for o in osds {
        s.add_osd_cfg(*o, |c| {
            c.ec_enable = ec::EcEnable::All;
            c.ec_enable_optimized = ec::EcEnable::All;
            c.ec_primary = true;
            c.ec_opt_primary = true;
            f(c);
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
    // parity: encode stripes of the zero padded object, take the parity columns
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

fn assert_o_shards(s: &Sim, be: &Backend, model: &BTreeMap<String, Vec<u8>>) {
    let acting = s.acting_of(denc::types::PgT::new(POOL, 0));
    for (name, data) in model {
        let want = o_shards(be, data);
        for (sh, osd) in acting.iter().enumerate() {
            if *osd == pgwire::NONE_OSD {
                continue;
            }
            let objs = s.nodes[osd].store.objects(s.spg_on(*osd, POOL, 0));
            let o = objs
                .get(&hobj(POOL, name))
                .unwrap_or_else(|| panic!("{name}: shard {sh} on osd.{osd} lacks the object"));
            assert_eq!(o.data.len(), want[sh].len(), "{name}: shard {sh} size");
            assert!(
                o.data == want[sh],
                "{name}: shard {sh} on osd.{osd} content"
            );
        }
    }
}

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
    assert_o_shards(s, be, model);
}

/// Log head of the PG on every acting member.
fn heads(s: &Sim) -> Vec<denc::types::Eversion> {
    let acting = s.acting_of(denc::types::PgT::new(POOL, 0));
    acting
        .iter()
        .map(|o| {
            let spg = s.spg_on(*o, POOL, 0);
            s.pg(*o, spg).unwrap().log().head()
        })
        .collect()
}

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
    r
}

#[test]
fn ec_opt_primary_partial_writes_skip_nonprimary_shards() {
    let (k, m, chunk) = (4, 2, 4096);
    let mut s = opt_cluster(31, &[0, 1, 2, 3, 4, 5], k, m, chunk);
    let be = backend(k, m, chunk);
    let st = be.s as usize;
    let mut model = BTreeMap::new();
    // first write of the interval (and a size change): every shard
    step(
        &mut s,
        &be,
        &mut model,
        "a",
        vec![EcOp::Touch, EcOp::Write(0, payload(1, 3 * st + 100))],
    );
    let h0 = heads(&s);
    assert!(h0.iter().all(|h| *h == h0[0]), "all shards written: {h0:?}");
    // in-place overwrite of data shard 2 only (stripe 1): shards 0, 2 and parity 4, 5 get it; 1 and 3 do not
    step(
        &mut s,
        &be,
        &mut model,
        "a",
        vec![EcOp::Write(st as u64 + 2 * 4096 + 10, payload(2, 100))],
    );
    let h1 = heads(&s);
    for sh in [0, 2, 4, 5] {
        assert!(h1[sh] > h0[sh], "shard {sh} got the partial write: {h1:?}");
    }
    for sh in [1, 3] {
        assert_eq!(h1[sh], h0[sh], "nonprimary shard {sh} skipped: {h1:?}");
    }
    // pre_submit_op (prim A.1): the primary's peer_info of skipped members advances too
    let lead = s.lead_spg(POOL, 0);
    let posd = s.primary_of(lead.pgid);
    let acting = s.acting_of(lead.pgid);
    let pg = s.pg(posd, lead).expect("lead pg");
    for sh in [1, 3] {
        let lu = pg
            .peer_infos()
            .find(|(o, _)| *o == acting[sh])
            .map(|(_, i)| i.last_update);
        assert_eq!(lu, Some(h1[0]), "peer_info of skipped shard {sh}");
    }
    // overwrite on shard 1 only
    step(
        &mut s,
        &be,
        &mut model,
        "a",
        vec![EcOp::Write(4096, payload(3, 4096))],
    );
    let h2 = heads(&s);
    assert!(h2[1] > h1[1] && h2[3] == h1[3]);
    // reads see the model
    let a = model["a"].clone();
    assert_eq!(read_ec(&mut s, "a", 0, a.len() as u64).unwrap(), a);
    assert_eq!(
        read_ec(&mut s, "a", 4000, 9000).unwrap(),
        a[4000..13000].to_vec()
    );
    // zero, truncate (unaligned), append, writefull, delete
    step(&mut s, &be, &mut model, "a", vec![EcOp::Zero(5000, 3000)]);
    step(
        &mut s,
        &be,
        &mut model,
        "a",
        vec![EcOp::Trunc(st as u64 + 777)],
    );
    step(
        &mut s,
        &be,
        &mut model,
        "a",
        vec![EcOp::Write(st as u64 + 777, payload(4, 20000))],
    );
    step(
        &mut s,
        &be,
        &mut model,
        "a",
        vec![EcOp::Trunc(0), EcOp::Write(0, payload(5, 5000))],
    );
    step(
        &mut s,
        &be,
        &mut model,
        "b",
        vec![EcOp::Touch, EcOp::Write(0, payload(6, 100))],
    );
    step(
        &mut s,
        &be,
        &mut model,
        "b",
        vec![EcOp::Write(50, payload(7, 10))],
    );
    step(&mut s, &be, &mut model, "b", vec![EcOp::Remove]);
    let a = model["a"].clone();
    assert_eq!(read_ec(&mut s, "a", 0, a.len() as u64).unwrap(), a);
    // the idle pipeline rolls everything forward: no stash generations left anywhere
    s.run_for(3000 * MS);
    for o in s.acting_of(denc::types::PgT::new(POOL, 0)) {
        let st = s.nodes[&o].store.stash(s.spg_on(o, POOL, 0));
        assert!(
            st.is_empty(),
            "stash left on osd.{o}: {:?}",
            st.keys().collect::<Vec<_>>()
        );
    }
}

#[test]
fn ec_opt_primary_pipelined_partial_writes() {
    let (k, m, chunk) = (3, 2, 4096);
    let mut s = opt_cluster(32, &[0, 1, 2, 3, 4], k, m, chunk);
    let be = backend(k, m, chunk);
    let mut model: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    step(
        &mut s,
        &be,
        &mut model,
        "p",
        vec![EcOp::Touch, EcOp::Write(0, payload(1, 40000))],
    );
    // several overlapping overwrites in flight at once on one object
    let lead = s.lead_spg(POOL, 0);
    let mut m = model["p"].clone();
    let mut tids = Vec::new();
    for i in 0..6u64 {
        let off = 3000 + i * 4500;
        let d = payload(10 + i as usize, 2500);
        m[off as usize..off as usize + d.len()].copy_from_slice(&d);
        tids.push(
            s.write_ops(POOL, 0, "p", &[EcOp::Write(off, d)], Some(m.len() as u64))
                .expect("accepted"),
        );
    }
    s.wait_writes(&tids, lead);
    s.run_for(100 * MS);
    model.insert("p".into(), m.clone());
    assert_o_shards(&s, &be, &model);
    assert_eq!(read_ec(&mut s, "p", 0, m.len() as u64).unwrap(), m);
}

fn live(s: &mut Sim, model: &mut BTreeMap<String, Vec<u8>>, name: &str, ops: Vec<EcOp>) {
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

/// Partial writes, a nonprimary / parity shard away while more partial and full writes happen, return, recovery;
/// then a primary restart (re-peering with sparse nonprimary logs): every shard ends in the O layout of the model.
#[test]
fn ec_opt_primary_shard_away_and_primary_restart() {
    let (k, m, chunk) = (4, 2, 4096);
    for victim_pos in [3usize, 1, 5] {
        let mut s = opt_cluster(50 + victim_pos as u64, &[0, 1, 2, 3, 4, 5], k, m, chunk);
        let be = backend(k, m, chunk);
        let st = be.s;
        let lead = s.lead_spg(POOL, 0);
        let mut model = BTreeMap::new();
        for i in 0..3 {
            step(
                &mut s,
                &be,
                &mut model,
                &format!("o{i}"),
                vec![
                    EcOp::Touch,
                    EcOp::Write(0, payload(i, 2 * st as usize + 300)),
                ],
            );
        }
        // partial writes: skip shards 1 and 3
        step(
            &mut s,
            &be,
            &mut model,
            "o0",
            vec![EcOp::Write(2 * 4096 + 7, payload(9, 50))],
        );
        let victim = s.acting_of(lead.pgid)[victim_pos];
        s.kill(victim);
        s.run_until(30_000 * MS, "degraded active", |s| {
            let p = s.primary_of(lead.pgid);
            s.pg(p, lead).is_some_and(|pg| {
                pg.acting().contains(&pgwire::NONE_OSD)
                    && pg.map_epoch() == s.epoch()
                    && pg.state_bits() & pgwire::state::ACTIVE != 0
            })
        });
        live(
            &mut s,
            &mut model,
            "o1",
            vec![EcOp::Write(4096 + 100, payload(10, 200))],
        ); // shard 1 only
        live(
            &mut s,
            &mut model,
            "o1",
            vec![EcOp::Write(3 * 4096, payload(11, 4096))],
        ); // shard 3 only
        live(
            &mut s,
            &mut model,
            "o2",
            vec![EcOp::Write(2 * st + 300, payload(12, 9000))],
        ); // append (all)
        live(
            &mut s,
            &mut model,
            "o3",
            vec![EcOp::Touch, EcOp::Write(0, payload(13, 777))],
        );
        s.run_for(200 * MS);
        s.restart(victim);
        s.run_until(60_000 * MS, "clean after return", |s| s.pool_clean(POOL));
        s.run_for(500 * MS);
        assert_o_shards(&s, &be, &model);
        // second interval change (parity shard away and back): re-peer with sparse logs, still consistent. (A dead
        // shard-0 primary is left to the primary-first pg_temp test below.)
        let prim = s.acting_of(lead.pgid)[4];
        s.kill(prim);
        s.run_for(3000 * MS);
        s.restart(prim);
        s.run_until(60_000 * MS, "clean after primary restart", |s| {
            s.pool_clean(POOL)
        });
        step(
            &mut s,
            &be,
            &mut model,
            "o0",
            vec![EcOp::Write(4096, payload(14, 10))],
        );
        step(
            &mut s,
            &be,
            &mut model,
            "o0",
            vec![EcOp::Write(3 * 4096 + 1, payload(15, 10))],
        );
        for (name, data) in model.clone() {
            assert_eq!(
                read_ec(&mut s, &name, 0, data.len() as u64).unwrap(),
                data,
                "{name}"
            );
        }
    }
}

/// Prim spec C.1-C.3: a full write that reached only primary-capable shards (sub-writes to every nonprimary shard lost)
/// when the interval changes. The authoritative (primary-capable) logs all have it, but fewer than k shards do: the
/// GET-LOG pass takes the oldest log incl. nonprimary shards, the entry was meant for that shard, so it is divergent
/// and rolled back everywhere (classic behaviour). Fetching from a primary-capable shard only would keep it and leave
/// the object unfound.
#[test]
fn ec_opt_primary_uses_nonprimary_log_to_roll_back_a_write_too_few_shards_have() {
    let (k, m, chunk) = (4, 2, 4096);
    let mut s = opt_cluster(61, &[0, 1, 2, 3, 4, 5], k, m, chunk);
    let be = backend(k, m, chunk);
    let lead = s.lead_spg(POOL, 0);
    let mut model = BTreeMap::new();
    let old = payload(1, 3 * be.s as usize);
    step(
        &mut s,
        &be,
        &mut model,
        "x",
        vec![EcOp::Touch, EcOp::Write(0, old.clone())],
    );
    let acting = s.acting_of(lead.pgid);
    let prim = acting[0];
    for np in &acting[1..k as usize] {
        s.drop_next.push((prim, *np, ecwire::ty::EC_WRITE));
    }
    let tid = s
        .write_ops(
            POOL,
            0,
            "x",
            &[EcOp::Write(0, payload(2, 3 * be.s as usize))],
            Some(old.len() as u64),
        )
        .expect("accepted");
    s.run_for(300 * MS);
    assert!(
        !s.is_acked(lead, tid),
        "write must not ack without the nonprimary shards"
    );
    // the write is on the primary and both parity shards; one parity shard goes away: only 2 < k shards hold it
    s.kill(acting[5]);
    s.run_until(30_000 * MS, "active without parity 2", |s| {
        let p = s.primary_of(lead.pgid);
        s.pg(p, lead).is_some_and(|pg| {
            pg.map_epoch() == s.epoch() && pg.state_bits() & pgwire::state::ACTIVE != 0
        })
    });
    s.restart(acting[5]);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(POOL));
    s.run_for(500 * MS);
    assert_eq!(read_ec(&mut s, "x", 0, old.len() as u64).unwrap(), old);
    assert_o_shards(&s, &be, &model);
    let heads = heads(&s);
    assert!(
        heads.windows(2).all(|w| w[0] == w[1]),
        "logs agree: {heads:?}"
    );
}

/// Prim spec C.3 keep rule: acked partial writes that skipped nonprimary shards survive an interval change right after
/// the ack (before any roll-forward could record them in pwlc), whatever shard's log GetLog fetches.
#[test]
fn ec_opt_primary_keeps_acked_partial_writes_across_an_immediate_interval_change() {
    let (k, m, chunk) = (4, 2, 4096);
    for (seed, victim) in [(62u64, 5usize), (63, 4)] {
        let mut s = opt_cluster(seed, &[0, 1, 2, 3, 4, 5], k, m, chunk);
        let be = backend(k, m, chunk);
        let lead = s.lead_spg(POOL, 0);
        let mut model = BTreeMap::new();
        step(
            &mut s,
            &be,
            &mut model,
            "y",
            vec![EcOp::Touch, EcOp::Write(0, payload(3, 2 * be.s as usize))],
        );
        let acting = s.acting_of(lead.pgid);
        // shard 2 only (+ primary-capable shards): nonprimary shards 1 and 3 are skipped
        live(
            &mut s,
            &mut model,
            "y",
            vec![EcOp::Write(2 * 4096 + 5, payload(4, 100))],
        );
        live(
            &mut s,
            &mut model,
            "y",
            vec![EcOp::Write(4096 + 5, payload(5, 100))],
        ); // shard 1 only
        s.kill(acting[victim]);
        s.run_until(30_000 * MS, "active", |s| {
            let p = s.primary_of(lead.pgid);
            s.pg(p, lead).is_some_and(|pg| {
                pg.map_epoch() == s.epoch() && pg.state_bits() & pgwire::state::ACTIVE != 0
            })
        });
        let d = model["y"].clone();
        assert_eq!(
            read_ec(&mut s, "y", 0, d.len() as u64).unwrap(),
            d,
            "degraded read"
        );
        s.restart(acting[victim]);
        s.run_until(60_000 * MS, "clean", |s| s.pool_clean(POOL));
        s.run_for(500 * MS);
        assert_o_shards(&s, &be, &model);
        assert_eq!(read_ec(&mut s, "y", 0, d.len() as u64).unwrap(), d);
    }
}

/// O1 (spec 2.4): a legacy (L1) pool whose `allow_ec_optimizations` flips: objects written before keep the legacy
/// layout (hinfo, every shard padded to whole stripes). After the flip they read back, take partial overwrites,
/// appends, truncates, recovery and a deep scrub.
#[test]
fn ec_opt_primary_legacy_objects_after_the_flag_flips() {
    let (k, m, chunk) = (3u32, 2u32, 16384u32);
    let mut s = Sim::new(64);
    for o in 0..5 {
        s.add_osd_cfg(o, |c| {
            c.ec_enable = ec::EcEnable::All;
            c.ec_enable_optimized = ec::EcEnable::All;
            c.ec_primary = true;
            c.ec_opt_primary = true;
        });
    }
    s.run_for(50 * MS);
    s.create_pool_ec(POOL, k, m, chunk, true, 1);
    s.run_for(2000 * MS);
    s.run_until(60_000 * MS, "legacy pool clean", |s| s.pool_clean(POOL));
    let lead = s.lead_spg(POOL, 0);
    let sw = (k * chunk) as usize;
    let mut model: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let sizes = [1usize, 5000, sw - 1, sw + 4097, 2 * sw + 100];
    for (i, n) in sizes.iter().enumerate() {
        let ss = denc::to_vec(&replwire::SnapSet::default()).unwrap();
        live(
            &mut s,
            &mut model,
            &format!("l{i}"),
            vec![
                EcOp::Touch,
                EcOp::Write(0, payload(i, *n)),
                EcOp::Attr("snapset", ss),
            ],
        );
    }
    s.run_for(300 * MS);
    let acting = s.acting_of(lead.pgid);
    {
        // legacy layout on disk: every shard a whole number of chunks per stripe, hinfo present
        let o = &s.nodes[&acting[1]]
            .store
            .objects(s.spg_on(acting[1], POOL, 0))[&hobj(POOL, "l1")];
        assert_eq!(
            o.data.len(),
            chunk as usize,
            "legacy shard padded to a full chunk"
        );
        assert!(
            o.xattrs.contains_key(&b"hinfo_key"[..]),
            "legacy object carries hinfo"
        );
    }
    s.new_epoch(|mp| {
        let p = mp.pools.get_mut(&POOL).unwrap();
        p.ec_optimizations = true;
        let e = std::sync::Arc::make_mut(p.ec.as_mut().unwrap());
        e.optimized = true;
        e.nonprimary = (1..k).collect();
    });
    s.run_until(60_000 * MS, "clean after flip", |s| {
        let p = s.primary_of(lead.pgid);
        s.pool_clean(POOL) && s.pg(p, lead).is_some_and(|pg| pg.map_epoch() == s.epoch())
    });
    let check = |s: &mut Sim, model: &BTreeMap<String, Vec<u8>>, why: &str| {
        for (name, d) in model {
            assert_eq!(
                read_ec(s, name, 0, d.len() as u64 + 4096).unwrap(),
                *d,
                "{why}: {name}"
            );
        }
    };
    check(&mut s, &model, "after flip");
    // partial overwrite (one data shard), append, truncate down / up, zero, full rewrite
    live(
        &mut s,
        &mut model,
        "l4",
        vec![EcOp::Write(chunk as u64 + 10, payload(20, 300))],
    );
    live(
        &mut s,
        &mut model,
        "l1",
        vec![EcOp::Write(5000, payload(21, 40_000))],
    );
    live(&mut s, &mut model, "l3", vec![EcOp::Trunc(7000)]);
    live(
        &mut s,
        &mut model,
        "l2",
        vec![EcOp::Trunc(sw as u64 + 9000)],
    );
    live(
        &mut s,
        &mut model,
        "l0",
        vec![EcOp::Zero(0, 1), EcOp::Write(2, payload(22, 10))],
    );
    live(
        &mut s,
        &mut model,
        "l3",
        vec![EcOp::Write(0, payload(23, 3 * sw))],
    );
    s.run_for(300 * MS);
    check(&mut s, &model, "after writes");
    // a nonprimary data shard and a parity shard away during more writes, then recovery
    for victim in [acting[2], acting[4]] {
        s.kill(victim);
        s.run_until(30_000 * MS, "degraded active", |s| {
            let p = s.primary_of(lead.pgid);
            s.pg(p, lead).is_some_and(|pg| {
                pg.map_epoch() == s.epoch() && pg.state_bits() & pgwire::state::ACTIVE != 0
            })
        });
        live(
            &mut s,
            &mut model,
            "l4",
            vec![EcOp::Write(2 * chunk as u64 + 5, payload(30, 100))],
        );
        check(&mut s, &model, "degraded");
        s.restart(victim);
        s.run_until(60_000 * MS, "clean after return", |s| s.pool_clean(POOL));
        check(&mut s, &model, "after recovery");
    }
    let prim = s.primary_of(lead.pgid);
    s.call(prim, |set, now, st| {
        set.request_scrub(now, lead, true, false, st)
    });
    s.run_until(60_000 * MS, "scrub finished", move |s| {
        let p = s.pg(prim, lead).unwrap();
        p.scrub_counts().0 > 0 && !p.scrub_running() && p.is_clean()
    });
    let errs = s
        .pg(prim, lead)
        .unwrap()
        .info()
        .stats
        .stats
        .sum
        .num_scrub_errors;
    assert_eq!(errs, 0, "deep scrub of mixed legacy / O objects");
}

/// adr 0067 am. 4.4: `ec_opt_primary` switched off at runtime while we lead an active optimized PG with writes in
/// flight: the interval keeps its role (no stalled pipeline), a new interval is requested (pg_temp = only us), there
/// the role is refused and the pg_temp cleared (acting = up, as after a start with the switch off). Switched on again,
/// the next interval leads normally and the acked data is intact.
#[test]
fn ec_opt_primary_switched_off_at_runtime_takes_effect_cleanly() {
    let (k, m, chunk) = (2, 2, 4096);
    let mut s = opt_cluster(65, &[0, 1, 2, 3], k, m, chunk);
    let be = backend(k, m, chunk);
    let lead = s.lead_spg(POOL, 0);
    let prim = s.primary_of(lead.pgid);
    let mut model = BTreeMap::new();
    step(
        &mut s,
        &be,
        &mut model,
        "a",
        vec![EcOp::Touch, EcOp::Write(0, payload(1, 20_000))],
    );
    // writes in flight when the switch flips
    let mut tids = Vec::new();
    for i in 0..4u64 {
        tids.push(
            s.write_ops(
                POOL,
                0,
                "b",
                &[EcOp::Write(i * 4096, payload(2 + i as usize, 4096))],
                Some((i + 1) * 4096),
            )
            .expect("accepted"),
        );
    }
    let switch = |s: &mut Sim, on: bool| {
        s.call(prim, |set, _, _| {
            set.set_ec_opt_primary(on);
            set.push_cfg_to_pgs();
            vec![]
        })
    };
    let e0 = s.epoch();
    switch(&mut s, false);
    s.run_until(
        30_000 * MS,
        "role refused in a new interval, pg_temp cleared",
        |s| {
            let pg = s.pg(prim, lead);
            s.epoch() >= e0 + 2
                && pg.is_some_and(|p| p.refusal().is_some() && p.map_epoch() == s.epoch())
                && s.map().pg_temp.get(&lead.pgid).is_none_or(|t| t.is_empty())
                && s.acting_of(lead.pgid) == s.up_of(lead.pgid)
        },
    );
    // every write of the old interval finished one way or the other (acked, or dropped with the interval)
    s.run_for(500 * MS);
    switch(&mut s, true);
    let parity = s.acting_of(lead.pgid)[3];
    s.kill(parity);
    s.run_for(1000 * MS);
    s.restart(parity);
    s.run_until(60_000 * MS, "clean again", |s| s.pool_clean(POOL));
    assert!(s.pg(prim, lead).unwrap().refusal().is_none());
    assert_eq!(read_ec(&mut s, "a", 0, 20_000).unwrap(), model["a"]);
    step(
        &mut s,
        &be,
        &mut model,
        "c",
        vec![EcOp::Touch, EcOp::Write(0, payload(9, 9000))],
    );
    assert_eq!(read_ec(&mut s, "c", 0, 9000).unwrap(), model["c"]);
    let _ = tids;
}

/// Deep scrub as mode O primary: partial writes (stale nonprimary `_`, per-shard sizes) scrub clean; a shard with a
/// wrong size is found and repaired by recovery.
#[test]
fn ec_opt_primary_scrub_clean_after_partial_writes_and_repairs_size() {
    let (k, m, chunk) = (3, 2, 4096);
    for victim_pos in [1usize, 2, 4] {
        let mut s = opt_cluster(70 + victim_pos as u64, &[0, 1, 2, 3, 4], k, m, chunk);
        let be = backend(k, m, chunk);
        let lead = s.lead_spg(POOL, 0);
        let prim = s.primary_of(lead.pgid);
        let mut model = BTreeMap::new();
        let ss = denc::to_vec(&replwire::SnapSet::default()).unwrap();
        for i in 0..4 {
            let d = payload(i, 5000 + i * 7000);
            step(
                &mut s,
                &be,
                &mut model,
                &format!("s{i}"),
                vec![
                    EcOp::Touch,
                    EcOp::Write(0, d),
                    EcOp::Attr("snapset", ss.clone()),
                ],
            );
        }
        // partial writes to shard 1 and shard 2 of different objects (stale `_` on the other)
        step(
            &mut s,
            &be,
            &mut model,
            "s2",
            vec![EcOp::Write(4096 + 9, payload(20, 30))],
        );
        step(
            &mut s,
            &be,
            &mut model,
            "s3",
            vec![EcOp::Write(2 * 4096 + 9, payload(21, 30))],
        );
        s.run_for(300 * MS);
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
        let errs = |s: &Sim| {
            s.pg(prim, lead)
                .unwrap()
                .info()
                .stats
                .stats
                .sum
                .num_scrub_errors
        };
        scrub(&mut s, false);
        assert_eq!(errs(&s), 0, "pos {victim_pos}: clean O pg reports errors");
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
            .data
            .truncate(4096);
        scrub(&mut s, false);
        assert!(errs(&s) > 0, "pos {victim_pos}: short shard not found");
        scrub(&mut s, true);
        s.run_until(60_000 * MS, "repaired and clean", |s| s.pool_clean(POOL));
        s.run_for(500 * MS);
        assert_o_shards(&s, &be, &model);
        scrub(&mut s, false);
        assert_eq!(errs(&s), 0, "pos {victim_pos}: errors remain after repair");
    }
}

/// Deep scrub as mode O primary, CRC linearity (prim spec E.6): a flipped byte (size unchanged) on a data shard or the
/// first parity shard is one deep error of the object; repair leaves it (object-level finding, no shard to blame);
/// a flip on the second parity shard stays invisible to this check (upstream UI-9). Clean after the byte is restored.
#[test]
fn ec_opt_primary_deep_scrub_crc_linearity() {
    let (k, m, chunk) = (3, 2, 4096);
    for (pos, seen) in [(0usize, true), (1, true), (3, true), (4, false)] {
        let mut s = opt_cluster(90 + pos as u64, &[0, 1, 2, 3, 4], k, m, chunk);
        let be = backend(k, m, chunk);
        let lead = s.lead_spg(POOL, 0);
        let prim = s.primary_of(lead.pgid);
        let mut model = BTreeMap::new();
        let ss = denc::to_vec(&replwire::SnapSet::default()).unwrap();
        step(
            &mut s,
            &be,
            &mut model,
            "c",
            vec![
                EcOp::Touch,
                EcOp::Write(0, payload(5, 40_000)),
                EcOp::Attr("snapset", ss),
            ],
        );
        s.run_for(300 * MS);
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
        let deep = |s: &Sim| {
            s.pg(prim, lead)
                .unwrap()
                .info()
                .stats
                .stats
                .sum
                .num_deep_scrub_errors
        };
        scrub(&mut s, false);
        assert_eq!(deep(&s), 0, "pos {pos}: clean");
        let osd = s.acting_of(lead.pgid)[pos];
        let sp = s.spg_on(osd, POOL, 0);
        let flip = |s: &mut Sim| {
            let d = &mut s
                .nodes
                .get_mut(&osd)
                .unwrap()
                .store
                .pgs
                .get_mut(&sp)
                .unwrap()
                .objects
                .get_mut(&hobj(POOL, "c"))
                .unwrap()
                .data;
            d[100] ^= 0x40;
        };
        flip(&mut s);
        scrub(&mut s, false);
        assert_eq!(deep(&s), u64::from(seen) as i64, "pos {pos}: crc finding");
        scrub(&mut s, true);
        assert_eq!(
            deep(&s),
            u64::from(seen) as i64,
            "pos {pos}: repair must not clear it"
        );
        flip(&mut s);
        scrub(&mut s, false);
        assert_eq!(deep(&s), 0, "pos {pos}: restored");
    }
}

/// ceph_test_rados "write initial": several unaligned appends to one new object in flight at once.
#[test]
fn ec_opt_primary_pipelined_unaligned_appends() {
    let (k, m, chunk) = (2, 2, 4096);
    let mut s = opt_cluster(33, &[0, 1, 2, 3], k, m, chunk);
    let be = backend(k, m, chunk);
    let lead = s.lead_spg(POOL, 0);
    let mut model: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut m = Vec::new();
    let mut tids = Vec::new();
    for (i, (a, b)) in [(0usize, 103368usize), (103368, 258403), (258403, 403368)]
        .iter()
        .enumerate()
    {
        let d = payload(40 + i, b - a);
        m.extend_from_slice(&d);
        let ops = if i == 0 {
            vec![EcOp::Touch, EcOp::Write(*a as u64, d)]
        } else {
            vec![EcOp::Write(*a as u64, d)]
        };
        tids.push(
            s.write_ops(POOL, 0, "w", &ops, Some(m.len() as u64))
                .expect("accepted"),
        );
    }
    s.wait_writes(&tids, lead);
    s.run_for(100 * MS);
    model.insert("w".into(), m.clone());
    assert_o_shards(&s, &be, &model);
}

/// S5: parity-delta writes + extent cache. Pipelined 4K overwrites hammering the same stripes (cache hits generate
/// on top of uncommitted writes), sub-page writes, a parity and a data shard away and back in between: shards always
/// end in the O layout of the model (parity == encode(data)) and read back.
#[test]
fn ec_opt_primary_pdw_and_extent_cache() {
    for (k, m, chunk, mode) in [
        (4u32, 2u32, 4096u32, "always"),
        (4, 2, 16384, "auto"),
        (2, 1, 4096, "always"),
    ] {
        let osds: Vec<i32> = (0..(k + m) as i32).collect();
        let mut s = opt_cluster_pdw(70 + k as u64 + chunk as u64, &osds, k, m, chunk, mode);
        let be = backend(k, m, chunk);
        let lead = s.lead_spg(POOL, 0);
        let mut model = BTreeMap::new();
        let len = 3 * be.s as usize + 1000;
        step(
            &mut s,
            &be,
            &mut model,
            "p",
            vec![EcOp::Touch, EcOp::Write(0, payload(1, len))],
        );
        let burst = |s: &mut Sim, model: &mut BTreeMap<String, Vec<u8>>, seed: usize| {
            let mut mm = model["p"].clone();
            let mut tids = Vec::new();
            for i in 0..12usize {
                let off = ((i * 7 + seed) % 9) as u64 * 4096 + if i % 3 == 0 { 100 } else { 0 };
                let d = payload(seed * 100 + i, if i % 4 == 1 { 300 } else { 4096 });
                if off as usize + d.len() > mm.len() {
                    continue;
                }
                mm[off as usize..off as usize + d.len()].copy_from_slice(&d);
                tids.push(
                    s.write_ops(POOL, 0, "p", &[EcOp::Write(off, d)], Some(mm.len() as u64))
                        .expect("accepted"),
                );
            }
            let l = s.lead_spg(POOL, 0);
            s.wait_writes(&tids, l);
            s.run_for(100 * MS);
            model.insert("p".into(), mm);
        };
        burst(&mut s, &mut model, 1);
        let (pdw, hits) = s
            .pg(s.primary_of(lead.pgid), lead)
            .map(|p| p.ec_pdw_stats())
            .unwrap();
        eprintln!("k{k}m{m} C{chunk} {mode}: pdw {pdw} cache hits {hits}");
        assert!(
            hits > 0 && (pdw > 0 || k == 2),
            "k{k}m{m} {mode}: pdw {pdw} hits {hits}"
        );
        assert_o_shards(&s, &be, &model);
        let away: &[usize] = if m >= 2 { &[4, 1] } else { &[] };
        for &pos in away {
            let victim = s.acting_of(lead.pgid)[pos];
            s.kill(victim);
            s.run_for(8000 * MS);
            burst(&mut s, &mut model, 2 + pos);
            s.restart(victim);
            s.run_until(60_000 * MS, "clean after revive", |s| s.pool_clean(POOL));
            burst(&mut s, &mut model, 5 + pos);
            assert_o_shards(&s, &be, &model);
        }
        let want = model["p"].clone();
        assert_eq!(
            read_ec(&mut s, "p", 0, want.len() as u64).unwrap(),
            want,
            "k{k}m{m} {mode}"
        );
    }
}

/// S5 regression: `ec_pdw` switched off and on again at runtime (config push into live PGs, same interval). Writes
/// generated across the switch (PDW and conventional) must not leave stale pages behind for later cache-served RMW
/// writes.
#[test]
fn ec_opt_primary_extent_cache_runtime_toggle() {
    let (k, m, chunk) = (4u32, 2u32, 4096u32);
    let osds: Vec<i32> = (0..(k + m) as i32).collect();
    let mut s = opt_cluster_pdw(91, &osds, k, m, chunk, "always");
    let be = backend(k, m, chunk);
    let mut model = BTreeMap::new();
    let len = 3 * be.s as usize;
    step(
        &mut s,
        &be,
        &mut model,
        "t",
        vec![EcOp::Touch, EcOp::Write(0, payload(1, len))],
    );
    let set_pdw = |s: &mut Sim, mode: &'static str| {
        for o in 0..(k + m) as i32 {
            s.call(o, |set, _, _| {
                set.set_ec_pdw(mode);
                set.push_cfg_to_pgs();
                vec![]
            });
        }
    };
    let burst = |s: &mut Sim, model: &mut BTreeMap<String, Vec<u8>>, seed: usize, n: usize| {
        let mut mm = model["t"].clone();
        let mut tids = Vec::new();
        for i in 0..n {
            let off = (i % 3) as u64 * 4096;
            let d = payload(seed * 100 + i, 4096);
            mm[off as usize..off as usize + d.len()].copy_from_slice(&d);
            tids.push(
                s.write_ops(POOL, 0, "t", &[EcOp::Write(off, d)], Some(mm.len() as u64))
                    .expect("accepted"),
            );
        }
        let l = s.lead_spg(POOL, 0);
        s.wait_writes(&tids, l);
        s.run_for(100 * MS);
        model.insert("t".into(), mm);
    };
    burst(&mut s, &mut model, 1, 6);
    set_pdw(&mut s, "off");
    burst(&mut s, &mut model, 2, 6);
    assert_o_shards(&s, &be, &model);
    set_pdw(&mut s, "always");
    // one page only: the other pages of the stripe stay as burst 2 left them
    burst(&mut s, &mut model, 3, 1);
    assert_o_shards(&s, &be, &model);
    let want = model["t"].clone();
    assert_eq!(read_ec(&mut s, "t", 0, want.len() as u64).unwrap(), want);
}

/// Pipelined appends to one object with the default config (`ec_pdw` off): every append whose stripe holds old bytes
/// takes its RMW read from the extent cache (no wait for the commit of the write before it, no shard read), with
/// unaligned sizes, a write over whole stripes and a create; a truncate in the burst drops the cache (appends after it
/// read the shards until the cache holds their rows again). Bytes on every shard and the read-back stay exact.
#[test]
fn ec_opt_primary_pipelined_appends_from_cache() {
    for (k, m, chunk) in [(2u32, 2u32, 4096u32), (4, 2, 16384), (2, 1, 4096)] {
        let osds: Vec<i32> = (0..(k + m) as i32).collect();
        let mut s = opt_cluster(110 + k as u64 + chunk as u64, &osds, k, m, chunk);
        let be = backend(k, m, chunk);
        let lead = s.lead_spg(POOL, 0);
        let mut model = BTreeMap::new();
        // (RMW shard reads started, extent cache hits) of the lead PG
        let stats = |s: &Sim| {
            let l = s.lead_spg(POOL, 0);
            let pg = s.pg(s.primary_of(l.pgid), l).unwrap();
            (pg.ec_rmw_stats().0, pg.ec_pdw_stats().1)
        };
        let st = be.s as usize;
        let sizes = [
            4096usize,
            4096,
            3000,
            1096,
            4096,
            2 * st + 4096,
            4096,
            100,
            3996,
            4096,
            4096,
            4096,
        ];
        step(
            &mut s,
            &be,
            &mut model,
            "a",
            vec![EcOp::Touch, EcOp::Write(0, payload(1, 4096))],
        );
        // "n" is created by the first append of its burst
        for (name, trunc_at) in [("a", None), ("n", None), ("a", Some(5usize))] {
            let (r0, h0) = stats(&s);
            let mut mm = model.get(name).cloned().unwrap_or_default();
            let mut tids = Vec::new();
            for (i, len) in sizes.iter().enumerate() {
                if trunc_at == Some(i) {
                    let t = mm.len() - 1000;
                    mm.truncate(t);
                    tids.push(
                        s.write_ops(POOL, 0, name, &[EcOp::Trunc(t as u64)], Some(t as u64))
                            .expect("accepted"),
                    );
                }
                let off = mm.len() as u64;
                let d = payload(name.len() * 1000 + i, *len);
                mm.extend_from_slice(&d);
                tids.push(
                    s.write_ops(POOL, 0, name, &[EcOp::Write(off, d)], Some(mm.len() as u64))
                        .expect("accepted"),
                );
            }
            s.wait_writes(&tids, lead);
            s.run_for(100 * MS);
            model.insert(name.into(), mm);
            let (r1, h1) = stats(&s);
            let (reads, hits) = (r1 - r0, h1 - h0);
            eprintln!(
                "k{k}m{m} C{chunk} {name} trunc {trunc_at:?}: shard reads {reads} cache hits {hits}"
            );
            assert!(
                hits > 0,
                "k{k}m{m} C{chunk} {name}: no append served by the extent cache"
            );
            // after the truncate the appends read what the dropped pages held (the rows of earlier writes); without it
            // nothing is read
            assert!(
                trunc_at.is_some() || reads == 0,
                "k{k}m{m} C{chunk} {name}: {reads} RMW shard reads"
            );
            assert_o_shards(&s, &be, &model);
        }
        for (name, want) in &model {
            assert_eq!(
                read_ec(&mut s, name, 0, want.len() as u64).unwrap(),
                *want,
                "k{k}m{m} {name}"
            );
        }
    }
}

/// Every node's store answers "device reads in flight" for the next `n` data probes.
fn cold_data(s: &Sim, n: u32) {
    for node in s.nodes.values() {
        node.store.data_waits.set(n);
    }
}

fn data_calls(s: &Sim) -> u32 {
    s.nodes.values().map(|n| n.store.data_calls.get()).sum()
}

/// Cold data blocks (device reads in flight): sub-reads, sub-write stashes and the primary's own shard wait for them
/// (held in order, nothing applied) instead of reading with the core blocked; bytes on every shard stay exact.
fn cold_data_run(pdw: &str, waits: u32, seed: u64) {
    let (k, m, chunk) = (2, 1, 4096);
    let mut s = opt_cluster_pdw(seed, &[0, 1, 2], k, m, chunk, pdw);
    let be = backend(k, m, chunk);
    let st = be.s as usize;
    let mut model = BTreeMap::new();
    step(
        &mut s,
        &be,
        &mut model,
        "a",
        vec![EcOp::Touch, EcOp::Write(0, payload(1, 6 * st))],
    );
    let c0 = data_calls(&s);
    cold_data(&s, waits);
    // sequential overwrites on both data shards (own shard and remote)
    for (i, off) in [0u64, 4096, 8192 + 100, 12288, 20000]
        .into_iter()
        .enumerate()
    {
        step(
            &mut s,
            &be,
            &mut model,
            "a",
            vec![EcOp::Write(off, payload(10 + i, 300))],
        );
    }
    // pipelined overwrites of one object behind waiting probes: order kept
    let lead = s.lead_spg(POOL, 0);
    let mut tids = Vec::new();
    let mut m2 = model.get("a").cloned();
    for i in 0..4usize {
        let ops = vec![EcOp::Write(4096 * i as u64 + 7, payload(30 + i, 200))];
        model_apply(&mut m2, &ops);
        tids.push(
            s.write_ops(POOL, 0, "a", &ops, m2.as_ref().map(|v| v.len() as u64))
                .expect("accepted"),
        );
    }
    s.wait_writes(&tids, lead);
    s.run_for(300 * MS);
    model.insert("a".into(), m2.unwrap());
    assert_o_shards(&s, &be, &model);
    let a = model["a"].clone();
    assert_eq!(read_ec(&mut s, "a", 0, a.len() as u64).unwrap(), a);
    assert!(data_calls(&s) > c0, "the stores were probed for data");
    assert!(s.classic_violations().is_empty());
    let left: u32 = s.nodes.values().map(|n| n.store.data_waits.get()).sum();
    assert_eq!(left, 0, "every injected cold answer was consumed");
}

#[test]
fn ec_opt_cold_data_blocks_wait_instead_of_blocking_the_core() {
    for (i, pdw) in ["off", "always"].into_iter().enumerate() {
        cold_data_run(pdw, 4, 70 + i as u64);
    }
}

/// Data blocks whose device reads never complete hold the write: no apply, no ack, however long (a time bound is no
/// durability signal); once the reads complete it finishes with exact bytes on every shard.
#[test]
fn ec_opt_data_that_never_loads_holds_the_write_until_it_does() {
    let (k, m, chunk) = (2, 1, 4096);
    let mut s = opt_cluster_pdw(75, &[0, 1, 2], k, m, chunk, "off");
    let be = backend(k, m, chunk);
    let st = be.s as usize;
    let mut model = BTreeMap::new();
    step(
        &mut s,
        &be,
        &mut model,
        "a",
        vec![EcOp::Touch, EcOp::Write(0, payload(1, 6 * st))],
    );
    let before = model.clone();
    cold_data(&s, u32::MAX);
    let lead = s.lead_spg(POOL, 0);
    let ops = vec![EcOp::Write(4096 + 7, payload(9, 300))];
    let mut m2 = model.get("a").cloned();
    model_apply(&mut m2, &ops);
    let t = s
        .write_ops(POOL, 0, "a", &ops, m2.as_ref().map(|v| v.len() as u64))
        .expect("accepted");
    s.run_for(2 * peering::REPOP_HELD_COMPLAINT_NS);
    assert!(
        !s.is_acked(lead, t),
        "no ack while the data blocks stay cold"
    );
    assert_o_shards(&s, &be, &before);
    let leases = |s: &Sim| -> usize {
        s.nodes
            .values()
            .map(|n| n.store.leases.borrow().len())
            .sum()
    };
    assert!(leases(&s) > 0, "the waits hold residency leases");
    cold_data(&s, 0);
    s.wait_writes(&[t], lead);
    s.run_for(300 * MS);
    assert_eq!(
        leases(&s),
        0,
        "released once the waiting ops consumed their data"
    );
    model.insert("a".into(), m2.unwrap());
    assert_o_shards(&s, &be, &model);
    let a = model["a"].clone();
    assert_eq!(read_ec(&mut s, "a", 0, a.len() as u64).unwrap(), a);
    assert!(s.classic_violations().is_empty());
}

/// A refused primary keeps reporting its state (INCOMPLETE, never the old active+clean), and switching the role on
/// again leaves the frozen state at once (new interval via pg_temp) without any other event.
#[test]
fn ec_primary_refused_reports_state_and_switch_on_unfreezes() {
    let (k, m, chunk) = (2, 2, 4096);
    let mut s = opt_cluster(66, &[0, 1, 2, 3], k, m, chunk);
    let lead = s.lead_spg(POOL, 0);
    let prim = s.primary_of(lead.pgid);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(POOL));
    let switch = |s: &mut Sim, on: bool| {
        s.call(prim, |set, _, _| {
            set.set_ec_opt_primary(on);
            set.push_cfg_to_pgs();
            vec![]
        })
    };
    switch(&mut s, false);
    s.run_until(30_000 * MS, "refused", |s| {
        s.pg(prim, lead).is_some_and(|p| p.refusal().is_some())
    });
    // the last report of the refused primary is not active
    s.run_for(15_000 * MS);
    let (_, st) = s
        .pgstats
        .get(&lead)
        .expect("stats of the refused PG")
        .clone();
    assert_eq!(st.state & pgwire::state::ACTIVE, 0, "state {:#x}", st.state);
    assert_ne!(
        st.state & pgwire::state::INCOMPLETE,
        0,
        "state {:#x}",
        st.state
    );
    switch(&mut s, true);
    s.run_until(60_000 * MS, "leads again, clean", |s| {
        s.pg(prim, lead).is_some_and(|p| p.refusal().is_none()) && s.pool_clean(POOL)
    });
}

/// OQ 37 (adr 0067 am. 5), lab workload: all-croit-flashstore-osd k2m1 under partial overwrites (most skip the nonprimary shard 1)
/// while a random OSD is killed and restarted every few hundred ms, ops in flight. Every PG must end active+clean
/// (liveness guard; the exact lab trigger is pinned by ec_opt_shard `np_ahead_by_stale_pwlc_rewinds_and_activates`).
/// Needs the Sim mon's primary-first pg_temp order (an elected nonprimary shard hands the lead to a primary-capable one).
#[test]
fn ec_opt_primary_quick_kill_restart_cycles_always_reactivate() {
    let (k, m, chunk) = (2, 1, 4096);
    let osds = [0, 1, 2, 3];
    let objs = 6usize;
    let size = 2 * (k * chunk) as u64;
    for seed in 0..48u64 {
        let mut s = opt_cluster(3700 + seed, &osds, k, m, chunk);
        let mut rng = Rng::new(seed);
        for i in 0..objs {
            let tid = s
                .write_ops(
                    POOL,
                    0,
                    &format!("q{i}"),
                    &[EcOp::Touch, EcOp::Write(0, payload(i, size as usize))],
                    Some(size),
                )
                .expect("accepted");
            let l = s.lead_spg(POOL, 0);
            s.wait_writes(&[tid], l);
        }
        for round in 0..12 {
            for _ in 0..rng.range(1, 6) {
                let o = rng.range(0, objs as u64 - 1);
                // chunk 0 only (skips shard 1) or chunk 1 (writes shard 1) of either stripe
                let stripe = rng.range(0, 1) * (k * chunk) as u64;
                let off = stripe
                    + if rng.range(0, 3) == 0 {
                        chunk as u64
                    } else {
                        0
                    }
                    + rng.range(0, 3000);
                let _ = s.write_ops(
                    POOL,
                    0,
                    &format!("q{o}"),
                    &[EcOp::Write(off, payload(round, 64))],
                    Some(size),
                );
                s.run_for(rng.range(0, 30) * MS);
            }
            let v = osds[rng.range(0, osds.len() as u64 - 1) as usize];
            s.kill(v);
            s.run_for(rng.range(0, 400) * MS);
            s.restart(v);
            s.run_for(rng.range(50, 600) * MS);
        }
        s.run_until(
            120_000 * MS,
            &format!("seed {seed}: clean after kill/restart cycles"),
            |s| s.pool_clean(POOL),
        );
    }
}

/// [`live`] across interval changes: a write failed by a new interval (EAGAIN) is sent again, like a client does.
fn live_retry(s: &mut Sim, model: &mut BTreeMap<String, Vec<u8>>, name: &str, ops: Vec<EcOp>) {
    let mut mm = model.get(name).cloned();
    model_apply(&mut mm, &ops);
    for _ in 0..80 {
        let Ok(t) = s.write_ops(POOL, 0, name, &ops, mm.as_ref().map(|v| v.len() as u64)) else {
            s.run_for(25 * MS);
            continue;
        };
        let lead = s.lead_spg(POOL, 0);
        let v = s
            .submitted
            .iter()
            .rev()
            .find(|x| x.0 == lead && x.1 == t)
            .unwrap()
            .2;
        let done = move |l: &[(denc::types::SpgT, u64, denc::types::Eversion)]| {
            l.iter().any(|x| x.0 == lead && x.1 == t && x.2 == v)
        };
        s.run_until(30_000 * MS, "write acked or failed", move |s| {
            done(&s.acked) || done(&s.failed)
        });
        if done(&s.acked) {
            match mm {
                Some(v) => model.insert(name.to_string(), v),
                None => model.remove(name),
            };
            return;
        }
    }
    panic!("write {name} never acked");
}

/// adr 0113 am. 3 review: the position of the PRIMARY's own shard moves to a new OSD (pg_temp keeps the primary acting,
/// the new OSD is a backfill target with the SAME shard id). Writes during the backfill to objects it already holds
/// must reach it with the full shard transaction (not the primary's local-only form): after the backfill every shard of
/// the new up set equals the O encoding of the model, reads return the model.
#[test]
fn ec_opt_primary_backfill_target_of_the_primary_shard_gets_writes() {
    let (k, m, chunk) = (2, 1, 4096);
    for seed in 0..2u64 {
        let mut s = Sim::new(9700 + seed);
        for o in 0..4 {
            s.add_osd_cfg(o, |c| {
                c.ec_enable = ec::EcEnable::All;
                c.ec_enable_optimized = ec::EcEnable::All;
                c.ec_primary = true;
                c.ec_opt_primary = true;
                // trimmed logs: the moved position is backfilled, not log-recovered
                c.min_pg_log_entries = 4;
                c.pg_log_trim_min = 1;
                c.pg_log_trim_max = 30;
            });
        }
        s.run_for(50 * MS);
        s.create_pool_ec_opt(POOL, k, m, chunk, true, 1);
        s.run_for(2000 * MS);
        s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
        let be = backend(k, m, chunk);
        let pg = denc::types::PgT::new(POOL, 0);
        let mut model = BTreeMap::new();
        let objs = 16usize;
        for i in 0..objs {
            live(
                &mut s,
                &mut model,
                &format!("b{i}"),
                vec![EcOp::Touch, EcOp::Write(0, payload(60 + i, 9000 + i * 977))],
            );
        }
        s.run_for(500 * MS);
        let before = s.acting_of(pg);
        let c = (0..4).find(|o| !before.contains(o)).unwrap();
        let up = vec![c, before[1], before[2]];
        let ctx = format!("seed {seed}: {before:?} -> {up:?}");
        s.set_up_override(pg, up.clone());
        let mut during = 0;
        for r in 0..400 {
            if s.pool_clean(POOL) && s.acting_of(pg) == up {
                break;
            }
            if s.acting_of(pg)[0] != c && during < 6 * objs {
                // overwrite shard 0 data (chunk 0 of stripe 0) of every object, backfilled or not
                let i = r % objs;
                live_retry(
                    &mut s,
                    &mut model,
                    &format!("b{i}"),
                    vec![EcOp::Write(100, payload(200 + r, 3000))],
                );
                during += 1;
            }
            s.run_for(5 * MS);
        }
        assert!(during > 0, "no backfill phase ({ctx})");
        s.run_until(120_000 * MS, "clean on the new up set", |s| {
            s.pool_clean(POOL) && s.acting_of(pg) == up
        });
        assert_o_shards(&s, &be, &model);
        for (name, data) in model.clone() {
            assert!(
                read_ec(&mut s, &name, 0, data.len() as u64).unwrap() == data,
                "{name} ({ctx})"
            );
        }
    }
}

/// Mode O partial writes (most skip the nonprimary shard 1), a few ms apart (idle roll-forward deferral `defer` ns: most
/// roll-forwards ride on the next write), while a random OSD is killed mid-write and restarted every 5th write. A
/// write is resent until acked (same op: idempotent). Err = a write never acked (PG stuck). Ok = every shard of the
/// acting set equals the O encoding of the model and reads return it.
fn rf_kill_run(seed: u64, defer: u64) -> Result<(), String> {
    let (k, m, chunk) = (2, 1, 4096);
    let osds = [0, 1, 2, 3];
    let objs = 4usize;
    let size = 2 * (k * chunk) as u64;
    let mut s = opt_cluster_with(4100 + seed, &osds, (k, m, chunk), |c| {
        c.ec_rf_defer_ns = defer
    });
    let be = backend(k, m, chunk);
    let mut rng = Rng::new(seed);
    let mut model = BTreeMap::new();
    for i in 0..objs {
        live(
            &mut s,
            &mut model,
            &format!("r{i}"),
            vec![EcOp::Touch, EcOp::Write(0, payload(i, size as usize))],
        );
    }
    for round in 0..40usize {
        let name = format!("r{}", rng.range(0, objs as u64 - 1));
        let stripe = rng.range(0, 1) * (k * chunk) as u64;
        let off = stripe
            + if rng.range(0, 3) == 0 {
                chunk as u64
            } else {
                0
            }
            + rng.range(0, 3000);
        let ops = vec![EcOp::Write(
            off,
            payload(300 + round, 64 + rng.range(0, 900) as usize),
        )];
        let mut mm = model.get(&name).cloned();
        model_apply(&mut mm, &ops);
        let mut kill = (round % 5 == 4).then(|| osds[rng.range(0, osds.len() as u64 - 1) as usize]);
        let mut acked = false;
        for _ in 0..100 {
            let Ok(t) = s.write_ops(POOL, 0, &name, &ops, mm.as_ref().map(|v| v.len() as u64))
            else {
                s.run_for(25 * MS);
                continue;
            };
            let lead = s.lead_spg(POOL, 0);
            let v = s
                .submitted
                .iter()
                .rev()
                .find(|x| x.0 == lead && x.1 == t)
                .unwrap()
                .2;
            let done = |l: &[(denc::types::SpgT, u64, denc::types::Eversion)]| {
                l.iter().any(|x| x.0 == lead && x.1 == t && x.2 == v)
            };
            if let Some(victim) = kill.take() {
                s.run_for(rng.range(0, 3) * MS);
                s.kill(victim);
                s.run_for(rng.range(0, 300) * MS);
                s.restart(victim);
            }
            for _ in 0..400 {
                if done(&s.acked) || done(&s.failed) {
                    break;
                }
                s.run_for(10 * MS);
            }
            if done(&s.acked) {
                acked = true;
                break;
            }
        }
        if !acked {
            return Err(format!(
                "seed {seed} defer {defer} round {round}: write never acked\n{}",
                s.dump()
            ));
        }
        model.insert(name, mm.unwrap());
        s.run_for(rng.range(1, 6) * MS);
    }
    s.run_until(120_000 * MS, &format!("seed {seed}: clean"), |s| {
        s.pool_clean(POOL)
    });
    s.run_for(500 * MS);
    assert_o_shards(&s, &be, &model);
    for (name, data) in model.clone() {
        assert!(
            read_ec(&mut s, &name, 0, data.len() as u64).unwrap() == data,
            "seed {seed} defer {defer}: {name}"
        );
    }
    Ok(())
}

/// adr 0160 am. 3 + adr 0113 am. 3 review: deferred (20 ms) and classic (0) idle roll-forward under mode O partial
/// writes and kill -9 / restart of random OSDs mid-write: byte-exact shards and reads after recovery.
#[test]
fn ec_opt_primary_deferred_rollforward_kill_restart_bytes_match() {
    for seed in 0..24u64 {
        for defer in [20 * MS, 0] {
            if let Err(e) = rf_kill_run(seed, defer) {
                panic!("{e}");
            }
        }
    }
}

/// (seed, defer) of [`rf_kill_run`] that stuck in Activating before adr 0067 am. 6 (both deferral bounds hit it): a
/// restarted nonprimary shard 1 (sparse log, head below the primary's pwlc-raised view of it) got an MOSDPGLog starting
/// after that view while the primary's activation roll-forward had already restarted the sent pwlc entry at (v, v) ->
/// "merge_log: no overlap", the replica stayed Stray, the primary waited forever.
const NP_PWLC_SEEDS: [(u64, u64); 4] = [(7, 0), (8, 0), (10, 20 * MS), (11, 20 * MS)];

/// Reproducer of the stuck activation above (adr 0067 am. 6: the primary rolls forward after building the peer
/// activation messages).
#[test]
fn ec_opt_primary_restarted_np_shard_activates_after_partial_writes() {
    for (seed, defer) in NP_PWLC_SEEDS {
        if let Err(e) = rf_kill_run(seed, defer) {
            panic!("{}", e.lines().take(12).collect::<Vec<_>>().join("\n"));
        }
    }
}

/// A data position j moves back to an OSD `x` that still holds an OLD copy of the PG (it was down while the position
/// lived on `c` and the logs were trimmed): `x` is a backfill target at shard j, `c` stays acting at shard j (pg_temp),
/// `nobackfill` holds the cursor at the start. Both members carry shard id j; reads of shard j must go to `c` (the
/// member that holds the object), never to `x` (stale bytes beyond its cursor, served silently by any shard). The
/// interesting case is `x < c` (member order by OSD id).
#[test]
fn ec_opt_primary_reads_skip_a_stale_backfill_target_of_the_same_shard() {
    let (k, m, chunk) = (2, 1, 4096);
    for seed in 0..3u64 {
        let mut s = Sim::new(9800 + seed);
        for o in 0..5 {
            s.add_osd_cfg(o, |c| {
                c.ec_enable = ec::EcEnable::All;
                c.ec_enable_optimized = ec::EcEnable::All;
                c.ec_primary = true;
                c.ec_opt_primary = true;
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
        // data shard 1 (read by every client read) on x; a spare c > x takes it over meanwhile
        let before = vec![3, 1, 2];
        let (x, c) = (1, 4);
        s.set_up_override(pg, before.clone());
        s.run_until(60_000 * MS, "clean on the start set", |s| {
            s.pool_clean(POOL) && s.acting_of(pg) == before
        });
        let ctx = format!("seed {seed}: acting {before:?}, x {x}, c {c}");
        let mut model = BTreeMap::new();
        let objs = 6usize;
        for i in 0..objs {
            live(
                &mut s,
                &mut model,
                &format!("s{i}"),
                vec![EcOp::Touch, EcOp::Write(0, payload(10 + i, 3 * 8192))],
            );
        }
        s.run_for(300 * MS);
        s.kill(x);
        let mut moved = before.clone();
        moved[1] = c;
        s.set_up_override(pg, moved.clone());
        s.run_until(120_000 * MS, "clean with c", |s| {
            s.pool_clean(POOL) && s.acting_of(pg) == moved
        });
        // new content everywhere (full overwrite, same size) + enough writes to trim the logs past x's head
        for r in 0..3 {
            for i in 0..objs {
                live_retry(
                    &mut s,
                    &mut model,
                    &format!("s{i}"),
                    vec![EcOp::Write(0, payload(100 + r * 10 + i, 3 * 8192))],
                );
            }
        }
        s.run_for(500 * MS);
        s.new_epoch(|m| m.rb.nobackfill = true);
        s.restart(x);
        s.set_up_override(pg, before.clone());
        s.run_until(60_000 * MS, "active with x as backfill target", |s| {
            let lead = s.lead_spg(POOL, 0);
            let p = s.primary_of(pg);
            s.acting_of(pg)[1] == c
                && s.pg(p, lead)
                    .is_some_and(|p| p.state_bits() & pgwire::state::ACTIVE != 0)
        });
        s.run_for(300 * MS);
        for (name, data) in model.clone() {
            let got = read_ec(&mut s, &name, 0, data.len() as u64);
            assert!(
                got.as_ref().is_ok_and(|g| *g == data),
                "{name}: wrong bytes ({ctx}): {:?}",
                got.map(|g| g.iter().zip(&data).position(|(a, b)| a != b))
            );
        }
    }
}

/// Mode O RMW (RmwO page reads) while every peer shard is held for 30 s: the read waits, the write is never failed
/// (OQ 28 O14: the old 10 s sub-read timeout left no read plan -> write EIO); after the heal it is acked, shards match.
#[test]
fn ec_opt_primary_rmw_write_waits_for_held_shards() {
    let (k, m, chunk) = (2, 1, 4096);
    let mut s = opt_cluster(83, &[0, 1, 2], k, m, chunk);
    let be = backend(k, m, chunk);
    let mut model = BTreeMap::new();
    step(
        &mut s,
        &be,
        &mut model,
        "w",
        vec![EcOp::Touch, EcOp::Write(0, payload(5, 3 * 4096))],
    );
    let lead = s.lead_spg(POOL, 0);
    let prim = s.primary_of(lead.pgid);
    for o in s.acting_of(lead.pgid) {
        if o != prim {
            s.partition(prim, o);
        }
    }
    let ops = vec![EcOp::Write(4096 + 100, payload(6, 300))];
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
    assert_o_shards(&s, &be, &model);
}

/// OSDs other than `asked` the primary sent a sub-read of `h` to since the capture started.
fn others_asked(s: &Sim, h: &denc::types::Hobject, asked: i32) -> Vec<i32> {
    let prim = s.primary_of(denc::types::PgT::new(POOL, 0));
    s.captured
        .iter()
        .filter_map(|(f, t, b)| match b {
            peering::Body::Ec(ecwire::EcMsg::Read(r))
                if *f == prim && *t != asked && r.op.to_read.contains_key(h) =>
            {
                Some(*t)
            }
            _ => None,
        })
        .collect()
}

/// A crafted reply of the shard `asked` (acting position `pos`) for the sub-read of `name` `[0, len)` the primary sent
/// while `asked` is partitioned away; `bad` builds its extents from the asked shard offset and the bytes the shard
/// really holds there. The read result afterwards (the partition still in place) and the other OSDs the read asked
/// (none = the reply was taken; else the shard failed and the read decoded around it).
fn read_with_reply(
    s: &mut Sim,
    name: &str,
    len: u64,
    (pos, asked): (usize, i32),
    bad: impl Fn(u64, &[u8]) -> Vec<(u64, Vec<u8>)>,
) -> (Result<Vec<u8>, i32>, Vec<i32>) {
    let lead = s.lead_spg(POOL, 0);
    let prim = s.primary_of(lead.pgid);
    let h = hobj(POOL, name);
    s.partition(prim, asked);
    s.captured.clear();
    s.capture = true;
    s.call(prim, |set, now, store| {
        let (r, acts) = set
            .with_pg(now, lead, store, |pg| {
                pg.ec_wait(&h, 0, len, store).is_none()
            })
            .expect("pg");
        assert!(!r, "{name}: the read goes to the shards");
        acts
    });
    let (tid, off, n) = s
        .captured
        .iter()
        .find_map(|(f, t, b)| match b {
            peering::Body::Ec(ecwire::EcMsg::Read(r)) if *f == prim && *t == asked => {
                let (o, l, _) = r.op.to_read[&h][0];
                Some((r.op.tid, o, l))
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("{name}: sub-read to shard {pos} on osd.{asked}"));
    assert_eq!(
        others_asked(s, &h, asked),
        Vec::<i32>::new(),
        "{name}: direct read"
    );
    let held = &s.nodes[&asked].store.objects(s.spg_on(asked, POOL, 0))[&h].data;
    let end = held.len().min((off + n) as usize);
    let mut op = ecwire::ECSubReadReply {
        from: denc::types::PgShard {
            osd: asked,
            shard: denc::types::ShardId(pos as i8),
        },
        tid,
        ..Default::default()
    };
    op.buffers_read.insert(
        h.clone(),
        bad(off, &held[off as usize..end])
            .into_iter()
            .map(|(o, d)| (o, bytes::Bytes::from(d)))
            .collect(),
    );
    let reply = ecwire::MOSDECSubOpReadReply {
        pgid: lead,
        map_epoch: s.epoch(),
        op,
        min_epoch: s.epoch(),
        trace: [0; 3],
    };
    s.inject(asked, prim, peering::Body::Ec(ecwire::EcMsg::from(reply)));
    s.run_for(50 * MS);
    let r = read_ec(s, name, 0, len);
    let others = others_asked(s, &h, asked);
    s.capture = false;
    s.heal();
    s.run_for(50 * MS);
    (r, others)
}

/// Review 2026-11-03 #8: a mode O sub-read reply is exactly one extent at the asked shard offset, at most the asked
/// length, and shorter only where a shard file can end (a 4 KiB boundary, ec-optimized.md 2.3). Two extents, none, a
/// torn (unaligned short), misplaced or long one fail the shard: the read decodes around it and never zero pads the
/// rest into the client data (an RMW would re-encode parity from those zeros). A genuinely sparse shard (its file
/// ends before the asked range) is taken as it is and zero padded.
#[test]
fn ec_opt_primary_malformed_sub_read_reply_fails_the_shard() {
    let (k, m, chunk) = (2, 2, 4096);
    let mut s = opt_cluster(97, &[0, 1, 2, 3], k, m, chunk);
    let be = backend(k, m, chunk);
    let mut model = BTreeMap::new();
    let lead = s.lead_spg(POOL, 0);
    let prim = s.primary_of(lead.pgid);
    // the nonprimary data shard (raw 1, identity mapping) on a peer: every full read asks it
    let np = (1, s.acting_of(lead.pgid)[1]);
    assert_ne!(np.1, prim);
    let len = 3 * 8192;
    type Bad = fn(u64, &[u8]) -> Vec<(u64, Vec<u8>)>;
    let cases: [(&str, Bad); 5] = [
        ("two extents", |o, d| {
            vec![(o, d[..4096].to_vec()), (o + 4096, d[4096..].to_vec())]
        }),
        ("no extent", |_, _| vec![]),
        ("torn short extent", |o, d| vec![(o, d[..5000].to_vec())]),
        ("misplaced extent", |o, d| {
            vec![(o + 4096, d[4096..].to_vec())]
        }),
        ("long extent", |o, d| {
            let mut v = d.to_vec();
            v.extend([0xee; 4096]);
            vec![(o, v)]
        }),
    ];
    let mut wrong = Vec::new();
    for (i, (what, bad)) in cases.into_iter().enumerate() {
        let name = format!("m{i}");
        step(
            &mut s,
            &be,
            &mut model,
            &name,
            vec![EcOp::Touch, EcOp::Write(0, payload(20 + i, len as usize))],
        );
        let want = &model[&name];
        match read_with_reply(&mut s, &name, len, np, bad) {
            (Ok(g), others) if g == *want && !others.is_empty() => {}
            (Ok(g), others) => wrong.push(format!(
                "{what}: wrong bytes from {:?}, decoded from {others:?}",
                g.iter().zip(want).position(|(a, b)| a != b)
            )),
            (Err(e), _) => wrong.push(format!("{what}: error {e}")),
        }
    }
    assert!(
        wrong.is_empty(),
        "malformed replies must fail the shard (decoded around): {wrong:?}"
    );
    // genuinely sparse: one stripe + 100 bytes leaves raw 1 one page while the read asks it for two; its short reply
    // (what it holds, ending on a page) is taken and zero padded, no decode
    let name = "sparse";
    step(
        &mut s,
        &be,
        &mut model,
        name,
        vec![EcOp::Touch, EcOp::Write(0, payload(40, 8192 + 100))],
    );
    let held = s.nodes[&np.1].store.objects(s.spg_on(np.1, POOL, 0))[&hobj(POOL, name)]
        .data
        .len();
    assert_eq!(held, 4096, "raw 1 holds one page");
    assert_eq!(
        read_with_reply(&mut s, name, 8192 + 100, np, |o, d| vec![(o, d.to_vec())]),
        (Ok(model[name].clone()), vec![]),
        "sparse shard reply taken as it is"
    );
    // the same shape served by the shard itself
    step(
        &mut s,
        &be,
        &mut model,
        "sparse2",
        vec![EcOp::Touch, EcOp::Write(0, payload(41, 8192 + 100))],
    );
    s.captured.clear();
    s.capture = true;
    assert_eq!(
        read_ec(&mut s, "sparse2", 0, 8192 + 100),
        Ok(model["sparse2"].clone())
    );
    let h = hobj(POOL, "sparse2");
    assert_eq!(others_asked(&s, &h, np.1), Vec::<i32>::new(), "no decode");
    s.capture = false;
}
