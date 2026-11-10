// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Recovery sources outside the acting set (spec doc/spec/missing-loc.md): one remap moves TWO positions of a PG to fresh
//! OSDs at once; the old holders stay up as strays and are the only copies of what the new members miss. The primary must
//! read from them (EC: per-shard sub-reads from the stray instance; replicated: pulls) instead of going recovery_unfound.
mod common;
use common::*;
use ecback::Backend;
use std::collections::BTreeMap;

const POOL: u64 = 1;

fn payload(i: usize, len: usize) -> Vec<u8> {
    (0..len).map(|j| ((i * 131 + j * 7) % 251) as u8).collect()
}

fn ec_sim(seed: u64, n: i32, prof: Option<(BTreeMap<String, String>, u32)>) -> Sim {
    let mut s = Sim::new(seed);
    s.ec_profile = prof;
    for o in 0..n {
        s.add_osd_cfg(o, |c| {
            c.ec_enable = ec::EcEnable::All;
            c.ec_primary = true;
        });
    }
    s.run_for(50 * MS);
    s
}

/// Client read through the op-layer interface (`ec_wait` until ready, then the cache).
fn read_ec(s: &mut Sim, name: &str, len: u64) -> Result<Vec<u8>, i32> {
    let lead = s.lead_spg(POOL, 0);
    let osd = s.primary_of(lead.pgid);
    let h = hobj(POOL, name);
    for _ in 0..4000 {
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

/// Remap positions `moved` of PG 0 to the unused OSDs, keep the rest; returns (old acting, new up).
fn remap_two(s: &mut Sim, nosd: i32, moved: [usize; 2]) -> (Vec<i32>, Vec<i32>) {
    let pg = denc::types::PgT::new(POOL, 0);
    let before = s.acting_of(pg);
    let mut spare = (0..nosd).filter(|o| !before.contains(o));
    let mut up = before.clone();
    for i in moved {
        up[i] = spare.next().expect("spare osd");
    }
    s.set_up_override(pg, up.clone());
    (before, up)
}

fn ec_case(
    seed: u64,
    nosd: i32,
    k: u32,
    m: u32,
    chunk: u32,
    prof: Option<(BTreeMap<String, String>, u32)>,
    moved: [usize; 2],
) {
    let be = match &prof {
        Some((p, _)) => {
            let n = p["k"].parse::<u32>().unwrap() + p["m"].parse::<u32>().unwrap();
            let n = n + p.get("l").map_or(0, |l| n / l.parse::<u32>().unwrap());
            Backend::from_profile(p, (k * chunk, chunk), (0..n).collect(), false).unwrap()
        }
        None => Backend::from_parts(
            "isa",
            "reed_sol_van",
            (k, m),
            (k * chunk, chunk),
            (0..k + m).collect(),
            false,
        )
        .unwrap(),
    };
    let mut s = ec_sim(seed, nosd, prof);
    s.create_pool_ec(POOL, k, m, chunk, false, 1);
    s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
    let lead = s.lead_spg(POOL, 0);
    let mut model = BTreeMap::new();
    for (i, len) in [1usize, 100, 4096, 8191, 65536, 100_003]
        .into_iter()
        .enumerate()
    {
        let d = payload(i, len);
        let name = format!("o{len}");
        let t = s
            .write_ops(
                POOL,
                0,
                &name,
                &[EcOp::Touch, EcOp::Write(0, d.clone())],
                Some(d.len() as u64),
            )
            .unwrap();
        s.wait_writes(&[t], lead);
        model.insert(name, d);
    }
    let pg = denc::types::PgT::new(POOL, 0);
    let (before, up) = remap_two(&mut s, nosd, moved);
    let ctx = format!("moved {moved:?}: {before:?} -> {up:?}");
    // reads while the PG peers / recovers: an answer must be the data (an error = not readable yet)
    let mut early = 0;
    for _ in 0..40 {
        s.run_for(25 * MS);
        if s.acting_of(pg) != up
            || s.pg(s.primary_of(pg), s.lead_spg(POOL, 0))
                .is_none_or(|p| !p.is_primary())
        {
            continue;
        }
        let st = s
            .pg(s.primary_of(pg), s.lead_spg(POOL, 0))
            .unwrap()
            .state_bits();
        // the strays are probed at activation: recovery never reports unfound on the way
        if st & pgwire::state::RECOVERY_UNFOUND != 0 {
            let p = s.primary_of(pg);
            let notes = s.nodes.get_mut(&p).unwrap().set.take_notices();
            panic!("unfound during the move ({ctx}): osd.{p} {notes:#?}");
        }
        for (name, data) in &model {
            if let Ok(d) = read_ec(&mut s, name, data.len() as u64) {
                assert_eq!(d, *data, "{name} read during the move ({ctx})");
                early += 1;
            }
        }
    }
    s.run_until(60_000 * MS, "clean after a 2-position remap", |s| {
        s.pool_clean(POOL) && s.acting_of(pg) == up
    });
    let lead = s.lead_spg(POOL, 0);
    let p = s.primary_of(pg);
    assert_eq!(
        s.pg(p, lead).unwrap().state_bits() & pgwire::state::RECOVERY_UNFOUND,
        0
    );
    // a shard rebuilt here is read to rebuild the peers' shards only once its local apply committed (spec
    // replication.md 6.6): no rebuild fails on a local shard that is not in the store yet
    for osd in &up {
        let e = &s
            .pg(*osd, s.spg_on(*osd, POOL, 0))
            .unwrap()
            .counters()
            .errors;
        assert!(
            !e.contains_key("ec recovery failed"),
            "osd.{osd} ({ctx}): {e:?}"
        );
    }
    // every shard on the new members equals the encoding of the model; the reads decode
    for (name, data) in &model {
        let mut padded = data.clone();
        padded.resize(data.len().div_ceil(be.s as usize) * be.s as usize, 0);
        let want = be.encode_stripes(&padded);
        for (sh, osd) in up.iter().enumerate() {
            let objs = s.nodes[osd].store.objects(s.spg_on(*osd, POOL, 0));
            let o = objs
                .get(&hobj(POOL, name))
                .unwrap_or_else(|| panic!("{name}: shard {sh} on osd.{osd} lacks it ({ctx})"));
            assert!(
                o.data == want[sh],
                "{name}: shard {sh} on osd.{osd} differs ({ctx})"
            );
        }
        assert!(
            read_ec(&mut s, name, data.len() as u64).unwrap() == *data,
            "{name} ({ctx})"
        );
    }
    eprintln!("{ctx}: {early} reads during the move");
}

fn pairs(n: usize) -> Vec<[usize; 2]> {
    (0..n)
        .flat_map(|a| (a + 1..n).map(move |b| [a, b]))
        .collect()
}

/// RS k=2 m=1: after the remap at most one current shard stays in the acting set (k-1); the others live on strays. Every
/// pair of positions, the primary's included.
#[test]
fn ec_two_position_remap_recovers_from_strays() {
    for (i, mv) in pairs(3).into_iter().enumerate() {
        ec_case(301 + i as u64, 5, 2, 1, 4096, None, mv);
    }
}

/// lrc k=2 m=1 l=3 (4 chunks): the lab case of open question 33, every pair of positions.
#[test]
fn ec_lrc_two_position_remap_recovers_from_strays() {
    let prof: BTreeMap<String, String> = [("plugin", "lrc"), ("k", "2"), ("m", "1"), ("l", "3")]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
    // pool size 4 = k + m + (k+m)/l: the sim derives size from k + m
    for (i, mv) in pairs(4).into_iter().enumerate() {
        ec_case(320 + i as u64, 6, 2, 2, 4096, Some((prof.clone(), 1)), mv);
    }
}

/// Replicated size 3: the primary and one replica move to fresh OSDs at once; the third member and the strays hold the
/// data. Objects written while the PG had only its old members are pulled from wherever they are.
#[test]
fn replicated_two_position_remap_recovers_from_strays() {
    let mut s = cluster(303, &[0, 1, 2, 3, 4], POOL, 3, 2, 1);
    let lead = s.lead_spg(POOL, 0);
    let mut model = BTreeMap::new();
    for i in 0..6 {
        let name = format!("r{i}");
        let t = s
            .write_obj(POOL, 0, &name, &payload(i, 50 + i * 100))
            .unwrap();
        s.wait_writes(&[t], lead);
        model.insert(name, payload(i, 50 + i * 100));
    }
    let (_, up) = remap_two(&mut s, 5, [0, 1]);
    s.run_until(60_000 * MS, "clean after a 2-position remap", |s| {
        s.pool_clean(POOL) && s.acting_of(denc::types::PgT::new(POOL, 0)) == up
    });
    s.assert_replicas_equal(POOL, 0, &model);
}

/// The case-21 shape (mixed gate, 2026-11-01): a remap makes two fresh OSDs the primary and a replica; the primary pulls
/// every object and pushes it on to the fresh replica, with the production budget (`osd_recovery_max_active_ssd` 10, every
/// pull in flight at once). A pulled object is pushed only once its local apply is in the store: no object is taken for
/// a lost local copy, none is repaired (pulled twice), the copies end equal.
#[test]
fn replicated_fresh_primary_and_replica_recover_without_repairs() {
    let mut s = cluster_cfg(304, &[0, 1, 2, 3, 4], POOL, 3, 2, 1, |c| {
        c.recovery_max_active = 10;
    });
    let lead = s.lead_spg(POOL, 0);
    let mut model = BTreeMap::new();
    for i in 0..8 {
        let name = format!("f{i}");
        let t = s
            .write_obj(POOL, 0, &name, &payload(i, 50 + i * 100))
            .unwrap();
        s.wait_writes(&[t], lead);
        model.insert(name, payload(i, 50 + i * 100));
    }
    let (_, up) = remap_two(&mut s, 5, [0, 1]);
    s.run_until(60_000 * MS, "clean after a 2-position remap", |s| {
        s.pool_clean(POOL) && s.acting_of(denc::types::PgT::new(POOL, 0)) == up
    });
    for osd in &up {
        let pg = s.pg(*osd, s.spg_on(*osd, POOL, 0)).unwrap();
        assert!(
            pg.counters().errors.is_empty(),
            "osd.{osd}: {:?}",
            pg.counters().errors
        );
        assert_eq!(pg.shards_repaired(), 0, "osd.{osd}");
    }
    s.assert_replicas_equal(POOL, 0, &model);
}

/// A stray source whose replies are held is waited for (no timer); once a map shows it down (same interval: it is not
/// in up/acting) its sub-reads and attribute reads are given up and served from the other sources (spec missing-loc.md
/// 5). RS k=2 m=1, positions 1 and 2 moved: only shard 0 stays current in the acting set, shards 1 and 2 live on the
/// strays A and B; A's replies are held.
#[test]
fn ec_stray_source_down_in_the_interval_is_dropped() {
    let (k, m, chunk) = (2, 1, 32);
    let mut s = ec_sim(330, 5, None);
    s.create_pool_ec(POOL, k, m, chunk, false, 1);
    s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
    let lead = s.lead_spg(POOL, 0);
    let mut model = BTreeMap::new();
    for i in 0..4usize {
        let d = payload(i, 100 + i * 300);
        let name = format!("s{i}");
        let t = s
            .write_ops(
                POOL,
                0,
                &name,
                &[EcOp::Touch, EcOp::Write(0, d.clone())],
                Some(d.len() as u64),
            )
            .unwrap();
        s.wait_writes(&[t], lead);
        model.insert(name, d);
    }
    let pg = denc::types::PgT::new(POOL, 0);
    let (before, up) = remap_two(&mut s, 5, [1, 2]);
    let prim = before[0];
    let a = before[1];
    // hold A's replies from the moment the new interval is active (its info reached the primary already)
    s.run_until(10_000 * MS, "remapped pg active", |s| {
        s.acting_of(pg) == up
            && s.pg(prim, s.lead_spg(POOL, 0))
                .is_some_and(|p| p.is_primary() && p.is_active() && p.acting() == up.as_slice())
    });
    s.blocked.insert((a, prim));
    s.run_for(20_000 * MS);
    let has = |s: &Sim| {
        let objs = s.nodes[&up[1]].store.objects(s.spg_on(up[1], POOL, 0));
        model
            .keys()
            .filter(|n| objs.contains_key(&hobj(POOL, n)))
            .count()
    };
    assert!(
        has(&s) == 0,
        "shard 1 recovered although stray osd.{a} (its direct source) is up and never answered"
    );
    s.mark_down(a);
    s.run_until(1_000 * MS, "clean from the other sources", |s| {
        s.pool_clean(POOL) && s.acting_of(pg) == up
    });
    for (name, data) in &model {
        assert_eq!(
            read_ec(&mut s, name, data.len() as u64).as_ref(),
            Ok(data),
            "{name}"
        );
    }
    s.blocked.clear();
}

/// Backend level of the lrc case: every read plan over every availability decodes to the data (crates/ec tests/lrc_top_layer.rs).
#[test]
fn lrc_backend_every_read_plan_decodes() {
    let prof: BTreeMap<String, String> = [("plugin", "lrc"), ("k", "2"), ("m", "1"), ("l", "3")]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
    let chunk = 4096u64;
    let be = Backend::from_profile(
        &prof,
        (2 * chunk as u32, chunk as u32),
        (0..4).collect(),
        false,
    )
    .unwrap();
    let ns = 13u64;
    let data = payload(3, (ns * be.s) as usize);
    let sh = be.encode_stripes(&data);
    for mask in 1u32..16 {
        let avail: Vec<u32> = (0..4).filter(|i| mask & (1 << i) != 0).collect();
        for (s0, s1) in [(0, ns), (0, 1), (3, 9)] {
            let Ok(plan) = be.plan_read(s0, s1, &[0, 1], &avail) else {
                continue;
            };
            let (off, len) = plan.shard_range(be.c);
            let got: BTreeMap<u32, Vec<u8>> = plan
                .shards
                .iter()
                .map(|s| {
                    (
                        *s,
                        sh[*s as usize][off as usize..(off + len) as usize].to_vec(),
                    )
                })
                .collect();
            let lo = s0 * be.s;
            let r = be.assemble(&plan, &got, lo, (s1 - s0) * be.s).unwrap();
            assert!(
                r == data[lo as usize..(s1 * be.s) as usize],
                "avail {avail:?} plan {:?} span {s0}..{s1}",
                plan.shards
            );
        }
    }
}
