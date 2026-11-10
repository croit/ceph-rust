// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Two shards of one EC PG on one OSD (adr 0049 am. 1): after a remap the primary's OSD also holds the old instance of
//! another position (a stray) or two positions of the acting set. The other local instance is a peer like any other
//! (classic skips only the exact own pg_shard): it is probed, queried, read from and written to through local loopback
//! delivery, never through the cluster messenger (the sim asserts that no PG message is addressed to its own OSD).
mod common;
use common::*;
use ecback::Backend;
use std::collections::BTreeMap;

const POOL: u64 = 1;

fn payload(i: usize, len: usize) -> Vec<u8> {
    (0..len).map(|j| ((i * 131 + j * 7) % 251) as u8).collect()
}

fn ec_sim(seed: u64, n: i32) -> Sim {
    ec_sim_x(seed, n, false)
}

/// `short_log`: logs trimmed to a few entries (a moved position is backfilled, not log-recovered).
fn ec_sim_x(seed: u64, n: i32, short_log: bool) -> Sim {
    let mut s = Sim::new(seed);
    for o in 0..n {
        s.add_osd_cfg(o, |c| {
            c.ec_enable = ec::EcEnable::All;
            c.ec_primary = true;
            if short_log {
                c.min_pg_log_entries = 4;
                c.pg_log_trim_min = 1;
                c.pg_log_trim_max = 30;
            }
        });
    }
    s.run_for(50 * MS);
    s
}

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

fn write(s: &mut Sim, model: &mut BTreeMap<String, Vec<u8>>, name: &str, d: Vec<u8>) {
    write_x(s, model, name, d, vec![]);
}

/// [`write`] plus extra ops (a snapset attr: scrub wants one on every head).
fn write_x(
    s: &mut Sim,
    model: &mut BTreeMap<String, Vec<u8>>,
    name: &str,
    d: Vec<u8>,
    extra: Vec<EcOp>,
) {
    let mut ops = vec![EcOp::Touch, EcOp::Write(0, d.clone())];
    ops.extend(extra);
    let mut tries = 0;
    let t = loop {
        match s.write_ops(POOL, 0, name, &ops, Some(d.len() as u64)) {
            Ok(t) => break t,
            Err(e) if tries < 2400 => {
                tries += 1;
                let _ = e;
                s.run_for(25 * MS);
            }
            Err(e) => panic!("write {name}: {e:?}\n{}", s.dump()),
        }
    };
    let lead = s.lead_spg(POOL, 0);
    s.wait_writes(&[t], lead);
    model.insert(name.to_string(), d);
}

/// Every object of `model`: each instance of the CURRENT up set holds the encoding of the data, the read decodes it.
fn verify(s: &mut Sim, be: &Backend, model: &BTreeMap<String, Vec<u8>>, up: &[i32], ctx: &str) {
    for (name, data) in model {
        let mut padded = data.clone();
        padded.resize(data.len().div_ceil(be.s as usize) * be.s as usize, 0);
        let want = be.encode_stripes(&padded);
        for (sh, osd) in up.iter().enumerate() {
            let spg = denc::types::SpgT {
                pgid: denc::types::PgT::new(POOL, 0),
                shard: denc::types::ShardId(sh as i8),
            };
            let objs = s.nodes[osd].store.objects(spg);
            let o = objs
                .get(&hobj(POOL, name))
                .unwrap_or_else(|| panic!("{name}: shard {sh} on osd.{osd} lacks it ({ctx})"));
            assert!(
                o.data == want[sh],
                "{name}: shard {sh} on osd.{osd} differs ({ctx})"
            );
        }
        assert!(
            read_ec(s, name, data.len() as u64).unwrap() == *data,
            "{name} ({ctx})"
        );
    }
}

fn backend(k: u32, m: u32, chunk: u32) -> Backend {
    Backend::from_parts(
        "isa",
        "reed_sol_van",
        (k, m),
        (k * chunk, chunk),
        (0..k + m).collect(),
        false,
    )
    .unwrap()
}

fn unfound_panic(s: &mut Sim, ctx: &str) {
    let pg = denc::types::PgT::new(POOL, 0);
    let p = s.primary_of(pg);
    let lead = s.lead_spg(POOL, 0);
    if s.pg(p, lead)
        .is_some_and(|x| x.state_bits() & pgwire::state::RECOVERY_UNFOUND != 0)
    {
        let notes = s.nodes.get_mut(&p).unwrap().set.take_notices();
        panic!("recovery_unfound ({ctx}): osd.{p} {notes:#?}");
    }
}

/// Lab case (doc/compat/ceph-21.1.2.md): k2m1, the shard-0 holder dies, the PG runs degraded and takes writes; then the
/// remap puts the old shard-2 holder at position 0 (it becomes primary) and a fresh OSD at position 2. Every object
/// written while degraded exists only on the shard-1 member and on the primary's OWN stray shard-2 instance: k = 2 needs
/// both. The primary must probe and read its local stray, not go recovery_unfound.
#[test]
fn ec_primary_recovers_from_local_stray_shard() {
    for seed in 0..4u64 {
        let (k, m, chunk) = (2, 1, 4096);
        let be = backend(k, m, chunk);
        let mut s = ec_sim(9100 + seed, 5);
        s.create_pool_ec(POOL, k, m, chunk, false, 1);
        s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
        let pg = denc::types::PgT::new(POOL, 0);
        let mut model = BTreeMap::new();
        for (i, len) in [1usize, 4096, 8191, 100_003].into_iter().enumerate() {
            write(&mut s, &mut model, &format!("a{len}"), payload(i, len));
        }
        let before = s.acting_of(pg);
        let (a, b, c) = (before[0], before[1], before[2]);
        let d = (0..5).find(|o| !before.contains(o)).unwrap();
        let ctx = format!("seed {seed}: {before:?} -> [{c}, {b}, {d}] with osd.{a} down");
        s.kill(a);
        s.set_up_override(pg, vec![pgwire::NONE_OSD, b, c]);
        s.run_until(60_000 * MS, "degraded active", |s| {
            let lead = s.lead_spg(POOL, 0);
            s.pg(s.primary_of(pg), lead)
                .is_some_and(|p| p.state_bits() & pgwire::state::ACTIVE != 0)
        });
        for (i, len) in [5usize, 4096, 65536].into_iter().enumerate() {
            write(&mut s, &mut model, &format!("b{len}"), payload(10 + i, len));
        }
        let up = vec![c, b, d];
        s.set_up_override(pg, up.clone());
        let stray = denc::types::SpgT {
            pgid: pg,
            shard: denc::types::ShardId(2),
        };
        for _ in 0..200 {
            s.run_for(25 * MS);
            unfound_panic(&mut s, &ctx);
            // the old shard-2 instance on the primary's OSD is a stray (a recovery source), never an acting member:
            // activating it must not mark it started in this interval
            let lead = s.lead_spg(POOL, 0);
            let since = s.pg(c, lead).map(|p| p.info().history.same_interval_since);
            if let (Some(since), Some(st)) = (since, s.pg(c, stray)) {
                assert!(
                    st.info().last_epoch_started < since,
                    "stray (osd.{c}, 2) marked started at {} in interval {since} ({ctx})",
                    st.info().last_epoch_started
                );
            }
        }
        // writes while the PG recovers onto the new members (possibly with osd.c at two positions via pg_temp)
        write(&mut s, &mut model, "c1", payload(20, 12_345));
        s.run_until(120_000 * MS, "clean after the remap", |s| {
            s.pool_clean(POOL) && s.acting_of(pg) == up
        });
        unfound_panic(&mut s, &ctx);
        verify(&mut s, &be, &model, &up, &ctx);
    }
}

/// The acting set names one OSD at two positions (pg_temp / upmap; CRUSH never does it): the primary writes its second
/// local shard through loopback (data must land, acks only after both local instances committed), recovery and reads
/// work, and when the double mapping ends the moved position is backfilled from it.
#[test]
fn ec_acting_with_one_osd_twice_writes_both_local_shards() {
    for seed in 0..4u64 {
        let (k, m, chunk) = (2, 1, 4096);
        let be = backend(k, m, chunk);
        let mut s = ec_sim(9200 + seed, 4);
        s.create_pool_ec(POOL, k, m, chunk, false, 1);
        s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
        let pg = denc::types::PgT::new(POOL, 0);
        let mut model = BTreeMap::new();
        write(&mut s, &mut model, "a1", payload(1, 9000));
        let before = s.acting_of(pg);
        let (a, b) = (before[0], before[1]);
        // position 2 moves onto the primary's OSD: backfilled locally from (a,0) + (b,1)
        let up = vec![a, b, a];
        let ctx = format!("seed {seed}: {before:?} -> {up:?}");
        s.set_up_override(pg, up.clone());
        s.run_until(120_000 * MS, "clean with one osd twice", |s| {
            s.pool_clean(POOL) && s.acting_of(pg) == up
        });
        verify(&mut s, &be, &model, &up, &ctx);
        for (i, len) in [3usize, 4096, 70_000].into_iter().enumerate() {
            write(&mut s, &mut model, &format!("w{len}"), payload(30 + i, len));
        }
        verify(&mut s, &be, &model, &up, &ctx);
        // undo: position 2 goes to a fresh OSD, the local instance at 2 becomes a stray and a source
        let d = (0..4).find(|o| !before.contains(o)).unwrap();
        let up2 = vec![a, b, d];
        s.set_up_override(pg, up2.clone());
        s.run_until(120_000 * MS, "clean after undo", |s| {
            s.pool_clean(POOL) && s.acting_of(pg) == up2
        });
        verify(&mut s, &be, &model, &up2, &ctx);
    }
}

/// Scrub of a PG whose acting set holds the primary's OSD twice: shallow and deep scrub include the second local shard
/// (request and map through local delivery), find a missing object and a flipped byte there, and repair rebuilds it.
#[test]
fn ec_scrub_covers_the_second_local_shard() {
    for seed in 0..2u64 {
        let (k, m, chunk) = (2, 1, 4096);
        let be = backend(k, m, chunk);
        let mut s = ec_sim(9300 + seed, 4);
        s.create_pool_ec(POOL, k, m, chunk, false, 1);
        s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
        let pg = denc::types::PgT::new(POOL, 0);
        let before = s.acting_of(pg);
        let (a, b) = (before[0], before[1]);
        let up = vec![a, b, a];
        let ctx = format!("seed {seed}: {before:?} -> {up:?}");
        s.set_up_override(pg, up.clone());
        s.run_until(120_000 * MS, "clean with one osd twice", |s| {
            s.pool_clean(POOL) && s.acting_of(pg) == up
        });
        let mut model = BTreeMap::new();
        for (i, len) in [3usize, 4096, 9000, 70_000].into_iter().enumerate() {
            let ss = denc::to_vec(&replwire::SnapSet::default()).unwrap();
            write_x(
                &mut s,
                &mut model,
                &format!("o{i}"),
                payload(40 + i, len),
                vec![EcOp::Attr("snapset", ss)],
            );
        }
        s.run_for(300 * MS);
        let lead = s.lead_spg(POOL, 0);
        assert_eq!(lead.shard.0, 0, "{ctx}");
        let second = denc::types::SpgT {
            pgid: pg,
            shard: denc::types::ShardId(2),
        };
        let scrub = |s: &mut Sim, deep: bool, repair: bool| -> i64 {
            let before = s.pg(a, lead).unwrap().scrub_counts().0;
            s.call(a, |set, now, st| {
                set.request_scrub(now, lead, deep, repair, st)
            });
            s.run_until(60_000 * MS, "scrub finished", move |s| {
                let p = s.pg(a, lead).unwrap();
                p.scrub_counts().0 > before && !p.scrub_running()
            });
            s.run_until(60_000 * MS, "clean after scrub", |s| s.pool_clean(POOL));
            s.run_for(300 * MS);
            s.pg(a, lead)
                .unwrap()
                .info()
                .stats
                .stats
                .sum
                .num_scrub_errors
        };
        let e0 = scrub(&mut s, true, false);
        assert_eq!(
            e0,
            0,
            "clean pg reports errors ({ctx}) {:#?}",
            s.pg(a, lead).unwrap().scrub_inconsistent()
        );
        // the second local instance must have served a map for every chunk
        let served = |s: &Sim| s.pg(a, second).unwrap().scrub_chunks_served();
        let n0 = served(&s);
        assert!(n0 > 0, "second local shard never scrubbed ({ctx})");
        // shallow: an object missing on the second local shard
        let gone = s
            .nodes
            .get_mut(&a)
            .unwrap()
            .store
            .pgs
            .get_mut(&second)
            .unwrap()
            .objects
            .remove(&hobj(POOL, "o1"));
        assert!(gone.is_some(), "{ctx}");
        assert!(
            scrub(&mut s, false, false) > 0,
            "missing object on the second local shard not found ({ctx})"
        );
        let r = &s.pg(a, lead).unwrap().scrub_inconsistent()[0];
        assert_eq!(r.bad_shards(), vec![2], "{ctx}");
        scrub(&mut s, false, true);
        s.run_until(60_000 * MS, "repaired", |s| s.pool_clean(POOL));
        verify(&mut s, &be, &model, &up, &ctx);
        assert_eq!(
            scrub(&mut s, true, false),
            0,
            "errors after shallow repair ({ctx})"
        );
        // deep: a flipped byte in the second local shard
        s.nodes
            .get_mut(&a)
            .unwrap()
            .store
            .pgs
            .get_mut(&second)
            .unwrap()
            .objects
            .get_mut(&hobj(POOL, "o3"))
            .unwrap()
            .data[100] ^= 0xFF;
        assert!(
            scrub(&mut s, true, false) > 0,
            "flipped byte on the second local shard not found ({ctx})"
        );
        scrub(&mut s, true, true);
        s.run_until(60_000 * MS, "repaired", |s| s.pool_clean(POOL));
        verify(&mut s, &be, &model, &up, &ctx);
        assert_eq!(
            scrub(&mut s, true, false),
            0,
            "errors after deep repair ({ctx})"
        );
        assert!(served(&s) > n0, "{ctx}");
    }
}

/// Trimmed logs: the position moving onto the primary's OSD is BACKFILLED from the other members while pg_temp keeps
/// the old holder acting. The local target shares an OSD with an acting member but is not one (classic `actingset`
/// holds pg_shards); writes during the backfill reach it through local delivery and it ends complete.
#[test]
fn ec_local_backfill_target_with_writes() {
    for seed in 0..2u64 {
        let (k, m, chunk) = (2, 1, 4096);
        let be = backend(k, m, chunk);
        let mut s = ec_sim_x(9400 + seed, 4, true);
        s.create_pool_ec(POOL, k, m, chunk, false, 1);
        s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
        let pg = denc::types::PgT::new(POOL, 0);
        let mut model = BTreeMap::new();
        for i in 0..24 {
            write(
                &mut s,
                &mut model,
                &format!("b{i}"),
                payload(60 + i, 100 + i * 977),
            );
        }
        s.run_for(500 * MS);
        let before = s.acting_of(pg);
        let (a, b) = (before[0], before[1]);
        let up = vec![a, b, a];
        let ctx = format!("seed {seed}: {before:?} -> {up:?}");
        s.set_up_override(pg, up.clone());
        let mut during = 0;
        for i in 0..400 {
            if s.pool_clean(POOL) && s.acting_of(pg) == up {
                break;
            }
            if s.acting_of(pg).get(2) != Some(&a) && during < 6 {
                write_retry(
                    &mut s,
                    &mut model,
                    &format!("w{i}"),
                    payload(90 + i, 5000 + i),
                );
                during += 1;
            }
            s.run_for(25 * MS);
        }
        assert!(during > 0, "no backfill phase ({ctx})");
        s.run_until(120_000 * MS, "clean with one osd twice", |s| {
            s.pool_clean(POOL) && s.acting_of(pg) == up
        });
        verify(&mut s, &be, &model, &up, &ctx);
    }
}

/// [`write`] across interval changes: a write the PG fails (EAGAIN: new interval) is sent again, like a client does.
/// A failed attempt may still have been rolled forward by the new interval (a real client's resend is answered from the
/// reqid dup index; this sim client has none): the append-only pool then refuses the resend (EOPNOTSUPP: object exists)
/// and the earlier attempt counts as written. `verify` checks the content.
fn write_retry(s: &mut Sim, model: &mut BTreeMap<String, Vec<u8>>, name: &str, d: Vec<u8>) {
    let mut failed_once = false;
    for _ in 0..50 {
        let t = match s.write_ops(
            POOL,
            0,
            name,
            &[EcOp::Touch, EcOp::Write(0, d.clone())],
            Some(d.len() as u64),
        ) {
            Ok(t) => t,
            Err(peering::WriteErr::TooBig(95)) if failed_once => {
                model.insert(name.to_string(), d);
                return;
            }
            Err(_) => {
                s.run_for(25 * MS);
                continue;
            }
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
            model.insert(name.to_string(), d);
            return;
        }
        failed_once = true;
    }
    panic!("write {name} never acked");
}

/// Mode O direct reads of a second local data shard survive multiple renewal intervals.
#[test]
fn optimized_local_data_shard_keeps_its_read_lease() {
    use denc::types::{PgT, ShardId, SpgT};
    use peering::ecdirect::DirectExtent;
    let mut s = Sim::new(9301);
    for o in 0..4 {
        s.add_osd_cfg(o, |c| {
            c.ec_enable = ec::EcEnable::All;
            c.ec_enable_optimized = ec::EcEnable::All;
            c.ec_primary = true;
            c.ec_opt_primary = true;
        });
    }
    s.run_for(50 * MS);
    s.create_pool_ec_opt(POOL, 2, 1, 4096, true, 1);
    s.run_until(60_000 * MS, "optimized EC clean", |s| s.pool_clean(POOL));
    let pgid = PgT::new(POOL, 0);
    let before = s.acting_of(pgid);
    let (a, b) = (before[0], before[2]);
    // Local position 1 is a data shard, not parity, so direct reads return its actual chunks.
    let up = vec![a, a, b];
    s.set_up_override(pgid, up.clone());
    s.run_until(120_000 * MS, "optimized local mapping clean", |s| {
        s.pool_clean(POOL) && s.acting_of(pgid) == up
    });
    let data = payload(44, 8192);
    let mut model = BTreeMap::new();
    write(&mut s, &mut model, "lease", data.clone());
    let local = SpgT {
        pgid,
        shard: ShardId(1),
    };
    let h = hobj(POOL, "lease");
    for _ in 0..3 {
        s.run_for(20_000 * MS); // default readable_interval = 16s
        let r = s
            .pg(a, local)
            .unwrap()
            .ec_direct_read(
                s.now,
                &h,
                &[DirectExtent {
                    offset: 4096,
                    length: 4096,
                    truncate_seq: 0,
                    truncate_size: 0,
                    sparse: false,
                }],
                false,
                &s.nodes[&a].store,
            )
            .expect("local data shard must receive renewals");
        assert_eq!(r.data, vec![data[4096..].to_vec()]);
    }
}
