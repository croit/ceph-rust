// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! EC acting set with a REMOTE OSD at two positions (`[a,b,b]`, pg_temp/upmap; adr 0049 am. 3): write and push waits,
//! reservations and backfill bookkeeping are per pg_shard. The client ack waits for BOTH shards on b; two backfill
//! targets on one OSD complete independently.
mod common;
use common::*;
use ecback::Backend;
use std::collections::BTreeMap;

const POOL: u64 = 1;

fn payload(i: usize, len: usize) -> Vec<u8> {
    (0..len).map(|j| ((i * 131 + j * 7) % 251) as u8).collect()
}

fn ec_sim(seed: u64, n: i32, short_log: bool) -> Sim {
    let mut s = Sim::new(seed);
    for o in 0..n {
        s.add_osd_cfg(o, |c| {
            c.ec_enable = ec::EcEnable::All;
            c.ec_primary = true;
            // Immediate roll-forward isolates per-shard replication/backfill bookkeeping from deferred dummy rounds.
            c.ec_rf_defer_ns = 0;
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

fn write(s: &mut Sim, model: &mut BTreeMap<String, Vec<u8>>, name: &str, d: Vec<u8>) {
    let ops = [EcOp::Touch, EcOp::Write(0, d.clone())];
    let mut tries = 0;
    let t = loop {
        match s.write_ops(POOL, 0, name, &ops, Some(d.len() as u64)) {
            Ok(t) => break t,
            Err(_) if tries < 2400 => {
                tries += 1;
                s.run_for(25 * MS);
            }
            Err(e) => panic!("write {name}: {e:?}\n{}", s.dump()),
        }
    };
    let lead = s.lead_spg(POOL, 0);
    s.wait_writes(&[t], lead);
    model.insert(name.to_string(), d);
}

/// Each instance of `up` holds the encoding of every object.
fn verify(s: &Sim, be: &Backend, model: &BTreeMap<String, Vec<u8>>, up: &[i32], ctx: &str) {
    for (name, data) in model {
        let mut padded = data.clone();
        padded.resize(data.len().div_ceil(be.s as usize) * be.s as usize, 0);
        let want = be.encode_stripes(&padded);
        for (sh, osd) in up.iter().enumerate() {
            let spg = shard_spg(sh);
            let objs = s.nodes[osd].store.objects(spg);
            let o = objs
                .get(&hobj(POOL, name))
                .unwrap_or_else(|| panic!("{name}: shard {sh} on osd.{osd} lacks it ({ctx})"));
            assert!(
                o.data == want[sh],
                "{name}: shard {sh} on osd.{osd} differs ({ctx})"
            );
        }
    }
}

fn shard_spg(sh: usize) -> denc::types::SpgT {
    denc::types::SpgT {
        pgid: denc::types::PgT::new(POOL, 0),
        shard: denc::types::ShardId(sh as i8),
    }
}

/// `[a,b,b]`: one of b's two sub-writes is lost. The write must NOT be acked on b's other shard's commit alone
/// (before: waits keyed by OSD, the first reply of b completed the wait one shard early).
#[test]
fn ec_ack_waits_for_both_shards_on_one_remote_osd() {
    for seed in 0..4u64 {
        let (k, m, chunk) = (2, 1, 4096);
        let be = backend(k, m, chunk);
        let mut s = ec_sim(9500 + seed, 4, false);
        s.create_pool_ec(POOL, k, m, chunk, false, 1);
        s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
        let pg = denc::types::PgT::new(POOL, 0);
        let mut model = BTreeMap::new();
        write(&mut s, &mut model, "a1", payload(1, 9000));
        let before = s.acting_of(pg);
        let (a, b) = (before[0], before[1]);
        let up = vec![a, b, b];
        let ctx = format!("seed {seed}: {before:?} -> {up:?}");
        s.set_up_override(pg, up.clone());
        s.run_until(120_000 * MS, "clean with remote osd twice", |s| {
            s.pool_clean(POOL) && s.acting_of(pg) == up
        });
        verify(&s, &be, &model, &up, &ctx);
        for (i, len) in [3usize, 4096, 70_000].into_iter().enumerate() {
            write(&mut s, &mut model, &format!("w{len}"), payload(30 + i, len));
        }
        verify(&s, &be, &model, &up, &ctx);
        // lose the next sub-write to b: one of its two shards never sees "x"
        s.drop_next.push((a, b, ecwire::ty::EC_WRITE));
        let d = payload(77, 12_345);
        let lead = s.lead_spg(POOL, 0);
        let t = s
            .write_ops(
                POOL,
                0,
                "x",
                &[EcOp::Touch, EcOp::Write(0, d.clone())],
                Some(d.len() as u64),
            )
            .expect("accepted");
        s.run_for(500 * MS);
        let h = hobj(POOL, "x");
        let on = |sh: usize| s.nodes[&b].store.objects(shard_spg(sh)).contains_key(&h);
        let (on1, on2) = (on(1), on(2));
        assert!(on1 != on2, "exactly one shard on osd.{b} got x ({ctx})");
        assert!(
            !s.is_acked(lead, t),
            "client ack before shard {} on osd.{b} committed ({ctx})",
            if on1 { 2 } else { 1 }
        );
        // b crashes and comes back: peering settles the write (acked only if both its shards hold it), the PG is
        // clean again and every shard agrees
        s.kill(b);
        s.run_for(200 * MS);
        s.restart(b);
        s.run_until(120_000 * MS, "clean after restart", |s| {
            s.pool_clean(POOL) && s.acting_of(pg) == up
        });
        if s.is_acked(lead, t) {
            model.insert("x".into(), d);
        }
        write(&mut s, &mut model, "after", payload(78, 5000));
        verify(&s, &be, &model, &up, &ctx);
    }
}

/// Two backfill targets on one remote OSD (`[a,c,c]` from `[a,b,x]`, trimmed logs): reservation, scan, pushes and
/// FINISH of both positions complete, writes during the backfill land on both.
#[test]
fn ec_two_backfill_targets_on_one_remote_osd() {
    for seed in 0..2u64 {
        let (k, m, chunk) = (2, 1, 4096);
        let be = backend(k, m, chunk);
        let mut s = ec_sim(9600 + seed, 4, true);
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
        let a = before[0];
        let c = (0..4).find(|o| !before.contains(o)).unwrap();
        let up = vec![a, c, c];
        let ctx = format!("seed {seed}: {before:?} -> {up:?}");
        s.set_up_override(pg, up.clone());
        // Stop at the actual state transition, before delivering its scan/push messages. Sampling every
        // 25 ms can skip the entire backfill and accidentally test only the remap's admission window.
        s.run_until(120_000 * MS, "two remote shards backfilling", |s| {
            s.pg(a, shard_spg(0)).is_some_and(|p| {
                p.machine_state()
                    == peering::St::Primary(peering::PSt::Active(peering::ASt::Backfilling))
            })
        });
        write(&mut s, &mut model, "during-backfill", payload(90, 5000));
        s.run_until(
            120_000 * MS,
            "clean with two backfilled shards on one osd",
            |s| s.pool_clean(POOL) && s.acting_of(pg) == up,
        );
        verify(&s, &be, &model, &up, &ctx);
    }
}
