// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Backfill must never derive a removal from a local read problem (review finding: errors conflated with "absent").
//! Backfill must push or remove every object a write reached log-only while the scan was in flight (review 2026-11-03 #1).
mod common;
use common::*;
use peering::Body;
use replwire::ReplMsg;
use std::collections::BTreeMap;

fn payload(i: usize, len: usize) -> Vec<u8> {
    (0..len).map(|j| ((i * 131 + j * 7) % 251) as u8).collect()
}

fn small_logs(c: &mut peering::Config) {
    c.min_pg_log_entries = 10;
    c.pg_log_trim_min = 1;
    c.pg_log_trim_max = 50;
    c.log_dups_tracked = 20;
}

fn fill(s: &mut Sim, n: usize, tag: &str) -> BTreeMap<String, Vec<u8>> {
    let mut model = BTreeMap::new();
    let mut tids = vec![];
    for i in 0..n {
        let name = format!("{tag}{i}");
        let d = payload(i, 100 + i * 13);
        tids.push(s.write_obj(1, 0, &name, &d).expect("write accepted"));
        model.insert(name, d);
        s.run_for(MS / 2);
    }
    s.wait_writes(&tids, spg(1, 0));
    model
}

/// Names removed by every captured MOSDPGBackfillRemove.
fn removed_names(s: &Sim) -> Vec<String> {
    s.captured
        .iter()
        .filter_map(|(_, _, b)| match b {
            Body::Repl(ReplMsg::BackfillRemove(m)) => Some(m),
            _ => None,
        })
        .flat_map(|m| {
            m.ls.iter()
                .map(|(h, _)| String::from_utf8_lossy(&h.oid).into_owned())
        })
        .collect()
}

/// Primary's object_info of `a3` is damaged while replica osd `victim` (which holds `a3`) is backfilled: the damaged
/// local object must not make the primary delete the replica's copy.
#[test]
fn corrupt_primary_object_never_removes_peer_copy() {
    let mut s = cluster_cfg(71, &[0, 1, 2], 1, 3, 2, 1, small_logs);
    let pg = spg(1, 0);
    let mut model = fill(&mut s, 8, "a");
    let acting = s.acting_of(pg.pgid);
    let (primary, victim) = (acting[0], acting[2]);
    s.kill(victim);
    s.run_for(300 * MS);
    model.extend(fill(&mut s, 40, "b"));
    // damage a3 on the primary (garbage object_info), after everything else settled
    let h = hobj(1, "a3");
    s.nodes
        .get_mut(&primary)
        .unwrap()
        .store
        .pgs
        .get_mut(&pg)
        .unwrap()
        .objects
        .get_mut(&h)
        .unwrap()
        .xattrs
        .insert(b"_".to_vec(), vec![0xff; 3]);
    s.capture = true;
    s.restart(victim);
    s.run_for(30_000 * MS);
    let removed = removed_names(&s);
    assert!(
        !removed.iter().any(|n| n == "a3"),
        "damaged local object a3 must not be removed from the peer: {removed:?}"
    );
    let vobjs = s.nodes[&victim].store.objects(pg);
    assert!(vobjs.contains_key(&h), "replica copy of a3 survived");
    let _ = model;
}

/// An unreadable local store (listing fails) aborts the backfill comparison: no removal, no push, PG not completed
/// (and no panic); the error is counted.
#[test]
fn unreadable_primary_listing_aborts_backfill_without_removals() {
    let mut s = cluster_cfg(72, &[0, 1, 2], 1, 3, 2, 1, small_logs);
    let pg = spg(1, 0);
    fill(&mut s, 8, "a");
    let acting = s.acting_of(pg.pgid);
    let (primary, victim) = (acting[0], acting[2]);
    s.kill(victim);
    s.run_for(300 * MS);
    fill(&mut s, 40, "b");
    s.nodes.get_mut(&primary).unwrap().store.list_error = true;
    s.capture = true;
    s.restart(victim);
    s.run_for(30_000 * MS);
    assert!(
        removed_names(&s).is_empty(),
        "no removal from a failed listing"
    );
    let p = s.pg(primary, pg).unwrap();
    assert!(
        p.counters()
            .errors
            .keys()
            .any(|k| k.contains("listing failed")),
        "error counted: {:?}",
        p.counters().errors
    );
    assert!(
        s.pg(victim, pg).unwrap().info().last_backfill != denc::types::Hobject::MAX(),
        "backfill must not be reported complete"
    );
}

fn bf_release_count(s: &Sim) -> usize {
    s.captured
        .iter()
        .filter(|(_, _, b)| {
            matches!(b, Body::Repl(ReplMsg::BackfillReserve(m)) if m.ty == replwire::MBackfillReserve::RELEASE)
        })
        .count()
}

/// A stalled backfill (local read error) must not hold reservations forever: they are released, the PG shows
/// backfill_unfound, and the backfill is retried (and completes) once the error is gone.
#[test]
fn stalled_backfill_releases_reservations_and_retries() {
    let mut s = cluster_cfg(75, &[0, 1, 2], 1, 3, 2, 1, small_logs);
    let pg = spg(1, 0);
    fill(&mut s, 8, "a");
    let acting = s.acting_of(pg.pgid);
    let (primary, victim) = (acting[0], acting[2]);
    s.kill(victim);
    s.run_for(300 * MS);
    fill(&mut s, 40, "b");
    s.nodes.get_mut(&primary).unwrap().store.list_error = true;
    s.capture = true;
    s.restart(victim);
    s.run_for(5_000 * MS);
    let st = s.pg(primary, pg).unwrap().state_string();
    assert!(st.contains("backfill_unfound"), "{st}");
    assert!(bf_release_count(&s) > 0, "reservations released");
    s.nodes.get_mut(&primary).unwrap().store.list_error = false;
    s.run_until(120_000 * MS, "backfill retried", |s| s.pool_clean(1));
}

/// A replica that cannot list sends no digest: the primary must not wait forever (deadline, release, retry).
#[test]
fn replica_scan_failure_times_out_and_retries() {
    let mut s = cluster_cfg(76, &[0, 1, 2], 1, 3, 2, 1, small_logs);
    let pg = spg(1, 0);
    fill(&mut s, 8, "a");
    let acting = s.acting_of(pg.pgid);
    let (primary, victim) = (acting[0], acting[2]);
    s.kill(victim);
    s.run_for(300 * MS);
    fill(&mut s, 40, "b");
    s.capture = true;
    s.restart(victim);
    s.nodes.get_mut(&victim).unwrap().store.list_error = true;
    s.run_for(60_000 * MS);
    let st = s.pg(primary, pg).unwrap().state_string();
    assert!(
        st.contains("backfill_unfound") || st.contains("backfill_wait"),
        "{st}"
    );
    assert!(
        bf_release_count(&s) > 0,
        "reservations released after the timeout"
    );
    s.nodes.get_mut(&victim).unwrap().store.list_error = false;
    s.run_until(120_000 * MS, "clean after the replica recovered", |s| {
        s.pool_clean(1)
    });
}

/// The first DIGEST `from` sent to `to` (captured; the test dropped it on the wire to hold it back).
fn captured_digest(s: &Sim, from: i32, to: i32) -> replwire::MOSDPGScan {
    s.captured
        .iter()
        .find_map(|(f, t, b)| match b {
            Body::Repl(ReplMsg::Scan(m))
                if (*f, *t) == (from, to) && m.op == replwire::MOSDPGScan::OP_DIGEST =>
            {
                Some(m.clone())
            }
            _ => None,
        })
        .expect("digest captured")
}

/// Review 2026-11-03 #1: the target's digest predates writes of the batch range, which reach the target log-only (the
/// scan is in flight, nothing is behind its cursor). Writes that committed before the primary compares the batch
/// (create, overwrite, delete) and writes still in flight then (overwrite, create, delete; they commit after the
/// comparison) must each be pushed or removed before the batch advances `last_backfill`; otherwise the target ends
/// complete with an absent or stale copy. Both store models: a queued txn visible to reads at once (storeadapt) and
/// visible only at commit.
#[test]
fn backfill_covers_writes_committed_around_the_digest() {
    for (seed, read_after_queue) in [(77u64, false), (78, true)] {
        let mut s = Sim::new(seed);
        s.read_after_queue = read_after_queue;
        for o in 0..3 {
            // one push at a time: the batch is still pushing when the writes in flight at the comparison commit
            s.add_osd_cfg(o, |c| {
                small_logs(c);
                c.recovery_max_active = 1;
            });
        }
        s.run_for(50 * MS);
        s.create_pool(1, 3, 2, 1);
        s.run_until(60_000 * MS, "pool clean", |s| s.pool_clean(1));
        let pg = spg(1, 0);
        let mut model = fill(&mut s, 20, "a");
        let acting = s.acting_of(pg.pgid);
        let (primary, other, victim) = (acting[0], acting[1], acting[2]);
        s.kill(victim);
        s.run_for(300 * MS);
        model.extend(fill(&mut s, 30, "b"));
        // the victim's log is trimmed past: it is backfilled; its first digest is held back (dropped, re-sent below)
        s.capture = true;
        s.drop_next.push((victim, primary, 94));
        s.restart(victim);
        s.run_until(60_000 * MS, "digest held", |s| s.dropped_lost > 0);
        let digest = captured_digest(&s, victim, primary);
        s.capture = false;
        let st = s.pg(primary, pg).unwrap().state_string();
        assert!(st.contains("backfilling"), "{st}");
        // committed before the primary compares the batch
        let mut tids = vec![];
        for (name, d) in [("a5", payload(905, 77)), ("b7", payload(907, 333))] {
            tids.push(s.write_obj(1, 0, name, &d).expect("overwrite accepted"));
            model.insert(name.into(), d);
        }
        for i in 0..6 {
            let (name, d) = (format!("c{i}"), payload(910 + i, 50 + i * 9));
            tids.push(s.write_obj(1, 0, &name, &d).expect("create accepted"));
            model.insert(name, d);
        }
        tids.push(s.delete_obj(1, 0, "a9").expect("delete accepted"));
        model.remove("a9");
        s.wait_writes(&tids, pg);
        // in flight when the primary compares the batch: the primary's own commits and the other replica's replies are
        // held (with visible-at-commit the listing does not show them yet)
        s.pg_commit_hold = Some((primary, pg, s.now + 40 * MS));
        s.blocked.insert((other, primary));
        let mut late = vec![];
        for (name, d) in [("a11", payload(920, 91)), ("d0", payload(921, 64))] {
            late.push(s.write_obj(1, 0, name, &d).expect("write accepted"));
            model.insert(name.into(), d);
        }
        late.push(s.delete_obj(1, 0, "a13").expect("delete accepted"));
        model.remove("a13");
        s.run_for(20 * MS);
        assert!(
            late.iter().all(|t| !s.is_acked(pg, *t)),
            "writes still in flight"
        );
        // the digest is older than all of them (the victim missed every b*): no c*/d0, a9 and a13 still listed
        let theirs: BTreeMap<String, denc::types::Eversion> = digest
            .digest
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|(h, v)| (String::from_utf8_lossy(&h.oid).into_owned(), v))
            .collect();
        assert!(!theirs.contains_key("c0") && !theirs.contains_key("d0"));
        assert!(theirs.contains_key("a9") && theirs.contains_key("a13"));
        s.inject(victim, primary, Body::Repl(ReplMsg::Scan(digest)));
        s.run_for(20 * MS);
        s.heal_link(other, primary);
        s.wait_writes(&late, pg);
        s.run_until(120_000 * MS, "clean after the backfill", |s| {
            s.pool_clean(1)
        });
        s.run_for(500 * MS);
        // the held digest was the one compared (one scan of the whole PG, no retry after a discard or deadline)
        assert_eq!(s.sent.get(&(primary, victim, 94)), Some(&1), "scans sent");
        assert!(s.acting_of(pg.pgid).contains(&victim));
        s.assert_replicas_equal(1, 0, &model);
        s.assert_persisted_consistent();
    }
}

/// Every acting shard holds exactly the model's objects, each the encoding of its data (EC pool 1, pg 0).
fn assert_ec_shards(s: &Sim, be: &ecback::Backend, model: &BTreeMap<String, Vec<u8>>) {
    let pg = denc::types::PgT::new(1, 0);
    let names: Vec<String> = model.keys().cloned().collect();
    for (sh, osd) in s.acting_of(pg).iter().enumerate() {
        let objs = s.nodes[osd].store.objects(s.spg_on(*osd, 1, 0));
        let mut have: Vec<String> = objs
            .keys()
            .map(|h| String::from_utf8_lossy(&h.oid).into_owned())
            .collect();
        have.sort();
        assert_eq!(have, names, "shard {sh} on osd.{osd}: object set");
        for (name, data) in model {
            let mut padded = data.clone();
            padded.resize(data.len().div_ceil(be.s as usize) * be.s as usize, 0);
            let want = &be.encode_stripes(&padded)[sh];
            assert!(
                &objs[&hobj(1, name)].data == want,
                "{name}: shard {sh} on osd.{osd} differs"
            );
        }
    }
}

/// EC sibling of [`backfill_covers_writes_committed_around_the_digest`] (adr 0049 am. 8, `ec_writes_in_flight_in`):
/// the backfilled shard's digest predates creates, overwrites and deletes that commit before the primary compares the
/// batch, and others that are queued (RMW read held) or uncommitted then. Each must reach the target shard.
#[test]
fn ec_backfill_covers_writes_committed_around_the_digest() {
    use peering::Body;
    let (k, m, chunk) = (2u32, 1u32, 32u32);
    let be = ecback::Backend::from_parts(
        "isa",
        "reed_sol_van",
        (k, m),
        (k * chunk, chunk),
        (0..k + m).collect(),
        true,
    )
    .unwrap();
    for (seed, read_after_queue) in [(531u64, false), (532, true)] {
        let mut s = Sim::new(seed);
        s.read_after_queue = read_after_queue;
        for o in 0..3 {
            s.add_osd_cfg(o, |c| {
                c.ec_enable = ec::EcEnable::All;
                c.ec_primary = true;
                small_logs(c);
                c.recovery_max_active = 1;
            });
        }
        s.run_for(50 * MS);
        s.create_pool_ec(1, k, m, chunk, true, 1);
        s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(1));
        let lead = s.lead_spg(1, 0);
        let primary = s.primary_of(lead.pgid);
        let acting = s.acting_of(lead.pgid);
        let victim = *acting.iter().rev().find(|o| **o != primary).unwrap();
        let mut model: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let put = |s: &mut Sim, model: &mut BTreeMap<String, Vec<u8>>, name: &str, d: Vec<u8>| {
            let tid = s
                .write_ops(
                    1,
                    0,
                    name,
                    &[EcOp::Touch, EcOp::Write(0, d.clone())],
                    Some(d.len() as u64),
                )
                .expect("accepted");
            model.insert(name.into(), d);
            tid
        };
        let mut tids = vec![];
        for i in 0..20 {
            tids.push(put(
                &mut s,
                &mut model,
                &format!("a{i}"),
                payload(i, 100 + i * 13),
            ));
            s.run_for(MS / 2);
        }
        s.wait_writes(&tids, s.lead_spg(1, 0));
        s.kill(victim);
        s.run_for(300 * MS);
        let mut tids = vec![];
        for i in 0..30 {
            tids.push(put(
                &mut s,
                &mut model,
                &format!("b{i}"),
                payload(100 + i, 90 + i * 7),
            ));
            s.run_for(MS / 2);
        }
        s.wait_writes(&tids, s.lead_spg(1, 0));
        // the victim's log is trimmed past: its shard is backfilled; its first digest is held back (re-sent below)
        s.capture = true;
        s.drop_next.push((victim, primary, 94));
        s.restart(victim);
        s.run_until(60_000 * MS, "digest held", |s| s.dropped_lost > 0);
        let digest = captured_digest(&s, victim, primary);
        s.capture = false;
        let st = s.pg(primary, lead).unwrap().state_string();
        assert!(st.contains("backfilling"), "{st}");
        // committed before the primary compares the batch (overwrites keep the length: the model is the new data)
        let mut tids = vec![];
        for (name, tag) in [("a5", 905usize), ("b7", 907)] {
            let d = payload(tag, model[name].len());
            tids.push(
                s.write_ops(
                    1,
                    0,
                    name,
                    &[EcOp::Write(0, d.clone())],
                    Some(d.len() as u64),
                )
                .expect("overwrite accepted"),
            );
            model.insert(name.into(), d);
        }
        for i in 0..6 {
            tids.push(put(
                &mut s,
                &mut model,
                &format!("c{i}"),
                payload(910 + i, 50 + i * 9),
            ));
        }
        tids.push(
            s.write_ops(1, 0, "a9", &[EcOp::Remove], None)
                .expect("delete accepted"),
        );
        model.remove("a9");
        s.wait_writes(&tids, lead);
        // sent (log-only to the target) but uncommitted when the primary compares the batch: the primary's own shard
        // commits are held (with visible-at-commit its listing does not show them yet)
        s.pg_commit_hold = Some((primary, lead, s.now + 40 * MS));
        let mut late = vec![];
        {
            // partial overwrite: read-modify-write of the stripe
            let mut d = model["a11"].clone();
            let patch = payload(920, 40);
            d[10..50].copy_from_slice(&patch);
            late.push(
                s.write_ops(1, 0, "a11", &[EcOp::Write(10, patch)], Some(d.len() as u64))
                    .expect("overwrite accepted"),
            );
            model.insert("a11".into(), d);
        }
        late.push(put(&mut s, &mut model, "d0", payload(921, 64)));
        late.push(
            s.write_ops(1, 0, "a13", &[EcOp::Remove], None)
                .expect("delete accepted"),
        );
        model.remove("a13");
        s.run_for(20 * MS);
        assert!(
            late.iter().all(|t| !s.is_acked(lead, *t)),
            "writes still in flight"
        );
        let theirs: Vec<String> = digest
            .digest
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|(h, _)| String::from_utf8_lossy(&h.oid).into_owned())
            .collect();
        assert!(!theirs.iter().any(|n| n == "c0" || n == "d0"), "{theirs:?}");
        assert!(theirs.iter().any(|n| n == "a9") && theirs.iter().any(|n| n == "a13"));
        s.inject(victim, primary, Body::Repl(ReplMsg::Scan(digest)));
        s.wait_writes(&late, lead);
        s.run_until(120_000 * MS, "clean after the backfill", |s| {
            s.pool_clean(1)
        });
        s.run_for(500 * MS);
        assert_eq!(s.sent.get(&(primary, victim, 94)), Some(&1), "scans sent");
        assert!(s.acting_of(lead.pgid).contains(&victim));
        assert_ec_shards(&s, &be, &model);
    }
}
