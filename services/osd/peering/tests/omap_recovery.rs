// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Recovery / backfill of huge-omap objects: bounded chunks with the `omap_recovered_to` cursor, push (we -> peer) and
//! pull (peer -> us), resumable after an interrupted push, no message the classic model rejects.
mod common;
use common::*;
use peering::Body;
use replwire::ReplMsg;

const CHUNK: usize = 100;
const KEYS: usize = 6000;

fn cfg(c: &mut peering::Config) {
    c.recovery_max_omap_entries = CHUNK;
    c.min_pg_log_entries = 10;
    c.pg_log_trim_min = 1;
    c.pg_log_trim_max = 50;
    c.log_dups_tracked = 20;
}

/// `big` with KEYS omap keys, written in batches through the normal replicated write path.
fn write_big(s: &mut Sim) {
    let mut tids = vec![];
    let batch = 1000;
    for b in 0..KEYS / batch {
        let kv: Vec<(Vec<u8>, Vec<u8>)> = (b * batch..(b + 1) * batch)
            .map(|i| (format!("k{i:08}").into_bytes(), vec![(i % 251) as u8; 40]))
            .collect();
        let ops = if b == 0 {
            vec![EcOp::Touch, EcOp::OmapSet(kv)]
        } else {
            vec![EcOp::OmapSet(kv)]
        };
        tids.push(
            s.write_ops(1, 0, "big", &ops, Some(0))
                .expect("write accepted"),
        );
        s.run_for(MS);
    }
    s.wait_writes(&tids, spg(1, 0));
}

fn pushes(s: &Sim) -> Vec<(i32, i32, replwire::PushOp)> {
    s.captured
        .iter()
        .filter_map(|(f, t, b)| match b {
            Body::Repl(ReplMsg::Push(m)) => Some((*f, *t, m.pushes.clone())),
            _ => None,
        })
        .flat_map(|(f, t, ops)| ops.into_iter().map(move |o| (f, t, o)))
        .collect()
}

fn omap_of(s: &Sim, osd: i32) -> std::collections::BTreeMap<Vec<u8>, Vec<u8>> {
    s.nodes[&osd].store.objects(spg(1, 0))[&hobj(1, "big")]
        .omap
        .clone()
}

/// Pushes of `big` sent TO `to` (`from` = the sender when set).
fn check_chunks(s: &Sim, to: i32) {
    let ps: Vec<_> = pushes(s)
        .into_iter()
        .filter(|(_, t, o)| *t == to && o.soid == hobj(1, "big"))
        .collect();
    let with: Vec<_> = ps
        .iter()
        .filter(|(_, _, o)| !o.omap_entries.is_empty())
        .collect();
    assert!(
        with.len() >= KEYS / CHUNK,
        "omap must travel in >= {} chunks, got {}",
        KEYS / CHUNK,
        with.len()
    );
    assert!(
        with.iter().all(|(_, _, o)| o.omap_entries.len() <= CHUNK),
        "every chunk holds <= {CHUNK} entries"
    );
    // cursor semantics: a continuing chunk starts at the previous chunk's omap_recovered_to
    for w in ps.windows(2) {
        let (a, b) = (&w[0].2, &w[1].2);
        if !a.after_progress.omap_complete && !b.before_progress.first {
            assert_eq!(
                b.before_progress.omap_recovered_to,
                a.after_progress.omap_recovered_to
            );
            assert_eq!(
                b.omap_entries.keys().next().map(|k| k.as_slice()),
                Some(a.after_progress.omap_recovered_to.as_slice())
            );
        }
    }
}

/// Recovery counters of the primary's PG stats (spec pg-io-stats.md 2): (objects, bytes, keys).
fn recovered(s: &Sim, primary: i32) -> (i64, i64, i64) {
    let st = &s
        .pg(primary, spg(1, 0))
        .expect("primary pg")
        .info()
        .stats
        .stats
        .sum;
    (
        st.num_objects_recovered,
        st.num_bytes_recovered,
        st.num_keys_recovered,
    )
}

fn converge(s: &mut Sim, acting: &[i32]) {
    s.run_until(120_000 * MS, "pool clean", |s| s.pool_clean(1));
    let want = omap_of(s, acting[0]);
    assert_eq!(want.len(), KEYS);
    for o in acting {
        assert_eq!(omap_of(s, *o), want, "osd.{o} omap identical");
    }
}

/// Log-based recovery push of a huge omap object to a replica that missed it.
#[test]
fn recovery_push_chunked() {
    let mut s = cluster_cfg(81, &[0, 1, 2], 1, 3, 2, 1, cfg);
    s.classic_all();
    let acting = s.acting_of(spg(1, 0).pgid);
    let victim = acting[2];
    s.kill(victim);
    s.run_for(300 * MS);
    write_big(&mut s);
    s.capture = true;
    s.restart(victim);
    converge(&mut s, &acting);
    check_chunks(&s, victim);
    // one object, counted once at completion; every pushed omap entry counts as a key
    assert_eq!(recovered(&s, acting[0]), (1, 0, KEYS as i64));
    assert!(
        s.classic_violations().is_empty(),
        "{:?}",
        s.classic_violations()
    );
}

/// Backfill (log too short) of a huge omap object.
#[test]
fn backfill_push_chunked() {
    let mut s = cluster_cfg(82, &[0, 1, 2], 1, 3, 2, 1, cfg);
    s.classic_all();
    let acting = s.acting_of(spg(1, 0).pgid);
    let victim = acting[2];
    s.kill(victim);
    s.run_for(300 * MS);
    write_big(&mut s);
    for i in 0..60 {
        s.write_obj(1, 0, &format!("f{i}"), b"x").unwrap();
        s.run_for(MS);
    }
    s.run_for(300 * MS);
    s.capture = true;
    s.restart(victim);
    converge(&mut s, &acting);
    check_chunks(&s, victim);
    let (objs, bytes, keys) = recovered(&s, acting[0]);
    assert!(
        objs >= 61 && bytes >= 60 && keys >= KEYS as i64,
        "backfill counted ({objs}, {bytes}, {keys})"
    );
    assert!(
        s.classic_violations().is_empty(),
        "{:?}",
        s.classic_violations()
    );
}

/// The old primary missed the object: it PULLS it in chunks from a replica.
#[test]
fn recovery_pull_chunked() {
    let mut s = cluster_cfg(83, &[0, 1, 2], 1, 3, 2, 1, cfg);
    s.classic_all();
    let acting = s.acting_of(spg(1, 0).pgid);
    let old = acting[0];
    s.kill(old);
    s.run_for(2_000 * MS);
    write_big(&mut s);
    s.capture = true;
    s.restart(old);
    s.run_for(5_000 * MS);
    converge(&mut s, &acting);
    check_chunks(&s, old);
    // the pulling primary counts the object it pulled
    let (objs, _, keys) = recovered(&s, old);
    assert!(
        objs >= 1 && keys >= KEYS as i64,
        "pull counted ({objs}, {keys})"
    );
    assert!(
        s.classic_violations().is_empty(),
        "{:?}",
        s.classic_violations()
    );
}

/// The replica dies in the middle of the chunk stream: the retry after restart starts over cleanly (temp object
/// replaced) and ends identical.
#[test]
fn interrupted_push_resumes() {
    let mut s = cluster_cfg(84, &[0, 1, 2], 1, 3, 2, 1, cfg);
    let acting = s.acting_of(spg(1, 0).pgid);
    let victim = acting[2];
    s.kill(victim);
    s.run_for(300 * MS);
    write_big(&mut s);
    s.capture = true;
    s.restart(victim);
    s.run_until(60_000 * MS, "some chunks", |s| {
        pushes(s)
            .iter()
            .filter(|(_, _, o)| !o.omap_entries.is_empty())
            .count()
            >= 10
    });
    s.kill(victim);
    s.run_for(500 * MS);
    s.restart(victim);
    converge(&mut s, &acting);
}

/// A heavy object gets a backfill batch of its own: while its multi-chunk push is in flight, client writes to every
/// OTHER object (below and above it in hash order) are accepted; only the object itself is held back.
#[test]
fn heavy_object_does_not_block_its_neighbours() {
    let mut s = cluster_cfg(85, &[0, 1, 2], 1, 3, 2, 1, cfg);
    let acting = s.acting_of(spg(1, 0).pgid);
    let victim = acting[2];
    s.kill(victim);
    s.run_for(300 * MS);
    let big = hobj(1, "big");
    // 25 names on each side of `big` in hash order
    let all: Vec<String> = (0..40_000).map(|i| format!("n{i}")).collect();
    let mut names: Vec<String> = all
        .iter()
        .filter(|n| hobj(1, n) < big)
        .take(25)
        .cloned()
        .collect();
    let below = names.len();
    names.extend(all.iter().filter(|n| hobj(1, n) > big).take(25).cloned());
    assert!(below > 3 && names.len() - below > 3, "both sides: {below}");
    for n in &names[..below] {
        s.write_obj(1, 0, n, b"x").unwrap();
        s.run_for(MS);
    }
    write_big(&mut s);
    for n in &names[below..] {
        s.write_obj(1, 0, n, b"x").unwrap();
        s.run_for(MS);
    }
    s.run_for(300 * MS);
    s.capture = true;
    s.restart(victim);
    // wait for the push of `big` to be in flight (started, not complete)
    s.run_until(60_000 * MS, "big in flight", |s| {
        pushes(s)
            .iter()
            .any(|(_, t, o)| *t == victim && o.soid == big && !o.after_progress.is_complete())
    });
    let mut refused = vec![];
    let mut tids = vec![];
    for n in &names {
        match s.write_obj(1, 0, n, b"y") {
            Ok(t) => tids.push(t),
            Err(e) => refused.push((n.clone(), e)),
        }
    }
    assert!(
        refused.is_empty(),
        "neighbours refused during the heavy push: {refused:?}"
    );
    assert!(
        s.write_obj(1, 0, "big", b"y").is_err(),
        "the heavy object itself is held back while it is pushed"
    );
    s.wait_writes(&tids, spg(1, 0));
    s.run_until(120_000 * MS, "pool clean", |s| s.pool_clean(1));
    // the victim converges on the neighbours' new data too
    let want = s.contents(acting[0], 1, 0);
    assert_eq!(s.contents(victim, 1, 0), want);
}

/// A backfill batch is bounded by our own listing (<= 512 objects) even when the target is EMPTY (its digest ends at
/// MAX): the whole PG used to be ONE batch, i.e. one write block over everything behind the cursor.
#[test]
fn backfill_batches_are_bounded_for_an_empty_target() {
    let mut s = cluster_cfg(86, &[0, 1, 2], 1, 3, 2, 1, cfg);
    let acting = s.acting_of(spg(1, 0).pgid);
    let victim = acting[2];
    s.kill(victim);
    s.run_for(300 * MS);
    let mut tids = vec![];
    for i in 0..1300 {
        tids.push(s.write_obj(1, 0, &format!("o{i}"), b"x").unwrap());
        if i % 50 == 0 {
            s.run_for(MS);
        }
    }
    s.wait_writes(&tids, spg(1, 0));
    s.capture = true;
    s.restart(victim);
    s.run_until(120_000 * MS, "pool clean", |s| s.pool_clean(1));
    let progress = s
        .captured
        .iter()
        .filter(|(_, t, b)| {
            *t == victim
                && matches!(b, Body::Repl(ReplMsg::Backfill(m)) if m.op == replwire::MOSDPGBackfill::OP_PROGRESS)
        })
        .count();
    assert!(
        progress >= 3,
        "1300 objects in >= 3 batches, got {progress}"
    );
    assert_eq!(s.contents(victim, 1, 0), s.contents(acting[0], 1, 0));
}

/// The objects before a heavy one that need NO push (in sync on the target) are not held back during its push either:
/// the batch in front of it ends at it even when it is the first object to push (the range block covers in-sync
/// objects too).
#[test]
fn in_sync_neighbours_before_a_heavy_object_are_not_held_back() {
    let mut s = cluster_cfg(87, &[0, 1, 2], 1, 3, 2, 1, cfg);
    let acting = s.acting_of(spg(1, 0).pgid);
    let victim = acting[2];
    let big = hobj(1, "big");
    let all: Vec<String> = (0..40_000).map(|i| format!("n{i}")).collect();
    let below: Vec<String> = all
        .iter()
        .filter(|n| hobj(1, n) < big)
        .take(25)
        .cloned()
        .collect();
    let above: Vec<String> = all
        .iter()
        .filter(|n| hobj(1, n) > big)
        .take(25)
        .cloned()
        .collect();
    assert!(below.len() > 3 && above.len() > 3);
    // `below` is on every replica before the victim goes down: in sync, never pushed
    let mut tids = vec![];
    for n in &below {
        tids.push(s.write_obj(1, 0, n, b"x").unwrap());
        s.run_for(MS);
    }
    s.wait_writes(&tids, spg(1, 0));
    s.run_for(300 * MS);
    s.kill(victim);
    s.run_for(300 * MS);
    write_big(&mut s);
    for r in 0..2 {
        for n in &above {
            s.write_obj(1, 0, n, if r == 0 { b"x" } else { b"z" })
                .unwrap();
            s.run_for(MS);
        }
    }
    s.run_for(300 * MS);
    s.capture = true;
    s.restart(victim);
    s.run_until(60_000 * MS, "big in flight", |s| {
        pushes(s)
            .iter()
            .any(|(_, t, o)| *t == victim && o.soid == big && !o.after_progress.is_complete())
    });
    assert!(
        s.captured
            .iter()
            .any(|(_, t, b)| *t == victim && matches!(b, Body::Repl(ReplMsg::Scan(_)))),
        "backfill (not log recovery) of the victim"
    );
    let mut refused = vec![];
    let mut tids = vec![];
    for n in &below {
        match s.write_obj(1, 0, n, b"y") {
            Ok(t) => tids.push(t),
            Err(e) => refused.push((n.clone(), e)),
        }
    }
    assert!(
        refused.is_empty(),
        "in-sync neighbours refused during the heavy push: {refused:?}"
    );
    assert!(s.write_obj(1, 0, "big", b"y").is_err());
    s.wait_writes(&tids, spg(1, 0));
    s.run_until(120_000 * MS, "pool clean", |s| s.pool_clean(1));
    let want = s.contents(acting[0], 1, 0);
    assert_eq!(s.contents(victim, 1, 0), want);
}
