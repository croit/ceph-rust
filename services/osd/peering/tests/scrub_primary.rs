// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Primary-side scrub (spec scrub.md 6) in the 3-OSD simulation: clean scrub, injected corruption, repair,
//! missing objects, write blocking per chunk, chunking around head/clone groups, scheduling, abort on interval
//! change, mgr command.
#![expect(clippy::field_reassign_with_default)]
mod common;
use common::*;
use denc::types::{Eversion, Hobject, PgShard, ShardId, SnapId, SpgT};
use peering::store::MemObj;
use peering::{Body, WriteErr};
use pgwire::state as pgs;
use replwire::{MOSDRepScrub, MOSDScrub2, ObjectInfo, ReplMsg, SnapSet};

fn cfg(c: &mut peering::Config) {
    c.scrub.chunk_min = 2;
    c.scrub.chunk_max = 3;
    c.scrub.shallow_chunk_min = 2;
    c.scrub.shallow_chunk_max = 3;
}

fn put_snapset(s: &mut Sim, osd: i32, pg: SpgT, h: &Hobject, ss: &SnapSet) {
    let o = s
        .nodes
        .get_mut(&osd)
        .unwrap()
        .store
        .pgs
        .get_mut(&pg)
        .unwrap()
        .objects
        .get_mut(h)
        .unwrap();
    o.xattrs
        .insert(b"snapset".to_vec(), denc::to_vec(ss).unwrap());
}

/// 3 OSDs, 1 PG, `names` written with distinct data; every head gets an (empty) snapset like real writes do.
fn setup(seed: u64, names: &[&str]) -> (Sim, SpgT, i32, Vec<i32>) {
    setup_cfg(seed, names, cfg)
}

fn setup_cfg(
    seed: u64,
    names: &[&str],
    f: impl Fn(&mut peering::Config),
) -> (Sim, SpgT, i32, Vec<i32>) {
    let mut s = cluster_cfg(seed, &[0, 1, 2], 1, 3, 2, 1, f);
    let pg = spg(1, 0);
    let t: Vec<u64> = names
        .iter()
        .map(|n| {
            s.write_obj(1, 0, n, format!("data-of-{n}").as_bytes())
                .unwrap()
        })
        .collect();
    s.wait_writes(&t, pg);
    s.run_for(200 * MS);
    for o in [0, 1, 2] {
        for n in names {
            put_snapset(&mut s, o, pg, &hobj(1, n), &SnapSet::default());
        }
    }
    let prim = s.primary_of(pg.pgid);
    let reps: Vec<i32> = s
        .acting_of(pg.pgid)
        .into_iter()
        .filter(|o| *o != prim)
        .collect();
    (s, pg, prim, reps)
}

fn request(s: &mut Sim, prim: i32, pg: SpgT, deep: bool, repair: bool) {
    s.call(prim, |set, now, st| {
        set.request_scrub(now, pg, deep, repair, st)
    });
}

fn done(s: &Sim, prim: i32, pg: SpgT) -> u64 {
    s.pg(prim, pg).unwrap().scrub_counts().0
}

fn wait_done(s: &mut Sim, prim: i32, pg: SpgT, n: u64) {
    s.run_until(60_000 * MS, "scrub finished", move |s| {
        let p = s.pg(prim, pg).unwrap();
        p.scrub_counts().0 >= n && !p.scrub_running() && p.is_clean()
    });
    s.run_for(300 * MS);
}

fn errors(s: &Sim, prim: i32, pg: SpgT) -> i64 {
    s.pg(prim, pg)
        .unwrap()
        .info()
        .stats
        .stats
        .sum
        .num_scrub_errors
}

fn data_of(s: &Sim, osd: i32, pg: SpgT, name: &str) -> Vec<u8> {
    s.nodes[&osd].store.pgs[&pg].objects[&hobj(1, name)]
        .data
        .clone()
}

fn flip(s: &mut Sim, osd: i32, pg: SpgT, name: &str) {
    s.nodes
        .get_mut(&osd)
        .unwrap()
        .store
        .pgs
        .get_mut(&pg)
        .unwrap()
        .objects
        .get_mut(&hobj(1, name))
        .unwrap()
        .data[2] ^= 0xFF;
}

#[test]
fn clean_deep_scrub_advances_stamps() {
    let (mut s, pg, prim, reps) = setup(100, &["a", "b", "c", "d", "e", "f", "g"]);
    let before = s.pg(prim, pg).unwrap().info().history.clone();
    request(&mut s, prim, pg, true, false);
    // the state shows scrubbing+deep while running
    s.run_until(5_000 * MS, "scrubbing", |s| {
        s.pg(prim, pg).unwrap().state_bits() & pgs::SCRUBBING != 0
    });
    assert!(
        s.pg(prim, pg)
            .unwrap()
            .state_string()
            .contains("scrubbing+deep")
    );
    wait_done(&mut s, prim, pg, 1);
    let p = s.pg(prim, pg).unwrap();
    let h = p.info().history.clone();
    assert!(h.last_deep_scrub_stamp > before.last_deep_scrub_stamp);
    assert!(h.last_scrub_stamp > before.last_scrub_stamp);
    assert!(h.last_clean_scrub_stamp > before.last_clean_scrub_stamp);
    assert!(h.last_deep_scrub >= before.last_deep_scrub);
    assert_eq!(errors(&s, prim, pg), 0);
    assert_eq!(
        p.state_bits() & (pgs::SCRUBBING | pgs::INCONSISTENT | pgs::DEEP),
        0
    );
    assert!(p.scrub_inconsistent().is_empty());
    let _ = p;
    // stamps reach the replicas with the info share and the mgr through the stats
    s.run_for(300 * MS);
    for r in &reps {
        assert_eq!(
            s.pg(*r, pg).unwrap().info().history.last_deep_scrub_stamp,
            h.last_deep_scrub_stamp
        );
        assert!(!s.pg(*r, pg).unwrap().scrub_reserved());
    }
    assert_eq!(
        s.pgstats[&pg].1.last_deep_scrub_stamp,
        h.last_deep_scrub_stamp
    );
    assert_eq!(s.nodes[&prim].set.local_scrubs(), 0);
    let p = s.pg(prim, pg).unwrap();
    assert!(p.counters().errors.is_empty(), "{:?}", p.counters().errors);
}

#[test]
fn shallow_scrub_leaves_deep_stamp() {
    let (mut s, pg, prim, _) = setup(101, &["a", "b"]);
    let before = s.pg(prim, pg).unwrap().info().history.clone();
    request(&mut s, prim, pg, false, false);
    wait_done(&mut s, prim, pg, 1);
    let h = &s.pg(prim, pg).unwrap().info().history;
    assert!(h.last_scrub_stamp > before.last_scrub_stamp);
    assert_eq!(h.last_deep_scrub_stamp, before.last_deep_scrub_stamp);
}

#[test]
fn replica_corruption_is_found_and_repaired() {
    let (mut s, pg, prim, reps) = setup(102, &["a", "b", "c", "d", "e"]);
    let bad = reps[0];
    flip(&mut s, bad, pg, "c");
    // shallow scrub does not see data corruption
    request(&mut s, prim, pg, false, false);
    wait_done(&mut s, prim, pg, 1);
    assert_eq!(errors(&s, prim, pg), 0);
    // deep scrub does
    request(&mut s, prim, pg, true, false);
    wait_done(&mut s, prim, pg, 2);
    let p = s.pg(prim, pg).unwrap();
    assert_eq!(errors(&s, prim, pg), 1);
    assert_eq!(p.info().stats.stats.sum.num_deep_scrub_errors, 1);
    assert!(
        p.state_string().contains("inconsistent"),
        "{}",
        p.state_string()
    );
    assert_eq!(p.scrub_inconsistent().len(), 1);
    let r = &p.scrub_inconsistent()[0];
    assert_eq!(r.soid, hobj(1, "c"));
    assert_eq!(r.bad_shards(), vec![bad]);
    // `rados list-inconsistent-obj` data: one object, every shard listed, data digest bit on the bad one
    let ls = |snaps| {
        p.scrub_ls(&peering::scrubls::LsArg {
            interval: 0,
            get_snapsets: snaps,
            start_after: (vec![], vec![], 0),
            max_return: 0,
        })
    };
    let (interval, vals) = ls(false).unwrap();
    assert_eq!(interval, p.info().history.same_interval_since);
    assert_eq!(vals.len(), 1);
    assert!(ls(true).unwrap().1.is_empty());
    assert!(
        p.scrub_ls(&peering::scrubls::LsArg {
            interval: interval + 1,
            get_snapsets: false,
            start_after: (vec![], vec![], 0),
            max_return: 0,
        })
        .is_err()
    );
    assert_ne!(data_of(&s, bad, pg, "c"), data_of(&s, prim, pg, "c"));
    // the mgr sees it
    assert!(s.pgstats[&pg].1.state & pgs::INCONSISTENT != 0);
    // repair
    request(&mut s, prim, pg, true, true);
    s.run_until(60_000 * MS, "repaired and verified", |s| {
        let p = s.pg(prim, pg).unwrap();
        p.scrub_counts().0 >= 4 && !p.scrub_running() && p.is_clean()
    });
    s.run_for(500 * MS);
    assert_eq!(data_of(&s, bad, pg, "c"), data_of(&s, prim, pg, "c"));
    let p = s.pg(prim, pg).unwrap();
    assert_eq!(errors(&s, prim, pg), 0);
    assert_eq!(
        p.state_bits() & (pgs::INCONSISTENT | pgs::FAILED_REPAIR | pgs::REPAIR),
        0
    );
    s.assert_replicas_equal(
        1,
        0,
        &(["a", "b", "c", "d", "e"]
            .iter()
            .map(|n| (n.to_string(), format!("data-of-{n}").into_bytes()))
            .collect()),
    );
}

/// A shallow pass cannot verify data and must not erase the evidence behind a PG's retained deep-error count.
#[test]
fn shallow_scrub_retains_deep_error_report() {
    let (mut s, pg, prim, reps) = setup(111, &["a", "b", "c"]);
    flip(&mut s, reps[0], pg, "b");
    request(&mut s, prim, pg, true, false);
    wait_done(&mut s, prim, pg, 1);
    let deep = s.pg(prim, pg).unwrap().scrub_inconsistent().to_vec();
    assert_eq!(deep.len(), 1);
    request(&mut s, prim, pg, false, false);
    wait_done(&mut s, prim, pg, 2);
    let p = s.pg(prim, pg).unwrap();
    assert_eq!(p.info().stats.stats.sum.num_deep_scrub_errors, 1);
    assert_eq!(p.info().stats.stats.sum.num_shallow_scrub_errors, 0);
    assert_eq!(p.scrub_inconsistent(), deep);
    assert_eq!(
        p.scrub_ls(&peering::scrubls::LsArg {
            interval: 0,
            get_snapsets: false,
            start_after: (vec![], vec![], 0),
            max_return: 0,
        })
        .unwrap()
        .1
        .len(),
        1
    );
    // New shallow evidence for the same version merges with the earlier deep shard facts.
    s.nodes
        .get_mut(&reps[0])
        .unwrap()
        .store
        .pgs
        .get_mut(&pg)
        .unwrap()
        .objects
        .get_mut(&hobj(1, "b"))
        .unwrap()
        .xattrs
        .insert(b"_user".to_vec(), b"damaged".to_vec());
    request(&mut s, prim, pg, false, false);
    wait_done(&mut s, prim, pg, 3);
    let merged = &s.pg(prim, pg).unwrap().scrub_inconsistent()[0];
    assert_eq!(
        merged.shards[&reps[0]],
        deep[0].shards[&reps[0]] | peering::scrubcmp::err::ATTR_NAME_MISMATCH
    );
    assert_eq!(merged.info, deep[0].info);
    // A later shallow pass drops the earlier shallow finding but keeps the deep report.
    s.nodes
        .get_mut(&reps[0])
        .unwrap()
        .store
        .pgs
        .get_mut(&pg)
        .unwrap()
        .objects
        .get_mut(&hobj(1, "b"))
        .unwrap()
        .xattrs
        .remove(b"_user".as_slice());
    request(&mut s, prim, pg, false, false);
    wait_done(&mut s, prim, pg, 4);
    assert_eq!(s.pg(prim, pg).unwrap().scrub_inconsistent(), deep);
    // A complete deep pass can clear the evidence after the bytes are restored.
    flip(&mut s, reps[0], pg, "b");
    request(&mut s, prim, pg, true, false);
    wait_done(&mut s, prim, pg, 5);
    assert_eq!(errors(&s, prim, pg), 0);
    assert!(s.pg(prim, pg).unwrap().scrub_inconsistent().is_empty());
}

#[test]
fn missing_object_on_replica_repaired() {
    let (mut s, pg, prim, reps) = setup(103, &["a", "b", "c"]);
    let bad = reps[1];
    s.nodes
        .get_mut(&bad)
        .unwrap()
        .store
        .pgs
        .get_mut(&pg)
        .unwrap()
        .objects
        .remove(&hobj(1, "b"));
    request(&mut s, prim, pg, false, false);
    wait_done(&mut s, prim, pg, 1);
    let p = s.pg(prim, pg).unwrap();
    assert_eq!(errors(&s, prim, pg), 1);
    assert_eq!(p.info().stats.stats.sum.num_shallow_scrub_errors, 1);
    assert_eq!(
        p.scrub_inconsistent()[0].shards[&bad],
        peering::scrubcmp::err::MISSING
    );
    request(&mut s, prim, pg, false, true);
    s.run_until(60_000 * MS, "repair verified", |s| {
        let p = s.pg(prim, pg).unwrap();
        p.scrub_counts().0 >= 3 && !p.scrub_running() && p.is_clean()
    });
    s.run_for(300 * MS);
    assert_eq!(data_of(&s, bad, pg, "b"), b"data-of-b");
    assert_eq!(errors(&s, prim, pg), 0);
}

#[test]
fn primary_corruption_pulled_from_replica() {
    let (mut s, pg, prim, _) = setup(104, &["a", "b", "c"]);
    flip(&mut s, prim, pg, "a");
    request(&mut s, prim, pg, true, true);
    s.run_until(60_000 * MS, "repair verified", |s| {
        let p = s.pg(prim, pg).unwrap();
        p.scrub_counts().0 >= 2 && !p.scrub_running() && p.is_clean()
    });
    s.run_for(300 * MS);
    assert_eq!(data_of(&s, prim, pg, "a"), b"data-of-a");
    for o in [0, 1, 2] {
        assert_eq!(data_of(&s, o, pg, "a"), b"data-of-a", "osd.{o}");
    }
    assert_eq!(errors(&s, prim, pg), 0);
}

#[test]
fn writes_to_the_active_chunk_are_blocked() {
    let names = ["a", "b", "c", "d", "e", "f", "g", "h"];
    // no preemption: every write into the chunk waits
    let (mut s, pg, prim, _) = setup_cfg(105, &names, |c| {
        cfg(c);
        c.scrub.max_preemptions = 0;
    });
    request(&mut s, prim, pg, true, false);
    let mut blocked_seen = false;
    let mut free_seen = false;
    for _ in 0..4000 {
        s.run_for(MS / 4);
        let p = s.pg(prim, pg).unwrap();
        let Some((start, end)) = p.scrub_range() else {
            continue;
        };
        for n in names {
            let h = hobj(1, n);
            let inside = h >= start && (end.max || h < end);
            match s.write_obj(1, 0, n, b"newer") {
                Err(WriteErr::Degraded(_)) => {
                    assert!(inside, "write outside the chunk was blocked");
                    // a write-only gate: reads of the chunk are served (client-ops 5.4 #16, 5.5 (6))
                    assert!(
                        !s.pg(prim, pg).unwrap().read_blocked(&h),
                        "scrub blocks reads"
                    );
                    blocked_seen = true;
                }
                Ok(_) => {
                    assert!(!inside, "write into the chunk was not blocked");
                    free_seen = true;
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        if blocked_seen && free_seen {
            break;
        }
    }
    assert!(blocked_seen && free_seen);
    wait_done(&mut s, prim, pg, 1);
    // after the scrub, writes go through again
    let t = s.write_obj(1, 0, "a", b"after").unwrap();
    s.wait_writes(&[t], pg);
}

/// A write accepted before the chunk whose repop a replica has not acked yet (held in a faulted carrier while a new
/// link already carries the scrub request: lab case 23) is in flight, not divergent: the chunk waits for its commit on
/// every shard before any map is asked for, and the scrub stays clean.
#[test]
fn chunk_waits_for_unacked_repops_into_its_range() {
    let names = ["a", "b", "c", "d", "e", "f", "g", "h"];
    let (mut s, pg, prim, reps) = setup(109, &names);
    let r = reps[0];
    // the repop to `r` stays in the old carrier ...
    s.partition(prim, r);
    let t = s.write_obj(1, 0, "a", b"newer-than-the-replica").unwrap();
    s.run_for(50 * MS);
    // ... while new messages (the scrub request) go over a new link ahead of it
    s.blocked.clear();
    request(&mut s, prim, pg, true, false);
    s.run_for(5_000 * MS);
    assert_eq!(
        errors(&s, prim, pg),
        0,
        "a write in flight was reported as an inconsistency"
    );
    assert_eq!(
        done(&s, prim, pg),
        0,
        "the chunk compared before the repop was acked"
    );
    // the old carrier's replay delivers the repop: the write commits, the chunk proceeds
    s.heal();
    s.wait_writes(&[t], pg);
    wait_done(&mut s, prim, pg, 1);
    assert_eq!(errors(&s, prim, pg), 0);
    assert_eq!(data_of(&s, r, pg, "a"), b"newer-than-the-replica");
}

/// 21.2.0 B6: a session that is queued or reserving (no chunk yet) blocks no write; the chunk range is gone when an
/// interval change drops the session.
#[test]
fn writes_wait_only_for_a_live_chunk_and_an_interval_change_drops_it() {
    let names = ["a", "b", "c", "d", "e", "f", "g", "h"];
    let (mut s, pg, prim, reps) = setup_cfg(107, &names, |c| {
        cfg(c);
        c.scrub.max_preemptions = 0;
    });
    request(&mut s, prim, pg, true, false);
    let mut early_free = false;
    let mut chunk_seen = false;
    for _ in 0..4000 {
        s.run_for(MS / 4);
        let p = s.pg(prim, pg).unwrap();
        if p.scrub_range().is_some() {
            chunk_seen = true;
            break;
        }
        if p.scrub_running() {
            // reserving / between chunks: nothing is blocked
            for n in names {
                assert!(
                    s.write_obj(1, 0, n, b"early").is_ok(),
                    "write blocked while no chunk exists ({n})"
                );
            }
            early_free = true;
        }
    }
    assert!(chunk_seen, "no chunk was ever built");
    assert!(
        early_free,
        "never observed a running session without a chunk"
    );
    // interval change: the session and its chunk range are dropped on the primary
    s.mark_down(reps[0]);
    s.run_until(30_000 * MS, "session dropped", |s| {
        let p = s.pg(prim, pg).unwrap();
        p.scrub_range().is_none() && !p.scrub_running()
    });
}

#[test]
fn chunks_never_split_head_from_clones() {
    let (mut s, pg, prim, _) = setup(106, &["a", "b", "c", "d"]);
    // clones of "b": snaps 2, 3
    let head = hobj(1, "b");
    let mut ss = SnapSet::default();
    ss.seq = 3;
    ss.clones = vec![SnapId(2), SnapId(3)];
    ss.clone_size.insert(SnapId(2), 4);
    ss.clone_size.insert(SnapId(3), 4);
    ss.clone_overlap.insert(SnapId(2), Default::default());
    ss.clone_overlap.insert(SnapId(3), Default::default());
    for o in [0, 1, 2] {
        put_snapset(&mut s, o, pg, &head, &ss);
        for sn in [2u64, 3] {
            let mut c = head.clone();
            c.snap = SnapId(sn);
            let mut oi = ObjectInfo::new(c.clone());
            oi.version = Eversion::new(1, 1);
            oi.size = 4;
            let mut obj = MemObj::default();
            obj.data = b"clon".to_vec();
            obj.xattrs.insert(b"_".to_vec(), denc::to_vec(&oi).unwrap());
            s.nodes
                .get_mut(&o)
                .unwrap()
                .store
                .pgs
                .get_mut(&pg)
                .unwrap()
                .objects
                .insert(c, obj);
        }
    }
    s.capture = true;
    for o in s.nodes.values_mut() {
        let _ = o;
    }
    request(&mut s, prim, pg, true, false);
    wait_done(&mut s, prim, pg, 1);
    assert_eq!(
        errors(&s, prim, pg),
        0,
        "{:?}",
        s.pg(prim, pg).unwrap().scrub_inconsistent()
    );
    let chunks: Vec<MOSDRepScrub> = s
        .captured
        .iter()
        .filter_map(|(f, _, b)| match b {
            Body::Repl(ReplMsg::RepScrub(m)) if *f == prim => Some(m.clone()),
            _ => None,
        })
        .collect();
    assert!(chunks.len() >= 3, "{} chunks", chunks.len());
    let group: Vec<Hobject> = [None, Some(2u64), Some(3)]
        .iter()
        .map(|sn| {
            let mut h = head.clone();
            h.snap = sn.map_or(SnapId::NOSNAP, SnapId);
            h
        })
        .collect();
    for c in chunks.iter().filter(|c| c.pgid.shard == ShardId::NO_SHARD) {
        let inn: Vec<bool> = group
            .iter()
            .map(|h| *h >= c.start && (c.end.max || *h < c.end))
            .collect();
        assert!(
            inn.iter().all(|x| *x) || inn.iter().all(|x| !*x),
            "chunk [{:?}, {:?}) splits the group: {inn:?}",
            c.start,
            c.end
        );
    }
    // a clone that the snapset does not list is an error
    let mut c = head.clone();
    c.snap = SnapId(9);
    let mut oi = ObjectInfo::new(c.clone());
    oi.version = Eversion::new(1, 1);
    let mut obj = MemObj::default();
    obj.xattrs.insert(b"_".to_vec(), denc::to_vec(&oi).unwrap());
    for o in [0, 1, 2] {
        s.nodes
            .get_mut(&o)
            .unwrap()
            .store
            .pgs
            .get_mut(&pg)
            .unwrap()
            .objects
            .insert(c.clone(), obj.clone());
    }
    request(&mut s, prim, pg, false, false);
    wait_done(&mut s, prim, pg, 2);
    assert_eq!(errors(&s, prim, pg), 1);
}

/// A local head-only listing must not put a peer's clone in the preceding chunk. The primary's missing clone
/// is one repairable shard error, rather than an apparent headless clone plus a clone absent everywhere.
#[test]
fn chunk_boundary_keeps_peer_only_clone_with_its_head() {
    let (mut s, pg, prim, reps) = setup_cfg(110, &["a", "b", "c", "d"], |c| {
        cfg(c);
        c.scrub.chunk_min = 1;
        c.scrub.chunk_max = 1;
    });
    let head = s.nodes[&prim].store.pgs[&pg]
        .objects
        .keys()
        .nth(1)
        .unwrap()
        .clone();
    let mut clone = head.clone();
    clone.snap = SnapId(2);
    let mut ss = SnapSet::default();
    ss.seq = 2;
    ss.clones = vec![clone.snap];
    ss.clone_size.insert(clone.snap, 4);
    ss.clone_overlap.insert(clone.snap, Default::default());
    ss.clone_snaps.insert(clone.snap, vec![clone.snap]);
    for osd in [0, 1, 2] {
        put_snapset(&mut s, osd, pg, &head, &ss);
    }
    let mut oi = ObjectInfo::new(clone.clone());
    oi.version = Eversion::new(1, 1);
    oi.size = 4;
    let mut obj = MemObj::default();
    obj.data = b"clon".to_vec();
    obj.xattrs.insert(b"_".to_vec(), denc::to_vec(&oi).unwrap());
    for osd in reps {
        s.nodes
            .get_mut(&osd)
            .unwrap()
            .store
            .pgs
            .get_mut(&pg)
            .unwrap()
            .objects
            .insert(clone.clone(), obj.clone());
    }
    request(&mut s, prim, pg, true, false);
    wait_done(&mut s, prim, pg, 1);
    let reports = s.pg(prim, pg).unwrap().scrub_inconsistent();
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(reports[0].soid, clone);
    assert_eq!(reports[0].obj_errors, 0, "{reports:?}");
    assert_eq!(
        reports[0].shards,
        std::collections::BTreeMap::from([(prim, peering::scrubcmp::err::MISSING)])
    );
    assert_eq!(errors(&s, prim, pg), 1);
}

#[test]
fn interval_change_aborts_and_cleans_up() {
    let (mut s, pg, prim, reps) = setup(107, &["a", "b", "c", "d", "e", "f"]);
    request(&mut s, prim, pg, true, false);
    s.run_until(5_000 * MS, "scrubbing", |s| {
        s.pg(prim, pg).unwrap().scrub_running()
    });
    s.mark_down(reps[0]);
    s.run_for(3_000 * MS);
    let p = s.pg(prim, pg).unwrap();
    assert!(!p.scrub_running());
    assert_eq!(p.state_bits() & (pgs::SCRUBBING | pgs::DEEP), 0);
    assert_eq!(s.nodes[&prim].set.local_scrubs(), 0);
    assert!(!s.pg(reps[1], pg).unwrap().scrub_chunk_active());
    // a later request works
    s.mark_up(reps[0]);
    s.run_until(60_000 * MS, "clean", |s| s.pool_clean(1));
    let before = done(&s, prim, pg);
    request(&mut s, prim, pg, true, false);
    wait_done(&mut s, prim, pg, before + 1);
    assert_eq!(errors(&s, prim, pg), 0);
}

/// A session that ends unfinished keeps its operator request: it runs again once the PG is clean, no second request
/// (classic keeps the target's urgency and only delays it; before, the aborted session consumed the request).
#[test]
fn operator_request_survives_an_aborted_session() {
    let (mut s, pg, prim, reps) = setup(117, &["a", "b", "c", "d", "e", "f"]);
    let before = done(&s, prim, pg);
    request(&mut s, prim, pg, true, false);
    s.run_until(5_000 * MS, "scrubbing", |s| {
        s.pg(prim, pg).unwrap().scrub_running()
    });
    s.mark_down(reps[0]);
    s.run_for(3_000 * MS);
    assert!(!s.pg(prim, pg).unwrap().scrub_running());
    assert!(
        s.pg(prim, pg).unwrap().scrub_requested().is_some(),
        "the aborted session's request must stay pending"
    );
    s.mark_up(reps[0]);
    wait_done(&mut s, prim, pg, before + 1);
    assert!(s.pg(prim, pg).unwrap().scrub_requested().is_none());
    assert_eq!(errors(&s, prim, pg), 0);
}

#[test]
fn periodic_schedule_load_and_window() {
    let mut s = cluster_cfg(108, &[0, 1, 2], 1, 3, 2, 1, |c| {
        cfg(c);
        c.scrub.min_interval = 10.0;
        c.scrub.deep_interval = 25.0;
        c.scrub.randomize_ratio = 0.0;
        c.scrub.retry = SEC_N;
    });
    let pg = spg(1, 0);
    let t = s.write_obj(1, 0, "a", b"x").unwrap();
    s.wait_writes(&[t], pg);
    for o in [0, 1, 2] {
        put_snapset(&mut s, o, pg, &hobj(1, "a"), &SnapSet::default());
    }
    let prim = s.primary_of(pg.pgid);
    // high load: nothing runs
    s.nodes.get_mut(&prim).unwrap().set.set_scrub_load(50.0);
    s.run_for(40_000 * MS);
    assert_eq!(done(&s, prim, pg), 0);
    // load drops: due scrubs run; a deep one is due too
    s.nodes.get_mut(&prim).unwrap().set.set_scrub_load(0.0);
    let before = s.pg(prim, pg).unwrap().info().history.clone();
    s.run_until(60_000 * MS, "periodic scrub", |s| done(s, prim, pg) >= 1);
    s.run_for(2_000 * MS);
    let h = &s.pg(prim, pg).unwrap().info().history;
    assert!(h.last_deep_scrub_stamp > before.last_deep_scrub_stamp);
    // and again after the interval
    let n = done(&s, prim, pg);
    s.run_until(120_000 * MS, "second periodic scrub", |s| {
        done(s, prim, pg) > n
    });
    assert_eq!(errors(&s, prim, pg), 0);
}

const SEC_N: u64 = 1_000_000_000;

#[test]
fn mgr_command_requests_scrub() {
    let (mut s, pg, prim, reps) = setup(109, &["a", "b"]);
    let e = s.epoch();
    let m = |deep, repair| MOSDScrub2 {
        fsid: [1; 16],
        epoch: e,
        scrub_pgs: vec![pg],
        repair,
        deep,
    };
    // a replica ignores it
    s.call(reps[0], |set, now, st| {
        set.scrub_command(now, m(true, false), st)
    });
    s.run_for(500 * MS);
    assert_eq!(done(&s, prim, pg), 0);
    assert!(s.pg(reps[0], pg).unwrap().scrub_requested().is_none());
    s.call(prim, |set, now, st| {
        set.scrub_command(now, m(true, false), st)
    });
    wait_done(&mut s, prim, pg, 1);
    assert_eq!(
        s.pgstats[&pg].1.last_deep_scrub,
        s.pg(prim, pg).unwrap().info().history.last_deep_scrub
    );
    let _ = PgShard::default();
}

#[test]
fn empty_pg_list_scrubs_every_primary_pg() {
    let (mut s, pg, prim, reps) = setup(110, &["a", "b"]);
    let m = MOSDScrub2 {
        fsid: [1; 16],
        epoch: s.epoch(),
        scrub_pgs: vec![],
        repair: false,
        deep: true,
    };
    // replicas do nothing, the primary scrubs its PG
    s.call(reps[0], |set, now, st| {
        set.scrub_command(now, m.clone(), st)
    });
    s.run_for(500 * MS);
    assert_eq!(done(&s, prim, pg), 0);
    assert!(s.pg(reps[0], pg).unwrap().scrub_requested().is_none());
    s.call(prim, |set, now, st| set.scrub_command(now, m.clone(), st));
    wait_done(&mut s, prim, pg, 1);
}

/// Deep scrub publishes num_omap_keys / num_omap_bytes / num_large_omap_objects (configured threshold) and tells
/// the cluster log with the text the mon's LARGE_OMAP_OBJECTS health points operators at.
#[test]
fn deep_scrub_reports_large_omap() {
    let (mut s, pg, prim, _reps) = setup(110, &["a", "b"]);
    // thresholds are per OSD config: lower them on the primary (it judges its own copy as the auth object)
    for o in [0, 1, 2] {
        let n = s.nodes.get_mut(&o).unwrap();
        n.set.scrub_cfg_mut().large_omap_keys = 4;
        n.set.push_cfg_to_pgs();
        for (k, v) in [
            ("k1", "v1"),
            ("k2", "v2"),
            ("k3", "v3"),
            ("k4", "v4"),
            ("k5", "v5"),
        ] {
            n.store
                .pgs
                .get_mut(&pg)
                .unwrap()
                .objects
                .get_mut(&hobj(1, "a"))
                .unwrap()
                .omap
                .insert(k.into(), v.into());
        }
    }
    request(&mut s, prim, pg, true, false);
    wait_done(&mut s, prim, pg, 1);
    let sum = s.pg(prim, pg).unwrap().info().stats.stats.sum;
    assert_eq!(sum.num_omap_keys, 5);
    assert_eq!(sum.num_omap_bytes, 20);
    assert_eq!(sum.num_large_omap_objects, 1);
    assert_eq!(sum.num_scrub_errors, 0);
    let notes = s.nodes.get_mut(&prim).unwrap().set.take_notices();
    let line = notes
        .iter()
        .find(|n| n.starts_with("WARN Large omap object found. Object: 1:"))
        .unwrap_or_else(|| panic!("{notes:?}"));
    assert!(
        line.contains("::a:head PG: 1.0 Key count: 5 Size (bytes): 10"),
        "{line}"
    );
}

#[test]
fn preempted_replica_map_aborts_without_comparing_partial_objects() {
    let (mut s, pg, prim, reps) = setup(919, &["a", "b", "c"]);
    let before = s.pg(prim, pg).unwrap().scrub_counts();
    let stamp = s
        .pg(prim, pg)
        .unwrap()
        .info()
        .history
        .last_clean_scrub_stamp;
    request(&mut s, prim, pg, true, true);
    s.run_until(5_000 * MS, "scrubbing a chunk", |s| {
        s.pg(prim, pg).unwrap().scrub_range().is_some()
    });
    // A current-interval reply while a peer is expected must not be accepted as an empty completed map.
    let epoch = s.pg(prim, pg).unwrap().last_peering_reset();
    s.inject(
        reps[0],
        prim,
        Body::Repl(replwire::ReplMsg::RepScrubMap(
            replwire::scrubmsgs::MOSDRepScrubMap {
                pgid: pg,
                map_epoch: epoch,
                from: PgShard {
                    osd: reps[0],
                    shard: ShardId::NO_SHARD,
                },
                preempted: true,
                map: Default::default(),
            },
        )),
    );
    s.run_for(50 * MS);
    assert_eq!(s.pg(prim, pg).unwrap().scrub_counts().0, before.0);
    assert!(s.pg(prim, pg).unwrap().scrub_counts().1 > before.1);
    assert_eq!(
        s.pg(prim, pg)
            .unwrap()
            .info()
            .history
            .last_clean_scrub_stamp,
        stamp
    );
}

/// `flashstore_scrub_slice_bytes` (ScrubCfg::slice_bytes): a deep scrub with tiny slices (one object per map slice on
/// every OSD) still finds a replica's corrupt object, and only that one.
#[test]
fn deep_scrub_with_tiny_slices_finds_the_corruption() {
    let names = ["a", "b", "c", "d", "e", "f", "g"];
    let mut s = cluster_cfg(117, &[0, 1, 2], 1, 3, 2, 1, |c| {
        cfg(c);
        c.scrub.slice_bytes = 1;
    });
    let pg = spg(1, 0);
    let t: Vec<u64> = names
        .iter()
        .map(|n| {
            s.write_obj(1, 0, n, format!("data-of-{n}").as_bytes())
                .unwrap()
        })
        .collect();
    s.wait_writes(&t, pg);
    s.run_for(200 * MS);
    for o in [0, 1, 2] {
        for n in names {
            put_snapset(&mut s, o, pg, &hobj(1, n), &SnapSet::default());
        }
    }
    let prim = s.primary_of(pg.pgid);
    let bad = s
        .acting_of(pg.pgid)
        .into_iter()
        .find(|o| *o != prim)
        .unwrap();
    flip(&mut s, bad, pg, "f");
    request(&mut s, prim, pg, true, false);
    wait_done(&mut s, prim, pg, 1);
    let p = s.pg(prim, pg).unwrap();
    assert_eq!(errors(&s, prim, pg), 1);
    assert_eq!(p.scrub_inconsistent().len(), 1);
    assert_eq!(p.scrub_inconsistent()[0].soid, hobj(1, "f"));
    assert_eq!(p.scrub_inconsistent()[0].bad_shards(), vec![bad]);
}

/// `osd_scrub_max_preemptions` (classic): a write into the chunk being scrubbed passes and preempts it (the range is
/// scrubbed again with fewer objects) until the budget is spent; then writes wait for the chunk. The scrub ends clean.
#[test]
fn writes_preempt_the_chunk_until_the_budget_is_spent() {
    let names = ["a", "b", "c", "d", "e", "f", "g", "h"];
    let (mut s, pg, prim, _) = setup_cfg(118, &names, |c| {
        cfg(c);
        c.scrub.max_preemptions = 2;
        c.scrub.slice_bytes = 1;
    });
    request(&mut s, prim, pg, true, false);
    let (mut passed, mut blocked) = (0, 0);
    let mut tids = Vec::new();
    for _ in 0..8000 {
        s.run_for(MS / 4);
        let Some((start, end)) = s.pg(prim, pg).unwrap().scrub_range() else {
            if blocked > 0 {
                break;
            }
            continue;
        };
        let Some(n) = names.iter().find(|n| {
            let h = hobj(1, n);
            h >= start && (end.max || h < end)
        }) else {
            continue;
        };
        match s.write_obj(1, 0, n, format!("newer-{n}-{passed}").as_bytes()) {
            Ok(t) => {
                passed += 1;
                tids.push(t);
            }
            Err(WriteErr::Degraded(_)) => blocked += 1,
            Err(e) => panic!("{e:?}"),
        }
    }
    assert_eq!(passed, 2, "writes that preempted a chunk");
    assert!(blocked > 0, "writes wait once the budget is spent");
    assert_eq!(s.pg(prim, pg).unwrap().scrub_preempted(), 2);
    s.wait_writes(&tids, pg);
    wait_done(&mut s, prim, pg, 1);
    assert_eq!(errors(&s, prim, pg), 0);
    assert_eq!(s.pg(prim, pg).unwrap().scrub_counts().1, 0, "no abort");
}

/// Two PGs led by the same OSD, a pool-wide operator scrub, `osd_max_scrubs` 1: with `flashstore_scrub_operator_limits`
/// (default) one runs at a time (the other waits for the slot) and both reserve their replicas; off (classic) both start
/// at once without reservations.
fn operator_scrubs(seed: u64, limits: bool) -> (usize, usize) {
    let mut s = cluster_cfg(seed, &[0, 1, 2], 1, 3, 2, 8, |c| {
        cfg(c);
        c.max_scrubs = 1;
        c.scrub.slice_bytes = 1;
        c.scrub.operator_limits = limits;
    });
    let prim = s.primary_of(spg(1, 0).pgid);
    let pgs: Vec<SpgT> = (0..8)
        .map(|i| spg(1, i))
        .filter(|p| s.primary_of(p.pgid) == prim)
        .take(2)
        .collect();
    assert_eq!(pgs.len(), 2, "two PGs led by osd.{prim}");
    let mut t = Vec::new();
    for p in &pgs {
        for n in ["a", "b", "c", "d", "e", "f"] {
            t.push((*p, s.write_obj(1, p.pgid.seed, n, b"some data").unwrap()));
        }
    }
    for (p, tid) in t {
        s.wait_writes(&[tid], p);
    }
    s.run_for(200 * MS);
    for o in [0, 1, 2] {
        for p in &pgs {
            for n in ["a", "b", "c", "d", "e", "f"] {
                put_snapset(&mut s, o, *p, &hobj(1, n), &SnapSet::default());
            }
        }
    }
    s.capture = true;
    let m = MOSDScrub2 {
        fsid: [1; 16],
        epoch: s.epoch(),
        scrub_pgs: vec![],
        repair: false,
        deep: true,
    };
    s.call(prim, |set, now, st| set.scrub_command(now, m.clone(), st));
    let mut most = 0;
    for _ in 0..20_000 {
        s.run_for(MS / 4);
        let running = pgs
            .iter()
            .filter(|p| s.pg(prim, **p).unwrap().scrub_running())
            .filter(|p| !s.pg(prim, **p).unwrap().scrub_waiting_slot())
            .count();
        most = most.max(running);
        if pgs.iter().all(|p| done(&s, prim, *p) >= 1) {
            break;
        }
    }
    for p in &pgs {
        assert_eq!(done(&s, prim, *p), 1, "{p} scrubbed");
        assert_eq!(errors(&s, prim, *p), 0);
    }
    let reqs = s
        .captured
        .iter()
        .filter(|(f, _, b)| {
            *f == prim
                && matches!(b, Body::Repl(ReplMsg::ScrubReserve(r)) if r.ty == replwire::MOSDScrubReserve::REQUEST)
        })
        .count();
    (most, reqs)
}

#[test]
fn operator_scrubs_observe_max_scrubs() {
    let (most, reqs) = operator_scrubs(119, true);
    assert_eq!(most, 1, "at most osd_max_scrubs sessions past the slot");
    assert_eq!(reqs, 4, "both PGs reserve both replicas");
}

#[test]
fn operator_scrubs_classic_bypass_the_limit() {
    let (most, reqs) = operator_scrubs(119, false);
    assert_eq!(most, 2, "classic: operator scrubs start at once");
    assert_eq!(reqs, 0, "classic: no replica reservations");
}

/// `osd_max_scrubs` 1 with the slot taken by an operator deep scrub: an operator repair of another PG starts at once
/// (no slot wait, no replica reservation) while a plain operator scrub of a third would have to queue.
#[test]
fn operator_repair_bypasses_the_limit() {
    let mut s = cluster_cfg(121, &[0, 1, 2], 1, 3, 2, 8, |c| {
        cfg(c);
        c.max_scrubs = 1;
        c.scrub.slice_bytes = 1;
        c.scrub.operator_limits = true;
    });
    let prim = s.primary_of(spg(1, 0).pgid);
    let pgs: Vec<SpgT> = (0..8)
        .map(|i| spg(1, i))
        .filter(|p| s.primary_of(p.pgid) == prim)
        .take(3)
        .collect();
    assert_eq!(pgs.len(), 3, "three PGs led by osd.{prim}");
    let mut t = Vec::new();
    for p in &pgs {
        for n in ["a", "b", "c", "d", "e", "f"] {
            t.push((*p, s.write_obj(1, p.pgid.seed, n, b"some data").unwrap()));
        }
    }
    for (p, tid) in t {
        s.wait_writes(&[tid], p);
    }
    s.run_for(200 * MS);
    for o in [0, 1, 2] {
        for p in &pgs {
            for n in ["a", "b", "c", "d", "e", "f"] {
                put_snapset(&mut s, o, *p, &hobj(1, n), &SnapSet::default());
            }
        }
    }
    let cmd = |s: &mut Sim, pg: SpgT, repair: bool| {
        let m = MOSDScrub2 {
            fsid: [1; 16],
            epoch: s.epoch(),
            scrub_pgs: vec![pg],
            repair,
            deep: true,
        };
        s.call(prim, |set, now, st| set.scrub_command(now, m.clone(), st));
    };
    let active = |s: &Sim, p: SpgT| {
        let pg = s.pg(prim, p).unwrap();
        pg.scrub_running() && !pg.scrub_waiting_slot()
    };
    cmd(&mut s, pgs[0], false);
    s.run_for(2 * MS);
    assert!(active(&s, pgs[0]), "first scrub holds the only slot");
    cmd(&mut s, pgs[1], false);
    cmd(&mut s, pgs[2], true);
    s.run_for(MS);
    assert!(active(&s, pgs[2]), "repair starts at once");
    assert!(
        !active(&s, pgs[1]),
        "plain operator scrub waits for the slot"
    );
    s.capture = true;
    for _ in 0..20_000 {
        s.run_for(MS / 4);
        if pgs.iter().all(|p| done(&s, prim, *p) >= 1) {
            break;
        }
    }
    for p in &pgs {
        assert_eq!(done(&s, prim, *p), 1, "{p} scrubbed");
    }
}

/// adr 0593-dedup-deep-scrub-reformat (dedup-listing.md 5): with `dedup_start_stamp` a successful deep scrub records the
/// wall time its session started (before the reservations, so before any dedup record it writes) next to its completion
/// stamp, shares it with the replicas and the mgr stats; a shallow scrub keeps it; without the option it stays zero.
#[test]
fn deep_scrub_start_stamp() {
    let (mut s, pg, prim, reps) = setup_cfg(102, &["a", "b", "c"], |c| {
        cfg(c);
        c.scrub.dedup_start_stamp = true;
    });
    let before = s.pg(prim, pg).unwrap().info().history.clone();
    assert_eq!(before.last_deep_scrub_start_stamp, Default::default());
    request(&mut s, prim, pg, true, false);
    wait_done(&mut s, prim, pg, 1);
    let h = s.pg(prim, pg).unwrap().info().history.clone();
    assert!(h.last_deep_scrub_start_stamp > before.last_deep_scrub_stamp);
    assert!(h.last_deep_scrub_start_stamp <= h.last_deep_scrub_stamp);
    s.run_for(300 * MS);
    for r in &reps {
        assert_eq!(
            s.pg(*r, pg)
                .unwrap()
                .info()
                .history
                .last_deep_scrub_start_stamp,
            h.last_deep_scrub_start_stamp
        );
    }
    assert_eq!(
        s.pgstats[&pg].1.last_deep_scrub_start_stamp,
        h.last_deep_scrub_start_stamp
    );
    // a shallow scrub leaves both deep stamps
    request(&mut s, prim, pg, false, false);
    wait_done(&mut s, prim, pg, 2);
    let h2 = s.pg(prim, pg).unwrap().info().history.clone();
    assert_eq!(
        (h2.last_deep_scrub_stamp, h2.last_deep_scrub_start_stamp),
        (h.last_deep_scrub_stamp, h.last_deep_scrub_start_stamp)
    );
    // option off: never set
    let (mut s, pg, prim, _) = setup(103, &["a"]);
    request(&mut s, prim, pg, true, false);
    wait_done(&mut s, prim, pg, 1);
    assert_eq!(
        s.pg(prim, pg)
            .unwrap()
            .info()
            .history
            .last_deep_scrub_start_stamp,
        Default::default()
    );
}

/// A remote scrub map cannot provide user key lengths. Keep the previous complete measurement until the
/// repaired local copy can be scanned, instead of reporting a value-only or partial total as key+value bytes.
#[test]
fn omap_accounting_keeps_complete_totals_until_local_keys_are_trustworthy() {
    let (mut s, pg, prim, reps) = setup(131, &["omap"]);
    let h = hobj(1, "omap");
    for osd in [0, 1, 2] {
        s.nodes
            .get_mut(&osd)
            .unwrap()
            .store
            .pgs
            .get_mut(&pg)
            .unwrap()
            .objects
            .get_mut(&h)
            .unwrap()
            .omap
            .insert(b"key".to_vec(), b"value".to_vec());
    }
    request(&mut s, prim, pg, true, false);
    wait_done(&mut s, prim, pg, 1);
    let stats = &s.pg(prim, pg).unwrap().info().stats;
    assert_eq!(
        (
            stats.stats.sum.num_omap_keys,
            stats.stats.sum.num_omap_bytes
        ),
        (1, 8)
    );
    assert!(!stats.omap_stats_invalid);

    s.nodes
        .get_mut(&prim)
        .unwrap()
        .store
        .pgs
        .get_mut(&pg)
        .unwrap()
        .objects
        .remove(&h);
    for osd in &reps {
        s.nodes
            .get_mut(osd)
            .unwrap()
            .store
            .pgs
            .get_mut(&pg)
            .unwrap()
            .objects
            .get_mut(&h)
            .unwrap()
            .omap
            .insert(b"key".to_vec(), vec![b'v'; 40]);
    }
    request(&mut s, prim, pg, true, false);
    wait_done(&mut s, prim, pg, 2);
    let stats = &s.pg(prim, pg).unwrap().info().stats;
    assert_eq!(
        (
            stats.stats.sum.num_omap_keys,
            stats.stats.sum.num_omap_bytes
        ),
        (1, 8)
    );
    assert!(stats.omap_stats_invalid);

    let repaired = s.nodes[&reps[0]].store.pgs[&pg].objects[&h].clone();
    s.nodes
        .get_mut(&prim)
        .unwrap()
        .store
        .pgs
        .get_mut(&pg)
        .unwrap()
        .objects
        .insert(h, repaired);
    request(&mut s, prim, pg, true, false);
    wait_done(&mut s, prim, pg, 3);
    let stats = &s.pg(prim, pg).unwrap().info().stats;
    assert_eq!(
        (
            stats.stats.sum.num_omap_keys,
            stats.stats.sum.num_omap_bytes
        ),
        (1, 43)
    );
    assert!(!stats.omap_stats_invalid);
}

// ---- scheduling options (spec scrub.md 12.1 / gaps G1-G10)

/// Periodic scrub knobs of the scheduling tests: due quickly, no random delay, no backoff.
fn sched_cfg(c: &mut peering::Config) {
    cfg(c);
    c.scrub.min_interval = 5.0;
    c.scrub.deep_interval = 3600.0;
    c.scrub.randomize_ratio = 0.0;
    c.scrub.deep_interval_cv = 0.0;
    c.scrub.backoff_ratio = 0.0;
    c.scrub.retry = SEC_N;
}

fn local_time(s: &mut Sim, osd: i32, hour: u32, weekday: u32) {
    s.nodes
        .get_mut(&osd)
        .unwrap()
        .set
        .set_local_time(peering::LocalTime { hour, weekday });
}

/// Hour of day and weekday windows are both evaluated in the OSD's local time, each with wrap-around; a PG overdue
/// past every interval waits for the next window instead of force-starting (spec scrub.md 12.1.1 / 12.1.4, G1/G2/G6).
#[test]
fn periodic_scrub_observes_the_local_hour_and_weekday_windows() {
    let mut s = cluster_cfg(120, &[0, 1, 2], 1, 3, 2, 1, |c| {
        sched_cfg(c);
        c.scrub.begin_hour = 20; // 20:00-05:59, wraps midnight
        c.scrub.end_hour = 6;
        c.scrub.begin_week_day = 5; // Friday, Saturday, Sunday, wraps
        c.scrub.end_week_day = 1;
    });
    let pg = spg(1, 0);
    let t = s.write_obj(1, 0, "a", b"x").unwrap();
    s.wait_writes(&[t], pg);
    for o in [0, 1, 2] {
        put_snapset(&mut s, o, pg, &hobj(1, "a"), &SnapSet::default());
    }
    let prim = s.primary_of(pg.pgid);
    // Monday noon: both windows closed; the PG is far overdue (min interval 5 s) but waits
    local_time(&mut s, prim, 12, 1);
    s.run_for(30_000 * MS);
    assert_eq!(done(&s, prim, pg), 0);
    // Sunday 03:00: hour wrap and weekday wrap both permit
    local_time(&mut s, prim, 3, 0);
    s.run_until(60_000 * MS, "periodic scrub inside the window", |s| {
        done(s, prim, pg) >= 1
    });
    // Tuesday 21:00: the hour is open, the weekday is not
    let n = done(&s, prim, pg);
    local_time(&mut s, prim, 21, 2);
    s.run_for(30_000 * MS);
    assert_eq!(done(&s, prim, pg), n);
    // a runtime window change takes effect on the next tick
    s.nodes
        .get_mut(&prim)
        .unwrap()
        .set
        .scrub_cfg_mut()
        .end_week_day = 3;
    s.nodes.get_mut(&prim).unwrap().set.push_cfg_to_pgs();
    s.run_until(60_000 * MS, "scrub after the runtime window change", |s| {
        done(s, prim, pg) > n
    });
}

/// The load gate compares the 1-minute load per CPU strictly below the threshold (spec scrub.md 12.1.2, G3).
#[test]
fn periodic_scrub_observes_the_load_threshold_strictly() {
    let mut s = cluster_cfg(121, &[0, 1, 2], 1, 3, 2, 1, sched_cfg);
    let pg = spg(1, 0);
    let t = s.write_obj(1, 0, "a", b"x").unwrap();
    s.wait_writes(&[t], pg);
    for o in [0, 1, 2] {
        put_snapset(&mut s, o, pg, &hobj(1, "a"), &SnapSet::default());
    }
    let prim = s.primary_of(pg.pgid);
    let threshold = s.nodes[&prim].set.cfg_ref().scrub.load_threshold;
    s.nodes
        .get_mut(&prim)
        .unwrap()
        .set
        .set_scrub_load(threshold);
    s.run_for(30_000 * MS);
    assert_eq!(
        done(&s, prim, pg),
        0,
        "equal to the threshold is not below it"
    );
    s.nodes
        .get_mut(&prim)
        .unwrap()
        .set
        .set_scrub_load(threshold / 2.0);
    s.run_until(
        60_000 * MS,
        "periodic scrub below the load threshold",
        |s| done(s, prim, pg) >= 1,
    );
}

/// `osd_scrub_backoff_ratio` skips the low urgencies about that often (spec scrub.md 12.1.3, G5): 1.0 never starts a
/// periodic scrub, 0.0 always may; the runtime change takes effect (G5 + runtime config).
#[test]
fn periodic_scrub_observes_the_random_backoff() {
    let mut s = cluster_cfg(122, &[0, 1, 2], 1, 3, 2, 1, |c| {
        sched_cfg(c);
        c.scrub.backoff_ratio = 1.0;
    });
    let pg = spg(1, 0);
    let t = s.write_obj(1, 0, "a", b"x").unwrap();
    s.wait_writes(&[t], pg);
    for o in [0, 1, 2] {
        put_snapset(&mut s, o, pg, &hobj(1, "a"), &SnapSet::default());
    }
    let prim = s.primary_of(pg.pgid);
    s.run_for(30_000 * MS);
    assert_eq!(done(&s, prim, pg), 0);
    s.nodes
        .get_mut(&prim)
        .unwrap()
        .set
        .scrub_cfg_mut()
        .backoff_ratio = 0.0;
    s.nodes.get_mut(&prim).unwrap().set.push_cfg_to_pgs();
    s.run_until(60_000 * MS, "periodic scrub without backoff", |s| {
        done(s, prim, pg) >= 1
    });
}

/// An operator request bypasses the hour / weekday window, the load gate, the random backoff and NOSCRUB / NODEEP_SCRUB
/// (spec scrub.md 12.1.7, G13).
#[test]
fn operator_request_bypasses_the_start_gates() {
    let mut s = cluster_cfg(123, &[0, 1, 2], 1, 3, 2, 1, |c| {
        sched_cfg(c);
        c.scrub.begin_hour = 2;
        c.scrub.end_hour = 3;
        c.scrub.backoff_ratio = 1.0;
    });
    let pg = spg(1, 0);
    let t = s.write_obj(1, 0, "a", b"y").unwrap();
    s.wait_writes(&[t], pg);
    for o in [0, 1, 2] {
        put_snapset(&mut s, o, pg, &hobj(1, "a"), &SnapSet::default());
    }
    let prim = s.primary_of(pg.pgid);
    local_time(&mut s, prim, 12, 3);
    s.nodes.get_mut(&prim).unwrap().set.set_scrub_load(1000.0);
    s.nodes
        .get_mut(&prim)
        .unwrap()
        .set
        .set_scrub_flags(peering::ScrubFlags {
            noscrub: true,
            nodeep: true,
            ..Default::default()
        });
    s.run_for(2_000 * MS);
    assert_eq!(done(&s, prim, pg), 0);
    request(&mut s, prim, pg, true, false);
    wait_done(&mut s, prim, pg, 1);
    assert_eq!(errors(&s, prim, pg), 0);
}

/// Setting noscrub while a periodic scrub runs aborts it at the next step; the target stays queued and starts again
/// once the flag is cleared (spec scrub.md 12.1.6, G10).
#[test]
fn noscrub_aborts_a_running_periodic_scrub() {
    let mut s = cluster_cfg(124, &[0, 1, 2], 1, 3, 2, 1, |c| {
        sched_cfg(c);
        c.scrub.min_interval = 1.0;
        // a long pause between chunks keeps the session alive while the flag is set
        c.scrub.sleep = 20 * SEC_N;
    });
    let pg = spg(1, 0);
    let mut tids = Vec::new();
    let names = ["a", "b", "c", "d", "e", "f", "g", "h"];
    for n in names {
        tids.push(
            s.write_obj(1, 0, n, format!("data-{n}").as_bytes())
                .unwrap(),
        );
    }
    s.wait_writes(&tids, pg);
    for o in [0, 1, 2] {
        for n in names {
            put_snapset(&mut s, o, pg, &hobj(1, n), &SnapSet::default());
        }
    }
    let prim = s.primary_of(pg.pgid);
    s.run_until(30_000 * MS, "periodic scrub running", |s| {
        s.pg(prim, pg).unwrap().scrub_running()
    });
    let (done0, aborted0) = s.pg(prim, pg).unwrap().scrub_counts();
    s.nodes
        .get_mut(&prim)
        .unwrap()
        .set
        .set_scrub_flags(peering::ScrubFlags {
            noscrub: true,
            ..Default::default()
        });
    s.run_for(2_000 * MS);
    let (done1, aborted1) = s.pg(prim, pg).unwrap().scrub_counts();
    assert_eq!(done1, done0, "the aborted scrub must not count as finished");
    assert!(
        aborted1 > aborted0,
        "noscrub aborts the running periodic scrub"
    );
    assert!(!s.pg(prim, pg).unwrap().scrub_running());
    // clearing the flag lets the still-queued target run
    s.nodes
        .get_mut(&prim)
        .unwrap()
        .set
        .set_scrub_flags(peering::ScrubFlags::default());
    s.run_until(
        180_000 * MS,
        "periodic scrub after noscrub was cleared",
        |s| done(s, prim, pg) > done0,
    );
}

/// Pool options override the OSD scrub intervals (`> 0` only) and the scrub op priority (spec scrub.md 12.1.6, G9).
#[test]
fn pool_scrub_options_override_the_globals() {
    let mut s = cluster_cfg(125, &[0, 1, 2], 1, 3, 2, 1, |c| {
        cfg(c);
        c.scrub.min_interval = 86_400.0;
        c.scrub.deep_interval = 86_400.0;
        c.scrub.randomize_ratio = 0.0;
        c.scrub.backoff_ratio = 0.0;
    });
    let pg = spg(1, 0);
    let t = s.write_obj(1, 0, "a", b"z").unwrap();
    s.wait_writes(&[t], pg);
    for o in [0, 1, 2] {
        put_snapset(&mut s, o, pg, &hobj(1, "a"), &SnapSet::default());
    }
    let prim = s.primary_of(pg.pgid);
    s.capture = true;
    s.run_for(20_000 * MS);
    assert_eq!(done(&s, prim, pg), 0, "the global 1 day interval holds");
    s.new_epoch(|m| {
        let p = m.pools.get_mut(&1).unwrap();
        p.scrub_min_interval_ns = Some(3_000_000_000);
        p.scrub_priority = Some(9);
    });
    s.run_until(60_000 * MS, "periodic scrub at the pool interval", |s| {
        done(s, prim, pg) >= 1
    });
    let prios: Vec<i32> = s
        .captured
        .iter()
        .filter_map(|(_, _, b)| match b {
            peering::Body::Repl(replwire::ReplMsg::RepScrub(m)) => Some(m.priority),
            _ => None,
        })
        .collect();
    assert!(!prios.is_empty());
    assert!(
        prios.iter().all(|p| *p == 9),
        "pool scrub_priority sent: {prios:?}"
    );
}
