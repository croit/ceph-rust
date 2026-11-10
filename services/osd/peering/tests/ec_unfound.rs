// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Unfound objects on an erasure-coded PG and `mark_unfound_lost delete` (spec doc/spec/ec-unfound-lost.md 5): k2m1,
//! objects written while one shard was down whose other holder is then lost cannot be decoded; they are listed with
//! their EC locations, marked lost with rollbackable LOST_DELETE entries (log-only update to every shard), and recovery
//! removes their pieces; the PG goes clean and reads answer ENOENT.
mod common;
use common::*;
use denc::types::{Eversion, PgShard, PgT, ShardId};
use peering::*;
use pgwire::LogOp;

const POOL: u64 = 1;

fn ec_sim(seed: u64, n: i32) -> Sim {
    let mut s = Sim::new(seed);
    for o in 0..n {
        s.add_osd_cfg(o, |c| {
            c.ec_enable = ec::EcEnable::All;
            c.ec_primary = true;
        });
    }
    s.run_for(50 * MS);
    s
}

fn put(s: &mut Sim, name: &str, d: &[u8]) {
    let lead = s.lead_spg(POOL, 0);
    let t = s
        .write_ops(
            POOL,
            0,
            name,
            &[EcOp::Touch, EcOp::Write(0, d.to_vec())],
            Some(d.len() as u64),
        )
        .unwrap();
    s.wait_writes(&[t], lead);
}

/// Client read through the op-layer interface (`ec_wait` until ready, then the cache); `Err(2)` = no such object.
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

fn mark_submit(s: &mut Sim, osd: i32, mode: LostMode) -> LostReply {
    let spg = s.spg_on(osd, POOL, 0);
    let mut out = None;
    s.call(osd, |set, now, store| {
        let (r, acts) = set.mark_unfound_lost(now, spg, mode, store);
        out = r;
        acts
    });
    out.expect("pg exists")
}

fn mark_answer(s: &mut Sim, osd: i32, tid: u64) -> LostResult {
    for _ in 0..500 {
        if let Some(i) = s
            .lost_done
            .iter()
            .position(|(o, d)| *o == osd && d.tid == tid)
        {
            return s.lost_done.remove(i).1.result;
        }
        s.run_for(10 * MS);
    }
    let lead = s.lead_spg(POOL, 0);
    let diag = s.pg(osd, lead).map(|p| (p.repops_diag(), p.state_string()));
    panic!("mark_unfound_lost tid {tid} on osd.{osd} never answered: {diag:?}");
}

fn lose(s: &mut Sim, osd: i32) {
    s.new_epoch(|m| {
        let e = m.epoch;
        m.osds.get_mut(&osd).unwrap().lost_at = e;
    });
}

fn has_piece(s: &Sim, osd: i32, name: &str) -> bool {
    s.nodes[&osd]
        .store
        .objects(s.spg_on(osd, POOL, 0))
        .contains_key(&hobj(POOL, name))
}

/// The recipe of spec 5. `classic`: the returning shard B is a classic stand-in (its deliveries are checked against
/// the classic model). `append`: an append to `x` (overwrites pool: reads its last stripe first) is submitted right
/// before the marking, so the lost entries queue behind it and take the versions after it.
fn ec_unfound_case(seed: u64, classic: bool, append: bool) {
    let mut s = ec_sim(seed, 4);
    s.create_pool_ec(POOL, 2, 1, 4096, append, 1);
    s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
    let pg = PgT::new(POOL, 0);
    let acting = s.acting_of(pg);
    let (a, b, c) = (acting[0], acting[1], acting[2]);
    let d = (0..4).find(|o| !acting.contains(o)).unwrap();
    s.set_up_override(pg, vec![a, b, c]);
    let x = vec![7u8; 9000];
    put(&mut s, "x", &x);
    // B down: y and z land on shards 0 and 2 only
    s.kill(b);
    s.run_for(300 * MS);
    put(&mut s, "y", b"y-data");
    put(&mut s, "z", b"z-data");
    // C down and lost (its data is gone); B back: shards 0 and 1, y and z exist on shard 0 only
    s.kill(c);
    s.run_for(300 * MS);
    if classic {
        s.classic_set(&[b]);
    }
    lose(&mut s, c);
    s.restart(b);
    s.run_until(30_000 * MS, "active with y, z unfound", |s| {
        let lead = s.lead_spg(POOL, 0);
        s.pg(a, lead)
            .is_some_and(|p| p.state_bits() & pgwire::state::RECOVERY_UNFOUND != 0)
    });
    let lead = s.lead_spg(POOL, 0);
    assert_eq!(s.primary_of(pg), a, "{}", s.dump());
    let p = s.pg(a, lead).unwrap();
    let uf = p.unfound();
    let names: Vec<&[u8]> = uf.iter().map(|u| u.oid.oid.as_slice()).collect();
    let mut want: Vec<&[u8]> = vec![b"y", b"z"];
    want.sort_by_key(|n| hobj(POOL, std::str::from_utf8(n).unwrap()));
    assert_eq!(names, want, "{}", p.state_string());
    let a0 = PgShard {
        osd: a,
        shard: ShardId(0),
    };
    for u in &uf {
        assert_eq!(
            u.locations,
            vec![a0],
            "only shard 0 holds it: not decodable"
        );
        assert_eq!(
            u.clean_regions,
            p.missing()
                .get(&u.oid)
                .map_or_else(|| u.clean_regions.clone(), |i| i.clean_regions.clone())
        );
    }
    // list_unfound: |N| (B's missing), the state machine name, paging
    let l = p.list_unfound(None, 256);
    assert_eq!((l.num_missing, l.num_unfound, l.more), (2, 2, false));
    assert_eq!(l.state, "NotRecovering");
    let might = l.might_have_unfound.expect("available in NotRecovering");
    assert!(
        might.iter().all(|(sh, _)| sh.osd == c),
        "only the lost shard is not probed: {might:?}"
    );
    let first = p.list_unfound(None, 1);
    assert_eq!((first.objects.len(), first.more), (1, true));
    assert_eq!(first.objects[0].oid, uf[0].oid);
    let second = p.list_unfound(Some(&first.objects[0].oid), 1);
    assert_eq!((second.objects.len(), second.more), (1, false));
    assert_eq!(second.objects[0].oid, uf[1].oid);
    assert_eq!(second.num_unfound, 2);
    let needs: Vec<Eversion> = uf.iter().map(|u| u.need).collect();
    // check order: revert on EC first, then primary
    assert_eq!(
        mark_submit(&mut s, b, LostMode::Revert),
        LostReply::Now(Err((-22, "mode must be 'delete' for ec pool".into())))
    );
    assert_eq!(
        mark_submit(&mut s, b, LostMode::Delete),
        LostReply::Now(Err((-30, "not primary".into())))
    );
    let mut x = x;
    let wtid = append.then(|| {
        let tail = vec![3u8; 100];
        x.extend_from_slice(&tail);
        s.write_ops(
            POOL,
            0,
            "x",
            &[EcOp::Write(9000, tail)],
            Some(x.len() as u64),
        )
        .unwrap()
    });
    let head = s.pg(a, lead).unwrap().log().head();
    let head = if append {
        Eversion::new(s.epoch(), head.version + 1)
    } else {
        head
    };
    let epoch = s.epoch();
    let LostReply::Later(tid) = mark_submit(&mut s, a, LostMode::Delete) else {
        panic!("marking submitted");
    };
    assert!(
        s.lost_done.is_empty(),
        "answered only after every shard committed"
    );
    // queued behind the append the entries are not in the log yet: still unfound until they are
    assert_eq!(
        s.pg(a, lead).unwrap().unfound().is_empty(),
        !append,
        "delete items are never unfound"
    );
    let r = mark_answer(&mut s, a, tid);
    if let Some(w) = wtid {
        s.wait_writes(&[w], lead);
        let xe = s
            .pg(a, lead)
            .unwrap()
            .log()
            .entries()
            .iter()
            .rev()
            .find(|e| e.soid.oid == b"x")
            .map(|e| e.version)
            .unwrap();
        assert_eq!(xe, head, "the append generated first");
    }
    assert_eq!(
        r,
        Ok("pg has 2 objects unfound and apparently lost marking".into())
    );
    // the entries, byte-exact (spec 3.1), equal on both shards
    let lost = |s: &Sim, osd: i32| -> Vec<pgwire::LogEntry> {
        s.pg(osd, s.spg_on(osd, POOL, 0))
            .unwrap()
            .log()
            .entries()
            .iter()
            .filter(|e| e.op == LogOp::LOST_DELETE)
            .cloned()
            .collect()
    };
    let ea = lost(&s, a);
    assert_eq!(ea.len(), 2);
    for (i, e) in ea.iter().enumerate() {
        assert_eq!(e.soid, uf[i].oid);
        assert_eq!(e.version, Eversion::new(epoch, head.version + 1 + i as u64));
        assert_eq!(e.prior_version, needs[i]);
        assert_eq!(e.user_version, 0);
        assert_eq!(e.clean_regions, pgwire::ObjectCleanRegions::default());
        let mut want_bl = vec![1u8, 1, 9, 0, 0, 0, 6];
        want_bl.extend_from_slice(&e.version.version.to_le_bytes());
        assert_eq!(
            e.mod_desc,
            pgwire::ObjectModDesc {
                version: 1,
                can_local_rollback: true,
                rollback_info_completed: true,
                bl: want_bl,
            },
            "TRY_DELETE of the entry's version"
        );
    }
    assert_eq!(
        denc::to_vec(&lost(&s, b)).unwrap(),
        denc::to_vec(&ea).unwrap(),
        "B got the same entries"
    );
    // recovery deletes the pieces; nothing missing or unfound remains
    s.run_until(20_000 * MS, "lost deletes recovered", |s| {
        let lead = s.lead_spg(POOL, 0);
        s.pg(a, lead).is_some_and(|p| {
            p.missing().is_empty()
                && p.state_bits() & pgwire::state::RECOVERY_UNFOUND == 0
                && p.list_unfound(None, 256).num_missing == 0
        })
    });
    for o in [a, b] {
        for n in ["y", "z"] {
            assert!(!has_piece(&s, o, n), "osd.{o}: piece of {n} removed");
        }
        assert!(has_piece(&s, o, "x"), "osd.{o}: x intact");
    }
    assert_eq!(read_ec(&mut s, "y", 6), Err(2));
    assert_eq!(read_ec(&mut s, "z", 6), Err(2));
    assert_eq!(read_ec(&mut s, "x", x.len() as u64).unwrap(), x);
    // a third shard (the replacement of C) makes the PG clean
    s.set_up_override(pg, vec![a, b, d]);
    s.run_until(60_000 * MS, "clean after the marking", |s| {
        s.pool_clean(POOL)
    });
    assert_eq!(read_ec(&mut s, "x", x.len() as u64).unwrap(), x);
    assert_eq!(read_ec(&mut s, "y", 6), Err(2));
    assert!(!has_piece(&s, d, "y"));
    assert!(
        s.classic_violations().is_empty(),
        "{:?}",
        s.classic_violations()
    );
}

#[test]
fn ec_unfound_listed_marked_deleted_clean() {
    ec_unfound_case(901, false, false);
}

#[test]
fn ec_unfound_with_a_classic_shard() {
    ec_unfound_case(902, true, false);
}

#[test]
fn ec_marking_queues_behind_an_earlier_write() {
    ec_unfound_case(903, false, true);
}
