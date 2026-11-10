// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Balanced PG placement (adr 0639): PGs that arrive on an OSD go to the least loaded core through the round
//! protocol of adr 0031 (placement moves without data), messages that came before the map move with them, PGs with a
//! copy on their core stay, the placement survives a restart, and other PGs keep serving meanwhile.
//! Child of `xcore_tests` (uses its multi-core harness).
use super::*;

/// Deleting an obsolete stranded collection retires its creation fence as well. A later split can reuse its seed,
/// and a subsequent remap can require creating that PG from a peer rather than from a local splitting parent.
#[test]
fn obsolete_stranded_copy_does_not_fence_a_later_pg_incarnation() {
    let mut mc = Mc::new(3);
    mc.up();
    let spg = SpgT {
        pgid: PgT::new(4, 31),
        shard: denc::types::ShardId::NO_SHARD,
    };
    let core = mc.osds[0].pg.set.core_of(spg.pgid);
    let now = mc.osds[core].pg_mono();
    let o = &mut mc.osds[core];
    let acts = o.pg.set.detach(now, spg, &o.pg.store);
    o.pg_exec(acts);
    o.cl.mig.strands.insert(spg);
    assert!(o.pg.set.pg(spg).is_none());
    assert!(peering::PgStoreOps::list_pgs(&o.pg.store).contains(&spg));
    // A peer cannot instantiate a second copy while the stranded data still exists.
    peer_notify(&mut mc, core, spg, 10);
    assert!(mc.osds[core].pg.set.pg(spg).is_none());
    mc.osds[core].on_mig_deferred(Vec::new());
    assert!(!peering::PgStoreOps::list_pgs(&mc.osds[core].pg.store).contains(&spg));
    // The collection no longer exists. The same legitimate peer state must now create the PG.
    peer_notify(&mut mc, core, spg, 10);
    assert!(
        mc.osds[core].pg.set.pg(spg).is_some(),
        "deleted stranded collection left a permanent PG creation fence"
    );
}

/// A completed migration retires its old core's creation fences. If a later incarnation maps back without a local
/// copy (for example after a merge, split and remap), peer state must be able to recreate it there.
#[test]
fn moved_copy_does_not_fence_a_later_pg_incarnation() {
    let mut mc = Mc::new(3);
    merge_setup(&mut mc);
    let (_, seed, src, dst) = moving_object(&mc);
    let spg = SpgT {
        pgid: PgT::new(4, seed),
        shard: denc::types::ShardId::NO_SHARD,
    };
    mc.deliver(pool4(&mc, 11, 10, 32, 5));
    mc.run_for(Duration::from_secs(1));
    assert_eq!(pool4_cores(&mc).get(&seed), Some(&dst));
    assert!(!peering::PgStoreOps::list_pgs(&mc.osds[src].pg.store).contains(&spg));
    // Model the intervening remap retiring the current copy, then returning ownership to the old core.
    let now = mc.osds[dst].pg_mono();
    let o = &mut mc.osds[dst];
    let acts = o.pg.set.detach(now, spg, &o.pg.store);
    o.pg_exec(acts);
    peering::PgStoreOps::mig_remove(&o.pg.store, spg).unwrap();
    let shard = mc.osds[src].cl.spec.owner().unwrap().default_shard(4, seed);
    assert_eq!(shard as usize % mc.n, src);
    for o in &mut mc.osds {
        o.set_input_placement(spg.pgid, shard);
    }
    peer_notify(&mut mc, src, spg, 11);
    assert!(
        mc.osds[src].pg.set.pg(spg).is_some(),
        "completed migration left a permanent PG creation fence on its old core"
    );
}

/// The Pair map at `epoch` plus pool `id` (a copy of pool 4) with `pg_num` PGs of size `size`.
fn with_pool(
    p: &Pair,
    epoch: u32,
    id: i64,
    pg_num: u32,
    size: u8,
    extra: &[(i64, u32, u8)],
) -> OsdMap {
    let mut m = p.map(epoch, [10, 10]);
    for &(id, pg_num, size) in [(id, pg_num, size)].iter().chain(extra) {
        let mut pool = m.pools.get(&4).unwrap().clone();
        pool.pg_num = pg_num;
        pool.pgp_num = pg_num;
        pool.pg_num_pending = pg_num;
        pool.pg_num_target = pg_num;
        pool.size = size;
        pool.min_size = 1;
        pool.last_change = epoch;
        m.pools.insert(id, pool);
        m.pool_name.insert(id, format!("p{id}").as_str().into());
    }
    m
}

/// PGs of `pool` per core of node `n`.
fn per_core(n: &Mc, pool: u64) -> Vec<usize> {
    n.pgs()
        .iter()
        .map(|v| v.iter().filter(|(p, _)| *p == pool).count())
        .collect()
}

fn spread(v: &[usize]) -> usize {
    v.iter().max().unwrap() - v.iter().min().unwrap()
}

/// Every PG of node `n` is on exactly one core and every core routes it there; all active.
fn assert_routed(who: i32, n: &Mc) {
    let pgs = n.pgs();
    let mut seen = BTreeSet::new();
    for (c, v) in pgs.iter().enumerate() {
        for &(pool, seed) in v {
            assert!(
                seen.insert((pool, seed)),
                "osd.{who} pg {pool}.{seed} on two cores"
            );
            for (k, o) in n.osds.iter().enumerate() {
                assert_eq!(
                    o.pg.set.core_of(PgT::new(pool, seed)),
                    c,
                    "osd.{who} core {k} routes {pool}.{seed}"
                );
            }
        }
    }
    for o in &n.osds {
        for (spg, s) in o.pg.set.pg_states() {
            assert!(s.contains("active"), "osd.{who} {spg} {s}");
        }
    }
}

/// Write `n` objects of `pool` through their primaries (size 1 or 2) and read them back.
fn write_pool(p: &mut Pair, pool: i64, prefix: &str, n: usize) {
    for i in 0..n {
        let name = format!("{prefix}{i}");
        let primary = primary_of(p, pool, &name);
        let pn = p.node(primary);
        let core = i % pn.n;
        let cl = pn.client(core);
        let data = vec![(i % 200) as u8 + 1; 4096];
        let op = pn.op(pool, &name, vec![OsdOp::writefull(data)]);
        let mut r = pn.call(core, cl, 1, op);
        p.settle();
        r.extend(p.node(primary).replies(core, cl));
        assert_eq!(r.len(), 1, "write {name} unanswered");
        assert_eq!(r[0].1.result, 0, "write {name}");
    }
    read_pool(p, pool, prefix, n);
}

fn read_pool(p: &mut Pair, pool: i64, prefix: &str, n: usize) {
    for i in 0..n {
        let name = format!("{prefix}{i}");
        let primary = primary_of(p, pool, &name);
        let pn = p.node(primary);
        let core = (i + 1) % pn.n;
        let cl = pn.client(core);
        let op = pn.op(pool, &name, vec![OsdOp::read(0, 4096)]);
        let r = pn.call(core, cl, 2, op);
        assert_eq!(r.len(), 1, "read {name} unanswered");
        assert_eq!(
            r[0].1.ops[0].outdata,
            vec![(i % 200) as u8 + 1; 4096],
            "object {name}"
        );
    }
}

fn primary_of(p: &Pair, pool: i64, name: &str) -> i32 {
    let map = p.a.osds[0].osdmap().unwrap();
    let raw = map
        .object_to_raw_pg(pool, name.as_bytes(), b"", b"", -1)
        .unwrap();
    let n = map.pool(pool).unwrap().pg_num;
    let pg = PgT::new(pool as u64, pgwire::pgmath::object_pg(raw.seed, n));
    map.pg_to_up_acting(pg).acting_primary
}

/// A pool created after the OSDs are up: each OSD holds a CRUSH subset of its PGs (size 1). Hash placement spreads
/// such a subset unevenly over the cores; the balanced placement gives every core the same count (+-1).
#[test]
fn pgs_of_a_new_pool_are_balanced_over_the_cores_of_each_osd() {
    let mut p = Pair::new(4, 4);
    p.up();
    let m = with_pool(&p, 11, 5, 128, 1, &[]);
    p.deliver(m);
    p.create_pool_pgs(5);
    p.run_for(Duration::from_secs(5));
    let mut hash_spread = 0;
    for (who, n) in [(0, &p.a), (1, &p.b)] {
        let per = per_core(n, 5);
        assert!(per.iter().sum::<usize>() > 32, "osd.{who} {per:?}");
        assert!(spread(&per) <= 1, "osd.{who} pool 5 per core {per:?}");
        assert_routed(who, n);
        // what hash placement would have done with the same PGs
        let mut hash = vec![0; n.n];
        for v in n.pgs() {
            for (_, seed) in v.iter().filter(|(p, _)| *p == 5) {
                hash[n.owner(5, *seed)] += 1;
            }
        }
        hash_spread = hash_spread.max(spread(&hash));
        // pools 1 and 4 came with the first map (nothing to compare with): hash placement
        for (c, v) in n.pgs().iter().enumerate() {
            for (pool, seed) in v.iter().filter(|(p, _)| *p != 5) {
                assert_eq!(n.owner(*pool, *seed), c);
            }
        }
    }
    assert!(hash_spread > 1, "the test needs an uneven hash spread");
    write_pool(&mut p, 5, "bal", 48);
}

/// osd.1 applies the map that creates the pool first: its PGs query and notify osd.0, and a client op for a PG
/// osd.0 leads arrives, all stamped with an epoch osd.0 does not have yet. They wait on the cores the hash routes
/// them to; the placement round hands them to the cores the balance chooses, nothing is lost.
#[test]
fn messages_that_came_before_the_map_move_with_the_arriving_pg() {
    let mut p = Pair::new(4, 4);
    p.up();
    let m = with_pool(&p, 11, 5, 64, 2, &[]);
    p.b.deliver(m.clone());
    let bmap = p.b.osds[0].osdmap().unwrap().clone();
    let (mut mine, mut theirs) = (vec![], vec![]);
    for seed in 0..64 {
        match bmap.pg_to_up_acting(PgT::new(5, seed)).acting_primary {
            0 => mine.push(seed),
            _ => theirs.push(seed),
        }
    }
    assert!(!mine.is_empty() && !theirs.is_empty());
    p.b.create_pgs(5, theirs);
    p.settle();
    // a client of osd.0 already has map 11: a write for a PG osd.0 leads
    let name = (0..)
        .map(|i| format!("early{i}"))
        .find(|n| {
            let raw = bmap
                .object_to_raw_pg(5, n.as_bytes(), b"", b"", -1)
                .unwrap();
            bmap.pg_to_up_acting(PgT::new(5, pgwire::pgmath::object_pg(raw.seed, 64)))
                .acting_primary
                == 0
        })
        .unwrap();
    let op = p.b.op(5, &name, vec![OsdOp::writefull(vec![7; 4096])]);
    let cl = p.a.client(3);
    let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
    p.a.osds[3].on_unknown_message(cl, 9, ty, ver, &segs);
    p.settle();
    assert!(
        p.a.replies(3, cl).is_empty(),
        "answered before osd.0 has the pool"
    );
    p.a.create_pgs_at(5, mine, 11, 11);
    p.a.deliver(m);
    p.settle();
    p.run_for(Duration::from_secs(5));
    let r = p.a.replies(3, cl);
    assert_eq!(r.len(), 1, "early write unanswered");
    assert_eq!(r[0].1.result, 0);
    for (who, n) in [(0, &p.a), (1, &p.b)] {
        assert_eq!(per_core(n, 5).iter().sum::<usize>(), 64, "osd.{who}");
        assert_routed(who, n);
    }
    // osd.0 decided the placement of all 64 (osd.1 held them before it saw them arrive: hash, its own business)
    assert!(spread(&per_core(&p.a, 5)) <= 1, "{:?}", per_core(&p.a, 5));
    assert!(p.a.osds.iter().all(|o| o.pg.c.dropped_ops.is_empty()));
}

/// A map that brings new PGs while writes of other PGs are in flight (waiting for the replica): the round holds only
/// the arriving PGs, the writes complete.
#[test]
fn arrivals_under_in_flight_writes() {
    let mut p = Pair::new(4, 4);
    p.up();
    let m = with_pool(&p, 11, 5, 32, 2, &[]);
    p.deliver(m);
    p.create_pool_pgs(5);
    p.run_for(Duration::from_secs(3));
    write_pool(&mut p, 5, "pre", 32);
    // writes to pool 5 leave osd.0's cores, the replica answers only after the map change
    let send = |p: &mut Pair, prefix: &str| {
        let mut sent = vec![];
        for i in 0..24usize {
            let name = format!("{prefix}{i}");
            if primary_of(p, 5, &name) != 0 {
                continue;
            }
            let core = i % 4;
            let cl = p.a.client(core);
            let op = p.a.op(
                5,
                &name,
                vec![OsdOp::writefull(vec![(i % 200) as u8 + 1; 4096])],
            );
            let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
            p.a.osds[core].on_unknown_message(cl, 1, ty, ver, &segs);
            p.a.settle();
            assert!(
                p.a.replies(core, cl).is_empty(),
                "{name} acked before the replica"
            );
            sent.push((core, cl, name));
        }
        assert!(!sent.is_empty());
        sent
    };
    let sent = send(&mut p, "fly");
    let m = with_pool(&p, 12, 5, 32, 2, &[(6, 64, 1)]);
    p.deliver(m);
    p.create_pool_pgs(6);
    p.settle();
    p.run_for(Duration::from_secs(3));
    assert!(
        p.a.osds[0]
            .logs
            .iter()
            .any(|l| l.contains("map 12: ") && l.contains("arriving PG(s) placed"))
    );
    // no interval change for pool 5: every in-flight write completes, none is dropped
    for (core, cl, name) in sent {
        let r = p.a.replies(core, cl);
        assert_eq!(r.len(), 1, "{name} unanswered");
        assert_eq!(r[0].1.result, 0, "{name}");
    }
    assert!(p.a.osds.iter().all(|o| o.pg.c.dropped_ops.is_empty()));
    assert!(spread(&per_core(&p.a, 6)) <= 1, "{:?}", per_core(&p.a, 6));
    for (who, n) in [(0, &p.a), (1, &p.b)] {
        assert_routed(who, n);
    }
    read_pool(&mut p, 5, "pre", 32);
}

/// An OSD marked out and in again: all its PGs leave and arrive again, but each still has its copy on its core. The
/// placement moves of the round find the copies and stay (a placement never carries data); nothing moves.
#[test]
fn out_and_in_again_keeps_every_pg_on_its_core() {
    let mut mc = Mc::new(4);
    mc.up();
    write_read_all(&mut mc, 1, "o", 32, 1);
    let before = mc.pgs();
    let mut out = mc.map(11, 10);
    out.osd_weight[0] = 0;
    mc.deliver(out);
    mc.run_for(Duration::from_secs(1));
    let m = mc.map(12, 10);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    assert!(
        mc.osds[0]
            .logs
            .iter()
            .any(|l| l.contains("arriving PG(s) placed")),
        "no placement decided"
    );
    assert!(
        mc.osds[0]
            .logs
            .iter()
            .any(|l| l.contains("arriving PG(s) kept on their cores"))
    );
    assert_eq!(mc.pgs(), before);
    assert_eq!(mc.osds.iter().map(|o| o.cl.mig.moved).sum::<u64>(), 0);
    for (c, v) in before.iter().enumerate() {
        for (pool, seed) in v {
            for o in &mc.osds {
                assert_eq!(o.pg.set.core_of(PgT::new(*pool, *seed)), c);
            }
        }
    }
    read_back(&mut mc, 1, "o", 32);
}

/// The balanced placement is where the collections are: a restart loads every PG on the core it was placed on.
#[test]
fn restart_keeps_the_balanced_placement() {
    let mut mc = Mc::new(4);
    mc.up();
    let m = map5(&mc, 11, 10, 32);
    mc.deliver(m);
    mc.create_pgs(5, 0..32);
    mc.run_for(Duration::from_secs(3));
    assert!(
        mc.osds[0]
            .logs
            .iter()
            .any(|l| l.contains("arriving PG(s) placed"))
    );
    let before = mc.pgs();
    // the 32 PGs of pool 5 are balanced on top of pools 1 and 4, not where they hash
    let moved = before
        .iter()
        .enumerate()
        .flat_map(|(c, v)| v.iter().filter(|(p, _)| *p == 5).map(move |(_, s)| (c, *s)))
        .filter(|(c, s)| mc.owner(5, *s) != *c)
        .count();
    assert!(moved > 0);
    write_read_all(&mut mc, 5, "r", 32, 1);
    mc.restart();
    assert_eq!(mc.pgs(), before);
    let m = map5(&mc, 12, 12, 32);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    assert_eq!(mc.pgs(), before);
    for (c, v) in before.iter().enumerate() {
        for (pool, seed) in v {
            for o in &mc.osds {
                assert_eq!(o.pg.set.core_of(PgT::new(*pool, *seed)), c);
            }
        }
    }
    read_back(&mut mc, 5, "r", 32);
}

/// The single-OSD map at `epoch` plus pool 5 (a copy of pool 4, created at epoch 11) with `pg_num` PGs.
fn map5(mc: &Mc, epoch: u32, up_from: u32, pg_num: u32) -> OsdMap {
    let mut m = mc.map(epoch, up_from);
    let mut pool = m.pools.get(&4).unwrap().clone();
    pool.pg_num = pg_num;
    pool.pgp_num = pg_num;
    pool.pg_num_pending = pg_num;
    pool.pg_num_target = pg_num;
    pool.last_change = if pg_num == 32 { 11 } else { epoch };
    m.pools.insert(5, pool);
    m.pool_name.insert(5, "p5".into());
    m
}

/// A split under in-flight writes: the children of balanced (off-hash) parents stay on their parents' cores (zero-copy
/// split), every write completes (or is resent after the interval change, as Objecter does), all data reads back.
#[test]
fn split_of_balanced_pgs_under_in_flight_writes() {
    let mut mc = Mc::new(4);
    mc.up();
    let m = map5(&mc, 11, 10, 32);
    mc.deliver(m);
    mc.create_pgs(5, 0..32);
    mc.run_for(Duration::from_secs(3));
    write_read_all(&mut mc, 5, "s", 32, 1);
    let parents: BTreeMap<u32, usize> = mc
        .pgs()
        .iter()
        .enumerate()
        .flat_map(|(c, v)| v.iter().filter(|(p, _)| *p == 5).map(move |(_, s)| (*s, c)))
        .collect();
    assert!(
        parents.iter().any(|(s, c)| mc.owner(5, *s) != *c),
        "balanced off the hash"
    );
    // writes on the links, not run yet, when the split map arrives
    let clients: Vec<u64> = (0..mc.n).map(|c| mc.client(c)).collect();
    let data = |i: usize| vec![(i % 251) as u8; 4096 + i];
    for i in 0..32usize {
        let c = i % mc.n;
        let op = mc.op(5, &format!("f{i}"), vec![OsdOp::writefull(data(i))]);
        let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
        let t = mc.t;
        mc.osds[c].set_now(t);
        mc.osds[c].on_unknown_message(clients[c], 100 + i as u64, ty, ver, &segs);
    }
    let m = map5(&mc, 12, 10, 64);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    let mut done = BTreeMap::new();
    for (c, cl) in clients.iter().enumerate() {
        for (tid, r) in mc.replies(c, *cl) {
            done.insert(tid, r.result);
        }
    }
    for i in 0..32usize {
        match done.get(&(100 + i as u64)) {
            Some(r) => assert_eq!(*r, 0, "f{i}"),
            None => {
                let c = i % mc.n;
                let op = mc.op(5, &format!("f{i}"), vec![OsdOp::writefull(data(i))]);
                let r = mc.call(c, clients[c], 200 + i as u64, op);
                assert_eq!(r.len(), 1, "resent f{i}");
                assert_eq!(r[0].1.result, 0, "resent f{i}");
            }
        }
    }
    for (c, v) in mc.pgs().iter().enumerate() {
        for (_, seed) in v.iter().filter(|(p, _)| *p == 5) {
            let parent = if *seed < 32 {
                *seed
            } else {
                pgwire::pgmath::ancestor(*seed, 32)
            };
            assert_eq!(parents[&parent], c, "5.{seed}");
            for o in &mc.osds {
                assert_eq!(o.pg.set.core_of(PgT::new(5, *seed)), c);
            }
        }
    }
    assert_eq!(
        mc.pgs().iter().flatten().filter(|(p, _)| *p == 5).count(),
        64
    );
    read_back(&mut mc, 5, "s", 32);
    read_back(&mut mc, 5, "f", 32);
}

/// EC sibling: an erasure pool's PG arrives as its shard instance(s); placement is per PG (every instance of it on one
/// core), counted by instance. (One OSD of a k=2 m=1 pool takes no client writes in this harness: placement only.)
#[test]
fn ec_pool_arrivals_are_placed_with_their_shards() {
    let mut mc = Mc::new(4);
    mc.ec4 = true;
    mc.up();
    let m = map5(&mc, 11, 10, 32);
    assert!(m.pools[&5].is_erasure());
    mc.deliver(m);
    mc.create_pgs(5, 0..32);
    mc.run_for(Duration::from_secs(3));
    assert!(
        mc.osds[0]
            .logs
            .iter()
            .any(|l| l.contains("arriving PG(s) placed"))
    );
    let mut per = vec![0usize; mc.n];
    for (c, o) in mc.osds.iter().enumerate() {
        for (spg, _) in o.pg.set.pgs().filter(|(s, _)| s.pgid.pool == 5) {
            assert_ne!(spg.shard, denc::types::ShardId::NO_SHARD, "{spg}");
            for k in &mc.osds {
                assert_eq!(k.pg.set.core_of(spg.pgid), c, "{spg}");
            }
            per[c] += 1;
        }
    }
    assert_eq!(per.iter().sum::<usize>(), 32, "{per:?}");
    assert!(spread(&per) <= 1, "{per:?}");
}
