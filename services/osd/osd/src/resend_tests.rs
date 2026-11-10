// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Resent client writes (doc/spec/client-ops.md 5.6, pglog.md 3, 6.3, 6.6, 7.4): a write resent with the same request id
//! (client entity, tid, incarnation) is answered from the PG log / dup records with the original result and versions and
//! is never applied twice; after a session reset to the same primary, a lost reply, a crash restart, a trim into dup
//! records, and on a new primary that got the entry through replication or through peering (log + dups over the wire).
//! Non-idempotent ops prove it: append, cmpxattr-guarded omap set, a class call (numops add), write_full with
//! assert_version. Child of `xcore_tests` (multi-core harness).
use super::*;
use opwire::consts::cmp;

const CLIENT: i64 = 7701;

fn who() -> EntityName {
    EntityName::client(CLIENT)
}

/// numops add input: key, decimal diff (two length-prefixed strings).
fn numops_add(key: &[u8], diff: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    for s in [key, diff] {
        v.extend_from_slice(&(s.len() as u32).to_le_bytes());
        v.extend_from_slice(s);
    }
    v
}

/// The four non-idempotent writes of one object, in order: `(tid, ops)`. `uv` = user_version the object has before the
/// last one (write_full guarded by assert_version).
fn writes(uv: u64) -> Vec<(u64, Vec<OsdOp>)> {
    let kv = BTreeMap::from([(b"k".to_vec(), b"v".to_vec())]);
    vec![
        (101, vec![OsdOp::append(b"abc".to_vec())]),
        (
            102,
            vec![
                OsdOp::cmpxattr(b"gen", b"", cmp::EQ, cmp::MODE_STRING),
                OsdOp::setxattr(b"gen", b"1"),
                OsdOp::omap_set_vals(&kv),
            ],
        ),
        (
            103,
            vec![OsdOp::call(b"numops", b"add", &numops_add(b"ctr", b"1"))],
        ),
        (
            104,
            vec![
                OsdOp::assert_version(uv),
                OsdOp::writefull(b"abcabc".to_vec()),
            ],
        ),
    ]
}

/// Reply summary: (result, replay_version, user_version).
fn sum(r: &MOSDOpReply) -> (i32, denc::types::Eversion, u64) {
    (r.result, r.replay_version, r.user_version)
}

/// Object state a second application of any of [`writes`] would change: data, xattr `gen`, omap.
fn state(n: &mut Mc, core: usize, oid: &str) -> (i32, Vec<u8>, Vec<u8>, Vec<u8>, u64) {
    let cl = n.client(core);
    let op = n.op(
        1,
        oid,
        vec![
            OsdOp::read(0, 64),
            OsdOp::getxattr(b"gen"),
            OsdOp::omap_get_vals(b"", 100, b""),
        ],
    );
    let r = n.call(core, cl, 9_000, op);
    assert_eq!(r.len(), 1, "state read of {oid}");
    let r = &r[0].1;
    (
        r.result,
        r.ops[0].outdata.to_vec(),
        r.ops[1].outdata.to_vec(),
        r.ops[2].outdata.to_vec(),
        r.user_version,
    )
}

/// Send the writes of [`writes`] in order from `who()` on a fresh link of `core`, one by one; their reply summaries.
fn send_all(n: &mut Mc, core: usize, oid: &str, uv: u64) -> Vec<(i32, denc::types::Eversion, u64)> {
    let cl = n.client_as(core, who());
    writes(uv)
        .into_iter()
        .map(|(tid, ops)| {
            let op = n.op(1, oid, ops);
            let r = n.call(core, cl, tid, op);
            assert_eq!(r.len(), 1, "{oid} tid {tid}");
            sum(&r[0].1)
        })
        .collect()
}

/// Expected state after exactly one application of each write.
fn assert_once(st: &(i32, Vec<u8>, Vec<u8>, Vec<u8>, u64), what: &str) {
    assert_eq!(st.0, 0, "{what}: state read");
    assert_eq!(st.1, b"abcabc", "{what}: data");
    assert_eq!(st.2, b"1", "{what}: xattr");
    // omap map<string,bufferlist>: {ctr: "1", k: "v"} (numops added once)
    let mut d = denc::Decoder::new(&st.3);
    let m = <BTreeMap<Vec<u8>, Vec<u8>> as denc::Decode>::decode(&mut d).unwrap();
    assert_eq!(
        m,
        BTreeMap::from([
            (b"ctr".to_vec(), b"1".to_vec()),
            (b"k".to_vec(), b"v".to_vec())
        ]),
        "{what}: omap"
    );
}

/// The writes of [`writes`] applied once from `who()`; the guarded write_full asserts the user_version the third left.
fn first_round(n: &mut Mc, core: usize, oid: &str) -> Vec<(i32, denc::types::Eversion, u64)> {
    let cl = n.client_as(core, who());
    let mut out = Vec::new();
    for (tid, ops) in writes(0).into_iter().take(3) {
        let op = n.op(1, oid, ops);
        let r = n.call(core, cl, tid, op);
        assert_eq!(r.len(), 1);
        out.push(sum(&r[0].1));
    }
    let uv = out[2].2;
    let (tid, ops) = writes(uv).pop().unwrap();
    let op = n.op(1, oid, ops);
    let r = n.call(core, cl, tid, op);
    assert_eq!(r.len(), 1);
    out.push(sum(&r[0].1));
    assert!(out.iter().all(|x| x.0 == 0), "first round: {out:?}");
    out
}

/// (a) session reset to the same primary, (c) the reply was lost (never read), then a crash restart and a trim of the
/// entries into dup records (restart again): every resend gets the original answer, nothing is applied twice.
#[test]
fn resent_writes_are_answered_from_the_log_after_reset_lost_reply_restart_and_trim() {
    let mut mc = Mc::new(2);
    mc.up();
    let oid = "dupobj";
    let first = first_round(&mut mc, 1, oid);
    let uv = first[2].2;
    assert_once(&state(&mut mc, 0, oid), "after the first round");
    // (a) new session (other core) of the same client: same answers
    assert_eq!(
        send_all(&mut mc, 0, oid, uv),
        first,
        "resend after a session reset"
    );
    assert_once(&state(&mut mc, 0, oid), "after the session-reset resend");
    // (c) a lost reply: send on a link whose replies are discarded, then resend
    let lost = mc.client_as(1, who());
    let op = mc.op(1, oid, writes(uv)[0].1.clone());
    let _ = mc.call(1, lost, 101, op);
    assert_eq!(
        send_all(&mut mc, 1, oid, uv),
        first,
        "resend after a lost reply"
    );
    // crash restart: the PG log is persisted, the answers too
    mc.restart();
    mc.deliver(mc.map(12, 12));
    mc.run_for(Duration::from_secs(3));
    assert_eq!(
        send_all(&mut mc, 0, oid, uv),
        first,
        "resend after a restart"
    );
    assert_once(&state(&mut mc, 0, oid), "after the restart resend");
    // trim the entries into dup records (osd_min_pg_log_entries 250): 400 more writes of the same PG
    let map = mc.osds[0].osdmap().unwrap().clone();
    let pg_of = |n: &str| {
        let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
        pgwire::pgmath::object_pg(raw.seed, 32)
    };
    let seed = pg_of(oid);
    let spg = SpgT {
        pgid: PgT::new(1, seed),
        shard: denc::types::ShardId::NO_SHARD,
    };
    let other = (0..)
        .map(|i| format!("fill{i}"))
        .find(|n| pg_of(n) == seed)
        .unwrap();
    let cl = mc.client(0);
    for i in 0..400u64 {
        let op = mc.op(1, &other, vec![OsdOp::write(0, vec![i as u8; 512])]);
        let r = mc.call(0, cl, 20_000 + i, op);
        assert_eq!(r[0].1.result, 0);
    }
    let core = mc.owner(1, seed);
    let tail = mc.osds[core].pg.set.pg(spg).unwrap().log().tail();
    assert!(
        tail >= first[3].1,
        "entries trimmed into dups: tail {tail} first round {:?}",
        first[3].1
    );
    assert_eq!(
        send_all(&mut mc, 1, oid, uv),
        first,
        "resend answered from dup records"
    );
    mc.restart();
    mc.deliver(mc.map(13, 13));
    mc.run_for(Duration::from_secs(3));
    assert_eq!(
        send_all(&mut mc, 0, oid, uv),
        first,
        "dup records after a restart"
    );
    assert_once(&state(&mut mc, 0, oid), "after every resend");
    // another client with the same tids is a new request
    let cl = mc.client(1);
    let op = mc.op(1, oid, writes(uv)[0].1.clone());
    let r = mc.call(1, cl, 101, op);
    assert_eq!(r[0].1.result, 0);
    assert!(r[0].1.replay_version > first[3].1, "applied as new");
}

/// Object name of pool 1 whose PG has primary `primary` in `map`.
fn obj_of(map: &OsdMap, prefix: &str, primary: i32) -> (String, u32) {
    (0..)
        .map(|i| format!("{prefix}{i}"))
        .map(|n| {
            let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
            let seed = pgwire::pgmath::object_pg(raw.seed, 32);
            (n, seed)
        })
        .find(|(_, seed)| map.pg_to_up_acting(PgT::new(1, *seed)).acting_primary == primary)
        .unwrap()
}

/// (b) primary change: the writes were applied on osd.0 (replicated to osd.1 by the repops) and their replies lost; osd.0
/// goes down, osd.1 leads with the entries in its log: the resends to osd.1 get the original answers.
#[test]
fn resent_writes_reach_a_new_primary_that_got_the_entries_by_replication() {
    let mut p = Pair::new(2, 2);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let (oid, _) = obj_of(&map, "rep", 0);
    // the first round on osd.0 (each write waits for the replica)
    let cl = p.a.client_as(0, who());
    let mut first: Vec<(i32, denc::types::Eversion, u64)> = Vec::new();
    for k in 0..4 {
        // the guarded write_full asserts the version the third write left
        let uv = if k == 3 { first[2].2 } else { 0 };
        let (tid, ops) = writes(uv).swap_remove(k);
        let op = p.a.op(1, &oid, ops);
        let mut r = p.a.call(0, cl, tid, op);
        p.settle();
        r.extend(p.a.replies(0, cl));
        assert_eq!(r.len(), 1, "tid {tid}");
        assert_eq!(r[0].1.result, 0, "tid {tid}");
        first.push(sum(&r[0].1));
    }
    let uv = first[2].2;
    // osd.0 down: osd.1 leads
    let mut m = p.map(11, [10, 10]);
    m.osd_state[0] = osd_state::EXISTS;
    p.b.deliver(m);
    p.b.settle();
    p.b.run_for(Duration::from_secs(30));
    assert_eq!(
        send_all(&mut p.b, 1, &oid, uv),
        first,
        "resend to the new primary"
    );
    assert_once(&state(&mut p.b, 0, &oid), "on the new primary");
}

/// (b) via peering: the writes are applied on osd.0 while osd.1 is down, the following fill trims them into dup records;
/// osd.1 comes back and gets the PG log with the dup records from osd.0 (backfill: the log slice with its dups over the
/// wire), then osd.0 goes down: the resends to osd.1 are answered from the dup records it received.
#[test]
fn resent_writes_reach_a_new_primary_that_got_the_dups_through_peering() {
    let mut p = Pair::new(1, 1);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let (oid, seed) = obj_of(&map, "peer", 0);
    let spg = SpgT {
        pgid: PgT::new(1, seed),
        shard: denc::types::ShardId::NO_SHARD,
    };
    // osd.1 crashes and is marked down; osd.0 writes alone
    let mut m11 = p.map(11, [10, 10]);
    m11.osd_state[1] = osd_state::EXISTS;
    m11.osd_info[1].down_at = 11;
    p.a.deliver(m11.clone());
    p.a.run_for(Duration::from_secs(20)); // the old interval's read lease runs out
    let first = first_round(&mut p.a, 0, &oid);
    let uv = first[2].2;
    // trim them into dup records
    let other = (0..)
        .map(|i| format!("pfill{i}"))
        .find(|n| {
            let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
            pgwire::pgmath::object_pg(raw.seed, 32) == seed
        })
        .unwrap();
    let cl = p.a.client(0);
    for i in 0..400u64 {
        let op = p.a.op(1, &other, vec![OsdOp::write(0, vec![i as u8; 512])]);
        let r = p.a.call(0, cl, 30_000 + i, op);
        assert_eq!(r[0].1.result, 0);
    }
    assert!(p.a.osds[0].pg.set.pg(spg).unwrap().log().tail() >= first[3].1);
    // osd.1 restarts and is up again: peering brings its PG up to date (log with the dup records, backfill)
    p.b.restart();
    p.acc.retain(|k, _| k.0 != 1);
    p.b.deliver(m11);
    let mut m = p.map(12, [10, 12]);
    m.osd_info[1].down_at = 11;
    p.deliver(m.clone());
    p.run_for(Duration::from_secs(5));
    // osd.1 is behind the log tail: osd.0 asks for a pg_temp (itself) to backfill it; the mon (the test) grants it,
    // then drops it again once the backfill is done
    m.epoch = 13;
    m.osd_info[0].up_thru = 13;
    m.osd_info[1].up_thru = 13;
    m.pg_temp.insert(spg.pgid, vec![0]);
    p.deliver(m.clone());
    p.run_for(Duration::from_secs(30));
    m.epoch = 14;
    m.osd_info[0].up_thru = 14;
    m.osd_info[1].up_thru = 14;
    m.pg_temp.clear();
    p.deliver(m.clone());
    p.run_for(Duration::from_secs(30));
    let a_pg = p.a.osds[0].pg.set.pg(spg).unwrap();
    let b_pg = p.b.osds[0].pg.set.pg(spg).unwrap();
    assert!(
        b_pg.log()
            .find_reqid(&denc::types::OsdReqId {
                name: who(),
                tid: 101,
                inc: 0,
            })
            .is_some(),
        "osd.1 got the dup record of the append; {:?} {:?} osd.1 {} lu {} tail {} dups {}; osd.0 {} lu {} tail {} dups {}",
        a_pg.machine_state(),
        b_pg.machine_state(),
        b_pg.state_string(),
        b_pg.info().last_update,
        b_pg.log().tail(),
        b_pg.log().log.dups.len(),
        a_pg.state_string(),
        a_pg.info().last_update,
        a_pg.log().tail(),
        a_pg.log().log.dups.len(),
    );
    // osd.0 dies: osd.1 leads with what peering gave it
    m.epoch = 15;
    m.osd_info[1].up_thru = 15;
    m.osd_state[0] = osd_state::EXISTS;
    m.osd_info[0].down_at = 15;
    p.b.deliver(m);
    p.b.run_for(Duration::from_secs(30)); // incl. the read lease of the old interval
    assert_eq!(
        send_all(&mut p.b, 0, &oid, uv),
        first,
        "resend to the new primary"
    );
    assert_once(&state(&mut p.b, 0, &oid), "on the new primary");
}
