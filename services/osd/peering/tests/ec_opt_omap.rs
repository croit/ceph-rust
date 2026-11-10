// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Optimized EC (mode O, adr 0067 am. 2) omap on the PRIMARY: EC_OMAP records in the log, applied at roll-forward on
//! primary-capable shards only, read overlay of the in-flight records, clone of a head with omap, delete / recreate,
//! restart before roll-forward. All croit-flashstore-osd on the deterministic simulator (4 OSDs, isa k2m2: shard 1 is the NP shard).
mod common;
use common::*;
use denc::types::{CollT, Eversion, Ghobject, Hobject, SnapId};
use peering::{PgStoreOps, WriteEntry, WriteReq};
use replwire::oi::{ObjectInfo, flag};
use replwire::txn::{Transaction, TxnOp};
use std::collections::BTreeMap;

const POOL: u64 = 1;
const NP: usize = 1;

fn opt_cluster(seed: u64) -> Sim {
    opt_cluster_cfg(seed, |_| {})
}

fn opt_cluster_cfg(seed: u64, configure: impl Fn(&mut peering::Config)) -> Sim {
    let mut s = Sim::new(seed);
    for o in 0..4 {
        s.add_osd_cfg(o, |c| {
            c.ec_enable = ec::EcEnable::All;
            c.ec_enable_optimized = ec::EcEnable::All;
            c.ec_primary = true;
            c.ec_opt_primary = true;
            configure(c);
        });
    }
    s.run_for(50 * MS);
    s.create_pool_ec_opt(POOL, 2, 2, 4096, true, 1);
    s.run_for(2000 * MS);
    s.run_until(60_000 * MS, "ec pool clean", |s| s.pool_clean(POOL));
    s
}

#[derive(Clone, Debug)]
enum O {
    Touch,
    Set(&'static [(&'static str, &'static str)]),
    Rm(&'static [&'static str]),
    Range(&'static str, &'static str),
    Clear,
    Header(&'static str),
    Remove,
}

/// Expected omap of one object.
#[derive(Default, Clone, Debug, PartialEq)]
struct Om {
    header: Vec<u8>,
    kv: BTreeMap<Vec<u8>, Vec<u8>>,
}

fn apply(m: &mut Option<Om>, ops: &[O]) {
    for op in ops {
        match op {
            O::Touch => {
                m.get_or_insert_with(Om::default);
            }
            O::Set(kv) => {
                let m = m.get_or_insert_with(Om::default);
                for (k, v) in *kv {
                    m.kv.insert(k.as_bytes().to_vec(), v.as_bytes().to_vec());
                }
            }
            O::Rm(keys) => {
                let m = m.get_or_insert_with(Om::default);
                for k in *keys {
                    m.kv.remove(k.as_bytes());
                }
            }
            O::Range(a, z) => {
                let m = m.get_or_insert_with(Om::default);
                m.kv.retain(|k, _| !(k.as_slice() >= a.as_bytes() && k.as_slice() < z.as_bytes()));
            }
            O::Clear => {
                let m = m.get_or_insert_with(Om::default);
                m.kv.clear();
                m.header.clear();
            }
            O::Header(h) => m.get_or_insert_with(Om::default).header = h.as_bytes().to_vec(),
            O::Remove => *m = None,
        }
    }
}

fn entry(op: pgwire::LogOp, soid: &Hobject, v: Eversion) -> WriteEntry {
    WriteEntry {
        op,
        soid: soid.clone(),
        user_version: v.version,
        mtime: Default::default(),
        snaps: vec![],
        return_code: 0,
        op_returns: vec![],
        prior: None,
    }
}

/// Write the omap ops of `name` like the op layer builds them (ops in order, then object_info with FLAG_OMAP).
fn write(s: &mut Sim, name: &str, ops: &[O]) -> u64 {
    let tid = submit(s, name, ops);
    let lead = s.lead_spg(POOL, 0);
    s.wait_writes(&[tid], lead);
    tid
}

fn submit(s: &mut Sim, name: &str, ops: &[O]) -> u64 {
    let lead = s.lead_spg(POOL, 0);
    let osd = s.primary_of(lead.pgid);
    let soid = hobj(POOL, name);
    let version = s.pg(osd, lead).unwrap().next_version();
    let gh = Ghobject::head(soid.clone(), lead.shard);
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(lead));
    let ox = t.obj(&gh);
    let removed = matches!(ops.last(), Some(O::Remove));
    for op in ops {
        match op {
            O::Touch => t.push(cx, TxnOp::Touch { oid: ox }),
            O::Set(kv) => t.push(
                cx,
                TxnOp::OmapSetKeys {
                    oid: ox,
                    pairs: kv
                        .iter()
                        .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
                        .collect(),
                },
            ),
            O::Rm(keys) => t.push(
                cx,
                TxnOp::OmapRmKeys {
                    oid: ox,
                    keys: keys.iter().map(|k| k.as_bytes()).collect(),
                },
            ),
            O::Range(a, z) => t.push(
                cx,
                TxnOp::OmapRmKeyRange {
                    oid: ox,
                    first: a.as_bytes(),
                    last: z.as_bytes(),
                },
            ),
            O::Clear => t.push(cx, TxnOp::OmapClear { oid: ox }),
            O::Header(h) => t.push(
                cx,
                TxnOp::OmapSetHeader {
                    oid: ox,
                    header: h.as_bytes(),
                },
            ),
            O::Remove => t.push(cx, TxnOp::Remove { oid: ox }),
        }
    }
    let oi;
    if !removed {
        oi = denc::to_vec(&ObjectInfo {
            soid: soid.clone(),
            version,
            size: 0,
            user_version: version.version,
            flags: flag::OMAP,
            ..Default::default()
        })
        .unwrap();
        t.push(
            cx,
            TxnOp::SetAttr {
                oid: ox,
                name: b"_",
                value: &oi,
            },
        );
    }
    let lop = if removed {
        pgwire::LogOp::DELETE
    } else {
        pgwire::LogOp::MODIFY
    };
    let req = WriteReq {
        entries: vec![entry(lop, &soid, version)],
        txn_data: t.encode_v9().unwrap().into(),
        ..Default::default()
    };
    s.submit_raw(POOL, 0, req).expect("accepted")
}

/// Clone of the head `name` to its clone object (snap 5), committed source state, like the op layer's make_writeable.
fn clone_head(s: &mut Sim, name: &str) -> (u64, Hobject) {
    let lead = s.lead_spg(POOL, 0);
    let osd = s.primary_of(lead.pgid);
    let head = hobj(POOL, name);
    let mut cl = head.clone();
    cl.snap = SnapId(5);
    let version = s.pg(osd, lead).unwrap().next_version();
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(lead));
    let a = t.obj(&Ghobject::head(head.clone(), lead.shard));
    let b = t.obj(&Ghobject::head(cl.clone(), lead.shard));
    t.push(
        cx,
        TxnOp::Clone {
            oid: a,
            dest_oid: b,
        },
    );
    let req = WriteReq {
        entries: vec![entry(pgwire::LogOp::CLONE, &cl, version)],
        txn_data: t.encode_v9().unwrap().into(),
        ..Default::default()
    };
    (s.submit_raw(POOL, 0, req).expect("accepted"), cl)
}

/// The omap the primary serves: its stored omap under the in-flight overlay (what `PgEnv` does for the op layer).
fn served(s: &Sim, h: &Hobject) -> Option<Om> {
    let lead = s.lead_spg(POOL, 0);
    let osd = s.primary_of(lead.pgid);
    let pg = s.pg(osd, lead).unwrap();
    let ov = pg.ec_omap_overlay(h).expect("overlay");
    let obj = s.nodes[&osd].store.pgs.get(&lead)?.objects.get(h)?.clone();
    let header = if ov.cleared() {
        Vec::new()
    } else {
        obj.omap_header.clone()
    };
    let (kv, more) = ov
        .range(
            |after, n| {
                let rest: Vec<_> = obj
                    .omap
                    .iter()
                    .filter(|(k, _)| after.is_none_or(|a| k.as_slice() > a))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                let more = rest.len() > n;
                Ok((rest.into_iter().take(n).collect(), more))
            },
            None,
            b"",
            usize::MAX,
            usize::MAX,
        )
        .unwrap();
    assert!(!more);
    Some(Om {
        header: ov.header(header),
        kv: kv.into_iter().collect(),
    })
}

/// The omap of `h` replayed from its whole log history on an empty object: what the EC_OMAP records emitted so far
/// say, independent of how far the roll-forward got (the Sim store lags the in-memory cursors by its commit latency).
fn history(s: &Sim, h: &Hobject) -> Option<Om> {
    let lead = s.lead_spg(POOL, 0);
    let osd = s.primary_of(lead.pgid);
    let es = s.pg(osd, lead).unwrap().log().entries();
    if es
        .iter()
        .rev()
        .find(|e| e.soid == *h)
        .is_none_or(|e| e.is_delete())
    {
        return None;
    }
    let ov = peering::ecomap::Overlay::of(&peering::ecomap::pending(es, h).expect("pending"));
    let (kv, _) = ov
        .range(
            |_, _| Ok((Vec::new(), false)),
            None,
            b"",
            usize::MAX,
            usize::MAX,
        )
        .unwrap();
    Some(Om {
        header: ov.header(Vec::new()),
        kv: kv.into_iter().collect(),
    })
}

/// Stored omap of `h` per acting position (`None` = object absent there).
fn stored(s: &Sim, h: &Hobject) -> Vec<Option<Om>> {
    let acting = s.acting_of(denc::types::PgT::new(POOL, 0));
    (0..acting.len())
        .map(|pos| {
            let sp = s.spg_on(acting[pos], POOL, 0);
            s.nodes[&acting[pos]]
                .store
                .pgs
                .get(&sp)
                .and_then(|p| p.objects.get(h))
                .map(|o| Om {
                    header: o.omap_header.clone(),
                    kv: o.omap.clone(),
                })
        })
        .collect()
}

fn rolled_forward(s: &Sim) -> bool {
    let acting = s.acting_of(denc::types::PgT::new(POOL, 0));
    acting.iter().all(|o| {
        let pg = s.pg(*o, s.spg_on(*o, POOL, 0)).unwrap();
        pg.log().log.can_rollback_to == pg.log().head()
    })
}

fn settle(s: &mut Sim) {
    s.run_until(30_000 * MS, "rolled forward everywhere", rolled_forward);
    s.run_for(100 * MS);
}

/// PC shards hold exactly `want`, the NP shard no omap at all.
fn assert_stored(s: &Sim, h: &Hobject, want: &Option<Om>) {
    for (pos, got) in stored(s, h).into_iter().enumerate() {
        if pos == NP {
            assert!(
                got.as_ref().is_none_or(|o| *o == Om::default()),
                "NP shard holds omap: {got:?}"
            );
        } else {
            assert_eq!(&got, want, "shard {pos}");
        }
    }
}

#[test]
fn ec_opt_omap_overlay_then_roll_forward() {
    let mut s = opt_cluster(71);
    let h = hobj(POOL, "o1");
    let mut m = None;
    let steps: Vec<Vec<O>> = vec![
        vec![
            O::Touch,
            O::Set(&[("a", "1"), ("b", "2"), ("c", "3")]),
            O::Header("h1"),
        ],
        vec![O::Set(&[("b", "22"), ("d", "4")]), O::Rm(&["a"])],
        vec![O::Range("c", "e")],
        // clear + header in one op: the header is set AFTER the clear (separate records, UI-3)
        vec![O::Clear, O::Header("h2"), O::Set(&[("z", "9")])],
        // set, clear, set in one op
        vec![O::Set(&[("q", "1")]), O::Clear, O::Set(&[("r", "2")])],
        // empty range end removes nothing (UI-5, literal half-open)
        vec![O::Range("r", "")],
    ];
    for ops in &steps {
        apply(&mut m, ops);
        write(&mut s, "o1", ops);
        // before roll-forward the primary serves the overlay, the stored omap lags
        assert_eq!(history(&s, &h), m, "records after {ops:?}");
    }
    assert_eq!(
        m.as_ref().unwrap().kv.keys().cloned().collect::<Vec<_>>(),
        vec![b"r".to_vec()]
    );
    assert_eq!(m.as_ref().unwrap().header, b"");
    settle(&mut s);
    assert_stored(&s, &h, &m);
    assert_eq!(served(&s, &h), m);
}

#[test]
fn ec_opt_omap_delete_and_recreate() {
    let mut s = opt_cluster(72);
    let h = hobj(POOL, "d1");
    let mut m = None;
    for ops in [
        vec![O::Touch, O::Set(&[("old", "1")]), O::Header("hold")],
        vec![O::Remove],
        vec![O::Touch, O::Set(&[("new", "2")])],
    ] {
        apply(&mut m, &ops);
        write(&mut s, "d1", &ops);
        assert_eq!(history(&s, &h), m);
    }
    settle(&mut s);
    assert_stored(&s, &h, &m);
    // no stash of the deleted incarnation is left, its omap was applied to it (and dropped with it)
    let acting = s.acting_of(denc::types::PgT::new(POOL, 0));
    for o in acting {
        let sp = s.spg_on(o, POOL, 0);
        assert!(s.nodes[&o].store.pgs[&sp].stash.is_empty());
    }
    // delete in the last step: the object is gone everywhere
    write(&mut s, "d1", &[O::Remove]);
    settle(&mut s);
    assert_stored(&s, &h, &None);
}

#[test]
fn ec_opt_primary_rollback_delete_preserves_acknowledged_omap() {
    let mut s = opt_cluster_cfg(79, |c| c.ec_rf_defer_ns = 20 * peering::SEC);
    let h = hobj(POOL, "rollback-omap");
    write(
        &mut s,
        "rollback-omap",
        &[O::Touch, O::Set(&[("base", "0")])],
    );
    settle(&mut s);
    write(
        &mut s,
        "rollback-omap",
        &[O::Set(&[("acked", "1")]), O::Header("ack")],
    );
    let lead = s.lead_spg(POOL, 0);
    let primary = s.primary_of(lead.pgid);
    let acknowledged = s.pg(primary, lead).unwrap().log().head();
    assert!(s.pg(primary, lead).unwrap().log().log.can_rollback_to < acknowledged);
    // Persist the delete on the primary only: it must remain rollbackable on the next peering.
    for peer in s.acting_of(lead.pgid) {
        if peer != primary {
            s.blocked.insert((primary, peer));
        }
    }
    let delete = submit(&mut s, "rollback-omap", &[O::Remove]);
    s.run_for(5 * MS);
    assert!(
        !s.acked
            .iter()
            .any(|(spg, tid, _)| *spg == lead && *tid == delete)
    );
    let mut store = s.nodes[&primary].store.clone();
    let mut persisted = store.load_pg(lead).unwrap();
    assert!(persisted.log.head > acknowledged);
    let mut log = peering::IndexedLog::new(persisted.log);
    let mut missing = peering::MissingSet::from_wire(persisted.missing);
    let ctx = peering::ecroll::EcCtx::of(
        s.map().pools[&POOL].ec.as_ref().unwrap(),
        lead.shard.0 as u32,
    );
    let mut ops = Vec::new();
    peering::plog::rewind_divergent_log_ec(
        &mut log,
        &mut persisted.info,
        &mut missing,
        &mut ops,
        acknowledged,
        ctx,
    )
    .unwrap();
    assert!(
        missing.is_empty(),
        "rollback restores the local copy without a recovery fetch"
    );
    store.submit(lead, &peering::StoreTxn { ops });
    let restored = &store.objects(lead)[&h];
    assert_eq!(restored.omap.get(b"acked".as_slice()).unwrap(), b"1");
    assert_eq!(restored.omap.get(b"base".as_slice()).unwrap(), b"0");
    assert_eq!(restored.omap_header, b"ack");
}

#[test]
fn ec_opt_omap_clone_of_head_replays_unrolled_records() {
    let mut s = opt_cluster(73);
    let h = hobj(POOL, "c1");
    let mut m = None;
    // part of the omap is rolled forward, part is in flight when the clone is made
    let ops = vec![O::Touch, O::Set(&[("a", "1"), ("b", "2")]), O::Header("h0")];
    apply(&mut m, &ops);
    write(&mut s, "c1", &ops);
    settle(&mut s);
    let ops = vec![O::Set(&[("c", "3")]), O::Rm(&["a"])];
    apply(&mut m, &ops);
    let t1 = submit(&mut s, "c1", &ops);
    let at_clone = m.clone();
    // no waiting: the clone is generated while the two records are not rolled forward
    let (t2, cl) = clone_head(&mut s, "c1");
    let lead = s.lead_spg(POOL, 0);
    s.wait_writes(&[t1, t2], lead);
    // the head moves on after the clone: the clone keeps the state at clone time
    let ops = vec![O::Set(&[("d", "4")]), O::Clear, O::Set(&[("e", "5")])];
    apply(&mut m, &ops);
    write(&mut s, "c1", &ops);
    let replay = peering::ecomap::pending(
        s.pg(s.primary_of(s.lead_spg(POOL, 0).pgid), s.lead_spg(POOL, 0))
            .unwrap()
            .log()
            .entries(),
        &cl,
    )
    .unwrap();
    assert_eq!(
        replay.len(),
        1,
        "the clone entry carries the unrolled record of its source"
    );
    assert_eq!(history(&s, &h), m);
    settle(&mut s);
    assert_stored(&s, &cl, &at_clone);
    assert_stored(&s, &h, &m);
}

#[test]
fn ec_opt_omap_survives_restart_before_roll_forward() {
    let mut s = opt_cluster(74);
    let lead = s.lead_spg(POOL, 0);
    let h = hobj(POOL, "r1");
    let mut m = None;
    for ops in [
        vec![O::Touch, O::Set(&[("a", "1")])],
        vec![O::Set(&[("b", "2")])],
        // a later delete + recreate of the same object (UI-4: the shard must not target the new live object)
        vec![O::Remove],
        vec![O::Touch, O::Set(&[("n", "7")])],
    ] {
        apply(&mut m, &ops);
        write(&mut s, "r1", &ops);
    }
    // a parity shard goes down right away (no roll-forward yet) and comes back
    let victim = s.acting_of(lead.pgid)[3];
    s.kill(victim);
    s.run_for(3000 * MS);
    let ops = vec![O::Set(&[("m", "8")])];
    apply(&mut m, &ops);
    write(&mut s, "r1", &ops);
    s.restart(victim);
    s.run_until(60_000 * MS, "clean after return", |s| s.pool_clean(POOL));
    settle(&mut s);
    assert_stored(&s, &h, &m);
    // restart of every shard in turn: contents stay
    for pos in [2usize, 3, 1] {
        let o = s.acting_of(lead.pgid)[pos];
        s.kill(o);
        s.run_for(3000 * MS);
        s.restart(o);
        s.run_until(60_000 * MS, "clean", |s| s.pool_clean(POOL));
        settle(&mut s);
        assert_stored(&s, &h, &m);
        assert_eq!(served(&s, &h), m);
    }
}
