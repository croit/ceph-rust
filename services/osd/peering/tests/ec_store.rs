// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `MemStore` model of the EC shard store contract (adr 0039/0040): generation objects, `StoreOp::Shard`,
//! rollback cursors, listing/scrub invisibility of stash objects, shard validation.
use denc::types::*;
use peering::store::{MemStore, PgStoreOps, ShardOp, StoreOp, StoreTxn};
use pgwire::{LogEntry, LogOp};
use replwire::txn::*;

const SH: i8 = 2;

fn spg() -> SpgT {
    SpgT {
        pgid: PgT::new(3, 0),
        shard: ShardId(SH),
    }
}
fn h(n: &str) -> Hobject {
    Hobject::new(n.as_bytes(), SnapId::NOSNAP, 9, 3, b"")
}
fn g(o: &Hobject, generation: u64, shard: i8) -> Ghobject {
    Ghobject::new(o.clone(), generation, ShardId(shard))
}
fn ev(v: u64) -> Eversion {
    Eversion::new(4, v)
}
fn ent(o: &Hobject, v: u64) -> LogEntry {
    LogEntry::new(LogOp::MODIFY, o.clone(), ev(v), ev(v - 1))
}
fn txn<'a>(f: impl FnOnce(&mut Transaction<'a>, Cx)) -> StoreOp {
    let mut t = Transaction::new();
    let c = t.coll(&CollT::Pg(spg()));
    f(&mut t, c);
    StoreOp::ApplyTxn {
        middle: Default::default(),
        data: t.encode_v9().unwrap().into(),
    }
}
fn store() -> MemStore {
    let mut m = MemStore::new();
    m.submit(
        spg(),
        &StoreTxn {
            ops: vec![StoreOp::CreatePg],
        },
    );
    m
}
fn submit(m: &mut MemStore, ops: Vec<StoreOp>) {
    m.submit(spg(), &StoreTxn { ops });
}

#[test]
fn generations_are_distinct_objects_invisible_to_listing() {
    let mut m = store();
    let a = h("a");
    submit(
        &mut m,
        vec![txn(|t, c| {
            let (live, st) = (t.obj(&g(&a, u64::MAX, SH)), t.obj(&g(&a, 7, SH)));
            t.push(
                c,
                TxnOp::Write {
                    oid: live,
                    off: 0,
                    data: Data::new(b"0123456789"),
                },
            );
            t.push(
                c,
                TxnOp::SetAttr {
                    oid: live,
                    name: b"_",
                    value: b"oi__",
                },
            );
            t.push(c, TxnOp::Touch { oid: st });
            t.push(
                c,
                TxnOp::CloneRange2 {
                    oid: live,
                    dest_oid: st,
                    src_off: 2,
                    len: 4,
                    dest_off: 2,
                },
            );
            t.push(
                c,
                TxnOp::Write {
                    oid: live,
                    off: 2,
                    data: Data::new(b"XXXX"),
                },
            );
        })],
    );
    let live = &m.objects(spg())[&a];
    assert_eq!(live.data, b"01XXXX6789");
    let stash = m.stash(spg());
    assert_eq!(stash[&(a.clone(), 7)].data, [0, 0, b'2', b'3', b'4', b'5']);
    // not in objects(), stats, scrub, ec_read of the live name
    assert_eq!(m.objects(spg()).len(), 1);
    let p = m.build_scrub_map(spg(), &Hobject::MIN(), &Hobject::MAX(), true, 10, u64::MAX);
    assert_eq!(p.objects.len(), 1);
    assert_eq!(m.ec_read(spg(), &a, 0, 100).unwrap().1, 10);
}

#[test]
fn shard_ops_semantics_and_missing_sources() {
    let mut m = store();
    let a = h("a");
    submit(
        &mut m,
        vec![txn(|t, c| {
            let live = t.obj(&g(&a, u64::MAX, SH));
            t.push(
                c,
                TxnOp::Write {
                    oid: live,
                    off: 0,
                    data: Data::new(b"live"),
                },
            );
            t.push(
                c,
                TxnOp::SetAttr {
                    oid: live,
                    name: b"k",
                    value: b"v",
                },
            );
        })],
    );
    // no-ops on missing sources: nothing appears
    submit(
        &mut m,
        vec![StoreOp::Shard(vec![
            ShardOp::Rename {
                soid: a.clone(),
                from_gen: 1,
                to_gen: 2,
            },
            ShardOp::CloneRange {
                soid: a.clone(),
                from_gen: 1,
                to_gen: 2,
                off: 0,
                len: 4,
            },
            ShardOp::SetAttrs {
                soid: a.clone(),
                generation: 5,
                attrs: vec![(b"x".to_vec(), Some(b"y".to_vec()))],
            },
            ShardOp::Truncate {
                soid: a.clone(),
                generation: 5,
                size: 3,
            },
            ShardOp::Remove {
                soid: a.clone(),
                generation: 5,
            },
        ])],
    );
    assert!(m.stash(spg()).is_empty());
    // rename live -> stash 3, then back over a recreated live (replaces it)
    submit(
        &mut m,
        vec![StoreOp::Shard(vec![ShardOp::Rename {
            soid: a.clone(),
            from_gen: u64::MAX,
            to_gen: 3,
        }])],
    );
    assert!(m.objects(spg()).is_empty());
    assert_eq!(m.stash(spg())[&(a.clone(), 3)].data, b"live");
    submit(
        &mut m,
        vec![
            txn(|t, c| {
                let live = t.obj(&g(&a, u64::MAX, SH));
                t.push(
                    c,
                    TxnOp::Write {
                        oid: live,
                        off: 0,
                        data: Data::new(b"newer"),
                    },
                );
            }),
            StoreOp::Shard(vec![
                ShardOp::Remove {
                    soid: a.clone(),
                    generation: u64::MAX,
                },
                ShardOp::Rename {
                    soid: a.clone(),
                    from_gen: 3,
                    to_gen: u64::MAX,
                },
                ShardOp::SetAttrs {
                    soid: a.clone(),
                    generation: u64::MAX,
                    attrs: vec![(b"k".to_vec(), None), (b"n".to_vec(), Some(b"1".to_vec()))],
                },
                ShardOp::Truncate {
                    soid: a.clone(),
                    generation: u64::MAX,
                    size: 2,
                },
            ]),
        ],
    );
    let o = &m.objects(spg())[&a];
    assert_eq!(o.data, b"li");
    assert_eq!(o.xattrs.len(), 2 - 1);
    assert_eq!(o.xattrs[b"n".as_slice()], b"1");
    assert!(m.stash(spg()).is_empty());
}

#[test]
fn txn_with_foreign_shard_object_is_rejected_atomically() {
    let mut m = store();
    let a = h("a");
    submit(
        &mut m,
        vec![txn(|t, c| {
            let ok = t.obj(&g(&a, u64::MAX, SH));
            let bad = t.obj(&g(&h("b"), u64::MAX, SH + 1));
            t.push(c, TxnOp::Touch { oid: ok });
            t.push(c, TxnOp::Touch { oid: bad });
        })],
    );
    assert_eq!(m.bad_txns, 1);
    assert!(m.objects(spg()).is_empty());
}

#[test]
fn cursors_and_keep_append() {
    let mut m = store();
    let a = h("a");
    submit(
        &mut m,
        vec![
            StoreOp::LogAppend(vec![ent(&a, 1)]),
            StoreOp::LogAppendKeep(vec![ent(&a, 2), ent(&a, 3)]),
        ],
    );
    let l = m.load_pg(spg()).unwrap().log;
    assert_eq!(
        (l.head, l.can_rollback_to, l.rollback_info_trimmed_to),
        (ev(3), ev(1), ev(1))
    );
    submit(
        &mut m,
        vec![StoreOp::LogCursors {
            can_rollback_to: ev(3),
            rollback_info_trimmed_to: ev(2),
        }],
    );
    let l = m.load_pg(spg()).unwrap().log;
    assert_eq!(
        (l.can_rollback_to, l.rollback_info_trimmed_to),
        (ev(3), ev(2))
    );
    // rewind clamps both
    submit(&mut m, vec![StoreOp::LogRewind { to: ev(2) }]);
    let l = m.load_pg(spg()).unwrap().log;
    assert_eq!(
        (l.head, l.can_rollback_to, l.rollback_info_trimmed_to),
        (ev(2), ev(2), ev(2))
    );
}
