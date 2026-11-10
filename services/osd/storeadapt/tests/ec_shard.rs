// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! EC shard role on the NVMe store (adr 0039/0040): generation (stash) objects, `StoreOp::Shard`, rollback cursors,
//! listing/scrub/removal rules, `ec_read`, EC scrub digests and crash safety. `MemStore` is the reference.
mod common;
use common::*;
use denc::types::*;
use peering::store::{MemStore, PgStoreOps, ShardOp, StoreOp, StoreTxn};
use pgwire::{LogEntry, LogOp};
use replwire::ecscrub::encode_hinfo;
use replwire::scrubmsgs::{DIGEST_SEED, data_digest_update};
use replwire::txn::*;
use std::collections::BTreeMap;
use store::dev::{CrashPolicy, SimClock, SimDisk};
use store::fsck::fsck;
use store::obj::{StoreCfg, onode::fsck_refs};
use store::shard::ShardCfg;

type Kv = BTreeMap<Vec<u8>, Vec<u8>>;
type StashMap = BTreeMap<(Hobject, u64), (Vec<u8>, Kv, Kv)>;
const SHARD: i8 = 1;
const CHUNK: usize = 4096;
fn scrub_all_ec(
    ad: &Ad,
    pg: SpgT,
    deep: bool,
    mode: replwire::ecscrub::EcScrubMode,
) -> peering::ScrubPart {
    let mut result = peering::ScrubPart::default();
    let mut cursor = Hobject::MIN();
    for _ in 0..10_000 {
        ad.poll_store(&mut Vec::new());
        ad.with_store(|s| s.idle());
        let p = ad.build_scrub_map_ec(
            pg,
            &cursor,
            &Hobject::MAX(),
            deep,
            100,
            u64::MAX,
            mode,
            CHUNK as u32,
        );
        assert!(p.error.is_none());
        result.objects.extend(p.objects);
        match p.next {
            Some(next) => cursor = next,
            None => return result,
        }
    }
    panic!("EC scrub timed out");
}

fn ec_spg() -> SpgT {
    SpgT {
        pgid: PgT::new(2, 0),
        shard: ShardId(SHARD),
    }
}

fn hobj(name: &str) -> Hobject {
    Hobject::new(name.as_bytes(), SnapId::NOSNAP, 0x11, 2, b"")
}

fn gho(h: &Hobject, generation: u64) -> Ghobject {
    Ghobject::new(h.clone(), generation, ShardId(SHARD))
}

fn ent(op: LogOp, h: &Hobject, v: u64) -> LogEntry {
    let mut e = LogEntry::new(
        op,
        h.clone(),
        Eversion::new(5, v),
        Eversion::new(5, v.saturating_sub(1)),
    );
    e.user_version = v;
    e
}

fn ev(v: u64) -> Eversion {
    Eversion::new(5, v)
}

fn apply<'a>(f: impl FnOnce(&mut Transaction<'a>, Cx)) -> StoreOp {
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(ec_spg()));
    f(&mut t, cx);
    StoreOp::ApplyTxn {
        middle: Default::default(),
        data: t.encode_v9().unwrap().into(),
    }
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Scripted shard history over objects A and B: create, overwrite with extent stash, delete-stash, roll-forward,
/// divergent rewind with rollback, truncate/attrs, cursors. Every txn is one atomic StoreTxn.
fn script() -> Vec<StoreTxn> {
    let (a, b) = (hobj("a"), hobj("b"));
    let hinfo = encode_hinfo(2 * CHUNK as u64, &[1, 2, 3]);
    let t = |ops: Vec<StoreOp>| StoreTxn { ops };
    let d1 = pattern(2 * CHUNK, 1);
    let d2 = pattern(CHUNK, 2);
    let d3 = pattern(CHUNK, 3);
    vec![
        // 1: create A
        t(vec![
            StoreOp::LogAppendKeep(vec![ent(LogOp::MODIFY, &a, 1)]),
            apply(|t, c| {
                let o = t.obj(&gho(&a, Ghobject::NO_GEN));
                t.push(c, TxnOp::Touch { oid: o });
                t.push(
                    c,
                    TxnOp::Write {
                        oid: o,
                        off: 0,
                        data: Data::new(&d1),
                    },
                );
                t.push(
                    c,
                    TxnOp::SetAttr {
                        oid: o,
                        name: b"hinfo_key",
                        value: &hinfo,
                    },
                );
                t.push(
                    c,
                    TxnOp::SetAttr {
                        oid: o,
                        name: b"_",
                        value: b"oi1",
                    },
                );
            }),
        ]),
        // 2: overwrite first chunk of A, stash the old bytes under generation 2
        t(vec![
            StoreOp::LogAppendKeep(vec![ent(LogOp::MODIFY, &a, 2)]),
            apply(|t, c| {
                let (live, st) = (t.obj(&gho(&a, Ghobject::NO_GEN)), t.obj(&gho(&a, 2)));
                t.push(c, TxnOp::Touch { oid: st });
                t.push(
                    c,
                    TxnOp::CloneRange2 {
                        oid: live,
                        dest_oid: st,
                        src_off: 0,
                        len: CHUNK as u64,
                        dest_off: 0,
                    },
                );
                t.push(
                    c,
                    TxnOp::Write {
                        oid: live,
                        off: 0,
                        data: Data::new(&d2),
                    },
                );
                t.push(
                    c,
                    TxnOp::SetAttr {
                        oid: live,
                        name: b"_",
                        value: b"oi2",
                    },
                );
            }),
        ]),
        // 3: create B
        t(vec![
            StoreOp::LogAppendKeep(vec![ent(LogOp::MODIFY, &b, 3)]),
            apply(|t, c| {
                let o = t.obj(&gho(&b, Ghobject::NO_GEN));
                t.push(
                    c,
                    TxnOp::Write {
                        oid: o,
                        off: 0,
                        data: Data::new(&d3),
                    },
                );
            }),
        ]),
        // 4: delete A: the live object is renamed to its stash generation
        t(vec![
            StoreOp::LogAppendKeep(vec![ent(LogOp::DELETE, &a, 4)]),
            apply(|t, c| {
                let (live, st) = (t.obj(&gho(&a, Ghobject::NO_GEN)), t.obj(&gho(&a, 4)));
                t.push(
                    c,
                    TxnOp::CollMoveRename {
                        oid: live,
                        dest_cid: c,
                        dest_oid: st,
                    },
                );
            }),
        ]),
        // 5: roll forward entry 2: cursors move, its extent stash disappears
        t(vec![
            StoreOp::Shard(vec![ShardOp::Remove {
                soid: a.clone(),
                generation: 2,
            }]),
            StoreOp::LogCursors {
                can_rollback_to: ev(2),
                rollback_info_trimmed_to: ev(2),
            },
        ]),
        // 6: the delete (4) is divergent: roll it back (remove live, stash -> live), rewind the log to 3
        t(vec![
            StoreOp::LogRewind { to: ev(3) },
            StoreOp::Shard(vec![
                ShardOp::Remove {
                    soid: a.clone(),
                    generation: Ghobject::NO_GEN,
                },
                ShardOp::Rename {
                    soid: a.clone(),
                    from_gen: 4,
                    to_gen: Ghobject::NO_GEN,
                },
                // missing source: no-ops
                ShardOp::Rename {
                    soid: a.clone(),
                    from_gen: 77,
                    to_gen: Ghobject::NO_GEN,
                },
                ShardOp::CloneRange {
                    soid: a.clone(),
                    from_gen: 78,
                    to_gen: Ghobject::NO_GEN,
                    off: 0,
                    len: 8,
                },
            ]),
        ]),
        // 7: next entry (append + attrs), old attrs restored/removed by Shard ops in one txn
        t(vec![
            StoreOp::LogAppendKeep(vec![ent(LogOp::MODIFY, &b, 4)]),
            apply(|t, c| {
                let (live, st) = (t.obj(&gho(&b, Ghobject::NO_GEN)), t.obj(&gho(&b, 4)));
                t.push(c, TxnOp::Touch { oid: st });
                t.push(
                    c,
                    TxnOp::CloneRange2 {
                        oid: live,
                        dest_oid: st,
                        src_off: 0,
                        len: 100,
                        dest_off: 0,
                    },
                );
                t.push(
                    c,
                    TxnOp::Write {
                        oid: live,
                        off: CHUNK as u64,
                        data: Data::new(&d3),
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
            }),
        ]),
        // 8: roll back entry 4 of B: truncate (APPEND), restore bytes, drop attr, remove stash
        t(vec![
            StoreOp::LogRewind { to: ev(3) },
            StoreOp::Shard(vec![
                ShardOp::Truncate {
                    soid: b.clone(),
                    generation: Ghobject::NO_GEN,
                    size: CHUNK as u64,
                },
                ShardOp::CloneRange {
                    soid: b.clone(),
                    from_gen: 4,
                    to_gen: Ghobject::NO_GEN,
                    off: 0,
                    len: 100,
                },
                ShardOp::SetAttrs {
                    soid: b.clone(),
                    generation: Ghobject::NO_GEN,
                    attrs: vec![(b"k".to_vec(), None), (b"z".to_vec(), Some(b"zz".to_vec()))],
                },
                ShardOp::Remove {
                    soid: b.clone(),
                    generation: 4,
                },
            ]),
            StoreOp::LogCursors {
                can_rollback_to: ev(3),
                rollback_info_trimmed_to: ev(3),
            },
        ]),
        // 9: stash an object of a later version again, cursors stay behind head
        t(vec![
            StoreOp::LogAppendKeep(vec![ent(LogOp::MODIFY, &a, 5), ent(LogOp::MODIFY, &b, 6)]),
            apply(|t, c| {
                let (live, st) = (t.obj(&gho(&a, Ghobject::NO_GEN)), t.obj(&gho(&a, 5)));
                t.push(c, TxnOp::Touch { oid: st });
                t.push(
                    c,
                    TxnOp::CloneRange2 {
                        oid: live,
                        dest_oid: st,
                        src_off: 0,
                        len: CHUNK as u64,
                        dest_off: 0,
                    },
                );
            }),
        ]),
        // 10: mode O roll-forward of entries 5 and 6: EC_OMAP on the stash generation (a,5) and the live B, a missing
        // generation (no-op), cursors move in the same txn
        t(vec![
            StoreOp::Shard(vec![
                ShardOp::Omap {
                    soid: a.clone(),
                    generation: 5,
                    omap: ec::moddesc::EcOmap {
                        clear: false,
                        header: Some(b"h".to_vec()),
                        ups: vec![ec::moddesc::OmapUp::Insert(vec![(
                            b"k".to_vec(),
                            b"v".to_vec(),
                        )])],
                    },
                },
                ShardOp::Omap {
                    soid: b.clone(),
                    generation: Ghobject::NO_GEN,
                    omap: ec::moddesc::EcOmap {
                        clear: true,
                        header: None,
                        ups: vec![ec::moddesc::OmapUp::Insert(vec![(
                            b"x".to_vec(),
                            vec![7; 300],
                        )])],
                    },
                },
                ShardOp::Omap {
                    soid: b.clone(),
                    generation: 66,
                    omap: Default::default(),
                },
            ]),
            StoreOp::LogCursors {
                can_rollback_to: ev(6),
                rollback_info_trimmed_to: ev(6),
            },
        ]),
    ]
}

fn ec_pg_create(mem: &mut MemStore, ad: &Ad) {
    let s = ec_spg();
    mem.submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::CreatePg],
        },
    );
    ad.submit_create(s);
}

/// `(hobject, generation) -> (data, xattrs)` of every stash object of the adapter's PG.
fn ad_stash(ad: &Ad, s: SpgT) -> StashMap {
    let c = CollT::Pg(s);
    ad.with_store(|st| {
        let mut out = BTreeMap::new();
        let mut cur = Ghobject::MIN();
        loop {
            let (v, n) = st.list(&c, &cur, None, 64).unwrap();
            for g in v {
                if g.generation == Ghobject::NO_GEN {
                    continue;
                }
                let size = st.stat(&c, &g).unwrap().unwrap().size;
                let data = st.read(&c, &g, 0, size).unwrap();
                let attrs = st.getattrs(&c, &g).unwrap().into_iter().collect();
                let omap = st.omap_all(&c, &g).unwrap();
                out.insert((g.hobj.clone(), g.generation), (data, attrs, omap));
            }
            match n {
                Some(x) => cur = x,
                None => return out,
            }
        }
    })
}

fn mem_stash(mem: &MemStore, s: SpgT) -> StashMap {
    mem.stash(s)
        .into_iter()
        .map(|(k, o)| (k, (o.data, o.xattrs, o.omap)))
        .collect()
}

fn same_all(mem: &MemStore, ad: &Ad, ctx: &str) {
    let s = ec_spg();
    assert_same(mem, ad, s, ctx);
    assert_same_objects(mem, ad, s, ctx);
    assert_eq!(mem_stash(mem, s), ad_stash(ad, s), "{ctx}: stash objects");
}

#[test]
fn header_created_object_receives_following_shard_attributes() {
    let (_disk, ad, _) = new_adapter(64, 1, 73);
    let mut mem = MemStore::new();
    ec_pg_create(&mut mem, &ad);
    let h = hobj("header-created");
    let txn = StoreTxn {
        ops: vec![
            apply(|t, c| {
                let oid = t.obj(&gho(&h, Ghobject::NO_GEN));
                t.push(
                    c,
                    TxnOp::OmapSetHeader {
                        oid,
                        header: b"header",
                    },
                );
            }),
            StoreOp::Shard(vec![ShardOp::SetAttrs {
                soid: h.clone(),
                generation: Ghobject::NO_GEN,
                attrs: vec![(b"_".to_vec(), Some(b"restored metadata".to_vec()))],
            }]),
        ],
    };
    mem.submit(ec_spg(), &txn);
    ad.try_submit(ec_spg(), &txn).unwrap();
    same_all(&mem, &ad, "header-created object");
    assert_eq!(
        ad.object(ec_spg(), &h).unwrap().xattrs[b"_".as_slice()],
        b"restored metadata"
    );
}

#[test]
fn missing_rename_does_not_create_following_shard_destination() {
    let (_disk, ad, _) = new_adapter(64, 1, 74);
    let mut mem = MemStore::new();
    ec_pg_create(&mut mem, &ad);
    let h = hobj("missing-rename");
    let txn = StoreTxn {
        ops: vec![
            apply(|t, c| {
                let oid = t.obj(&gho(&h, 5));
                let dest_oid = t.obj(&gho(&h, Ghobject::NO_GEN));
                t.push(c, TxnOp::TryRename { oid, dest_oid });
            }),
            StoreOp::Shard(vec![ShardOp::SetAttrs {
                soid: h.clone(),
                generation: Ghobject::NO_GEN,
                attrs: vec![(b"_".to_vec(), Some(b"must not create".to_vec()))],
            }]),
        ],
    };
    mem.submit(ec_spg(), &txn);
    ad.try_submit(ec_spg(), &txn).unwrap();
    same_all(&mem, &ad, "missing rename source");
    assert!(ad.object(ec_spg(), &h).is_none());
}

#[test]
fn temp_collection_does_not_supply_shard_object_existence() {
    let (_disk, ad, _) = new_adapter(64, 1, 75);
    ad.submit_create(ec_spg());
    let h = hobj("temp-only");
    let txn = StoreTxn {
        ops: vec![
            apply(|t, _| {
                let temp = t.coll(&CollT::PgTemp(ec_spg()));
                let oid = t.obj(&gho(&h, Ghobject::NO_GEN));
                t.push(temp, TxnOp::Touch { oid });
            }),
            StoreOp::Shard(vec![ShardOp::SetAttrs {
                soid: h.clone(),
                generation: Ghobject::NO_GEN,
                attrs: vec![(b"_".to_vec(), Some(b"must not create".to_vec()))],
            }]),
        ],
    };
    ad.try_submit(ec_spg(), &txn).unwrap();
    assert!(ad.object(ec_spg(), &h).is_none());
    ad.with_store(|st| {
        assert!(
            st.stat(&CollT::PgTemp(ec_spg()), &gho(&h, Ghobject::NO_GEN))
                .unwrap()
                .is_some()
        );
    });
}

fn rollback_truncate_delete_restores_acknowledged_object(optimized: bool) {
    use ec::moddesc::ModDescBuilder;
    use peering::ecroll::EcCtx;
    use peering::plog::rewind_divergent_log_ec;
    use peering::{IndexedLog, MissingSet};

    let (disk, ad, sim) = new_adapter(64, 1, 19);
    let mut mem = MemStore::new();
    ec_pg_create(&mut mem, &ad);
    let s = ec_spg();
    let a = hobj("rollback-truncate-delete");
    let ctx = EcCtx {
        stripe_width: (2 * CHUNK) as u64,
        chunk: CHUNK as u64,
        shard: SHARD as u32,
        opt: optimized,
        k: 2,
        raw: 0,
        ..Default::default()
    };
    let logical_size = (4 * CHUNK) as u64;
    let shortened_size = (2 * CHUNK) as u64;
    let data = pattern(ctx.shard_size(logical_size) as usize, 23);
    let old_oi = oi_bytes(&a, ev(1), logical_size);
    let short_oi = oi_bytes(&a, ev(2), shortened_size);
    let old_snapset = denc::to_vec(&replwire::SnapSet::default()).unwrap();
    let mut attrs = vec![
        (b"_".to_vec(), old_oi.clone()),
        (b"snapset".to_vec(), old_snapset),
    ];
    if !optimized {
        attrs.push((
            b"hinfo_key".to_vec(),
            encode_hinfo(logical_size, &[1, 2, 3]),
        ));
    }
    let acknowledged = StoreTxn {
        ops: vec![
            StoreOp::LogAppend(vec![ent(LogOp::MODIFY, &a, 1)]),
            apply(|t, c| {
                let live = t.obj(&gho(&a, Ghobject::NO_GEN));
                t.push(
                    c,
                    TxnOp::Write {
                        oid: live,
                        off: 0,
                        data: Data::new(&data),
                    },
                );
                for (name, value) in &attrs {
                    t.push(
                        c,
                        TxnOp::SetAttr {
                            oid: live,
                            name,
                            value,
                        },
                    );
                }
            }),
        ],
    };
    mem.submit(s, &acknowledged);
    ad.try_submit(s, &acknowledged).unwrap();

    let tail = ctx.shard_size(shortened_size);
    let tail_len = ctx.shard_size(logical_size) - tail;
    let mut md = ModDescBuilder::new();
    md.set_attrs(
        &attrs
            .iter()
            .map(|(k, v)| (k.clone(), Some(v.clone())))
            .collect::<Vec<_>>(),
    );
    if optimized {
        md.rollback_extents_v3(2, &[(tail, tail_len)], logical_size, &[[0, 0]]);
    } else {
        md.rollback_extents(2, &[(tail, tail_len)]);
    }
    let (bl, version, rollback_info_completed) = md.finish();
    let mut truncate = ent(LogOp::MODIFY, &a, 2);
    truncate.mod_desc = pgwire::ObjectModDesc {
        version,
        can_local_rollback: true,
        rollback_info_completed,
        bl,
    };
    let mut md = ModDescBuilder::new();
    md.delete(3);
    let (bl, version, rollback_info_completed) = md.finish();
    let mut delete = ent(LogOp::DELETE, &a, 3);
    delete.mod_desc = pgwire::ObjectModDesc {
        version,
        can_local_rollback: true,
        rollback_info_completed,
        bl,
    };
    // Both writes reached this shard, but the acting set never acknowledged them.
    let divergent = StoreTxn {
        ops: vec![
            StoreOp::LogAppendKeep(vec![truncate, delete]),
            apply(|t, c| {
                let live = t.obj(&gho(&a, Ghobject::NO_GEN));
                let truncated = t.obj(&gho(&a, 2));
                let deleted = t.obj(&gho(&a, 3));
                t.push(c, TxnOp::Touch { oid: truncated });
                t.push(
                    c,
                    TxnOp::CloneRange2 {
                        oid: live,
                        dest_oid: truncated,
                        src_off: tail,
                        len: tail_len,
                        dest_off: tail,
                    },
                );
                t.push(
                    c,
                    TxnOp::Truncate {
                        oid: live,
                        size: tail,
                    },
                );
                t.push(
                    c,
                    TxnOp::SetAttr {
                        oid: live,
                        name: b"_",
                        value: &short_oi,
                    },
                );
                t.push(
                    c,
                    TxnOp::RmAttr {
                        oid: live,
                        name: b"snapset",
                    },
                );
                if !optimized {
                    t.push(
                        c,
                        TxnOp::RmAttr {
                            oid: live,
                            name: b"hinfo_key",
                        },
                    );
                }
                t.push(
                    c,
                    TxnOp::CollMoveRename {
                        oid: live,
                        dest_cid: c,
                        dest_oid: deleted,
                    },
                );
            }),
        ],
    };
    mem.submit(s, &divergent);
    ad.try_submit(s, &divergent).unwrap();
    assert!(ad.object(s, &a).is_none());
    let mut persisted = ad.load_pg(s).unwrap();
    persisted.info.last_backfill = Hobject::MAX();
    let mut log = IndexedLog::new(persisted.log);
    let mut missing = MissingSet::from_wire(persisted.missing);
    let mut ops = Vec::new();
    rewind_divergent_log_ec(
        &mut log,
        &mut persisted.info,
        &mut missing,
        &mut ops,
        ev(1),
        ctx,
    )
    .unwrap();
    assert!(
        missing.is_empty(),
        "local rollback must restore the acknowledged object"
    );
    ops.push(StoreOp::PutInfo(Box::new(persisted.info)));
    let rollback = StoreTxn { ops };
    mem.submit(s, &rollback);
    ad.try_submit(s, &rollback).unwrap();
    let restored = ad.object(s, &a).unwrap();
    let oi: replwire::ObjectInfo = denc::from_slice(&restored.xattrs[b"_".as_slice()]).unwrap();
    assert_eq!(
        oi.size, logical_size,
        "acknowledged tail must remain readable"
    );
    assert_eq!(oi.version, ev(1));
    assert_eq!(restored.data, data);
    assert_eq!(restored.xattrs, attrs.into_iter().collect());
    same_all(&mem, &ad, "rollback of truncate followed by delete");
    let image = disk.image();
    drop(ad);
    let (_disk, mounted) = open(&image, &sim, &StoreCfg::default());
    same_all(&mem, &mounted, "rollback survives remount");
}

#[test]
fn ec_rollback_truncate_delete_restores_acknowledged_object() {
    rollback_truncate_delete_restores_acknowledged_object(false);
}

#[test]
fn ec_opt_rollback_truncate_delete_restores_acknowledged_object() {
    rollback_truncate_delete_restores_acknowledged_object(true);
}

#[test]
fn shard_batch_metadata_follows_rename_clone_and_remove() {
    use ec::moddesc::{EcOmap, OmapUp};

    let (_disk, ad, _sim) = new_adapter(64, 1, 20);
    let mut mem = MemStore::new();
    ec_pg_create(&mut mem, &ad);
    let s = ec_spg();
    let a = hobj("batch-metadata");
    let data = pattern(CHUNK, 29);
    let metadata = |generation| ShardOp::SetAttrs {
        soid: a.clone(),
        generation,
        attrs: vec![(b"metadata".to_vec(), Some(b"restored".to_vec()))],
    };
    let omap = |generation| ShardOp::Omap {
        soid: a.clone(),
        generation,
        omap: EcOmap {
            header: Some(b"header".to_vec()),
            ups: vec![OmapUp::Insert(vec![(b"key".to_vec(), b"value".to_vec())])],
            ..Default::default()
        },
    };
    let setup = StoreTxn {
        ops: vec![apply(|t, c| {
            let stash = t.obj(&gho(&a, 7));
            t.push(
                c,
                TxnOp::Write {
                    oid: stash,
                    off: 0,
                    data: Data::new(&data),
                },
            );
        })],
    };
    mem.submit(s, &setup);
    ad.try_submit(s, &setup).unwrap();
    let restore = StoreTxn {
        ops: vec![StoreOp::Shard(vec![
            ShardOp::Rename {
                soid: a.clone(),
                from_gen: 7,
                to_gen: Ghobject::NO_GEN,
            },
            metadata(Ghobject::NO_GEN),
            omap(Ghobject::NO_GEN),
            ShardOp::CloneRange {
                soid: a.clone(),
                from_gen: Ghobject::NO_GEN,
                to_gen: 8,
                off: 0,
                len: CHUNK as u64,
            },
            metadata(8),
            omap(8),
        ])],
    };
    mem.submit(s, &restore);
    ad.try_submit(s, &restore).unwrap();
    let restored = ad.object(s, &a).unwrap();
    assert_eq!(restored.data, data);
    assert_eq!(restored.xattrs[b"metadata".as_slice()], b"restored");
    assert_eq!(restored.omap_header, b"header");
    assert_eq!(restored.omap[b"key".as_slice()], b"value");
    let stash = ad_stash(&ad, s);
    assert_eq!(stash[&(a.clone(), 8)].0, data);
    assert_eq!(
        stash[&(a.clone(), 8)].1[b"metadata".as_slice()],
        b"restored"
    );
    assert_eq!(stash[&(a.clone(), 8)].2[b"key".as_slice()], b"value");
    same_all(
        &mem,
        &ad,
        "metadata after rename and clone in one shard batch",
    );

    // Updates after a removal must remain no-ops, including for a stash generation.
    let remove = StoreTxn {
        ops: vec![StoreOp::Shard(vec![
            ShardOp::Remove {
                soid: a.clone(),
                generation: Ghobject::NO_GEN,
            },
            metadata(Ghobject::NO_GEN),
            omap(Ghobject::NO_GEN),
            ShardOp::Remove {
                soid: a.clone(),
                generation: 8,
            },
            metadata(8),
            omap(8),
        ])],
    };
    mem.submit(s, &remove);
    ad.try_submit(s, &remove).unwrap();
    assert!(ad.object(s, &a).is_none());
    assert!(ad_stash(&ad, s).is_empty());
    same_all(
        &mem,
        &ad,
        "metadata after removal cannot resurrect an object",
    );
}

#[test]
fn script_adapter_matches_memstore_step_by_step() {
    let (_d, ad, _sim) = new_adapter(64, 1, 1);
    let mut mem = MemStore::new();
    ec_pg_create(&mut mem, &ad);
    let s = ec_spg();
    for (i, t) in script().iter().enumerate() {
        mem.submit(s, t);
        ad.try_submit(s, t)
            .unwrap_or_else(|e| panic!("txn {i}: {e}"));
        same_all(&mem, &ad, &format!("after txn {}", i + 1));
    }
}

#[test]
fn stash_lifecycle_states() {
    let (_d, ad, _sim) = new_adapter(64, 1, 2);
    let mut mem = MemStore::new();
    ec_pg_create(&mut mem, &ad);
    let s = ec_spg();
    let (a, b) = (hobj("a"), hobj("b"));
    let sc = script();
    let mut pos = 0usize;
    let mut st = |n: usize| {
        for t in &sc[pos..pos + n] {
            mem.submit(s, t);
            ad.try_submit(s, t).unwrap();
        }
        pos += n;
    };
    // after 2: stash (a,2) holds the OLD first chunk, live has the new one
    st(2);
    let stash = ad_stash(&ad, s);
    assert_eq!(stash[&(a.clone(), 2)].0, pattern(CHUNK, 1));
    assert_eq!(
        ad.object(s, &a).unwrap().data[..CHUNK],
        pattern(CHUNK, 2)[..]
    );
    // after 4: live A gone, delete stash (a,4) carries everything (data + attrs)
    st(2);
    assert!(ad.object(s, &a).is_none());
    let stash = ad_stash(&ad, s);
    assert_eq!(stash[&(a.clone(), 4)].0.len(), 2 * CHUNK);
    assert_eq!(stash[&(a.clone(), 4)].1[b"_".as_slice()], b"oi2");
    // after 5: roll-forward removed the extent stash, cursors persisted
    st(1);
    assert!(!ad_stash(&ad, s).contains_key(&(a.clone(), 2)));
    let p = ad.load_pg(s).unwrap();
    assert_eq!(
        (p.log.can_rollback_to, p.log.rollback_info_trimmed_to),
        (ev(2), ev(2))
    );
    assert_eq!(p.log.head, ev(4));
    // after 6: rollback of the delete restored the live object, log rewound to 3 (cursors clamp to <= 3)
    st(1);
    let o = ad.object(s, &a).unwrap();
    assert_eq!(o.data.len(), 2 * CHUNK);
    assert!(ad_stash(&ad, s).is_empty());
    assert_eq!(ad.load_pg(s).unwrap().log.head, ev(3));
    // after 8: B rolled back to its prior content
    st(2);
    let o = ad.object(s, &b).unwrap();
    assert_eq!(o.data, pattern(CHUNK, 3));
    assert_eq!(
        o.xattrs.get(b"z".as_slice()).map(|v| v.as_slice()),
        Some(b"zz".as_slice())
    );
    assert!(!o.xattrs.contains_key(b"k".as_slice()));
    assert!(!ad_stash(&ad, s).contains_key(&(b.clone(), 4)));
    let p = ad.load_pg(s).unwrap();
    assert_eq!(
        (p.log.can_rollback_to, p.log.rollback_info_trimmed_to),
        (ev(3), ev(3))
    );
    same_all(&mem, &ad, "end");
}

#[test]
fn append_keep_leaves_cursors_and_survives_remount() {
    let sim = sim_cfg(64, 3);
    let img = fresh_image(&sim, 1, 512);
    let (disk, ad) = open(&img, &sim, &StoreCfg::default());
    let s = ec_spg();
    ad.submit_create(s);
    let a = hobj("a");
    // LogAppend (replicated rule) sets cursors := head; LogAppendKeep must not move them
    let mut t = StoreTxn::default();
    t.push(StoreOp::LogAppend(vec![ent(LogOp::MODIFY, &a, 1)]));
    t.push(StoreOp::LogAppendKeep(vec![
        ent(LogOp::MODIFY, &a, 2),
        ent(LogOp::MODIFY, &a, 3),
    ]));
    ad.try_submit(s, &t).unwrap();
    let p = ad.load_pg(s).unwrap();
    assert_eq!(
        (
            p.log.head,
            p.log.can_rollback_to,
            p.log.rollback_info_trimmed_to
        ),
        (ev(3), ev(1), ev(1))
    );
    // cursors are absolute and the last op of a txn wins
    let mut t = StoreTxn::default();
    t.push(StoreOp::LogCursors {
        can_rollback_to: ev(3),
        rollback_info_trimmed_to: ev(3),
    });
    t.push(StoreOp::LogCursors {
        can_rollback_to: ev(2),
        rollback_info_trimmed_to: ev(1),
    });
    ad.try_submit(s, &t).unwrap();
    // LogCursors may follow a LogAppendKeep and a LogRewind-first txn
    let mut t = StoreTxn::default();
    t.push(StoreOp::LogRewind { to: ev(2) });
    t.push(StoreOp::LogAppendKeep(vec![ent(LogOp::MODIFY, &a, 3)]));
    t.push(StoreOp::LogCursors {
        can_rollback_to: ev(2),
        rollback_info_trimmed_to: ev(2),
    });
    ad.try_submit(s, &t).unwrap();
    ad.with_store(|st| st.checkpoint().unwrap());
    let img2 = disk.image();
    drop(ad);
    let (_d2, ad2) = open(&img2, &sim, &StoreCfg::default());
    let p = ad2.load_pg(s).unwrap();
    assert_eq!(
        (
            p.log.head,
            p.log.can_rollback_to,
            p.log.rollback_info_trimmed_to
        ),
        (ev(3), ev(2), ev(2))
    );
    assert_eq!(p.log.log.len(), 3);
}

/// adr 0160 am. 2: `LogHeadIs` replaces the `_loghead` read-back (debug builds assert it equals the stored value), and an
/// EC shard writing no `_info` per write (lazy info) reloads with info rebuilt from the log; same state in MemStore.
#[test]
fn ec_head_hint_and_lazy_info_survive_remount() {
    let sim = sim_cfg(64, 3);
    let img = fresh_image(&sim, 1, 512);
    let (disk, ad) = open(&img, &sim, &StoreCfg::default());
    let mut mem = MemStore::default();
    let s = ec_spg();
    ad.submit_create(s);
    mem.submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::CreatePg],
        },
    );
    let a = hobj("a");
    let z = Eversion::default();
    let txns = [
        vec![
            StoreOp::LogHeadIs(z, z, z),
            StoreOp::LogAppendKeep(vec![ent(LogOp::MODIFY, &a, 1)]),
        ],
        vec![
            StoreOp::LogHeadIs(ev(1), z, z),
            StoreOp::LogAppendKeep(vec![ent(LogOp::MODIFY, &a, 2)]),
            StoreOp::LogCursors {
                can_rollback_to: ev(1),
                rollback_info_trimmed_to: ev(1),
            },
        ],
        // roll-forward only (no entries, no info)
        vec![
            StoreOp::LogHeadIs(ev(2), ev(1), ev(1)),
            StoreOp::LogCursors {
                can_rollback_to: ev(2),
                rollback_info_trimmed_to: ev(2),
            },
        ],
        vec![
            StoreOp::LogHeadIs(ev(2), ev(2), ev(2)),
            StoreOp::LogAppendKeep(vec![ent(LogOp::MODIFY, &a, 3)]),
            // a later hint of the same txn is ignored (the translator already knows the head)
            StoreOp::LogHeadIs(ev(3), ev(2), ev(2)),
        ],
    ];
    for ops in txns {
        let t = StoreTxn { ops };
        ad.try_submit(s, &t).unwrap();
        mem.submit(s, &t);
    }
    ad.with_store(|st| st.checkpoint().unwrap());
    let img2 = disk.image();
    drop(ad);
    let (_d2, ad2) = open(&img2, &sim, &StoreCfg::default());
    for p in [ad2.load_pg(s).unwrap(), mem.load_pg(s).unwrap()] {
        assert_eq!(
            (
                p.log.head,
                p.log.can_rollback_to,
                p.log.rollback_info_trimmed_to
            ),
            (ev(3), ev(2), ev(2))
        );
        assert_eq!(p.log.log.len(), 3);
        assert_eq!((p.info.last_update, p.info.last_complete), (ev(3), ev(3)));
    }
}

#[test]
fn listing_scrub_backfill_skip_stash_and_removal_deletes_it() {
    let (_d, ad, _sim) = new_adapter(64, 1, 4);
    let mut mem = MemStore::new();
    ec_pg_create(&mut mem, &ad);
    let s = ec_spg();
    let sc = script();
    for t in &sc[..4] {
        mem.submit(s, t);
        ad.try_submit(s, t).unwrap();
    }
    // stash (a,2) and (a,4) exist; only B is live
    assert_eq!(ad_stash(&ad, s).len(), 2);
    for (name, l) in [
        ("adapter", ad.list_objects(s, &Hobject::MIN(), 0, 100)),
        ("mem", mem.list_objects(s, &Hobject::MIN(), 0, 100)),
    ] {
        let names: Vec<_> = l.unwrap().objs.iter().map(|(h, _)| h.oid.clone()).collect();
        // B has no object_info xattr in this script, so it is not listed either way; no stash entries may appear
        assert!(names.iter().all(|n| n != b"a"), "{name}: {names:?}");
    }
    assert_eq!(ad.all_object_names(s), vec![hobj("b")]);
    let (lo, hi) = (Hobject::MIN(), Hobject::MAX());
    for deep in [false, true] {
        let p = scrub_all_ec(&ad, s, deep, true.into());
        assert_eq!(p.objects.keys().collect::<Vec<_>>(), vec![&hobj("b")]);
        let p2 =
            mem.build_scrub_map_ec(s, &lo, &hi, deep, 100, u64::MAX, true.into(), CHUNK as u32);
        assert_eq!(p.objects, p2.objects);
    }
    // PG removal deletes live and stash objects
    ad.remove_pg(s).unwrap();
    assert!(ad.list_pgs().is_empty());
    ad.submit_create(s);
    assert!(ad_stash(&ad, s).is_empty());
    assert!(ad.all_object_names(s).is_empty());
}

#[test]
fn large_sparse_ec_shard_write_stash_and_rollback_survive_remount() {
    // k=2, logical size 300 MiB: each shard is 150 MiB. The configured
    // client size policy has already run; the adapter must accept these offsets.
    let (disk, ad, sim) = new_adapter(64, 1, 847);
    ad.submit_create(ec_spg());
    let h = hobj("large-sparse");
    let size = 150 << 20;
    let off = size - CHUNK as u64;
    let old = pattern(CHUNK, 17);
    let new = pattern(CHUNK, 29);
    let initial = StoreTxn {
        ops: vec![apply(|t, c| {
            let oid = t.obj(&gho(&h, Ghobject::NO_GEN));
            t.push(c, TxnOp::Touch { oid });
            t.push(c, TxnOp::Truncate { oid, size });
            t.push(
                c,
                TxnOp::Write {
                    oid,
                    off,
                    data: Data::new(&old),
                },
            );
        })],
    };
    ad.try_submit(ec_spg(), &initial).unwrap();
    let overwrite = StoreTxn {
        ops: vec![apply(|t, c| {
            let oid = t.obj(&gho(&h, Ghobject::NO_GEN));
            let stash = t.obj(&gho(&h, 2));
            t.push(c, TxnOp::Touch { oid: stash });
            t.push(
                c,
                TxnOp::CloneRange2 {
                    oid,
                    dest_oid: stash,
                    src_off: off,
                    len: CHUNK as u64,
                    dest_off: off,
                },
            );
            t.push(
                c,
                TxnOp::Write {
                    oid,
                    off,
                    data: Data::new(&new),
                },
            );
        })],
    };
    ad.try_submit(ec_spg(), &overwrite).unwrap();
    assert_eq!(
        ad.ec_read(ec_spg(), &h, off, CHUNK as u64).unwrap(),
        (new, size)
    );
    let img = disk.image();
    drop(ad);
    let (disk, ad) = open(&img, &sim, &StoreCfg::default());
    let rollback = StoreTxn {
        ops: vec![apply(|t, c| {
            let oid = t.obj(&gho(&h, Ghobject::NO_GEN));
            let stash = t.obj(&gho(&h, 2));
            t.push(
                c,
                TxnOp::CloneRange2 {
                    oid: stash,
                    dest_oid: oid,
                    src_off: off,
                    len: CHUNK as u64,
                    dest_off: off,
                },
            );
            t.push(c, TxnOp::Remove { oid: stash });
        })],
    };
    ad.try_submit(ec_spg(), &rollback).unwrap();
    let img = disk.image();
    drop(ad);
    let (_, ad) = open(&img, &sim, &StoreCfg::default());
    assert_eq!(
        ad.ec_read(ec_spg(), &h, off, CHUNK as u64).unwrap(),
        (old, size)
    );
    assert_eq!(
        ad.ec_read(ec_spg(), &h, off - CHUNK as u64, CHUNK as u64)
            .unwrap()
            .0,
        vec![0; CHUNK]
    );
    assert!(ad.ec_list_stash(ec_spg()).is_empty());
}

#[test]
fn ec_read_and_attrs() {
    let (_d, ad, _sim) = new_adapter(64, 1, 5);
    let mut mem = MemStore::new();
    ec_pg_create(&mut mem, &ad);
    let s = ec_spg();
    let a = hobj("a");
    let sc = script();
    for t in &sc[..2] {
        mem.submit(s, t);
        ad.try_submit(s, t).unwrap();
    }
    let want = {
        let mut v = pattern(CHUNK, 2);
        v.extend(&pattern(2 * CHUNK, 1)[CHUNK..]);
        v
    };
    for store in [&ad as &dyn PgStoreOps, &mem as &dyn PgStoreOps] {
        assert_eq!(
            store.ec_read(s, &a, 0, 1 << 20).unwrap(),
            (want.clone(), 2 * CHUNK as u64)
        );
        assert_eq!(
            store.ec_read(s, &a, 100, 50).unwrap().0,
            want[100..150].to_vec()
        );
        // short read at EOF, empty past EOF, still success
        assert_eq!(
            store
                .ec_read(s, &a, 2 * CHUNK as u64 - 10, 100)
                .unwrap()
                .0
                .len(),
            10
        );
        assert_eq!(
            store.ec_read(s, &a, 3 * CHUNK as u64, 100).unwrap(),
            (vec![], 2 * CHUNK as u64)
        );
        assert_eq!(store.ec_read(s, &hobj("nope"), 0, 10), Err(-2));
        let at = store.ec_getattrs(s, &a).unwrap();
        assert_eq!(at[b"_".as_slice()], b"oi2");
        assert!(at.contains_key(b"hinfo_key".as_slice()));
        assert_eq!(store.ec_getattrs(s, &hobj("nope")), Err(-2));
        // stash objects are not readable as live objects
        assert_eq!(
            store.ec_read(s, &hobj("a"), 0, 1).map(|x| x.1),
            Ok(2 * CHUNK as u64)
        );
    }
}

/// Shard object with a given content and hinfo; returns its scrub object from the adapter and MemStore (must agree).
fn scrub_one(
    legacy: impl Into<replwire::ecscrub::EcScrubMode> + Copy,
    data: &[u8],
    hinfo: Option<Vec<u8>>,
    shard: i8,
) -> replwire::scrubmsgs::ScrubObject {
    let s = SpgT {
        pgid: PgT::new(2, 1),
        shard: ShardId(shard),
    };
    let (_d, ad, _sim) = new_adapter(64, 1, 6);
    let mut mem = MemStore::new();
    mem.submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::CreatePg],
        },
    );
    ad.submit_create(s);
    let h = hobj("x");
    let g = Ghobject::new(h.clone(), Ghobject::NO_GEN, ShardId(shard));
    let mut t = Transaction::new();
    let c = t.coll(&CollT::Pg(s));
    let o = t.obj(&g);
    t.push(c, TxnOp::Touch { oid: o });
    if !data.is_empty() {
        t.push(
            c,
            TxnOp::Write {
                oid: o,
                off: 0,
                data: Data::new(data),
            },
        );
    }
    if let Some(h) = &hinfo {
        t.push(
            c,
            TxnOp::SetAttr {
                oid: o,
                name: b"hinfo_key",
                value: h,
            },
        );
    }
    let st = StoreTxn {
        ops: vec![StoreOp::ApplyTxn {
            middle: Default::default(),
            data: t.encode_v9().unwrap().into(),
        }],
    };
    mem.submit(s, &st);
    ad.try_submit(s, &st).unwrap();
    let (lo, hi) = (Hobject::MIN(), Hobject::MAX());
    let a = scrub_all_ec(&ad, s, true, legacy.into());
    let m = mem.build_scrub_map_ec(s, &lo, &hi, true, 10, u64::MAX, legacy.into(), CHUNK as u32);
    assert_eq!(a.objects, m.objects, "adapter == memstore");
    // shallow: size + all attrs only
    let sh = ad.build_scrub_map_ec(
        s,
        &lo,
        &hi,
        false,
        10,
        u64::MAX,
        legacy.into(),
        CHUNK as u32,
    );
    let so = &sh.objects[&h];
    assert!(!so.digest_present && so.size == data.len() as u64);
    assert_eq!(so.object_omap_key_bytes, None);
    assert_eq!(
        so.attrs.contains_key(b"hinfo_key".as_slice()),
        hinfo.is_some()
    );
    let so = &a.objects[&h];
    assert_eq!(
        so.object_omap_key_bytes,
        (!so.read_error && !so.ec_hash_mismatch && !so.ec_size_mismatch).then_some(0)
    );
    so.clone()
}

#[test]
fn ec_scrub_digest_rules() {
    let data = pattern(2 * CHUNK, 9);
    let crc = data_digest_update(DIGEST_SEED, &data);
    let n = data.len() as u64;
    // L0 good (shard 1): digest := hash of shard 0
    let o = scrub_one(false, &data, Some(encode_hinfo(n, &[0xAAAA, crc, 7])), 1);
    assert!(o.digest_present && o.digest == 0xAAAA && !o.read_error);
    assert!(!o.ec_hash_mismatch && !o.ec_size_mismatch);
    assert!(o.omap_digest_present && o.omap_digest == u32::MAX);
    assert_eq!(o.size, n);
    // hash of our shard differs
    let o = scrub_one(
        false,
        &data,
        Some(encode_hinfo(n, &[0xAAAA, crc ^ 1, 7])),
        1,
    );
    assert!(o.ec_hash_mismatch && !o.digest_present && !o.read_error);
    // total_chunk_size != size: read error
    let o = scrub_one(
        false,
        &data,
        Some(encode_hinfo(n + CHUNK as u64, &[1, crc, 3])),
        1,
    );
    assert!(o.read_error && !o.digest_present);
    // no hinfo / undecodable hinfo
    assert!(scrub_one(false, &data, None, 1).read_error);
    assert!(scrub_one(false, &data, Some(vec![1, 1, 200, 0, 0, 0, 1]), 1).read_error);
    // hashes cleared (overwrite pool data in an L0 pool = inconsistent): size mismatch flag
    let o = scrub_one(false, &data, Some(encode_hinfo(n, &[])), 1);
    assert!(o.ec_size_mismatch && !o.digest_present);
    // shard size not a multiple of the chunk size: read error
    let odd = pattern(CHUNK + 5, 4);
    assert!(
        scrub_one(
            false,
            &odd,
            Some(encode_hinfo(odd.len() as u64, &[1, 2, 3])),
            1
        )
        .read_error
    );
    // L1: digest 0 present, hinfo ignored
    let o = scrub_one(true, &data, None, 2);
    assert!(o.digest_present && o.digest == 0 && !o.read_error && !o.ec_hash_mismatch);
    assert!(scrub_one(true, &odd, None, 2).read_error);
    // shard 0 compares with hashes[0]
    let o = scrub_one(false, &data, Some(encode_hinfo(n, &[crc, 5, 6])), 0);
    assert!(o.digest_present && o.digest == crc);
    // mode O: whole-file crc32c always, hinfo ignored (even a stale one), no chunk-multiple rule, omap digest -1
    use replwire::ecscrub::EcScrubMode::Optimized;
    let o = scrub_one(Optimized, &data, Some(encode_hinfo(n, &[1, 2, 3])), 1);
    assert!(o.digest_present && o.digest == crc && !o.read_error && !o.ec_hash_mismatch);
    assert!(o.omap_digest_present && o.omap_digest == u32::MAX);
    let crc_odd = data_digest_update(DIGEST_SEED, &odd);
    let o = scrub_one(Optimized, &odd, None, 2);
    assert!(o.digest_present && o.digest == crc_odd && !o.read_error);
}

#[test]
fn optimized_ec_scrub_counts_paged_binary_omap_without_changing_digests() {
    use ec::moddesc::{EcOmap, OmapUp};
    use replwire::ecscrub::EcScrubMode::Optimized;
    let (disk, ad, _) = new_adapter(128, 1, 72);
    let mut mem = MemStore::new();
    ec_pg_create(&mut mem, &ad);
    let pg = ec_spg();
    let h = hobj("optimized-omap");
    let data = vec![0xa5; CHUNK];
    let mut t = Transaction::new();
    let c = t.coll(&CollT::Pg(pg));
    let g = t.obj(&gho(&h, Ghobject::NO_GEN));
    t.push(
        c,
        TxnOp::Write {
            oid: g,
            off: 0,
            data: Data::new(&data),
        },
    );
    let pairs: Vec<_> = (0..1025u16)
        .map(|i| {
            let key = vec![0, (i >> 8) as u8, i as u8, 0xff];
            let value = if i % 2 == 0 {
                vec![]
            } else {
                vec![0, 0xff, i as u8]
            };
            (key, value)
        })
        .collect();
    let txn = StoreTxn {
        ops: vec![
            StoreOp::ApplyTxn {
                middle: Default::default(),
                data: t.encode_v9().unwrap().into(),
            },
            StoreOp::Shard(vec![ShardOp::Omap {
                soid: h.clone(),
                generation: Ghobject::NO_GEN,
                omap: EcOmap {
                    clear: false,
                    header: Some(b"header excluded from payload".to_vec()),
                    ups: vec![OmapUp::Insert(pairs)],
                },
            }]),
        ],
    };
    mem.submit(pg, &txn);
    ad.try_submit(pg, &txn).unwrap();
    let mut completed = None;
    let mut slices = 0;
    for _ in 0..10_000 {
        ad.poll_store(&mut Vec::new());
        ad.with_store(|s| s.idle());
        let part = ad.build_scrub_map_ec(
            pg,
            &h,
            &Hobject::MAX(),
            true,
            10,
            1,
            Optimized,
            CHUNK as u32,
        );
        assert!(part.error.is_none());
        slices += 1;
        if let Some(object) = part.objects.get(&h) {
            assert!(part.next.is_none());
            completed = Some(object.clone());
            break;
        }
        assert!(
            part.objects.is_empty(),
            "partial OMAP stats must stay unpublished"
        );
        assert_eq!(part.next, Some(h.clone()));
    }
    let object = completed.expect("optimized EC OMAP continuation timed out");
    assert!(
        slices > 1,
        "OMAP must cross the bounded listing page boundary"
    );
    assert_eq!(object.object_omap_key_bytes, Some(4100));
    assert_eq!(
        (object.object_omap_keys, object.object_omap_bytes),
        (1025, 1536)
    );
    assert_eq!(
        (object.digest, object.digest_present),
        (data_digest_update(DIGEST_SEED, &data), true)
    );
    assert_eq!(
        (object.omap_digest, object.omap_digest_present),
        (DIGEST_SEED, true)
    );
    let reference = mem.build_scrub_map_ec(
        pg,
        &Hobject::MIN(),
        &Hobject::MAX(),
        true,
        10,
        u64::MAX,
        Optimized,
        CHUNK as u32,
    );
    assert_eq!(object, reference.objects[&h], "adapter == memstore");
    let shallow = ad.build_scrub_map_ec(
        pg,
        &Hobject::MIN(),
        &Hobject::MAX(),
        false,
        10,
        u64::MAX,
        Optimized,
        CHUNK as u32,
    );
    assert_eq!(shallow.objects[&h].object_omap_key_bytes, None);
    let mut thresholds = object.clone();
    thresholds.apply_large_omap(u64::MAX, 1536);
    assert!(
        !thresholds.large_omap_object_found,
        "large OMAP uses only value bytes"
    );
    thresholds.apply_large_omap(u64::MAX, 1535);
    assert!(thresholds.large_omap_object_found);
    assert_eq!(thresholds.large_omap_object_value_size, 1536);

    let image = disk.image();
    let lba = (0..image.lba_count)
        .find(|&lba| image.read_lba(lba).iter().all(|&byte| byte == 0xa5))
        .expect("shard data block");
    disk.corrupt(lba, 17, 1);
    let corrupt = scrub_all_ec(&ad, pg, true, Optimized);
    let object = &corrupt.objects[&h];
    assert!(object.read_error && !object.digest_present && !object.omap_digest_present);
    assert_eq!(object.object_omap_key_bytes, None);
}

/// Mode O EC_OMAP roll-forward op (`ShardOp::Omap`): header, clear, updates in classic order on any generation;
/// a missing generation is a no-op; the adapter matches MemStore, also the sub-read omap batches.
#[test]
fn omap_shard_op_matches_memstore() {
    use ec::moddesc::{EcOmap, OmapUp};
    let (_d, ad, _sim) = new_adapter(64, 1, 7);
    let mut mem = MemStore::new();
    ec_pg_create(&mut mem, &ad);
    let s = ec_spg();
    let a = hobj("a");
    let both = |mem: &mut MemStore, t: StoreTxn| {
        mem.submit(s, &t);
        ad.try_submit(s, &t).unwrap();
    };
    let mk = apply(|t, c| {
        let (live, st) = (t.obj(&gho(&a, Ghobject::NO_GEN)), t.obj(&gho(&a, 9)));
        t.push(c, TxnOp::Touch { oid: live });
        t.push(c, TxnOp::Touch { oid: st });
    });
    both(&mut mem, StoreTxn { ops: vec![mk] });
    let up = |g: u64, o: EcOmap| {
        StoreOp::Shard(vec![ShardOp::Omap {
            soid: a.clone(),
            generation: g,
            omap: o,
        }])
    };
    let ins = |k: &str| OmapUp::Insert(vec![(k.as_bytes().to_vec(), k.as_bytes().to_vec())]);
    both(
        &mut mem,
        StoreTxn {
            ops: vec![
                up(
                    Ghobject::NO_GEN,
                    EcOmap {
                        clear: false,
                        header: Some(b"h1".to_vec()),
                        ups: vec![ins("a"), ins("b"), ins("c"), ins("d")],
                    },
                ),
                up(
                    9,
                    EcOmap {
                        clear: false,
                        header: None,
                        ups: vec![ins("s")],
                    },
                ),
                // missing generation: no-op
                up(
                    77,
                    EcOmap {
                        clear: false,
                        header: None,
                        ups: vec![ins("x")],
                    },
                ),
                up(
                    Ghobject::NO_GEN,
                    EcOmap {
                        clear: false,
                        header: None,
                        ups: vec![
                            OmapUp::Remove(vec![b"a".to_vec()]),
                            OmapUp::RemoveRange(b"b".to_vec(), b"c".to_vec()),
                        ],
                    },
                ),
            ],
        },
    );
    same_all(&mem, &ad, "after omap ops");
    let live = ad.object(s, &a).unwrap();
    assert_eq!(
        live.omap.keys().cloned().collect::<Vec<_>>(),
        vec![b"c".to_vec(), b"d".to_vec()]
    );
    assert_eq!(live.omap_header, b"h1");
    assert_eq!(mem.objects(s)[&a].omap, live.omap);
    assert!(
        mem.stash(s)[&(a.clone(), 9)]
            .omap
            .contains_key(b"s".as_slice())
    );
    assert!(!mem.stash(s).contains_key(&(a.clone(), 77)));
    // sub-read batches (from the first key, or strictly after the cursor)
    for st in [&mem as &dyn PgStoreOps, &ad as &dyn PgStoreOps] {
        assert_eq!(st.ec_omap_header(s, &a).unwrap(), b"h1");
        let (kv, done) = st.ec_omap_read(s, &a, None, 1 << 20, 1).unwrap();
        assert_eq!((kv.len(), done), (1, false));
        let (kv, done) = st
            .ec_omap_read(s, &a, Some(b"c".as_slice()), 1 << 20, 10)
            .unwrap();
        assert_eq!((kv, done), (vec![(b"d".to_vec(), b"d".to_vec())], true));
    }
    // clear + header: classic order is header first, then clear (the header does not survive)
    both(
        &mut mem,
        StoreTxn {
            ops: vec![up(
                Ghobject::NO_GEN,
                EcOmap {
                    clear: true,
                    header: Some(b"h2".to_vec()),
                    ups: vec![ins("z")],
                },
            )],
        },
    );
    let live = ad.object(s, &a).unwrap();
    assert_eq!((live.omap_header.len(), live.omap.len()), (0, 1));
    same_all(&mem, &ad, "after clear");
    // the empty key: `None` starts at it, `Some("")` strictly after it; a batch ends at it only as the last one
    both(
        &mut mem,
        StoreTxn {
            ops: vec![up(
                Ghobject::NO_GEN,
                EcOmap {
                    clear: false,
                    header: None,
                    ups: vec![OmapUp::Insert(vec![(Vec::new(), b"e".to_vec())])],
                },
            )],
        },
    );
    let (e, z) = ((Vec::new(), b"e".to_vec()), (b"z".to_vec(), b"z".to_vec()));
    for st in [&mem as &dyn PgStoreOps, &ad as &dyn PgStoreOps] {
        let r = st.ec_omap_read(s, &a, None, 1 << 20, 1).unwrap();
        assert_eq!(r, (vec![e.clone(), z.clone()], true));
        let r = st
            .ec_omap_read(s, &a, Some(b"".as_slice()), 1 << 20, 1)
            .unwrap();
        assert_eq!(r, (vec![z.clone()], true));
    }
}

// ---- crash safety -------------------------------------------------------------------------------------------

fn crash_scenario(
    img: &store::dev::SimImage,
    sim: &store::dev::SimConfig,
    cfg: &StoreCfg,
    txns: &[StoreTxn],
    k: u64,
    pol: CrashPolicy,
    seed: u64,
) -> Result<(), String> {
    let s = ec_spg();
    let mut s2 = sim.clone();
    s2.seed = seed;
    let (disk, ad) = open(img, &s2, cfg);
    ad.submit_create(s);
    disk.arm_crash(disk.events() + k);
    let mut ok = 0;
    for t in txns {
        match ad.try_submit(s, t) {
            Ok(()) => ok += 1,
            Err(_) if disk.crashed() => break,
            Err(e) => return Err(format!("submit: {e}")),
        }
    }
    disk.crash_now();
    let cimg = disk.crash_image(pol);
    drop(ad);
    {
        let d = SimDisk::from_image(&cimg, sim.clone());
        let mut dev = d.queue();
        let mut clk = SimClock::default();
        fsck(&mut dev, &mut clk, Some(&fsck_refs)).map_err(|e| format!("fsck: {e}"))?;
    }
    let (_d2, ad2) = open(&cimg, sim, cfg);
    let state = |n: usize| {
        let mut mem = MemStore::new();
        mem.submit(
            s,
            &StoreTxn {
                ops: vec![StoreOp::CreatePg],
            },
        );
        for t in &txns[..n] {
            mem.submit(s, t);
        }
        mem
    };
    let eq = |mem: &MemStore| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            same_all(mem, &ad2, "crash")
        }))
        .is_ok()
    };
    // all-or-nothing per txn: log, cursors, objects and stash objects always agree with one acked prefix
    if eq(&state(ok)) || (ok < txns.len() && eq(&state(ok + 1))) {
        return Ok(());
    }
    Err(format!(
        "recovered state matches neither prefix {ok} nor {}",
        ok + 1
    ))
}

#[test]
fn shard_apply_is_atomic_at_every_io_boundary() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let cfg = StoreCfg {
        shard: ShardCfg {
            ckpt_wal_pct: 4,
            ..StoreCfg::default().shard
        },
    };
    let sim = sim_cfg(40, 11);
    let img = fresh_image(&sim, 1, 512);
    let txns = script();
    let (disk, ad) = open(&img, &sim, &cfg);
    ad.submit_create(ec_spg());
    let e0 = disk.events();
    for t in &txns {
        ad.try_submit(ec_spg(), t).unwrap();
    }
    let events = disk.events() - e0;
    drop(ad);
    let mut n = 0;
    let mut err = None;
    for k in 0..events {
        for (i, pol) in [
            CrashPolicy::DROP_ALL,
            CrashPolicy::PERSIST_ALL,
            CrashPolicy::MIXED,
        ]
        .iter()
        .enumerate()
        {
            if let Err(e) = crash_scenario(&img, &sim, &cfg, &txns, k, *pol, k * 3 + i as u64 + 1) {
                err = Some(format!("k={k} policy#{i}: {e}"));
            }
            n += 1;
        }
    }
    std::panic::set_hook(prev);
    assert!(err.is_none(), "{err:?}");
    assert!(n > 30, "{n} scenarios");
}

#[test]
fn migration_carries_stash_objects() {
    use storeadapt::migrate::ExportCursor;
    let s = ec_spg();
    let (_d, src, _) = new_adapter(64, 1, 7);
    let mut mem = MemStore::new();
    ec_pg_create(&mut mem, &src);
    for t in &script()[..4] {
        src.try_submit(s, t).unwrap();
    }
    assert_eq!(ad_stash(&src, s).len(), 2);
    let mut cur = ExportCursor::default();
    let mut ops = Vec::new();
    loop {
        let (o, last) = src.export_chunk(s, &mut cur, 1 << 20).unwrap();
        ops.extend(o);
        if last {
            break;
        }
    }
    let (_d2, dst, _) = new_adapter(64, 1, 8);
    dst.import_ops(s, ops).unwrap();
    assert_eq!(ad_stash(&src, s), ad_stash(&dst, s));
    assert_eq!(src.objects(s).len(), dst.objects(s).len());
}

/// Live race (ceph_test_rados rollback x3 in flight after a new snap, then an RMW overwrite): on a data shard the head
/// is cloned to the snap clone, then twice stashed away (rename to a generation) and replaced by a clone of that snap
/// clone; the stashes are rolled forward (removed), the head is overwritten with an extent stash. The head and the
/// clone must keep every byte (multi-page objects, checkpoints in between, remount).
#[test]
fn rollback_race_clone_rename_chain_keeps_data() {
    let sim = sim_cfg(64, 9);
    let img = fresh_image(&sim, 1, 512);
    let (disk, ad) = open(&img, &sim, &StoreCfg::default());
    let mut mem = MemStore::new();
    ec_pg_create(&mut mem, &ad);
    let s = ec_spg();
    let (h, c) = (hobj("h"), hobj("h.c15"));
    let n = 110 * CHUNK + 1234;
    let d0 = pattern(n, 7);
    let d1 = pattern(5 * CHUNK, 9);
    let live = Ghobject::NO_GEN;
    let mut step = |i: usize, ops: Vec<StoreOp>, ckpt: bool| {
        let t = StoreTxn { ops };
        mem.submit(s, &t);
        ad.try_submit(s, &t)
            .unwrap_or_else(|e| panic!("txn {i}: {e}"));
        if ckpt {
            ad.with_store(|st| st.checkpoint().unwrap());
        }
        same_all(&mem, &ad, &format!("after txn {i}"));
    };
    step(
        1,
        vec![apply(|t, x| {
            let o = t.obj(&gho(&h, live));
            t.push(x, TxnOp::Touch { oid: o });
            t.push(
                x,
                TxnOp::Write {
                    oid: o,
                    off: 0,
                    data: Data::new(&d0),
                },
            );
            t.push(
                x,
                TxnOp::SetAttr {
                    oid: o,
                    name: b"_",
                    value: b"oi1",
                },
            );
        })],
        true,
    );
    // make_writeable: clone the head to the snap clone
    step(
        2,
        vec![apply(|t, x| {
            let (a, b) = (t.obj(&gho(&h, live)), t.obj(&gho(&c, live)));
            t.push(
                x,
                TxnOp::Clone {
                    oid: a,
                    dest_oid: b,
                },
            );
            t.push(
                x,
                TxnOp::SetAttr {
                    oid: b,
                    name: b"_",
                    value: b"oic",
                },
            );
            t.push(
                x,
                TxnOp::SetAttr {
                    oid: a,
                    name: b"_",
                    value: b"oi2",
                },
            );
        })],
        false,
    );
    // two rollbacks to the clone: stash the head under generation g, clone the clone back
    for (i, g) in [(3usize, 3u64), (4, 4)] {
        step(
            i,
            vec![apply(|t, x| {
                let (a, st, b) = (
                    t.obj(&gho(&h, live)),
                    t.obj(&gho(&h, g)),
                    t.obj(&gho(&c, live)),
                );
                t.push(
                    x,
                    TxnOp::CollMoveRename {
                        oid: a,
                        dest_cid: x,
                        dest_oid: st,
                    },
                );
                t.push(
                    x,
                    TxnOp::Clone {
                        oid: b,
                        dest_oid: a,
                    },
                );
                t.push(
                    x,
                    TxnOp::SetAttr {
                        oid: a,
                        name: b"_",
                        value: b"oi3",
                    },
                );
            })],
            i == 3,
        );
    }
    // roll forward: the stashes go
    step(
        5,
        vec![apply(|t, x| {
            for g in [3u64, 4] {
                let st = t.obj(&gho(&h, g));
                t.push(x, TxnOp::Remove { oid: st });
            }
        })],
        true,
    );
    // RMW overwrite of the head with an extent stash (generation 6)
    step(
        6,
        vec![apply(|t, x| {
            let (a, st) = (t.obj(&gho(&h, live)), t.obj(&gho(&h, 6)));
            t.push(x, TxnOp::Touch { oid: st });
            t.push(
                x,
                TxnOp::CloneRange2 {
                    oid: a,
                    dest_oid: st,
                    src_off: 30 * CHUNK as u64,
                    len: 5 * CHUNK as u64,
                    dest_off: 30 * CHUNK as u64,
                },
            );
            t.push(
                x,
                TxnOp::Write {
                    oid: a,
                    off: 30 * CHUNK as u64,
                    data: Data::new(&d1),
                },
            );
        })],
        true,
    );
    step(
        7,
        vec![apply(|t, x| {
            let st = t.obj(&gho(&h, 6));
            t.push(x, TxnOp::Remove { oid: st });
        })],
        true,
    );
    let mut want = d0.clone();
    want[30 * CHUNK..35 * CHUNK].copy_from_slice(&d1);
    assert_eq!(ad.object(s, &h).unwrap().data, want, "head");
    assert_eq!(ad.object(s, &c).unwrap().data, d0, "clone");
    let img2 = disk.image();
    drop(ad);
    let (_d2, ad2) = open(&img2, &sim, &StoreCfg::default());
    assert_eq!(ad2.object(s, &h).unwrap().data, want, "head after remount");
    assert_eq!(ad2.object(s, &c).unwrap().data, d0, "clone after remount");
}

/// EC recovery must not materialize a key-count page and discard all but the byte-budgeted reply.
#[test]
fn ec_omap_source_materializes_only_the_reply_batch() {
    let (_disk, ad, _sim) = new_adapter(128, 1, 0x718);
    let s = ec_spg();
    ad.submit_create(s);
    let h = hobj("budgeted-omap");
    let pairs: Vec<_> = (0..32u8)
        .map(|i| (vec![i], incompressible(16 << 10, i as u64 + 1)))
        .collect();
    ad.try_submit(
        s,
        &StoreTxn {
            ops: vec![apply(|t, c| {
                let o = t.obj(&gho(&h, Ghobject::NO_GEN));
                t.push(c, TxnOp::Touch { oid: o });
                t.push(
                    c,
                    TxnOp::OmapSetKeys {
                        oid: o,
                        pairs: pairs
                            .iter()
                            .map(|(k, v)| (k.as_slice(), v.as_slice()))
                            .collect(),
                    },
                );
            })],
        },
    )
    .unwrap();
    for (budget, limit) in [(16_385, 1024), (0, 0), (32_770, usize::MAX)] {
        ad.ec_omap_scan_bytes.set(0);
        let got = ad.ec_omap_read(s, &h, None, budget, limit).unwrap();
        let want = peering::ecopt::omap_batch(pairs.clone().into_iter(), budget, limit);
        assert_eq!(got, want);
        let sent = got
            .0
            .iter()
            .map(|(k, v)| (k.len() + v.len()) as u64)
            .sum::<u64>();
        assert_eq!(
            ad.ec_omap_scan_bytes.get(),
            sent,
            "source must not copy values that the reply discards"
        );
    }
    let empty_value = vec![7; 16 << 10];
    ad.try_submit(
        s,
        &StoreTxn {
            ops: vec![apply(|t, c| {
                let o = t.obj(&gho(&h, Ghobject::NO_GEN));
                t.push(
                    c,
                    TxnOp::OmapSetKeys {
                        oid: o,
                        pairs: vec![(b"".as_slice(), empty_value.as_slice())].into(),
                    },
                );
            })],
        },
    )
    .unwrap();
    let mut all = vec![(Vec::new(), empty_value)];
    all.extend(pairs);
    // Empty-key continuation, exact byte fits, oversized first entries, exhausted
    // cursors and unlimited entries preserve the shared EC batching contract.
    for after in [
        None,
        Some(b"".as_slice()),
        Some(b"\0".as_slice()),
        Some(b"\xff".as_slice()),
    ] {
        for budget in [0, 1, 16_384, 16_385, 32_769, u64::MAX] {
            for limit in [0, 1, 2, usize::MAX] {
                let want = peering::ecopt::omap_batch(
                    all.iter()
                        .filter(|(k, _)| after.is_none_or(|a| k.as_slice() > a))
                        .cloned(),
                    budget,
                    limit,
                );
                let got = ad.ec_omap_read(s, &h, after, budget, limit).unwrap();
                assert_eq!(got, want, "cursor={after:?} budget={budget} limit={limit}");
            }
        }
    }
}
