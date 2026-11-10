// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Hardening: remote input must never panic or corrupt. Random, mutated and extreme RepOp transactions are fed
//! to `MemStore` and to the NVMe store adapter (async queue path). Required: no panic or half-apply.
//! Synchronous garbage is rejected; a deferred failure stops the adapter before a later PG persist (ADR 0066).
mod common;
use common::*;
use denc::types::*;
use peering::store::{MemStore, PgStoreOps, Queued, StoreOp, StoreTxn};
use replwire::txn::*;
use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use store::rng::Rng;

const EXTREME: [u64; 10] = [
    0,
    1,
    4095,
    1 << 20,
    (128 << 20) - 1,
    128 << 20,
    (128 << 20) + 1,
    u64::MAX / 2,
    u64::MAX - 3,
    u64::MAX,
];

fn pick(r: &mut Rng, v: &[u64]) -> u64 {
    v[r.below(v.len() as u64) as usize]
}

/// Structurally valid transactions with hostile values (huge offsets/lengths, missing sources, foreign collections).
fn extreme_txn(g: &PgGen, r: &mut Rng) -> Vec<u8> {
    let mut t = Transaction::new();
    let own = t.coll(&CollT::Pg(g.spg));
    let other = if r.pct(20) {
        t.coll(&CollT::Pg(spg(g.spg.pgid.pool + 1, 3)))
    } else {
        own
    };
    let n = r.range(1, 6);
    let data = vec![0xabu8; 700];
    for _ in 0..n {
        let a = g.names[r.below(g.names.len() as u64) as usize].clone();
        let b = g.names[r.below(g.names.len() as u64) as usize].clone();
        let (oa, ob) = (t.obj(&g.g(&a)), t.obj(&g.g(&b)));
        let op = match r.below(9) {
            0 => TxnOp::Write {
                oid: oa,
                off: pick(r, &EXTREME),
                data: Data::new(&data[..r.below(700) as usize]),
            },
            1 => TxnOp::Zero {
                oid: oa,
                off: pick(r, &EXTREME),
                len: pick(r, &EXTREME),
            },
            2 => TxnOp::Truncate {
                oid: oa,
                size: pick(r, &EXTREME),
            },
            3 => TxnOp::CloneRange2 {
                oid: oa,
                dest_oid: ob,
                src_off: pick(r, &EXTREME),
                len: pick(r, &EXTREME),
                dest_off: pick(r, &EXTREME),
            },
            4 => TxnOp::Clone {
                oid: oa,
                dest_oid: ob,
            },
            5 => TxnOp::Remove { oid: oa },
            6 => TxnOp::TryRename {
                oid: oa,
                dest_oid: ob,
            },
            7 => TxnOp::OmapSetHeader {
                oid: oa,
                header: &data[..r.below(700) as usize],
            },
            _ => TxnOp::Touch { oid: oa },
        };
        t.push(if r.pct(30) { other } else { own }, op);
    }
    t.encode_v9().unwrap()
}

fn mutate(r: &mut Rng, valid: &[u8]) -> Vec<u8> {
    let mut v = valid.to_vec();
    match r.below(5) {
        0 => {
            for _ in 0..r.range(1, 8) {
                if !v.is_empty() {
                    let i = r.below(v.len() as u64) as usize;
                    v[i] ^= 1 << r.below(8);
                }
            }
        }
        1 => v.truncate(r.below(v.len() as u64 + 1) as usize),
        2 => {
            let mut x = vec![0u8; r.range(1, 64) as usize];
            r.fill(&mut x);
            let at = r.below(v.len() as u64 + 1) as usize;
            v.splice(at..at, x);
        }
        3 => {
            for _ in 0..r.range(1, 4) {
                if !v.is_empty() {
                    let i = r.below(v.len() as u64) as usize;
                    v[i] = [0, 0xff, 0x7f, 0x80][r.below(4) as usize];
                }
            }
        }
        _ => {
            let at = r.below(v.len() as u64 + 1) as usize;
            let n = r.below(40) as usize;
            v.drain(at..(at + n).min(v.len()));
        }
    }
    v
}

fn garbage(r: &mut Rng) -> Vec<u8> {
    let mut v = vec![0u8; r.below(300) as usize];
    r.fill(&mut v);
    if r.pct(60) && v.len() > 8 {
        // plausible versioned header: struct_v 9, compat 9, length
        v[0] = 9;
        v[1] = 9;
        let l = (v.len() - 6) as u32;
        v[2..6].copy_from_slice(&l.to_le_bytes());
    }
    v
}

fn store_txn(r: &mut Rng, bytes: Vec<u8>) -> StoreTxn {
    let mut t = StoreTxn::default();
    if r.pct(50) {
        t.push(StoreOp::ApplyTxn {
            middle: Default::default(),
            data: bytes.into(),
        });
    } else {
        let split = r.below(bytes.len() as u64 + 1) as usize;
        t.push(StoreOp::ApplyTxn {
            middle: bytes[..split].to_vec().into(),
            data: bytes[split..].to_vec().into(),
        });
    }
    t
}

fn inputs(seed: u64, n: usize) -> (SpgT, Vec<StoreTxn>) {
    let s = spg(1, 0);
    let mut g = PgGen::new(s, seed);
    let mut r = Rng::new(seed ^ 0x77);
    let mut exist = BTreeSet::new();
    let mut out = Vec::new();
    for _ in 0..n {
        let valid = g.object_txn(&mut exist);
        let bytes = match r.below(10) {
            0..=1 => valid,
            2..=5 => mutate(&mut r, &valid),
            6 => garbage(&mut r),
            _ => extreme_txn(&g, &mut r),
        };
        out.push(store_txn(&mut r, bytes));
    }
    (s, out)
}

#[test]
fn memstore_survives_garbage() {
    for seed in 0..300 {
        let (s, txns) = inputs(seed, 40);
        let mut m = MemStore::new();
        m.submit(
            s,
            &StoreTxn {
                ops: vec![StoreOp::CreatePg],
            },
        );
        for (i, t) in txns.iter().enumerate() {
            let r = catch_unwind(AssertUnwindSafe(|| m.queue(s, t, i as u64)));
            assert!(r.is_ok(), "seed {seed} input {i}: MemStore panicked");
        }
    }
}

#[test]
fn adapter_survives_garbage() {
    let mut rejected = 0u64;
    let mut accepted = 0u64;
    for seed in 0..60 {
        let (s, txns) = inputs(seed, 40);
        let (_d, mut ad, _sim) = new_adapter(256, 2, seed);
        ad.submit_create(s);
        for (i, t) in txns.iter().enumerate() {
            let r = catch_unwind(AssertUnwindSafe(|| ad.queue(s, t, i as u64)));
            match r {
                Err(_) => panic!("seed {seed} input {i}: adapter panicked"),
                Ok(Queued::Rejected(_)) => rejected += 1,
                Ok(Queued::Durable | Queued::Pending) => accepted += 1,
                Ok(Queued::Failed(m)) => {
                    panic!("seed {seed} input {i}: garbage caused a local failure: {m}")
                }
            }
        }
        // drain completions
        // through the adapter's own poll (as the OSD does): a parked txn's error fail-stops it (adr 0066)
        let mut done = Vec::new();
        let mut drained = Ok(());
        for _ in 0..1_000_000 {
            ad.poll_commits(&mut done);
            if ad.failed().is_some() {
                drained = Err(ad
                    .queue_errors
                    .borrow()
                    .last()
                    .map_or(store::obj::ObjError::Eio("poll".into()), |e| e.2.clone()));
                break;
            }
            if ad.pending() == 0 {
                break;
            }
            ad.with_store(|st| st.idle());
        }
        if let Err(e) = drained {
            // Malformed input behind a parked write is rejected asynchronously. The PG's
            // in-memory log cannot safely continue past that failure (ADR 0066).
            assert!(Ad::is_input_error(&e), "seed {seed}: local failure {e:?}");
            assert!(ad.failed().is_some());
            let errors = ad.queue_errors.borrow();
            assert!(errors.iter().any(|(_, _, err)| err == &e));
            rejected += errors.len() as u64;
            assert!(
                ad.with_store(|st| st.check(true))
                    .unwrap()
                    .errors
                    .is_empty()
            );
            continue;
        }
        assert!(
            ad.failed().is_none(),
            "seed {seed}: adapter failed after garbage: {:?}",
            ad.failed()
        );
        assert!(
            ad.pending() == 0,
            "seed {seed}: txns still pending after sync"
        );
        let rep = ad.with_store(|st| st.check(true)).unwrap();
        assert!(
            rep.errors.is_empty(),
            "seed {seed}: checker: {:?}",
            rep.errors
        );
        // still healthy: a valid txn applies
        let mut g = PgGen::new(s, seed + 1000);
        let mut exist = BTreeSet::new();
        let ok = StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: Default::default(),
                data: g.object_txn(&mut exist).into(),
            }],
        };
        assert!(
            matches!(ad.queue(s, &ok, 9999), Queued::Durable | Queued::Pending),
            "seed {seed}: valid txn refused after garbage"
        );
    }
    assert!(
        rejected > 200 && accepted > 200,
        "test is vacuous: rejected {rejected} accepted {accepted}"
    );
}

/// Missing-source semantics (replication.md 1.6): Clone/CloneRange2 of a missing source fail the transaction,
/// Truncate of a missing object is a no-op; a source offset past the end reads zeros. Same in both stores.
#[test]
fn missing_source_semantics_agree() {
    let s = spg(1, 0);
    let g = PgGen::new(s, 5);
    let (a, b) = (g.names[0].clone(), g.names[1].clone());
    let build = |f: &dyn Fn(&mut Transaction<'_>, Ox, Ox, Cx)| {
        let mut t = Transaction::new();
        let c = t.coll(&CollT::Pg(s));
        let (oa, ob) = (t.obj(&g.g(&a)), t.obj(&g.g(&b)));
        f(&mut t, oa, ob, c);
        StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: Default::default(),
                data: t.encode_v9().unwrap().into(),
            }],
        }
    };
    let (_d, mut ad, _) = new_adapter(64, 1, 3);
    ad.submit_create(s);
    let mut mem = MemStore::new();
    mem.submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::CreatePg],
        },
    );
    // truncate of a missing object: no-op, does not create
    let t = build(&|t, oa, _, c| t.push(c, TxnOp::Truncate { oid: oa, size: 100 }));
    assert!(matches!(mem.queue(s, &t, 1), Queued::Durable));
    assert!(matches!(
        ad.queue(s, &t, 1),
        Queued::Durable | Queued::Pending
    ));
    assert!(mem.objects(s).is_empty() && ad.objects(s).is_empty());
    // clone / clone_range of a missing source: transaction refused, nothing created
    for t in [
        build(&|t, oa, ob, c| {
            t.push(
                c,
                TxnOp::Clone {
                    oid: oa,
                    dest_oid: ob,
                },
            )
        }),
        build(&|t, oa, ob, c| {
            t.push(
                c,
                TxnOp::CloneRange2 {
                    oid: oa,
                    dest_oid: ob,
                    src_off: 0,
                    len: 10,
                    dest_off: 0,
                },
            )
        }),
    ] {
        assert!(matches!(mem.queue(s, &t, 2), Queued::Rejected(_)));
        assert!(matches!(ad.queue(s, &t, 2), Queued::Rejected(_)));
        assert!(mem.objects(s).is_empty() && ad.objects(s).is_empty());
    }
    // clone_range with the source offset past the end must not panic and reads zeros
    let t = build(&|t, oa, _, c| {
        t.push(
            c,
            TxnOp::Write {
                oid: oa,
                off: 0,
                data: Data::new(&[7u8; 100]),
            },
        )
    });
    mem.queue(s, &t, 3);
    ad.queue(s, &t, 3);
    let t = build(&|t, oa, ob, c| {
        t.push(
            c,
            TxnOp::CloneRange2 {
                oid: oa,
                dest_oid: ob,
                src_off: 5000,
                len: 64,
                dest_off: 0,
            },
        )
    });
    assert!(matches!(mem.queue(s, &t, 4), Queued::Durable));
    assert!(matches!(
        ad.queue(s, &t, 4),
        Queued::Durable | Queued::Pending
    ));
    let (m, d) = (mem.objects(s), ad.objects(s));
    assert_eq!(m.get(&b).map(|o| o.data.clone()), Some(vec![0u8; 64]));
    assert_eq!(d.get(&b).map(|o| o.data.clone()), Some(vec![0u8; 64]));
}

/// Local failure policy: running the device out of space (ENOSPC on commit) must surface as a sticky
/// `Queued::Failed` / `failed()`, never as a panic; the durable state stays consistent.
#[test]
fn enospc_is_a_sticky_failure_not_a_panic() {
    let s = spg(1, 0);
    let (_d, mut ad, _) = new_adapter(24, 1, 11);
    ad.submit_create(s);
    let h = PgGen::new(s, 1).names[0].clone();
    let mut failed = None;
    for i in 0..2000u64 {
        let mut t = Transaction::new();
        let c = t.coll(&CollT::Pg(s));
        let g = PgGen::new(s, 1).g(&h);
        let o = t.obj(&g);
        let big = vec![i as u8; 1 << 20];
        t.push(
            c,
            TxnOp::Write {
                oid: o,
                off: i * (1 << 20) % (64 << 20),
                data: Data::new(&big),
            },
        );
        let st = StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: Default::default(),
                data: t.encode_v9().unwrap().into(),
            }],
        };
        match catch_unwind(AssertUnwindSafe(|| ad.queue(s, &st, i))) {
            Err(_) => panic!("panic on ENOSPC"),
            Ok(Queued::Failed(m)) => {
                failed = Some(m);
                break;
            }
            Ok(_) => {}
        }
    }
    assert!(failed.is_some(), "device never filled up");
    assert!(ad.failed().is_some());
    assert!(
        matches!(
            ad.queue(
                s,
                &StoreTxn {
                    ops: vec![StoreOp::PutEpoch(3)]
                },
                1
            ),
            Queued::Failed(_)
        ),
        "failure is sticky"
    );
    let mut out = Vec::new();
    ad.poll_commits(&mut out); // must not panic either
}

/// adr 0021 am. 23 review: the txns of a PG re-created while its old incarnation's deletion cannot proceed (NoSpace)
/// wait in `deferred`. Meanwhile reads see an empty PG (never the old objects); a txn rejected when it is finally
/// applied is never acknowledged (nothing applied) and fails the store (fail-stop, adr 0066: the PG logged it in memory
/// already); the process exits (acks of earlier txns do not matter any more); the old object never comes back.
#[test]
fn deferred_recreate_hides_the_old_pg_and_fail_stops_on_a_rejected_txn() {
    let s = spg(1, 0);
    let g = PgGen::new(s, 7);
    let (a, b) = (g.names[0].clone(), g.names[1].clone());
    let build = |f: &dyn Fn(&mut Transaction<'_>, Ox, Ox, Cx)| {
        let mut t = Transaction::new();
        let c = t.coll(&CollT::Pg(s));
        let (oa, ob) = (t.obj(&g.g(&a)), t.obj(&g.g(&b)));
        f(&mut t, oa, ob, c);
        StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: Default::default(),
                data: t.encode_v9().unwrap().into(),
            }],
        }
    };
    static PAY: [[u8; 100]; 2] = [[1; 100], [2; 100]];
    let write = |which: u8| {
        build(&move |t, oa, ob, c| {
            t.push(
                c,
                TxnOp::Write {
                    oid: if which == 0 { oa } else { ob },
                    off: 0,
                    data: Data::new(&PAY[which as usize]),
                },
            )
        })
    };
    let (_d, mut ad, _) = new_adapter(64, 1, 3);
    ad.submit_create(s);
    ad.try_submit(s, &write(0)).unwrap(); // old incarnation: object a
    let rm = StoreTxn {
        ops: vec![StoreOp::RemovePg],
    };
    assert!(matches!(ad.queue(s, &rm, 1), Queued::Pending));
    ad.remove_nospace_from.set(1);
    let create = StoreTxn {
        ops: vec![StoreOp::CreatePg],
    };
    // clone of the (gone) object a: rejected once applied to the re-created, empty PG
    let bad = build(&|t, oa, ob, c| {
        t.push(
            c,
            TxnOp::Clone {
                oid: oa,
                dest_oid: ob,
            },
        )
    });
    for (tok, t) in [(10, &create), (11, &bad), (12, &write(1))] {
        assert_eq!(ad.queue(s, t, tok), Queued::Pending, "txn {tok} waits");
    }
    assert!(ad.failure().is_none(), "{:?}", ad.failure());
    // the old incarnation is invisible while the re-create waits
    let l = ad.list_objects(s, &Hobject::MIN(), 0, 100).unwrap();
    assert!(l.objs.is_empty() && l.corrupt.is_empty(), "{l:?}");
    assert!(ad.object_version(s, &a).is_err());
    assert_eq!(ad.object_stats(s), (0, 0));
    ad.remove_nospace_from.set(0);
    let mut out = Vec::new();
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while ad.failure().is_none() {
        assert!(
            std::time::Instant::now() < end,
            "WARNING TIMEOUT deferred txns applied exceeded 10s (deletion finish)"
        );
        PgStoreOps::step_removals(&ad, u64::MAX);
        ad.poll_commits(&mut out);
        ad.with_store(|st| st.idle());
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let toks: Vec<u64> = out.iter().map(|x| x.1).collect();
    assert!(
        !toks.contains(&11),
        "a rejected (not applied) txn must never be acked: {toks:?}"
    );
    assert!(
        !toks.contains(&12),
        "nothing after the refused txn: {toks:?}"
    );
    assert_eq!(ad.rejected.get(), 1);
    let f = ad.failure().unwrap();
    assert!(f.contains("deferred transaction refused"), "{f}");
    assert!(!ad.objects(s).contains_key(&a), "old object resurrected");
}
