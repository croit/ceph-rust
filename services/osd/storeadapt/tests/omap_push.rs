// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Huge-omap object push building on the real store: bounded chunks, key cursor, no omap counter.
mod common;
use common::*;
use denc::types::*;
use peering::store::{MemStore, PgStoreOps, StoreOp, StoreTxn};
use replwire::ObjectRecoveryProgress;
use replwire::txn::*;
use std::collections::BTreeMap;

const KEYS: usize = 5000;

fn batch(g: &PgGen, h: &Hobject, from: usize, to: usize, first: bool) -> Vec<u8> {
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(g.spg));
    let ox = t.obj(&g.g(h));
    let oi;
    let kv: Vec<(Vec<u8>, Vec<u8>)> = (from..to)
        .map(|i| (format!("k{i:08}").into_bytes(), vec![(i % 251) as u8; 40]))
        .collect();
    if first {
        t.push(cx, TxnOp::Touch { oid: ox });
        oi = oi_bytes(h, Eversion::new(1, 1), 0);
        t.push(
            cx,
            TxnOp::SetAttr {
                oid: ox,
                name: b"_",
                value: &oi,
            },
        );
        t.push(
            cx,
            TxnOp::OmapSetHeader {
                oid: ox,
                header: b"hdr",
            },
        );
    }
    t.push(
        cx,
        TxnOp::OmapSetKeys {
            oid: ox,
            pairs: kv
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect(),
        },
    );
    t.encode_v9().unwrap()
}

fn apply(mem: &mut MemStore, ad: &Ad, pg: SpgT, d: Vec<u8>) {
    let t = StoreTxn {
        ops: vec![StoreOp::ApplyTxn {
            middle: Default::default(),
            data: d.into(),
        }],
    };
    mem.submit(pg, &t);
    ad.try_submit(pg, &t).unwrap();
}

/// Adapter + reference store holding one object `big` with KEYS omap keys.
fn big_pg() -> (store::dev::SimDisk, Ad, MemStore, SpgT, Hobject, PgGen) {
    let (disk, ad, _sim) = new_adapter(128, 1, 9);
    let pg = spg(1, 0);
    let mut mem = MemStore::new();
    mem.submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::CreatePg],
        },
    );
    ad.submit_create(pg);
    let g = PgGen::new(pg, 1);
    let h = Hobject::new(b"big", SnapId::NOSNAP, 0x1234, 1, b"");
    for (i, from) in (0..KEYS).step_by(1000).enumerate() {
        apply(&mut mem, &ad, pg, batch(&g, &h, from, from + 1000, i == 0));
    }
    (disk, ad, mem, pg, h, g)
}

/// Deep scrub of the whole PG through slices of `max_bytes`; returns the object map and the slice count.
fn deep_scrub(
    s: &impl PgStoreOps,
    pg: SpgT,
    max_bytes: u64,
    mut between: impl FnMut(usize),
) -> (BTreeMap<Hobject, replwire::scrubmsgs::ScrubObject>, usize) {
    let (mut cur, mut map, mut n) = (Hobject::MIN(), BTreeMap::new(), 0);
    loop {
        let part = s.build_scrub_map(pg, &cur, &Hobject::MAX(), true, 64, max_bytes);
        map.extend(part.objects);
        n += 1;
        between(n);
        match part.next {
            Some(x) => cur = x,
            None => return (map, n),
        }
        assert!(n < 10_000);
    }
}

#[test]
fn deep_scrub_of_huge_omap_parks_and_resumes() {
    let (_d, ad, mut mem, pg, h, g) = big_pg();
    let (want, n1) = deep_scrub(&mem, pg, u64::MAX, |_| {});
    assert_eq!(n1, 1);
    let o = &want[&h];
    assert_eq!(
        (o.object_omap_keys, o.object_omap_bytes),
        (KEYS as u64, KEYS as u64 * 40)
    );
    // budget of ~1 batch (1024 keys x 49 B): the omap digest is built over several slices, identical result
    let (got, n) = deep_scrub(&ad, pg, 50_000, |_| {});
    assert!(n >= 4, "streamed over {n} slices");
    assert_eq!(got, want);
    // a write between two slices invalidates the parked state: the result equals a fresh scrub of the new state
    let mut wrote = false;
    let (got, _) = deep_scrub(&ad, pg, 50_000, |i| {
        if i == 2 && !wrote {
            wrote = true;
            // overwrite an ALREADY digested key (same length) and bump the object_info, as every real write does
            let mut t = Transaction::new();
            let cx = t.coll(&CollT::Pg(pg));
            let ox = t.obj(&g.g(&h));
            let oi = oi_bytes(&h, Eversion::new(1, 2), 0);
            t.push(
                cx,
                TxnOp::SetAttr {
                    oid: ox,
                    name: b"_",
                    value: &oi,
                },
            );
            t.push(
                cx,
                TxnOp::OmapSetKeys {
                    oid: ox,
                    pairs: vec![(b"k00000000".as_slice(), [7u8; 40].as_slice())].into(),
                },
            );
            apply(&mut mem, &ad, pg, t.encode_v9().unwrap());
        }
    });
    assert!(wrote);
    let (fresh, _) = deep_scrub(&mem, pg, u64::MAX, |_| {});
    assert_eq!(got[&h].object_omap_keys, KEYS as u64);
    assert_eq!(got[&h].omap_digest, fresh[&h].omap_digest);
}

/// NT-deadcode-02: `osd_deep_scrub_keys` sets the omap page of the digest (was a fixed 1024): with a one-byte budget a
/// slice digests one page, so smaller pages take more slices; the digest is the same.
#[test]
fn deep_scrub_keys_sets_the_omap_page() {
    let (_d, ad, mem, pg, h, _g) = big_pg();
    let (want, _) = deep_scrub(&mem, pg, u64::MAX, |_| {});
    let (got, n_default) = deep_scrub(&ad, pg, 1, |_| {});
    ad.set_deep_scrub_reads(4 << 20, 100);
    let (small, n_small) = deep_scrub(&ad, pg, 1, |_| {});
    assert_eq!(got[&h], want[&h]);
    assert_eq!(small[&h], want[&h]);
    assert!(n_default < KEYS / 100, "default pages: {n_default} slices");
    assert!(n_small >= KEYS / 100, "100-key pages: {n_small} slices");
}

/// Two PGs of one core deep-scrub at the same time (own chunk + replica chunk, or two replica chunks): the parked
/// digest of PG A's huge object survives PG B's slices in between. A shared slot made every B slice drop A's state,
/// A restarted its object each slice and never finished (chunk write block held forever).
#[test]
fn parked_deep_scrub_survives_other_pgs_slices() {
    let (_d, ad, mem, pg, h, _g) = big_pg();
    let (want, _) = deep_scrub(&mem, pg, u64::MAX, |_| {});
    let pg2 = spg(1, 1);
    let mut mem2 = MemStore::new();
    mem2.submit(
        pg2,
        &StoreTxn {
            ops: vec![StoreOp::CreatePg],
        },
    );
    ad.submit_create(pg2);
    let g2 = PgGen::new(pg2, 1);
    let h2 = Hobject::new(b"small", SnapId::NOSNAP, 0x1235, 1, b"");
    apply(&mut mem2, &ad, pg2, batch(&g2, &h2, 0, 10, true));
    let (want2, _) = deep_scrub(&mem2, pg2, u64::MAX, |_| {});
    let (got, n) = deep_scrub(&ad, pg, 50_000, |_| {
        let (got2, _) = deep_scrub(&ad, pg2, 50_000, |_| {});
        assert_eq!(got2, want2);
    });
    assert!(n >= 4, "streamed over {n} slices");
    assert_eq!(got[&h], want[&h]);
}

#[test]
fn large_omap_push_is_chunked_by_cursor() {
    let (_disk, ad, mem, pg, h, _g) = big_pg();
    let ri = ad.recovery_info(pg, &h).expect("info");
    assert_eq!(ri.num_omap_keys, 0, "omap keys are not counted");
    for (limit, over) in [(KEYS as u64 - 1, true), (KEYS as u64, false)] {
        assert_eq!(ad.omap_keys_over(pg, &h, limit), Some(over));
        assert_eq!(mem.omap_keys_over(pg, &h, limit), Some(over));
    }
    assert_eq!(mem.recovery_info(pg, &h).unwrap(), ri);
    // chunk loop: bounded entries, cursor chain, every key exactly once, identical to the reference store
    let (mut p, mut got) = (ObjectRecoveryProgress::default(), BTreeMap::new());
    let mut chunks = 0;
    loop {
        let op = ad.build_push(pg, &ri, &p, 1 << 20, 100).unwrap();
        assert_eq!(op, mem.build_push(pg, &ri, &p, 1 << 20, 100).unwrap());
        assert!(op.omap_entries.len() <= 100);
        assert_eq!(
            !p.first,
            op.omap_header.is_empty(),
            "header only in chunk 1"
        );
        for (k, v) in &op.omap_entries {
            assert!(got.insert(k.clone(), v.clone()).is_none(), "key sent twice");
        }
        chunks += 1;
        p = op.after_progress;
        if !p.omap_complete {
            assert_eq!(
                p.omap_recovered_to,
                format!("k{:08}", chunks * 100).into_bytes(),
                "cursor = first key of the next chunk"
            );
        }
        if p.is_complete() {
            break;
        }
        assert!(chunks < 1000);
    }
    assert_eq!(chunks, KEYS / 100);
    assert_eq!(got.len(), KEYS);
    // byte budget bounds a chunk too (40 B values: ~45 B per entry)
    let op = ad
        .build_push(pg, &ri, &ObjectRecoveryProgress::default(), 1000, 100_000)
        .unwrap();
    assert!(op.omap_entries.len() <= 23, "{}", op.omap_entries.len());
}

/// A clean omap can be skipped only while recovery updates the live object in one chunk. A temp object needs
/// the keys again, even when the request initially marked omap complete (classic partial recovery).
#[test]
fn clean_omap_is_resent_when_data_requires_a_temp_object() {
    let (_disk, ad, _sim) = new_adapter(128, 1, 12);
    let pg = spg(1, 0);
    let h = Hobject::new(b"clean-omap", SnapId::NOSNAP, 0x1234, 1, b"");
    let g = PgGen::new(pg, 1);
    let mut mem = MemStore::new();
    mem.submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::CreatePg],
        },
    );
    ad.submit_create(pg);
    apply(&mut mem, &ad, pg, batch(&g, &h, 0, 2, true));
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(pg));
    let ox = t.obj(&g.g(&h));
    let oi = oi_bytes(&h, Eversion::new(1, 1), 16);
    t.push(
        cx,
        TxnOp::Write {
            oid: ox,
            off: 0,
            data: replwire::Data::new(b"0123456789abcdef"),
        },
    );
    t.push(
        cx,
        TxnOp::SetAttr {
            oid: ox,
            name: b"_",
            value: &oi,
        },
    );
    apply(&mut mem, &ad, pg, t.encode_v9().unwrap());
    let ri = ad.recovery_info(pg, &h).unwrap();
    for budget in [4, 16] {
        let mut progress = ObjectRecoveryProgress {
            omap_complete: true,
            ..Default::default()
        };
        let mut recovered = BTreeMap::new();
        let mut chunks = 0;
        loop {
            let op = ad.build_push(pg, &ri, &progress, budget, 100).unwrap();
            assert_eq!(op, mem.build_push(pg, &ri, &progress, budget, 100).unwrap());
            if chunks == 0 {
                assert!(op.before_progress.omap_complete);
                assert_eq!(
                    op.after_progress.omap_complete,
                    budget == 16,
                    "multi-chunk recovery must request omap for its fresh temp object"
                );
                assert!(op.omap_entries.is_empty());
            }
            recovered.extend(op.omap_entries);
            progress = op.after_progress;
            chunks += 1;
            if progress.is_complete() {
                break;
            }
            assert!(chunks < 20);
        }
        assert_eq!(recovered.len(), if budget == 16 { 0 } else { 2 });
    }
}

/// The recovery pull side on the omap LSM engine (adr 0610 phase 2b): the pull applies its push chunks as ordinary
/// object txns (touch, header, `omap_clear` on a partial copy, one sorted `set_keys` batch per chunk). Every key of the
/// source object lands in the engine, a stale local key is dropped by the clear, and the object check is clean.
#[test]
fn recovery_pull_writes_omap_into_the_engine() {
    with_omap_lsm(|| {
        let (_d, src, _mem, pg, h, g) = big_pg();
        let want = src.with_store(|st| st.omap_all(&CollT::Pg(pg), &g.g(&h)).unwrap());
        // a target store with the same PG and a stale key that the pull's `omap_clear` must remove
        let (_d2, dst, _sim) = new_adapter(128, 1, 10);
        dst.submit_create(pg);
        let mut t = Transaction::new();
        let cx = t.coll(&CollT::Pg(pg));
        let ox = t.obj(&g.g(&h));
        t.push(cx, TxnOp::Touch { oid: ox });
        t.push(
            cx,
            TxnOp::OmapSetKeys {
                oid: ox,
                pairs: vec![(b"stale".as_slice(), b"x".as_slice())].into(),
            },
        );
        dst.try_submit(
            pg,
            &StoreTxn {
                ops: vec![StoreOp::ApplyTxn {
                    middle: Default::default(),
                    data: t.encode_v9().unwrap().into(),
                }],
            },
        )
        .unwrap();
        let ri = src.recovery_info(pg, &h).unwrap();
        let (mut p, mut chunks) = (ObjectRecoveryProgress::default(), 0);
        loop {
            let op = src.build_push(pg, &ri, &p, 1 << 20, 100).unwrap();
            let mut t = Transaction::new();
            let cx = t.coll(&CollT::Pg(pg));
            let ox = t.obj(&g.g(&h));
            if p.first {
                t.push(cx, TxnOp::Touch { oid: ox });
                // `omap_clear` also drops the header: it belongs before the header of this chunk
                if !p.omap_complete {
                    t.push(cx, TxnOp::OmapClear { oid: ox });
                }
                if !op.attrset.is_empty() {
                    t.push(
                        cx,
                        TxnOp::SetAttrs {
                            oid: ox,
                            attrs: op
                                .attrset
                                .iter()
                                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                                .collect(),
                        },
                    );
                }
                if !op.omap_header.is_empty() {
                    t.push(
                        cx,
                        TxnOp::OmapSetHeader {
                            oid: ox,
                            header: &op.omap_header,
                        },
                    );
                }
            }
            let pairs: Vec<(&[u8], &[u8])> = op
                .omap_entries
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect();
            if !pairs.is_empty() {
                t.push(
                    cx,
                    TxnOp::OmapSetKeys {
                        oid: ox,
                        pairs: pairs.into(),
                    },
                );
            }
            dst.try_submit(
                pg,
                &StoreTxn {
                    ops: vec![StoreOp::ApplyTxn {
                        middle: Default::default(),
                        data: t.encode_v9().unwrap().into(),
                    }],
                },
            )
            .unwrap();
            chunks += 1;
            p = op.after_progress;
            if p.is_complete() {
                break;
            }
            assert!(chunks < 1000);
        }
        assert!(chunks > 1, "the push is chunked: {chunks}");
        let got = dst.with_store(|st| st.omap_all(&CollT::Pg(pg), &g.g(&h)).unwrap());
        assert_eq!(got.len(), KEYS);
        assert_eq!(got, want);
        assert_eq!(
            dst.with_store(|st| st.omap_header(&CollT::Pg(pg), &g.g(&h)).unwrap()),
            b"hdr"
        );
        let rep = dst.with_store(|st| st.check(false)).unwrap();
        assert!(rep.errors.is_empty(), "{:?}", rep.errors);
        // plus the PG's own state keys in the pgmeta omap
        assert!(rep.omap_keys > KEYS as u64, "{rep:?}");
    });
}

/// The omap LSM engine (adr 0610): parked deep scrub and cursor-chunked push over flushed runs and memtables.
#[test]
fn deep_scrub_and_chunked_push_on_the_omap_lsm() {
    with_omap_lsm(|| {
        let (_d, ad, ..) = big_pg();
        let st = ad
            .with_store(|st| st.shards[0].sh.olsm_stats())
            .expect("engine on");
        assert!(st.flushes > 0, "the fixture reaches the runs: {st:?}");
        deep_scrub_of_huge_omap_parks_and_resumes();
        parked_deep_scrub_survives_other_pgs_slices();
        large_omap_push_is_chunked_by_cursor();
    });
}

/// `omap_keys_over` at the small edges (0..=2 keys, limit 0..=2) and the first push chunk's
/// object_info check / xattr set against the reference store. Limit 0 admits one key like a push
/// chunk does (one key = one chunk, not heavy); the reference store answers `len > 0` there.
#[test]
fn omap_keys_over_edges_and_first_chunk_version_check() {
    let (_disk, ad, _sim) = new_adapter(128, 1, 11);
    let pg = spg(1, 0);
    let mut mem = MemStore::new();
    mem.submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::CreatePg],
        },
    );
    ad.submit_create(pg);
    let g = PgGen::new(pg, 1);
    for n in 0..=2usize {
        let h = Hobject::new(
            format!("o{n}").as_bytes(),
            SnapId::NOSNAP,
            0x40 + n as u32,
            1,
            b"",
        );
        apply(&mut mem, &ad, pg, batch(&g, &h, 0, n, true));
        for limit in 0..=2u64 {
            let want = n as u64 > limit.max(1);
            assert_eq!(
                ad.omap_keys_over(pg, &h, limit),
                Some(want),
                "{n} keys, limit {limit}"
            );
            if limit > 0 {
                assert_eq!(
                    mem.omap_keys_over(pg, &h, limit),
                    Some(want),
                    "ref {n}, {limit}"
                );
            }
        }
        let ri = ad.recovery_info(pg, &h).expect("info");
        let first = ObjectRecoveryProgress::default();
        let op = ad.build_push(pg, &ri, &first, 1 << 20, 100).unwrap();
        assert_eq!(op, mem.build_push(pg, &ri, &first, 1 << 20, 100).unwrap());
        assert!(op.attrset.contains_key(b"_".as_slice()));
        let mut stale = ri.clone();
        stale.version = Eversion::new(1, 2);
        for p in [first.clone(), op.after_progress.clone()] {
            assert!(matches!(
                ad.build_push(pg, &stale, &p, 1 << 20, 100),
                Err(peering::store::StoreReadError::VersionMismatch)
            ));
        }
    }
    let gone = Hobject::new(b"gone", SnapId::NOSNAP, 0x50, 1, b"");
    let ri = ad
        .recovery_info(pg, &Hobject::new(b"o1", SnapId::NOSNAP, 0x41, 1, b""))
        .unwrap();
    let ri = replwire::ObjectRecoveryInfo { soid: gone, ..ri };
    assert!(matches!(
        ad.build_push(pg, &ri, &ObjectRecoveryProgress::default(), 1 << 20, 100),
        Err(peering::store::StoreReadError::NoObject)
    ));
}
