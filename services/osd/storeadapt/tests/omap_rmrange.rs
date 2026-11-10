// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Replica-side omap range removal on the real store: the repop txn removes the range itself, over a cold range and
//! after sets inside the range; what is left is exactly the keys outside it (recount of the stored entries).
mod common;
use common::*;
use denc::types::*;
use peering::store::{Queued, StoreOp, StoreTxn};
use replwire::txn::*;
use store::obj::StoreCfg;
use store::shard::ShardCfg;

fn nkeys() -> usize {
    std::env::var("NKEYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60_000)
}

fn key(i: usize) -> Vec<u8> {
    format!("{i:08}/some/prefix/with/a/typical/s3/key/name").into_bytes()
}

fn txn<'a>(
    g: &PgGen,
    h: &Hobject,
    ver: u64,
    f: impl FnOnce(&mut Transaction<'a>, Cx, Ox),
) -> StoreTxn {
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(g.spg));
    let ox = t.obj(&g.g(h));
    f(&mut t, cx, ox);
    let oi: &'static [u8] = Box::leak(oi_bytes(h, Eversion::new(1, ver), 0).into_boxed_slice());
    t.push(
        cx,
        TxnOp::SetAttr {
            oid: ox,
            name: b"_",
            value: oi,
        },
    );
    StoreTxn {
        ops: vec![StoreOp::ApplyTxn {
            middle: Default::default(),
            data: t.encode_v9().unwrap().into(),
        }],
    }
}

fn set_keys(g: &PgGen, h: &Hobject, ver: u64, from: usize, to: usize) -> StoreTxn {
    let kv: Vec<(Vec<u8>, Vec<u8>)> = (from..to)
        .map(|i| (key(i), vec![(i % 251) as u8; 100]))
        .collect();
    txn(g, h, ver, |t, cx, ox| {
        if ver == 1 {
            t.push(cx, TxnOp::Touch { oid: ox });
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
    })
}

fn rm_range(g: &PgGen, h: &Hobject, ver: u64, a: usize, b: usize) -> StoreTxn {
    let (a, b) = (key(a), key(b));
    txn(g, h, ver, |t, cx, ox| {
        t.push(
            cx,
            TxnOp::OmapRmKeyRange {
                oid: ox,
                first: &a,
                last: &b,
            },
        )
    })
}

fn cfg() -> StoreCfg {
    StoreCfg {
        shard: ShardCfg {
            cache_pages: 2048,
            ..StoreCfg::default().shard
        },
    }
}

/// PG with one object of NKEYS omap keys, checkpointed; returns the durable image.
fn fixture() -> (
    store::dev::SimImage,
    store::dev::SimConfig,
    SpgT,
    Hobject,
    PgGen,
) {
    let sim = sim_cfg(1024, 5);
    let img = fresh_image(&sim, 1, 4096);
    let (disk, ad) = open(&img, &sim, &cfg());
    let pg = spg(1, 0);
    ad.submit_create(pg);
    let g = PgGen::new(pg, 1);
    let h = Hobject::new(b"idx", SnapId::NOSNAP, 0x77, 1, b"");
    for (n, from) in (0..nkeys()).step_by(500).enumerate() {
        ad.try_submit(pg, &set_keys(&g, &h, n as u64 + 1, from, from + 500))
            .unwrap();
    }
    ad.with_store(|st| st.checkpoint()).unwrap();
    let img = disk.image();
    (img, sim, pg, h, g)
}

fn durable(ad: &Ad, spg: SpgT, t: &StoreTxn, token: u64) {
    match ad.queue_txn(spg, t, token) {
        Queued::Pending => {}
        Queued::Durable => return,
        o => panic!("{o:?}"),
    }
    for _ in 0..200_000 {
        let mut out = vec![];
        ad.poll_store(&mut out);
        if out.contains(&(spg, token)) {
            return;
        }
        ad.with_store(|st| st.idle());
    }
    panic!("never durable");
}

fn pg_coll(s: SpgT) -> CollT {
    CollT::Pg(s)
}

/// Recount of the stored omap entries: `(keys, user key + value bytes)`.
fn recount(ad: &Ad, pg: SpgT, h: &Hobject, g: &PgGen) -> (u64, u64) {
    let r = ad
        .with_store(|st| st.scrub(&pg_coll(pg), &g.g(h), 0))
        .unwrap();
    (r.omap_keys, r.omap_bytes)
}

/// Exactly the keys outside `[a, b)` are left: the recount, and the keys at both borders.
fn assert_left_outside(ad: &Ad, pg: SpgT, h: &Hobject, g: &PgGen, a: usize, b: usize) {
    let (k, by) = recount(ad, pg, h, g);
    assert_eq!(k, (nkeys() - (b - a)) as u64);
    assert_eq!(by, k * (key(0).len() as u64 + 100));
    let (ka, kb) = (key(a), key(b));
    let (before, after) = (key(a - 1), key(b - 1));
    let got = ad
        .with_store(|st| st.omap_get(&pg_coll(pg), &g.g(h), &[&before, &ka, &after, &kb]))
        .unwrap();
    assert_eq!(
        got.keys().collect::<Vec<_>>(),
        [&before, &kb],
        "the keys just outside the range stay, the ones at its first and last position are gone"
    );
}

/// A removal over a range nothing of which is cached (fresh open of the checkpointed image).
#[test]
fn replica_range_removal_over_a_cold_range_is_exact() {
    let (img, sim, pg, h, g) = fixture();
    let (a, b) = (nkeys() / 10, nkeys() * 9 / 10);
    let (_d, ad) = open(&img, &sim, &cfg());
    durable(&ad, pg, &rm_range(&g, &h, 1000, a, b), 1);
    assert_left_outside(&ad, pg, &h, &g, a, b);
}

/// Sets inside the range (a new key, a replaced key; earlier repops of the same PG) before the removal: the removal
/// drops them with the rest of the range.
#[test]
fn sets_inside_the_range_before_a_removal_go_with_it() {
    let (img, sim, pg, h, g) = fixture();
    let (_d, ad) = open(&img, &sim, &cfg());
    let (a, b) = (1000, 9000);
    // new key inside the range, replaced key inside the range, then the removal
    durable(&ad, pg, &set_keys(&g, &h, 2000, a + 10, a + 12), 1);
    let extra = txn(&g, &h, 2001, |t, cx, ox| {
        t.push(
            cx,
            TxnOp::OmapSetKeys {
                oid: ox,
                pairs: vec![(b"00001500/zz-new-key".as_slice(), b"v".as_slice())].into(),
            },
        )
    });
    durable(&ad, pg, &extra, 2);
    durable(&ad, pg, &rm_range(&g, &h, 2002, a, b), 3);
    assert_left_outside(&ad, pg, &h, &g, a, b);
}
