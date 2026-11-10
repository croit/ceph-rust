// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Pool compression options reach the store through the adapter (adr 0059 am. 1): mode x alloc hint decide per txn, the
//! data reads back unchanged, `compress_stats` reports what the store compressed.
mod common;
use common::*;
use denc::types::*;
use peering::store::{PgStoreOps, PoolCompOpts, StoreOp, StoreTxn};
use replwire::txn::*;

fn opts(mode: &str, alg: &str) -> PoolCompOpts {
    PoolCompOpts {
        mode: mode.into(),
        algorithm: alg.into(),
        ..Default::default()
    }
}

fn cdata(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i / 300 % 7) as u8).collect()
}

/// One txn: optional alloc hint, then a write of `d` to object `name`.
fn write(ad: &mut Ad, s: SpgT, name: &str, hint: Option<u32>, d: &[u8]) {
    let h = Hobject::new(
        name.as_bytes(),
        SnapId::NOSNAP,
        0x55,
        s.pgid.pool as i64,
        b"",
    );
    let g = storeadapt::gh(s, &h);
    let mut b = Transaction::new();
    let c = b.coll(&CollT::Pg(s));
    let o = b.obj(&g);
    if let Some(flags) = hint {
        b.push(
            c,
            TxnOp::SetAllocHint {
                oid: o,
                expected_object_size: 1 << 20,
                expected_write_size: 1 << 16,
                flags,
            },
        );
    }
    b.push(
        c,
        TxnOp::Write {
            oid: o,
            off: 0,
            data: Data::new(d),
        },
    );
    let mut t = StoreTxn::default();
    t.push(StoreOp::ApplyTxn {
        middle: Default::default(),
        data: b.encode_v9().unwrap().into(),
    });
    ad.submit(s, &t);
    assert_eq!(ad.object(s, &h).unwrap().data, d, "{name} reads back");
}

#[test]
fn pool_options_decide_per_txn_and_data_reads_back() {
    let (_d, mut ad, _) = new_adapter(128, 1, 3);
    let s = spg(1, 0);
    ad.submit_create(s);
    let d = cdata(128 << 10);
    // no options: nothing compressed
    write(&mut ad, s, "a", None, &d);
    assert_eq!(ad.compress_stats(s), (0, 0));
    // passive: only with the COMPRESSIBLE hint (256)
    ad.set_pool_compression(1, &opts("passive", "lz4"));
    write(&mut ad, s, "b", None, &d);
    assert_eq!(ad.compress_stats(s), (0, 0));
    write(&mut ad, s, "c", Some(256), &d);
    let (p1, o1) = ad.compress_stats(s);
    assert_eq!(o1, 128 << 10);
    assert!(p1 > 0 && p1 < o1 / 2, "{p1} {o1}");
    // aggressive: unless INCOMPRESSIBLE (512)
    ad.set_pool_compression(1, &opts("aggressive", "zstd"));
    write(&mut ad, s, "d", Some(512), &d);
    assert_eq!(ad.compress_stats(s).1, o1);
    write(&mut ad, s, "e", None, &d);
    assert_eq!(ad.compress_stats(s).1, 2 * o1);
    // unknown algorithm: stored uncompressed; mode none: same
    ad.set_pool_compression(1, &opts("force", "brotli"));
    write(&mut ad, s, "f", None, &d);
    ad.set_pool_compression(1, &opts("none", "lz4"));
    write(&mut ad, s, "g", None, &d);
    assert_eq!(ad.compress_stats(s).1, 2 * o1);
    // other pools are unaffected
    let s2 = spg(2, 0);
    ad.submit_create(s2);
    ad.set_pool_compression(1, &opts("force", "snappy"));
    write(&mut ad, s2, "h", None, &d);
    assert_eq!(ad.compress_stats(s2), (0, 0));
}

/// EC shard transaction: the shard collection (shard id set) with the hint ecback carries to every shard
/// (OQ 99 / adr 0059 am. 6): passive + COMPRESSIBLE compresses, aggressive + INCOMPRESSIBLE does not, like replicated.
#[test]
fn ec_shard_txn_hint_decides_compression() {
    let (_d, mut ad, _) = new_adapter(128, 1, 3);
    let s = SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId(2),
    };
    ad.submit_create(s);
    let d = cdata(128 << 10);
    ad.set_pool_compression(1, &opts("passive", "lz4"));
    write(&mut ad, s, "a", None, &d);
    assert_eq!(ad.compress_stats(s), (0, 0), "passive without hint");
    write(&mut ad, s, "b", Some(256), &d);
    let (p, o) = ad.compress_stats(s);
    assert_eq!(o, 128 << 10, "passive + COMPRESSIBLE compresses");
    assert!(p > 0 && p < o / 2, "{p} {o}");
    ad.set_pool_compression(1, &opts("aggressive", "zstd"));
    write(&mut ad, s, "c", Some(512), &d);
    assert_eq!(
        ad.compress_stats(s).1,
        o,
        "aggressive + INCOMPRESSIBLE stores plain"
    );
    write(&mut ad, s, "d", None, &d);
    assert_eq!(
        ad.compress_stats(s).1,
        2 * o,
        "aggressive without hint compresses"
    );
}
