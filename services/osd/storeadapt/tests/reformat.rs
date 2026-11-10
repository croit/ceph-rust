// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! Deep-scrub reformat engines over the NVMe store (adr 0593-dedup-deep-scrub-reformat, doc/spec/dedup-reformat.md 11):
//! lazy recompression, defragmentation, rewrites refused for objects changed during their scrub, data version tracking
//! following the pool's engines, unknown engine names, the scrub result unaffected.
mod common;
use common::*;
use denc::types::*;
use peering::store::{PgStoreOps, PoolCompOpts, StoreOp, StoreTxn};
use replwire::txn::*;
use store::obj::SpanStats;

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

fn hobj(s: SpgT, name: &str) -> Hobject {
    Hobject::new(
        name.as_bytes(),
        SnapId::NOSNAP,
        0x55,
        s.pgid.pool as i64,
        b"",
    )
}

fn write(ad: &mut Ad, s: SpgT, name: &str, off: u64, d: &[u8]) {
    let g = storeadapt::gh(s, &hobj(s, name));
    let mut b = Transaction::new();
    let c = b.coll(&CollT::Pg(s));
    let o = b.obj(&g);
    b.push(
        c,
        TxnOp::Write {
            oid: o,
            off,
            data: Data::new(d),
        },
    );
    let mut t = StoreTxn::default();
    t.ops.push(StoreOp::ApplyTxn {
        middle: Default::default(),
        data: b.encode_v9().unwrap().into(),
    });
    ad.submit(s, &t);
}

/// One whole deep scrub of the PG (slices of `max_bytes`); the scrub map's data digests.
fn deep_scrub(ad: &Ad, s: SpgT, max_bytes: u64) -> Vec<(Hobject, u32)> {
    let mut out = Vec::new();
    let mut start = Hobject::MIN();
    for _ in 0..10_000 {
        step(ad);
        let p = ad.scrub_slice(s, &start, &Hobject::MAX(), true, 64, max_bytes);
        out.extend(p.objects.iter().map(|(h, o)| (h.clone(), o.digest)));
        match p.next {
            Some(n) => start = n,
            None => return out,
        }
    }
    panic!("scrub did not finish");
}

/// Let parked media reads complete (the scrub never waits for IO itself).
fn step(ad: &Ad) {
    let mut done = Vec::new();
    ad.poll_store(&mut done);
    ad.with_store(|st| st.idle());
}

fn span(ad: &Ad, s: SpgT, name: &str, len: u64) -> SpanStats {
    let g = storeadapt::gh(s, &hobj(s, name));
    ad.with_store(|st| st.span_stats(&CollT::Pg(s), &g, 0, len))
        .unwrap()
        .unwrap()
}

fn tracking(ad: &Ad, s: SpgT, name: &str) -> bool {
    let g = storeadapt::gh(s, &hobj(s, name));
    ad.with_store(|st| st.data_version(&CollT::Pg(s), &g))
        .unwrap()
        .unwrap()
        .tracking
}

fn counters(ad: &Ad) -> [u64; 6] {
    let c = ad.reformat_counters();
    [
        c.compress_attempted.get(),
        c.compress_omitted.get(),
        c.defragment_attempted.get(),
        c.defragment_omitted.get(),
        c.issued.get(),
        c.skipped.get(),
    ]
}

fn sync(ad: &Ad) {
    ad.with_store(|st| st.sync()).unwrap();
}

#[test]
fn lazy_mode_compresses_on_deep_scrub_only() {
    let (_d, mut ad, _) = new_adapter(128, 1, 3);
    let s = spg(1, 0);
    ad.submit_create(s);
    ad.set_pool_compression(1, &opts("force_lazy", "lz4"));
    assert!(ad.set_pool_reformat(1, "recompress").is_empty());
    let d = cdata(512 << 10);
    write(&mut ad, s, "a", 0, &d);
    // client writes stay raw in a lazy mode
    assert_eq!(ad.compress_stats(s), (0, 0));
    // the first deep scrub switches data version tracking on: no rewrite of state taken before
    let digests = deep_scrub(&ad, s, 1 << 20);
    assert!(tracking(&ad, s, "a"));
    assert_eq!(counters(&ad), [0; 6]);
    // the next one recompresses (one read: the whole object fits one 1 MiB slice)
    assert_eq!(
        deep_scrub(&ad, s, 1 << 20),
        digests,
        "the scrub result is unchanged"
    );
    sync(&ad);
    assert_eq!(counters(&ad), [1, 0, 0, 0, 1, 0]);
    let (phys, orig) = ad.compress_stats(s);
    assert!(orig == 512 << 10 && phys < orig / 2, "{phys} {orig}");
    assert_eq!(ad.object(s, &hobj(s, "a")).unwrap().data, d);
    // nothing raw is left: no further attempt
    deep_scrub(&ad, s, 1 << 20);
    assert_eq!(counters(&ad), [1, 0, 0, 0, 1, 0]);
    // incompressible data: the estimate says no, nothing is rewritten
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    let r: Vec<u8> = (0..256u64 << 10)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        })
        .collect();
    write(&mut ad, s, "a", 0, &r);
    deep_scrub(&ad, s, 1 << 20);
    sync(&ad);
    let c = counters(&ad);
    assert_eq!((c[0], c[1], c[4]), (2, 1, 1), "{c:?}");
}

#[test]
fn defragment_rewrites_scattered_objects() {
    let (_d, mut ad, _) = new_adapter(128, 1, 5);
    let s = spg(1, 0);
    ad.submit_create(s);
    assert!(ad.set_pool_reformat(1, "defragment").is_empty());
    let a = vec![b'a'; 256 << 10];
    write(&mut ad, s, "o", 0, &a);
    deep_scrub(&ad, s, 1 << 20); // tracking on
    // contiguous: not attempted
    deep_scrub(&ad, s, 1 << 20);
    assert_eq!(counters(&ad), [0; 6]);
    let c = vec![b'c'; 4096];
    for blk in (0..64u64).step_by(2) {
        write(&mut ad, s, "o", blk * 4096, &c);
    }
    let before = span(&ad, s, "o", 256 << 10);
    assert!(before.frags > 1, "{before:?}");
    let want = ad.object(s, &hobj(s, "o")).unwrap().data;
    deep_scrub(&ad, s, 1 << 20);
    sync(&ad);
    assert_eq!(counters(&ad), [0, 0, 1, 0, 1, 0]);
    let after = span(&ad, s, "o", 256 << 10);
    assert!(after.frags < before.frags, "{before:?} -> {after:?}");
    assert_eq!(ad.object(s, &hobj(s, "o")).unwrap().data, want);
    // shared blocks (a clone) are left alone
    ad.submit(
        s,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: Default::default(),
                data: {
                    let mut b = Transaction::new();
                    let cc = b.coll(&CollT::Pg(s));
                    let src = b.obj(&storeadapt::gh(s, &hobj(s, "o")));
                    let dst = b.obj(&storeadapt::gh(s, &hobj(s, "o-clone")));
                    b.push(
                        cc,
                        TxnOp::Clone {
                            oid: src,
                            dest_oid: dst,
                        },
                    );
                    b.encode_v9().unwrap().into()
                },
            }],
        },
    );
    for blk in (0..64u64).step_by(2) {
        write(&mut ad, s, "o", blk * 4096 + 4096, &c);
    }
    let shared = span(&ad, s, "o", 256 << 10);
    assert!(
        shared.allocated_shared > 0 && shared.frags > 1,
        "{shared:?}"
    );
    deep_scrub(&ad, s, 1 << 20);
    sync(&ad);
    assert_eq!(
        counters(&ad),
        [0, 0, 1, 0, 1, 0],
        "o still shares blocks with its clone: left alone"
    );
}

#[test]
fn object_changed_during_its_scrub_is_not_rewritten() {
    let (_d, mut ad, _) = new_adapter(128, 1, 7);
    let s = spg(1, 0);
    ad.submit_create(s);
    ad.set_pool_compression(1, &opts("force_lazy", "lz4"));
    ad.set_pool_reformat(1, "recompress");
    let d = cdata(2 << 20);
    write(&mut ad, s, "big", 0, &d);
    deep_scrub(&ad, s, 1 << 20); // tracking on
    // a slice of 1 MiB reads the first half and parks; a client write lands before the second half is read
    let mut p = ad.scrub_slice(s, &Hobject::MIN(), &Hobject::MAX(), true, 64, 1 << 20);
    while counters(&ad)[4] == 0 && p.objects.is_empty() {
        step(&ad);
        p = ad.scrub_slice(
            s,
            p.next.as_ref().unwrap(),
            &Hobject::MAX(),
            true,
            64,
            1 << 20,
        );
    }
    assert!(p.objects.is_empty(), "parked inside the object");
    sync(&ad);
    let first = counters(&ad);
    assert_eq!(
        first[4], 1,
        "the first half was rewritten before the write: {first:?}"
    );
    let x = vec![b'x'; 4096];
    write(&mut ad, s, "big", 1 << 20, &x);
    let mut start = p.next.unwrap_or_else(Hobject::MIN);
    loop {
        step(&ad);
        let p = ad.scrub_slice(s, &start, &Hobject::MAX(), true, 64, 1 << 20);
        match p.next {
            Some(n) => start = n,
            None => break,
        }
    }
    sync(&ad);
    assert_eq!(counters(&ad)[4], 1, "no rewrite after the change");
    let mut want = d.clone();
    want[1 << 20..(1 << 20) + 4096].copy_from_slice(&x);
    assert_eq!(ad.object(s, &hobj(s, "big")).unwrap().data, want);
}

#[test]
fn engines_off_switch_tracking_off_and_unknown_names_are_reported() {
    let (_d, mut ad, _) = new_adapter(128, 1, 9);
    let s = spg(1, 0);
    ad.submit_create(s);
    assert_eq!(
        ad.set_pool_reformat(1, "collect_cksum; foo ,,; "),
        vec!["collect_cksum".to_owned(), "foo ".to_owned()]
    );
    write(&mut ad, s, "a", 0, &cdata(64 << 10));
    deep_scrub(&ad, s, 1 << 20);
    assert!(!tracking(&ad, s, "a"), "no valid engine: no tracking");
    ad.set_pool_reformat(1, "defragment");
    deep_scrub(&ad, s, 1 << 20);
    assert!(tracking(&ad, s, "a"));
    ad.set_pool_reformat(1, "");
    deep_scrub(&ad, s, 1 << 20);
    assert!(
        !tracking(&ad, s, "a"),
        "the pool lost its engines: tracking off again"
    );
    // other pools are unaffected
    let s2 = spg(2, 0);
    ad.submit_create(s2);
    ad.set_pool_reformat(1, "defragment");
    write(&mut ad, s2, "b", 0, &cdata(64 << 10));
    deep_scrub(&ad, s2, 1 << 20);
    assert!(!tracking(&ad, s2, "b"));
}
