// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `PgStoreOps::check_write` (client-ops.md s5.4 rule 14b): a client txn the store could never apply is refused with
//! an errno BEFORE the PG logs it; nothing is applied, the store stays healthy, normal txns still go through.
mod common;
use common::*;
use denc::types::*;
use peering::WriteErr;
use peering::store::{PgStoreOps, StoreOp, StoreTxn};
use replwire::txn::{Transaction, TxnOp};

fn omap_txn(pg: SpgT, name: &str, keys: usize, vlen: usize, tag: u8) -> bytes::Bytes {
    let h = Hobject::new(name.as_bytes(), SnapId::NOSNAP, 5, 1, b"");
    let g = Ghobject::new(h, Ghobject::NO_GEN, ShardId::NO_SHARD);
    let mut t = Transaction::new();
    let c = t.coll(&CollT::Pg(pg));
    let o = t.obj(&g);
    t.push(c, TxnOp::Touch { oid: o });
    let ks: Vec<String> = (0..keys).map(|i| format!("key-{i:07}")).collect();
    let v = incompressible(vlen, u64::from(tag));
    t.push(
        c,
        TxnOp::OmapSetKeys {
            oid: o,
            pairs: ks.iter().map(|k| (k.as_bytes(), v.as_slice())).collect(),
        },
    );
    t.encode_v9().unwrap().into()
}

fn objects(ad: &Ad, pg: SpgT) -> usize {
    ad.with_store(|st| st.list(&CollT::Pg(pg), &Ghobject::MIN(), None, 1000))
        .map(|(v, _)| v.len())
        .unwrap_or(0)
}

#[test]
fn oversized_txn_is_refused_before_it_is_logged() {
    // ring of 1024 blocks = 4 MiB: one txn record may use ~2 MiB
    let (_d, ad, _sim) = new_adapter(256, 1, 31);
    let pg = spg(1, 0);
    ad.submit_create(pg);
    let base = objects(&ad, pg);
    let empty = bytes::Bytes::new();
    // 3 MiB of omap in one client txn: no way into the ring
    let big = omap_txn(pg, "dirfrag", 1500, 2000, 1);
    assert!(big.len() > 2 << 20);
    assert_eq!(
        ad.check_write(pg, &empty, &big),
        Err(WriteErr::TooBig(denc::errno::EMSGSIZE)),
        "must be refused with EMSGSIZE"
    );
    assert_eq!(objects(&ad, pg), base, "nothing applied");
    // the same bytes WOULD be an input error of the store (what used to exit the OSD)
    let r = ad.try_submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: empty.clone(),
                data: big.clone(),
            }],
        },
    );
    assert!(r.is_err(), "store refuses it too: {r:?}");
    assert!(
        ad.failure().is_none(),
        "a refused txn is not a store failure"
    );
    // a big-but-legal txn passes the check and applies; small ones skip the check entirely
    let ok = omap_txn(pg, "dirfrag", 300, 2000, 2);
    assert!(ok.len() > 64 << 10);
    assert_eq!(ad.check_write(pg, &empty, &ok), Ok(()));
    ad.try_submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: empty.clone(),
                data: ok,
            }],
        },
    )
    .unwrap();
    assert_eq!(objects(&ad, pg), base + 1);
    let small = omap_txn(pg, "small", 3, 10, 3);
    assert_eq!(ad.check_write(pg, &empty, &small), Ok(()));
    // garbage that decodes to nothing sensible: refused as EINVAL, never fatal
    let junk = bytes::Bytes::from(vec![0xffu8; 100_000]);
    assert_eq!(
        ad.check_write(pg, &junk, &empty),
        Err(WriteErr::TooBig(denc::errno::EINVAL))
    );
    assert!(ad.failure().is_none());
}

#[test]
fn ordinary_big_writes_skip_the_full_check() {
    // hot path: a 16 KiB..4 MiB write payload must not be decoded a second time by check_write (1 GiB-class ring)
    let sim = sim_cfg(512, 33);
    let img = fresh_image(&sim, 1, 65536);
    let (_d, ad) = open(&img, &sim, &Default::default());
    let pg = spg(1, 0);
    ad.submit_create(pg);
    let empty = bytes::Bytes::new();
    for len in [16 << 10, 64 << 10, 1 << 20, 4 << 20] {
        let data = bytes::Bytes::from(vec![7u8; len]);
        assert_eq!(ad.check_write(pg, &empty, &data), Ok(()));
    }
    assert_eq!(
        ad.slow_checks.get(),
        0,
        "payload must not take the decode path"
    );
    // a big op section still does
    let big = omap_txn(pg, "dirfrag", 300, 2000, 2);
    assert_eq!(ad.check_write(pg, &big, &empty), Ok(()));
    assert_eq!(ad.slow_checks.get(), 1);
}

#[test]
fn name_key_bound_is_sound_for_nul_heavy_names() {
    use store::obj::keys::name_key_of;
    let mut r = 0x1234_5678_9abc_def1u64;
    let mut next = || {
        r ^= r << 13;
        r ^= r >> 7;
        r ^= r << 17;
        r
    };
    for _ in 0..2000 {
        let mut gen_bytes = |max: u64| -> Vec<u8> {
            let n = (next() % max) as usize;
            (0..n)
                .map(|_| if next() % 3 == 0 { 0 } else { b'a' })
                .collect()
        };
        let (oid, key, ns) = (gen_bytes(80), gen_bytes(40), gen_bytes(40));
        let mut h = Hobject::new(&oid, SnapId::NOSNAP, 5, 1, &ns);
        h.set_key(&key);
        let g = Ghobject::new(h, Ghobject::NO_GEN, ShardId::NO_SHARD);
        let real = name_key_of(7, &g).len();
        let bound = opexec::engine::name_key_upper_bound(&oid, &key, &ns);
        assert!(real <= bound, "real {real} > bound {bound}");
    }
}

/// `io_quiet` (driver deep idle): false while a txn is queued / in flight, true once it is durable and nothing else runs.
#[test]
fn io_quiet_tracks_inflight_work() {
    let (_d, mut ad, _sim) = new_adapter(256, 1, 32);
    let pg = spg(1, 0);
    ad.submit_create(pg);
    let mut done = Vec::new();
    let settle = |ad: &mut Ad, done: &mut Vec<(SpgT, u64)>| {
        for _ in 0..100_000 {
            ad.poll_commits(done);
            if ad.io_quiet() {
                return true;
            }
            ad.with_store(|st| st.idle());
        }
        false
    };
    assert!(settle(&mut ad, &mut done), "fresh store settles quiet");
    let t = omap_txn(pg, "q", 3, 10, 1);
    ad.try_submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: bytes::Bytes::new(),
                data: t,
            }],
        },
    )
    .unwrap();
    assert!(!ad.io_quiet(), "a submitted txn is work in flight");
    done.clear();
    assert!(settle(&mut ad, &mut done), "quiet again once durable");
}

/// Names up to the classic limits (oid 2048, locator 2048, namespace 256 each alone) are accepted through the adapter
/// (adr 0021 am. 30: long-name index), applied and listable; a locator plus an oid that are both long stay refused.
#[test]
fn classic_name_limits_pass_the_name_gate() {
    use opexec::view::ObjView;
    let (_d, ad, _sim) = new_adapter(256, 1, 33);
    let pg = spg(1, 0);
    ad.submit_create(pg);
    let mk = |oid: &[u8], key: &[u8], ns: &[u8]| {
        let mut h = Hobject::new(oid, SnapId::NOSNAP, 5, 1, ns);
        h.set_key(key);
        h
    };
    let a = |n: usize| vec![b'a'; n];
    let ok = [
        mk(&a(2048), b"", b""),
        mk(&a(2047), b"", b""),
        mk(b"a", &a(2048), b""),
        mk(b"a", b"", &a(256)),
    ];
    for h in &ok {
        assert!(ad.ov_name_fits(pg, h));
        let g = Ghobject::new(h.clone(), Ghobject::NO_GEN, ShardId::NO_SHARD);
        let mut t = Transaction::new();
        let c = t.coll(&CollT::Pg(pg));
        let o = t.obj(&g);
        t.push(c, TxnOp::Touch { oid: o });
        let b: bytes::Bytes = t.encode_v9().unwrap().into();
        assert_eq!(ad.check_write(pg, &bytes::Bytes::new(), &b), Ok(()));
    }
    assert!(!ad.ov_name_fits(pg, &mk(&a(2047), &a(2048), b"")));
}

/// A size check whose walk needs a cold metadata page never waits for it on the PG core (adr 0021 S8): `Blocked`
/// with the load submitted and no (simulated) time passed; it passes once the loads completed.
#[test]
fn cold_check_is_blocked_not_waited_for() {
    let sim = sim_cfg(256, 37);
    let img = fresh_image(&sim, 1, 1024);
    let (disk, ad) = open(&img, &sim, &store::obj::StoreCfg::default());
    let pg = spg(1, 0);
    ad.submit_create(pg);
    let empty = bytes::Bytes::new();
    for i in 0..40u8 {
        let t = omap_txn(pg, &format!("obj{i:03}"), 200, 300, i);
        let ops = vec![StoreOp::ApplyTxn {
            middle: empty.clone(),
            data: t,
        }];
        ad.try_submit(pg, &StoreTxn { ops }).unwrap();
    }
    ad.with_store(|st| st.checkpoint()).unwrap();
    drop(ad);
    // a fresh mount: every tree page below the roots is cold
    let (_d, ad) = open(&disk.image(), &sim, &store::obj::StoreCfg::default());
    let big = omap_txn(pg, "obj007", 300, 2000, 9);
    let st = ad.shared();
    let t0 = st.borrow().clk.t;
    assert_eq!(ad.check_write(pg, &empty, &big), Err(WriteErr::Blocked));
    assert_eq!(st.borrow().clk.t, t0, "the check never waited");
    assert!(
        !st.borrow_mut().take_blocked(),
        "the refusal does not leak into the next executor pass"
    );
    let mut rounds = 1;
    loop {
        st.borrow_mut().wait_loads().unwrap();
        match ad.check_write(pg, &empty, &big) {
            Ok(()) => break,
            Err(WriteErr::Blocked) => rounds += 1,
            Err(e) => panic!("{e:?}"),
        }
        assert!(rounds < 64, "the loads must converge");
    }
    assert_eq!(ad.check_blocks.get(), rounds);
    assert!(ad.failure().is_none());
}
