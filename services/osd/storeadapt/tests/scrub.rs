// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Replica scrub map builder: the NVMe adapter must produce the same maps as `MemStore` (reference), slice
//! by slice, and map store errors to object flags.
mod common;
use common::*;
use denc::types::*;
use peering::ScrubPart;
use peering::store::{MemStore, PgStoreOps, StoreOp, StoreTxn};
use pgwire::LogOp;
use replwire::scrubmsgs::{ScrubMap, ScrubObject};
use std::collections::{BTreeMap, BTreeSet};

fn data_fixture(size: usize) -> (store::dev::SimDisk, Ad, SpgT, Hobject, Vec<u8>) {
    let (disk, ad, _) = new_adapter(128, 1, 33);
    let pg = spg(1, 0);
    ad.submit_create(pg);
    let h = Hobject::new(b"large", SnapId::NOSNAP, 5, 1, b"");
    let data: Vec<u8> = (0..size).map(|i| (i * 7 + i / 4096) as u8).collect();
    let mut t = replwire::txn::Transaction::new();
    let c = t.coll(&CollT::Pg(pg));
    let g = t.obj(&Ghobject::new(h.clone(), Ghobject::NO_GEN, pg.shard));
    t.push(
        c,
        replwire::txn::TxnOp::Write {
            oid: g,
            off: 0,
            data: replwire::txn::Data::new(&data),
        },
    );
    ad.try_submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: Default::default(),
                data: t.encode_v9().unwrap().into(),
            }],
        },
    )
    .unwrap();
    (disk, ad, pg, h, data)
}

#[test]
#[ignore = "local scrub scheduling benchmark"]
fn perf_scrub_first_slice() {
    let (disk, ad, pg, _, _) = data_fixture(8 << 20);
    let before = disk.stats();
    let t = std::time::Instant::now();
    let p = ad.scrub_slice(pg, &Hobject::MIN(), &Hobject::MAX(), true, 10, 1 << 20);
    println!(
        "first_slice_ns={} submitted_bytes={} completed_objects={} continuation={}",
        t.elapsed().as_nanos(),
        (disk.stats().read_lbas - before.read_lbas) * 4096,
        p.objects.len(),
        p.next.is_some()
    );
}

#[test]
fn deep_data_scrub_yields_inside_a_large_object() {
    let (_, ad, pg, h, data) = data_fixture(8 << 20);
    let clock = ad.with_store(|s| s.clk.t);
    let first = ad.scrub_slice(pg, &Hobject::MIN(), &Hobject::MAX(), true, 10, 1 << 20);
    assert_eq!(
        ad.with_store(|s| s.clk.t),
        clock,
        "scrub must never wait for media IO"
    );
    assert!(
        first.objects.is_empty(),
        "large object must not complete in its first slice"
    );
    assert_eq!(first.next, Some(h.clone()));
    let mut done = Vec::new();
    for _ in 0..10_000 {
        ad.poll_store(&mut done);
        ad.with_store(|s| s.idle());
        let p = ad.scrub_slice(pg, &h, &Hobject::MAX(), true, 10, 1 << 20);
        if let Some(o) = p.objects.get(&h) {
            assert_eq!(o.digest, crc::crc32c(0xFFFF_FFFF, &data));
            assert!(!o.read_error);
            assert_eq!(o.object_omap_key_bytes, Some(0));
            return;
        }
    }
    panic!("scrub continuation timed out");
}

/// NT-deadcode-02: `osd_deep_scrub_stride` sets the size of one deep scrub data read (was a fixed 4 MiB): a slice
/// parks behind its pending media read, so smaller reads take more slices; the digest does not depend on it.
#[test]
fn deep_scrub_stride_sets_the_read_size() {
    let mut slices = Vec::new();
    for stride in [None, Some(64u64 << 10)] {
        let (_, ad, pg, h, data) = data_fixture(8 << 20);
        if let Some(s) = stride {
            ad.set_deep_scrub_reads(s, 1024);
        }
        let mut done = Vec::new();
        let mut start = Hobject::MIN();
        let digest = (1..10_000).find_map(|n| {
            let p = ad.scrub_slice(pg, &start, &Hobject::MAX(), true, 10, 64 << 20);
            start = h.clone();
            ad.poll_store(&mut done);
            ad.with_store(|s| s.idle());
            p.objects.get(&h).map(|o| (o.digest, n))
        });
        let (digest, n) = digest.expect("scrub completes");
        assert_eq!(digest, crc::crc32c(0xFFFF_FFFF, &data), "stride {stride:?}");
        slices.push(n);
    }
    assert!(
        slices[1] > slices[0],
        "slices with 4 MiB / 64 KiB reads: {slices:?}"
    );
}

#[test]
fn deep_scrub_restarts_a_changed_object_and_ignores_prefetch() {
    let (disk, ad, pg, h, _) = data_fixture(2 << 20);
    let first = ad.scrub_slice(pg, &Hobject::MIN(), &Hobject::MAX(), true, 10, 1 << 20);
    assert_eq!(first.next, Some(h.clone()));
    let data = vec![0xa5; 2 << 20];
    let mut t = replwire::txn::Transaction::new();
    let c = t.coll(&CollT::Pg(pg));
    let g = t.obj(&Ghobject::new(h.clone(), Ghobject::NO_GEN, pg.shard));
    t.push(
        c,
        replwire::txn::TxnOp::Write {
            oid: g,
            off: 0,
            data: replwire::txn::Data::new(&data),
        },
    );
    t.push(
        c,
        replwire::txn::TxnOp::SetAttr {
            oid: g,
            name: b"_version",
            value: b"new",
        },
    );
    ad.try_submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: Default::default(),
                data: t.encode_v9().unwrap().into(),
            }],
        },
    )
    .unwrap();
    let map = full(&ad, pg, &Hobject::MIN(), &Hobject::MAX(), true, 10, 1 << 20);
    assert_eq!(map[&h].digest, crc::crc32c(!0, &data));
    let gh = Ghobject::new(h.clone(), Ghobject::NO_GEN, pg.shard);
    let mut warmed = false;
    for _ in 0..10_000 {
        let ready = ad.with_store(|s| s.warm_data(&CollT::Pg(pg), &gh, 0, 1 << 20).unwrap());
        if ready {
            warmed = true;
            break;
        }
        ad.drive();
    }
    assert!(warmed, "client prefetch timed out");
    let image = disk.image();
    let lba = (0..image.lba_count)
        .find(|&lba| image.read_lba(lba).iter().all(|&b| b == 0xa5))
        .unwrap();
    disk.corrupt(lba, 17, 1);
    let map = full(&ad, pg, &Hobject::MIN(), &Hobject::MAX(), true, 10, 1 << 20);
    assert!(
        map[&h].read_error,
        "media corruption must not be hidden by client prefetch"
    );
    assert!(!map[&h].digest_present);
}

trait ScrubDrive {
    fn drive(&self) {}
}

#[test]
fn a_new_scrub_chunk_discards_an_abandoned_media_digest() {
    let (disk, ad, pg, h, data) = data_fixture(2 << 20);
    let reads = disk.stats().read_lbas;
    let mut parked_after_prefix = false;
    for _ in 0..10_000 {
        ad.drive();
        let p = ad.scrub_slice(pg, &Hobject::MIN(), &Hobject::MAX(), true, 10, 1 << 20);
        if disk.stats().read_lbas - reads >= (2 << 20) / 4096 && p.objects.is_empty() {
            parked_after_prefix = true;
            break;
        }
    }
    assert!(parked_after_prefix, "scrub prefix never completed");
    let image = disk.image();
    let lba = (0..image.lba_count)
        .find(|&lba| image.read_lba(lba) == data[..4096])
        .unwrap();
    disk.corrupt(lba, 17, 1);
    ad.reset_scrub(pg);
    let map = full(&ad, pg, &Hobject::MIN(), &Hobject::MAX(), true, 10, 1 << 20);
    assert!(
        map[&h].read_error,
        "a new scrub must verify its prefix again"
    );
}
impl ScrubDrive for MemStore {}
impl ScrubDrive for Ad {
    fn drive(&self) {
        self.poll_store(&mut Vec::new());
        self.with_store(|s| s.idle());
    }
}

fn full<S: PgStoreOps + ScrubDrive>(
    s: &S,
    pg: SpgT,
    a: &Hobject,
    b: &Hobject,
    deep: bool,
    n: usize,
    bytes: u64,
) -> BTreeMap<Hobject, ScrubObject> {
    let mut map = ScrubMap::default();
    let mut cur = a.clone();
    let mut slices = 0;
    loop {
        s.drive();
        let ScrubPart {
            objects,
            next,
            error,
        } = s.build_scrub_map(pg, &cur, b, deep, n, bytes);
        assert!(error.is_none(), "scrub error: {error:?}");
        map.objects.extend(objects);
        slices += 1;
        assert!(slices < 10_000);
        match next {
            Some(x) => {
                assert!(x > cur || slices == 1 || x >= cur, "progress");
                cur = x;
            }
            None => return map.objects,
        }
    }
}

#[test]
fn adapter_matches_memstore() {
    for seed in [1u64, 2, 3] {
        let (_disk, ad, _sim) = new_adapter(128, 2, seed);
        let mut mem = MemStore::new();
        let pg = spg(1, 0);
        let t = StoreTxn {
            ops: vec![StoreOp::CreatePg],
        };
        mem.submit(pg, &t);
        ad.submit_create(pg);
        let mut g = PgGen::new(pg, seed);
        let mut exist = BTreeSet::new();
        for _ in 0..200 {
            let mut t = StoreTxn::default();
            let e = g.entry(LogOp::MODIFY);
            t.push(StoreOp::LogAppend(vec![e]));
            let d = g.object_txn(&mut exist);
            t.push(StoreOp::ApplyTxn {
                middle: Default::default(),
                data: d.into(),
            });
            mem.submit(pg, &t);
            let mut ad_t = t.clone();
            ad_t.ops.retain(|_| true);
            ad.try_submit(pg, &ad_t).unwrap();
        }
        let (lo, hi) = (Hobject::MIN(), Hobject::MAX());
        for deep in [false, true] {
            let want = full(&mem, pg, &lo, &hi, deep, 1000, u64::MAX);
            assert!(!want.is_empty());
            // all slicings agree with the reference and with each other
            for (n, bytes) in [(1000, u64::MAX), (3, u64::MAX), (1, 1), (5, 20_000)] {
                assert_eq!(
                    full(&ad, pg, &lo, &hi, deep, n, bytes),
                    want,
                    "seed {seed} deep {deep} n {n}"
                );
                assert_eq!(full(&mem, pg, &lo, &hi, deep, n, bytes), want);
            }
            // sub ranges
            let names: Vec<_> = want.keys().cloned().collect();
            let mid = names[names.len() / 2].clone();
            let a = full(&ad, pg, &lo, &mid, deep, 4, u64::MAX);
            let b = full(&ad, pg, &mid, &hi, deep, 4, u64::MAX);
            assert_eq!(a.len() + b.len(), want.len());
            assert!(b.contains_key(&mid) && !a.contains_key(&mid));
            assert_eq!(a, full(&mem, pg, &lo, &mid, deep, 4, u64::MAX));
        }
        // internal/user attrs: only `_`, `snapset`, `_*` are visible
        for o in full(&ad, pg, &lo, &hi, false, 100, u64::MAX).values() {
            assert!(o.attrs.keys().all(|k| k == b"snapset" || k[0] == b'_'));
        }
    }
}

#[test]
fn digests_large_object_and_omap() {
    let (_disk, ad, _sim) = new_adapter(256, 1, 9);
    let pg = spg(1, 0);
    ad.submit_create(pg);
    let h = Hobject::new(b"big", SnapId::NOSNAP, 5, 1, b"");
    let empty = Hobject::new(b"empty", SnapId::NOSNAP, 6, 1, b"");
    let data: Vec<u8> = (0..9_000_000u32)
        .map(|i| (i * 7 + i / 4096) as u8)
        .collect();
    let mut t = replwire::txn::Transaction::new();
    let c = t.coll(&CollT::Pg(pg));
    let (g, ge) = (
        t.obj(&Ghobject::new(
            h.clone(),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        )),
        t.obj(&Ghobject::new(
            empty.clone(),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        )),
    );
    t.push(
        c,
        replwire::txn::TxnOp::Write {
            oid: g,
            off: 0,
            data: replwire::txn::Data::new(&data),
        },
    );
    t.push(
        c,
        replwire::txn::TxnOp::SetAttr {
            oid: g,
            name: b"_user",
            value: b"v",
        },
    );
    t.push(
        c,
        replwire::txn::TxnOp::SetAttr {
            oid: g,
            name: b"hinfo_key",
            value: b"hidden",
        },
    );
    t.push(
        c,
        replwire::txn::TxnOp::OmapSetHeader {
            oid: g,
            header: b"hdr",
        },
    );
    t.push(
        c,
        replwire::txn::TxnOp::OmapSetKeys {
            oid: g,
            pairs: vec![
                (b"k1".as_slice(), b"v1".as_slice()),
                (b"k2".as_slice(), b"value2".as_slice()),
            ]
            .into(),
        },
    );
    t.push(c, replwire::txn::TxnOp::Touch { oid: ge });
    ad.try_submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: Default::default(),
                data: t.encode_v9().unwrap().into(),
            }],
        },
    )
    .unwrap();
    let m = full(
        &ad,
        pg,
        &Hobject::MIN(),
        &Hobject::MAX(),
        true,
        10,
        u64::MAX,
    );
    let o = &m[&h];
    assert_eq!(o.size, 9_000_000);
    assert_eq!(o.digest, crc::crc32c(0xFFFF_FFFF, &data));
    let mut w = crc::crc32c(0xFFFF_FFFF, b"hdr");
    for p in [
        &[2u8, 0, 0, 0][..],
        b"k1",
        &[2, 0, 0, 0],
        b"v1",
        &[2, 0, 0, 0],
        b"k2",
        &[6, 0, 0, 0],
        b"value2",
    ] {
        w = crc::crc32c(w, p);
    }
    assert_eq!(o.omap_digest, w);
    assert_eq!((o.object_omap_keys, o.object_omap_bytes), (2, 8));
    assert_eq!(o.object_omap_key_bytes, Some(4));
    assert_eq!(o.attrs.keys().collect::<Vec<_>>(), vec![&b"_user".to_vec()]);
    let e = &m[&empty];
    assert_eq!(e.object_omap_key_bytes, Some(0));
    assert_eq!(
        (
            e.size,
            e.digest,
            e.digest_present,
            e.omap_digest,
            e.omap_digest_present
        ),
        (0, 0xFFFF_FFFF, true, 0xFFFF_FFFF, true)
    );
    // shallow: no digests
    let s = full(
        &ad,
        pg,
        &Hobject::MIN(),
        &Hobject::MAX(),
        false,
        10,
        u64::MAX,
    );
    assert!(!s[&h].digest_present && !s[&h].omap_digest_present && s[&h].size == 9_000_000);
    assert_eq!(s[&h].object_omap_key_bytes, None);
    assert_eq!(s[&empty].object_omap_key_bytes, None);
}

#[test]
fn paged_omap_scan_counts_binary_keys_and_empty_values_only_when_complete() {
    let (_disk, ad, _) = new_adapter(128, 1, 71);
    let pg = spg(1, 0);
    ad.submit_create(pg);
    let h = Hobject::new(b"key-only-omap", SnapId::NOSNAP, 5, 1, b"");
    let keys: Vec<Vec<u8>> = (0..1025u16)
        .map(|i| vec![0, (i >> 8) as u8, i as u8, 0xff])
        .collect();
    let mut t = replwire::txn::Transaction::new();
    let c = t.coll(&CollT::Pg(pg));
    let g = t.obj(&Ghobject::new(h.clone(), Ghobject::NO_GEN, pg.shard));
    t.push(c, replwire::txn::TxnOp::Touch { oid: g });
    t.push(
        c,
        replwire::txn::TxnOp::OmapSetHeader {
            oid: g,
            header: b"header excluded from logical usage",
        },
    );
    t.push(
        c,
        replwire::txn::TxnOp::OmapSetKeys {
            oid: g,
            pairs: keys
                .iter()
                .map(|key| (key.as_slice(), b"".as_slice()))
                .collect::<Vec<_>>()
                .into(),
        },
    );
    ad.try_submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: Default::default(),
                data: t.encode_v9().unwrap().into(),
            }],
        },
    )
    .unwrap();
    let mut slices = 0;
    loop {
        ad.drive();
        let part = ad.scrub_slice(pg, &h, &Hobject::MAX(), true, 10, 1);
        assert!(part.error.is_none());
        slices += 1;
        assert!(slices < 10_000, "OMAP continuation timed out");
        if let Some(object) = part.objects.get(&h) {
            assert!(slices > 1, "the first OMAP page must park the digest");
            assert!(part.next.is_none());
            assert_eq!(object.object_omap_key_bytes, Some(1025 * 4));
            assert_eq!(
                (object.object_omap_keys, object.object_omap_bytes),
                (1025, 0)
            );
            assert!(object.omap_digest_present && !object.read_error);
            break;
        }
        assert!(
            part.objects.is_empty(),
            "partial OMAP metadata must stay unpublished"
        );
        assert_eq!(part.next, Some(h.clone()));
    }
}

#[test]
fn corrupt_data_is_a_read_error() {
    let (disk, ad, _sim) = new_adapter(64, 1, 11);
    let pg = spg(1, 0);
    ad.submit_create(pg);
    let h = Hobject::new(b"victim", SnapId::NOSNAP, 5, 1, b"");
    let ok = Hobject::new(b"fine", SnapId::NOSNAP, 6, 1, b"");
    let pat = |b: u8| vec![b; 64 * 1024];
    let mut t = replwire::txn::Transaction::new();
    let c = t.coll(&CollT::Pg(pg));
    let (gv, gf) = (
        t.obj(&Ghobject::new(
            h.clone(),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        )),
        t.obj(&Ghobject::new(
            ok.clone(),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        )),
    );
    let (dv, df) = (pat(0xA5), pat(0x3C));
    t.push(
        c,
        replwire::txn::TxnOp::Write {
            oid: gv,
            off: 0,
            data: replwire::txn::Data::new(&dv),
        },
    );
    t.push(
        c,
        replwire::txn::TxnOp::Write {
            oid: gf,
            off: 0,
            data: replwire::txn::Data::new(&df),
        },
    );
    ad.try_submit(
        pg,
        &StoreTxn {
            ops: vec![StoreOp::ApplyTxn {
                middle: Default::default(),
                data: t.encode_v9().unwrap().into(),
            }],
        },
    )
    .unwrap();
    // find the victim's blocks on the media and flip a bit
    let img = disk.image();
    let mut hit = 0;
    for lba in 0..img.lba_count {
        let b = img.read_lba(lba);
        if b.iter().all(|x| *x == 0xA5) {
            disk.corrupt(lba, 17, 0x01);
            hit += 1;
            break;
        }
    }
    assert_eq!(hit, 1, "victim data block located");
    let m = full(
        &ad,
        pg,
        &Hobject::MIN(),
        &Hobject::MAX(),
        true,
        10,
        u64::MAX,
    );
    assert!(
        m[&h].read_error && !m[&h].digest_present && !m[&h].omap_digest_present,
        "{:?}",
        m[&h]
    );
    assert_eq!(m[&h].object_omap_key_bytes, None);
    assert!(!m[&ok].read_error && m[&ok].digest_present);
    // shallow scrub does not read data
    let s = full(
        &ad,
        pg,
        &Hobject::MIN(),
        &Hobject::MAX(),
        false,
        10,
        u64::MAX,
    );
    assert!(!s[&h].read_error);
}
