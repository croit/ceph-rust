// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! Dedup info collection over the NVMe store (adr 0593-dedup-deep-scrub-reformat, doc/spec/dedup-collection.md 9): records
//! from the primary's deep scrub only, digests over multi-read objects, no record for an object changed during its read,
//! sharded listing, prune, other digest algorithms, clear and stats.
mod common;
use common::*;
use denc::types::*;
use md5::Digest;
use peering::store::{DedupEntry, DedupListReq, PgStoreOps, StoreOp, StoreTxn, merge_dedup_parts};
use replwire::txn::*;
use std::collections::BTreeMap;

fn hobj(s: SpgT, name: &str, hash: u32) -> Hobject {
    Hobject::new(
        name.as_bytes(),
        SnapId::NOSNAP,
        hash,
        s.pgid.pool as i64,
        b"",
    )
}

fn write(ad: &mut Ad, s: SpgT, h: &Hobject, off: u64, d: &[u8]) {
    let g = storeadapt::gh(s, h);
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

fn step(ad: &Ad) {
    let mut done = Vec::new();
    ad.poll_store(&mut done);
    ad.with_store(|st| st.idle());
}

fn deep_scrub(ad: &Ad, s: SpgT, primary: bool) {
    ad.scrub_role(s, primary);
    let mut start = Hobject::MIN();
    for _ in 0..10_000 {
        step(ad);
        let p = ad.scrub_slice(s, &start, &Hobject::MAX(), true, 64, 1 << 20);
        match p.next {
            Some(n) => start = n,
            None => {
                ad.with_store(|st| st.sync()).unwrap();
                return;
            }
        }
    }
    panic!("scrub did not finish");
}

/// Every record of `pool`: each of 32 digest shards listed one record per call, like the fork's test.
fn records(ad: &Ad, pool: i64, retrieve_after_ns: u64, remove_before_ns: u64) -> Vec<DedupEntry> {
    let mut all = Vec::new();
    for shard in 0..32 {
        let mut after = Vec::new();
        for _ in 0..1000 {
            let r = DedupListReq {
                pool,
                shard,
                shard_bits: 5,
                after: after.clone(),
                max: 1,
                retrieve_after_ns,
                remove_before_ns,
                max_duration_s: 0.0,
            };
            let part = ad.dedup_list(&r).unwrap().unwrap();
            let (entries, next, done) = merge_dedup_parts(vec![part], 1);
            for e in &entries {
                assert_eq!(
                    (e.digest[0] >> 3) as u32,
                    shard,
                    "the record belongs to its shard"
                );
            }
            all.extend(entries);
            if done {
                break;
            }
            after = next;
        }
    }
    all
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

#[test]
fn primary_records_digests_and_listing_groups_duplicates() {
    let (_d, mut ad, _) = new_adapter(256, 1, 21);
    let s = spg(1, 0);
    ad.submit_create(s);
    assert!(ad.set_pool_reformat(1, "collect_csum").is_empty());
    let a = vec![b'a'; 500 << 10];
    let a3 = vec![b'a'; (500 << 10) / 3];
    let (h1, h2, h3) = (
        hobj(s, "obj", 0x11),
        hobj(s, "obj2", 0x22),
        hobj(s, "obj3", 0x33),
    );
    write(&mut ad, s, &h1, 0, &a);
    write(&mut ad, s, &h2, 0, &a);
    write(&mut ad, s, &h3, 0, &a3);
    // the first object a scrub reads switches data version tracking on and is not recorded; the rest are
    deep_scrub(&ad, s, true);
    assert_eq!(records(&ad, 1, 0, 0).len(), 2);
    ad.dedup_clear(1).unwrap().unwrap();
    // The session cutoff must use the very same clock as collected records.
    let t0 = ad
        .dedup_wall_ns()
        .expect("dedup collector supplies its wall clock");
    // a replica's map never records
    deep_scrub(&ad, s, false);
    assert!(records(&ad, 1, 0, 0).is_empty());
    deep_scrub(&ad, s, true);
    let r = records(&ad, 1, t0, 0);
    assert_eq!(r.len(), 3);
    let mut by_digest: BTreeMap<Vec<u8>, Vec<u32>> = BTreeMap::new();
    for e in &r {
        assert_eq!(e.digest.len(), 16);
        by_digest
            .entry(e.digest.clone())
            .or_default()
            .push(e.hash_key.reverse_bits());
    }
    assert_eq!(by_digest.len(), 2);
    let dup = &by_digest[&md5::Md5::digest(&a).to_vec()];
    let mut dup = dup.clone();
    dup.sort();
    assert_eq!(dup, [0x11, 0x22]);
    assert_eq!(by_digest[&md5::Md5::digest(&a3).to_vec()], [0x33]);
    // nothing newer than now
    assert!(records(&ad, 1, now_ns(), 0).is_empty());
    // other pools see nothing
    assert!(records(&ad, 2, 0, 0).is_empty());
    // a second scrub adds new records; listing newer than the first scrub's end prunes the older ones on the way
    let t1 = now_ns();
    deep_scrub(&ad, s, true);
    assert_eq!(records(&ad, 1, 0, 0).len(), 6);
    assert_eq!(
        records(&ad, 1, t1, t1).len(),
        3,
        "the older three are pruned"
    );
    assert_eq!(records(&ad, 1, 0, 0).len(), 3);
    assert_eq!(ad.dedup_counters().pruned.get(), 3);
    // stats and clear
    let (bytes, n) = ad.dedup_stats(1).unwrap();
    assert!(n == 3 && bytes > 3 * 40, "{bytes} {n}");
    ad.dedup_clear(1).unwrap().unwrap();
    assert_eq!(ad.dedup_stats(1).unwrap(), (0, 0));
    assert!(records(&ad, 1, 0, 0).is_empty());
}

#[test]
fn multi_read_objects_and_changes_during_the_read() {
    let (_d, mut ad, _) = new_adapter(256, 1, 23);
    let s = spg(1, 0);
    ad.submit_create(s);
    ad.set_pool_reformat(1, "collect_csum");
    // 3 MiB: three 1 MiB scrub slices
    let big: Vec<u8> = (0..3u32 << 20)
        .map(|i| b'a' + (i / 4096 % 26) as u8)
        .collect();
    let h = hobj(s, "big", 0x44);
    write(&mut ad, s, &h, 0, &big);
    deep_scrub(&ad, s, true); // tracking on (the only object: not recorded)
    assert!(records(&ad, 1, 0, 0).is_empty());
    deep_scrub(&ad, s, true);
    let r = records(&ad, 1, 0, 0);
    assert_eq!(r.len(), 1);
    assert_eq!(
        r[0].digest,
        md5::Md5::digest(&big).to_vec(),
        "digest of the whole object"
    );
    ad.dedup_clear(1).unwrap().unwrap();
    // a write lands between the first and the second slice of the object: no record
    ad.scrub_role(s, true);
    let mut p = ad.scrub_slice(s, &Hobject::MIN(), &Hobject::MAX(), true, 64, 1 << 20);
    assert!(p.objects.is_empty(), "parked inside the object");
    write(&mut ad, s, &h, 1 << 20, &[b'x'; 4096]);
    let mut start = p.next.take().unwrap();
    loop {
        step(&ad);
        let q = ad.scrub_slice(s, &start, &Hobject::MAX(), true, 64, 1 << 20);
        match q.next {
            Some(n) => start = n,
            None => break,
        }
    }
    ad.with_store(|st| st.sync()).unwrap();
    assert!(records(&ad, 1, 0, 0).is_empty());
    assert!(ad.dedup_counters().dropped.get() >= 1);
    // empty objects are never recorded
    let e = hobj(s, "empty", 0x55);
    write(&mut ad, s, &e, 0, &[]);
    deep_scrub(&ad, s, true);
    let r = records(&ad, 1, 0, 0);
    assert!(r.iter().all(|x| x.hash_key.reverse_bits() != 0x55));
}

#[test]
fn all_zero_objects_are_recorded_only_when_enabled() {
    let (_d, mut ad, _) = new_adapter(256, 1, 29);
    let s = spg(1, 0);
    ad.submit_create(s);
    ad.set_pool_reformat(1, "collect_csum");
    let n = 300 << 10;
    let mut tail = vec![0u8; n];
    tail[n - 1] = 1;
    let (hz, hs, ht, hd) = (
        hobj(s, "zeros", 0x71),
        hobj(s, "sparse", 0x72),
        hobj(s, "tail", 0x73),
        hobj(s, "data", 0x74),
    );
    write(&mut ad, s, &hz, 0, &vec![0u8; n]);
    // only the last byte written: the rest reads back as zeros (holes), the object is all zero
    write(&mut ad, s, &hs, (n - 1) as u64, &[0]);
    write(&mut ad, s, &ht, 0, &tail);
    write(&mut ad, s, &hd, 0, &vec![b'x'; n]);
    let hashes = |ad: &Ad| {
        let mut v: Vec<u32> = records(ad, 1, 0, 0)
            .iter()
            .map(|e| e.hash_key.reverse_bits())
            .collect();
        v.sort();
        v
    };
    assert!(!ad.dedup_zero_objects(), "off by default");
    deep_scrub(&ad, s, true); // tracking on
    ad.dedup_clear(1).unwrap().unwrap();
    let skipped = ad.dedup_counters().zero_skipped.get();
    deep_scrub(&ad, s, true);
    assert_eq!(
        hashes(&ad),
        vec![0x73, 0x74],
        "one non-zero byte at the end is enough"
    );
    assert_eq!(ad.dedup_counters().zero_skipped.get() - skipped, 2);
    ad.dedup_clear(1).unwrap().unwrap();
    ad.set_dedup_zero_objects(true);
    deep_scrub(&ad, s, true);
    assert_eq!(hashes(&ad), vec![0x71, 0x72, 0x73, 0x74]);
    let r = records(&ad, 1, 0, 0);
    let zd = |h: u32| {
        r.iter()
            .find(|e| e.hash_key.reverse_bits() == h)
            .unwrap()
            .digest
            .clone()
    };
    assert_eq!(
        zd(0x71),
        zd(0x72),
        "written zeros and holes are the same content"
    );
    assert_eq!(zd(0x71), md5::Md5::digest(vec![0u8; n]).to_vec());
}

#[test]
fn sha256_records_and_switching_prunes_the_other_length() {
    let (_d, mut ad, _) = new_adapter(256, 1, 25);
    let s = spg(1, 0);
    ad.submit_create(s);
    ad.set_pool_reformat(1, "collect_csum");
    assert!(ad.set_dedup_digest("sha256"));
    assert!(!ad.set_dedup_digest("crc32"), "unknown names are refused");
    let d = vec![7u8; 64 << 10];
    write(&mut ad, s, &hobj(s, "o", 0x66), 0, &d);
    deep_scrub(&ad, s, true);
    deep_scrub(&ad, s, true);
    let r = records(&ad, 1, 0, 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].digest, sha2::Sha256::digest(&d).to_vec());
    // back to MD5: listings drop the SHA-256 records (another digest length)
    assert!(ad.set_dedup_digest("md5"));
    assert!(records(&ad, 1, 0, 0).is_empty());
    assert_eq!(ad.dedup_stats(1).unwrap().1, 0);
}

#[test]
fn listing_is_bounded_and_resumes() {
    let (_d, mut ad, _) = new_adapter(256, 1, 27);
    let s = spg(1, 0);
    ad.submit_create(s);
    ad.set_pool_reformat(1, "collect_csum");
    for i in 0..40u32 {
        write(
            &mut ad,
            s,
            &hobj(s, &format!("o{i}"), i),
            0,
            &(i + 1).to_le_bytes().repeat(1024), // never all zero (not recorded by default)
        );
    }
    deep_scrub(&ad, s, true); // tracking on
    ad.dedup_clear(1).unwrap().unwrap();
    deep_scrub(&ad, s, true);
    // one pass over the whole pool (0 shard bits), 7 per call: every record exactly once, in key order
    let mut after = Vec::new();
    let mut seen = Vec::new();
    loop {
        let part = ad
            .dedup_list(&DedupListReq {
                pool: 1,
                after: after.clone(),
                max: 7,
                ..Default::default()
            })
            .unwrap()
            .unwrap();
        let (e, next, done) = merge_dedup_parts(vec![part], 7);
        assert!(e.len() <= 7);
        seen.extend(e.into_iter().map(|x| x.key));
        if done {
            break;
        }
        after = next;
    }
    assert_eq!(seen.len(), 40);
    assert!(seen.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn a_core_that_examines_nothing_keeps_the_cursor() {
    let (_d, ad, _) = new_adapter(256, 1, 29);
    let after = vec![0x80, 0, 0, 0, 0, 0, 0, 1, b':', 0x55];
    // an empty store: completed, and the cursor is the request's
    let part = ad
        .dedup_list(&DedupListReq {
            pool: 1,
            after: after.clone(),
            max: 10,
            ..Default::default()
        })
        .unwrap()
        .unwrap();
    assert!(part.completed);
    assert_eq!(part.examined, after);
    // merged with an incomplete core that stopped at the same cursor: the global cursor does not move back
    let stalled = peering::store::DedupListPart {
        examined: after.clone(),
        ..Default::default()
    };
    let (_, next, done) = merge_dedup_parts(vec![part, stalled], 10);
    assert_eq!((next, done), (after, false));
}
