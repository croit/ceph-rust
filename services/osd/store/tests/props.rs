// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Property tests: codec round trips, state machine vs reference model, allocator invariants, crash scenarios.
mod common;
use common::*;
use proptest::prelude::*;
use store::codec::{Dec, Enc};
use store::dev::CrashPolicy;
use store::shard::ShardCfg;
use store::state::{Extent, Op, Record};
use store::wal::{UnitHeader, decode_record, encode_record};

fn arb_key() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(0u8..4, 0..6)
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (arb_key(), proptest::collection::vec(any::<u8>(), 0..40)).prop_map(|(k, v)| Op::Put(k, v)),
        arb_key().prop_map(Op::Del),
        (arb_key(), arb_key()).prop_map(|(a, b)| Op::DelRange(a, b)),
    ]
}

fn arb_record() -> impl Strategy<Value = Record> {
    (
        any::<u64>(),
        proptest::collection::vec(arb_op(), 0..8),
        proptest::collection::vec(
            (any::<u64>(), proptest::collection::vec(any::<u32>(), 1..6)),
            0..4,
        ),
        proptest::collection::vec((any::<u64>(), 1u32..100), 0..4),
    )
        .prop_map(|(lsn, ops, data, frees)| Record {
            lsn,
            ops,
            data: data
                .into_iter()
                .map(|(blk, crcs)| Extent {
                    blk,
                    nblk: crcs.len() as u32,
                    crcs,
                })
                .collect(),
            frees,
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn record_roundtrip(r in arb_record()) {
        let mut e = Enc::new();
        encode_record(&r, &mut e);
        let mut d = Dec::new(&e.b);
        prop_assert_eq!(decode_record(&mut d), Some(r));
        prop_assert_eq!(d.left(), 0);
    }

    #[test]
    fn record_decode_never_panics_on_garbage_or_truncation(r in arb_record(), cut in 0usize..200, flip in any::<(usize, u8)>()) {
        let mut e = Enc::new();
        encode_record(&r, &mut e);
        let mut b = e.b.clone();
        b.truncate(cut.min(b.len()));
        let _ = decode_record(&mut Dec::new(&b));
        let mut b = e.b;
        if !b.is_empty() {
            let i = flip.0 % b.len();
            b[i] ^= flip.1;
            let _ = decode_record(&mut Dec::new(&b));
        }
    }

    #[test]
    fn unit_header_roundtrip_and_crc(epoch in any::<u32>(), lsn in 1u64.., ntxn in any::<u32>(), nb in any::<u16>(), pl in any::<u32>(), prev in any::<u32>(), pc in any::<u32>(), bit in 0usize..(60 * 8)) {
        let h = UnitHeader { epoch, first_lsn: lsn, ntxn, nblocks: nb, flags: 0, shard: 3, payload_len: pl, prev_crc: prev, payload_crc: pc, acked_lsn: 0, store_id: 0 };
        let mut b = vec![0u8; 4096];
        let c = h.write(&mut b);
        prop_assert_eq!(UnitHeader::read(&b), Some((h, c)));
        b[bit / 8] ^= 1 << (bit % 8);
        prop_assert!(UnitHeader::read(&b).is_none(), "single bit flip in header must be detected");
    }

    #[test]
    fn allocator_never_hands_out_overlaps(sizes in proptest::collection::vec(1u32..9, 1..80), frees in proptest::collection::vec(any::<prop::sample::Index>(), 0..40)) {
        let env = make_env(8, 64, 1, ShardCfg::default());
        let mut h = Harness::new(&env, 1);
        let mut live: Vec<(u64, u32)> = Vec::new();
        for s in &sizes {
            if let Ok(b) = h.shard.alloc(*s) {
                for &(lb, ln) in &live {
                    prop_assert!(b + *s as u64 <= lb || lb + ln as u64 <= b, "overlap {b}+{s} with {lb}+{ln}");
                }
                prop_assert!(b >= env.dir.data_start && b + *s as u64 <= env.dir.data_start + env.dir.data_blocks);
                live.push((b, *s));
            }
        }
        for ix in frees {
            if live.is_empty() { break; }
            let (b, n) = live.remove(ix.index(live.len()));
            h.shard.unreserve(b, n);
        }
        // everything unreserved is allocatable again
        for (b, n) in live.drain(..) { h.shard.unreserve(b, n); }
        prop_assert!(h.shard.alloc(1).is_ok());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn random_crash_scenarios(seed in any::<u64>(), k in 0u64..500, pol in 0usize..3, ntxn in 5u64..80, burst in 1u64..8, gens in 1u32..4, wal in prop::sample::select(vec![64u64, 128, 512])) {
        let cfg = ShardCfg { max_unit_blocks: if wal == 64 { 4 } else { 16 }, ..Default::default() };
        let env = make_env(32, wal, if seed % 5 == 0 { 64 } else { 1 }, cfg);
        let policy = [CrashPolicy::DROP_ALL, CrashPolicy::PERSIST_ALL, CrashPolicy::MIXED][pol];
        one_run(&env, seed, Some(k), policy, ntxn, burst, gens).map_err(TestCaseError::fail)?;
    }
}
