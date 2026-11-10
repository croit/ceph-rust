// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Malformed peer input: every replication message with hostile counts / lengths / offsets (not only bit flips) in
//! any segment decodes to `Err` or a value, never panics, never allocates from an unchecked wire count. Targeted
//! regressions for push interval sets (E1) and transaction index tables (E2).
mod common;

use common::*;
use denc::Encode;
use denc::types::Eversion;
use messages::{Message, Segments};
use replwire::*;
use std::collections::BTreeMap;

/// xorshift64*: seeded, reproducible.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    /// 1-4 edits: bit flip, hostile 32/64-bit value (huge count, length, offset), random byte; sometimes a truncation.
    fn mutate(&mut self, b: &mut Vec<u8>) {
        if b.is_empty() {
            return;
        }
        for _ in 0..1 + self.below(4) {
            let at = self.below(b.len());
            let hostile: [u8; 8] = match self.below(4) {
                0 => [0xff; 8],
                1 => [0xff, 0xff, 0xff, 0x7f, 0, 0, 0, 0],
                2 => [0, 0, 0, 1, 0, 0, 0, 0],
                _ => (u64::MAX - self.below(16) as u64).to_le_bytes(),
            };
            match self.below(3) {
                0 => b[at] ^= 1 << self.below(8),
                1 => {
                    let end = (at + 8).min(b.len());
                    b[at..end].copy_from_slice(&hostile[..end - at]);
                }
                _ => b[at] = self.next() as u8,
            }
        }
        if self.below(5) == 0 {
            let cut = self.below(b.len());
            b.truncate(cut);
        }
    }
}

#[test]
fn messages_with_hostile_values_never_panic() {
    let mut r = Rng(0x5eed_4e91);
    for (_, m) in messages() {
        let (ty, ver, _, s) = m.encode(denc::features::ALL).unwrap();
        for _ in 0..400 {
            let mut s2 = s.clone();
            match r.below(3) {
                0 => r.mutate(&mut s2.front),
                1 => r.mutate(&mut s2.middle),
                _ => {
                    let mut d = s2.data.to_vec();
                    r.mutate(&mut d);
                    s2.data = d.into();
                }
            }
            if let Ok(Some(ReplMsg::RepOp(op))) = decode_repl(ty, ver, &s2) {
                // the replica decodes the shipped transaction too
                let _ = op.txn(DEFAULT_PAGE);
            }
        }
    }
}

#[test]
fn transactions_with_hostile_values_never_panic() {
    let buf = payload();
    let t = big_txn(&buf);
    let v9 = t.encode_v9().unwrap();
    let mut r = Rng(0x5eed_07a9);
    for _ in 0..3000 {
        let mut a = v9.clone();
        r.mutate(&mut a);
        let _ = Transaction::decode(&[], &a, DEFAULT_PAGE);
        if let Ok(mut s) = OpStream::new(&[], &a, DEFAULT_PAGE) {
            while let Ok(Some(_)) = s.next_op() {}
        }
    }
}

#[test]
fn recovery_structs_with_hostile_values_never_panic() {
    let mut r = Rng(0x5eed_09e5);
    let pu = push_op().encode_to_vec().unwrap();
    let ri = recovery_infos().remove(0).1.encode_to_vec().unwrap();
    for _ in 0..3000 {
        let (mut a, mut b) = (pu.clone(), ri.clone());
        r.mutate(&mut a);
        r.mutate(&mut b);
        if let Ok(p) = denc::from_slice::<PushOp>(&a) {
            assert!(
                p.data_consistent(),
                "a decoded push always covers its data exactly"
            );
        }
        let _ = denc::from_slice::<ObjectRecoveryInfo>(&b);
    }
}

/// MOSDPGUpdateLogMissing(+Reply) are v3 messages: every trailing field of the v3 layout is required, a frame that
/// ends early (or claims an older header version) is refused instead of decoding the missing fields as 0'0.
#[test]
fn update_log_missing_requires_its_v3_fields() {
    let miss = ReplMsg::UpdateLogMissing(MOSDPGUpdateLogMissing {
        map_epoch: 33,
        rep_tid: 55,
        min_epoch: 30,
        pg_trim_to: Eversion::new(30, 90),
        pg_committed_to: Eversion::new(33, 100),
        ..Default::default()
    });
    let reply = ReplMsg::UpdateLogMissingReply(MOSDPGUpdateLogMissingReply {
        map_epoch: 33,
        rep_tid: 55,
        min_epoch: 30,
        last_complete_ondisk: Eversion::new(33, 100),
        ..Default::default()
    });
    for (m, cut) in [(miss, 24), (reply, 16)] {
        let (ty, ver, _, seg) = m.encode(denc::features::ALL).unwrap();
        assert_eq!(decode_repl(ty, ver, &seg).unwrap().unwrap(), m);
        // the trailing v3 fields are min_epoch + two eversions (4 + 12 + 12) / min_epoch + one (4 + 12)
        let mut short = seg.front.clone();
        short.truncate(short.len() - cut);
        assert!(
            decode_repl(ty, ver, &Segments::front(short)).is_err(),
            "type {ty}: a truncated v3 frame never decodes"
        );
        // no older layout that could lack those fields is accepted either
        assert!(decode_repl(ty, ver - 1, &seg).is_err(), "type {ty}: v{ver}");
    }
}

/// The received-push path (`decode_shared`, payload slices of the rx front) is as hostile-input safe as the copy path.
#[test]
fn shared_front_push_with_hostile_values_never_panics() {
    let m = ReplMsg::Push(push_msg(push_op()));
    let (ty, ver, _, s) = m.encode(denc::features::ALL).unwrap();
    let mut r = Rng(0x5eed_11d3);
    for _ in 0..2000 {
        let mut front = s.front.clone();
        r.mutate(&mut front);
        let seg = Segments {
            front_zc: vec![(0, front.into())],
            ..Default::default()
        };
        if let Ok(Some(ReplMsg::Push(p))) = decode_repl(ty, ver, &seg) {
            assert!(
                p.pushes.iter().all(PushOp::data_consistent),
                "a decoded push always covers its data exactly"
            );
        }
    }
}

fn push_msg(op: PushOp) -> MOSDPGPush {
    MOSDPGPush {
        pushes: vec![op],
        ..Default::default()
    }
}

/// E1: interval sets that wrap the u64 sum, overlap, or do not cover the data exactly are refused on decode.
#[test]
fn push_with_bad_interval_set_is_refused() {
    for (inc, data) in [
        (BTreeMap::from([(0, 1), (1, u64::MAX)]), vec![]),
        (BTreeMap::from([(u64::MAX, 2)]), vec![0; 2]),
        (BTreeMap::from([(0, 8), (4, 4)]), vec![0; 12]),
        (BTreeMap::from([(0, 8)]), vec![0; 7]),
        (BTreeMap::new(), vec![0; 1]),
    ] {
        let mut op = push_op();
        op.data_included = inc.clone();
        op.data = data.into();
        let s = push_msg(op).encode(denc::features::ALL).unwrap();
        let ty = <MOSDPGPush as Message>::MSG_TYPE;
        assert!(
            decode_repl(ty, <MOSDPGPush as Message>::HEAD_VERSION, &s).is_err(),
            "{inc:?}"
        );
    }
    let mut ri = recovery_infos().remove(0).1;
    ri.copy_subset = BTreeMap::from([(0, 1), (1, u64::MAX)]);
    assert!(denc::from_slice::<ObjectRecoveryInfo>(&ri.encode_to_vec().unwrap()).is_err());
    // the unbounded "whole object" request classic sends stays valid
    ri.copy_subset = BTreeMap::from([(0, u64::MAX)]);
    assert!(denc::from_slice::<ObjectRecoveryInfo>(&ri.encode_to_vec().unwrap()).is_ok());
}
