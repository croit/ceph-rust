// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Malformed peer input: peering structs and messages with hostile counts / lengths (not only bit flips) decode to
//! `Err` or a value, never panic; PastIntervals acceptance (E6, peering.md 2.5 / 3.3).
use denc::types::{PgShard, ShardId};
use denc::{Encode, from_slice};
use messages::Segments;
use pgwire::*;
use std::collections::BTreeSet;
use std::path::PathBuf;

fn td(p: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../testdata/pgwire")
            .join(p),
    )
    .unwrap()
}

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
    /// 1-4 edits: bit flip, hostile 32/64-bit value, random byte; sometimes a truncation.
    fn mutate(&mut self, b: &mut Vec<u8>) {
        if b.is_empty() {
            return;
        }
        for _ in 0..1 + self.below(4) {
            let at = self.below(b.len());
            let hostile: [u8; 8] = match self.below(3) {
                0 => [0xff; 8],
                1 => [0xff, 0xff, 0xff, 0x7f, 0, 0, 0, 0],
                _ => [0, 0, 0, 1, 0, 0, 0, 0],
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

/// Fixture file and the checks run on each mutation of it.
type Case = (&'static str, fn(&[u8]));

#[test]
fn structs_with_hostile_values_never_panic() {
    let mut r = Rng(0x5eed_09e1);
    let cases: Vec<Case> = vec![
        ("PastIntervals/3.bin", |b| {
            if let Ok(p) = from_slice::<PastIntervals>(b) {
                assert!(
                    p.check_wire().is_ok(),
                    "a decoded PastIntervals is well formed"
                );
                let _ = p.intervals_since(0).count();
            }
        }),
        ("ObjectCleanRegions/2.bin", |b| {
            if let Ok(mut c) = from_slice::<ObjectCleanRegions>(b) {
                c.merge(&ObjectCleanRegions::default());
                c.trim(1);
            }
        }),
        ("pg_log_t/2.bin", |b| drop(from_slice::<PgLog>(b))),
        ("pg_missing_t/1.bin", |b| drop(from_slice::<PgMissing>(b))),
        ("pg_info_t/2.bin", |b| drop(from_slice::<PgInfo>(b))),
        ("pg_notify_t/3.bin", |b| drop(from_slice::<PgNotify>(b))),
        ("pg_log_entry_t/3.bin", |b| drop(from_slice::<LogEntry>(b))),
    ];
    for (f, check) in cases {
        let base = td(f);
        for _ in 0..1500 {
            let mut b = base.clone();
            r.mutate(&mut b);
            check(&b);
        }
    }
}

/// Dencoder message wrapper: 53 B header, 12 B crcs, 1 B flag, u32 front len (front at offset 70).
/// Returns `(type, version, front)`.
fn msg_front(name: &str) -> (u16, u16, Vec<u8>) {
    let raw = td(&format!("msg/{name}.bin"));
    let ty = u16::from_le_bytes([raw[16], raw[17]]);
    let ver = u16::from_le_bytes([raw[20], raw[21]]);
    let flen = u32::from_le_bytes(raw[22..26].try_into().unwrap()) as usize;
    (ty, ver, raw[70..70 + flen].to_vec())
}

#[test]
fn messages_with_hostile_values_never_panic() {
    let mut r = Rng(0x5eed_03e5);
    for name in [
        "MOSDPGCreate2",
        "MOSDPGLog",
        "MOSDPGRecoveryDelete",
        "MOSDPGRemove",
        "MOSDPGTrim",
    ] {
        let (ty, ver, front) = msg_front(name);
        for _ in 0..1500 {
            let mut f = front.clone();
            r.mutate(&mut f);
            let _ = decode_peering(ty, ver, &Segments::front(f));
        }
    }
}

/// Every field of an hv6 MOSDPGLog is mandatory, the lease presence byte included (peering 4.1): a
/// message cut after `from` must not decode as `lease = None`.
#[test]
fn mosdpglog_prefixes_are_errors() {
    let (ty, ver, front) = msg_front("MOSDPGLog");
    assert!(
        decode_peering(ty, ver, &Segments::front(front.clone()))
            .unwrap()
            .is_ok()
    );
    for n in 0..front.len() {
        assert!(
            decode_peering(ty, ver, &Segments::front(front[..n].to_vec()))
                .unwrap()
                .is_err(),
            "MOSDPGLog prefix {n}"
        );
    }
}

fn shard(osd: i32) -> PgShard {
    PgShard {
        osd,
        shard: ShardId::NO_SHARD,
    }
}

fn pi(first: u32, last: u32, iv: &[(u32, u32)]) -> PastIntervals {
    PastIntervals {
        first,
        last,
        all_participants: BTreeSet::from([shard(0), shard(1)]),
        intervals: iv
            .iter()
            .map(|&(first, last)| CompactInterval {
                first,
                last,
                acting: BTreeSet::from([shard(0)]),
            })
            .collect(),
    }
}

/// E6: out-of-order, inverted or out-of-range stored intervals are refused on decode.
#[test]
fn malformed_past_intervals_are_refused() {
    let ok = pi(10, 40, &[(10, 19), (20, 29), (30, 40)]);
    assert!(from_slice::<PastIntervals>(&ok.encode_to_vec().unwrap()).is_ok());
    for bad in [
        pi(10, 40, &[(30, 40), (10, 19)]),
        pi(10, 40, &[(20, 15)]),
        pi(10, 40, &[(10, 50)]),
        pi(0, 0, &[(10, 19)]),
    ] {
        assert!(
            from_slice::<PastIntervals>(&bad.encode_to_vec().unwrap()).is_err(),
            "{bad:?}"
        );
    }
}

/// E6: classic's required bounds `[max(lec or created, oldest), max(sis, created))`.
#[test]
fn required_bounds() {
    let h = |lec: u32, sis: u32| PgHistory {
        epoch_pool_created: 5,
        last_epoch_clean: lec,
        same_interval_since: sis,
        ..Default::default()
    };
    let p = pi(10, 40, &[(30, 40)]);
    let c = p.check_required_bounds(&h(10, 41), 1);
    assert!(c.is_ok() && c.required == (10, 41) && c.past == (10, 41));
    assert!(
        p.check_required_bounds(&h(20, 41), 1).is_ok(),
        "starts before the required start"
    );
    let c = p.check_required_bounds(&h(8, 41), 1);
    assert_eq!(
        (c.verdict, c.required),
        (BoundsVerdict::StartAfter, (8, 41)),
        "misses [8, 10)"
    );
    assert!(
        p.check_required_bounds(&h(8, 41), 10).is_ok(),
        "oldest map lifts the start"
    );
    let c = p.check_required_bounds(&h(10, 45), 1);
    assert_eq!(
        (c.verdict, c.required),
        (BoundsVerdict::EndDiffers, (10, 45)),
        "misses [41, 45)"
    );
    let c = PastIntervals::default().check_required_bounds(&h(10, 41), 1);
    assert_eq!((c.verdict, c.past), (BoundsVerdict::EmptyPast, (0, 0)));
    // nothing required: an empty set is silent, a non-empty one only warns (case 1)
    let c = PastIntervals::default().check_required_bounds(&h(41, 41), 1);
    assert_eq!(c.verdict, BoundsVerdict::Ok);
    assert_eq!(
        PastIntervals::default()
            .check_required_bounds(&h(0, 5), 1)
            .verdict,
        BoundsVerdict::Ok
    );
    assert_eq!(
        p.check_required_bounds(&h(41, 41), 1).verdict,
        BoundsVerdict::EmptyRequired
    );
    // a start clamped to the trim bound is not history-derived: no warning
    assert_eq!(
        p.check_required_bounds(&h(8, 8), 10).verdict,
        BoundsVerdict::Ok
    );
}
