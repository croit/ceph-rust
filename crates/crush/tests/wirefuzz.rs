// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Wire-fuzz robustness tests for the CRUSH map codec (AGENTS.md wire-fuzz goal, target 4).
//!
//! Property, for ANY input bytes: the decoder returns Ok or Err — it never panics, never
//! overflows/aborts, never allocates more than a bound proportional to the input (no
//! length-field-driven huge `Vec::with_capacity`), never loops forever. The CRUSH map stream
//! comes from the mon (inside the OSDMap full map / incremental), so a malformed map must be
//! an `Err`, never a panic. The single decode entry point is `crush::codec::decode`
//! (alias `CrushMap::decode`), covering:
//!  * the header (`MAGIC`, `max_buckets`, `max_rules`, `max_devices`) and its admission
//!    bounds;
//!  * every bucket algorithm (uniform / list / tree / straw / straw2) incl. the
//!    `bucket alg mismatch` and `bucket id != slot` checks;
//!  * every rule slot and step;
//!  * the three name maps (incl. the legacy 64-bit-key quirk reader);
//!  * all nine optional trailing stages (tunables, device classes, choose_args, msr).
//!
//! Plus, where an encoder exists:
//!  * roundtrip: `decode(encode(x)) == x` for generated valid `x`;
//!  * truncated: a valid encoding cut at every point is Err — or, if the prefix happens to
//!    be a complete encoding of its own (a cut on a stage boundary), Ok of a value whose
//!    canonical encoding is exactly the consumed prefix (never a value that consumed past
//!    the end);
//!  * mutated: a valid encoding with one byte flipped / inserted / deleted, or a length
//!    field set to an extreme (0, u32::MAX, i32::MIN, len-1, len+1), decodes to Ok or Err.
//!
//! Random bytes alone rarely get past the first length check, so the mutation strategies
//! start from valid encodings (the crate's own `CrushMap::encode`) and disturb them.
//!
//! Default case count is small (this crate's wirefuzz tests finish in < 20 s in debug);
//! `WIREFUZZ_CASES` raises it for long runs (lab/wirefuzz-long.sh).

use crush::codec;
use crush::{Bucket, BucketKind, ChooseArg, ChooseArgs, CrushMap, Rule, Step, Tunables};
use proptest::prelude::*;
use std::collections::BTreeMap;

/// Case count: 256 by default, `WIREFUZZ_CASES` raises it for long runs.
fn cases() -> u32 {
    std::env::var("WIREFUZZ_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(256)
}

/// The proptest! block below shares this case-count config.
fn cfg() -> ProptestConfig {
    ProptestConfig::with_cases(cases())
}

/// Arbitrary bytes, biased short (decoders must fail fast, not grind).
fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..2048)
}

/// Short, non-empty names: the name-map reader treats a zero length prefix as the legacy
/// 64-bit-key form, so roundtrippable maps carry no empty names.
const NAME: &str = r"[a-z0-9.]{1,12}";

/// Extreme values written into a u32 length field.
#[derive(Clone, Copy, Debug)]
enum LenExtreme {
    Zero,
    Max,
    IMin,
    MinusOne,
    PlusOne,
}

/// One local mutation of a valid encoding.
#[derive(Clone, Copy, Debug)]
enum Mutation {
    Flip(usize, u8),
    Delete(usize),
    Insert(usize, u8),
    Len(usize, LenExtreme),
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof!(
        (0usize..512, any::<u8>()).prop_map(|(p, b)| Mutation::Flip(p, b)),
        (0usize..512).prop_map(Mutation::Delete),
        (0usize..=512, any::<u8>()).prop_map(|(p, b)| Mutation::Insert(p, b)),
        (0usize..512, 0..5usize).prop_map(|(p, i)| {
            Mutation::Len(
                p,
                match i {
                    0 => LenExtreme::Zero,
                    1 => LenExtreme::Max,
                    2 => LenExtreme::IMin,
                    3 => LenExtreme::MinusOne,
                    _ => LenExtreme::PlusOne,
                },
            )
        })
    )
}

fn apply(enc: &[u8], m: &Mutation) -> Vec<u8> {
    let mut v = enc.to_vec();
    match m {
        Mutation::Flip(p, b) => {
            if !v.is_empty() {
                let i = *p % v.len();
                v[i] = *b;
            }
        }
        Mutation::Delete(p) => {
            if *p < v.len() {
                v.remove(*p);
            }
        }
        Mutation::Insert(p, b) => v.insert((*p).min(v.len()), *b),
        Mutation::Len(p, x) if v.len() >= 4 => {
            let p = (*p).min(v.len() - 4);
            let cur = u32::from_le_bytes(v[p..p + 4].try_into().unwrap());
            let val = match x {
                LenExtreme::Zero => 0,
                LenExtreme::Max => u32::MAX,
                LenExtreme::IMin => i32::MIN as u32,
                LenExtreme::MinusOne => cur.wrapping_sub(1),
                LenExtreme::PlusOne => cur.wrapping_add(1),
            };
            v[p..p + 4].copy_from_slice(&val.to_le_bytes());
        }
        _ => {}
    }
    v
}

// ---- value strategies ------------------------------------------------------

fn strmap() -> impl Strategy<Value = BTreeMap<i32, String>> {
    prop::collection::btree_map(any::<i32>(), NAME, 0..6)
}

fn bucket() -> impl Strategy<Value = Bucket> {
    prop::collection::vec(0i32..=32, 0..8)
        .prop_flat_map(|items| {
            let n = items.len();
            (
                Just(items),
                any::<u16>(),
                any::<u8>(),
                any::<u32>(),
                0usize..5,
                prop::collection::vec(any::<u32>(), n * 2 + 4),
            )
        })
        .prop_map(|(items, btype, hash, weight, k, extra)| {
            let n = items.len();
            let mut it = extra.into_iter();
            let kind = match k {
                0 => BucketKind::Uniform {
                    item_weight: it.next().unwrap(),
                },
                1 => BucketKind::List {
                    item_weights: it.by_ref().take(n).collect(),
                    sum_weights: it.by_ref().take(n).collect(),
                },
                2 => BucketKind::Tree {
                    node_weights: it.by_ref().take(4).collect(),
                },
                3 => BucketKind::Straw {
                    item_weights: it.by_ref().take(n).collect(),
                    straws: it.by_ref().take(n).collect(),
                },
                _ => BucketKind::Straw2 {
                    item_weights: it.by_ref().take(n).collect(),
                },
            };
            // `id` is fixed to the slot by `crush_map`; the decoder requires `id == -1 - slot`.
            Bucket {
                id: 0,
                btype,
                hash,
                weight,
                items,
                kind,
            }
        })
}

fn rule() -> impl Strategy<Value = Rule> {
    (
        any::<u8>(),
        any::<u8>(),
        any::<u8>(),
        prop::collection::vec((any::<u32>(), any::<i32>(), any::<i32>()), 0..6),
    )
        .prop_map(|(rule_type, min_size, max_size, steps)| Rule {
            rule_type,
            min_size,
            max_size,
            steps: steps
                .into_iter()
                .map(|(op, arg1, arg2)| Step::new(op, arg1, arg2))
                .collect(),
        })
}

fn tunables() -> impl Strategy<Value = Tunables> {
    (
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u8>(),
        any::<u8>(),
        any::<u8>(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
    )
        .prop_map(
            |(
                choose_local_tries,
                choose_local_fallback_tries,
                choose_total_tries,
                chooseleaf_descend_once,
                chooseleaf_vary_r,
                chooseleaf_stable,
                straw_calc_version,
                allowed_bucket_algs,
                msr_descents,
                msr_collision_tries,
            )| {
                Tunables {
                    choose_local_tries,
                    choose_local_fallback_tries,
                    choose_total_tries,
                    chooseleaf_descend_once,
                    chooseleaf_vary_r,
                    chooseleaf_stable,
                    straw_calc_version,
                    allowed_bucket_algs,
                    msr_descents,
                    msr_collision_tries,
                }
            },
        )
}

type ClassMaps = (
    BTreeMap<i32, i32>,
    BTreeMap<i32, String>,
    BTreeMap<i32, BTreeMap<i32, i32>>,
);

fn class_maps() -> impl Strategy<Value = ClassMaps> {
    (
        prop::collection::btree_map(any::<i32>(), any::<i32>(), 0..3),
        prop::collection::btree_map(any::<i32>(), NAME, 0..3),
        prop::collection::btree_map(
            any::<i32>(),
            prop::collection::btree_map(any::<i32>(), any::<i32>(), 0..3),
            0..3,
        ),
    )
}

/// choose_args overrides the decoder keeps: straw2 buckets only, every weight position
/// exactly the bucket's item count (longer ones get truncated), `ids` empty or full-size,
/// and one shared position count across entries. `straw2` = (slot, item count) per straw2
/// bucket, owned so the strategy does not borrow the map. No straw2 buckets = no overrides.
fn choose_args_for(
    straw2: Vec<(usize, usize)>,
) -> impl Strategy<Value = BTreeMap<i64, ChooseArgs>> {
    let total: usize = straw2.iter().map(|(_, s)| *s).sum();
    (any::<i64>(), 1usize..=2)
        .prop_flat_map(move |(key, positions)| {
            (
                Just(key),
                Just(positions),
                prop::collection::vec(any::<u32>(), positions * total + total),
            )
        })
        .prop_map(move |(key, positions, w)| {
            let mut it = w.into_iter();
            let mut entries: Vec<(u32, ChooseArg)> = Vec::new();
            for (bi, bsize) in &straw2 {
                let mut weight_set = Vec::with_capacity(positions);
                for _ in 0..positions {
                    let mut ws = Vec::with_capacity(*bsize);
                    for _ in 0..*bsize {
                        ws.push(it.next().unwrap());
                    }
                    weight_set.push(ws);
                }
                let mut ids = Vec::with_capacity(*bsize);
                for _ in 0..*bsize {
                    ids.push(it.next().unwrap() as i32);
                }
                entries.push((*bi as u32, ChooseArg { weight_set, ids }));
            }
            if entries.is_empty() {
                return BTreeMap::new();
            }
            let mut m = BTreeMap::new();
            m.insert(key, ChooseArgs::from_iter(entries));
            m
        })
}

fn straw2_slots(buckets: &[Bucket]) -> Vec<(usize, usize)> {
    buckets
        .iter()
        .enumerate()
        .filter_map(|(i, b)| match b.kind {
            BucketKind::Straw2 { .. } => Some((i, b.items.len())),
            _ => None,
        })
        .collect()
}

fn crush_map() -> impl Strategy<Value = CrushMap> {
    prop::collection::vec(bucket(), 0..5)
        .prop_flat_map(|buckets| {
            (
                Just(buckets.clone()),
                choose_args_for(straw2_slots(&buckets)),
                prop::collection::vec(rule(), 0..3),
                strmap(),
                strmap(),
                strmap(),
                class_maps(),
                tunables(),
            )
        })
        .prop_map(
            |(
                buckets,
                choose_args,
                rules,
                type_map,
                name_map,
                rule_name_map,
                classes,
                tunables,
            )| {
                let mut m = CrushMap::new();
                for (slot, mut b) in buckets.into_iter().enumerate() {
                    // The decoder requires `id == -1 - slot`.
                    b.id = -(slot as i32 + 1);
                    m.add_bucket(b);
                }
                for (idx, r) in rules.into_iter().enumerate() {
                    m.add_rule(idx, r);
                }
                m.tunables = tunables;
                m.type_map = type_map;
                m.name_map = name_map;
                m.rule_name_map = rule_name_map;
                m.class_map = classes.0;
                m.class_name = classes.1;
                m.class_bucket = classes.2;
                m.choose_args = choose_args;
                // `add_bucket` already ran `finalize` before the name map was known; recompute
                // so `max_devices` includes the name-map device ids, exactly like decode does.
                m.finalize();
                m
            },
        )
}

// ---- the codec ------------------------------------------------------------

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn any_byte(b in bytes()) {
        let _ = codec::decode(&b);
        let _ = CrushMap::decode(&b);
    }

    #[test]
    fn roundtrip(m in crush_map()) {
        let enc = m.encode();
        let dec = codec::decode(&enc).unwrap();
        assert_eq!(dec, m);
    }

    #[test]
    fn truncated(m in crush_map()) {
        let enc = m.encode();
        for c in 0..enc.len() {
            if let Ok(dec) = codec::decode(&enc[..c]) {
                assert_eq!(
                    dec.encode(),
                    &enc[..c],
                    "cut {c}: Ok value re-encodes differently (consumed past the end?)"
                );
            }
        }
    }

    #[test]
    fn mutated(m in crush_map(), mt in mutation()) {
        let enc = m.encode();
        let buf = apply(&enc, &mt);
        let _ = codec::decode(&buf);
    }
}

// ---- W17: deterministic regressions for the documented decode branches ----

/// A straw2 bucket with three items, at `slot` with the decoder-required `id == -1 - slot`.
fn straw2_bucket(slot: i32, items: Vec<i32>) -> Bucket {
    Bucket {
        id: -1 - slot,
        btype: 1,
        hash: 1,
        weight: 10,
        kind: BucketKind::Straw2 {
            item_weights: items.iter().map(|_| 1).collect(),
        },
        items,
    }
}

/// `ChooseArgs` with `ids` empty (the "no id override" form) must survive the wire.
#[test]
fn choose_args_empty_ids_roundtrip() {
    let mut m = CrushMap::new();
    m.add_bucket(straw2_bucket(0, vec![7, 8, 9]));
    m.choose_args.insert(
        -1,
        ChooseArgs::from_iter([(
            0,
            ChooseArg {
                weight_set: vec![vec![10, 20, 30]],
                ids: vec![],
            },
        )]),
    );
    m.finalize();
    let enc = m.encode();
    let dec = codec::decode(&enc).expect("empty-ids choose_args must decode");
    assert_eq!(dec.choose_args, m.choose_args, "empty ids must roundtrip");
}

/// `Bucket { id: 0 }` at slot 3 violates `id == -1 - slot` and must be rejected.
#[test]
fn bucket_id_mismatch_rejected() {
    let mut m = CrushMap::new();
    // `add_bucket` enforces `id < 0` by construction, so the hostile bucket goes in through
    // the public slot array (the wire carries ids verbatim; nothing stops a mon sending this).
    let mut bad = straw2_bucket(3, vec![1, 2]);
    bad.id = 0; // must be -4
    m.buckets = vec![
        Some(straw2_bucket(0, vec![7])),
        Some(straw2_bucket(1, vec![8])),
        Some(straw2_bucket(2, vec![9])),
        Some(bad),
    ];
    m.finalize();
    let enc = m.encode();
    assert!(
        codec::decode(&enc).is_err(),
        "a bucket at slot 3 with id 0 must be rejected"
    );
}

/// A choose_args override of a non-straw2 bucket (alg mismatch) is dropped by decode.
#[test]
fn choose_args_bucket_alg_mismatch_dropped() {
    let mut m = CrushMap::new();
    m.add_bucket(straw2_bucket(0, vec![1, 2, 3]));
    m.add_bucket(Bucket {
        id: -2,
        btype: 1,
        hash: 1,
        weight: 10,
        items: vec![4, 5],
        kind: BucketKind::Straw {
            item_weights: vec![1, 2],
            straws: vec![9, 8],
        },
    });
    let good = ChooseArg {
        weight_set: vec![vec![1, 2, 3]],
        ids: vec![],
    };
    m.choose_args.insert(
        -1,
        ChooseArgs::from_iter([
            (0, good.clone()),
            (
                1,
                ChooseArg {
                    weight_set: vec![vec![9, 8]],
                    ids: vec![],
                },
            ),
        ]),
    );
    m.finalize();
    let enc = m.encode();
    let dec = codec::decode(&enc).expect("the map itself must decode");
    assert_eq!(
        dec.choose_args,
        BTreeMap::from([(-1, ChooseArgs::from_iter([(0, good)]))]),
        "the non-straw2 override must be dropped"
    );
}
