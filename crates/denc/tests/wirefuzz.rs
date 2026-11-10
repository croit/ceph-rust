// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Wire-fuzz robustness tests for every denc decoder (AGENTS.md wire-fuzz goal, target 1).
//!
//! Property, for ANY input bytes: a decoder returns Ok or Err — it never panics, never
//! overflows/aborts, never allocates more than a bound proportional to the input (no
//! length-field-driven huge `Vec::with_capacity`; enforced by the counting global allocator
//! on the any-byte and length-mutation cases), never loops forever. Plus, where an
//! encoder exists:
//!  * roundtrip: `decode(encode(x)) == x` for generated valid `x`;
//!  * truncated: a valid encoding cut at every point is Err — or, if the prefix happens to
//!    be a complete encoding of its own, Ok of a value whose canonical encoding is exactly
//!    the consumed prefix (never a value that consumed past the end);
//!  * mutated: a valid encoding with one byte flipped / inserted / deleted, or a length
//!    field set to an extreme (0, u32::MAX, i32::MIN, len-1, len+1), decodes to Ok or Err.
//!
//! Random bytes alone rarely get past the first length check, so the mutation strategies
//! start from valid encodings (the crate's own encoders) and disturb them.
//!
//! Default case count is small (each crate's wirefuzz tests finish in < 20 s in debug);
//! `WIREFUZZ_CASES` raises it for long runs (lab/wirefuzz-long.sh).

use denc::types::entity::{AF_INET, AF_INET6};
use denc::types::{
    CollT, EntityAddr, EntityAddrVec, EntityInst, EntityName, Eversion, Ghobject, Hobject,
    ObjectLocator, OsdReqId, PgShard, PgT, SObject, ShardId, SnapId, SpgT, Timespan, UTime, Uuid,
};
use denc::{Decoder, Encode, Encoder, Error, from_slice};
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Case count: 256 by default, `WIREFUZZ_CASES` raises it for long runs.
fn cases() -> u32 {
    std::env::var("WIREFUZZ_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(256)
}

/// The proptest! blocks below all share this case-count config.
fn cfg() -> ProptestConfig {
    ProptestConfig::with_cases(cases())
}

/// Counting global allocator (W3): a decoder must not allocate more than a bound proportional
/// to the input (no length-field-driven huge `Vec::with_capacity`). Tracks peak live bytes for
/// the whole test binary; [`baseline`] re-arms it right before the decode under test so only the
/// decode's own growth is measured (the 1 MiB slack covers concurrent tests' transient
/// allocations in this process).
mod allocs {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    // Per-thread counters: the decoders run on the calling thread, so the measurement sees only the decode under
    // test, never the allocations of tests running in parallel threads (no noise, no re-runs). `const` thread
    // locals with `Cell` need no allocation, so the allocator can use them.
    thread_local! {
        static LIVE: Cell<i64> = const { Cell::new(0) };
        static PEAK: Cell<i64> = const { Cell::new(0) };
    }

    struct Counting;

    #[global_allocator]
    static GLOBAL: Counting = Counting;

    fn bump(delta: i64) {
        // `try_with`: allocations during thread-local teardown are simply not counted
        let _ = LIVE.try_with(|live| {
            let now = live.get() + delta;
            live.set(now);
            let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
        });
    }

    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let p = unsafe { System.alloc(layout) };
            if !p.is_null() {
                bump(layout.size() as i64);
            }
            p
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) };
            bump(-(layout.size() as i64));
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let p = unsafe { System.realloc(ptr, layout, new_size) };
            if !p.is_null() {
                bump(new_size as i64 - layout.size() as i64);
            }
            p
        }
    }

    /// W3 bound, measured once around one decode on this thread: the growth of live heap memory during the decode
    /// (peak live bytes minus the live total right before it) must stay `<= 64 * input_len + 1 MiB`. A decoder that
    /// sizes an allocation from an untrusted length field instead of the remaining input fails deterministically.
    pub fn measure<F: FnMut()>(input_len: usize, what: &str, mut decode: F) {
        let bound = 64 * input_len + 1024 * 1024;
        let base = LIVE.with(Cell::get);
        PEAK.with(|peak| peak.set(base));
        decode();
        let growth = usize::try_from(PEAK.with(Cell::get) - base).unwrap_or(0);
        assert!(
            growth <= bound,
            "{what}: live heap growth {growth} B during one decode exceeds 64 * {input_len} B + 1 MiB"
        );
    }
}

/// Arbitrary bytes, biased short (decoders must fail fast, not grind).
fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..2048)
}

fn u8s(n: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..n)
}

/// proptest 1.12: a `&'static str` regex is itself a string strategy.
const STR_UNI_64: &str = r"[\p{L}\p{N}\p{P}\p{S}\p{Z}]{0,64}";
const STR_UNI_8: &str = r"[\p{L}\p{N}]{0,8}";
const STR_ASCII_1_8: &str = r"[a-z]{1,8}";

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

/// The pool -1 -> MIN fix-up (hobject v >= 4): applied by every hobject field decode.
/// Mirrors `Hobject::decode_fields` exactly, incl. the `!max` guard (a MAX sentinel object
/// keeps pool -1; only real empty objects are folded to `i64::MIN`).
fn norm_hobject_fields(h: Hobject) -> Hobject {
    if h.pool == -1 && h.snap.0 == 0 && h.hash == 0 && !h.max && h.oid.is_empty() {
        Hobject {
            pool: i64::MIN,
            ..h
        }
    } else {
        h
    }
}

/// `decode(encode(x)) == norm(x)`: the pool fix-up plus the MAX sentinel collapse
/// (hobject_t decode maps max=true to canonical MAX), so roundtrips compare canonical.
fn norm_hobject(h: Hobject) -> Hobject {
    if h.max {
        return Hobject::MAX();
    }
    norm_hobject_fields(h)
}

/// ghobject_t decodes the hobject via `decode_fields` (no MAX collapse; the outer `max`
/// flag is separate), so only the pool fix-up applies to the inner object.
fn norm_ghobject(g: Ghobject) -> Ghobject {
    Ghobject {
        hobj: norm_hobject_fields(g.hobj),
        ..g
    }
}

fn entity_name() -> impl Strategy<Value = EntityName> {
    (any::<u8>(), any::<i64>()).prop_map(|(ty, num)| EntityName::new(ty, num))
}

fn entity_addr() -> impl Strategy<Value = EntityAddr> {
    (
        any::<u32>(),
        any::<u32>(),
        prop_oneof!(Just(0u16), Just(AF_INET), Just(AF_INET6)),
        prop::array::uniform::<_, 26>(any::<u8>()),
    )
        .prop_map(|(ty, nonce, family, mut data)| {
            // the v4 form carries only 14 data bytes on the wire; the rest must be zero
            if family == AF_INET {
                data[14..].fill(0);
            }
            EntityAddr {
                ty,
                nonce,
                family,
                data,
            }
        })
}

fn spg() -> impl Strategy<Value = SpgT> {
    ((any::<u64>(), any::<u32>()), any::<i8>()).prop_map(|((pool, seed), shard)| SpgT {
        pgid: PgT::new(pool, seed),
        shard: ShardId(shard),
    })
}

fn hobject() -> impl Strategy<Value = Hobject> {
    (
        u8s(16),
        u8s(16),
        any::<u64>(),
        any::<u32>(),
        any::<bool>(),
        u8s(16),
        any::<i64>(),
    )
        .prop_map(|(key, oid, snap, hash, max, nspace, pool)| Hobject {
            key,
            oid,
            snap: SnapId(snap),
            hash,
            max,
            nspace,
            pool,
        })
}

fn ghobject() -> impl Strategy<Value = Ghobject> {
    (hobject(), any::<u64>(), any::<i8>(), any::<bool>()).prop_map(
        |(hobj, generation, shard, max)| Ghobject {
            hobj,
            generation,
            shard: ShardId(shard),
            max,
        },
    )
}

fn kv_pairs() -> impl Strategy<Value = Vec<(String, Vec<u8>)>> {
    prop::collection::vec((STR_ASCII_1_8, u8s(8)), 0..8).prop_map(|mut v| {
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v.dedup_by(|a, b| a.0 == b.0);
        v
    })
}

/// Four wirefuzz tests per type: any-byte decode (no panic, no huge allocation), roundtrip,
/// truncation at every cut point, and single-mutation of a valid encoding.
macro_rules! wirefuzz_type {
    ($name:ident, $ty:ty, $strategy:expr, $normalize:expr) => {
        mod $name {
            use super::*;

            proptest! {
                #![proptest_config(cfg())]

                #[test]
                fn any_byte(b in bytes()) {
                    allocs::measure(b.len(), concat!(stringify!($name), " any_byte"), || {
                        let _ = from_slice::<$ty>(&b);
                    });
                }

                #[test]
                fn roundtrip(v in $strategy) {
                    let enc = v.encode_to_vec().unwrap();
                    let dec = from_slice::<$ty>(&enc).unwrap();
                    let exp = $normalize(v);
                    assert_eq!(dec, exp);
                }

                #[test]
                fn truncated(v in $strategy) {
                    let enc = v.encode_to_vec().unwrap();
                    for c in 0..enc.len() {
                        if let Ok(dec) = from_slice::<$ty>(&enc[..c]) {
                            let re = $normalize(dec);
                            assert_eq!(
                                re.encode_to_vec().unwrap(),
                                &enc[..c],
                                "cut {c}: Ok value re-encodes differently (consumed past the end?)"
                            );
                        }
                    }
                }

                #[test]
                fn mutated(v in $strategy, m in mutation()) {
                    let enc = v.encode_to_vec().unwrap();
                    let buf = apply(&enc, &m);
                    // only the Len mutations can drive a length-field allocation
                    let len = matches!(m, Mutation::Len(..));
                    if len {
                        allocs::measure(buf.len(), concat!(stringify!($name), " mutated"), || {
                            let _ = from_slice::<$ty>(&buf);
                        });
                    }
                }
            }
        }
    };
}

wirefuzz_type!(u8, u8, any::<u8>(), |v| v);
wirefuzz_type!(i8, i8, any::<i8>(), |v| v);
wirefuzz_type!(u16, u16, any::<u16>(), |v| v);
wirefuzz_type!(i16, i16, any::<i16>(), |v| v);
wirefuzz_type!(u32, u32, any::<u32>(), |v| v);
wirefuzz_type!(i32, i32, any::<i32>(), |v| v);
wirefuzz_type!(u64, u64, any::<u64>(), |v| v);
wirefuzz_type!(i64, i64, any::<i64>(), |v| v);
wirefuzz_type!(bool, bool, any::<bool>(), |v| v);
wirefuzz_type!(
    f32,
    f32,
    any::<u32>()
        .prop_map(f32::from_bits)
        .prop_filter("no NaN (not PartialEq)", |v| !v.is_nan()),
    |v| v
);
wirefuzz_type!(
    f64,
    f64,
    any::<u64>()
        .prop_map(f64::from_bits)
        .prop_filter("no NaN (not PartialEq)", |v| !v.is_nan()),
    |v| v
);
wirefuzz_type!(string, String, STR_UNI_64, |v| v);
wirefuzz_type!(vec_u8, Vec<u8>, u8s(256), |v| v);
wirefuzz_type!(
    vec_u32,
    Vec<u32>,
    prop::collection::vec(any::<u32>(), 0..32),
    |v| v
);
wirefuzz_type!(
    vecdeque_u16,
    VecDeque<u16>,
    prop::collection::vec(any::<u16>(), 0..32).prop_map(VecDeque::from),
    |v| v
);
wirefuzz_type!(
    btreemap_u32_string,
    BTreeMap<u32, String>,
    prop::collection::btree_map(any::<u32>(), STR_UNI_8, 0..8),
    |v| v
);
wirefuzz_type!(
    btreemap_u64_u64,
    BTreeMap<u64, u64>,
    prop::collection::btree_map(any::<u64>(), any::<u64>(), 0..8),
    |v| v
);
wirefuzz_type!(
    btreemap_string_vec_u8,
    BTreeMap<String, Vec<u8>>,
    prop::collection::btree_map(STR_UNI_8, u8s(16), 0..4),
    |v| v
);
wirefuzz_type!(
    btreemap_u32_option_u32,
    BTreeMap<u32, Option<u32>>,
    prop::collection::btree_map(any::<u32>(), any::<Option<u32>>(), 0..8),
    |v| v
);
wirefuzz_type!(
    btree_set_u64,
    BTreeSet<u64>,
    prop::collection::btree_set(any::<u64>(), 0..8),
    |v| v
);
wirefuzz_type!(option_u32, Option<u32>, any::<Option<u32>>(), |v| v);
wirefuzz_type!(tuple2_u8_u16, (u8, u16), (any::<u8>(), any::<u16>()), |v| v);
wirefuzz_type!(
    tuple3_u32_i32_i64,
    (u32, i32, i64),
    (any::<u32>(), any::<i32>(), any::<i64>()),
    |v| v
);
wirefuzz_type!(
    array_u8_16,
    [u8; 16],
    prop::array::uniform::<_, 16>(any::<u8>()),
    |v| v
);
wirefuzz_type!(
    uuid,
    Uuid,
    prop::array::uniform::<_, 16>(any::<u8>()).prop_map(Uuid),
    |v| v
);
wirefuzz_type!(entity_name, EntityName, entity_name(), |v| v);
wirefuzz_type!(entity_addr, EntityAddr, entity_addr(), |v| v);
wirefuzz_type!(
    entity_addr_vec,
    EntityAddrVec,
    prop::collection::vec(entity_addr(), 0..4).prop_map(EntityAddrVec),
    |v| v
);
wirefuzz_type!(
    entity_inst,
    EntityInst,
    (entity_name(), entity_addr()).prop_map(|(name, addr)| EntityInst { name, addr }),
    |v| v
);
wirefuzz_type!(
    utime,
    UTime,
    (any::<u32>(), any::<u32>()).prop_map(|(sec, nsec)| UTime::new(sec, nsec)),
    |v| v
);
wirefuzz_type!(
    timespan,
    Timespan,
    (any::<i32>(), any::<i32>()).prop_map(|(sec, nsec)| Timespan { sec, nsec }),
    |v| v
);
wirefuzz_type!(snap_id, SnapId, any::<u64>().prop_map(SnapId), |v| v);
wirefuzz_type!(shard_id, ShardId, any::<i8>().prop_map(ShardId), |v| v);
wirefuzz_type!(
    eversion,
    Eversion,
    (any::<u32>(), any::<u64>()).prop_map(|(epoch, version)| Eversion::new(epoch, version)),
    |v| v
);
wirefuzz_type!(
    osd_req_id,
    OsdReqId,
    (entity_name(), any::<u64>(), any::<i32>()).prop_map(|(name, tid, inc)| OsdReqId {
        name,
        tid,
        inc
    }),
    |v| v
);
wirefuzz_type!(
    pg_t,
    PgT,
    (any::<u64>(), any::<u32>()).prop_map(|(pool, seed)| PgT::new(pool, seed)),
    |v| v
);
wirefuzz_type!(spg_t, SpgT, spg(), |v| v);
wirefuzz_type!(
    pg_shard,
    PgShard,
    (any::<i32>(), any::<i8>()).prop_map(|(osd, shard)| PgShard {
        osd,
        shard: ShardId(shard)
    }),
    |v| v
);
wirefuzz_type!(
    sobject,
    SObject,
    (u8s(32), any::<u64>()).prop_map(|(oid, snap)| SObject {
        oid,
        snap: SnapId(snap)
    }),
    |v| v
);
wirefuzz_type!(hobject, Hobject, hobject(), norm_hobject);
wirefuzz_type!(ghobject, Ghobject, ghobject(), norm_ghobject);
wirefuzz_type!(
    object_locator,
    ObjectLocator,
    (any::<i64>(), u8s(16), u8s(16), any::<i64>()).prop_map(|(pool, key, nspace, hash)| {
        ObjectLocator {
            pool,
            key,
            nspace,
            hash,
        }
    }),
    |v| v
);
wirefuzz_type!(
    coll_t,
    CollT,
    prop_oneof!(
        Just(CollT::Meta),
        spg().prop_map(CollT::Pg),
        spg().prop_map(CollT::PgTemp)
    ),
    |v| v
);

// Borrowed decoders: the value is the input itself, so the canonicality check is
// `decoded.encode_to_vec() == the exact prefix consumed`.
proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn borrow_slice_any_byte(b in bytes()) {
        allocs::measure(b.len(), "borrow_slice any_byte", || {
            let _ = from_slice::<&[u8]>(&b);
        });
    }

    #[test]
    fn borrow_slice_roundtrip(v in u8s(256)) {
        let enc = v.clone().encode_to_vec().unwrap();
        let dec: &[u8] = from_slice(&enc).unwrap();
        assert_eq!(dec, v.as_slice());
        assert_eq!(&enc[4..], v.as_slice());
    }

    #[test]
    fn borrow_slice_truncated(v in u8s(256)) {
        let enc = v.clone().encode_to_vec().unwrap();
        for c in 0..enc.len() {
            if let Ok(dec) = from_slice::<&[u8]>(&enc[..c]) {
                assert_eq!(
                    dec.encode_to_vec().unwrap(),
                    &enc[..c],
                    "cut {c}: consumed a different range"
                );
            }
        }
    }

    #[test]
    fn borrow_slice_mutated(v in u8s(256), m in mutation()) {
        let enc = v.clone().encode_to_vec().unwrap();
        let buf = apply(&enc, &m);
        let len = matches!(m, Mutation::Len(..));
        if len {
            allocs::measure(buf.len(), "borrow_slice mutated", || {
                let _ = from_slice::<&[u8]>(&buf);
            });
        }
    }

    #[test]
    fn borrow_str_any_byte(b in bytes()) {
        allocs::measure(b.len(), "borrow_str any_byte", || {
            let _ = from_slice::<&str>(&b);
        });
    }

    #[test]
    fn borrow_str_roundtrip(v in STR_UNI_64) {
        let enc = v.clone().encode_to_vec().unwrap();
        let dec: &str = from_slice(&enc).unwrap();
        assert_eq!(dec, v.as_str());
        assert_eq!(&enc[4..], v.as_bytes());
    }

    #[test]
    fn borrow_str_truncated(v in STR_UNI_64) {
        let enc = v.clone().encode_to_vec().unwrap();
        for c in 0..enc.len() {
            if let Ok(dec) = from_slice::<&str>(&enc[..c]) {
                assert_eq!(
                    dec.encode_to_vec().unwrap(),
                    &enc[..c],
                    "cut {c}: consumed a different range"
                );
            }
        }
    }

    #[test]
    fn borrow_str_mutated(v in STR_UNI_64, m in mutation()) {
        let enc = v.clone().encode_to_vec().unwrap();
        let buf = apply(&enc, &m);
        let len = matches!(m, Mutation::Len(..));
        if len {
            allocs::measure(buf.len(), "borrow_str mutated", || {
                let _ = from_slice::<&str>(&buf);
            });
        }
    }
}

// LEB128 varint family: decoder methods, no `Decode` type.
macro_rules! wirefuzz_varint {
    ($name:ident, $enc_fn:ident, $strategy:expr, $note:expr) => {
        mod $name {
            use super::*;

            proptest! {
                #![proptest_config(cfg())]

                #[test]
                fn any_byte(b in bytes()) {
                    allocs::measure(b.len(), concat!(stringify!($name), " any_byte"), || {
                        let mut d = Decoder::new(&b);
                        let _ = d.$enc_fn();
                    });
                }

                #[test]
                fn roundtrip(v in $strategy) {
                    let mut e = Encoder::new();
                    e.$enc_fn(v).unwrap();
                    let enc = e.into_vec();
                    let mut d = Decoder::new(&enc);
                    assert_eq!(d.$enc_fn().unwrap(), v);
                    assert_eq!(d.remaining(), 0);
                }

                #[test]
                fn truncated(v in $strategy) {
                    let mut e = Encoder::new();
                    e.$enc_fn(v).unwrap();
                    let enc = e.into_vec();
                    for c in 0..enc.len() {
                        let mut d = Decoder::new(&enc[..c]);
                        if let Ok(x) = d.$enc_fn() {
                            let mut re = Encoder::new();
                            re.$enc_fn(x).unwrap();
                            assert_eq!(
                                re.into_vec(),
                                &enc[..c],
                                "cut {c}: varint prefix re-encodes differently ($note)"
                            );
                        }
                    }
                }

                #[test]
                fn mutated(v in $strategy, m in mutation()) {
                    let mut e = Encoder::new();
                    e.$enc_fn(v).unwrap();
                    let enc = e.into_vec();
                    let buf = apply(&enc, &m);
                    let len = matches!(m, Mutation::Len(..));
                    if len {
                        allocs::measure(buf.len(), concat!(stringify!($name), " mutated"), || {
                            let mut d = Decoder::new(&buf);
                            let _ = d.$enc_fn();
                        });
                    }
                }
            }
        }
    };
}

wirefuzz_varint!(varint, varint, any::<u64>(), "u64");
wirefuzz_varint!(
    varint_signed,
    varint_signed,
    any::<i64>().prop_filter("i64::MIN has no varint encoding", |v| *v != i64::MIN),
    "i64"
);
wirefuzz_varint!(varint_lowz, varint_lowz, 0..(1u64 << 62), "u64 < 2^62");
wirefuzz_varint!(
    varint_lowz_signed,
    varint_lowz_signed,
    (-((1i64 << 61) - 1))..((1i64 << 61) - 1),
    "i64, |v| < 2^61"
);

// Versioned envelope (ENCODE_START/DECODE_START) and raw envelope borrowing.
proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn envelope_raw_any_byte(b in bytes()) {
        allocs::measure(b.len(), "envelope_raw any_byte", || {
            let mut d = Decoder::new(&b);
            let _ = d.envelope_raw();
        });
    }

    #[test]
    fn envelope_vec_raw_any_byte(b in bytes()) {
        allocs::measure(b.len(), "envelope_vec_raw any_byte", || {
            let mut d = Decoder::new(&b);
            let _ = d.envelope_vec_raw();
        });
    }

    #[test]
    fn versioned_any_byte(b in bytes()) {
        allocs::measure(b.len(), "versioned any_byte", || {
            let mut d = Decoder::new(&b);
            let _ = d.versioned(255, |_d, _v| Ok::<u8, Error>(0));
        });
    }
}

/// Nested envelopes decode; unknown trailing bytes inside the body are skipped (spec 4.5).
#[test]
fn versioned_roundtrip_and_skip() {
    let enc = denc::encode_exact(denc::features::ALL, |e| {
        e.versioned(3, 1, |e| {
            e.u32(42)?;
            e.versioned(2, 2, |e| {
                e.u16(7)?;
                e.raw(&[9u8; 3]) // unknown trailing bytes, bounded by the envelope len
            })
        })
    })
    .unwrap();
    let mut d = Decoder::new(&enc);
    let (x, y) = d
        .versioned(3, |d, v| {
            assert_eq!(v, 3);
            let x = d.u32()?;
            let y: u16 = d.versioned(2, |d, _| d.u16())?;
            Ok((x, y))
        })
        .unwrap();
    assert_eq!((x, y), (42, 7));
    assert_eq!(d.remaining(), 0);

    // struct_compat above max -> Err, struct_v below oldest -> Err
    let buf = vec![9u8, 5, 0, 0, 0, 0];
    assert!(matches!(
        Decoder::new(&buf).versioned(3, |_, _| Ok(0u8)),
        Err(Error::CompatTooNew { .. })
    ));
    let buf = vec![3u8, 5, 0, 0, 0, 0];
    assert!(matches!(
        Decoder::new(&buf).versioned_min(4, 9, |_, _| Ok(0u8)),
        Err(Error::VersionTooOld { .. })
    ));
}

/// Extreme length fields: Err, not a huge allocation.
#[test]
fn extreme_length_fields_are_err_not_alloc() {
    // count = u32::MAX
    let mut buf = u32::MAX.to_le_bytes().to_vec();
    buf.extend_from_slice(&[0u8; 16]);
    assert!(matches!(
        Decoder::new(&buf).count(),
        Err(Error::BadLength { .. })
    ));
    // count = i32::MIN (written as u32)
    let buf = (i32::MIN as u32).to_le_bytes();
    assert!(Decoder::new(&buf).count().is_err());
    // versioned envelope, struct_len = u32::MAX
    let mut buf = vec![1u8, 1];
    buf.extend_from_slice(&u32::MAX.to_le_bytes());
    buf.extend_from_slice(&[0u8; 16]);
    assert!(Decoder::new(&buf).versioned(1, |_, _| Ok(0u8)).is_err());
    // envelope_raw, len = u32::MAX
    let mut buf = vec![0u8, 0];
    buf.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(Decoder::new(&buf).envelope_raw().is_err());
    // envelope_vec_raw: count says 3, only room for one 6-byte envelope
    let mut buf = vec![3, 0, 0, 0];
    buf.extend_from_slice(&[1u8, 1, 0, 0, 0, 0]);
    assert!(Decoder::new(&buf).envelope_vec_raw().is_err());
    // bytes() with len-1 / len+1 around the truth: 8 bytes after the count, count 7 and 9
    let mut ok = Vec::new();
    ok.extend_from_slice(&8u32.to_le_bytes());
    ok.extend_from_slice(&[7u8; 8]);
    assert_eq!(Decoder::new(&ok).bytes().unwrap(), &[7u8; 8]);
    ok[0] = 7; // len-1: a valid shorter value; the trailing byte is from_slice's concern
    assert_eq!(Decoder::new(&ok).bytes().unwrap(), &[7u8; 7]);
    ok[0] = 9; // len+1: more than available
    assert!(Decoder::new(&ok).bytes().is_err());
}

/// varint: 10-byte cap, overflow rejection, and the max value.
#[test]
fn varint_overflow_and_too_long() {
    assert!(Decoder::new(&[0xff; 10]).varint().is_err());
    assert!(Decoder::new(&[0xff; 11]).varint().is_err());
    let mut b = vec![0xff; 9];
    b.push(0x83); // i == 9 with bits > 1: overflow
    assert!(Decoder::new(&b).varint().is_err());
    let mut b = vec![0xff; 9];
    b.push(0x01);
    assert_eq!(Decoder::new(&b).varint().unwrap(), u64::MAX);
}

/// The fixed-offset reads are bounds-checked at every entry point that uses them.
#[test]
fn decoder_core_reads_are_bounded() {
    let b = vec![1, 2, 3];
    let mut d = Decoder::new(&b);
    assert_eq!(d.array::<2>().unwrap(), [1, 2]);
    assert!(d.array::<2>().is_err());
    let mut d = Decoder::new(&b);
    d.skip(1).unwrap();
    assert!(d.take(3).is_err());
    assert!(Decoder::new(&[]).u8().is_err());
    assert!(Decoder::new(&[]).envelope_raw().is_err());
}

// SortedKv (map<string,bufferlist> view): parse is the untrusted entry point.
proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn sorted_kv_any_byte(b in bytes()) {
        allocs::measure(b.len(), "sorted_kv any_byte", || {
            let _ = denc::kv::SortedKv::parse(&b);
        });
    }

    #[test]
    fn sorted_kv_roundtrip(pairs in kv_pairs()) {
        let mut enc = Vec::new();
        denc::kv::SortedKv::encode_into(&mut enc, pairs.len(), pairs.iter().map(|(k, v)| (k.as_bytes(), v.as_slice())));
        let denc::kv::KvShape::Sorted(kv) = denc::kv::SortedKv::parse(&enc).unwrap() else {
            panic!("strictly ascending keys must parse as Sorted");
        };
        assert_eq!(kv.len(), pairs.len());
        let got: Vec<(&[u8], &[u8])> = kv.iter().collect();
        for (g, p) in got.iter().zip(&pairs) {
            assert_eq!(*g, (p.0.as_bytes(), p.1.as_slice()));
        }
    }

    #[test]
    fn sorted_kv_truncated(pairs in kv_pairs()) {
        let mut enc = Vec::new();
        denc::kv::SortedKv::encode_into(&mut enc, pairs.len(), pairs.iter().map(|(k, v)| (k.as_bytes(), v.as_slice())));
        for c in 0..enc.len() {
            if let Ok(denc::kv::KvShape::Sorted(kv)) = denc::kv::SortedKv::parse(&enc[..c]) {
                let mut re = Vec::new();
                denc::kv::SortedKv::encode_into(&mut re, kv.len(), kv.iter());
                assert_eq!(re, &enc[..c], "cut {c}: kv prefix re-encodes differently");
            }
        }
    }

    #[test]
    fn sorted_kv_mutated(pairs in kv_pairs(), m in mutation()) {
        let mut enc = Vec::new();
        denc::kv::SortedKv::encode_into(&mut enc, pairs.len(), pairs.iter().map(|(k, v)| (k.as_bytes(), v.as_slice())));
        let buf = apply(&enc, &m);
        let len = matches!(m, Mutation::Len(..));
        if len {
            allocs::measure(buf.len(), "sorted_kv mutated", || {
                let _ = denc::kv::SortedKv::parse(&buf);
            });
        }
    }
}
