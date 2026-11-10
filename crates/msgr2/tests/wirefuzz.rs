// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Wire-fuzz robustness tests for every msgr2 decoder (AGENTS.md wire-fuzz goal, target 2).
//!
//! Property, for ANY input bytes: a decoder returns Ok or Err — it never panics, never
//! overflows/aborts, never allocates more than a bound proportional to the input (no
//! length-field-driven huge `Vec::with_capacity`; enforced by the counting global allocator on
//! the any-byte and length-mutation cases), never loops forever (the frame drain is bounded and
//! asserts no phantom frame). The msgr2 decoders that
//! parse bytes from outside the process are:
//!  * the banner (`Banner::parse`);
//!  * the frame preamble (CRC, segment count, segment table, limits) reached through the
//!    [`Decoder`] feed/poll path, in both revisions and in crc and secure mode;
//!  * the frame segment assembly + epilogue (segment crcs, `late_status`);
//!  * the secure (AES-128-GCM) framing (testable with a throwaway test secret, no real keys);
//!  * every control-frame payload (`payload::*::from_bytes`);
//!  * the MESSAGE header2 (`MsgHeader2::from_bytes`).
//!
//! Plus, where an encoder exists:
//!  * roundtrip: `decode(encode(x)) == x` for generated valid `x` (frames compared segment-wise);
//!  * truncated: a valid frame cut at every point delivers no frame and does not panic — the
//!    preamble declares the exact total, so a proper prefix can never be a complete frame;
//!  * mutated: a valid encoding with one byte flipped / inserted / deleted, or a length field set
//!    to an extreme (0, u32::MAX, i32::MIN, len-1, len+1), decodes to Ok or Err (never a panic,
//!    never a huge allocation).
//!
//! Random bytes alone rarely get past the first preamble CRC, so the mutation strategies start
//! from valid encodings (the crate's own [`Encoder`]) and disturb them; the extreme-length cases
//! are built deterministically with a recomputed preamble CRC so the limit check (not the CRC) is
//! what must reject them.
//!
//! Default case count is small (this crate's wirefuzz tests finish in < 20 s in debug);
//! `WIREFUZZ_CASES` raises it for long runs (lab/wirefuzz-long.sh).

use msgr2::payload::{
    Ack, AuthBadMethod, AuthDone, AuthReplyMore, AuthRequest, AuthRequestMore, AuthSignature,
    ClientIdent, CompressionDone, CompressionRequest, Hello, IdentMissingFeatures, Keepalive2,
    Keepalive2Ack, Payload, RdmaUpgrade, ServerIdent, SessionReconnect, SessionReconnectOk,
    SessionReset, SessionRetry, SessionRetryGlobal, Wait,
};
use msgr2::{Banner, ConnSecret, Decoder, Encoder, Limits, MsgHeader2, Revision, Role, Seg, Tag};
use proptest::prelude::*;

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

/// Poll every complete frame out of the decoder via `poll_owned`. Bounded: a complete frame is
/// at least `PREAMBLE_LEN` bytes, so `wire_len / PREAMBLE_LEN + 2` is the most a buffer of
/// `wire_len` bytes can yield; the final poll must deliver nothing (no phantom frame from an
/// exhausted buffer).
fn drain(d: &mut Decoder, wire_len: usize) {
    for _ in 0..=wire_len / msgr2::PREAMBLE_LEN + 2 {
        match d.poll_owned() {
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    assert!(
        matches!(d.poll_owned(), Ok(None) | Err(_)),
        "phantom frame from an exhausted buffer"
    );
}

/// The same, over the borrowed `poll` path (different guards: `Busy` on dispatch/secure_lent,
/// `direct()` for crc/V21): every yielded frame is dropped before the next poll.
fn drain_poll(d: &mut Decoder, wire_len: usize) {
    for _ in 0..=wire_len / msgr2::PREAMBLE_LEN + 2 {
        match d.poll() {
            Ok(Some(f)) => {
                let _ = f.num_segments;
            }
            _ => break,
        }
    }
    assert!(
        matches!(d.poll(), Ok(None) | Err(_)),
        "phantom frame from an exhausted buffer (poll)"
    );
}

// ---------------------------------------------------------------------------
// banner
// ---------------------------------------------------------------------------

fn banner() -> impl Strategy<Value = Banner> {
    (any::<u64>(), any::<u64>()).prop_map(|(supported, required)| Banner {
        supported,
        required,
    })
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn banner_any_byte(b in bytes()) {
        allocs::measure(b.len(), "banner any_byte", || {
            let _ = Banner::parse(&b);
        });
    }

    #[test]
    fn banner_roundtrip(b in banner()) {
        let mut v = Vec::new();
        b.encode(&mut v);
        let (dec, n) = Banner::parse(&v).unwrap().unwrap();
        assert_eq!(dec, b);
        assert_eq!(n, v.len());
    }

    #[test]
    fn banner_truncated(b in banner()) {
        let mut v = Vec::new();
        b.encode(&mut v);
        for c in 0..v.len() {
            assert_eq!(Banner::parse(&v[..c]), Ok(None), "cut {c}");
        }
    }

    #[test]
    fn banner_mutated(b in banner(), m in mutation()) {
        let mut v = Vec::new();
        b.encode(&mut v);
        let buf = apply(&v, &m);
        let len = matches!(m, Mutation::Len(..));
        if len {
            allocs::measure(buf.len(), "banner mutated", || {
                let _ = Banner::parse(&buf);
            });
        }
    }
}

// ---------------------------------------------------------------------------
// control-frame payloads (spec 7)
// ---------------------------------------------------------------------------

use denc::types::entity::{AF_INET, AF_INET6};
use denc::types::{EntityAddr, EntityAddrVec};

fn entity_addr() -> impl Strategy<Value = EntityAddr> {
    (
        any::<u32>(),
        any::<u32>(),
        prop_oneof![Just(0u16), Just(AF_INET), Just(AF_INET6)],
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

fn entity_addr_vec() -> impl Strategy<Value = EntityAddrVec> {
    prop::collection::vec(entity_addr(), 0..4).prop_map(EntityAddrVec)
}

fn vec_u32() -> impl Strategy<Value = Vec<u32>> {
    prop::collection::vec(any::<u32>(), 0..8)
}

fn opaque() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..64)
}

macro_rules! wirefuzz_payload {
    ($name:ident, $ty:ty, $strategy:expr) => {
        mod $name {
            use super::*;

            proptest! {
                #![proptest_config(cfg())]

                #[test]
                fn any_byte(b in bytes()) {
                    allocs::measure(b.len(), concat!(stringify!($name), " any_byte"), || {
                        let _ = <$ty>::from_bytes(&b);
                    });
                }

                #[test]
                fn roundtrip(v in $strategy) {
                    let enc = v.to_bytes().unwrap();
                    let dec = <$ty>::from_bytes(&enc).unwrap();
                    assert_eq!(dec, v);
                }

                #[test]
                fn truncated(v in $strategy) {
                    let enc = v.to_bytes().unwrap();
                    for c in 0..enc.len() {
                        if let Ok(dec) = <$ty>::from_bytes(&enc[..c]) {
                            assert_eq!(
                                dec.to_bytes().unwrap(),
                                &enc[..c],
                                "cut {c}: prefix re-encodes differently (consumed past the end?)"
                            );
                        }
                    }
                }

                #[test]
                fn mutated(v in $strategy, m in mutation()) {
                    let enc = v.to_bytes().unwrap();
                    let buf = apply(&enc, &m);
                    let len = matches!(m, Mutation::Len(..));
                    if len {
                        allocs::measure(buf.len(), concat!(stringify!($name), " mutated"), || {
                            let _ = <$ty>::from_bytes(&buf);
                        });
                    }
                }
            }
        }
    };
}

wirefuzz_payload!(
    hello,
    Hello,
    (any::<u8>(), entity_addr()).prop_map(|(entity_type, peer_addr)| Hello {
        entity_type,
        peer_addr
    })
);
wirefuzz_payload!(
    auth_request,
    AuthRequest,
    (any::<u32>(), vec_u32(), opaque()).prop_map(|(method, preferred_modes, auth_payload)| {
        AuthRequest {
            method,
            preferred_modes,
            auth_payload,
        }
    })
);
wirefuzz_payload!(
    auth_bad_method,
    AuthBadMethod,
    (any::<u32>(), any::<i32>(), vec_u32(), vec_u32()).prop_map(
        |(method, result, allowed_methods, allowed_modes)| AuthBadMethod {
            method,
            result,
            allowed_methods,
            allowed_modes
        }
    )
);
wirefuzz_payload!(
    auth_reply_more,
    AuthReplyMore,
    opaque().prop_map(|auth_payload| AuthReplyMore { auth_payload })
);
wirefuzz_payload!(
    auth_request_more,
    AuthRequestMore,
    opaque().prop_map(|auth_payload| AuthRequestMore { auth_payload })
);
wirefuzz_payload!(
    auth_done,
    AuthDone,
    (any::<u64>(), any::<u32>(), opaque()).prop_map(
        |(global_id, connection_mode, auth_payload)| {
            AuthDone {
                global_id,
                connection_mode,
                auth_payload,
            }
        }
    )
);
wirefuzz_payload!(
    auth_signature,
    AuthSignature,
    prop::array::uniform::<_, 32>(any::<u8>()).prop_map(|signature| AuthSignature { signature })
);
wirefuzz_payload!(
    client_ident,
    ClientIdent,
    (
        entity_addr_vec(),
        entity_addr(),
        any::<i64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
    )
        .prop_map(
            |(
                addrs,
                target_addr,
                gid,
                global_seq,
                supported_features,
                required_features,
                flags,
                cookie,
            )| ClientIdent {
                addrs,
                target_addr,
                gid,
                global_seq,
                supported_features,
                required_features,
                flags,
                cookie,
            },
        )
);
wirefuzz_payload!(
    server_ident,
    ServerIdent,
    (
        entity_addr_vec(),
        any::<i64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
    )
        .prop_map(
            |(addrs, gid, global_seq, supported_features, required_features, flags, cookie)| {
                ServerIdent {
                    addrs,
                    gid,
                    global_seq,
                    supported_features,
                    required_features,
                    flags,
                    cookie,
                }
            },
        )
);
wirefuzz_payload!(
    ident_missing_features,
    IdentMissingFeatures,
    any::<u64>().prop_map(|features| IdentMissingFeatures { features })
);
wirefuzz_payload!(
    session_reconnect,
    SessionReconnect,
    (
        entity_addr_vec(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
    )
        .prop_map(
            |(addrs, client_cookie, server_cookie, global_seq, connect_seq, msg_seq)| {
                SessionReconnect {
                    addrs,
                    client_cookie,
                    server_cookie,
                    global_seq,
                    connect_seq,
                    msg_seq,
                }
            },
        )
);
wirefuzz_payload!(
    session_reset,
    SessionReset,
    any::<bool>().prop_map(|full| SessionReset { full })
);
wirefuzz_payload!(
    session_retry,
    SessionRetry,
    any::<u64>().prop_map(|connect_seq| SessionRetry { connect_seq })
);
wirefuzz_payload!(
    session_retry_global,
    SessionRetryGlobal,
    any::<u64>().prop_map(|global_seq| SessionRetryGlobal { global_seq })
);
wirefuzz_payload!(
    session_reconnect_ok,
    SessionReconnectOk,
    any::<u64>().prop_map(|msg_seq| SessionReconnectOk { msg_seq })
);
wirefuzz_payload!(wait, Wait, Just(Wait {}));
wirefuzz_payload!(
    keepalive2,
    Keepalive2,
    (any::<u32>(), any::<u32>()).prop_map(|(sec, nsec)| Keepalive2 { sec, nsec })
);
wirefuzz_payload!(
    keepalive2_ack,
    Keepalive2Ack,
    (any::<u32>(), any::<u32>()).prop_map(|(sec, nsec)| Keepalive2Ack { sec, nsec })
);
wirefuzz_payload!(ack, Ack, any::<u64>().prop_map(|seq| Ack { seq }));
wirefuzz_payload!(
    compression_request,
    CompressionRequest,
    (any::<bool>(), vec_u32()).prop_map(|(is_compress, preferred_methods)| CompressionRequest {
        is_compress,
        preferred_methods
    })
);
wirefuzz_payload!(
    compression_done,
    CompressionDone,
    (any::<bool>(), any::<u32>()).prop_map(|(is_compress, method)| CompressionDone {
        is_compress,
        method
    })
);
wirefuzz_payload!(
    rdma_upgrade,
    RdmaUpgrade,
    (any::<u8>(), opaque()).prop_map(|(op, endpoint)| RdmaUpgrade { op, endpoint })
);

// ---------------------------------------------------------------------------
// message header2 (spec 8.1)
// ---------------------------------------------------------------------------

fn header2() -> impl Strategy<Value = MsgHeader2> {
    (
        any::<u64>(),
        any::<u64>(),
        any::<u16>(),
        any::<u16>(),
        any::<u16>(),
        any::<u32>(),
        any::<u16>(),
        any::<u64>(),
        any::<u8>(),
        any::<u16>(),
        any::<u16>(),
    )
        .prop_map(
            |(
                seq,
                tid,
                msg_type,
                priority,
                version,
                dpp,
                data_off,
                ack_seq,
                flags,
                compat,
                reserved,
            )| MsgHeader2 {
                seq,
                tid,
                msg_type,
                priority,
                version,
                data_pre_padding_len: dpp,
                data_off,
                ack_seq,
                flags,
                compat_version: compat,
                reserved,
            },
        )
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn header2_any_byte(b in bytes()) {
        allocs::measure(b.len(), "header2 any_byte", || {
            let _ = MsgHeader2::from_bytes(&b);
        });
    }

    #[test]
    fn header2_roundtrip(h in header2()) {
        let enc = h.to_bytes();
        assert_eq!(MsgHeader2::from_bytes(&enc).unwrap(), h);
    }

    #[test]
    fn header2_truncated(h in header2()) {
        let enc = h.to_bytes();
        for c in 0..enc.len() {
            if let Ok(dec) = MsgHeader2::from_bytes(&enc[..c]) {
                assert_eq!(dec.to_bytes(), enc, "cut {c}: consumed a different range");
            }
        }
    }

    #[test]
    fn header2_mutated(h in header2(), m in mutation()) {
        let enc = h.to_bytes();
        let buf = apply(&enc, &m);
        let len = matches!(m, Mutation::Len(..));
        if len {
            allocs::measure(buf.len(), "header2 mutated", || {
                let _ = MsgHeader2::from_bytes(&buf);
            });
        }
    }
}

// ---------------------------------------------------------------------------
// frame assembler: preamble + segment table + epilogue, crc and secure, both
// revisions
// ---------------------------------------------------------------------------

/// Framing under test: crc (plaintext) or secure (AES-128-GCM, throwaway test secret).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Crc,
    Secure,
}

/// A throwaway connection secret: secure framing is fully testable without real keys.
fn secret() -> ConnSecret {
    ConnSecret::new(&(0..64u8).collect::<Vec<_>>()).unwrap()
}

fn mk_dec(rev: Revision, mode: Mode) -> Decoder {
    let mut d = Decoder::new(rev);
    if mode == Mode::Secure {
        d.set_secure(&secret(), Role::Server).unwrap();
    }
    d
}

fn mk_enc(rev: Revision, mode: Mode) -> Encoder {
    let mut e = Encoder::new(rev);
    if mode == Mode::Secure {
        e.set_secure(&secret(), Role::Client).unwrap();
    }
    e
}

fn rev_mode() -> impl Strategy<Value = (Revision, Mode)> {
    (
        prop_oneof![Just(Revision::V20), Just(Revision::V21)],
        prop_oneof![Just(Mode::Crc), Just(Mode::Secure)],
    )
}

/// A frame: a valid tag and 1..=4 non-empty segments of 1..=48 bytes.
fn frame_spec() -> impl Strategy<Value = (u8, Vec<Vec<u8>>)> {
    (
        prop_oneof![
            Just(1u8),
            Just(2),
            Just(3),
            Just(4),
            Just(5),
            Just(6),
            Just(8),
            Just(9),
            Just(10),
            Just(11),
            Just(12),
            Just(13),
            Just(14),
            Just(15),
            Just(16),
            Just(17),
            Just(18),
            Just(19),
            Just(20)
        ],
        prop::collection::vec(prop::collection::vec(any::<u8>(), 1..=48), 1..=4),
    )
}

fn encode_frame(e: &mut Encoder, tag: u8, segs: &[Vec<u8>]) -> Vec<u8> {
    let s: Vec<Seg> = segs.iter().map(|d| Seg { data: d, align: 8 }).collect();
    let mut out = Vec::new();
    e.encode(tag, &s, &mut out).unwrap();
    out
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn frame_any_byte((rev, mode) in rev_mode(), b in bytes()) {
        allocs::measure(b.len(), "frame any_byte", || {
            let mut d = mk_dec(rev, mode);
            d.feed(&b);
            drain(&mut d, b.len());
        });
    }

    // W9: random bytes pass the 4-byte preamble crc with p = 2^-32, so the plain any-byte case
    // only ever hits `BadPreambleCrc`. This variant recomputes the preamble crc over the random
    // bytes, so CRC-valid hostile preambles reach the segment table, size limits, assembly and
    // epilogue. (Crc mode only: a secure preamble is authenticated by GCM, not a plain crc32c.)
    #[test]
    fn frame_any_byte_crc_fixed((rev, mode) in rev_mode(), b in bytes()) {
        if mode != Mode::Secure && b.len() >= msgr2::PREAMBLE_LEN {
            let mut w = b;
            fix_preamble_crc(&mut w);
            allocs::measure(w.len(), "frame any_byte crc_fixed", || {
                let mut d = mk_dec(rev, Mode::Crc);
                d.feed(&w);
                drain(&mut d, w.len());
            });
        }
    }

    #[test]
    fn frame_roundtrip((rev, mode) in rev_mode(), (tag, segs) in frame_spec()) {
        let wire = encode_frame(&mut mk_enc(rev, mode), tag, &segs);
        let mut d = mk_dec(rev, mode);
        d.feed(&wire);
        let f = d.poll_owned().unwrap().unwrap();
        assert_eq!(f.tag, tag);
        assert_eq!(f.segs.len(), segs.len());
        for (i, s) in segs.iter().enumerate() {
            assert_eq!(f.segs[i].as_ref(), s.as_slice());
        }
        assert!(d.poll_owned().unwrap().is_none());
    }

    // W10: the same roundtrip over the borrowed `poll` path (the `poll_owned` twin above covers
    // the owned delivery; `poll` has its own guards and the `direct()` shortcut).
    #[test]
    fn frame_roundtrip_poll((rev, mode) in rev_mode(), (tag, segs) in frame_spec()) {
        let wire = encode_frame(&mut mk_enc(rev, mode), tag, &segs);
        let mut d = mk_dec(rev, mode);
        d.feed(&wire);
        let f = d.poll().unwrap().expect("poll must deliver the frame");
        assert_eq!(f.tag, tag);
        assert_eq!(f.num_segments, segs.len());
        for (i, s) in segs.iter().enumerate() {
            assert_eq!(f.segment(i), s.as_slice(), "segment {i}");
        }
        assert!(d.poll().unwrap().is_none(), "no second frame");
    }

    #[test]
    fn frame_truncated((rev, mode) in rev_mode(), (tag, segs) in frame_spec()) {
        let wire = encode_frame(&mut mk_enc(rev, mode), tag, &segs);
        for c in 0..wire.len() {
            let mut d = mk_dec(rev, mode);
            d.feed(&wire[..c]);
            // the preamble declares the exact total; a proper prefix is never a complete frame
            assert!(
                d.poll_owned().unwrap().is_none(),
                "cut {c}: delivered a frame from a truncated prefix"
            );
        }
    }

    // W10: the truncated twin over the borrowed path.
    #[test]
    fn frame_truncated_poll((rev, mode) in rev_mode(), (tag, segs) in frame_spec()) {
        let wire = encode_frame(&mut mk_enc(rev, mode), tag, &segs);
        for c in 0..wire.len() {
            let mut d = mk_dec(rev, mode);
            d.feed(&wire[..c]);
            assert!(
                d.poll().unwrap().is_none(),
                "cut {c}: poll delivered a frame from a truncated prefix"
            );
        }
    }

    // W10: an any-byte case driving the borrowed path (W8's bounded `drain_poll` also states the
    // no-phantom-frame property for `poll`).
    #[test]
    fn frame_any_byte_poll((rev, mode) in rev_mode(), b in bytes()) {
        let mut d = mk_dec(rev, mode);
        d.feed(&b);
        drain_poll(&mut d, b.len());
    }

    #[test]
    fn frame_mutated((rev, mode) in rev_mode(), (tag, segs) in frame_spec(), m in mutation()) {
        let wire = encode_frame(&mut mk_enc(rev, mode), tag, &segs);
        let buf = apply(&wire, &m);
        let len = matches!(m, Mutation::Len(..));
        if len {
            allocs::measure(buf.len(), "frame mutated", || {
                let mut d = mk_dec(rev, mode);
                d.feed(&buf);
                drain(&mut d, buf.len());
            });
        } else {
            let mut d = mk_dec(rev, mode);
            d.feed(&buf);
            drain(&mut d, buf.len());
        }
    }
}

// ---------------------------------------------------------------------------
// deterministic: the limit checks (not the CRC) must reject extreme lengths
// ---------------------------------------------------------------------------

/// Recompute the preamble CRC (bytes 0..28) into bytes 28..32 so a surgically altered segment
/// length passes the CRC and reaches the size-limit check.
fn fix_preamble_crc(w: &mut Vec<u8>) {
    // the preamble is 28 content bytes + a 4-byte CRC; size it up if the caller built it bare
    w.resize(msgr2::PREAMBLE_LEN, 0);
    let c = crc::crc32c(0, &w[..28]).to_le_bytes();
    w[28..32].copy_from_slice(&c);
}

#[test]
fn extreme_segment_lengths_rejected_before_allocation() {
    for rev in [Revision::V20, Revision::V21] {
        let mut wire = Vec::new();
        Encoder::new(rev)
            .encode_control(Tag::Ack as u8, &7u64.to_le_bytes(), &mut wire)
            .unwrap();
        // len[0] lives at preamble bytes 2..6.
        for extreme in [u32::MAX, i32::MIN as u32] {
            let mut w = wire.clone();
            w[2..6].copy_from_slice(&extreme.to_le_bytes());
            fix_preamble_crc(&mut w);
            let mut d = Decoder::new(rev);
            d.feed(&w);
            assert!(
                d.poll_owned().is_err(),
                "rev {rev:?}: extreme len[0]={extreme} must be rejected, not allocated"
            );
        }
        // len[0] = 0 is a legitimate (empty) single-segment frame: no panic, no allocation.
        let mut w = wire.clone();
        w[2..6].copy_from_slice(&0u32.to_le_bytes());
        fix_preamble_crc(&mut w);
        let mut d = Decoder::new(rev);
        d.feed(&w);
        let _ = d.poll_owned();
    }
}

#[test]
fn bad_segment_counts_rejected() {
    for rev in [Revision::V20, Revision::V21] {
        for n in [0u8, 5] {
            let mut w = Vec::new();
            w.push(1);
            w.push(n);
            for _ in 0..4 {
                w.extend_from_slice(&0u32.to_le_bytes());
                w.extend_from_slice(&0u16.to_le_bytes());
            }
            w.push(0);
            w.push(0);
            fix_preamble_crc(&mut w);
            let mut d = Decoder::new(rev);
            d.feed(&w);
            assert!(
                d.poll_owned().is_err(),
                "rev {rev:?}: segment count {n} must be rejected"
            );
        }
    }
}

#[test]
fn limits_reject_oversized_preambles() {
    // A CRC-valid preamble whose declared total exceeds the default frame ceiling must be an
    // Err, with no body allocation.
    for rev in [Revision::V20, Revision::V21] {
        let mut w = Vec::new();
        w.push(Tag::Message as u8);
        w.push(4);
        // four segments, each just under the per-segment ceiling so the sum exceeds max_frame
        let big = (1u32 << 28) - 1;
        for _ in 0..4 {
            w.extend_from_slice(&big.to_le_bytes());
            w.extend_from_slice(&8u16.to_le_bytes());
        }
        w.push(0);
        w.push(0);
        fix_preamble_crc(&mut w);
        let mut d = Decoder::new(rev);
        d.set_limits(Limits::default());
        d.feed(&w);
        assert!(
            d.poll_owned().is_err(),
            "rev {rev:?}: oversize frame must be rejected"
        );
    }
}

#[test]
fn tag_mapping_is_total() {
    for v in 0..=255u8 {
        if let Some(t) = Tag::from_u8(v) {
            assert_eq!(t as u8, v);
        }
    }
    assert!(Tag::from_u8(0).is_none() && Tag::from_u8(23).is_none());
    assert_eq!(Tag::from_u8(0xF1), Some(Tag::RdmaUpgrade));
}
