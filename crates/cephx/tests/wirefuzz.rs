// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Wire-fuzz robustness tests for every cephx decoder (AGENTS.md wire-fuzz goal, target 5).
//!
//! Property, for ANY input bytes: a decoder returns Ok or Err — it never panics, never
//! overflows/aborts, never allocates more than a bound proportional to the input (no
//! length-field-driven huge `Vec::with_capacity`; enforced by the counting global allocator
//! on the any-byte and length-mutation cases), never loops forever. The cephx decoders
//! that parse bytes from outside the process (mon ticket replies / rotating secrets, peer
//! authorizers + the challenge/reply crypto envelopes, NONE-mode payloads, keyring files) are:
//!  * every versioned wire struct in `types` (RequestHeader, ResponseHeader, ServerChallenge,
//!    ChallengeBlob, TicketBlob, Authenticate, ServiceTicketRequest, ServiceTicket, CapsInfo,
//!    AuthTicket, ServiceTicketInfo, Authorize, AuthorizeChallenge, AuthorizeReply,
//!    ExpiringCryptoKey, RotatingSecrets);
//!  * `CryptoKey` (type 0/1/2, secret bounded by a u16 length) and the entity-name encodings;
//!  * the RAW/WRAPPED crypto envelope (`open_raw`, `open_wrapped`, `open_raw_t`, `open_wrapped_t`,
//!    `open_string_wrapped`);
//!  * `decode_ticket_reply` (mon ticket reply: a length-driven entry loop over sealed blobs);
//!  * the authorizer path (`parse_authorizer` via `AuthorizerVerifier::verify`, `Authorizer::
//!    on_reply_more` / `on_done`);
//!  * `MonAuthClient::on_reply_more` / `on_done` / `on_response`;
//!  * the NONE-mode payloads (`parse_none_payload`, `verify_none`);
//!  * `ConnectionSecret::from_bytes`;
//!  * `Keyring::parse` (keyring file, disk).
//!
//! Plus, where an encoder exists:
//!  * roundtrip: `decode(encode(x)) == x` for generated valid `x`;
//!  * truncated: a valid encoding cut at every point is Err — or, if the prefix happens to be
//!    a complete encoding of its own, Ok of a value whose canonical encoding is exactly the
//!    consumed prefix (never a value that consumed past the end);
//!  * mutated: a valid encoding with one byte flipped / inserted / deleted, or a length field
//!    set to an extreme (0, u32::MAX, i32::MIN, len-1, len+1), decodes to Ok or Err.
//!
//! Random bytes alone rarely get past the first length check, so the mutation strategies start
//! from valid encodings (the crate's own encoders) and disturb them.
//!
//! Default case count is small (this crate's wirefuzz tests finish in < 20 s in debug);
//! `WIREFUZZ_CASES` raises it for long runs (lab/wirefuzz-long.sh).

use cephx::UTime;
use cephx::authorizer::Authorizer;
use cephx::envelope::{
    open_raw, open_raw_t, open_string_wrapped, open_wrapped, open_wrapped_t, seal_raw,
    seal_string_wrapped, seal_wrapped_t,
};
use cephx::key::{CryptoKey, KeyType, Usage};
use cephx::keyring::Keyring;
use cephx::modes::CON_MODE_CRC;
use cephx::monclient::{MonAuthClient, MonAuthConfig, MonReply};
use cephx::none::{
    AUTH_MODE_AUTHORIZER, AUTH_MODE_MON, ByteEntityName, ENTITY_AUTH, ENTITY_MGR, ENTITY_MON,
    ENTITY_OSD, EntityName, mon_auth_payload, none_authorizer, parse_none_payload, verify_none,
};
use cephx::secret::ConnectionSecret;
use cephx::ticket::{TicketEntry, decode_ticket_reply, encode_ticket_reply, seal_ticket_info};
use cephx::types::{
    AUTH_UID_DEFAULT, AuthTicket, Authenticate, Authorize, AuthorizeChallenge, AuthorizeReply,
    CEPHX_GET_AUTH_SESSION_KEY, CEPHX_GET_PRINCIPAL_SESSION_KEY, CapsInfo, ChallengeBlob,
    ExpiringCryptoKey, RequestHeader, ResponseHeader, RotatingSecrets, ServerChallenge,
    ServiceTicket, ServiceTicketInfo, ServiceTicketRequest, TicketBlob,
};
use cephx::verifier::{AuthorizerVerifier, Verdict};
use denc::{Decoder, Encode, from_slice};
use proptest::prelude::*;
use std::time::Duration;
use zeroize::Zeroizing;

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
const STR_UNI_8: &str = r"[\p{L}\p{N}]{0,8}";

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

// ---- value strategies -------------------------------------------------------

fn utime() -> impl Strategy<Value = UTime> {
    (any::<u32>(), any::<u32>()).prop_map(|(sec, nsec)| UTime::new(sec, nsec))
}

/// A usable AES-128 key: exactly 16 secret bytes.
fn aes_key() -> impl Strategy<Value = CryptoKey> {
    (
        any::<u32>(),
        any::<u32>(),
        prop::collection::vec(any::<u8>(), 16),
    )
        .prop_map(|(sec, nsec, secret)| {
            CryptoKey::new(KeyType::Aes, UTime::new(sec, nsec), &secret)
        })
}

/// W16: AES-256 (KRB5) keys take the 32-byte `u16`-length secret path; roundtrip both sizes.
fn aes256krb5_key() -> impl Strategy<Value = CryptoKey> {
    (
        any::<u32>(),
        any::<u32>(),
        prop::collection::vec(any::<u8>(), 32),
    )
        .prop_map(|(sec, nsec, secret)| {
            CryptoKey::new(KeyType::Aes256Krb5, UTime::new(sec, nsec), &secret)
        })
}

/// Every usable key type at its real secret length (16 AES, 32 AES256KRB5).
fn crypto_key() -> impl Strategy<Value = CryptoKey> {
    prop_oneof![aes_key(), aes256krb5_key()]
}

fn entity_name() -> impl Strategy<Value = EntityName> {
    (any::<u32>(), STR_UNI_8).prop_map(|(ty, id)| EntityName { ty, id })
}

fn byte_entity_name() -> impl Strategy<Value = ByteEntityName> {
    (any::<u32>(), u8s(16)).prop_map(|(ty, id)| ByteEntityName { ty, id })
}

fn ticket_blob() -> impl Strategy<Value = TicketBlob> {
    (any::<u64>(), u8s(64)).prop_map(|(secret_id, blob)| TicketBlob { secret_id, blob })
}

fn service_ticket() -> impl Strategy<Value = ServiceTicket> {
    (aes_key(), utime()).prop_map(|(session_key, validity)| ServiceTicket {
        session_key,
        validity,
    })
}

fn caps_info() -> impl Strategy<Value = CapsInfo> {
    prop_oneof![
        Just(CapsInfo::default()),
        STR_UNI_8.prop_map(|t| CapsInfo::from_text(&t)),
    ]
}

fn auth_ticket() -> impl Strategy<Value = AuthTicket> {
    (
        byte_entity_name(),
        any::<u64>(),
        utime(),
        utime(),
        caps_info(),
        any::<u32>(),
    )
        .prop_map(
            |(name, global_id, created, expires, caps, flags)| AuthTicket {
                name,
                global_id,
                auid: AUTH_UID_DEFAULT,
                created,
                expires,
                caps,
                flags,
            },
        )
}

fn service_ticket_info() -> impl Strategy<Value = ServiceTicketInfo> {
    (auth_ticket(), aes_key()).prop_map(|(ticket, session_key)| ServiceTicketInfo {
        ticket,
        session_key,
    })
}

fn authorize() -> impl Strategy<Value = Authorize> {
    (any::<u64>(), any::<bool>(), any::<u64>()).prop_map(
        |(nonce, have_challenge, server_challenge_plus_one)| Authorize {
            nonce,
            have_challenge,
            server_challenge_plus_one,
        },
    )
}

fn authorize_reply() -> impl Strategy<Value = AuthorizeReply> {
    (any::<u64>(), u8s(64)).prop_map(|(nonce_plus_one, secret)| AuthorizeReply {
        nonce_plus_one,
        connection_secret: Zeroizing::new(secret),
    })
}

fn expiring_crypto_key() -> impl Strategy<Value = ExpiringCryptoKey> {
    (aes_key(), utime()).prop_map(|(key, expiration)| ExpiringCryptoKey { key, expiration })
}

fn rotating_secrets() -> impl Strategy<Value = RotatingSecrets> {
    (
        prop::collection::btree_map(any::<u64>(), expiring_crypto_key(), 0..4),
        any::<u64>(),
    )
        .prop_map(|(secrets, max_ver)| RotatingSecrets { secrets, max_ver })
}

fn ticket_entry() -> impl Strategy<Value = TicketEntry> {
    (any::<u32>(), aes_key(), utime(), ticket_blob()).prop_map(
        |(service_id, session_key, validity, blob)| TicketEntry {
            service_id,
            session_key,
            validity,
            blob,
        },
    )
}

fn ticket_entries() -> impl Strategy<Value = Vec<TicketEntry>> {
    prop::collection::vec(ticket_entry(), 0..4)
}

/// Fixed, usable keys for the context entry points (deterministic; no RNG in the loop).
fn principal_key() -> CryptoKey {
    CryptoKey::new(KeyType::Aes, UTime::new(100, 0), &[7u8; 16])
}

fn old_key() -> CryptoKey {
    CryptoKey::new(KeyType::Aes, UTime::new(100, 0), &[8u8; 16])
}

fn krb5_key() -> CryptoKey {
    CryptoKey::new(KeyType::Aes256Krb5, UTime::new(100, 0), &[9u8; 32])
}

// ---- denc-decodable wire structs: four wirefuzz tests each -------------------

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

wirefuzz_type!(
    request_header,
    RequestHeader,
    (any::<u16>()).prop_map(|request_type| RequestHeader { request_type }),
    |v| v
);
wirefuzz_type!(
    response_header,
    ResponseHeader,
    (any::<u16>(), any::<i32>()).prop_map(|(request_type, status)| ResponseHeader {
        request_type,
        status
    }),
    |v| v
);
wirefuzz_type!(
    server_challenge,
    ServerChallenge,
    any::<u64>().prop_map(|server_challenge| ServerChallenge { server_challenge }),
    |v| v
);
wirefuzz_type!(
    challenge_blob,
    ChallengeBlob,
    (any::<u64>(), any::<u64>()).prop_map(|(server_challenge, client_challenge)| ChallengeBlob {
        server_challenge,
        client_challenge
    }),
    |v| v
);
wirefuzz_type!(ticket_blob, TicketBlob, ticket_blob(), |v| v);
wirefuzz_type!(
    authenticate,
    Authenticate,
    (any::<u64>(), any::<u64>(), ticket_blob(), any::<u32>()).prop_map(
        |(client_challenge, key, old_ticket, other_keys)| Authenticate {
            client_challenge,
            key,
            old_ticket,
            other_keys
        }
    ),
    |v| v
);
wirefuzz_type!(
    service_ticket_request,
    ServiceTicketRequest,
    any::<u32>().prop_map(|keys| ServiceTicketRequest { keys }),
    |v| v
);
wirefuzz_type!(service_ticket, ServiceTicket, service_ticket(), |v| v);
wirefuzz_type!(caps_info, CapsInfo, caps_info(), |v| v);
wirefuzz_type!(auth_ticket, AuthTicket, auth_ticket(), |v| v);
wirefuzz_type!(
    service_ticket_info,
    ServiceTicketInfo,
    service_ticket_info(),
    |v| v
);
wirefuzz_type!(authorize, Authorize, authorize(), |v| v);
wirefuzz_type!(
    authorize_challenge,
    AuthorizeChallenge,
    any::<u64>().prop_map(|server_challenge| AuthorizeChallenge { server_challenge }),
    |v| v
);
wirefuzz_type!(authorize_reply, AuthorizeReply, authorize_reply(), |v| v);
wirefuzz_type!(
    expiring_crypto_key,
    ExpiringCryptoKey,
    expiring_crypto_key(),
    |v| v
);
wirefuzz_type!(rotating_secrets, RotatingSecrets, rotating_secrets(), |v| v);
wirefuzz_type!(crypto_key, CryptoKey, crypto_key(), |v| v);
wirefuzz_type!(entity_name, EntityName, entity_name(), |v| v);
wirefuzz_type!(byte_entity_name, ByteEntityName, byte_entity_name(), |v| v);

// W16: an unknown key type must be rejected, not decoded (the `u16`-length secret path with
// 32 bytes / `Aes256Krb5` is covered by the `crypto_key` roundtrip strategy above).
#[test]
fn crypto_key_unknown_type_is_err() {
    let k = CryptoKey::new(KeyType::Aes, UTime::new(1, 0), &[4u8; 16]);
    let mut enc = k.to_bytes().unwrap();
    enc[..2].copy_from_slice(&3u16.to_le_bytes());
    assert!(
        CryptoKey::from_bytes(&enc).is_err(),
        "key type 3 (unknown) must not decode"
    );
}

// ---- the RAW/WRAPPED crypto envelope -----------------------------------------

mod envelope {
    use super::*;

    proptest! {
        #![proptest_config(cfg())]

        // Every open_* entry point over arbitrary ciphertext/buffer: Ok or Err, never a panic.
        // Both ciphers (AES CBC and AES256KRB5 HMAC+CTS) are exercised.
        #[test]
        fn any_byte(b in bytes()) {
            allocs::measure(b.len(), "envelope any_byte", || {
                for k in [principal_key(), krb5_key()] {
                    let mut d = Decoder::new(&b);
                    let _ = open_raw(&k, Usage::TicketInfo, &b);
                    let _ = open_raw_t::<ServiceTicketInfo>(&k, Usage::TicketInfo, &b);
                    let _ = open_wrapped(&k, Usage::TicketInfo, &mut d);
                    let mut d = Decoder::new(&b);
                    let _ = open_wrapped_t::<ServiceTicketInfo>(&k, Usage::TicketInfo, &mut d);
                    let mut d = Decoder::new(&b);
                    let _ = open_string_wrapped(&k, Usage::AuthConnectionSecret, &mut d);
                }
            });
        }

        #[test]
        fn roundtrip_raw(body in u8s(256)) {
            let k = principal_key();
            let ct = seal_raw(&k, Usage::TicketInfo, &body).unwrap();
            let got = open_raw(&k, Usage::TicketInfo, &ct).unwrap();
            assert_eq!(&*got, body.as_slice());
        }

        #[test]
        fn roundtrip_wrapped_t(v in service_ticket_info()) {
            let k = principal_key();
            let enc = seal_wrapped_t(&k, Usage::TicketInfo, &v).unwrap();
            let dec = open_wrapped_t::<ServiceTicketInfo>(&k, Usage::TicketInfo, &mut Decoder::new(&enc)).unwrap();
            assert_eq!(dec, v);
        }

        #[test]
        fn roundtrip_string_wrapped(s in u8s(64)) {
            let k = principal_key();
            let enc = seal_string_wrapped(&k, Usage::AuthConnectionSecret, &s).unwrap();
            let dec = open_string_wrapped(&k, Usage::AuthConnectionSecret, &mut Decoder::new(&enc)).unwrap();
            assert_eq!(&*dec, s.as_slice());
        }

        #[test]
        fn truncated(s in service_ticket_info(), ) {
            let k = principal_key();
            let enc = seal_wrapped_t(&k, Usage::TicketInfo, &s).unwrap();
            for c in 0..enc.len() {
                let mut d = Decoder::new(&enc[..c]);
                if let Ok(dec) = open_wrapped_t::<ServiceTicketInfo>(&k, Usage::TicketInfo, &mut d) {
                    assert_eq!(dec, s, "cut {c}: consumed past the end?");
                }
            }
        }

        #[test]
        fn mutated(s in service_ticket_info(), m in mutation()) {
            let k = principal_key();
            let enc = seal_wrapped_t(&k, Usage::TicketInfo, &s).unwrap();
            let buf = apply(&enc, &m);
            let len = matches!(m, Mutation::Len(..));
            if len {
                allocs::measure(buf.len(), "envelope mutated", || {
                    let mut d = Decoder::new(&buf);
                    let _ = open_wrapped_t::<ServiceTicketInfo>(&k, Usage::TicketInfo, &mut d);
                });
            } else {
                let mut d = Decoder::new(&buf);
                let _ = open_wrapped_t::<ServiceTicketInfo>(&k, Usage::TicketInfo, &mut d);
            }
        }
    }
}

// ---- decode_ticket_reply (mon ticket reply) ----------------------------------

mod ticket_reply {
    use super::*;

    proptest! {
        #![proptest_config(cfg())]

        #[test]
        fn any_byte(b in bytes()) {
            allocs::measure(b.len(), "ticket_reply any_byte", || {
                for (p, o) in [
                    (principal_key(), old_key()),
                    (krb5_key(), krb5_key()),
                ] {
                    let _ = decode_ticket_reply(&mut Decoder::new(&b), &p, Some(&o));
                    let _ = decode_ticket_reply(&mut Decoder::new(&b), &p, None);
                }
            });
        }

        #[test]
        fn roundtrip_plain(entries in ticket_entries()) {
            let p = principal_key();
            let enc = encode_ticket_reply(&entries, &p, None).unwrap();
            let dec = decode_ticket_reply(&mut Decoder::new(&enc), &p, None).unwrap();
            assert_eq!(dec, entries);
        }

        #[test]
        fn roundtrip_wrapped(entries in ticket_entries()) {
            let p = principal_key();
            let o = old_key();
            let enc = encode_ticket_reply(&entries, &p, Some(&o)).unwrap();
            let dec = decode_ticket_reply(&mut Decoder::new(&enc), &p, Some(&o)).unwrap();
            assert_eq!(dec, entries);
        }

        #[test]
        fn truncated(entries in ticket_entries()) {
            let p = principal_key();
            let enc = encode_ticket_reply(&entries, &p, None).unwrap();
            for c in 0..enc.len() {
                if let Ok(dec) = decode_ticket_reply(&mut Decoder::new(&enc[..c]), &p, None) {
                    let re = encode_ticket_reply(&dec, &p, None).unwrap();
                    assert_eq!(re, &enc[..c], "cut {c}: re-encodes differently (consumed past the end?)");
                }
            }
        }

        #[test]
        fn mutated(entries in ticket_entries(), m in mutation()) {
            let p = principal_key();
            let o = old_key();
            let enc = encode_ticket_reply(&entries, &p, Some(&o)).unwrap();
            let buf = apply(&enc, &m);
            let len = matches!(m, Mutation::Len(..));
            if len {
                allocs::measure(buf.len(), "ticket_reply mutated", || {
                    let _ = decode_ticket_reply(&mut Decoder::new(&buf), &p, Some(&o));
                });
            } else {
                let _ = decode_ticket_reply(&mut Decoder::new(&buf), &p, Some(&o));
            }
        }
    }
}

// ---- authorizer path (parse via the verifier; client on_reply_more/on_done) ---

fn valid_authorizer() -> Authorizer {
    let rk = principal_key();
    let sk = old_key();
    let info = ServiceTicketInfo {
        ticket: AuthTicket {
            name: ByteEntityName {
                ty: ENTITY_OSD,
                id: vec![0],
            },
            global_id: 5000,
            auid: AUTH_UID_DEFAULT,
            created: UTime::new(100, 0),
            expires: UTime::new(200, 0),
            caps: CapsInfo::from_text("allow *"),
            flags: 0,
        },
        session_key: sk.clone(),
    };
    let blob = seal_ticket_info(&rk, 7, &info).unwrap();
    Authorizer::from_ticket(5000, ENTITY_OSD, &blob, &sk).unwrap()
}

fn valid_rotating() -> RotatingSecrets {
    let mut rot = RotatingSecrets::default();
    rot.secrets.insert(
        7,
        ExpiringCryptoKey {
            key: principal_key(),
            expiration: UTime::new(4700, 0),
        },
    );
    rot
}

mod authorizer {
    use super::*;

    proptest! {
        #![proptest_config(cfg())]

        // Service side: an arbitrary AUTH_REQUEST payload must not panic the verifier.
        #[test]
        fn verify_any_byte(b in bytes()) {
            let rot = valid_rotating();
            allocs::measure(b.len(), "authorizer verify_any_byte", || {
                let mut v = AuthorizerVerifier::new(ENTITY_OSD, false);
                let _ = v.verify(&b, &rot);
            });
        }

        // Client side: arbitrary challenge / reply payloads must not panic.
        #[test]
        fn on_reply_more_any_byte(b in bytes()) {
            let mut az = valid_authorizer();
            let _ = az.on_reply_more(&b);
        }

        #[test]
        fn on_done_any_byte(b in bytes()) {
            let mut az = valid_authorizer();
            let _ = az.on_done(&b);
        }

        // Full roundtrip: a generated ticket authorizes across the challenge round.
        #[test]
        fn roundtrip_handshake(
            name_id in u8s(8),
            global_id in any::<u64>(),
            sec in 0u32..1_000_000,
            caps_text in STR_UNI_8,
        ) {
            let now = sec as u64;
            let rk = CryptoKey::new(KeyType::Aes, UTime::new(sec, 0), &[1u8; 16]);
            let sk = CryptoKey::new(KeyType::Aes, UTime::new(sec, 0), &[2u8; 16]);
            let mut rot = RotatingSecrets::default();
            rot.secrets.insert(
                7,
                ExpiringCryptoKey {
                    key: rk.clone(),
                    expiration: UTime::new((now + 3600) as u32, 0),
                },
            );
            let info = ServiceTicketInfo {
                ticket: AuthTicket {
                    name: ByteEntityName { ty: ENTITY_OSD, id: name_id },
                    global_id,
                    auid: AUTH_UID_DEFAULT,
                    created: UTime::new(sec, 0),
                    expires: UTime::new((now + 100) as u32, 0),
                    caps: CapsInfo::from_text(&caps_text),
                    flags: 0,
                },
                session_key: sk.clone(),
            };
            let blob = seal_ticket_info(&rk, 7, &info).unwrap();
            let mut az = Authorizer::from_ticket(global_id, ENTITY_OSD, &blob, &sk).unwrap();
            let mut v = AuthorizerVerifier::new(ENTITY_OSD, false);
            let more = match v.verify(az.payload(), &rot).unwrap() {
                Verdict::More(m) => m,
                Verdict::Done(_) => panic!("must challenge first"),
            };
            let p2 = az.on_reply_more(&more).unwrap().to_vec();
            let Verdict::Done(peer) = v.verify(&p2, &rot).unwrap() else {
                panic!("second round must complete");
            };
            az.on_done(&peer.reply).unwrap();
            assert!(az.is_done());
            assert_eq!(peer.global_id, global_id);
            assert_eq!(peer.session_key, sk);
        }

        // Single mutation of a valid authorizer payload: Ok or Err, never a panic.
        #[test]
        fn mutated(m in mutation()) {
            let rot = valid_rotating();
            let enc = valid_authorizer().payload().to_vec();
            let buf = apply(&enc, &m);
            let len = matches!(m, Mutation::Len(..));
            if len {
                allocs::measure(buf.len(), "authorizer mutated", || {
                    let mut v = AuthorizerVerifier::new(ENTITY_OSD, false);
                    let _ = v.verify(&buf, &rot);
                });
            } else {
                let mut v = AuthorizerVerifier::new(ENTITY_OSD, false);
                let _ = v.verify(&buf, &rot);
            }
        }
    }

    // Truncation of a valid authorizer payload: Err at every cut (never a wrong Done).
    #[test]
    fn truncated() {
        let rot = valid_rotating();
        let payload = valid_authorizer().payload().to_vec();
        for n in 0..payload.len() {
            let mut v = AuthorizerVerifier::new(ENTITY_OSD, false);
            assert!(v.verify(&payload[..n], &rot).is_err(), "cut {n}");
        }
    }
}

// ---- MonAuthClient (mon handshake + MAuthReply) --------------------------------

/// Drive a fresh client to `Established` with a fixed, valid mon reply.
fn established_client() -> MonAuthClient {
    let key = principal_key();
    let cfg = MonAuthConfig::osd(EntityName::parse("osd.0").unwrap(), key.clone());
    let mut c = MonAuthClient::new(cfg);
    c.start();
    let sc = ServerChallenge {
        server_challenge: 42,
    };
    c.on_reply_more(&sc.encode_to_vec().unwrap(), Duration::from_secs(100))
        .unwrap();
    let entry = TicketEntry {
        service_id: ENTITY_AUTH,
        session_key: old_key(),
        validity: UTime::new(3600, 0),
        blob: TicketBlob::default(),
    };
    let mut body = ResponseHeader {
        request_type: CEPHX_GET_AUTH_SESSION_KEY,
        status: 0,
    }
    .encode_to_vec()
    .unwrap();
    body.extend(encode_ticket_reply(std::slice::from_ref(&entry), &key, None).unwrap());
    c.on_done(7, CON_MODE_CRC, &body, Duration::from_secs(100))
        .unwrap();
    c
}

mod monclient {
    use super::*;

    proptest! {
        #![proptest_config(cfg())]

        #[test]
        fn on_reply_more_any_byte(b in bytes()) {
            // the client is built inside the measured closure: a re-run must start fresh
            allocs::measure(b.len(), "monclient on_reply_more any_byte", || {
                let key = principal_key();
                let cfg = MonAuthConfig::osd(EntityName::parse("osd.0").unwrap(), key);
                let mut c = MonAuthClient::new(cfg);
                c.start();
                let _ = c.on_reply_more(&b, Duration::from_secs(100));
            });
        }

        #[test]
        fn on_done_any_byte(b in bytes()) {
            allocs::measure(b.len(), "monclient on_done any_byte", || {
                let key = principal_key();
                let cfg = MonAuthConfig::osd(EntityName::parse("osd.0").unwrap(), key);
                let mut c = MonAuthClient::new(cfg);
                c.start();
                let sc = ServerChallenge { server_challenge: 42 };
                c.on_reply_more(&sc.encode_to_vec().unwrap(), Duration::from_secs(100)).unwrap();
                let _ = c.on_done(7, 1, &b, Duration::from_secs(100));
            });
        }

        // MAuthReply `result_bl` is untrusted: Ok/Ignored/Err, never a panic.
        #[test]
        fn on_response_any_byte(result in any::<i32>(), gid in any::<u64>(), b in bytes()) {
            allocs::measure(b.len(), "monclient on_response any_byte", || {
                let mut c = established_client();
                let _ = c.on_response(result, gid, &b, Duration::from_secs(200));
            });
        }
    }

    // Roundtrip: the reply to a polled principal request installs its tickets.
    #[test]
    fn on_response_roundtrip() {
        let mut c = established_client();
        let now = Duration::from_secs(200);
        let auth_key = c.session_key().unwrap().clone();
        let req = c.poll(now).unwrap().unwrap();
        assert_eq!(req.request_type, CEPHX_GET_PRINCIPAL_SESSION_KEY);
        let entries = [ENTITY_MON, ENTITY_OSD, ENTITY_MGR].map(|svc| TicketEntry {
            service_id: svc,
            session_key: CryptoKey::new(KeyType::Aes, UTime::new(200, 0), &[9u8; 16]),
            validity: UTime::new(3600, 0),
            blob: TicketBlob::default(),
        });
        let mut body = ResponseHeader {
            request_type: req.request_type,
            status: 0,
        }
        .encode_to_vec()
        .unwrap();
        body.extend(encode_ticket_reply(&entries, &auth_key, None).unwrap());
        assert_eq!(
            c.on_response(0, 7, &body, now).unwrap(),
            MonReply::Installed
        );
        for svc in [ENTITY_MON, ENTITY_OSD, ENTITY_MGR] {
            assert!(c.ticket(svc).unwrap().have_key(now), "svc {svc:#x}");
        }
    }
}

// ---- NONE-mode payloads ---------------------------------------------------------

mod none {
    use super::*;

    proptest! {
        #![proptest_config(cfg())]

        #[test]
        fn any_byte(b in bytes()) {
            allocs::measure(b.len(), "none any_byte", || {
                let _ = parse_none_payload(&b);
                let _ = verify_none(&b);
            });
        }

        #[test]
        fn roundtrip(name in entity_name(), gid in any::<u64>()) {
            let p = none_authorizer(&name, gid);
            let (mode, n, g) = parse_none_payload(&p).unwrap();
            assert_eq!(mode, AUTH_MODE_AUTHORIZER);
            assert_eq!(n, name);
            assert_eq!(g, gid);
            assert!(verify_none(&p).is_ok());
            // the mon-mode payload is not a peer authorizer
            let pm = mon_auth_payload(&name, gid);
            let (mode, _, _) = parse_none_payload(&pm).unwrap();
            assert_eq!(mode, AUTH_MODE_MON);
            assert!(verify_none(&pm).is_err());
        }

        #[test]
        fn truncated(name in entity_name(), gid in any::<u64>()) {
            let p = none_authorizer(&name, gid);
            for c in 0..p.len() {
                if let Ok((_, n, g)) = parse_none_payload(&p[..c]) {
                    let re = none_authorizer(&n, g);
                    assert_eq!(re, &p[..c], "cut {c}: re-encodes differently (consumed past the end?)");
                }
            }
        }

        #[test]
        fn mutated(name in entity_name(), gid in any::<u64>(), m in mutation()) {
            let p = none_authorizer(&name, gid);
            let buf = apply(&p, &m);
            let len = matches!(m, Mutation::Len(..));
            if len {
                allocs::measure(buf.len(), "none mutated", || {
                    let _ = parse_none_payload(&buf);
                    let _ = verify_none(&buf);
                });
            } else {
                let _ = parse_none_payload(&buf);
                let _ = verify_none(&buf);
            }
        }
    }
}

// ---- ConnectionSecret ------------------------------------------------------------

mod connection_secret {
    use super::*;

    proptest! {
        #![proptest_config(cfg())]

        #[test]
        fn any_byte(b in bytes()) {
            allocs::measure(b.len(), "connection_secret any_byte", || {
                let _ = ConnectionSecret::from_bytes(&b);
            });
        }
    }

    #[test]
    fn boundaries() {
        assert!(ConnectionSecret::from_bytes(&[]).unwrap().is_none());
        assert!(ConnectionSecret::from_bytes(&[0u8; 39]).is_err());
        // W16: the exact 40-byte minimum is accepted
        let s40 = ConnectionSecret::from_bytes(&[0u8; 40]).unwrap().unwrap();
        assert_eq!(s40.as_bytes().len(), 40);
        let s = ConnectionSecret::from_bytes(&[0u8; 64]).unwrap().unwrap();
        assert_eq!(s.as_bytes().len(), 64);
    }
}

// ---- Keyring (keyring file, disk) --------------------------------------------------

mod keyring {
    use super::*;

    fn valid_text() -> String {
        let key = principal_key();
        let b64 = key.to_base64().unwrap();
        format!("[osd.0]\nkey = {b64}\ncaps mon = \"allow * \"\n")
    }

    proptest! {
        #![proptest_config(cfg())]

        // Arbitrary (lossy-UTF-8) keyring text must not panic the parser.
        #[test]
        fn any_text(b in bytes()) {
            let text = String::from_utf8_lossy(&b).into_owned();
            allocs::measure(b.len(), "keyring any_text", || {
                let _ = Keyring::parse(&text);
            });
        }

        #[test]
        fn mutated(m in mutation()) {
            let text = valid_text();
            let buf = apply(text.as_bytes(), &m);
            let len = matches!(m, Mutation::Len(..));
            if len {
                allocs::measure(buf.len(), "keyring mutated", || {
                    let s = String::from_utf8_lossy(&buf).into_owned();
                    let _ = Keyring::parse(&s);
                });
            } else {
                let s = String::from_utf8_lossy(&buf).into_owned();
                let _ = Keyring::parse(&s);
            }
        }
    }

    #[test]
    fn valid() {
        let text = valid_text();
        let kr = Keyring::parse(&text).unwrap();
        let e = kr.get("osd.0").unwrap();
        assert!(e.key.is_some());
        assert_eq!(e.caps.get("mon"), Some(&"allow * ".to_string()));
    }

    #[test]
    fn truncated() {
        let text = valid_text();
        for c in 0..text.len() {
            let _ = Keyring::parse(&text[..c]);
        }
    }
}
