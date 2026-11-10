// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Spec vectors + black-box fixtures (testdata/cephx).

use cephx::challenge::compute_key;
use cephx::envelope::*;
use cephx::keyring::Keyring;
use cephx::none::*;
use cephx::secret::ConnectionSecret;
use cephx::{CryptoKey, KeyType, UTime, Usage, krb5_derive};
use denc::{Decoder, Encoder};

fn tohex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn td(name: &str) -> String {
    format!("{}/../../testdata/cephx/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn k1() -> CryptoKey {
    CryptoKey::new(KeyType::Aes, UTime::default(), b"1234567890123456")
}
fn k2() -> CryptoKey {
    CryptoKey::new(
        KeyType::Aes256Krb5,
        UTime::default(),
        b"12345678901234567890123456789012",
    )
}

#[test]
fn base64_examples() {
    assert_eq!(
        k1().to_base64().unwrap(),
        "AQAAAAAAAAAAABAAMTIzNDU2Nzg5MDEyMzQ1Ng=="
    );
    assert_eq!(
        k2().to_base64().unwrap(),
        "AgAAAAAAAAAAACAAMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
    );
    assert_eq!(
        CryptoKey::from_base64("AQAAAAAAAAAAABAAMTIzNDU2Nzg5MDEyMzQ1Ng==").unwrap(),
        k1()
    );
    assert_eq!(
        CryptoKey::from_base64("AgAAAAAAAAAAACAAMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
            .unwrap(),
        k2()
    );
}

#[test]
fn krb5_derive_vector() {
    let (ki, ke) = krb5_derive(k2().secret(), 0x30);
    assert_eq!(
        tohex(&*ki),
        "e55cfb442df7603fb60a5bad855649365348e619e9f9d05a"
    );
    assert_eq!(
        tohex(&*ke),
        "a4f4b8de32a89bd79e405082df19e1ae0d27e977c90e95b5244b1eb4e3132e2e"
    );
}

#[test]
fn challenge_vectors() {
    assert_eq!(compute_key(&k1(), 1, 2).unwrap(), 0x0b5914cea6cc7a4a);
    assert_eq!(compute_key(&k2(), 1, 2).unwrap(), 0xf18dddee917f0cf4);
    // ciphertext of the type-1 vector
    let blob = cephx::challenge::challenge_blob(1, 2);
    let raw = seal_raw(&k1(), Usage::TicketSessionKey, &blob).unwrap();
    assert_eq!(
        tohex(&raw),
        "e0ef5f0c1b4aa32b5c5ddb1a07115048abdede6376213fc5d978037e9cd78ab8"
    );
}

#[test]
fn aes_padding_and_lenient_decrypt() {
    let k = k1();
    for n in [0usize, 1, 15, 16, 17, 31, 32, 100] {
        let p: Vec<u8> = (0..n as u8).collect();
        let c = k.encrypt(&p, Usage::Authorize).unwrap();
        assert_eq!(c.len(), 16 * (n / 16 + 1));
        assert_eq!(&**k.decrypt(&c, Usage::Authorize).unwrap(), &p[..]);
    }
    assert!(k.decrypt(&[0; 15], Usage::Authorize).is_err());
    assert!(k.decrypt(&[], Usage::Authorize).is_err());
}

#[test]
fn krb5_roundtrip_all_lengths() {
    let k = k2();
    for n in 0..100usize {
        let p: Vec<u8> = (0..n).map(|i| i as u8 ^ 0x5a).collect();
        let c = k.encrypt(&p, Usage::TicketInfo).unwrap();
        assert_eq!(c.len(), 16 + n + 24);
        assert_eq!(
            &**k.decrypt(&c, Usage::TicketInfo).unwrap(),
            &p[..],
            "n={n}"
        );
        assert!(
            k.decrypt(&c, Usage::Authorize).is_err(),
            "wrong usage must fail"
        );
        let mut bad = c.clone();
        bad[0] ^= 1;
        assert!(k.decrypt(&bad, Usage::TicketInfo).is_err());
    }
    assert!(k.decrypt(&[0; 39], Usage::TicketInfo).is_err());
}

// RFC 3962 appendix B CTS vectors (AES-128, key "chicken teriyaki", iv 0) are CS3 for the
// Kerberos variant. Our CTS is AES-256, so verify the CS3 structure against the same
// construction via lengths 17..48 round trip (above) and against the RFC 3962 17-byte vector
// using the crate's internal-agnostic public API is not possible; covered by unit test in src.

#[test]
fn envelope_forms() {
    let k = k1();
    let body = [7u8; 5];
    let w = seal_wrapped(&k, Usage::Authorize, &body).unwrap();
    let mut r = Decoder::new(&w);
    let out = open_wrapped(&k, Usage::Authorize, &mut r).unwrap();
    assert_eq!(&out[..5], &body);
    assert_eq!(r.remaining(), 0);
    let ct = &w[4..];
    assert_eq!(
        u32::from_le_bytes(w[..4].try_into().unwrap()) as usize,
        ct.len()
    );
    // bad magic
    let bad = k.encrypt(&[0u8; 20], Usage::Authorize).unwrap();
    assert!(open_raw(&k, Usage::Authorize, &bad).is_err());
    // string form (connection secret)
    for kk in [k1(), k2()] {
        let sec = [9u8; 64];
        let w = seal_string_wrapped(&kk, Usage::AuthConnectionSecret, &sec).unwrap();
        let s =
            open_string_wrapped(&kk, Usage::AuthConnectionSecret, &mut Decoder::new(&w)).unwrap();
        assert_eq!(&s[..], &sec[..]);
    }
}

#[test]
fn encode_hash_is_hmac() {
    let h = encode_hash(&k2(), &cephx::challenge::challenge_blob(1, 2));
    assert_eq!(
        tohex(&h),
        "3a55c06559bbdd8909c2fa132bed3de6c48038883426d389031b7d6fa8adbe17"
    );
}

#[test]
fn connection_secret_layout() {
    let raw: Vec<u8> = (0..64).collect();
    let c = ConnectionSecret::from_bytes(&raw).unwrap().unwrap();
    assert_eq!(c.gcm_key(), &raw[0..16]);
    let (rx, tx) = c.client_rx_tx();
    assert_eq!((rx.as_slice(), tx.as_slice()), (&raw[16..28], &raw[28..40]));
    let (rx, tx) = c.acceptor_rx_tx();
    assert_eq!((rx.as_slice(), tx.as_slice()), (&raw[28..40], &raw[16..28]));
    assert!(ConnectionSecret::from_bytes(&[]).unwrap().is_none());
    assert_eq!(ConnectionSecret::generate().unwrap().as_bytes().len(), 64);
}

#[test]
fn key_decode_rules() {
    // unknown type
    assert!(CryptoKey::from_bytes(&[3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    // short aes
    let mut w = Encoder::new();
    w.u16(1).unwrap();
    w.u32(0).unwrap();
    w.u32(0).unwrap();
    w.u16(8).unwrap();
    w.raw(&[0; 8]).unwrap();
    assert!(CryptoKey::from_bytes(w.buf()).is_err());
    // empty valid but unusable
    let mut w = Encoder::new();
    w.u16(1).unwrap();
    w.u32(0).unwrap();
    w.u32(0).unwrap();
    w.u16(0).unwrap();
    let k = CryptoKey::from_bytes(w.buf()).unwrap();
    assert!(k.encrypt(b"x", Usage::Authorize).is_err());
    // type none refuses crypto
    let n = CryptoKey::new(KeyType::None, UTime::default(), b"");
    assert!(n.encrypt(b"x", Usage::Authorize).is_err());
    // truncated
    assert!(CryptoKey::from_bytes(&k1().to_bytes().unwrap()[..10]).is_err());
    // debug redacts
    assert!(!format!("{:?}", k1()).contains("1234"));
}

/// A secret longer than the u16 wire length is unrepresentable: encoding refuses it instead of
/// emitting a truncated key that would read back as a different one.
#[test]
fn oversized_key_secret_is_refused_not_truncated() {
    let k = CryptoKey::new(KeyType::Aes, UTime::default(), &[0u8; 65_536]);
    assert!(k.to_bytes().is_err());
    assert!(k.to_base64().is_err());
    // the largest representable secret still encodes (2 type + 8 utime + 2 len + secret)
    let ok = CryptoKey::new(KeyType::Aes, UTime::default(), &[0u8; u16::MAX as usize]);
    assert_eq!(ok.to_bytes().unwrap().len(), 12 + usize::from(u16::MAX));
}

#[test]
fn generated_keys() {
    let a = CryptoKey::generate(KeyType::Aes, UTime::default()).unwrap();
    let b = CryptoKey::generate(KeyType::Aes256Krb5, UTime::default()).unwrap();
    assert_eq!((a.secret().len(), b.secret().len()), (16, 32));
    assert!(a.to_base64().unwrap().starts_with("AQ") && b.to_base64().unwrap().starts_with("Ag"));
}

// ---- black-box fixtures from the reference cluster ----

#[test]
fn dencoder_cryptokey_samples() {
    let b = std::fs::read(td("cryptokey.2.bin")).unwrap();
    let k = CryptoKey::from_bytes(&b).unwrap();
    assert_eq!(k.key_type(), KeyType::Aes);
    assert_eq!(
        k.created(),
        UTime {
            sec: 123,
            nsec: 456
        }
    );
    assert_eq!(k.secret(), b"1234567890123456");
    assert_eq!(&**k.to_bytes().unwrap(), &b[..]);
    let b = std::fs::read(td("cryptokey.1.bin")).unwrap();
    let k = CryptoKey::from_bytes(&b).unwrap();
    assert_eq!(k.key_type(), KeyType::None);
    assert_eq!(&**k.to_bytes().unwrap(), &b[..]);
}

#[test]
fn reference_keyrings() {
    let kr = Keyring::parse(&std::fs::read_to_string(td("admin.keyring")).unwrap()).unwrap();
    let e = kr.get("client.admin").unwrap();
    let k = e.key.as_ref().unwrap();
    assert_eq!(k.key_type(), KeyType::Aes256Krb5);
    assert_eq!(k.secret().len(), 32);
    assert_ne!(k.created().sec, 0);
    assert_eq!(
        k.to_base64().unwrap(),
        "AgCUu8hq7NGRECAAruI5W2mmG0l87BQqEJ4W/l1stgBVCSaqL7tPpeO6hZM="
    );
    assert_eq!(e.caps["osd"], "allow *");
    assert_eq!(e.caps.len(), 4);

    let kr = Keyring::parse(&std::fs::read_to_string(td("mon.keyring")).unwrap()).unwrap();
    assert!(kr.get("mon.").is_some() && kr.get("client.admin").is_some());

    let kr = Keyring::parse(&std::fs::read_to_string(td("type1.keyring")).unwrap()).unwrap();
    let e = kr.get("osd.7").unwrap();
    assert_eq!(e.key.as_ref().unwrap().key_type(), KeyType::Aes);
    assert_eq!(e.key.as_ref().unwrap().secret().len(), 16);
    assert_eq!(e.caps["mon"], "allow profile osd");
}

#[test]
fn keyring_syntax_variants() {
    let k = k1().to_base64().unwrap();
    let txt = format!(
        "# c\n[global]\nfoo = bar\n[osd.1]\n  key = {k} ; trailing\n  caps_mon = 'allow profile osd'\n  caps  osd=allow \\\n rwx # x\n  pending key = {k}\n  auid = 5\n[client.x.y]\r\n\tkey=\"{k}\"\r\n"
    );
    let kr = Keyring::parse(&txt).unwrap();
    let e = kr.get("osd.1").unwrap();
    assert_eq!(e.key.as_ref().unwrap(), &k1());
    assert_eq!(e.pending_key.as_ref().unwrap(), &k1());
    assert_eq!(e.caps["mon"], "allow profile osd");
    assert_eq!(e.caps["osd"], "allow  rwx");
    assert!(kr.get("client.x.y").unwrap().key.is_some());
    assert!(Keyring::parse("[foo.1]\nkey = x\n").is_err());
    assert!(Keyring::parse("[osd.1]\nbogus = x\n").is_err());
    assert!(Keyring::parse("[osd.1]\nkey = !!!\n").is_err());
}

/// A repeated section continues the entity (concatenated keyrings): later lines win per field, earlier
/// fields stay.
#[test]
fn keyring_repeated_sections_merge() {
    let a = k1().to_base64().unwrap();
    let txt = format!(
        "[osd.3]\nkey = {a}\ncaps mon = \"allow profile osd\"\n[client.x]\nkey = {a}\n[osd.3]\ncaps osd = \"allow *\"\ncaps mon = \"allow r\"\n"
    );
    let kr = Keyring::parse(&txt).unwrap();
    let e = kr.get("osd.3").unwrap();
    assert_eq!(
        e.key.as_ref().unwrap(),
        &k1(),
        "key of the first block survives"
    );
    assert_eq!(e.caps["osd"], "allow *");
    assert_eq!(e.caps["mon"], "allow r", "later block wins per field");
    assert!(kr.get("client.x").unwrap().key.is_some());
}

#[test]
fn none_payloads() {
    let n = EntityName::parse("osd.12").unwrap();
    assert_eq!(n.to_string(), "osd.12");
    let p = mon_auth_payload(&n, 0);
    assert_eq!(
        p,
        [
            10u8, 4, 0, 0, 0, 2, 0, 0, 0, b'1', b'2', 0, 0, 0, 0, 0, 0, 0, 0
        ]
    );
    let (m, nm, g) = parse_none_payload(&none_authorizer(&n, 77)).unwrap();
    assert_eq!((m, nm, g), (1, n, 77));
}

/// The wire encoding of a key is built in one exactly sized buffer: no growth copy of the secret is left behind.
#[test]
fn key_wire_bytes_are_one_exact_allocation() {
    for (ty, len) in [(cephx::KeyType::Aes, 16), (cephx::KeyType::Aes256Krb5, 32)] {
        let k = cephx::CryptoKey::new(ty, cephx::UTime::new(1, 2), &vec![7; len]);
        let b = k.to_bytes().unwrap();
        assert_eq!(b.len(), b.capacity());
        assert_eq!(cephx::CryptoKey::from_bytes(&b).unwrap(), k);
    }
}
