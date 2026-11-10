// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Spec hex examples, envelope rules, ordering, robustness.

use denc::types::*;
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Error, SliceBuf, features, from_slice};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn check<T>(v: T, h: &str)
where
    T: for<'a> Decode<'a> + Encode + PartialEq + core::fmt::Debug,
{
    let b = hex(h);
    assert_eq!(v.encode_to_vec().unwrap(), b);
    assert_eq!(from_slice::<T>(&b).unwrap(), v);
}

#[test]
fn primitives_and_containers() {
    check(0x11223344u32, "44 33 22 11");
    check(-2i16, "fe ff");
    check(true, "01");
    check(1.5f64, "00 00 00 00 00 00 f8 3f");
    check("ab".to_string(), "02 00 00 00 61 62");
    check(Vec::<u8>::new(), "00 00 00 00");
    check(vec![1u16, 2], "02 00 00 00 01 00 02 00");
    check(
        std::collections::BTreeMap::from([(1u32, "a".to_string())]),
        "01000000 01000000 01000000 61",
    );
    check(None::<u32>, "00");
    check(Some(5u32), "01 05 00 00 00");
    check((1u8, 2u8), "01 02");
    check([1u8, 2, 3], "01 02 03".replace(' ', "").as_str());
}

#[test]
fn spec_types() {
    check(UTime::new(1, 2), "01 00 00 00 02 00 00 00");
    check(EntityName::osd(3), "04 03 00 00 00 00 00 00 00");
    check(Eversion::new(1, 2), "02 00 00 00 00 00 00 00 01 00 00 00");
    check(
        PgT::new(2, 0x1f),
        "01 02 00 00 00 00 00 00 00 1f 00 00 00 ff ff ff ff",
    );
    check(
        SpgT {
            pgid: PgT::new(1, 2),
            shard: ShardId(3),
        },
        "01 01 12 00 00 00 | 01 01 00 00 00 00 00 00 00 02 00 00 00 ff ff ff ff | 03",
    );
    check(
        OsdReqId {
            name: EntityName::client(5),
            tid: 7,
            inc: 1,
        },
        "02 02 15 00 00 00 | 08 05 00 00 00 00 00 00 00 | 07 00 00 00 00 00 00 00 | 01 00 00 00",
    );
    check(
        ObjectLocator {
            pool: 2,
            ..Default::default()
        },
        "06 03 1c 00 00 00 | 02 00 00 00 00 00 00 00 | ff ff ff ff | 00 00 00 00 | 00 00 00 00 | ff ff ff ff ff ff ff ff",
    );
    let mut h = Hobject::new(b"a", SnapId::NOSNAP, 0x12345678, 2, b"");
    check(
        h.clone(),
        "04 03 22 00 00 00 | 00 00 00 00 | 01 00 00 00 61 | fe ff ff ff ff ff ff ff | 78 56 34 12 | 00 | 00 00 00 00 | 02 00 00 00 00 00 00 00",
    );
    h.set_key(b"a");
    assert!(h.key.is_empty());
}

fn addr() -> EntityAddr {
    EntityAddr::v4(2, 0x11223344, [10, 0, 0, 1], 6800)
}
const ADDR_HEX: &str = "01 | 01 01 1c 00 00 00 | 02 00 00 00 | 44 33 22 11 | 10 00 00 00 | 02 00 | 1a 90 | 0a 00 00 01 | 00 00 00 00 00 00 00 00";

#[test]
fn addr_examples() {
    check(addr(), ADDR_HEX);
    check(
        EntityAddrVec::single(addr()),
        &format!("02 01 00 00 00 {ADDR_HEX}"),
    );
    // legacy 136 bytes
    let mut a = addr();
    a.ty = 1;
    let b = a.encode_to_vec_with_features(!features::MSG_ADDR2).unwrap();
    assert_eq!(b.len(), 136);
    assert_eq!(
        &b[..16],
        &hex("00 00 00 00 | 44 33 22 11 | 00 02 | 1a 90 | 0a 00 00 01")[..]
    );
    assert_eq!(from_slice::<EntityAddr>(&b).unwrap(), a);
    // blank: 47 bytes
    assert_eq!(EntityAddr::blank().encode_to_vec().unwrap().len(), 47);
    // ANY demoted to LEGACY without SERVER_NAUTILUS
    let mut any = addr();
    any.ty = 3;
    let b = any.encode_to_vec_with_features(!4u64).unwrap();
    assert_eq!(from_slice::<EntityAddr>(&b).unwrap().ty, 1);
    assert_eq!(
        from_slice::<EntityAddr>(&any.encode_to_vec().unwrap())
            .unwrap()
            .ty,
        3
    );
}

#[test]
fn addr_v6_and_elen0() {
    let a = EntityAddr::v6(2, 9, [1; 16], 3300, 7);
    let b = a.encode_to_vec().unwrap();
    assert_eq!(b.len(), 47);
    assert_eq!(from_slice::<EntityAddr>(&b).unwrap(), a);
    // elen == 0 accepted
    let b = hex("01 | 01 01 0c 00 00 00 | 02 00 00 00 | 05 00 00 00 | 00 00 00 00");
    let a: EntityAddr = from_slice(&b).unwrap();
    assert!(a.is_blank() && a.nonce == 5);
    // elen 29 rejected, elen 1 rejected
    for elen in [1u8, 29] {
        let mut b = hex("01 | 01 01 1d 00 00 00 | 02 00 00 00 | 05 00 00 00 | 00 00 00 00");
        b[14] = elen;
        b.resize(b.len() + 30, 0);
        assert!(from_slice::<EntityAddr>(&b).is_err());
    }
    // addrvec marker 1 (single addr) accepted
    let b = addr().encode_to_vec().unwrap();
    assert_eq!(from_slice::<EntityAddrVec>(&b).unwrap().0, vec![addr()]);
    assert_eq!(from_slice::<EntityAddrVec>(&[3]), Err(Error::BadMarker(3)));
}

#[test]
fn addr_text_forms_match_spec_6() {
    // IPv6 compressed (RFC 5952), bracketed, lower case
    let a = EntityAddr::v6(
        EntityAddr::TYPE_MSGR2,
        1234,
        "fd00:77::11"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
        6800,
        0,
    );
    assert_eq!(a.to_string(), "v2:[fd00:77::11]:6800/1234");
    let lo = EntityAddr::v6(
        EntityAddr::TYPE_MSGR2,
        0,
        "::1".parse::<std::net::Ipv6Addr>().unwrap().octets(),
        3300,
        0,
    );
    assert_eq!(lo.to_string(), "v2:[::1]:3300/0");
    // v4-mapped prints as inet_ntop does
    let m = EntityAddr::v6(
        EntityAddr::TYPE_LEGACY,
        0,
        "::ffff:10.0.0.1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
        6789,
        0,
    );
    assert_eq!(m.to_string(), "v1:[::ffff:10.0.0.1]:6789/0");
    // TYPE_ANY: no prefix; TYPE_NONE: `-` only; CIDR: prefix
    assert_eq!(
        EntityAddr::v4(EntityAddr::TYPE_ANY, 7, [10, 1, 2, 3], 0).to_string(),
        "10.1.2.3:0/7"
    );
    assert_eq!(
        EntityAddr::v4(EntityAddr::TYPE_NONE, 5, [0; 4], 0).to_string(),
        "-"
    );
    assert_eq!(
        EntityAddr::v4(EntityAddr::TYPE_CIDR, 24, [10, 9, 0, 0], 0).to_string(),
        "cidr:10.9.0.0:0/24"
    );
    assert_eq!(
        EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [10, 0, 0, 1], 6800).to_string(),
        "v2:10.0.0.1:6800/0"
    );
    // a family we do not know
    let b = EntityAddr {
        ty: EntityAddr::TYPE_MSGR2,
        family: 99,
        ..EntityAddr::blank()
    };
    assert_eq!(b.to_string(), "v2:(unrecognized address family 99)/0");
}

#[test]
fn addr_ip_and_socket_helpers() {
    use std::net::{IpAddr, SocketAddr};
    let a = EntityAddr::v6(
        EntityAddr::TYPE_MSGR2,
        0,
        [0xfd, 0, 0, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11],
        6800,
        3,
    );
    assert_eq!(a.ip(), Some("fd00:77::11".parse::<IpAddr>().unwrap()));
    assert_eq!(a.scope_id(), 3);
    assert_eq!(
        a.socket_addr(),
        Some("[fd00:77::11%3]:6800".parse::<SocketAddr>().unwrap())
    );
    assert_eq!(EntityAddr::blank().ip(), None);
    assert_eq!(EntityAddr::blank().socket_addr(), None);
    let s = EntityAddr::from_socket(
        EntityAddr::TYPE_MSGR2,
        0,
        "[fd00:77::11%3]:6800".parse::<SocketAddr>().unwrap(),
    );
    assert_eq!(
        (s.family, s.port(), s.scope_id()),
        (denc::types::entity::AF_INET6, 6800, 3)
    );
    let v4 = EntityAddr::from_socket(EntityAddr::TYPE_MSGR2, 0, "10.0.0.1:6800".parse().unwrap());
    assert_eq!(v4.to_string(), "v2:10.0.0.1:6800/0");
}

#[test]
fn addr_ordering_is_memcmp() {
    // 256 vs 1 as nonce: LE bytes compare 00 01.. < 01 00.. => 256 < 1 in memcmp order
    let a = EntityAddr {
        nonce: 256,
        ..EntityAddr::blank()
    };
    let b = EntityAddr {
        nonce: 1,
        ..EntityAddr::blank()
    };
    assert!(a < b);
}

#[test]
fn envelope_rules() {
    // unknown trailing bytes skipped, nested bounded
    let b = hex("05 01 0a 00 00 00 | 01 00 00 00 | aa bb cc dd 11 22 | 99");
    let mut d = Decoder::new(&b);
    let (x, v) = d.versioned(1, |d, v| Ok((d.u32()?, v))).unwrap();
    assert_eq!((x, v), (1, 5));
    assert_eq!(d.u8().unwrap(), 0x99);
    // compat too new
    let b = hex("01 02 00 00 00 00");
    assert!(matches!(
        Decoder::new(&b).versioned(1, |_, _| Ok(())),
        Err(Error::CompatTooNew {
            compat: 2,
            supported: 1
        })
    ));
    // oldest
    let b = hex("01 01 00 00 00 00");
    assert!(matches!(
        Decoder::new(&b).versioned_min(2, 1, |_, _| Ok(())),
        Err(Error::VersionTooOld { .. })
    ));
    // len beyond buffer
    let b = hex("01 01 09 00 00 00 00");
    assert!(Decoder::new(&b).versioned(1, |_, _| Ok(())).is_err());
    // reading past struct end fails even though outer buffer has bytes
    let b = hex("01 01 02 00 00 00 aa bb cc dd");
    assert!(Decoder::new(&b).versioned(1, |d, _| d.u32()).is_err());
    // encode patching
    let mut e = Encoder::new();
    e.versioned(3, 1, |e| e.u32(7)).unwrap();
    assert_eq!(e.into_vec(), hex("03 01 04 00 00 00 07 00 00 00"));
}

#[test]
fn huge_length_prefixes() {
    let b = hex("ff ff ff ff 00");
    assert!(matches!(
        from_slice::<Vec<u8>>(&b),
        Err(Error::BadLength { .. })
    ));
    assert!(matches!(
        from_slice::<Vec<u64>>(&b),
        Err(Error::BadLength { .. })
    ));
    assert!(from_slice::<std::collections::BTreeMap<u32, u32>>(&b).is_err());
    assert!(from_slice::<&[u8]>(&b).is_err());
}

#[test]
fn borrowed_decode() {
    let b = hex("03 00 00 00 61 62 63");
    let s: &[u8] = from_slice(&b).unwrap();
    assert_eq!(s, b"abc");
    assert!(core::ptr::eq(s.as_ptr(), b[4..].as_ptr()));
    assert_eq!(from_slice::<&str>(&b).unwrap(), "abc");
    assert_eq!(from_slice::<&str>(&hex("01 00 00 00 ff")), Err(Error::Utf8));
}

#[test]
fn slice_buf() {
    let mut m = [0u8; 10];
    let mut e = Encoder::from_buf(SliceBuf::new(&mut m));
    e.versioned(1, 1, |e| e.u32(5)).unwrap();
    assert_eq!(e.buf().len(), 10);
    assert_eq!(e.u8(0), Err(Error::NoSpace));
    assert_eq!(
        e.into_inner().written(),
        &hex("01 01 04 00 00 00 05 00 00 00")[..]
    );
}

#[test]
fn varints() {
    let mut e = Encoder::new();
    e.varint(300).unwrap();
    e.varint_signed(-1).unwrap();
    e.varint_lowz(0x1000).unwrap();
    assert_eq!(e.into_vec(), hex("ac 02 03 07"));
    for v in [
        0u64,
        1,
        127,
        128,
        300,
        0x1000,
        0xdead_0000,
        u64::MAX,
        1 << 63,
    ] {
        let mut e = Encoder::new();
        e.varint(v).unwrap();
        let v2 = v & ((1 << 60) - 1);
        e.varint_lowz(v2).unwrap();
        let b = e.into_vec();
        let mut d = Decoder::new(&b);
        assert_eq!(d.varint().unwrap(), v);
        assert_eq!(d.varint_lowz().unwrap(), v2);
    }
    for v in [0i64, -1, 1, -4096, 4096, i64::MAX, i64::MIN + 1, 0x10_0000] {
        let mut e = Encoder::new();
        e.varint_signed(v).unwrap();
        let v2 = v % (1 << 58);
        e.varint_lowz_signed(v2).unwrap();
        let b = e.into_vec();
        let mut d = Decoder::new(&b);
        assert_eq!(d.varint_signed().unwrap(), v);
        assert_eq!(d.varint_lowz_signed().unwrap(), v2);
    }
    assert!(Decoder::new(&[0x80; 11]).varint().is_err());
    assert!(
        Decoder::new(&hex("ff ff ff ff ff ff ff ff ff 7f"))
            .varint()
            .is_err()
    );
}

/// The varint family cannot represent every value: the encoder rejects those instead of truncating them silently.
#[test]
fn varint_out_of_range_is_an_error() {
    let mut e = Encoder::new();
    assert_eq!(
        e.varint_signed(i64::MIN),
        Err(Error::BadValue("varint_signed out of range"))
    );
    // the packed form (value << 2, resp. << 3) would need more than 64 bits
    for v in [u64::MAX, (1u64 << 63) + 1] {
        assert_eq!(
            e.varint_lowz(v),
            Err(Error::BadValue("varint_lowz out of range")),
            "{v:#x}"
        );
    }
    for v in [i64::MAX, (1i64 << 62) + 1] {
        assert_eq!(
            e.varint_lowz_signed(v),
            Err(Error::BadValue("varint_lowz_signed out of range")),
            "{v}"
        );
    }
    // the edges that do fit still round-trip
    for v in [(1u64 << 62) - 1, 1 << 62, 1 << 63, u64::MAX >> 12 << 12] {
        let mut e = Encoder::new();
        e.varint_lowz(v).unwrap();
        assert_eq!(Decoder::new(&e.into_vec()).varint_lowz().unwrap(), v);
    }
    for v in [
        (1i64 << 61) - 1,
        1 << 61,
        (1i64 << 61) + (1 << 12),
        i64::MIN,
    ] {
        let mut e = Encoder::new();
        e.varint_lowz_signed(v).unwrap();
        assert_eq!(Decoder::new(&e.into_vec()).varint_lowz_signed().unwrap(), v);
    }
    let mut e = Encoder::new();
    e.varint_signed(i64::MIN + 1).unwrap();
    assert_eq!(
        Decoder::new(&e.into_vec()).varint_signed().unwrap(),
        i64::MIN + 1
    );
}

#[test]
fn lowz_decode_rejects_overflow_instead_of_truncating() {
    // The LEB128 itself fits; restoring the stripped nibbles does not.
    for n in 1..=3 {
        let shift = 4 * n;
        let mut e = Encoder::new();
        e.varint(((1u64 << (64 - shift)) << 2) | n).unwrap();
        assert!(Decoder::new(&e.into_vec()).varint_lowz().is_err());
        for sign in 0..=1 {
            let mut e = Encoder::new();
            e.varint(((1u64 << (64 - shift)) << 3) | (n << 1) | sign)
                .unwrap();
            assert!(Decoder::new(&e.into_vec()).varint_lowz_signed().is_err());
        }
    }
    // A positive magnitude of 2^63 cannot be represented by i64; the negative one can.
    let mut e = Encoder::new();
    e.varint(((1u64 << 59) << 3) | 2).unwrap();
    assert!(Decoder::new(&e.into_vec()).varint_lowz_signed().is_err());
    let mut e = Encoder::new();
    e.varint_lowz_signed(i64::MIN).unwrap();
    assert_eq!(
        Decoder::new(&e.into_vec()).varint_lowz_signed().unwrap(),
        i64::MIN
    );
}

#[test]
fn hobject_order_and_fixups() {
    let mk = |oid: &[u8], hash: u32| Hobject::new(oid, SnapId::NOSNAP, hash, 1, b"");
    // bitwise: hash 1 reversed = 0x80000000 > hash 2 (0x40000000)
    assert!(mk(b"a", 2) < mk(b"a", 1));
    assert!(Hobject::MIN() < mk(b"a", 0));
    assert!(mk(b"z", 5) < Hobject::MAX());
    let mut x = mk(b"a", 1);
    let mut y = mk(b"a", 1);
    y.snap = SnapId(3);
    assert!(y < x);
    x.nspace = b"n".to_vec();
    assert!(y < x);
    // pool -1 fix-up on wire
    let mut h = Hobject::MIN();
    h.pool = -1;
    let b = h.encode_to_vec().unwrap();
    assert_eq!(from_slice::<Hobject>(&b).unwrap(), Hobject::MIN());
    // max normalisation
    let mut m = mk(b"junk", 9);
    m.max = true;
    assert_eq!(
        from_slice::<Hobject>(&m.encode_to_vec().unwrap()).unwrap(),
        Hobject::MAX()
    );
    // match_hash and temp pool
    let h = mk(b"a", 0b1011);
    assert!(h.match_hash(1, 0b0011, 2) && !h.match_hash(1, 0b0010, 2) && !h.match_hash(2, 0b11, 2));
    assert_eq!(Hobject::temp_pool(Hobject::temp_pool(7)), 7);
    // ghobject order: shard before hobj, gen last
    let a = Ghobject::new(mk(b"a", 1), 5, ShardId(1));
    let b = Ghobject::new(mk(b"a", 1), 5, ShardId(0));
    assert!(b < a && Ghobject::new(mk(b"a", 1), 4, ShardId(1)) < a && a < Ghobject::MAX());
    assert!(Ghobject::pgmeta(1, 3, ShardId::NO_SHARD).is_pgmeta());
}

#[test]
fn misc_semantics() {
    assert!(Eversion::new(2, 1) > Eversion::new(1, 9));
    assert_eq!(
        Eversion::new(1, 2).key_string(),
        "0000000001.00000000000000000002"
    );
    assert_eq!(PgT::new(2, 0x1f).to_string(), "2.1f");
    assert_eq!(SpgT::parse("2.1fs3").unwrap().to_string(), "2.1fs3");
    assert_eq!(
        Uuid::parse("01234567-89ab-cdef-0123-456789abcdef")
            .unwrap()
            .to_string(),
        "01234567-89ab-cdef-0123-456789abcdef"
    );
    assert!(SnapId::NOSNAP > SnapId::MAXSNAP && SnapId::SNAPDIR > SnapId::NOSNAP);
    assert_eq!(
        UTime::new(1, 1_500_000_000).normalized(),
        UTime::new(2, 500_000_000)
    );
    for c in [
        CollT::Meta,
        CollT::Pg(SpgT::parse("1.0s2").unwrap()),
        CollT::PgTemp(SpgT::parse("1.0s2").unwrap()),
    ] {
        assert_eq!(from_slice::<CollT>(&c.encode_to_vec().unwrap()).unwrap(), c);
    }
    let _ = <Vec<u8> as BufMut>::len(&vec![1]);
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn fuzz_one<T: for<'a> Decode<'a> + Encode + PartialEq + core::fmt::Debug>(r: &mut Rng) {
    for _ in 0..3000 {
        let n = (r.next() % 80) as usize;
        let b = r.bytes(n);
        // never panics; if it decodes, re-encode decodes to same value
        if let Ok(v) = from_slice::<T>(&b)
            && let Ok(re) = v.encode_to_vec()
        {
            assert_eq!(from_slice::<T>(&re).unwrap(), v);
        }
        // mutate valid-ish prefix: truncations must not panic
        let _ = from_slice::<T>(&b[..b.len() / 2]);
    }
}

#[test]
fn fuzz_no_panic_and_stable() {
    let mut r = Rng(0x1234_5678_9abc_def1);
    fuzz_one::<Hobject>(&mut r);
    fuzz_one::<Ghobject>(&mut r);
    fuzz_one::<EntityAddr>(&mut r);
    fuzz_one::<EntityAddrVec>(&mut r);
    fuzz_one::<EntityInst>(&mut r);
    fuzz_one::<ObjectLocator>(&mut r);
    fuzz_one::<SpgT>(&mut r);
    fuzz_one::<CollT>(&mut r);
    fuzz_one::<Vec<Option<(u8, String)>>>(&mut r);
}

#[test]
fn roundtrip_random_values() {
    let mut r = Rng(42);
    for _ in 0..2000 {
        let n = (r.next() % 20) as usize;
        let oid = r.bytes(n);
        let mut h = Hobject::new(
            &oid,
            SnapId(r.next()),
            r.next() as u32,
            (r.next() % 50) as i64 - 3,
            &r.bytes(3),
        );
        if r.next().is_multiple_of(2) {
            let k = r.bytes(4);
            h.set_key(&k);
        }
        if h.pool == -1 && h.oid.is_empty() && h.snap.0 == 0 && h.hash == 0 {
            continue;
        }
        let g = Ghobject::new(h.clone(), r.next(), ShardId(r.next() as i8));
        assert_eq!(
            from_slice::<Hobject>(&h.encode_to_vec().unwrap()).unwrap(),
            h
        );
        assert_eq!(
            from_slice::<Ghobject>(&g.encode_to_vec().unwrap()).unwrap(),
            g
        );
        let l = ObjectLocator {
            pool: r.next() as i64,
            key: r.bytes(3),
            nspace: r.bytes(2),
            hash: -1,
        };
        assert_eq!(
            from_slice::<ObjectLocator>(&l.encode_to_vec().unwrap()).unwrap(),
            l
        );
        let l2 = ObjectLocator {
            key: vec![],
            hash: (r.next() % 1000) as i64,
            ..l
        };
        let b = l2.encode_to_vec().unwrap();
        assert_eq!(b[1], if l2.hash != -1 { 6 } else { 3 });
        assert_eq!(from_slice::<ObjectLocator>(&b).unwrap(), l2);
    }
}
