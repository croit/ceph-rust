// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! numops scenarios (spec/cls_numops.md) on MemStore.
mod common;
use cls::errno::*;
use cls::mem::MemStore;
use common::*;

const O: &str = "obj";

fn str_enc(s: &[u8]) -> Vec<u8> {
    cat(&[&(s.len() as u32).to_le_bytes(), s])
}
fn kd(key: &str, diff: &str) -> Vec<u8> {
    cat(&[&str_enc(key.as_bytes()), &str_enc(diff.as_bytes())])
}
fn nval(s: &MemStore, key: &str) -> String {
    String::from_utf8(s.omap_get(O, key).unwrap().to_vec()).unwrap()
}
fn seed_num(s: &mut MemStore, key: &str, val: &[u8]) {
    let ob = s.objects.entry(O.into()).or_default();
    ob.omap.insert(key.as_bytes().to_vec(), val.to_vec());
}

#[test]
fn numops_registry() {
    use cls::registry::*;
    assert_eq!(methods("numops").len(), 2);
    assert_eq!(lookup("numops", "add").unwrap().flags, RW);
    assert_eq!(lookup("numops", "mul").unwrap().flags, RW);
}

#[test]
fn fmt_g10() {
    use cls::numops::fmt_g10;
    for (v, t) in [
        (0.0, "0"),
        (-0.0, "-0"),
        (1.0, "1"),
        (0.5, "0.5"),
        (3.501, "3.501"),
        (0.1 + 0.2, "0.3"),
        (123456789.0, "123456789"),
        (1234567890.0, "1234567890"),
        (12345678901.0, "1.23456789e+10"),
        (1e10, "1e+10"),
        (1e100, "1e+100"),
        (0.0001, "0.0001"),
        (0.00001, "1e-05"),
        (0.000123456, "0.000123456"),
        (-2.5e-7, "-2.5e-07"),
        (1.0 / 3.0, "0.3333333333"),
        (2.0 / 3.0, "0.6666666667"),
        (99999.99999999, "100000"),
        (9999999999.5, "1e+10"),
        (f64::INFINITY, "inf"),
        (f64::NEG_INFINITY, "-inf"),
    ] {
        assert_eq!(fmt_g10(v), t, "{v:e}");
    }
}

#[test]
fn strtod_grammar() {
    use cls::numops::strtod;
    assert_eq!(strtod(b"  -1.5e2xyz"), (-150.0, 8));
    assert_eq!(strtod(b"1e"), (1.0, 1));
    assert_eq!(strtod(b".5"), (0.5, 2));
    assert_eq!(strtod(b"5."), (5.0, 2));
    assert_eq!(strtod(b"."), (0.0, 0));
    assert_eq!(strtod(b"0x1.8p1"), (3.0, 7));
    assert_eq!(strtod(b"0xg"), (0.0, 1));
    assert_eq!(strtod(b"InFiNiTy").0, f64::INFINITY);
    assert_eq!(strtod(b"nan(abc)").1, 8);
    assert_eq!(strtod(b"abc"), (0.0, 0));
}

#[test]
fn hex_float_range_and_rounding() {
    use cls::numops::strtod;
    for (text, bits) in [
        ("0x0p99999".to_string(), 0),
        ("-0x0p99999".to_string(), 1 << 63),
        (format!("0x1{}p-1024", "0".repeat(256)), 1f64.to_bits()),
        (format!("0x0.{}1p1200", "0".repeat(299)), 1f64.to_bits()),
        ("0x1p-1074".to_string(), 1),
        ("0x1p-1075".to_string(), 0),
        ("0x3p-1075".to_string(), 2),
        ("0x5p-1075".to_string(), 2),
        ("0x0.fffffffffffff8p-1022".to_string(), 1 << 52),
        ("0x1.0000000000000001p-1075".to_string(), 1),
        ("0x1.fffffffffffffp1023".to_string(), f64::MAX.to_bits()),
        (
            "0x1.fffffffffffff8p1023".to_string(),
            f64::INFINITY.to_bits(),
        ),
        ("0x1.00000000000008".to_string(), 1f64.to_bits()),
        ("0x1.000000000000080001".to_string(), 1f64.to_bits() + 1),
        ("0x1.00000000000018".to_string(), 1f64.to_bits() + 2),
    ] {
        let (value, consumed) = strtod(text.as_bytes());
        assert_eq!(consumed, text.len(), "{text}");
        assert_eq!(value.to_bits(), bits, "{text}");
    }
    // Exact powers and halfway cases over every normal exponent, without a platform oracle.
    for exponent in -1022i32..=1023 {
        let bits = ((exponent + 1023) as u64) << 52;
        for (significand, expected) in [
            ("1", bits),
            ("1.00000000000008", bits),
            ("1.000000000000080001", bits + 1),
        ] {
            let text = format!("0x{significand}p{exponent}");
            assert_eq!(strtod(text.as_bytes()).0.to_bits(), expected, "{text}");
        }
    }
}

#[test]
fn hex_float_arithmetic_preserves_finite_values() {
    let mut s = MemStore::new();
    let one = format!("0x1{}p-1024", "0".repeat(256));
    seed_num(&mut s, "k", b"2");
    ok(&mut s, O, "numops", "add", &kd("k", &one));
    assert_eq!(nval(&s, "k"), "3");
    seed_num(&mut s, "k", one.as_bytes());
    ok(&mut s, O, "numops", "mul", &kd("k", "2"));
    assert_eq!(nval(&s, "k"), "2");
}

#[test]
fn add_mul() {
    let mut s = MemStore::new();
    s.objects.insert(O.into(), Default::default());
    seed_num(&mut s, "k", b"");
    ok(&mut s, O, "numops", "add", &kd("k", "0.5"));
    assert_eq!(nval(&s, "k"), "0.5");
    ok(&mut s, O, "numops", "add", &kd("k", "3.001"));
    assert_eq!(nval(&s, "k"), "3.501");
    ok(&mut s, O, "numops", "mul", &kd("k", "2"));
    assert_eq!(nval(&s, "k"), "7.002");
    ok(&mut s, O, "numops", "add", &kd("k", "-7.002"));
    assert_eq!(nval(&s, "k"), "0");
    seed_num(&mut s, "big", b"1e300");
    ok(&mut s, O, "numops", "mul", &kd("big", "1e300"));
    assert_eq!(nval(&s, "big"), "inf");
    // empty diff = 0
    seed_num(&mut s, "z", b"5");
    ok(&mut s, O, "numops", "mul", &kd("z", ""));
    assert_eq!(nval(&s, "z"), "0");
    // NUL truncates the diff
    ok(
        &mut s,
        O,
        "numops",
        "add",
        &cat(&[&str_enc(b"z"), &str_enc(b"2\0junk")]),
    );
    assert_eq!(nval(&s, "z"), "2");
}

#[test]
fn missing_key_and_object_start_from_zero() {
    // gtest ceph_test_cls_numops: add to a key of a non-existing object succeeds
    let mut s = MemStore::new();
    ok(&mut s, O, "numops", "add", &kd("my-key", "0.5"));
    assert_eq!(nval(&s, "my-key"), "0.5");
    ok(&mut s, O, "numops", "mul", &kd("other", "3"));
    assert_eq!(nval(&s, "other"), "0");
}

#[test]
fn errors() {
    let mut s = MemStore::new();
    s.objects.insert(O.into(), Default::default());
    err(&mut s, O, "numops", "add", &[], EINVAL);
    err(&mut s, O, "numops", "add", &str_enc(b"k"), EINVAL);
    err(&mut s, O, "numops", "add", &kd("k", "abc"), EINVAL);
    err(&mut s, O, "numops", "mul", &kd("k", " "), EINVAL);
    err(&mut s, O, "numops", "add", &kd("k", "1x"), EINVAL);
    seed_num(&mut s, "k", b"some-text");
    err(&mut s, O, "numops", "add", &kd("k", "2"), EBADMSG);
    assert_eq!(nval(&s, "k"), "some-text");
    seed_num(&mut s, "k", b" ");
    err(&mut s, O, "numops", "mul", &kd("k", "2"), EBADMSG);
}
