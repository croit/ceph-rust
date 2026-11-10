// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cmpomap scenarios (spec/cls_cmpomap.md) on MemStore.
mod common;
use cls::cmpomap::*;
use cls::errno::*;
use cls::mem::MemStore;
use common::*;

const O: &str = "obj";

fn op(mode: u8, cmp: u8, kv: &[(&str, &[u8])], dflt: Option<&[u8]>) -> CmpOp {
    CmpOp {
        mode,
        comparison: cmp,
        values: kv
            .iter()
            .map(|(k, v)| (k.as_bytes().to_vec(), v.to_vec()))
            .collect(),
        default_value: dflt.map(|d| d.to_vec()),
    }
}
fn seed(s: &mut MemStore, kv: &[(&str, &[u8])]) {
    let o = s.objects.entry(O.into()).or_default();
    for (k, v) in kv {
        o.omap.insert(k.as_bytes().to_vec(), v.to_vec());
    }
}
fn get(s: &MemStore, k: &str) -> Option<Vec<u8>> {
    s.omap_get(O, k).map(|v| v.to_vec())
}
fn vals(o: &CmpOp) -> Vec<u8> {
    o.to_bytes(true)
}
fn n(v: u64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

#[test]
fn registry_and_exact_bytes() {
    use cls::registry::*;
    assert_eq!(methods("cmpomap").len(), 3);
    assert_eq!(lookup("cmpomap", "cmp_vals").unwrap().flags, RD);
    assert_eq!(lookup("cmpomap", "cmp_set_vals").unwrap().flags, RW);
    assert_eq!(lookup("cmpomap", "cmp_rm_keys").unwrap().flags, RW);
    // 01 01 len | mode=2 cmp=3 | count=1 | "k" | bytes "ab" | optional absent
    let o = op(MODE_U64, OP_GT, &[("k", b"ab")], None);
    assert_eq!(
        o.to_bytes(true),
        [
            1, 1, 18, 0, 0, 0, 2, 3, 1, 0, 0, 0, 1, 0, 0, 0, b'k', 2, 0, 0, 0, b'a', b'b', 0
        ]
    );
    // rm_keys has no optional
    assert_eq!(o.to_bytes(false).len(), 23);
}

#[test]
fn cmp_vals_string_ops() {
    let mut s = MemStore::new();
    seed(&mut s, &[("a", b"m"), ("b", b"m")]);
    // input (left) vs stored (right)
    for (c, input, ok_) in [
        (OP_EQ, b"m".as_slice(), true),
        (OP_EQ, b"n", false),
        (OP_NE, b"n", true),
        (OP_GT, b"n", true),
        (OP_GT, b"m", false),
        (OP_GTE, b"m", true),
        (OP_LT, b"a", true),
        (OP_LT, b"m", false),
        (OP_LTE, b"m", true),
        (OP_LTE, b"z", false),
    ] {
        let o = op(MODE_STRING, c, &[("a", input), ("b", input)], None);
        let r = call(&mut s, O, "cmpomap", "cmp_vals", &vals(&o));
        assert_eq!(r.ret, if ok_ { 0 } else { ECANCELED }, "op {c} {input:?}");
    }
    // lexicographic bytes: "m" < "ma"
    let o = op(MODE_STRING, OP_LT, &[("a", b"ma")], None);
    err(&mut s, O, "cmpomap", "cmp_vals", &vals(&o), ECANCELED);
    let o = op(MODE_STRING, OP_GT, &[("a", b"ma")], None);
    ok(&mut s, O, "cmpomap", "cmp_vals", &vals(&o));
}

#[test]
fn cmp_vals_u64_default_and_missing() {
    let mut s = MemStore::new();
    seed(&mut s, &[("a", &n(5)), ("e", b"")]);
    let o = op(MODE_U64, OP_GT, &[("a", &n(6))], None);
    ok(&mut s, O, "cmpomap", "cmp_vals", &vals(&o));
    let o = op(MODE_U64, OP_EQ, &[("a", &n(6))], None);
    err(&mut s, O, "cmpomap", "cmp_vals", &vals(&o), ECANCELED);
    // trailing input bytes ignored
    let mut longer = n(5);
    longer.extend_from_slice(b"zz");
    let o = op(MODE_U64, OP_EQ, &[("a", &longer)], None);
    ok(&mut s, O, "cmpomap", "cmp_vals", &vals(&o));
    // empty stored value = 0
    let o = op(MODE_U64, OP_EQ, &[("e", &n(0))], None);
    ok(&mut s, O, "cmpomap", "cmp_vals", &vals(&o));
    // missing key: ECANCELED without default, compared against default with one
    let o = op(MODE_U64, OP_EQ, &[("x", &n(0))], None);
    err(&mut s, O, "cmpomap", "cmp_vals", &vals(&o), ECANCELED);
    let o = op(MODE_U64, OP_EQ, &[("x", &n(7))], Some(&n(7)));
    ok(&mut s, O, "cmpomap", "cmp_vals", &vals(&o));
    // empty values map
    ok(
        &mut s,
        O,
        "cmpomap",
        "cmp_vals",
        &vals(&op(MODE_U64, OP_EQ, &[], None)),
    );
}

#[test]
fn cmp_vals_error_codes() {
    let mut s = MemStore::new();
    seed(&mut s, &[("a", &n(5)), ("short", b"123")]);
    let o = op(MODE_U64, OP_EQ, &[("short", &n(1))], None);
    err(&mut s, O, "cmpomap", "cmp_vals", &vals(&o), EIO);
    let o = op(MODE_U64, OP_EQ, &[("a", b"1234567")], None);
    err(&mut s, O, "cmpomap", "cmp_vals", &vals(&o), EINVAL);
    let o = op(7, OP_EQ, &[("a", &n(5))], None);
    err(&mut s, O, "cmpomap", "cmp_vals", &vals(&o), EINVAL);
    let o = op(MODE_STRING, 9, &[("a", b"x")], None);
    err(&mut s, O, "cmpomap", "cmp_vals", &vals(&o), EINVAL);
    err(
        &mut s,
        O,
        "cmpomap",
        "cmp_vals",
        &[1, 1, 5, 0, 0, 0, 1],
        EINVAL,
    );
    err(&mut s, O, "cmpomap", "cmp_vals", &[], EINVAL);
}

#[test]
fn cmp_set_vals_semantics() {
    let mut s = MemStore::new();
    seed(&mut s, &[("a", &n(5)), ("b", &n(9)), ("bad", b"xy")]);
    // GT: write where input > stored; missing keys skipped without default
    let o = op(
        MODE_U64,
        OP_GT,
        &[("a", &n(6)), ("b", &n(6)), ("bad", &n(1)), ("new", &n(1))],
        None,
    );
    ok(&mut s, O, "cmpomap", "cmp_set_vals", &vals(&o));
    assert_eq!(get(&s, "a"), Some(n(6)), "6 > 5 written");
    assert_eq!(get(&s, "b"), Some(n(9)), "6 > 9 false");
    assert_eq!(get(&s, "bad"), Some(b"xy".to_vec()), "EIO = false");
    assert_eq!(get(&s, "new"), None);
    // with default: missing key compared against default, true -> inserted
    let o = op(
        MODE_U64,
        OP_GT,
        &[("new", &n(1)), ("new2", &n(0))],
        Some(&n(0)),
    );
    ok(&mut s, O, "cmpomap", "cmp_set_vals", &vals(&o));
    assert_eq!(get(&s, "new"), Some(n(1)));
    assert_eq!(get(&s, "new2"), None, "0 > 0 false");
    // nothing to write
    let before = s.objects.clone();
    let o = op(MODE_STRING, OP_EQ, &[("zz", b"1")], None);
    ok(&mut s, O, "cmpomap", "cmp_set_vals", &vals(&o));
    assert_eq!(s.objects, before);
    // invalid mode aborts with EINVAL
    let o = op(0, OP_EQ, &[("a", b"1")], None);
    err(&mut s, O, "cmpomap", "cmp_set_vals", &vals(&o), EINVAL);
}

#[test]
fn cmp_rm_keys_semantics() {
    let mut s = MemStore::new();
    seed(
        &mut s,
        &[("a", &n(5)), ("b", &n(9)), ("c", &n(1)), ("bad", b"q")],
    );
    let o = op(
        MODE_U64,
        OP_GTE,
        &[
            ("a", &n(5)),
            ("b", &n(5)),
            ("bad", &n(5)),
            ("c", &n(2)),
            ("gone", &n(1)),
        ],
        None,
    );
    ok(&mut s, O, "cmpomap", "cmp_rm_keys", &o.to_bytes(false));
    assert_eq!(get(&s, "a"), None, "5 >= 5");
    assert_eq!(get(&s, "b"), Some(n(9)), "5 >= 9 false");
    assert_eq!(get(&s, "c"), None, "2 >= 1");
    assert_eq!(get(&s, "bad"), Some(b"q".to_vec()), "EIO = false");
    // error aborts and discards the earlier remove of the same call
    let mut s2 = MemStore::new();
    seed(&mut s2, &[("a", &n(1)), ("b", &n(1))]);
    let o = op(MODE_U64, OP_EQ, &[("a", &n(1)), ("b", b"x")], None);
    err(
        &mut s2,
        O,
        "cmpomap",
        "cmp_rm_keys",
        &o.to_bytes(false),
        EINVAL,
    );
    assert_eq!(get(&s2, "a"), Some(n(1)));
}

/// Review F3: string mode orders values like a classic OSD of the same architecture orders `bufferlist`s (bytes as the
/// platform C `char`: 0x80 < 0x7f on x86_64, 0x80 > 0x7f on aarch64 Linux); a proper prefix sorts first.
#[test]
fn cmp_vals_string_order_is_classic_char_order() {
    let signed = (0x80u8 as std::ffi::c_char) < 0;
    #[cfg(target_arch = "x86_64")]
    assert!(signed, "x86_64 classic compares signed chars");
    let mut s = MemStore::new();
    seed(&mut s, &[("a", &[0x80])]);
    // input (left) GT stored (right): 0x7f > 0x80 holds for signed chars only
    let o = op(MODE_STRING, OP_GT, &[("a", &[0x7f])], None);
    let r = call(&mut s, O, "cmpomap", "cmp_vals", &vals(&o));
    assert_eq!(r.ret, if signed { 0 } else { ECANCELED });
    let o = op(MODE_STRING, OP_LT, &[("a", &[0x7f])], None);
    let r = call(&mut s, O, "cmpomap", "cmp_vals", &vals(&o));
    assert_eq!(r.ret, if signed { ECANCELED } else { 0 });
    assert_eq!(
        cls::cmpomap::bufferlist_cmp(&[0xff], &[0xff, 0]),
        std::cmp::Ordering::Less,
        "prefix first"
    );
}
