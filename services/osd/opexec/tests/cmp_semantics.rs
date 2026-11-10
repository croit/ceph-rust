// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Compare ops against classic semantics: OMAP_CMP order (review F3), CMPXATTR u64 parsing (review F4).
mod common;
use common::*;
use opwire::OsdOp;
use std::collections::BTreeMap;

/// Run `ops` as one message on object "o"; the reply result.
fn result(pg: &mut TPg, eng: &mut opexec::Engine, tid: u64, ops: Vec<OsdOp>) -> i32 {
    let mut out = run(pg, eng, 1, tid, client(7), mkop(b"o", ops));
    out.extend(settle(pg, eng));
    reply_of(&mut out, 1, tid).unwrap().result
}

fn omap_cmp(key: &[u8], val: &[u8], cop: i32) -> OsdOp {
    let mut cmp = OsdOp::read(0, 0);
    cmp.op = opwire::op::OMAP_CMP;
    let a: opwire::OmapCmpIn = BTreeMap::from([(key.to_vec(), (val.to_vec(), cop))]);
    cmp.indata = denc::to_vec(&a).unwrap().into();
    cmp
}

/// OMAP_CMP GT/LT order values like a classic OSD of the same architecture orders `bufferlist`s (bytes as the C
/// `char`: signed on x86_64); a proper prefix sorts first.
#[test]
fn omap_cmp_orders_like_classic_bufferlists() {
    let signed = (0x80u8 as std::ffi::c_char) < 0;
    #[cfg(target_arch = "x86_64")]
    assert!(signed);
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let mut set = OsdOp::read(0, 0);
    set.op = opwire::op::OMAP_SET_VALS;
    set.indata = denc::to_vec(&BTreeMap::from([(b"k".to_vec(), vec![0x80u8])]))
        .unwrap()
        .into();
    assert_eq!(result(&mut pg, &mut eng, 1, vec![set]), 0);
    let canceled = -125;
    // stored 0x80 GT 0x7f: false for signed chars
    let gt = result(&mut pg, &mut eng, 2, vec![omap_cmp(b"k", &[0x7f], 3)]);
    assert_eq!(gt, if signed { canceled } else { 0 });
    let lt = result(&mut pg, &mut eng, 3, vec![omap_cmp(b"k", &[0x7f], 5)]);
    assert_eq!(lt, if signed { 0 } else { canceled });
    // prefix: stored [0x80] LT [0x80, 0]
    assert_eq!(
        result(&mut pg, &mut eng, 4, vec![omap_cmp(b"k", &[0x80, 0], 5)]),
        0
    );
}

/// CMPXATTR u64 mode: the stored text is parsed like classic `std::from_chars` (leading digits, trailing bytes
/// ignored, no sign or whitespace); the given value is the 8-byte LE u64 after the name, `value_len` not consulted.
#[test]
fn cmpxattr_u64_parses_stored_text_like_classic() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    // a true comparison leaves the classic op result 1
    let (eq, mode_u64, einval, yes) = (1u8, 2u8, -22, 1);
    let mut tid = 0;
    let mut cmp = |pg: &mut TPg, eng: &mut opexec::Engine, stored: &[u8], op: OsdOp| {
        tid += 2;
        assert_eq!(result(pg, eng, tid, vec![OsdOp::setxattr(b"a", stored)]), 0);
        result(pg, eng, tid + 1, vec![op])
    };
    let twelve = 12u64.to_le_bytes();
    for (stored, want) in [
        (b"12\0".as_slice(), yes),
        (b"12abc", yes),
        (b"12", yes),
        (b"0012", yes),
        (b" 12", einval),
        (b"+12", einval),
        (b"abc", einval),
        (b"99999999999999999999", einval),
    ] {
        let op = OsdOp::cmpxattr(b"a", &twelve, eq, mode_u64);
        assert_eq!(
            cmp(&mut pg, &mut eng, stored, op),
            want,
            "stored {stored:?}"
        );
    }
    // value_len is not consulted: 8 bytes after the name are the value, extra bytes ignored
    let mut long = OsdOp::cmpxattr(b"a", &[twelve.as_slice(), b"xyz"].concat(), eq, mode_u64);
    assert_eq!(cmp(&mut pg, &mut eng, b"12", long.clone()), yes);
    let mut x = long.xattr();
    x.value_len = 3;
    long.set_xattr(x);
    assert_eq!(cmp(&mut pg, &mut eng, b"12", long), yes);
    // fewer than 8 bytes after the name: EINVAL
    let short = OsdOp::cmpxattr(b"a", &[1, 2, 3], eq, mode_u64);
    assert_eq!(cmp(&mut pg, &mut eng, b"12", short), einval);
}

/// Build `cmpext` with an extent length independent of the payload length.
fn cmpext(off: u64, window: u64, data: &[u8]) -> OsdOp {
    let mut op = OsdOp::cmpext(off, data.to_vec());
    let mut e = op.extent();
    e.length = window;
    op.set_extent(e);
    op
}

/// 16.2 (E8): no payload/extent length equality. The comparison walks the whole indata against the read window
/// clipped to the object (zeros past it), so a short payload compares its prefix and a long one needs zeros after.
#[test]
fn cmpext_compares_the_payload_against_the_clipped_window() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(
        result(
            &mut pg,
            &mut eng,
            1,
            vec![OsdOp::write(0, b"abcdef".to_vec())]
        ),
        0
    );
    let mismatch = |i: u64| opwire::errno::cmpext_mismatch(i);
    let cases: Vec<(u64, u64, &[u8], i32)> = vec![
        // indata shorter than the extent: only the prefix is compared
        (0, 6, b"abc", 0),
        (0, 6, b"abx", mismatch(2)),
        // indata longer than the extent: the bytes past the window must be zero
        (0, 3, b"abc", 0),
        (0, 3, b"abc\0\0\0", 0),
        (0, 3, b"abc\0x", mismatch(4)),
        // read window past EOF is empty: every payload byte must be zero
        (6, 2, b"\0\0", 0),
        (6, 2, b"g", mismatch(0)),
        // empty payload always compares equal
        (0, 3, b"", 0),
    ];
    for (i, (off, window, data, want)) in cases.into_iter().enumerate() {
        assert_eq!(
            result(
                &mut pg,
                &mut eng,
                10 + i as u64,
                vec![cmpext(off, window, data)]
            ),
            want,
            "cmpext {off} window {window} data {data:?}"
        );
    }
}
