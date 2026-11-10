// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! otp scenarios (spec/cls_otp.md) on MemStore.
mod common;
use cls::errno::*;
use cls::mem::MemStore;
use cls::otp::*;
use common::*;
use denc::types::UTime;

const O: &str = "otp_obj";
/// RFC 4226/6238 test secret "12345678901234567890" in hex.
const HEXSEED: &str = "3132333435363738393031323334353637383930";
const SEED: &[u8] = b"12345678901234567890";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn info(id: &str, seed: &str, st: u8) -> OtpInfo {
    OtpInfo {
        id: id.into(),
        seed: seed.into(),
        seed_type: st,
        ..Default::default()
    }
}
fn set(s: &mut MemStore, v: Vec<OtpInfo>) -> i32 {
    call(s, O, "otp", "otp_set", &e(&SetOp { entries: v })).ret
}
fn check(s: &mut MemStore, id: &str, val: &str, token: &str) -> i32 {
    let op = CheckOp {
        id: id.into(),
        val: val.into(),
        token: token.into(),
    };
    call(s, O, "otp", "otp_check", &e(&op)).ret
}
fn result(s: &mut MemStore, id: &str, token: &str) -> OtpCheck {
    let op = CheckOp {
        id: id.into(),
        val: vec![],
        token: token.into(),
    };
    d::<GetResultReply>(&ok(s, O, "otp", "otp_get_result", &e(&op))).result
}
fn get(s: &mut MemStore, all: bool, ids: &[&str]) -> Vec<OtpInfo> {
    let op = GetOp {
        get_all: all,
        ids: ids.iter().map(|i| i.as_bytes().to_vec()).collect(),
    };
    d::<GetReply>(&ok(s, O, "otp", "otp_get", &e(&op))).found_entries
}
fn at(s: &mut MemStore, sec: u32) {
    s.env.now = UTime::new(sec, 0);
}
fn instance(s: &MemStore, id: &str) -> Instance {
    d(s.omap_get(O, &format!("otp/{id}")).unwrap())
}

#[test]
fn sha1_vectors() {
    assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(
        hex(&sha1(b"abc")),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        hex(&sha1(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
    assert_eq!(
        hex(&sha1(&vec![b'a'; 1_000_000])),
        "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
    );
    // padding boundaries (55, 56, 63, 64, 65 bytes) must not panic and must differ
    let mut seen = std::collections::HashSet::new();
    for n in [55usize, 56, 57, 63, 64, 65, 119, 120] {
        assert!(seen.insert(sha1(&vec![7u8; n])));
    }
}

#[test]
fn hmac_vectors() {
    assert_eq!(
        hex(&hmac_sha1(&[0x0b; 20], b"Hi There")),
        "b617318655057264e28bc0b6fb378c8ef146be00"
    );
    assert_eq!(
        hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    );
    assert_eq!(
        hex(&hmac_sha1(
            &[0xaa; 80],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        )),
        "aa4ae5e15272d00e95705637ce8a3b55ed402112"
    );
}

#[test]
fn hotp_rfc4226_and_totp_rfc6238() {
    let want = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];
    for (i, w) in want.iter().enumerate() {
        assert_eq!(hotp(SEED, i as u64, 6), *w);
    }
    for (t, v) in [
        (59u32, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
    ] {
        assert_eq!(
            totp_validate(SEED, t, 30, 0, 0, v.as_bytes()),
            Some(0),
            "t={t}"
        );
        assert_eq!(totp_validate(SEED, t, 30, 0, 0, b"00000000"), None);
    }
    // digits outside 6..=8 and step 0 never validate
    assert_eq!(totp_validate(SEED, 59, 30, 0, 2, b"12345"), None);
    assert_eq!(totp_validate(SEED, 59, 30, 0, 2, b"123456789"), None);
    assert_eq!(totp_validate(SEED, 59, 0, 0, 2, b"94287082"), None);
    // result = absolute displacement from t; t-d and t+d both give d
    for (ctr, d) in [
        (37037036u64, 0),
        (37037038, 2),
        (37037034, 2),
        (37037035, 1),
    ] {
        let v = hotp(SEED, ctr, 6);
        assert_eq!(
            totp_validate(SEED, 1111111109, 30, 0, 2, v.as_bytes()),
            Some(d),
            "counter {ctr}"
        );
    }
    // the value is a C string: it ends at the first NUL
    assert_eq!(
        totp_validate(SEED, 1111111109, 30, 0, 0, b"07081804\0junk"),
        Some(0)
    );
    // counters wrap modulo 2^64 below 0 (no lower bound)
    let v = hotp(SEED, u64::MAX, 6);
    assert_eq!(totp_validate(SEED, 0, 30, 0, 1, v.as_bytes()), Some(1));
    // time offset shifts the counter
    let v = hotp(SEED, (1111111109 - 60) / 30, 6);
    assert_eq!(
        totp_validate(SEED, 1111111109, 30, 60, 0, v.as_bytes()),
        Some(0)
    );
    // huge windows are clamped, not looped for ever
    assert_eq!(totp_validate(SEED, 59, 30, 0, u32::MAX, b"000000"), None);
}

#[test]
fn registry() {
    use cls::registry::*;
    assert_eq!(methods("otp").len(), 6);
    for (m, f) in [
        ("otp_set", RW),
        ("otp_get", RD),
        ("otp_check", RW),
        ("otp_get_result", RD),
        ("otp_remove", RW),
        ("get_current_time", RD),
    ] {
        assert_eq!(lookup("otp", m).unwrap().flags, f, "{m}");
    }
}

#[test]
fn seed_parsing() {
    assert_eq!(parse_seed(b"00ff7F", SEED_HEX).unwrap(), [0, 255, 127]);
    assert_eq!(parse_seed(b"", SEED_HEX).unwrap(), Vec::<u8>::new());
    assert_eq!(parse_seed(b"0", SEED_HEX), None, "odd length");
    assert_eq!(parse_seed(b"zz", SEED_HEX), None);
    assert_eq!(parse_seed(b"0g", 0), None, "unknown seed type = hex");
    // RFC 4648 vectors
    assert_eq!(
        parse_seed(b"MZXW6YTBOI======", SEED_BASE32).unwrap(),
        b"foobar"
    );
    assert_eq!(parse_seed(b"MZXW6YTBOI", SEED_BASE32).unwrap(), b"foobar");
    assert_eq!(parse_seed(b"mzxw6ytboi", SEED_BASE32).unwrap(), b"foobar");
    assert_eq!(parse_seed(b"MY======", SEED_BASE32).unwrap(), b"f");
    assert_eq!(
        parse_seed(b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", SEED_BASE32).unwrap(),
        SEED
    );
    // liboath: spaces dropped, implicit padding for lengths 2/4/5/7 mod 8
    assert_eq!(parse_seed(b"MZXW 6YTB", SEED_BASE32).unwrap(), b"fooba");
    assert_eq!(parse_seed(b" MY == ==== ", SEED_BASE32).unwrap(), b"f");
    assert_eq!(parse_seed(b"MY==", SEED_BASE32).unwrap(), b"f");
    assert_eq!(parse_seed(b"MZXW6", SEED_BASE32).unwrap(), b"foo");
    assert_eq!(parse_seed(b"MZXW6YQ", SEED_BASE32).unwrap(), b"foob");
    assert_eq!(parse_seed(b"", SEED_BASE32).unwrap(), Vec::<u8>::new());
    // a padded group may be followed by further groups
    assert_eq!(
        parse_seed(b"MY======MZXW6YTB", SEED_BASE32).unwrap(),
        b"ffooba"
    );
    for bad in [
        &b"M"[..],     // 1 mod 8: never padded
        b"MZX",        // 3 mod 8
        b"MZXW6Y",     // 6 mod 8
        b"MY=",        // 3 chars incl. '=': not padded, short
        b"M=======",   // one data char
        b"MZX=====",   // three data chars
        b"MY=A====",   // data after '=' inside a group
        b"MZXW?6YTB",  // not in the alphabet
        b"MZXW\t6YTB", // only ' ' is dropped
        b"MZXW6YTB\0", // NUL counts (full length decoded)
    ] {
        assert_eq!(parse_seed(bad, SEED_BASE32), None, "{bad:?}");
    }
    // hex is a C string: decoding stops at the first NUL
    assert_eq!(parse_seed(b"0aff\0zz", SEED_HEX).unwrap(), [10, 255]);
    assert_eq!(
        parse_seed(b"MZXW1", SEED_BASE32),
        None,
        "1 is not in the alphabet"
    );
}

#[test]
fn set_get_remove_and_stored_bytes() {
    let mut s = MemStore::new();
    assert_eq!(
        set(
            &mut s,
            vec![info("b", HEXSEED, SEED_HEX), info("a", "6162", SEED_HEX)]
        ),
        0
    );
    // header: (1,1,len) set<string> {"a","b"}
    assert_eq!(
        s.omap_get(O, "header").unwrap(),
        [
            1, 1, 14, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, b'a', 1, 0, 0, 0, b'b'
        ]
    );
    let a = &get(&mut s, true, &[])[0];
    assert_eq!(
        (a.id.as_slice(), a.seed_bin.as_slice()),
        (b"a".as_slice(), b"ab".as_slice())
    );
    // exact otp_info bytes of "a"
    let want = cat(&[
        &[1, 1, 0, 0, 0, 0],
        &[2],
        &[1, 0, 0, 0, b'a'],
        &[4, 0, 0, 0, b'6', b'1', b'6', b'2'],
        &[1],
        &[2, 0, 0, 0, b'a', b'b'],
        &0i32.to_le_bytes(),
        &30u32.to_le_bytes(),
        &2u32.to_le_bytes(),
    ]);
    let mut want = want;
    let l = (want.len() - 6) as u32;
    want[2..6].copy_from_slice(&l.to_le_bytes());
    assert_eq!(e(a), want);
    // request order, unknown ids skipped
    let ids: Vec<_> = get(&mut s, false, &["b", "zz", "a"])
        .into_iter()
        .map(|i| i.id)
        .collect();
    assert_eq!(ids, vec![b"b".to_vec(), b"a".to_vec()]);
    // remove: unknown ignored; header untouched when nothing removed
    let rm = |s: &mut MemStore, ids: &[&str]| {
        let op = RemoveOp {
            ids: ids.iter().map(|i| i.as_bytes().to_vec()).collect(),
        };
        call(s, O, "otp", "otp_remove", &e(&op)).ret
    };
    let hdr = s.omap_get(O, "header").unwrap().to_vec();
    assert_eq!(rm(&mut s, &["nope"]), 0);
    assert_eq!(s.omap_get(O, "header").unwrap(), hdr);
    assert_eq!(rm(&mut s, &["a", "nope"]), 0);
    assert!(s.omap_get(O, "otp/a").is_none());
    assert_eq!(get(&mut s, true, &[]).len(), 1);
    // bad seed rejects the whole call
    let before = s.objects.clone();
    assert_eq!(
        set(
            &mut s,
            vec![info("c", "6162", SEED_HEX), info("d", "xyz", SEED_HEX)]
        ),
        EINVAL
    );
    assert_eq!(s.objects, before);
}

#[test]
fn check_success_replay_and_results() {
    let mut s = MemStore::new();
    set(&mut s, vec![info("u", HEXSEED, SEED_HEX)]);
    at(&mut s, 1111111109);
    assert_eq!(check(&mut s, "u", "07081804", "t1"), 0);
    let r = result(&mut s, "u", "t1");
    assert_eq!(
        (r.result, r.timestamp),
        (CHECK_SUCCESS, UTime::new(1111111109, 0))
    );
    let i = instance(&s, "u");
    assert_eq!(
        i.last_success,
        1111111109 / 30,
        "index = displacement + counter"
    );
    // same code again: replay -> FAIL
    assert_eq!(check(&mut s, "u", "07081804", "t2"), 0);
    assert_eq!(result(&mut s, "u", "t2").result, CHECK_FAIL);
    // wrong code, unknown token
    assert_eq!(check(&mut s, "u", "00000000", "t3"), 0);
    assert_eq!(result(&mut s, "u", "t3").result, CHECK_FAIL);
    assert_eq!(result(&mut s, "u", "nope").result, CHECK_UNKNOWN);
    // newer code (next step) works
    at(&mut s, 1111111111);
    assert_eq!(check(&mut s, "u", "14050471", "t4"), 0);
    assert_eq!(result(&mut s, "u", "t4").result, CHECK_SUCCESS);
    // unknown id
    err(
        &mut s,
        O,
        "otp",
        "otp_check",
        &e(&CheckOp {
            id: "zz".into(),
            ..Default::default()
        }),
        ENOENT,
    );
    err(
        &mut s,
        O,
        "otp",
        "otp_get_result",
        &e(&CheckOp {
            id: "zz".into(),
            ..Default::default()
        }),
        ENOENT,
    );
}

#[test]
fn window_boundaries() {
    let mut s = MemStore::new();
    set(&mut s, vec![info("u", HEXSEED, SEED_HEX)]);
    let now = 1_700_000_010u32;
    at(&mut s, now);
    let t = (now / 30) as u64;
    // counters t-2 .. t+2 are inside the default window; t+3 and t-3 are not
    for (i, (delta, ok_)) in [(3i64, false), (-3, false), (2, true)].iter().enumerate() {
        let v = hotp(SEED, (t as i64 + delta) as u64, 6);
        let tok = format!("w{i}");
        assert_eq!(check(&mut s, "u", &v, &tok), 0);
        let r = result(&mut s, "u", &tok).result;
        assert_eq!(
            r,
            if *ok_ { CHECK_SUCCESS } else { CHECK_FAIL },
            "delta {delta}"
        );
    }
    // a past code (t-1) is older than last_success (t+2) -> replay
    let v = hotp(SEED, t - 1, 6);
    check(&mut s, "u", &v, "old");
    assert_eq!(result(&mut s, "u", "old").result, CHECK_FAIL);
}

/// Classic replay index = |displacement| + current step: after a success at `t`, the older code
/// `t-1` still counts as `t+1` and succeeds, and then `t+1` is rejected as already used.
#[test]
fn replay_index_follows_classic_displacement() {
    let mut s = MemStore::new();
    set(&mut s, vec![info("u", HEXSEED, SEED_HEX)]);
    let now = 1_700_000_010u32;
    at(&mut s, now);
    let t = (now / 30) as u64;
    for (i, (ctr, ok_, last)) in [
        (t, true, t),
        (t - 1, true, t + 1),
        (t + 1, false, t + 1),
        (t - 2, true, t + 2),
    ]
    .iter()
    .enumerate()
    {
        let tok = format!("r{i}");
        assert_eq!(check(&mut s, "u", &hotp(SEED, *ctr, 6), &tok), 0);
        assert_eq!(
            result(&mut s, "u", &tok).result,
            if *ok_ { CHECK_SUCCESS } else { CHECK_FAIL },
            "counter t{:+}",
            *ctr as i64 - t as i64
        );
        assert_eq!(instance(&s, "u").last_success, *last);
    }
}

#[test]
fn rate_limit_and_expiry() {
    let mut s = MemStore::new();
    set(&mut s, vec![info("u", HEXSEED, SEED_HEX)]);
    at(&mut s, 1000);
    for i in 0..5 {
        assert_eq!(check(&mut s, "u", "000000", &format!("t{i}")), 0);
    }
    let before = s.objects.clone();
    assert_eq!(
        check(&mut s, "u", "000000", "t5"),
        0,
        "rate limited call still succeeds"
    );
    assert_eq!(s.objects, before, "and writes nothing");
    assert_eq!(result(&mut s, "u", "t5").result, CHECK_UNKNOWN);
    assert_eq!(result(&mut s, "u", "t4").result, CHECK_FAIL);
    // after step_size seconds the old checks are trimmed
    at(&mut s, 1031);
    assert_eq!(result(&mut s, "u", "t4").result, CHECK_UNKNOWN);
    assert_eq!(check(&mut s, "u", "000000", "t6"), 0);
    assert_eq!(instance(&s, "u").last_checks.len(), 1);
}

#[test]
fn set_keeps_state_and_step_zero_is_safe() {
    let mut s = MemStore::new();
    set(&mut s, vec![info("u", HEXSEED, SEED_HEX)]);
    at(&mut s, 1111111109);
    check(&mut s, "u", "07081804", "t1");
    let ls = instance(&s, "u").last_success;
    assert_ne!(ls, 0);
    let mut i2 = info("u", HEXSEED, SEED_HEX);
    i2.window = 7;
    set(&mut s, vec![i2]);
    let i = instance(&s, "u");
    assert_eq!(
        (i.last_success, i.last_checks.len(), i.otp.window),
        (ls, 1, 7)
    );
    // step_size 0 would divide by zero upstream
    let mut z = info("z", HEXSEED, SEED_HEX);
    z.step_size = 0;
    set(&mut s, vec![z]);
    assert_eq!(check(&mut s, "z", "07081804", "t"), 0);
    assert_eq!(result(&mut s, "z", "t").result, CHECK_FAIL);
}

#[test]
fn current_time_and_garbage() {
    let mut s = MemStore::new();
    at(&mut s, 77);
    let out = ok(&mut s, O, "otp", "get_current_time", &e(&CurrentTimeOp {}));
    assert_eq!(out, [1, 1, 8, 0, 0, 0, 77, 0, 0, 0, 0, 0, 0, 0]);
    for m in [
        "otp_set",
        "otp_get",
        "otp_check",
        "otp_get_result",
        "otp_remove",
        "get_current_time",
    ] {
        err(&mut s, O, "otp", m, &[9], EINVAL);
    }
    // corrupt stored instance / header -> EIO
    set(&mut s, vec![info("u", HEXSEED, SEED_HEX)]);
    s.objects
        .get_mut(O)
        .unwrap()
        .omap
        .insert(b"otp/u".to_vec(), vec![1, 2, 3]);
    err(
        &mut s,
        O,
        "otp",
        "otp_check",
        &e(&CheckOp {
            id: "u".into(),
            ..Default::default()
        }),
        EIO,
    );
    err(
        &mut s,
        O,
        "otp",
        "otp_get",
        &e(&GetOp {
            get_all: true,
            ids: vec![],
        }),
        EIO,
    );
    s.objects
        .get_mut(O)
        .unwrap()
        .omap
        .insert(b"header".to_vec(), vec![1]);
    err(
        &mut s,
        O,
        "otp",
        "otp_get",
        &e(&GetOp {
            get_all: true,
            ids: vec![],
        }),
        EIO,
    );
}

/// Two-message scenario (recorded for the classic differential): `get_current_time` on an object
/// that holds an instance; the reply is the wall clock.
#[test]
fn current_time_after_set() {
    let mut s = MemStore::new();
    set(&mut s, vec![info("u", HEXSEED, SEED_HEX)]);
    at(&mut s, 99);
    let out = ok(&mut s, O, "otp", "get_current_time", &e(&CurrentTimeOp {}));
    assert_eq!(out, [1, 1, 8, 0, 0, 0, 99, 0, 0, 0, 0, 0, 0, 0]);
}
