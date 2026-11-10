// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Our encodings vs ceph-dencoder. `EMIT_SAMPLES=1 cargo test -p replwire --test oracle` writes
//! testdata/replwire/ours/*.bin; testdata/replwire/oracle.sh feeds them through dencoder
//! (decode -> encode -> export, dump_json) into oracle/. This test asserts: round trip, stored
//! samples == fresh encodings, and (raw types) dencoder's re-encoding == ours byte for byte.
mod common;
use common::*;
use denc::{Decode, Encode};
use replwire::txn::*;
use replwire::*;
use std::collections::BTreeMap;

fn emit() -> bool {
    std::env::var_os("EMIT_SAMPLES").is_some()
}

fn check_ours(name: &str, bytes: &[u8]) {
    let p = testdata(&format!("ours/{name}.bin"));
    if emit() {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
        return;
    }
    let stored =
        std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e} (EMIT_SAMPLES=1)", p.display()));
    assert_eq!(stored, bytes, "{name}: differs from stored sample");
    // dencoder re-encoding (raw types only; messages keep the payload verbatim)
    let o = testdata(&format!("oracle/{name}.bin"));
    if let Ok(re) = std::fs::read(&o) {
        assert_eq!(re, bytes, "{name}: dencoder re-encode differs from ours");
    }
}

fn raw<T: Encode + for<'a> Decode<'a> + PartialEq + std::fmt::Debug>(ty: &str, name: &str, v: &T) {
    let b = v.encode_to_vec().unwrap();
    let back: T = denc::from_slice(&b).unwrap();
    assert_eq!(&back, v, "{ty}.{name}");
    check_ours(&format!("{ty}.{name}"), &b);
}

#[test]
fn raw_types() {
    for (n, v) in object_infos() {
        raw("object_info_t", n, &v);
    }
    for (n, v) in snapsets() {
        raw("SnapSet", n, &v);
    }
    for (n, v) in snapcontexts() {
        raw("SnapContext", n, &v);
    }
    for (n, v) in recovery_infos() {
        raw("ObjectRecoveryInfo", n, &v);
    }
    for (n, v) in progress() {
        raw("ObjectRecoveryProgress", n, &v);
    }
    raw("PushOp", "a", &push_op());
    raw("PullOp", "a", &pull_op());
    raw(
        "PushReplyOp",
        "a",
        &PushReplyOp {
            soid: hobj("a.b", denc::types::SnapId(3), 5, 1),
        },
    );
    raw(
        "watch_info_t",
        "a",
        &object_infos()
            .remove(0)
            .1
            .watchers
            .into_values()
            .next()
            .unwrap(),
    );
}

#[test]
fn transactions() {
    let buf = payload();
    let t = big_txn(&buf);
    let b = t.encode_v9().unwrap();
    let back = Transaction::decode(&[], &b, DEFAULT_PAGE).unwrap();
    assert_eq!(back.trailing, 0);
    assert_eq!(back.ops, t.ops);
    assert_eq!(back.encode_v9().unwrap(), b, "v9 re-encode");
    check_ours("ObjectStore__Transaction.big_v9", &b);

    // v10: same logical ops, d part carries aligned data
    let mut t10 = t.clone();
    t10.data_features = SERVER_TENTACLE;
    let (p, d) = t10.encode_v10(DEFAULT_PAGE).unwrap();
    let back10 = Transaction::decode(&p, &d, DEFAULT_PAGE).unwrap();
    assert_eq!(back10.struct_v, 10);
    assert_eq!(back10.trailing, 0);
    assert_eq!(back10.ops, t.ops, "v10 ops == v9 ops");
    let (p2, d2) = back10.encode_v10(DEFAULT_PAGE).unwrap();
    assert_eq!((p2.as_slice(), d2.as_slice()), (p.as_slice(), d.as_slice()));
    assert!(!d.is_empty() && d.len() > 0x2000, "aligned stream used");
    // v10 without the tentacle bit in data_features: no split (as sent by classic primaries)
    let (pn, dn) = t.encode_v10(DEFAULT_PAGE).unwrap();
    let backn = Transaction::decode(&pn, &dn, DEFAULT_PAGE).unwrap();
    assert_eq!((backn.ops == t.ops, backn.trailing), (true, 0));
    // v10 with empty d: p goes in DATA
    let e = Transaction::new();
    let (pe, de) = e.encode_v10(DEFAULT_PAGE).unwrap();
    assert!(de.is_empty());
    assert!(
        Transaction::decode(&[], &pe, DEFAULT_PAGE)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn messages_roundtrip_and_samples() {
    for (n, m) in messages() {
        let (ty, ver, compat, segs) = m.encode(denc::features::ALL).unwrap();
        let back = decode_repl(ty, ver, &segs).unwrap().expect("known type");
        assert_eq!(back, m, "{}.{n}", msg_name(&m));
        assert_eq!(
            back.encode(denc::features::ALL).unwrap().3,
            segs,
            "re-encode"
        );
        if let Some(dt) = dencoder_msg_type(&m) {
            check_ours(
                &format!("{dt}.{n}"),
                &dencoder_wrapper(ty, ver, compat, &segs),
            );
        } else {
            check_ours(&format!("{}.{n}", msg_name(&m)), &segs.front);
        }
    }
    assert!(decode_repl(1, 1, &Default::default()).unwrap().is_none());
}

/// A received push (front >= `SHARED_FRONT_MIN` = one shared run of the rx buffer) keeps the payload a slice of
/// that run; the decoder must not copy every recovered byte out of the front.
#[test]
fn received_push_payload_is_shared_with_the_front() {
    let n = 128 * 1024;
    let mut op = push_op();
    op.data = vec![0x5a; n].into();
    op.data_included = BTreeMap::from([(0, n as u64)]);
    let msg = ReplMsg::Push(MOSDPGPush {
        pushes: vec![op],
        ..Default::default()
    });
    let (ty, ver, _, seg) = msg.encode(denc::features::ALL).unwrap();
    // what the session hands to the decoder for a large front (messages::decode_with_header_owned)
    let shared = bytes::Bytes::from(seg.front.clone());
    let rx = messages::Segments {
        front_zc: vec![(0, shared.clone())],
        ..Default::default()
    };
    let Some(ReplMsg::Push(back)) = decode_repl(ty, ver, &rx).unwrap() else {
        panic!("a push decodes")
    };
    assert_eq!(ReplMsg::Push(back.clone()), msg);
    let base = shared.as_ptr() as usize;
    let p = back.pushes[0].data.as_ptr() as usize;
    assert!(
        p >= base && p + n <= base + shared.len(),
        "payload is a slice of the shared front, not a copy"
    );
}

#[test]
fn repop_txn_accessor() {
    let m = repop();
    let t = m.txn(DEFAULT_PAGE).unwrap();
    assert_eq!(t.ops.len(), big_txn(&payload()).ops.len());
}

/// Split a dencoder message wrapper: (type, version, segments).
fn unwrap_msg(b: &[u8]) -> (u16, u16, messages::Segments) {
    let ty = u16::from_le_bytes([b[16], b[17]]);
    let ver = u16::from_le_bytes([b[20], b[21]]);
    let mut p = 53 + 13;
    let mut seg = || {
        let n = u32::from_le_bytes(b[p..p + 4].try_into().unwrap()) as usize;
        let s = b[p + 4..p + 4 + n].to_vec();
        p += 4 + n;
        s
    };
    let (front, middle, data) = (seg(), seg(), seg());
    (
        ty,
        ver,
        messages::Segments {
            front_zc: Vec::new(),
            front_hints: Default::default(),
            front,
            middle,
            data: data.into(),
        },
    )
}

/// Default-constructed messages from the real dencoder decode with us and re-encode to the same front.
#[test]
fn dencoder_default_messages() {
    let dir = testdata("msgdefault");
    let mut n = 0;
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let b = std::fs::read(&p).unwrap();
        let (ty, ver, seg) = unwrap_msg(&b);
        let m = decode_repl(ty, ver, &seg)
            .unwrap_or_else(|e| panic!("{}: {e}", p.display()))
            .unwrap_or_else(|| panic!("{}: unknown type {ty}", p.display()));
        let (_, v, _, re) = m.encode(denc::features::ALL).unwrap();
        assert_eq!(v, ver, "{}: head version", p.display());
        assert_eq!(re, seg, "{}: re-encode differs", p.display());
        n += 1;
    }
    assert_eq!(n, 11);
}

#[test]
fn object_info_older_versions() {
    for (n, oi) in object_infos() {
        for v in [13u8, 14, 15, 16, 17] {
            // version gates drop trailing fields; shard_versions/manifest only where present
            let b = object_info_old(&oi, v);
            let back: ObjectInfo = denc::from_slice(&b).unwrap_or_else(|e| panic!("{n} v{v}: {e}"));
            let mut want = oi.clone();
            if v < 18 {
                want.shard_versions.clear();
            }
            if v < 17 {
                want.manifest = None;
            }
            if v < 16 {
                (
                    want.expected_object_size,
                    want.expected_write_size,
                    want.alloc_hint_flags,
                ) = (0, 0, 0);
            }
            if v < 15 {
                (want.data_digest, want.omap_digest) = (u32::MAX, u32::MAX);
                want.flags &= !(flag::DATA_DIGEST | flag::OMAP_DIGEST);
            }
            if v < 14 {
                want.local_mtime = Default::default();
            }
            assert_eq!(back, want, "{n} v{v}");
            check_dec_only(&format!("object_info_t.{n}_v{v}"), &b);
        }
    }
}

/// Sample that is only decoded (not re-encoded) by dencoder: stored under `ours/` with a `.dec` marker.
fn check_dec_only(name: &str, bytes: &[u8]) {
    let p = testdata(&format!("ours/{name}.dec.bin"));
    if emit() {
        std::fs::write(&p, bytes).unwrap();
        return;
    }
    assert_eq!(std::fs::read(&p).unwrap_or_default(), bytes, "{name}");
}

/// Truncated / bit-flipped inputs never panic (decode returns Ok or Err).
#[test]
fn malformed_inputs_do_not_panic() {
    let buf = payload();
    let mut t = big_txn(&buf);
    let v9 = t.encode_v9().unwrap();
    t.data_features = SERVER_TENTACLE;
    let (p10, d10) = t.encode_v10(DEFAULT_PAGE).unwrap();
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for cut in (0..v9.len()).step_by(7) {
        let _ = Transaction::decode(&[], &v9[..cut], DEFAULT_PAGE);
    }
    for cut in (0..p10.len()).step_by(5) {
        let _ = Transaction::decode(&p10[..cut], &d10, DEFAULT_PAGE);
    }
    for _ in 0..3000 {
        let mut a = v9.clone();
        let mut p = p10.clone();
        for _ in 0..3 {
            let i = rnd() as usize % a.len();
            a[i] ^= 1 << (rnd() % 8);
            let j = rnd() as usize % p.len();
            p[j] ^= 1 << (rnd() % 8);
        }
        let _ = Transaction::decode(&[], &a, DEFAULT_PAGE);
        let _ = Transaction::decode(&p, &d10, DEFAULT_PAGE);
        let _ = Transaction::decode(&p, &d10[..d10.len() / 2], 512);
    }
    // object_info_t / snapset / push: same
    let oi = object_infos().remove(0).1.encode_to_vec().unwrap();
    let pu = push_op().encode_to_vec().unwrap();
    for _ in 0..3000 {
        let mut a = oi.clone();
        let mut b = pu.clone();
        let i = rnd() as usize % a.len();
        a[i] ^= 1 << (rnd() % 8);
        let j = rnd() as usize % b.len();
        b[j] ^= 1 << (rnd() % 8);
        let _ = denc::from_slice::<ObjectInfo>(&a);
        let _ = denc::from_slice::<PushOp>(&b);
    }
    for (_, m) in messages() {
        let (ty, ver, _, s) = m.encode(denc::features::ALL).unwrap();
        for _ in 0..300 {
            let mut s2 = s.clone();
            let i = rnd() as usize % s2.front.len();
            s2.front[i] ^= 1 << (rnd() % 8);
            let _ = decode_repl(ty, ver, &s2);
            let cut = rnd() as usize % s2.front.len();
            s2.front.truncate(cut);
            let _ = decode_repl(ty, ver, &s2);
        }
    }
}

fn hex(s: &str) -> Vec<u8> {
    let c: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
    c.chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

/// replication.md 1.8 worked example (hand-derived v9 touch), byte for byte.
#[test]
fn spec_hex_example_touch() {
    use denc::types::*;
    let z = |n: usize| "00 ".repeat(n);
    let spec = hex(&format!(
        "09 09 CC 00 00 00  00 00 00 00  48 00 00 00  09 00 00 00 00000000 00000000 {}  01 00 00 00  02 02  01 01 12 00 00 00  01  01 00 00 00 00 00 00 00  00 00 00 00  ff ff ff ff  ff  fe ff ff ff ff ff ff ff  00 00 00 00  01 00 00 00  06 03 2c 00 00 00  00 00 00 00  01 00 00 00 61  fe ff ff ff ff ff ff ff  78 56 34 12  00  00 00 00 00  01 00 00 00 00 00 00 00  ff ff ff ff ff ff ff ff  ff  00  00 00 00 00  01 00 00 00 00 00 00 00  {}",
        z(60),
        z(16)
    ));
    // the spec's coll_t line has pg_t as "01 | 01 00..(pool=1) | seed 0 | -1": normalise by building ours
    let mut t = Transaction::new();
    let c = t.coll(&CollT::Pg(SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId::NO_SHARD,
    }));
    let o = t.obj(&Ghobject::new(
        Hobject::new(b"a", SnapId::NOSNAP, 0x1234_5678, 1, b""),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    ));
    t.push(c, TxnOp::Touch { oid: o });
    let ours = t.encode_v9().unwrap();
    assert_eq!(ours.len(), 210);
    assert_eq!(spec.len(), 210, "spec hex length");
    assert_eq!(ours, spec);
}
