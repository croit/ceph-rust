// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Frozen tests of the EC sub-op codecs. Golden bytes in this file are derived by hand from ec.md 6 and the denc
//! rules; `tests/fixtures/*.bin` are classic-produced bytes (see fixtures/README) used as an oracle result.

use bytes::Bytes;
use denc::types::{Eversion, Hobject, PgShard, PgT, ShardId, SnapId, SpgT};
use ecwire::*;
use messages::{Message, Segments};
use std::collections::{BTreeMap, BTreeSet};

fn spg() -> SpgT {
    SpgT {
        pgid: PgT::new(3, 5),
        shard: ShardId(2),
    }
}
const SPG_BYTES: [u8; 24] = [
    1, 1, 18, 0, 0, 0, // env v1 c1 len 18
    1, 3, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, // pg_t
    2,    // shard
];
fn pgs(osd: i32, sh: i8) -> PgShard {
    PgShard {
        osd,
        shard: ShardId(sh),
    }
}
fn pgs_bytes(osd: u8, sh: u8) -> Vec<u8> {
    vec![1, 1, 5, 0, 0, 0, osd, 0, 0, 0, sh]
}
fn ev(epoch: u32, version: u64) -> Eversion {
    Eversion { epoch, version }
}
fn hob(name: &str) -> Hobject {
    Hobject::new(name.as_bytes(), SnapId::NOSNAP, 0x1234_5678, 3, b"")
}

#[test]
fn write_reply_golden() {
    let m = MOSDECSubOpWriteReply {
        pgid: spg(),
        map_epoch: 0x64,
        op: ECSubWriteReply {
            from: pgs(2, 1),
            tid: 7,
            last_complete: ev(0x0a, 0x10),
            committed: true,
            applied: true,
        },
        min_epoch: 0x5a,
        trace: [0; 3],
    };
    let mut want = SPG_BYTES.to_vec();
    want.extend([0x64, 0, 0, 0]);
    want.extend([1, 1, 0x21, 0, 0, 0]);
    want.extend(pgs_bytes(2, 1));
    want.extend([7, 0, 0, 0, 0, 0, 0, 0]);
    want.extend([0x10, 0, 0, 0, 0, 0, 0, 0, 0x0a, 0, 0, 0]);
    want.extend([1, 1]);
    want.extend([0x5a, 0, 0, 0]);
    want.extend([0u8; 24]);
    let (ty, hv, hc, seg) = EcMsg::from(m.clone()).encode(0).unwrap();
    assert_eq!((ty, hv, hc), (109, 2, 1));
    assert_eq!(seg.front, want);
    assert!(seg.middle.is_empty() && seg.data.is_empty());
    assert_eq!(EcMsg::from(m.clone()).priority(), 196);
    match decode_ec(109, 2, &seg).unwrap().unwrap() {
        EcMsg::WriteReply(d) => assert_eq!(d, m),
        _ => panic!(),
    }
    // header version 1: no min_epoch (:= map_epoch); trace tolerated either way
    let mut old = want.clone();
    old.drain(old.len() - 28..old.len() - 24);
    let d = MOSDECSubOpWriteReply::decode(1, &old, &[], &[]).unwrap();
    assert_eq!(d.min_epoch, 0x64);
}

#[test]
fn read_golden_and_old_versions() {
    let m = MOSDECSubOpRead {
        pgid: spg(),
        map_epoch: 9,
        op: ECSubRead {
            from: pgs(1, 0),
            tid: 3,
            ..Default::default()
        },
        min_epoch: 8,
        trace: [0; 3],
        cost: 0x1000,
    };
    let mut want = SPG_BYTES.to_vec();
    want.extend([9, 0, 0, 0]);
    want.extend([4, 2, 0x27, 0, 0, 0]);
    want.extend(pgs_bytes(1, 0));
    want.extend([3, 0, 0, 0, 0, 0, 0, 0]);
    want.extend([0u8; 20]); // five empty containers
    want.extend([8, 0, 0, 0]);
    want.extend([0u8; 24]);
    want.extend([0, 0x10, 0, 0, 0, 0, 0, 0]);
    let (ty, hv, hc, seg) = EcMsg::from(m.clone()).encode(0).unwrap();
    assert_eq!((ty, hv, hc), (110, 4, 1));
    assert_eq!(seg.front, want);
    assert_eq!(EcMsg::from(m.clone()).priority(), 127);
    match decode_ec(110, 4, &seg).unwrap().unwrap() {
        EcMsg::Read(d) => assert_eq!(d, m),
        _ => panic!(),
    }
    // header v2: pgid, map_epoch, op only
    let mut v2 = SPG_BYTES.to_vec();
    v2.extend([9, 0, 0, 0]);
    // struct v1 (pairs): from, tid, to_read, attrs_to_read
    v2.extend([1, 1, 0x1b, 0, 0, 0]);
    v2.extend(pgs_bytes(1, 0));
    v2.extend([3, 0, 0, 0, 0, 0, 0, 0]);
    v2.extend([0u8; 8]);
    let d = MOSDECSubOpRead::decode(2, &v2, &[], &[]).unwrap();
    assert_eq!(d.min_epoch, 9);
    assert_eq!(d.cost, 0);
    assert_eq!(d.op.tid, 3);
    assert!(d.op.subchunks.is_empty());
}

#[test]
fn read_struct_ladder() {
    // one object, one range; v1/v2c1 = pairs, v2c2/v3 = triples (+ subchunks from v3)
    let h = hob("o");
    let mut hb = Vec::new();
    denc_enc(&h, &mut hb);
    let build = |v: u8, c: u8, triples: bool, sub: bool, omap: bool| {
        let mut body = pgs_bytes(1, 0);
        body.extend([3, 0, 0, 0, 0, 0, 0, 0]);
        body.extend([1, 0, 0, 0]);
        body.extend(&hb);
        body.extend([1, 0, 0, 0]);
        body.extend([0x10, 0, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0]);
        if triples {
            body.extend([0x08, 0, 0, 0]);
        }
        body.extend([0, 0, 0, 0]); // attrs_to_read
        if sub {
            body.extend([1, 0, 0, 0]);
            body.extend(&hb);
            body.extend([1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]);
        }
        if omap {
            body.extend([0u8; 8]);
        }
        let mut b = vec![v, c];
        b.extend((body.len() as u32).to_le_bytes());
        b.extend(body);
        b
    };
    for (v, c, tr, sub, omap) in [
        (1, 1, false, false, false),
        (2, 1, false, false, false),
        (2, 2, true, false, false),
        (3, 2, true, true, false),
        (4, 2, true, true, true),
    ] {
        let d = ECSubRead::from_struct_bytes(&build(v, c, tr, sub, omap)).unwrap();
        assert_eq!(d.tid, 3, "v{v}c{c}");
        let want_flags = if tr { 8 } else { 0 };
        assert_eq!(d.to_read[&h], vec![(0x10, 0x20, want_flags)], "v{v}c{c}");
        let sc = if sub { vec![(2, 3)] } else { vec![(0, 1)] };
        assert_eq!(d.subchunks[&h], sc, "v{v}c{c}");
    }
}

/// `struct_compat` names the oldest decoder version that can read the struct: a sender whose compat exceeds the version
/// our decoder reads must be refused (a compat at or below it is a layout we read: appended fields only). The EC type
/// ids are not in `messages::HEAD_BY_TYPE`, so this struct gate is the only compat gate these four have. Each decoder
/// accepts compat up to the highest struct_v it reads: ECSubWrite 5, ECSubRead 4, ECSubReadReply 3, ECSubWriteReply 1.
#[test]
fn struct_compat_above_what_we_understand_is_refused() {
    let wr = MOSDECSubOpWrite {
        pgid: spg(),
        map_epoch: 5,
        op: sample_write(false),
        min_epoch: 4,
        trace: [0; 3],
    };
    let wrr = MOSDECSubOpWriteReply {
        pgid: spg(),
        op: ECSubWriteReply {
            tid: 7,
            ..Default::default()
        },
        ..Default::default()
    };
    let rd = MOSDECSubOpRead {
        pgid: spg(),
        ..Default::default()
    };
    let rdr = MOSDECSubOpReadReply {
        pgid: spg(),
        op: ECSubReadReply {
            from: pgs(2, 1),
            tid: 6,
            buffers_read: BTreeMap::from([(hob("a"), vec![(0, Bytes::from_static(b"xy"))])]),
            data_segment: true,
            ..Default::default()
        },
        ..Default::default()
    };
    // (message, struct_v we emit, its compat, highest struct_compat we accept)
    for (m, sv, sc, max) in [
        (EcMsg::from(wr), 4u8, 1u8, 5u8),
        (EcMsg::from(wrr), 1, 1, 1),
        (EcMsg::from(rd), 4, 2, 4),
        (EcMsg::from(rdr), 3, 2, 3),
    ] {
        let (ty, hv, _, mut seg) = m.encode(0).unwrap();
        // the payload struct envelope follows the message head (pgid, map_epoch)
        let at = SPG_BYTES.len() + 4;
        assert_eq!(&seg.front[at..at + 2], [sv, sc], "type {ty}");
        assert!(decode_ec(ty, hv, &seg).unwrap().is_ok(), "type {ty}");
        seg.front[at + 1] = max;
        assert!(
            decode_ec(ty, hv, &seg).unwrap().is_ok(),
            "type {ty}: compat {max} is readable"
        );
        seg.front[at + 1] = max + 1;
        match decode_ec(ty, hv, &seg) {
            Some(Err(denc::Error::CompatTooNew { compat, supported })) => {
                assert_eq!((compat, supported), (max + 1, max), "type {ty}");
            }
            _ => panic!("type {ty}: struct_compat {} must be refused", max + 1),
        }
    }
}

fn denc_enc<T: denc::Encode>(t: &T, out: &mut Vec<u8>) {
    let mut e = denc::Encoder::new();
    t.encode(&mut e).unwrap();
    out.extend(e.into_vec());
}

#[test]
fn read_roundtrip_full() {
    let (a, b) = (hob("a"), hob("b"));
    let op = ECSubRead {
        from: pgs(4, 3),
        tid: 99,
        to_read: BTreeMap::from([
            (a.clone(), vec![(0, 4096, 0), (8192, 4096, 8)]),
            (b.clone(), vec![(0, 1, 0)]),
        ]),
        attrs_to_read: BTreeSet::from([a.clone()]),
        subchunks: BTreeMap::from([(a.clone(), vec![(0, 1)]), (b.clone(), vec![(0, 1)])]),
        omap_read_from: BTreeMap::from([(b.clone(), (b"k\xff".to_vec(), 77))]),
        omap_headers_to_read: BTreeSet::from([b]),
    };
    let m = MOSDECSubOpRead {
        pgid: spg(),
        map_epoch: 5,
        op,
        min_epoch: 4,
        trace: [1, 2, 3],
        cost: 12,
    };
    let (_, _, _, seg) = EcMsg::from(m.clone()).encode(0).unwrap();
    assert_eq!(decode_ec(110, 4, &seg).unwrap().unwrap(), EcMsg::Read(m));
}

#[test]
fn read_reply_v1_golden_and_roundtrip() {
    // empty reply by hand
    let m = MOSDECSubOpReadReply {
        pgid: spg(),
        map_epoch: 6,
        op: ECSubReadReply {
            from: pgs(2, 1),
            tid: 5,
            ..Default::default()
        },
        min_epoch: 2,
        trace: [0; 3],
    };
    let mut want = SPG_BYTES.to_vec();
    want.extend([6, 0, 0, 0]);
    want.extend([1, 1, 0x1f, 0, 0, 0]);
    want.extend(pgs_bytes(2, 1));
    want.extend([5, 0, 0, 0, 0, 0, 0, 0]);
    want.extend([0u8; 12]);
    want.extend([2, 0, 0, 0]);
    want.extend([0u8; 24]);
    let (ty, hv, hc, seg) = EcMsg::from(m.clone()).encode(0).unwrap();
    assert_eq!((ty, hv, hc), (111, 2, 1));
    assert_eq!(seg.front, want);
    assert!(seg.data.is_empty());

    let a = hob("a");
    let full = ECSubReadReply {
        from: pgs(2, 1),
        tid: 5,
        buffers_read: BTreeMap::from([(
            a.clone(),
            vec![
                (0, Bytes::from_static(b"hello")),
                (4096, Bytes::from_static(b"")),
            ],
        )]),
        attrs_read: BTreeMap::from([(
            a.clone(),
            BTreeMap::from([
                (b"_".to_vec(), vec![1, 2, 3]),
                (b"hinfo_key".to_vec(), vec![]),
            ]),
        )]),
        errors: BTreeMap::from([(hob("gone"), -2)]),
        ..Default::default()
    };
    let m = MOSDECSubOpReadReply { op: full, ..m };
    let (_, hv, hc, seg) = EcMsg::from(m.clone()).encode(0).unwrap();
    assert_eq!((hv, hc), (2, 1));
    assert!(seg.data.is_empty(), "v1 keeps data inline");
    assert_eq!(
        decode_ec(111, 2, &seg).unwrap().unwrap(),
        EcMsg::ReadReply(m)
    );
}

#[test]
fn read_reply_v3_data_segment() {
    let a = hob("a");
    let op = ECSubReadReply {
        from: pgs(2, 1),
        tid: 5,
        buffers_read: BTreeMap::from([(
            a.clone(),
            vec![
                (0, Bytes::from_static(b"abc")),
                (10, Bytes::from_static(b"defgh")),
            ],
        )]),
        omap_headers_read: BTreeMap::from([(a.clone(), vec![9, 9])]),
        omap_entries_read: BTreeMap::from([(
            a.clone(),
            BTreeMap::from([(b"k\xff\x00".to_vec(), vec![1])]),
        )]),
        omaps_complete: BTreeMap::from([(a, true)]),
        ..Default::default()
    };
    let m = MOSDECSubOpReadReply {
        pgid: spg(),
        map_epoch: 1,
        op,
        min_epoch: 1,
        trace: [0; 3],
    };
    let (_, _, _, seg) = EcMsg::from(m.clone()).encode(0).unwrap();
    assert_eq!(&seg.data[..], b"abcdefgh");
    assert_eq!(
        decode_ec(111, 2, &seg).unwrap().unwrap(),
        EcMsg::ReadReply(m.clone())
    );
    // data segment shorter than announced lengths: error, not panic
    let mut bad = seg.clone();
    bad.data = Bytes::from_static(b"abcdefg");
    assert!(decode_ec(111, 2, &bad).unwrap().is_err());
    // the struct alone, as emitted by a tentacle classic peer (struct v3 with data segment)
    let (sb, data) = m.op.to_struct_bytes().unwrap();
    assert_eq!(sb[..2], [3, 2]);
    assert_eq!(ECSubReadReply::from_struct_bytes(&sb, &data).unwrap(), m.op);
}

fn sample_write(backfill: bool) -> ECSubWrite {
    // a minimal valid v9 transaction envelope: an empty one is `09 09 len body`; build it with replwire
    let t = replwire::Transaction::new();
    let txn = t.encode_v9().unwrap();
    ECSubWrite {
        from: pgs(1, 0),
        tid: 42,
        soid: hob("obj"),
        txn_data: txn.into(),
        at_version: ev(5, 17),
        trim_to: ev(5, 3),
        temp_added: BTreeSet::from([hob("t1")]),
        temp_removed: BTreeSet::from([hob("t2"), hob("t3")]),
        pg_committed_to: ev(5, 16),
        backfill_or_async_recovery: backfill,
        ..Default::default()
    }
}

#[test]
fn write_roundtrip_v4_inline() {
    for backfill in [false, true] {
        let m = MOSDECSubOpWrite {
            pgid: spg(),
            map_epoch: 5,
            op: sample_write(backfill),
            min_epoch: 4,
            trace: [0; 3],
        };
        let (ty, hv, hc, seg) = EcMsg::from(m.clone()).encode(0).unwrap();
        assert_eq!((ty, hv, hc), (108, 2, 1));
        assert!(seg.data.is_empty() && seg.middle.is_empty());
        // struct header: v4 compat 1 right after pgid + map_epoch
        assert_eq!(seg.front[24 + 4..24 + 6], [4, 1]);
        let d = match decode_ec(108, 2, &seg).unwrap().unwrap() {
            EcMsg::Write(d) => d,
            _ => panic!(),
        };
        assert_eq!(d, m);
        assert!(d.txn(4096).unwrap().is_empty());
        assert_eq!(EcMsg::from(d).gating(), (5, 4));
    }
}

#[test]
fn write_v5_front_p_data_segment() {
    // hand-build a struct v5: same as v4 but the txn envelope is the p-part and the DATA segment carries d bytes
    let mut w = sample_write(false);
    let p = w.txn_data.clone();
    w.txn_middle = p; // p-part lives in the front
    w.txn_data = Bytes::from_static(b"DATABYTES");
    let m = MOSDECSubOpWrite {
        pgid: spg(),
        map_epoch: 5,
        op: w,
        min_epoch: 4,
        trace: [0; 3],
    };
    let (_, _, _, seg) = EcMsg::from(m.clone()).encode(0).unwrap();
    assert_eq!(seg.front[24 + 4..24 + 6], [5, 1]);
    assert_eq!(&seg.data[..], b"DATABYTES");
    assert_eq!(decode_ec(108, 2, &seg).unwrap().unwrap(), EcMsg::Write(m));
}

#[test]
fn write_old_struct_versions() {
    // strip a v4 struct down to v1/v2/v3 by cutting trailing fields and fixing the header
    let w = sample_write(false);
    let full = w.to_struct_bytes().unwrap();
    let body = &full[6..];
    // v4 tail: ... temp sets, hit_set u8 (v2), pct 12 bytes (v3), backfill 1 byte (v4)
    let cut = |drop: usize, v: u8| {
        let mut b = vec![v, 1];
        let n = body.len() - drop;
        b.extend((n as u32).to_le_bytes());
        b.extend(&body[..n]);
        b
    };
    let v3 = ECSubWrite::from_struct_bytes(&cut(1, 3), &Bytes::new()).unwrap();
    assert_eq!(v3.pg_committed_to, w.pg_committed_to);
    assert!(
        v3.backfill_or_async_recovery,
        "empty transaction is log-only"
    );
    let v2 = ECSubWrite::from_struct_bytes(&cut(13, 2), &Bytes::new()).unwrap();
    assert_eq!(v2.pg_committed_to, w.trim_to, "v<3: := trim_to");
    let v1 = ECSubWrite::from_struct_bytes(&cut(14, 1), &Bytes::new()).unwrap();
    assert_eq!(v1.updated_hit_set_history, None);
    assert_eq!(v1.temp_removed, w.temp_removed);
}

#[test]
fn write_reply_struct_oracle_fixture_shape() {
    let b = include_bytes!("fixtures/ECSubWriteReply.1.bin");
    let d = ECSubWriteReply::from_struct_bytes(b).unwrap();
    assert_eq!(d.from, pgs(-1, -1));
    assert_eq!(d.tid, 0x14);
    assert_eq!(d.last_complete, ev(100, 2000));
    assert!(d.committed && !d.applied);
    assert_eq!(d.to_struct_bytes().unwrap(), b);
}

#[test]
fn oracle_fixtures_roundtrip() {
    // classic-produced bytes decode, and re-encode byte-exactly (we emit the same struct version)
    for b in [
        &include_bytes!("fixtures/ECSubWriteReply.2.bin")[..],
        &include_bytes!("fixtures/ECSubWriteReply.1.bin")[..],
    ] {
        let d = ECSubWriteReply::from_struct_bytes(b).unwrap();
        assert_eq!(d.to_struct_bytes().unwrap(), b);
    }
    for b in [
        &include_bytes!("fixtures/ECSubRead.1.bin")[..],
        &include_bytes!("fixtures/ECSubRead.2.bin")[..],
    ] {
        let d = ECSubRead::from_struct_bytes(b).unwrap();
        assert!(!d.to_read.is_empty());
        assert_eq!(d.to_struct_bytes().unwrap(), b);
    }
    for b in [
        &include_bytes!("fixtures/ECSubReadReply.1.bin")[..],
        &include_bytes!("fixtures/ECSubReadReply.2.bin")[..],
    ] {
        let d = ECSubReadReply::from_struct_bytes(b, &Bytes::new()).unwrap();
        assert!(!d.buffers_read.is_empty() || !d.attrs_read.is_empty());
        assert_eq!(d.to_struct_bytes().unwrap().0, b);
    }
    for b in [
        &include_bytes!("fixtures/ECSubWrite.1.bin")[..],
        &include_bytes!("fixtures/ECSubWrite.2.bin")[..],
        &include_bytes!("fixtures/ECSubWrite.3.bin")[..],
    ] {
        let d = ECSubWrite::from_struct_bytes(b, &Bytes::new()).unwrap();
        assert!(d.txn_middle.is_empty());
        let re = d.to_struct_bytes().unwrap();
        assert_eq!(re, b, "byte-exact re-encode");
    }
}

#[test]
fn not_ours() {
    let seg = Segments::default();
    assert!(decode_ec(112, 3, &seg).is_none());
    assert!(decode_ec(105, 1, &seg).is_none());
}

fn xorshift(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}

#[test]
fn truncation_and_garbage_never_panic() {
    let mut msgs: Vec<EcMsg> = Vec::new();
    msgs.push(
        MOSDECSubOpWrite {
            pgid: spg(),
            map_epoch: 5,
            op: sample_write(true),
            min_epoch: 4,
            trace: [0; 3],
        }
        .into(),
    );
    msgs.push(MOSDECSubOpWriteReply::default().into());
    let a = hob("a");
    msgs.push(
        MOSDECSubOpRead {
            op: ECSubRead {
                to_read: BTreeMap::from([(a.clone(), vec![(0, 1, 0)])]),
                subchunks: BTreeMap::from([(a.clone(), vec![(0, 1)])]),
                ..Default::default()
            },
            ..Default::default()
        }
        .into(),
    );
    msgs.push(
        MOSDECSubOpReadReply {
            op: ECSubReadReply {
                buffers_read: BTreeMap::from([(a.clone(), vec![(0, Bytes::from_static(b"xyz"))])]),
                omaps_complete: BTreeMap::from([(a, true)]),
                ..Default::default()
            },
            ..Default::default()
        }
        .into(),
    );
    let mut s = 0x9e37_79b9_7f4a_7c15u64;
    for m in &msgs {
        let (ty, hv, _, seg) = m.encode(0).unwrap();
        // every truncation of the front, and of the data segment
        for n in 0..seg.front.len() {
            let mut t = seg.clone();
            t.front.truncate(n);
            let _ = decode_ec(ty, hv, &t);
        }
        for n in 0..seg.data.len() {
            let mut t = seg.clone();
            t.data = seg.data.slice(..n);
            let _ = decode_ec(ty, hv, &t);
        }
        // random byte flips, random header versions
        for _ in 0..3000 {
            let mut t = seg.clone();
            for _ in 0..1 + xorshift(&mut s) % 4 {
                if t.front.is_empty() {
                    break;
                }
                let i = (xorshift(&mut s) as usize) % t.front.len();
                t.front[i] = xorshift(&mut s) as u8;
            }
            let _ = decode_ec(ty, 1 + (xorshift(&mut s) % 6) as u16, &t);
        }
        // pure garbage
        for _ in 0..500 {
            let len = (xorshift(&mut s) % 200) as usize;
            let g: Vec<u8> = (0..len).map(|_| xorshift(&mut s) as u8).collect();
            let t = Segments {
                front: g,
                ..Default::default()
            };
            let _ = decode_ec(ty, 4, &t);
        }
    }
}

#[test]
fn size_bombs_are_rejected_cheaply() {
    // a count of u32::MAX in every container position must fail on the length check, not allocate
    let huge = u32::MAX.to_le_bytes();
    for ty in [108u16, 109, 110, 111] {
        let mut f = SPG_BYTES.to_vec();
        f.extend([1, 0, 0, 0]);
        f.extend([4, 1, 0xff, 0, 0, 0]);
        f.extend(pgs_bytes(1, 0));
        f.extend([0u8; 8]);
        for _ in 0..8 {
            f.extend(huge);
        }
        let seg = Segments {
            front: f,
            ..Default::default()
        };
        let r = decode_ec(ty, 4, &seg).unwrap();
        assert!(r.is_err(), "type {ty}");
    }
    // ReadReply v3: per-item length far beyond the data segment
    let a = hob("a");
    let mut body = pgs_bytes(1, 0);
    body.extend([0u8; 8]);
    body.extend([1, 0, 0, 0]);
    denc_enc(&a, &mut body);
    body.extend([1, 0, 0, 0]);
    body.extend([0u8; 8]);
    body.extend(huge);
    let mut b = vec![3, 2];
    b.extend((body.len() as u32).to_le_bytes());
    b.extend(body);
    assert!(ECSubReadReply::from_struct_bytes(&b, &Bytes::from_static(b"zz")).is_err());
}

#[test]
fn message_meta() {
    assert_eq!(<MOSDECSubOpWrite as Message>::MSG_TYPE, 108);
    assert_eq!(<MOSDECSubOpWriteReply as Message>::HEAD_VERSION, 2);
    assert_eq!(<MOSDECSubOpRead as Message>::HEAD_VERSION, 4);
    assert_eq!(<MOSDECSubOpReadReply as Message>::MSG_TYPE, 111);
    let m: EcMsg = MOSDECSubOpRead {
        pgid: spg(),
        ..Default::default()
    }
    .into();
    assert_eq!(m.spgid(), spg());
    assert_eq!(m.msg_type(), 110);
}

/// A 2 MiB shard sub-write: the sender splices the payload (rope, flattened = the plain bytes); a receiver that keeps
/// the large front by reference (`decode_with_header_owned`) decodes the transaction as a slice of it (no copy).
#[test]
fn write_v4_rope_send_and_shared_receive() {
    let payload = Bytes::from((0..(2 << 20)).map(|i| (i * 13) as u8).collect::<Vec<u8>>());
    let mut t = replwire::Transaction::new();
    let c = t.coll(&denc::types::CollT::Pg(spg()));
    let o = t.obj(&denc::types::Ghobject::new(
        hob("o"),
        denc::types::Ghobject::NO_GEN,
        ShardId(1),
    ));
    t.push(
        c,
        replwire::TxnOp::Write {
            oid: o,
            off: 0,
            data: replwire::Data::new(&payload),
        },
    );
    let plain_txn = t.encode_v9().unwrap();
    let (inline, zc) = t.encode_v9_rope(std::slice::from_ref(&payload)).unwrap();
    let mut op = sample_write(false);
    op.txn_data = inline.into();
    op.txn_zc = zc;
    let m = MOSDECSubOpWrite {
        pgid: spg(),
        map_epoch: 5,
        op,
        min_epoch: 4,
        trace: [0; 3],
    };
    let (_, _, _, seg) = EcMsg::from(m.clone()).encode(0).unwrap();
    assert_eq!(seg.front_zc.len(), 1, "payload spliced");
    assert_eq!(seg.front_zc[0].1.as_ptr(), payload.as_ptr());
    let mut plain = m.clone();
    plain.op.txn_data = plain_txn.clone().into();
    plain.op.txn_zc.clear();
    let (_, _, _, pseg) = EcMsg::from(plain.clone()).encode(0).unwrap();
    assert!(pseg.front_zc.is_empty());
    let wire = seg.front_bytes().unwrap().into_owned();
    assert_eq!(wire, pseg.front, "same wire bytes");
    // receive: the front as one shared buffer
    let rx = Bytes::from(wire);
    let h = messages::Header2::new(1, 108, 2, 1);
    let messages::AnyMessage::Unknown { segments, .. } =
        messages::decode_with_header_owned(&h, &rx, &[], &Bytes::new()).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        segments.front_shared().map(|b| b.as_ptr()),
        Some(rx.as_ptr())
    );
    let EcMsg::Write(d) = decode_ec(108, 2, &segments).unwrap().unwrap() else {
        panic!()
    };
    assert_eq!(d, plain);
    let base = rx.as_ptr() as usize;
    let p = d.op.txn_data.as_ptr() as usize;
    assert!(
        p >= base && p + d.op.txn_data.len() <= base + rx.len(),
        "txn not copied"
    );
    // small fronts stay inline copies
    let small = Bytes::from(pseg.front[..100].to_vec());
    let messages::AnyMessage::Unknown { segments, .. } =
        messages::decode_with_header_owned(&h, &small, &[], &Bytes::new()).unwrap()
    else {
        panic!()
    };
    assert!(segments.front_zc.is_empty() && segments.front.len() == 100);
}

/// Struct v5 for a SERVER_TENTACLE peer (`ECSubWrite::data_segment`): the v4 rope becomes the unsplit v10 encoding
/// (front p = `encode_v10` p, DATA = `encode_v10` d, byte for byte), the shard payloads stay by reference with their crc
/// hints, `data_off` puts the first payload on a page boundary, and the receiver decodes the same transaction. An empty
/// transaction converts too.
#[test]
fn write_v5_data_segment_is_the_v10_encoding_by_reference() {
    let payload = Bytes::from((0..(256 << 10)).map(|i| (i * 7) as u8).collect::<Vec<u8>>());
    let mut t = replwire::Transaction::new();
    let c = t.coll(&denc::types::CollT::Pg(spg()));
    let o = t.obj(&denc::types::Ghobject::new(
        hob("o"),
        denc::types::Ghobject::NO_GEN,
        ShardId(1),
    ));
    t.push(c, replwire::TxnOp::Touch { oid: o });
    t.push(
        c,
        replwire::TxnOp::SetAttr {
            oid: o,
            name: b"hinfo_key",
            value: &[9u8; 37],
        },
    );
    t.push(
        c,
        replwire::TxnOp::Write {
            oid: o,
            off: 0,
            data: replwire::Data::new(&payload),
        },
    );
    let (p10, d10) = t.encode_v10(4096).unwrap();
    let (inline, zc) = t.encode_v9_rope(std::slice::from_ref(&payload)).unwrap();
    let hint = crc::CrcHint::new(&payload, crc::crc32c(!0, &payload));
    let mut op = sample_write(false);
    op.txn_data = inline.into();
    op.txn_zc = zc;
    op.txn_hints = vec![hint].into();
    op.txn_payload_at = t.payload_at();
    let data_off = op.data_segment().unwrap();
    assert_eq!(&op.txn_middle[..], &p10[..], "front p = v10 p");
    let mut d = op.txn_data.to_vec();
    op.txn_data_more
        .iter()
        .for_each(|(b, _)| d.extend_from_slice(b));
    assert_eq!(d, d10, "DATA = v10 d");
    let at = t.payload_at().unwrap();
    assert_eq!(
        (at as u16).wrapping_add(data_off),
        0,
        "data_off names the payload"
    );
    let (run, h) = op
        .txn_data_more
        .iter()
        .find(|(b, _)| b.as_ptr() == payload.as_ptr())
        .expect("payload by reference");
    assert_eq!(run.len(), payload.len());
    assert_eq!(h.of(run), Some(crc::crc32c(!0, &payload)));
    assert_eq!(op.data_segment().unwrap(), data_off, "idempotent");
    let m = MOSDECSubOpWrite {
        pgid: spg(),
        map_epoch: 5,
        op,
        min_epoch: 4,
        trace: [0; 3],
    };
    let (_, _, _, seg) = EcMsg::from(m.clone()).encode(denc::features::ALL).unwrap();
    assert_eq!(seg.front[24 + 4..24 + 6], [5, 1]);
    assert_eq!(&seg.data[..], &d10[..]);
    let EcMsg::Write(r) = decode_ec(108, 2, &seg).unwrap().unwrap() else {
        panic!()
    };
    assert_eq!(
        r.txn(4096).unwrap().encode_v9().unwrap(),
        t.encode_v9().unwrap(),
        "the receiver decodes the same transaction"
    );
    // an empty transaction (skipped shard): v5 with an empty DATA segment
    let mut e = sample_write(true);
    assert_eq!(e.data_segment().unwrap(), 0);
    assert!(e.txn_data.is_empty() && e.txn_data_more.is_empty());
    let m = MOSDECSubOpWrite {
        pgid: spg(),
        map_epoch: 5,
        op: e,
        min_epoch: 4,
        trace: [0; 3],
    };
    let (_, _, _, seg) = EcMsg::from(m).encode(denc::features::ALL).unwrap();
    let EcMsg::Write(r) = decode_ec(108, 2, &seg).unwrap().unwrap() else {
        panic!()
    };
    assert!(r.txn(4096).unwrap().is_empty());
}

#[test]
fn read_reply_data_segment_without_omap() {
    // tentacle+ receiver: struct v3 (compat 2) with empty omap fields, the one buffer IS the DATA segment (shared)
    let a = hob("a");
    let buf = Bytes::from((0..8192u32).map(|i| i as u8).collect::<Vec<u8>>());
    let op = ECSubReadReply {
        from: pgs(2, 1),
        tid: 6,
        buffers_read: BTreeMap::from([(a.clone(), vec![(4096, buf.clone())])]),
        data_segment: true,
        ..Default::default()
    };
    let m = MOSDECSubOpReadReply {
        pgid: spg(),
        map_epoch: 1,
        op,
        min_epoch: 1,
        trace: [0; 3],
    };
    let (_, _, _, seg) = EcMsg::from(m.clone()).encode(0).unwrap();
    assert_eq!(
        seg.data.as_ptr(),
        buf.as_ptr(),
        "no copy into the DATA segment"
    );
    assert_eq!(seg.data.len(), buf.len());
    let EcMsg::ReadReply(d) = decode_ec(111, 2, &seg).unwrap().unwrap() else {
        panic!("not a read reply");
    };
    assert_eq!(d, m);
    let got = &d.op.buffers_read[&a][0].1;
    assert_eq!(
        got.as_ptr(),
        seg.data.as_ptr(),
        "receiver slices the DATA segment"
    );
    let (sb, data) = m.op.to_struct_bytes().unwrap();
    assert_eq!(sb[..2], [3, 2]);
    assert_eq!(ECSubReadReply::from_struct_bytes(&sb, &data).unwrap(), m.op);
    // default (classic pre-tentacle shape): struct v1, data inline, empty DATA segment
    let mut v1 = m.clone();
    v1.op.data_segment = false;
    let (_, _, _, seg1) = EcMsg::from(v1.clone()).encode(0).unwrap();
    assert!(seg1.data.is_empty());
    assert_eq!(
        decode_ec(111, 2, &seg1).unwrap().unwrap(),
        EcMsg::ReadReply(v1)
    );
    // two buffers: concatenated in order
    let mut two = m.clone();
    two.op
        .buffers_read
        .insert(hob("b"), vec![(0, Bytes::from_static(b"xy"))]);
    let (_, _, _, seg2) = EcMsg::from(two.clone()).encode(0).unwrap();
    assert_eq!(seg2.data.len(), buf.len() + 2);
    assert_eq!(
        decode_ec(111, 2, &seg2).unwrap().unwrap(),
        EcMsg::ReadReply(two)
    );
}

#[test]
fn read_reply_buffer_pieces_by_reference() {
    // the shard's one buffer in store pieces (adr 0116 am. 4): the extent covers every piece, the plain
    // encode concatenates them, the cluster send moves the tail pieces out and sends the head piece as the DATA segment
    let a = hob("a");
    let data: Vec<u8> = (0..3 * 8192u32).map(|i| (i * 7) as u8).collect();
    let all = Bytes::from(data);
    let (p0, p1, p2) = (
        all.slice(..8192),
        all.slice(8192..16384),
        all.slice(16384..),
    );
    let hint = |b: &Bytes| crc::CrcHint::new(b, crc::crc32c(!0, b));
    let op = ECSubReadReply {
        from: pgs(2, 1),
        tid: 7,
        buffers_read: BTreeMap::from([(a.clone(), vec![(4096, p0.clone())])]),
        data_segment: true,
        data_more: vec![(p1.clone(), hint(&p1)), (p2.clone(), hint(&p2))],
        ..Default::default()
    };
    let m = MOSDECSubOpReadReply {
        pgid: spg(),
        map_epoch: 1,
        op,
        min_epoch: 1,
        trace: [0; 3],
    };
    // plain encode: one DATA segment with every piece, decodes to the whole buffer
    let (_, _, _, seg) = EcMsg::from(m.clone()).encode(0).unwrap();
    assert_eq!(seg.data, all);
    let EcMsg::ReadReply(d) = decode_ec(111, 2, &seg).unwrap().unwrap() else {
        panic!("not a read reply");
    };
    assert_eq!(d.op.buffers_read[&a], vec![(4096, all.clone())]);
    // cluster send: the tail pieces leave by reference, the front still announces the whole extent
    let mut s = m.clone();
    let more = s.op.take_data_more();
    assert_eq!(more.len(), 2);
    assert_eq!(more[0].0.as_ptr(), p1.as_ptr(), "pieces by reference");
    let (_, _, _, seg2) = EcMsg::from(s).encode(0).unwrap();
    assert_eq!(
        seg2.data.as_ptr(),
        p0.as_ptr(),
        "head piece is the DATA segment"
    );
    assert_eq!(
        seg2.front, seg.front,
        "same front: the extent length covers the moved pieces"
    );
    // the receiver sees the frame data = head ++ tail pieces
    let mut wire = seg2.clone();
    let mut flat = seg2.data.to_vec();
    for (b, _) in &more {
        flat.extend_from_slice(b);
    }
    wire.data = Bytes::from(flat);
    let EcMsg::ReadReply(d2) = decode_ec(111, 2, &wire).unwrap().unwrap() else {
        panic!("not a read reply");
    };
    assert_eq!(d2.op.buffers_read[&a], vec![(4096, all)]);
    // pieces without the one-buffer v3 shape: refused (never a short extent on the wire)
    let mut bad = m;
    bad.op.data_segment = false;
    assert!(EcMsg::from(bad).encode(0).is_err());
}

/// The payload fields hold up to a stripe width per shard: a `{:?}` (log line, failing `assert_eq!`) must show their
/// size, never the bytes.
#[test]
fn debug_never_dumps_the_payload() {
    const MIB2: usize = 2 << 20;
    let payload = Bytes::from((0..MIB2).map(|i| (i * 13) as u8).collect::<Vec<u8>>());
    let mut w = sample_write(false);
    w.txn_data = payload.clone();
    w.txn_zc = vec![(0, payload.clone())];
    w.txn_data_more = vec![(payload.clone(), crc::CrcHint::default())];
    let m = MOSDECSubOpWrite {
        pgid: spg(),
        map_epoch: 5,
        op: w,
        min_epoch: 4,
        trace: [0; 3],
    };
    let s = format!("{:?}", EcMsg::from(m));
    assert!(s.len() < 4096, "{} bytes of Debug output", s.len());
    assert!(s.contains(&MIB2.to_string()), "payload size: {s}");

    let op = ECSubReadReply {
        from: pgs(2, 1),
        tid: 6,
        buffers_read: BTreeMap::from([(
            hob("a"),
            vec![(0, payload.clone()), (4096, payload.clone())],
        )]),
        data_segment: true,
        data_more: vec![(payload.clone(), crc::CrcHint::default())],
        ..Default::default()
    };
    let m = MOSDECSubOpReadReply {
        pgid: spg(),
        op,
        ..Default::default()
    };
    let s = format!("{:?}", EcMsg::from(m));
    assert!(s.len() < 4096, "{} bytes of Debug output", s.len());
    assert!(s.contains(&MIB2.to_string()), "payload size: {s}");
}

#[test]
fn legacy_empty_subwrite_is_log_only() {
    for empty in [true, false] {
        let mut op = sample_write(false);
        if !empty {
            let mut t = replwire::Transaction::new();
            let c = t.coll(&denc::types::CollT::Pg(spg()));
            let o = t.obj(&denc::types::Ghobject::new(
                hob("obj"),
                denc::types::Ghobject::NO_GEN,
                ShardId(2),
            ));
            t.push(c, replwire::TxnOp::Touch { oid: o });
            op.txn_data = t.encode_v9().unwrap().into();
        }
        let original = op.to_struct_bytes().unwrap();
        for version in 1..=3 {
            let mut old = original.clone();
            old.pop(); // v4 backfill_or_async_recovery
            if version < 3 {
                old.truncate(old.len() - 12); // pg_committed_to
            }
            if version < 2 {
                old.pop(); // absent updated_hit_set_history
            }
            old[0] = version;
            let len = (old.len() - 6) as u32;
            old[2..6].copy_from_slice(&len.to_le_bytes());
            let decoded = ECSubWrite::from_struct_bytes(&old, &Bytes::new()).unwrap();
            assert_eq!(decoded.backfill_or_async_recovery, empty, "v{version}");
        }
    }
}
