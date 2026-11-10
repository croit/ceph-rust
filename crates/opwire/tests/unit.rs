// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Hand vectors and unit tests (spec client-ops.md).
use denc::Encode;
use denc::types::*;
use messages::{Message, Segments};
use opwire::consts::{self, backoff, cmp as cmpc, csum, watch_op};
use opwire::*;

#[test]
fn decoded_request_size_includes_trailing_data() {
    let request = MOSDOp {
        ops: vec![OsdOp::write(0, b"x".to_vec())],
        ..Default::default()
    };
    for version in [7, 8, 9] {
        let encoded = request.encode_version(version, 0).unwrap();
        let data = bytes::Bytes::from_static(b"xtrailing");
        let decoded = MOSDOp::decode_shared(version, &encoded.front, &data).unwrap();
        assert_eq!(decoded.ops[0].indata.as_ref(), b"x");
        assert_eq!(decoded.data_len(), data.len());
        assert_eq!(decoded.into_owned_identity().data_len(), data.len());
        let copied = MOSDOp::decode(version, &encoded.front, &[], &data).unwrap();
        assert_eq!(copied.data_len(), data.len());
    }
}

#[test]
fn default_kv_run_is_an_encoded_empty_map() {
    let run = KvRun::default();
    assert_eq!(run.iter().count(), 0);
    assert_eq!(run.encoded().as_ref(), [0; 4]);
    assert_eq!(KvRun::parse(run.encoded()).unwrap(), run);
}

#[test]
fn placement_read_eligibility_is_one_large_plain_read() {
    let mut request = MOSDOp {
        ops: vec![OsdOp::read(0, 1_048_576)],
        ..Default::default()
    };
    assert!(request.placement_read_eligible());
    request.ops.push(OsdOp::read(0, 1_048_576));
    assert!(!request.placement_read_eligible());
    request.ops.pop();
    request.ops[0] = OsdOp::read(0, 1_048_575);
    assert!(!request.placement_read_eligible());
    request.ops[0] = OsdOp::new(consts::op::SPARSE_READ);
    assert!(!request.placement_read_eligible());
    request.ops[0] = OsdOp::read(0, 1_048_576);
    for incompatible in [
        flag::EC_DIRECT_READ,
        flag::FORCE_OSD,
        flag::PGOP,
        flag::WRITE,
    ] {
        request.flags = incompatible;
        assert!(!request.placement_read_eligible());
    }
}

#[test]
fn placement_read_marker_is_local_only() {
    let mut request = MOSDOp {
        ops: vec![OsdOp::read(0, 1_048_576)],
        ..Default::default()
    };
    let ordinary = request.encode_version(9, u64::MAX).unwrap();
    request.placement_read = Some(2);
    let marked = request.encode_version(9, u64::MAX).unwrap();
    assert_eq!(ordinary.front, marked.front);
    assert_eq!(ordinary.middle, marked.middle);
    assert_eq!(ordinary.data, marked.data);
    let decoded = MOSDOp::decode(9, &marked.front, &marked.middle, &marked.data).unwrap();
    assert_eq!(decoded.placement_read, None);
    assert_eq!(request.placement_read, Some(2));
}

#[test]
fn placed_plain_read_reply_has_receipt_and_no_inline_payload() {
    let mut reply = MOSDOpReply {
        ops: vec![OsdOp::read(17, 8192)],
        ..Default::default()
    };
    reply.ops[0].set_extent(Extent {
        offset: 17,
        length: 4097,
        truncate_size: 0,
        truncate_seq: 0,
    });
    let receipt = vec![1, 2, 3, 4];
    let wire = reply.encode_placed_read(0, receipt.clone(), 4097).unwrap();
    assert_eq!(wire.middle, receipt);
    assert!(wire.data.is_empty());
    let decoded = MOSDOpReply::decode(8, &wire.front, &wire.middle, &wire.data).unwrap();
    assert_eq!(decoded.ops[0].extent().length, 4097);
    assert!(decoded.ops[0].outdata.is_empty());
    assert_eq!(decoded.ops[0].header_bytes(0)[34..38], [0; 4]);

    assert!(reply.encode_placed_read(0, vec![], 4097).is_err());
    assert!(reply.encode_placed_read(0, vec![1], 4096).is_err());
    reply.ops[0].outdata = bytes::Bytes::from_static(b"x");
    assert!(reply.encode_placed_read(0, vec![1], 4097).is_err());
    reply.ops[0].outdata = bytes::Bytes::new();
    reply.result = -1;
    assert!(reply.encode_placed_read(0, vec![1], 4097).is_err());
}

#[test]
fn placed_read_terminal_error_drops_source_and_carries_retirement() {
    let mut reply = MOSDOpReply {
        ops: vec![OsdOp::read(0, 1 << 20)],
        ..Default::default()
    };
    reply.ops[0].outdata = bytes::Bytes::from(vec![7u8; 1 << 20]);
    let retired = [4u8; 28];
    let wire = reply
        .encode_placed_error(0, retired, errno::EOPNOTSUPP)
        .unwrap();
    assert_eq!(wire.middle, retired);
    assert!(wire.data.is_empty());
    let decoded = MOSDOpReply::decode(8, &wire.front, &wire.middle, &wire.data).unwrap();
    assert_eq!(decoded.result, -errno::EOPNOTSUPP);
    assert_eq!(decoded.ops[0].rval, -errno::EOPNOTSUPP);
    assert!(decoded.ops[0].outdata.is_empty());

    let reply = MOSDOpReply {
        result: -errno::ENOENT,
        ops: vec![OsdOp::read(0, 1 << 20)],
        ..Default::default()
    };
    let wire = reply
        .encode_placed_error(0, retired, errno::EOPNOTSUPP)
        .unwrap();
    let decoded = MOSDOpReply::decode(8, &wire.front, &wire.middle, &wire.data).unwrap();
    assert_eq!(decoded.result, -errno::ENOENT);
    assert_eq!(decoded.ops[0].rval, -errno::ENOENT);
}

#[test]
fn placed_read_payload_moves_pieces_without_copy_and_rejects_bad_sidecars() {
    let first = bytes::Bytes::from(vec![7; 4096]);
    let second = bytes::Bytes::from(vec![9; 3]);
    let first_ptr = first.as_ptr();
    let second_ptr = second.as_ptr();
    let mut operation = OsdOp::read(0, 4099);
    operation.set_outdata_parts([(first, None), (second, None)]);
    operation.outdata_block_crcs = Some(vec![11]);
    let mut reply = MOSDOpReply {
        ops: vec![operation],
        ..Default::default()
    };
    assert!(reply.take_placed_read_payload().is_none());
    assert_eq!(
        reply.ops[0].outdata_len(),
        4099,
        "rejection preserves SEND fallback"
    );
    reply.ops[0].outdata_block_crcs = Some(vec![11, 12]);
    let payload = reply.take_placed_read_payload().expect("valid source");
    assert_eq!(payload.len, 4099);
    assert_eq!(payload.block_crcs, vec![11, 12]);
    assert_eq!(payload.first.0.as_ptr(), first_ptr);
    assert_eq!(payload.more[0].0.as_ptr(), second_ptr);
    assert_eq!(reply.ops[0].outdata_len(), 0);
    assert!(reply.ops[0].outdata_block_crcs.is_none());
    payload.restore(&mut reply).expect("preflight fallback");
    assert_eq!(reply.ops[0].outdata.as_ptr(), first_ptr);
    assert_eq!(reply.ops[0].outdata_more[0].0.as_ptr(), second_ptr);
    assert_eq!(reply.ops[0].outdata_block_crcs, Some(vec![11, 12]));
}

#[test]
fn placed_read_eof_has_no_write_source_piece() {
    let mut operation = OsdOp::read(4096, 0);
    operation.outdata_block_crcs = Some(Vec::new());
    let mut reply = MOSDOpReply {
        ops: vec![operation],
        ..Default::default()
    };
    let payload = reply.take_placed_read_payload().expect("valid EOF");
    assert_eq!(payload.len, 0);
    assert!(payload.pieces().is_empty());
    payload.restore(&mut reply).expect("EOF fallback");
    assert_eq!(reply.ops[0].outdata_len(), 0);
}

#[test]
fn read_op_hand_vector() {
    // s1.3: read 0~4096 = 01 12 | flags 0 | offset 0 | length 0x1000 | trunc_size 0 | trunc_seq 0 | payload_len 0
    let o = OsdOp::read(0, 4096);
    let mut want = vec![0x01, 0x12, 0, 0, 0, 0];
    want.extend_from_slice(&[0; 8]);
    want.extend_from_slice(&0x1000u64.to_le_bytes());
    want.extend_from_slice(&[0; 8 + 4]); // truncate_size, truncate_seq
    want.extend_from_slice(&[0; 4]); // payload_len
    assert_eq!(want.len(), 38);
    assert_eq!(o.header_bytes(0).to_vec(), want);
    let (back, pl) = OsdOp::parse_header(&want).unwrap();
    assert_eq!((back, pl), (o, 0));
}

#[test]
fn union_views_roundtrip_and_offsets() {
    let w = Watch {
        cookie: 1,
        ver: 2,
        op: watch_op::WATCH,
        gen_: 0x0a0b0c0d,
        timeout: 30,
    };
    let u = w.to_union();
    assert_eq!(u[16], 3);
    assert_eq!(&u[17..21], &0x0a0b0c0du32.to_le_bytes());
    assert_eq!(&u[21..25], &30u32.to_le_bytes());
    assert_eq!(&u[25..], &[0, 0, 0]);
    assert_eq!(Watch::from_union(&u), w);
    let c = Cls {
        class_len: 4,
        method_len: 5,
        argc: 0,
        indata_len: 0x01020304,
    };
    let u = c.to_union();
    assert_eq!(&u[..7], &[4, 5, 0, 4, 3, 2, 1]);
    let k = Checksum {
        offset: 8,
        length: 16,
        chunk_size: 4,
        ty: csum::CRC32C,
    };
    assert_eq!(Checksum::from_union(&k.to_union()), k);
    assert_eq!(k.to_union()[20], 2);
    let a = AllocHint {
        expected_object_size: 1 << 22,
        expected_write_size: 1 << 16,
        flags: 3,
    };
    assert_eq!(AllocHint::from_union(&a.to_union()), a);
    let x = Xattr {
        name_len: 1,
        value_len: 2,
        cmp_op: cmpc::GT,
        cmp_mode: cmpc::MODE_U64,
    };
    assert_eq!(&x.to_union()[..10], &[1, 0, 0, 0, 2, 0, 0, 0, 3, 2]);
    let cf = CopyFrom {
        snapid: NOSNAP,
        src_version: 0,
        flags: 0,
        src_fadvise_flags: 0x48,
    };
    assert_eq!(CopyFrom::from_union(&cf.to_union()), cf);
    let p = Pgls {
        count: 1024,
        start_epoch: 214,
    };
    assert_eq!(Pgls::from_union(&p.to_union()), p);
    let av = AssertVer { unused: 0, ver: 9 };
    assert_eq!(&av.to_union()[8..16], &9u64.to_le_bytes());
    let ws = WriteSame {
        offset: 1,
        length: 2,
        data_length: 3,
    };
    assert_eq!(WriteSame::from_union(&ws.to_union()), ws);
}

#[test]
fn unknown_union_bytes_survive_roundtrip() {
    let mut raw = [0u8; 38];
    raw[0] = 0x01;
    raw[1] = 0x12;
    raw[30] = 0xee; // garbage in the unused tail
    let (o, _) = OsdOp::parse_header(&raw).unwrap();
    assert_eq!(o.header_bytes(0), raw);
}

#[test]
fn data_segment_framing() {
    let m = MOSDOp {
        oid: b"o".to_vec(),
        ops: vec![
            OsdOp::write(0, vec![1; 3]),
            OsdOp::read(0, 10),
            OsdOp::setxattr(b"ab", b"cde"),
            OsdOp::writefull(vec![9; 2]),
        ],
        ..Default::default()
    };
    let s = m.encode_version(9, u64::MAX).unwrap();
    assert_eq!(s.data[..], [1, 1, 1, b'a', b'b', b'c', b'd', b'e', 9, 9]);
    let back = MOSDOp::decode(9, &s.front, &[], &s.data).unwrap();
    assert_eq!(back, m);
    // payload_len sum larger than the data segment is rejected
    assert!(MOSDOp::decode(9, &s.front, &[], &s.data[..5]).is_err());
}

#[test]
fn request_data_crc_hint_preserves_one_owner_and_rejects_composite_or_changed_data() {
    let data = bytes::Bytes::from((0..8193).map(|n| (n % 251) as u8).collect::<Vec<_>>());
    let checksum = crc::soft(!0, &data);
    let mut write = OsdOp::writefull(Vec::new());
    write.indata = data.clone();
    write.indata_crc = CrcHint::new(&write.indata, checksum);
    let mut request = MOSDOp {
        ops: vec![OsdOp::stat(), write],
        ..Default::default()
    };
    for version in [7, 8, 9] {
        let encoded = request.encode_version(version, u64::MAX).unwrap();
        assert_eq!(encoded.data.as_ptr(), data.as_ptr());
        assert_eq!(request.data_crc_hint().of(&encoded.data), Some(checksum));
        let mut plain = request.clone();
        plain.ops[1].indata_crc = Default::default();
        let baseline = plain.encode_version(version, u64::MAX).unwrap();
        assert_eq!(encoded.front, baseline.front);
        assert_eq!(encoded.data, baseline.data);
    }
    request.ops[1].indata = data.slice(1..);
    assert_eq!(
        request
            .data_crc_hint()
            .of(&request.encode_version(9, u64::MAX).unwrap().data),
        None
    );
    request.ops[1].indata = bytes::Bytes::copy_from_slice(&data);
    assert_eq!(
        request
            .data_crc_hint()
            .of(&request.encode_version(9, u64::MAX).unwrap().data),
        None
    );
    request.ops[1].indata = data.clone();
    request.ops.push(OsdOp::append(vec![1, 0, 255]));
    let composite = request.encode_version(9, u64::MAX).unwrap();
    assert_eq!(request.data_crc_hint().of(&composite.data), None);
    assert_eq!(&composite.data[..data.len()], data.as_ref());
    assert_eq!(&composite.data[data.len()..], &[1, 0, 255]);
    request.ops.clear();
    assert_eq!(request.data_crc_hint().of(&[]), None);
}
#[test]
fn reply_data_crc_hint_is_only_trusted_for_the_exact_payload() {
    let data = bytes::Bytes::from(vec![7u8; 5000]);
    let mut r = MOSDOpReply::default();
    let mut rd = OsdOp::read(0, 5000);
    rd.outdata = data.clone();
    let c = crc::crc32c(!0, &data);
    rd.outdata_crc = CrcHint::new(&rd.outdata, c);
    r.ops = vec![OsdOp::new(op::STAT), rd];
    // the segment the encoder emits is that very payload (shared, not copied): the hint applies to it
    let s = r.encode(u64::MAX).unwrap();
    assert_eq!(s.data.as_ptr(), data.as_ptr());
    assert_eq!(r.data_crc_hint().of(&s.data), Some(c));
    // cut or replaced payload (hint left stale on purpose): never applies to the new segment
    r.ops[1].outdata = r.ops[1].outdata.slice(..4096);
    let s = r.encode(u64::MAX).unwrap();
    assert_eq!(r.data_crc_hint().of(&s.data), None);
    r.ops[1].outdata = bytes::Bytes::from(vec![7u8; 5000]);
    let s = r.encode(u64::MAX).unwrap();
    assert_eq!(r.data_crc_hint().of(&s.data), None);
    // two data-carrying ops: the segment is a concatenation
    r.ops[1].outdata = data.clone();
    r.ops[0].outdata = bytes::Bytes::from_static(b"x");
    let s = r.encode(u64::MAX).unwrap();
    assert_eq!(r.data_crc_hint().of(&s.data), None);
}

#[test]
fn version_by_features() {
    assert_eq!(mosdop_version_for(u64::MAX), 9);
    assert_eq!(
        mosdop_version_for(consts::feat::RESEND_ON_SPLIT | consts::feat::NEW_OSDOP_ENCODING),
        8
    );
    assert_eq!(mosdop_version_for(consts::feat::NEW_OSDOP_ENCODING), 7);
    let m = MOSDOp {
        oid: b"x".to_vec(),
        ..Default::default()
    };
    let (_, v, c, _) = ClientMsg::Op(m)
        .encode(consts::feat::NEW_OSDOP_ENCODING)
        .unwrap();
    assert_eq!((v, c), (7, 3));
}

#[test]
fn mosdop_old_versions_rejected() {
    assert!(MOSDOp::decode(6, &[0; 64], &[], &[]).is_err());
    assert!(MOSDOpReply::decode(7, &[0; 64], &[], &[]).is_err());
}

#[test]
fn v9_otel_valid_is_skipped_and_kept() {
    let mut m = MOSDOp {
        oid: b"x".to_vec(),
        ..Default::default()
    };
    m.otel.valid = Some(([1; 16], [2; 8], 3));
    let s = m.encode_version(9, u64::MAX).unwrap();
    let back = MOSDOp::decode(9, &s.front, &[], &[]).unwrap();
    assert_eq!(back.otel.valid, Some(([1; 16], [2; 8], 3)));
    assert_eq!(back, m);
}

#[test]
fn effective_reqid() {
    let peer = EntityName::client(55);
    let mut m = MOSDOp {
        client_inc: 7,
        ..Default::default()
    };
    let r = m.effective_reqid(peer, 99);
    assert_eq!((r.name, r.tid, r.inc), (peer, 99, 7));
    m.reqid = OsdReqId {
        name: EntityName::client(1),
        tid: 5,
        inc: 2,
    };
    assert_eq!(m.effective_reqid(peer, 99), m.reqid);
}

#[test]
fn reply_for_request_and_versions() {
    let req = MOSDOp {
        oid: b"o".to_vec(),
        flags: flag::ONDISK | flag::WRITE | flag::RETRY | flag::ONNVRAM,
        retry_attempt: 3,
        ops: vec![OsdOp::write(0, vec![1; 8]), OsdOp::stat()],
        ..Default::default()
    };
    let mut r = MOSDOpReply::for_request(&req, 11);
    assert_eq!(
        r.flags as u32,
        flag::ACK | flag::ONDISK | flag::WRITE | flag::RETRY
    );
    assert!(r.ops.iter().all(|o| o.indata.is_empty()));
    assert_eq!((r.retry_attempt, r.osdmap_epoch), (3, 11));
    r.set_versions(Eversion::new(11, 40), 7);
    assert_eq!(r.bad_replay_version, Eversion::new(11, 7));
    r.ops[1].outdata = denc::to_vec(&StatOut {
        size: 8,
        mtime: UTime::new(1, 2),
    })
    .unwrap()
    .into();
    r.ops[1].rval = 0;
    let s = r.encode(u64::MAX).unwrap();
    assert_eq!(s.data.len(), 16);
    let back = MOSDOpReply::decode(8, &s.front, &[], &s.data).unwrap();
    // payload_len of ops is derived from outdata
    assert_eq!(back, r);
}

#[test]
fn reply_flags_are_8_bytes_on_the_wire() {
    // oid(4+1) pg(17) flags(8)...: result is at offset 5 + 17 + 8
    let mut r = MOSDOpReply {
        oid: b"o".to_vec(),
        flags: 0x0123_4567_89ab_cdef,
        result: -2,
        ..Default::default()
    };
    r.pgid = PgT::new(1, 2);
    let s = r.encode(u64::MAX).unwrap();
    assert_eq!(&s.front[22..30], &0x0123_4567_89ab_cdefu64.to_le_bytes());
    assert_eq!(&s.front[30..34], &(-2i32).to_le_bytes());
}

#[test]
fn backoff_hand_vector_and_roundtrip() {
    let b = MOSDBackoff {
        pgid: SpgT {
            pgid: PgT::new(1, 13),
            shard: ShardId::NO_SHARD,
        },
        map_epoch: 248,
        op: backoff::BLOCK,
        id: 1,
        begin: Hobject::new(b"", SnapId(0), 13, 1, b""),
        end: Hobject::new(b"", SnapId::NOSNAP, 0x7000_0000, 1, b""),
    };
    let s = b.encode(u64::MAX).unwrap();
    // spg_t (ENV 1,1,len 18 + pg_t 17 + shard) = 6 + 18 = 24; then epoch, op, id
    assert_eq!(&s.front[..6], &[1, 1, 18, 0, 0, 0]);
    assert_eq!(&s.front[24..28], &248u32.to_le_bytes());
    assert_eq!(s.front[28], 1);
    assert_eq!(&s.front[29..37], &1u64.to_le_bytes());
    assert_eq!(MOSDBackoff::decode(1, &s.front, &[], &[]).unwrap(), b);
    assert!(s.data.is_empty() && s.middle.is_empty());
}

#[test]
fn client_msg_dispatch() {
    let m = MWatchNotify {
        msg_ver: 1,
        opcode: 3,
        cookie: 5,
        ..Default::default()
    };
    let (ty, v, c, segs) = ClientMsg::WatchNotify(m.clone()).encode(0).unwrap();
    assert_eq!((ty, v, c), (44, 3, 1));
    assert_eq!(
        decode_client(ty, v, &segs).unwrap(),
        ClientMsg::WatchNotify(m)
    );
    let u = decode_client(1234, 2, &Segments::front(vec![1, 2])).unwrap();
    assert!(matches!(u, ClientMsg::Unknown { ty: 1234, .. }));
}

#[test]
fn truncated_and_garbage_never_panic() {
    for (_, ver, m) in [(
        "x",
        9u16,
        ClientMsg::Op(MOSDOp {
            oid: b"abc".to_vec(),
            ops: vec![OsdOp::write(0, vec![1; 4])],
            ..Default::default()
        }),
    )] {
        let (ty, v, _c, s) = match &m {
            ClientMsg::Op(o) => (42, ver, 3, o.encode_version(ver, u64::MAX).unwrap()),
            _ => unreachable!(),
        };
        for n in 0..s.front.len() {
            let _ = decode_client_parts(ty, v, &s.front[..n], &[], &s.data);
        }
        // absurd num_ops / lengths
        let mut f = s.front.clone();
        for i in 0..f.len() {
            let old = f[i];
            f[i] = 0xff;
            let _ = decode_client_parts(ty, v, &f, &[], &s.data);
            f[i] = old;
        }
    }
}

#[test]
fn classification_helpers() {
    use op::*;
    assert!(modifies(WRITE) && modifies(OMAP_RM_KEY_RANGE) && modifies(WATCH) && modifies(TMAPUP));
    assert!(!modifies(READ) && !modifies(CALL));
    assert!(
        reads(READ)
            && reads(STAT)
            && reads(NOTIFY)
            && !reads(CALL)
            && !reads(WRITE)
            && reads(TMAPGET)
    );
    assert!(is_pg_op(PGNLS) && is_pg_op(PGLS_FILTER) && !is_pg_op(READ));
    assert!(is_cache(CACHE_FLUSH) && is_cache(SET_CHUNK) && !is_cache(WRITE));
    assert!(is_sub(0x4001));
    assert!(
        is_later(MASKTRUNC)
            && is_later(TMAP2OMAP)
            && !is_later(MAPEXT)
            && !is_later(COPY_FROM2)
            && !is_later(CHECKSUM)
    );
    assert_eq!(op::name(CMPEXT), Some("cmpext"));
    assert_eq!(op::name(0x4003), Some("sub-op"));
    assert_eq!(op::name(0x7777), None);
}

fn flags_of(rd: bool, wr: bool) -> impl Fn(&[u8], &[u8]) -> Option<ClsEntry> {
    move |c, m| {
        (c == b"lock" || c == b"rbd").then_some(ClsEntry {
            flags: ClsFlags {
                rd: rd && !m.is_empty(),
                wr,
            },
            allowed: true,
        })
    }
}

#[test]
fn opinfo_classification() {
    let no_cls = |_: &[u8], _: &[u8]| None;
    let i = OpInfo::classify(&[OsdOp::read(0, 1)], 0, &no_cls).unwrap();
    assert!(i.may_read && !i.may_write && i.read_data && !i.rwordered && !i.primary_only);
    let i = OpInfo::classify(&[OsdOp::stat()], 0, &no_cls).unwrap();
    assert!(i.may_read && !i.read_data);
    let i = OpInfo::classify(&[OsdOp::stat()], flag::RWORDERED, &no_cls).unwrap();
    assert!(i.rwordered);
    let i = OpInfo::classify(&[OsdOp::write(0, vec![1])], 0, &no_cls).unwrap();
    assert!(i.may_write && !i.may_read && i.rwordered);
    let i = OpInfo::classify(
        &[OsdOp::cmpext(0, vec![1]), OsdOp::write(0, vec![1])],
        0,
        &no_cls,
    )
    .unwrap();
    assert!(i.may_write && i.may_read && i.read_data);
    // watch: may_read forced, primary-only; PING is not a write but rwordered
    let w = OsdOp::watch_op(1, watch_op::WATCH, 0);
    let i = OpInfo::classify(&[w], 0, &no_cls).unwrap();
    assert!(i.may_write && i.may_read && i.primary_only);
    let p = OsdOp::watch_op(1, watch_op::PING, 0);
    let i = OpInfo::classify(&[p], 0, &no_cls).unwrap();
    assert!(!i.may_write && i.may_read && i.rwordered && i.primary_only);
    let i = OpInfo::classify(&[OsdOp::notify_op(1, 0, b"x")], 0, &no_cls).unwrap();
    assert!(i.primary_only && i.may_read);
    // pg ops
    let i = OpInfo::classify(&[OsdOp::pgnls(10, &Hobject::MIN())], 0, &no_cls).unwrap();
    assert!(i.pg_op && i.primary_only);
    // cls: flags from the registry
    let call = OsdOp::call(b"lock", b"lock", b"");
    let i = OpInfo::classify(std::slice::from_ref(&call), 0, &flags_of(true, true)).unwrap();
    assert!(i.may_read && i.may_write && i.cls.len() == 1 && i.cls[0].class == b"lock");
    let i = OpInfo::classify(std::slice::from_ref(&call), 0, &flags_of(false, true)).unwrap();
    assert!(!i.may_read && i.may_write);
    // unknown method -> EOPNOTSUPP; no flags at all -> EINVAL; SUB op -> EINVAL
    assert_eq!(
        OpInfo::classify(&[OsdOp::call(b"x", b"y", b"")], 0, &no_cls),
        Err(errno::EOPNOTSUPP)
    );
    assert_eq!(
        OpInfo::classify(
            &[OsdOp::call(b"lock", b"", b"")],
            0,
            &flags_of(false, false)
        ),
        Err(errno::EINVAL)
    );
    assert_eq!(
        OpInfo::classify(&[OsdOp::new(0x4001)], 0, &no_cls),
        Err(errno::EINVAL)
    );
    // malformed call framing
    let mut bad = call;
    bad.indata = bad.indata.slice(..bad.indata.len() - 1);
    assert_eq!(
        OpInfo::classify(&[bad], 0, &flags_of(true, true)),
        Err(errno::EINVAL)
    );
}

#[test]
fn cmpext_mismatch_codes() {
    assert_eq!(errno::cmpext_mismatch(0), -4095);
    assert_eq!(errno::cmpext_mismatch(17), -4112);
    assert_eq!(errno::cmpext_index(-4112), Some(17));
    assert_eq!(errno::cmpext_index(-125), None);
    assert_eq!(errno::cmpext_index(-4095), Some(0));
}

#[test]
fn cls_call_and_xattr_framing() {
    let o = OsdOp::call(b"rbd", b"get_size", b"\x01\x02");
    let c = o.cls_call().unwrap();
    assert_eq!(
        (c.class, c.method, c.input),
        (&b"rbd"[..], &b"get_size"[..], &b"\x01\x02"[..])
    );
    let x = OsdOp::cmpxattr(b"name", &7u64.to_le_bytes(), cmpc::EQ, cmpc::MODE_U64);
    let (n, v) = x.xattr_name_value().unwrap();
    assert_eq!((n, v), (&b"name"[..], &7u64.to_le_bytes()[..]));
}

#[test]
#[should_panic(expected = "class name does not fit the u8 wire length")]
fn call_constructor_refuses_oversized_class() {
    let _ = OsdOp::call(&[b'x'; 256], b"m", b"");
}

#[test]
#[should_panic(expected = "method name does not fit the u8 wire length")]
fn call_constructor_refuses_oversized_method() {
    let _ = OsdOp::call(b"c", &[b'x'; 256], b"");
}

#[test]
fn indata_payloads_roundtrip() {
    let n = OsdOp::notify_op(5, 10, b"payload");
    let ni: NotifyIn = n.indata_as().unwrap();
    assert_eq!(
        (ni.prot_ver, ni.timeout, ni.payload.as_slice()),
        (1, 10, &b"payload"[..])
    );
    let a = OsdOp::notify_ack(0xe8_0000_008f, 77, b"r");
    let ai: NotifyAckIn = a.indata_as().unwrap();
    assert_eq!(
        (ai.notify_id, ai.cookie, ai.reply.as_slice()),
        (0xe8_0000_008f, 77, &b"r"[..])
    );
    let g = OsdOp::omap_get_vals(b"a", 10, b"p");
    assert_eq!(
        g.indata_as::<OmapGetValsIn>().unwrap(),
        OmapGetValsIn {
            start_after: b"a".to_vec(),
            max_return: 10,
            filter_prefix: b"p".to_vec()
        }
    );
    let mut kv = KvMap::new();
    kv.insert(b"k1".to_vec(), b"v1".to_vec());
    kv.insert(vec![0xff, 0], vec![]);
    assert_eq!(OsdOp::omap_set_vals(&kv).indata_as::<KvMap>().unwrap(), kv);
    let cmp: OmapCmpIn = [(b"k".to_vec(), (b"v".to_vec(), 1i32))].into();
    assert_eq!(
        denc::from_slice::<OmapCmpIn>(&denc::to_vec(&cmp).unwrap()).unwrap(),
        cmp
    );
    let pg = OsdOp::pgnls(5, &Hobject::MIN());
    assert_eq!(pgls_cursor(&pg.indata).unwrap(), Hobject::MIN());
    assert_eq!(pg.pgls().count, 5);
}

#[test]
fn outdata_payloads_roundtrip() {
    let c = ChecksumOut {
        ty: csum::XXHASH64,
        values: vec![1, u64::MAX],
    };
    let b = c.encode_to_vec().unwrap();
    assert_eq!(b.len(), 4 + 16);
    assert_eq!(ChecksumOut::decode(csum::XXHASH64, &b).unwrap(), c);
    let c32 = ChecksumOut {
        ty: csum::CRC32C,
        values: vec![0xdead_beef],
    };
    assert_eq!(
        c32.encode_to_vec().unwrap(),
        [1, 0, 0, 0, 0xef, 0xbe, 0xad, 0xde]
    );
    assert!(ChecksumOut::decode(csum::CRC32C, &[5, 0, 0, 0]).is_err());
    let s = SparseReadOut {
        extents: [(0u64, 4u64), (8, 2)].into(),
        data: vec![1; 6],
    };
    assert_eq!(
        denc::from_slice::<SparseReadOut>(&denc::to_vec(&s).unwrap()).unwrap(),
        s
    );
    let o = OmapKeysOut {
        keys: vec![b"a".to_vec(), b"b".to_vec()],
        truncated: true,
    };
    let b = denc::to_vec(&o).unwrap();
    assert_eq!(*b.last().unwrap(), 1);
    assert_eq!(denc::from_slice::<OmapKeysOut>(&b).unwrap(), o);
    let w = WatchItem {
        name: EntityName::client(5),
        cookie: 9,
        timeout_s: 30,
        addr: EntityAddr::v4(EntityAddr::TYPE_ANY, 77, [10, 0, 0, 1], 0),
    };
    let r = ObjListWatchResponse { entries: vec![w] };
    assert_eq!(
        denc::from_slice::<ObjListWatchResponse>(&denc::to_vec(&r).unwrap()).unwrap(),
        r
    );
    let l = ObjListSnapResponse {
        clones: vec![
            CloneInfo {
                cloneid: 4,
                snaps: vec![2, 3],
                overlap: vec![(0, 10)],
                size: 10,
            },
            CloneInfo {
                cloneid: NOSNAP,
                size: 12,
                ..Default::default()
            },
        ],
        seq: 4,
    };
    assert_eq!(
        denc::from_slice::<ObjListSnapResponse>(&denc::to_vec(&l).unwrap()).unwrap(),
        l
    );
    let n = NotifyCompleteData {
        replies: [((1, 2), vec![3])].into(),
        missed: vec![(4, 5)],
    };
    assert_eq!(
        denc::from_slice::<NotifyCompleteData>(&denc::to_vec(&n).unwrap()).unwrap(),
        n
    );
}

#[test]
fn pgnls_filter_plain() {
    let mut e = denc::Encoder::new();
    e.bytes(b"pg").unwrap();
    e.bytes(b"filter").unwrap();
    e.bytes(b"plain").unwrap();
    e.bytes(b"x").unwrap();
    e.bytes(b"needle").unwrap();
    Hobject::MIN().encode(&mut e).unwrap();
    let f: PgFilterIn = denc::from_slice(&e.into_vec()).unwrap();
    assert_eq!(
        f.filter,
        Some(PgFilter::Xattr {
            xattr: b"x".to_vec(),
            val: b"needle".to_vec()
        })
    );
    assert_eq!(f.cursor, Some(Hobject::MIN()));
}

#[test]
fn errno_and_const_spot_checks() {
    assert_eq!(op::WRITESAME, 0x2226);
    assert_eq!(op::OMAP_RM_KEY_RANGE, 0x222c);
    assert_ne!(op::TIER_EVICT, op::OMAP_RM_KEY_RANGE);
    assert_eq!(flag::RETURNVEC, 0x4000000);
    assert_eq!(NOSNAP, 0xffff_ffff_ffff_fffe);
    assert_eq!(SNAPDIR, u64::MAX);
}

#[test]
fn decode_client_shares_the_data_segment() {
    let mut m = MOSDOp::default();
    m.ops.push(OsdOp::write(0, vec![7; 10_000]));
    m.ops.push(OsdOp::write(10_000, vec![8; 5]));
    let (ty, ver, _, segs) = ClientMsg::Op(m).encode(u64::MAX).unwrap();
    let ClientMsg::Op(back) = decode_client(ty, ver, &segs).unwrap() else {
        panic!()
    };
    let base = segs.data.as_ptr() as usize;
    assert_eq!(back.ops[0].indata.as_ptr() as usize, base);
    assert_eq!(back.ops[1].indata.as_ptr() as usize, base + 10_000);
    let ClientMsg::Op(borrowed) =
        decode_client_shared_parts(ty, ver, &segs.front, &segs.middle, &segs.data).unwrap()
    else {
        panic!()
    };
    assert_eq!(borrowed.ops[0].indata.as_ptr() as usize, base);
    assert_eq!(borrowed.ops[1].indata.as_ptr() as usize, base + 10_000);
    // single non-empty op: the reply data segment is the op's buffer itself
    let mut r = MOSDOpReply::default();
    let mut o = OsdOp::new(opwire::consts::op::READ);
    o.outdata = vec![1; 4096].into();
    let p = o.outdata.as_ptr();
    r.ops.push(o);
    r.ops.push(OsdOp::new(opwire::consts::op::STAT));
    let (ty, ver, _, reply) = ClientMsg::OpReply(r).encode(u64::MAX).unwrap();
    assert_eq!(reply.data.as_ptr(), p);
    let ClientMsg::OpReply(decoded) =
        decode_client_shared_parts(ty, ver, &reply.front, &reply.middle, &reply.data).unwrap()
    else {
        panic!()
    };
    assert_eq!(decoded.ops[0].outdata.as_ptr(), p);
}

#[test]
fn pgnls_filter_cls_types() {
    let head = |ty: &[u8]| {
        let mut e = denc::Encoder::new();
        e.bytes(b"pg").unwrap();
        e.bytes(b"filter").unwrap();
        e.bytes(ty).unwrap();
        e
    };
    let mut e = head(b"cephfs.inode_tag");
    e.versioned(1, 1, |e| e.bytes(b"tag1")).unwrap();
    Hobject::MIN().encode(&mut e).unwrap();
    let f: PgFilterIn = denc::from_slice(&e.into_vec()).unwrap();
    assert_eq!(
        f.filter,
        Some(PgFilter::CephfsInodeTag {
            scrub_tag: b"tag1".to_vec()
        })
    );
    assert_eq!(f.cursor, Some(Hobject::MIN()));
    let mut e = head(b"hello.hello");
    e.bytes(b"a").unwrap();
    e.bytes(b"b").unwrap();
    Hobject::MAX().encode(&mut e).unwrap();
    let f: PgFilterIn = denc::from_slice(&e.into_vec()).unwrap();
    assert!(matches!(f.filter, Some(PgFilter::Xattr { .. })));
    // unknown type: no filter, no cursor (the op answers EINVAL)
    let f: PgFilterIn = denc::from_slice(&head(b"foo.bar").into_vec()).unwrap();
    assert_eq!((f.filter, f.cursor), (None, None));
}

#[test]
fn normal_reply_front_size_vectors_and_encoder_agree_without_payload_allocations() {
    assert_eq!(MOSDOpReply::normal_front_len(0, 0), Some(102));
    assert_eq!(MOSDOpReply::normal_front_len(10, 1), Some(154));
    assert_eq!(MOSDOpReply::normal_front_len(3, 2), Some(189));
    assert_eq!(MOSDOpReply::normal_front_len(usize::MAX, 1), None);
    assert_eq!(MOSDOpReply::normal_front_len(1, usize::MAX), None);
    for n in [0, 1, 2, 40] {
        let reply = MOSDOpReply {
            oid: b"x\0\xff".to_vec(),
            ops: (0..n).map(|_| OsdOp::read(0, 4)).collect(),
            ..Default::default()
        };
        let encoded = reply.encode(0).unwrap();
        assert_eq!(
            encoded.front.len(),
            MOSDOpReply::normal_front_len(3, n).unwrap()
        );
        assert!(encoded.data.is_empty());
    }
}

#[test]
fn checksum_reply_empty_and_exact_width_vectors() {
    for ty in [csum::XXHASH32, csum::XXHASH64, csum::CRC32C] {
        assert_eq!(
            ChecksumOut::decode(ty, &[]).unwrap().values,
            Vec::<u64>::new()
        );
        assert_eq!(
            ChecksumOut::decode(ty, &[0, 0, 0, 0]).unwrap().values,
            Vec::<u64>::new()
        );
        let value = if ty == csum::XXHASH64 {
            0xfedcba9876543210u64
        } else {
            0x98765432u64
        };
        let width = if ty == csum::XXHASH64 { 8 } else { 4 };
        let mut vector = vec![1, 0, 0, 0];
        vector.extend_from_slice(&value.to_le_bytes()[..width]);
        assert_eq!(ChecksumOut::decode(ty, &vector).unwrap().values, [value]);
        for length in 1..4 {
            assert!(ChecksumOut::decode(ty, &vector[..length]).is_err());
        }
        assert!(ChecksumOut::decode(ty, &vector[..vector.len() - 1]).is_err());
    }
    assert!(ChecksumOut::decode(255, &[]).is_err());
}
#[test]
fn checksum_reply_rejects_trailing_and_excessive_count() {
    for ty in [csum::XXHASH32, csum::XXHASH64, csum::CRC32C] {
        assert_eq!(
            ChecksumOut::decode(ty, &[0, 0, 0, 0, 42]),
            Err(denc::Error::TrailingBytes(1))
        );
        let mut vector = vec![1, 0, 0, 0];
        vector.extend_from_slice(&[0; 8][..if ty == csum::XXHASH64 { 8 } else { 4 }]);
        vector.push(0);
        assert_eq!(
            ChecksumOut::decode(ty, &vector),
            Err(denc::Error::TrailingBytes(1))
        );
        assert!(ChecksumOut::decode(ty, &u32::MAX.to_le_bytes()).is_err());
    }
}

fn sparse_wire(extents: &[(u64, u64)], data: &[u8]) -> Vec<u8> {
    let mut b = (extents.len() as u32).to_le_bytes().to_vec();
    for (at, len) in extents {
        b.extend_from_slice(&at.to_le_bytes());
        b.extend_from_slice(&len.to_le_bytes());
    }
    b.extend_from_slice(&(data.len() as u32).to_le_bytes());
    b.extend_from_slice(data);
    b
}

#[test]
fn sparse_results_reject_ambiguous_extents_and_mismatched_data() {
    for (extents, data) in [
        (vec![(1, 1), (1, 1)], vec![0, 1]), // duplicate
        (vec![(8, 1), (1, 1)], vec![0, 1]), // unsorted
        (vec![(1, 4), (3, 2)], vec![0; 6]), // overlap
        (vec![(u64::MAX, 1)], vec![0]),     // end overflow
        (vec![(1, 2)], vec![0]),            // short data
        (vec![(1, 1)], vec![0, 1]),         // extra data
        (vec![], vec![0]),
    ] {
        let raw = sparse_wire(&extents, &data);
        assert!(denc::from_slice::<SparseReadView<'_>>(&raw).is_err());
        assert!(denc::from_slice::<SparseReadOut>(&raw).is_err());
    }
    let valid = sparse_wire(&[(4, 2), (9, 1)], &[0xff, 0, 1]);
    for end in 0..valid.len() {
        assert!(denc::from_slice::<SparseReadView<'_>>(&valid[..end]).is_err());
    }
    assert!(denc::from_slice::<SparseReadView<'_>>(&u32::MAX.to_le_bytes()).is_err());
    let mut suffix = valid;
    suffix.push(0);
    assert!(matches!(
        denc::from_slice::<SparseReadOut>(&suffix),
        Err(denc::Error::TrailingBytes(1))
    ));
}

#[test]
fn sparse_view_preserves_binary_data_stream_boundaries_and_ranges() {
    use denc::Decode;
    let raw = sparse_wire(&[(4, 2), (6, 0), (9, 1)], &[0xff, 0, 1]);
    let view: SparseReadView<'_> = denc::from_slice(&raw).unwrap();
    assert_eq!(view.extents().collect::<Vec<_>>(), [(4, 2), (6, 0), (9, 1)]);
    assert_eq!(view.data().as_ptr(), raw[raw.len() - 3..].as_ptr());
    assert!(view.validate_range(4, 6).is_ok());
    assert!(view.validate_range(5, 5).is_err());
    assert!(view.validate_range(4, 5).is_err());
    assert!(view.validate_range(u64::MAX, 1).is_err());
    let empty = sparse_wire(&[], &[]);
    let view: SparseReadView<'_> = denc::from_slice(&empty).unwrap();
    assert!(view.extents().next().is_none());
    assert!(view.validate_range(100, 0).is_ok());
    let adjacent = sparse_wire(&[(4, 1), (5, 1)], &[1, 2]);
    assert!(denc::from_slice::<SparseReadOut>(&adjacent).is_ok());
    let mut stream = raw.clone();
    stream.extend_from_slice(&[0x12, 0x34]);
    let mut d = denc::Decoder::new(&stream);
    let owned = SparseReadOut::decode(&mut d).unwrap();
    assert_eq!(owned.data, [0xff, 0, 1]);
    assert_eq!(d.position(), raw.len());
    assert_eq!(d.u16().unwrap(), 0x3412);
}

/// omap-set-vals indata as one buffer (KvRun): canonical input is kept as is, other input normalized with the map
/// rule (ascending, last value of a repeated key wins), errors as a KvMap decode.
#[test]
fn kv_run_parse() {
    let enc = |pairs: &[(&[u8], &[u8])]| {
        let mut v = (pairs.len() as u32).to_le_bytes().to_vec();
        for (k, x) in pairs {
            v.extend_from_slice(&(k.len() as u32).to_le_bytes());
            v.extend_from_slice(k);
            v.extend_from_slice(&(x.len() as u32).to_le_bytes());
            v.extend_from_slice(x);
        }
        bytes::Bytes::from(v)
    };
    let canon = enc(&[(b"a", b"1"), (b"b", b""), (&[0xff, 0], b"3")]);
    let r = KvRun::parse(&canon).unwrap();
    assert_eq!(r.len(), 3);
    assert_eq!(
        r.encoded().as_ptr(),
        canon.as_ptr(),
        "canonical indata is not copied"
    );
    let got: Vec<_> = r.iter().collect();
    assert_eq!(
        got,
        vec![(&b"a"[..], &b"1"[..]), (b"b", b""), (&[0xff, 0][..], b"3")]
    );
    // unsorted with a repeated key: map order, last value wins (same as decoding a KvMap)
    let raw = enc(&[(b"b", b"1"), (b"a", b"2"), (b"b", b"3")]);
    let r = KvRun::parse(&raw).unwrap();
    let m: KvMap = denc::from_slice(&raw).unwrap();
    assert_eq!(
        r.iter()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect::<KvMap>(),
        m
    );
    assert_eq!(
        r.iter().map(|(k, _)| k).collect::<Vec<_>>(),
        vec![&b"a"[..], b"b"]
    );
    assert_eq!(r.encoded()[..], enc(&[(b"a", b"2"), (b"b", b"3")])[..]);
    assert_eq!(
        r,
        KvRun::from_pairs([(&b"b"[..], &b"1"[..]), (b"a", b"2"), (b"b", b"3")])
    );
    // errors: truncated, trailing bytes, count beyond the buffer
    let mut t = canon.to_vec();
    t.pop();
    assert!(KvRun::parse(&bytes::Bytes::from(t)).is_err());
    let mut t = canon.to_vec();
    t.push(0);
    assert!(KvRun::parse(&bytes::Bytes::from(t)).is_err());
    assert!(KvRun::parse(&bytes::Bytes::from_static(&[9, 0, 0, 0])).is_err());
    let e = KvRun::parse(&enc(&[])).unwrap();
    assert!(e.is_empty() && e.iter().next().is_none());
}

#[test]
fn peek_write_finds_the_pg_and_the_single_write_without_the_data() {
    let feats = [
        u64::MAX,
        consts::feat::RESEND_ON_SPLIT | consts::feat::NEW_OSDOP_ENCODING,
    ];
    for f in feats {
        let mk = |ops: Vec<OsdOp>| {
            let m = MOSDOp {
                pgid: SpgT {
                    pgid: PgT::new(3, 17),
                    shard: ShardId::NO_SHARD,
                },
                oid: b"rbd_data.1".to_vec(),
                ops,
                ..Default::default()
            };
            let (_, v, _, segs) = ClientMsg::Op(m).encode(f).unwrap();
            MOSDOp::peek_write(v, &segs.front_bytes().unwrap()).unwrap()
        };
        let hint = OsdOp::new(consts::op::SET_ALLOC_HINT);
        let p = mk(vec![hint.clone(), OsdOp::write(8192, vec![1; 1 << 20])]);
        assert_eq!(p.pgid.pgid, PgT::new(3, 17));
        assert_eq!(
            p.write,
            Some(PeekWrite {
                at: 0,
                offset: 8192,
                len: 1 << 20
            })
        );
        let p = mk(vec![OsdOp::writefull(vec![2; 300_000])]);
        assert_eq!(
            p.write.map(|w| (w.at, w.offset, w.len)),
            Some((0, 0, 300_000))
        );
        // two data ops, or data that is not a write: no pre-write hint
        let two = mk(vec![
            OsdOp::write(0, vec![1; 10]),
            OsdOp::write(10, vec![1; 1 << 20]),
        ]);
        assert_eq!(two.write, None);
        let cmp = mk(vec![OsdOp::new(consts::op::STAT)]);
        assert_eq!(cmp.write, None);
    }
    assert!(MOSDOp::peek_write(9, &[1, 2, 3]).is_err());
}

#[test]
fn omap_vals_out_matches_the_map_encoding() {
    let kv = |p: &[(&[u8], &[u8])]| -> Vec<(Vec<u8>, Vec<u8>)> {
        p.iter().map(|(k, v)| (k.to_vec(), v.to_vec())).collect()
    };
    let map_enc = |e: &[(Vec<u8>, Vec<u8>)], t: bool| {
        denc::to_vec(&OmapValsOut {
            vals: e.iter().cloned().collect(),
            truncated: t,
        })
        .unwrap()
    };
    // listing order (strictly ascending): written directly; anything else takes the map rule (sorted, last wins)
    for (e, t) in [
        (kv(&[]), false),
        (kv(&[(b"a", b"1")]), true),
        (
            kv(&[(b"a", b""), (b"ab", b"2"), (b"b", &[0u8; 300])]),
            false,
        ),
        (kv(&[(b"b", b"1"), (b"a", b"2")]), true),
        (kv(&[(b"a", b"1"), (b"a", b"2"), (b"c", b"3")]), false),
    ] {
        assert_eq!(omap_vals_out(&e, t), map_enc(&e, t), "{e:?}");
    }
}

/// A listing encoded by the store, finished in place, is byte for byte the vals / keys reply of the same entries.
#[test]
fn omap_list_out_matches_the_reply_encodings() {
    let e: Vec<(Vec<u8>, Vec<u8>)> = [(&b"a"[..], &b""[..]), (b"ab", b"2"), (b"b", &[7u8; 300])]
        .iter()
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect();
    for (n, t) in [(0usize, false), (1, true), (3, false), (3, true)] {
        let (mut vals, mut keys) = (vec![0u8; OMAP_LIST_HEAD], vec![0u8; OMAP_LIST_HEAD]);
        for (k, v) in &e[..n] {
            for b in [&mut vals, &mut keys] {
                b.extend_from_slice(&(k.len() as u32).to_le_bytes());
                b.extend_from_slice(k);
            }
            vals.extend_from_slice(&(v.len() as u32).to_le_bytes());
            vals.extend_from_slice(v);
        }
        assert_eq!(
            omap_list_out(vals, n as u32, t),
            omap_vals_out(&e[..n], t),
            "vals n {n} truncated {t}"
        );
        let want = denc::to_vec(&OmapKeysOut {
            keys: e[..n].iter().map(|(k, _)| k.clone()).collect(),
            truncated: t,
        })
        .unwrap();
        assert_eq!(
            omap_list_out(keys, n as u32, t),
            want,
            "keys n {n} truncated {t}"
        );
    }
}

/// Microbench (ignored; `cargo test --release -p opwire --test unit perf_omap_vals_out -- --ignored --nocapture`): one
/// 1024-entry omap-get-vals reply (14 B keys, 200 B values) through the map encoding vs straight from the listing.
#[test]
#[ignore]
fn perf_omap_vals_out() {
    let e: Vec<(Vec<u8>, Vec<u8>)> = (0..1024u32)
        .map(|i| (format!("key.{i:010}").into_bytes(), vec![i as u8; 200]))
        .collect();
    let n = 200;
    // the listing is moved into the map (as the executor did), so copies are made before the clock starts
    let copies: Vec<_> = (0..n).map(|_| e.clone()).collect();
    let t = std::time::Instant::now();
    for c in copies {
        let vals: KvMap = c.into_iter().collect();
        std::hint::black_box(
            denc::to_vec(&OmapValsOut {
                vals,
                truncated: true,
            })
            .unwrap(),
        );
    }
    let map_ns = t.elapsed().as_nanos() as f64 / (n * e.len()) as f64;
    let t = std::time::Instant::now();
    for _ in 0..n {
        std::hint::black_box(omap_vals_out(std::hint::black_box(&e), true));
    }
    let direct_ns = t.elapsed().as_nanos() as f64 / (n * e.len()) as f64;
    println!(
        "omap-get-vals reply encode: map {map_ns:.1} ns/entry, direct {direct_ns:.1} ns/entry"
    );
}

#[test]
fn mosdop_identity_storage_preserves_all_wire_versions_and_payload_owners() {
    for locator_hash in [-1, 42] {
        let owned = MOSDOp {
            pgid: SpgT {
                pgid: PgT::new(7, 13),
                shard: ShardId::NO_SHARD,
            },
            hash: 13,
            osdmap_epoch: 91,
            flags: flag::WRITE | flag::ONDISK | flag::RETRY,
            reqid: OsdReqId {
                name: EntityName::client(31),
                tid: 97,
                inc: 11,
            },
            reassert_version: Eversion::new(12, 99),
            trace: [3; 24],
            otel: OtelTrace {
                valid: Some(([4; 16], [5; 8], 6)),
            },
            client_inc: 11,
            mtime: UTime::new(7, 8),
            oloc: ObjectLocator {
                pool: 7,
                key: if locator_hash == -1 {
                    b"locator\0key".to_vec()
                } else {
                    Vec::new()
                },
                nspace: b"namespace\0bytes".to_vec(),
                hash: locator_hash,
            },
            oid: b"object\0identity".to_vec(),
            ops: vec![
                OsdOp::read(9, 1 << 20),
                OsdOp::write(5, b"shared-payload".to_vec()),
            ],
            snap_seq: 80,
            snaps: vec![78, 71],
            retry_attempt: 3,
            features: 0x1234,
            ..Default::default()
        };
        let borrowed = MOSDOpStorage {
            source_pull: None,
            source_pull_error: None,
            pgid: owned.pgid,
            hash: owned.hash,
            osdmap_epoch: owned.osdmap_epoch,
            flags: owned.flags,
            reqid: owned.reqid,
            reassert_version: owned.reassert_version,
            trace: owned.trace,
            otel: owned.otel,
            client_inc: owned.client_inc,
            mtime: owned.mtime,
            oloc: ObjectLocatorStorage {
                pool: owned.oloc.pool,
                key: owned.oloc.key.as_slice(),
                nspace: owned.oloc.nspace.as_slice(),
                hash: owned.oloc.hash,
            },
            oid: owned.oid.as_slice(),
            ops: owned.ops.clone(),
            snapid: owned.snapid,
            snap_seq: owned.snap_seq,
            snaps: owned.snaps.clone(),
            retry_attempt: owned.retry_attempt,
            features: owned.features,
            ..Default::default()
        };
        assert_eq!(borrowed.oid.as_ptr(), owned.oid.as_ptr());
        assert_eq!(borrowed.oloc.nspace.as_ptr(), owned.oloc.nspace.as_ptr());
        for version in [7, 8, 9] {
            for features in [0, u64::MAX] {
                let a = owned.encode_version(version, features).unwrap();
                let b = borrowed.encode_version(version, features).unwrap();
                assert_eq!(
                    (a.front.as_slice(), a.middle.as_slice(), a.data.as_ref()),
                    (b.front.as_slice(), b.middle.as_slice(), b.data.as_ref())
                );
                let decoded = MOSDOp::decode_shared(version, &b.front, &b.data).unwrap();
                assert_eq!(decoded.oid, owned.oid);
                assert_eq!(decoded.oloc, owned.oloc);
                assert_eq!(decoded.ops, owned.ops);
                assert_eq!(
                    (decoded.snapid, decoded.snap_seq, decoded.snaps),
                    (owned.snapid, owned.snap_seq, owned.snaps.clone())
                );
                let (parts, _, more) = borrowed.encode_parts_version(version, features).unwrap();
                assert_eq!(parts.front, a.front);
                assert!(more.is_empty());
                assert_eq!(parts.data.as_ptr(), owned.ops[1].indata.as_ptr());
            }
        }
        assert_eq!(
            MOSDOpReply::for_request(&borrowed, 91),
            MOSDOpReply::for_request(&owned, 91)
        );
    }
}

/// A write whose input is several pieces (a multi-segment caller buffer) is the same on the wire as one flat input:
/// the op header carries the total length, the data segment is the pieces in order, and the scatter encoding hands out
/// the very pieces (no flattening copy).
#[test]
fn multi_piece_write_input_encodes_like_the_flat_input_and_shares_its_pieces() {
    let first = bytes::Bytes::from(vec![1; 4096]);
    let second = bytes::Bytes::from(vec![2; 5]);
    let third = bytes::Bytes::from(vec![3; 700]);
    let (first_ptr, second_ptr, third_ptr) = (first.as_ptr(), second.as_ptr(), third.as_ptr());
    let mut flat_bytes = Vec::new();
    for piece in [&first, &second, &third] {
        flat_bytes.extend_from_slice(piece);
    }
    let mut pieces = OsdOp::write_bytes(0, bytes::Bytes::new());
    pieces.set_indata_parts([
        (first.clone(), Some(crc::crc32c(!0, &first))),
        (bytes::Bytes::new(), None),
        (second.clone(), None),
        (third.clone(), Some(crc::crc32c(!0, &third))),
    ]);
    let mut extent = pieces.extent();
    extent.length = flat_bytes.len() as u64;
    pieces.set_extent(extent);
    assert_eq!(pieces.indata_len(), flat_bytes.len());
    assert_eq!(pieces.indata_more.len(), 2, "the empty piece is skipped");
    let flat = OsdOp::write_bytes(0, flat_bytes.clone().into());
    let message = |op: OsdOp| MOSDOp {
        ops: vec![op],
        ..Default::default()
    };
    let (split, flattened) = (message(pieces), message(flat));
    let a = split.encode_version(9, 0).unwrap();
    let b = flattened.encode_version(9, 0).unwrap();
    assert_eq!(a.front, b.front, "the same op header (payload_len = total)");
    assert_eq!(a.data, b.data);
    assert_eq!(split.data_len(), flat_bytes.len());
    let (segments, hint, more) = split.encode_parts_version(9, 0).unwrap();
    assert_eq!(segments.front, b.front);
    assert_eq!(segments.data.as_ptr(), first_ptr);
    assert_eq!(more[0].0.as_ptr(), second_ptr);
    assert_eq!(more[1].0.as_ptr(), third_ptr);
    assert!(hint.of(&segments.data).is_some());
    assert!(more[0].1.of(&more[0].0).is_none());
    assert!(more[1].1.of(&more[1].0).is_some());
    // the OSD side decodes one flat input
    let decoded = MOSDOp::decode(9, &a.front, &[], &a.data).unwrap();
    assert_eq!(decoded.ops[0].indata.as_ref(), &flat_bytes[..]);
    assert!(decoded.ops[0].indata_more.is_empty());
}
