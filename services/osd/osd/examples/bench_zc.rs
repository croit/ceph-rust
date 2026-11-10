// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Payload copies on the in-memory message path (no NIC, no device): 4 MiB client write on a size-3 primary
//! (rx frame -> decode -> txn -> 2 x MOSDRepOp frames) and the matching read reply (store buffer -> reply frame).
//! `cargo run --release -p osd --example bench_zc -- [KiB]`.
use bytes::Bytes;
use messages::Header2;
use msgr2::{Decoder, Encoder, Revision};
use opwire::{ClientMsg, MOSDOp, MOSDOpReply, OsdOp};
use replwire::{MOSDRepOp, Transaction, TxnOp};
use std::hint::black_box;
use std::time::Instant;

fn tx_frame(enc: &mut Encoder, h: &Header2, segs: &messages::Segments) -> usize {
    let hb = msgr2::MsgHeader2 {
        seq: 1,
        tid: h.tid,
        msg_type: h.ty,
        priority: 127,
        version: h.version,
        data_pre_padding_len: 0,
        data_off: 0,
        ack_seq: 0,
        flags: 1,
        compat_version: h.compat_version,
        reserved: 0,
    };
    let (mut out, mut chunks) = (Vec::new(), Vec::new());
    enc.encode_message_zc(
        &hb.to_bytes(),
        &segs.front,
        &segs.middle,
        &segs.data,
        &Default::default(),
        &mut out,
        &mut chunks,
    )
    .unwrap();
    // what the socket layer sees: runs, payload run by reference
    chunks.iter().map(Bytes::len).sum::<usize>() + out.len()
}

fn main() {
    let kib: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(4096);
    let n = kib << 10;
    let iters = ((4usize << 30) / n).max(16);
    let payload: Vec<u8> = (0..n).map(|i| (i * 7) as u8).collect();

    // client frame (4 MiB write)
    let mut op = MOSDOp {
        oid: b"rbd_data.1.0000".to_vec(),
        ..Default::default()
    };
    op.ops.push(OsdOp::write(0, payload.clone()));
    let (ty, ver, compat, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
    let mut cenc = Encoder::new(Revision::V21);
    let hb = msgr2::MsgHeader2 {
        seq: 1,
        tid: 7,
        msg_type: ty,
        priority: 127,
        version: ver,
        data_pre_padding_len: 0,
        data_off: 0,
        ack_seq: 0,
        flags: 1,
        compat_version: compat,
        reserved: 0,
    };
    let mut wire = Vec::new();
    cenc.encode_message(
        &hb.to_bytes(),
        &segs.front,
        &segs.middle,
        &segs.data,
        &mut wire,
    )
    .unwrap();

    let mut dec = Decoder::new(Revision::V21);
    let mut enc = Encoder::new(Revision::V21);
    let run = |label: &str, f: &mut dyn FnMut()| {
        for _ in 0..3 {
            f();
        }
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        let ns = t.elapsed().as_nanos() as f64 / (iters * n) as f64;
        println!("| {label} | {ns:.3} ns/B | {:.2} GB/s |", 1.0 / ns);
    };
    println!("{kib} KiB payload, {iters} iterations");
    println!("| stage | cost | rate |");
    println!("|---|---|---|");

    // write path, primary
    run(
        "write: rx feed + frame assembly (essential copy)",
        &mut || {
            dec.feed(&wire);
            black_box(dec.poll_owned().unwrap().unwrap());
        },
    );
    dec.feed(&wire);
    let f = dec.poll_owned().unwrap().unwrap();
    let mut it = f.segs.into_iter();
    let (h, front, middle, data) = (
        it.next().unwrap(),
        it.next().unwrap(),
        it.next().unwrap_or_default(),
        it.next().unwrap(),
    );
    let h2 = Header2 {
        seq: 1,
        tid: 7,
        ty,
        priority: 127,
        version: ver,
        data_pre_padding_len: 0,
        data_off: 0,
        ack_seq: 0,
        flags: 1,
        compat_version: compat,
        reserved: 0,
    };
    let _ = h;
    run("write: messages decode + opwire decode_client", &mut || {
        let m = messages::decode_with_header_shared(&h2, &front, &middle, &data).unwrap();
        let messages::AnyMessage::Unknown { segments, .. } = m else {
            panic!()
        };
        black_box(opwire::decode_client(ty, ver, &segments).unwrap());
    });
    let m = messages::decode_with_header_shared(&h2, &front, &middle, &data).unwrap();
    let messages::AnyMessage::Unknown { segments, .. } = m else {
        panic!()
    };
    let ClientMsg::Op(req) = opwire::decode_client(ty, ver, &segments).unwrap() else {
        panic!()
    };
    let txn_blob = |req: &MOSDOp| -> Bytes {
        let mut t = Transaction::new();
        let cx = t.coll(&denc::types::CollT::Pg(req.pgid));
        let ox = t.obj(&denc::types::Ghobject::head(
            denc::types::Hobject::default(),
            req.pgid.shard,
        ));
        t.push(
            cx,
            TxnOp::Write {
                oid: ox,
                off: 0,
                data: replwire::Data::new(&req.ops[0].indata),
            },
        );
        t.encode_v9().unwrap().into()
    };
    run("write: txn encode (indata -> blob)", &mut || {
        black_box(txn_blob(&req));
    });
    let blob = txn_blob(&req);
    let mut total = 0usize;
    run("write: 2 x MOSDRepOp frame (fan-out, tx runs)", &mut || {
        for _ in 0..2 {
            let r = MOSDRepOp {
                txn_data: blob.clone(),
                pg_stats: vec![1, 1, 0, 0, 0, 0].into(),
                ..Default::default()
            };
            let (ty, ver, compat, segs) = replwire::ReplMsg::RepOp(r).encode(u64::MAX).unwrap();
            let h = Header2 {
                seq: 1,
                tid: 1,
                ty,
                priority: 127,
                version: ver,
                data_pre_padding_len: 0,
                data_off: 0,
                ack_seq: 0,
                flags: 1,
                compat_version: compat,
                reserved: 0,
            };
            total += tx_frame(&mut enc, &h, &segs);
        }
    });
    black_box(total);

    // read path
    let store_buf: Bytes = payload.clone().into(); // what the store read hands over (its own buffer, not a copy)
    run("read: reply build (outdata -> frame, tx runs)", &mut || {
        let mut rep = MOSDOpReply::default();
        let mut o = OsdOp::new(opwire::consts::op::READ);
        o.outdata = store_buf.clone();
        rep.ops.push(o);
        let (ty, ver, compat, segs) = ClientMsg::OpReply(rep).encode(u64::MAX).unwrap();
        let h = Header2 {
            seq: 1,
            tid: 1,
            ty,
            priority: 127,
            version: ver,
            data_pre_padding_len: 0,
            data_off: 0,
            ack_seq: 0,
            flags: 1,
            compat_version: compat,
            reserved: 0,
        };
        black_box(tx_frame(&mut enc, &h, &segs));
    });
}
