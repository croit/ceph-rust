// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
#![allow(clippy::allow_attributes, dead_code)]
use messages::Header2;
use msgr2::{Banner, Decoder};
use std::path::PathBuf;

pub fn testdata(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/opwire")
        .join(rel)
}

/// (header, front, middle, data)
pub type Frame = (Header2, Vec<u8>, Vec<u8>, Vec<u8>);

/// All MESSAGE frames of a raw msgr2 stream (one direction). None if the stream is not decodable
/// (e.g. secure mode).
pub fn frames(stream: &[u8]) -> Option<Vec<Frame>> {
    let (b, n) = Banner::parse(stream).ok()??;
    let mut d = Decoder::new(b.revision());
    d.feed(&stream[n..]);
    let mut out = Vec::new();
    loop {
        match d.poll() {
            Ok(Some(f)) => {
                if f.tag != 17 {
                    continue;
                }
                let h = Header2::parse(f.segment(0)).ok()?;
                out.push((
                    h,
                    f.segment(1).to_vec(),
                    f.segment(2).to_vec(),
                    f.segment(3).to_vec(),
                ));
            }
            Ok(None) => break,
            Err(_) => return None,
        }
    }
    Some(out)
}

/// Capture directory: `$OPWIRE_CAPDIR` or testdata/opwire.
pub fn capture_files() -> Vec<(String, Vec<u8>)> {
    let dir = std::env::var_os("OPWIRE_CAPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| testdata(""));
    let mut v = Vec::new();
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "bin") {
            v.push((
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read(&p).unwrap(),
            ));
        }
    }
    v.sort();
    v
}

use denc::types::*;
use messages::Segments;
use opwire::*;

/// Sample client messages: (name, header version, message). For the oracle (testdata/opwire/oracle.sh).
pub fn samples() -> Vec<(&'static str, u16, ClientMsg)> {
    let mut v = Vec::new();
    let mut m = MOSDOp {
        pgid: SpgT {
            pgid: PgT::new(1, 13),
            shard: ShardId::NO_SHARD,
        },
        hash: 0x6d31_a10d,
        osdmap_epoch: 248,
        flags: flag::ACK | flag::ONDISK | flag::WRITE | flag::KNOWN_REDIR | flag::SUPPORTSPOOLEIO,
        reqid: OsdReqId {
            name: EntityName::client(4242),
            tid: 77,
            inc: 5,
        },
        client_inc: 5,
        mtime: UTime::new(1_791_547_664, 199_647_800),
        oloc: ObjectLocator {
            pool: 1,
            key: b"lockey".to_vec(),
            nspace: b"ns".to_vec(),
            hash: -1,
        },
        oid: b"obj1".to_vec(),
        ops: vec![
            OsdOp::alloc_hint_op(4 << 20, 4 << 20, alloc_hint_flags()),
            OsdOp::write(4096, vec![0xab; 100]),
            OsdOp::setxattr(b"k", b"value"),
            OsdOp::call(b"lock", b"lock", b"inp"),
        ],
        snap_seq: 9,
        snaps: vec![9, 7, 3],
        retry_attempt: 2,
        features: 0x3f17_ffff_fffd_ffff,
        ..Default::default()
    };
    v.push(("MOSDOp.v9", 9, ClientMsg::Op(m.clone())));
    v.push(("MOSDOp.v8", 8, ClientMsg::Op(m.clone())));
    m.reassert_version = Eversion::new(3, 4);
    m.pgid.pgid.seed = m.hash; // v7 carries the raw pg: seed == hash
    v.push(("MOSDOp.v7", 7, ClientMsg::Op(m.clone())));
    let rd = MOSDOp {
        flags: flag::ACK | flag::ONDISK | flag::READ,
        ops: vec![
            OsdOp::read(0, 4096),
            OsdOp::stat(),
            OsdOp::sparse_read(0, 65536),
        ],
        oid: b"rbd_data.1.0000000000000000".to_vec(),
        snapid: 5,
        reassert_version: Eversion::default(),
        ..m.clone()
    };
    v.push(("MOSDOp.read", 9, ClientMsg::Op(rd.clone())));
    let mut r = MOSDOpReply::for_request(&rd, 250);
    r.ops[0].outdata = (vec![1; 4096]).into();
    r.ops[1].outdata = (vec![2; 16]).into();
    r.ops[2].rval = -2;
    r.result = -2;
    r.set_versions(Eversion::new(250, 17), 12);
    v.push(("MOSDOpReply.a", 8, ClientMsg::OpReply(r)));
    let mut r2 = MOSDOpReply::for_request(&m, 250);
    r2.set_versions(Eversion::new(250, 18), 13);
    r2.redirect = Some(RequestRedirect {
        oloc: ObjectLocator {
            pool: 2,
            ..Default::default()
        },
        redirect_object: b"other".to_vec(),
    });
    v.push(("MOSDOpReply.redirect", 8, ClientMsg::OpReply(r2)));
    v.push((
        "MWatchNotify.notify",
        3,
        ClientMsg::WatchNotify(MWatchNotify {
            msg_ver: 1,
            opcode: notify_ev::NOTIFY,
            cookie: 0xaaaa_1310_9b40,
            ver: 377,
            notify_id: (232 << 32) | 143,
            bl: vec![5, 0, 0, 0, b'h', b'e', b'l', b'l', b'o'],
            return_code: 0,
            notifier_gid: 25062,
            data: vec![],
        }),
    ));
    let mut c = NotifyCompleteData::default();
    c.replies.insert((25059, 0xaaab_1310_9b40), vec![1, 2, 3]);
    c.missed.push((7, 8));
    v.push((
        "MWatchNotify.complete",
        3,
        ClientMsg::WatchNotify(MWatchNotify {
            msg_ver: 1,
            opcode: notify_ev::NOTIFY_COMPLETE,
            cookie: 1,
            ver: 377,
            notify_id: 5,
            bl: vec![],
            return_code: -110,
            notifier_gid: 25062,
            data: denc::to_vec(&c).unwrap(),
        }),
    ));
    v.push((
        "MOSDBackoff.a",
        1,
        ClientMsg::Backoff(MOSDBackoff {
            pgid: SpgT {
                pgid: PgT::new(1, 13),
                shard: ShardId::NO_SHARD,
            },
            map_epoch: 248,
            op: opwire::consts::backoff::BLOCK,
            id: 1,
            begin: Hobject::new(b"", SnapId(0), 13, 1, b""),
            end: Hobject::MAX(),
        }),
    ));
    v
}

fn alloc_hint_flags() -> u32 {
    opwire::consts::alloc_hint::SEQUENTIAL_WRITE | opwire::consts::alloc_hint::INCOMPRESSIBLE
}
use opwire::consts::notify as notify_ev;

/// ceph-dencoder's container for Message types (observed black-box, see messages oracle.sh):
/// legacy msgr1 `ceph_msg_header` (53 B) + footer_old (13 B) + three length-prefixed segments.
pub fn dencoder_wrapper(ty: u16, ver: u16, compat: u16, s: &Segments) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0u64.to_le_bytes()); // seq
    b.extend_from_slice(&0u64.to_le_bytes()); // tid
    b.extend_from_slice(&ty.to_le_bytes());
    b.extend_from_slice(&127u16.to_le_bytes()); // priority
    b.extend_from_slice(&ver.to_le_bytes());
    b.extend_from_slice(&(s.front.len() as u32).to_le_bytes());
    b.extend_from_slice(&(s.middle.len() as u32).to_le_bytes());
    b.extend_from_slice(&(s.data.len() as u32).to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes()); // data_off
    b.push(8); // src type client
    b.extend_from_slice(&0i64.to_le_bytes());
    b.extend_from_slice(&compat.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    let hcrc = crc::crc32c(0, &b);
    b.extend_from_slice(&hcrc.to_le_bytes());
    b.extend_from_slice(&crc::crc32c(0, &s.front).to_le_bytes());
    b.extend_from_slice(&crc::crc32c(0, &s.middle).to_le_bytes());
    b.extend_from_slice(&crc::crc32c(0, &s.data).to_le_bytes());
    b.push(1);
    for seg in [&s.front[..], &s.middle[..], &s.data[..]] {
        b.extend_from_slice(&(seg.len() as u32).to_le_bytes());
        b.extend_from_slice(seg);
    }
    b
}

/// Encode a sample at its header version.
pub fn encode_sample(ver: u16, m: &ClientMsg) -> (u16, u16, u16, Segments) {
    match m {
        ClientMsg::Op(o) => (
            42,
            ver,
            3,
            o.encode_version(ver, denc::features::ALL).unwrap(),
        ),
        other => other.encode(denc::features::ALL).unwrap(),
    }
}
