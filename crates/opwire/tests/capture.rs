// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Real librados/librbd <-> classic OSD streams (testdata/opwire/*.bin, msgr2 crc mode, see README):
//! decode every client op message, re-encode, require byte equality.
mod common;
use common::*;
use messages::Message;
use opwire::*;
use std::collections::BTreeMap;

#[test]
fn every_captured_client_message_roundtrips_byte_exact() {
    let files = capture_files();
    assert!(!files.is_empty());
    let mut seen: BTreeMap<u16, usize> = BTreeMap::new();
    let mut ops_seen: BTreeMap<u16, usize> = BTreeMap::new();
    let mut vers: BTreeMap<(u16, u16), usize> = BTreeMap::new();
    for (name, bytes) in &files {
        let Some(frs) = frames(bytes) else {
            println!("skip {name}: not decodable");
            continue;
        };
        for (i, (h, front, mid, data)) in frs.into_iter().enumerate() {
            if !matches!(h.ty, 42 | 43 | 44 | 61) {
                continue;
            }
            let m = decode_client_parts(h.ty, h.version, &front, &mid, &data).unwrap_or_else(|e| {
                panic!("{name}#{i} type {} v{}: {e}\n{front:02x?}", h.ty, h.version)
            });
            let (ty, ver, _compat, segs) = m
                .encode(denc::features::ALL)
                .unwrap_or_else(|e| panic!("{name}#{i}: {e}"));
            assert_eq!(ty, h.ty);
            let segs = match &m {
                ClientMsg::Op(o) => o.encode_version(h.version, denc::features::ALL).unwrap(),
                _ => segs,
            };
            let _ = ver;
            assert_eq!(segs.front, front, "{name}#{i} type {} front\n{m:#?}", h.ty);
            assert_eq!(segs.data, data, "{name}#{i} data");
            assert!(mid.is_empty());
            *seen.entry(h.ty).or_default() += 1;
            *vers.entry((h.ty, h.version)).or_default() += 1;
            match &m {
                ClientMsg::Op(o) => o
                    .ops
                    .iter()
                    .for_each(|x| *ops_seen.entry(x.op).or_default() += 1),
                ClientMsg::OpReply(o) => o
                    .ops
                    .iter()
                    .for_each(|x| *ops_seen.entry(x.op).or_default() += 1),
                _ => {}
            }
        }
    }
    println!("types {seen:?}\nversions {vers:?}");
    for (o, n) in &ops_seen {
        println!("{:#06x} {:24} {n}", o, op::name(*o).unwrap_or("?"));
    }
    let _ = MOSDOp::HEAD_VERSION;
}

/// Per-op structural checks on every captured request and its reply: indata/outdata layouts of s1.4
/// and s7 parse with our payload types, framing rules hold, replies echo the request.
#[test]
fn captured_ops_are_structurally_sane() {
    let files = capture_files();
    let mut checked = 0usize;
    for (name, bytes) in &files {
        if !name.ends_with("-c2s.bin") {
            continue;
        }
        let rname = name.replace("-c2s.bin", "-s2c.bin");
        let rbytes = &files.iter().find(|f| f.0 == rname).expect("pair").1;
        let (Some(reqs), Some(reps)) = (frames(bytes), frames(rbytes)) else {
            continue;
        };
        let mut replies = BTreeMap::new();
        for (h, f, m, d) in &reps {
            if h.ty == 43 {
                let ClientMsg::OpReply(r) = decode_client_parts(h.ty, h.version, f, m, d).unwrap()
                else {
                    panic!()
                };
                assert!(
                    replies.insert(h.tid, (r, h.data_off)).is_none(),
                    "{name}: dup reply tid"
                );
            }
        }
        for (h, f, m, d) in &reqs {
            if h.ty != 42 {
                continue;
            }
            let ClientMsg::Op(q) = decode_client_parts(h.ty, h.version, f, m, d).unwrap() else {
                panic!()
            };
            let ctx = format!(
                "{name} tid {} oid {:?}",
                h.tid,
                String::from_utf8_lossy(&q.oid)
            );
            // identity & routing fields as sent by a real Objecter
            assert_eq!(
                (q.reqid.name.ty, q.reqid.tid),
                (0, 0),
                "{ctx}: explicit reqid"
            );
            assert_eq!(q.client_inc, 0, "{ctx}");
            assert!(q.pgid.shard.0 >= -1, "{ctx}"); // EC pools (seen: pool 7 via rbd_children) carry the primary shard id
            assert_eq!(q.oloc.pool as u64, q.pgid.pgid.pool);
            assert_eq!(q.retry_attempt, 0);
            assert_ne!(q.features, 0);
            assert!(
                q.flags & flag::KNOWN_REDIR != 0 && q.flags & flag::ONDISK != 0,
                "{ctx}"
            );
            assert_eq!(h.compat_version, 3);
            // data segment framing
            assert_eq!(q.data_len(), d.len(), "{ctx}");
            let info = OpInfo::classify(&q.ops, q.flags, &|c, m| {
                // registry stand-in: lock.* and rbd.* mutate/read as the client flags say
                let _ = (c, m);
                Some(ClsEntry {
                    flags: ClsFlags {
                        rd: q.flags & flag::READ != 0,
                        wr: q.flags & flag::WRITE != 0,
                    },
                    allowed: true,
                })
            })
            .unwrap_or_else(|e| panic!("{ctx}: classify errno {e}"));
            assert_eq!(info.pg_op, q.ops.iter().any(|o| o.op == op::PGNLS), "{ctx}");
            if info.may_write {
                assert_eq!(q.snapid, NOSNAP, "{ctx}");
                assert!(
                    q.snaps.windows(2).all(|w| w[0] > w[1])
                        && q.snaps.first().is_none_or(|s| *s <= q.snap_seq),
                    "{ctx}"
                );
                assert!(
                    q.flags & flag::WRITE != 0,
                    "{ctx}: client WRITE flag matches classification"
                );
            }
            for o in &q.ops {
                match o.op {
                    op::WRITE | op::WRITEFULL | op::APPEND | op::CMPEXT => {
                        assert_eq!(o.extent().length as usize, o.indata.len(), "{ctx}");
                    }
                    op::WRITESAME => {
                        let w = o.write_same();
                        assert_eq!(w.data_length as usize, o.indata.len());
                        assert_eq!(w.length % w.data_length, 0);
                    }
                    op::SETXATTR | op::CMPXATTR | op::GETXATTR | op::RMXATTR => {
                        let (n, v) = o.xattr_name_value().unwrap();
                        assert_eq!(
                            (n.len(), v.len()),
                            (o.xattr().name_len as usize, o.xattr().value_len as usize)
                        );
                        if o.op == op::CMPXATTR
                            && o.xattr().cmp_mode == opwire::consts::cmp::MODE_U64
                        {
                            assert_eq!(v.len(), 8);
                        }
                    }
                    op::CALL => {
                        let c = o.cls_call().unwrap_or_else(|e| panic!("{ctx}: {e}"));
                        assert!(!c.class.is_empty() && !c.method.is_empty());
                    }
                    op::NOTIFY => {
                        let n: NotifyIn = o.indata_as().unwrap();
                        assert_eq!(n.prot_ver, 1);
                    }
                    op::NOTIFY_ACK => {
                        let a: NotifyAckIn = o.indata_as().unwrap();
                        assert_ne!(a.notify_id, 0);
                    }
                    op::WATCH => {
                        assert!(matches!(o.watch().op, 0 | 3 | 5 | 7), "{ctx}");
                        assert!(o.indata.is_empty());
                    }
                    op::PGNLS => {
                        assert!(q.oid.is_empty());
                        pgls_cursor(&o.indata).unwrap();
                        assert_eq!(
                            q.flags & flag::PGOP,
                            0,
                            "librados does not set PGOP on pgnls (observed)"
                        );
                    }
                    op::OMAP_GET_KEYS => drop(o.indata_as::<OmapGetKeysIn>().unwrap()),
                    op::OMAP_GET_VALS => drop(o.indata_as::<OmapGetValsIn>().unwrap()),
                    op::OMAP_GET_VALS_BY_KEYS | op::OMAP_RM_KEYS => {
                        drop(o.indata_as::<KeySet>().unwrap())
                    }
                    op::OMAP_SET_VALS => drop(o.indata_as::<KvMap>().unwrap()),
                    op::COPY_FROM => {
                        let c = CopyFromIn::parse(o).unwrap();
                        assert!(!c.src_oid.is_empty());
                    }
                    op::SET_ALLOC_HINT => {
                        let a = o.alloc_hint();
                        assert!(a.expected_object_size > 0 && a.flags & !0x7ff == 0);
                    }
                    _ => {}
                }
            }
            // the reply
            let Some((r, data_off)) = replies.get(&h.tid) else {
                continue; // e.g. connection closed before the reply
            };
            assert_eq!(*data_off, r.data_off_hint(), "{ctx}: reply header data_off");
            assert_eq!(r.oid, q.oid, "{ctx}");
            assert_eq!(r.pgid, q.pgid.pgid);
            assert_eq!(r.retry_attempt, q.retry_attempt);
            assert_eq!(r.ops.len(), q.ops.len(), "{ctx}");
            assert_eq!(
                r.flags as u32 & !(flag::ACK | flag::ONDISK),
                q.flags & !(flag::ACK | flag::ONDISK),
                "{ctx}: reply flags = request flags | ACK | ONDISK"
            );
            // ACK is added on the normal path; the early read-ENOENT error reply echoes the request flags (no ACK)
            assert!(r.flags & flag::ONDISK as u64 != 0);
            if r.result >= 0 {
                assert!(r.flags & flag::ACK as u64 != 0, "{ctx}");
            }
            assert!(r.redirect.is_none());
            for (o, qo) in r.ops.iter().zip(&q.ops) {
                assert_eq!(o.op, qo.op);
                assert_eq!(o.flags, qo.flags, "{ctx}: per-op flags echoed");
                let ok = o.rval >= 0 && r.result >= 0 && q.flags & flag::WRITE == 0; // mutating replies carry no outdata
                match o.op {
                    op::STAT if ok => {
                        let s: StatOut = denc::from_slice(&o.outdata).unwrap();
                        assert!(s.mtime.sec > 0);
                    }
                    op::READ if ok => {
                        assert_eq!(
                            o.outdata.len() as u64,
                            o.extent().length,
                            "{ctx}: reply extent.length = bytes returned"
                        );
                        assert!(
                            o.outdata.len() as u64 <= qo.extent().length || qo.extent().length == 0
                        );
                    }
                    op::SPARSE_READ if ok => {
                        let s: SparseReadOut = denc::from_slice(&o.outdata).unwrap();
                        let tot: u64 = s.extents.values().sum();
                        assert_eq!(tot as usize, s.data.len(), "{ctx}");
                    }
                    op::LIST_SNAPS if ok => {
                        drop(denc::from_slice::<ObjListSnapResponse>(&o.outdata).unwrap())
                    }
                    op::LIST_WATCHERS if ok => {
                        drop(denc::from_slice::<ObjListWatchResponse>(&o.outdata).unwrap())
                    }
                    op::PGNLS if ok => {
                        let p: PgNlsResponse = denc::from_slice(&o.outdata).unwrap();
                        assert!(r.result == 1 || r.result == 0);
                        assert!(p.entries.len() as u64 <= qo.pgls().count);
                    }
                    op::OMAP_GET_KEYS if ok => {
                        drop(denc::from_slice::<OmapKeysOut>(&o.outdata).unwrap())
                    }
                    op::OMAP_GET_VALS if ok => {
                        drop(denc::from_slice::<OmapValsOut>(&o.outdata).unwrap())
                    }
                    op::OMAP_GET_VALS_BY_KEYS | op::GETXATTRS if ok => {
                        drop(denc::from_slice::<KvMap>(&o.outdata).unwrap())
                    }
                    op::NOTIFY if ok => assert_eq!(o.outdata.len(), 8),
                    op::GETXATTR if ok => assert_eq!(o.xattr().value_len as usize, o.outdata.len()),
                    op::WRITE | op::WRITEFULL | op::DELETE | op::SETXATTR if ok => {
                        assert!(o.outdata.is_empty())
                    }
                    _ => {}
                }
            }
            // versions (s2.2)
            if r.result >= 0
                && q.ops
                    .iter()
                    .all(|o| !opwire::modifies(o.op) && o.op != op::CALL && o.op != op::PGNLS)
            {
                assert_eq!(
                    r.replay_version,
                    denc::types::Eversion::default(),
                    "{ctx}: read success replay_version 0'0"
                );
                assert_eq!(
                    r.bad_replay_version,
                    denc::types::Eversion::new(0, r.user_version),
                    "{ctx}"
                );
            }
            if r.result >= 0
                && q.ops
                    .iter()
                    .any(|o| o.op == op::WRITE || o.op == op::DELETE)
            {
                assert_eq!(
                    r.bad_replay_version,
                    denc::types::Eversion::new(r.replay_version.epoch, r.user_version),
                    "{ctx}"
                );
                assert!(r.replay_version.version > 0);
            }
            checked += 1;
        }
    }
    assert!(checked > 100, "only {checked} request/reply pairs checked");
    println!("checked {checked} pairs");
}
