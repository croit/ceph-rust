// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Sample objects shared by the oracle / roundtrip tests.
#![allow(clippy::allow_attributes, dead_code)]
use denc::Encode;
use denc::types::*;
use messages::Segments;
use replwire::txn::*;
use replwire::*;
use std::collections::BTreeMap;
use std::path::PathBuf;

pub fn testdata(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/replwire")
        .join(rel)
}

pub fn aux(name: &str) -> Vec<u8> {
    std::fs::read(testdata(&format!("aux/{name}.bin"))).unwrap()
}

pub fn hobj(oid: &str, snap: SnapId, hash: u32, pool: i64) -> Hobject {
    Hobject::new(oid.as_bytes(), snap, hash, pool, b"")
}

fn addr() -> EntityAddr {
    EntityAddr::v4(EntityAddr::TYPE_MSGR2, 1234, [172, 28, 0, 40], 6800)
}

pub fn object_infos() -> Vec<(&'static str, ObjectInfo)> {
    let mut head = ObjectInfo::new(hobj(
        "rbd_data.abc.0000000000000001",
        SnapId::NOSNAP,
        0xdead_beef,
        5,
    ));
    head.version = Eversion::new(12, 345);
    head.prior_version = Eversion::new(12, 300);
    head.last_reqid = OsdReqId {
        name: EntityName::client(4123),
        tid: 77,
        inc: 1,
    };
    head.size = 4 << 20;
    head.mtime = UTime::new(1_700_000_000, 123_456_789);
    head.truncate_seq = 3;
    head.truncate_size = 4 << 20;
    head.user_version = 999;
    head.watchers.insert(
        (7, EntityName::client(4100)),
        WatchInfo {
            cookie: 7,
            timeout_seconds: 30,
            addr: addr(),
        },
    );
    head.flags = flag::DIRTY | flag::OMAP | flag::DATA_DIGEST | flag::OMAP_DIGEST;
    head.local_mtime = UTime::new(1_700_000_001, 5);
    head.data_digest = 0x1234_5678;
    head.omap_digest = 0x9abc_def0;
    head.expected_object_size = 4 << 20;
    head.expected_write_size = 65536;
    head.alloc_hint_flags = 3;

    let mut clone = ObjectInfo::new(Hobject {
        key: b"loc".to_vec(),
        nspace: b"ns".to_vec(),
        ..hobj("obj", SnapId(5), 0x11, 2)
    });
    clone.version = Eversion::new(3, 4);
    clone.size = 100;
    clone.flags = flag::DIRTY;

    let mut wo = ObjectInfo::new(hobj("wh", SnapId::NOSNAP, 1, 1));
    wo.flags = flag::WHITEOUT | flag::MANIFEST | flag::REDIRECT_HAS_REFERENCE;
    wo.manifest = Some(ObjectManifest::Redirect(hobj(
        "target",
        SnapId::NOSNAP,
        9,
        3,
    )));

    let mut ch = ObjectInfo::new(hobj("chunked", SnapId::NOSNAP, 2, 1));
    ch.flags = flag::MANIFEST;
    ch.manifest = Some(ObjectManifest::Chunked(BTreeMap::from([
        (
            0,
            ChunkInfo {
                offset: 0,
                length: 4096,
                oid: hobj("c0", SnapId::NOSNAP, 3, 4),
                flags: 1,
            },
        ),
        (
            8192,
            ChunkInfo {
                offset: 8192,
                length: 100,
                oid: hobj("c1", SnapId::NOSNAP, 4, 4),
                flags: 0,
            },
        ),
    ])));

    let mut sv = ObjectInfo::new(hobj("ec", SnapId::NOSNAP, 3, 1));
    sv.shard_versions = BTreeMap::from([
        (ShardId(0), Eversion::new(1, 2)),
        (ShardId(2), Eversion::new(3, 4)),
    ]);
    vec![
        ("head", head),
        ("clone", clone),
        ("whiteout_redirect", wo),
        ("chunked", ch),
        ("shard_versions", sv),
    ]
}

pub fn snapsets() -> Vec<(&'static str, SnapSet)> {
    let mut s = SnapSet {
        seq: 12,
        clones: vec![SnapId(4), SnapId(9)],
        ..Default::default()
    };
    s.clone_overlap
        .insert(SnapId(4), BTreeMap::from([(0, 4096), (8192, 100)]));
    s.clone_overlap.insert(SnapId(9), BTreeMap::new());
    s.clone_size.insert(SnapId(4), 12288);
    s.clone_size.insert(SnapId(9), 0);
    s.clone_snaps.insert(SnapId(4), vec![SnapId(3), SnapId(2)]);
    s.clone_snaps
        .insert(SnapId(9), vec![SnapId(9), SnapId(8), SnapId(5)]);
    vec![("two_clones", s)]
}

pub fn snapcontexts() -> Vec<(&'static str, SnapContext)> {
    vec![(
        "three",
        SnapContext {
            seq: 12,
            snaps: vec![12, 9, 4],
        },
    )]
}

fn big_info() -> ObjectInfo {
    object_infos().remove(0).1
}

pub fn recovery_infos() -> Vec<(&'static str, ObjectRecoveryInfo)> {
    let mut clone_subset = BTreeMap::new();
    clone_subset.insert(
        hobj("head", SnapId(3), 7, 1),
        BTreeMap::from([(0, 100), (4096, 4096)]),
    );
    let ri = ObjectRecoveryInfo {
        soid: hobj(
            "rbd_data.abc.0000000000000001",
            SnapId::NOSNAP,
            0xdead_beef,
            5,
        ),
        version: Eversion::new(12, 345),
        size: 4 << 20,
        oi: big_info(),
        ss: snapsets().remove(0).1,
        copy_subset: BTreeMap::from([(0, 8192), (65536, 4096)]),
        clone_subset,
        object_exist: true,
        num_omap_keys: 17,
    };
    vec![("full", ri)]
}

pub fn progress() -> Vec<(&'static str, ObjectRecoveryProgress)> {
    vec![
        ("start", ObjectRecoveryProgress::default()),
        (
            "mid",
            ObjectRecoveryProgress {
                first: false,
                data_complete: true,
                data_recovered_to: 8 << 20,
                omap_recovered_to: b"key_0042".to_vec(),
                omap_complete: false,
            },
        ),
    ]
}

pub fn push_op() -> PushOp {
    let ri = recovery_infos().remove(0).1;
    PushOp {
        soid: ri.soid.clone(),
        version: ri.version,
        data: (0..12288u32).map(|i| i as u8).collect(),
        data_included: BTreeMap::from([(0, 8192), (65536, 4096)]),
        omap_header: b"hdr".to_vec(),
        omap_entries: BTreeMap::from([(b"k1".to_vec(), b"v1".to_vec()), (b"k2".to_vec(), vec![])]),
        attrset: BTreeMap::from([
            (b"_".to_vec(), big_info().encode_to_vec().unwrap()),
            (
                b"snapset".to_vec(),
                snapsets().remove(0).1.encode_to_vec().unwrap(),
            ),
        ]),
        recovery_info: ri,
        after_progress: progress().remove(1).1,
        before_progress: progress().remove(0).1,
    }
}

pub fn pull_op() -> PullOp {
    let ri = recovery_infos().remove(0).1;
    PullOp {
        soid: ri.soid.clone(),
        recovery_info: ri,
        recovery_progress: progress().remove(1).1,
    }
}

pub fn pgmeta_coll() -> CollT {
    CollT::Pg(SpgT {
        pgid: PgT::new(5, 0x1f),
        shard: ShardId::NO_SHARD,
    })
}

/// A transaction exercising every supported op; payload slices come from `buf`.
pub fn big_txn(buf: &[u8]) -> Transaction<'_> {
    let c = pgmeta_coll();
    let head = Ghobject::new(
        hobj("head", SnapId::NOSNAP, 0x1f, 5),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    );
    let clone = Ghobject::new(
        hobj("head", SnapId(7), 0x1f, 5),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    );
    let tmp = Ghobject::new(
        hobj(
            "temp_5.1f_0_12_1",
            SnapId::NOSNAP,
            0x1f,
            Hobject::temp_pool(5),
        ),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    );
    let mut t = Transaction::new();
    let cx = t.coll(&c);
    let h = t.obj(&head);
    let cl = t.obj(&clone);
    let tp = t.obj(&tmp);
    t.fadvise_flags = 0x8;
    t.push(cx, TxnOp::Remove { oid: cl });
    t.push(
        cx,
        TxnOp::Clone {
            oid: h,
            dest_oid: cl,
        },
    );
    t.push(
        cx,
        TxnOp::RmAttr {
            oid: cl,
            name: b"snapset",
        },
    );
    t.push(
        cx,
        TxnOp::SetAttrs {
            oid: cl,
            attrs: vec![(b"_", &buf[..40])],
        },
    );
    t.push(cx, TxnOp::Create { oid: h });
    t.push(cx, TxnOp::Touch { oid: tp });
    t.push(
        cx,
        TxnOp::Truncate {
            oid: h,
            size: 1 << 20,
        },
    );
    t.push(
        cx,
        TxnOp::SetAttrs {
            oid: h,
            attrs: vec![
                (b"_", &buf[..100]),
                (b"snapset", &buf[..20]),
                (b"_user", b""),
            ],
        },
    );
    t.push(
        cx,
        TxnOp::SetAttr {
            oid: h,
            name: b"one",
            value: b"v",
        },
    );
    t.push(cx, TxnOp::OmapClear { oid: h });
    t.push(
        cx,
        TxnOp::OmapSetHeader {
            oid: h,
            header: b"header",
        },
    );
    t.push(
        cx,
        TxnOp::OmapSetKeys {
            oid: h,
            pairs: vec![(&b"a"[..], &b"1"[..]), (b"b", &buf[..300])].into(),
        },
    );
    t.push(
        cx,
        TxnOp::OmapRmKeys {
            oid: h,
            keys: vec![b"x", b"y"],
        },
    );
    t.push(
        cx,
        TxnOp::OmapRmKeyRange {
            oid: h,
            first: b"k0",
            last: b"k9",
        },
    );
    t.push(
        cx,
        TxnOp::SetAllocHint {
            oid: h,
            expected_object_size: 4 << 20,
            expected_write_size: 4 << 20,
            flags: 3,
        },
    );
    // small, aligned, misaligned prefix+suffix, exactly one page
    t.push(
        cx,
        TxnOp::Write {
            oid: h,
            off: 7,
            data: Data::new(&buf[..100]),
        },
    );
    t.push(
        cx,
        TxnOp::Write {
            oid: h,
            off: 4096,
            data: Data::new(&buf[..4096]),
        },
    );
    t.push(
        cx,
        TxnOp::Write {
            oid: h,
            off: 0x1200,
            data: Data::new(&buf[..0x3000]),
        },
    );
    t.push(
        cx,
        TxnOp::Write {
            oid: h,
            off: 0x100000,
            data: Data::new(&buf[..0x10000]),
        },
    );
    t.push(
        cx,
        TxnOp::Zero {
            oid: h,
            off: 22,
            len: 33,
        },
    );
    t.push(
        cx,
        TxnOp::CloneRange2 {
            oid: h,
            dest_oid: tp,
            src_off: 1,
            len: 12,
            dest_off: 99,
        },
    );
    t.push(
        cx,
        TxnOp::CollMoveRename {
            oid: tp,
            dest_cid: cx,
            dest_oid: h,
        },
    );
    t.push(
        cx,
        TxnOp::TryRename {
            oid: tp,
            dest_oid: h,
        },
    );
    t.push(cx, TxnOp::RmAttrs { oid: h });
    t.push(
        cx,
        TxnOp::CollHint {
            ty: 1,
            data: &buf[..12],
        },
    );
    t.push(cx, TxnOp::MkColl { bits: 5 });
    t.push(cx, TxnOp::CollSetBits { bits: 6 });
    t.push(cx, TxnOp::Nop);
    t
}

/// Payload bytes used by [`big_txn`] (deterministic, >= 0x10000).
pub fn payload() -> Vec<u8> {
    (0..0x10000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect()
}

fn pgid() -> SpgT {
    SpgT {
        pgid: PgT::new(5, 0x1f),
        shard: ShardId::NO_SHARD,
    }
}
fn from() -> PgShard {
    PgShard {
        osd: 2,
        shard: ShardId::NO_SHARD,
    }
}
pub fn logbl() -> Vec<u8> {
    let mut v = 2u32.to_le_bytes().to_vec();
    v.extend(aux("pg_log_entry_t.1"));
    v.extend(aux("pg_log_entry_t.2"));
    v
}
fn objs() -> Vec<(Hobject, Eversion)> {
    vec![
        (hobj("a", SnapId::NOSNAP, 1, 5), Eversion::new(4, 10)),
        (hobj("b.c", SnapId(3), 2, 5), Eversion::new(4, 11)),
    ]
}

pub fn repop() -> MOSDRepOp {
    let buf = payload();
    let mut m = MOSDRepOp {
        map_epoch: 33,
        min_epoch: 30,
        reqid: OsdReqId {
            name: EntityName::client(4123),
            tid: 9,
            inc: 0,
        },
        pgid: pgid(),
        poid: hobj("head", SnapId::NOSNAP, 0x1f, 5),
        acks_wanted: 5,
        version: Eversion::new(33, 101),
        logbl: logbl().into(),
        pg_stats: aux("pg_stat_t.1").into(),
        pg_trim_to: Eversion::new(30, 90),
        new_temp_oid: Hobject::MIN(),
        discard_temp_oid: Hobject::MIN(),
        from: from(),
        updated_hit_set_history: None,
        pg_committed_to: Eversion::new(33, 100),
        ..Default::default()
    };
    m.set_txn(&big_txn(&buf)).unwrap();
    m
}

/// All message samples `(name, msg)`.
pub fn messages() -> Vec<(&'static str, ReplMsg)> {
    let mut with_hs = repop();
    with_hs.updated_hit_set_history = Some(aux("pg_hit_set_history_t.1"));
    with_hs.new_temp_oid = hobj(
        "temp_5.1f_0_33_1",
        SnapId::NOSNAP,
        0x1f,
        Hobject::temp_pool(5),
    );
    let mut v10 = repop();
    let mut v10n = repop();
    {
        let buf = payload();
        let mut t = big_txn(&buf);
        let (p, d) = t.encode_v10(DEFAULT_PAGE).unwrap();
        v10n.txn_middle = p.into();
        v10n.txn_data = d.into();
        t.data_features = SERVER_TENTACLE;
        let (p, d) = t.encode_v10(DEFAULT_PAGE).unwrap();
        v10.txn_middle = p.into();
        v10.txn_data = d.into();
    }
    let mut empty = repop();
    empty.set_txn(&Transaction::new()).unwrap();
    vec![
        ("a", repop().into()),
        ("hitset_temp", with_hs.into()),
        ("v10", v10.into()),
        ("v10_nosplit", v10n.into()),
        ("empty_txn", empty.into()),
        (
            "a",
            MOSDRepOpReply {
                map_epoch: 33,
                min_epoch: 30,
                reqid: repop().reqid,
                pgid: pgid(),
                ack_type: 4,
                result: 0,
                last_complete_ondisk: Eversion::new(33, 100),
                from: from(),
                ..Default::default()
            }
            .into(),
        ),
        (
            "a",
            MOSDPGUpdateLogMissing {
                map_epoch: 33,
                pgid: pgid(),
                from: ShardId::NO_SHARD,
                rep_tid: 55,
                entries: logbl(),
                min_epoch: 30,
                pg_trim_to: Eversion::new(30, 90),
                pg_committed_to: Eversion::new(33, 100),
            }
            .into(),
        ),
        (
            "a",
            MOSDPGUpdateLogMissingReply {
                map_epoch: 33,
                pgid: pgid(),
                from: ShardId::NO_SHARD,
                rep_tid: 55,
                min_epoch: 30,
                last_complete_ondisk: Eversion::new(33, 100),
            }
            .into(),
        ),
        (
            "a",
            MOSDPGPCT {
                map_epoch: 33,
                min_epoch: 30,
                pgid: pgid(),
                pg_committed_to: Eversion::new(33, 100),
            }
            .into(),
        ),
        (
            "a",
            MOSDPGPush {
                pgid: pgid(),
                map_epoch: 33,
                pushes: vec![push_op(), push_op()],
                cost: 99999,
                from: from(),
                min_epoch: 30,
                is_repair: true,
            }
            .into(),
        ),
        (
            "a",
            MOSDPGPushReply {
                pgid: pgid(),
                map_epoch: 33,
                replies: vec![PushReplyOp {
                    soid: hobj("a", SnapId::NOSNAP, 1, 5),
                }],
                cost: 5,
                from: from(),
                min_epoch: 30,
            }
            .into(),
        ),
        (
            "a",
            MOSDPGPull {
                pgid: pgid(),
                map_epoch: 33,
                pulls: vec![pull_op()],
                cost: 5,
                from: from(),
                min_epoch: 30,
            }
            .into(),
        ),
        (
            "a",
            MOSDPGRecoveryDelete {
                from: from(),
                pgid: pgid(),
                map_epoch: 33,
                min_epoch: 30,
                cost: 1000,
                objects: objs(),
            }
            .into(),
        ),
        (
            "a",
            MOSDPGRecoveryDeleteReply {
                pgid: pgid(),
                map_epoch: 33,
                min_epoch: 30,
                objects: objs(),
                from: from(),
            }
            .into(),
        ),
        (
            "get",
            MOSDPGScan {
                op: MOSDPGScan::OP_GET_DIGEST,
                map_epoch: 33,
                query_epoch: 31,
                pgid: pgid(),
                begin: Hobject::MIN(),
                end: Hobject::MAX(),
                from: from(),
                digest: None,
            }
            .into(),
        ),
        (
            "digest",
            MOSDPGScan {
                op: MOSDPGScan::OP_DIGEST,
                map_epoch: 33,
                query_epoch: 31,
                pgid: pgid(),
                begin: hobj("a", SnapId::NOSNAP, 1, 5),
                end: hobj("z", SnapId::NOSNAP, 9, 5),
                from: from(),
                digest: Some(objs()),
            }
            .into(),
        ),
        (
            "a",
            MOSDPGBackfill {
                op: MOSDPGBackfill::OP_PROGRESS,
                map_epoch: 33,
                query_epoch: 31,
                pgid: pgid(),
                last_backfill: hobj("a", SnapId::NOSNAP, 1, 5),
                compat_stats: aux("object_stat_collection_t.1"),
                stats: aux("pg_stat_t.1"),
            }
            .into(),
        ),
        (
            "a",
            MOSDPGBackfillRemove {
                pgid: pgid(),
                map_epoch: 33,
                ls: objs(),
            }
            .into(),
        ),
        (
            "a",
            MBackfillReserve {
                pgid: pgid(),
                query_epoch: 31,
                ty: MBackfillReserve::REQUEST,
                priority: 140,
                primary_num_bytes: 1 << 30,
                shard_num_bytes: 5,
            }
            .into(),
        ),
        (
            "a",
            MRecoveryReserve {
                pgid: pgid(),
                query_epoch: 31,
                ty: MRecoveryReserve::REQUEST,
                priority: 180,
            }
            .into(),
        ),
    ]
}

/// ceph-dencoder's container for Message types (see messages crate oracle notes).
pub fn dencoder_wrapper(ty: u16, ver: u16, compat: u16, s: &Segments) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0u64.to_le_bytes());
    b.extend_from_slice(&0u64.to_le_bytes());
    b.extend_from_slice(&ty.to_le_bytes());
    b.extend_from_slice(&127u16.to_le_bytes());
    b.extend_from_slice(&ver.to_le_bytes());
    b.extend_from_slice(&(s.front.len() as u32).to_le_bytes());
    b.extend_from_slice(&(s.middle.len() as u32).to_le_bytes());
    b.extend_from_slice(&(s.data.len() as u32).to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.push(8);
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

/// dencoder type name of a message (None = not registered in dencoder).
pub fn dencoder_msg_type(m: &ReplMsg) -> Option<&'static str> {
    Some(match m {
        ReplMsg::RepOp(_) => "MOSDRepOp",
        ReplMsg::RepOpReply(_) => "MOSDRepOpReply",
        ReplMsg::UpdateLogMissing(_) => "MOSDPGUpdateLogMissing",
        ReplMsg::UpdateLogMissingReply(_) => "MOSDPGUpdateLogMissingReply",
        ReplMsg::Push(_) => "MOSDPGPush",
        ReplMsg::PushReply(_) => "MOSDPGPushReply",
        ReplMsg::RecoveryDelete(_) => "MOSDPGRecoveryDelete",
        ReplMsg::RecoveryDeleteReply(_) => "MOSDPGRecoveryDeleteReply",
        ReplMsg::Scan(_) => "MOSDPGScan",
        ReplMsg::Backfill(_) => "MOSDPGBackfill",
        ReplMsg::RecoveryReserve(_) => "MRecoveryReserve",
        _ => return None,
    })
}

pub fn msg_name(m: &ReplMsg) -> String {
    let d = format!("{m:?}");
    d.split('(').next().unwrap_or("?").to_string()
}

/// `inline` with the rope runs `zc` (`(offset in inline, bytes)`, ascending) spliced in: the flattened encoding.
pub fn flat(inline: &[u8], zc: &[(usize, bytes::Bytes)]) -> Vec<u8> {
    let mut v = Vec::with_capacity(inline.len() + zc.iter().map(|(_, r)| r.len()).sum::<usize>());
    let mut pos = 0;
    for (at, r) in zc {
        v.extend_from_slice(&inline[pos..*at]);
        v.extend_from_slice(r);
        pos = *at;
    }
    v.extend_from_slice(&inline[pos..]);
    v
}

/// Hand-built older object_info_t encodings (struct_v 13..=17): the v18 field order cut at the
/// version gates of spec 5.1 (the same bytes are fed to ceph-dencoder by oracle.sh).
pub fn object_info_old(oi: &ObjectInfo, v: u8) -> Vec<u8> {
    let full = oi.encode_to_vec().unwrap();
    // v18 bytes: 6 header + body. Trailing fixed-size parts per version gate (see ObjectInfo::encode):
    // shard_versions (4 + 13 per entry) | manifest | hints 20 | digests 8 | local_mtime 8 | flags 4.
    let mut body = full[6..].to_vec();
    let sv = 4 + 13 * oi.shard_versions.len();
    if v < 18 {
        body.truncate(body.len() - sv);
    }
    let man = if oi.flags & flag::MANIFEST != 0 {
        oi.manifest
            .as_ref()
            .map_or(0, |m| m.encode_to_vec().unwrap().len())
    } else {
        0
    };
    if v < 17 {
        body.truncate(body.len() - man);
    }
    if v < 16 {
        body.truncate(body.len() - 20);
    }
    if v < 15 {
        body.truncate(body.len() - 8);
    }
    if v < 14 {
        body.truncate(body.len() - 8);
    }
    // v < 13 would also drop flags and keep lost/uses_tmap only; not generated here.
    // manifest sits before shard_versions, so for v17 re-insert order is already right (cut from the end).
    let mut out = vec![v, 8];
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}
