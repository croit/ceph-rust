// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Message round-trips: dencoder default-constructed messages (legacy framing stripped) and
//! messages composed from struct goldens in the field order of peering.md 4.1.

use denc::types::{Eversion, PgShard, ShardId, SpgT, UTime};
use denc::{Encode, from_slice};
use messages::{Message, Segments};
use pgwire::*;
use std::path::PathBuf;

fn td(p: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../testdata")
            .join(p),
    )
    .unwrap()
}

/// Legacy dencoder message framing: 53 B header, 12 B crcs, 1 B flag, then 3 x (u32 len + bytes).
fn legacy_front(raw: &[u8]) -> (u16, u16, u16, Vec<u8>) {
    let ty = u16::from_le_bytes([raw[16], raw[17]]);
    let ver = u16::from_le_bytes([raw[20], raw[21]]);
    let flen = u32::from_le_bytes(raw[22..26].try_into().unwrap()) as usize;
    let compat = u16::from_le_bytes([raw[45], raw[46]]);
    let blen = u32::from_le_bytes(raw[66..70].try_into().unwrap()) as usize;
    assert_eq!(blen, flen);
    (ty, ver, compat, raw[70..70 + flen].to_vec())
}

fn check_default<M: Message + PartialEq + std::fmt::Debug>(name: &str, prio: Option<u16>) {
    let raw = td(&format!("pgwire/msg/{name}.bin"));
    let (ty, ver, compat, front) = legacy_front(&raw);
    assert_eq!(ty, M::MSG_TYPE, "{name} type");
    assert_eq!(ver, M::HEAD_VERSION, "{name} head version");
    assert_eq!(compat.max(1), M::COMPAT_VERSION.max(1), "{name} compat");
    if let Some(p) = prio {
        assert_eq!(u16::from_le_bytes([raw[18], raw[19]]), p);
    }
    let m = M::decode(ver, &front, &[], &[]).unwrap_or_else(|e| panic!("{name}: {e}"));
    let seg = m.encode(u64::MAX).unwrap();
    assert_eq!(seg.front, front, "{name} re-encode");
    assert!(seg.middle.is_empty() && seg.data.is_empty());
}

#[test]
fn dencoder_defaults() {
    check_default::<MOSDPGLog>("MOSDPGLog", Some(PRIO_HIGH));
    check_default::<MOSDPGTrim>("MOSDPGTrim", None);
    check_default::<MOSDPGRemove>("MOSDPGRemove", None);
    check_default::<MOSDPGCreate2>("MOSDPGCreate2", None);
    check_default::<MOSDPGRecoveryDelete>("MOSDPGRecoveryDelete", None);
    check_default::<MOSDPGRecoveryDeleteReply>("MOSDPGRecoveryDeleteReply", None);
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn rt<M: Message + PartialEq + std::fmt::Debug>(payload: &[u8]) -> M {
    let m = M::decode(M::HEAD_VERSION, payload, &[], &[]).unwrap();
    let seg = m.encode(u64::MAX).unwrap();
    assert_eq!(
        seg.front,
        payload,
        "{} composed payload",
        std::any::type_name::<M>()
    );
    m
}

#[test]
fn composed_from_struct_vectors() {
    let spg = td("denc/spg_t/1.bin");
    let notify = td("pgwire/pg_notify_t/2.bin");
    let query = td("pgwire/pg_query_t/3.bin");
    let info = td("pgwire/pg_info_t/2.bin");
    let lease = td("pgwire/pg_lease_t/2.bin");
    let ack = td("pgwire/pg_lease_ack_t/2.bin");
    let log = td("pgwire/pg_log_t/2.bin");
    let missing = td("pgwire/pg_missing_t/3.bin");
    let pi = td("pgwire/PastIntervals/2.bin");
    let hist = td("pgwire/pg_history_t/2.bin");
    let ev = td("denc/eversion_t/2.bin");

    let m: MOSDPGNotify2 = rt(&cat(&[&spg, &notify]));
    assert_eq!(m.spgid, from_slice::<SpgT>(&spg).unwrap());
    let g = PeeringMsg::from(m.clone()).gating();
    assert_eq!(g, (m.notify.epoch_sent, m.notify.query_epoch));

    let m: MOSDPGQuery2 = rt(&cat(&[&spg, &query]));
    let _ = m.query.ty;

    // Info2 with and without optionals
    for (l, a) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut p = cat(&[&spg, &7u32.to_le_bytes(), &5u32.to_le_bytes(), &info]);
        if l {
            p.push(1);
            p.extend(&lease)
        } else {
            p.push(0)
        }
        if a {
            p.push(1);
            p.extend(&ack)
        } else {
            p.push(0)
        }
        let m: MOSDPGInfo2 = rt(&p);
        assert_eq!(
            (
                m.epoch_sent,
                m.min_epoch,
                m.lease.is_some(),
                m.lease_ack.is_some()
            ),
            (7, 5, l, a)
        );
    }

    // PGLog with lease
    let mut p = cat(&[
        &9u32.to_le_bytes(),
        &info,
        &log,
        &missing,
        &8u32.to_le_bytes(),
        &pi,
        &[0xff, 0xff],
    ]);
    p.push(1);
    p.extend(&lease);
    let m: MOSDPGLog = rt(&p);
    assert_eq!((m.epoch, m.query_epoch), (9, 8));
    assert!(m.lease.is_some());
    assert_eq!(m.log.log.len(), 3);
    assert_eq!(PeeringMsg::from(m).gating(), (9, 8));

    let m: MOSDPGLease = rt(&cat(&[&4u32.to_le_bytes(), &spg, &lease]));
    assert_eq!(m.epoch, 4);
    let m: MOSDPGLeaseAck = rt(&cat(&[&4u32.to_le_bytes(), &spg, &ack]));
    assert_eq!(m.epoch, 4);
    let m: MOSDPGPCT = rt(&cat(&[&4u32.to_le_bytes(), &3u32.to_le_bytes(), &spg, &ev]));
    assert_eq!((m.map_epoch, m.min_epoch), (4, 3));

    // Create2 with one pg
    let mut p = 11u32.to_le_bytes().to_vec();
    p.extend(1u32.to_le_bytes());
    p.extend(&spg);
    p.extend(10u32.to_le_bytes());
    p.extend([1u8, 0, 0, 0, 2, 0, 0, 0]);
    p.extend(1u32.to_le_bytes());
    p.extend(&spg);
    p.extend(&hist);
    p.extend(&pi);
    let m: MOSDPGCreate2 = rt(&p);
    assert_eq!(m.pgs.values().next().unwrap(), &(10, UTime::new(1, 2)));
    assert_eq!(m.pg_extra.len(), 1);
}

#[test]
fn built_from_structs() {
    let spg = SpgT {
        pgid: denc::types::PgT::new(3, 0x1f),
        shard: ShardId::NO_SHARD,
    };
    // empty PastIntervals constant (spec test-vectors-m2 4.1)
    let empty = PastIntervals::default().encode_to_vec().unwrap();
    assert_eq!(
        empty,
        [
            0x01, 0x01, 0x17, 0, 0, 0, 0x02, 0x01, 0x01, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0
        ]
    );
    // DNE reply as the OSD builds it for an INFO query
    let dne = PgNotify::dne(
        PgInfo::dne(SpgT {
            pgid: spg.pgid,
            shard: ShardId(2),
        }),
        ShardId(0),
        40,
        41,
    );
    assert_eq!(dne.from, ShardId(2));
    assert_eq!(dne.pg_features, 1);
    assert!(dne.info.dne_flag());
    let m = MOSDPGNotify2 {
        spgid: SpgT {
            pgid: spg.pgid,
            shard: ShardId(0),
        },
        notify: dne,
    };
    let pm = PeeringMsg::from(m.clone());
    assert_eq!(pm.gating(), (41, 40));
    assert_eq!(pm.priority(), PRIO_HIGH);
    let (t, v, c, seg) = pm.encode(u64::MAX).unwrap();
    assert_eq!((t, v, c), (130, 1, 1));
    let back = decode_peering(t, v, &seg).unwrap().unwrap();
    assert_eq!(back, pm);

    // activation ack
    let mut info = PgInfo::new(spg);
    info.history.last_epoch_started = 12;
    info.last_update = Eversion::new(12, 99);
    let ack = MOSDPGInfo2 {
        spgid: spg,
        epoch_sent: 13,
        min_epoch: 13,
        info,
        lease: None,
        lease_ack: Some(PgLeaseAck {
            readable_until_ub: denc::types::Timespan {
                sec: 1,
                nsec: 500_000_000,
            },
        }),
    };
    let pm = PeeringMsg::from(ack);
    let (t, v, _, seg) = pm.encode(u64::MAX).unwrap();
    assert_eq!(decode_peering(t, v, &seg).unwrap().unwrap(), pm);
    // 1.5 s duration bytes (spec 4.6): 01 00 00 00 00 65 cd 1d
    let b = PgLeaseAck {
        readable_until_ub: denc::types::Timespan {
            sec: 1,
            nsec: 500_000_000,
        },
    }
    .encode_to_vec()
    .unwrap();
    assert_eq!(&b[6..], &[1, 0, 0, 0, 0x00, 0x65, 0xcd, 0x1d]);

    // not ours
    assert!(decode_peering(99, 5, &Segments::default()).is_none());
    // truncated payload is an error, not a panic
    assert!(
        decode_peering(130, 1, &Segments::front(vec![1, 2, 3]))
            .unwrap()
            .is_err()
    );

    // Remove / Trim / RecoveryDelete
    let rm = MOSDPGRemove {
        epoch: 5,
        pgs: vec![
            spg,
            SpgT {
                pgid: spg.pgid,
                shard: ShardId(1),
            },
        ],
    };
    let seg = rm.encode(0).unwrap();
    assert_eq!(MOSDPGRemove::decode(3, &seg.front, &[], &[]).unwrap(), rm);
    let tr = MOSDPGTrim {
        epoch: 5,
        pgid: spg.pgid,
        trim_to: Eversion::new(5, 7),
        shard: ShardId(1),
    };
    let seg = tr.encode(0).unwrap();
    assert_eq!(seg.front.len(), 34);
    assert_eq!(MOSDPGTrim::decode(2, &seg.front, &[], &[]).unwrap(), tr);
    // hv1 trim has no shard
    assert_eq!(
        MOSDPGTrim::decode(1, &seg.front[..33], &[], &[])
            .unwrap()
            .shard,
        ShardId::NO_SHARD
    );
    let rd = MOSDPGRecoveryDelete {
        from: PgShard {
            osd: 3,
            shard: ShardId::NO_SHARD,
        },
        pgid: spg,
        map_epoch: 9,
        min_epoch: 8,
        cost: 1 << 20,
        objects: vec![(
            denc::types::Hobject::new(b"rbd_data.1", denc::types::SnapId::NOSNAP, 0xabcd, 3, b""),
            Eversion::new(9, 4),
        )],
    };
    let seg = rd.encode(0).unwrap();
    assert_eq!(
        MOSDPGRecoveryDelete::decode(2, &seg.front, &[], &[]).unwrap(),
        rd
    );
}
