// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Behavioural tests: versions, features, tolerance, perf-counter bookkeeping.
mod common;
use common::*;
use denc::features::{ALL, MSG_ADDR2};
use denc::types::*;
use messages::*;
use std::collections::BTreeMap;

#[test]
fn header2_roundtrip_and_layout() {
    let h = Header2 {
        seq: 1,
        tid: 2,
        ty: 0x702,
        priority: 127,
        version: 9,
        data_pre_padding_len: 0,
        data_off: 3,
        ack_seq: 5,
        flags: 3,
        compat_version: 1,
        reserved: 0,
    };
    let b = h.encode();
    assert_eq!(b.len(), 41);
    assert_eq!(&b[16..18], &[0x02, 0x07]);
    assert_eq!(Header2::parse(&b).unwrap(), h);
    assert!(Header2::parse(&b[..40]).is_err());
    let z = Header2 {
        version: 4,
        ..Default::default()
    };
    assert_eq!(z.effective_compat(), 4);
}

#[test]
fn consts_match_spec() {
    assert_eq!(
        (
            MOSDBoot::MSG_TYPE,
            MOSDBoot::HEAD_VERSION,
            MOSDBoot::COMPAT_VERSION
        ),
        (71, 7, 7)
    );
    assert_eq!(
        (
            MOSDMap::MSG_TYPE,
            MOSDMap::HEAD_VERSION,
            MOSDMap::COMPAT_VERSION
        ),
        (41, 4, 3)
    );
    assert_eq!(
        (
            MOSDPing::MSG_TYPE,
            MOSDPing::HEAD_VERSION,
            MOSDPing::COMPAT_VERSION
        ),
        (70, 5, 4)
    );
    assert_eq!((MMgrReport::MSG_TYPE, MMgrReport::HEAD_VERSION), (0x702, 9));
    assert_eq!(
        (
            MPGStats::MSG_TYPE,
            MPGStats::HEAD_VERSION,
            MPGStats::COMPAT_VERSION
        ),
        (87, 2, 1)
    );
    assert_eq!(
        (MOSDBeacon::HEAD_VERSION, MOSDBeacon::COMPAT_VERSION),
        (3, 1)
    );
    assert_eq!(
        (MMonSubscribe::HEAD_VERSION, MMonSubscribe::COMPAT_VERSION),
        (3, 1)
    );
}

#[test]
fn unknown_type_passes_through() {
    let m = decode_any(0x7fff, 3, &[1, 2], &[3], &[4]).unwrap();
    let AnyMessage::Unknown {
        ty,
        version,
        compat,
        segments,
    } = &m
    else {
        panic!()
    };
    assert_eq!((*ty, *version, *compat), (0x7fff, 3, 3));
    assert_eq!(
        (
            segments.front.clone(),
            segments.middle.clone(),
            segments.data.clone()
        ),
        (vec![1, 2], vec![3], bytes::Bytes::from_static(&[4]))
    );
    let (t, v, c, s) = m.encode(ALL).unwrap();
    assert_eq!((t, v, c, s.front), (0x7fff, 3, 3, vec![1, 2]));
}

/// MSG-02: an unsupported type re-encodes with the compat version it arrived with, so a mixed-version peer is asked for
/// no newer decoder than the original sender did (`decode_any` has no header, so it keeps compat = version there).
#[test]
fn unknown_type_keeps_the_received_compat_version() {
    let h = Header2 {
        ty: 0x6fff,
        version: 7,
        compat_version: 3,
        ..Default::default()
    };
    let m = decode_with_header(&h, &[1, 2], &[], &[]).unwrap();
    assert!(matches!(
        m,
        AnyMessage::Unknown {
            compat: 3,
            version: 7,
            ..
        }
    ));
    let (t, v, c, s) = m.encode(ALL).unwrap();
    assert_eq!((t, v, c, s.front), (0x6fff, 7, 3, vec![1, 2]));
    // a sender that left compat 0 meant `version`
    let h = Header2 {
        compat_version: 0,
        ..h
    };
    let (_, _, c, _) = decode_with_header(&h, &[1, 2], &[], &[])
        .unwrap()
        .encode(ALL)
        .unwrap();
    assert_eq!(c, 7);
}

/// MSG-07: `front_zc` is public state, so a broken rope must be an error, never a slice panic inside the decode path.
#[test]
fn front_rope_offsets_are_checked() {
    let ok = Segments {
        front: vec![1, 4],
        front_zc: vec![
            (1, bytes::Bytes::from_static(b"23")),
            (2, bytes::Bytes::from_static(b"56")),
        ],
        ..Default::default()
    };
    assert_eq!(&*ok.front_bytes().unwrap(), b"\x01\x32\x33\x04\x35\x36");
    let past_end = Segments {
        front: vec![1],
        front_zc: vec![(5, bytes::Bytes::from_static(b"x"))],
        ..Default::default()
    };
    assert!(past_end.front_bytes().is_err());
    let out_of_order = Segments {
        front: vec![1, 2],
        front_zc: vec![
            (2, bytes::Bytes::from_static(b"z")),
            (1, bytes::Bytes::from_static(b"y")),
        ],
        ..Default::default()
    };
    assert!(out_of_order.front_bytes().is_err());
}

/// MSG-09: no `Debug` output may carry key material or payload bytes (ticket, cephx request, keyring JSON).
#[test]
fn message_debug_never_prints_payloads() {
    let secret = "SECRET-TICKET";
    let bytes = secret.as_bytes().to_vec();
    let dump = |m: &dyn std::fmt::Debug| format!("{m:?}");
    for text in [
        dump(&MAuth {
            auth_payload: bytes.clone(),
            ..Default::default()
        }),
        dump(&MAuthReply {
            result_bl: bytes.clone(),
            result_msg: "denied".into(),
            ..Default::default()
        }),
        dump(&MMonCommand {
            data: bytes.clone(),
            cmd: vec!["osd new".into()],
            ..Default::default()
        }),
        dump(&MCommand {
            data: bytes.clone(),
            ..Default::default()
        }),
        dump(&MPing {
            reply: Some(bytes.clone()),
        }),
        dump(&AnyMessage::from(MAuth {
            auth_payload: bytes.clone(),
            ..Default::default()
        })),
        dump(&Segments {
            data: bytes.clone().into(),
            ..Default::default()
        }),
    ] {
        assert!(!text.contains(secret), "{text}");
    }
    let text = dump(&MAuth {
        auth_payload: vec![0; 13],
        ..Default::default()
    });
    assert!(text.contains("auth_payload_len: 13"), "{text}");
}

/// MSG-10: `Default` must produce frames a peer can decode, not zero-length blobs or a missing tail.
#[test]
fn defaults_are_wire_valid() {
    let open = MMgrOpen::default();
    assert_eq!(
        ConfigBl::decode(&open.config_bl).unwrap(),
        ConfigBl::default()
    );
    assert_eq!(open.config_bl, ConfigBl::default().encode().unwrap());
    assert!(
        decode_config_defaults_bl(&open.config_defaults_bl)
            .unwrap()
            .is_empty()
    );
    let c = MMgrConfigure::default();
    let seg = c.encode(ALL).unwrap();
    assert_eq!(seg.front.len(), 4 + 4 + MMgrConfigure::EMPTY_TAIL.len());
    assert_eq!(MMgrConfigure::decode(4, &seg.front, &[], &[]).unwrap(), c);
    let r = MMgrReport::default();
    assert_eq!(r.packed, MMgrReport::EMPTY_PACKED);
    assert_eq!(r.packed, encode_packed(&[]).unwrap());
    assert_eq!(decode_packed(&[], &r.packed).unwrap(), []);
    let seg = r.encode(ALL).unwrap();
    assert_eq!(MMgrReport::decode(9, &seg.front, &[], &[]).unwrap(), r);
}

/// MSG-08: the mask is a `u64`, so an id outside `1..64` is rejected instead of shifting/wrapping.
#[test]
fn feature_ids_are_range_checked() {
    let f = FeatureSet::new(&[(1, "a"), (63, "b")]);
    assert_eq!((f.mask, f.names.len()), (1 << 1 | 1 << 63, 2));
    for id in [0, 64, 200] {
        assert!(
            std::panic::catch_unwind(|| FeatureSet::new(&[(id, "x")])).is_err(),
            "id {id}"
        );
    }
}

/// MSG-12: a counter whose `type` changes gets its schema re-declared (the packed layout differs), and `decode_packed`
/// rejects a body that does not match the declared set exactly.
#[test]
fn perf_reporter_redeclares_a_changed_type() {
    let mut c: BTreeMap<_, _> = [counter("osd.op", pct::GAUGE, 5, 1)].into();
    let mut r = PerfReporter::new();
    assert_eq!(r.build(&c, 5).unwrap().declare_types.len(), 1);
    c.get_mut("osd.op").unwrap().0.ty = pct::TIME_AVG;
    let changed = r.build(&c, 5).unwrap();
    assert_eq!(changed.undeclare_types, ["osd.op"]);
    assert!(changed.declare_types.is_empty());
    assert_eq!(changed.packed, encode_packed(&[]).unwrap());
    let redeclared = r.build(&c, 5).unwrap();
    assert_eq!(redeclared.declare_types.len(), 1);
    assert_eq!(redeclared.declare_types[0].ty, pct::TIME_AVG);
    assert_eq!(redeclared.packed.len(), 6 + 24);
    let ty: Vec<&PerfCounterType> = redeclared.declare_types.iter().collect();
    assert_eq!(decode_packed(&ty, &redeclared.packed).unwrap().len(), 1);
    // a body that carries more than the declared set is refused
    let mut extra = redeclared.packed.clone();
    extra.extend_from_slice(&[0; 8]);
    let len = u32::from_le_bytes(extra[2..6].try_into().unwrap());
    extra[2..6].copy_from_slice(&(len + 8).to_le_bytes());
    assert!(decode_packed(&ty, &extra).is_err());
}

#[test]
fn compat_too_new_is_rejected() {
    let s = MOSDAlive {
        version: 1,
        want: 2,
    }
    .encode(ALL)
    .unwrap();
    let h = Header2 {
        ty: 73,
        version: 5,
        compat_version: 3,
        ..Default::default()
    };
    assert!(matches!(
        decode_with_header(&h, &s.front, &[], &[]),
        Err(denc::Error::CompatTooNew { .. })
    ));
    // newer version but compatible: decodes, trailing fields ignored
    let mut front = s.front.clone();
    front.extend_from_slice(&[9; 8]);
    let h = Header2 {
        ty: 73,
        version: 5,
        compat_version: 1,
        ..Default::default()
    };
    assert!(decode_with_header(&h, &front, &[], &[]).is_ok());
}

#[test]
fn truncated_payloads_error_not_panic() {
    for (t, n, m) in samples() {
        let (ty, ver, _, s) = m.encode(ALL).unwrap();
        for cut in [0, 1, s.front.len() / 2, s.front.len().saturating_sub(1)] {
            if cut >= s.front.len() {
                continue;
            }
            // Messages with an opaque raw tail may accept a short prefix; all that matters: no panic.
            let _ = decode_any(ty, ver, &s.front[..cut], &[], &[]);
        }
        let _ = (t, n);
    }
}

#[test]
fn old_versions_decode_with_defaults() {
    // MOSDBeacon v1: no scrub stamp / interval.
    let mut e = denc::Encoder::new();
    e.u64(7).unwrap();
    e.i16(-1).unwrap();
    e.u64(0).unwrap();
    e.u32(0).unwrap();
    e.u32(5).unwrap();
    let b = MOSDBeacon::decode(1, &e.into_vec(), &[], &[]).unwrap();
    assert_eq!(
        (
            b.version,
            b.min_last_epoch_clean,
            b.osd_beacon_report_interval
        ),
        (7, 5, 0)
    );
    // MMonGetVersionReply v1
    let mut e = denc::Encoder::new();
    e.u64(1).unwrap();
    e.u64(2).unwrap();
    let r = MMonGetVersionReply::decode(1, &e.into_vec(), &[], &[]).unwrap();
    assert_eq!((r.handle, r.version, r.oldest_version), (1, 2, 0));
    // MLogAck without channel
    let mut e = denc::Encoder::new();
    Uuid([1; 16]).encode_to_vec().unwrap();
    e.raw(&[1; 16]).unwrap();
    e.u64(9).unwrap();
    let a = MLogAck::decode(1, &e.into_vec(), &[], &[]).unwrap();
    assert_eq!((a.last, a.channel.as_str()), (9, ""));
}

use denc::Encode;

#[test]
fn addrvec_follows_features() {
    let m = MOSDMarkMeDown {
        target_addrs: EntityAddrVec::single(EntityAddr::v4(
            EntityAddr::TYPE_LEGACY,
            5,
            [1, 2, 3, 4],
            6800,
        )),
        ..Default::default()
    };
    let with = m.encode(ALL).unwrap().front;
    let without = m.encode(ALL & !MSG_ADDR2).unwrap().front;
    assert_ne!(with, without);
    // legacy form decodes back to the same address
    let back = MOSDMarkMeDown::decode(4, &without, &[], &[]).unwrap();
    assert_eq!(back.target_addrs.0.len(), 1);
    assert_eq!(back.target_addrs.0[0].port(), 6800);
}

#[test]
fn osd_ping_padding_and_span() {
    let p = MOSDPing {
        pad_len: MOSDPing::pad_len_for(2000),
        ..Default::default()
    };
    assert_eq!(p.pad_len, 1971);
    let f = p.encode(ALL).unwrap().front;
    let base = MOSDPing {
        pad_len: 0,
        ..p.clone()
    }
    .encode(ALL)
    .unwrap()
    .front;
    assert_eq!(f.len(), base.len() + 1971);
    assert!(f[base.len()..].iter().all(|b| *b == 0));
    assert!(MOSDPing::decode(5, &f[..f.len() - 1], &[], &[]).is_err());
    assert!(MOSDPing::decode(5, &f[..base.len()], &[], &[]).is_err());
    assert_eq!(MOSDPing::pad_len_for(10), 0);
    // v4 sender: no trailing hv5 fields
    let mut e = denc::Encoder::new();
    e.raw(&[0; 16]).unwrap();
    e.u32(7).unwrap();
    e.u8(4).unwrap();
    e.u32(1).unwrap();
    e.u32(2).unwrap();
    e.u32(0).unwrap();
    let mut legacy = e.into_vec();
    let old = MOSDPing::decode(4, &legacy, &[], &[]).unwrap();
    legacy[29..33].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(MOSDPing::decode(4, &legacy, &[], &[]).is_err());
    assert_eq!(
        (old.map_epoch, old.op, old.up_from, old.delta_ub),
        (7, 4, 0, None)
    );
    // signedspan truncates toward zero, nsec carries the sign
    assert_eq!(
        span_from_nanos(-1_000_000_500),
        Timespan {
            sec: -1,
            nsec: -500
        }
    );
    assert_eq!(
        span_to_nanos(span_from_nanos(-1_000_000_500)),
        -1_000_000_500
    );
    assert_eq!(
        span_from_nanos(2_500_000_000),
        Timespan {
            sec: 2,
            nsec: 500_000_000
        }
    );
}

#[test]
fn mgrmap_prefix() {
    let raw = denc::Encoder::new();
    let mut e = raw;
    e.versioned(14, 6, |e| {
        e.u32(42)?;
        EntityAddrVec::single(EntityAddr::v4(
            EntityAddr::TYPE_MSGR2,
            9,
            [172, 28, 0, 11],
            6800,
        ))
        .encode(e)?;
        e.u64(4100)?;
        e.bool(true)?;
        "x".encode(e)?;
        e.raw(&[0xee; 100]) // standbys, modules, ... skipped
    })
    .unwrap();
    let raw = e.into_vec();
    let m = MMgrMap::from_raw(raw.clone()).unwrap();
    assert_eq!(
        (m.prefix.epoch, m.prefix.active_gid, m.prefix.available),
        (42, 4100, true)
    );
    assert_eq!(m.prefix.active_name, "x");
    assert_eq!(m.prefix.active_addrs.v2().unwrap().port(), 6800);
    assert_eq!(m.encode(ALL).unwrap().front, raw); // opaque re-emit
    // struct_compat newer than we understand -> error
    let mut bad = raw;
    bad[1] = 7;
    assert!(MgrMapPrefix::parse(&bad).is_err());
}

#[test]
fn mgr_configure_keeps_tail() {
    let mut e = denc::Encoder::new();
    e.u32(5).unwrap();
    e.u32(7).unwrap();
    e.raw(&[0, 0, 0, 0, 1, 2, 3]).unwrap();
    let front = e.into_vec();
    let c = MMgrConfigure::decode(4, &front, &[], &[]).unwrap();
    assert_eq!((c.stats_period, c.stats_threshold), (5, 7));
    assert_eq!(c.encode(ALL).unwrap().front, front);
    let v1 = MMgrConfigure::decode(1, &front[..4], &[], &[]).unwrap();
    assert_eq!((v1.stats_period, v1.stats_threshold), (5, 0));
    assert_eq!(
        MMgrConfigure::new(5, 5).encode(ALL).unwrap().front.len(),
        13
    );
}

#[test]
fn config_blobs() {
    let bl = ConfigBl {
        options: vec![(
            "osd_max_backfills".into(),
            vec![(1, "2".into()), (2, "3".into())],
        )],
        ignored_mon_values: [("a".to_string(), "b".to_string())].into(),
    };
    let b = bl.encode().unwrap();
    assert_eq!(ConfigBl::decode(&b).unwrap(), bl);
    assert_eq!(ConfigBl::default().encode().unwrap(), vec![0; 8]);
    let d = vec![("x".to_string(), "1".to_string())];
    assert_eq!(
        decode_config_defaults_bl(&encode_config_defaults_bl(&d).unwrap()).unwrap(),
        d
    );
    assert_eq!(MMgrOpen::osd(3).config_bl, vec![0; 8]);
}

fn counter(p: &str, ty: u8, prio: u8, v: u64) -> (String, (PerfCounterType, CounterValue)) {
    (
        p.to_string(),
        (
            PerfCounterType::new(p, ty, prio, 1),
            CounterValue {
                value: v,
                avgcount: 1,
                avgcount2: 1,
            },
        ),
    )
}

#[test]
fn perf_reporter_declares_once_and_packs_sorted() {
    let mut c: BTreeMap<_, _> = [
        counter("osd.op", pct::COUNTER_U64, 10, 5),
        counter("osd.numpg", pct::GAUGE, 5, 3),
        counter("osd.op_latency", pct::TIME_AVG, 9, 1000),
        counter("osd.low", pct::GAUGE, 2, 9),
    ]
    .into();
    let mut r = PerfReporter::new();
    let r1 = r.build(&c, 5).unwrap();
    let names: Vec<_> = r1.declare_types.iter().map(|t| t.path.as_str()).collect();
    assert_eq!(names, ["osd.numpg", "osd.op", "osd.op_latency"]);
    assert!(r1.undeclare_types.is_empty());
    // packed: numpg (u64), op (u64), op_latency (u64 + 2 avg) = 8+8+24 in a 6-byte envelope
    assert_eq!(r1.packed.len(), 6 + 8 + 8 + 24);
    let ty: Vec<&PerfCounterType> = r1.declare_types.iter().collect();
    let vals = decode_packed(&ty, &r1.packed).unwrap();
    assert_eq!(
        vals.iter().map(|v| v.value).collect::<Vec<_>>(),
        [3, 5, 1000]
    );
    assert_eq!(vals[2].avgcount, 1);
    // second report: nothing new to declare, values still packed
    let r2 = r.build(&c, 5).unwrap();
    assert!(r2.declare_types.is_empty() && r2.undeclare_types.is_empty());
    assert_eq!(r2.packed.len(), r1.packed.len());
    // threshold raised: lower-priority counters are undeclared and dropped from packed
    let r3 = r.build(&c, 9).unwrap();
    assert_eq!(r3.undeclare_types, ["osd.numpg"]);
    assert_eq!(r3.packed.len(), 6 + 8 + 24);
    // counter disappears
    c.remove("osd.op");
    let r4 = r.build(&c, 9).unwrap();
    assert_eq!(r4.undeclare_types, ["osd.op"]);
    // new session: everything is declared again
    r.reset();
    assert_eq!(r.build(&c, 9).unwrap().declare_types.len(), 1);
}

#[test]
fn pgstats_opaque_pg_stat_roundtrips() {
    let env = {
        let mut e = denc::Encoder::new();
        e.versioned(30, 22, |e| e.raw(&[1, 2, 3, 4, 5])).unwrap();
        e.into_vec()
    };
    let m = MPGStats {
        fsid: fsid(),
        osd_stat: osd_stat(),
        pg_stat: vec![(PgT::new(1, 4), env.clone()), (PgT::new(1, 5), env)],
        epoch: 9,
        ..Default::default()
    };
    let s = m.encode(ALL).unwrap();
    assert_eq!(MPGStats::decode(2, &s.front, &[], &[]).unwrap(), m);
}

#[test]
fn osd_stat_from_statfs_follows_spec() {
    let s = osd_stat();
    assert_eq!(s.kb, (8i64 << 30) >> 10);
    assert_eq!(s.kb_avail, (7i64 << 30) >> 10);
    assert_eq!(s.kb_used, (1i64 << 30) >> 10);
    assert_eq!(
        (s.num_osds, s.num_per_pool_osds, s.num_per_pool_omap_osds),
        (1, 1, 0)
    );
    assert_eq!(s.seq >> 32, 62);
}

#[test]
fn osdmap_epoch_range_and_commands_data() {
    let m = MOSDMap {
        incremental_maps: [(5u32, vec![]), (9, vec![])].into(),
        maps: [(3u32, vec![])].into(),
        ..Default::default()
    };
    assert_eq!(m.epoch_range(), Some((3, 9)));
    assert_eq!(MOSDMap::default().epoch_range(), None);
    let c = MMonCommand {
        data: vec![1, 2, 3],
        ..Default::default()
    };
    let s = c.encode(ALL).unwrap();
    assert_eq!(s.data, vec![1, 2, 3]);
    assert!(s.middle.is_empty());
}

#[test]
fn initial_compat_set_shape() {
    let c = CompatSet::osd_initial();
    assert_eq!(c.incompat.names.len(), 17);
    assert_eq!(c.incompat.mask, 0x3fffe);
    assert_eq!(c.compat, FeatureSet::default());
}

#[test]
fn mgrmap_default_roundtrips() {
    let m = MMgrMap::default();
    let seg = m.encode(ALL).unwrap();
    let back = MMgrMap::decode(1, &seg.front, &[], &[]).unwrap();
    assert_eq!(back, m);
    assert!(!back.prefix.available);
}

#[test]
fn pg_ready_to_merge_spec_example() {
    use denc::types::{Eversion, PgT};
    // split-merge.md 6.2: pool 3, S = 3.f, epoch 200, sv 195'42, tv 190'77, les = lec = 180, ready
    let hex = "c800000000000000 ffff 0000000000000000 01 0300000000000000 0f000000 ffffffff 2a00000000000000 c3000000 4d00000000000000 be000000 b4000000 b4000000 01";
    let want: Vec<u8> = hex
        .split_whitespace()
        .flat_map(|w| {
            (0..w.len() / 2)
                .map(|i| u8::from_str_radix(&w[2 * i..2 * i + 2], 16).unwrap())
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(want.len(), 68);
    let m = messages::MOSDPGReadyToMerge {
        version: 200,
        pgid: PgT::new(3, 0xf),
        source_version: Eversion::new(195, 42),
        target_version: Eversion::new(190, 77),
        last_epoch_started: 180,
        last_epoch_clean: 180,
        ready: true,
    };
    let (ty, hv, hc, seg) = messages::AnyMessage::from(m.clone())
        .encode(u64::MAX)
        .unwrap();
    assert_eq!((ty, hv, hc), (122, 1, 0));
    assert_eq!(seg.front, want);
    match messages::decode_any(122, 1, &want, &[], &[]).unwrap() {
        messages::AnyMessage::MOSDPGReadyToMerge(d) => assert_eq!(d, m),
        o => panic!("{o:?}"),
    }
}

/// objectstore_perf_stat_t (spec pg-io-stats.md 4): ns pair (v2) for OS_PERF_STAT_NS peers, else floor ms (v1); v1
/// decodes as ms * 10^6.
#[test]
fn objectstore_perf_stat_follows_features() {
    let p = ObjectstorePerfStat {
        os_commit_latency_ns: 2_500_000,
        os_apply_latency_ns: 700_000,
    };
    let v2 = p
        .encode_to_vec_with_features(denc::features::OS_PERF_STAT_NS)
        .unwrap();
    assert_eq!(&v2[..6], &[2, 2, 16, 0, 0, 0]);
    assert_eq!(denc::from_slice::<ObjectstorePerfStat>(&v2).unwrap(), p);
    let v1 = p.encode_to_vec_with_features(0).unwrap();
    assert_eq!(v1, [1, 1, 8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]);
    let d: ObjectstorePerfStat = denc::from_slice(&v1).unwrap();
    assert_eq!(
        (d.os_commit_latency_ns, d.os_apply_latency_ns),
        (2_000_000, 0)
    );
}
