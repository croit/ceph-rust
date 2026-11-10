// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Sample messages shared by the golden / oracle / roundtrip tests.
#![allow(clippy::allow_attributes, dead_code)]
use denc::types::*;
use messages::*;
use std::collections::BTreeMap;

pub fn testdata(rel: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/messages")
        .join(rel)
}

pub fn fsid() -> Uuid {
    Uuid::parse("6d2f4f0e-6e1a-4a64-9a55-6e766d65736f").unwrap()
}
fn addr(port: u16, nonce: u32) -> EntityAddrVec {
    EntityAddrVec::single(EntityAddr::v4(
        EntityAddr::TYPE_MSGR2,
        nonce,
        [172, 28, 0, 40],
        port,
    ))
}
fn smap(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
    kv.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

pub fn superblock() -> OsdSuperblock {
    OsdSuperblock {
        cluster_fsid: fsid(),
        whoami: 3,
        current_epoch: 61,
        weight: 0.0,
        compat_features: CompatSet::osd_initial(),
        clean_thru: 60,
        mounted: 59,
        osd_fsid: Uuid([7; 16]),
        purged_snaps_last: 58,
        last_purged_snaps_scrub: UTime::new(1_700_000_000, 5),
        cluster_osdmap_trim_lower_bound: 1,
        mapc: [(1u32, 61u32)].into(),
    }
}

pub fn osd_stat() -> OsdStat {
    let st = StoreStatfs {
        total: 8 << 30,
        available: 7 << 30,
        internally_reserved: 1 << 20,
        allocated: 1 << 20,
        data_stored: 1000,
        data_compressed: 0,
        data_compressed_allocated: 0,
        data_compressed_original: 0,
        omap_allocated: 4096,
        internal_metadata: 8192,
    };
    let mut s = OsdStat::from_statfs(st, 62, (62 << 32) + 3);
    s.hb_peers = vec![0, 1, 2];
    s.os_perf_stat = ObjectstorePerfStat {
        os_commit_latency_ns: 2_500_000,
        os_apply_latency_ns: 3_000_000,
    };
    s.hb_pingtime = vec![HbPingtime {
        osd: 1,
        last_update: 1_700_000_000,
        back_pingtime: [100, 200, 300],
        back_min: [90, 190, 290],
        back_max: [110, 210, 310],
        back_last: 101,
        front_pingtime: [120, 220, 320],
        front_min: [91, 191, 291],
        front_max: [111, 211, 311],
        front_last: 121,
    }];
    s
}

/// (dencoder type name, sample name, message). Type name is used by tests/oracle.sh.
pub fn samples() -> Vec<(&'static str, &'static str, AnyMessage)> {
    let a = addr(6800, 1234);
    let mut v: Vec<(&'static str, &'static str, AnyMessage)> = Vec::new();
    macro_rules! add {
        ($t:literal, $n:literal, $m:expr) => {
            v.push(($t, $n, AnyMessage::from($m)))
        };
    }
    add!(
        "MAuth",
        "a",
        MAuth {
            version: 0,
            protocol: 2,
            auth_payload: vec![1, 2, 3],
            monmap_epoch: 5
        }
    );
    add!(
        "MAuthReply",
        "a",
        MAuthReply {
            protocol: 2,
            result: -13,
            global_id: 4242,
            result_bl: vec![9; 7],
            result_msg: "denied".into()
        }
    );
    add!("MMonGetMap", "a", MMonGetMap);
    add!(
        "MMonSubscribe",
        "a",
        MMonSubscribe {
            what: [
                (
                    "osdmap".to_string(),
                    SubItem {
                        start: 62,
                        flags: 1
                    }
                ),
                ("config".to_string(), SubItem::default())
            ]
            .into(),
            hostname: "host1".into(),
        }
    );
    add!(
        "MMonSubscribeAck",
        "a",
        MMonSubscribeAck {
            interval: 300,
            fsid: fsid()
        }
    );
    add!(
        "MMonGetVersion",
        "a",
        MMonGetVersion {
            handle: 7,
            what: "osdmap".into()
        }
    );
    add!(
        "MMonGetVersionReply",
        "a",
        MMonGetVersionReply {
            handle: 7,
            version: 100,
            oldest_version: 3
        }
    );
    add!(
        "MMonCommand",
        "a",
        MMonCommand {
            version: 0,
            fsid: fsid(),
            cmd: vec![r#"{"prefix":"osd new","uuid":"x"}"#.into()],
            data: b"{\"cephx_secret\":\"k\"}".to_vec(),
        }
    );
    add!(
        "MMonCommandAck",
        "a",
        MMonCommandAck {
            version: 11,
            r: -17,
            rs: "exists".into(),
            cmd: vec!["{}".into()],
            data: b"out".to_vec()
        }
    );
    add!(
        "MMonMap",
        "a",
        MMonMap {
            monmap: vec![5; 33]
        }
    );
    add!(
        "MConfig",
        "a",
        MConfig {
            config: smap(&[("osd_max_backfills", "2"), ("debug_osd", "1/5")])
        }
    );
    add!(
        "MGetConfig",
        "a",
        MGetConfig {
            name: CephEntityName {
                ty: 4,
                id: "3".into()
            },
            host: "host1".into(),
            device_class: "nvme".into()
        }
    );
    add!(
        "MLog",
        "a",
        MLog {
            version: 0,
            fsid: fsid(),
            entries: vec![LogEntry {
                name: CephEntityName {
                    ty: 4,
                    id: "3".into()
                },
                rank: EntityName::osd(3),
                addrs: a.clone(),
                stamp: UTime::new(1_700_000_001, 9),
                seq: 17,
                prio: clog::WARN,
                msg: "wrongly marked down".into(),
                channel: "cluster".into(),
            }],
        }
    );
    add!(
        "MLogAck",
        "a",
        MLogAck {
            fsid: fsid(),
            last: 17,
            channel: "cluster".into()
        }
    );
    add!(
        "MCommand",
        "a",
        MCommand {
            fsid: fsid(),
            cmd: vec![r#"{"prefix":"version"}"#.into()],
            data: vec![1, 2]
        }
    );
    add!(
        "MCommandReply",
        "a",
        MCommandReply {
            r: -2,
            rs: "unknown".into(),
            data: vec![3, 4]
        }
    );
    add!(
        "MOSDMap",
        "a",
        MOSDMap {
            fsid: fsid(),
            incremental_maps: [(5u32, vec![1; 10]), (6, vec![2; 4])].into(),
            maps: [(4u32, vec![3; 20])].into(),
            cluster_osdmap_trim_lower_bound: 1,
            newest_map: 6,
        }
    );
    add!(
        "MMonGetOSDMap",
        "a",
        MMonGetOSDMap {
            version: 0,
            full_first: 3,
            full_last: 5,
            inc_first: 0,
            inc_last: 0
        }
    );
    add!(
        "MOSDBoot",
        "a",
        MOSDBoot {
            version: 61,
            sb: superblock(),
            hb_back_addrs: addr(6801, 1234),
            cluster_addrs: addr(6802, 1234),
            boot_epoch: 0,
            hb_front_addrs: addr(6803, 1234),
            metadata: smap(&[
                ("hostname", "host1"),
                ("osd_objectstore", "bluestore"),
                ("ceph_version_short", "21.1.1")
            ]),
            osd_features: 0x3f01_ffff_ffff_ffff,
        }
    );
    add!(
        "MOSDAlive",
        "a",
        MOSDAlive {
            version: 61,
            want: 62
        }
    );
    add!(
        "MOSDBeacon",
        "a",
        MOSDBeacon {
            version: 61,
            pgs: vec![PgT::new(1, 2), PgT::new(1, 3)],
            min_last_epoch_clean: 60,
            last_purged_snaps_scrub: UTime::new(5, 6),
            osd_beacon_report_interval: 300,
        }
    );
    add!(
        "MOSDMarkMeDown",
        "a",
        MOSDMarkMeDown {
            version: 0,
            fsid: fsid(),
            target_osd: 3,
            target_addrs: a.clone(),
            epoch: 61,
            request_ack: true,
            down_and_dead: true,
        }
    );
    add!(
        "MOSDMarkMeDead",
        "a",
        MOSDMarkMeDead {
            version: 0,
            fsid: fsid(),
            target_osd: 3,
            epoch: 61
        }
    );
    add!(
        "MOSDFailure",
        "a",
        MOSDFailure {
            version: 61,
            fsid: fsid(),
            target_osd: 1,
            target_addrs: a.clone(),
            epoch: 61,
            flags: MOSDFailure::FLAG_FAILED | MOSDFailure::FLAG_IMMEDIATE,
            failed_for: 21,
        }
    );
    add!(
        "MOSDFull",
        "a",
        MOSDFull {
            version: 0,
            map_epoch: 61,
            state: 1 << 5
        }
    );
    add!(
        "MOSDPing",
        "a",
        MOSDPing {
            fsid: fsid(),
            map_epoch: 61,
            op: MOSDPing::PING,
            ping_stamp: UTime::new(1_700_000_000, 123),
            pad_len: MOSDPing::pad_len_for(2000),
            up_from: 59,
            mono_ping_stamp: Timespan { sec: 100, nsec: 5 },
            mono_send_stamp: Timespan { sec: 100, nsec: 9 },
            delta_ub: Some(Timespan {
                sec: -1,
                nsec: -500
            }),
        }
    );
    add!(
        "MOSDPing",
        "b",
        MOSDPing {
            fsid: fsid(),
            map_epoch: 61,
            op: MOSDPing::YOU_DIED,
            ping_stamp: UTime::new(1, 2),
            pad_len: 0,
            up_from: 0,
            mono_ping_stamp: Timespan::default(),
            mono_send_stamp: Timespan::default(),
            delta_ub: None,
        }
    );
    add!(
        "MOSDPGTemp",
        "a",
        MOSDPGTemp {
            version: 61,
            map_epoch: 61,
            pg_temp: [(PgT::new(1, 0), vec![0, 1]), (PgT::new(1, 1), vec![])].into(),
            forced: true
        }
    );
    add!(
        "MOSDPGCreated",
        "a",
        MOSDPGCreated {
            version: 0,
            pgid: PgT::new(2, 5)
        }
    );
    add!(
        "MMonGetPurgedSnaps",
        "a",
        MMonGetPurgedSnaps {
            version: 0,
            start: 59,
            last: 62
        }
    );
    add!(
        "MMonGetPurgedSnapsReply",
        "a",
        MMonGetPurgedSnapsReply {
            version: 0,
            start: 59,
            last: 62,
            purged_snaps: [(60u32, [(1i64, [(2u64, 3u64)].into())].into())].into(),
        }
    );
    add!("MMgrOpen", "a", MMgrOpen::osd(3));
    add!(
        "MMgrOpen",
        "svc",
        MMgrOpen {
            daemon_name: "rgw.x".into(),
            service_name: "rgw".into(),
            service_daemon: true,
            daemon_metadata: smap(&[("k", "v")]),
            daemon_status: smap(&[("s", "t")]),
            config_bl: vec![0; 8],
            config_defaults_bl: vec![0; 4],
        }
    );
    add!("MMgrConfigure", "a", MMgrConfigure::new(5, 5));
    let mut rep = MMgrReport::new("3".into());
    let mut counters = BTreeMap::new();
    let t = |p, ty, pr, u| PerfCounterType::new(p, ty, pr, u);
    counters.insert(
        "osd.op".to_string(),
        (
            t("osd.op", pct::COUNTER_U64, 10, pct::UNIT_NONE),
            CounterValue {
                value: 7,
                ..Default::default()
            },
        ),
    );
    counters.insert(
        "osd.op_latency".to_string(),
        (
            t("osd.op_latency", pct::TIME_AVG, 9, pct::UNIT_NONE),
            CounterValue {
                value: 5000,
                avgcount: 2,
                avgcount2: 2,
            },
        ),
    );
    counters.insert(
        "osd.debug".to_string(),
        (
            t("osd.debug", pct::GAUGE, 0, pct::UNIT_NONE),
            CounterValue {
                value: 1,
                ..Default::default()
            },
        ),
    );
    rep.set_perf(PerfReporter::new().build(&counters, 5).unwrap());
    rep.daemon_health_metrics = vec![DaemonHealthMetric {
        ty: DaemonHealthMetric::SLOW_OPS,
        value: (30 << 32) | 2,
    }];
    add!("MMgrReport", "a", rep);
    add!(
        "MPGStats",
        "a",
        MPGStats {
            version: 0,
            fsid: fsid(),
            osd_stat: osd_stat(),
            pg_stat: vec![],
            epoch: 61,
            dummy: UTime::default(),
            pool_stat: [(
                1i64,
                StoreStatfs {
                    total: 10,
                    available: 5,
                    ..Default::default()
                }
            )]
            .into(),
        }
    );
    v
}
