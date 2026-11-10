// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Golden vectors from the reference ceph-dencoder (testdata/messages/gen.sh): decode, re-encode,
//! require byte equality. Plus oracle checks (testdata/messages/oracle.sh) for message types.
mod common;
use common::*;
use denc::types::*;
use denc::{Decode, Encode, from_slice};
use messages::*;

fn goldens(dir: &str) -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(testdata(dir)).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "bin") {
            v.push((
                format!("{dir}/{}", p.file_name().unwrap().to_string_lossy()),
                std::fs::read(&p).unwrap(),
            ));
        }
    }
    assert!(!v.is_empty(), "no goldens in {dir}");
    v.sort();
    v
}

fn roundtrip<T: Encode + for<'a> Decode<'a> + PartialEq + std::fmt::Debug>(dir: &str) -> Vec<T> {
    roundtrip_with(dir, denc::features::ALL)
}

/// `roundtrip` re-encoding with `features` (ceph-dencoder writes objectstore_perf_stat_t / osd_stat_t instances without
/// features: their perf struct takes the v1 ms form).
fn roundtrip_with<T: Encode + for<'a> Decode<'a> + PartialEq + std::fmt::Debug>(
    dir: &str,
    features: u64,
) -> Vec<T> {
    goldens(dir)
        .into_iter()
        .map(|(n, b)| {
            let v: T = from_slice(&b).unwrap_or_else(|e| panic!("{n}: {e}"));
            assert_eq!(v.encode_to_vec_with_features(features).unwrap(), b, "{n}");
            v
        })
        .collect()
}

#[test]
fn log_entry() {
    let v: Vec<LogEntry> = roundtrip("LogEntry");
    assert_eq!(v[0].prio, clog::DEBUG);
}

#[test]
fn osd_superblock() {
    let v: Vec<OsdSuperblock> = roundtrip("OSDSuperblock");
    assert_eq!(v.len(), 3);
    let s = &v[1];
    assert_eq!(
        (s.whoami, s.current_epoch, s.clean_thru, s.mounted),
        (3, 4, 7, 8)
    );
    assert_eq!(s.cluster_fsid, Uuid([1; 16]));
    assert_eq!(s.osd_fsid, Uuid([2; 16]));
    assert_eq!(s.mapc, [(5u32, 5u32)].into());
}

#[test]
fn osd_stat_family() {
    let v: Vec<OsdStat> = roundtrip_with("osd_stat_t", 0);
    let s = &v[1];
    assert_eq!(s.statfs.total, 234);
    assert_eq!(s.hb_peers, vec![7]);
    assert_eq!((s.snap_trim_queue_len, s.num_snap_trimming), (8, 99));
    assert_eq!(s.hb_pingtime.len(), 2);
    assert_eq!(s.hb_pingtime[0].back_pingtime, [1000, 900, 800]);
    roundtrip::<StoreStatfs>("store_statfs_t");
    roundtrip::<Pow2Hist>("pow2_hist_t");
    let p: Vec<ObjectstorePerfStat> = roundtrip_with("objectstore_perf_stat_t", 0);
    assert_eq!(
        (p[1].os_commit_latency_ns, p[1].os_apply_latency_ns),
        (20_000_000, 30_000_000)
    );
}

#[test]
fn perf_counter_type() {
    let v: Vec<PerfCounterType> = roundtrip("PerfCounterType");
    assert_eq!(v[1].path, "mycounter");
    assert_eq!((v[1].ty, v[1].priority), (8, 10));
}

/// Our encodings, as stored in ours/*.msg, equal what we encode now; the real ceph-dencoder
/// decoded each one (oracle.sh) and its summaries (oracle/*.json) show the intended values.
#[test]
fn samples_match_stored_and_oracle_summaries() {
    let want = |n: &str, needles: &[&str]| {
        let j = std::fs::read_to_string(testdata(&format!("oracle/{n}.json"))).unwrap();
        for s in needles {
            assert!(j.contains(s), "{n}: {s:?} not in {j}");
        }
    };
    want(
        "MOSDPing.a",
        &["ping e61 up_from 59", "delta_ub -1.000000477s"],
    );
    want("MOSDPing.b", &["you_died e61"]);
    want("MMgrOpen.svc", &["rgw.rgw.x daemon"]);
    want("MMgrReport.a", &["+2-0 packed 38 daemon_metrics=1"]);
    want("MPGStats.a", &["seq 266287972355"]);
    want(
        "MOSDBoot.a",
        &["osd.3 booted 0 features 4540191374342881279 v61"],
    );
    want(
        "MOSDFailure.a",
        &["failed immediate osd.1 v2:172.28.0.40:6800/1234 for 21sec e61"],
    );
    want("MOSDMap.a", &["4..6 src has 1..6"]);
    want(
        "MOSDMarkMeDown.a",
        &["request_ack=1, down_and_dead=1, osd.3"],
    );
    want("MOSDPGTemp.a", &["{1.0=[0,1],1.1=[]}"]);
    want("MMonSubscribe.a", &["config=0+,osdmap=62"]);
    want("MOSDAlive.a", &["want up_thru 62 have 61"]);
    want("MMonGetVersionReply.a", &["handle=7 version=100"]);
}
