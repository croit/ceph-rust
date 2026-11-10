// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Golden round-trips against ceph-dencoder output (testdata/pgwire, regenerate with gen.sh).

use denc::{Decode, Encode, from_slice};
use pgwire::*;
use serde_json::Value;
use std::fmt::Debug;
use std::path::PathBuf;

fn dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/pgwire")
        .join(name)
}

fn count(name: &str) -> usize {
    (1..)
        .take_while(|i| dir(name).join(format!("{i}.bin")).exists())
        .count()
}

fn json(name: &str, i: usize) -> Value {
    serde_json::from_slice(&std::fs::read(dir(name).join(format!("{i}.json"))).unwrap()).unwrap()
}

/// decode -> re-encode byte-identical, for every generated instance. Returns decoded values.
fn golden<T>(name: &str) -> Vec<T>
where
    T: Encode + for<'a> Decode<'a> + Debug + PartialEq,
{
    let n = count(name);
    assert!(n > 0, "no vectors for {name}");
    let mut out = vec![];
    for i in 1..=n {
        let bytes = std::fs::read(dir(name).join(format!("{i}.bin"))).unwrap();
        let v: T = from_slice(&bytes).unwrap_or_else(|e| panic!("{name}/{i} decode: {e}"));
        let re = v.encode_to_vec().unwrap();
        assert_eq!(re, bytes, "{name}/{i} re-encode differs");
        let v2: T = from_slice(&re).unwrap();
        assert_eq!(v, v2);
        out.push(v);
    }
    out
}

#[test]
fn history() {
    let v: Vec<PgHistory> = golden("pg_history_t");
    let j = json("pg_history_t", 2);
    let h = &v[1];
    assert_eq!(h.epoch_created as u64, j["epoch_created"]);
    assert_eq!(h.last_epoch_marked_full as u64, j["last_epoch_marked_full"]);
    assert_eq!(h.last_interval_clean as u64, j["last_interval_clean"]);
    assert_eq!(h.same_primary_since, 7);
    assert_eq!(h.last_deep_scrub.to_string(), "12'13");
    assert_eq!(h.last_clean_scrub_stamp.sec, 16);
    assert_eq!(
        (
            h.prior_readable_until_ub.sec,
            h.prior_readable_until_ub.nsec
        ),
        (3, 141_500_000)
    );
    // v11 (21.2.0): the six latch fields of the populated instance, in upstream order
    let t = |u: denc::types::UTime| (u.sec, u.nsec);
    assert_eq!(
        [
            t(h.last_degraded),
            t(h.last_clean),
            t(h.vuln_window_reported),
            t(h.last_rebuild_active_start),
            t(h.rebuild_span_reported),
            t(h.rebuild_active_accum)
        ],
        [(19, 20), (21, 22), (21, 22), (23, 24), (25, 26), (0, 27)]
    );
    assert_eq!(j["last_degraded"], "19.000000");
    assert_eq!(j["rebuild_span_reported"], "25.000000");
    assert_eq!(v[0], PgHistory::default());
}

#[test]
fn stats() {
    let v: Vec<ObjectStatSum> = golden("object_stat_sum_t");
    let j = json("object_stat_sum_t", 1);
    let fields = v[0].fields();
    assert_eq!(fields.len(), 40);
    for (name, val) in fields {
        assert_eq!(j[name].as_i64().unwrap(), val, "field {name}");
    }
    let _: Vec<ObjectStatCollection> = golden("object_stat_collection_t");
    let st: Vec<PgStat> = golden("pg_stat_t");
    for (i, s) in st.iter().enumerate() {
        let j = json("pg_stat_t", i + 1);
        assert_eq!(
            s.state_string(),
            j["state"].as_str().unwrap(),
            "state string {i}"
        );
        assert_eq!(s.reported_seq, j["reported_seq"].as_u64().unwrap());
        assert_eq!(s.log_size, j["log_size"].as_i64().unwrap());
        assert_eq!(s.snaptrimq_len as u64, j["snaptrimq_len"].as_u64().unwrap());
        assert_eq!(s.up.len(), j["up"].as_array().unwrap().len());
        assert_eq!(
            s.blocked_by.len(),
            j["blocked_by"].as_array().unwrap().len()
        );
        assert_eq!(
            s.object_location_counts.len(),
            j["object_location_counts"].as_array().unwrap().len()
        );
        assert_eq!(
            s.snaptrim_duration,
            j["snaptrim_duration"].as_f64().unwrap()
        );
        assert_eq!(
            s.last_degraded.sec as f64,
            j["last_degraded"].as_str().unwrap().parse::<f64>().unwrap()
        );
    }
    let s = &st[2];
    assert_eq!(s.up, vec![123, 124]);
    assert_eq!(s.acting, vec![456, 124]);
    assert_eq!(s.blocked_by, vec![155, 156]);
    assert_eq!(s.snaptrimq_len, 1_048_576);
    assert_eq!(s.last_scrub_duration, 3617);
    assert_eq!(s.parent.to_string(), "2.1");
    assert_eq!(s.avail_no_missing.len(), 1);
}

#[test]
fn info_and_hitset() {
    let h: Vec<PgHitSetHistory> = golden("pg_hit_set_history_t");
    assert_eq!(h[1].history.len(), 1);
    assert_eq!(h[1].current_last_update.to_string(), "1'2");
    let _: Vec<PgHitSetInfo> = golden("pg_hit_set_info_t");
    let i: Vec<PgInfo> = golden("pg_info_t");
    assert!(i[0].dne_flag() && i[0].is_empty());
    assert!(!i[0].is_incomplete());
    // constant hit_set bytes of a default info (spec test-vectors-m2 item 5)
    let hb = PgHitSetHistory::default().encode_to_vec().unwrap();
    assert_eq!(hb.len(), 65);
    assert_eq!(
        hb,
        std::fs::read(dir("pg_hit_set_history_t").join("1.bin")).unwrap()
    );
}

#[test]
fn intervals() {
    let p: Vec<PastIntervals> = golden("PastIntervals");
    assert_eq!(p[1].intervals.len(), 2);
    assert_eq!(p[0].all_participants.len(), 6);
    let _: Vec<PgInterval> = golden("PastIntervals__pg_interval_t");
}

#[test]
fn peer_structs() {
    let n: Vec<PgNotify> = golden("pg_notify_t");
    for x in &n {
        assert_eq!(x.from, x.info.pgid.shard);
    }
    let q: Vec<PgQuery> = golden("pg_query_t");
    let types: Vec<_> = q.iter().map(|x| x.ty).collect();
    for t in [
        QueryType::INFO,
        QueryType::LOG,
        QueryType::MISSING,
        QueryType::FULLLOG,
    ] {
        assert!(types.contains(&t), "{t:?}");
    }
    // features are ignored by pg_query_t
    for i in 1..=count("pg_query_t") {
        assert_eq!(
            std::fs::read(dir("pg_query_t").join(format!("{i}.bin"))).unwrap(),
            std::fs::read(dir("pg_query_t").join(format!("{i}.nofeat.bin"))).unwrap()
        );
    }
    let l: Vec<PgLease> = golden("pg_lease_t");
    assert_eq!(l[0].encode_to_vec().unwrap().len(), 30);
    let a: Vec<PgLeaseAck> = golden("pg_lease_ack_t");
    assert_eq!(a[0].encode_to_vec().unwrap().len(), 14);
}

#[test]
fn log_structs() {
    let e: Vec<LogEntry> = golden("pg_log_entry_t");
    assert_eq!(e[0].op, LogOp(0));
    assert_eq!(e[1].op, LogOp::MODIFY);
    assert_eq!(e[2].op, LogOp::ERROR);
    assert_eq!(e[2].return_code, -2);
    assert_eq!(e[1].version.to_string(), "1'2");
    assert_eq!(e[1].prior_version.to_string(), "3'4");
    assert_eq!(e[1].user_version, 1);
    assert!(e[1].reqid_is_indexed() && e[2].reqid_is_indexed() && !e[0].reqid_is_indexed());
    let _: Vec<LogDup> = golden("pg_log_dup_t");
    let l: Vec<PgLog> = golden("pg_log_t");
    assert_eq!(l[1].log.len(), 3);
    let m: Vec<ObjectModDesc> = golden("ObjectModDesc");
    assert!(m.iter().any(|x| !x.bl.is_empty()));
    let c: Vec<ObjectCleanRegions> = golden("ObjectCleanRegions");
    assert_eq!(c[0], ObjectCleanRegions::default());
    let _: Vec<LogOpReturnItem> = golden("pg_log_op_return_item_t");
}

#[test]
fn missing_structs() {
    let m: Vec<PgMissing> = golden("pg_missing_t");
    for (i, x) in m.iter().enumerate() {
        assert!(x.may_include_deletes);
        // legacy item form (features = 0) must still decode to the same set, modulo clean regions
        let b = std::fs::read(dir("pg_missing_t").join(format!("{}.nofeat.bin", i + 1))).unwrap();
        let old: PgMissing = from_slice(&b).unwrap();
        assert_eq!(old.missing.len(), x.missing.len());
        for (k, v) in &x.missing {
            let o = &old.missing[k];
            assert_eq!((o.need, o.have, o.flags), (v.need, v.have, v.flags));
            assert_eq!(o.clean_regions, ObjectCleanRegions::fully_dirty());
        }
    }
    let it: Vec<MissingItem> = golden("pg_missing_item");
    assert_eq!(it.len(), 3);
    for i in 1..=count("pg_missing_item") {
        let b = std::fs::read(dir("pg_missing_item").join(format!("{i}.nofeat.bin"))).unwrap();
        let old: MissingItem = from_slice(&b).unwrap();
        assert_eq!(
            (old.need, old.have, old.flags),
            (it[i - 1].need, it[i - 1].have, it[i - 1].flags)
        );
    }
}

/// croit fork `wip-ifed-dedup` vectors (testdata/pgwire/fork-dedup, gen-fork-dedup.sh; adr 0593-dedup-deep-scrub-reformat):
/// pg_stat_t v32 carries `last_deep_scrub_start_stamp`. The fork always writes the new version; croit-flashstore-osd writes it only
/// while the stamp is set: with a stamp the bytes are identical, without one croit-flashstore-osd's bytes are the fork's minus the 8
/// stamp bytes (struct_v 31, envelope length - 8) and decode to the same value. pg_history_t: the fork's 21.1.x layout
/// (v11 = v10 + stamp) is superseded by upstream v11 (adr 0628-pg-history-v12, stamp now v12); its vectors are gone until
/// the fork rebased on 21.2.0 is captured (hand vectors in history.rs meanwhile).
fn fork_dedup<T>(name: &str, v_old: u8, stamp: impl Fn(&T) -> denc::types::UTime)
where
    T: Encode + for<'a> Decode<'a> + Debug + PartialEq,
{
    let dir = dir("fork-dedup").join(name);
    let n = (1..)
        .take_while(|i| dir.join(format!("{i}.bin")).exists())
        .count();
    assert!(n > 0, "no fork vectors for {name}");
    let mut stamped = 0;
    for i in 1..=n {
        let fork = std::fs::read(dir.join(format!("{i}.bin"))).unwrap();
        let v: T = from_slice(&fork).unwrap_or_else(|e| panic!("{name}/{i} decode: {e}"));
        let ours = v.encode_to_vec().unwrap();
        if stamp(&v) != Default::default() {
            stamped += 1;
            assert_eq!(
                ours, fork,
                "{name}/{i}: stamped instance re-encodes identically"
            );
        } else {
            assert_eq!(ours[0], v_old, "{name}/{i}: no stamp, old version");
            assert_eq!(ours.len() + 8, fork.len());
            assert_eq!(&ours[6..], &fork[6..fork.len() - 8], "{name}/{i}");
            assert_eq!(from_slice::<T>(&ours).unwrap(), v);
        }
    }
    assert!(
        stamped > 0,
        "{name}: the fork's populated instance has a stamp"
    );
}

#[test]
fn fork_dedup_deep_scrub_start_stamp() {
    fork_dedup::<PgStat>("pg_stat_t", 31, |s| s.last_deep_scrub_start_stamp);
}
