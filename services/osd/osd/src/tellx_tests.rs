// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Operator commands of `tellx.rs` (parity WP-T): JSON shapes and the refusals. Child of `xcore_tests` (multi-core
//! harness on a simulated device).
use super::*;
use crate::tell::ReplyTo;
use serde_json::{Value, json};

/// Run a command on core 0 like an admin socket request; the cores settle meanwhile.
pub(super) fn ask(mc: &mut Mc, cmd: Value) -> (i32, Value) {
    let (tx, rx) = std::sync::mpsc::channel();
    mc.osds[0].cmds.seq += 1;
    let tok = mc.osds[0].cmds.seq;
    mc.osds[0].cmds.pending.insert(tok, tx);
    let t = mc.t;
    mc.osds[0].set_now(t);
    mc.osds[0].exec_command(&cmd.to_string(), ReplyTo::Asok(tok));
    mc.settle();
    let (r, rs, out) = rx.try_recv().expect("command answered");
    (
        r,
        serde_json::from_slice(&out.into_bytes()).unwrap_or(Value::String(rs)),
    )
}

/// Like [`ask`], the reply bytes untouched.
fn ask_raw(mc: &mut Mc, cmd: Value) -> (i32, String, Vec<u8>) {
    let (tx, rx) = std::sync::mpsc::channel();
    mc.osds[0].cmds.seq += 1;
    let tok = mc.osds[0].cmds.seq;
    mc.osds[0].cmds.pending.insert(tok, tx);
    let t = mc.t;
    mc.osds[0].set_now(t);
    mc.osds[0].exec_command(&cmd.to_string(), ReplyTo::Asok(tok));
    mc.settle();
    let (r, rs, out) = rx.try_recv().expect("command answered");
    (r, rs, out.into_bytes())
}

fn up_with_data() -> Mc {
    let mut mc = Mc::new(4);
    mc.up();
    write_read_all(&mut mc, 1, "t", 8, 1);
    mc.run_for(Duration::from_secs(2));
    mc
}

#[test]
fn tell_report_formats() {
    use messages::{MCommand, MCommandReply, MMonCommand, MMonCommandAck, Message};

    let mut mc = Mc::new(4);
    mc.up();
    // Enter on a worker connection, including reports merged asynchronously on core 0.
    let cl = mc.client(2);
    mc.osds[2]
        .links
        .get_mut(&cl)
        .unwrap()
        .auth
        .borrow_mut()
        .caps = Some("allow *".into());
    let mut tid = 100;
    for prefix in [
        "version",
        "perf dump",
        "counter dump",
        "dump_mempools",
        "dump_pgs",
    ] {
        for format in [None, Some("json-pretty"), Some("json"), Some("jsonl")] {
            for legacy in [false, true] {
                let mut cmd = json!({"prefix": prefix});
                if let Some(format) = format {
                    cmd["format"] = json!(format);
                }
                let cmd = vec![cmd.to_string()];
                let msg = if legacy {
                    MMonCommand {
                        version: 0,
                        fsid: mc.fsid,
                        cmd,
                        data: vec![],
                    }
                    .into()
                } else {
                    MCommand {
                        fsid: mc.fsid,
                        cmd,
                        data: vec![],
                    }
                    .into()
                };
                mc.osds[2].t.out.clear();
                mc.osds[2].on_link_message(cl, crate::osd::Purpose::Accepted, tid, msg);
                mc.settle();
                let reply = mc.osds[2]
                    .t
                    .out
                    .iter()
                    .find(|f| f.0 == cl && f.1 == tid && f.2.0 == if legacy { 51 } else { 98 })
                    .expect("command reply on worker connection");
                let segs = &reply.3;
                let (r, out) = if legacy {
                    let r =
                        MMonCommandAck::decode(reply.2.1, &segs.front, &segs.middle, &segs.data)
                            .unwrap();
                    (r.r, r.data)
                } else {
                    let r = MCommandReply::decode(reply.2.1, &segs.front, &segs.middle, &segs.data)
                        .unwrap();
                    (r.r, r.data)
                };
                assert_eq!(r, 0, "{prefix} {format:?} legacy={legacy}");
                let value: Value = serde_json::from_slice(&out).unwrap();
                let expected = if matches!(format, Some("json" | "jsonl")) {
                    value.to_string()
                } else {
                    format!("{}\n", serde_json::to_string_pretty(&value).unwrap())
                };
                assert_eq!(
                    out,
                    expected.as_bytes(),
                    "{prefix} {format:?} legacy={legacy}"
                );
                tid += 1;
            }
        }
    }
}

/// A PG this OSD leads, `pool.seed`.
fn primary_pg(mc: &mut Mc) -> String {
    let (_, d) = ask(mc, json!({"prefix": "dump_pgs"}));
    d["pgs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["primary"] == true)
        .expect("a primary pg")["pgid"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn blocked_ops_forms() {
    let mut mc = up_with_data();
    let (r, d) = ask(&mut mc, json!({"prefix": "dump_blocked_ops_count"}));
    assert_eq!(r, 0);
    assert_eq!(d["num_blocked_ops"], 0);
    assert!(d["complaint_time"].as_f64().unwrap() > 0.0);
    let (r, d) = ask(&mut mc, json!({"prefix": "dump_blocked_ops"}));
    assert_eq!(r, 0);
    assert_eq!(d["ops"], json!([]));
    assert_eq!(d["num_blocked_ops"], 0);
    assert!(d.get("num_ops").is_none(), "blocked form has no num_ops");
    assert!(d["complaint_time"].is_number());
    let (_, d) = ask(&mut mc, json!({"prefix": "dump_ops_in_flight"}));
    assert!(d["num_ops"].is_number());
}

#[test]
fn count_commands_do_not_render_per_op_documents() {
    // The allocation counter is the existing test allocator's per-thread wprof
    // hook. --features wprof-on verifies a constant allocation cost as the
    // tracker grows; ordinary builds still verify count/threshold semantics.
    fn measured(o: &mut Osd<B>, prefix: &str) -> ((i32, Value), u64) {
        let cmd = json!({"prefix": prefix});
        let _ = wprof::take();
        let result = {
            let _span = wprof::span(wprof::S::Gate);
            o.query_local_ext(prefix, &cmd).unwrap()
        };
        let allocations = wprof::take().iter().map(|s| s.2).sum();
        (result, allocations)
    }

    let mut mc = Mc::new(1);
    mc.up();
    let mut op = mc.op(4, "waiting", vec![OsdOp::read(0, 1)]);
    op.osdmap_epoch += 1;
    let client = mc.client(0);
    assert!(mc.call(0, client, 1, op.clone()).is_empty());
    assert_eq!(mc.osds[0].pg_parked_len(), 1);
    let o = &mut mc.osds[0];
    o.set_now(Duration::from_secs(100));
    let (empty, count_allocs) = measured(o, "dump_blocked_ops_count");
    assert_eq!(empty, (0, json!(1)));
    let (_, pq_allocs) = measured(o, "dump_op_pq_state");
    let threshold = 100_000_000_000 - o.tracker.lim.complaint_ns;
    for tid in 0..1024 {
        // Below, on, and above the inclusive complaint-time boundary.
        let start = threshold + tid % 3 - 1;
        o.tracker.start(crate::optrack::OpRec::new(
            client,
            tid + 2,
            EntityName::default(),
            EntityAddr::default(),
            &op,
            start,
        ));
    }
    let (blocked, grown_count_allocs) = measured(o, "dump_blocked_ops_count");
    assert_eq!(blocked, (0, json!(1 + 683)));
    let ((r, pq), grown_pq_allocs) = measured(o, "dump_op_pq_state");
    assert_eq!(r, 0);
    assert_eq!(pq["ops_in_flight"], 1024);
    assert_eq!(pq["ops_parked"], 1);
    if wprof::ENABLED && !cfg!(feature = "perf4-plain-allocator") {
        assert_eq!(grown_count_allocs, count_allocs, "count allocation growth");
        assert_eq!(grown_pq_allocs, pq_allocs, "queue allocation growth");
    }
}

#[test]
fn store_housekeeping_commands() {
    let mut mc = up_with_data();
    let (r, d) = ask(&mut mc, json!({"prefix": "flush_journal"}));
    assert_eq!((r, d), (0, json!({})));
    let (r, d) = ask(&mut mc, json!({"prefix": "compact"}));
    assert_eq!(r, 0);
    assert_eq!(d["elapsed_time"], 0.0);
    // checkpointed: the tree pages are clean
    ask(&mut mc, json!({"prefix": "flush_journal"}));
    mc.run_for(Duration::from_secs(3));
    let (_, before) = ask(&mut mc, json!({"prefix": "cache status"}));
    assert_eq!(before["cache_drops"], 0);
    assert!(before["tree_pages"].as_u64().unwrap() > 0, "{before}");
    // Ceph: exit 0, empty output
    for p in ["flush_store_cache", "cache drop"] {
        let (r, d) = ask(&mut mc, json!({"prefix": p}));
        assert_eq!((r, d), (0, Value::String(String::new())), "{p}");
    }
    let (_, after) = ask(&mut mc, json!({"prefix": "cache status"}));
    // every core dropped (twice); the clean tree pages went, the counters show it
    assert!(after["cache_drops"].as_u64().unwrap() > 0, "{after}");
    assert!(after["dropped_data_bytes"].as_u64().unwrap() > 0, "{after}");
    assert_eq!(after["data_cache_bytes"], 0);
    assert!(after["dropped_tree_pages"].as_u64().unwrap() > 0, "{after}");
    assert!(
        after["tree_pages"].as_u64() < before["tree_pages"].as_u64(),
        "{before} {after}"
    );
    assert_eq!(after["object_ctx"], 0);
    let (r, d) = ask(&mut mc, json!({"prefix": "cache status"}));
    assert_eq!(r, 0);
    for k in [
        "object_ctx",
        "tree_page_loads",
        "tree_page_evictions",
        "tree_hint_hits",
    ] {
        assert!(d[k].is_u64(), "{k}: {d}");
    }
}

#[test]
fn bench_reports_rate() {
    let mut mc = up_with_data();
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "bench", "count": 1 << 20, "size": 65536}),
    );
    assert_eq!(r, 0, "{d}");
    // the formatter's top-level section name is not printed in JSON (spec osd-lifecycle.md 9.1)
    assert_eq!(d["bytes_written"], 1 << 20);
    assert_eq!(d["blocksize"], 65536);
    assert!(d["bytes_per_sec"].as_f64().unwrap() > 0.0);
    assert!(d["iops"].as_f64().unwrap() > 0.0);
    assert!(d["elapsed_sec"].as_f64().unwrap() > 0.0);
    // the scratch objects are gone
    let (r, _) = ask(&mut mc, json!({"prefix": "bench", "size": 0}));
    assert_eq!(r, -22);
    let (r, _) = ask(&mut mc, json!({"prefix": "bench", "size": 1 << 30}));
    assert_eq!(r, -22, "block size cap");
}

#[test]
fn pq_state_and_pgstate_history() {
    let mut mc = up_with_data();
    let (r, d) = ask(&mut mc, json!({"prefix": "dump_op_pq_state"}));
    assert_eq!(r, 0);
    let s = d["shards"].as_array().unwrap();
    assert_eq!(s.len(), 4);
    assert_eq!(s[2]["shard"], 2);
    assert!(s[0]["ops_in_flight"].is_u64() && s[0]["ops_parked"].is_u64());
    let (r, d) = ask(&mut mc, json!({"prefix": "dump_pgstate_history"}));
    assert_eq!(r, 0);
    let pgs = d["pgs"].as_array().unwrap();
    assert!(!pgs.is_empty());
    let p = &pgs[0];
    assert!(p["pg"].is_string() && p["currently"].is_string());
    let h = p["history"].as_array().unwrap();
    assert!(!h.is_empty());
    assert!(h[0]["state"].is_string() && h[0]["enter"].as_str().unwrap().contains('T'));
}

/// `dump_pg_recovery_stats` / `reset_pg_recovery_stats` (spec osd-tell-gaps.md 1): one record per state name seen,
/// summed over the cores; reset answers rc 0 with nothing and the next dump is the empty array.
#[test]
fn pg_recovery_stats_dump_and_reset() {
    let mut mc = up_with_data();
    let (r, d) = ask(&mut mc, json!({"prefix": "dump_pg_recovery_stats"}));
    assert_eq!(r, 0);
    let rows = d.as_array().unwrap();
    let row = |n: &str| {
        rows.iter()
            .find(|x| x["nested_states"].as_array().unwrap().join_str() == n)
            .cloned()
    };
    let clean = row("Started/Primary/Active/Clean").expect("PGs went clean");
    assert!(clean["enter"].as_u64().unwrap() >= 1);
    // classic layout: ints for the counters, `<sec>.<usec>` strings for the times, the key split into its path
    for k in ["enter", "exit", "events"] {
        assert!(clean[k].is_u64(), "{k}");
    }
    for k in ["event_time", "total_time", "min_time", "max_time"] {
        let t = clean[k].as_str().unwrap();
        let (sec, us) = t.split_once('.').unwrap();
        assert!(
            sec.parse::<u64>().is_ok() && us.len() == 6 && us.parse::<u64>().is_ok(),
            "{k}={t}"
        );
    }
    assert_eq!(
        clean["nested_states"],
        json!(["Started", "Primary", "Active", "Clean"])
    );
    // the peering states the PGs passed on the way up are exited and timed
    let info = row("Started/Primary/Peering/GetInfo").expect("peered");
    assert!(info["exit"].as_u64().unwrap() >= 1);
    assert!(rows.iter().all(|x| x["nested_states"][0] != "Initial"));
    // names are unique and sorted
    let names: Vec<String> = rows
        .iter()
        .map(|x| x["nested_states"].as_array().unwrap().join_str())
        .collect();
    let mut sorted = names.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(names, sorted);
    // reset: rc 0, no bytes, idempotent; the table is empty afterwards
    for _ in 0..2 {
        let (r, rs, out) = ask_raw(&mut mc, json!({"prefix": "reset_pg_recovery_stats"}));
        assert_eq!((r, rs.as_str(), out.as_slice()), (0, "", b"".as_slice()));
    }
    let (r, rs, out) = ask_raw(&mut mc, json!({"prefix": "dump_pg_recovery_stats"}));
    assert_eq!((r, rs.as_str(), out.as_slice()), (0, "", b"[]".as_slice()));
}

trait JoinStr {
    fn join_str(&self) -> String;
}
impl JoinStr for Vec<Value> {
    fn join_str(&self) -> String {
        self.iter()
            .map(|v| v.as_str().unwrap())
            .collect::<Vec<_>>()
            .join("/")
    }
}

/// The store probes of a store without RocksDB, and the profiler of a build without it (spec osd-tell-gaps.md 4).
#[test]
fn store_probes_answer_like_classic_without_rocksdb() {
    let mut mc = up_with_data();
    let (r, rs, out) = ask_raw(&mut mc, json!({"prefix": "dump_objectstore_kv_stats"}));
    assert_eq!(r, 0, "{rs}");
    assert_eq!(
        out,
        b"error: RocksDB perf is disabled, can't probe for stats.\n"
    );
    let (r, rs, out) = ask_raw(&mut mc, json!({"prefix": "calc_objectstore_db_histogram"}));
    assert_eq!((r, rs.as_str(), out.as_slice()), (0, "", b"".as_slice()));
    for arg in ["status", "flush"] {
        let (r, rs, out) = ask_raw(&mut mc, json!({"prefix": "cpu_profiler", "arg": arg}));
        assert_eq!(r, 0, "{rs}");
        assert_eq!(out, b"cpu_profiler support not linked in", "{arg}");
    }
    // cputrace stays unregistered like a stock build; an unknown prefix is EINVAL (spec ops-observability 6.10)
    assert_eq!(
        ask(&mut mc, json!({"prefix": "cputrace start"})).0,
        -libc::EINVAL
    );
}

/// `scrub_purged_snaps` (spec osd-tell-gaps.md 2): rc 0 and no output with or without findings, a stray (a clone still
/// mapped for a snap the PG purged) is queued for trimming again, the superblock records the run.
#[test]
fn scrub_purged_snaps_requeues_strays() {
    let mut mc = Mc::new(2);
    mc.up();
    let cl = mc.client(0);
    let n = mc.osds[0].osdmap().unwrap().pool(1).unwrap().pg_num;
    let w = |mc: &mut Mc, tid: u64, data: &[u8]| {
        let op = mc.op(1, "snapobj", vec![OsdOp::writefull(data.to_vec())]);
        mc.call(0, cl, tid, op)[0].1.result
    };
    let clones = |mc: &mut Mc, tid: u64| {
        let mut op = mc.op(1, "snapobj", vec![OsdOp::list_snaps()]);
        op.snapid = opwire::SNAPDIR;
        let r = mc.call(0, cl, tid, op);
        let l: opwire::ObjListSnapResponse = denc::from_slice(&r[0].1.ops[0].outdata).unwrap();
        l.clones.len()
    };
    // without findings
    mc.osds[0].sb.last_purged_snaps_scrub = denc::types::UTime::new(0, 0);
    let (r, rs, out) = ask_raw(&mut mc, json!({"prefix": "scrub_purged_snaps"}));
    assert_eq!((r, rs.as_str(), out.as_slice()), (0, "", b"".as_slice()));
    assert!(mc.osds[0].sb.last_purged_snaps_scrub.sec > 0, "run stamped");
    // a clone for pool snap 1
    assert_eq!(w(&mut mc, 1, b"first"), 0);
    let mut m = with_pg_num(&mc, 11, 1, n);
    let p = m.pools.get_mut(&1).unwrap();
    p.flags |= osdmap::pool::flags::POOL_SNAPS;
    p.snap_seq = 1;
    p.snap_epoch = 11;
    p.snaps.insert(
        1,
        osdmap::pool::PoolSnapInfo {
            snapid: 1,
            stamp: denc::types::UTime::new(1, 0),
            name: b"s1".to_vec(),
        },
    );
    mc.deliver(m);
    assert_eq!(w(&mut mc, 2, b"second"), 0);
    assert_eq!(clones(&mut mc, 3), 2);
    // rmsnap with trimming off; the PG wrongly counts snap 1 as purged: its clone is a stray
    let mut m = with_pg_num(&mc, 12, 1, n);
    let p = m.pools.get_mut(&1).unwrap();
    p.flags |= osdmap::pool::flags::POOL_SNAPS;
    p.snap_seq = 1;
    p.snap_epoch = 12;
    m.flags |= osdmap::consts::map_flags::NOSNAPTRIM;
    m.removed_snaps_queue.entry(1).or_default().0.insert(1, 1);
    mc.deliver(m);
    let raw = mc.osds[0]
        .osdmap()
        .unwrap()
        .object_to_raw_pg(1, b"snapobj", b"", b"", -1)
        .unwrap();
    let seed = pgwire::pgmath::object_pg(raw.seed, n);
    let core = mc.owner(1, seed);
    let spg = SpgT {
        pgid: PgT { pool: 1, seed },
        shard: denc::types::ShardId::NO_SHARD,
    };
    mc.osds[core].pg.set.pg_mut(spg).unwrap().trim_snap_done(1);
    let (r, rs, out) = ask_raw(&mut mc, json!({"prefix": "scrub_purged_snaps"}));
    assert_eq!((r, rs.as_str(), out.as_slice()), (0, "", b"".as_slice()));
    assert_eq!(
        mc.osds[core].pg.set.pg(spg).unwrap().snap_trimq_len(),
        1,
        "the stray snap is queued again"
    );
    // trimming allowed again: the clone goes, the snap stays purged
    let m = with_pg_num(&mc, 13, 1, n);
    let mut m = m;
    let p = m.pools.get_mut(&1).unwrap();
    p.flags |= osdmap::pool::flags::POOL_SNAPS;
    p.snap_seq = 1;
    p.snap_epoch = 12;
    m.removed_snaps_queue.entry(1).or_default().0.insert(1, 1);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(5));
    assert_eq!(clones(&mut mc, 4), 1, "only the head after the retrim");
    assert_eq!(mc.osds[core].pg.set.pg(spg).unwrap().snap_trimq_len(), 0);
}

/// The periodic run: due once `osd_scrub_min_interval` (+ jitter) passed since the stamp, not before.
#[test]
fn purged_snaps_scrub_runs_from_the_tick() {
    let mut mc = up_with_data();
    let wall = mc.osds[0].wall().sec;
    mc.osds[0].sb.last_purged_snaps_scrub = denc::types::UTime::new(wall, 0);
    mc.osds[0].purged_snaps_scrub_tick();
    assert_eq!(mc.osds[0].sb.last_purged_snaps_scrub.sec, wall, "not due");
    mc.osds[0].sb.last_purged_snaps_scrub = denc::types::UTime::new(wall - 86400 * 2, 0);
    mc.osds[0].purged_snaps_scrub_tick();
    mc.settle();
    assert!(mc.osds[0].sb.last_purged_snaps_scrub.sec >= wall, "ran");
}

#[test]
fn reservation_dumps() {
    let mut mc = up_with_data();
    let (r, d) = ask(&mut mc, json!({"prefix": "dump_recovery_reservations"}));
    assert_eq!(r, 0);
    for side in ["local_reservations", "remote_reservations"] {
        let s = &d[side];
        assert!(s["max_allowed"].is_u64(), "{d}");
        assert!(s["min_priority"].is_u64());
        assert!(s["queues"].is_array() && s["in_progress"].is_array());
    }
    let (r, d) = ask(&mut mc, json!({"prefix": "dump_scrub_reservations"}));
    assert_eq!(r, 0);
    assert_eq!(d["scrubs_local"], 0);
    assert_eq!(d["scrubs_remote"], 0);
    assert!(d["osd_max_scrubs"].is_u64());
    assert!(d["granted_reservations"].is_array() && d["queued_reservations"].is_array());
}

#[test]
fn pool_views() {
    let mut mc = up_with_data();
    let (r, d) = ask(&mut mc, json!({"prefix": "get_mapped_pools"}));
    assert_eq!(r, 0);
    assert!(d.as_array().unwrap().contains(&json!(1)), "{d}");
    let (r, d) = ask(&mut mc, json!({"prefix": "dump_pool_statfs", "poolid": 1}));
    assert_eq!(r, 0, "{d}");
    assert_eq!(d["poolid"], 1);
    assert!(d["data_stored"].as_u64().unwrap() > 0);
    for k in [
        "total",
        "available",
        "internally_reserved",
        "allocated",
        "data_compressed",
        "data_compressed_allocated",
        "data_compressed_original",
        "omap_allocated",
        "internal_metadata",
    ] {
        assert!(d[k].is_u64(), "{k}");
    }
    assert_eq!(
        ask(&mut mc, json!({"prefix": "dump_pool_statfs", "poolid": 99})).0,
        -2
    );
    assert_eq!(ask(&mut mc, json!({"prefix": "dump_pool_statfs"})).0, -22);
    // MPGStats pool_stat carries data usage; the OSD disables per-pool OMAP allocation so the mgr uses PG scrub totals.
    let (_, s) = ask(&mut mc, json!({"prefix": "dump_osd_pg_stats"}));
    assert_eq!(s["osd_stat"]["num_per_pool_omap_osds"], 0);
    let p = s["pool_stat"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["poolid"] == 1)
        .expect("pool 1 in pool_stat");
    assert_eq!(p["data_stored"], d["data_stored"], "{p}");
    assert_eq!(p["allocated"], p["data_stored"]);
    assert_eq!(p["omap_allocated"], d["omap_allocated"]);
    let f = crate::pgs::pool_statfs(1000, 0, 0);
    assert_eq!(
        (f.data_stored, f.allocated, f.omap_allocated),
        (1000, 1000, 0)
    );
}

#[test]
fn osd_pg_stats_shape() {
    let mut mc = up_with_data();
    let (r, d) = ask(&mut mc, json!({"prefix": "dump_osd_pg_stats"}));
    assert_eq!(r, 0);
    assert!(d["pool_stat"].is_array());
    let pgs = d["pg_stat"].as_array().unwrap();
    assert!(!pgs.is_empty());
    assert!(pgs[0]["pgid"].is_string() && pgs[0]["state"].is_string());
    assert!(pgs[0]["stat_sum"]["num_objects"].is_number());
    let o = &d["osd_stat"];
    for k in [
        "up_from",
        "seq",
        "num_pgs",
        "kb",
        "kb_used",
        "kb_avail",
        "statfs",
        "perf_stat",
        "hb_peers",
    ] {
        assert!(!o[k].is_null(), "{k}");
    }
    assert!(o["statfs"]["total"].as_u64().unwrap() > 0);
}

#[test]
fn heap_and_profiler_are_refused_cleanly() {
    let mut mc = up_with_data();
    for sub in [
        "stats",
        "start_profiler",
        "stop_profiler",
        "release",
        "get_release_rate",
    ] {
        let (r, d) = ask(&mut mc, json!({"prefix": "heap", "heapcmd": sub}));
        assert_eq!(r, -95, "{sub}");
        assert!(d.as_str().unwrap().contains("not using tcmalloc"));
    }
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "get_heap_property", "property": "x"}),
    );
    assert_eq!(r, 0);
    assert_eq!(d["success"], false);
    assert_eq!(d["error"], "invalid property");
    assert_eq!(d["value"], 0);
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "set_heap_property", "property": "x", "value": 1}),
    );
    assert_eq!((r, d["success"].clone()), (0, json!(false)));
}

#[test]
fn cluster_log_and_log_dump() {
    let mut mc = up_with_data();
    for l in ["error", "warning", "info", "debug"] {
        let (r, _) = ask(
            &mut mc,
            json!({"prefix": "cluster_log", "level": l, "message": ["hello", "world"]}),
        );
        assert_eq!(r, 0, "{l}");
    }
    assert_eq!(
        ask(
            &mut mc,
            json!({"prefix": "cluster_log", "level": "info", "message": []})
        )
        .0,
        -22
    );
    assert_eq!(
        ask(
            &mut mc,
            json!({"prefix": "cluster_log", "level": "loud", "message": "x"})
        )
        .0,
        -22
    );
    // log dump/flush answer rc 0 with no output (spec 6.9)
    assert_eq!(ask(&mut mc, json!({"prefix": "log dump"})), (0, json!("")));
    assert_eq!(ask(&mut mc, json!({"prefix": "log flush"})), (0, json!("")));
}

#[test]
fn trim_stale_osdmaps_answers() {
    let mut mc = up_with_data();
    let (r, d) = ask(&mut mc, json!({"prefix": "trim stale osdmaps"}));
    assert_eq!(r, 0, "{d}");
    assert!(d["oldest_stored_map"].is_u64());
}

#[test]
fn pg_commands_route_to_the_owner() {
    let mut mc = up_with_data();
    let pg = primary_pg(&mut mc);
    // both spellings: `pg <pgid> list_unfound` and the bare classic prefix
    for cmd in [
        json!({"prefix": "pg", "pgid": pg, "cmd": "list_unfound"}),
        json!({"prefix": "list_unfound", "pgid": pg}),
    ] {
        let (r, d) = ask(&mut mc, cmd);
        assert_eq!(r, 0, "{d}");
        assert_eq!(d["num_missing"], 0);
        assert_eq!(d["num_unfound"], 0);
        assert_eq!(d["objects"], json!([]));
        assert_eq!(d["more"], false);
        assert_eq!(d["state"], "Active");
        assert_eq!(d["available_might_have_unfound"], true);
    }
    // offset: an hobject in its dump form; listing starts strictly after it
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "list_unfound", "pgid": pg,
            "offset": r#"{"oid":"a","key":"","snapid":-2,"hash":7,"max":0,"pool":1,"namespace":""}"#}),
    );
    assert_eq!(r, 0, "{d}");
    assert_eq!(d["offset"]["oid"], "a");
    assert_eq!(d["offset"]["snapid"], u64::MAX - 1);
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "list_unfound", "pgid": pg, "offset": "{nope"}),
    );
    assert_eq!(r, -22);
    assert!(
        d.as_str().unwrap().starts_with("error parsing offset: "),
        "{d}"
    );
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "mark_unfound_lost", "pgid": pg, "mulcmd": "revert"}),
    );
    assert_eq!((r, d.as_str().unwrap()), (0, "pg has no unfound objects"));
    let (r, _) = ask(
        &mut mc,
        json!({"prefix": "mark_unfound_lost", "pgid": pg, "mulcmd": "mark"}),
    );
    assert_eq!(r, -22);
    let (r, _) = ask(&mut mc, json!({"prefix": "scrub-abort", "pgid": pg}));
    assert_eq!(r, 0);
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "scrubdebug", "pgid": pg, "opcode": "status"}),
    );
    assert_eq!(r, 0);
    assert_eq!(d["scrubbing"], false);
    assert_eq!(
        ask(
            &mut mc,
            json!({"prefix": "scrubdebug", "pgid": pg, "opcode": "block"})
        )
        .0,
        -95
    );
    let (r, _) = ask(
        &mut mc,
        json!({"prefix": "schedule-deep-scrub", "pgid": pg}),
    );
    assert_eq!(r, 0);
    // a running or requested scrub is stopped
    let (r, _) = ask(&mut mc, json!({"prefix": "scrub-abort", "pgid": pg}));
    assert_eq!(r, 0);
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "pg", "pgid": "77.0", "cmd": "list_unfound"}),
    );
    assert_eq!((r, d.as_str().unwrap()), (-2, "i don't have pgid 77.0"));
    assert_eq!(
        ask(
            &mut mc,
            json!({"prefix": "scrub-abort", "pgid": "nonsense"})
        )
        .0,
        -22
    );
}

#[test]
fn dump_watchers_lists_real_watches() {
    let mut mc = Mc::new(4);
    mc.up();
    let c = mc.client(0);
    assert_eq!(
        ask(&mut mc, json!({"prefix": "dump_watchers"})),
        (0, json!([]))
    );
    let op = mc.op(
        1,
        "wobj",
        vec![
            OsdOp::create(false),
            OsdOp::watch_op(0xAB, opwire::consts::watch_op::WATCH, 0),
        ],
    );
    assert_eq!(mc.call(0, c, 100, op)[0].1.result, 0);
    let (r, d) = ask(&mut mc, json!({"prefix": "dump_watchers"}));
    assert_eq!(r, 0);
    let w = d.as_array().unwrap();
    assert_eq!(w.len(), 1, "{d}");
    assert_eq!(w[0]["object"], "wobj");
    assert_eq!(w[0]["namespace"], "");
    assert_eq!(w[0]["cookie"], 0xAB);
    assert_eq!(w[0]["entity_name"]["type"], "client");
    assert!(w[0]["entity_name"]["num"].is_number());
    assert!(w[0]["timeout"].is_number());
    assert!(w[0]["entity_addr_t"]["addr"].is_string());
}

#[test]
fn mempools_shape() {
    let mut mc = up_with_data();
    let (r, d) = ask(&mut mc, json!({"prefix": "dump_mempools"}));
    assert_eq!(r, 0);
    let bp = d["mempool"]["by_pool"].as_object().unwrap();
    // only real pools: none of the classic bluestore/bluefs placeholders, every entry has bytes
    assert!(
        !bp.keys()
            .any(|k| k.starts_with("bluestore") || k.starts_with("bluefs") || k == "bloom_filter")
    );
    for (n, p) in bp {
        assert!(
            p["items"].is_u64() && p["bytes"].as_u64().unwrap() > 0,
            "{n}"
        );
    }
    // PG log RAM is estimated (the test PGs hold entries), process memory comes from /proc (Linux)
    assert!(bp["osd_pglog"]["bytes"].as_u64().unwrap() > 0);
    assert!(d["process"].is_object());
    // memory envelope: target = base + ingress + caches (default target) and both ingress pools reported
    let e = &d["envelope"];
    assert_eq!(e["ingress_pools"].as_array().unwrap().len(), 2);
    assert!(e["ingress_pools"][0]["limit"].as_u64().unwrap() >= 90 << 20);
    assert_eq!(
        e["base"].as_u64().unwrap()
            + e["ingress"].as_u64().unwrap()
            + e["caches"].as_u64().unwrap(),
        e["target"].as_u64().unwrap()
    );
    #[cfg(target_os = "linux")]
    assert!(d["process"]["VmRSS"].as_u64().unwrap() > 0);
    let tb: u64 = bp.values().map(|p| p["bytes"].as_u64().unwrap()).sum();
    assert_eq!(d["mempool"]["total"]["bytes"].as_u64().unwrap(), tb);
}

#[test]
fn bluestore_commands_are_explained() {
    let mut mc = up_with_data();
    assert_eq!(
        ask(&mut mc, json!({"prefix": "bluestore bluefs stats"})).0,
        -libc::EINVAL,
        "unknown command prefix is EINVAL (spec ops-observability 6.10)"
    );
    for op in ["dump", "score", "fragmentation"] {
        let p = format!("bluestore allocator {op}");
        let (r, d) = ask(&mut mc, json!({"prefix": p, "name": "block"}));
        assert_eq!(r, 0, "{op}: {d}");
        match op {
            "dump" => {
                assert_eq!(d["alloc_unit"], 4096);
                assert_eq!(d["alloc_name"], "block");
                let cap = d["capacity"].as_u64().unwrap();
                let ext = d["extents"].as_array().unwrap();
                assert!(cap > 0 && !ext.is_empty());
                let hex = |s: &Value| {
                    u64::from_str_radix(s.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
                };
                let free: u64 = ext.iter().map(|e| hex(&e["length"])).sum();
                assert!(free <= cap);
                let offs: Vec<u64> = ext.iter().map(|e| hex(&e["offset"])).collect();
                assert!(offs.windows(2).all(|w| w[0] < w[1]), "ascending, merged");
            }
            "score" => assert!(d["fragmentation_score"].as_f64().unwrap() >= 0.0),
            _ => assert!(d["fragmentation_rating"].as_f64().unwrap() >= 0.0),
        }
        assert_eq!(
            ask(&mut mc, json!({"prefix": p, "name": "bluefs-db"})).0,
            -2
        );
    }
    // native free-space report (same backing data)
    let (r, d) = ask(&mut mc, json!({"prefix": "store free", "extents": true}));
    assert_eq!(r, 0, "{d}");
    assert!(d["free_bytes"].as_u64().unwrap() <= d["capacity"].as_u64().unwrap());
    assert_eq!(
        d["extent_list"].as_array().unwrap().len() as u64,
        d["extents"].as_u64().unwrap()
    );
    assert!(
        ask(&mut mc, json!({"prefix": "store free"}))
            .1
            .get("extent_list")
            .is_none()
    );
    // extent census of the idle sweep (adr 0533): summed per-core parts, a request is accepted
    let (r, d) = ask(&mut mc, json!({"prefix": "store census", "request": true}));
    assert_eq!(r, 0, "{d}");
    for k in [
        "census_seq",
        "objects",
        "records",
        "windows",
        "cut_chunks",
        "recompact_chunks",
    ] {
        assert!(d[k].as_u64().is_some(), "{k} missing: {d}");
    }
    // typed as one line
    assert_eq!(
        ask(
            &mut mc,
            json!({"prefix": "bluestore allocator score block"})
        )
        .0,
        0
    );
    // online expand is refused with the offline recipe
    for p in ["bluestore bluefs-bdev-expand", "bdev expand"] {
        let (r, d) = ask(&mut mc, json!({"prefix": p}));
        assert_eq!(r, -95);
        assert!(d.as_str().unwrap().contains("croit-flashstore-tool expand"));
    }
}

#[test]
fn new_commands_are_described() {
    let mut mc = up_with_data();
    let (_, d) = ask(&mut mc, json!({"prefix": "get_command_descriptions"}));
    let all: Vec<String> = d
        .as_object()
        .unwrap()
        .values()
        .map(|c| {
            c["sig"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|w| w.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    for want in [
        "bench",
        "cache drop",
        "cache status",
        "cluster_log",
        "compact",
        "flush_journal",
        "dump_blocked_ops_count",
        "dump_op_pq_state",
        "dump_pgstate_history",
        "dump_recovery_reservations",
        "dump_scrub_reservations",
        "get_mapped_pools",
        "dump_pool_statfs",
        "dump_osd_pg_stats",
        "dump_mempools",
        "heap",
        "scrub-abort",
        "trim stale osdmaps",
        "log dump",
        "bluestore allocator dump",
        "store free",
        "store census",
    ] {
        assert!(all.iter().any(|s| s == want), "{want} not described");
    }
}

#[test]
fn bench_is_chunked_not_blocking() {
    let mut mc = up_with_data();
    let (tx, rx) = std::sync::mpsc::channel();
    mc.osds[0].cmds.seq += 1;
    let tok = mc.osds[0].cmds.seq;
    mc.osds[0].cmds.pending.insert(tok, tx);
    let t = mc.t;
    mc.osds[0].set_now(t);
    let cmd = json!({"prefix": "bench", "count": 1 << 20, "size": 4096}).to_string();
    mc.osds[0].exec_command(&cmd, ReplyTo::Asok(tok));
    // started, not answered: the command returned to the loop
    assert!(rx.try_recv().is_err() && mc.osds[0].cmds.bench.is_some());
    // one write per driver iteration
    assert!(mc.osds[0].poll_store(t));
    assert!(rx.try_recv().is_err());
    // other commands are served meanwhile; a second bench is refused
    let (r, _) = ask(
        &mut mc,
        json!({"prefix": "bench", "count": 1 << 20, "size": 4096}),
    );
    assert_eq!(r, -16);
    mc.settle();
    let (r, _, out) = rx.try_recv().expect("bench answered");
    assert_eq!(r, 0);
    let d: Value = serde_json::from_slice(&out.into_bytes()).unwrap();
    assert_eq!(d["bytes_written"], 1 << 20);
    assert!(mc.osds[0].cmds.bench.is_none());
}

#[test]
fn leftover_commands_answer_cleanly() {
    let mut mc = up_with_data();
    // dump_missing: one (empty) array per PG
    let (r, d) = ask(&mut mc, json!({"prefix": "debug dump_missing"}));
    assert_eq!(r, 0, "{d}");
    let a = d.as_array().unwrap();
    assert!(!a.is_empty() && a.iter().all(|x| x.as_array().is_some_and(Vec::is_empty)));
    // recovery delay: only "no delay" is true here
    for p in ["debug kick_recovery_wq", "set_recovery_delay"] {
        assert_eq!(ask(&mut mc, json!({"prefix": p, "delay": 0})).0, 0, "{p}");
        assert_eq!(
            ask(&mut mc, json!({"prefix": p, "delay": 5, "utime": 5})).0,
            -95,
            "{p}"
        );
    }
    assert_eq!(
        ask(
            &mut mc,
            json!({"prefix": "clear_shards_repaired", "count": 0})
        )
        .0,
        0
    );
    assert_eq!(
        ask(&mut mc, json!({"prefix": "reset_purged_snaps_last"})).0,
        0
    );
    assert_eq!(mc.osds[0].sb.purged_snaps_last, 0);
    // no key blob over the admin socket
    assert_eq!(ask(&mut mc, json!({"prefix": "rotate-stored-key"})).0, -22);
    // legacy names are the perf commands
    let (r, d) = ask(&mut mc, json!({"prefix": "perfcounters_dump"}));
    assert_eq!(r, 0);
    assert!(d.get("osd").is_some());
    let (r, d) = ask(&mut mc, json!({"prefix": "perfcounters_schema"}));
    assert_eq!(r, 0);
    assert!(d.get("osd").is_some());
}

/// The stored key is the device record (what a restart falls back to) and, when present, the dir keyring
/// (`$osd_data/keyring`, rewritten 0600); a bad key changes nothing.
#[test]
fn rotate_stored_key_rewrites_the_stored_copies() {
    use crate::meta::MetaStore as _;
    use std::os::unix::fs::PermissionsExt as _;
    fn stored(mc: &Mc) -> String {
        let s = mc.osds[0].store.as_ref().unwrap();
        s.load_identity().unwrap().unwrap().key
    }
    let mut mc = up_with_data();
    let dir = std::env::temp_dir().join(format!("croit-flashstore-rotate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    mc.osds[0]
        .conf
        .set(
            crate::config::Level::Override,
            "osd_data",
            dir.to_str().unwrap(),
        )
        .unwrap();
    let k1 = cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, cephx::UTime::new(1, 0))
        .unwrap()
        .to_base64()
        .unwrap();
    mc.osds[0].cmds.inbl = format!("{k1}\n").into_bytes();
    // no dir keyring: the device record alone
    assert_eq!(mc.osds[0].rotate_stored_key().0, 0);
    assert_eq!(stored(&mc), k1);
    assert!(!dir.join("keyring").exists(), "no keyring is created");
    std::fs::write(dir.join("keyring"), "[osd.0]\n\tkey = OLD\n").unwrap();
    let k2 = cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, cephx::UTime::new(2, 0))
        .unwrap()
        .to_base64()
        .unwrap();
    mc.osds[0].cmds.inbl = k2.clone().into_bytes();
    assert_eq!(mc.osds[0].rotate_stored_key().0, 0);
    let t = std::fs::read_to_string(dir.join("keyring")).unwrap();
    assert_eq!(t, format!("[osd.0]\n\tkey = {k2}\n"));
    let mode = std::fs::metadata(dir.join("keyring"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(stored(&mc), k2);
    mc.osds[0].cmds.inbl = b"bad key!".to_vec();
    assert_eq!(mc.osds[0].rotate_stored_key().0, -22);
    assert_eq!(stored(&mc), k2);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `mark_unfound_lost revert` end to end, as a client sees it: osd.0 (primary) wrote `a` v2 and created `b` while osd.1
/// was down, osd.1 learned the log under norecover, osd.0 died and was declared lost. On osd.1 `a` reads back v1 (the
/// LOST_REVERT), `b` is gone (LOST_DELETE: ENOENT), and a new write on `a` works.
#[test]
fn mark_unfound_lost_is_what_clients_see() {
    use osdmap::consts::map_flags;
    let mut p = Pair::new(1, 1);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let n = map.pool(1).unwrap().pg_num;
    let pg_of = |name: &str| {
        let raw = map
            .object_to_raw_pg(1, name.as_bytes(), b"", b"", -1)
            .unwrap();
        PgT::new(1, pgwire::pgmath::object_pg(raw.seed, n))
    };
    let a = (0..)
        .map(|i| format!("ua{i}"))
        .find(|x| map.pg_to_up_acting(pg_of(x)).acting_primary == 0)
        .unwrap();
    let pg = pg_of(&a);
    let b = (0..)
        .map(|i| format!("ub{i}"))
        .find(|x| pg_of(x) == pg)
        .unwrap();
    let put = |m: &mut Mc, tid: u64, name: &str, data: &[u8]| {
        let cl = m.client(0);
        let op = m.op(1, name, vec![OsdOp::writefull(data.to_vec())]);
        m.call(0, cl, tid, op)
    };
    let get = |m: &mut Mc, tid: u64, name: &str| {
        let cl = m.client(0);
        let op = m.op(1, name, vec![OsdOp::read(0, 64)]);
        let r = m.call(0, cl, tid, op);
        assert_eq!(r.len(), 1, "read {name}: {r:?}");
        (r[0].1.result, r[0].1.ops[0].outdata.to_vec())
    };
    let cl = p.a.client(0);
    let op = p.a.op(1, &a, vec![OsdOp::writefull(b"a-v1".to_vec())]);
    assert!(p.a.call(0, cl, 1, op).is_empty());
    p.settle();
    let r = p.a.replies(0, cl);
    assert_eq!((r.len(), r[0].1.result), (1, 0), "a v1 on both");
    // epoch 11: osd.1 crashed and is marked down; osd.0 writes alone
    let mut m = p.map(11, [10, 10]);
    m.osd_state[1] = osd_state::EXISTS;
    m.osd_info[1].down_at = 11;
    p.a.deliver(m.clone());
    p.a.run_for(Duration::from_secs(20)); // the old interval's read lease runs out
    for (tid, name, data) in [(2, &a, b"a-v2"), (3, &b, b"b-v1")] {
        let r = put(&mut p.a, tid, name, data);
        assert_eq!(r.len(), 1, "write {name} alone: {r:?}");
        assert_eq!(r[0].1.result, 0);
    }
    p.b.restart();
    p.acc.retain(|k, _| k.0 != 1);
    p.b.deliver(m);
    // epoch 12: osd.1 back, norecover: it learns the log, not the data
    let mut m = p.map(12, [10, 12]);
    m.flags |= map_flags::NORECOVER;
    m.osd_info[1].down_at = 11;
    p.deliver(m.clone());
    p.run_for(Duration::from_secs(5));
    let spg = SpgT {
        pgid: pg,
        shard: denc::types::ShardId::NO_SHARD,
    };
    let missing = |m: &Mc| m.osds[0].pg.set.pg(spg).unwrap().missing().len();
    assert_eq!(missing(&p.b), 2, "osd.1 misses a and b");
    // epoch 13: osd.0 dies; epoch 14: declared lost, recovery allowed again
    m.epoch = 13;
    m.osd_info[1].up_thru = 13;
    m.osd_state[0] = osd_state::EXISTS;
    m.osd_info[0].down_at = 13;
    p.b.deliver(m.clone());
    p.b.run_for(Duration::from_secs(2));
    m.epoch = 14;
    m.osd_info[1].up_thru = 14;
    m.osd_info[0].lost_at = 14;
    m.flags &= !map_flags::NORECOVER;
    p.b.deliver(m);
    p.b.run_for(Duration::from_secs(20)); // incl. the read lease of the old interval
    let pgid = pg.to_string();
    let (r, d) = ask(&mut p.b, json!({"prefix": "list_unfound", "pgid": pgid}));
    assert_eq!((r, d["num_unfound"].as_u64()), (0, Some(2)), "{d}");
    assert!(
        d["objects"]
            .as_array()
            .unwrap()
            .iter()
            .all(|o| o["locations"] == json!([]))
    );
    let (r, d) = ask(&mut p.b, json!({"prefix": "debug dump_missing"}));
    assert_eq!(r, 0);
    let objs: Vec<&Value> = d
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|x| x.as_array().unwrap())
        .collect();
    assert_eq!(objs.len(), 2, "{d}");
    assert!(
        objs.iter()
            .all(|o| o["unfound"] == true && o["locations"] == json!([])),
        "{d}"
    );
    // reads of unfound objects wait (parked), they are answered after the marking. This test covers that wait path:
    // with the classic default osd_backoff_on_unfound=true the read gets an object-level BLOCK and is dropped (16.6).
    for o in p.b.osds.iter_mut() {
        o.conf
            .set(
                crate::config::Level::Override,
                "osd_backoff_on_unfound",
                "false",
            )
            .expect("valid option value");
        o.conf_changed();
    }
    let cl = p.b.client(0);
    let op = p.b.op(1, &b, vec![OsdOp::read(0, 64)]);
    assert!(
        p.b.call(0, cl, 50, op).is_empty(),
        "read of an unfound object waits"
    );
    let parked = p.b.osds[0]
        .pg
        .eng
        .get(&spg)
        .map(|e| e.dump_state())
        .unwrap_or_default();
    assert!(parked.contains("parked_obj=1"), "{parked}");
    let (r, d) = ask(
        &mut p.b,
        json!({"prefix": "mark_unfound_lost", "pgid": pgid, "mulcmd": "revert"}),
    );
    assert_eq!(r, 0, "{d}");
    assert_eq!(d, "pg has 2 objects unfound and apparently lost marking");
    p.b.run_for(Duration::from_secs(3));
    assert_eq!(missing(&p.b), 0);
    let r = p.b.replies(0, cl);
    assert_eq!(r.len(), 1, "parked read answered");
    assert_eq!(r[0].1.result, -2, "b was deleted");
    assert_eq!(
        get(&mut p.b, 51, &a),
        (0, b"a-v1".to_vec()),
        "a reverted to v1"
    );
    assert_eq!(get(&mut p.b, 52, &b).0, -2);
    let r = put(&mut p.b, 53, &a, b"a-v3");
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].1.result, 0);
    assert_eq!(get(&mut p.b, 54, &a), (0, b"a-v3".to_vec()));
    let (r, d) = ask(&mut p.b, json!({"prefix": "list_unfound", "pgid": pgid}));
    assert_eq!((r, d["num_unfound"].as_u64()), (0, Some(0)), "{d}");
}

/// Shutdown during a bench: the requester gets an answer (the loop stops polling), the scratch objects go; scratch
/// objects a crash left behind are removed at the next start.
#[test]
fn bench_is_cleaned_up_on_shutdown_and_after_a_crash() {
    use crate::meta::MetaStore as _;
    let mut mc = up_with_data();
    let has = |mc: &Mc, k: u64| {
        mc.osds[0]
            .store
            .as_ref()
            .unwrap()
            .read_obj(&format!("bench.{k}"))
            .unwrap()
            .is_some()
    };
    let (tx, rx) = std::sync::mpsc::channel();
    mc.osds[0].cmds.seq += 1;
    let tok = mc.osds[0].cmds.seq;
    mc.osds[0].cmds.pending.insert(tok, tx);
    let cmd = json!({"prefix": "bench", "count": 1 << 20, "size": 4096}).to_string();
    mc.osds[0].exec_command(&cmd, ReplyTo::Asok(tok));
    let t = mc.t;
    assert!(mc.osds[0].poll_store(t) && mc.osds[0].poll_store(t));
    assert!(has(&mc, 0) && has(&mc, 1));
    mc.osds[0].finish_shutdown();
    let (r, rs, _) = rx.try_recv().expect("bench answered at shutdown");
    assert_eq!(r, -4, "{rs}");
    assert!(mc.osds[0].cmds.bench.is_none());
    assert!(!has(&mc, 0) && !has(&mc, 1));
    // a crash in the middle of a bench leaves slots behind: the next start removes them
    let mut mc = up_with_data();
    mc.osds[0]
        .store
        .as_mut()
        .unwrap()
        .bench_put(5, b"x")
        .unwrap();
    assert!(has(&mc, 5));
    mc.restart();
    assert!(!has(&mc, 5));
}

/// `bluestore dedup stats|clear|list` (adr 0593-dedup-deep-scrub-reformat, dedup-collection.md 7): scattered over every core,
/// the fork's output sections and fields, argument errors.
#[test]
fn dedup_commands() {
    let mut mc = up_with_data();
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "bluestore dedup stats", "pool": 1}),
    );
    assert_eq!(r, 0, "{d}");
    assert_eq!(
        d["deduplication stats"],
        json!({"pool": 1, "bytes": 0, "entries": 0})
    );
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "bluestore dedup list", "pool": 1, "shard": 3, "shard_bits": 4}),
    );
    assert_eq!(r, 0, "{d}");
    let l = &d["deduplication list"];
    assert_eq!(
        (&l["pool"], &l["shard"], &l["shard_bits"], &l["completed"]),
        (&json!(1), &json!(3), &json!(4), &json!(true))
    );
    assert_eq!(l["entries"], json!([]));
    assert!(l["next"].is_string());
    assert_eq!(
        ask(
            &mut mc,
            json!({"prefix": "bluestore dedup clear", "pool": 1})
        )
        .0,
        0
    );
    for bad in [
        json!({"prefix": "bluestore dedup stats", "pool": -1}),
        json!({"prefix": "bluestore dedup list", "pool": 1, "shard": 16, "shard_bits": 4}),
        json!({"prefix": "bluestore dedup list", "pool": 1, "shard_bits": 33}),
        json!({"prefix": "bluestore dedup list", "pool": 1, "after": "ABC"}),
        json!({"prefix": "bluestore dedup list", "pool": 1, "max": 0}),
    ] {
        assert_eq!(ask(&mut mc, bad.clone()).0, -22, "{bad}");
    }
}

/// Admin commands (tell and legacy mon command) need an unrestricted `allow *` grant in the parsed caps; a
/// scoped `allow *` (pool, namespace, tag, object_prefix), any non-`*` cap, unparsable or missing caps get
/// EACCES. The grant's network clause does not matter for this check.
#[test]
fn tell_needs_unrestricted_allow_star() {
    use messages::{MCommand, MCommandReply, MMonCommand, MMonCommandAck, Message};

    let mut mc = Mc::new(2);
    mc.up();
    let cl = mc.client(1);
    let cases: &[(Option<&str>, bool)] = &[
        (Some("allow *"), true),
        (Some("allow all"), true),
        (Some("allow r pool=a, allow *"), true),
        (Some("allow * network 10.0.0.0/8"), true),
        (Some("allow * network bogus"), true),
        (Some("allow * pool=images"), false),
        (Some("allow * pool images"), false),
        (Some("allow * namespace=n"), false),
        (Some("allow * object_prefix rbd_data"), false),
        (Some("allow * tag rbd *=*"), false),
        (Some("allow pool=images *"), false),
        (Some("allow rwx"), false),
        (Some("allow rwx pool=a, allow * pool=b"), false),
        (Some("profile rbd"), false),
        (Some("allow r, 'allow *'"), false),
        (Some("allow r # allow *"), false),
        (Some("allow * pool=x; allow all pool=y"), false),
        (Some(""), false),
        (None, false),
    ];
    let mut tid = 500;
    for (caps, want) in cases {
        mc.osds[1]
            .links
            .get_mut(&cl)
            .unwrap()
            .auth
            .borrow_mut()
            .caps = caps.map(str::to_owned);
        for legacy in [false, true] {
            tid += 1;
            let cmd = vec![json!({"prefix": "version"}).to_string()];
            let msg = if legacy {
                MMonCommand {
                    version: 0,
                    fsid: mc.fsid,
                    cmd,
                    data: vec![],
                }
                .into()
            } else {
                MCommand {
                    fsid: mc.fsid,
                    cmd,
                    data: vec![],
                }
                .into()
            };
            mc.osds[1].t.out.clear();
            mc.osds[1].on_link_message(cl, crate::osd::Purpose::Accepted, tid, msg);
            mc.settle();
            let reply = mc.osds[1]
                .t
                .out
                .iter()
                .find(|f| f.0 == cl && f.1 == tid && f.2.0 == if legacy { 51 } else { 98 })
                .expect("command reply");
            let segs = &reply.3;
            let r = if legacy {
                MMonCommandAck::decode(reply.2.1, &segs.front, &segs.middle, &segs.data)
                    .unwrap()
                    .r
            } else {
                MCommandReply::decode(reply.2.1, &segs.front, &segs.middle, &segs.data)
                    .unwrap()
                    .r
            };
            if *want {
                assert_eq!(r, 0, "{caps:?} legacy={legacy}");
            } else {
                assert_eq!(r, -libc::EACCES, "{caps:?} legacy={legacy}");
            }
        }
    }
}

/// `rotate-key` swaps the live mon-client key (bad base64 is -EINVAL); `wipe-rotating-secrets` drops the rotating set
/// and invalidates the tickets. Nothing reaches disk.
#[test]
fn rotate_key_and_wipe_act_on_the_live_session() {
    use cephx::none::{ENTITY_AUTH, ENTITY_OSD};
    let mut mc = up_with_data();
    let stored = mc.osds[0].id.key.clone();
    mc.osds[0].cmds.inbl = b"bad key!".to_vec();
    assert_eq!(mc.osds[0].rotate_live_key().0, -22);
    let k =
        cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, cephx::UTime::new(3, 0)).unwrap();
    mc.osds[0].cmds.inbl = k.to_base64().unwrap().into_bytes();
    assert_eq!(
        mc.osds[0].rotate_live_key().0,
        0,
        "the harness OSD runs cephx"
    );
    assert_eq!(mc.osds[0].id.key, stored, "rotate-key writes nothing");
    let (r, _) = ask(&mut mc, json!({"prefix": "wipe-rotating-secrets"}));
    assert_eq!(r, 0);
    let st = mc.osds[0].mc.with_cephx(|c| {
        (
            c.rotating().secrets.len(),
            c.need_mask(std::time::Duration::from_secs(u64::MAX / 2)) & (ENTITY_AUTH | ENTITY_OSD),
        )
    });
    assert_eq!(st, Some((0, ENTITY_AUTH | ENTITY_OSD)));
    // auth_service_ticket_ttl is a runtime option of the mon client
    let ttl = |mc: &Mc| {
        mc.osds[0]
            .mc
            .with_cephx(cephx::MonAuthClient::service_ticket_ttl)
    };
    assert_eq!(ttl(&mc), Some(3600));
    mc.osds[0]
        .conf
        .set(crate::config::Level::Mon, "auth_service_ticket_ttl", "7200")
        .unwrap();
    mc.osds[0].refresh_obs_conf();
    assert_eq!(ttl(&mc), Some(7200));
}

/// Error text and unknown commands (spec ops-observability 6.10): every errno prints its libc text on the admin socket,
/// and an unregistered prefix answers -EINVAL `unknown command prefix <p>` on both transports.
#[test]
fn errno_text_is_libc_and_unknown_prefix_is_einval() {
    let d = crate::asok::render("{}", (-16, String::new(), crate::tell::Out::default()));
    let text = String::from_utf8_lossy(&d);
    assert!(
        text.starts_with("ERROR: (16) ") && text.ends_with("\n\n"),
        "{text}"
    );
    assert!(!text.contains("Unknown error"), "{text}");
    for (r, text) in [
        (-2, "No such file or directory"),
        (-13, "Permission denied"),
        (-28, "No space left on device"),
        (-4, "Interrupted system call"),
        (-22, "Invalid argument"),
    ] {
        let d = crate::asok::render("{}", (r, String::new(), crate::tell::Out::default()));
        assert_eq!(
            String::from_utf8_lossy(&d),
            format!("ERROR: ({}) {text}\n\n", -r)
        );
    }
    let mut mc = up_with_data();
    let (r, rs, out) = ask_raw(&mut mc, json!({"prefix": "no_such_command"}));
    assert_eq!(
        (r, rs.as_str(), out.is_empty()),
        (-22, "unknown command prefix no_such_command", true)
    );
}

/// `config show` / `config get` cover the whole pinned schema (spec ops-observability 6.6): every option with its
/// effective daemon default, meta-expanded; unknown names are -ENOENT, a missing `var` is -EINVAL.
#[test]
fn config_show_and_get_cover_the_whole_schema() {
    let mut mc = up_with_data();
    let whoami = mc.osds[0].whoami();
    // every schema option + every locally known key (the daemon's own flashstore_* options) + name/cluster
    let mut want: std::collections::BTreeSet<String> =
        crate::schema::names().map(str::to_owned).collect();
    want.extend(mc.osds[0].conf.all().into_keys());
    want.insert("name".into());
    want.insert("cluster".into());
    let (r, d) = ask(&mut mc, json!({"prefix": "config show", "format": "json"}));
    assert_eq!(r, 0);
    assert_eq!(d.as_object().unwrap().len(), want.len(), "{d}");
    assert_eq!(crate::schema::names().count(), 2225);
    assert_eq!(d["name"], format!("osd.{whoami}"));
    assert_eq!(d["cluster"], "ceph");
    // daemon defaults apply although the option was never set
    assert_eq!(
        d["log_file"],
        format!("/var/log/ceph/ceph-osd.{whoami}.log")
    );
    assert_eq!(
        d["admin_socket"],
        format!("/var/run/ceph/ceph-osd.{whoami}.asok")
    );
    assert_eq!(d["log_max_recent"], "10000");
    assert_eq!(d["log_to_stderr"], "true");
    assert_eq!(d["log_to_file"], "false");
    assert_eq!(d["pid_file"], "");
    assert_eq!(d["osd_op_complaint_time"], "30.000000");
    assert_eq!(d["mon_dns_srv_name"], "ceph-mon");
    assert_eq!(d["osd_data"], format!("/var/lib/ceph/osd/ceph-{whoami}"));
    assert_eq!(d["log_to_syslog"], "false");
    assert_eq!(d["log_to_journald"], "false");
    assert_eq!(d["log_to_graylog"], "false");
    for (name, want) in [
        ("log_max_recent", "10000"),
        ("osd_op_complaint_time", "30.000000"),
        ("mon_dns_srv_name", "ceph-mon"),
    ] {
        let (r, d) = ask(&mut mc, json!({"prefix": "config get", "var": name}));
        assert_eq!(r, 0, "{name}");
        assert_eq!(d[name], want, "{name}");
    }
    let (r, rs, _) = ask_raw(
        &mut mc,
        json!({"prefix": "config get", "var": "no_such_option"}),
    );
    assert_eq!(r, -2);
    assert_eq!(
        rs,
        "error getting 'no_such_option': (2) No such file or directory"
    );
    let (r, ..) = ask(&mut mc, json!({"prefix": "config get"}));
    assert_eq!(r, -22);
    // a locally set option appears in show, get and diff
    let (r, ..) = ask(
        &mut mc,
        json!({"prefix": "config set", "var": "osd_max_backfills", "val": "7"}),
    );
    assert_eq!(r, 0);
    let (_, d) = ask(
        &mut mc,
        json!({"prefix": "config get", "var": "osd_max_backfills"}),
    );
    assert_eq!(d["osd_max_backfills"], "7");
    let (_, d) = ask(&mut mc, json!({"prefix": "config diff"}));
    assert_eq!(d["diff"]["osd_max_backfills"]["default"], 1);
    assert_eq!(d["diff"]["osd_max_backfills"]["override"], 7);
    assert_eq!(d["diff"]["osd_max_backfills"]["final"], 7);
}

/// `pg <pgid> log` (spec osd-tell-gaps.md 5): registered as `pg ... cmd=log` and as the bare `log` prefix (distinct
/// from `log dump|flush|reopen`), answered by the PG's owner core with the classic `pg_log_t` document, -ENOENT for a
/// PG this OSD does not have.
#[test]
fn pg_log_dump_answers_the_classic_document() {
    let mut mc = up_with_data();
    // the PG that holds one of the written objects (its log is not empty)
    let pg = mc
        .op(1, "t0", vec![OsdOp::read(0, 1)])
        .pgid
        .pgid
        .to_string();
    let (r, d) = ask(&mut mc, json!({"prefix": "pg", "pgid": pg, "cmd": "log"}));
    assert_eq!(r, 0, "{d}");
    let l = &d["pg_log_t"];
    assert!(l.is_object(), "{d}");
    assert!(l["head"].as_str().unwrap().contains('\''), "{d}");
    assert!(l["tail"].as_str().unwrap().contains('\''), "{d}");
    let entries = l["log"].as_array().unwrap();
    assert!(!entries.is_empty(), "{l}");
    // array elements are bare objects (the reference's `entry` section name is dropped inside an array)
    let e = &entries[0];
    assert!(e.get("entry").is_none(), "{e}");
    assert!(e["op"].is_string(), "{e}");
    assert_eq!(e["object"].as_str().unwrap().split(':').count(), 6, "{e}");
    assert!(e["version"].as_str().unwrap().contains('\''), "{e}");
    assert!(e["prior_version"].as_str().unwrap().contains('\''), "{e}");
    assert!(e["reqid"].as_str().unwrap().starts_with("client."), "{e}");
    assert!(e["extra_reqids"].is_array(), "{e}");
    assert!(e["mtime"].as_str().unwrap().contains('T'), "{e}");
    assert!(e["return_code"].is_i64(), "{e}");
    assert!(
        e["written_shards"].as_str().unwrap().starts_with('['),
        "{e}"
    );
    assert!(e["mod_desc"]["object_mod_desc"].is_object(), "{e}");
    assert!(e["mod_desc"]["object_mod_desc"]["can_local_rollback"].is_boolean());
    assert!(e["mod_desc"]["object_mod_desc"]["ops"].is_array());
    assert!(
        e["clean_regions"]["object_clean_regions"]["clean_offsets"]
            .as_str()
            .unwrap()
            .starts_with('[')
    );
    assert!(l["dups"].is_array(), "{l}");
    // the bare classic prefix with a pgid answers the same document
    let (r2, d2) = ask(&mut mc, json!({"prefix": "log", "pgid": pg}));
    assert_eq!(r2, 0, "{d2}");
    assert_eq!(d2["pg_log_t"]["head"], l["head"]);
    // an OSD without that PG says so
    let (r3, rs, _) = ask_raw(
        &mut mc,
        json!({"prefix": "pg", "pgid": "999.0", "cmd": "log"}),
    );
    assert_eq!(r3, -2);
    assert_eq!(rs, "i don't have pgid 999.0");
    // the log family stays distinct from the bare prefix
    let (r4, ..) = ask(&mut mc, json!({"prefix": "log dump"}));
    assert_eq!(r4, 0);
}

/// Hostile `bluestore dedup list` arguments: a non-ASCII cursor is invalid hex like any other (a `str` slice on the byte
/// grid used to panic on a multi-byte character and take the OSD down), and an age that does not fit the nanosecond
/// multiply saturates instead of overflowing.
#[test]
fn dedup_list_rejects_a_non_ascii_cursor_and_saturates_huge_ages() {
    let mut mc = up_with_data();
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "bluestore dedup list", "pool": 1, "after": "a€"}),
    );
    assert_eq!(r, -22, "{d}");
    assert_eq!(d.as_str().unwrap(), "Invalid cursor:a€");
    for key in ["newer_than", "prune_older_than"] {
        let mut cmd = json!({"prefix": "bluestore dedup list", "pool": 1});
        cmd[key] = json!(99999999999999i64);
        let (r, d) = ask(&mut mc, cmd.clone());
        assert_eq!(r, 0, "{cmd}: {d}");
        assert_eq!(d["deduplication list"]["entries"], json!([]), "{cmd}");
    }
}

/// `dump_osd_network value=<ms>`: a huge client value saturates the µs threshold instead of overflowing it.
#[test]
fn dump_osd_network_saturates_a_huge_threshold() {
    let mut mc = up_with_data();
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "dump_osd_network", "value": i64::MAX}),
    );
    assert_eq!(r, 0, "{d}");
    assert_eq!(d["entries"], json!([]), "{d}");
}

/// `osd_op_history_duration` is seconds and is multiplied to ns: a value an operator (or `mon config set`) can write
/// saturates there and in the history window, it does not overflow a debug build.
#[test]
fn a_huge_history_duration_does_not_overflow() {
    let mut mc = up_with_data();
    let cmd =
        json!({"prefix": "config set", "var": "osd_op_history_duration", "val": "99999999999"});
    let (r, d) = ask(&mut mc, cmd.clone());
    assert_eq!(r, 0, "{cmd}: {d}");
    let (r, d) = ask(&mut mc, json!({"prefix": "dump_historic_ops"}));
    assert_eq!(r, 0, "{d}");
    assert!(!d["ops"].as_array().unwrap().is_empty(), "{d}");
}

/// A bench write the device fails answers the store error, not `EOPNOTSUPP` ("not supported") that only the missing
/// store on a worker core means.
#[test]
fn a_failed_bench_write_reports_the_store_error() {
    let mut mc = up_with_data();
    // every write fails with a media error
    mc.disk.fail_writes(0, 1 << 40);
    let (tx, rx) = std::sync::mpsc::channel();
    mc.osds[0].cmds.seq += 1;
    let tok = mc.osds[0].cmds.seq;
    mc.osds[0].cmds.pending.insert(tok, tx);
    let t = mc.t;
    mc.osds[0].set_now(t);
    let cmd = json!({"prefix": "bench", "count": 1, "size": 4096});
    assert!(
        mc.osds[0].start_bench(&cmd, &ReplyTo::Asok(tok)).is_none(),
        "accepted"
    );
    assert!(
        mc.osds[0].poll_bench(),
        "the write failed, the answer follows"
    );
    let (r, rs, _) = rx.try_recv().expect("bench answered");
    assert_eq!(r, -denc::errno::EIO, "{rs}");
}

/// A keyring write that fails changes nothing: the device copy stays on the key the mon knows, and so does the running
/// identity. (The keyring wins at the next start, so it is written before the device copy.)
#[test]
fn a_failed_keyring_write_leaves_the_stored_key_alone() {
    use crate::meta::MetaStore as _;
    let mut mc = up_with_data();
    let dir = std::env::temp_dir().join(format!(
        "croit-flashstore-rotate-fail-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    mc.osds[0]
        .conf
        .set(
            crate::config::Level::Override,
            "osd_data",
            dir.to_str().unwrap(),
        )
        .unwrap();
    let old = "[osd.0]\n\tkey = OLD\n";
    std::fs::write(dir.join("keyring"), old).unwrap();
    // `write_atomic_mode` writes `<path>.tmp` first: a directory planted there makes the keyring write fail
    std::fs::create_dir(dir.join("keyring.tmp")).unwrap();
    let device = mc.osds[0]
        .store
        .as_ref()
        .unwrap()
        .load_identity()
        .unwrap()
        .unwrap()
        .key;
    let key = cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, cephx::UTime::new(2, 0))
        .unwrap()
        .to_base64()
        .unwrap();
    mc.osds[0].cmds.inbl = key.into_bytes();
    let (r, rs, _) = mc.osds[0].rotate_stored_key();
    assert_eq!(r, -5, "{rs}");
    assert_eq!(
        mc.osds[0]
            .store
            .as_ref()
            .unwrap()
            .load_identity()
            .unwrap()
            .unwrap()
            .key,
        device,
        "the device key is untouched"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("keyring")).unwrap(),
        old,
        "the keyring is untouched"
    );
    assert_eq!(
        mc.osds[0].id.key, device,
        "the running identity is untouched"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

thread_local! {
    /// [`hold_first_dump_pgs_part`]: the first `dump_pgs` part was held back.
    static HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// `delay` hook: the first `dump_pgs` part reply waits until [`deliver_delayed`], so the parts reach the control core in
/// an order that is not the core order.
fn hold_first_dump_pgs_part(_dst: usize, m: &XMsg) -> bool {
    matches!(m, XMsg::QueryReply { r: 0, out, .. } if out.get("pgs").is_some())
        && HELD.with(|h| !h.replace(true))
}

/// `dump_pgs` carries the core that owns each PG, not the index of its part in the merged reply (the parts arrive in
/// reply order, which is not core order).
#[test]
fn dump_pgs_labels_every_pg_with_its_owning_core() {
    let mut mc = up_with_data();
    let mut owner = std::collections::HashMap::new();
    for c in 0..mc.n {
        for (s, _) in mc.osds[c].pg.set.pgs() {
            owner.insert(s.pgid.to_string(), c);
        }
    }
    assert!(
        owner.values().any(|&c| c != 0),
        "a PG must live off core 0 for the test to mean anything: {owner:?}"
    );
    HELD.with(|h| h.set(false));
    mc.delay = Some(hold_first_dump_pgs_part);
    let (tx, rx) = std::sync::mpsc::channel();
    mc.osds[0].cmds.seq += 1;
    let tok = mc.osds[0].cmds.seq;
    mc.osds[0].cmds.pending.insert(tok, tx);
    let t = mc.t;
    mc.osds[0].set_now(t);
    mc.osds[0].exec_command(
        &json!({"prefix": "dump_pgs"}).to_string(),
        ReplyTo::Asok(tok),
    );
    mc.settle();
    deliver_delayed(&mut mc);
    let (r, _, out) = rx.try_recv().expect("dump_pgs answered");
    assert_eq!(r, 0);
    let d: Value = serde_json::from_slice(&out.into_bytes()).unwrap();
    let pgs = d["pgs"].as_array().unwrap();
    assert_eq!(pgs.len(), owner.len());
    for pg in pgs {
        let pgid = pg["pgid"].as_str().unwrap();
        assert_eq!(
            pg["core"].as_u64(),
            owner.get(pgid).map(|c| *c as u64),
            "{pgid}: {pg}"
        );
    }
}

/// A scattered part that answers `PENDING` (its core delivers the part later) stays under the loud timeout: a core that
/// makes no progress answers `-ETIMEDOUT` for the whole command instead of hanging it silently.
#[test]
fn a_late_scattered_part_logs_the_timeout_and_times_out() {
    let mut mc = Mc::new(2);
    mc.up();
    // nobody beats: the core that owes the late part makes no progress the whole time
    let live: &'static crate::liveness::Liveness =
        Box::leak(Box::new(crate::liveness::Liveness::new()));
    mc.osds[0].set_liveness(live);
    // the worker's part answers PENDING; its real part never arrives (the whole `scrub_purged_snaps` walk reply is lost)
    mc.lose = Some(|_, m| matches!(m, XMsg::QueryReply { r: 0, .. }));
    let (tx, rx) = std::sync::mpsc::channel();
    mc.osds[0].cmds.seq += 1;
    let tok = mc.osds[0].cmds.seq;
    mc.osds[0].cmds.pending.insert(tok, tx);
    let t = mc.t;
    mc.osds[0].set_now(t);
    mc.osds[0].exec_command(
        &json!({"prefix": "scrub_purged_snaps"}).to_string(),
        ReplyTo::Asok(tok),
    );
    mc.settle();
    assert!(
        rx.try_recv().is_err(),
        "the lost part keeps the command open"
    );
    // past the 5 s scatter deadline, before `osd_op_thread_timeout` (15 s)
    mc.run_for(Duration::from_secs(6));
    let logs: Vec<String> = std::iter::from_fn(|| mc.osds[0].poll_log().map(|l| l.text)).collect();
    assert!(
        logs.iter().any(|l| l
            == "WARNING TIMEOUT scattered command exceeded 5.000s (command \"scrub_purged_snaps\": cores {1} did not answer yet, waiting)"),
        "{logs:?}"
    );
    assert!(
        rx.try_recv().is_err(),
        "still waiting while the owner lives"
    );
    mc.run_for(Duration::from_secs(11));
    let (r, rs, _) = rx
        .try_recv()
        .expect("answered once the owner made no progress");
    assert_eq!(r, -denc::errno::ETIMEDOUT, "{rs}");
    assert!(rs.contains("did not answer"), "{rs}");
}

/// A core that beats once and then stalls is fails the scatter once it was silent for `osd_op_thread_timeout`: the
/// command answers `-ETIMEDOUT` with the loud line instead of waiting forever.
#[test]
fn a_core_that_beats_once_and_then_stalls_fails_the_scatter() {
    let mut mc = Mc::new(2);
    mc.up();
    let live: &'static crate::liveness::Liveness =
        Box::leak(Box::new(crate::liveness::Liveness::new()));
    mc.osds[0].set_liveness(live);
    let (tx, rx) = std::sync::mpsc::channel();
    mc.osds[0].cmds.seq += 1;
    let id = mc.osds[0].cmds.seq;
    mc.osds[0].cmds.pending.insert(id, tx);
    mc.osds[0].cmds.scatter.insert(
        id,
        crate::tell::Scatter::pending(
            ReplyTo::Asok(id),
            json!({"prefix": "scrub_purged_snaps"}),
            [1usize].into(),
            mc.t,
            vec![0, 0],
        ),
    );
    // one beat after the start, then nothing
    live.beat(1);
    for _ in 0..30 {
        mc.t += Duration::from_secs(1);
        let t = mc.t;
        mc.osds[0].set_now(t);
        mc.osds[0].scatter_expire();
    }
    let (r, rs, _) = rx.try_recv().expect("answered once the core stalled");
    assert_eq!(r, -denc::errno::ETIMEDOUT, "{rs}");
    let logs: Vec<String> = std::iter::from_fn(|| mc.osds[0].poll_log().map(|l| l.text)).collect();
    assert!(
        logs.iter().any(|l| l.starts_with(
            "WARNING TIMEOUT scattered command exceeded 5.000s (command \"scrub_purged_snaps\": cores [1] made no progress"
        )),
        "{logs:?}"
    );
}

/// A core silent for longer than the scatter wait but shorter than `osd_op_thread_timeout` is still waited for: once it
/// beats and answers, the command succeeds.
#[test]
fn a_core_silent_below_the_limit_still_answers_the_scatter() {
    let mut mc = Mc::new(2);
    mc.up();
    let live: &'static crate::liveness::Liveness =
        Box::leak(Box::new(crate::liveness::Liveness::new()));
    mc.osds[0].set_liveness(live);
    let (tx, rx) = std::sync::mpsc::channel();
    mc.osds[0].cmds.seq += 1;
    let tok = mc.osds[0].cmds.seq;
    mc.osds[0].cmds.pending.insert(tok, tx);
    let t = mc.t;
    mc.osds[0].set_now(t);
    mc.osds[0].exec_command(r#"{"prefix":"dump_ops_in_flight"}"#, ReplyTo::Asok(tok));
    let tick = |mc: &mut Mc, secs: u64| {
        for _ in 0..secs {
            mc.t += Duration::from_secs(1);
            let t = mc.t;
            mc.osds[0].set_now(t);
            mc.osds[0].scatter_expire();
        }
    };
    // core 1 stays silent past the 5 s scatter wait, then beats late in the command's life (> 15 s old)
    tick(&mut mc, 14);
    live.beat(1);
    tick(&mut mc, 8);
    assert!(rx.try_recv().is_err(), "a core silent for 8 s is not gone");
    mc.settle();
    let (r, rs, _) = rx.try_recv().expect("answered once the core replied");
    assert_eq!(r, 0, "{rs}");
}

/// A deferred `mark_unfound_lost` whose PG goes away before the marking commits answers `-EAGAIN`: no owner is left to
/// answer it, and the command used to wait forever.
#[test]
fn a_lost_marking_answers_when_its_pg_is_removed() {
    let mut mc = Mc::new(2);
    mc.up();
    let spg = SpgT {
        pgid: PgT::new(1, 0),
        shard: denc::types::ShardId::NO_SHARD,
    };
    let (tx, rx) = std::sync::mpsc::channel();
    mc.osds[0].cmds.seq += 1;
    let id = mc.osds[0].cmds.seq;
    let tok = mc.osds[0].cmds.seq;
    mc.osds[0].cmds.pending.insert(tok, tx);
    let cmd = json!({"prefix": "mark_unfound_lost", "pgid": spg.to_string(), "mulcmd": "revert"});
    // the state of a marking whose parts answered and whose PG answers later (DEFERRED)
    mc.osds[0].cmds.scatter.insert(
        id,
        crate::tell::Scatter::pending(
            ReplyTo::Asok(tok),
            cmd,
            Default::default(),
            mc.t,
            vec![0, 0],
        ),
    );
    mc.osds[0].cmds.lost_wait.insert((spg, 7), (0, id));
    mc.osds[0].pg_exec(vec![peering::Action::PgRemoved { spg }]);
    mc.settle();
    let (r, rs, _) = rx.try_recv().expect("the abandoned marking answered");
    assert_eq!(r, -denc::errno::EAGAIN, "{rs}");
    assert!(
        rs.contains("was removed before the lost marking answered"),
        "{rs}"
    );
    assert!(mc.osds[0].cmds.lost_wait.is_empty(), "the waiter is gone");
}

/// A periodic command the OSD starts itself (`ReplyTo::Internal`) has nobody to receive its error: it is logged, so a
/// failing purged-snaps scrub stamp is visible instead of silently retried.
#[test]
fn a_failed_periodic_command_is_logged() {
    let mut mc = Mc::new(2);
    mc.up();
    mc.osds[0].finish_cmd(
        ReplyTo::Internal,
        (
            -denc::errno::EIO,
            "Error writing superblock: device gone".into(),
            crate::tell::Out::default(),
        ),
    );
    let logs: Vec<String> = std::iter::from_fn(|| mc.osds[0].poll_log().map(|l| l.text)).collect();
    assert!(
        logs.iter()
            .any(|l| l
                == "WARNING internal command failed (-5): Error writing superblock: device gone"),
        "{logs:?}"
    );
}

/// `config set` / `injectargs` (spec osd-lifecycle.md 9.2): no always-written log line carries a value; the runtime
/// rule comes from the option's schema flags plus the daemon's observers — a startup option no observer tracks (`key`,
/// `keyfile`) and an unobserved `str` option are refused with `-EPERM` (also at its own value), an observed option and
/// a number-like one are accepted, and the value an option already has is a no-op success.
#[test]
fn config_values_never_reach_the_log_and_unobserved_immutable_options_are_refused() {
    let mut mc = up_with_data();
    let drain = |mc: &mut Mc| -> Vec<String> {
        std::iter::from_fn(|| mc.osds[0].poll_log().map(|l| l.text)).collect()
    };
    drain(&mut mc);
    let secret = "AQBsecretsecretsecret==";
    let (r, rs, out) = ask_raw(
        &mut mc,
        json!({"prefix": "config set", "var": "key", "val": secret}),
    );
    assert_eq!(r, -denc::errno::EPERM, "{rs}");
    assert_eq!(
        rs,
        format!("error setting 'key' to '{secret}': (1) Operation not permitted")
    );
    assert!(out.is_empty(), "an error reply has an empty body");
    let (r, rs, _) = ask_raw(
        &mut mc,
        json!({"prefix": "config set", "var": "keyfile", "val": "/etc/ceph/other.key"}),
    );
    assert_eq!(r, -denc::errno::EPERM, "{rs}");
    assert!(rs.ends_with("Operation not permitted"), "{rs}");
    // the value the option already has (the daemon's own key source) is a no-op success
    mc.osds[0]
        .conf
        .set(crate::config::Level::File, "key", "AQBownkey==")
        .unwrap();
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "config set", "var": "key", "val": "AQBownkey=="}),
    );
    assert_eq!((r, d), (0, json!({"success": ""})), "same value is a no-op");
    // a `str` option without the runtime flag and without an observer is refused (not only startup options)
    let (r, rs, _) = ask_raw(
        &mut mc,
        json!({"prefix": "config set", "var": "bluestore_allocator", "val": "bitmap"}),
    );
    assert_eq!(r, -denc::errno::EPERM, "{rs}");
    assert_eq!(
        rs,
        "error setting 'bluestore_allocator' to 'bitmap': (1) Operation not permitted"
    );
    // an observed option is accepted although its flags alone would refuse it (`ms_cluster_mode` is `str` + startup,
    // the auth observer re-reads it for new sessions)
    let schema = crate::optval::schema("ms_cluster_mode").unwrap();
    assert!(!schema.runtime_changeable() && crate::osd::Osd::<B>::observed("ms_cluster_mode"));
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "config set", "var": "ms_cluster_mode", "val": "secure"}),
    );
    assert_eq!((r, d), (0, json!({"success": ""})));
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "config get", "var": "ms_cluster_mode"}),
    );
    assert_eq!((r, d["ms_cluster_mode"].as_str()), (0, Some("secure")));
    // number-like options change without an observer: with the runtime flag (`osd_max_backfills`) and without it
    // (`osd_op_history_size` is `uint` only)
    for (k, v) in [("osd_max_backfills", "7"), ("osd_op_history_size", "42")] {
        let (r, d) = ask(&mut mc, json!({"prefix": "config set", "var": k, "val": v}));
        assert_eq!((r, d), (0, json!({"success": ""})), "{k}");
        assert_eq!(mc.osds[0].conf.get(k), Some(v), "{k}");
    }
    // injectargs refuses an immutable token with classic's shape and keeps the tokens before it
    let (r, rs, _) = ask_raw(
        &mut mc,
        json!({"prefix": "injectargs", "injected_args": ["--osd_recovery_max_active=4", "--key=AQBothersecret=="]}),
    );
    assert_eq!(r, -denc::errno::EPERM, "{rs}");
    assert_eq!(
        rs,
        "Parse error setting key to 'AQBothersecret==' using injectargs (Configuration option 'key' may not be \
         modified at runtime).\n"
    );
    assert_eq!(mc.osds[0].conf.u64("osd_recovery_max_active", 0), 4);
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "injectargs", "injected_args": ["--osd_scrub_min_interval=86400"]}),
    );
    assert_eq!((r, d), (0, json!({})), "a number-like token applies");
    let logs = drain(&mut mc);
    for l in &logs {
        assert!(!l.contains("AQB"), "{l}");
        assert!(!l.contains("osd_max_backfills"), "{l}");
        assert!(!l.contains("osd_op_history_size"), "{l}");
        assert!(!l.contains("osd_recovery_max_active"), "{l}");
    }
    assert_eq!(mc.osds[0].conf.get("key"), Some("AQBownkey=="));
}

/// The observer registry is the daemon's real "tracked by an observer" property (spec osd-lifecycle.md 9.2): every key
/// an observer declares is an option the daemon knows (a renamed option would otherwise silently drop out of the
/// runtime-change rule), and the startup key sources are not tracked.
#[test]
fn observer_registry_names_known_options_and_skips_the_key_sources() {
    use crate::config::KeyClass;
    for k in crate::osd::Osd::<B>::observed_keys() {
        assert_ne!(
            crate::config::classify(k),
            KeyClass::Unknown,
            "observer key '{k}' is no known option"
        );
    }
    for k in [
        "key",
        "keyfile",
        "keyring",
        "admin_socket",
        "bluestore_allocator",
    ] {
        assert!(!crate::osd::Osd::<B>::observed(k), "{k} is not tracked");
    }
    for k in [
        "ms_cluster_mode",
        "debug_osd",
        "osd_class_load_list",
        "osd_memory_target",
        "osd_max_backfills",
    ] {
        assert!(crate::osd::Osd::<B>::observed(k), "{k} is tracked");
    }
}

/// `config unset` (spec osd-lifecycle.md 9.3): an unknown name is `-EINVAL` with the classic text and an empty body, a
/// known name without an override is a no-op success (`{}`, no change pass), and only a real override drop runs it.
#[test]
fn config_unset_unknown_name_is_invalid_and_an_empty_unset_is_a_no_op() {
    let mut mc = up_with_data();
    let (r, rs, out) = ask_raw(
        &mut mc,
        json!({"prefix": "config unset", "var": "no_such_option"}),
    );
    assert_eq!(r, -denc::errno::EINVAL, "{rs}");
    assert_eq!(
        rs,
        "error unsetting 'no_such_option': (22) Invalid argument"
    );
    assert!(out.is_empty(), "an error reply has an empty body");
    // unlike `config set` there is no whitespace normalization
    let (r, rs, _) = ask_raw(
        &mut mc,
        json!({"prefix": "config unset", "var": "osd max backfills"}),
    );
    assert_eq!(r, -denc::errno::EINVAL, "{rs}");
    assert_eq!(
        rs,
        "error unsetting 'osd max backfills': (22) Invalid argument"
    );
    // known name without an override: nothing changes and the change pass does not run
    let version = mc.osds[0].conf.version();
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "config unset", "var": "osd_max_backfills"}),
    );
    assert_eq!((r, d), (0, json!({})));
    assert_eq!(mc.osds[0].conf.version(), version);
    // with an override: it is dropped and the layer below takes effect again
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "config set", "var": "osd_max_backfills", "val": "7"}),
    );
    assert_eq!(r, 0, "{d}");
    assert_eq!(mc.osds[0].conf.get("osd_max_backfills"), Some("7"));
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "config unset", "var": "osd_max_backfills"}),
    );
    assert_eq!((r, d), (0, json!({})));
    assert_eq!(mc.osds[0].conf.get("osd_max_backfills"), Some("1"));
}

/// `bench` (spec osd-lifecycle.md 9.4): `osd_bench_duration` never caps the run, it bounds the accepted `count`; the
/// precheck texts are verbatim, `object_size` overrides a larger `size`, and the body is the bare result object.
#[test]
fn bench_duration_bounds_the_count_not_the_wall_clock() {
    let mut mc = up_with_data();
    // 4 KiB at 100 IOPS for 30 s allows 12 288 000 bytes
    let (r, rs, _) = ask_raw(
        &mut mc,
        json!({"prefix": "bench", "count": 12_288_001, "size": 4096}),
    );
    assert_eq!(r, -denc::errno::EINVAL, "{rs}");
    assert_eq!(
        rs,
        "'count' values greater than 12288000 for a block size of 4096, assuming 100 IOPS, for 30 seconds, can cause ill effects on osd.  Please adjust 'osd_bench_small_size_max_iops' with a higher value if you wish to use a higher 'count'."
    );
    // a larger block: 100 MiB/s for 30 s
    let (r, rs, _) = ask_raw(
        &mut mc,
        json!({"prefix": "bench", "count": 3_145_728_001u64, "size": 1 << 20}),
    );
    assert_eq!(r, -denc::errno::EINVAL, "{rs}");
    assert_eq!(
        rs,
        "'count' values greater than 3145728000 for a block size of 1048576, assuming 100 MiB/s, for 30 seconds, can cause ill effects on osd.  Please adjust 'osd_bench_large_size_max_throughput' with a higher value if you wish to use a higher 'count'."
    );
    // the block size cap names the option's value in the byte_u_t shape
    let (r, rs, _) = ask_raw(
        &mut mc,
        json!({"prefix": "bench", "count": 1 << 20, "size": (64 << 20) + 1}),
    );
    assert_eq!(r, -denc::errno::EINVAL, "{rs}");
    assert_eq!(
        rs,
        "block 'size' values are capped at 64 MiB. If you wish to use a higher value, please adjust 'osd_bench_max_block_size'"
    );
    let (r, rs, _) = ask_raw(&mut mc, json!({"prefix": "bench", "size": 0}));
    assert_eq!(
        (r, rs.as_str()),
        (
            -denc::errno::EINVAL,
            "block size and/or count of Bytes to write not specified"
        )
    );
    // a run writes exactly `count` bytes, reported under the body root
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "bench", "count": 1 << 20, "size": 65536}),
    );
    assert_eq!(r, 0, "{d}");
    assert_eq!(d["bytes_written"], 1 << 20, "{d}");
    assert_eq!(d["blocksize"], 65536, "{d}");
    assert!(d["elapsed_sec"].as_f64().unwrap() > 0.0, "{d}");
    assert!(d["bytes_per_sec"].as_f64().unwrap() > 0.0, "{d}");
    // `object_size` smaller than `size` overrides the block size, with the classic log line
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "bench", "count": 1 << 20, "size": 1 << 20, "object_size": 65536}),
    );
    assert_eq!(r, 0, "{d}");
    assert_eq!(d["blocksize"], 65536, "{d}");
    let logs: Vec<String> = std::iter::from_fn(|| mc.osds[0].poll_log().map(|l| l.text)).collect();
    assert!(
        logs.iter().any(|l| l
            == "OSDBenchTest::precheck: bsize: 1048576 is greater than osize: 65536. Running test by overriding bsize to 65536."),
        "{logs:?}"
    );
    // a fractional duration never reaches the bench: the option type is uint
    let (r, rs, _) = ask_raw(
        &mut mc,
        json!({"prefix": "config set", "var": "osd_bench_duration", "val": "0.5"}),
    );
    assert_eq!(r, -denc::errno::EINVAL, "{rs}");
    assert_eq!(
        rs,
        "error setting 'osd_bench_duration' to '0.5': (22) Invalid argument"
    );
    // a duration of 0 accepts no positive count
    let (r, _) = ask(
        &mut mc,
        json!({"prefix": "config set", "var": "osd_bench_duration", "val": "0"}),
    );
    assert_eq!(r, 0);
    let (r, rs, _) = ask_raw(
        &mut mc,
        json!({"prefix": "bench", "count": 4096, "size": 4096}),
    );
    assert_eq!(r, -denc::errno::EINVAL, "{rs}");
    assert!(
        rs.starts_with("'count' values greater than 0 for a block size of 4096"),
        "{rs}"
    );
    // 12 s is used as given: a count above the 10 s bound of a clamp is accepted
    let (r, _) = ask(
        &mut mc,
        json!({"prefix": "config set", "var": "osd_bench_duration", "val": "12"}),
    );
    assert_eq!(r, 0);
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "bench", "count": 4096 * 11 * 100, "size": 4096}),
    );
    assert_eq!(r, 0, "{d}");
    assert_eq!(d["bytes_written"], 4096 * 11 * 100);
}

/// `help` keeps one text per command: two signatures share the words `pg`, and the second (empty) one used to erase the
/// first.
#[test]
fn help_keeps_a_text_for_a_shared_command() {
    let mut mc = Mc::new(2);
    mc.up();
    let (r, d) = ask(&mut mc, json!({"prefix": "help"}));
    assert_eq!(r, 0, "{d}");
    assert_eq!(d["pg"], json!("show details of a specific pg"), "{d}");
    assert_eq!(d["log"], json!("dump pg_log of a specific pg"), "{d}");
}

#[test]
fn tell_rejects_invalid_arguments_before_dispatch() {
    let mut mc = Mc::new(1);
    for cmd in [
        json!({"prefix": "bench", "count": "4096"}),
        json!({"prefix": "bench", "count": u64::MAX}),
        json!({"prefix": "bench", "size": false}),
        json!({"prefix": "bench", "object_num": 1.5}),
        json!({"prefix": "scrub", "pgid": 5}),
        json!({"prefix": "config set", "var": "debug_osd", "val": 5}),
        json!({"prefix": "injectargs", "injected_args": [7]}),
        json!({"prefix": "config get"}),
        json!({"prefix": "heap"}),
        json!({"prefix": "pg", "pgid": "1.0"}),
    ] {
        let (r, rs, out) = ask_raw(&mut mc, cmd.clone());
        assert_eq!((r, rs.as_str()), (-22, "invalid command json"), "{cmd}");
        assert!(out.is_empty(), "{cmd}");
        assert!(mc.osds[0].cmds.bench.is_none(), "{cmd}");
    }
}

#[test]
fn modern_and_legacy_tell_forward_key_rotation_input() {
    use messages::{MCommand, MCommandReply, MMonCommand, MMonCommandAck, Message};
    let mut mc = up_with_data();
    let cl = mc.client(2);
    mc.osds[2]
        .links
        .get_mut(&cl)
        .unwrap()
        .auth
        .borrow_mut()
        .caps = Some("allow *".into());
    for legacy in [false, true] {
        let key = cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, cephx::UTime::new(3, 0))
            .unwrap();
        let data = key.to_base64().unwrap().into_bytes();
        let cmd = vec![json!({"prefix": "rotate-key"}).to_string()];
        let message = if legacy {
            MMonCommand {
                version: 0,
                fsid: mc.fsid,
                cmd,
                data,
            }
            .into()
        } else {
            MCommand {
                fsid: mc.fsid,
                cmd,
                data,
            }
            .into()
        };
        mc.osds[2].t.out.clear();
        mc.osds[2].on_link_message(cl, crate::osd::Purpose::Accepted, 123, message);
        mc.settle();
        let reply = mc.osds[2]
            .t
            .out
            .iter()
            .find(|f| f.0 == cl && f.1 == 123 && f.2.0 == if legacy { 51 } else { 98 })
            .unwrap();
        let segs = &reply.3;
        let r = if legacy {
            MMonCommandAck::decode(reply.2.1, &segs.front, &segs.middle, &segs.data)
                .unwrap()
                .r
        } else {
            MCommandReply::decode(reply.2.1, &segs.front, &segs.middle, &segs.data)
                .unwrap()
                .r
        };
        assert_eq!(r, 0, "legacy={legacy}");
        assert!(mc.osds.iter().all(|o| o.cmds.inbl.is_empty()));
    }
}

#[test]
fn objecter_requests_is_described_and_reports_no_internal_objecter() {
    let mut mc = Mc::new(1);
    let (r, result) = ask(&mut mc, json!({"prefix": "objecter_requests"}));
    assert_eq!(r, 0, "{result}");
    assert_eq!(
        result,
        json!({"ops": [], "linger_ops": [], "pool_ops": [],
        "pool_stat_ops": [], "statfs_ops": [], "command_ops": []})
    );
    let (r, help) = ask(&mut mc, json!({"prefix": "help"}));
    assert_eq!(r, 0);
    assert!(help.get("objecter_requests").is_some());
}

/// NT-deadcode-01..04 (doc/reviews/2026-11-08-nt-deadcode.md): runtime values of the honoured options reach every core
/// (map share window, backfill scan bounds, map cache); a no-effect option is accepted, reported and logged once as a
/// WARNING (control core only); a startup-only no-effect option is still refused at runtime like classic.
#[test]
fn honoured_options_reach_every_core_and_no_effect_options_warn() {
    let mut mc = Mc::new(2);
    mc.up();
    for (k, v) in [
        ("osd_map_share_max_epochs", "10"),
        ("osd_backfill_scan_min", "8"),
        ("osd_backfill_scan_max", "16"),
        ("osd_map_cache_size", "70"),
        ("osd_deep_scrub_stride", "8388608"),
        ("osd_deep_scrub_keys", "256"),
    ] {
        let (r, d) = ask(&mut mc, json!({"prefix": "config set", "var": k, "val": v}));
        assert_eq!((r, d), (0, json!({"success": ""})), "{k}");
    }
    for o in &mc.osds {
        assert_eq!(o.pg.map_share, 10);
        let c = o.pg.set.config();
        assert_eq!(
            (c.backfill_scan_min, c.backfill_scan_max, c.map_cache),
            (8, 16, 70)
        );
    }
    // lines logged since the last call
    let warns = |mc: &mut Mc, core: usize| {
        std::iter::from_fn(|| mc.osds[core].poll_log())
            .filter(|l| l.text.contains("has no effect on croit-flashstore-osd"))
            .count()
    };
    warns(&mut mc, 0);
    warns(&mut mc, 1);
    let (r, d) = ask(
        &mut mc,
        json!({"prefix": "config set", "var": "osd_mclock_profile", "val": "high_client_ops"}),
    );
    assert_eq!((r, d), (0, json!({"success": ""})));
    let (_, d) = ask(
        &mut mc,
        json!({"prefix": "config get", "var": "osd_mclock_profile"}),
    );
    assert_eq!(d["osd_mclock_profile"], "high_client_ops", "still reported");
    assert_eq!(warns(&mut mc, 0), 1);
    assert_eq!(warns(&mut mc, 1), 0, "one line per OSD");
    // same value again: no new line
    ask(
        &mut mc,
        json!({"prefix": "config set", "var": "osd_mclock_profile", "val": "high_client_ops"}),
    );
    assert_eq!(warns(&mut mc, 0), 0);
    // `osd_op_num_shards` is a startup option: the reporting guard must not make it runtime-changeable
    assert!(!crate::osd::Osd::<B>::observed("osd_op_num_shards"));
    let (r, _) = ask(
        &mut mc,
        json!({"prefix": "config set", "var": "osd_op_num_shards", "val": "8"}),
    );
    assert_ne!(r, 0);
    assert_eq!(mc.osds[0].conf.get("osd_op_num_shards"), Some("0"));
}
