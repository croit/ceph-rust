// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Multi-core simulation (adr 0031): N `Osd` cores of one OSD over a simulated NVMe device, cross-core messages moved
//! by hand, clients and the mon played by the test. No sockets: frames are fed to / read from the cores' links.
use crate::meta::{Identity, MetaStore};
use crate::nvmestore::{Nvme, NvmeMeta, open_nvme, open_nvme_pgs};
use crate::osd::{Listener, Osd, OsdConfig, State};
use crate::xcore::{ConnInfo, CoreSpec, XMsg};
use denc::types::{EntityAddr, EntityAddrVec, EntityName, PgT, SpgT, Uuid};
use messages::{CompatSet, MOSDMap, OsdSuperblock};
use opexec::caps::Caps;
use opwire::{ClientMsg, MOSDOp, MOSDOpReply, OsdOp};
use osdmap::OsdMap;
use osdmap::consts::{osd_state, release};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use store::dev::{SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::{Store, StoreCfg};

#[path = "crcopt_tests.rs"]
mod crcopt_tests;
#[path = "ctrsnap_tests.rs"]
mod ctrsnap_tests;
#[path = "omap_stats_tests.rs"]
mod omap_stats;
#[path = "omap_threshold_runtime_tests.rs"]
mod omap_threshold_runtime;
#[path = "op_limits_tests.rs"]
mod op_limits;
#[path = "oversize_tests.rs"]
mod oversize;

type B = Nvme<SimDev, SimClock>;

const S: u32 = 8;

fn helper_batch(batch: usize) -> BTreeMap<Vec<u8>, Vec<u8>> {
    (batch * 1024..(batch + 1) * 1024)
        .map(|i| (format!("k{i:06}").into_bytes(), vec![batch as u8; 64]))
        .collect()
}

fn helper_counter(mc: &Mc, core: usize, name: &str) -> u64 {
    mc.osds[core].pg.store.with_store(|s| {
        s.perf_counters()
            .into_iter()
            .find(|(n, _, _)| *n == name)
            .unwrap()
            .2
    })
}

fn helper_read(mc: &mut Mc, client: u64, tid: u64) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut all = BTreeMap::new();
    let mut after = Vec::new();
    for page in 0..256 {
        let op = mc.op(
            1,
            "helper-object",
            vec![OsdOp::omap_get_vals(&after, 512, b"")],
        );
        let replies = mc.call(0, client, tid + page, op);
        if replies.is_empty() {
            for (core, o) in mc.osds.iter().enumerate() {
                eprintln!(
                    "helper core {core} inflight={} {}",
                    mc.disk.inflight(),
                    o.pg.store.with_store(|s| s.diag())
                );
                o.pg.store.with_store(|s| {
                    for ss in &s.shards {
                        eprintln!("helper shard {} {:?}", ss.idx, ss.sh.olsm_stats());
                    }
                });
            }
        }
        assert_eq!(
            replies.len(),
            1,
            "cores={} tid={tid} page={page} after={after:?}",
            mc.n
        );
        assert_eq!(replies[0].1.result, 0);
        let out: opwire::payload::OmapValsOut =
            denc::from_slice(&replies[0].1.ops[0].outdata).unwrap();
        assert!(out.vals.keys().all(|k| *k > after));
        if let Some(k) = out.vals.keys().next_back() {
            after = k.clone();
        }
        all.extend(out.vals);
        if !out.truncated {
            return all;
        }
    }
    panic!("helper read pagination did not terminate");
}

#[test]
fn failsafe_space_growth_failure_logs_without_fullness_and_retains_failure_context() {
    let mut mc = Mc::new(2);
    mc.up();
    mc.t += Duration::from_secs(2);
    let mut stats = mc.osds[1].local_stats();
    stats.sampled_at = mc.t - Duration::from_millis(750);
    let shard = &mut stats.space_shards[0];
    let id = shard.shard;
    shard.meta_grow_blocked = true;
    shard.meta_growth_failure = Some(peering::store::MetaGrowthFailure {
        sequence: 3,
        reason: "no_contiguous_run",
        unix_time_ns: 1_700_000_000_123_456_789,
        store_poll_time_ns: 123_000_000,
        requested_free_pages: 2048,
        free_meta_pages: 1024,
        cell_blocks: 256,
        pages_per_cell: 128,
        free_data_blocks: 1000,
        held_data_blocks: 12,
        reserved_data_blocks: 4,
        reserve_data_blocks: 100,
        image_bytes: 256,
        image_reserve_bytes: 64,
        deferred_image_bytes: 0,
        image_needed_bytes: 344,
        image_limit_bytes: 8192,
        free_windows: 0,
    });
    let records = |o: &Osd<B>| -> Vec<serde_json::Value> {
        o.logs
            .iter()
            .filter_map(|s| {
                s.split_once("metadata growth blocked ")
                    .map(|(_, s)| serde_json::from_str(s).unwrap())
            })
            .collect()
    };
    let o = &mut mc.osds[0];
    o.logs.clear();
    o.log_level = 0;
    o.on_xmsg(1, XMsg::Stats(Box::new(stats.clone())), mc.t);
    assert!(
        !o.pg.failsafe,
        "a failed growth attempt alone must not change admission"
    );
    let first = records(o);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0]["core"], 1);
    assert_eq!(first[0]["shard"], id);
    assert_eq!(first[0]["report_age_ms"], 750);
    assert_eq!(first[0]["failed_attempts_since_previous_log"], 3);
    assert_eq!(first[0]["failure"]["reason"], "no_contiguous_run");
    assert_eq!(
        first[0]["failure"]["unix_time_ns"],
        1_700_000_000_123_456_789u64
    );
    assert_eq!(first[0]["failure"]["cell_bytes"], 1 << 20);
    o.on_xmsg(1, XMsg::Stats(Box::new(stats.clone())), mc.t);
    assert_eq!(
        records(o).len(),
        1,
        "repeated reports do not repeat the failure log"
    );

    // A later report can observe recovery; the retained failure payload still describes its original attempt.
    stats.space_shards[0].meta_grow_blocked = false;
    stats.space_shards[0]
        .meta_growth_failure
        .as_mut()
        .unwrap()
        .sequence = 5;
    o.on_xmsg(1, XMsg::Stats(Box::new(stats.clone())), mc.t);
    let later = records(o);
    assert_eq!(later.len(), 2);
    assert_eq!(later[1]["failed_attempts_since_previous_log"], 2);
    assert_eq!(later[1]["currently_blocked"], false);
    o.pg.failsafe = true; // exercise a clearing record with that worker's retained cause
    o.update_local_failsafe();
    let transitions = failsafe_records(o);
    let detail = &transitions.last().unwrap()["cores"][1]["shards"][0]["meta_growth_failure"];
    assert_eq!(detail["reason"], "no_contiguous_run");
    assert_eq!(detail["sequence"], 5);
    assert_eq!(detail["unix_time_ns"], 1_700_000_000_123_456_789u64);
    stats.space_shards[0]
        .meta_growth_failure
        .as_mut()
        .unwrap()
        .sequence = 4;
    o.on_xmsg(1, XMsg::Stats(Box::new(stats)), mc.t);
    assert_eq!(
        records(o).len(),
        2,
        "an older sample does not log an old failure again"
    );
}

fn failsafe_records(o: &Osd<B>) -> Vec<serde_json::Value> {
    o.logs
        .iter()
        .filter_map(|s| {
            s.split_once("local failsafe full transition ")
                .map(|(_, json)| serde_json::from_str(json).unwrap())
        })
        .collect()
}

/// `osd_failsafe_full_ratio` in percent (`97`, classic spelling) is 0.97: a full device trips the failsafe.
#[test]
fn failsafe_ratio_in_percent_is_normalized() {
    let mut mc = Mc::new(2);
    mc.up();
    let mut stats = mc.osds[1].local_stats();
    stats.space = Some(peering::Space {
        total: 1 << 30,
        available: 0,
        allocated: 1 << 30,
        ..Default::default()
    });
    mc.osds[0].cl.stats[1] = Some(stats);
    let o = &mut mc.osds[0];
    o.log_level = 0;
    o.conf
        .set(
            crate::config::Level::Override,
            "osd_failsafe_full_ratio",
            "97",
        )
        .unwrap();
    o.update_local_failsafe();
    assert!(o.pg.failsafe);
    let r = &failsafe_records(o)[0];
    assert_eq!(r["configured_ratio"], 0.97);
}

#[test]
fn failsafe_space_transition_reports_exact_inputs_age_missing_core_and_shards() {
    let mut mc = Mc::new(3);
    mc.up();
    mc.t = Duration::from_secs(20);
    for o in &mut mc.osds {
        o.now = mc.t;
    }
    let mut stats = mc.osds[1].local_stats();
    stats.sampled_at = Duration::from_secs(1);
    stats.space = Some(peering::Space {
        total: 1 << 30,
        available: 0,
        allocated: 1 << 30,
        ..Default::default()
    });
    assert!(!stats.space_shards.is_empty());
    mc.osds[0].cl.stats[1] = Some(stats);
    mc.osds[0].cl.stats[2] = None;
    let o = &mut mc.osds[0];
    o.log_level = 0; // protection transitions remain visible even when ordinary logs are suppressed
    o.conf
        .set(
            crate::config::Level::Override,
            "osd_failsafe_full_ratio",
            "0.99",
        )
        .unwrap();
    Arc::make_mut(o.map.as_mut().unwrap()).full_ratio = 0.995;
    let expected = o.statfs_all();
    o.update_local_failsafe();
    assert!(o.pg.failsafe);
    let records = failsafe_records(o);
    assert_eq!(records.len(), 1);
    let r = &records[0];
    assert_eq!(r["enabled"], true);
    assert_eq!(r["configured_ratio"], 0.99);
    assert_eq!(r["threshold_ratio"], f64::from(0.995f32));
    assert_eq!(r["aggregate"]["total_bytes"], expected.total);
    assert_eq!(r["aggregate"]["available_bytes"], expected.available);
    assert_eq!(r["aggregate"]["fill_ratio"], 1.0);
    assert!(
        r["aggregate"]["available_before_clamp_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(r["fullest_core"], 1);
    assert_eq!(r["cores"][1]["sample_age_ms"], 19000);
    assert_eq!(r["cores"][1]["space"]["pooled"], false);
    let ids: Vec<_> = r["cores"][1]["shards"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["shard"].as_u64().unwrap())
        .collect();
    assert_eq!(ids, vec![1, 4, 7]);
    assert_eq!(r["cores"][2]["reported"], false);
    assert!(r["cores"][2]["sample_age_ms"].is_null());
    assert!(r["cores"][2]["space"].is_null());
    o.update_local_failsafe();
    assert_eq!(
        failsafe_records(o).len(),
        1,
        "unchanged state must not repeat diagnostic"
    );
    mc.settle();
    assert!(mc.osds.iter().all(|o| o.pg.failsafe));

    // Same full worker becomes pooled with room in the pool (its fullest shard reads 0): its own sum no longer clamps
    // the aggregate.
    let o = &mut mc.osds[0];
    let stats = o.cl.stats[1].as_mut().unwrap();
    stats.space.as_mut().unwrap().pooled = true;
    stats.sampled_at = Duration::from_secs(21); // saturating age if the sender clock is ahead
    o.update_local_failsafe();
    let records = failsafe_records(o);
    assert_eq!(records.len(), 2);
    assert_eq!(records[1]["enabled"], false);
    assert_eq!(records[1]["cores"][1]["space"]["pooled"], true);
    assert_eq!(records[1]["cores"][1]["sample_age_ms"], 0);
    mc.settle();
    assert!(mc.osds.iter().all(|o| !o.pg.failsafe));
}

#[test]
fn failsafe_space_single_core_clear_has_live_shards_and_no_spurious_activation() {
    let mut mc = Mc::new(1);
    mc.up();
    let o = &mut mc.osds[0];
    o.logs.clear();
    o.update_local_failsafe();
    assert!(
        failsafe_records(o).is_empty(),
        "healthy unchanged state is silent"
    );
    o.pg.failsafe = true;
    o.update_local_failsafe();
    let records = failsafe_records(o);
    assert_eq!(records.len(), 1);
    let r = &records[0];
    assert_eq!(r["enabled"], false);
    assert_eq!(r["cores"].as_array().unwrap().len(), 1);
    assert_eq!(r["cores"][0]["sample_age_ms"], 0);
    assert_eq!(r["cores"][0]["reported"], true);
    let shards = r["cores"][0]["shards"].as_array().unwrap();
    assert_eq!(shards.len(), S as usize);
    for (shard, detail) in shards.iter().enumerate() {
        assert_eq!(detail["shard"], shard as u64);
        assert!(detail["space"]["total_bytes"].as_u64().unwrap() > 0);
        assert!(detail["meta_usable_pages"].as_u64().unwrap() > 0);
        assert!(!detail["meta_grow_blocked"].as_bool().unwrap());
    }
}

#[test]
fn compaction_helpers_execute_on_another_core_and_single_core_stays_inline() {
    for cores in [1, 2, 4] {
        let mut mc = Mc::with_helpers(cores);
        mc.up();
        let cl = mc.client(0);
        let mut expected = BTreeMap::new();
        let probe = mc.op(1, "helper-object", vec![]);
        let owner = mc.osds[0].input_shard(probe.pgid.pgid) % cores;
        for batch in 0..8 {
            let vals = helper_batch(batch);
            let op = mc.op(1, "helper-object", vec![OsdOp::omap_set_vals(&vals)]);
            let r = mc.call(0, cl, batch as u64 + 1, op);
            assert_eq!(r.len(), 1);
            assert_eq!(r[0].1.result, 0);
            expected.extend(vals);
        }
        assert_eq!(helper_read(&mut mc, cl, 20), expected);
        let served = (0..cores)
            .filter(|c| *c != owner)
            .map(|c| helper_counter(&mc, c, "run_helper_served"))
            .sum::<u64>();
        if cores == 1 {
            assert_eq!(helper_counter(&mc, owner, "run_helper_jobs"), 0);
        } else {
            assert!(
                served > 0,
                "different logical core actually built output/Bloom"
            );
            assert!(helper_counter(&mc, owner, "run_helper_done") > 0);
        }
        mc.restart();
        let map = mc.map(12, 12);
        mc.deliver(map);
        mc.run_for(Duration::from_secs(3));
        let cl = mc.client(0);
        assert_eq!(
            helper_read(&mut mc, cl, 21),
            expected,
            "crash-style remount"
        );
    }
}

/// Omap LSM flush / merge rounds (adr 0610 am. 3) run on another core of a multi-core OSD by default; a single-core OSD
/// steps them inline. Contents survive a restart either way.
#[test]
fn olsm_rounds_run_on_helper_cores_and_single_core_stays_inline() {
    for cores in [1, 2, 3] {
        let mut mc = Mc::with_olsm(cores, 512);
        mc.up();
        let cl = mc.client(0);
        let mut expected = BTreeMap::new();
        let probe = mc.op(1, "helper-object", vec![]);
        let owner = mc.osds[0].input_shard(probe.pgid.pgid) % cores;
        for batch in 0..40 {
            let vals = helper_batch(batch);
            let op = mc.op(1, "helper-object", vec![OsdOp::omap_set_vals(&vals)]);
            let r = mc.call(0, cl, batch as u64 + 1, op);
            assert_eq!(r.len(), 1);
            assert_eq!(r[0].1.result, 0);
            expected.extend(vals);
        }
        mc.run_for(Duration::from_secs(1));
        assert_eq!(helper_read(&mut mc, cl, 1000), expected);
        let c = |n| helper_counter(&mc, owner, n);
        assert!(
            c("olsm_flushes") >= 8 && c("olsm_merges") >= 1,
            "cores {cores}"
        );
        if cores == 1 {
            assert_eq!(c("olsm_helper_rounds"), 0);
            assert!(c("olsm_inline_rounds") > 0);
        } else {
            assert!(c("olsm_helper_rounds") > 0, "cores {cores}");
            assert_eq!(c("olsm_inline_rounds"), 0, "cores {cores}");
        }
        mc.restart();
        let map = mc.map(12, 12);
        mc.deliver(map);
        mc.run_for(Duration::from_secs(3));
        let cl = mc.client(0);
        assert_eq!(helper_read(&mut mc, cl, 2000), expected, "remount");
    }
}

#[test]
fn compaction_helper_delayed_result_is_bounded_and_cannot_resurrect_clear() {
    let mut mc = Mc::with_helpers(2);
    mc.up();
    mc.delay = Some(|_, m| matches!(m, XMsg::CompactDone(_)));
    let cl = mc.client(0);
    let mut expected = BTreeMap::new();
    for batch in 0..8 {
        let vals = helper_batch(batch);
        let op = mc.op(1, "helper-object", vec![OsdOp::omap_set_vals(&vals)]);
        let r = mc.call(0, cl, batch as u64 + 1, op);
        assert_eq!(r.len(), 1, "foreground continues while result is held");
        assert_eq!(r[0].1.result, 0);
        expected.extend(vals);
    }
    assert_eq!(mc.delayed.len(), 1, "one credit includes return transit");
    let owner = mc.delayed[0].1;
    assert_ne!(mc.delayed[0].0, owner);
    assert!(helper_counter(&mc, owner, "run_helper_reserved") > 0);
    assert_eq!(helper_read(&mut mc, cl, 20), expected);
    let vals = helper_batch(10);
    let op = mc.op(
        1,
        "helper-object",
        vec![OsdOp::omap_clear(), OsdOp::omap_set_vals(&vals)],
    );
    assert_eq!(mc.call(0, cl, 200, op)[0].1.result, 0);
    mc.release_delayed();
    assert_eq!(helper_read(&mut mc, cl, 300), vals);
    assert_eq!(helper_counter(&mc, owner, "run_helper_reserved"), 0);
    assert!(helper_counter(&mc, owner, "run_helper_lost") > 0);
}

#[test]
fn compaction_helper_return_from_old_incarnation_is_ignored_after_restart() {
    let mut mc = Mc::with_helpers(2);
    mc.up();
    mc.delay = Some(|_, m| matches!(m, XMsg::CompactDone(_)));
    let cl = mc.client(0);
    let mut expected = BTreeMap::new();
    for batch in 0..4 {
        let vals = helper_batch(batch);
        let op = mc.op(1, "helper-object", vec![OsdOp::omap_set_vals(&vals)]);
        assert_eq!(mc.call(0, cl, batch as u64 + 1, op)[0].1.result, 0);
        expected.extend(vals);
    }
    assert_eq!(mc.delayed.len(), 1);
    mc.restart();
    let map = mc.map(12, 12);
    mc.deliver(map);
    mc.run_for(Duration::from_secs(3));
    mc.release_delayed();
    let cl = mc.client(0);
    assert_eq!(helper_read(&mut mc, cl, 20), expected);
}

#[test]
fn compaction_helper_shutdown_declines_job_without_redispatch_livelock() {
    let mut mc = Mc::with_helpers(2);
    mc.up();
    mc.delay = Some(|_, m| matches!(m, XMsg::CompactWork(_)));
    let cl = mc.client(0);
    for batch in 0..4 {
        let op = mc.op(
            1,
            "helper-object",
            vec![OsdOp::omap_set_vals(&helper_batch(batch))],
        );
        assert_eq!(mc.call(0, cl, batch as u64 + 1, op)[0].1.result, 0);
    }
    assert_eq!(mc.delayed.len(), 1);
    let (owner, helper) = (mc.delayed[0].0, mc.delayed[0].1);
    mc.osds[helper].state = State::Stopping;
    mc.release_delayed();
    assert_eq!(helper_counter(&mc, owner, "run_helper_jobs"), 1);
    assert_eq!(helper_counter(&mc, owner, "run_helper_reserved"), 0);
}

fn publish_utilization(mc: &mut Mc, core: usize) {
    if core != 0 {
        let snapshot = mc.osds[core].local_stats();
        mc.osds[0].on_xmsg(core, XMsg::Stats(Box::new(snapshot)), mc.t);
    }
}

fn recreate_utilization_pg(mc: &mut Mc, core: usize, spg: SpgT) {
    let o = &mut mc.osds[core];
    let actions = o.pg.set.detach(o.pg_mono(), spg, &o.pg.store);
    o.pg_exec(actions);
    assert!(o.pg.set.pg(spg).is_none());
    let actions = o.pg.set.adopt(o.pg_mono(), spg, &o.pg.store);
    o.pg_exec(actions);
    assert_eq!(o.pg.set.pg(spg).unwrap().counters().work_ops, 0);
}

#[test]
fn utilization_reset_tracks_local_and_worker_pg_lifetimes() {
    for cores in [1, 2] {
        let mut mc = Mc::new(cores);
        mc.up();
        let core = cores - 1;
        let spg = *mc.osds[core].pg.set.pgs().next().unwrap().0;
        let name = format!(
            "flashstore_pg_{core}_{}_{:x}_s{}",
            spg.pgid.pool, spg.pgid.seed, spg.shard.0
        );
        mc.osds[core].note_pg_work(spg, 6, 6);
        mc.osds[core].note_core_busy(6);
        publish_utilization(&mut mc, core);
        let baseline = mc.osds[0].perf_dump(None, None)[&name]["ops"]
            .as_u64()
            .unwrap();
        assert!(baseline >= 6);
        mc.osds[0].perf_reset("all");
        recreate_utilization_pg(&mut mc, core, spg);
        for count in 0..=baseline + 1 {
            if count > 0 {
                mc.osds[core].note_pg_work(spg, 1, 1);
                mc.osds[core].note_core_busy(1);
            }
            publish_utilization(&mut mc, core);
            let expected = mc.osds[core]
                .pg_utilization()
                .into_iter()
                .find(|(s, _)| *s == spg)
                .unwrap()
                .1;
            let dump = mc.osds[0].perf_dump(None, None);
            assert_eq!(
                dump[&name]["ops"], count,
                "fresh PG lifetime at count {count}"
            );
            assert_eq!(dump[&name]["busy_ns"], expected.busy_ns);
            assert_eq!(dump[&name]["bytes"], expected.bytes);
            assert_eq!(
                dump[&name].as_object().unwrap().len(),
                3,
                "lifetime IDs stay internal"
            );
            assert_eq!(
                dump[format!("flashstore_core_{core}")]["ops"],
                count,
                "core counters retain their process lifetime across PG replacement"
            );
        }
        mc.osds[0].perf_reset("all");
        mc.osds[core].note_pg_work(spg, 1, 1);
        mc.osds[core].note_core_busy(1);
        publish_utilization(&mut mc, core);
        let dump = mc.osds[0].perf_dump(None, None);
        for counter in ["busy_ns", "ops", "bytes"] {
            assert_eq!(dump[&name][counter], 1);
        }
    }
}

#[test]
fn utilization_reset_detects_replacement_between_worker_snapshots() {
    let mut mc = Mc::new(2);
    mc.up();
    let spg = *mc.osds[1].pg.set.pgs().next().unwrap().0;
    let name = format!(
        "flashstore_pg_1_{}_{:x}_s{}",
        spg.pgid.pool, spg.pgid.seed, spg.shard.0
    );
    mc.osds[1].note_pg_work(spg, 6, 6);
    mc.osds[1].note_core_busy(6);
    publish_utilization(&mut mc, 1);
    let old = mc.osds[0].perf_dump(None, None)[&name].clone();
    let baseline = old["ops"].as_u64().unwrap();
    mc.osds[0].perf_reset("all");
    recreate_utilization_pg(&mut mc, 1, spg);
    mc.osds[1].note_pg_work(spg, baseline + 3, old["bytes"].as_u64().unwrap() + 3);
    mc.osds[1].note_core_busy(old["busy_ns"].as_u64().unwrap() + 3);
    publish_utilization(&mut mc, 1);
    let expected = mc.osds[1]
        .pg_utilization()
        .into_iter()
        .find(|(s, _)| *s == spg)
        .unwrap()
        .1;
    let dump = mc.osds[0].perf_dump(None, None);
    for (counter, value) in [
        ("busy_ns", expected.busy_ns),
        ("ops", expected.ops),
        ("bytes", expected.bytes),
    ] {
        assert!(value > old[counter].as_u64().unwrap());
        assert_eq!(
            dump[&name][counter], value,
            "the new PG exceeded the old {counter} baseline before its first worker snapshot"
        );
    }
}

#[test]
fn utilization_diagnostics_show_hot_pg_without_changing_mgr_catalogue() {
    let mut mc = Mc::new(1);
    mc.up();
    let cl = mc.client(0);
    let op = mc.op(1, "util-hot", vec![OsdOp::writefull(vec![7; 4096])]);
    let spg = op.pgid;
    let name = format!(
        "flashstore_pg_0_{}_{:x}_s{}",
        spg.pgid.pool, spg.pgid.seed, spg.shard.0
    );
    let before = mc.osds[0].perf_dump(None, None);
    let ops = before[&name]["ops"].as_u64().unwrap_or(0);
    let bytes = before[&name]["bytes"].as_u64().unwrap_or(0);
    assert_eq!(mc.call(0, cl, 1, op)[0].1.result, 0);
    let op = mc.op(1, "util-hot", vec![OsdOp::read(0, 4096)]);
    assert_eq!(mc.call(0, cl, 2, op)[0].1.result, 0);
    let o = &mut mc.osds[0];
    o.note_core_busy(1_000); // the runtime loop reports the iteration; the PGs that ran get its time
    let dump = o.perf_dump(None, None);
    assert_eq!(dump[&name]["ops"].as_u64().unwrap() - ops, 2);
    assert_eq!(dump[&name]["bytes"].as_u64().unwrap() - bytes, 8192);
    assert!(dump[&name]["busy_ns"].as_u64().unwrap() > 0);
    assert!(dump["flashstore_core_0"]["ops"].as_u64().unwrap() >= 2);
    // store checkpoint / back-pressure section (adr 0021 am. 43)
    let s = &dump["flashstore_store_0"];
    assert!(s["txns"].as_u64().unwrap() >= 1);
    assert!(s["dirty_hard"].as_u64().unwrap() > s["dirty_soft"].as_u64().unwrap());
    assert!(s["wal_blocks"].as_u64().unwrap() > 0);
    assert_eq!(s["parked_txns"], 0);
    assert!(
        o.counters_now()
            .keys()
            .all(|k| !k.starts_with("flashstore_core_") && !k.starts_with("flashstore_pg_"))
    );
    o.perf_reset("all");
    let reset = o.perf_dump(None, None);
    assert_eq!(reset[&name]["ops"], 0);
    assert_eq!(reset[&name]["bytes"], 0);
    assert_eq!(reset[&name]["busy_ns"], 0);
}

#[test]
#[ignore = "PG dispatch instrumentation benchmark; run explicitly"]
fn utilization_dispatch_bench() {
    let mut mc = Mc::new(1);
    mc.up();
    let o = &mut mc.osds[0];
    let spg = *o.pg.set.pgs().next().unwrap().0;
    o.pg_run(spg, |_, _| {});
    let n = 100_000;
    let start = std::time::Instant::now();
    for _ in 0..n {
        o.pg_run(spg, |e, _| {
            std::hint::black_box(e);
        });
    }
    eprintln!(
        "utilization_dispatch ns/call={}",
        start.elapsed().as_nanos() / n
    );
}

/// Cost breakdown of the counter dumps and the periodic reports on the control core: 4 cores, `NV_PD_PGS` (128) PGs.
/// `cargo test --release -p osd --lib perf_dump_cost_bench -- --ignored --nocapture`
#[test]
#[ignore = "admin counter dump cost breakdown; run explicitly"]
fn perf_dump_cost_bench() {
    use std::hint::black_box;
    let mut mc = Mc::new(4);
    mc.pool4 = std::env::var("NV_PD_PGS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(128);
    mc.up();
    write_read_all(&mut mc, 4, "pd", 64, 1);
    mc.run_for(Duration::from_secs(2));
    let n = 300u32;
    let row = |name: &str, f: &mut dyn FnMut()| {
        f();
        let mut v: Vec<u128> = (0..n)
            .map(|_| {
                let t = std::time::Instant::now();
                f();
                t.elapsed().as_nanos()
            })
            .collect();
        v.sort_unstable();
        eprintln!(
            "perf_dump_cost {name:<28} median {:>8.1} us  p90 {:>8.1} us",
            v[v.len() / 2] as f64 / 1e3,
            v[v.len() * 9 / 10] as f64 / 1e3
        );
    };
    mc.osds[0].sample_counters();
    let req = |o: &Osd<B>, doc| crate::ctrsnap::CounterReq {
        snap: o.counter_snap(),
        doc,
        logger: None,
        counter: None,
    };
    let dump_len = req(&mc.osds[0], crate::ctrsnap::Doc::PerfDump)
        .render(true)
        .len();
    eprintln!(
        "perf_dump_cost pgs {} dump {dump_len} B compact",
        mc.pool4 + 8
    );
    {
        let o = &mc.osds[0];
        // control core: per request
        row("core0 counter_snap", &mut || {
            black_box(o.counter_snap());
        });
        // every core once a second
        row("core tick counter_sample", &mut || {
            black_box(o.counter_sample());
        });
        row("core0 tick control sample", &mut || {
            black_box(o.fresh_counter_snap());
        });
        row("core0 op_perf_all", &mut || {
            black_box(o.op_perf_all());
        });
        // admin socket thread
        for (name, doc, compact) in [
            (
                "render perf dump compact",
                crate::ctrsnap::Doc::PerfDump,
                true,
            ),
            (
                "render perf dump pretty",
                crate::ctrsnap::Doc::PerfDump,
                false,
            ),
            (
                "render counter dump compact",
                crate::ctrsnap::Doc::CounterDump,
                true,
            ),
            (
                "render perf schema pretty",
                crate::ctrsnap::Doc::PerfSchema,
                false,
            ),
        ] {
            let r = req(o, doc);
            row(name, &mut || {
                black_box(r.render(compact));
            });
        }
        // MMgrReport (control core, every stats period)
        row("core0 mgr counters", &mut || {
            black_box(o.counters());
        });
        let c = o.counters();
        let mut rep = messages::PerfReporter::new();
        row("core0 mgr reporter build", &mut || {
            black_box(rep.build(&c, 0).unwrap());
        });
        row("core0 pg_stat_list", &mut || {
            black_box(o.pg_stat_list());
        });
        row("core0 pg_pool_statfs", &mut || {
            black_box(o.pg_pool_statfs());
        });
    }
    let o = &mut mc.osds[0];
    row("core0 osd_stat", &mut || {
        black_box(o.osd_stat());
    });
    let (tx, rx) = std::sync::mpsc::channel();
    // what the control core does per admin socket request: parse, snapshot, hand over (the worker renders)
    row("core0 asok perf dump", &mut || {
        o.cmds.seq += 1;
        let tok = o.cmds.seq;
        o.cmds.pending.insert(tok, tx.clone());
        o.exec_command(r#"{"prefix":"perf dump"}"#, crate::tell::ReplyTo::Asok(tok));
        black_box(rx.try_recv().unwrap());
    });
}

/// Admin counter commands of a quiescent 4-core OSD written to `$NV_PD_OUT/<n>.out` through the admin socket path
/// (reply bodies as the socket sends them): byte comparison of two builds (doc/perf/perfdump-offcore-20261101.md).
/// `NV_PD_OUT=dir cargo test --release -p osd --lib perf_dump_golden_capture -- --ignored`
#[test]
#[ignore = "writes command outputs for a byte comparison of two builds; run explicitly"]
fn perf_dump_golden_capture() {
    let out = std::path::PathBuf::from(std::env::var("NV_PD_OUT").expect("NV_PD_OUT"));
    std::fs::create_dir_all(&out).unwrap();
    let mut mc = Mc::new(4);
    mc.up();
    write_read_all(&mut mc, 4, "pd", 64, 1);
    mc.run_for(Duration::from_secs(3));
    let cmds = [
        r#"{"prefix":"perf dump"}"#,
        r#"{"prefix":"perf dump","format":"json"}"#,
        r#"{"prefix":"perf dump","logger":"osd","counter":"op_r"}"#,
        r#"{"prefix":"perf dump","logger":"nope","format":"json"}"#,
        r#"{"prefix":"perf dump","logger":"flashstore_core_1"}"#,
        r#"{"prefix":"counter dump","format":"json"}"#,
        r#"{"prefix":"counter dump"}"#,
        r#"{"prefix":"counter dump","logger":"throttle-osd_client_bytes","counter":"max"}"#,
        r#"{"prefix":"perf schema"}"#,
        r#"{"prefix":"perf schema","format":"json"}"#,
        r#"{"prefix":"counter schema","format":"json"}"#,
        r#"{"prefix":"counter schema"}"#,
        r#"{"prefix":"perf histogram dump"}"#,
        r#"{"prefix":"perf histogram dump","logger":"osd","counter":"op_w_latency_in_bytes_histogram","format":"json"}"#,
        r#"{"prefix":"perf histogram schema","format":"json"}"#,
        r#"{"prefix":"perf reset","var":"all"}"#,
        r#"{"prefix":"perf dump","format":"json"}"#,
    ];
    let (tx, rx) = std::sync::mpsc::channel();
    for (i, cmd) in cmds.iter().enumerate() {
        let o = &mut mc.osds[0];
        o.cmds.seq += 1;
        let tok = o.cmds.seq;
        o.cmds.pending.insert(tok, tx.clone());
        o.exec_command(cmd, crate::tell::ReplyTo::Asok(tok));
        let res = rx.try_recv().unwrap();
        std::fs::write(
            out.join(format!("{i:02}.out")),
            crate::asok::render(cmd, res),
        )
        .unwrap();
    }
}

#[test]
fn utilization_worker_snapshots_and_counter_only_updates() {
    let mut mc = Mc::new(2);
    mc.up();
    let worker = &mut mc.osds[1];
    let spg = *worker.pg.set.pgs().next().unwrap().0;
    let mut touched = Vec::new();
    let _ = worker.pg.set.take_touched(&mut touched);
    worker.note_core_busy(0); // end of the iteration that ran mc.up(): its PGs are attributed
    worker.note_pg_work(spg, 6, 789);
    worker.note_core_busy(123);
    worker.note_slice_cut();
    worker.note_net_diag(4096, 3, 7_500_000, [5, 2, 1]); // kernel tier transport counters (adr 0474 am. 1)
    assert_eq!(
        worker.pg.set.take_touched(&mut touched),
        peering::Touched::Listed
    );
    assert!(touched.is_empty(), "metrics must not trigger engine sync");
    let snapshot = worker.local_stats();
    mc.osds[0].on_xmsg(1, XMsg::Stats(Box::new(snapshot)), mc.t);
    let dump = mc.osds[0].perf_dump(None, None);
    assert_eq!(dump["flashstore_core_1"]["busy_ns"], 123);
    assert_eq!(dump["flashstore_core_1"]["slice_cuts"], 1);
    assert_eq!(dump["flashstore_core_1"]["hold_store_max_us"], 0);
    // transport diagnostics travel in CoreStats like busy_ns: per-cell deltas for the bench
    assert_eq!(dump["flashstore_core_1"]["rx_bytes"], 4096);
    assert_eq!(dump["flashstore_core_1"]["rx_pauses"], 3);
    assert_eq!(dump["flashstore_core_1"]["rx_pause_ms"], 7);
    assert_eq!(dump["flashstore_core_1"]["long_1ms"], 5);
    assert_eq!(dump["flashstore_core_1"]["long_10ms"], 2);
    assert_eq!(dump["flashstore_core_1"]["long_100ms"], 1);
    assert!(dump["flashstore_store_1"]["dirty_hard"].as_u64().unwrap() > 0);
    let name = format!(
        "flashstore_pg_1_{}_{:x}_s{}",
        spg.pgid.pool, spg.pgid.seed, spg.shard.0
    );
    assert!(dump[&name]["busy_ns"].as_u64().unwrap() >= 45);
    assert!(dump[&name]["ops"].as_u64().unwrap() >= 6);
    assert!(dump[&name]["bytes"].as_u64().unwrap() >= 789);
}

fn real_map() -> OsdMap {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/osdmap/full/0091.bin");
    OsdMap::decode_from(&std::fs::read(p).unwrap()).unwrap()
}

fn addr(ip: [u8; 4], port: u16, nonce: u32) -> EntityAddrVec {
    EntityAddrVec::single(EntityAddr::v4(EntityAddr::TYPE_MSGR2, nonce, ip, port))
}

fn cfg(whoami: i32) -> OsdConfig {
    let h = whoami as u8;
    OsdConfig {
        hostname: "h1".into(),
        public_ips: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4 + h))],
        cluster_ips: vec![IpAddr::V4(Ipv4Addr::new(10, 1, 0, 4 + h))],
        public_port: 6800,
        cluster_port: 6801,
        hb_front_port: 6802,
        hb_back_port: 6803,
        mon_host: monc::parse_mon_host("v2:10.0.0.1:3300").unwrap(),
        wall_origin_unix: 1_700_000_000,
        wall_from_clock: false,
        seed: 42,
        nonce: 555 + whoami as u32,
        sys_metadata: BTreeMap::new(),
        // never the host's `/var/lib/ceph/osd/ceph-<id>/keyring` (lab runners host OSDs): keys come from the device
        local_config: vec![(
            "keyring".into(),
            "/nonexistent/croit-flashstore-test/keyring".into(),
        )],
        local_sources: Default::default(),
        data_path: "/d".into(),
        rdma: false,
        placement: false,
        source_pull: false,
    }
}

/// One OSD (osd.0) of `n` cores on one simulated device.
struct Mc {
    whoami: i32,
    n: usize,
    /// Store shards of the device (mkfs).
    shards: u32,
    disk: SimDisk,
    osds: Vec<Osd<B>>,
    t: Duration,
    fsid: Uuid,
    epoch: u32,
    next_port: u16,
    /// pg_num of pool 4 in `map()`.
    pool4: u32,
    /// Pool 4 is erasure coded (isa k=2 m=1, overwrites): its PG instances carry a shard id.
    ec4: bool,
    /// Exercise the real opt-in OSD construction path in placement tests.
    placement: bool,
    helpers: bool,
    /// Test hook: messages (destination core, message) this returns true for are lost.
    lose: Option<fn(usize, &XMsg) -> bool>,
    /// Pool run (`with_pool`): elastic lending/reclaim on.
    #[cfg(feature = "elastic")]
    pool: bool,
    /// Test hook: messages this returns true for wait in `delayed` (until `release_delayed`): cross-ring reordering.
    delay: Option<fn(usize, &XMsg) -> bool>,
    delayed: Vec<(usize, usize, XMsg)>,
}

impl Mc {
    /// Format a device and start osd.0 with `n` cores.
    fn new(n: usize) -> Mc {
        Mc::with(0, n)
    }

    fn new_placement(n: usize) -> Mc {
        Mc::with_pool_placement(0, n, S, 2048, false, true, false)
    }

    fn with(whoami: i32, n: usize) -> Mc {
        Mc::with_wal(whoami, n, 2048)
    }

    fn with_wal(whoami: i32, n: usize, wal_blocks: u64) -> Mc {
        Mc::with_layout(whoami, n, S, wal_blocks)
    }

    /// osd.0 on a device formatted with `shards` store shards, run with `n` cores.
    fn with_shards(n: usize, shards: u32) -> Mc {
        Mc::with_layout(0, n, shards, 2048)
    }

    fn with_layout(whoami: i32, n: usize, shards: u32, wal_blocks: u64) -> Mc {
        Mc::with_pool(whoami, n, shards, wal_blocks, false)
    }

    /// [`Self::with_layout`]; `pool` = a chunked store (1 MiB chunks, half the data space as base) run with the elastic pool on
    /// (only effective with the `elastic` feature).
    fn with_pool(whoami: i32, n: usize, shards: u32, wal_blocks: u64, pool: bool) -> Mc {
        Mc::with_pool_placement(whoami, n, shards, wal_blocks, pool, false, false)
    }

    /// osd.0 with `n` cores on a store with the omap LSM engine (adr 0610); a small ring keeps the memtables small.
    fn with_olsm(n: usize, wal_blocks: u64) -> Mc {
        Mc::with_pool_placement(0, n, S, wal_blocks, false, false, true)
    }

    fn with_pool_placement(
        whoami: i32,
        n: usize,
        shards: u32,
        wal_blocks: u64,
        pool: bool,
        placement: bool,
        omap_lsm: bool,
    ) -> Mc {
        let disk = SimDisk::new(SimConfig::new(if wal_blocks > 2048 {
            4 << 30
        } else {
            512 << 20
        }));
        let p = MkfsParams {
            shards,
            wal_blocks,
            align_blocks: 1,
            meta_pct: 8,
            chunked: pool,
            chunk_blocks: 256,
            base_pct: 50,
            omap_lsm,
            ..Default::default()
        };
        mkfs(&mut disk.queue(), &mut SimClock::default(), &p).unwrap();
        let fsid = real_map().fsid;
        // identity + superblock through core 0's store
        {
            let d = disk.clone();
            let (st, _) =
                Store::mount(move || d.queue(), SimClock::default(), StoreCfg::default()).unwrap();
            let st = Rc::new(RefCell::new(st));
            let mut meta = NvmeMeta::new(st.clone()).unwrap();
            let key = cephx::CryptoKey::generate(
                cephx::KeyType::Aes256Krb5,
                denc::types::UTime::new(1, 0),
            )
            .unwrap();
            meta.store_identity(&Identity {
                whoami,
                cluster_fsid: fsid,
                osd_fsid: Uuid([9; 16]),
                key: key.to_base64().unwrap(),
                crush_device_class: "nvme".into(),
                created_at: "t".into(),
                ceph_version_when_created: "v".into(),
            })
            .unwrap();
            meta.store_superblock(&OsdSuperblock {
                cluster_fsid: fsid,
                whoami,
                osd_fsid: Uuid([9; 16]),
                compat_features: CompatSet::osd_initial(),
                purged_snaps_last: 1000,
                ..Default::default()
            })
            .unwrap();
            // a deallocate in flight (adr 0642) completes before this store goes: the sim keeps a dropped queue's IO in
            // flight and `settle` waits for an idle device
            let mut st = st.borrow_mut();
            let mut acked = Vec::new();
            while disk.inflight() > 0 {
                st.poll(&mut acked).unwrap();
                st.idle();
            }
        }
        let mut m = Mc {
            whoami,
            n,
            shards,
            disk,
            osds: Vec::new(),
            t: Duration::from_secs(1),
            fsid,
            epoch: 0,
            next_port: 40000,
            #[cfg(feature = "elastic")]
            pool,
            pool4: 32,
            ec4: false,
            placement,
            helpers: false,
            lose: None,
            delay: None,
            delayed: Vec::new(),
        };
        m.boot();
        m
    }

    fn mount(&self, core: usize) -> Store<SimDev, SimClock> {
        let (d, n) = (self.disk.clone(), self.n);
        let mut cfg = StoreCfg::default();
        cfg.shard.run_helpers = self.helpers;
        // w4k bench: tiny tree cache = cold leaves (NV_W4K_CACHE = pages per shard)
        if let Some(p) = std::env::var("NV_W4K_CACHE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
        {
            cfg.shard.cache_pages = p;
            cfg.shard.dirty_soft_pages = p / 8;
            cfg.shard.dirty_hard_pages = p * 3 / 8;
        }
        #[cfg(feature = "elastic")]
        {
            cfg.shard.lend_auto = self.pool;
        }
        Store::mount_shards(
            move || d.queue(),
            SimClock::default(),
            cfg,
            move |s| s as usize % n == core,
        )
        .unwrap()
        .0
    }

    /// (Re)start every core from the device.
    fn boot(&mut self) {
        let spec = |id| CoreSpec::new(id, self.n, self.n, self.shards).unwrap();
        let mut config = cfg(self.whoami);
        config.rdma = self.placement;
        config.placement = self.placement;
        // The simulated transport serves the READ, so the harness OSD offers source-pull
        // whenever it offers placement (production ties it to READ-capable QPs).
        config.source_pull = self.placement;
        let parts = open_nvme(self.mount(0)).unwrap();
        let mut o0 = Osd::<B>::control(config.clone(), parts.meta, parts.pgs, spec(0)).unwrap();
        let (id, sb) = (o0.identity().clone(), o0.superblock().clone());
        let mut osds = vec![];
        let ingress = crate::input_credits(self.shards);
        o0.set_ingress_credits(ingress.clone());
        o0.start(self.t);
        o0.state = State::Booting;
        osds.push(o0);
        for c in 1..self.n {
            let pg = open_nvme_pgs(self.mount(c)).unwrap();
            let mut o =
                Osd::<B>::worker(config.clone(), id.clone(), sb.clone(), pg, spec(c)).unwrap();
            o.set_ingress_credits(ingress.clone());
            o.start(self.t);
            osds.push(o);
        }
        self.osds = osds;
        self.settle();
    }

    /// Crash-style restart: drop every core (nothing flushed beyond what was acked), mount again.
    fn restart(&mut self) {
        self.osds.clear();
        self.epoch = 0;
        self.boot();
    }

    fn with_helpers(n: usize) -> Mc {
        let mut mc = Mc::new(n);
        mc.helpers = true;
        mc.restart();
        mc
    }

    /// [`Self::restart`] with another core count (adr 0160: the store keeps its shards, PGs follow shard % cores).
    fn restart_with_cores(&mut self, n: usize) {
        self.osds.clear();
        self.n = n;
        self.epoch = 0;
        self.boot();
    }

    /// Move cross-core messages, reap store commits, run due timers; until nothing moves.
    fn settle(&mut self) {
        let mut quiet = 0;
        for _ in 0..100_000 {
            let mut progress = false;
            for i in 0..self.n {
                progress |= self.osds[i].resume_inputs(self.t);
                while let Some((dst, m)) = self.osds[i].poll_xmsg() {
                    progress = true;
                    if self.lose.is_some_and(|f| f(dst, &m)) {
                        continue;
                    }
                    if self.delay.is_some_and(|f| f(dst, &m)) {
                        self.delayed.push((i, dst, m));
                        continue;
                    }
                    let t = self.t;
                    self.osds[dst].on_xmsg_send_first(i, m, t);
                    self.osds[dst].apply_late(); // as `rt::XPort` (the outbox moves on with the next poll)
                }
                if self.osds[i].poll_store(self.t) {
                    progress = true;
                }
            }
            if progress {
                quiet = 0;
                continue;
            }
            quiet += 1;
            if quiet > 3 && self.disk.inflight() == 0 {
                return;
            }
            // nothing to do now: let simulated time pass (device completions, timers)
            self.t += Duration::from_millis(1);
            for o in &mut self.osds {
                o.pg.store.with_store(|s| s.idle());
                if o.next_timer().is_some_and(|d| d <= self.t) {
                    o.on_timer(self.t);
                }
            }
        }
        panic!("simulation did not settle");
    }

    /// Deliver what the `delay` hook held back (in order) and go on without delaying.
    fn release_delayed(&mut self) {
        self.delay = None;
        let t = self.t;
        for (from, dst, m) in std::mem::take(&mut self.delayed) {
            self.osds[dst].on_xmsg(from, m, t);
        }
        self.settle();
    }

    /// Advance virtual time by `d`, settling after each step.
    fn run_for(&mut self, d: Duration) {
        let end = self.t + d;
        while self.t < end {
            self.t += Duration::from_millis(100);
            for o in &mut self.osds {
                if o.next_timer().is_some_and(|x| x <= self.t) {
                    o.on_timer(self.t);
                }
            }
            self.settle();
        }
    }

    /// The map of the test: the real lab map reduced to osd.0 (size 1 pools `1` and `4`, plus `extra` pools).
    fn map(&self, epoch: u32, up_from: u32) -> OsdMap {
        let mut m = real_map();
        m.epoch = epoch;
        m.pools.retain(|id, _| matches!(id, 1 | 4));
        m.pool_name.retain(|id, _| matches!(id, 1 | 4));
        for p in m.pools.values_mut() {
            p.size = 1;
            p.min_size = 1;
        }
        if let Some(p) = m.pools.get_mut(&4) {
            p.pg_num = self.pool4;
            p.pgp_num = self.pool4;
            p.pg_num_pending = self.pool4;
            p.pg_num_target = self.pool4;
            if self.ec4 {
                p.ptype = osdmap::pool::TYPE_ERASURE;
                p.size = 3;
                p.min_size = 2;
                p.stripe_width = 8192;
                p.erasure_code_profile = "mig".into();
                p.flags &= !osdmap::pool::flags::OMAP;
                p.flags |= osdmap::pool::flags::EC_OVERWRITES;
            }
        }
        if self.ec4 {
            let prof = [
                ("plugin", "isa"),
                ("technique", "reed_sol_van"),
                ("k", "2"),
                ("m", "1"),
            ];
            m.erasure_code_profiles.insert(
                "mig".into(),
                prof.iter()
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .collect(),
            );
        }
        m.osd_state = vec![
            osd_state::EXISTS | osd_state::UP,
            osd_state::EXISTS,
            osd_state::EXISTS,
        ];
        m.osd_weight = vec![0x10000, 0, 0];
        m.require_osd_release = release::UMBRELLA;
        m.osd_uuid = vec![Uuid([9; 16]); 3];
        let o = &self.osds[0];
        m.client_addrs[0] = o.public_addrs.clone();
        m.cluster_addrs[0] = o.cluster_addrs.clone();
        m.hb_back_addrs[0] = o.hb_back_addrs.clone();
        m.hb_front_addrs[0] = o.hb_front_addrs.clone();
        for (i, inf) in m.osd_info.iter_mut().enumerate() {
            inf.up_from = if i == 0 { up_from } else { 1 };
            inf.up_thru = epoch;
            inf.down_at = 0;
        }
        m
    }

    /// The mon sends `map` (full map message) to core 0.
    fn deliver(&mut self, map: OsdMap) {
        let e = map.epoch;
        let blob = map.encode_full().unwrap();
        let msg = MOSDMap {
            fsid: self.fsid,
            incremental_maps: BTreeMap::new(),
            maps: BTreeMap::from([(e, blob)]),
            cluster_osdmap_trim_lower_bound: 1,
            newest_map: e,
        };
        self.epoch = e;
        let o = &mut self.osds[0];
        o.mc.set_osdmap(map.clone());
        o.on_osdmap_event(Arc::new(map), &msg);
        self.settle();
    }

    /// A fake authenticated client connection accepted on `core`'s public listener.
    fn client(&mut self, core: usize) -> u64 {
        let name = EntityName::client(4100 + i64::from(self.next_port + 1));
        self.client_as(core, name)
    }

    /// [`Self::client`] with a given entity name (e.g. another OSD acting as a client).
    fn client_as(&mut self, core: usize, name: EntityName) -> u64 {
        self.client_with(core, name, "allow *")
    }

    /// [`Self::client`] whose session holds the caps text `caps` (e.g. a read-only client).
    fn client_caps(&mut self, core: usize, caps: &str) -> u64 {
        let name = EntityName::client(4100 + i64::from(self.next_port + 1));
        self.client_with(core, name, caps)
    }

    fn client_with(&mut self, core: usize, name: EntityName, caps: &str) -> u64 {
        self.next_port += 1;
        let port = self.next_port;
        let ip = [10, 9, 0, 1 + core as u8];
        let t = self.t;
        let o = &mut self.osds[core];
        let id = o.on_accept(Listener::Public, crate::osd::sock4(ip, port), t);
        let caps = Arc::new(Caps::parse(caps).unwrap_or_else(|e| panic!("{caps}: {e}")));
        let l = o.links.get_mut(&id).unwrap();
        l.peer = Some(msgr2::PeerInfo {
            name,
            addrs: addr(ip, port, 1),
            features: u64::MAX,
            lossy: true,
            resumed: false,
            global_id: 1,
            auth_name: None,
        });
        l.caps = Some(caps.clone());
        l.info = Some(Arc::new(ConnInfo {
            who: name,
            features: u64::MAX,
            addr: EntityAddr::v4(EntityAddr::TYPE_MSGR2, 1, ip, port),
            peer_addr: EntityAddr::v4(EntityAddr::TYPE_MSGR2, 1, ip, port),
            caps: Some(caps),
        }));
        id
    }

    /// MOSDOp for object `oid` in `pool` against the current map.
    fn op(&self, pool: i64, oid: &str, ops: Vec<OsdOp>) -> MOSDOp {
        let map = self.osds[0].osdmap().unwrap();
        let raw = map
            .object_to_raw_pg(pool, oid.as_bytes(), b"", b"", -1)
            .unwrap();
        let n = map.pool(pool).unwrap().pg_num;
        let pg = PgT::new(pool as u64, pgwire::pgmath::object_pg(raw.seed, n));
        let write = ops.iter().any(|o| o.op & 0x2000 != 0);
        let mut flags = opwire::flag::ONDISK | opwire::flag::KNOWN_REDIR;
        flags |= if write {
            opwire::flag::WRITE
        } else {
            opwire::flag::READ
        };
        MOSDOp {
            pgid: SpgT {
                pgid: pg,
                shard: denc::types::ShardId::NO_SHARD,
            },
            hash: raw.seed,
            osdmap_epoch: map.epoch,
            flags,
            oloc: denc::types::ObjectLocator {
                pool,
                key: vec![],
                nspace: vec![],
                hash: -1,
            },
            oid: oid.as_bytes().to_vec(),
            ops,
            mtime: denc::types::UTime::new(1_700_000_001, 5),
            ..Default::default()
        }
    }

    /// Client on `core`/`link` sends `op`; settles; returns the replies that went out on that link.
    fn call(&mut self, core: usize, link: u64, tid: u64, op: MOSDOp) -> Vec<(u64, MOSDOpReply)> {
        let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
        let t = self.t;
        self.osds[core].set_now(t);
        self.osds[core].on_unknown_message(link, tid, ty, ver, &segs);
        self.settle();
        self.replies(core, link)
    }

    /// Replies queued on `link` of `core` since the last call.
    fn replies(&mut self, core: usize, link: u64) -> Vec<(u64, MOSDOpReply)> {
        let out = std::mem::take(&mut self.osds[core].t.out);
        let mut mine = Vec::new();
        let mut keep = Vec::new();
        for f in out {
            if f.0 == link {
                mine.push(f);
            } else {
                keep.push(f);
            }
        }
        self.osds[core].t.out = keep;
        mine.into_iter()
            .filter_map(|(_, tid, (ty, ver, _), segs)| {
                match opwire::decode_client(ty, ver, &segs) {
                    Ok(ClientMsg::OpReply(r)) => Some((tid, r)),
                    _ => None,
                }
            })
            .collect()
    }

    /// PGs per core: `(pool, seed)` lists, sorted.
    fn pgs(&self) -> Vec<Vec<(u64, u32)>> {
        self.osds
            .iter()
            .map(|o| {
                let mut v: Vec<(u64, u32)> =
                    o.pg.set
                        .pgs()
                        .map(|(s, _)| (s.pgid.pool, s.pgid.seed))
                        .collect();
                v.sort_unstable();
                v
            })
            .collect()
    }

    /// Core owning `(pool, seed)`.
    fn owner(&self, pool: u64, seed: u32) -> usize {
        peering::pg_core(pool, seed, self.n as u32, self.shards)
    }

    /// The mon asks the primary (core 0 receives it on the mon session) to create PGs `seeds` of `pool`.
    fn create_pgs(&mut self, pool: u64, seeds: impl IntoIterator<Item = u32>) {
        self.create_pgs_at(pool, seeds, self.epoch, self.epoch);
    }

    /// [`Self::create_pgs`] with the message epoch `msg_epoch` (may be ahead of ours) and the PGs' creation epoch `e`.
    fn create_pgs_at(
        &mut self,
        pool: u64,
        seeds: impl IntoIterator<Item = u32>,
        msg_epoch: u32,
        e: u32,
    ) {
        let mut m = pgwire::MOSDPGCreate2 {
            epoch: msg_epoch,
            ..Default::default()
        };
        let map = self.osds[0].osdmap().cloned();
        for seed in seeds {
            // EC pool: the PG instance of this OSD is the shard it holds in the acting set
            let mut shard = denc::types::ShardId::NO_SHARD;
            if let Some(m) = map.as_ref()
                && m.pool(pool as i64).is_some_and(|p| p.is_erasure())
                && let Some(i) = m
                    .pg_to_up_acting(PgT::new(pool, seed))
                    .acting
                    .iter()
                    .position(|&o| o == self.whoami)
            {
                shard = denc::types::ShardId(i as i8);
            }
            let s = SpgT {
                pgid: PgT::new(pool, seed),
                shard,
            };
            m.pgs.insert(s, (e, denc::types::UTime::new(1, 0)));
            m.pg_extra.insert(
                s,
                (
                    pgwire::PgHistory::new_pg(e, denc::types::UTime::new(1, 0)),
                    pgwire::PastIntervals::default(),
                ),
            );
        }
        let (ty, ver, _c, segs) = peering::Body::Peering(m.into()).encode(u64::MAX).unwrap();
        let t = self.t;
        self.osds[0].set_now(t);
        assert!(self.osds[0].pg_on_mon_unknown(ty, ver, &segs));
        self.settle();
    }

    /// Bring the OSD up (map epoch 10), create the PGs of the pools and let them peer.
    fn up(&mut self) {
        let m = self.map(10, 10);
        self.deliver(m);
        for p in [1u64, 4] {
            let n = self.osds[0]
                .osdmap()
                .unwrap()
                .pool(p as i64)
                .unwrap()
                .pg_num;
            self.create_pgs(p, 0..n);
        }
        self.run_for(Duration::from_secs(3));
    }
}

/// peering.md 7.3 rule 3a wiring: at the hard limit (`mon_max_pg_per_osd` x `osd_max_pg_per_osd_hard_ratio`, all cores
/// counted) mon creates are withheld and reported as `PENDING_CREATING_PGS`; once the operator raises the limit, the
/// next tick asks the mon for its creates again (a worker core through the control core) and they are created.
#[test]
fn pg_hard_limit_withholds_creates_reports_them_and_resolicits() {
    let mut mc = Mc::new(2);
    let set = |mc: &mut Mc, k: &str, v: &str| {
        for o in &mut mc.osds {
            o.conf.set(crate::config::Level::Override, k, v).unwrap();
            o.conf_changed();
        }
    };
    // the control core's 1 s tick (the harness never finishes the mon init that gates it): OSD-wide PG count, then
    // the PG tick; the worker cores tick in `run_for`
    let tick = |mc: &mut Mc| {
        mc.run_for(Duration::from_secs(1));
        mc.osds[0].pg_sync_num_pgs();
        mc.osds[0].pg_tick();
        mc.settle();
    };
    set(&mut mc, "mon_max_pg_per_osd", "2");
    set(&mut mc, "osd_max_pg_per_osd_hard_ratio", "1");
    let m = mc.map(10, 10);
    mc.deliver(m);
    let n = mc.osds[0].osdmap().unwrap().pool(4).unwrap().pg_num;
    assert!(n > 4, "{n}");
    let total = |mc: &Mc| mc.pgs().iter().map(Vec::len).sum::<usize>();
    let pending = |mc: &Mc| mc.osds[0].health_metrics()[1].value;
    mc.create_pgs(4, 0..2);
    tick(&mut mc);
    assert_eq!(total(&mc), 2);
    // every core counts the PGs of all cores: the rest is withheld on whichever core owns it
    mc.create_pgs(4, 2..n);
    tick(&mut mc);
    assert_eq!(total(&mc), 2, "{:?}", mc.pgs());
    assert_eq!(pending(&mc), u64::from(n - 2));
    assert!(
        mc.osds
            .iter()
            .all(|o| o.t.subs.iter().all(|s| s.0 != "osd_pg_creates"))
    );
    set(&mut mc, "mon_max_pg_per_osd", "500");
    tick(&mut mc);
    tick(&mut mc);
    assert_eq!(pending(&mc), 0);
    assert!(
        mc.osds[0]
            .t
            .subs
            .iter()
            .any(|s| *s == ("osd_pg_creates".to_string(), 10, 0)),
        "{:?}",
        mc.osds[0].t.subs
    );
    // the mon answers with its creates again
    mc.create_pgs(4, 0..n);
    assert_eq!(total(&mc), n as usize);
}

#[test]
fn map_requests_are_deduplicated_per_epoch_never_repeated_by_time() {
    // classic `sub_want_increment`: asking again for an epoch already asked for is a no-op however long ago it went out
    // (the MonClient keeps the subscription and replays it with a new session); a newer epoch is asked for at once
    let mut mc = Mc::new(2);
    mc.up();
    let have = mc.osds[0].epoch();
    let asked = |mc: &Mc, start: u32| {
        mc.osds[0]
            .t
            .subs
            .iter()
            .filter(|s| s.0 == "osdmap" && s.1 == u64::from(start))
            .count()
    };
    let before = asked(&mc, have + 1);
    mc.osds[1].pg_request_map(have);
    mc.settle();
    mc.osds[0].pg_request_map(have);
    mc.osds[1].pg_request_map(have);
    mc.settle();
    assert_eq!(asked(&mc, have + 1), before + 1, "one request per epoch");
    mc.run_for(Duration::from_secs(5));
    mc.osds[0].pg_request_map(have);
    mc.osds[1].pg_request_map(have);
    mc.osds[1].pg_request_map(have - 1);
    mc.settle();
    assert_eq!(
        asked(&mc, have + 1),
        before + 1,
        "nothing asked again by time"
    );
    let newer = asked(&mc, have + 2);
    mc.osds[1].pg_request_map(have + 1);
    mc.settle();
    assert_eq!(
        asked(&mc, have + 2),
        newer + 1,
        "a newer epoch is asked for"
    );
}

#[test]
fn pgs_spread_over_cores_by_shard() {
    let mut mc = Mc::new(4);
    mc.up();
    assert_eq!(
        mc.osds[0].state,
        State::Active,
        "log: {:?}",
        mc.osds[0].logs
    );
    assert!(mc.osds.iter().all(|o| o.state == State::Active));
    let pgs = mc.pgs();
    // 2 pools x 32 PGs, every PG exactly on its owner core, all cores used
    assert_eq!(pgs.iter().map(Vec::len).sum::<usize>(), 64);
    for (c, v) in pgs.iter().enumerate() {
        assert!(!v.is_empty(), "core {c} has no PG");
        for (pool, seed) in v {
            assert_eq!(mc.owner(*pool, *seed), c);
        }
    }
    // every PG is active+clean (size 1)
    for o in &mc.osds {
        for (_, s) in o.pg.set.pg_states() {
            assert!(s.contains("active"), "{s}");
        }
    }
}

/// Two OSDs (osd.0 with `na` cores, osd.1 with `nb` cores) wired by moving their cluster-link frames; size 2 pools.
struct Pair {
    a: Mc,
    b: Mc,
    /// Accepted fake cluster links: (receiver whoami, sender whoami, core) -> link id.
    acc: BTreeMap<(i32, i32, usize), u64>,
    /// Client links of one OSD to the other (source reads of copy-from): `(sender, sender core, sender link)` ->
    /// `(receiver core, accepted link)`, and the way back `(receiver, receiver core, accepted link)` -> sender side.
    cl_fwd: BTreeMap<(i32, usize, u64), (usize, u64)>,
    cl_back: BTreeMap<(i32, usize, u64), (i32, usize, u64)>,
    /// Receiver core of each sending cluster link `(sender, sender core, link)`: a msgr2 connection lives on one core,
    /// so all its frames arrive there in order (Ceph orders messages per connection); new links spread round robin.
    wire_core: BTreeMap<(i32, usize, u64), usize>,
    rr: usize,
    frames: u64,
    held_peer: VecDeque<(i32, usize, u64, u64, u16, u16, messages::Segments)>,
    /// Repops reach the receiver through a msgr2 decoder with pre-write, scanned like a link (prewrite_tests.rs).
    pre_wire: bool,
}

impl Pair {
    fn new(na: usize, nb: usize) -> Pair {
        Pair::of(Mc::with(0, na), Mc::with(1, nb))
    }

    fn of(a: Mc, b: Mc) -> Pair {
        Pair {
            a,
            b,
            acc: BTreeMap::new(),
            cl_fwd: BTreeMap::new(),
            cl_back: BTreeMap::new(),
            wire_core: BTreeMap::new(),
            rr: 0,
            frames: 0,
            held_peer: VecDeque::new(),
            pre_wire: false,
        }
    }

    /// Client-link traffic: mark dialed client links up, carry their requests to the other OSD's public side (as an
    /// accepted `osd.N` session) and the answers back.
    fn exchange_clients(&mut self) -> bool {
        let mut moved = false;
        for who in [0i32, 1] {
            let x = self.node(who);
            for o in x.osds.iter_mut() {
                for (osd, link) in o.pg.cp.unready() {
                    if let Some(l) = o.links.get_mut(&link) {
                        l.peer = Some(msgr2::PeerInfo {
                            name: EntityName::osd(i64::from(osd)),
                            addrs: EntityAddrVec::default(),
                            features: u64::MAX,
                            lossy: true,
                            resumed: false,
                            global_id: 1,
                            auth_name: None,
                        });
                    }
                    o.copy_link_ready(osd, link);
                    moved = true;
                }
            }
        }
        for from in [0i32, 1] {
            let to = 1 - from;
            let back: std::collections::BTreeSet<_> = self.cl_back.keys().copied().collect();
            let mut reqs = Vec::new();
            let mut answers = Vec::new();
            {
                let x = self.node(from);
                for (c, o) in x.osds.iter_mut().enumerate() {
                    let out = std::mem::take(&mut o.t.out);
                    for f in out {
                        match o.links.get(&f.0).map(|l| l.purpose) {
                            Some(crate::osd::Purpose::Copy(_)) => reqs.push((c, f)),
                            Some(crate::osd::Purpose::Accepted)
                                if back.contains(&(from, c, f.0)) =>
                            {
                                answers.push((c, f))
                            }
                            _ => o.t.out.push(f),
                        }
                    }
                }
            }
            for (c, (link, tid, (ty, ver, _), segs)) in reqs {
                moved = true;
                let (rc, rl) = match self.cl_fwd.get(&(from, c, link)) {
                    Some(x) => *x,
                    None => {
                        self.rr += 1;
                        let rc = self.rr % self.node(to).n;
                        let rl = self
                            .node(to)
                            .client_as(rc, EntityName::osd(i64::from(from)));
                        self.cl_fwd.insert((from, c, link), (rc, rl));
                        self.cl_back.insert((to, rc, rl), (from, c, link));
                        (rc, rl)
                    }
                };
                let y = self.node(to);
                let t = y.t;
                y.osds[rc].set_now(t);
                y.osds[rc].on_unknown_message(rl, tid, ty, ver, &segs);
            }
            for (c, (link, tid, (ty, ver, compat), segs)) in answers {
                moved = true;
                let (sf, sc, sl) = self.cl_back[&(from, c, link)];
                let x = self.node(sf);
                let t = x.t;
                x.osds[sc].set_now(t);
                x.osds[sc].on_link_message(
                    sl,
                    crate::osd::Purpose::Copy(from),
                    tid,
                    messages::AnyMessage::Unknown {
                        ty,
                        version: ver,
                        compat,
                        segments: segs,
                    },
                );
            }
        }
        moved
    }

    /// Both OSDs know the other as croit-flashstore-osd (metadata answer): sender credits (switched on here, default off)
    /// and the unpaused receive path apply.
    fn flashstore(&mut self) {
        for who in [0i32, 1] {
            for o in &mut self.node(who).osds {
                o.conf
                    .set(
                        crate::config::Level::Override,
                        "flashstore_repop_credit",
                        "true",
                    )
                    .unwrap();
                o.pg.peer_nv = BTreeSet::from([1 - who]);
                let _ = o.pg.set.set_flashstore_peers(o.pg.peer_nv.clone());
            }
        }
    }

    fn node(&mut self, who: i32) -> &mut Mc {
        if who == 0 { &mut self.a } else { &mut self.b }
    }

    fn map(&self, epoch: u32, up_from: [u32; 2]) -> OsdMap {
        let mut m = real_map();
        m.epoch = epoch;
        m.pools.retain(|id, _| matches!(id, 1 | 4));
        m.pool_name.retain(|id, _| matches!(id, 1 | 4));
        for p in m.pools.values_mut() {
            p.size = 2;
            p.min_size = 1;
        }
        m.osd_state = vec![
            osd_state::EXISTS | osd_state::UP,
            osd_state::EXISTS | osd_state::UP,
            osd_state::EXISTS,
        ];
        m.osd_weight = vec![0x10000, 0x10000, 0];
        m.require_osd_release = release::UMBRELLA;
        m.osd_uuid = vec![Uuid([9; 16]); 3];
        for (i, n) in [&self.a, &self.b].into_iter().enumerate() {
            let o = &n.osds[0];
            m.client_addrs[i] = o.public_addrs.clone();
            m.cluster_addrs[i] = o.cluster_addrs.clone();
            m.hb_back_addrs[i] = o.hb_back_addrs.clone();
            m.hb_front_addrs[i] = o.hb_front_addrs.clone();
        }
        for (i, inf) in m.osd_info.iter_mut().enumerate() {
            inf.up_from = up_from.get(i).copied().unwrap_or(1);
            inf.up_thru = epoch;
            inf.down_at = 0;
        }
        m
    }

    fn deliver(&mut self, m: OsdMap) {
        self.a.deliver(m.clone());
        self.b.deliver(m);
        self.settle();
    }

    /// Move peer frames between the nodes: each frame lands on the next core of the receiver (round robin), as if a
    /// flow of the peer's link had been steered there. True if any frame moved.
    fn exchange(&mut self) -> bool {
        let mut moved = false;
        let mut blocked = BTreeSet::new();
        for _ in 0..self.held_peer.len() {
            let (to, core, link, tid, ty, ver, segs) = self.held_peer.pop_front().unwrap();
            let y = self.node(to);
            let t = y.t;
            if !y.osds[core].links.contains_key(&link) {
                continue;
            }
            if blocked.contains(&(to, core, link)) || !y.osds[core].input_ready(link) {
                blocked.insert((to, core, link));
                self.held_peer
                    .push_back((to, core, link, tid, ty, ver, segs));
            } else {
                y.osds[core].on_unknown_message(link, tid, ty, ver, &segs);
                y.osds[core].set_now(t);
                moved = true;
            }
        }
        // accepted cluster links answer the peer that dialed them (it may use them for its own sends, see peer_transmit)
        let accepted: BTreeMap<(i32, usize, u64), i32> = self
            .acc
            .iter()
            .map(|(&(r, s, c), &l)| ((r, c, l), s))
            .collect();
        for from in [0i32, 1] {
            let mut frames = Vec::new();
            {
                let x = self.node(from);
                for (c, o) in x.osds.iter_mut().enumerate() {
                    let out = std::mem::take(&mut o.t.out);
                    for f in out {
                        match o.links.get(&f.0).map(|l| l.purpose) {
                            Some(crate::osd::Purpose::Peer(to)) => frames.push((to, c, f)),
                            Some(crate::osd::Purpose::Accepted)
                                if let Some(&to) = accepted.get(&(from, c, f.0)) =>
                            {
                                frames.push((to, c, f))
                            }
                            _ => o.t.out.push(f),
                        }
                    }
                }
            }
            for (to, sc, (sl, tid, (ty, ver, _), segs)) in frames {
                moved = true;
                self.frames += 1;
                let n = self.node(to).n;
                let core = match self.wire_core.get(&(from, sc, sl)) {
                    Some(&c) => c,
                    None => {
                        self.rr += 1;
                        let c = self.rr % n;
                        self.wire_core.insert((from, sc, sl), c);
                        c
                    }
                };
                let y = self.node(to);
                let t = y.t;
                let key = (to, from, core);
                // an accepted link the receiver closed meanwhile (stale incarnation) is accepted anew
                let live = self
                    .acc
                    .get(&key)
                    .copied()
                    .filter(|l| self.node(to).osds[core].links.contains_key(l));
                let link = match live {
                    Some(l) => l,
                    None => {
                        let y = self.node(to);
                        let ip = [10, 1, 0, 4 + from as u8];
                        let l = y.osds[core].on_accept(
                            Listener::Cluster,
                            crate::osd::sock4(ip, 41000),
                            t,
                        );
                        y.osds[core].links.get_mut(&l).unwrap().peer = Some(msgr2::PeerInfo {
                            name: EntityName::osd(i64::from(from)),
                            addrs: addr(ip, 6801, 555 + from as u32),
                            features: u64::MAX,
                            lossy: false,
                            resumed: false,
                            global_id: 1,
                            auth_name: None,
                        });
                        self.acc.insert(key, l);
                        l
                    }
                };
                let held = self
                    .held_peer
                    .iter()
                    .any(|f| (f.0, f.1, f.2) == (to, core, link));
                let pre_wire = self.pre_wire;
                let y = self.node(to);
                y.osds[core].set_now(t);
                let segs = if pre_wire && ty == replwire::ty::REPOP {
                    prewrite_tests::receive_on(&mut y.osds[core], tid, ty, ver, &segs)
                } else {
                    segs
                };
                if held || !y.osds[core].input_ready(link) {
                    self.held_peer
                        .push_back((to, core, link, tid, ty, ver, segs));
                } else {
                    y.osds[core].on_unknown_message(link, tid, ty, ver, &segs);
                }
            }
        }
        moved
    }

    fn settle(&mut self) {
        for _ in 0..10_000 {
            self.a.settle();
            self.b.settle();
            let peers = self.exchange();
            let clients = self.exchange_clients();
            if !peers && !clients {
                return;
            }
        }
        panic!("pair did not settle");
    }

    fn run_for(&mut self, d: Duration) {
        let end = self.a.t + d;
        while self.a.t < end {
            for n in [&mut self.a, &mut self.b] {
                n.t += Duration::from_millis(100);
                let t = n.t;
                for o in &mut n.osds {
                    if o.next_timer().is_some_and(|x| x <= t) {
                        o.on_timer(t);
                    }
                }
            }
            self.settle();
        }
    }

    /// Create every PG of `pool` at the primary the map gives it.
    fn create_pool_pgs(&mut self, pool: u64) {
        let map = self.a.osds[0].osdmap().unwrap().clone();
        let n = map.pool(pool as i64).unwrap().pg_num;
        let mut by: [Vec<u32>; 2] = [vec![], vec![]];
        for seed in 0..n {
            let m = map.pg_to_up_acting(PgT::new(pool, seed));
            by[m.acting_primary as usize].push(seed);
        }
        for (who, seeds) in by.into_iter().enumerate() {
            if !seeds.is_empty() {
                self.node(who as i32).create_pgs(pool, seeds);
            }
        }
        self.settle();
    }

    fn up(&mut self) {
        let m = self.map(10, [10, 10]);
        self.deliver(m);
        for p in [1u64, 4] {
            self.create_pool_pgs(p);
        }
        self.run_for(Duration::from_secs(5));
    }
}

#[test]
fn replicated_pgs_across_cores_of_two_osds() {
    let mut p = Pair::new(4, 2);
    p.up();
    assert!(
        p.a.osds
            .iter()
            .chain(&p.b.osds)
            .all(|o| o.state == State::Active)
    );
    // all 64 PGs exist on both OSDs, active, each on its owner core
    for (who, n) in [(0, &p.a), (1, &p.b)] {
        let pgs = n.pgs();
        assert_eq!(pgs.iter().map(Vec::len).sum::<usize>(), 64, "osd.{who}");
        for (c, v) in pgs.iter().enumerate() {
            for (pool, seed) in v {
                assert_eq!(
                    peering::pg_core(*pool, *seed, n.n as u32, S),
                    c,
                    "osd.{who} pg {pool}.{seed}"
                );
            }
        }
        for o in &n.osds {
            for (spg, s) in o.pg.set.pg_states() {
                assert!(s.contains("active"), "osd.{who} {spg} {s}");
            }
        }
    }
    // writes through the primary's clients; the replica must hold the data
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let mut checked = 0;
    for i in 0..48usize {
        let name = format!("rep{i}");
        let raw = map
            .object_to_raw_pg(1, name.as_bytes(), b"", b"", -1)
            .unwrap();
        let pg = PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32));
        let primary = map.pg_to_up_acting(pg).acting_primary;
        let (pn, rn) = if primary == 0 {
            (&mut p.a, 1)
        } else {
            (&mut p.b, 0)
        };
        let core = i % pn.n;
        let cl = pn.client(core);
        let data = vec![(i % 200) as u8 + 1; 8192];
        let op = pn.op(1, &name, vec![OsdOp::writefull(data.clone())]);
        let r = pn.call(core, cl, 1, op);
        assert!(r.is_empty(), "no ack before the replica answered?");
        p.settle();
        let pn = p.node(primary);
        let r = pn.replies(core, cl);
        assert_eq!(r.len(), 1, "write {i} unanswered");
        assert_eq!(r[0].1.result, 0);
        // the replica's store has the object
        let spg = SpgT {
            pgid: pg,
            shard: denc::types::ShardId::NO_SHARD,
        };
        let rn = p.node(rn);
        let oc = peering::pg_core(1, pg.seed, rn.n as u32, S);
        let mut h = denc::types::Hobject::new(
            name.as_bytes(),
            denc::types::SnapId::NOSNAP,
            raw.seed,
            1,
            b"",
        );
        h.set_key(b"");
        let got = opexec::ObjView::ov_read(&rn.osds[oc].pg.store, spg, &h, 0, 8192).unwrap();
        assert_eq!(got, data, "replica copy of {name}");
        // the store-derived msgr2 data crc (reply hint) equals a pass over the bytes
        let (d2, crc) =
            opexec::ObjView::ov_read_crc(&rn.osds[oc].pg.store, spg, &h, 0, 8192).unwrap();
        assert_eq!(d2, data);
        assert_eq!(crc, Some(crc::crc32c(!0, &data)), "read crc hint of {name}");
        checked += 1;
    }
    assert_eq!(checked, 48);
    // traffic really crossed cores on both sides
    let fwd_pg: u64 = p.a.osds.iter().chain(&p.b.osds).map(|o| o.cl.fwd_pg).sum();
    let fwd_tx: u64 =
        p.a.osds
            .iter()
            .chain(&p.b.osds)
            .map(|o| o.cl.fwd_peer_tx)
            .sum();
    assert!(fwd_pg > 0 && fwd_tx > 0, "{fwd_pg} {fwd_tx}");
    // perf counters: every write is one client op on its primary and one sub-op (with latency) on the replica
    let sum = |f: fn(&crate::perf::OpPerf) -> u64| -> u64 {
        p.a.osds
            .iter()
            .chain(&p.b.osds)
            .map(|o| f(&o.perf.op))
            .sum()
    };
    assert_eq!(sum(|c| c.op_w), 48);
    assert_eq!(sum(|c| c.subop_w), 48);
    assert_eq!(sum(|c| c.subop_w_lat.n), 48);
    assert!(sum(|c| c.subop_w_in) > 48 * 8192);
}

/// Live hang (adr 0084 am. 2; rented 3x1 OSD, rados bench 4M rep3): the primary's client writes of one
/// physical shard hold that shard's whole input window while they wait for replica acks; the peer's repop for another
/// PG of the same shard then cannot be admitted, the peer link pauses with it at the head, and the acks the client
/// writes wait for queue behind it on the same stream. Peer data must not depend on capacity that waits on the peer.
fn client_writes_filling_a_shard_window(nv: bool) {
    // WAL room for 16 x 4 MiB in flight
    let mut p = Pair::of(Mc::with_wal(0, 1, 65536), Mc::with_wal(1, 1, 65536));
    p.up();
    if nv {
        p.flashstore();
    }
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let pg_of = |n: &str| {
        let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
        PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32))
    };
    let shard_a = |pg: PgT| p.a.osds[0].input_shard(pg);
    // a PG of osd.0 and one of osd.1, both on the same physical shard of osd.0
    let pa = (0..32)
        .map(|s| PgT::new(1, s))
        .find(|&pg| map.pg_to_up_acting(pg).acting_primary == 0)
        .unwrap();
    let pb = (0..32)
        .map(|s| PgT::new(1, s))
        .find(|&pg| map.pg_to_up_acting(pg).acting_primary == 1 && shard_a(pg) == shard_a(pa))
        .unwrap();
    let names = |pg: PgT, n: usize| -> Vec<String> {
        (0..)
            .map(|i| format!("o{i}"))
            .filter(|s| pg_of(s) == pg)
            .take(n)
            .collect()
    };
    let data = vec![5u8; 4 << 20];
    // 15 x 4 MiB writes to osd.0 (shard window: 64 MiB); their repops wait in osd.0's outbox
    let ca = p.a.client(0);
    for (i, n) in names(pa, 15).iter().enumerate() {
        let op = p.a.op(1, n, vec![OsdOp::writefull(data.clone())]);
        assert!(p.a.call(0, ca, 1 + i as u64, op).is_empty());
    }
    // one 4 MiB write to osd.1 whose repop reaches osd.0 before osd.1's acks of the 15 repops
    let cb = p.b.client(0);
    let n = &names(pb, 1)[0];
    let op = p.b.op(1, n, vec![OsdOp::writefull(data.clone())]);
    assert!(p.b.call(0, cb, 1, op).is_empty());
    p.settle();
    p.run_for(Duration::from_secs(30));
    let ra = p.a.replies(0, ca);
    let rb = p.b.replies(0, cb);
    assert_eq!(ra.len(), 15, "osd.0 writes acked");
    assert!(ra.iter().all(|r| r.1.result == 0));
    assert_eq!(rb.len(), 1, "osd.1 write acked");
    assert_eq!(rb[0].1.result, 0);
    if nv {
        // the credits really held writes back, and every credit came back
        assert!(
            p.a.osds[0]
                .pg
                .c
                .link_events
                .get("repop_credit_wait")
                .copied()
                .unwrap_or(0)
                > 0
        );
        assert!(p.a.osds[0].pg.flow.idle() && p.b.osds[0].pg.flow.idle());
    }
}

#[test]
fn client_writes_filling_a_shard_window_never_block_peer_acks_behind_a_peer_repop() {
    client_writes_filling_a_shard_window(false);
}

/// Same, between croit-flashstore-osd peers: the primary paces its repops (adr 0084 am. 3), the replica never pauses the link.
#[test]
fn client_writes_filling_a_shard_window_with_repop_credits() {
    client_writes_filling_a_shard_window(true);
}

/// One shard of the replica (osd.1) is congested (its store admits nothing for that shard): osd.0 writes 4 PGs of that
/// shard and one PG of another shard. Returns (acked other-shard writes, acked congested-shard writes) while the shard
/// is congested for 3 s, then the same after it recovered, and the replica's store-cause input holds.
fn congested_replica_shard(nv: bool) -> ([(usize, usize); 2], crate::utilization::HoldStat) {
    let mut p = Pair::new(1, 1);
    p.up();
    if nv {
        p.flashstore();
    }
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let pg_of = |n: &str| {
        let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
        PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32))
    };
    let primaries: Vec<(PgT, u32)> = (0..32)
        .map(|s| PgT::new(1, s))
        .filter(|&pg| map.pg_to_up_acting(pg).acting_primary == 0)
        .map(|pg| (pg, p.b.osds[0].input_shard(pg) as u32))
        .collect();
    let (px, sx) = primaries[0];
    let (py, _) = *primaries.iter().find(|(_, s)| *s != sx).unwrap();
    let names = |pg: PgT, n: usize| -> Vec<String> {
        (0..)
            .map(|i| format!("o{i}"))
            .filter(|s| pg_of(s) == pg)
            .take(n)
            .collect()
    };
    p.b.osds[0].pg.store.deny_admission_shard.set(Some(sx));
    let ca = p.a.client(0);
    // the congested shard's writes first: their repops lead the link, the other shard's write follows
    for (i, n) in names(px, 4).iter().enumerate() {
        let op = p.a.op(1, n, vec![OsdOp::writefull(vec![1u8; 4096])]);
        assert!(p.a.call(0, ca, 1 + i as u64, op).is_empty());
    }
    let op =
        p.a.op(1, &names(py, 1)[0], vec![OsdOp::writefull(vec![2u8; 4096])]);
    assert!(p.a.call(0, ca, 100, op).is_empty());
    p.settle();
    p.run_for(Duration::from_secs(3));
    let count = |p: &mut Pair| {
        let r = p.a.replies(0, ca);
        assert!(r.iter().all(|x| x.1.result == 0));
        (
            r.iter().filter(|x| x.0 == 100).count(),
            r.iter().filter(|x| x.0 != 100).count(),
        )
    };
    let during = count(&mut p);
    p.b.osds[0].pg.store.deny_admission_shard.set(None);
    p.run_for(Duration::from_secs(5));
    let holds = p.b.osds[0].perf.util.holds[crate::utilization::HoldWhy::Store as usize];
    ([during, count(&mut p)], holds)
}

/// Classic peers keep today's receive path exactly (adr 0084 am. 3): the replica pauses the link at the repop of the
/// congested shard, the write of the other shard waits behind it, everything completes once the shard recovers.
#[test]
fn classic_peer_link_pauses_at_a_congested_replica_shard() {
    let ([during, after], holds) = congested_replica_shard(false);
    assert_eq!(holds.n, 1, "one repop retained for the store: {holds:?}");
    assert!(
        holds.max_ns >= 3_000_000_000,
        "held for the whole congestion: {holds:?}"
    );
    assert_eq!(
        during,
        (0, 0),
        "classic: head of line blocking is the old behavior"
    );
    assert_eq!(after, (1, 4));
}

/// Between croit-flashstore-osd peers a congested replica shard does not delay the other shards of the same link: their repops and
/// acks flow while the congested shard's repops wait inside their PG (with their reservation).
#[test]
fn congested_replica_shard_does_not_delay_other_shards_between_flashstore_peers() {
    let ([during, after], _) = congested_replica_shard(true);
    assert_eq!(
        during,
        (1, 0),
        "other shard acked within 3 s of virtual time while the shard is stuck"
    );
    assert_eq!(after, (0, 4), "congested shard completes after recovery");
}

/// Same deadlock by count (omapbench 2026-10-15, 4 clients x QD 32 omap-set-vals on ONE object): 128 small client
/// writes fill the shard window's 128 inputs (bytes are irrelevant) while they wait for replica acks; most of them only
/// wait in the object's order queue. The peer's repop for another PG of that shard must still be admitted.
fn many_small_omap_writes_on_one_object(nv: bool) {
    let mut p = Pair::of(Mc::with_wal(0, 1, 65536), Mc::with_wal(1, 1, 65536));
    p.up();
    if nv {
        p.flashstore();
    }
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let pg_of = |n: &str| {
        let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
        PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32))
    };
    let shard_a = |pg: PgT| p.a.osds[0].input_shard(pg);
    let pa = (0..32)
        .map(|s| PgT::new(1, s))
        .find(|&pg| map.pg_to_up_acting(pg).acting_primary == 0)
        .unwrap();
    let pb = (0..32)
        .map(|s| PgT::new(1, s))
        .find(|&pg| map.pg_to_up_acting(pg).acting_primary == 1 && shard_a(pg) == shard_a(pa))
        .unwrap();
    let name_in = |pg: PgT| {
        (0..)
            .map(|i| format!("o{i}"))
            .find(|s| pg_of(s) == pg)
            .unwrap()
    };
    let (hot, other) = (name_in(pa), name_in(pb));
    let kv = |i: usize| BTreeMap::from([(format!("k{i:06}").into_bytes(), vec![7u8; 256])]);
    const N: usize = 128; // ingress::WINDOW_COUNT
    let ca = p.a.client(0);
    for i in 0..N {
        let op = p.a.op(1, &hot, vec![OsdOp::omap_set_vals(&kv(i))]);
        assert!(p.a.call(0, ca, 1 + i as u64, op).is_empty());
    }
    let cb = p.b.client(0);
    let op = p.b.op(1, &other, vec![OsdOp::omap_set_vals(&kv(0))]);
    assert!(p.b.call(0, cb, 1, op).is_empty());
    p.settle();
    p.run_for(Duration::from_secs(30));
    let ra = p.a.replies(0, ca);
    assert_eq!(ra.len(), N, "osd.0 omap writes acked");
    assert!(ra.iter().all(|r| r.1.result == 0));
    let rb = p.b.replies(0, cb);
    assert_eq!(rb.len(), 1, "osd.1 write acked");
    assert_eq!(rb[0].1.result, 0);
    if nv {
        assert!(p.a.osds[0].pg.flow.idle() && p.b.osds[0].pg.flow.idle());
    }
}

#[test]
fn many_small_omap_writes_on_one_object_never_block_peer_acks_behind_a_peer_repop() {
    many_small_omap_writes_on_one_object(false);
}

/// Count variant between croit-flashstore-osd peers: repop credits also bound the number of inputs (adr 0084 am. 4).
#[test]
fn many_small_omap_writes_on_one_object_with_repop_credits() {
    many_small_omap_writes_on_one_object(true);
}

/// OSD wiring: an omap range removal of 25 000 of 30 000 keys applies on the replica without a timer, the client gets its
/// ack, and both copies keep exactly the keys outside the range.
#[test]
fn replica_applies_an_omap_range_removal_and_acks() {
    let mut p = Pair::new(1, 1);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let pg_of = |n: &str| {
        let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
        (
            PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32)),
            raw.seed,
        )
    };
    let name = (0..)
        .map(|i| format!("idx{i}"))
        .find(|n| map.pg_to_up_acting(pg_of(n).0).acting_primary == 0)
        .unwrap();
    let (pg, hash) = pg_of(&name);
    let cl = p.a.client(0);
    let key = |i: usize| format!("k{i:06}").into_bytes();
    for b in 0..30usize {
        let m: BTreeMap<Vec<u8>, Vec<u8>> = (0..1000)
            .map(|i| (key(b * 1000 + i), vec![7u8; 32]))
            .collect();
        let op = p.a.op(1, &name, vec![OsdOp::omap_set_vals(&m)]);
        p.a.call(0, cl, 1 + b as u64, op);
        p.settle();
        assert_eq!(p.a.replies(0, cl).len(), 1, "fill {b}");
    }
    let mut rm = OsdOp::new(opwire::op::OMAP_RM_KEY_RANGE);
    rm.indata = denc::Encode::encode_to_vec(&opwire::payload::OmapRmKeyRangeIn {
        begin: key(1000),
        end: key(26_000),
    })
    .unwrap()
    .into();
    let op = p.a.op(1, &name, vec![rm]);
    let t0 = p.b.t;
    assert!(
        p.a.call(0, cl, 100, op).is_empty(),
        "no ack before the replica"
    );
    p.settle();
    let r = p.a.replies(0, cl);
    assert_eq!(r.len(), 1, "acked without a timer");
    assert_eq!(r[0].1.result, 0);
    assert!(
        p.b.t - t0 < Duration::from_millis(20),
        "replica took {:?}",
        p.b.t - t0
    );
    let spg = SpgT {
        pgid: pg,
        shard: denc::types::ShardId::NO_SHARD,
    };
    let mut h =
        denc::types::Hobject::new(name.as_bytes(), denc::types::SnapId::NOSNAP, hash, 1, b"");
    h.set_key(b"");
    for (who, n) in [(0, &p.a), (1, &p.b)] {
        let c = peering::pg_core(1, pg.seed, n.n as u32, S);
        let store = &n.osds[c].pg.store;
        let over = |l| peering::PgStoreOps::omap_keys_over(store, spg, &h, l);
        assert_eq!(over(4999), Some(true), "osd.{who} holds 5000 keys");
        assert_eq!(
            over(5000),
            Some(false),
            "osd.{who} holds no more than 5000 keys"
        );
    }
}
/// adr 0160 D5 wiring: with `flashstore_obj_cache` on, the replicated client write path leaves the PG's object-state
/// generation alone, so the ops after a write and repeated reads take the state from the cache (debug builds check every
/// hit against the store); off = no cache.
#[test]
fn object_state_cache_serves_repeated_ops_through_the_real_write_path() {
    for (cap, hits) in [("true", true), ("false", false)] {
        let mut p = Pair::new(2, 1);
        for o in p.a.osds.iter_mut().chain(p.b.osds.iter_mut()) {
            o.conf
                .set(crate::config::Level::Override, "flashstore_obj_cache", cap)
                .unwrap();
            o.refresh_obs_conf();
        }
        p.up();
        let map = p.a.osds[0].osdmap().unwrap().clone();
        let name = (0..)
            .map(|i| format!("oc{i}"))
            .find(|n| {
                let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
                let pg = PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32));
                map.pg_to_up_acting(pg).acting_primary == 0
            })
            .unwrap();
        let cl = p.a.client(0);
        let mut tid = 0;
        let mut call = |p: &mut Pair, ops: Vec<OsdOp>| {
            tid += 1;
            let op = p.a.op(1, &name, ops);
            let mut r = p.a.call(0, cl, tid, op);
            p.settle();
            r.extend(p.a.replies(0, cl));
            assert_eq!(r.len(), 1);
            assert_eq!(r[0].1.result, 0);
            r[0].1.ops[0].outdata.clone()
        };
        call(&mut p, vec![OsdOp::writefull(vec![1u8; 4096])]);
        for _ in 0..3 {
            assert_eq!(
                &call(&mut p, vec![OsdOp::read(0, 4096)])[..],
                &[1u8; 4096][..]
            );
        }
        call(&mut p, vec![OsdOp::write(0, vec![2u8; 4096])]);
        assert_eq!(
            &call(&mut p, vec![OsdOp::read(0, 4096)])[..],
            &[2u8; 4096][..]
        );
        let hit: u64 = p.a.osds.iter().map(|o| o.perf.op.obj_cache_hit).sum();
        let miss: u64 = p.a.osds.iter().map(|o| o.perf.op.obj_cache_miss).sum();
        if hits {
            assert!(hit >= 4, "hits {hit} misses {miss}");
        } else {
            assert_eq!(hit + miss, 0);
        }
    }
}

/// Large reads through the real store and reply path (adr 0043 am. 13: store buffers by reference -> reply pieces -> msgr2
/// parts): READ (whole, unaligned), SPARSE_READ and a read together with a stat reply the stored bytes exactly.
/// adr 0021 S8: a PGNLS of a PG that has writes in flight (queued, parked) runs non-blocking and replies with the whole
/// PG; the writes keep arriving while it lists (live A/B on zen4a: PGNLS next to a steady write stream got no reply).
#[test]
fn pgnls_next_to_a_write_stream_replies() {
    let mut p = Pair::new(1, 1);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let pg_of = |n: &str| {
        let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
        PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32))
    };
    let pg = (0..32)
        .map(|s| PgT::new(1, s))
        .find(|&pg| map.pg_to_up_acting(pg).acting_primary == 0)
        .unwrap();
    let names: Vec<String> = (0..)
        .map(|i| format!("o{i}"))
        .filter(|s| pg_of(s) == pg)
        .take(700)
        .collect();
    let cl = p.a.client(0);
    let mut tid = 0u64;
    let send = |p: &mut Pair, tid: u64, op: MOSDOp| {
        let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
        let t = p.a.t;
        p.a.osds[0].set_now(t);
        p.a.osds[0].on_unknown_message(cl, tid, ty, ver, &segs);
    };
    let mut acked = 0;
    for ch in names.chunks(100) {
        for n in ch {
            tid += 1;
            let op = p.a.op(1, n, vec![OsdOp::create(false)]);
            send(&mut p, tid, op);
        }
        p.settle();
        p.run_for(Duration::from_secs(1));
        acked += p.a.replies(0, cl).len();
    }
    assert_eq!(acked, names.len(), "creates acked");
    // the listing, with 1 MiB writes to the PG queued before and after it (they park in the store)
    let w = |p: &Pair, i: usize| {
        p.a.op(
            1,
            &names[i % names.len()],
            vec![OsdOp::write(0, vec![i as u8; 1 << 20])],
        )
    };
    for i in 0..8 {
        tid += 1;
        let op = w(&p, i);
        send(&mut p, tid, op);
    }
    tid += 1;
    let ls = tid;
    let mut op = p.a.op(
        1,
        "",
        vec![OsdOp::pgnls(1024, &denc::types::Hobject::MIN())],
    );
    op.pgid.pgid = pg;
    op.hash = pg.seed;
    op.oid.clear();
    op.flags = opwire::flag::READ | opwire::flag::IGNORE_OVERLAY | opwire::flag::ONDISK;
    send(&mut p, ls, op);
    for i in 8..64 {
        tid += 1;
        let op = w(&p, i);
        send(&mut p, tid, op);
        p.a.settle();
    }
    p.settle();
    p.run_for(Duration::from_secs(10));
    let r = p.a.replies(0, cl);
    let l = r.iter().find(|(t, _)| *t == ls).expect("the PGNLS replied");
    assert_eq!(l.1.result, 1, "the PG listed to its end");
    let resp: opwire::PgNlsResponse = denc::from_slice(&l.1.ops[0].outdata).unwrap();
    assert_eq!(resp.entries.len(), names.len());
}

/// adr 0522 (PG-core share): omap listings that continue over many slices and a PGNLS, next to a point read of their object, with
/// the listing share forced to one continuation per loop iteration (messages waiting): continuations are deferred to later iterations (no
/// store wake names them), every listing still replies with the whole object, byte for byte equal, and the point read
/// replies.
#[test]
fn deferred_listing_continuations_complete() {
    let mut p = Pair::new(1, 1);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let obj = (0..)
        .map(|i| format!("big{i}"))
        .find(|n| {
            let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
            let pg = PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32));
            map.pg_to_up_acting(pg).acting_primary == 0
        })
        .unwrap();
    // one client session per listing (concurrent listings as from separate clients)
    let cls: Vec<u64> = (0..8).map(|_| p.a.client(0)).collect();
    let cl = cls[0];
    let send = |p: &mut Pair, cl: u64, tid: u64, op: MOSDOp| {
        let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
        let t = p.a.t;
        p.a.osds[0].set_now(t);
        p.a.osds[0].on_unknown_message(cl, tid, ty, ver, &segs);
    };
    let n_keys = 3000u32;
    let mut tid = 0u64;
    for b in 0..n_keys / 500 {
        let m: opwire::KvMap = (b * 500..(b + 1) * 500)
            .map(|i| (format!("k{i:06}").into_bytes(), vec![i as u8; 100]))
            .collect();
        tid += 1;
        let op = p.a.op(1, &obj, vec![OsdOp::omap_set_vals(&m)]);
        send(&mut p, cl, tid, op);
        p.settle();
    }
    p.run_for(Duration::from_secs(1));
    assert!(
        p.a.replies(0, cl).iter().all(|(_, r)| r.result == 0),
        "omap filled"
    );
    p.a.osds[0].pg.share.one_per_iteration = true;
    let d0 = p.a.osds[0].perf.op.list_deferred;
    tid += 1;
    for &c in &cls[..6] {
        let op =
            p.a.op(1, &obj, vec![OsdOp::omap_get_vals(b"", 10_000, b"")]);
        send(&mut p, c, tid, op);
    }
    let mut x = OsdOp::new(opwire::op::OMAP_GET_VALS_BY_KEYS);
    let keys: BTreeSet<Vec<u8>> = [b"k001234".to_vec()].into();
    x.indata = denc::Encode::encode_to_vec(&keys).unwrap().into();
    let op = p.a.op(1, &obj, vec![x]);
    send(&mut p, cls[6], tid, op);
    // a PGNLS of the object's PG: its first pass is deferred like the omap listings' (first passes share the core too)
    let raw = map
        .object_to_raw_pg(1, obj.as_bytes(), b"", b"", -1)
        .unwrap();
    let pg = PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32));
    let mut op = p.a.op(
        1,
        "",
        vec![OsdOp::pgnls(1024, &denc::types::Hobject::MIN())],
    );
    op.pgid.pgid = pg;
    op.hash = pg.seed;
    op.oid.clear();
    op.flags = opwire::flag::READ | opwire::flag::IGNORE_OVERLAY | opwire::flag::ONDISK;
    send(&mut p, cls[7], tid, op);
    p.settle();
    p.run_for(Duration::from_secs(2));
    let point = p.a.replies(0, cls[6]);
    assert_eq!(point.len(), 1, "the point read replied");
    assert_eq!(point[0].1.result, 0);
    let ls = p.a.replies(0, cls[7]);
    assert_eq!(ls.len(), 1, "the PGNLS replied");
    assert_eq!(ls[0].1.result, 1, "the PG listed to its end");
    let resp: opwire::PgNlsResponse = denc::from_slice(&ls[0].1.ops[0].outdata).unwrap();
    assert!(
        resp.entries.iter().any(|e| e.oid == obj.as_bytes()),
        "the object is listed"
    );
    let rs: Vec<_> = cls[..6].iter().map(|&c| p.a.replies(0, c)).collect();
    let mut first: Option<&[u8]> = None;
    for r in &rs {
        let l = r
            .iter()
            .find(|(x, _)| *x == tid)
            .expect("every listing replied");
        assert_eq!(l.1.result, 0);
        let out = &l.1.ops[0].outdata;
        let v: opwire::OmapValsOut = denc::from_slice(out).unwrap();
        // the OSD's per-request entry limit (1024: 4 listing slices) cuts the page
        assert_eq!(v.vals.len(), 1024);
        assert!(v.truncated);
        assert!(first.is_none_or(|f| f == &out[..]), "listings differ");
        first = Some(out);
    }
    assert!(
        p.a.osds[0].perf.op.list_deferred > d0,
        "no continuation was deferred"
    );
}

/// adr 0522: the listing share goes round robin over the PGs. With one continuation per loop iteration, a listing of a PG
/// late in the PG order runs its passes between those of an earlier PG's listings instead of after all of them (walked
/// from the first PG every iteration, the share stayed with the first PGs while they had listings: per8.o100 scans
/// 160 ms on the last PGs of a core, doc/perf/omap-scan-p99-20261030.md).
#[test]
fn listing_share_is_round_robin_over_pgs() {
    let mut p = Pair::new(1, 1);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let pg_of = |n: &str| {
        let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
        PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32))
    };
    let mine = (0..)
        .map(|i| format!("big{i}"))
        .filter(|n| map.pg_to_up_acting(pg_of(n)).acting_primary == 0);
    let mut objs: Vec<String> = Vec::new();
    for n in mine {
        if objs.iter().all(|o| pg_of(o) != pg_of(&n)) {
            objs.push(n);
        }
        if objs.len() == 2 {
            break;
        }
    }
    objs.sort_by_key(|o| pg_of(o).seed);
    let (lo, hi) = (objs[0].clone(), objs[1].clone());
    let cls: Vec<u64> = (0..5).map(|_| p.a.client(0)).collect();
    let send = |p: &mut Pair, cl: u64, tid: u64, op: MOSDOp| {
        let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
        let t = p.a.t;
        p.a.osds[0].set_now(t);
        p.a.osds[0].on_unknown_message(cl, tid, ty, ver, &segs);
    };
    let mut tid = 0u64;
    for o in [&lo, &hi] {
        for b in 0..6u32 {
            let m: opwire::KvMap = (b * 500..(b + 1) * 500)
                .map(|i| (format!("k{i:06}").into_bytes(), vec![1; 100]))
                .collect();
            tid += 1;
            let op = p.a.op(1, o, vec![OsdOp::omap_set_vals(&m)]);
            send(&mut p, cls[0], tid, op);
            p.settle();
        }
    }
    p.run_for(Duration::from_secs(1));
    let _ = p.a.replies(0, cls[0]);
    p.a.osds[0].pg.share.one_per_iteration = true;
    // four listings of the first PG (4 passes each), then one of the later PG
    tid += 1;
    for &c in &cls[..4] {
        let op = p.a.op(1, &lo, vec![OsdOp::omap_get_vals(b"", 10_000, b"")]);
        send(&mut p, c, tid, op);
    }
    let op = p.a.op(1, &hi, vec![OsdOp::omap_get_vals(b"", 10_000, b"")]);
    send(&mut p, cls[4], tid, op);
    p.settle();
    p.run_for(Duration::from_secs(2));
    let order: Vec<u64> = p.a.osds[0]
        .t
        .out
        .iter()
        .filter(|f| f.1 == tid && cls.contains(&f.0))
        .map(|f| f.0)
        .collect();
    assert_eq!(order.len(), 5, "every listing replied: {order:?}");
    let at = order.iter().position(|&c| c == cls[4]).unwrap();
    assert!(
        at < 4,
        "the later PG's listing waited for all listings of the first PG: reply order {order:?}"
    );
    for &c in &cls[1..] {
        let r = p.a.replies(0, c);
        let l = r.iter().find(|(t, _)| *t == tid).unwrap();
        assert_eq!(l.1.result, 0);
        let v: opwire::OmapValsOut = denc::from_slice(&l.1.ops[0].outdata).unwrap();
        assert_eq!(v.vals.len(), 1024);
    }
}

/// adr 0522 am. 1: an omap listing that holds a later write of its object (another session) is no background work: once
/// the write waits behind it, it lists whole and outside the core share instead of one CPU slice per loop iteration
/// (adr 0021 S8); it still replies the object as before the write, and the write applies after it. A listing that holds
/// nothing keeps slicing.
#[test]
fn listing_holding_a_write_lists_whole() {
    let mut p = Pair::new(1, 1);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let obj = (0..)
        .map(|i| format!("big{i}"))
        .find(|n| {
            let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
            let pg = PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32));
            map.pg_to_up_acting(pg).acting_primary == 0
        })
        .unwrap();
    let cls: Vec<u64> = (0..3).map(|_| p.a.client(0)).collect();
    let send = |p: &mut Pair, cl: u64, tid: u64, op: MOSDOp| {
        let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
        let t = p.a.t;
        p.a.osds[0].set_now(t);
        p.a.osds[0].on_unknown_message(cl, tid, ty, ver, &segs);
    };
    let slices = |p: &Pair| {
        p.a.osds[0].pg.store.with_store(|s| {
            s.perf_counters()
                .iter()
                .find(|c| c.0 == "scan_slices")
                .map(|c| c.2)
                .unwrap()
        })
    };
    let mut tid = 0u64;
    for b in 0..6u32 {
        let m: opwire::KvMap = (b * 500..(b + 1) * 500)
            .map(|i| (format!("k{i:06}").into_bytes(), vec![1; 100]))
            .collect();
        tid += 1;
        let op = p.a.op(1, &obj, vec![OsdOp::omap_set_vals(&m)]);
        send(&mut p, cls[0], tid, op);
        p.settle();
    }
    p.run_for(Duration::from_secs(1));
    p.a.osds[0].pg.share.one_per_iteration = true;
    let s0 = slices(&p);
    tid += 1;
    let list = tid;
    let op =
        p.a.op(1, &obj, vec![OsdOp::omap_get_vals(b"", 10_000, b"")]);
    send(&mut p, cls[1], list, op);
    let m: opwire::KvMap = [(b"k000000".to_vec(), vec![2; 100])].into();
    tid += 1;
    let op = p.a.op(1, &obj, vec![OsdOp::omap_set_vals(&m)]);
    send(&mut p, cls[2], tid, op);
    p.settle();
    p.run_for(Duration::from_secs(1));
    let s1 = slices(&p);
    let l = p.a.replies(0, cls[1]);
    assert_eq!(l.len(), 1, "the listing replied");
    let v: opwire::OmapValsOut = denc::from_slice(&l[0].1.ops[0].outdata).unwrap();
    assert_eq!(v.vals.len(), 1024);
    assert_eq!(
        v.vals[&b"k000000"[..]],
        vec![1; 100],
        "the listing ran before the write"
    );
    let w = p.a.replies(0, cls[2]);
    assert_eq!((w.len(), w[0].1.result), (1, 0), "the write applied");
    // the first pass ran before the write arrived (sliced); the rest of the listing in one pass
    assert!(s1 - s0 <= 1, "a held listing sliced: {}", s1 - s0);
    // the same listing alone: one slice per 256 entries
    tid += 1;
    let op =
        p.a.op(1, &obj, vec![OsdOp::omap_get_vals(b"", 10_000, b"")]);
    send(&mut p, cls[1], tid, op);
    p.settle();
    p.run_for(Duration::from_secs(1));
    let l = p.a.replies(0, cls[1]);
    assert_eq!(l.len(), 1, "the second listing replied");
    let v: opwire::OmapValsOut = denc::from_slice(&l[0].1.ops[0].outdata).unwrap();
    assert_eq!(v.vals[&b"k000000"[..]], vec![2; 100]);
    assert!(
        slices(&p) - s1 >= 3,
        "a listing that holds nothing keeps slicing"
    );
}

#[test]
fn large_reads_reply_the_stored_bytes() {
    let mut p = Pair::new(2, 1);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let name = (0..)
        .map(|i| format!("big{i}"))
        .find(|n| {
            let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
            let pg = PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32));
            map.pg_to_up_acting(pg).acting_primary == 0
        })
        .unwrap();
    let cl = p.a.client(0);
    let mut tid = 0;
    let mut call = |p: &mut Pair, ops: Vec<OsdOp>| {
        tid += 1;
        let op = p.a.op(1, &name, ops);
        let mut r = p.a.call(0, cl, tid, op);
        p.settle();
        r.extend(p.a.replies(0, cl));
        assert_eq!(r.len(), 1, "tid {tid}");
        assert_eq!(r[0].1.result, 0);
        r.remove(0).1.ops
    };
    let data: Vec<u8> = (0..(1u32 << 20) + 8192)
        .map(|i| (i * 29 + 3) as u8)
        .collect();
    for (i, c) in data.chunks(64 << 10).enumerate() {
        call(&mut p, vec![OsdOp::write((i as u64) << 16, c.to_vec())]);
    }
    let n = data.len() as u64;
    for (off, len) in [(0u64, n), (4096, 1 << 20), (1000, 700_000), (n - 100, 4096)] {
        let ops = call(&mut p, vec![OsdOp::read(off, len)]);
        let end = (off + len).min(n) as usize;
        assert_eq!(
            &ops[0].outdata[..],
            &data[off as usize..end],
            "read {off} {len}"
        );
        let ops = call(&mut p, vec![OsdOp::sparse_read(off, len)]);
        let o = denc::from_slice::<opwire::payload::SparseReadOut>(&ops[0].outdata).unwrap();
        assert_eq!(
            o.extents.into_iter().collect::<Vec<_>>(),
            vec![(off, (end - off as usize) as u64)]
        );
        assert!(o.data[..] == data[off as usize..end], "sparse {off} {len}");
    }
    let ops = call(&mut p, vec![OsdOp::read(0, n), OsdOp::stat()]);
    assert_eq!(&ops[0].outdata[..], &data[..]);
    assert!(!ops[1].outdata.is_empty(), "stat output");
}

/// copy-from whose source lives on the OTHER OSD: the read goes over a client link (`osd.N` session on the public side
/// of the source primary) and the answer comes back over it.
#[test]
fn copy_from_pulls_the_source_from_another_osd() {
    let mut p = Pair::new(2, 2);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let primary_of = |name: &str| {
        let raw = map
            .object_to_raw_pg(1, name.as_bytes(), b"", b"", -1)
            .unwrap();
        let pg = PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32));
        map.pg_to_up_acting(pg).acting_primary
    };
    let locator = denc::types::ObjectLocator {
        pool: 1,
        key: vec![],
        nspace: vec![],
        hash: -1,
    };
    let (mut done_01, mut done_10) = (0, 0);
    for i in 0..40usize {
        let (src, dst) = (format!("csrc{i}"), format!("cdst{i}"));
        let (ps, pd) = (primary_of(&src), primary_of(&dst));
        if ps == pd && i % 4 != 0 {
            continue;
        }
        let body = vec![(i % 199) as u8 + 1; 5000 + i];
        // write the source through its primary
        let sn = p.node(ps);
        let core = i % sn.n;
        let cl = sn.client(core);
        let op = sn.op(
            1,
            &src,
            vec![
                OsdOp::writefull(body.clone()),
                OsdOp::setxattr(b"k", b"v"),
                OsdOp::omap_set_vals(&BTreeMap::from([(b"ok".to_vec(), b"ov".to_vec())])),
            ],
        );
        sn.call(core, cl, 1, op);
        p.settle();
        let r = p.node(ps).replies(core, cl);
        assert_eq!(r.len(), 1, "write {src} i={i} ps={ps} pd={pd} unanswered");
        assert_eq!(r[0].1.result, 0, "write {src}");
        // copy through the destination's primary
        let dn = p.node(pd);
        let core = (i + 1) % dn.n;
        let cl = dn.client(core);
        let cpop = OsdOp::copy_from_req(
            opwire::op::COPY_FROM2,
            src.as_bytes(),
            &locator,
            opwire::NOSNAP,
            0,
            0,
            None,
        );
        let op = dn.op(1, &dst, vec![cpop]);
        dn.call(core, cl, 2, op);
        p.settle();
        let r = p.node(pd).replies(core, cl);
        assert_eq!(
            r.len(),
            1,
            "copy {i} {src}->{dst} (osd.{ps}->osd.{pd}) unanswered"
        );
        assert_eq!(r[0].1.result, 0, "copy {i}");
        // read it back through the destination primary
        let dn = p.node(pd);
        let op = dn.op(
            1,
            &dst,
            vec![
                OsdOp::read(0, 100_000),
                OsdOp::getxattr(b"k"),
                OsdOp::omap_get_vals(b"", 10, b""),
            ],
        );
        let r = dn.call(core, cl, 3, op);
        assert_eq!(r[0].1.result, 0, "read {dst}");
        assert_eq!(r[0].1.ops[0].outdata, body, "data {dst}");
        assert_eq!(r[0].1.ops[1].outdata, &b"v"[..], "xattr {dst}");
        if ps != pd {
            if pd == 0 {
                done_10 += 1;
            } else {
                done_01 += 1;
            }
        }
    }
    assert!(done_01 > 0 && done_10 > 0, "{done_01} {done_10}");
    // client links exist and nothing is left in flight
    assert!(
        p.a.osds.iter().chain(&p.b.osds).all(|o| o.pg.cp.is_empty()),
        "reads left"
    );
}

/// A source bigger than one chunk goes through a temp object (adr 0057 am. 1): chunks pulled from the other OSD,
/// staged on the acting set, renamed by the final write; content and omap identical, nothing left behind.
#[test]
fn copy_from_a_big_object_across_osds_is_staged() {
    // virtual time must not run long in one step: idle fake links time out
    fn reply(p: &mut Pair, who: i32, link: u64, imm: Vec<(u64, MOSDOpReply)>) -> MOSDOpReply {
        let mut got = imm;
        for _ in 0..60 {
            if !got.is_empty() {
                break;
            }
            p.run_for(std::time::Duration::from_secs(1));
            got = p.node(who).replies(0, link);
        }
        assert_eq!(got.len(), 1, "unanswered");
        got.pop().unwrap().1
    }
    let mut p = Pair::new(2, 2);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let primary_of = |name: &str| {
        let raw = map
            .object_to_raw_pg(1, name.as_bytes(), b"", b"", -1)
            .unwrap();
        map.pg_to_up_acting(PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32)))
            .acting_primary
    };
    let src = (0..)
        .map(|i| format!("bsrc{i}"))
        .find(|n| primary_of(n) == 1)
        .unwrap();
    let dst = (0..)
        .map(|i| format!("bdst{i}"))
        .find(|n| primary_of(n) == 0)
        .unwrap();
    // 9 MiB: two chunks; omap and header ride along
    let body: Vec<u8> = (0..9u32 << 20).map(|i| (i % 251) as u8).collect();
    let mut keys = BTreeMap::new();
    for i in 0..100u32 {
        keys.insert(format!("k{i:05}").into_bytes(), vec![(i % 200) as u8; 8192]);
    }
    let cl = p.b.client(0);
    let op = p.b.op(
        1,
        &src,
        vec![
            OsdOp::writefull(body.clone()),
            OsdOp::setxattr(b"k", b"v"),
            OsdOp::omap_set_vals(&keys),
            OsdOp::omap_set_header(b"HDR".to_vec()),
        ],
    );
    let imm = p.b.call(0, cl, 1, op);
    assert_eq!(reply(&mut p, 1, cl, imm).result, 0, "source write");
    let cl = p.a.client(0);
    let cpop = OsdOp::copy_from_req(
        opwire::op::COPY_FROM2,
        src.as_bytes(),
        &denc::types::ObjectLocator {
            pool: 1,
            key: vec![],
            nspace: vec![],
            hash: -1,
        },
        opwire::NOSNAP,
        0,
        0,
        None,
    );
    let op = p.a.op(1, &dst, vec![cpop]);
    let imm = p.a.call(0, cl, 2, op);
    assert_eq!(reply(&mut p, 0, cl, imm).result, 0, "copy");
    let op = p.a.op(
        1,
        &dst,
        vec![
            OsdOp::read(0, 12 << 20),
            OsdOp::getxattr(b"k"),
            OsdOp::omap_get_vals(b"", 1000, b""),
            OsdOp::omap_get_header(),
            OsdOp::stat(),
        ],
    );
    let imm = p.a.call(0, cl, 3, op);
    let r = reply(&mut p, 0, cl, imm);
    assert_eq!(r.result, 0, "read");
    assert!(r.ops[0].outdata[..] == body[..], "data");
    assert_eq!(r.ops[1].outdata, &b"v"[..]);
    assert!(r.ops[2].outdata.len() > 100 * 8192, "omap keys");
    assert_eq!(r.ops[3].outdata, &b"HDR"[..]);
    assert!(
        p.a.osds.iter().chain(&p.b.osds).all(|o| o.pg.cp.is_empty()),
        "reads left"
    );
}

/// The client link to the source OSD dies before the answer: the read is sent again on a new link and the copy completes.
#[test]
fn copy_from_survives_a_lost_client_link() {
    let mut p = Pair::new(2, 2);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let primary_of = |name: &str| {
        let raw = map
            .object_to_raw_pg(1, name.as_bytes(), b"", b"", -1)
            .unwrap();
        map.pg_to_up_acting(PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32)))
            .acting_primary
    };
    let src = (0..)
        .map(|i| format!("lsrc{i}"))
        .find(|n| primary_of(n) == 1)
        .unwrap();
    let dst = (0..)
        .map(|i| format!("ldst{i}"))
        .find(|n| primary_of(n) == 0)
        .unwrap();
    let sn = &mut p.b;
    let cl = sn.client(0);
    let op = sn.op(1, &src, vec![OsdOp::writefull(b"payload".to_vec())]);
    sn.call(0, cl, 1, op);
    p.settle();
    assert_eq!(p.b.replies(0, cl)[0].1.result, 0);
    let dn = &mut p.a;
    let cl = dn.client(0);
    let cpop = OsdOp::copy_from_req(
        opwire::op::COPY_FROM2,
        src.as_bytes(),
        &denc::types::ObjectLocator {
            pool: 1,
            key: vec![],
            nspace: vec![],
            hash: -1,
        },
        opwire::NOSNAP,
        0,
        0,
        None,
    );
    let op = dn.op(1, &dst, vec![cpop]);
    dn.call(0, cl, 2, op);
    // the link was dialed but is not up yet: it dies
    let mut killed = 0;
    for o in &mut p.a.osds {
        for (_, link) in o.pg.cp.unready() {
            o.close_link(link);
            killed += 1;
        }
    }
    assert_eq!(killed, 1, "one client link to osd.1");
    p.settle();
    assert!(p.a.replies(0, cl).is_empty(), "not answered yet");
    // the retry timer dials a new link; it completes
    p.run_for(Duration::from_millis(600));
    let r = p.a.replies(0, cl);
    assert_eq!(r.len(), 1, "copy unanswered after the retry");
    assert_eq!(r[0].1.result, 0);
    let dn = &mut p.a;
    let op = dn.op(1, &dst, vec![OsdOp::read(0, 100)]);
    let r = dn.call(0, cl, 3, op);
    assert_eq!(r[0].1.ops[0].outdata, &b"payload"[..]);
}

#[test]
fn engine_of_a_replica_pg_is_torn_down_without_a_pg_touch() {
    // An engine created for a PG that is not primary (pg_run creates on first use, e.g. the WriteDone(-EAGAIN) of
    // an aborted interval after the PG became a replica) must go at the next engine sync even though the PG
    // machinery did not touch that PG again (touched-list sync, adr 0043).
    let mut p = Pair::new(2, 2);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let seed = (0..32u32)
        .find(|&s| map.pg_to_up_acting(PgT::new(1, s)).acting_primary != 0)
        .expect("a pg where osd.0 is a replica");
    let spg = SpgT {
        pgid: PgT::new(1, seed),
        shard: denc::types::ShardId::NO_SHARD,
    };
    let oc = peering::pg_core(1, seed, p.a.n as u32, S);
    let o = &mut p.a.osds[oc];
    assert!(o.pg.set.pg(spg).is_some_and(|pg| !pg.is_primary()));
    o.pg_post(); // drain the touched list
    o.pg_run(spg, |_, _| {}); // creates the engine; its trailing pg_exec -> pg_post syncs
    o.pg_post();
    assert!(
        !o.pg.eng.contains_key(&spg),
        "engine of replica pg {spg} survived the sync"
    );
}

/// adr 0065 with the real store: on the primary, a data block of one object rots (checksum error on read) and the
/// object_info of another stops decoding. Client reads of both wait (no EIO), the PG pulls the objects from the replica,
/// the reads are served with the right bytes, the primary's store copies are good again, counters say so.
#[test]
fn damaged_primary_objects_are_repaired_from_the_replica_and_served() {
    let mut p = Pair::new(2, 1);
    p.up();
    // the rot below happens behind the PG: found when the reads load the object (cold). A cached object_info (adr 0160
    // D5, like classic's object contexts) serves the last good state until scrub finds the damage.
    for o in &mut p.a.osds {
        o.conf
            .set(
                crate::config::Level::Override,
                "flashstore_obj_cache",
                "false",
            )
            .unwrap();
        o.refresh_obs_conf();
    }
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let at = |n: &str| {
        let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
        let pg = PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32));
        let mut h =
            denc::types::Hobject::new(n.as_bytes(), denc::types::SnapId::NOSNAP, raw.seed, 1, b"");
        h.set_key(b"");
        (pg, h)
    };
    let mut names = (0..)
        .map(|i| format!("rot{i}"))
        .filter(|n| map.pg_to_up_acting(at(n).0).acting_primary == 0);
    let (data_obj, oi_obj) = (names.next().unwrap(), names.next().unwrap());
    let (b1, b2) = (vec![0xA7u8; 8192], vec![0x5Cu8; 4096]);
    let cl = p.a.client(0);
    for (tid, (n, b)) in [(&data_obj, &b1), (&oi_obj, &b2)].into_iter().enumerate() {
        let op = p.a.op(1, n, vec![OsdOp::writefull(b.clone())]);
        p.a.call(0, cl, 1 + tid as u64, op);
        p.settle();
        let r = p.a.replies(0, cl);
        assert_eq!(r.len(), 1, "write {n}");
        assert_eq!(r[0].1.result, 0);
    }
    p.run_for(Duration::from_secs(2));
    let spg_of = |n: &str| SpgT {
        pgid: at(n).0,
        shard: denc::types::ShardId::NO_SHARD,
    };
    let na = p.a.n as u32;
    let core_of = |n: &str| peering::pg_core(1, at(n).0.seed, na, S);
    // 1. rot every media block holding the data of `data_obj` on osd.0 (the replica keeps its own device)
    let img = p.a.disk.image();
    let mut rotted = 0;
    for lba in 0..img.lba_count {
        if img.read_lba(lba).iter().all(|b| *b == 0xA7) {
            p.a.disk.corrupt(lba, 17, 0x01);
            rotted += 1;
        }
    }
    assert!(rotted >= 2, "data blocks located: {rotted}");
    // 2. object_info of `oi_obj` on osd.0 no longer decodes
    {
        let (spg, h) = (spg_of(&oi_obj), at(&oi_obj).1);
        let mut t = replwire::Transaction::new();
        let c = t.coll(&denc::types::CollT::Pg(spg));
        let o = t.obj(&denc::types::Ghobject::head(
            h,
            denc::types::ShardId::NO_SHARD,
        ));
        t.push(
            c,
            replwire::TxnOp::SetAttrs {
                oid: o,
                attrs: vec![(b"_".as_slice(), [0xffu8; 3].as_slice())],
            },
        );
        let data = t.encode_v9().unwrap();
        let oc = core_of(&oi_obj);
        peering::PgStoreOps::submit(
            &mut p.a.osds[oc].pg.store,
            spg,
            &peering::StoreTxn {
                ops: vec![peering::StoreOp::ApplyTxn {
                    middle: Default::default(),
                    data: data.into(),
                }],
            },
        );
        p.settle();
    }
    for n in [&data_obj, &oi_obj] {
        let (spg, h) = (spg_of(n), at(n).1);
        assert!(
            peering::PgStoreOps::recovery_info_checked(&p.a.osds[core_of(n)].pg.store, spg, &h)
                .is_err()
                || opexec::ObjView::ov_read(&p.a.osds[core_of(n)].pg.store, spg, &h, 0, 8192)
                    .is_err(),
            "{n} is damaged on the primary"
        );
    }
    // the reads wait for the repair and are served with the replica's bytes
    for (tid, (n, b)) in [(&data_obj, &b1), (&oi_obj, &b2)].into_iter().enumerate() {
        let tid = 10 + tid as u64;
        let op = p.a.op(1, n, vec![OsdOp::read(0, 8192)]);
        let mut r = p.a.call(0, cl, tid, op);
        for _ in 0..100 {
            if !r.is_empty() {
                break;
            }
            p.run_for(Duration::from_millis(200));
            r = p.a.replies(0, cl);
        }
        assert_eq!(r.len(), 1, "read of {n} answered");
        assert_eq!(r[0].1.result, 0, "read of {n}: no EIO");
        assert_eq!(
            &r[0].1.ops[0].outdata[..],
            &b[..],
            "{n} served from the repair"
        );
        let (spg, h) = (spg_of(n), at(n).1);
        let st = &p.a.osds[core_of(n)].pg.store;
        assert_eq!(
            opexec::ObjView::ov_read(st, spg, &h, 0, 8192).unwrap(),
            *b,
            "{n} repaired in the primary's store"
        );
        assert!(peering::PgStoreOps::recovery_info_checked(st, spg, &h).is_ok());
    }
    p.run_for(Duration::from_secs(2));
    let repaired: u64 =
        p.a.osds
            .iter()
            .flat_map(|o| o.pg.set.pgs().map(|(_, pg)| pg.shards_repaired()))
            .sum();
    assert_eq!(repaired, 2);
    let waited: u64 = p.a.osds.iter().map(|o| o.perf.op.read_repair).sum();
    assert_eq!(waited, 2);
    // the control core of this harness never finishes its mon-driven init (no mon): sample its PGs by hand, the
    // workers did on their ticks and reported to core 0
    p.a.osds[0].pg_tick();
    assert_eq!(
        p.a.osds[0].shards_repaired_shown(),
        2,
        "num_shards_repaired"
    );
}

/// Write `n` objects of pool 1 / read them back, each from the client on core `i % cores`.
fn write_read_all(mc: &mut Mc, pool: i64, prefix: &str, n: usize, tid0: u64) {
    let clients: Vec<u64> = (0..mc.n).map(|c| mc.client(c)).collect();
    for i in 0..n {
        let c = i % mc.n;
        let data = vec![(i % 251) as u8; 4096 + i];
        let op = mc.op(pool, &format!("{prefix}{i}"), vec![OsdOp::writefull(data)]);
        let r = mc.call(c, clients[c], tid0 + i as u64, op);
        assert_eq!(r.len(), 1, "write {i}: {r:?}");
        assert_eq!(r[0].1.result, 0, "write {i}");
        // read from a different core's client
        let c2 = (i + 1) % mc.n;
        let op = mc.op(
            pool,
            &format!("{prefix}{i}"),
            vec![OsdOp::read(0, 4096 + i as u64)],
        );
        let r = mc.call(c2, clients[c2], 1000 + tid0 + i as u64, op);
        assert_eq!(r.len(), 1, "read {i}: {r:?}");
        assert_eq!(r[0].1.result, 0, "read {i}");
        assert_eq!(
            r[0].1.ops[0].outdata,
            vec![(i % 251) as u8; 4096 + i],
            "object {i}"
        );
    }
}

/// Next epoch: same map, pool `pool` gets `n` PGs.
fn with_pg_num(mc: &Mc, epoch: u32, pool: i64, n: u32) -> OsdMap {
    let mut m = mc.map(epoch, 10);
    for (id, p) in m.pools.iter_mut() {
        // earlier changes of the test persist: take the pg_num the OSD holds now
        if let Some(cur) = mc.osds[0].osdmap().and_then(|c| c.pool(*id)) {
            p.pg_num = cur.pg_num;
            p.pgp_num = cur.pgp_num;
            p.pg_num_pending = cur.pg_num_pending;
            p.pg_num_target = cur.pg_num_target;
        }
    }
    let p = m.pools.get_mut(&pool).unwrap();
    p.pg_num = n;
    p.pgp_num = n;
    p.pg_num_pending = n;
    p.pg_num_target = n;
    p.last_change = epoch;
    m
}

/// Passive EC PGs retain INCOMPLETE reports only while their pool and PG still exist.
#[test]
fn orphan_pg_stats_retire_after_pool_deletion_and_pg_shrink() {
    let mut mc = Mc::new(1);
    mc.ec4 = true;
    mc.up();
    mc.run_for(Duration::from_secs(7));
    let o = &mut mc.osds[0];
    o.conf
        .set(crate::config::Level::Override, "ec_enable_pools", "off")
        .unwrap();
    o.conf
        .set(
            crate::config::Level::Override,
            "ec_decline_unsupported",
            "false",
        )
        .unwrap();
    o.pg_apply_ec_cfg();
    // Feed the last primary publication and removal actions at the service boundary: no EC peers are needed
    // to exercise retirement of the report after its PG instance has gone.
    for seed in 0..2 {
        let spg = SpgT {
            pgid: PgT::new(4, seed),
            shard: denc::types::ShardId(0),
        };
        o.pg_exec(vec![
            peering::Action::PgStats {
                spg,
                stat: Box::new(pgwire::PgStat {
                    state: pgwire::state::ACTIVE | pgwire::state::CLEAN,
                    reported_epoch: 10,
                    reported_seq: 1,
                    ..Default::default()
                }),
            },
            peering::Action::PgRemoved { spg },
        ]);
    }
    assert!(
        o.pg.orphan_stats.iter().any(|p| p.pool == 4),
        "disabling EC must leave an inactive report"
    );
    let retained: BTreeSet<_> = o.pg.orphan_stats.clone();
    assert!(retained.iter().any(|p| p.seed > 0));

    let mut pending_merge = with_pg_num(&mc, 11, 4, mc.pool4);
    pending_merge.pools.get_mut(&4).unwrap().pg_num_pending = 1;
    mc.deliver(pending_merge);
    assert_eq!(
        mc.osds[0].pg.orphan_stats, retained,
        "pending merge keeps the PGs"
    );

    mc.deliver(with_pg_num(&mc, 12, 4, 1));
    let o = &mc.osds[0];
    assert_eq!(
        o.pg.orphan_stats,
        retained.into_iter().filter(|p| p.seed == 0).collect(),
        "shrink retires only PGs that no longer exist"
    );
    assert!(o.pg.stats.keys().all(|p| p.pool != 4 || p.seed == 0));
    assert!(o.pg_stat_list().iter().any(|(p, _)| p.pool == 4));

    let mut map = with_pg_num(&mc, 13, 4, 1);
    map.pools.remove(&4);
    map.pool_name.remove(&4);
    mc.deliver(map);
    let o = &mc.osds[0];
    assert!(o.pg.orphan_stats.is_empty());
    assert!(o.pg.stats.keys().all(|p| p.pool != 4));
    assert!(o.pg_stat_list().iter().all(|(p, _)| p.pool != 4));
    assert!(o.pg_stat_list().iter().any(|(p, _)| p.pool == 1));
}

#[test]
fn split_keeps_children_on_their_parents_core() {
    let mut mc = Mc::new(4);
    mc.up();
    write_read_all(&mut mc, 1, "obj", 64, 1);
    let m = with_pg_num(&mc, 11, 1, 64);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    assert_eq!(
        mc.osds[0].state,
        State::Active,
        "log: {:?}",
        mc.osds[0].logs
    );
    let pgs = mc.pgs();
    let in_pool1: usize = pgs
        .iter()
        .map(|v| v.iter().filter(|(p, _)| *p == 1).count())
        .sum();
    assert_eq!(in_pool1, 64, "{pgs:?}");
    for (c, v) in pgs.iter().enumerate() {
        for (pool, seed) in v {
            assert_eq!(mc.owner(*pool, *seed), c, "pg {pool}.{seed} on core {c}");
        }
    }
    for o in &mc.osds {
        for (spg, s) in o.pg.set.pg_states() {
            assert!(s.contains("active"), "{spg} {s}");
        }
    }
    // objects written before the split are in the children now; reads and new writes work from any core
    let clients: Vec<u64> = (0..mc.n).map(|c| mc.client(c)).collect();
    for i in 0..64usize {
        let c = (i + 1) % mc.n;
        let op = mc.op(1, &format!("obj{i}"), vec![OsdOp::read(0, 4096 + i as u64)]);
        let r = mc.call(c, clients[c], i as u64, op);
        assert_eq!(r.len(), 1, "read {i}: log {:?}", mc.osds[1].logs);
        assert_eq!(
            r[0].1.ops[0].outdata,
            vec![(i % 251) as u8; 4096 + i],
            "object {i}"
        );
    }
    write_read_all(&mut mc, 1, "after", 64, 5000);
}

/// Next epoch with pool 4 at `pg_num` / `pending` (a merge is announced by lowering `pending` first).
fn pool4(mc: &Mc, epoch: u32, up_from: u32, pg_num: u32, pending: u32) -> OsdMap {
    let mut m = mc.map(epoch, up_from);
    let p = m.pools.get_mut(&4).unwrap();
    p.pg_num = pg_num;
    p.pgp_num = pg_num;
    p.pg_num_pending = pending;
    p.pg_num_target = pending;
    p.last_change = epoch;
    m
}

/// Where each PG of pool 4 lives: seed -> core.
fn pool4_cores(mc: &Mc) -> BTreeMap<u32, usize> {
    let mut v = BTreeMap::new();
    for (c, o) in mc.osds.iter().enumerate() {
        for (spg, _) in o.pg.set.pgs() {
            if spg.pgid.pool == 4 {
                assert!(v.insert(spg.pgid.seed, c).is_none(), "{spg} on two cores");
            }
        }
    }
    v
}

fn read_back(mc: &mut Mc, pool: i64, prefix: &str, n: usize) {
    let clients: Vec<u64> = (0..mc.n).map(|c| mc.client(c)).collect();
    for i in 0..n {
        let c = (i + 1) % mc.n;
        let op = mc.op(
            pool,
            &format!("{prefix}{i}"),
            vec![OsdOp::read(0, 4096 + i as u64)],
        );
        let r = mc.call(c, clients[c], 9000 + i as u64, op);
        assert_eq!(r.len(), 1, "read {prefix}{i}");
        assert_eq!(
            r[0].1.ops[0].outdata,
            vec![(i % 251) as u8; 4096 + i],
            "object {prefix}{i}"
        );
    }
}

#[test]
fn split_children_inherit_the_parents_shard_and_core() {
    let mut mc = Mc::new(3);
    mc.pool4 = 6; // children 6 and 7 hash to other shards than their parents (2, 3)
    mc.up();
    write_read_all(&mut mc, 4, "s", 48, 1);
    let before = pool4_cores(&mc);
    assert_eq!(before.len(), 6);
    mc.deliver(pool4(&mc, 11, 10, 12, 12));
    mc.run_for(Duration::from_secs(3));
    let after = pool4_cores(&mc);
    assert_eq!(after.len(), 12, "{after:?}");
    for s in 6..12u32 {
        let parent = pgwire::pgmath::ancestor(s, 6);
        assert_eq!(after[&s], after[&parent], "child {s} of {parent}");
    }
    // the table knows it everywhere, the data followed (zero-copy split on one shard)
    let off_hash = mc.osds[2].pg.set.placements().count();
    assert!(off_hash > 0);
    read_back(&mut mc, 4, "s", 48);
    // a restart finds every PG on the core of its shard again
    mc.restart();
    assert_eq!(pool4_cores(&mc), after);
    let m = pool4(&mc, 13, 13, 12, 12);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    read_back(&mut mc, 4, "s", 48);
}

/// Merge pool 4 from 32 to 5 PGs: most sources start on another core than their target.
fn merge_setup(mc: &mut Mc) {
    mc.up();
    write_read_all(mc, 4, "m", 64, 1);
}

fn assert_merged(mc: &mut Mc, pgs: usize) {
    let after = pool4_cores(mc);
    assert_eq!(after.len(), pgs, "{after:?}");
    for (s, c) in &after {
        assert_eq!(
            mc.osds[*c].pg.set.core_of(PgT::new(4, *s)),
            *c,
            "pg 4.{s} on core {c}"
        );
    }
    // every object sits in the store of its target PG on the target's core (the harness has no mon to hand out the
    // merge metadata that lets a merged PG go active again, so the objects are checked in the stores)
    let map = mc.osds[0].osdmap().unwrap().clone();
    for i in 0..64usize {
        let name = format!("m{i}");
        let raw = map
            .object_to_raw_pg(4, name.as_bytes(), b"", b"", -1)
            .unwrap();
        let seed = pgwire::pgmath::object_pg(raw.seed, pgs as u32);
        let core = after[&seed];
        let spg = SpgT {
            pgid: PgT::new(4, seed),
            shard: denc::types::ShardId::NO_SHARD,
        };
        let mut h = denc::types::Hobject::new(
            name.as_bytes(),
            denc::types::SnapId::NOSNAP,
            raw.seed,
            4,
            b"",
        );
        h.set_key(b"");
        let got = opexec::ObjView::ov_read(&mc.osds[core].pg.store, spg, &h, 0, 4096 + i as u64)
            .unwrap_or_else(|e| panic!("object {name} missing in pg {spg} on core {core}: {e}"));
        assert_eq!(got, vec![(i % 251) as u8; 4096 + i], "object {name}");
    }
}

#[test]
fn merge_across_cores_moves_the_sources_first() {
    let mut mc = Mc::new(3);
    merge_setup(&mut mc);
    // announce: pg_num_pending 5 (the mon waits for the PGs to report ready); sources move to their targets' cores
    mc.deliver(pool4(&mc, 11, 10, 32, 5));
    mc.run_for(Duration::from_secs(3));
    let moved: u64 = mc.osds.iter().map(|o| o.cl.mig.moved).sum();
    assert!(moved > 0, "no PG moved");
    let cores = pool4_cores(&mc);
    for s in 5..32u32 {
        let t = pgwire::pgmath::merge_target(s, 5);
        assert_eq!(cores[&s], cores[&t], "source {s} next to target {t}");
    }
    // pg_num drops: the merge runs inside one PG set
    mc.deliver(pool4(&mc, 12, 10, 5, 5));
    mc.run_for(Duration::from_secs(3));
    assert_eq!(mc.osds[0].state, State::Active, "{:?}", mc.osds[0].logs);
    assert_merged(&mut mc, 5);
}

#[test]
fn merge_without_the_announcement_still_moves_before_applying() {
    let mut mc = Mc::new(3);
    merge_setup(&mut mc);
    mc.deliver(pool4(&mc, 11, 10, 5, 5));
    mc.run_for(Duration::from_secs(3));
    assert_merged(&mut mc, 5);
}

#[test]
fn crash_after_the_copy_before_the_source_is_deleted() {
    let mut mc = Mc::new(3);
    merge_setup(&mut mc);
    // the destination's acknowledgements get lost: every source core still holds its (complete) copy
    mc.lose = Some(|_, m| matches!(m, XMsg::MigAck { .. }));
    mc.deliver(pool4(&mc, 11, 10, 32, 5));
    mc.run_for(Duration::from_secs(2));
    mc.lose = None;
    // power cut: both copies of each moved PG exist on disk; the destination (every instance, newer generation) wins
    assert!(
        mc.osds.iter().all(|o| o.cl.mig.moved == 0),
        "acks were lost"
    );
    mc.restart();
    let dup = mc.osds.iter().any(|o| {
        o.logs
            .iter()
            .any(|l| l.contains("lives on another core, deleting"))
    });
    assert!(dup, "boot saw no duplicate");
    let m = pool4(&mc, 12, 12, 32, 5);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    let cores = pool4_cores(&mc); // asserts: no PG on two cores
    for s in 5..32u32 {
        let t = pgwire::pgmath::merge_target(s, 5);
        assert_eq!(cores[&s], cores[&t]);
    }
    let m = pool4(&mc, 13, 12, 5, 5);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    assert_merged(&mut mc, 5);
}

#[test]
fn crash_in_the_middle_of_the_copy() {
    let mut mc = Mc::new(3);
    merge_setup(&mut mc);
    // only the first batch of each PG arrives: the destination holds incomplete collections
    mc.lose = Some(|_, m| matches!(m, XMsg::MigData { last: true, .. } | XMsg::MigCredit { .. }));
    mc.deliver(pool4(&mc, 11, 10, 32, 5));
    mc.run_for(Duration::from_secs(2));
    mc.lose = None;
    assert!(
        mc.osds.iter().all(|o| o.cl.mig.moved == 0),
        "nothing was acknowledged"
    );
    mc.restart();
    // boot found the half copies (garbage); the sources are complete at their old cores and move again (runtime retry)
    mc.run_for(Duration::from_secs(3));
    let moving = mc
        .osds
        .iter()
        .any(|o| o.logs.iter().any(|l| l.contains("moving to core")));
    assert!(moving, "the moves were not redone");
    assert_colocated(&mc, 5);
    let m = pool4(&mc, 12, 12, 5, 5);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    assert_merged(&mut mc, 5);
}

// ---------------------------------------------------------------- merge migration: PG identity (EC shard), every byte

/// The only instance of PG `4.seed` on the OSD: `(core, spg)` (EC: the shard this OSD holds).
fn pool4_instance(mc: &Mc, seed: u32) -> (usize, SpgT) {
    let found: Vec<(usize, SpgT)> = mc
        .osds
        .iter()
        .enumerate()
        .flat_map(|(c, o)| o.pg.set.pgs().map(move |(s, _)| (c, *s)))
        .filter(|(_, s)| s.pgid == PgT::new(4, seed))
        .collect();
    assert_eq!(found.len(), 1, "pg 4.{seed}: {found:?}");
    found[0]
}

fn pool4_hobj(name: &str, hash: u32) -> denc::types::Hobject {
    let mut h =
        denc::types::Hobject::new(name.as_bytes(), denc::types::SnapId::NOSNAP, hash, 4, b"");
    h.set_key(b"");
    h
}

/// `n` objects of distinct sizes written straight into the store collections of their pool 4 PG instances (EC
/// instances: under their shard id): `(name, raw hash, bytes)`.
fn populate_pool4(mc: &mut Mc, n: usize) -> Vec<(String, u32, Vec<u8>)> {
    let map = mc.osds[0].osdmap().unwrap().clone();
    let pg_num = map.pool(4).unwrap().pg_num;
    let mut v = Vec::new();
    for i in 0..n {
        let name = format!("p{i}");
        let raw = map
            .object_to_raw_pg(4, name.as_bytes(), b"", b"", -1)
            .unwrap();
        let (core, spg) = pool4_instance(mc, pgwire::pgmath::object_pg(raw.seed, pg_num));
        let data: Vec<u8> = (0..4096 + 517 * i)
            .map(|k| (k * 7 + i * 13) as u8)
            .collect();
        let h = pool4_hobj(&name, raw.seed);
        mc.osds[core].pg.store.with_store(|st| {
            let mut t = store::obj::OTxn::new();
            t.write(storeadapt::pg_coll(spg), &storeadapt::gh(spg, &h), 0, &data);
            st.commit(&t).unwrap();
        });
        v.push((name, raw.seed, data));
    }
    v
}

/// Every object of `objs` has all its bytes in the instance of its PG at `pg_num`.
fn verify_pool4(mc: &Mc, objs: &[(String, u32, Vec<u8>)], pg_num: u32) {
    for (name, hash, data) in objs {
        let (core, spg) = pool4_instance(mc, pgwire::pgmath::object_pg(*hash, pg_num));
        let got = opexec::ObjView::ov_read(
            &mc.osds[core].pg.store,
            spg,
            &pool4_hobj(name, *hash),
            0,
            data.len() as u64,
        )
        .unwrap_or_else(|e| panic!("object {name} missing in pg {spg} on core {core}: {e}"));
        assert!(got == *data, "object {name} in pg {spg}: bytes differ");
    }
}

fn assert_colocated(mc: &Mc, lo: u32) {
    let cores = pool4_cores(mc);
    for (s, c) in &cores {
        let t = pgwire::pgmath::merge_target(*s, lo);
        assert_eq!(*c, cores[&t], "source 4.{s} next to target 4.{t}");
    }
}

/// Merge 32 -> 5 across 3 cores with populated PGs, restarts in between: no byte is lost. One path for both pool types:
/// an EC PG instance (shard id != NO_SHARD) must travel exactly like a replicated one. `crash`: the copies are cut
/// before their last batch and the OSD restarts: runtime retries redo them.
fn merge_keeps_every_byte(ec: bool, crash: bool) {
    let mut mc = Mc::new(3);
    mc.ec4 = ec;
    mc.up();
    for o in &mc.osds {
        for (spg, _) in o.pg.set.pgs().filter(|(s, _)| s.pgid.pool == 4) {
            assert_eq!(spg.shard == denc::types::ShardId::NO_SHARD, !ec, "{spg}");
        }
    }
    let objs = populate_pool4(&mut mc, 96);
    verify_pool4(&mc, &objs, 32);
    if crash {
        mc.lose =
            Some(|_, m| matches!(m, XMsg::MigData { last: true, .. } | XMsg::MigCredit { .. }));
    }
    mc.deliver(pool4(&mc, 11, 10, 32, 5));
    mc.run_for(Duration::from_secs(3));
    if crash {
        mc.lose = None;
        assert!(mc.osds.iter().all(|o| o.cl.mig.moved == 0));
        mc.restart();
        mc.run_for(Duration::from_secs(3));
        let redo = mc
            .osds
            .iter()
            .any(|o| o.logs.iter().any(|l| l.contains("moving to core")));
        assert!(redo, "the moves were not redone");
    } else {
        assert!(
            mc.osds.iter().map(|o| o.cl.mig.moved).sum::<u64>() > 0,
            "no PG moved"
        );
    }
    assert_colocated(&mc, 5);
    verify_pool4(&mc, &objs, 32);
    mc.restart();
    assert_eq!(pool4_cores(&mc).len(), 32, "every PG came back");
    assert_colocated(&mc, 5);
    verify_pool4(&mc, &objs, 32);
    let m = pool4(&mc, 12, 12, 5, 5);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    assert_eq!(pool4_cores(&mc).len(), 5);
    verify_pool4(&mc, &objs, 5);
    mc.restart();
    verify_pool4(&mc, &objs, 5);
}

#[test]
fn ec_merge_across_cores_keeps_every_byte() {
    merge_keeps_every_byte(true, false);
}

#[test]
fn replicated_merge_across_cores_keeps_every_byte() {
    merge_keeps_every_byte(false, false);
}

#[test]
fn ec_merge_crash_mid_copy_keeps_every_byte() {
    merge_keeps_every_byte(true, true);
}

#[test]
fn replicated_merge_crash_mid_copy_keeps_every_byte() {
    merge_keeps_every_byte(false, true);
}

// ---------------------------------------------------------------- merge migration: crash matrix

thread_local! {
    /// `(migration messages seen, cut after)`: [`mig_cut`] loses every migration message from the cut on.
    static MIG_CUT: std::cell::Cell<(u32, u32)> = const { std::cell::Cell::new((0, u32::MAX)) };
}

/// Lose hook: a power cut at the `cut`-th migration message (everything of the migration protocol after it is lost;
/// the restart that follows is the cut).
fn mig_cut(_: usize, m: &XMsg) -> bool {
    if !matches!(
        m,
        XMsg::MigReserve { .. }
            | XMsg::MigGrant { .. }
            | XMsg::MigAbort { .. }
            | XMsg::MigData { .. }
            | XMsg::MigCredit { .. }
            | XMsg::MigAck { .. }
            | XMsg::MigDone { .. }
            | XMsg::Release { .. }
    ) {
        return false;
    }
    MIG_CUT.with(|c| {
        let (seen, cut) = c.get();
        c.set((seen + 1, cut));
        seen >= cut
    })
}

/// One cut: merge 32 -> 5 across 3 cores, migration cut at message `cut`, restart (runtime retries finish the moves), then
/// the merge: every byte at 32 and at 5, across restarts. Returns the migration messages of the run.
fn mig_crash_at(ec: bool, cut: u32) -> u32 {
    let mut mc = Mc::new(3);
    mc.ec4 = ec;
    mc.up();
    let objs = populate_pool4(&mut mc, 48);
    MIG_CUT.with(|c| c.set((0, cut)));
    mc.lose = Some(mig_cut);
    mc.deliver(pool4(&mc, 11, 10, 32, 5));
    mc.run_for(Duration::from_secs(3));
    mc.lose = None;
    let seen = MIG_CUT.with(|c| c.get().0);
    mc.restart();
    mc.run_for(Duration::from_secs(3));
    assert!(
        mc.osds.iter().all(|o| !o.pg.dead),
        "cut {cut}: a core stopped"
    );
    assert_colocated(&mc, 5);
    verify_pool4(&mc, &objs, 32);
    let m = pool4(&mc, 12, 12, 5, 5);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    assert_eq!(pool4_cores(&mc).len(), 5, "cut {cut}");
    verify_pool4(&mc, &objs, 5);
    mc.restart();
    verify_pool4(&mc, &objs, 5);
    seen
}

/// Every `stride`-th cut point of the migration protocol (replicated and EC: one path).
fn mig_crash_matrix(stride: u32) {
    for ec in [false, true] {
        let n = mig_crash_at(ec, u32::MAX);
        assert!(n > 10, "migration messages: {n}");
        let mut cuts = 0;
        for cut in (0..n).step_by(stride.max(1) as usize) {
            mig_crash_at(ec, cut);
            cuts += 1;
        }
        eprintln!("mig crash matrix ec={ec}: {n} migration messages, {cuts} cuts");
    }
}

#[test]
fn mig_crash_matrix_strided() {
    let stride = std::env::var("MIG_CRASH_STRIDE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9);
    mig_crash_matrix(stride);
}

/// Soak: every cut point (lab/mig-crash.sh).
#[test]
#[ignore]
fn mig_crash_matrix_every_message() {
    mig_crash_matrix(1);
}

// ---------------------------------------------------------------- merge migration: headroom (near-full destination)

/// Fill the store shards of the merge targets of pool 4 (`seed < lo`, where the sources move to) with filler objects
/// in their collections until no 4 KiB user write fits above the data floor: a moving copy finds no room there.
fn fill_targets(mc: &mut Mc, lo: u32) -> Vec<(usize, SpgT, denc::types::Hobject)> {
    let targets: Vec<(usize, SpgT)> = mc
        .osds
        .iter()
        .enumerate()
        .flat_map(|(c, o)| o.pg.set.pgs().map(move |(s, _)| (c, *s)))
        .filter(|(_, s)| s.pgid.pool == 4 && s.pgid.seed < lo)
        .collect();
    let mut v = Vec::new();
    for (core, spg) in targets {
        let c = storeadapt::pg_coll(spg);
        for sz in [1usize << 20, 64 << 10, 4 << 10] {
            let data = vec![0x5a; sz];
            while mc.osds[core]
                .pg
                .store
                .with_store(|st| st.write_room(&c, sz as u64, 1))
            {
                let h = pool4_hobj(&format!("fill{}", v.len()), spg.pgid.seed);
                mc.osds[core].pg.store.with_store(|st| {
                    let mut t = store::obj::OTxn::new();
                    t.write(c, &storeadapt::gh(spg, &h), 0, &data);
                    st.commit(&t).unwrap();
                });
                v.push((core, spg, h));
            }
        }
    }
    assert!(!v.is_empty(), "nothing filled");
    v
}

fn unfill(mc: &mut Mc, fill: Vec<(usize, SpgT, denc::types::Hobject)>) {
    for (core, spg, h) in fill {
        mc.osds[core].pg.store.with_store(|st| {
            let mut t = store::obj::OTxn::new();
            t.remove(storeadapt::pg_coll(spg), &storeadapt::gh(spg, &h));
            st.commit(&t).unwrap();
        });
    }
}

fn deferred_visible(mc: &Mc) -> usize {
    let o = &mc.osds[0];
    for (c, o) in mc.osds.iter().enumerate() {
        assert!(
            !o.pg.dead,
            "core {c} stopped: {:?}",
            o.logs.iter().rev().take(8).collect::<Vec<_>>()
        );
    }
    let n = o.cl.mig.deferred.len();
    if n > 0 {
        assert!(
            o.os_alerts().contains_key("FLASHSTORE_PG_MOVE_DEFERRED"),
            "health warning"
        );
        let v = o.perf_dump(Some("flashstore_mig"), None);
        let get = |k: &str| v["flashstore_mig"][k].as_u64();
        assert_eq!(get("pgs_deferred"), Some(n as u64));
        assert!(get("moves_deferred").unwrap_or(0) >= n as u64);
    } else {
        assert!(!o.os_alerts().contains_key("FLASHSTORE_PG_MOVE_DEFERRED"));
    }
    n
}

/// Merge 32 -> 5 across 3 cores while the destination shards are full (adr 0031 am. 4): the moves are deferred (no
/// crash, nothing detached, warning + counters), a restart defers them again (boot never moves; the runtime retry finds
/// no room), freeing space lets the control core retry them; every byte survives.
fn merge_near_full(ec: bool) {
    let mut mc = Mc::new(3);
    mc.ec4 = ec;
    mc.up();
    let objs = populate_pool4(&mut mc, 96);
    let fill = fill_targets(&mut mc, 5);
    mc.deliver(pool4(&mc, 11, 10, 32, 5));
    mc.run_for(Duration::from_secs(3));
    assert_eq!(mc.osds.iter().map(|o| o.cl.mig.moved).sum::<u64>(), 0);
    let n = deferred_visible(&mc);
    assert!(n > 0, "no move deferred");
    assert_eq!(pool4_cores(&mc).len(), 32, "every PG still served");
    verify_pool4(&mc, &objs, 32);
    mc.restart();
    assert!(
        mc.osds[0]
            .logs
            .iter()
            .any(|l| l.contains("move deferred to a runtime retry")),
        "boot deferred the moves"
    );
    mc.run_for(Duration::from_secs(3));
    assert_eq!(deferred_visible(&mc), n);
    assert_eq!(pool4_cores(&mc).len(), 32, "every PG still served");
    verify_pool4(&mc, &objs, 32);
    unfill(&mut mc, fill);
    mc.run_for(Duration::from_secs(5));
    assert_eq!(deferred_visible(&mc), 0, "retried once room appeared");
    assert_colocated(&mc, 5);
    verify_pool4(&mc, &objs, 32);
    let m = pool4(&mc, 12, 12, 5, 5);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    assert_eq!(pool4_cores(&mc).len(), 5);
    verify_pool4(&mc, &objs, 5);
    mc.restart();
    verify_pool4(&mc, &objs, 5);
}

/// Stranded copies by core: `(core, spg)` of every instance the cores keep unloaded.
fn strands(mc: &Mc) -> Vec<(usize, SpgT)> {
    mc.osds
        .iter()
        .enumerate()
        .flat_map(|(c, o)| o.cl.mig.strands.iter().map(move |s| (c, *s)))
        .collect()
}

/// The objects of `objs` that belong to a stranded source (at 32 PGs) still have every byte in its unloaded copy; the
/// others are in the merged PGs (at 5).
fn verify_stranded(mc: &Mc, objs: &[(String, u32, Vec<u8>)]) {
    let st = strands(mc);
    let mut in_strands = 0;
    for (name, hash, data) in objs {
        let seed = pgwire::pgmath::object_pg(*hash, 32);
        let Some(&(core, spg)) = st.iter().find(|(_, s)| s.pgid == PgT::new(4, seed)) else {
            verify_pool4(mc, &[(name.clone(), *hash, data.clone())], 5);
            continue;
        };
        in_strands += 1;
        let got = opexec::ObjView::ov_read(
            &mc.osds[core].pg.store,
            spg,
            &pool4_hobj(name, *hash),
            0,
            data.len() as u64,
        )
        .unwrap_or_else(|e| panic!("object {name} missing in stranded {spg} on core {core}: {e}"));
        assert!(
            got == *data,
            "object {name} in stranded {spg}: bytes differ"
        );
    }
    assert!(in_strands > 0, "no object in a stranded copy");
}

/// Every merged PG that lacks a stranded source is incomplete (`last_backfill` MIN): it never serves or peers as
/// complete.
fn assert_strand_targets_incomplete(mc: &Mc) {
    let st = strands(mc);
    assert!(!st.is_empty());
    for (_, s) in &st {
        let t = PgT::new(4, pgwire::pgmath::merge_target(s.pgid.seed, 5));
        let core = mc.osds[0].pg.set.core_of(t);
        let inst: Vec<_> = mc.osds[core]
            .pg
            .set
            .pgs()
            .filter(|(k, _)| k.pgid == t)
            .collect();
        assert!(!inst.is_empty(), "merged pg {t} on core {core}");
        for (k, p) in inst {
            assert_ne!(
                p.info().last_backfill,
                denc::types::Hobject::MAX(),
                "{k} lacks stranded {s} but claims to be complete"
            );
        }
    }
}

/// Merge 32 -> 5 completed by the map while the destination shards are full (a non-primary member does not gate it;
/// adr 0031 am. 5): the sources are stranded: unloaded, kept, never a second target instance; every merged PG that
/// lacks a stranded source is incomplete (its peers backfill it). A stranded copy is never moved, not even with room
/// again; it is deleted once obsolete (the merged PG complete again: reported by the target's core) or with its pool.
fn merge_completed_near_full(ec: bool) {
    let mut mc = Mc::new(3);
    mc.ec4 = ec;
    mc.up();
    let objs = populate_pool4(&mut mc, 96);
    let fill = fill_targets(&mut mc, 5);
    mc.deliver(pool4(&mc, 11, 10, 32, 5));
    mc.run_for(Duration::from_secs(3));
    let n = deferred_visible(&mc);
    assert!(n > 0, "no move deferred");
    mc.deliver(pool4(&mc, 12, 10, 5, 5));
    mc.run_for(Duration::from_secs(3));
    assert!(
        mc.osds
            .iter()
            .any(|o| o.logs.iter().any(|l| l.contains("before it can move"))),
        "sources stranded"
    );
    let check = |mc: &Mc| {
        assert_eq!(
            pool4_cores(mc).len(),
            5,
            "no PG on two cores, no second target"
        );
        let pgs: BTreeSet<PgT> = strands(mc).iter().map(|s| s.1.pgid).collect();
        assert_eq!(pgs.len(), n, "every deferred source stranded");
        assert_eq!(deferred_visible(mc), n);
        verify_stranded(mc, &objs);
        assert_strand_targets_incomplete(mc);
    };
    check(&mc);
    mc.restart();
    mc.run_for(Duration::from_secs(2));
    check(&mc);
    // room again: a stranded copy never moves (it would overwrite what the merged PG got since)
    unfill(&mut mc, fill);
    mc.run_for(Duration::from_secs(5));
    assert_eq!(mc.osds.iter().map(|o| o.cl.mig.moved).sum::<u64>(), 0);
    check(&mc);
    // the target's core found the merged PG complete: the holder deletes the copy
    let first = strands(&mc)[0];
    mc.osds[0].on_mig_obsolete(first.1.pgid);
    mc.run_for(Duration::from_secs(1));
    assert!(
        !peering::PgStoreOps::list_pgs(&mc.osds[first.0].pg.store).contains(&first.1),
        "obsolete copy deleted"
    );
    assert_eq!(deferred_visible(&mc), n - 1);
    assert!(strands(&mc).iter().all(|s| s.1.pgid != first.1.pgid));
    // the pool goes: every stranded copy with it
    let mut m = pool4(&mc, 13, 10, 5, 5);
    m.pools.remove(&4);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(5));
    assert_eq!(deferred_visible(&mc), 0);
    assert!(strands(&mc).is_empty(), "{:?}", strands(&mc));
}

/// The destination runs out of room in the middle of the copies after all (headroom estimate short): the import is
/// undone (nothing adopted, the half copy deleted, placement restored), the source serves its untouched copy again,
/// the move is deferred and retried; never a store failure, every byte kept (adr 0031 am. 5).
fn merge_import_nospace(ec: bool) {
    let mut mc = Mc::new(3);
    mc.ec4 = ec;
    mc.up();
    let objs = populate_pool4(&mut mc, 96);
    for o in &mc.osds {
        o.pg.store.import_nospace_after.set(Some(1));
    }
    mc.deliver(pool4(&mc, 11, 10, 32, 5));
    mc.run_for(Duration::from_secs(3));
    for (c, o) in mc.osds.iter().enumerate() {
        assert!(!o.pg.dead, "core {c} stopped");
    }
    assert!(
        mc.osds
            .iter()
            .any(|o| o.logs.iter().any(|l| l.contains("import undone"))),
        "no import ran out of room"
    );
    assert!(
        mc.osds
            .iter()
            .any(|o| o.logs.iter().any(|l| l.contains("move undone, deferred"))),
        "source not told"
    );
    assert!(mc.osds[0].cl.mig.deferrals > 0);
    // the refusal was one-shot: the retries found room
    mc.run_for(Duration::from_secs(3));
    assert_eq!(deferred_visible(&mc), 0);
    assert_colocated(&mc, 5);
    verify_pool4(&mc, &objs, 32);
    mc.restart();
    assert_eq!(pool4_cores(&mc).len(), 32, "every PG came back, none twice");
    verify_pool4(&mc, &objs, 32);
    let m = pool4(&mc, 12, 12, 5, 5);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    assert_eq!(pool4_cores(&mc).len(), 5);
    verify_pool4(&mc, &objs, 5);
}

/// Queue filler objects (256 KiB, then 16 KiB, then 4 KiB) into collection `c` of `core`'s store (the elastic path:
/// the shard borrows from the shared pool through the owner core) until the store refuses them with NoSpace; returns
/// the filler objects.
#[cfg(feature = "elastic")]
fn fill_queued(
    mc: &mut Mc,
    core: usize,
    c: denc::types::CollT,
    tag: &str,
) -> Vec<denc::types::Ghobject> {
    let denc::types::CollT::Pg(spg) = c else {
        unreachable!()
    };
    let mut v = Vec::new();
    for sz in [256usize << 10, 16 << 10, 4 << 10] {
        let data = vec![0xa5u8; sz];
        loop {
            assert!(v.len() < 100_000, "never full");
            let i = v.len();
            let o = storeadapt::gh(spg, &pool4_hobj(&format!("{tag}{i}"), spg.pgid.seed));
            let mut t = store::obj::OTxn::new();
            t.write(c, &o, 0, &data);
            match mc.osds[core]
                .pg
                .store
                .with_store(|s| s.queue(&t, 7_000_000 + i as u64))
            {
                Ok(_) => {}
                Err(store::obj::ObjError::NoSpace) => break,
                Err(e) => panic!("filler {tag}{i}: {e:?}"),
            }
            mc.settle();
            let mut errs = Vec::new();
            mc.osds[core]
                .pg
                .store
                .with_store(|s| s.take_queue_errors(&mut errs));
            if let Some((_, e)) = errs.first() {
                assert_eq!(*e, store::obj::ObjError::NoSpace, "filler {tag}{i}");
                break;
            }
            v.push(o);
        }
    }
    v
}

/// Gate (b) on the elastic store: the merge targets' shards borrowed the shared pool dry and are full: the merge moves
/// are deferred (warning, counters, no stop), also across a restart; space freed on the targets' shards lets the
/// control core retry them; every byte survives. (Borrowing for a deferred move: store test
/// `mig_want_borrows_until_the_copy_fits`.)
#[cfg(feature = "elastic")]
fn merge_pool_exhausted(ec: bool) {
    let mut mc = Mc::with_pool(0, 3, S, 2048, true);
    mc.ec4 = ec;
    mc.up();
    let objs = populate_pool4(&mut mc, 96);
    let targets: Vec<(usize, SpgT)> = mc
        .osds
        .iter()
        .enumerate()
        .flat_map(|(c, o)| o.pg.set.pgs().map(move |(s, _)| (c, *s)))
        .filter(|(_, s)| s.pgid.pool == 4 && s.pgid.seed < 5)
        .collect();
    let mut fill = Vec::new();
    for (core, spg) in &targets {
        let c = storeadapt::pg_coll(*spg);
        fill.extend(
            fill_queued(&mut mc, *core, c, "fill")
                .into_iter()
                .map(|o| (*core, c, o)),
        );
    }
    let free = mc.osds[0]
        .pg
        .store
        .with_store(|s| s.lending().unwrap().free_chunks());
    assert_eq!(free, 0, "pool exhausted");
    mc.deliver(pool4(&mc, 11, 10, 32, 5));
    mc.run_for(Duration::from_secs(3));
    assert_eq!(mc.osds.iter().map(|o| o.cl.mig.moved).sum::<u64>(), 0);
    let n = deferred_visible(&mc);
    assert!(n > 0, "no move deferred");
    verify_pool4(&mc, &objs, 32);
    mc.restart();
    assert_eq!(deferred_visible(&mc), n);
    verify_pool4(&mc, &objs, 32);
    for (i, (core, c, o)) in fill.iter().enumerate() {
        let mut t = store::obj::OTxn::new();
        t.remove(*c, o);
        mc.osds[*core]
            .pg
            .store
            .with_store(|s| s.queue(&t, 8_000_000 + i as u64))
            .unwrap();
        mc.settle();
    }
    mc.run_for(Duration::from_secs(5));
    assert_eq!(deferred_visible(&mc), 0, "retried once room appeared");
    assert_colocated(&mc, 5);
    verify_pool4(&mc, &objs, 32);
    let m = pool4(&mc, 12, 12, 5, 5);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    assert_eq!(pool4_cores(&mc).len(), 5);
    verify_pool4(&mc, &objs, 5);
    mc.restart();
    verify_pool4(&mc, &objs, 5);
}

#[cfg(feature = "elastic")]
#[test]
fn ec_merge_pool_exhausted_defers_and_keeps_every_byte() {
    merge_pool_exhausted(true);
}

#[cfg(feature = "elastic")]
#[test]
fn replicated_merge_pool_exhausted_defers_and_keeps_every_byte() {
    merge_pool_exhausted(false);
}

#[test]
fn ec_merge_near_full_defers_and_keeps_every_byte() {
    merge_near_full(true);
}

#[test]
fn replicated_merge_near_full_defers_and_keeps_every_byte() {
    merge_near_full(false);
}

#[test]
fn ec_merge_completed_near_full_strands_never_absorbs() {
    merge_completed_near_full(true);
}

#[test]
fn replicated_merge_completed_near_full_strands_never_absorbs() {
    merge_completed_near_full(false);
}

#[test]
fn ec_merge_import_nospace_undoes_and_defers() {
    merge_import_nospace(true);
}

#[test]
fn replicated_merge_import_nospace_undoes_and_defers() {
    merge_import_nospace(false);
}

/// Client writes leave `_info` alone (perf-w4k, `Pg::info_adv`): after a crash the reloaded PG info is rebuilt from the log
/// (last_update = head, last_complete, last_user_version, log_tail) and the next write continues the versions.
#[test]
fn info_lagging_the_log_is_rebuilt_at_load() {
    let mut mc = Mc::new(1);
    mc.up();
    write_read_all(&mut mc, 4, "lag", 40, 1);
    let state = |mc: &Mc| -> Vec<(
        SpgT,
        denc::types::Eversion,
        denc::types::Eversion,
        u64,
        denc::types::Eversion,
    )> {
        let mut v: Vec<_> = mc.osds[0]
            .pg
            .set
            .pgs()
            .map(|(s, p)| {
                (
                    *s,
                    p.info().last_update,
                    p.info().last_complete,
                    p.info().last_user_version,
                    p.log().head(),
                )
            })
            .collect();
        v.sort_by_key(|x| x.0);
        v
    };
    let before = state(&mc);
    assert!(
        before
            .iter()
            .any(|x| x.1 > denc::types::Eversion::default())
    );
    for x in &before {
        assert_eq!(
            (x.1, x.2),
            (x.4, x.4),
            "in memory: info follows the log head"
        );
    }
    mc.restart();
    mc.deliver(mc.map(12, 12));
    mc.run_for(Duration::from_secs(3));
    let after = state(&mc);
    for (b, a) in before.iter().zip(&after) {
        assert_eq!(b.0, a.0);
        assert!(a.1 >= b.1 && a.4 >= b.4, "{:?} -> {:?}", b, a);
        assert_eq!(
            a.2, a.1,
            "last_complete follows last_update with nothing missing"
        );
        assert!(a.3 >= b.3, "last_user_version never goes back");
    }
    // writes go on from there
    write_read_all(&mut mc, 4, "lag2", 8, 100);
}

#[test]
fn restart_reloads_every_cores_pgs() {
    let mut mc = Mc::new(4);
    mc.up();
    write_read_all(&mut mc, 1, "obj", 64, 1);
    let before = mc.pgs();
    mc.restart();
    // PGs came back from the per-core stores before any map arrived on this run
    assert_eq!(mc.pgs(), before, "log: {:?}", mc.osds[1].logs);
    // the mon marks us up again: new epoch, new up_from
    let m = mc.map(12, 12);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    assert!(mc.osds.iter().all(|o| o.state == State::Active));
    for o in &mc.osds {
        for (spg, s) in o.pg.set.pg_states() {
            assert!(s.contains("active"), "{spg} {s}");
        }
    }
    // data written before the restart is served by the right cores
    let clients: Vec<u64> = (0..mc.n).map(|c| mc.client(c)).collect();
    for i in 0..64usize {
        let c = (i + 2) % mc.n;
        let op = mc.op(1, &format!("obj{i}"), vec![OsdOp::read(0, 4096 + i as u64)]);
        let r = mc.call(c, clients[c], i as u64, op);
        assert_eq!(r.len(), 1, "read {i}");
        assert_eq!(r[0].1.ops[0].outdata, vec![(i % 251) as u8; 4096 + i]);
    }
}

#[test]
fn control_plane_stays_on_core_0() {
    let mut mc = Mc::new(4);
    mc.up();
    // aggregated numbers: 64 PGs, all primary (size 1), none of them lost in the per-core split
    assert_eq!(mc.osds[0].pg_num_pgs(), 64);
    let (lce, pgs) = mc.osds[0].pg_collect();
    assert_eq!(pgs.len(), 64);
    assert!(lce <= 10);
    assert_eq!(mc.osds[0].pg_role_counts(), (64, 64, 0));
    assert!(mc.osds[0].workers_reported());
    // capacity: the sum of all cores' shards, not core 0's alone
    let total = mc.osds[0].statfs_all().total;
    let own = crate::meta::MetaStore::statfs(mc.osds[0].store.as_ref().unwrap()).total;
    assert!(total > own * 3, "{total} vs {own}");
    // a tell command arriving on a worker core is answered by core 0 over the worker's connection
    let cl = mc.client(2);
    mc.osds[2]
        .links
        .get_mut(&cl)
        .unwrap()
        .auth
        .borrow_mut()
        .caps = Some("allow *".into());
    let cmd = messages::MCommand {
        fsid: mc.fsid,
        cmd: vec![r#"{"prefix":"version"}"#.into()],
        data: vec![],
    };
    mc.osds[2].on_link_message(cl, crate::osd::Purpose::Accepted, 77, cmd.into());
    mc.settle();
    let out = std::mem::take(&mut mc.osds[2].t.out);
    let reply = out
        .iter()
        .find(|f| f.0 == cl && f.2.0 == 98)
        .unwrap_or_else(|| panic!("no MCommandReply on the worker link: {out:?}"));
    assert_eq!(reply.1, 77);
}

/// CEPH_MSG_PING (decoded as MPing) from a client: dropped like classic does, no reply and no "unhandled" log line
/// (lab case 23 logged one every 5 s).
#[test]
fn a_client_ping_is_dropped_quietly() {
    let mut mc = Mc::new(2);
    mc.up();
    let cl = mc.client(1);
    while mc.osds[1].poll_log().is_some() {}
    mc.osds[1].on_link_message(
        cl,
        crate::osd::Purpose::Accepted,
        5,
        messages::MPing::default().into(),
    );
    mc.settle();
    let logs: Vec<String> = std::iter::from_fn(|| mc.osds[1].poll_log().map(|l| l.text)).collect();
    assert!(!logs.iter().any(|l| l.contains("unhandled")), "{logs:?}");
    assert!(!mc.osds[1].t.out.iter().any(|f| f.0 == cl), "no reply");
}

/// Open question 13d, worker path: a PG of a worker core created from a Notify stamped far below the kept maps asks the
/// control core for the stored maps (`OldMapsReq` -> `OldMaps`) and replays every interval since the sender's epoch.
/// Maps keep arriving while the request is outstanding: the worker must not trim the maps the answer ends at.
#[test]
fn worker_creates_pg_from_an_old_message_via_the_control_cores_maps() {
    const SENT: u32 = 15;
    let mut mc = Mc::new(2);
    // pool 1: size 2 in [40, 60), else 1 (only osd.0 is up: the mapping stays [0], the size changes are the intervals)
    let sized = |mc: &Mc, e: u32| {
        let mut m = mc.map(e, 10);
        m.pools.get_mut(&1).unwrap().size = if (40..60).contains(&e) { 2 } else { 1 };
        m
    };
    for e in 10..=100 {
        let m = sized(&mc, e);
        mc.deliver(m);
    }
    let n = mc.osds[0].osdmap().unwrap().pool(1).unwrap().pg_num;
    let seed = (0..n)
        .find(|s| mc.owner(1, *s) == 1)
        .expect("a PG of core 1");
    let spg = SpgT {
        pgid: PgT::new(1, seed),
        shard: denc::types::ShardId::NO_SHARD,
    };
    let mut info = pgwire::PgInfo::dne(spg);
    info.history = pgwire::PgHistory::new_pg(12, denc::types::UTime::new(1, 0));
    let notify = pgwire::MOSDPGNotify2 {
        spgid: spg,
        notify: pgwire::PgNotify {
            query_epoch: SENT,
            epoch_sent: SENT,
            info,
            to: denc::types::ShardId::NO_SHARD,
            from: denc::types::ShardId::NO_SHARD,
            past_intervals: pgwire::PastIntervals::default(),
            pg_features: 0,
        },
    };
    let (ty, ver, _c, segs) = peering::Body::Peering(notify.into())
        .encode(u64::MAX)
        .unwrap();
    mc.delay = Some(|_, m| matches!(m, XMsg::OldMapsReq { .. }));
    // osd.1 speaks on a cluster link of core 0, which forwards to the owner (core 1)
    let t = mc.t;
    let ip = [10, 1, 0, 5];
    let link = mc.osds[0].on_accept(Listener::Cluster, crate::osd::sock4(ip, 41000), t);
    mc.osds[0].links.get_mut(&link).unwrap().peer = Some(msgr2::PeerInfo {
        name: EntityName::osd(1),
        addrs: addr(ip, 6801, 556),
        features: u64::MAX,
        lossy: false,
        resumed: false,
        global_id: 1,
        auth_name: None,
    });
    mc.osds[0].set_now(t);
    mc.osds[0].on_unknown_message(link, 1, ty, ver, &segs);
    mc.settle();
    assert!(
        mc.delayed.iter().any(|(src, dst, m)| *src == 1
            && *dst == 0
            && matches!(m, XMsg::OldMapsReq { from: SENT, .. })),
        "core 1 asks core 0 for the stored maps"
    );
    assert!(
        mc.osds[1].pg.set.pg(spg).is_none(),
        "parked, not created on a newer map"
    );
    // 40 more epochs while the request is held: the worker's cache would otherwise drop everything below 90
    for e in 101..=140 {
        let m = sized(&mc, e);
        mc.deliver(m);
    }
    mc.release_delayed();
    let pg = mc.osds[1]
        .pg
        .set
        .pg(spg)
        .expect("created on core 1 from the stored start map");
    assert_eq!(pg.map_epoch(), 140);
    assert_eq!(
        pg.info().history.same_interval_since,
        60,
        "every interval replayed (40, 60), none hidden by a gap"
    );
    let (lo, _) = pg.past_intervals().bounds();
    assert!(
        lo <= SENT,
        "past intervals reach back to the sender's epoch, from {lo}"
    );
    assert!(
        mc.osds[0].pg.set.pg(spg).is_none(),
        "nothing on the control core"
    );
}

/// A worker's core map runs ahead of its PG set while the control core's gate for the new epoch is in flight. An op of
/// the new epoch that arrives in that window waits for the PG set like the earlier parked one: it never runs against
/// the older map and never overtakes a parked op of its client (ceph_test_rados "finished tid 1 when last_acked_tid
/// was 5" under the knet build, ecbad case 20).
#[test]
fn new_epoch_ops_wait_for_the_pg_set_in_order() {
    let mut mc = Mc::new(2);
    mc.up();
    let name = (0..)
        .map(|i| format!("ord{i}"))
        .find(|n| {
            let op = mc.op(1, n, vec![OsdOp::writefull(vec![1])]);
            mc.owner(1, op.pgid.pgid.seed) == 1
        })
        .unwrap();
    let cl = mc.client(1);
    mc.delay = Some(|dst, m| dst == 1 && matches!(m, XMsg::Map(_) | XMsg::Gate { .. }));
    let m = mc.map(11, 10);
    mc.deliver(m);
    assert_eq!(mc.osds[1].epoch(), 10);
    // A: newer than core 1's map, parked
    let a = mc.op(1, &name, vec![OsdOp::writefull(vec![1; 4096])]);
    assert_eq!(a.osdmap_epoch, 11);
    assert!(mc.call(1, cl, 1, a).is_empty(), "A waits for the map");
    // the map reaches core 1, the control core's gate decision not yet: core map 11, PG set 10
    let (maps, gates): (Vec<_>, Vec<_>) = std::mem::take(&mut mc.delayed)
        .into_iter()
        .partition(|(_, _, m)| matches!(m, XMsg::Map(_)));
    mc.delayed = gates;
    assert!(!maps.is_empty() && !mc.delayed.is_empty());
    let t = mc.t;
    for (from, dst, m) in maps {
        mc.osds[dst].on_xmsg(from, m, t);
    }
    mc.settle();
    assert_eq!(mc.osds[1].epoch(), 11);
    assert_eq!(mc.osds[1].pg.set.epoch(), 10);
    // B: same client, same object, sent after A
    let b = mc.op(1, &name, vec![OsdOp::writefull(vec![2; 4096])]);
    let early = mc.call(1, cl, 2, b);
    assert!(
        early.is_empty(),
        "B ran on PG set epoch 10 ahead of parked A: {early:?}"
    );
    mc.release_delayed();
    let r = mc.replies(1, cl);
    let tids: Vec<u64> = r.iter().map(|(t, _)| *t).collect();
    assert_eq!(tids, vec![1, 2], "{r:?}");
    assert!(r.iter().all(|(_, x)| x.result == 0), "{r:?}");
    assert!(r[0].1.replay_version < r[1].1.replay_version, "{r:?}");
}

#[test]
fn stale_client_gets_maps_on_its_own_core() {
    let mut mc = Mc::new(4);
    mc.up();
    let m = mc.map(11, 10);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(1));
    let cl = mc.client(1);
    let mut op = mc.op(1, "x", vec![OsdOp::stat()]);
    op.osdmap_epoch = 9; // the client lags
    let pg = op.pgid;
    let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
    mc.osds[1].on_unknown_message(cl, 5, ty, ver, &segs);
    mc.settle();
    let out = std::mem::take(&mut mc.osds[1].t.out);
    // exactly one MOSDMap (type 41) for the client, produced on core 1 whichever core owns the PG
    let maps = out.iter().filter(|f| f.0 == cl && f.2.0 == 41).count();
    assert_eq!(
        maps,
        1,
        "pg {pg:?} owner {}: {out:?}",
        mc.owner(1, pg.pgid.seed)
    );
}

#[test]
fn client_ops_cross_cores() {
    let mut mc = Mc::new(4);
    mc.up();
    write_read_all(&mut mc, 1, "obj", 96, 1);
    // ops were really forwarded: every core received ops for PGs of its own from other cores
    let fwd: Vec<u64> = mc.osds.iter().map(|o| o.cl.fwd_ops).collect();
    assert!(fwd.iter().all(|f| *f > 0), "{fwd:?}");
}

/// adr 0059 am. 1: a pool with `compression_mode` is served and the operator is told once that its chunks are compressed.
#[test]
fn pool_compression_mode_is_noted_once() {
    let mut mc = Mc::new(2);
    mc.up();
    let n = mc.osds[0].osdmap().unwrap().pool(1).unwrap().pg_num;
    let mut m = with_pg_num(&mc, 11, 1, n);
    m.pools
        .get_mut(&1)
        .unwrap()
        .opts
        .0
        .insert(6, osdmap::pool::OptVal::Str("aggressive".into()));
    mc.deliver(m);
    let m = with_pg_num(&mc, 12, 1, n);
    let mut m2 = m;
    m2.pools
        .get_mut(&1)
        .unwrap()
        .opts
        .0
        .insert(6, osdmap::pool::OptVal::Str("aggressive".into()));
    mc.deliver(m2);
    let notes = mc.osds[0]
        .logs
        .iter()
        .filter(|l| l.contains("compression_mode aggressive algorithm snappy"))
        .count();
    assert_eq!(notes, 1, "once per pool and mode: {:?}", mc.osds[0].logs);
    let cl = mc.client(0);
    let op = mc.op(1, "c", vec![OsdOp::writefull(vec![7; 8192])]);
    assert_eq!(mc.call(0, cl, 1, op)[0].1.result, 0);
}

/// adr 0059 am. 1: a pool without its own `compression_*` options follows `bluestore_compression_*`; the OSD-wide
/// statfs and the `bluestore` perf counters show what was compressed.
#[test]
fn osd_compression_defaults_statfs_and_perf() {
    let mut mc = Mc::new(2);
    mc.up();
    for o in &mut mc.osds {
        o.conf
            .set(
                crate::config::Level::Override,
                "bluestore_compression_mode",
                "force",
            )
            .unwrap();
        o.conf
            .set(
                crate::config::Level::Override,
                "bluestore_compression_algorithm",
                "lz4",
            )
            .unwrap();
        o.conf_changed();
    }
    mc.settle();
    let cl = mc.client(0);
    let data: Vec<u8> = (0..65536usize).map(|i| (i / 64 % 7) as u8).collect();
    let mut tid = 0;
    for i in 0..4 {
        tid += 1;
        let op = mc.op(1, &format!("comp{i}"), vec![OsdOp::writefull(data.clone())]);
        assert_eq!(mc.call(0, cl, tid, op)[0].1.result, 0);
    }
    mc.settle();
    let sf = mc.osds[0].statfs_all();
    assert!(
        sf.data_compressed > 0 && sf.data_compressed_original > sf.data_compressed,
        "{sf:?}"
    );
    let c = mc.osds[0].counters_now();
    assert!(c["bluestore.compress_success_count"].1.value > 0, "{c:?}");
    assert!(c["bluestore.compressed_original"].1.value > 0);
}

/// Pool option keys 9/10 are max/min respectively; use unequal bounds and prove compression runs.
#[test]
fn pool_compression_blob_bounds_follow_wire_option_keys() {
    let mut mc = Mc::new(2);
    mc.up();
    let n = mc.osds[0].osdmap().unwrap().pool(1).unwrap().pg_num;
    let mut m = with_pg_num(&mc, 11, 1, n);
    let opts = &mut m.pools.get_mut(&1).unwrap().opts.0;
    use osdmap::pool::OptVal;
    opts.insert(6, OptVal::Str("force".into()));
    opts.insert(9, OptVal::Int(65536));
    opts.insert(10, OptVal::Int(8192));
    mc.deliver(m);
    let cl = mc.client(0);
    let data: Vec<u8> = (0..65536usize).map(|i| (i / 64 % 7) as u8).collect();
    let op = mc.op(1, "pool-comp-bounds", vec![OsdOp::writefull(data)]);
    assert_eq!(mc.call(0, cl, 1, op)[0].1.result, 0);
    mc.settle();
    let successes: u64 = mc
        .osds
        .iter()
        .map(|o| o.counters_now()["bluestore.compress_success_count"].1.value)
        .sum();
    assert!(successes > 0, "no core compressed the write");
    let originals: u64 = mc
        .osds
        .iter()
        .map(|o| o.counters_now()["bluestore.compressed_original"].1.value)
        .sum();
    let compressed: u64 = mc
        .osds
        .iter()
        .map(|o| o.counters_now()["bluestore.compressed"].1.value)
        .sum();
    assert!(originals > compressed && compressed > 0);
}

/// FlashStore keeps its fixed checksum format, but must disclose unsupported pool overrides.
#[test]
fn pool_checksum_override_is_warned_on_change() {
    let mut mc = Mc::new(2);
    mc.up();
    let n = mc.osds[0].osdmap().unwrap().pool(1).unwrap().pg_num;
    for (epoch, value) in [
        (11, Some(3)),
        (12, Some(3)),
        (13, Some(4)),
        (14, Some(1)),
        (15, None),
        (16, Some(1)),
    ] {
        let mut m = with_pg_num(&mc, epoch, 1, n);
        let opts = &mut m.pools.get_mut(&1).unwrap().opts.0;
        opts.remove(&11);
        if let Some(value) = value {
            opts.insert(11, osdmap::pool::OptVal::Int(value));
        }
        mc.deliver(m);
    }
    let warnings: Vec<_> = mc.osds[0]
        .logs
        .iter()
        .filter(|l| l.contains("WARNING pool 1: csum_type"))
        .collect();
    assert_eq!(warnings.len(), 3, "{warnings:?}");
    assert!(warnings[0].contains("csum_type 3"));
    assert!(warnings[1].contains("csum_type 1"));
    assert!(warnings[2].contains("fixed crc32c"));
}

/// FU-12: a pool `read_lease_interval` the admission cap bounds is disclosed once per pool and value.
#[test]
fn pool_read_lease_cap_is_warned_once_per_pool() {
    let mut mc = Mc::new(2);
    mc.up();
    let n = mc.osds[0].osdmap().unwrap().pool(1).unwrap().pg_num;
    for (epoch, value) in [
        (11, Some(2e10)),
        (12, Some(2e10)),
        (13, Some(5.0)),
        (14, Some(f64::INFINITY)),
        (15, Some(f64::INFINITY)),
        (16, None),
    ] {
        let mut m = with_pg_num(&mc, epoch, 1, n);
        let opts = &mut m.pools.get_mut(&1).unwrap().opts.0;
        opts.remove(&19);
        if let Some(value) = value {
            opts.insert(19, osdmap::pool::OptVal::Double(value));
        }
        mc.deliver(m);
    }
    let warnings: Vec<_> = mc.osds[0]
        .logs
        .iter()
        .filter(|l| l.contains("WARNING pool 1: read_lease_interval"))
        .collect();
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(warnings[0].contains("20000000000 s"), "{warnings:?}");
    assert!(warnings[1].contains("inf s"), "{warnings:?}");
    assert!(warnings[1].contains("using 1073741824 s"), "{warnings:?}");
}

/// A valid peer pool can request an algorithm absent from this store; disclose the fallback.
#[test]
fn unsupported_pool_compression_algorithm_is_warned() {
    let mut mc = Mc::new(2);
    mc.up();
    let n = mc.osds[0].osdmap().unwrap().pool(1).unwrap().pg_num;
    for (epoch, alg) in [(11, "snappy"), (12, "brotli"), (13, "brotli"), (14, "none")] {
        let mut m = with_pg_num(&mc, epoch, 1, n);
        let opts = &mut m.pools.get_mut(&1).unwrap().opts.0;
        opts.insert(6, osdmap::pool::OptVal::Str("force".into()));
        opts.insert(7, osdmap::pool::OptVal::Str(alg.into()));
        mc.deliver(m);
    }
    let logs = &mc.osds[0].logs;
    assert_eq!(
        logs.iter()
            .filter(|l| l.contains(
                "WARNING pool 1: compression algorithm 'brotli' unsupported; storing uncompressed"
            ))
            .count(),
        1,
        "{logs:?}"
    );
    assert!(
        logs.iter()
            .any(|l| l.contains("compression_mode force algorithm none: compression disabled")),
        "{logs:?}"
    );
    // pools that never compressed (mode none since the first map) are not reported
    assert!(
        !logs.iter().any(|l| l.contains("compression_mode none")),
        "{logs:?}"
    );
}

/// Pool snapshots (`rados mksnap`): the map puts pool 1 in pool-snap mode; writes without any client snap context clone
/// for the pool's snap, reads at the snap id see the old data, rmsnap hides it again.
#[test]
fn pool_snapshot_clones_come_from_the_map() {
    let mut mc = Mc::new(2);
    mc.up();
    let cl = mc.client(0);
    let n = mc.osds[0].osdmap().unwrap().pool(1).unwrap().pg_num;
    let w = |mc: &mut Mc, tid: u64, data: &[u8]| {
        let op = mc.op(1, "snapobj", vec![OsdOp::writefull(data.to_vec())]);
        mc.call(0, cl, tid, op)[0].1.result
    };
    let rd = |mc: &mut Mc, tid: u64, snap: u64| {
        let mut op = mc.op(1, "snapobj", vec![OsdOp::read(0, 100)]);
        op.snapid = snap;
        let r = mc.call(0, cl, tid, op);
        (r[0].1.result, r[0].1.ops[0].outdata.to_vec())
    };
    assert_eq!(w(&mut mc, 1, b"first"), 0);
    // mksnap: pool flag + snap in the map
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
    assert_eq!(rd(&mut mc, 3, 1), (0, b"first".to_vec()));
    assert_eq!(rd(&mut mc, 4, opwire::NOSNAP), (0, b"second".to_vec()));
    // rmsnap: snap leaves the pool, the mon queues it as removed
    let mut m = with_pg_num(&mc, 12, 1, n);
    let p = m.pools.get_mut(&1).unwrap();
    p.flags |= osdmap::pool::flags::POOL_SNAPS;
    p.snap_seq = 1;
    p.snap_epoch = 12;
    m.removed_snaps_queue.entry(1).or_default().0.insert(1, 1);
    mc.deliver(m);
    assert_eq!(rd(&mut mc, 5, 1).0, -opwire::errno::ENOENT);
    assert_eq!(rd(&mut mc, 6, opwire::NOSNAP), (0, b"second".to_vec()));
    // the trimmer deletes the clone of the removed pool snap
    let clones = |mc: &mut Mc, tid: u64| {
        let mut op = mc.op(1, "snapobj", vec![OsdOp::list_snaps()]);
        op.snapid = opwire::SNAPDIR;
        let r = mc.call(0, cl, tid, op);
        let l: opwire::ObjListSnapResponse = denc::from_slice(&r[0].1.ops[0].outdata).unwrap();
        l.clones.len()
    };
    mc.run_for(Duration::from_secs(5));
    assert_eq!(clones(&mut mc, 8), 1, "only the head after trimming");
}

/// copy-from: the destination PG pulls its source from the PG that holds it (same core, another core, same PG).
#[test]
fn copy_from_routes_source_reads_across_pgs_and_cores() {
    let mut mc = Mc::new(4);
    mc.up();
    let clients: Vec<u64> = (0..mc.n).map(|c| mc.client(c)).collect();
    let n_pg = mc.osds[0].osdmap().unwrap().pool(1).unwrap().pg_num;
    let owner = |mc: &Mc, name: &str| {
        let m = mc.osds[0].osdmap().unwrap();
        let raw = m
            .object_to_raw_pg(1, name.as_bytes(), b"", b"", -1)
            .unwrap();
        let pg = pgwire::pgmath::object_pg(raw.seed, n_pg);
        (pg, mc.owner(1, pg))
    };
    let (mut same_pg, mut same_core, mut cross_core) = (0, 0, 0);
    for i in 0..40usize {
        let (src, dst) = (format!("src{i}"), format!("dst{i}"));
        let c = i % mc.n;
        let body = vec![(i % 251) as u8; 3000 + i];
        let w = mc.op(
            1,
            &src,
            vec![
                OsdOp::writefull(body.clone()),
                OsdOp::setxattr(b"x", src.as_bytes()),
            ],
        );
        assert_eq!(mc.call(c, clients[c], 10 + i as u64, w)[0].1.result, 0);
        let cp = OsdOp::copy_from_req(
            opwire::op::COPY_FROM2,
            src.as_bytes(),
            &denc::types::ObjectLocator {
                pool: 1,
                key: vec![],
                nspace: vec![],
                hash: -1,
            },
            opwire::NOSNAP,
            0,
            0,
            None,
        );
        let op = mc.op(1, &dst, vec![cp]);
        let r = mc.call(c, clients[c], 100 + i as u64, op);
        assert_eq!(r.len(), 1, "copy {i}: {r:?}");
        assert_eq!(r[0].1.result, 0, "copy {i}");
        let (a, b) = (owner(&mc, &src), owner(&mc, &dst));
        if a.0 == b.0 {
            same_pg += 1;
        } else if a.1 == b.1 {
            same_core += 1;
        } else {
            cross_core += 1;
        }
        let rd = mc.op(
            1,
            &dst,
            vec![OsdOp::read(0, 100_000), OsdOp::getxattr(b"x")],
        );
        let r = mc.call((i + 1) % mc.n, clients[(i + 1) % mc.n], 200 + i as u64, rd);
        assert_eq!(r[0].1.result, 0, "read {i}");
        assert_eq!(r[0].1.ops[0].outdata, body, "data {i}");
        assert_eq!(r[0].1.ops[1].outdata, src.as_bytes(), "xattr {i}");
    }
    assert!(
        same_core > 0 && cross_core > 0,
        "{same_pg}/{same_core}/{cross_core}"
    );
    // a missing source is an ENOENT for the caller, not a hang
    let cp = OsdOp::copy_from_req(
        opwire::op::COPY_FROM2,
        b"ghost",
        &denc::types::ObjectLocator {
            pool: 1,
            key: vec![],
            nspace: vec![],
            hash: -1,
        },
        opwire::NOSNAP,
        0,
        0,
        None,
    );
    let op = mc.op(1, "dst-ghost", vec![cp]);
    let r = mc.call(0, clients[0], 999, op);
    assert_eq!(r[0].1.result, -opwire::errno::ENOENT);
    assert!(mc.osds.iter().all(|o| o.pg.cp.is_empty()), "no read left");
}

// ---------------------------------------------------------------------------------------------------------------------
// observability (perf counters, op tracker, scattered commands, beacon)

mod obs {
    use super::*;
    use crate::config::Level;
    use crate::tell::ReplyTo;
    use serde_json::Value;

    /// Move cross-core messages only: no store polling, no time (the held write stays in flight).
    fn xfer(mc: &mut Mc) {
        loop {
            let mut moved = false;
            for i in 0..mc.n {
                while let Some((dst, m)) = mc.osds[i].poll_xmsg() {
                    moved = true;
                    let t = mc.t;
                    mc.osds[dst].on_xmsg(i, m, t);
                }
            }
            if !moved {
                return;
            }
        }
    }

    fn ask(mc: &mut Mc, cmd: &str) -> (i32, serde_json::Value) {
        ask_with(mc, cmd, true)
    }

    /// Run a JSON command on core 0 as an admin socket request; `settle` = let the OSD run on (completes held writes).
    fn ask_with(mc: &mut Mc, cmd: &str, settle: bool) -> (i32, Value) {
        let (tx, rx) = std::sync::mpsc::channel();
        mc.osds[0].cmds.seq += 1;
        let tok = mc.osds[0].cmds.seq;
        mc.osds[0].cmds.pending.insert(tok, tx);
        let t = mc.t;
        mc.osds[0].set_now(t);
        mc.osds[0].exec_command(cmd, ReplyTo::Asok(tok));
        if settle {
            mc.settle();
        } else {
            xfer(mc);
        }
        let (r, rs, out) = rx.try_recv().expect("command answered");
        (
            r,
            serde_json::from_slice(&out.into_bytes()).unwrap_or(Value::String(rs)),
        )
    }

    #[test]
    fn perf_counters_count_client_ops() {
        let mut mc = Mc::new(4);
        mc.up();
        write_read_all(&mut mc, 1, "p", 8, 1);
        mc.run_for(Duration::from_secs(2)); // the workers report their numbers once a second
        let c = mc.osds[0].counters_now();
        let v = |n: &str| c[&format!("osd.{n}")].1;
        let wbytes: u64 = (0..8).map(|i| 4096 + i).sum();
        assert_eq!(v("op").value, 16);
        assert_eq!(
            (v("op_w").value, v("op_r").value, v("op_rw").value),
            (8, 8, 0)
        );
        assert_eq!(v("op_in_bytes").value, wbytes);
        assert_eq!(v("op_w_in_bytes").value, wbytes);
        assert_eq!(v("op_out_bytes").value, wbytes);
        assert_eq!(v("op_r_out_bytes").value, wbytes);
        assert_eq!(
            (v("op_latency").avgcount, v("op_latency").avgcount2),
            (16, 16)
        );
        assert_eq!(v("op_w_latency").avgcount, 8);
        assert_eq!(v("op_wip").value, 0);
        // classic JSON shape, avgtime = sum / avgcount
        let (r, d) = ask(&mut mc, r#"{"prefix":"perf dump"}"#);
        assert_eq!(r, 0);
        let l = &d["osd"]["op_latency"];
        assert_eq!(l["avgcount"], 16);
        let (sum, avg) = (l["sum"].as_f64().unwrap(), l["avgtime"].as_f64().unwrap());
        assert!(sum > 0.0, "{l}");
        assert!((avg - sum / 16.0).abs() < 1e-9, "{l}");
        let (_, d) = ask(
            &mut mc,
            r#"{"prefix":"perf dump","logger":"osd","counter":"op_r"}"#,
        );
        assert_eq!(d["osd"], serde_json::json!({"op_r": 8}));
        let (_, s) = ask(&mut mc, r#"{"prefix":"perf schema"}"#);
        assert_eq!(s["osd"]["op_latency"]["value_type"], "real-integer-pair");
        assert_eq!(s["osd"]["op"]["metric_type"], "counter");
        assert_eq!(s["osd"]["numpg"]["metric_type"], "gauge");
        let (_, cd) = ask(&mut mc, r#"{"prefix":"counter dump"}"#);
        assert_eq!(cd["osd"][0]["counters"]["op"], 16);
        // the mgr report packs (sum, count, count) for averages
        let mut rep = messages::PerfReporter::new();
        let r = rep.build(&mc.osds[0].counters_now(), 0).unwrap();
        let types: Vec<&messages::PerfCounterType> = r.declare_types.iter().collect();
        let vals = messages::decode_packed(&types, &r.packed).unwrap();
        let i = types
            .iter()
            .position(|t| t.path == "osd.op_latency")
            .unwrap();
        assert_eq!((vals[i].avgcount, vals[i].avgcount2), (16, 16));
        // secondary loggers fed by the live PGs: commits timed
        let c = mc.osds[0].counters_now();
        assert!(c["bluestore.txc_count"].1.value > 0);
        assert_eq!(c["throttle-osd_client_messages.val"].1.value, 0);
        assert!(c["throttle-osd_client_messages.get"].1.value >= 16);
        assert!(c["bluestore.allocated"].1.value > 0);
        // perf reset: counters restart, gauges stay
        let (r, _) = ask(&mut mc, r#"{"prefix":"perf reset","var":"all"}"#);
        assert_eq!(r, 0);
        assert_eq!(mc.osds[0].counters_now()["osd.op"].1.value, 0);
        assert!(mc.osds[0].counters_now()["osd.numpg"].1.value > 0);
    }

    /// Op counters (spec ops-observability.md 2d): a request is classified by its op codes, never by the client
    /// READ/WRITE flags (`stat`+`delete` = rw, `stat` alone = read, `delete` alone = write), and an error reply moves
    /// no counter.
    #[test]
    fn op_counters_follow_the_op_codes_not_the_client_flags() {
        let mut mc = Mc::new(2);
        mc.up();
        write_read_all(&mut mc, 1, "cls", 2, 1);
        // one request without any client READ/WRITE flag, run on the core that owns its PG
        let run = |mc: &mut Mc,
                   oid: &str,
                   ops: Vec<OsdOp>,
                   tid: u64|
         -> (usize, i32, (u64, u64, u64, u64)) {
            let mut op = mc.op(1, oid, ops);
            op.flags = 0;
            let core = mc.owner(1, op.pgid.pgid.seed);
            let cl = mc.client(core);
            let before = {
                let o = &mc.osds[core].perf.op;
                (o.op, o.op_r, o.op_w, o.op_rw)
            };
            let r = mc.call(core, cl, tid, op);
            (core, r[0].1.result, before)
        };
        // both mode bits in one request: a read-write op although the client set no flag at all
        let (core, r, before) = run(&mut mc, "cls0", vec![OsdOp::stat(), OsdOp::delete()], 700);
        assert_eq!(r, 0);
        {
            let o = &mc.osds[core].perf.op;
            assert_eq!(
                (o.op, o.op_r, o.op_w, o.op_rw),
                (before.0 + 1, before.1, before.2, before.3 + 1)
            );
            assert_eq!((o.op_rw_in, o.op_rw_out), (0, 0));
        }
        // read only
        let (core, r, before) = run(&mut mc, "cls1", vec![OsdOp::stat()], 701);
        assert_eq!(r, 0);
        {
            let o = &mc.osds[core].perf.op;
            assert_eq!(
                (o.op, o.op_r, o.op_w, o.op_rw),
                (before.0 + 1, before.1 + 1, before.2, before.3)
            );
        }
        // write only
        let (core, r, before) = run(&mut mc, "cls1", vec![OsdOp::delete()], 702);
        assert_eq!(r, 0);
        {
            let o = &mc.osds[core].perf.op;
            assert_eq!(
                (o.op, o.op_r, o.op_w, o.op_rw),
                (before.0 + 1, before.1, before.2 + 1, before.3)
            );
        }
        // an error reply is counted nowhere
        let (core, r, before) = run(&mut mc, "gone", vec![OsdOp::stat()], 703);
        assert!(r < 0);
        {
            let o = &mc.osds[core].perf.op;
            assert_eq!(
                (o.op, o.op_r, o.op_w, o.op_rw),
                (before.0, before.1, before.2, before.3)
            );
        }
    }

    #[test]
    fn op_tracker_off_keeps_no_per_op_record() {
        let mut mc = Mc::new(2);
        mc.up();
        for o in &mut mc.osds {
            o.conf
                .set(Level::Override, "osd_enable_op_tracker", "false")
                .unwrap();
            o.refresh_obs_conf();
        }
        let name = (0..)
            .map(|i| format!("off{i}"))
            .find(|n| {
                let op = mc.op(1, n, vec![OsdOp::writefull(vec![1])]);
                mc.owner(1, op.pgid.pgid.seed) == 1
            })
            .unwrap();
        let cl = mc.client(1);
        let op = mc.op(1, &name, vec![OsdOp::writefull(vec![7; 4096])]);
        let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
        let t0 = mc.t;
        mc.osds[1].set_now(t0);
        mc.osds[1].on_unknown_message(cl, 9, ty, ver, &segs);
        assert_eq!(mc.osds[1].tracker.len(), 0);
    }

    #[test]
    fn nt_health_ec_pg_observer_records_served_states() {
        let mut mc = Mc::new(2);
        mc.ec4 = true;
        mc.up();
        let mut ec_pgs = 0;
        for o in &mut mc.osds {
            o.set_now(mc.t);
            let states: Vec<_> =
                o.pg.set
                    .pgs()
                    .filter(|(_, pg)| pg.is_ec_pool())
                    .map(|(spg, _)| (*spg, "peering".to_owned()))
                    .collect();
            ec_pgs += states.len();
            o.pg_observe(&states);
            o.set_now(mc.t + Duration::from_secs(3));
            let states: Vec<_> = states
                .into_iter()
                .map(|(spg, _)| (spg, "active+clean".to_owned()))
                .collect();
            o.pg_observe(&states);
            assert_eq!(o.perf.op.rs[0].n, states.len() as u64);
            assert_eq!(o.perf.op.rs[0].sum_ns, states.len() as u64 * 3_000_000_000);
        }
        assert!(ec_pgs > 0);
    }

    #[test]
    fn nt_health_tracker_disable_during_write_does_not_leave_a_slow_op() {
        let mut mc = Mc::new(2);
        mc.up();
        let name = (0..)
            .map(|i| format!("toggle{i}"))
            .find(|n| {
                let op = mc.op(1, n, vec![OsdOp::writefull(vec![1])]);
                mc.owner(1, op.pgid.pgid.seed) == 1
            })
            .unwrap();
        let cl = mc.client(1);
        let op = mc.op(1, &name, vec![OsdOp::writefull(vec![7; 4096])]);
        let (ty, ver, _, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
        mc.osds[1].on_unknown_message(cl, 9, ty, ver, &segs);
        assert_eq!(mc.osds[1].tracker.len(), 1);
        mc.osds[1]
            .conf
            .set(Level::Override, "osd_enable_op_tracker", "false")
            .unwrap();
        mc.osds[1].refresh_obs_conf();
        mc.settle();
        assert!(mc.osds[1].t.out.iter().any(|f| f.0 == cl && f.1 == 9));
        assert_eq!(mc.osds[1].tracker.len(), 0, "completed record must close");
        mc.run_for(Duration::from_secs(40));
        assert_eq!(mc.osds[0].op_perf_all().wip, 0);
        assert!(mc.osds[0].health_metrics().iter().all(|m| m.value == 0));
    }

    #[test]
    fn slow_ops_are_tracked_reported_and_dumped() {
        let mut mc = Mc::new(2);
        mc.up();
        // an object on core 1's PG, a client on core 1: the write stays in the store (no settle)
        let name = (0..)
            .map(|i| format!("slow{i}"))
            .find(|n| {
                let op = mc.op(1, n, vec![OsdOp::writefull(vec![1])]);
                mc.owner(1, op.pgid.pgid.seed) == 1
            })
            .unwrap();
        let cl = mc.client(1);
        let op = mc.op(1, &name, vec![OsdOp::writefull(vec![7; 4096])]);
        let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
        let t0 = mc.t;
        mc.osds[1].set_now(t0);
        mc.osds[1].on_unknown_message(cl, 9, ty, ver, &segs);
        // the core loop ends its pass (the WAL unit is sealed and written) and the device completes; the op stays
        // un-acked until the next store poll: the reply waits for it below
        mc.osds[1].end_pass();
        mc.osds[1].pg.store.with_store(|s| s.idle());
        assert_eq!(mc.osds[1].tracker.len(), 1);
        assert_eq!(mc.osds[1].op_perf_local().wip, 1);
        for o in &mut mc.osds {
            o.conf
                .set(Level::Override, "osd_op_complaint_time", "30")
                .unwrap();
            o.refresh_obs_conf();
        }
        // 4 s in flight, younger than osd_op_complaint_time (30 s): SLOW_OPS 0/0 like classic; an age without a
        // count is a SLOW_OPS warning at the mgr ("0 slow ops, oldest one blocked for 4 sec", ec-migrate 2026-11-05)
        let young = t0 + Duration::from_secs(4);
        for o in &mut mc.osds {
            o.set_now(young);
        }
        assert_eq!(mc.osds[1].op_perf_local().slow_n, 0);
        mc.osds[1].push_stats();
        while let Some((_, m)) = mc.osds[1].poll_xmsg() {
            mc.osds[0].on_xmsg(1, m, young);
        }
        assert_eq!(
            mc.osds[0].health_metrics()[0].value,
            0,
            "no slow op, no age"
        );
        // 40 s later: older than osd_op_complaint_time (30 s)
        let later = t0 + Duration::from_secs(40);
        for o in &mut mc.osds {
            o.set_now(later);
        }
        assert_eq!(mc.osds[1].op_perf_local().slow_n, 1);
        // the worker ships its numbers; core 0 turns them into the SLOW_OPS daemon health metric
        mc.osds[1].push_stats();
        while let Some((dst, m)) = mc.osds[1].poll_xmsg() {
            assert_eq!(dst, 0);
            mc.osds[0].on_xmsg(1, m, later);
        }
        let h = mc.osds[0].health_metrics();
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].ty, messages::DaemonHealthMetric::SLOW_OPS);
        assert_eq!(h[0].value & 0xffff_ffff, 1, "count");
        assert!(h[0].value >> 32 >= 40, "oldest age {}", h[0].value >> 32);
        assert_eq!(h[1].ty, messages::DaemonHealthMetric::PENDING_CREATING_PGS);
        assert_eq!(h[1].value, 0);
        // dump_ops_in_flight / dump_blocked_ops show it (scattered: core 1 answers)
        mc.t = later;
        let (r, d) = ask_with(&mut mc, r#"{"prefix":"dump_ops_in_flight"}"#, false);
        assert_eq!((r, d["num_ops"].as_u64()), (0, Some(1)), "{d}");
        let op = &d["ops"][0];
        assert!(op["description"].as_str().unwrap().contains(&name), "{op}");
        assert!(op["age"].as_f64().unwrap() >= 40.0);
        assert_eq!(op["type_data"]["flag_point"], "reached pg");
        let (_, d) = ask_with(&mut mc, r#"{"prefix":"dump_blocked_ops"}"#, false);
        assert_eq!(d["num_blocked_ops"], 1, "classic blocked form: {d}");
        // completing the op clears the metric and fills the history
        mc.settle();
        let out = std::mem::take(&mut mc.osds[1].t.out);
        assert!(out.iter().any(|f| f.0 == cl && f.1 == 9), "reply sent");
        assert_eq!(mc.osds[1].tracker.len(), 0);
        mc.osds[1].push_stats();
        while let Some((_, m)) = mc.osds[1].poll_xmsg() {
            mc.osds[0].on_xmsg(1, m, later);
        }
        assert!(mc.osds[0].health_metrics().iter().all(|m| m.value == 0));
        let (_, d) = ask(&mut mc, r#"{"prefix":"dump_historic_ops"}"#);
        assert_eq!(d["ops"].as_array().unwrap().len(), 1, "{d}");
        assert_eq!(d["ops"][0]["type_data"]["flag_point"], "done");
        let (_, d) = ask(&mut mc, r#"{"prefix":"dump_historic_ops_by_duration"}"#);
        assert_eq!(d["ops"].as_array().unwrap().len(), 1);
        let (_, d) = ask(&mut mc, r#"{"prefix":"dump_historic_slow_ops"}"#);
        assert_eq!(
            d["ops"].as_array().unwrap().len(),
            1,
            "40 s >= slow threshold: {d}"
        );
    }

    /// Incident 2026-11-06 (SLOW_OPS `[watch]` of RBD clients for 130-170 s, until the next OSD restart): an op the
    /// primary drops inside a live backoff of its session gets no reply. A linger op (watch / notify) is never resent
    /// with that tid: the Objecter re-registers under a NEW tid on the next interval. The op-tracker record of the
    /// dropped tid stayed until the session closed (SLOW_OPS, `dump_ops_in_flight` "reached pg", shutdown drain).
    #[test]
    fn ops_dropped_inside_a_backoff_leave_the_op_tracker() {
        use opwire::consts::{backoff as bo, watch_op};
        let mut mc = Mc::new(2);
        mc.up();
        let name = (0..)
            .map(|i| format!("rbd_header.{i}"))
            .find(|n| {
                let op = mc.op(1, n, vec![OsdOp::stat()]);
                mc.owner(1, op.pgid.pgid.seed) == 1
            })
            .unwrap();
        let cl = mc.client(1);
        let watch = |mc: &Mc, sub| mc.op(1, &name, vec![OsdOp::watch_op(0xAB, sub, 30)]);
        let op = mc.op(1, &name, vec![OsdOp::create(false)]);
        assert_eq!(mc.call(1, cl, 1, op)[0].1.result, 0);
        let op = watch(&mc, watch_op::WATCH);
        assert_eq!(mc.call(1, cl, 2, op)[0].1.result, 0);
        // the op replies and backoffs sent on the client link since the last look: `(tid, message)`
        let frames = |mc: &mut Mc| -> Vec<(u64, ClientMsg)> {
            let out = std::mem::take(&mut mc.osds[1].t.out);
            let (mine, keep): (Vec<_>, Vec<_>) = out.into_iter().partition(|f| f.0 == cl);
            mc.osds[1].t.out = keep;
            mine.into_iter()
                .filter_map(|(_, tid, (ty, ver, _), segs)| {
                    match opwire::decode_client(ty, ver, &segs) {
                        Ok(m @ (ClientMsg::OpReply(_) | ClientMsg::Backoff(_))) => Some((tid, m)),
                        _ => None,
                    }
                })
                .collect()
        };
        let send = |mc: &mut Mc, tid: u64, m: ClientMsg| {
            let (ty, ver, _c, segs) = m.encode(u64::MAX).unwrap();
            let t = mc.t;
            mc.osds[1].set_now(t);
            mc.osds[1].on_unknown_message(cl, tid, ty, ver, &segs);
            mc.settle();
        };
        // min_size 2 on a size-1 pool: new interval, the PG peers but cannot go active (PEERED: client io backed off)
        let mut m = mc.map(11, 10);
        m.pools.get_mut(&1).unwrap().min_size = 2;
        mc.deliver(m);
        let _ = frames(&mut mc);
        // the client re-registers its watch for the new interval: PG-wide BLOCK, no reply
        let op = ClientMsg::Op(watch(&mc, watch_op::RECONNECT));
        send(&mut mc, 3, op);
        let f = frames(&mut mc);
        let block = match &f[..] {
            [(_, ClientMsg::Backoff(b))] if b.op == bo::BLOCK => b.clone(),
            other => panic!("expected one BLOCK: {other:?}"),
        };
        // sent before the client processed the BLOCK (another interval, another re-registration): dropped without a
        // message; the client cancels it locally and never resends tid 4
        let op = ClientMsg::Op(watch(&mc, watch_op::RECONNECT));
        send(&mut mc, 4, op);
        assert!(frames(&mut mc).is_empty(), "dropped inside the backoff");
        let ack = opwire::MOSDBackoff {
            op: bo::ACK_BLOCK,
            ..block
        };
        send(&mut mc, 0, ClientMsg::Backoff(ack));
        // min_size 1 again: active, UNBLOCK; the client re-registers once more under a new tid
        let m = mc.map(12, 10);
        mc.deliver(m);
        let unblocked = frames(&mut mc)
            .iter()
            .any(|(_, m)| matches!(m, ClientMsg::Backoff(b) if b.op == bo::UNBLOCK));
        assert!(unblocked, "UNBLOCK on activation");
        let op = watch(&mc, watch_op::RECONNECT);
        assert_eq!(mc.call(1, cl, 5, op)[0].1.result, 0);
        // no record outlives its op: nothing live, no SLOW_OPS once the complaint time has passed
        assert_eq!(mc.osds[1].tracker.len(), 0, "{:?}", mc.osds[1].tracker);
        let later = mc.t + Duration::from_secs(40);
        for o in &mut mc.osds {
            o.set_now(later);
        }
        assert_eq!(mc.osds[1].op_perf_local().slow_n, 0);
    }

    #[test]
    fn flush_pg_stats_refreshes_every_core() {
        let mut mc = Mc::new(4);
        mc.up();
        mc.run_for(Duration::from_secs(2));
        // ops since the last 1 s report: core 0's view of the workers is stale
        write_read_all(&mut mc, 1, "f", 12, 1);
        let real: u64 = mc.osds.iter().map(|o| o.perf.op.op).sum();
        assert_eq!(real, 24);
        let (r, d) = ask(&mut mc, r#"{"prefix":"flush_pg_stats"}"#);
        assert_eq!(r, 0, "{d}");
        assert!(d["stat_seq"].is_u64(), "{d}");
        for c in 1..4 {
            let s = mc.osds[0].cl.stats[c].as_ref().unwrap();
            assert_eq!(
                s.counters.perf.op, mc.osds[c].perf.op.op,
                "core {c} numbers are fresh"
            );
        }
        assert_eq!(mc.osds[0].op_perf_all().op, 24);
        // dump_pgs / pg query reach PGs of every core
        let (_, d) = ask(&mut mc, r#"{"prefix":"dump_pgs"}"#);
        assert_eq!(d["pgs"].as_array().unwrap().len(), 64);
        let on3 = mc.pgs()[3][0];
        let pgid = format!("{}.{:x}", on3.0, on3.1);
        let (r, q) = ask(
            &mut mc,
            &format!(r#"{{"prefix":"pg","pgid":"{pgid}","cmd":"query"}}"#),
        );
        assert_eq!(r, 0, "{q}");
        assert_eq!(
            q["state"].as_str().map(|s| s.contains("active")),
            Some(true)
        );
        let (r, _) = ask(&mut mc, r#"{"prefix":"pg","pgid":"9.9","cmd":"query"}"#);
        assert_eq!(r, -2);
    }

    #[test]
    fn beacon_carries_min_last_epoch_clean_and_the_primary_pgs() {
        let mut mc = Mc::new(4);
        mc.up();
        mc.osds[0].t.sent.clear();
        mc.osds[0].send_beacon();
        let b = mc.osds[0]
            .t
            .sent
            .iter()
            .find_map(|m| match m {
                messages::AnyMessage::MOSDBeacon(b) => Some(b.clone()),
                _ => None,
            })
            .expect("beacon sent");
        // collected at send time (no mgr in this test): every PG of every core is primary and clean
        assert_eq!(b.pgs.len(), 64);
        assert!(b.min_last_epoch_clean >= 1 && b.min_last_epoch_clean <= mc.osds[0].epoch());
        assert_eq!(b.version, u64::from(mc.osds[0].epoch()));
    }

    #[test]
    fn debug_osd_level_filters_our_log() {
        let mut mc = Mc::new(1);
        let o = &mut mc.osds[0];
        o.logs.clear();
        o.logl(10, "chatty");
        assert!(o.logs.is_empty());
        o.conf.set(Level::Override, "debug_osd", "10/20").unwrap();
        o.refresh_obs_conf();
        o.logl(10, "chatty");
        assert_eq!(o.logs.len(), 1);
        o.logl(11, "chattier");
        assert_eq!(o.logs.len(), 1);
    }

    // ---------------------------------------------------------------- sampled op tracing (trace.rs)

    fn trace_on(mc: &mut Mc, n: &str) {
        for o in &mut mc.osds {
            o.conf
                .set(Level::Override, "flashstore_trace_sample", n)
                .unwrap();
            o.refresh_obs_conf();
        }
    }

    /// The sim has no driver loop: the tx step of every core ends here.
    fn trace_tx(mc: &mut Mc) {
        for o in &mut mc.osds {
            o.trace_tx_done();
        }
    }

    fn traces(mc: &mut Mc) -> Vec<Value> {
        let (r, d) = ask(mc, r#"{"prefix":"dump_op_traces","format":"json"}"#);
        assert_eq!(r, 0, "{d}");
        d["traces"].as_array().unwrap().clone()
    }

    fn stages(t: &Value) -> Vec<&str> {
        t["stages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["stage"].as_str().unwrap())
            .collect()
    }

    #[test]
    fn sampled_ops_leave_complete_traces_across_cores() {
        let mut mc = Mc::new(4);
        mc.up();
        // off: nothing is recorded
        write_read_all(&mut mc, 1, "off", 4, 1);
        trace_tx(&mut mc);
        assert!(traces(&mut mc).is_empty());
        trace_on(&mut mc, "1");
        write_read_all(&mut mc, 1, "tr", 8, 100);
        trace_tx(&mut mc);
        let t = traces(&mut mc);
        assert_eq!(t.len(), 16, "{t:?}");
        for x in &t {
            assert_eq!(x["complete"], true, "{x}");
            assert_eq!(x["role"], "primary");
        }
        let w: Vec<_> = t.iter().filter(|x| x["type"] == "write").collect();
        let r: Vec<_> = t.iter().filter(|x| x["type"] == "read").collect();
        assert_eq!((w.len(), r.len()), (8, 8));
        for x in &w {
            let s = stages(x);
            for n in [
                "rx", "routed", "pg_in", "pg_run", "submit", "durable", "reply", "tx",
            ] {
                assert!(s.contains(&n), "{n} in {s:?}");
            }
            let at = |n: &str| s.iter().position(|x| *x == n).unwrap();
            assert!(
                at("pg_in") < at("pg_run") && at("pg_run") < at("submit"),
                "{s:?}"
            );
            let sg = |n: &str| x["segments"][n].as_u64().unwrap();
            let sum = sg("pg_wait") + sg("pg_work");
            assert!(sum.abs_diff(sg("exec")) <= 2, "{sum} vs {}", sg("exec"));
            assert!(x["segments"]["store"].is_u64());
            assert_eq!(x["op"], "writefull");
        }
        // an op whose connection core is not its PG core shows both cores
        assert!(
            t.iter().any(|x| {
                let c: std::collections::BTreeSet<_> = x["stages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| s["core"].as_u64().unwrap())
                    .collect();
                c.len() >= 2
            }),
            "no op crossed cores"
        );
        // summary + last + historic events from the same stamps
        let (r, s) = ask(&mut mc, r#"{"prefix":"trace_summary","format":"json"}"#);
        assert_eq!((r, s["complete"].as_u64()), (0, Some(16)), "{s}");
        assert!(
            s["classes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["type"] == "write" && c["segments"]["store"]["n"].as_u64() > Some(0))
        );
        let (_, d) = ask(
            &mut mc,
            r#"{"prefix":"dump_op_traces","format":"json","last":3}"#,
        );
        assert_eq!(d["traces"].as_array().unwrap().len(), 3);
        let (_, h) = ask(&mut mc, r#"{"prefix":"dump_historic_ops"}"#);
        let ev = |o: &Value| -> Vec<String> {
            o["type_data"]["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["event"].as_str().unwrap().to_owned())
                .collect()
        };
        assert!(
            h["ops"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| ev(o).contains(&"started".to_owned())
                    && ev(o).contains(&"commit_sent".to_owned())),
            "{h}"
        );
        let (r, _) = ask(&mut mc, r#"{"prefix":"trace_reset"}"#);
        assert_eq!(r, 0);
        assert!(traces(&mut mc).is_empty());
    }

    #[test]
    fn sampling_one_in_n_picks_a_stable_subset() {
        let mut mc = Mc::new(2);
        mc.up();
        trace_on(&mut mc, "4");
        write_read_all(&mut mc, 1, "s", 40, 1);
        trace_tx(&mut mc);
        let t = traces(&mut mc);
        assert!(!t.is_empty() && t.len() < 80, "{}", t.len());
        // the same requests are picked on a second run (deterministic rule)
        let mut a: Vec<_> = t
            .iter()
            .map(|x| x["trace_id"].as_str().unwrap().to_owned())
            .collect();
        a.sort();
        let mut mc2 = Mc::new(2);
        mc2.up();
        trace_on(&mut mc2, "4");
        write_read_all(&mut mc2, 1, "s", 40, 1);
        trace_tx(&mut mc2);
        let mut b: Vec<_> = traces(&mut mc2)
            .iter()
            .map(|x| x["trace_id"].as_str().unwrap().to_owned())
            .collect();
        b.sort();
        assert_eq!(a, b);
    }

    /// Replicated write: the primary stamps its repop send / ack per peer, the replica OSD records its own part under
    /// the same trace id (sampled by the same rule, no wire change).
    #[test]
    fn replica_part_of_a_sampled_write_shares_the_trace_id() {
        let mut p = Pair::new(4, 2);
        p.up();
        trace_on(&mut p.a, "1");
        trace_on(&mut p.b, "1");
        let map = p.a.osds[0].osdmap().unwrap().clone();
        let name = "trrep";
        let raw = map
            .object_to_raw_pg(1, name.as_bytes(), b"", b"", -1)
            .unwrap();
        let pg = PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32));
        let primary = map.pg_to_up_acting(pg).acting_primary;
        let pn = p.node(primary);
        let cl = pn.client(0);
        let op = pn.op(1, name, vec![OsdOp::writefull(vec![5; 8192])]);
        assert!(pn.call(0, cl, 1, op).is_empty());
        p.settle();
        assert_eq!(p.node(primary).replies(0, cl).len(), 1);
        trace_tx(&mut p.a);
        trace_tx(&mut p.b);
        p.settle();
        trace_tx(&mut p.a);
        trace_tx(&mut p.b);
        let tp = traces(p.node(primary));
        let tr = traces(p.node(1 - primary));
        assert_eq!((tp.len(), tr.len()), (1, 1), "{tp:?} {tr:?}");
        let (tp, tr) = (&tp[0], &tr[0]);
        assert_eq!(
            (tp["role"].clone(), tr["role"].clone()),
            ("primary".into(), "replica".into())
        );
        assert_eq!(tp["trace_id"], tr["trace_id"]);
        assert_eq!(tp["complete"], true, "{tp}");
        assert_eq!(tr["complete"], true, "{tr}");
        let s = stages(tp);
        assert!(s.contains(&"rep_send") && s.contains(&"rep_ack"), "{s:?}");
        let peer = tp["stages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["stage"] == "rep_send")
            .unwrap()["peer"]
            .as_i64();
        assert_eq!(peer, Some(i64::from(1 - primary)));
        assert!(tp["segments"]["repop_rtt"].is_u64());
        for n in [
            "r_rx",
            "r_in",
            "r_pg",
            "r_submit",
            "r_durable",
            "r_ack_out",
            "r_tx",
        ] {
            assert!(stages(tr).contains(&n), "{n} in {:?}", stages(tr));
        }
    }
}

// ---------------------------------------------------------------- review findings: ordering across rings

/// An object of pool 4 (written by `merge_setup`) whose PG is a merge source (pg_num 32 -> 5) on a worker core whose
/// target sits on core 0. `(object index, seed, source core)`.
fn moving_object(mc: &Mc) -> (usize, u32, usize, usize) {
    let map = mc.osds[0].osdmap().unwrap().clone();
    (1..64usize)
        .find_map(|i| {
            let raw = map
                .object_to_raw_pg(4, format!("m{i}").as_bytes(), b"", b"", -1)
                .unwrap();
            let seed = pgwire::pgmath::object_pg(raw.seed, 32);
            let t = pgwire::pgmath::merge_target(seed, 5);
            let (src, dst) = (mc.owner(4, seed), mc.owner(4, t));
            (seed >= 5 && src != 0 && dst == 0).then_some((i, seed, src, dst))
        })
        .expect("a moving object on a worker core")
}

/// `(pg_num, merge target pg_num)` of pool 4 on three cores whose merge moves ALL start on core 0: the workers have
/// nothing to export, so the only reason for them to take part in a round is what reaches them.
fn one_source_core_merge() -> (u32, u32) {
    (8..=64u32)
        .flat_map(|n| (2..n).map(move |lo| (n, lo)))
        .find(|&(n, lo)| {
            let from: Vec<usize> = (lo..n)
                .filter_map(|s| {
                    let t = pgwire::pgmath::merge_target(s, lo);
                    let (f, t) = (
                        peering::pg_core(4, s, 3, S) as usize,
                        peering::pg_core(4, t, 3, S) as usize,
                    );
                    (f != t).then_some(f)
                })
                .collect();
            !from.is_empty() && from.iter().all(|f| *f == 0)
        })
        .expect("a merge whose moves all start on core 0")
}

#[test]
fn merge_round_survives_the_map_reaching_workers_late() {
    let (n, lo) = one_source_core_merge();
    let mut mc = Mc::new(3);
    mc.pool4 = n;
    merge_setup(&mut mc);
    // rings are independent: the migration data of a round reaches a worker before the map itself, and with it the
    // worker's own placement table already says "nothing to move"
    mc.delay = Some(|dst, m| dst != 0 && matches!(m, XMsg::Map(_)));
    mc.deliver(pool4(&mc, 11, 10, lo, lo));
    assert!(!mc.delayed.is_empty());
    mc.release_delayed();
    mc.run_for(Duration::from_secs(3));
    assert!(mc.osds.iter().all(|o| o.cl.mig.round.is_none()));
    assert_merged(&mut mc, lo as usize);
}

#[test]
fn moves_survive_data_before_the_boot_answer() {
    let mut mc = Mc::new(3);
    merge_setup(&mut mc);
    // half copies on disk (as in crash_in_the_middle_of_the_copy), the announced merge moves them again after boot
    mc.lose = Some(|_, m| matches!(m, XMsg::MigData { last: true, .. } | XMsg::MigCredit { .. }));
    mc.deliver(pool4(&mc, 11, 10, 32, 5));
    mc.run_for(Duration::from_secs(2));
    mc.lose = None;
    // core 2's boot answer is slower than the data other cores send it: a map the control core gated before its boot
    // answers went out starts a round on core 2 before its boot (no source moves before every core is in the round,
    // adr 0031 am. 8: a retry round, which needs the boot answer, never races it)
    mc.delay = Some(|dst, m| dst == 2 && matches!(m, XMsg::Boot(_)));
    mc.restart();
    let m = pool4(&mc, 12, 12, 32, 5);
    mc.deliver(m);
    assert!(
        !mc.osds[2].cl.mig.boot_early.is_empty(),
        "the race did not happen"
    );
    mc.release_delayed();
    mc.run_for(Duration::from_secs(1));
    assert_eq!(pool4_cores(&mc).len(), 32, "every PG came back");
    let m = pool4(&mc, 13, 12, 5, 5);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    assert_merged(&mut mc, 5);
}

#[test]
fn client_ops_for_a_moving_pg_wait_and_are_answered() {
    let mut mc = Mc::new(3);
    merge_setup(&mut mc);
    let (i, seed, src, dst) = moving_object(&mc);
    // a connection on a core that is neither the source nor the destination: routes by its old table
    let other = (1..3).find(|c| *c != src && *c != dst).unwrap();
    let link = mc.client(other);
    // the last batch of every PG is held back: the sources have left their cores, the copies are not complete
    mc.delay = Some(|_, m| matches!(m, XMsg::MigData { last: true, .. }));
    mc.deliver(pool4(&mc, 11, 10, 32, 5));
    let spg = SpgT {
        pgid: PgT::new(4, seed),
        shard: denc::types::ShardId::NO_SHARD,
    };
    assert!(mc.osds[src].pg.set.pg(spg).is_none());
    let op = mc.op(4, &format!("m{i}"), vec![OsdOp::read(0, 4096 + i as u64)]);
    // a client still at epoch 10 (the source's PG set epoch): waits for the move itself
    let mut old = op.clone();
    old.osdmap_epoch = 10;
    for (tid, op) in [(77, op), (78, old)] {
        let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
        mc.osds[other].on_unknown_message(link, tid, ty, ver, &segs);
    }
    mc.settle();
    // (map shares to the epoch-10 client aside)
    let frames = |mc: &mut Mc| {
        let out = std::mem::take(&mut mc.osds[other].t.out);
        let n = out.iter().filter(|f| f.0 == link && f.2.0 != 41).count();
        mc.osds[other].t.out = out.into_iter().filter(|f| f.0 != link).collect();
        n
    };
    assert_eq!(frames(&mut mc), 0, "waits at the routing core");
    // (the routing core holds what it routes for the round's PGs until its Release, adr 0031 am. 8)
    assert_eq!(mc.osds[other].cl.mig.hold_q.len(), 2);
    assert_eq!(mc.osds[src].pg_parked_len(), 0);
    mc.release_delayed();
    mc.run_for(Duration::from_secs(1));
    // the op reached the PG on its new core: queued there or answered with a backoff (the PG is `premerge`, the
    // harness has no mon to move it on). What must not happen is a silent drop: nothing would trigger the resend.
    let answered = frames(&mut mc);
    let queued = mc.osds[dst].tracker.len();
    assert_eq!(answered + queued, 2, "an op was dropped");
    assert!(mc.osds.iter().all(|o| o.pg.c.dropped_ops.is_empty()));
}

thread_local! {
    /// The core whose [`XMsg::Release`] [`late_release`] holds back (`delay` hooks are plain fns).
    static LATE_RELEASE: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
}

/// `delay` hook: the Release of core [`LATE_RELEASE`] comes late (its ring is slower than the others).
fn late_release(dst: usize, m: &XMsg) -> bool {
    matches!(m, XMsg::Release { .. }) && LATE_RELEASE.with(|c| c.get()) == dst
}

/// Deliver what the `delay` hook held back so far; the hook stays (what it matches from now on waits again).
fn deliver_delayed(mc: &mut Mc) {
    let t = mc.t;
    for (from, dst, m) in std::mem::take(&mut mc.delayed) {
        mc.osds[dst].on_xmsg(from, m, t);
    }
    mc.settle();
}

/// osd.1 sends a notify for `spg` stamped `epoch` on a new cluster link of `core`; returns its message type.
fn peer_notify(mc: &mut Mc, core: usize, spg: SpgT, epoch: u32) -> u16 {
    let mut info = pgwire::PgInfo::dne(spg);
    info.history = pgwire::PgHistory::new_pg(epoch, denc::types::UTime::new(1, 0));
    let notify = pgwire::MOSDPGNotify2 {
        spgid: spg,
        notify: pgwire::PgNotify {
            query_epoch: epoch,
            epoch_sent: epoch,
            info,
            to: denc::types::ShardId::NO_SHARD,
            from: denc::types::ShardId::NO_SHARD,
            past_intervals: pgwire::PastIntervals::default(),
            pg_features: 0,
        },
    };
    let (ty, ver, _c, segs) = peering::Body::Peering(notify.into())
        .encode(u64::MAX)
        .unwrap();
    let t = mc.t;
    let ip = [10, 1, 0, 5];
    mc.next_port += 1;
    let link = mc.osds[core].on_accept(Listener::Cluster, crate::osd::sock4(ip, mc.next_port), t);
    mc.osds[core].links.get_mut(&link).unwrap().peer = Some(msgr2::PeerInfo {
        name: EntityName::osd(1),
        addrs: addr(ip, 6801, 556),
        features: u64::MAX,
        lossy: false,
        resumed: false,
        global_id: 1,
        auth_name: None,
    });
    mc.osds[core].set_now(t);
    mc.osds[core].on_unknown_message(link, 1, ty, ver, &segs);
    mc.settle();
    ty
}

/// Drops of the PG set that would lose a message of a moving PG.
fn move_drops(mc: &Mc) -> Vec<(usize, &'static str, u64)> {
    let mut v = Vec::new();
    for (c, o) in mc.osds.iter().enumerate() {
        for k in [
            "pg owned by another core",
            "create info for a pg stored unloaded here",
        ] {
            if let Some(n) = o.pg.set.dropped.get(k) {
                v.push((c, k, *n));
            }
        }
    }
    v
}

/// One client's ops for a moving PG keep their order (adr 0031 am. 8): the routing core holds the first one during
/// the round; its Release comes before the source's, and the next op goes straight to the new core. Before, the first
/// op waited on the source core and was sent on from there at the source's Release: the second one overtook it.
#[test]
fn client_ops_of_a_moving_pg_keep_their_order_when_the_source_switches_last() {
    let mut mc = Mc::new(3);
    merge_setup(&mut mc);
    let (i, _seed, src, dst) = moving_object(&mc);
    let other = (1..3).find(|c| *c != src && *c != dst).unwrap();
    let link = mc.client(other);
    // the copy stalls at its last batch: the round runs, nothing is switched yet
    mc.delay = Some(|_, m| matches!(m, XMsg::MigData { last: true, .. }));
    mc.deliver(pool4(&mc, 11, 10, 32, 5));
    let send = |mc: &mut Mc, tid: u64| {
        let op = mc.op(4, &format!("m{i}"), vec![OsdOp::read(0, 4096 + i as u64)]);
        let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
        mc.osds[other].on_unknown_message(link, tid, ty, ver, &segs);
        mc.settle();
    };
    mc.osds[dst].t.client_in.clear();
    send(&mut mc, 77);
    // the copy completes; the source's Release is slower than the routing core's
    LATE_RELEASE.with(|c| c.set(src));
    mc.delay = Some(late_release);
    deliver_delayed(&mut mc);
    assert!(
        mc.delayed
            .iter()
            .any(|(_, d, m)| *d == src && matches!(m, XMsg::Release { .. })),
        "the race did not happen"
    );
    assert!(
        mc.osds[other].cl.mig.round.is_none(),
        "the routing core switched"
    );
    send(&mut mc, 78);
    mc.release_delayed();
    mc.run_for(Duration::from_secs(1));
    let seen = &mc.osds[dst].t.client_in;
    let first = |tid: u64| seen.iter().position(|t| *t == tid);
    assert!(first(77).is_some() && first(78).is_some(), "{seen:?}");
    assert!(first(77) < first(78), "op 78 overtook op 77: {seen:?}");
    assert!(mc.osds.iter().all(|o| o.pg.c.dropped_ops.is_empty()));
}

/// A peer message for a PG that already left its core (detached, copy in flight) reaches the PG on its new core
/// (adr 0031 am. 8). Before, the source core created an empty second instance of the PG from the notify.
#[test]
fn peer_message_for_a_detached_pg_reaches_its_new_core() {
    let mut mc = Mc::new(3);
    merge_setup(&mut mc);
    let (_, seed, src, dst) = moving_object(&mc);
    let other = (1..3).find(|c| *c != src && *c != dst).unwrap();
    let spg = SpgT {
        pgid: PgT::new(4, seed),
        shard: denc::types::ShardId::NO_SHARD,
    };
    mc.delay = Some(|_, m| matches!(m, XMsg::MigData { last: true, .. }));
    mc.deliver(pool4(&mc, 11, 10, 32, 5));
    assert!(
        mc.osds[src].pg.set.pg(spg).is_none(),
        "detached, copy in flight"
    );
    // a peer still at epoch 10, its link on a core that routes by its old table
    let ty = peer_notify(&mut mc, other, spg, 10);
    assert!(mc.osds[src].pg.set.pg(spg).is_none(), "no second instance");
    mc.release_delayed();
    mc.run_for(Duration::from_secs(1));
    assert_eq!(pool4_cores(&mc).get(&seed), Some(&dst));
    assert_eq!(
        mc.osds[dst].pg.c.in_by_type.get(&ty),
        Some(&1),
        "delivered on the new core"
    );
    assert_eq!(mc.osds[src].pg.c.in_by_type.get(&ty), None);
    assert_eq!(move_drops(&mc), vec![]);
}

/// A peer message that waits on the source core for the round's (held) map moves with its PG (adr 0031 am. 8).
/// Before, it stayed in the source's queue and was dropped there when the map came ("pg owned by another core").
#[test]
fn peer_message_waiting_for_the_held_map_moves_with_its_pg() {
    let mut mc = Mc::new(3);
    merge_setup(&mut mc);
    let (_, seed, src, dst) = moving_object(&mc);
    let other = (1..3).find(|c| *c != src && *c != dst).unwrap();
    let spg = SpgT {
        pgid: PgT::new(4, seed),
        shard: denc::types::ShardId::NO_SHARD,
    };
    // a peer already at epoch 11: its notify waits on the PG's core for the map
    let ty = peer_notify(&mut mc, other, spg, 11);
    assert_eq!(mc.osds[src].pg.set.parked_msgs().0, 1, "waits for map 11");
    mc.deliver(pool4(&mc, 11, 10, 32, 5));
    mc.run_for(Duration::from_secs(1));
    assert_eq!(pool4_cores(&mc).get(&seed), Some(&dst));
    assert_eq!(move_drops(&mc), vec![]);
    assert_eq!(mc.osds[src].pg.set.parked_msgs().0, 0);
    assert_eq!(
        mc.osds[dst].pg.c.in_by_type.get(&ty),
        Some(&1),
        "delivered on the new core"
    );
}

/// A PG leaving its core aborts its in-flight sub-writes at the detach like a merge source (`SubWritesAborted`, adr
/// 0031 am. 8): their repop credits come back before the round ends, not only when the held map drops them
/// (`flow_after_map`). The replica's late replies find no credit, nothing is released twice.
#[test]
fn in_flight_sub_writes_of_a_moving_pg_are_aborted_at_the_detach() {
    let mut p = Pair::of(Mc::with_wal(0, 3, 65536), Mc::with_wal(1, 1, 65536));
    p.up();
    p.flashstore();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let lo = 5;
    // an object of a merge source led by osd.0 on a worker core of osd.0, its target on another core
    let (src, name) = (0..)
        .map(|i| format!("mv{i}"))
        .find_map(|n| {
            let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
            let seed = pgwire::pgmath::object_pg(raw.seed, 32);
            let t = pgwire::pgmath::merge_target(seed, lo);
            let (s, d) = (p.a.owner(1, seed), p.a.owner(1, t));
            let primary = map.pg_to_up_acting(PgT::new(1, seed)).acting_primary;
            (seed >= lo && s != 0 && s != d && primary == 0).then_some((s, n))
        })
        .unwrap();
    let cl = p.a.client(src);
    let op = p.a.op(1, &name, vec![OsdOp::writefull(vec![5u8; 4096])]);
    assert!(p.a.call(src, cl, 1, op).is_empty());
    assert!(
        !p.a.osds[src].pg.flow.idle(),
        "repop charged, still in the outbox"
    );
    let mut m = p.map(11, [10, 10]);
    let pool = m.pools.get_mut(&1).unwrap();
    pool.pg_num_pending = lo;
    pool.pg_num_target = lo;
    pool.last_change = 11;
    // the round runs up to its Release: the sources detached, the map not applied by the workers
    p.a.delay = Some(|_, m| matches!(m, XMsg::Release { .. }));
    p.a.deliver(m.clone());
    assert!(
        !p.a.delayed.is_empty(),
        "the round did not finish its moves"
    );
    assert!(p.a.osds[src].cl.mig.round.is_some());
    assert!(p.a.osds[src].pg.flow.idle(), "aborted at the detach");
    assert_eq!(
        p.a.osds[src].pg.c.link_events.get("repop_credit_aborted"),
        Some(&1)
    );
    p.a.release_delayed();
    // the replica, still in the old interval, answers the aborted repop: no credit to return
    p.settle();
    assert!(p.a.osds.iter().all(|o| o.pg.flow.idle()));
    p.b.deliver(m);
    p.settle();
    p.run_for(Duration::from_secs(5));
    assert!(p.a.osds.iter().all(|o| o.pg.flow.idle()));
    assert_eq!(
        p.a.osds[src].pg.c.link_events.get("repop_credit_aborted"),
        Some(&1)
    );
}

// ---------------------------------------------------------------- review findings: small ones

#[test]
fn core_count_is_capped_at_the_mask_width() {
    assert!(CoreSpec::new(0, 64, 1, 128).is_ok());
    let e = CoreSpec::new(0, 65, 1, 128).unwrap_err();
    assert!(e.contains("at most 64"), "{e}");
}

#[test]
fn active_line_is_logged_whatever_debug_osd_says() {
    let mut mc = Mc::new(1);
    mc.osds[0].log_level = 0;
    mc.up();
    assert_eq!(mc.osds[0].state, State::Active);
    assert!(
        mc.osds[0]
            .logs
            .iter()
            .any(|l| l.contains(crate::osd::ACTIVE_MARKER)),
        "{:?}",
        mc.osds[0].logs
    );
}

#[test]
fn peer_features_are_only_trusted_for_the_incarnation_they_were_negotiated_with() {
    let mut mc = Mc::new(1);
    mc.up();
    let safe = denc::features::ALL & !denc::features::TENTACLE_BIT;
    let o = &mut mc.osds[0];
    let up_from = o.osdmap().unwrap().osd_info[1].up_from;
    assert_eq!(o.peer_features(1), safe, "no link yet");
    o.cl.peer_feat.insert(1, (up_from, 0x1234));
    assert_eq!(o.peer_features(1), 0x1234);
    // the peer restarted (new up_from): the old link's features say nothing about the new daemon
    o.cl.peer_feat.insert(1, (up_from.wrapping_sub(1), 0x1234));
    assert_eq!(o.peer_features(1), safe);
}

/// The peer's dial won the race (spec 10.3): the accepted cluster link carries the PG traffic, so its negotiated
/// features count like a dialed link's (ECSubWrite v5 to a tentacle peer, spec ec.md 6.1.1), for the incarnation at
/// the address the peer identified with; another address (an older incarnation) says nothing.
#[test]
fn an_accepted_peer_link_records_the_peer_features() {
    let mut mc = Mc::new(1);
    mc.up();
    let safe = denc::features::ALL & !denc::features::TENTACLE_BIT;
    let link = mc.client_as(0, EntityName::osd(1));
    let o = &mut mc.osds[0];
    o.cl.peer_feat.clear();
    let (_, addrs) = o.peer_target(1).unwrap();
    for (a, want) in [
        (denc::types::EntityAddrVec::default(), safe),
        (addrs, 0x1234 | denc::features::TENTACLE_BIT),
    ] {
        let l = o.links.get_mut(&link).unwrap();
        l.msgr = crate::osd::MsgrId::Cluster;
        let p = l.peer.as_mut().unwrap();
        p.addrs = a;
        p.features = 0x1234 | denc::features::TENTACLE_BIT;
        o.link_ready_info(link, crate::osd::Purpose::Accepted);
        assert_eq!(o.peer_features(1), want);
    }
}

#[test]
fn reserved_peer_control_input_is_bounded_and_independent_of_data_credits() {
    let mut mc = Mc::new(2);
    mc.up();
    let source = 1;
    let link = mc.client_as(source, EntityName::osd(1));
    mc.osds[source].links.get_mut(&link).unwrap().msgr = crate::osd::MsgrId::Cluster;
    let pgid = (0..32)
        .map(|seed| PgT::new(1, seed))
        .find(|&pgid| mc.osds[source].pg.set.core_of(pgid) == 0)
        .unwrap();
    let spg = SpgT {
        pgid,
        shard: denc::types::ShardId::NO_SHARD,
    };
    let shard = mc.osds[source].input_shard(pgid);
    let held_data = mc.osds[source].cl.ingress.reserve(shard, 64 << 20).unwrap();
    let body = peering::Body::Peering(
        pgwire::MOSDPGNotify2 {
            spgid: spg,
            notify: pgwire::PgNotify {
                epoch_sent: mc.epoch + 1,
                query_epoch: mc.epoch + 1,
                info: pgwire::PgInfo::dne(spg),
                ..Default::default()
            },
        }
        .into(),
    );
    let (ty, version, _, segments) = body.encode(u64::MAX).unwrap();
    let before = mc.osds[source].cl.out.len();
    for tid in 1..=32 {
        assert!(mc.osds[source].input_ready(link));
        mc.osds[source].on_unknown_message(link, tid, ty, version, &segments);
    }
    assert_eq!(mc.osds[source].cl.out.len(), before + 32);
    mc.osds[source].on_unknown_message(link, 33, ty, version, &segments);
    assert!(!mc.osds[source].input_ready(link));
    assert_eq!(mc.osds[source].cl.out.len(), before + 32);
    assert!(matches!(
        mc.osds[source].links[&link].pending_input,
        Some(crate::osd::PendingInput::Peer { tid: 33, .. })
    ));
    mc.settle(); // future epoch messages retain their ownership on the destination actor
    assert!(!mc.osds[source].input_ready(link));
    let map = mc.map(mc.epoch + 1, 10);
    mc.deliver(map); // map/control progress is not gated by either input pool
    assert!(mc.osds[source].links[&link].pending_input.is_none());
    assert!(mc.osds[source].input_ready(link));
    assert!(mc.osds[source].cl.control_ingress.idle());
    drop(held_data);
}

#[test]
fn peer_lifecycle_messages_create_core_pair_barriers() {
    use ingress::order::Route;
    let mc = Mc::new(2);
    for body in [
        peering::Body::Peering(pgwire::MOSDPGNotify2::default().into()),
        peering::Body::Peering(pgwire::MOSDPGQuery2::default().into()),
        peering::Body::Peering(pgwire::MOSDPGLog::default().into()),
        peering::Body::Peering(pgwire::MOSDPGRemove::default().into()),
    ] {
        let message = XMsg::Pg {
            ingress: Default::default(),
            link: 0,
            from: 1,
            tid: 1,
            prio: pgwire::msgs::PRIO_DEFAULT,
            body: Box::new(body),
        };
        assert_eq!(mc.osds[1].xroute(&message), Route::Ordered);
    }
}

/// The mesh data lane of a PG message (`input_shard`, stamped by `xsend`) belongs to the destination core
/// (`PgSet::core_of`): both come from the PG set's map. A store placement the PG set has not loaded (mount scan of a
/// detached, unloadable or temp-only PG) must not move the lane to another core: the mesh has no such lane to the
/// destination and panics on a misrouted message.
#[test]
fn data_lane_follows_the_pg_set_not_an_unloaded_store_placement() {
    use peering::PgStoreOps;
    let mut mc = Mc::new(2);
    mc.up();
    let o = &mc.osds[0];
    let shards = o.cl.spec.shards;
    let pg_num = o.osdmap().unwrap().pool(1).unwrap().pg_num;
    let pgid = (0..pg_num)
        .map(|seed| PgT::new(1, seed))
        .find(|&p| o.pg.set.core_of(p) == 1)
        .unwrap();
    let other = (0..shards).find(|s| s % 2 == 0).unwrap();
    // the store alone learns an off-hash placement on a shard of core 0
    o.pg.store.place(pgid, other);
    assert_eq!(o.pg.store.shard_of_pg(pgid), Some(other));
    assert_eq!(o.pg.set.core_of(pgid), 1);
    assert_eq!(
        o.input_shard(pgid) % 2,
        1,
        "lane owned by the destination core"
    );
    assert_eq!(o.input_shard(pgid), o.pg.set.pg_shard(pgid) as usize);
}

/// A single-core OSD derives its lane and input-window count from the mounted store: a fixed count indexed past
/// `pending_input` (and the ingress windows) on a device with more shards, so the first op of such a shard panicked.
#[test]
fn single_core_osd_takes_its_shard_count_from_the_mounted_store() {
    let shards = 64;
    // 64 shards need more room than the default device: 2049 WAL blocks select the 4 GiB one
    let mut mc = Mc::with_layout(0, 1, shards, 2049);
    // the single-core production constructor, not the multi-core test boot
    mc.osds.clear();
    let parts = open_nvme(mc.mount(0)).unwrap();
    let o = Osd::<B>::with_pg_store(cfg(mc.whoami), parts.meta, parts.pgs).unwrap();
    assert_eq!(o.cl.spec.shards, shards);
    assert_eq!(o.cl.pending_input.len(), 2 * shards as usize + 1);
}

/// A core routes a peer message by its own placement table, which can lag the owner's (a PG moved at the end of a
/// merge round, adr 0031): the message reaches a core that no longer owns the PG. That core knows better and passes
/// the message on; its PG set would drop it ("pg owned by another core") and no peer re-sends a peering message by
/// itself.
#[test]
fn peer_message_routed_by_a_stale_placement_reaches_the_owner() {
    let mut mc = Mc::new(3);
    mc.up();
    // osd.2's session lives on core 2, whose table still has the default placement of the PG (core 1); cores 0 and 1
    // know it moved to a shard of core 0
    let link = mc.client_as(2, EntityName::osd(2));
    mc.osds[2].links.get_mut(&link).unwrap().msgr = crate::osd::MsgrId::Cluster;
    let pg_num = mc.osds[2].osdmap().unwrap().pool(1).unwrap().pg_num;
    let pgid = (0..pg_num)
        .map(|seed| PgT::new(1, seed))
        .find(|&p| mc.osds[2].pg.set.core_of(p) == 1)
        .unwrap();
    for c in [0, 1] {
        mc.osds[c].set_input_placement(pgid, 3);
        assert_eq!(mc.osds[c].pg.set.core_of(pgid), 0);
    }
    let spg = SpgT {
        pgid,
        shard: denc::types::ShardId::NO_SHARD,
    };
    let body = peering::Body::Peering(
        pgwire::MOSDPGQuery2 {
            spgid: spg,
            query: pgwire::PgQuery {
                ty: pgwire::QueryType::INFO,
                epoch_sent: mc.epoch,
                to: denc::types::ShardId::NO_SHARD,
                from: denc::types::ShardId::NO_SHARD,
                ..Default::default()
            },
        }
        .into(),
    );
    let (ty, ver, _, segs) = body.encode(u64::MAX).unwrap();
    let delivered = |mc: &Mc| {
        mc.osds
            .iter()
            .map(|o| o.pg.c.peering_msgs_in)
            .collect::<Vec<_>>()
    };
    let before = delivered(&mc);
    let fwd = mc.osds[1].cl.fwd_pg;
    mc.osds[2].on_unknown_message(link, 7, ty, ver, &segs);
    mc.settle();
    let after = delivered(&mc);
    assert_eq!(mc.osds[1].cl.fwd_pg, fwd + 1, "core 1 passed it on");
    assert_eq!(
        (after[0] - before[0], after[1] - before[1]),
        (1, 0),
        "the owner's PG set got it"
    );
    for o in &mc.osds {
        assert!(
            !o.pg.set.dropped.contains_key("pg owned by another core"),
            "{:?}",
            o.pg.set.dropped
        );
    }
}

/// A split child lives on its parent's shard (adr 0031). Every core places it from the map itself, and while its map
/// lacks the split it routes the child (named by a peer or client that applied the split first) to the parent already:
/// the route and the lane of a child never change, so nothing is forwarded or reordered, also when the parent's core
/// announces the children late.
#[test]
fn split_children_route_to_their_parent_before_and_after_the_map() {
    let mut mc = Mc::new(3);
    mc.pool4 = 6; // children 6 and 7 hash to other shards than their parents (2, 3)
    mc.up();
    write_read_all(&mut mc, 4, "s", 48, 1);
    let kids: Vec<PgT> = (6..12u32).map(|s| PgT::new(4, s)).collect();
    let want: Vec<u32> = kids
        .iter()
        .map(|k| {
            let parent = PgT::new(4, pgwire::pgmath::ancestor(k.seed, 6));
            mc.osds[0].pg.set.pg_shard(parent)
        })
        .collect();
    assert!(
        kids.iter().zip(&want).any(|(k, w)| (4 + k.seed) % S != *w),
        "a child that hashes to another shard than its parent"
    );
    let check = |mc: &Mc, when: &str| {
        for (c, o) in mc.osds.iter().enumerate() {
            for (k, w) in kids.iter().zip(&want) {
                assert_eq!(o.pg.set.pg_shard(*k), *w, "core {c}, {k} {when}");
                assert_eq!(
                    o.input_shard(*k),
                    *w as usize,
                    "core {c}, lane of {k} {when}"
                );
            }
        }
    };
    check(&mc, "before the split");
    // the parents' cores announce no child: the map alone places them
    mc.delay = Some(|_, m| matches!(m, XMsg::Placement { .. }));
    mc.deliver(pool4(&mc, 11, 10, 12, 12));
    mc.run_for(Duration::from_secs(3));
    assert!(!mc.delayed.is_empty(), "the split announced its children");
    check(&mc, "after the split");
    let at = pool4_cores(&mc);
    for k in &kids {
        assert_eq!(at[&k.seed], mc.osds[1].pg.set.core_of(*k), "{k}");
    }
    read_back(&mut mc, 4, "s", 48);
    mc.release_delayed();
    check(&mc, "after the announcement");
    read_back(&mut mc, 4, "s", 48);
}

/// A peer that applied a split sends for a child before a core of ours has the map. That core routes the message to
/// the parent's core (where the child is split off), not by the child's hash to a core that would park it until the
/// map and then drop it as owned by another core (no peer sends a peering message again by itself).
#[test]
fn split_child_message_on_a_core_behind_the_map_reaches_the_parents_core() {
    let mut mc = Mc::new(3);
    mc.pool4 = 6;
    mc.up();
    let link = mc.client_as(2, EntityName::osd(2));
    mc.osds[2].links.get_mut(&link).unwrap().msgr = crate::osd::MsgrId::Cluster;
    // child 6 hashes to core 2, its parent 2 lives on core 0
    let kid = PgT::new(4, 6);
    assert_eq!(mc.osds[2].pg.set.stored_core(kid), 2);
    assert_eq!(mc.osds[2].pg.set.core_of(PgT::new(4, 2)), 0);
    // core 2 gets the split map late, and the announcement of the children
    mc.delay = Some(|dst, m| dst == 2 && matches!(m, XMsg::Map(_) | XMsg::Placement { .. }));
    mc.deliver(pool4(&mc, 11, 10, 12, 12));
    mc.run_for(Duration::from_secs(1));
    assert_eq!(mc.osds[2].pg.set.epoch(), 10);
    assert!(
        mc.osds[0]
            .pg
            .set
            .pg(SpgT {
                pgid: kid,
                shard: denc::types::ShardId::NO_SHARD
            })
            .is_some()
    );
    let body = peering::Body::Peering(
        pgwire::MOSDPGQuery2 {
            spgid: SpgT {
                pgid: kid,
                shard: denc::types::ShardId::NO_SHARD,
            },
            query: pgwire::PgQuery {
                ty: pgwire::QueryType::INFO,
                epoch_sent: 11,
                to: denc::types::ShardId::NO_SHARD,
                from: denc::types::ShardId::NO_SHARD,
                ..Default::default()
            },
        }
        .into(),
    );
    let (ty, ver, _, segs) = body.encode(u64::MAX).unwrap();
    let delivered = |mc: &Mc| {
        mc.osds
            .iter()
            .map(|o| o.pg.c.peering_msgs_in)
            .collect::<Vec<_>>()
    };
    let before = delivered(&mc);
    let fwd: Vec<u64> = mc.osds.iter().map(|o| o.cl.fwd_pg).collect();
    mc.osds[2].on_unknown_message(link, 7, ty, ver, &segs);
    mc.settle();
    let after = delivered(&mc);
    assert_eq!(
        (
            after[0] - before[0],
            after[1] - before[1],
            after[2] - before[2]
        ),
        (1, 0, 0),
        "the parent's core got it"
    );
    assert_eq!(mc.osds[0].cl.fwd_pg, fwd[0], "no second hop");
    assert_eq!(mc.osds[1].cl.fwd_pg, fwd[1], "no second hop");
    mc.release_delayed();
    mc.run_for(Duration::from_secs(1));
    for o in &mc.osds {
        assert_eq!(o.pg.set.core_of(kid), 0);
        assert!(
            !o.pg.set.dropped.contains_key("pg owned by another core"),
            "{:?}",
            o.pg.set.dropped
        );
    }
}

#[test]
fn marked_cross_core_reply_without_live_attempt_is_suppressed() {
    let mut mc = Mc::new(2);
    mc.up();
    let link = mc.client(1);
    let mut read = OsdOp::read(0, 6);
    read.set_outdata_parts([
        (bytes::Bytes::from_static(b"abc"), Default::default()),
        (bytes::Bytes::from_static(b"def"), Default::default()),
    ]);
    let reply = MOSDOpReply {
        ops: vec![read],
        ..Default::default()
    };
    mc.osds[1].on_xmsg(
        0,
        XMsg::ClientReply {
            link,
            tid: 51,
            retry: 0,
            reply: Box::new(reply),
        },
        mc.t,
    );
    assert!(mc.osds[1].t.out.iter().all(|frame| frame.1 != 51));
}

#[test]
fn forwarding_to_a_stalled_core_is_bounded_and_held_in_order() {
    use crate::xcore::XOUT_MAX;
    let mut mc = Mc::new(2);
    mc.up();
    let link = mc.client(1);
    // an object whose PG lives on core 0; core 1's outbox does not move while the ops are routed: core 0 "does not keep up"
    let name = (0..)
        .map(|i| format!("o{i}"))
        .find(|n| {
            let op = mc.op(1, n, vec![OsdOp::read(0, 1)]);
            mc.owner(1, op.pgid.pgid.seed) == 0
        })
        .unwrap();
    let before = mc.osds[1].cl.out.len();
    let t = mc.t;
    let total = (XOUT_MAX + 50) as u64;
    for tid in 0..total {
        let op = mc.op(1, &name, vec![OsdOp::read(0, 1)]);
        mc.osds[1].set_now(t);
        mc.osds[1].route_client_op(link, tid, op);
    }
    assert!(mc.osds[1].cl.out.len() <= XOUT_MAX + before, "unbounded");
    assert!(mc.osds[1].cl.xout_wait.len() >= 50, "overflow waits");
    assert!(
        mc.replies(1, link).is_empty(),
        "no reply (no EAGAIN) while it waits"
    );
    // new input of the link is held behind the waiting ops (arrival order)
    let late = mc.op(1, &name, vec![OsdOp::read(0, 1)]);
    mc.osds[1].admit_client_op(link, total, late, 0);
    assert_eq!(mc.osds[1].cl.pending_count, 1);
    mc.settle();
    assert!(mc.osds[1].cl.xout_wait.is_empty());
    let r = mc.replies(1, link);
    assert_eq!(r.len() as u64, total + 1, "every op answered");
    assert!(r.iter().all(|(_, r)| r.result != -11), "no EAGAIN");
    assert!(r.windows(2).all(|w| w[0].0 < w[1].0), "in order");
}

/// ADR 0021 am. 8 regression: an op parked on a cold tree page must run when the page load finishes (store wake),
/// not at the next timer tick (~1 s stalls at QD1: nothing else drives `pg_post`).
#[test]
fn cold_read_is_not_parked_until_the_next_tick() {
    let mut mc = Mc::new(1);
    mc.up();
    write_read_all(&mut mc, 1, "obj", 8, 1);
    // enough objects for a multi-page tree
    let c = mc.client(0);
    for i in 0..1500usize {
        let op = mc.op(
            1,
            &format!("fill{i}"),
            vec![OsdOp::writefull(vec![1u8; 512])],
        );
        let r = mc.call(0, c, 10_000 + i as u64, op);
        assert_eq!(r.len(), 1, "fill {i}");
        assert_eq!(r[0].1.result, 0);
    }
    for o in &mut mc.osds {
        o.pg.store.with_store(|s| s.checkpoint().unwrap()); // restart then loads pages lazily
    }
    mc.restart(); // cold page cache
    let m = mc.map(12, 12);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    let c = mc.client(0);
    for i in 0..8usize {
        let op = mc.op(1, &format!("obj{i}"), vec![OsdOp::read(0, 4096 + i as u64)]);
        let t0 = mc.t;
        let r = mc.call(0, c, 500 + i as u64, op);
        assert_eq!(r.len(), 1, "read {i} still parked after settle");
        assert_eq!(r[0].1.ops[0].outdata, vec![(i % 251) as u8; 4096 + i]);
        assert!(
            mc.t - t0 < Duration::from_millis(50),
            "read {i}: {:?}",
            mc.t - t0
        );
    }
}

/// ADR 0043 am. 9: a burst of reads of cold objects (many gated ops waiting for different tree pages) all complete
/// from the store wakes alone (no timer), and the wakes skip the ops whose pages did not arrive.
#[test]
fn a_burst_of_cold_reads_is_woken_by_page_tokens() {
    let mut mc = Mc::new(1);
    mc.up();
    write_read_all(&mut mc, 1, "obj", 8, 1);
    let c = mc.client(0);
    for i in 0..1500usize {
        let op = mc.op(
            1,
            &format!("fill{i}"),
            vec![OsdOp::writefull(vec![(i % 200) as u8; 512])],
        );
        let r = mc.call(0, c, 10_000 + i as u64, op);
        assert_eq!(r[0].1.result, 0, "fill {i}");
    }
    for o in &mut mc.osds {
        o.pg.store.with_store(|s| s.checkpoint().unwrap());
    }
    mc.restart(); // cold page cache
    let m = mc.map(12, 12);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    let c = mc.client(0);
    let t0 = mc.t;
    let n = 96usize;
    for k in 0..n {
        let i = (k * 15) % 1500;
        let op = mc.op(1, &format!("fill{i}"), vec![OsdOp::read(0, 512)]);
        let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
        let t = mc.t;
        mc.osds[0].set_now(t);
        mc.osds[0].on_unknown_message(c, 700 + k as u64, ty, ver, &segs);
    }
    mc.settle();
    let r = mc.replies(0, c);
    assert_eq!(
        r.len(),
        n,
        "every cold read answered by the store wakes alone"
    );
    for (tid, rep) in &r {
        let i = ((*tid as usize - 700) * 15) % 1500;
        assert_eq!(rep.result, 0);
        assert_eq!(rep.ops[0].outdata, vec![(i % 200) as u8; 512], "fill{i}");
    }
    assert!(mc.t - t0 < Duration::from_millis(50), "{:?}", mc.t - t0);
    let (probes, skips) = mc.osds[0]
        .pg
        .eng
        .values()
        .fold((0, 0), |a, e| (a.0 + e.c.wake_probes, a.1 + e.c.wake_skips));
    assert!(
        skips > 0,
        "no wake skipped an op (probes {probes}): the tokens are not used"
    );
}

/// Wake sources of parked ops without any other op arriving: reads gated only on store page loads are no sticky PG
/// (visited only when the store woke); a PG pass with an empty wake and no state change leaves them alone, and the
/// next store wake alone answers them.
#[test]
fn cold_parked_reads_are_woken_by_the_store_wake_alone_and_not_swept_by_other_passes() {
    let mut mc = Mc::new(1);
    mc.up();
    write_read_all(&mut mc, 1, "obj", 8, 1);
    let c = mc.client(0);
    for i in 0..1500usize {
        let op = mc.op(
            1,
            &format!("fill{i}"),
            vec![OsdOp::writefull(vec![(i % 200) as u8; 512])],
        );
        let r = mc.call(0, c, 10_000 + i as u64, op);
        assert_eq!(r[0].1.result, 0, "fill {i}");
    }
    for o in &mut mc.osds {
        o.pg.store.with_store(|s| s.checkpoint().unwrap());
    }
    mc.restart();
    let m = mc.map(12, 12);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    let c = mc.client(0);
    let n = 24usize;
    for k in 0..n {
        let i = (k * 61) % 1500;
        let op = mc.op(1, &format!("fill{i}"), vec![OsdOp::read(0, 512)]);
        let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
        let t = mc.t;
        mc.osds[0].set_now(t);
        mc.osds[0].on_unknown_message(c, 900 + k as u64, ty, ver, &segs);
    }
    let o = &mut mc.osds[0];
    assert!(!o.pg.eng_parked.is_empty(), "cold reads must park");
    assert!(
        o.pg.eng_sticky.is_empty(),
        "only store loads gate them: no PG is visited on every pass"
    );
    // passes with nothing woken and no PG touched leave the parked PGs alone (engine counters do not move)
    let before: Vec<_> =
        o.pg.eng
            .values()
            .map(|e| (e.c.wake_probes, e.c.wake_skips))
            .collect();
    let (gate_skip, tick_all) = (o.perf.op.gate_skip, o.pg.wake.any());
    assert!(!tick_all);
    for _ in 0..5 {
        o.pg_post();
    }
    let after: Vec<_> =
        o.pg.eng
            .values()
            .map(|e| (e.c.wake_probes, e.c.wake_skips))
            .collect();
    assert_eq!(before, after, "an empty-wake pass probed parked ops");
    assert_eq!(gate_skip, o.perf.op.gate_skip);
    // the store wakes alone answer every read
    mc.settle();
    assert_eq!(mc.replies(0, c).len(), n, "reads answered by store wakes");
    assert!(mc.osds[0].pg.eng_parked.is_empty());
}

/// Cost per op of a warm PG while many OTHER PGs have ops parked on cold store loads (efficiency review #28): the
/// parked PGs wait for store wakes only, so an op on the hot PG must not pay for them. Prints wall ns per `stat` op with
/// 0 and with every other PG parked; the second must not grow with the number of parked PGs.
/// `N=20000 ROUNDS=5 cargo test --release -p osd --lib perf_parked_walk -- --ignored --nocapture`
#[test]
#[ignore]
fn perf_parked_walk() {
    let env = |k: &str, d: usize| -> usize {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let (n, rounds) = (env("N", 20_000), env("ROUNDS", 5));
    let fill = 2500usize;
    let mut mc = Mc::new(1);
    mc.up();
    write_read_all(&mut mc, 1, "obj", 8, 1);
    let c = mc.client(0);
    for i in 0..fill {
        let op = mc.op(
            1,
            &format!("fill{i}"),
            vec![OsdOp::writefull(vec![(i % 200) as u8; 512])],
        );
        let mut r = mc.call(0, c, 10_000 + i as u64, op);
        for _ in 0..50 {
            if !r.is_empty() {
                break;
            }
            mc.run_for(Duration::from_millis(100));
            r = mc.replies(0, c);
        }
        if let Some(r0) = r.first() {
            assert_eq!(r0.1.result, 0, "fill {i}");
        }
    }
    for o in &mut mc.osds {
        o.pg.store.with_store(|s| s.checkpoint().unwrap());
    }
    let map = mc.osds[0].osdmap().unwrap().clone();
    let pg_of = |n: &str| {
        let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
        pgwire::pgmath::object_pg(raw.seed, 32)
    };
    let hot = "fill0";
    let hot_pg = pg_of(hot);
    // one cold object per other PG
    let mut cold: BTreeMap<u32, usize> = BTreeMap::new();
    for i in 1..fill {
        let pg = pg_of(&format!("fill{i}"));
        if pg != hot_pg {
            cold.entry(pg).or_insert(i);
        }
    }
    for (label, parked) in [("parked0", false), ("parked", true)] {
        let mut ns = Vec::new();
        let mut npg = 0;
        for round in 0..rounds {
            mc.restart();
            let m = mc.map(12 + round as u32 + if parked { 100 } else { 0 }, 12);
            mc.deliver(m);
            mc.run_for(Duration::from_secs(3));
            let c = mc.client(0);
            // warm the hot object (stat answers from the object cache)
            let op = mc.op(1, hot, vec![OsdOp::stat()]);
            assert_eq!(mc.call(0, c, 400, op)[0].1.result, 0);
            if parked {
                for (k, i) in cold.values().enumerate() {
                    let op = mc.op(1, &format!("fill{i}"), vec![OsdOp::read(0, 512)]);
                    let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
                    let t = mc.t;
                    mc.osds[0].set_now(t);
                    mc.osds[0].on_unknown_message(c, 500 + k as u64, ty, ver, &segs);
                }
                npg = mc.osds[0].pg.eng_parked.len();
                assert!(npg > 8, "cold reads must park ({npg} PGs)");
            }
            let msgs: Vec<_> = (0..n)
                .map(|k| {
                    let op = mc.op(1, hot, vec![OsdOp::stat()]);
                    (
                        1_000_000 + k as u64,
                        ClientMsg::Op(op).encode(u64::MAX).unwrap(),
                    )
                })
                .collect();
            let t0 = std::time::Instant::now();
            for (tid, (ty, ver, _c, segs)) in &msgs {
                let t = mc.t;
                mc.osds[0].set_now(t);
                mc.osds[0].on_unknown_message(c, *tid, *ty, *ver, segs);
            }
            ns.push(t0.elapsed().as_nanos() as u64 / n as u64);
            mc.settle();
        }
        ns.sort_unstable();
        println!(
            "{label}: parked PGs {npg}, ns/op min {} median {} (N={n}, {rounds} rounds)",
            ns[0],
            ns[ns.len() / 2]
        );
    }
}

/// Cost of a burst of cold reads through the real store (sim device without latency): wall time of the burst per op and
/// the gate probes the wakes cost.
/// `FILL=6000 N=512 ROUNDS=5 cargo test --release -p osd --lib perf_cold_burst -- --ignored --nocapture`
#[test]
#[ignore]
fn perf_cold_burst() {
    let env = |k: &str, d: usize| -> usize {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let (fill, n, rounds) = (env("FILL", 2500), env("N", 512), env("ROUNDS", 5));
    // KIND=read (4 KiB-class read), rmw (64 B overwrite inside a block: boundary block read), omap (4 KiB omap value set)
    let kind = std::env::var("KIND").unwrap_or_else(|_| "read".into());
    let mut om = BTreeMap::new();
    om.insert(b"key".to_vec(), vec![5u8; 4096]);
    let mut mc = Mc::new(1);
    mc.up();
    write_read_all(&mut mc, 1, "obj", 8, 1);
    let c = mc.client(0);
    for i in 0..fill {
        let op = mc.op(
            1,
            &format!("fill{i}"),
            vec![OsdOp::writefull(vec![(i % 200) as u8; 512])],
        );
        let mut r = mc.call(0, c, 10_000 + i as u64, op);
        for _ in 0..50 {
            if !r.is_empty() {
                break;
            }
            mc.run_for(Duration::from_millis(100)); // the sim device answers in real time
            r = mc.replies(0, c);
        }
        assert_eq!(r[0].1.result, 0, "fill {i}");
    }
    for o in &mut mc.osds {
        o.pg.store.with_store(|s| s.checkpoint().unwrap());
    }
    let (mut ns, mut probes, mut skips, mut alls) = (Vec::new(), 0u64, 0u64, 0u64);
    let mut lost = 0;
    let mut ns_burst: Vec<u64> = Vec::new();
    let mut lat_ms: Vec<u64> = Vec::new();
    let mut sim_ms = 0u64;
    for round in 0..rounds {
        mc.restart(); // cold page cache
        let m = mc.map(12 + round as u32, 12 + round as u32);
        mc.deliver(m);
        mc.run_for(Duration::from_secs(3));
        mc.osds[0].pg.wake_diag = true;
        let c = mc.client(0);
        let mut s = 0x9E37_79B9_7F4A_7C15u64 ^ round as u64;
        let mut msgs = Vec::new();
        for k in 0..n {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let i = (s % fill as u64) as usize;
            let ops = match kind.as_str() {
                "rmw" => vec![OsdOp::write(100, vec![9u8; 64])],
                "omap" => vec![OsdOp::omap_set_vals(&om)],
                _ => vec![OsdOp::read(0, 512)],
            };
            let op = mc.op(1, &format!("fill{i}"), ops);
            msgs.push((700 + k as u64, ClientMsg::Op(op).encode(u64::MAX).unwrap()));
        }
        let t0 = std::time::Instant::now();
        for (tid, (ty, ver, _c, segs)) in &msgs {
            let t = mc.t;
            mc.osds[0].set_now(t);
            mc.osds[0].on_unknown_message(c, *tid, *ty, *ver, segs);
        }
        mc.settle();
        ns_burst.push(t0.elapsed().as_nanos() as u64);
        let sim0 = mc.t;
        let mut got = mc.replies(0, c).len();
        lat_ms.extend(std::iter::repeat_n(0u64, got));
        for _ in 0..400 {
            if got == n {
                break;
            }
            mc.run_for(Duration::from_millis(100)); // durable acks of the write kinds
            let k = mc.replies(0, c).len();
            got += k;
            lat_ms.extend(std::iter::repeat_n((mc.t - sim0).as_millis() as u64, k));
        }
        sim_ms += (mc.t - sim0).as_millis() as u64;
        ns.push(t0.elapsed().as_nanos() as u64);
        lost += mc.osds[0]
            .logs
            .iter()
            .filter(|l| l.contains("wake diag"))
            .count();
        if got != n {
            for e in mc.osds[0].pg.eng.values() {
                eprintln!("{}", e.dump_state());
            }
            eprintln!("{}", peering::PgStoreOps::diag(&mc.osds[0].pg.store));
        }
        assert_eq!(got, n);
        for e in mc.osds[0].pg.eng.values() {
            probes += e.c.wake_probes;
            skips += e.c.wake_skips;
            alls += e.c.wake_all;
        }
    }
    ns.sort_unstable();
    ns_burst.sort_unstable();
    eprintln!(
        "burst + first settle only: ns/op median={} max={}",
        ns_burst[ns_burst.len() / 2] / n as u64,
        ns_burst[ns_burst.len() - 1] / n as u64
    );
    lat_ms.sort_unstable();
    let lq = |p: f64| lat_ms[((lat_ms.len() as f64 * p) as usize).min(lat_ms.len() - 1)];
    eprintln!(
        "sim completion ms after the burst settled: p50={} p90={} p99={} p99.99={} max={}",
        lq(0.5),
        lq(0.9),
        lq(0.99),
        lq(0.9999),
        lat_ms[lat_ms.len() - 1]
    );
    eprintln!(
        "fill={fill} burst={n} kind={kind}: ns/op median={} min={} max={}; gate probes={probes} skips={skips} all-wakes={alls} tick-rescues={lost} sim-ms-after-burst-settle={}/round (all rounds)",
        ns[ns.len() / 2] / n as u64,
        ns[0] / n as u64,
        ns[ns.len() - 1] / n as u64,
        sim_ms / rounds as u64,
    );
}

/// A pool created at a later epoch than the OSDs' boot, 128 PGs, PGs created at the primaries only (the mon
/// sends MOSDPGCreate2 to the acting primary): every PG on both multi-core OSDs must peer and go active.
#[test]
fn late_pool_creation_across_two_multicore_osds() {
    let mut p = Pair::new(4, 4);
    p.up();
    let mut m = p.map(11, [10, 10]);
    let mut pool = m.pools.get(&4).unwrap().clone();
    pool.pg_num = 128;
    pool.pgp_num = 128;
    pool.pg_num_pending = 128;
    pool.pg_num_target = 128;
    pool.last_change = 11;
    m.pools.insert(5, pool);
    m.pool_name.insert(5, "late".into());
    p.deliver(m);
    p.create_pool_pgs(5);
    p.run_for(Duration::from_secs(10));
    for (who, n) in [(0, &p.a), (1, &p.b)] {
        let mut bad = Vec::new();
        let mut cnt = 0;
        for o in &n.osds {
            for (spg, s) in o.pg.set.pg_states() {
                if spg.pgid.pool == 5 {
                    cnt += 1;
                    if !s.contains("active") {
                        bad.push(format!("{spg} {s}"));
                    }
                }
            }
        }
        assert_eq!(cnt, 128, "osd.{who} pgs");
        assert!(bad.is_empty(), "osd.{who} not active: {bad:?}");
    }
}

/// Maps reach the cores one by one: the core that owns the link to the peer may still have an older map (one in
/// which the peer is not up) when another core's PG already sends. Those frames must not be dropped (the PGs
/// would wait for an answer forever).
#[test]
fn peer_frames_survive_a_link_core_with_an_older_map() {
    let mut p = Pair::new(4, 4);
    // node a: the core owning the link to osd.1 (core 1) gets no map until released
    let link_core = p.a.osds[0].cl.spec.peer_core(1);

    p.a.delay = Some(|dst, m| dst == 1 && matches!(m, XMsg::Map(_)));
    assert_eq!(link_core, 1, "test hook targets core 1");
    let m = p.map(10, [10, 10]);
    p.a.deliver(m.clone());
    p.b.deliver(m);
    for pool in [1u64, 4] {
        p.create_pool_pgs(pool);
    }
    p.run_for(Duration::from_secs(2));
    p.a.release_delayed();
    p.run_for(Duration::from_secs(10));
    for (who, n) in [(0, &p.a), (1, &p.b)] {
        for o in &n.osds {
            for (spg, s) in o.pg.set.pg_states() {
                assert!(s.contains("active"), "osd.{who} {spg} {s}");
            }
        }
    }
}

/// A client without the newest-encoding feature (older release) is never sent the stored map blobs: its decoder aborts on them
/// (rados 19.2.6 vs Ceph main crashed on a pg_num change); it follows the mon's map stream.
#[test]
fn an_older_client_gets_no_stored_map_blobs() {
    let mut mc = Mc::new(4);
    mc.up();
    let m = mc.map(11, 10);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(1));
    let cl = mc.client(1);
    let old = !denc::features::TENTACLE_BIT;
    mc.osds[1]
        .links
        .get_mut(&cl)
        .unwrap()
        .peer
        .as_mut()
        .unwrap()
        .features = old;
    let mut op = mc.op(1, "x", vec![OsdOp::stat()]);
    op.osdmap_epoch = 9;
    let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(old).unwrap();
    mc.osds[1].on_unknown_message(cl, 5, ty, ver, &segs);
    mc.settle();
    let out = std::mem::take(&mut mc.osds[1].t.out);
    assert_eq!(
        out.iter().filter(|f| f.0 == cl && f.2.0 == 41).count(),
        0,
        "{out:?}"
    );
}

/// CPU cost of a 4 KiB client read through the whole op path (decode, PG gate, opexec, store on the simulated
/// device, reply encode). Virtual device time: wall time here is pure CPU. `--ignored --nocapture`.
#[test]
#[ignore]
fn bench_read_4k_op_path() {
    // a fresh OSD per round (the harness stops answering after ~2000 ops of virtual time); NV_BENCH_ROUNDS for profiling
    let rounds: usize = std::env::var("NV_BENCH_ROUNDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let reads: usize = std::env::var("NV_BENCH_READS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_500);
    let n: usize = std::env::var("NV_BENCH_OBJS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(512);
    let mut total = std::time::Duration::ZERO;
    for _ in 0..rounds {
        let mut mc = Mc::new(1);
        // PGs of pool 4 (NV_BENCH_PGS): per-op cost must not grow with the number of PGs
        mc.pool4 = std::env::var("NV_BENCH_PGS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(32);
        mc.up();
        let cl = mc.client(0);
        // idle client connections: per-op work must not grow with them (NV_BENCH_LINKS)
        let idle: usize = std::env::var("NV_BENCH_LINKS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        for _ in 0..idle {
            mc.client(0);
        }
        for i in 0..n {
            let data = vec![(i % 251) as u8; 4096];
            let op = mc.op(4, &format!("b{i}"), vec![OsdOp::writefull(data)]);
            assert_eq!(mc.call(0, cl, i as u64, op)[0].1.result, 0);
        }
        let ops: Vec<MOSDOp> = (0..reads)
            .map(|i| mc.op(4, &format!("b{}", (i * 7) % n), vec![OsdOp::read(0, 4096)]))
            .collect();
        let t0 = std::time::Instant::now();
        for (i, op) in ops.into_iter().enumerate() {
            assert_eq!(mc.call(0, cl, 10_000 + i as u64, op).len(), 1, "read {i}");
        }
        total += t0.elapsed();
    }
    println!(
        "bench_read_4k_op_path: {} reads, {:.2} us/op CPU",
        reads * rounds,
        total.as_secs_f64() * 1e6 / (reads * rounds) as f64
    );
}

/// Regression (PGs of pools created after a hole in the stored map history were removed at boot: rebuilt chain stopped
/// at the hole, the PGs' pools looked deleted): the rebuild continues at the next stored full map.
#[test]
fn stored_map_history_with_a_hole_is_rebuilt_past_the_hole() {
    let mut mc = Mc::new(1);
    mc.up();
    let m = mc.map(14, 10); // epochs 11..13 never received
    mc.deliver(m);
    let epochs: Vec<u32> = mc.osds[0]
        .pg_load_maps(10, 14)
        .iter()
        .map(|m| m.epoch)
        .collect();
    assert_eq!(epochs, vec![10, 14]);
}

/// `mc.map(epoch, 10)` plus pool 5 (a copy of pool 4, `pg_num` 8).
fn map_with_pool5(mc: &Mc, epoch: u32) -> OsdMap {
    let mut m = mc.map(epoch, 10);
    let mut p = m.pools[&4].clone();
    for n in [
        &mut p.pg_num,
        &mut p.pgp_num,
        &mut p.pg_num_pending,
        &mut p.pg_num_target,
    ] {
        *n = 8;
    }
    m.pools.insert(5, p);
    m.pool_name.insert(5, "p5".into());
    m
}

fn pool5_pgs(mc: &Mc) -> usize {
    mc.pgs().iter().flatten().filter(|(p, _)| *p == 5).count()
}

/// Regression (oq 14, live: 28 of 32 PGs of a new pool removed at boot): pool 5 is created after a hole in the stored map
/// history; its PGs survive restarts (the rebuilt chain used to stop at the hole, their pool looked deleted).
#[test]
fn pgs_of_a_pool_created_after_a_map_hole_survive_restarts() {
    for n in [1usize, 3] {
        let mut mc = Mc::new(n);
        mc.up();
        let m = map_with_pool5(&mc, 14); // 11..13 never received
        mc.deliver(m);
        mc.create_pgs(5, 0..8);
        mc.run_for(Duration::from_secs(3));
        assert_eq!(pool5_pgs(&mc), 8, "n={n}");
        let m = map_with_pool5(&mc, 15);
        mc.deliver(m);
        mc.run_for(Duration::from_secs(1));
        let before = mc.pgs();
        for _ in 0..2 {
            mc.restart();
            assert_eq!(mc.pgs(), before, "n={n}");
        }
    }
}

/// Crash points of a map commit (blobs durable, superblock not: the commit is maps first, superblock last): the OSD
/// comes back on the old epoch with every PG, and the next delivery of the same maps closes the history without a hole.
#[test]
fn crash_between_map_blobs_and_superblock_loses_nothing() {
    use crate::meta::{MapKind, MetaStore as _};
    let mut mc = Mc::new(1);
    mc.up();
    let m = map_with_pool5(&mc, 11);
    mc.deliver(m);
    mc.create_pgs(5, 0..8);
    mc.run_for(Duration::from_secs(3));
    let before = mc.pgs();
    // the next message (epochs 12, 13) was being persisted when the process died: blobs in, superblock old
    let sb = mc.osds[0].superblock().clone();
    let blobs: Vec<(u32, MapKind, Vec<u8>)> = [12u32, 13]
        .iter()
        .map(|e| {
            (
                *e,
                MapKind::Full,
                map_with_pool5(&mc, *e).encode_full().unwrap(),
            )
        })
        .collect();
    for cut in 1..=blobs.len() {
        let o = &mut mc.osds[0];
        o.store
            .as_mut()
            .unwrap()
            .commit_maps(&blobs[..cut], &sb)
            .unwrap();
        mc.restart();
        assert_eq!(mc.osds[0].epoch(), 11, "cut {cut}");
        assert_eq!(mc.pgs(), before, "cut {cut}");
    }
    let m = map_with_pool5(&mc, 13);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(1));
    let epochs: Vec<u32> = mc.osds[0]
        .pg_load_maps(10, 13)
        .iter()
        .map(|m| m.epoch)
        .collect();
    assert_eq!(epochs, vec![10, 11, 12, 13]);
    mc.restart();
    assert_eq!(mc.pgs(), before);
}

/// A PG the mon told us to create (and that went active, i.e. was reported) must survive a crash right after.
#[test]
fn created_pgs_survive_an_immediate_crash() {
    for n in [1usize, 4, 8] {
        let mut mc = Mc::new(n);
        mc.up();
        let before = mc.pgs();
        mc.restart();
        assert_eq!(mc.pgs(), before, "n={n}");
    }
}

// ---------------------------------------------------------------- op intake invariant (open question 14)

/// Ops of `twin` (an OSD that is up) as a client sends them.
fn twin_ops(n: usize, count: usize) -> Vec<MOSDOp> {
    let mut twin = Mc::new(n);
    twin.up();
    let m = twin.map(12, 12); // the map of the restarted OSD's boot
    twin.deliver(m);
    twin.run_for(Duration::from_secs(3));
    (0..count)
        .map(|i| {
            twin.op(
                4,
                &format!("early{i}"),
                vec![OsdOp::writefull(vec![i as u8; 512])],
            )
        })
        .collect()
}

/// Regression (MDS op never answered after an croit-flashstore-osd restart): a client that learned of our boot from the mon connects
/// and sends its op before we are up in the map (`Booting`, maybe no map at all, a worker core that does not know the
/// state yet). The op used to be dropped silently, the client never resends on a live connection. It must wait and
/// be answered once the OSD is up; nothing is dropped.
#[test]
fn ops_before_the_osd_is_up_wait_and_are_answered() {
    for n in [1usize, 3] {
        let ops = twin_ops(n, 12);
        let mut mc = Mc::new(n);
        mc.up();
        mc.restart(); // PGs are loaded from the stores, no map yet, Booting
        assert_eq!(mc.osds[0].state, State::Booting);
        let clients: Vec<u64> = (0..n).map(|c| mc.client(c)).collect();
        for (i, op) in ops.iter().enumerate() {
            let c = i % n;
            let r = mc.call(c, clients[c], 100 + i as u64, op.clone());
            assert!(r.is_empty(), "no answer while booting");
        }
        let parked: usize = mc.osds.iter().map(|o| o.pg_parked_len()).sum();
        assert_eq!(parked, ops.len(), "n={n}: every op waits");
        let m = mc.map(12, 12);
        mc.deliver(m);
        mc.run_for(Duration::from_secs(3));
        let mut answered = BTreeMap::new();
        for (c, &l) in clients.iter().enumerate() {
            for (tid, r) in mc.replies(c, l) {
                answered.insert(tid, r.result);
            }
        }
        for i in 0..ops.len() {
            assert_eq!(
                answered.get(&(100 + i as u64)),
                Some(&0),
                "n={n} op {i}: {answered:?}"
            );
        }
        assert!(mc.osds.iter().all(|o| o.pg.c.dropped_ops.is_empty()));
        assert_eq!(mc.osds.iter().map(|o| o.pg_parked_len()).sum::<usize>(), 0);
    }
}

/// The op carries an epoch newer than the map we come up with: waits for that map, is answered when it arrives.
#[test]
fn op_newer_than_our_map_before_up_is_answered_after_the_map() {
    let mut twin = Mc::new(1);
    twin.up();
    let m = twin.map(11, 10);
    twin.deliver(m);
    let op = twin.op(4, "ahead", vec![OsdOp::writefull(vec![7; 100])]);
    assert_eq!(op.osdmap_epoch, 11);
    let mut mc = Mc::new(1);
    let l = mc.client(0);
    assert!(mc.call(0, l, 5, op).is_empty());
    mc.up(); // epoch 10: the op is still ahead
    assert!(mc.replies(0, l).is_empty());
    assert_eq!(mc.osds[0].pg_parked_len(), 1);
    // dump_ops_in_flight lists the waiting op with its reason
    let w = mc.osds[0].pg_parked_dump(1_000_000_000, &|_| "t".into(), false);
    assert_eq!(w.len(), 1);
    assert_eq!(w[0].1["type_data"]["flag_point"], "waiting for map");
    assert!(w[0].1["description"].as_str().unwrap().contains("osd_op("));
    assert!(
        mc.osds[0]
            .pg_parked_dump(1_000_000_000, &|_| "t".into(), true)
            .is_empty()
    );
    let m = mc.map(11, 10);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(1));
    let r = mc.replies(0, l);
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0].1.result, 0);
    assert!(mc.osds[0].pg.c.dropped_ops.is_empty());
    assert!(
        mc.osds[0]
            .pg_parked_dump(2_000_000_000, &|_| "t".into(), false)
            .is_empty()
    );
}

/// Intake invariant: an op that reaches a PG core is answered, tracked, waiting, or counted as dropped; never silent.
#[test]
fn every_client_op_is_answered_tracked_parked_or_counted() {
    let ops = twin_ops(1, 4);
    let mut mc = Mc::new(1);
    let l = mc.client(0);
    for (state, expect_parked) in [
        (State::Preboot, true),
        (State::Booting, true),
        (State::WaitingForHealthy, true),
        (State::Stopping, false),
    ] {
        mc.osds[0].state = state;
        let (p0, d0) = (
            mc.osds[0].pg_parked_len(),
            mc.osds[0].pg.c.dropped_ops.values().sum::<u64>(),
        );
        let r = mc.call(0, l, 1, ops[0].clone());
        let (p1, d1) = (
            mc.osds[0].pg_parked_len(),
            mc.osds[0].pg.c.dropped_ops.values().sum::<u64>(),
        );
        assert!(r.is_empty());
        assert_eq!(
            (p1 - p0, d1 - d0),
            if expect_parked { (1, 0) } else { (0, 1) },
            "{state:?}"
        );
    }
}

/// Op for a PG the map makes us primary of, before the PG exists (mon create pending): waits for the PG (classic
/// `waiting_for_pg`), answered once it is created; nothing is dropped (the client would never resend).
#[test]
fn op_for_a_pg_not_created_yet_waits_for_the_pg() {
    for n in [1usize, 3] {
        let mut mc = Mc::new(n);
        mc.up();
        let m = map_with_pool5(&mc, 11);
        mc.deliver(m);
        let clients: Vec<u64> = (0..n).map(|c| mc.client(c)).collect();
        for i in 0..6u64 {
            let c = i as usize % n;
            let op = mc.op(
                5,
                &format!("w{i}"),
                vec![OsdOp::writefull(vec![i as u8; 64])],
            );
            assert!(mc.call(c, clients[c], 10 + i, op).is_empty());
        }
        let parked: usize = mc.osds.iter().map(|o| o.pg_parked_len()).sum();
        assert_eq!(
            parked,
            6,
            "n={n} {:?}",
            mc.osds
                .iter()
                .map(|o| o.pg.c.dropped_ops.clone())
                .collect::<Vec<_>>()
        );
        let m = map_with_pool5(&mc, 12); // a map change re-judges them: still ours, still waiting
        mc.deliver(m);
        assert_eq!(mc.osds.iter().map(|o| o.pg_parked_len()).sum::<usize>(), 6);
        mc.create_pgs_at(5, 0..8, 12, 11); // created with the pool's creation epoch
        mc.run_for(Duration::from_secs(3));
        let mut done = BTreeMap::new();
        for (c, &l) in clients.iter().enumerate() {
            for (tid, r) in mc.replies(c, l) {
                done.insert(tid, r.result);
            }
        }
        assert_eq!(done.len(), 6, "n={n}: {done:?}");
        assert!(done.values().all(|r| *r == 0));
        assert!(mc.osds.iter().all(|o| o.pg.c.dropped_ops.is_empty()));
    }
}

/// A waiting op whose PG no longer maps to us (pool deleted) is dropped (counted) on the next map, not kept forever.
#[test]
fn op_waiting_for_a_pg_is_dropped_when_the_map_moves_it_away() {
    let mut mc = Mc::new(1);
    mc.up();
    let m = map_with_pool5(&mc, 11);
    mc.deliver(m);
    let l = mc.client(0);
    let op = mc.op(5, "gone", vec![OsdOp::writefull(vec![1; 8])]);
    assert!(mc.call(0, l, 1, op).is_empty());
    assert_eq!(mc.osds[0].pg_parked_len(), 1);
    let m = mc.map(12, 10); // pool 5 deleted
    mc.deliver(m);
    assert_eq!(mc.osds[0].pg_parked_len(), 0);
    assert_eq!(mc.osds[0].pg.c.dropped_ops.values().sum::<u64>(), 1);
}

/// Ordering: two writes of one client to one object wait for different reasons (PG missing / map behind); a map change
/// judges the first again and it waits again. Both become runnable in one step: they must run in arrival order (the
/// object ends with the second).
#[test]
fn waiting_ops_of_one_client_never_overtake_each_other() {
    let mut mc = Mc::new(1);
    mc.up();
    let m = map_with_pool5(&mc, 11);
    mc.deliver(m);
    let l = mc.client(0);
    let first = mc.op(5, "obj", vec![OsdOp::writefull(vec![1; 32])]);
    let mut second = mc.op(5, "obj", vec![OsdOp::writefull(vec![2; 32])]);
    second.osdmap_epoch = 13; // the client already has 13, we do not
    assert!(mc.call(0, l, 1, first).is_empty());
    assert!(mc.call(0, l, 2, second).is_empty());
    let m = map_with_pool5(&mc, 12); // the first is judged again and waits again
    mc.deliver(m);
    // the mon creates the PGs with a message of epoch 13: they appear while 13 is handled, both ops can run then
    mc.create_pgs_at(5, 0..8, 13, 11);
    assert_eq!(mc.osds[0].pg_parked_len(), 2);
    let m = map_with_pool5(&mc, 13);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    let tids: Vec<u64> = mc.replies(0, l).iter().map(|(t, _)| *t).collect();
    assert_eq!(tids, vec![1, 2]);
    let r = mc.call(0, l, 3, mc.op(5, "obj", vec![OsdOp::read(0, 32)]));
    assert_eq!(r[0].1.ops[0].outdata, vec![2; 32]);
}

/// Waiting ops count as ops in flight / slow ops (SLOW_OPS), and a closed connection takes its waiting ops along.
#[test]
fn waiting_ops_are_visible_as_slow_and_die_with_their_connection() {
    let mut mc = Mc::new(1);
    mc.up();
    let m = map_with_pool5(&mc, 11);
    mc.deliver(m);
    let l = mc.client(0);
    let op = mc.op(5, "slow", vec![OsdOp::writefull(vec![1; 8])]);
    assert!(mc.call(0, l, 1, op).is_empty());
    assert_eq!(mc.osds[0].pg_parked_len(), 1);
    mc.run_for(Duration::from_secs(2));
    let t = mc.t;
    mc.osds[0].set_now(t);
    mc.osds[0].tracker.lim.complaint_ns = 1_000_000_000;
    let (n, oldest) = mc.osds[0].slow_ops();
    assert_eq!(n, 1);
    assert!(oldest >= 1_000_000_000, "{oldest}");
    mc.osds[0].pg_link_closed(l, 0);
    assert_eq!(mc.osds[0].pg_parked_len(), 0);
    assert_eq!(mc.osds[0].slow_ops().0, 0);
}

#[path = "pgplace_tests.rs"]
mod pgplace;

#[path = "placement_tests.rs"]
mod placement;

#[path = "rdma_tests.rs"]
mod rdma;

#[path = "rdmastat_tests.rs"]
mod rdmastat;

#[path = "resend_tests.rs"]
mod resend;

#[path = "tellx_tests.rs"]
mod tellx;

/// The source OSD backs off the PG of a copy's read (MOSDBackoff BLOCK on the client link): the read is held (the peer
/// drops every op of the session inside the backoff, a re-send would be lost) and goes again on the UNBLOCK.
/// Regression: the read was re-sent after 100 ms into the backoff and UNBLOCK was ignored (copy hung until timeout).
#[test]
fn copy_from_holds_its_read_while_the_source_backs_off() {
    let mut p = Pair::new(2, 2);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let pg_of = |name: &str| {
        let raw = map
            .object_to_raw_pg(1, name.as_bytes(), b"", b"", -1)
            .unwrap();
        PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32))
    };
    let primary_of = |name: &str| map.pg_to_up_acting(pg_of(name)).acting_primary;
    let src = (0..)
        .map(|i| format!("bsrc{i}"))
        .find(|n| primary_of(n) == 1)
        .unwrap();
    let dst = (0..)
        .map(|i| format!("bdst{i}"))
        .find(|n| primary_of(n) == 0)
        .unwrap();
    let sn = &mut p.b;
    let cl = sn.client(0);
    let op = sn.op(1, &src, vec![OsdOp::writefull(b"held".to_vec())]);
    sn.call(0, cl, 1, op);
    p.settle();
    assert_eq!(p.b.replies(0, cl)[0].1.result, 0);
    let dn = &mut p.a;
    let cl = dn.client(0);
    let cpop = OsdOp::copy_from_req(
        opwire::op::COPY_FROM2,
        src.as_bytes(),
        &denc::types::ObjectLocator {
            pool: 1,
            key: vec![],
            nspace: vec![],
            hash: -1,
        },
        opwire::NOSNAP,
        0,
        0,
        None,
    );
    let op = dn.op(1, &dst, vec![cpop]);
    dn.call(0, cl, 2, op);
    // the source PG backs off before the link is up
    let spg = SpgT {
        pgid: pg_of(&src),
        shard: denc::types::ShardId::NO_SHARD,
    };
    let backoff = |op: u8| {
        let b = opwire::MOSDBackoff {
            pgid: spg,
            map_epoch: map.epoch,
            op,
            id: 7,
            begin: Default::default(),
            end: Default::default(),
        };
        ClientMsg::Backoff(b).encode(denc::features::ALL).unwrap()
    };
    let core =
        p.a.osds
            .iter()
            .position(|o| o.pg.cp.link_state(1).is_some())
            .expect("client link to osd.1");
    let (link, ..) = p.a.osds[core].pg.cp.link_state(1).unwrap();
    let (ty, v, _, segs) = backoff(opwire::consts::backoff::BLOCK);
    p.a.osds[core].copy_link_message(link, 1, 0, ty, v, &segs);
    p.settle();
    p.run_for(Duration::from_millis(600));
    assert!(p.a.replies(0, cl).is_empty(), "answered inside the backoff");
    assert_eq!(
        p.a.osds[core].pg.cp.link_state(1),
        Some((link, 1, 0, 1)),
        "read held, nothing on the wire"
    );
    let (ty, v, _, segs) = backoff(opwire::consts::backoff::UNBLOCK);
    p.a.osds[core].copy_link_message(link, 1, 0, ty, v, &segs);
    p.settle();
    let r = p.a.replies(0, cl);
    assert_eq!(r.len(), 1, "copy unanswered after the UNBLOCK");
    assert_eq!(r[0].1.result, 0);
    assert_eq!(p.a.osds[core].pg.cp.link_state(1).map(|s| s.3), Some(0));
}

/// Retired origin reads must release their link-side MOSDOps even when other traffic keeps the link alive.
#[test]
fn copy_retirement_releases_requests_on_a_busy_link() {
    for origin in [0, 1] {
        for expire in [false, true] {
            let mut p = Pair::new(2, 2);
            p.up();
            let op = (0..)
                .map(|i| p.a.op(1, &format!("retire{i}"), vec![OsdOp::read(0, 1)]))
                .find(|op| {
                    p.a.osds[0]
                        .osdmap()
                        .unwrap()
                        .pg_to_up_acting(op.pgid.pgid)
                        .acting_primary
                        == 1
                })
                .unwrap();
            p.a.osds[origin].copy_start(op.pgid, 1, op.clone());
            // Move only local messages: the remote source intentionally sends no answer.
            p.a.settle();
            assert_eq!(p.a.osds[1].pg.cp.link_state(1).unwrap().1, 1);
            p.a.t += Duration::from_secs(151);
            for o in &mut p.a.osds {
                o.set_now(p.a.t);
            }
            // A different read keeps the same session active; idle close cannot mask the leak.
            p.a.osds[1].copy_out(1, 999, op);
            if expire {
                p.a.osds[origin].copy_tick();
            } else {
                p.a.osds[origin].copy_back(1, Err(opwire::errno::EAGAIN));
            }
            p.a.settle();
            assert!(p.a.osds[origin].pg.cp.is_empty());
            assert_eq!(
                p.a.osds[1].pg.cp.link_state(1).unwrap().1,
                1,
                "retired request retained: origin={origin}, expire={expire}"
            );
        }
    }
}

#[test]
fn copy_retarget_releases_the_old_links_request() {
    let mut p = Pair::new(2, 2);
    p.up();
    let op = (0..)
        .map(|i| p.a.op(1, &format!("reroute{i}"), vec![OsdOp::read(0, 1)]))
        .find(|op| {
            p.a.osds[0]
                .osdmap()
                .unwrap()
                .pg_to_up_acting(op.pgid.pgid)
                .acting_primary
                == 1
        })
        .unwrap();
    p.a.osds[0].copy_start(op.pgid, 1, op.clone());
    p.a.settle();
    assert_eq!(p.a.osds[1].pg.cp.link_state(1).unwrap().1, 1);
    let mut map = p.a.osds[0].osdmap().unwrap().clone();
    map.epoch += 1;
    map.pg_temp.insert(op.pgid.pgid, vec![0, 1]);
    map.primary_temp.insert(op.pgid.pgid, 0);
    assert_eq!(map.pg_to_up_acting(op.pgid.pgid).acting_primary, 0);
    p.a.osds[0].map = Some(Arc::new(map));
    p.a.osds[0].copy_after_map();
    p.a.settle();
    assert_eq!(p.a.osds[1].pg.cp.link_state(1).unwrap().1, 0);
}

/// A new client session of `core` with the given cap text (caps are fixed for a session, as after
/// `ms_handle_fast_authentication`; a caps change needs a new link).
fn client_with_caps(mc: &mut Mc, core: usize, text: &str) -> u64 {
    let link = mc.client(core);
    let c = Arc::new(Caps::parse(text).unwrap());
    let l = mc.osds[core].links.get_mut(&link).unwrap();
    l.caps = Some(c.clone());
    let i = l.info.as_ref().expect("client info");
    l.info = Some(Arc::new(ConnInfo {
        who: i.who,
        features: i.features,
        addr: i.addr,
        peer_addr: i.peer_addr,
        caps: Some(c),
    }));
    link
}

/// Class load policy (cls.md 2.1, osdcaps.md 5.4): `osd_class_load_list` decides which classes the OSD serves at all
/// (-EPERM, before caps: `sdk` is a registered test probe that is on neither Ceph list), and a class kept off
/// `osd_class_default_list` is reachable only through `allow class NAME`, not through plain rwx / class-read bits.
#[test]
fn class_load_and_default_lists_gate_class_calls() {
    let mut mc = Mc::new(2);
    mc.up();
    let obj = "cls-policy";
    let all = client_with_caps(&mut mc, 0, "allow *");
    let w = mc.op(1, obj, vec![OsdOp::writefull(vec![3; 16])]);
    assert_eq!(mc.call(0, all, 1, w)[0].1.result, 0);
    let call =
        |mc: &Mc, class: &[u8], method: &[u8]| mc.op(1, obj, vec![OsdOp::call(class, method, b"")]);
    // plain rwx caps: a default-list class is reachable, a class off the load list is not served
    let l = client_with_caps(&mut mc, 0, "allow rwx");
    let r = mc.call(0, l, 2, call(&mc, b"lock", b"list_locks"));
    assert_eq!(r[0].1.result, 0, "default-list class with an rwx cap");
    let r = mc.call(0, l, 3, call(&mc, b"sdk", b"test_coverage_write"));
    assert_eq!(
        r[0].1.result,
        -denc::errno::EPERM,
        "a class off osd_class_load_list is refused"
    );
    // operator narrowing of the default list: rwx no longer reaches lock, an explicit `allow class lock` does
    for o in &mut mc.osds {
        o.conf
            .set(
                crate::config::Level::Override,
                "osd_class_default_list",
                "hello rbd",
            )
            .unwrap();
        o.refresh_obs_conf();
    }
    let l = client_with_caps(&mut mc, 0, "allow rwx");
    let r = mc.call(0, l, 4, call(&mc, b"lock", b"list_locks"));
    assert_eq!(r[0].1.result, -denc::errno::EPERM, "rwx without `x` class");
    let l = client_with_caps(&mut mc, 0, "allow rwx, allow class lock");
    let r = mc.call(0, l, 5, call(&mc, b"lock", b"list_locks"));
    assert_eq!(r[0].1.result, 0, "explicit `allow class lock`");
    // narrowing the load list refuses the class whatever the caps say
    for o in &mut mc.osds {
        o.conf
            .set(
                crate::config::Level::Override,
                "osd_class_load_list",
                "hello rbd",
            )
            .unwrap();
        o.refresh_obs_conf();
    }
    let l = client_with_caps(&mut mc, 0, "allow rwx, allow class lock");
    let r = mc.call(0, l, 6, call(&mc, b"lock", b"list_locks"));
    assert_eq!(
        r[0].1.result,
        -denc::errno::EPERM,
        "a class off osd_class_load_list is not served"
    );
}

/// Fencing (client-ops 5.2 #10): every core enforces the blocklist of its own map; a blocklisted client's ops are
/// refused with EBLOCKLISTED on whichever core owns the PG, its watches go away, an unblocklist lets it back in; ranges.
#[test]
fn blocklist_fences_clients_on_every_core() {
    use denc::types::UTime;
    const EBLOCKLISTED: i32 = 108;
    let mut mc = Mc::new(4);
    mc.up();
    let n = mc.osds[0].osdmap().unwrap().pool(1).unwrap().pg_num;
    let bad = mc.client(0); // ip 10.9.0.1
    let good = mc.client(2); // ip 10.9.0.3
    let w = |mc: &mut Mc, core, l, tid, oid: &str| {
        let op = mc.op(1, oid, vec![OsdOp::writefull(vec![1; 4096])]);
        mc.call(core, l, tid, op)[0].1.result
    };
    for i in 0..8 {
        assert_eq!(w(&mut mc, 0, bad, i, &format!("o{i}")), 0);
    }
    // a watch of the soon fenced client
    let op = mc.op(
        1,
        "wobj",
        vec![
            OsdOp::create(false),
            OsdOp::watch_op(0xAB, opwire::consts::watch_op::WATCH, 0),
        ],
    );
    assert_eq!(mc.call(0, bad, 100, op)[0].1.result, 0);
    let lw = |mc: &mut Mc, tid| {
        let op = mc.op(1, "wobj", vec![OsdOp::list_watchers()]);
        let r = mc.call(2, good, tid, op);
        let o: opwire::ObjListWatchResponse = denc::from_slice(&r[0].1.ops[0].outdata).unwrap();
        o.entries.len()
    };
    assert_eq!(lw(&mut mc, 1), 1);
    // epoch 11: 10.9.0.1 (ip only, any port / nonce) blocklisted
    let mut m = with_pg_num(&mc, 11, 1, n);
    m.blocklist.insert(
        EntityAddr::v4(EntityAddr::TYPE_ANY, 0, [10, 9, 0, 1], 0),
        UTime::default(),
    );
    mc.deliver(m);
    mc.run_for(Duration::from_secs(1));
    for i in 0..8 {
        assert_eq!(
            w(&mut mc, 0, bad, 200 + i, &format!("o{i}")),
            -EBLOCKLISTED,
            "obj {i}"
        );
        let op = mc.op(1, &format!("o{i}"), vec![OsdOp::read(0, 10)]);
        assert_eq!(mc.call(0, bad, 300 + i, op)[0].1.result, -EBLOCKLISTED);
        assert_eq!(w(&mut mc, 2, good, 400 + i, &format!("g{i}")), 0);
    }
    assert_eq!(lw(&mut mc, 2), 0, "watch of a blocklisted client removed");
    // unblocklist: back in (data of the earlier writes intact)
    let m = with_pg_num(&mc, 12, 1, n);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(1));
    let op = mc.op(1, "o3", vec![OsdOp::read(0, 4096)]);
    let r = mc.call(0, bad, 500, op);
    assert_eq!(r[0].1.result, 0);
    assert!(r[0].1.ops[0].outdata.iter().all(|b| *b == 1) && r[0].1.ops[0].outdata.len() == 4096);
    // range blocklist 10.9.0.0/24 fences both
    let mut m = with_pg_num(&mc, 13, 1, n);
    m.insert_range_blocklist(
        EntityAddr::v4(EntityAddr::TYPE_CIDR, 24, [10, 9, 0, 0], 0),
        UTime::default(),
    );
    mc.deliver(m);
    mc.run_for(Duration::from_secs(1));
    assert_eq!(w(&mut mc, 0, bad, 600, "o1"), -EBLOCKLISTED);
    assert_eq!(w(&mut mc, 2, good, 601, "o1"), -EBLOCKLISTED);
}

/// adr 0066 (OQ 23): a replica whose store refuses a repop fail-stops (classic: a failed apply aborts the OSD) instead
/// of dropping it unacked, which held every later write of the PG until a re-peer. Its down mark is the interval change
/// that lets the primary finish the write alone; nothing was acked before.
#[test]
fn a_replica_refusing_a_repop_fail_stops_and_the_primary_completes_the_write() {
    let mut p = Pair::new(1, 1);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let name = (0..)
        .map(|i| format!("ref{i}"))
        .find(|n| {
            let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
            let pg = PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32));
            map.pg_to_up_acting(pg).acting_primary == 0
        })
        .unwrap();
    p.b.osds[0].pg.refuse_next = Some("test knob");
    let cl = p.a.client(0);
    let op = p.a.op(1, &name, vec![OsdOp::writefull(vec![5u8; 8192])]);
    assert!(p.a.call(0, cl, 1, op).is_empty());
    p.settle();
    assert!(p.b.osds[0].pg.dead, "replica fail-stopped");
    assert_eq!(p.b.osds[0].fail_code, Some(1));
    assert_eq!(p.b.osds[0].pg.c.bad_txns, 1);
    assert!(
        p.a.replies(0, cl).is_empty(),
        "never acked without the replica"
    );
    // the mon marks osd.1 down: new interval, the primary re-runs the write alone (min_size 1)
    let mut m = p.map(11, [10, 10]);
    m.osd_state[1] = osd_state::EXISTS;
    p.a.deliver(m);
    p.a.settle();
    // (the prior interval's read lease expires first: PG state `wait`)
    p.a.run_for(Duration::from_secs(30));
    let r = p.a.replies(0, cl);
    assert_eq!(r.len(), 1, "write completed after the interval change");
    assert_eq!(r[0].1.result, 0);
    let op = p.a.op(1, &name, vec![OsdOp::read(0, 8192)]);
    let cl2 = p.a.client(0); // the first link went idle while time ran
    let r = p.a.call(0, cl2, 2, op);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].1.ops[0].outdata.as_ref(), vec![5u8; 8192].as_slice());
}

/// R1 (adr 0066 am. 4): the primary's own client txn refused by its store on the inline path (no send-first hop) after
/// the PG logged the entry in memory: the primary fail-stops (never a PG that keeps a phantom head it may persist later),
/// its repop is withdrawn (the replica never sees the entry), nothing is acked; the replica then serves without it.
#[test]
fn a_primary_refusing_its_own_txn_fail_stops_without_sending_the_repop() {
    let mut p = Pair::new(1, 1);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let (name, pgid) = (0..)
        .map(|i| {
            let n = format!("own{i}");
            let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
            (n, PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32)))
        })
        .find(|(_, pg)| map.pg_to_up_acting(*pg).acting_primary == 0)
        .unwrap();
    let spg = SpgT {
        pgid,
        shard: denc::types::ShardId::NO_SHARD,
    };
    let lu = |o: &Osd<_>| {
        o.pg.set
            .pg(spg)
            .map(|g| g.info().last_update.version)
            .unwrap_or(0)
    };
    let before = lu(&p.b.osds[0]);
    assert_eq!(lu(&p.a.osds[0]), before, "primary and replica in step");
    p.a.osds[0].pg.refuse_next = Some("test knob");
    let cl = p.a.client(0);
    let op = p.a.op(1, &name, vec![OsdOp::writefull(vec![9u8; 4096])]);
    assert!(p.a.call(0, cl, 1, op).is_empty());
    p.settle();
    assert!(p.a.osds[0].pg.refuse_next.is_none(), "the knob was used");
    assert!(p.a.osds[0].pg.dead, "primary fail-stopped");
    assert_eq!(p.a.osds[0].fail_code, Some(1));
    // counted like a refused repop or held-back txn (`pg_exec`): one persist path for every PG txn
    assert_eq!(p.a.osds[0].pg.c.bad_txns, 1);
    assert!(p.a.replies(0, cl).is_empty(), "never acked");
    assert_eq!(lu(&p.b.osds[0]), before, "the repop never left");
}

/// adr 0021 S4 (review S1): a replica whose store shard is at its system floor holds the repop (nothing applied, no
/// ack) instead of applying it into NoSpace (fail-stop, the same repop again after every restart). Once the shard has
/// room the held write applies and the primary completes it; the replica never goes down. Classic and croit-flashstore-osd peers.
fn replica_at_its_floor_holds_the_repop(nv: bool) {
    let mut p = Pair::new(1, 1);
    p.up();
    if nv {
        p.flashstore();
    }
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let (name, pg) = (0..)
        .map(|i| {
            let n = format!("full{i}");
            let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
            (n, PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32)))
        })
        .find(|(_, pg)| map.pg_to_up_acting(*pg).acting_primary == 0)
        .unwrap();
    let shard = p.b.osds[0].input_shard(pg) as u32;
    p.b.osds[0].pg.store.deny_room_shard.set(Some(shard));
    let cl = p.a.client(0);
    let op = p.a.op(1, &name, vec![OsdOp::writefull(vec![9u8; 8192])]);
    assert!(p.a.call(0, cl, 1, op).is_empty());
    p.settle();
    p.run_for(Duration::from_secs(3));
    assert!(!p.b.osds[0].pg.dead, "replica stays up at its floor");
    assert_eq!(p.b.osds[0].fail_code, None);
    assert!(p.a.replies(0, cl).is_empty(), "not acked while held");
    p.b.osds[0].pg.store.deny_room_shard.set(None);
    p.run_for(Duration::from_secs(5));
    let r = p.a.replies(0, cl);
    assert_eq!(r.len(), 1, "write completes once the shard has room");
    assert_eq!(r[0].1.result, 0);
    assert!(!p.b.osds[0].pg.dead);
    let op = p.a.op(1, &name, vec![OsdOp::read(0, 8192)]);
    let cl2 = p.a.client(0);
    let r = p.a.call(0, cl2, 2, op);
    assert_eq!(r[0].1.ops[0].outdata.as_ref(), vec![9u8; 8192].as_slice());
}

#[test]
fn replica_at_its_floor_holds_the_repop_classic_link() {
    replica_at_its_floor_holds_the_repop(false);
}

#[test]
fn replica_at_its_floor_holds_the_repop_flashstore_link() {
    replica_at_its_floor_holds_the_repop(true);
}

/// Send-first (adr 0008 am. 2): a client write that hops to its PG core sends its repop before the local txn is
/// queued. A local txn the store then refuses fail-stops the primary (like a classic primary whose apply asserts),
/// nothing is acked, the replica holds the entry: after the interval change it serves the write, consistently.
#[test]
fn send_first_local_refusal_after_the_repop_left_fail_stops_and_the_replica_serves_it() {
    let mut p = Pair::new(2, 1);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    // primary osd.0, PG owned by core 1, client on core 0: the op hops (XMsg::Op), the window applies
    let (name, pgid) = (0..)
        .map(|i| {
            let n = format!("sf{i}");
            let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
            (n, PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32)))
        })
        .find(|(_, pg)| {
            map.pg_to_up_acting(*pg).acting_primary == 0 && p.a.osds[0].input_shard(*pg) % 2 == 1
        })
        .unwrap();
    let spg = SpgT {
        pgid,
        shard: denc::types::ShardId::NO_SHARD,
    };
    let lu = |o: &Osd<_>| {
        o.pg.set
            .pg(spg)
            .map(|g| g.info().last_update.version)
            .unwrap_or(0)
    };
    let before = lu(&p.b.osds[0]);
    assert_eq!(lu(&p.a.osds[1]), before, "primary and replica in step");
    let cl = p.a.client(0);
    // a held-back txn (send-first): the knob is taken on the `pg_exec` path
    p.a.osds[1].pg.refuse_next = Some("test knob");
    let op = p.a.op(1, &name, vec![OsdOp::writefull(vec![7u8; 4096])]);
    assert!(p.a.call(0, cl, 1, op).is_empty());
    p.settle();
    assert!(
        p.a.osds[1].pg.dead,
        "primary fail-stopped on its refused local txn"
    );
    assert_eq!(p.a.osds[1].fail_code, Some(1));
    assert!(
        p.a.osds[1].pg.refuse_next.is_none(),
        "the held-back txn went through pg_exec"
    );
    assert_eq!(p.a.osds[1].pg.c.bad_txns, 1);
    assert!(p.a.replies(0, cl).is_empty(), "never acked");
    assert_eq!(
        lu(&p.b.osds[0]),
        before + 1,
        "the repop had left: the replica logged the entry"
    );
    // the mon marks osd.0 down: osd.1 leads with the entry
    let mut m = p.map(11, [10, 10]);
    m.osd_state[0] = osd_state::EXISTS;
    p.b.deliver(m);
    p.b.settle();
    p.b.run_for(Duration::from_secs(30));
    let clb = p.b.client(0);
    let op = p.b.op(1, &name, vec![OsdOp::read(0, 4096)]);
    let r = p.b.call(0, clb, 2, op);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].1.result, 0);
    assert_eq!(r[0].1.ops[0].outdata.as_ref(), vec![7u8; 4096].as_slice());
}

/// adr 0008 am. 3: a client write decoded on its own PG core (no hop) inside the driver's send-first window leaves its
/// repop on the peer link before its local txn is applied; the driver's `apply_late` applies it, nothing is lost.
#[test]
fn same_core_write_in_the_window_sends_its_repop_before_the_local_txn() {
    let mut p = Pair::new(1, 1);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let (name, pgid) = (0..)
        .map(|i| {
            let n = format!("sc{i}");
            let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
            (n, PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32)))
        })
        .find(|(_, pg)| map.pg_to_up_acting(*pg).acting_primary == 0)
        .unwrap();
    let spg = SpgT {
        pgid,
        shard: denc::types::ShardId::NO_SHARD,
    };
    let lu = |o: &Osd<_>| {
        o.pg.set
            .pg(spg)
            .map(|g| g.info().last_update.version)
            .unwrap_or(0)
    };
    let before = lu(&p.a.osds[0]);
    let cl = p.a.client(0);
    let op = p.a.op(1, &name, vec![OsdOp::writefull(vec![3u8; 4096])]);
    let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
    let t = p.a.t;
    let o = &mut p.a.osds[0];
    o.set_now(t);
    o.set_local_send_first(true);
    // what `Osd::on_bytes` does around its pump
    o.pg.late_ok = true;
    o.on_unknown_message(cl, 1, ty, ver, &segs);
    o.pg.late_ok = false;
    assert!(o.late_pending(), "the local txn is held back");
    assert!(
        o.poll_output_ready().is_some() || o.poll_xmsg().is_some(),
        "the repop is queued for its link"
    );
    o.apply_late();
    assert!(!o.late_pending());
    assert_eq!(lu(o), before + 1, "logged");
    assert_eq!(o.perf.op.late_held, 1);
    assert_eq!(o.perf.op.late_driver, 1);
    p.settle();
    let r = p.a.replies(0, cl);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].1.result, 0);
    assert_eq!(
        lu(&p.b.osds[0]),
        before + 1,
        "the replica applied the repop"
    );
}

/// Send-first keeps the per-object order and the result: pipelined writes and appends to one object through a
/// hopping PG core, read back on both OSDs.
#[test]
fn send_first_pipelined_writes_keep_order_on_primary_and_replica() {
    let mut p = Pair::new(2, 1);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let (name, seed, pgid) = (0..)
        .map(|i| {
            let n = format!("sfo{i}");
            let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
            let pg = PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32));
            (n, raw.seed, pg)
        })
        .find(|(_, _, pg)| {
            map.pg_to_up_acting(*pg).acting_primary == 0 && p.a.osds[0].input_shard(*pg) % 2 == 1
        })
        .unwrap();
    let cl = p.a.client(0);
    // several ops in one delivery: the PG core runs them back to back (pipelined on one object)
    let mut want = Vec::new();
    for i in 0..8u8 {
        let op = p.a.op(1, &name, vec![OsdOp::append(vec![i + 1; 512])]);
        want.extend_from_slice(&[i + 1; 512]);
        let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
        let t = p.a.t;
        p.a.osds[0].set_now(t);
        p.a.osds[0].on_unknown_message(cl, 10 + u64::from(i), ty, ver, &segs);
    }
    p.settle();
    let r = p.a.replies(0, cl);
    assert_eq!(r.len(), 8);
    assert!(r.iter().all(|(_, x)| x.result == 0));
    let op = p.a.op(1, &name, vec![OsdOp::read(0, 8192)]);
    let r = p.a.call(0, cl, 100, op);
    assert_eq!(r[0].1.ops[0].outdata.as_ref(), want.as_slice());
    // the replica applied the same sequence
    let spg = SpgT {
        pgid,
        shard: denc::types::ShardId::NO_SHARD,
    };
    let mut h =
        denc::types::Hobject::new(name.as_bytes(), denc::types::SnapId::NOSNAP, seed, 1, b"");
    h.set_key(b"");
    let got = opexec::ObjView::ov_read(&p.b.osds[0].pg.store, spg, &h, 0, 8192).unwrap();
    assert_eq!(got, want, "replica copy");
}

/// adr 0021 am. 30 / OQ 29: a replica whose store cannot hold a replicated long name fails the same way (down, nothing
/// acked without it) but exits with "refused" (3), so the unit does not restart-loop on the PG log entry and the recovery
/// push of that object until the store is upgraded.
#[test]
fn a_replica_without_long_names_exits_refused_not_in_a_restart_loop() {
    let mut p = Pair::new(1, 1);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let name = (0..)
        .map(|i| format!("lng{i}"))
        .find(|n| {
            let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
            let pg = PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32));
            map.pg_to_up_acting(pg).acting_primary == 0
        })
        .unwrap();
    p.b.osds[0].pg.refuse_next = Some("repop: NameTooLong");
    let cl = p.a.client(0);
    let op = p.a.op(1, &name, vec![OsdOp::writefull(vec![5u8; 4096])]);
    assert!(p.a.call(0, cl, 1, op).is_empty());
    p.settle();
    assert!(p.b.osds[0].pg.dead, "replica stopped");
    assert_eq!(p.b.osds[0].fail_code, Some(crate::release::EXIT_REFUSED));
    assert!(
        p.a.replies(0, cl).is_empty(),
        "never acked without the replica"
    );
}

#[path = "w4k_bench.rs"]
mod w4k;

/// Trims without store reads (adr 0021 am. 28): a hot object's PG log trims (tail without a `_logtail` read, dups
/// dropped as one key range) across restarts; every restart (WAL replay) brings back the same PG log state and data,
/// and the PGs go on writing from there.
#[test]
fn pg_log_trims_survive_restarts() {
    let state = |mc: &Mc| -> Vec<(
        SpgT,
        denc::types::Eversion,
        denc::types::Eversion,
        denc::types::Eversion,
        usize,
    )> {
        let mut v: Vec<_> = mc
            .osds
            .iter()
            .flat_map(|o| {
                o.pg.set.pgs().map(|(s, p)| {
                    (
                        *s,
                        p.info().last_update,
                        p.log().head(),
                        p.log().tail(),
                        p.log().log.log.len(),
                    )
                })
            })
            .collect();
        v.sort_by_key(|x| x.0);
        v
    };
    let mut mc = Mc::new(4);
    mc.up();
    let clients: Vec<u64> = (0..mc.n).map(|c| mc.client(c)).collect();
    let mut tid = 50_000u64;
    for round in 0..3u32 {
        write_read_all(
            &mut mc,
            1,
            &format!("d{round}_"),
            40,
            10_000 * (round as u64 + 1),
        );
        // one hot object: its PG log trims (every 100 entries over 250) and drops dups
        for i in 0..400u32 {
            let c = i as usize % mc.n;
            let op = mc.op(1, "hot", vec![OsdOp::write(0, vec![(i % 251) as u8; 4096])]);
            tid += 1;
            let r = mc.call(c, clients[c], tid, op);
            assert_eq!(r.len(), 1, "hot write {i}");
            assert_eq!(r[0].1.result, 0);
        }
        let before = state(&mc);
        assert!(
            before.iter().any(|x| x.3.version > 0),
            "round {round}: no PG log trimmed"
        );
        mc.restart();
        mc.deliver(mc.map(12 + round, 12 + round));
        mc.run_for(Duration::from_secs(3));
        let after = state(&mc);
        assert_eq!(before.len(), after.len());
        for (b, a) in before.iter().zip(&after) {
            assert_eq!(b.0, a.0);
            assert_eq!(
                (b.1, b.2, b.3, b.4),
                (a.1, a.2, a.3, a.4),
                "{}: log state across the restart",
                b.0
            );
        }
        let clients2: Vec<u64> = (0..mc.n).map(|c| mc.client(c)).collect();
        for r0 in 0..=round {
            for i in 0..40usize {
                let c = i % mc.n;
                let op = mc.op(
                    1,
                    &format!("d{r0}_{i}"),
                    vec![OsdOp::read(0, 4096 + i as u64)],
                );
                tid += 1;
                let r = mc.call(c, clients2[c], tid, op);
                assert_eq!(
                    r[0].1.ops[0].outdata,
                    vec![(i % 251) as u8; 4096 + i],
                    "d{r0}_{i}"
                );
            }
        }
        let op = mc.op(1, "hot", vec![OsdOp::read(0, 4096)]);
        tid += 1;
        let r = mc.call(0, clients2[0], tid, op);
        assert_eq!(r[0].1.ops[0].outdata, vec![(399 % 251) as u8; 4096]);
        // the PGs keep writing from where they were
        let _ = clients;
    }
}

/// A lost cluster session to a peer (adr 0071) reaches the PG sets of every core (each core's PGs talk to that peer):
/// all of them count the loss and redrive; the PGs stay active.
#[test]
fn peer_session_loss_reaches_every_core() {
    let mut p = Pair::new(2, 2);
    p.up();
    let core = p.a.osds[0].cl.spec.peer_core(1);
    p.a.osds[core].pg_peer_link(1, false);
    p.settle();
    for (i, o) in p.a.osds.iter().enumerate() {
        assert_eq!(o.pg.set.peer_stats.faults, 1, "core {i}");
        assert!(o.pg.set.peer_stats.redrives >= 1, "core {i}");
    }
    p.a.osds[core].pg_peer_link(1, true);
    p.run_for(Duration::from_secs(2));
    for o in &p.a.osds {
        for (spg, s) in o.pg.set.pg_states() {
            assert!(s.contains("active"), "{spg} {s}");
        }
    }
}

#[test]
fn a_cold_parked_write_leaves_the_core_free_for_network_mesh_and_another_shard() {
    use denc::types::{CollT, Ghobject, Hobject, ShardId, SnapId};
    use store::obj::{OTxn, Queued};
    let mut mc = Mc::new(2);
    let c = CollT::Pg(SpgT {
        pgid: PgT::new(9, 1),
        shard: ShardId::NO_SHARD,
    });
    let hot = CollT::Pg(SpgT {
        pgid: PgT::new(9, 3),
        shard: ShardId::NO_SHARD,
    });
    let object = |i: u32| {
        Ghobject::new(
            Hobject::new(format!("park-{i}").as_bytes(), SnapId::NOSNAP, i, 9, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        )
    };
    mc.osds[0].pg.store.with_store(|st| {
        for cid in [c, hot] {
            let mut t = OTxn::new();
            t.mkcoll(cid);
            st.commit(&t).unwrap();
        }
        for batch in 0..20 {
            let mut t = OTxn::new();
            for i in batch * 50..(batch + 1) * 50 {
                t.write(c, &object(i), 0, &[0x31; 4096]);
            }
            st.commit(&t).unwrap();
        }
        st.checkpoint().unwrap();
    });
    mc.osds[0].pg.store = storeadapt::StoreAdapter::new(mc.mount(0));
    mc.osds[0].pg.store.with_store(|st| {
        let mut t = OTxn::new();
        t.write(hot, &object(1), 0, &[0x31; 4096]);
        st.commit(&t).unwrap();
    });
    let before = mc.osds[0].pg.store.with_store(|st| st.clk.t);
    mc.osds[0].pg.store.with_store(|st| {
        let mut t = OTxn::new();
        t.write(c, &object(500), 0, &[0x42; 4096]);
        assert_eq!(st.queue(&t, 123).unwrap(), Queued::Pending(123));
        assert_eq!(st.clk.t, before);
    });
    // Same core, before any cold IO completion: messenger output and mesh dispatch still run.
    let id = mc.osds[0].on_accept(
        Listener::Public,
        crate::osd::sock4([10, 9, 0, 1], 48000),
        mc.t,
    );
    assert!(!mc.osds[0].poll_output_chunks(id).is_empty());
    mc.osds[0].on_xmsg(
        1,
        XMsg::Stats(Box::new(crate::xcore::CoreStats {
            num_pgs: 77,
            ..Default::default()
        })),
        mc.t,
    );
    assert_eq!(mc.osds[0].cl.stats[1].as_ref().unwrap().num_pgs, 77);
    mc.osds[0].pg.store.with_store(|st| {
        let mut t = OTxn::new();
        t.write(hot, &object(1), 0, &[0x43; 4096]);
        assert!(matches!(st.queue(&t, 124).unwrap(), Queued::Submitted(_)));
        assert_eq!(st.clk.t, before);
        assert_eq!(st.queued_count(), 1);
    });
}

// ---------------------------------------------------------------- adr 0160: store_shards vs cores

/// Every PG sits on the core of its store shard (`shard % cores`) and is active.
fn assert_owned_by_shard(mc: &Mc) {
    for (c, v) in mc.pgs().iter().enumerate() {
        for (pool, seed) in v {
            assert_eq!(mc.owner(*pool, *seed), c, "pg {pool}.{seed} on core {c}");
        }
    }
    for o in &mc.osds {
        assert_eq!(o.state, State::Active);
        for (spg, s) in o.pg.set.pg_states() {
            assert!(s.contains("active"), "{spg} {s}");
        }
    }
}

/// mkfs with 6 shards; run with 4 cores (unbalanced), then 6, 5, 1, 3 (non-dividing), 2 and 6 again across restarts:
/// PGs follow their shard's core, everything written under one layout is readable under every later one.
#[test]
fn core_count_changes_across_restarts_with_six_shards() {
    let mut mc = Mc::with_shards(4, 6);
    mc.up();
    assert_owned_by_shard(&mc);
    write_read_all(&mut mc, 1, "c4-", 24, 1);
    let pgs: usize = mc.pgs().iter().map(Vec::len).sum();
    let mut written = vec![("c4-", 24usize)];
    for (k, n) in [6usize, 5, 1, 3, 2, 6].into_iter().enumerate() {
        let epoch = 12 + k as u32;
        mc.restart_with_cores(n);
        assert_eq!(
            mc.pgs().iter().map(Vec::len).sum::<usize>(),
            pgs,
            "n {n}: PGs reloaded"
        );
        let m = mc.map(epoch, epoch);
        mc.deliver(m);
        mc.run_for(Duration::from_secs(3));
        assert_owned_by_shard(&mc);
        for (p, cnt) in &written {
            read_back(&mut mc, 1, p, *cnt);
        }
        let prefix: &'static str = ["c6-", "c5-", "c1-", "c3-", "c2-", "c6b-"][k];
        write_read_all(&mut mc, 1, prefix, 12, 100 * (k as u64 + 1) * 100);
        written.push((prefix, 12));
    }
}

/// Crash-style restart (nothing flushed beyond the acks) from 3 cores on 3 shards to 2 cores (non-dividing): every
/// acked write is served by the core that now owns its shard.
#[test]
fn crash_restart_with_fewer_cores_keeps_acked_writes() {
    let mut mc = Mc::with_shards(3, 3);
    mc.up();
    write_read_all(&mut mc, 1, "x", 30, 1);
    mc.restart_with_cores(2);
    let m = mc.map(12, 12);
    mc.deliver(m);
    mc.run_for(Duration::from_secs(3));
    assert_owned_by_shard(&mc);
    read_back(&mut mc, 1, "x", 30);
}

#[test]
fn shard_balance_warning_names_the_fix() {
    assert_eq!(CoreSpec::shard_balance(8, 8, 8), None);
    let w = CoreSpec::shard_balance(32, 8, 8).unwrap();
    assert!(
        w.contains("4 WAL rings per core") && w.contains("redeploy"),
        "{w}"
    );
    let w = CoreSpec::shard_balance(6, 4, 4).unwrap();
    assert!(
        w.contains("unbalanced") && w.contains("cores 0..2 own 2 shards, the others 1"),
        "{w}"
    );
    let w = CoreSpec::shard_balance(6, 6, 8).unwrap();
    assert!(
        w.contains("8 cores configured") && w.contains("running on 6"),
        "{w}"
    );
    // non-dividing core counts are valid specs (core c owns the shards s % n == c)
    assert!(CoreSpec::new(0, 5, 5, 6).is_ok());
    assert!(CoreSpec::new(0, 7, 7, 6).is_err());
}

// ---------------------------------------------------------------- ops behind a parked large write (adr 0043 am. 8)

/// Primary-0 object names of pool 1 (`prefix0`, `prefix1`, ...); `n` of them, the first `same_pg` in one PG.
fn names_at_a(p: &Pair, prefix: &str, n: usize) -> Vec<String> {
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let pg_of = |s: &str| {
        let raw = map.object_to_raw_pg(1, s.as_bytes(), b"", b"", -1).unwrap();
        PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32))
    };
    let first = (0..)
        .map(|i| format!("{prefix}{i}"))
        .find(|s| map.pg_to_up_acting(pg_of(s)).acting_primary == 0)
        .unwrap();
    let pg = pg_of(&first);
    let mut v = vec![first];
    v.extend(
        (0..)
            .map(|i| format!("{prefix}x{i}"))
            .filter(|s| pg_of(s) == pg)
            .take(n - 1),
    );
    v
}

/// Client ops sent back to back (no settle in between) on one link of osd.0 core 0.
fn send_raw(p: &mut Pair, cl: u64, ops: Vec<(u64, &str, Vec<OsdOp>)>) {
    for (tid, name, o) in ops {
        let op = p.a.op(1, name, o);
        let (ty, ver, _c, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
        let t = p.a.t;
        p.a.osds[0].set_now(t);
        p.a.osds[0].on_unknown_message(cl, tid, ty, ver, &segs);
    }
}

/// An op right behind a large (> 256 KiB: parked in the store) write of the same object, and an op of another
/// object of the same PG: all acked in order without a timer. The gate's warm probe of the second op saw the
/// parked write and latched the store's "run refused" flag; the next run (succeeding after the write's apply had
/// consumed the only wake) read it as its own refusal and waited for a wake that never came.
#[test]
fn ops_behind_a_parked_large_write_are_woken() {
    let mut m = BTreeMap::new();
    m.insert(b"k".to_vec(), b"v".to_vec());
    let seconds: Vec<(&str, Vec<OsdOp>)> = vec![
        ("writefull", vec![OsdOp::writefull(vec![4u8; 100])]),
        ("write", vec![OsdOp::write(4096, vec![5u8; 100])]),
        ("read", vec![OsdOp::read(0, 4096)]),
        ("stat", vec![OsdOp::stat()]),
        ("truncate", vec![OsdOp::truncate(100)]),
        ("omap", vec![OsdOp::omap_set_vals(&m)]),
        ("setxattr", vec![OsdOp::setxattr(b"_x", b"y")]),
        ("delete", vec![OsdOp::delete()]),
        ("big", vec![OsdOp::writefull(vec![6u8; 300 << 10])]),
    ];
    for (what, second) in seconds {
        let mut p = Pair::new(1, 1);
        p.up();
        let names = names_at_a(&p, "big", 2);
        let cl = p.a.client(0);
        send_raw(
            &mut p,
            cl,
            vec![
                (1, &names[0], vec![OsdOp::writefull(vec![3u8; 300 << 10])]),
                (2, &names[0], second),
                (3, &names[1], vec![OsdOp::writefull(vec![7u8; 100])]),
                (4, &names[0], vec![OsdOp::stat()]),
            ],
        );
        p.settle();
        let r = p.a.replies(0, cl);
        let tids: Vec<u64> = r.iter().map(|x| x.0).collect();
        assert_eq!(tids.len(), 4, "{what}: acked without a timer: {tids:?}");
        let same: Vec<u64> = tids.iter().copied().filter(|t| *t != 3).collect();
        if matches!(what, "read" | "stat") {
            // two pure reads behind the write: both after it, in either order (spec client-ops 5.7 step 9)
            assert_eq!(same[0], 1, "{what}: a read overtook the write: {same:?}");
        } else {
            assert_eq!(same, vec![1, 2, 4], "{what}: per-object order");
        }
        for (tid, rep) in &r {
            let ok = rep.result == 0 || (what == "delete" && *tid == 4 && rep.result == -2);
            assert!(ok, "{what}: tid {tid} result {}", rep.result);
        }
        if what == "read" {
            let rd = &r.iter().find(|x| x.0 == 2).unwrap().1;
            assert_eq!(
                rd.ops[0].outdata.as_ref(),
                &[3u8; 4096][..],
                "read sees the large write"
            );
        }
    }
}

/// Repop tids count per PG: several PGs of one (peer, shard) lane use the same tids. Every credit must come back
/// (the first live build keyed credits by tid only: leaked credits, deferred repops never sent, rep3 4M hung).
#[test]
fn repop_credits_of_several_pgs_with_equal_tids_all_return() {
    let mut p = Pair::of(Mc::with_wal(0, 1, 65536), Mc::with_wal(1, 1, 65536));
    p.up();
    p.flashstore();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let pg_of = |n: &str| {
        let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
        PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32))
    };
    let prim: Vec<(PgT, usize)> = (0..32)
        .map(|s| PgT::new(1, s))
        .filter(|&pg| map.pg_to_up_acting(pg).acting_primary == 0)
        .map(|pg| (pg, p.b.osds[0].input_shard(pg)))
        .collect();
    let shard = prim[0].1;
    let pgs: Vec<PgT> = prim
        .iter()
        .filter(|(_, s)| *s == shard)
        .map(|(pg, _)| *pg)
        .collect();
    assert!(pgs.len() >= 2, "need two PGs on one shard: {pgs:?}");
    let data = vec![3u8; 4 << 20];
    let ca = p.a.client(0);
    let mut tid = 0;
    // 2 x 7 x 4 MiB fit the client window of the shard (64 MiB)
    for pg in pgs.iter().take(2) {
        let names: Vec<String> = (0..)
            .map(|i| format!("q{i}"))
            .filter(|s| pg_of(s) == *pg)
            .take(7)
            .collect();
        for n in names {
            tid += 1;
            let op = p.a.op(1, &n, vec![OsdOp::writefull(data.clone())]);
            assert!(p.a.call(0, ca, tid, op).is_empty());
        }
    }
    p.settle();
    p.run_for(Duration::from_secs(30));
    let r = p.a.replies(0, ca);
    assert_eq!(r.len(), tid as usize, "all writes acked");
    assert!(
        p.a.osds[0]
            .pg
            .c
            .link_events
            .get("repop_credit_wait")
            .copied()
            .unwrap_or(0)
            > 0
    );
    assert!(p.a.osds[0].pg.flow.idle(), "every credit returned");
}

/// A replica discards the repops of an older interval unanswered (peering.md 7.3). Their credits return when the
/// primary's PG starts that interval too and aborts them (`Action::SubWritesAborted`), not after a timeout: right after
/// the map nothing is charged, and the writes, re-run in the new interval, complete (adr 0084 am. 5; was a 10 s
/// expiry that kept the lane budget).
#[test]
fn repop_credits_of_an_older_interval_return_at_the_map() {
    let mut p = Pair::of(Mc::with_wal(0, 1, 65536), Mc::with_wal(1, 1, 65536));
    p.up();
    p.flashstore();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let names: Vec<String> = (0..)
        .map(|i| format!("iv{i}"))
        .filter(|n| {
            let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
            let pg = PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32));
            map.pg_to_up_acting(pg).acting_primary == 0
        })
        .take(4)
        .collect();
    let cl = p.a.client(0);
    for (i, n) in names.iter().enumerate() {
        let op = p.a.op(1, n, vec![OsdOp::writefull(vec![6u8; 4096])]);
        assert!(p.a.call(0, cl, 1 + i as u64, op).is_empty());
    }
    assert!(
        !p.a.osds[0].pg.flow.idle(),
        "repops charged, still in the outbox"
    );
    // a new interval for every PG of pool 1 (min_size), seen by the replica first: it discards the repops unanswered
    let mut m = p.map(11, [10, 10]);
    m.pools.get_mut(&1).unwrap().min_size = 2;
    p.b.deliver(m.clone());
    p.settle();
    assert!(p.a.replies(0, cl).is_empty(), "no write acked");
    assert!(!p.a.osds[0].pg.flow.idle(), "no reply came: still charged");
    // nothing returns a credit by time; perf dump shows the age (detection only)
    p.run_for(Duration::from_secs(2));
    assert!(!p.a.osds[0].pg.flow.idle(), "no timer returns a credit");
    let gauge = |p: &mut Pair, n: &str| {
        let t = p.a.t;
        p.a.osds[0].set_now(t);
        p.a.osds[0].counters_now()[&format!("osd.{n}")].1.value
    };
    assert!(gauge(&mut p, "repop_credit_oldest_ms") >= 2000);
    assert_eq!(gauge(&mut p, "repop_credit_blocked_lanes"), 0);
    p.a.deliver(m);
    assert!(
        p.a.osds[0].pg.flow.idle(),
        "the old interval's credits return at the map"
    );
    assert_eq!(gauge(&mut p, "repop_credit_oldest_ms"), 0);
    assert_eq!(
        p.a.osds[0].pg.c.link_events.get("repop_credit_aborted"),
        Some(&4)
    );
    p.settle();
    p.run_for(Duration::from_secs(30));
    let r = p.a.replies(0, cl);
    assert_eq!(r.len(), 4, "the writes complete in the new interval");
    assert!(r.iter().all(|x| x.1.result == 0));
    assert!(p.a.osds[0].pg.flow.idle());
}

/// The primary sees the new interval first: it aborts its unanswered repops and their credits return at once; the
/// replica, still in the old interval, applies and answers them later. Those late replies find no credit (no double
/// release) and the writes, re-run in the new interval, complete with every credit back.
#[test]
fn repop_credits_return_at_the_primary_abort_before_the_replica_answers() {
    let mut p = Pair::of(Mc::with_wal(0, 1, 65536), Mc::with_wal(1, 1, 65536));
    p.up();
    p.flashstore();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let names: Vec<String> = (0..)
        .map(|i| format!("ab{i}"))
        .filter(|n| {
            let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
            let pg = PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32));
            map.pg_to_up_acting(pg).acting_primary == 0
        })
        .take(4)
        .collect();
    let cl = p.a.client(0);
    for (i, n) in names.iter().enumerate() {
        let op = p.a.op(1, n, vec![OsdOp::writefull(vec![7u8; 4096])]);
        assert!(p.a.call(0, cl, 1 + i as u64, op).is_empty());
    }
    assert!(!p.a.osds[0].pg.flow.idle(), "repops charged");
    let mut m = p.map(11, [10, 10]);
    m.pools.get_mut(&1).unwrap().min_size = 2;
    p.a.deliver(m.clone());
    assert!(
        p.a.osds[0].pg.flow.idle(),
        "aborted by the primary: credits back before any reply"
    );
    assert_eq!(
        p.a.osds[0].pg.c.link_events.get("repop_credit_aborted"),
        Some(&4)
    );
    // the replica (old interval) answers the aborted repops: no credit to return
    p.settle();
    assert!(p.a.osds[0].pg.flow.idle());
    p.b.deliver(m);
    p.settle();
    p.run_for(Duration::from_secs(30));
    let r = p.a.replies(0, cl);
    assert_eq!(r.len(), 4, "the writes complete in the new interval");
    assert!(r.iter().all(|x| x.1.result == 0));
    assert!(p.a.osds[0].pg.flow.idle());
}

/// adr 0084 am. 6: a PG message never overtakes that PG's repops held for credit. The primary of PG `pa` has repops
/// waiting for credit when the PG sends an UpdateLogMissing with the next version (the log-only path of
/// `mark_unfound_lost`, lost.rs; injected here). Before: it went out at once, the replica's `last_update` passed the
/// held repops, it discarded them as duplicates unanswered (log hole) and their writes never completed.
#[test]
fn update_log_missing_never_overtakes_its_pgs_repops_held_for_credit() {
    let mut p = Pair::of(Mc::with_wal(0, 1, 65536), Mc::with_wal(1, 1, 65536));
    p.up();
    p.flashstore();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let pg_of = |n: &str| {
        let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
        (
            PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32)),
            raw.seed,
        )
    };
    let pa = (0..32)
        .map(|s| PgT::new(1, s))
        .find(|&pg| map.pg_to_up_acting(pg).acting_primary == 0)
        .unwrap();
    let names: Vec<String> = (0..)
        .map(|i| format!("lm{i}"))
        .filter(|s| pg_of(s).0 == pa)
        .take(12)
        .collect();
    // 12 x 4 MiB: the lane budget (32 MiB with one croit-flashstore-osd peer) sends the first ones, the rest wait for credit
    let data = vec![9u8; 4 << 20];
    let cl = p.a.client(0);
    for (i, n) in names.iter().enumerate() {
        let op = p.a.op(1, n, vec![OsdOp::writefull(data.clone())]);
        assert!(p.a.call(0, cl, 1 + i as u64, op).is_empty());
    }
    assert_eq!(
        p.a.osds[0].flow_gauges().0,
        1,
        "repops of pa wait for credit"
    );
    let spg = SpgT {
        pgid: pa,
        shard: denc::types::ShardId::NO_SHARD,
    };
    let head = p.a.osds[0].pg.set.pg(spg).unwrap().info().last_update;
    let epoch = p.a.osds[0].epoch();
    let next = denc::types::Eversion::new(head.epoch, head.version + 1);
    let soid = denc::types::Hobject::new(
        names[0].as_bytes(),
        denc::types::SnapId::NOSNAP,
        pg_of(&names[0]).1,
        1,
        b"",
    );
    let entry = pgwire::LogEntry::new(pgwire::LogOp::ERROR, soid, next, head);
    let body = peering::Body::Repl(replwire::ReplMsg::UpdateLogMissing(
        replwire::MOSDPGUpdateLogMissing {
            map_epoch: epoch,
            pgid: spg,
            from: denc::types::ShardId::NO_SHARD,
            rep_tid: 1 << 40,
            entries: denc::to_vec(&vec![entry]).unwrap(),
            min_epoch: epoch,
            ..Default::default()
        },
    ));
    p.a.osds[0].pg_send(Box::new(peering::Send {
        to: 1,
        epoch,
        tid: 1 << 40,
        prio: body.priority(),
        body,
        producer: None,
    }));
    p.settle();
    p.run_for(Duration::from_secs(30));
    let replica = p.b.osds[0].pg.set.pg(spg).unwrap();
    assert_eq!(
        replica.counters().discards.get("duplicate repop"),
        None,
        "no held repop arrived after the newer log entry"
    );
    assert_eq!(
        replica.info().last_update,
        next,
        "every entry applied in order"
    );
    let r = p.a.replies(0, cl);
    assert_eq!(r.len(), names.len(), "every write completed");
    assert!(r.iter().all(|x| x.1.result == 0));
    assert!(
        p.a.osds[0]
            .pg
            .c
            .link_events
            .get("repop_credit_order_wait")
            .is_some_and(|&n| n >= 1),
        "the update log missing waited behind its PG's held repops"
    );
    assert!(
        p.a.osds[0].pg.flow.idle(),
        "every credit returned, nothing held"
    );
}

// ---------------------------------------------------------------- adr 0021 am. 53: elastic pool across cores
#[cfg(feature = "elastic")]
mod pool {
    use super::*;
    use denc::types::{CollT, Ghobject, Hobject, ShardId, SnapId};
    use store::obj::OTxn;

    // Pool messages seen on the lanes (the `lose` hook only counts, it never drops); per test thread.
    thread_local! {
        static SEEN: std::cell::Cell<[u64; 7]> = const { std::cell::Cell::new([0; 7]) };
    }

    fn seen() -> (u64, u64, u64) {
        let s = SEEN.get();
        (s[0], s[1], s[2])
    }

    fn count(_dst: usize, m: &XMsg) -> bool {
        if let XMsg::Pool(p) = m {
            let mut s = SEEN.get();
            s[match p {
                peering::PoolMsg::Request { .. } => 0,
                peering::PoolMsg::Grant { .. } => 1,
                peering::PoolMsg::Deny { .. } => 2,
                peering::PoolMsg::Return { .. } => 3,
                peering::PoolMsg::Grew { .. } => 4,
                peering::PoolMsg::Size { .. } => 5,
                peering::PoolMsg::Spare { .. } => 6,
            }] += 1;
            SEEN.set(s);
        }
        false
    }

    const OBJ: usize = 64 << 10;

    fn oid(i: u32) -> Ghobject {
        Ghobject::new(
            Hobject::new(format!("o{i}").as_bytes(), SnapId::NOSNAP, i, 1, b""),
            Ghobject::NO_GEN,
            ShardId::NO_SHARD,
        )
    }

    fn data(i: u32) -> Vec<u8> {
        (0..OBJ).map(|k| (k as u32 * 31 + i * 17) as u8).collect()
    }

    /// A PG collection living on device shard `shard`.
    fn coll_of(mc: &Mc, shard: usize) -> CollT {
        let core = shard % mc.n;
        mc.osds[core].pg.store.with_store(|s| {
            (0..512u32)
                .map(|seed| {
                    CollT::Pg(SpgT {
                        pgid: PgT::new(1, seed),
                        shard: denc::types::ShardId::NO_SHARD,
                    })
                })
                .find(|c| s.shard_of(c) == shard)
                .unwrap()
        })
    }

    /// Queue `n` 64 KiB objects into the PG on `shard` through its core's store (no PG layer), settling the OSD after each.
    fn fill(mc: &mut Mc, shard: usize, c: CollT, n: u32) {
        let core = shard % mc.n;
        for i in 0..n {
            let mut t = OTxn::new();
            if i == 0 {
                t.mkcoll(c);
            }
            let d = data(i);
            t.write(c, &oid(i), 0, &d);
            mc.osds[core]
                .pg
                .store
                .with_store(|s| s.queue(&t, 1_000_000 + i as u64))
                .unwrap();
            mc.settle();
        }
        let mut errs = Vec::new();
        mc.osds[core]
            .pg
            .store
            .with_store(|s| s.take_queue_errors(&mut errs));
        assert!(errs.is_empty(), "queue errors {errs:?}");
    }

    fn lent(mc: &Mc, shard: usize) -> usize {
        mc.osds[shard % mc.n]
            .pg
            .store
            .with_store(|s| s.lent_chunks(shard as u32).unwrap())
            .iter()
            .filter(|e| e.0 != store::alloc::HOLE)
            .count()
    }

    fn reads_back(mc: &Mc, shard: usize, c: CollT, n: u32) {
        mc.osds[shard % mc.n].pg.store.with_store(|s| {
            for i in (0..n).step_by(7) {
                assert_eq!(
                    s.read(&c, &oid(i), 0, OBJ as u64).unwrap(),
                    data(i),
                    "object {i}"
                );
            }
        });
    }

    /// Base of one shard in blocks (4 KiB) from the pool geometry (core 0 holds the table).
    fn geom(mc: &Mc) -> (u64, u64, u64) {
        mc.osds[0].pg.store.with_store(|s| {
            let l = s.lending().expect("core 0 owns the pool");
            (l.geom.base * l.geom.chunk, l.geom.chunk, l.free_chunks())
        })
    }

    /// A shard on a worker core outgrows its base: request to core 0, durable grant back, exactly one answer per request,
    /// the data reads back, the OSD statfs does not charge the fullest shard.
    #[test]
    fn worker_shard_borrows_from_the_owner_core() {
        let mut mc = Mc::with_pool(0, 2, S, 2048, true);
        mc.lose = Some(count);
        let (base, chunk, pool0) = geom(&mc);
        assert!(pool0 > 4, "pool {pool0} chunks");
        let c = coll_of(&mc, 1);
        let n = ((base + 2 * chunk) as usize * 4096 / OBJ) as u32;
        let (r0, g0, d0) = seen();
        fill(&mut mc, 1, c, n);
        reads_back(&mc, 1, c, n);
        let borrowed = lent(&mc, 1) as u64;
        let (r1, g1, d1) = seen();
        let (req, grant) = (r1 - r0, g1 - g0);
        assert!(borrowed >= 2, "borrowed {borrowed}");
        // exactly once: every cross-core request got one grant (or deny), every grant is one chunk of the shard
        assert_eq!(grant, borrowed, "grants {grant} vs lent {borrowed}");
        assert_eq!(req, grant + (d1 - d0), "requests {req}");
        let (_, _, free) = geom(&mc);
        assert_eq!(
            free,
            pool0 - borrowed,
            "the pool lost exactly what was lent"
        );
        // statfs of the OSD: shard 1 is past its base but the pool has chunks: not full
        mc.osds[1].push_stats();
        mc.settle();
        let s = mc.osds[0].statfs_all();
        assert!(
            s.available * 2 > s.total,
            "avail {} of {}",
            s.available,
            s.total
        );
        assert!(
            s.allocated as u64 >= n as u64 * OBJ as u64,
            "usage is real: {}",
            s.allocated
        );
        // remount: the table holds the grants, the data is intact
        mc.restart();
        assert_eq!(lent(&mc, 1) as u64, borrowed);
        reads_back(&mc, 1, c, n);
    }

    /// The owner core's own shards are served in the same poll (no message), the answer count stays zero.
    #[test]
    fn owner_shard_borrows_locally() {
        let mut mc = Mc::with_pool(0, 2, S, 2048, true);
        mc.lose = Some(count);
        let (base, chunk, _) = geom(&mc);
        let c = coll_of(&mc, 0);
        let n = ((base + chunk) as usize * 4096 / OBJ) as u32;
        let (_, g0, _) = seen();
        fill(&mut mc, 0, c, n);
        reads_back(&mc, 0, c, n);
        assert!(lent(&mc, 0) >= 1);
        assert_eq!(
            seen().1,
            g0,
            "no lane message for the owner core's own shard"
        );
        mc.osds[1].push_stats();
        mc.settle();
        let s = mc.osds[0].statfs_all();
        assert!(
            s.available * 2 > s.total,
            "avail {} of {}",
            s.available,
            s.total
        );
    }

    /// Two cores ask while the pool is nearly dry: the pool is never lent twice (sum of lent chunks + free = pool).
    #[test]
    fn two_worker_cores_never_share_a_chunk() {
        let mut mc = Mc::with_pool(0, 3, S, 2048, true);
        mc.lose = Some(count);
        let (base, chunk, pool0) = geom(&mc);
        let (c1, c2) = (coll_of(&mc, 1), coll_of(&mc, 2));
        let n = ((base + 3 * chunk) as usize * 4096 / OBJ) as u32;
        // interleave: both cores keep asking
        for round in 0..4u32 {
            let part = n / 4;
            for (sh, c) in [(1usize, c1), (2, c2)] {
                let core = sh % mc.n;
                for i in round * part..(round + 1) * part {
                    let mut t = OTxn::new();
                    if i == 0 {
                        t.mkcoll(c);
                    }
                    let d = data(i);
                    t.write(c, &oid(i), 0, &d);
                    mc.osds[core]
                        .pg
                        .store
                        .with_store(|s| s.queue(&t, 2_000_000 + i as u64))
                        .unwrap();
                }
            }
            mc.settle();
        }
        let (l1, l2) = (lent(&mc, 1) as u64, lent(&mc, 2) as u64);
        let (_, _, free) = geom(&mc);
        assert_eq!(
            l1 + l2 + free,
            pool0,
            "lent {l1} + {l2}, free {free}, pool {pool0}"
        );
        reads_back(&mc, 1, c1, n);
        reads_back(&mc, 2, c2, n);
    }

    /// A pooled core is judged by its fullest shard against what that shard can still borrow (adr 0021 S4, review S1):
    /// its own sum reading full does not make the OSD read full while the pool has room (`fullest` low); its fullest
    /// shard at the floor with the pool dry (`fullest` 1) does, like a plain core whose capacity reads full.
    #[test]
    fn statfs_charges_the_fullest_shard_of_a_pooled_core() {
        let mut mc = Mc::with_pool(0, 2, S, 2048, true);
        let avail = |mc: &Mc| mc.osds[0].statfs_all().available;
        let base = avail(&mc);
        let sp = |pooled, fullest| crate::xcore::CoreStats {
            space: Some(peering::Space {
                total: 1 << 30,
                available: 0,
                allocated: 1 << 30,
                internal_metadata: 0,
                pooled,
                fullest,
            }),
            ..Default::default()
        };
        mc.osds[0].cl.stats[1] = Some(sp(true, 0.2));
        let pooled = avail(&mc);
        mc.osds[0].cl.stats[1] = Some(sp(true, 1.0));
        let pooled_dry = avail(&mc);
        mc.osds[0].cl.stats[1] = Some(sp(false, 0.0));
        let plain = avail(&mc);
        // pool with room: the sum rules (the other core's capacity is all used, the rest is free); a dry pool or a plain
        // full core caps it
        assert!(pooled >= base, "pooled {pooled} base {base}");
        assert_eq!(pooled_dry, 0, "pooled core with a dry pool reads full");
        assert!(plain < pooled / 2, "plain {plain} pooled {pooled}");
    }

    /// The replica's TOOFULL decision (`peering::LocalFull`, backfill REJECT/REVOKE and push refusal) follows the
    /// fullest store shard (review S1/F1): a pooled core whose hot shard is past backfillfull with the pool dry sets it
    /// although the OSD's summed capacity is mostly free; the same core with pool room clears it.
    #[test]
    fn backfillfull_follows_the_fullest_shard() {
        let mut mc = Mc::with_pool(0, 2, S, 2048, true);
        mc.up();
        let sp = |fullest| crate::xcore::CoreStats {
            space: Some(peering::Space {
                total: 1 << 20,
                available: 1 << 19,
                allocated: 1 << 19,
                internal_metadata: 0,
                pooled: true,
                fullest,
            }),
            ..Default::default()
        };
        let o = &mut mc.osds[0];
        let map = Arc::make_mut(o.map.as_mut().unwrap());
        (map.nearfull_ratio, map.backfillfull_ratio, map.full_ratio) = (0.85, 0.9, 0.95);
        o.cl.stats[1] = Some(sp(0.1));
        o.update_local_failsafe();
        assert!(!o.pg.backfillfull, "sum and shards have room");
        o.cl.stats[1] = Some(sp(0.92));
        o.update_local_failsafe();
        assert!(o.pg.backfillfull, "hot shard past backfillfull");
        assert!(!o.pg.failsafe, "below the failsafe ratio");
        o.cl.stats[1] = Some(sp(1.0));
        o.update_local_failsafe();
        assert!(o.pg.failsafe, "hot shard full with the pool dry");
        o.cl.stats[1] = Some(sp(0.1));
        o.update_local_failsafe();
        assert!(
            !o.pg.backfillfull && !o.pg.failsafe,
            "cleared once the shard has room again"
        );
    }

    /// Held backfill reservation bytes count in the OSD's fill (osd-lifecycle 4.4): a worker core's held bytes push the
    /// adjusted fill past backfillfull (not the physical one: no failsafe), and every core's reservation view carries the
    /// OTHER cores' held bytes, never its own (each core adds its own live sum at judgement time).
    #[test]
    fn held_backfill_bytes_count_in_the_osd_fill() {
        let mut mc = Mc::with_pool(0, 2, S, 2048, true);
        mc.up();
        let st = |bf_held| crate::xcore::CoreStats {
            space: Some(peering::Space {
                total: 1 << 20,
                available: 1 << 19,
                allocated: 1 << 19,
                internal_metadata: 0,
                pooled: false,
                fullest: 0.0,
            }),
            bf_held,
            ..Default::default()
        };
        let o = &mut mc.osds[0];
        let map = Arc::make_mut(o.map.as_mut().unwrap());
        (map.nearfull_ratio, map.backfillfull_ratio, map.full_ratio) = (0.85, 0.9, 0.95);
        o.cl.stats[1] = Some(st(0));
        o.update_local_failsafe();
        assert!(!o.pg.backfillfull);
        let a = o.statfs_all();
        let used = a.total - a.available;
        assert!((used as f64) < a.total as f64 * 0.8, "room: {a:?}");
        let held = (a.total as f64 * 0.92) as u64 - used;
        o.cl.stats[1] = Some(st(held));
        o.update_local_failsafe();
        assert!(o.pg.backfillfull, "held bytes past backfillfull");
        assert!(!o.pg.failsafe, "failsafe stays on the physical fill");
        let sent = o.cl.local_full_sent[1].expect("worker view sent");
        assert_eq!(
            sent.used, used,
            "the worker's own held bytes are not in its view"
        );
        assert!(!sent.backfillfull_with(0) && sent.backfillfull_with(held));
        o.cl.stats[1] = Some(st(0));
        o.update_local_failsafe();
        assert!(!o.pg.backfillfull, "released reservation clears it");
    }

    /// adr 0021 am. 72 (customer incident 2026-10-31): a worker core's shard filled to just below its base, never having
    /// asked for a chunk, knows the true pool from the owner's `Size` updates: the OSD statfs is the real device usage
    /// (no fullest-shard clamp) and neither backfillfull nor failsafe trip. Before, its pool hint stayed at the mount
    /// placeholder and the shard read ~its base fill as the OSD's fill.
    #[test]
    fn worker_shard_at_its_base_keeps_the_osd_at_real_usage() {
        let mut mc = Mc::with_pool(0, 3, S, 2048, true);
        let (base, chunk, pool0) = geom(&mc);
        let c = coll_of(&mc, 1);
        let n = ((base - chunk) as usize * 4096 / OBJ) as u32;
        fill(&mut mc, 1, c, n);
        let (ctl, sf) = shard_state(&mc, 1);
        assert_eq!(ctl.grants, 0, "no chunk borrowed");
        assert_eq!(
            ctl.pool,
            pool0 * chunk,
            "the owner's Size reached the worker core"
        );
        assert!(sf.fill_ratio() > 0.8, "near its base: {sf:?}");
        // balanced fill: every shard just below its base, the pool untouched
        for shard in (0..S as usize).filter(|&s| s != 1) {
            let c = coll_of(&mc, shard);
            fill(&mut mc, shard, c, n);
        }
        let (_, _, free) = geom(&mc);
        assert_eq!(free, pool0, "nobody borrowed");
        mc.up();
        for core in 1..mc.n {
            mc.osds[core].push_stats();
        }
        mc.settle();
        let o = &mut mc.osds[0];
        let snap = o.statfs_snapshot();
        let a = &snap.aggregate;
        // statfs = the real device usage: no fullest-shard clamp on a balanced fill
        assert_eq!(
            a.available, snap.available_before_clamp,
            "no fullest-shard clamp: {a:?}"
        );
        let fill = (a.total - a.available) as f64 / a.total as f64;
        assert!(
            (0.3..0.5).contains(&fill),
            "OSD fill {fill}: the bases are ~90 % used, the pool free"
        );
        let map = Arc::make_mut(o.map.as_mut().unwrap());
        (map.nearfull_ratio, map.backfillfull_ratio, map.full_ratio) = (0.85, 0.9, 0.95);
        o.update_local_failsafe();
        assert!(!o.pg.backfillfull && !o.pg.failsafe);
    }

    const BIG: usize = 1 << 20;

    fn shard_state(mc: &Mc, shard: usize) -> (store::lend::Ctl, store::shard::Statfs) {
        mc.osds[shard % mc.n].pg.store.with_store(|s| {
            let x = s.shards.iter().find(|x| x.idx == shard as u32).unwrap();
            (x.sh.lend.clone(), x.sh.statfs())
        })
    }

    /// Write objects `first..` into the PG on `shard` until the pool denies the shard; returns `(objects, bytes)`. 1 MiB
    /// objects while the shard has room or the pool has chunks, else 64 KiB ones: the denial comes from the watermark
    /// request, never from a txn hitting ENOSPC (the PG adapter fail-stops the core on a queue error, ADR 0066; the PG
    /// layer's fullness admission keeps client writes from it).
    fn fill_until_denied(mc: &mut Mc, shard: usize, c: CollT, first: u32) -> (u32, u64) {
        let core = shard % mc.n;
        let d0 = shard_state(mc, shard).0.denies;
        let mut bytes = 0;
        for i in first..first + 100_000 {
            let sf = shard_state(mc, shard).1;
            let room = sf.data_free.saturating_sub(sf.data_reserve);
            let len = if room > 1024 || geom(mc).2 > 0 {
                BIG
            } else {
                OBJ
            };
            let d = vec![shard as u8 + 1; len];
            let mut t = OTxn::new();
            t.push(store::obj::TOp::MkColl {
                cid: c,
                bits: 0,
                exist_ok: true,
            });
            t.write(c, &oid(i), 0, &d);
            mc.osds[core]
                .pg
                .store
                .with_store(|s| s.queue(&t, 5_000_000 + i as u64))
                .unwrap();
            mc.settle();
            bytes += len as u64;
            assert!(!mc.osds[core].pg.dead, "core {core} failed at object {i}");
            if shard_state(mc, shard).0.denies > d0 {
                return (i + 1 - first, bytes);
            }
        }
        panic!("shard {shard} never denied");
    }

    /// Elastic reclaim (adr 0021 am. 57): shard 1 (core 1) holds the whole pool, shard 2 (core 2) is denied; shard 1
    /// deletes its data: its empty chunks go back as `Return` over the lane to core 0, the owner's durable free entries
    /// send one `Grew` over the lane to core 2, whose shard borrows again. Pool accounting exact, data intact.
    #[test]
    fn denied_worker_shard_reopens_when_chunks_return() {
        let mut mc = Mc::with_pool(0, 3, S, 2048, true);
        mc.lose = Some(count);
        let (_, chunk, pool0) = geom(&mc);
        let (c1, c2) = (coll_of(&mc, 1), coll_of(&mc, 2));
        let (n1, _) = fill_until_denied(&mut mc, 1, c1, 0);
        assert_eq!(lent(&mc, 1) as u64, pool0, "shard 1 holds the pool");
        fill_until_denied(&mut mc, 2, c2, 100_000);
        assert!(!shard_state(&mc, 2).0.open, "shard 2 denied");
        let s0 = SEEN.get();
        for i in 0..n1 {
            let mut t = OTxn::new();
            t.remove(c1, &oid(i));
            mc.osds[1]
                .pg
                .store
                .with_store(|s| s.queue(&t, 6_000_000 + i as u64))
                .unwrap();
        }
        mc.settle();
        // store clocks move only with device time here: jump them past the reclaim checks (one return per second)
        let mut back = false;
        for _ in 0..(pool0 as usize + 20) * 20 {
            for o in &mc.osds {
                o.pg.store.with_store(|s| s.clk.t += 100_000_000);
            }
            mc.settle();
            if lent(&mc, 1) == 0 && !mc.osds[0].pg.store.with_store(|s| s.lend_busy()) {
                back = true;
                break;
            }
        }
        assert!(back, "lent {} {:?}", lent(&mc, 1), shard_state(&mc, 1));
        let s1 = SEEN.get();
        assert_eq!(s1[3] - s0[3], pool0, "one Return per chunk over the lane");
        // every Grew answers one earlier denial (shard 1 at the end of its fill, shard 2 once or more while chunks trickle back)
        let denied = shard_state(&mc, 1).0.denies + shard_state(&mc, 2).0.denies;
        assert!(
            s1[4] >= 1 && s1[4] <= denied,
            "Grew {} denies {denied}",
            s1[4]
        );
        assert!(shard_state(&mc, 2).0.open, "Grew reached core 2");
        let (_, _, free) = geom(&mc);
        assert_eq!(free + lent(&mc, 2) as u64, pool0, "nothing lost");
        let (_, more) = fill_until_denied(&mut mc, 2, c2, 200_000);
        assert!(
            more >= (pool0 - 1) * chunk * 4096 * 8 / 10,
            "shard 2 borrowed again: {more} bytes, pool {pool0} chunks"
        );
        mc.osds[2].pg.store.with_store(|s| {
            assert_eq!(
                s.read(&c2, &oid(200_000), 0, BIG as u64).unwrap(),
                vec![3u8; BIG]
            );
        });
    }
}

/// A cluster link dialled for a dead incarnation of a peer is closed when a map names the new incarnation, not only when
/// something is next sent to that peer (lossless link: it would redial the old nonce for ever and the restarted OSD
/// would log "target addr is not ours" every 15 s).
#[test]
fn map_with_a_new_peer_incarnation_closes_the_old_cluster_link() {
    let mut p = Pair::new(2, 2);
    p.up();
    let old = |p: &Pair| {
        p.a.osds
            .iter()
            .filter(|o| o.pg.peers.get(&1).is_some_and(|c| c.up_from == 10))
            .count()
    };
    assert!(old(&p) > 0, "a cluster link to osd.1 incarnation 10 exists");
    let m = p.map(11, [10, 11]);
    p.a.deliver(m);
    assert_eq!(old(&p), 0, "no link left for incarnation 10");
    let swept: u64 =
        p.a.osds
            .iter()
            .map(|o| {
                o.pg.c
                    .link_events
                    .get("peer_link_swept_new_incarnation")
                    .copied()
                    .unwrap_or(0)
            })
            .sum();
    assert!(swept > 0, "the sweep, not a later send, closed it");
}

/// Wrongly marked down (a SIGSTOP longer than the heartbeat grace): every core takes the new cluster + heartbeat nonce.
/// A worker that kept the old one refused each peer dial of the new address as "target addr is not ours", so the PGs it
/// owned never peered again and client ops hung.
#[test]
fn wrongly_marked_down_rebinds_every_core() {
    use crate::osd::MsgrId;
    let mut mc = Mc::new(3);
    mc.up();
    let old = mc.osds[0].cluster_addrs.clone();
    let mut m = mc.map(11, 10);
    m.osd_state[0] = osd_state::EXISTS;
    mc.deliver(m);
    mc.settle();
    let new = mc.osds[0].cluster_addrs.clone();
    assert_ne!(new, old, "control core rebound");
    for (i, o) in mc.osds.iter().enumerate() {
        assert_eq!(o.cluster_addrs, new, "core {i} cluster identity");
        assert_eq!(
            o.msgr[MsgrId::Cluster as usize].cfg.addrs,
            new,
            "core {i} accepts dials of the new cluster address"
        );
        assert_eq!(
            o.msgr[MsgrId::HbBackSrv as usize].cfg.addrs,
            o.hb_back_addrs,
            "core {i} heartbeat identity"
        );
        assert_eq!(o.hb_back_addrs, mc.osds[0].hb_back_addrs);
    }
}

/// Every dial names the bind address of its messenger (classic `ms_bind_before_connect`): cluster and heartbeat back the
/// cluster address, public, heartbeat front and the mon link the public one.
#[test]
fn dials_bind_the_address_of_their_messenger() {
    use crate::osd::{IoCmd, MsgrId, Purpose};
    let mut mc = Mc::new(1);
    mc.up();
    let o = &mut mc.osds[0];
    o.cfg.public_ips = vec![IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))];
    o.cfg.cluster_ips = vec![IpAddr::V4(Ipv4Addr::new(10, 2, 2, 2))];
    let peer = EntityAddrVec::single(EntityAddr::v4(
        EntityAddr::TYPE_MSGR2,
        7,
        [10, 3, 3, 3],
        6801,
    ));
    let cases = [
        (MsgrId::Public, IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))),
        (MsgrId::Cluster, IpAddr::V4(Ipv4Addr::new(10, 2, 2, 2))),
        (MsgrId::HbFrontCli, IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))),
        (MsgrId::HbBackCli, IpAddr::V4(Ipv4Addr::new(10, 2, 2, 2))),
    ];
    for (m, want) in cases {
        let id = o.dial(m, Purpose::Peer(1), EntityName::OSD, &peer).unwrap();
        o.pump();
        let mut got = None;
        while let Some(c) = o.poll_io() {
            if let IoCmd::Dial { conn, src, .. } = c
                && conn == id
            {
                got = Some(src);
            }
        }
        assert_eq!(got, Some(Some(want)), "{m:?}");
    }
}

#[test]
fn the_drain_slice_learns_the_cost_per_work_unit_from_the_loop() {
    let mut s = crate::xcore::Slice::default();
    assert_eq!(
        s.budget(),
        crate::xcore::SLICE_NS as usize,
        "1 ns per unit until measured"
    );
    // an iteration without drained work teaches nothing
    s.learn(1_000_000);
    assert_eq!(s.budget(), crate::xcore::SLICE_NS as usize);
    // 4 KiB of work in 40 us: 10 ns per unit; the EWMA moves 1/8 per iteration and converges
    for _ in 0..100 {
        s.add(4096);
        s.learn(40_960);
    }
    let b = s.budget();
    assert!(
        (9_000..=11_000).contains(&b),
        "~100 us at 10 ns per unit: {b}"
    );
}

#[test]
fn the_drain_slice_gets_as_long_as_the_background_work_took() {
    let mut s = crate::xcore::Slice::default();
    let base = s.budget();
    // a short background step keeps the slice
    s.share(crate::xcore::SLICE_NS / 2);
    assert_eq!(s.budget(), base);
    // a 3.4 ms merge slice in the previous iteration: the drains may take as long (fair share)
    s.share(3_400_000);
    assert_eq!(s.budget(), base * 34);
    // no background work: back to the plain slice
    s.share(0);
    assert_eq!(s.budget(), base);
}

/// adr 0006 am. 6: each source core's share of an inbox drain is at least what the own links handed on before it.
#[test]
fn each_source_core_may_hand_on_as_much_as_the_own_links_did() {
    let mut s = crate::xcore::Slice::default();
    let base = s.budget();
    // nothing on the own links: one slice per source core
    assert_eq!(s.start_drain(), base);
    // five 256-key omap batches (~61 KiB each) on the own links since the previous drain
    for _ in 0..5 {
        s.add_link(61 << 10);
    }
    assert_eq!(s.start_drain(), 5 * (61 << 10));
    // the own links' count starts over with every drain
    assert_eq!(s.start_drain(), base);
    // less than a slice on the own links: one slice
    s.add_link(4096);
    assert_eq!(s.start_drain(), base);
    // the link work also teaches the slice its cost per unit
    for _ in 0..100 {
        s.add_link(4096);
        s.learn(40_960);
    }
    assert!((9_000..=11_000).contains(&s.budget()));
}

/// One client writefull of `size` bytes on a pair whose WAL rings have `wal_blocks` blocks per OSD: returns the
/// answer's result and, when it succeeded, whether a read gets the bytes back. The answer must always come (the
/// harness' `settle` waits for the simulated device, whose 1 MiB transfers outlast the quiet window).
fn big_writefull(size: usize, wal_blocks: u64) -> (i32, bool) {
    {
        let mut p = Pair::of(
            Mc::with_wal(0, 2, wal_blocks),
            Mc::with_wal(1, 1, wal_blocks),
        );
        p.up();
        let map = p.a.osds[0].osdmap().unwrap().clone();
        let name = (0..)
            .map(|i| format!("big{i}"))
            .find(|n| {
                let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
                let pg = PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32));
                map.pg_to_up_acting(pg).acting_primary == 0
            })
            .unwrap();
        let cl = p.a.client(0);
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let op = p.a.op(1, &name, vec![OsdOp::writefull(data.clone())]);
        let mut r = p.a.call(0, cl, 1, op);
        p.settle();
        r.extend(p.a.replies(0, cl));
        assert_eq!(r.len(), 1, "no reply for a {size} byte writefull");
        if r[0].1.result != 0 {
            return (r[0].1.result, false);
        }
        let op = p.a.op(1, &name, vec![OsdOp::read(0, size as u64)]);
        let mut r = p.a.call(0, cl, 2, op);
        p.settle();
        r.extend(p.a.replies(0, cl));
        assert_eq!(r.len(), 1, "no read reply for {size} bytes");
        (0, r[0].1.ops[0].outdata == data)
    }
}

/// Realistic object sizes (1 MiB .. 64 MiB) in one writefull are answered and read back intact.
#[test]
fn big_single_writefull_is_answered() {
    for size in [1usize << 20, 4 << 20, 16 << 20, 64 << 20] {
        assert_eq!(big_writefull(size, 65536), (0, true), "{size} bytes");
    }
}

/// On the small default test rings a write the ring cannot hold is still answered (an error), never silence.
#[test]
fn writefull_beyond_the_wal_ring_is_answered_with_an_error() {
    let (res, _) = big_writefull(64 << 20, 2048);
    assert_ne!(res, 0);
}

#[path = "prewrite_tests.rs"]
mod prewrite_tests;

#[path = "mgrc_tests.rs"]
mod mgrc_tests;

/// devicehealth (doc/spec/devicehealth.md): the mgr scrapes with `{"prefix":"smart","format":"json","devid":""}` (all devices) or
/// the device's id as filter. Every form is answered with a JSON object keyed by the classic-form device id (a filter that
/// matches nothing = `{}`, never no reply); boot metadata and `list_devices` name the device like classic.
#[test]
fn devicehealth_mgr_scrape_forms() {
    let mut mn = [b' '; 40];
    mn[..26].copy_from_slice(b"SAMSUNG MZQL27T6HBLA-00A07");
    let mut sn = [b' '; 20];
    sn[..14].copy_from_slice(b"S6CKNS0X903238");
    let id = "SAMSUNG_MZQL27T6HBLA-00A07_______________S6CKNS0X903238______";
    nvme::health::set_device(nvme::health::DevMeta {
        name: "nvme2n1".into(),
        pci: "0000:01:00.0".into(),
        kernel: true,
        ident: nvme::health::Ident::from_raw(&mn, &sn, b"FW"),
        size_bytes: 4096 * 100,
    });
    nvme::health::set_smart_json(r#"{"temperature":{"current":30}}"#.into());
    let mut mc = Mc::new(1);
    mc.up();
    let run = |mc: &mut Mc, cmd: &str| {
        let (r, _, out) = mc.osds[0]
            .run_command(cmd, &crate::tell::ReplyTo::Asok(0))
            .expect("smart is answered at once");
        assert_eq!(r, 0);
        serde_json::from_slice::<serde_json::Value>(&out.into_bytes()).unwrap()
    };
    let all = run(&mut mc, r#"{"prefix":"smart","format":"json","devid":""}"#);
    assert_eq!(all[id]["temperature"]["current"], 30);
    assert_eq!(all.as_object().unwrap().len(), 1);
    let one = run(
        &mut mc,
        &format!(r#"{{"prefix":"smart","format":"json","devid":"{id}"}}"#),
    );
    assert_eq!(one, all);
    // an id of an earlier registration (trimmed form) matches nothing: an empty object, still an answer
    let old = run(
        &mut mc,
        r#"{"prefix":"smart","format":"json","devid":"SAMSUNG_MZQL27T6HBLA-00A07_S6CKNS0X903238"}"#,
    );
    assert_eq!(old, serde_json::json!({}));
    let ld = run(&mut mc, r#"{"prefix":"list_devices"}"#);
    assert_eq!(
        ld,
        serde_json::json!([{"device": "/dev/nvme2n1", "device_id": id}])
    );
    let md = mc.osds[0].boot_metadata();
    assert_eq!(md["devices"], "nvme2n1");
    assert_eq!(md["device_ids"], format!("nvme2n1={id}"));
    assert_eq!(md["device_paths"], "nvme2n1=pci-0000:01:00.0-nvme-1");
    assert_eq!(md["bluestore_bdev_dev_node"], "/dev/nvme2n1");
}

/// adr 0593-dedup-deep-scrub-reformat (dedup-listing.md 3, 4): MOSDDedupList on a worker core link is validated there,
/// scattered over every core by the control core and answered on the worker's link; errors per the fork's order.
#[test]
fn dedup_list_request_on_a_worker_link() {
    use messages::{MOSDDedupList, MOSDDedupListReply, Message};
    let mut mc = Mc::new(4);
    mc.up();
    for o in &mut mc.osds {
        o.conf
            .set(
                crate::config::Level::Override,
                "flashstore_dedup_list",
                "true",
            )
            .unwrap();
    }
    let cl = mc.client(2);
    let ask_list = |mc: &mut Mc, m: MOSDDedupList, tid: u64| -> MOSDDedupListReply {
        mc.osds[2].on_link_message(cl, crate::osd::Purpose::Accepted, tid, m.into());
        mc.settle();
        let out = std::mem::take(&mut mc.osds[2].t.out);
        let f = out
            .iter()
            .find(|f| f.0 == cl && f.1 == tid && f.2.0 == 138)
            .unwrap_or_else(|| panic!("no MOSDDedupListReply on the worker link: {out:?}"));
        MOSDDedupListReply::decode(f.2.1, &f.3.front, &[], &[]).unwrap()
    };
    let req = MOSDDedupList {
        fsid: mc.fsid,
        pool: 1,
        shard: 3,
        shard_bits: 4,
        max: 100,
        ..Default::default()
    };
    // no records yet: an empty, complete answer with the OSD's clock
    let r = ask_list(&mut mc, req.clone(), 10);
    assert_eq!(
        (r.r, r.result.completed, r.result.entries.len()),
        (0, true, 0)
    );
    assert!(r.result.now > 1_600_000_000_000_000_000);
    // errors, answered by the receiving core with the default result
    for (tid, m, want) in [
        (
            11,
            MOSDDedupList {
                fsid: Default::default(),
                ..req.clone()
            },
            -22,
        ),
        (
            12,
            MOSDDedupList {
                shard: 16,
                ..req.clone()
            },
            -22,
        ),
        (
            13,
            MOSDDedupList {
                max: 0,
                ..req.clone()
            },
            -22,
        ),
        (
            14,
            MOSDDedupList {
                pool: 99,
                ..req.clone()
            },
            -2,
        ),
    ] {
        let r = ask_list(&mut mc, m, tid);
        assert_eq!(
            (r.r, r.result.clone()),
            (want, Default::default()),
            "tid {tid}"
        );
    }
    // caps: pool-wide read; pruning needs write too
    let set_caps = |mc: &mut Mc, c: &str| {
        let caps = Arc::new(Caps::parse(c).unwrap());
        mc.osds[2].links.get_mut(&cl).unwrap().caps = Some(caps);
    };
    set_caps(&mut mc, "allow r pool=other");
    assert_eq!(ask_list(&mut mc, req.clone(), 15).r, -1);
    set_caps(&mut mc, "allow r namespace=ns1");
    assert_eq!(
        ask_list(&mut mc, req.clone(), 16).r,
        -1,
        "a namespace grant is not pool-wide"
    );
    set_caps(&mut mc, "allow r");
    assert_eq!(ask_list(&mut mc, req.clone(), 17).r, 0);
    let prune = MOSDDedupList {
        prune_older_than: 3600,
        ..req.clone()
    };
    assert_eq!(ask_list(&mut mc, prune.clone(), 18).r, -1);
    set_caps(&mut mc, "allow rw");
    assert_eq!(ask_list(&mut mc, prune, 19).r, 0);
    // not served without the option
    for o in &mut mc.osds {
        o.conf
            .set(
                crate::config::Level::Override,
                "flashstore_dedup_list",
                "false",
            )
            .unwrap();
    }
    assert_eq!(ask_list(&mut mc, req, 20).r, -95);
}

/// adr 0593-dedup-deep-scrub-reformat (dedup-listing.md 2): feature bit 51 (+57) in MOSDBoot only with `flashstore_dedup_list`.
#[test]
fn boot_advertises_dedup_list_only_when_served() {
    let mut mc = Mc::new(1);
    mc.up();
    for on in [false, true] {
        let o = &mut mc.osds[0];
        o.conf
            .set(
                crate::config::Level::Override,
                "flashstore_dedup_list",
                if on { "true" } else { "false" },
            )
            .unwrap();
        o.t.sent.clear();
        o.send_boot();
        let f =
            o.t.sent
                .iter()
                .find_map(|m| match m {
                    messages::AnyMessage::MOSDBoot(b) => Some(b.osd_features),
                    _ => None,
                })
                .expect("MOSDBoot sent");
        assert_eq!(
            f & messages::FEATUREMASK_OSD_DEDUP_LIST == messages::FEATUREMASK_OSD_DEDUP_LIST,
            on
        );
        assert_eq!(
            f & !messages::FEATUREMASK_OSD_DEDUP_LIST,
            crate::release::CLAIMED_FEATURES & !messages::FEATUREMASK_OSD_DEDUP_LIST
        );
    }
}

/// Cap checks of the op engine, the EC direct read and the dedup list match the pool by its name and application
/// metadata from one helper; an unknown pool or no map has neither (osdcaps.md: `pool=` and `tag` grants miss).
#[test]
fn pool_caps_info_names_the_pool_and_its_apps() {
    let mut m = real_map();
    let (&id, name) = m.pool_name.iter().next().unwrap();
    let name = name.as_bytes().to_vec();
    m.pools
        .get_mut(&id)
        .unwrap()
        .application_metadata
        .insert("rbd".into(), Default::default());
    let (n, apps) = crate::ops::pool_caps_info(Some(&m), id);
    assert_eq!(n, name.as_slice());
    assert!(apps.is_some_and(|a| a.contains_key("rbd")));
    assert_eq!(crate::ops::pool_caps_info(Some(&m), 999), (&b""[..], None));
    assert_eq!(crate::ops::pool_caps_info(None, id), (&b""[..], None));
}

/// Idle unauthenticated links hold only their own banner, charged at accept to their listener's budget: an
/// unauthenticated host that opens thousands of public connections cannot stop the cluster or heartbeat listeners from
/// taking peer connections (classic has no link cap either; `ms_connection_ready_timeout` closes the idle links).
#[test]
fn idle_pre_auth_links_never_block_another_listener() {
    let mut mc = Mc::new(1);
    mc.up();
    let t = mc.t;
    let o = &mut mc.osds[0];
    for port in 0..2000u16 {
        let id = o.on_accept(
            Listener::Public,
            crate::osd::sock4([10, 9, 0, 1], 20_000 + port),
            t,
        );
        assert!(o.links.contains_key(&id), "public accept {port}");
    }
    for (listener, port) in [
        (Listener::Cluster, 7000),
        (Listener::HbFront, 7001),
        (Listener::HbBack, 7002),
    ] {
        let id = o.on_accept(listener, crate::osd::sock4([10, 1, 0, 1], port), t);
        assert!(
            o.links.contains_key(&id),
            "{listener:?} accept blocked by idle public links"
        );
    }
    // every buffered byte is charged, to its own messenger, from the accept on
    let mut held = [0u64; crate::osd::MsgrId::COUNT];
    for l in o.links.values() {
        held[l.msgr as usize] += l.conn.preauth_bytes() as u64;
    }
    assert!(held[crate::osd::MsgrId::Public as usize] > 0, "the banners");
    assert_eq!(o.cl.preauth_used, held);
}

/// Pre-auth memory is bounded by the bytes actually buffered, per messenger: handshake bytes are charged to the
/// listener's budget and the transcript that would exceed it closes its link (the peer retries). A public charge is
/// not visible to the cluster listener's budget, so client handshakes never starve peer accepts.
#[test]
fn pre_auth_transcript_bytes_are_bounded_per_messenger() {
    use crate::osd::MsgrId;
    use msgr2::auth::AuthNoneClient;
    use msgr2::{Connection, PolicyTable, SessionTable};
    let mut mc = Mc::new(1);
    mc.up();
    let t = mc.t;
    // a client banner is the first pre-auth bytes on the wire
    let banner = {
        let name = EntityName::client(4300);
        let target = mc.osds[0].public_addrs.clone();
        let mut c = Connection::client(
            1,
            msgr2::Config::new(
                name,
                addr([10, 9, 0, 1], 4301, 1),
                PolicyTable::uniform(msgr2::Policy::lossy_client(0)),
            ),
            SessionTable::new(7),
            Box::new(AuthNoneClient { name, global_id: 0 }),
            EntityName::OSD,
            target.clone(),
            target.0[0],
        );
        while let Some(e) = c.poll_event() {
            assert!(matches!(e, msgr2::Event::Dial { .. }), "{e:?}");
        }
        c.on_connected(t);
        let b = c.poll_output();
        assert!(!b.is_empty(), "the client sends its banner");
        b
    };
    let o = &mut mc.osds[0];
    let first = o.on_accept(Listener::Public, crate::osd::sock4([10, 9, 0, 1], 7001), t);
    o.on_bytes(first, &banner, t);
    let held = o.links[&first].conn.preauth_bytes() as u64;
    assert!(held > 0, "the handshake bytes are buffered");
    assert_eq!(
        o.cl.preauth_used[MsgrId::Public as usize],
        held,
        "the buffered transcript is charged"
    );
    // room for exactly one transcript: the next public handshake crosses the budget and is closed
    o.cl.preauth_limit = held;
    let second = o.on_accept(Listener::Public, crate::osd::sock4([10, 9, 0, 1], 7002), t);
    o.on_bytes(second, &banner, t);
    assert!(
        !o.links.contains_key(&second),
        "the transcript over the budget closes its link"
    );
    assert_eq!(
        o.cl.preauth_used[MsgrId::Public as usize],
        held,
        "the closed link's share is released"
    );
    assert!(
        o.links.contains_key(&first),
        "the link inside the budget stays"
    );
    // the cluster listener has its own budget: the same bytes are charged there and never refused by the public use
    let cluster = o.on_accept(Listener::Cluster, crate::osd::sock4([10, 1, 0, 1], 7003), t);
    o.on_bytes(cluster, &banner, t);
    assert!(o.links.contains_key(&cluster));
    assert!(o.cl.preauth_used[MsgrId::Cluster as usize] > 0);
    assert_eq!(o.cl.preauth_used[MsgrId::Public as usize], held);
    // authentication frees the public share
    let name = EntityName::client(4301);
    o.links.get_mut(&first).unwrap().auth.borrow_mut().caps = Some("allow *".into());
    o.on_link_event(
        first,
        msgr2::Event::Connected(msgr2::PeerInfo {
            name,
            addrs: addr([10, 9, 0, 1], 7001, 1),
            features: u64::MAX,
            lossy: true,
            resumed: false,
            global_id: 1,
            auth_name: None,
        }),
    );
    assert_eq!(
        o.cl.preauth_used[MsgrId::Public as usize],
        0,
        "authentication releases the charge"
    );
}

/// Dial-failure warnings are per peer and family (the old key held only the purpose: after the first failed dial every
/// other peer of that purpose stayed silent), and a peer that answers re-arms its warnings.
#[test]
fn dial_warnings_dedupe_per_peer_and_rearm() {
    use crate::osd::{MsgrId, Purpose};
    let mut mc = Mc::new(1);
    mc.up();
    let t = mc.t;
    let o = &mut mc.osds[0];
    let dial = |o: &mut Osd<B>, peer: i32, port: u16| {
        o.dial(
            MsgrId::Cluster,
            Purpose::Peer(peer),
            EntityName::OSD,
            &addr([10, 2, 0, 1], port, peer as u32),
        )
        .expect("a target of our family")
    };
    let failed = |o: &Osd<B>| {
        o.logs
            .iter()
            .filter(|l| l.contains("dial ") && l.contains("failed"))
            .count()
    };
    let a = dial(o, 1, 6801);
    let b = dial(o, 2, 6802);
    o.on_dial_failed(a, true, t);
    o.on_dial_failed(b, true, t);
    assert_eq!(failed(o), 2, "{:?}", o.logs);
    // once per peer: a repeated failure is silent, the second peer was never hidden behind the first
    let again = dial(o, 1, 6801);
    o.on_dial_failed(again, true, t);
    assert_eq!(failed(o), 2, "{:?}", o.logs);
    // the peer answers: its entry leaves, the other peer keeps its warning
    let ok = dial(o, 1, 6801);
    o.on_link_event(
        ok,
        msgr2::Event::Connected(msgr2::PeerInfo {
            name: EntityName::osd(1),
            addrs: addr([10, 2, 0, 1], 6801, 1),
            features: u64::MAX,
            lossy: false,
            resumed: false,
            global_id: 1,
            auth_name: None,
        }),
    );
    assert!(
        !o.dial_warned
            .iter()
            .any(|w| matches!(w, crate::osd::DialWarn::Failed(Purpose::Peer(1), _, _))),
        "{:?}",
        o.dial_warned
    );
    let later = dial(o, 1, 6801);
    o.on_dial_failed(later, true, t);
    assert_eq!(failed(o), 3, "the re-armed peer logs again: {:?}", o.logs);
}

/// `osd_client_message_size_cap` is enforced (spec msgr2.md 8.2): a `config set` reaches the public links at once and
/// the public messenger for new links; the cluster/heartbeat messengers keep their own bound.
#[test]
fn client_message_size_cap_reaches_public_links_and_new_connections() {
    let mut mc = Mc::new(1);
    mc.up();
    let cl = mc.osds[0].on_accept(
        Listener::Public,
        crate::osd::sock4([10, 9, 0, 1], 49000),
        mc.t,
    );
    let o = &mut mc.osds[0];
    assert_eq!(
        o.links.get(&cl).unwrap().conn.frame_cap(),
        524_288_000,
        "the classic default (500 MiB) is applied at start"
    );
    o.conf
        .set(
            crate::config::Level::Override,
            "osd_client_message_size_cap",
            "1048576",
        )
        .unwrap();
    o.refresh_obs_conf();
    assert_eq!(o.links.get(&cl).unwrap().conn.frame_cap(), 1 << 20);
    assert_eq!(
        o.msgr[crate::osd::MsgrId::Public as usize].cfg.max_message,
        1 << 20,
        "new public connections follow"
    );
    assert_eq!(
        o.msgr[crate::osd::MsgrId::Cluster as usize].cfg.max_message,
        u64::MAX,
        "the peer messenger is not a client"
    );
}

/// `config_bl` of MMgrReport (spec ops-observability 6.3): the full non-default snapshot travels once after a config
/// change (and in MMgrOpen), an unchanged config sends the empty blob, and ignored mon values go with it.
#[test]
fn mgr_report_carries_config_bl_only_after_a_change() {
    use crate::config::Level;
    use messages::{ConfigBl, MMgrOpen, MMgrReport, Message};

    let mut mc = Mc::new(1);
    mc.up();
    let mgr = mc.client(0);
    mc.osds[0]
        .conf
        .set(Level::Override, "osd_max_backfills", "2")
        .unwrap();
    mc.osds[0].mgr.link = Some(mgr);
    mc.osds[0].t.out.clear();
    mc.osds[0].mgr_ready(mgr);
    let frame = mc.osds[0]
        .t
        .out
        .iter()
        .find(|f| f.0 == mgr && f.2.0 == 0x700)
        .expect("MMgrOpen");
    let segs = &frame.3;
    let open = MMgrOpen::decode(frame.2.1, &segs.front, &segs.middle, &segs.data).unwrap();
    let bl = ConfigBl::decode(&open.config_bl).unwrap();
    assert!(bl.options.iter().any(|(k, _)| k == "osd_max_backfills"));
    assert!(bl.options.iter().all(|(k, _)| k != "fsid" && k != "host"));

    let report = |mc: &mut Mc| -> Vec<u8> {
        mc.osds[0].t.out.clear();
        mc.osds[0].send_mgr_report(mgr);
        let frame = mc.osds[0]
            .t
            .out
            .iter()
            .find(|f| f.0 == mgr && f.2.0 == 0x702)
            .expect("MMgrReport");
        let segs = &frame.3;
        MMgrReport::decode(frame.2.1, &segs.front, &segs.middle, &segs.data)
            .unwrap()
            .config_bl
    };
    assert!(report(&mut mc).is_empty(), "open sent the snapshot");
    mc.osds[0]
        .conf
        .set(Level::Override, "osd_max_backfills", "4")
        .unwrap();
    let bl = ConfigBl::decode(&report(&mut mc)).expect("snapshot after the change");
    let (_, levels) = bl
        .options
        .iter()
        .find(|(k, _)| k == "osd_max_backfills")
        .expect("changed option");
    assert_eq!(levels.last().unwrap(), &(5, "4".to_owned()));
    assert!(
        report(&mut mc).is_empty(),
        "unchanged config sends the empty blob"
    );
    // a mon value a local source overrides is reported as ignored
    let mut mon = std::collections::BTreeMap::new();
    mon.insert("osd_max_backfills".to_owned(), "9".to_owned());
    mc.osds[0].conf.apply_mon(&mon);
    let bl = ConfigBl::decode(&report(&mut mc)).unwrap();
    assert_eq!(
        bl.ignored_mon_values.get("osd_max_backfills"),
        Some(&"9".to_owned())
    );
    assert_eq!(
        bl.options
            .iter()
            .find(|(k, _)| k == "osd_max_backfills")
            .unwrap()
            .1
            .last()
            .unwrap()
            .1,
        "4"
    );
}

/// Heartbeat RTT statistics (spec ops-observability 6.4/6.5): completed rounds fill `osd_stat.hb_pingtime` per peer
/// and direction (osd_mon_heartbeat_stat_stale prunes), and `dump_osd_network` filters by its threshold, sorts by
/// pingtime desc (ties: higher peer id first, back before front) and prints the classic µs/1000 numbers.
#[test]
fn heartbeat_rtt_feeds_osd_stat_and_dump_osd_network() {
    use crate::hb::{HbPeer, PingStats};

    let mut mc = Mc::new(1);
    mc.up();
    let t0 = mc.osds[0].wall().sec;
    let mut st = PingStats::default();
    // first closed window at t0-70: mean 200 us (100..300)
    st.add(t0 - 130, 100, 60);
    st.add(t0 - 120, 200, 60);
    st.add(t0 - 70, 300, 60);
    // second closed window at t0-10: mean 300 us (300, 400), then an open window with 800
    st.add(t0 - 10, 400, 60);
    st.add(t0, 800, 60);
    let peer = HbPeer {
        front: Some(1),
        rtt: [st.clone(), st],
        ..Default::default()
    };
    mc.osds[0].hb.peers.insert(7, peer);

    let stat = mc.osds[0].osd_stat();
    assert_eq!(stat.hb_pingtime.len(), 1);
    let e = &stat.hb_pingtime[0];
    assert_eq!(e.osd, 7);
    assert_eq!(e.last_update, t0 - 10);
    assert_eq!(e.back_pingtime, [300, 180, 160]);
    assert_eq!(e.back_min, [300, 100, 100]);
    assert_eq!(e.back_max, [300, 300, 300]);
    assert_eq!(e.back_last, 800);
    assert_eq!(e.front_pingtime, e.back_pingtime);
    assert_eq!(e.front_last, 800);
    // the stat entry is dropped past osd_mon_heartbeat_stat_stale
    assert!(mc.osds[0].hb_pingtime(t0 + 200, 100).is_empty());

    // run a JSON command on core 0 like an admin socket request (obs module helper)
    fn ask(mc: &mut Mc, cmd: &str) -> (i32, serde_json::Value) {
        let (tx, rx) = std::sync::mpsc::channel();
        mc.osds[0].cmds.seq += 1;
        let tok = mc.osds[0].cmds.seq;
        mc.osds[0].cmds.pending.insert(tok, tx);
        let t = mc.t;
        mc.osds[0].set_now(t);
        mc.osds[0].exec_command(cmd, crate::tell::ReplyTo::Asok(tok));
        mc.settle();
        let (r, rs, out) = rx.try_recv().expect("command answered");
        (
            r,
            serde_json::from_slice(&out.into_bytes()).unwrap_or(serde_json::Value::String(rs)),
        )
    }
    let dump = |mc: &mut Mc, cmd: serde_json::Value| {
        let (r, d) = ask(mc, &cmd.to_string());
        assert_eq!(r, 0, "{d}");
        d
    };
    let d = dump(
        &mut mc,
        serde_json::json!({"prefix": "dump_osd_network", "value": 0}),
    );
    assert_eq!(d["threshold"], 0);
    let es = d["entries"].as_array().unwrap();
    assert_eq!(es.len(), 2, "{d}");
    assert_eq!(es[0]["interface"], "back", "back before front: {d}");
    assert_eq!(es[1]["interface"], "front");
    assert_eq!(es[0]["to osd"], 7);
    assert_eq!(es[0]["from osd"], 0);
    assert_eq!(
        es[0]["average"],
        serde_json::json!({"1min": 0.3, "5min": 0.18, "15min": 0.16})
    );
    assert_eq!(es[0]["min"]["1min"], 0.3);
    assert_eq!(es[0]["max"]["1min"], 0.3);
    assert_eq!(es[0]["last"], 0.8);
    assert_eq!(es[0]["stale"], false);
    // 0.1 ms threshold still lists the peer (0.3 ms >= it); 1 ms filters it out
    let d = dump(
        &mut mc,
        serde_json::json!({"prefix": "dump_osd_network", "value": 1}),
    );
    assert_eq!(d["threshold"], 1, "threshold prints us/1000");
    assert_eq!(d["entries"].as_array().unwrap().len(), 0, "{d}");
    // no value: osd_heartbeat_grace (20 s) x mon_warn_on_slow_ping_ratio (0.05) = 1 s
    let d = dump(&mut mc, serde_json::json!({"prefix": "dump_osd_network"}));
    assert_eq!(d["threshold"], 1000);
    assert_eq!(d["entries"].as_array().unwrap().len(), 0, "{d}");
}

/// Scattered commands answer complete or not at all (spec ops-observability 6.7): while a missing core is alive the
/// reply waits (no deadline answer, loud TIMEOUT line only), and a core that stops making progress past
/// osd_op_thread_timeout turns the answer into an error instead of a well-formed subset.
#[test]
fn scattered_commands_wait_for_every_core_and_error_when_one_is_gone() {
    use crate::liveness::Liveness;
    use crate::tell::ReplyTo;

    let mut mc = Mc::new(2);
    mc.up();
    let start = |mc: &mut Mc, cmd: &str| {
        let (tx, rx) = std::sync::mpsc::channel();
        mc.osds[0].cmds.seq += 1;
        let tok = mc.osds[0].cmds.seq;
        mc.osds[0].cmds.pending.insert(tok, tx);
        let t = mc.t;
        mc.osds[0].set_now(t);
        mc.osds[0].exec_command(cmd, ReplyTo::Asok(tok));
        rx
    };
    let xfer = |mc: &mut Mc| loop {
        let mut moved = false;
        for i in 0..mc.n {
            while let Some((dst, m)) = mc.osds[i].poll_xmsg() {
                moved = true;
                let t = mc.t;
                mc.osds[dst].on_xmsg(i, m, t);
            }
        }
        if !moved {
            return;
        }
    };
    let tick = |mc: &mut Mc| {
        mc.t += Duration::from_secs(1);
        let t = mc.t;
        mc.osds[0].set_now(t);
        mc.osds[0].scatter_expire();
    };
    // an unsupervised core is waited for: no answer, no partial document
    let rx = start(&mut mc, r#"{"prefix":"dump_ops_in_flight"}"#);
    assert_eq!(mc.osds[0].cmds.scatter.len(), 1, "core 1 was asked");
    for _ in 0..60 {
        tick(&mut mc);
    }
    assert!(
        rx.try_recv().is_err(),
        "no partial answer while the core is alive"
    );
    xfer(&mut mc); // core 1 answers: the merged, complete document arrives
    let (r, _rs, out) = rx.try_recv().expect("complete answer");
    assert_eq!(r, 0);
    assert!(out.into_bytes().starts_with(b"{"));
    // supervised: core 1 stops beating -> the answer becomes an error after osd_op_thread_timeout
    let live: &'static Liveness = Box::leak(Box::new(Liveness::new()));
    for o in &mut mc.osds {
        o.set_liveness(live);
    }
    let rx = start(&mut mc, r#"{"prefix":"dump_ops_in_flight"}"#);
    for _ in 0..20 {
        tick(&mut mc);
    }
    let (r, rs, _) = rx.try_recv().expect("error answer");
    assert_eq!(r, -110, "{rs}");
    assert!(rs.contains("did not answer"), "{rs}");
    assert!(mc.osds[0].cmds.scatter.is_empty());
}

/// Boot metadata carries the device and NUMA identity keys (spec osd-lifecycle.md 3.3.1, J-12): the facts this daemon
/// owns are present, and keys whose fact does not exist (BlueFS/BlueStore internals, kernel device geometry) stay absent.
#[test]
fn boot_metadata_carries_device_and_numa_identity() {
    let mut mc = Mc::new(1);
    mc.up();
    mc.osds[0].cfg.sys_metadata.insert(
        "flashstore_placement".into(),
        "cpus=[0, 1] l3 placement".into(),
    );
    mc.osds[0]
        .cfg
        .sys_metadata
        .insert("front_iface".into(), "croit-flashstore-test0".into());
    mc.osds[0]
        .cfg
        .sys_metadata
        .insert("back_iface".into(), "croit-flashstore-test0".into());
    let m = mc.osds[0].boot_metadata();
    assert!(
        !m.contains_key("bluefs"),
        "croit-flashstore-osd has no BlueFS"
    );
    assert!(!m.contains_key("bluestore_allocator"));
    assert!(!m.contains_key("bluestore_min_alloc_size"));
    // an interface without NUMA info is named, the unknown keys stay absent (not invented)
    assert_eq!(m["network_numa_unknown_ifaces"], "{back_iface,front_iface}");
    assert!(!m.contains_key("network_numa_nodes"));
    // numa_node is the host's node of the pinned CPUs 0 and 1 (absent without NUMA sysfs, e.g. macOS)
    if let Some(n) = m.get("numa_node") {
        assert!(n.parse::<i32>().is_ok_and(|n| n >= 0), "{n}");
        assert!(m.contains_key("numa_node_cpus"));
    }
    assert!(
        !m.contains_key("bluestore_bdev_dev"),
        "no kernel device here"
    );
}

/// `pg_run` runs on every client op of a PG: with its engine present it must not copy the OSD's class lists
/// (`osd_class_load_list` / `osd_class_default_list`, ~40 strings each) nor allocate anything else on that path.
#[test]
fn pg_run_with_a_live_engine_does_not_allocate() {
    let mut mc = Mc::new(1);
    mc.up();
    let spg = mc.osds[0]
        .pg
        .set
        .pgs()
        .map(|(s, _)| *s)
        .next()
        .expect("a PG on core 0");
    // the first call builds the engine (that one copies the class lists)
    mc.osds[0].pg_run(spg, |_, _| {});
    assert!(mc.osds[0].pg.eng.contains_key(&spg), "engine built");
    let _ = wprof::take();
    {
        let _s = wprof::span(wprof::S::Gate);
        mc.osds[0].pg_run(spg, |_, _| {});
    }
    let allocs: u64 = wprof::take().iter().map(|s| s.2).sum();
    assert_eq!(allocs, 0, "pg_run allocated with the engine already there");
}

/// Tracker 74943 alert: the text the operator reads (local log, cluster log, `tell status`) is single-spaced.
#[test]
fn isa_decode_cache_alert_text_has_no_runs_of_spaces() {
    let mut mc = Mc::new(1);
    mc.up();
    let mut m = mc.map(11, 10);
    // two ISA pools of different (k, m): the gate of the tracker 74943 check
    let ec = |m: &mut OsdMap, id: i64, prof: &str, k: u32, mm: u32| {
        let p = m.pools.get_mut(&id).unwrap();
        p.ptype = osdmap::pool::TYPE_ERASURE;
        p.size = (k + mm) as u8;
        p.min_size = (k + 1) as u8;
        p.stripe_width = k * 4096;
        p.erasure_code_profile = prof.into();
        p.flags &= !osdmap::pool::flags::OMAP;
        p.flags |= osdmap::pool::flags::EC_OVERWRITES;
        m.erasure_code_profiles.insert(
            prof.into(),
            [
                ("plugin", "isa".to_string()),
                ("technique", "reed_sol_van".into()),
                ("k", k.to_string()),
                ("m", mm.to_string()),
            ]
            .into_iter()
            .map(|(a, b)| (a.to_string(), b))
            .collect(),
        );
    };
    ec(&mut m, 1, "p32", 3, 2);
    ec(&mut m, 4, "p21", 2, 1);
    // osd.1 shares the acting sets and runs a classic release before the tracker 74943 fix
    m.osd_state[1] = osd_state::EXISTS | osd_state::UP;
    m.osd_weight[1] = 0x10000;
    mc.osds[0].pg.peer_ceph_ver.insert(1, "20.2.4".into());
    mc.osds[0].logs.clear();
    mc.deliver(m);
    let line = mc.osds[0]
        .logs
        .iter()
        .find(|l| l.contains("Ceph tracker 74943"))
        .unwrap_or_else(|| panic!("no alert in {:?}", mc.osds[0].logs));
    assert!(!line.contains("  "), "double spaces in the alert: {line:?}");
    assert!(line.contains("older than ceph 21.1.2"), "{line}");
}

/// The dedup settings are store-wide (`flashstore_dedup_digest` / `flashstore_dedup_zero_objects`), not pool options:
/// every map applies them once, a map without any pool too.
#[test]
fn dedup_digest_is_applied_by_a_map_without_pools() {
    let mut mc = Mc::new(1);
    mc.up();
    mc.osds[0]
        .conf
        .set(
            crate::config::Level::Override,
            "flashstore_dedup_digest",
            "crc32",
        )
        .unwrap();
    mc.osds[0].logs.clear();
    let mut m = mc.map(11, 10);
    m.pools.clear();
    m.pool_name.clear();
    mc.deliver(m);
    let line = mc.osds[0]
        .logs
        .iter()
        .find(|l| l.contains("flashstore_dedup_digest 'crc32' unknown"))
        .unwrap_or_else(|| panic!("no digest complaint in {:?}", mc.osds[0].logs));
    assert!(line.text.contains("kept the previous one"), "{line:?}");
}

/// Excluding an unserved EC pool from this OSD clears its alert immediately, even inside the log suppression window.
#[test]
fn nt_health_unmapped_ec_pool_clears_not_served_alert() {
    let mut mc = Mc::new(1);
    mc.ec4 = true;
    mc.osds[0]
        .conf
        .set(crate::config::Level::Override, "ec_enable_pools", "off")
        .unwrap();
    mc.osds[0].refresh_obs_conf();
    mc.osds[0].pg_apply_ec_cfg();
    mc.up();
    let alert = "FLASHSTORE_EC_POOL_NOT_SERVED";
    assert!(mc.osds[0].pg_passive_pools().contains(&4));
    assert!(mc.osds[0].os_alerts().contains_key(alert));

    // An unchanged map is still unhealthy while the warning itself is rate limited.
    let mapped = mc.map(11, 10);
    mc.deliver(mapped);
    assert!(mc.osds[0].os_alerts().contains_key(alert));

    let mut excluded = mc.map(12, 10);
    excluded.osd_weight = vec![0, 0x10000, 0x10000];
    excluded.osd_state[1] = osd_state::EXISTS | osd_state::UP;
    excluded.osd_state[2] = osd_state::EXISTS | osd_state::UP;
    excluded.pg_temp.clear();
    for seed in 0..excluded.pools[&4].pg_num {
        let placement = excluded.pg_to_up_acting(PgT::new(4, seed));
        assert!(!placement.up.contains(&0));
        assert!(!placement.acting.contains(&0));
    }
    mc.deliver(excluded);
    assert!(!mc.osds[0].pg_passive_pools().contains(&4));
    assert!(!mc.osds[0].os_alerts().contains_key(alert));

    // Reintroduction is visible again even though the original log entry is less than an hour old.
    let mapped = mc.map(13, 10);
    mc.deliver(mapped);
    assert!(mc.osds[0].os_alerts().contains_key(alert));
}

/// Local client demand must bound listing work just like forwarded demand, even
/// when this one-core OSD never drains a cross-core inbox. Charge a deterministic
/// continuation quantum rather than relying on the simulator's wall-clock speed.
#[test]
fn local_reads_bound_listing_work_without_an_inbox() {
    let mut p = Pair::new(1, 1);
    p.up();
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let obj = (0..)
        .map(|i| format!("local-fairness-{i}"))
        .find(|n| {
            let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
            let pg = PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32));
            map.pg_to_up_acting(pg).acting_primary == 0
        })
        .unwrap();
    let cl = p.a.client(0);
    // An absent-object read still performs legitimate point work and replies.
    let op = p.a.op(1, &obj, vec![OsdOp::read(0, 4096)]);
    let (ty, ver, _, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
    let now = p.a.t;
    p.a.osds[0].set_now(now);
    p.a.osds[0].on_unknown_message(cl, 9001, ty, ver, &segs);
    assert_eq!(p.a.replies(0, cl).len(), 1, "local read completed");
    // A driver may report an empty inbox after handling its own links. It must
    // preserve that local demand until the common iteration boundary.
    p.a.osds[0].slice_add(0);
    p.a.osds[0].poll_store(now);
    let share = &mut p.a.osds[0].pg.share;
    assert!(share.turn(false), "one listing continuation gets a turn");
    share.ran();
    share.exhaust_slice();
    let admitted = (0..64).filter(|_| share.turn(false)).count();
    assert_eq!(
        admitted, 0,
        "local reads must stop the other PGs' listing passes once the core quantum is spent"
    );
    share.next_iteration();
    share.exhaust_slice();
    assert!(
        share.turn(false),
        "without new point demand listings remain work-conserving"
    );
    share.ran();
}
