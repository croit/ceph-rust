// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Counter documents off the cores (ctrsnap.rs, adr 0035 am. 3): the control core answers a counter command with a
//! snapshot of the samples the cores published (no per-request work that grows with PGs or counters); the documents
//! keep the classic names, types and JSON form. Child of `xcore_tests` (multi-core harness on a simulated device).
use super::*;
use crate::ctrsnap::{CounterReq, CounterSnap, Doc, Sorted};
use crate::tell::{Out, ReplyTo};
use serde_json::{Value, json};

/// Run `cmd` on core 0 like an admin socket request: the unserialized result the socket thread renders.
fn asok_cmd(mc: &mut Mc, cmd: &str) -> crate::asok::CmdResult {
    let (tx, rx) = std::sync::mpsc::channel();
    let o = &mut mc.osds[0];
    o.cmds.seq += 1;
    let tok = o.cmds.seq;
    o.cmds.pending.insert(tok, tx);
    o.exec_command(cmd, ReplyTo::Asok(tok));
    rx.try_recv().expect("command answered")
}

fn counters_of(res: crate::asok::CmdResult) -> CounterReq {
    match res {
        (0, _, Out::Counters(req)) => *req,
        other => panic!("not a counter document: {other:?}"),
    }
}

/// A 3-core OSD with data, every core has published a sample.
fn published() -> Mc {
    let mut mc = Mc::new(3);
    mc.up();
    write_read_all(&mut mc, 4, "cs", 16, 1);
    mc.run_for(Duration::from_secs(2));
    mc
}

/// The samples core 0 holds now: its own and the last one of every worker.
fn stored(o: &Osd<B>) -> Vec<Arc<crate::ctrsnap::CoreCounters>> {
    (0..o.cores())
        .map(|c| match c {
            0 => o.perf.own.clone(),
            c => o.cl.stats[c]
                .as_ref()
                .expect("worker sample")
                .counters
                .clone(),
        })
        .collect()
}

/// The core's share of every counter command is a snapshot: one `Arc` of each core's published sample and of the
/// control aggregates. Nothing is sampled, named or serialized per request, so its cost does not grow with PGs,
/// counters or loggers; requests between two ticks share the same samples.
#[test]
fn counter_commands_snapshot_the_published_samples() {
    let mut mc = published();
    let cmds = [
        r#"{"prefix":"perf dump"}"#,
        r#"{"prefix":"perf dump","logger":"osd","counter":"op_r","format":"json"}"#,
        r#"{"prefix":"counter dump","format":"json"}"#,
        r#"{"prefix":"perf schema"}"#,
        r#"{"prefix":"counter schema"}"#,
        r#"{"prefix":"perf histogram dump"}"#,
        r#"{"prefix":"perf histogram schema"}"#,
    ];
    let want = stored(&mc.osds[0]);
    let ctl = mc.osds[0].perf.ctl.clone();
    for cmd in cmds {
        let req = counters_of(asok_cmd(&mut mc, cmd));
        assert_eq!(req.snap.cores.len(), want.len(), "{cmd}");
        for (c, w) in want.iter().enumerate() {
            let got = req.snap.cores[c].as_ref().expect("sample");
            assert!(
                Arc::ptr_eq(got, w),
                "{cmd}: core {c} sample is the published one"
            );
        }
        assert!(
            Arc::ptr_eq(&req.snap.ctl, &ctl),
            "{cmd}: control aggregates"
        );
        assert!(req.snap.reset.is_none());
    }
    // the next tick publishes new samples; the requests after it see them
    mc.run_for(Duration::from_secs(1));
    let req = counters_of(asok_cmd(&mut mc, r#"{"prefix":"perf dump"}"#));
    for (c, old) in want.iter().enumerate() {
        let got = req.snap.cores[c].as_ref().unwrap();
        assert!(!Arc::ptr_eq(got, old), "core {c} resampled at its tick");
        assert!(Arc::ptr_eq(got, &stored(&mc.osds[0])[c]));
    }
}

/// `perf reset` resamples core 0 and keeps the samples as the baseline: counters restart at 0, gauges stay, and the
/// later requests are snapshots again.
#[test]
fn perf_reset_keeps_the_samples_as_baseline() {
    let mut mc = published();
    let before = counters_of(asok_cmd(&mut mc, r#"{"prefix":"perf dump"}"#));
    let before: Value = serde_json::from_slice(&before.render(true)).unwrap();
    assert!(before["osd"]["op_w"].as_u64().unwrap() > 0);
    let (r, _, _) = asok_cmd(&mut mc, r#"{"prefix":"perf reset","var":"all"}"#);
    assert_eq!(r, 0);
    let req = counters_of(asok_cmd(&mut mc, r#"{"prefix":"perf dump"}"#));
    let base = req.snap.reset.clone().expect("reset baseline");
    for (c, s) in req.snap.cores.iter().enumerate() {
        let b = base.for_logger("osd").unwrap();
        assert!(Arc::ptr_eq(s.as_ref().unwrap(), b[c].as_ref().unwrap()));
    }
    let after: Value = serde_json::from_slice(&req.render(true)).unwrap();
    assert_eq!(after["osd"]["op_w"], 0);
    assert_eq!(after["osd"]["op_r"], 0);
    assert_eq!(after["flashstore_core_1"]["ops"], 0);
    assert_eq!(
        after["osd"]["numpg"], before["osd"]["numpg"],
        "gauges are not reset"
    );
}

/// The classic document of a sorted catalogue built as a `serde_json::Value` (the form a classic OSD prints).
fn classic(sorted: &Sorted, doc: Doc) -> Value {
    let secs = |ns: u64| ns as f64 / 1e9;
    let mut d = serde_json::Map::new();
    for (lg, cs) in sorted {
        let mut m = serde_json::Map::new();
        for c in cs {
            let (avg, time) = (
                c.ty & messages::pct::LONGRUNAVG != 0,
                c.ty & messages::pct::TIME != 0,
            );
            let v = match doc {
                Doc::PerfSchema | Doc::CounterSchema => json!({
                    "description": c.desc,
                    "metric_type": if c.ty & messages::pct::COUNTER != 0 { "counter" } else { "gauge" },
                    "nick": c.nick,
                    "priority": c.prio,
                    "type": c.ty,
                    "units": if c.unit == messages::pct::UNIT_BYTES { "bytes" } else { "none" },
                    "value_type": match (avg, time) {
                        (true, true) => "real-integer-pair",
                        (true, false) => "integer-integer-pair",
                        (false, true) => "real",
                        (false, false) => "integer",
                    },
                }),
                _ if avg => json!({
                    "avgcount": c.v.avgcount,
                    "sum": secs(c.v.value),
                    "avgtime": secs(c.v.value.checked_div(c.v.avgcount).unwrap_or(0)),
                }),
                _ if time => json!(secs(c.v.value)),
                _ => json!(c.v.value),
            };
            m.insert(c.name.to_string(), v);
        }
        let m = Value::Object(m);
        let v = match doc {
            Doc::CounterDump | Doc::CounterSchema => json!([{"counters": m, "labels": {}}]),
            _ => m,
        };
        d.insert(lg.to_string(), v);
    }
    Value::Object(d)
}

/// The documents written straight from the snapshot are byte for byte the classic JSON (compact and pretty), with
/// and without filters.
#[test]
fn counter_documents_are_the_classic_json() {
    let mut mc = published();
    let snap: CounterSnap = mc.osds[0].counter_snap();
    let filters = [
        (None, None),
        (Some("osd"), None),
        (Some("osd"), Some("op_r_latency")),
        (Some(""), Some("ops")),
        (Some("nope"), None),
    ];
    for doc in [
        Doc::PerfDump,
        Doc::CounterDump,
        Doc::PerfSchema,
        Doc::CounterSchema,
    ] {
        for (lg, ctr) in filters {
            let req = CounterReq {
                snap: snap.clone(),
                doc,
                logger: lg.map(str::to_owned),
                counter: ctr.map(str::to_owned),
            };
            let want = classic(&snap.catalogue().sorted(lg, ctr), doc);
            assert_eq!(
                req.render(true),
                want.to_string().into_bytes(),
                "{doc:?} {lg:?} {ctr:?} compact"
            );
            assert_eq!(
                req.render(false),
                crate::asok::pretty(&want),
                "{doc:?} {lg:?} {ctr:?} pretty"
            );
        }
    }
    // the admin socket body of a request is the document for its format
    for (cmd, compact) in [
        (r#"{"prefix":"perf dump"}"#, false),
        (r#"{"prefix":"counter dump","format":"json"}"#, true),
    ] {
        let res = asok_cmd(&mut mc, cmd);
        let (_, _, Out::Counters(req)) = &res else {
            panic!("{cmd}")
        };
        let doc = req.doc;
        let want = classic(&snap.catalogue().sorted(None, None), doc);
        let want = if compact {
            want.to_string().into_bytes()
        } else {
            crate::asok::pretty(&want)
        };
        assert_eq!(crate::asok::render(cmd, res), want, "{cmd}");
    }
}

/// The counter names, types and units are pinned in `tests/perf-schema.txt` (`logger counter type metric_type
/// value_type priority units nick`, sorted): operator dashboards and ceph-exporter read them. Per-PG loggers and the
/// elastic-pool store counters (`lend_*`, `reclaim_*`, feature `elastic`) are left out. Splinter's feature-only
/// additions are pinned separately, not excluded from the assertion. `UPDATE_PERF_NAMES=1` rewrites the common
/// file only in a build without Splinter; feature additions must be reviewed separately.
#[test]
fn perf_schema_is_stable() {
    let mut mc = Mc::new(2);
    mc.up();
    mc.run_for(Duration::from_secs(1));
    let cmd = r#"{"prefix":"perf schema","format":"json"}"#;
    let schema: Value =
        serde_json::from_slice(&crate::asok::render(cmd, asok_cmd(&mut mc, cmd))).unwrap();
    let mut got = Vec::new();
    for (lg, cs) in schema.as_object().unwrap() {
        if lg.starts_with("flashstore_pg_") {
            continue;
        }
        for (name, s) in cs.as_object().unwrap() {
            if lg.starts_with("flashstore_store_")
                && (name.starts_with("lend_") || name.starts_with("reclaim_"))
            {
                continue;
            }
            let nick = s["nick"].as_str().unwrap();
            got.push(format!(
                "{lg} {name} {} {} {} {} {} {}",
                s["type"],
                s["metric_type"].as_str().unwrap(),
                s["value_type"].as_str().unwrap(),
                s["priority"],
                s["units"].as_str().unwrap(),
                if nick.is_empty() { "-" } else { nick }
            ));
        }
    }
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/perf-schema.txt");
    if std::env::var_os("UPDATE_PERF_NAMES").is_some() {
        if cfg!(feature = "splinterdb") {
            panic!(
                "update the common schema without splinterdb; review perf-schema-splinterdb.txt separately"
            );
        }
        std::fs::write(path, got.join("\n") + "\n").unwrap();
        return;
    }
    let want = std::fs::read_to_string(path).unwrap();
    let mut want: Vec<String> = want.lines().map(str::to_owned).collect();
    #[cfg(feature = "splinterdb")]
    for logger in ["flashstore_store_0", "flashstore_store_1"] {
        want.extend(
            include_str!("../tests/perf-schema-splinterdb.txt")
                .lines()
                .map(|entry| format!("{logger} {entry}")),
        );
    }
    want.sort_unstable();
    assert_eq!(
        got, want,
        "perf schema changed (common schema: perf-schema.txt; feature additions: perf-schema-splinterdb.txt)"
    );
}

/// A `ceph tell` counter command with an admin socket running: the core hands the snapshot to the render thread and
/// sends the reply when the body is back (polled with the admin socket); an admin socket request is rendered by the
/// socket's worker. Both bodies are the document of the snapshot.
#[test]
fn counter_bodies_are_built_by_the_admin_socket_threads() {
    use messages::{MCommand, MCommandReply, Message};
    let mut mc = published();
    let p = std::env::temp_dir().join(format!("ctrsnap-{}.asok", std::process::id()));
    let (srv, link) = crate::asok::start(&p).unwrap();
    mc.osds[0].attach_asok(link);
    let cl = mc.client(0);
    mc.osds[0]
        .links
        .get_mut(&cl)
        .unwrap()
        .auth
        .borrow_mut()
        .caps = Some("allow *".into());
    let want = CounterReq {
        snap: mc.osds[0].counter_snap(),
        doc: Doc::CounterDump,
        logger: None,
        counter: None,
    }
    .render(true);
    let msg = MCommand {
        fsid: mc.fsid,
        cmd: vec![r#"{"prefix":"counter dump","format":"json"}"#.into()],
        data: vec![],
    }
    .into();
    let reply = |mc: &Mc| {
        mc.osds[0]
            .t
            .out
            .iter()
            .find(|f| f.0 == cl && f.1 == 7 && f.2.0 == 98)
            .map(|f| MCommandReply::decode(f.2.1, &f.3.front, &f.3.middle, &f.3.data).unwrap())
    };
    mc.osds[0].t.out.clear();
    mc.osds[0].on_link_message(cl, crate::osd::Purpose::Accepted, 7, msg);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while reply(&mc).is_none() {
        assert!(
            std::time::Instant::now() < deadline,
            "WARNING TIMEOUT render thread reply exceeded 10s (ceph tell counter dump)"
        );
        std::thread::sleep(Duration::from_millis(1));
        let t = mc.t;
        mc.osds[0].poll_asok(t);
    }
    let r = reply(&mc).unwrap();
    assert_eq!(r.r, 0);
    assert_eq!(r.data, want);
    // an admin socket client: its worker renders while the core only polls
    let path = p.clone();
    let client = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let mut c = std::os::unix::net::UnixStream::connect(&path).unwrap();
        c.write_all(br#"{"prefix":"counter dump","format":"json"}"#)
            .unwrap();
        c.write_all(b"\0").unwrap();
        let mut len = [0u8; 4];
        c.read_exact(&mut len).unwrap();
        let mut v = vec![0u8; u32::from_be_bytes(len) as usize];
        c.read_exact(&mut v).unwrap();
        v
    });
    while !client.is_finished() {
        assert!(
            std::time::Instant::now() < deadline,
            "WARNING TIMEOUT admin socket reply exceeded 10s (counter dump)"
        );
        std::thread::sleep(Duration::from_millis(1));
        let t = mc.t;
        mc.osds[0].poll_asok(t);
    }
    assert_eq!(client.join().unwrap(), want);
    drop(srv);
}

/// `perf reset <name>` (spec ops-observability 6.1): one logger restarts, the others keep their baselines; `all`
/// restarts every logger; an unknown name answers an error document and resets nothing; gauges keep their value.
#[test]
fn perf_reset_scopes_to_one_logger() {
    let mut mc = published();
    let get = |mc: &Mc, lg: &str, c: &str| -> u64 {
        mc.osds[0].perf_dump(Some(lg), Some(c))[lg][c]
            .as_u64()
            .unwrap()
    };
    let cmd = |mc: &mut Mc, var: &str| {
        let cmd = json!({"prefix": "perf reset", "var": var}).to_string();
        let (r, _rs, out) = asok_cmd(mc, &cmd);
        assert_eq!(r, 0);
        serde_json::from_slice::<Value>(&out.into_bytes()).unwrap()
    };
    let op_before = get(&mc, "osd", "op");
    let bs_before = get(&mc, "bluestore", "txc_count");
    let pgs = get(&mc, "osd", "numpg");
    assert!(op_before > 0 && bs_before > 0 && pgs > 0);
    // unknown name: rc 0, "Not find", nothing restarts
    assert_eq!(
        cmd(&mut mc, "no_such_logger"),
        json!({"error": "Not find: no_such_logger"})
    );
    assert_eq!(
        get(&mc, "osd", "op"),
        op_before,
        "unknown name resets nothing"
    );
    // one logger: osd restarts, bluestore keeps running
    assert_eq!(cmd(&mut mc, "osd"), json!({"success": "perf reset osd"}));
    write_read_all(&mut mc, 1, "pr", 4, 1);
    mc.run_for(Duration::from_secs(2)); // every core publishes its counters
    assert_eq!(get(&mc, "osd", "op"), 8, "osd counts the new ops only");
    assert!(
        get(&mc, "bluestore", "txc_count") >= bs_before,
        "bluestore keeps its baseline"
    );
    assert_eq!(get(&mc, "osd", "numpg"), pgs, "gauges keep their value");
    // the other direction: bluestore restarts, osd continues
    assert_eq!(
        cmd(&mut mc, "bluestore"),
        json!({"success": "perf reset bluestore"})
    );
    let bs_zero = get(&mc, "bluestore", "txc_count");
    write_read_all(&mut mc, 1, "pz", 1, 100);
    mc.run_for(Duration::from_secs(2));
    assert!(
        get(&mc, "osd", "op") > 8,
        "osd was not reset with bluestore"
    );
    assert!(
        get(&mc, "bluestore", "txc_count") > bs_zero,
        "bluestore counts since its own reset"
    );
    // all: every logger restarts (per-logger baselines are dropped)
    assert_eq!(cmd(&mut mc, "all"), json!({"success": "perf reset all"}));
    assert_eq!(get(&mc, "osd", "op"), 0);
    assert_eq!(get(&mc, "bluestore", "txc_count"), 0);
    assert_eq!(get(&mc, "osd", "numpg"), pgs, "still a gauge");
}

/// `perf reset <logger>` keeps a baseline only for a logger that still exists: the per-PG logger names change with every
/// interval, so their baselines would otherwise accumulate one full per-core snapshot each, forever.
#[test]
fn perf_reset_drops_the_baselines_of_loggers_that_are_gone() {
    let mut mc = published();
    let samples = mc.osds[0].fresh_counter_snap().cores;
    let mut b = crate::ctrsnap::ResetBaselines::default();
    b.insert_for_test("flashstore_pg_1_0_s0", samples);
    mc.osds[0].perf.reset = Some(b);
    let (r, _, _) = asok_cmd(&mut mc, r#"{"prefix":"perf reset","var":"osd"}"#);
    assert_eq!(r, 0);
    let b = mc.osds[0].perf.reset.as_ref().unwrap();
    assert_eq!(b.logger_count(), 1, "only the logger that exists remains");
    assert!(b.for_logger("flashstore_pg_1_0_s0").is_none());
    assert!(b.for_logger("osd").is_some());
}

#[test]
fn perf_reset_diagnostic_counters_preserves_gauges_and_raw_baselines() {
    let mut mc = published();
    let sample = |mc: &mut Mc, commits, dirty| {
        mc.osds[0].cl.stats[1].as_mut().unwrap().counters =
            Arc::new(crate::ctrsnap::CoreCounters {
                store: vec![("wal_batches", false, commits), ("dirty_hard", true, dirty)],
                ..Default::default()
            });
    };
    let get = |mc: &Mc, lg: &str, name: &str| {
        mc.osds[0].perf_dump(Some(lg), Some(name))[lg][name]
            .as_u64()
            .unwrap()
    };
    sample(&mut mc, 11, 19);
    mc.osds[0].cl.mig.deferrals = 23;
    let op_before = get(&mc, "osd", "op");
    assert!(mc.osds[0].perf_reset("flashstore_store_1"));
    assert_eq!(get(&mc, "flashstore_store_1", "wal_batches"), 0);
    assert_eq!(get(&mc, "flashstore_store_1", "dirty_hard"), 19);
    assert_eq!(get(&mc, "flashstore_mig", "moves_deferred"), 23);
    assert_eq!(get(&mc, "osd", "op"), op_before);

    sample(&mut mc, 16, 31);
    assert_eq!(get(&mc, "flashstore_store_1", "wal_batches"), 5);
    assert!(mc.osds[0].perf_reset("flashstore_store_1"));
    assert_eq!(get(&mc, "flashstore_store_1", "wal_batches"), 0);
    sample(&mut mc, 18, 37);
    assert_eq!(get(&mc, "flashstore_store_1", "wal_batches"), 2);
    assert_eq!(get(&mc, "flashstore_store_1", "dirty_hard"), 37);

    assert!(mc.osds[0].perf_reset("flashstore_mig"));
    assert_eq!(get(&mc, "flashstore_mig", "moves_deferred"), 0);
    mc.osds[0].cl.mig.deferrals += 3;
    assert_eq!(get(&mc, "flashstore_mig", "moves_deferred"), 3);
    assert_eq!(get(&mc, "flashstore_store_1", "wal_batches"), 2);

    assert!(mc.osds[0].perf_reset("all"));
    assert_eq!(get(&mc, "flashstore_mig", "moves_deferred"), 0);
    assert_eq!(get(&mc, "flashstore_store_1", "wal_batches"), 0);
    assert_eq!(get(&mc, "flashstore_store_1", "dirty_hard"), 37);
}

/// A snapshot renders only what it sampled: host load and the process-wide pool counters are read on the control core
/// at sample time, not by the thread that renders the reply (two renders of one snapshot are byte-identical).
#[test]
fn counter_snapshot_carries_host_load_and_pool_counters() {
    let mc = published();
    let mut snap: CounterSnap = mc.osds[0].counter_snap();
    let mut ctl = crate::ctrsnap::ControlCounters {
        loadavg_x100: 12_345,
        ..Default::default()
    };
    ctl.pools[0] = ("flashstore_payload_pool", vec![("allocs".to_owned(), 7)]);
    snap.ctl = Arc::new(ctl);
    let req = CounterReq {
        snap,
        doc: Doc::PerfDump,
        logger: None,
        counter: None,
    };
    let v: Value = serde_json::from_slice(&req.render(true)).unwrap();
    assert_eq!(v["osd"]["loadavg"], 12_345);
    assert_eq!(v["flashstore_payload_pool"]["allocs"], 7);
}
