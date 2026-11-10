// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! RDMA visibility (Ceph-compatible means only): perf counters with their types, `rdma status` in every format, and the
//! cluster-log / daemon-log lines with their rate limits. Child of `xcore_tests` (multi-core harness).
use super::tellx::ask;
use super::*;
use ::rdma::status::{Counters, DeviceStatus, Process, Setup, Unusable};
use messages::pct;
use serde_json::json;

fn dev(sessions: u32, c: Counters) -> DeviceStatus {
    DeviceStatus {
        addr: "172.28.0.11".into(),
        device: "mlx5_0".into(),
        sessions,
        capacity: 100,
        slots: 320,
        granted: 3 * sessions,
        session_credits: 3 * sessions,
        held: 1,
        counters: c,
    }
}

fn logged(mc: &Mc, what: &str) -> usize {
    mc.osds[0].logs.iter().filter(|l| l.contains(what)).count()
}

#[test]
fn counters_status_and_rate_limited_warnings() {
    let mut mc = Mc::new(2);
    mc.up();
    for o in &mut mc.osds {
        o.cfg.rdma = true;
    }
    mc.osds[0].note_rdma_setup(Setup {
        max_sessions: 4,
        unusable: vec![Unusable {
            addr: "172.28.0.12".into(),
            reason: "path MTU 1024 below 4096".into(),
        }],
        reads: false,
    });
    let two = Counters {
        upgraded: 2,
        tx_write_wrs: 3,
        tx_write_bytes: 1536,
        tx_write_doorbells: 3,
        tx_write_sq_stalls: 1,
        ..Default::default()
    };
    let process = Process {
        leaked_cores: 1,
        teardown_failures: 2,
        qp_drain_timeouts: 3,
        quarantined_windows: 4,
        quarantined_write_sources: 5,
    };
    mc.osds[0].note_rdma(vec![dev(2, two)], process);
    mc.osds[1].note_rdma(
        vec![dev(
            2,
            Counters {
                sessions_capped: 1,
                credit_stalls: 9,
                ..two
            },
        )],
        process,
    );
    mc.run_for(Duration::from_secs(3));
    assert!(
        mc.osds[0].logs.iter().any(|l| l.contains("rdma")),
        "{:?} {}",
        mc.osds[0].logs,
        mc.osds[0].rdma.setup.max_sessions
    );
    assert_eq!(
        logged(
            &mc,
            "rdma: device 172.28.0.12 unusable: path MTU 1024 below 4096"
        ),
        1
    );
    assert_eq!(
        logged(
            &mc,
            "rdma: max_sessions 4 reached, new connections stay on TCP"
        ),
        1
    );
    // capped connections keep coming: nothing more within the interval
    mc.osds[1].note_rdma(
        vec![dev(
            2,
            Counters {
                sessions_capped: 500,
                credit_stalls: 9,
                credit_stall_ns: 123,
                grants_demand: 5,
                idle_decays: 2,
                rx_post_failures: 1,
                cq_errors: 2,
                rx_withheld: 3,
                ..two
            },
        )],
        process,
    );
    mc.run_for(Duration::from_secs(60));
    assert_eq!(logged(&mc, "rdma:"), 2, "{:?}", mc.osds[0].logs);

    // counters: names, types (U64|COUNTER for counts, U64 for the gauge), sums over the cores
    let c = mc.osds[0].counters_now();
    let get = |n: &str| {
        let (t, v) = &c[&format!("osd.{n}")];
        (t.ty, v.value)
    };
    assert_eq!(get("rdma_upgraded"), (pct::COUNTER_U64, 4));
    assert_eq!(get("rdma_tx_write_wrs"), (pct::COUNTER_U64, 6));
    assert_eq!(get("rdma_tx_write_bytes"), (pct::COUNTER_U64, 3072));
    assert_eq!(get("rdma_tx_write_doorbells"), (pct::COUNTER_U64, 6));
    assert_eq!(get("rdma_tx_write_sq_stalls"), (pct::COUNTER_U64, 2));

    assert_eq!(get("rdma_sessions_capped"), (pct::COUNTER_U64, 500));
    assert_eq!(get("rdma_credit_stalls"), (pct::COUNTER_U64, 9));
    assert_eq!(get("rdma_credit_stall_ns"), (pct::COUNTER_U64, 123));
    assert_eq!(get("rdma_grants_demand"), (pct::COUNTER_U64, 5));
    assert_eq!(get("rdma_idle_decays"), (pct::COUNTER_U64, 2));
    assert_eq!(get("rdma_sessions"), (pct::GAUGE, 4));
    // robustness counters: per core summed; the process-wide ones once (not times the cores)
    assert_eq!(get("rdma_rx_post_failures"), (pct::COUNTER_U64, 1));
    assert_eq!(get("rdma_cq_errors"), (pct::COUNTER_U64, 2));
    assert_eq!(get("rdma_rx_withheld"), (pct::COUNTER_U64, 3));
    assert_eq!(get("rdma_leaked_cores"), (pct::COUNTER_U64, 1));
    assert_eq!(get("rdma_teardown_failures"), (pct::COUNTER_U64, 2));
    assert_eq!(get("rdma_qp_drain_timeouts"), (pct::COUNTER_U64, 3));
    assert_eq!(get("rdma_quarantined_windows"), (pct::COUNTER_U64, 4));
    assert_eq!(get("rdma_quarantined_write_sources"), (pct::COUNTER_U64, 5));
    for n in [
        "rdma_declined",
        "rdma_faulted",
        "rdma_queue_stalls",
        "rdma_close_fence_timeouts",
        "rdma_zc_bytes",
        "rdma_zc_misses",
        "rdma_tx_bytes",
        "rdma_tx_sends",
        "rdma_tx_chunks",
        "rdma_tx_doorbells",
        "rdma_rx_doorbells",
        "rdma_wakes",
    ] {
        assert_eq!(get(n), (pct::COUNTER_U64, 0), "{n}");
    }

    // rdma status
    let (r, d) = ask(&mut mc, json!({"prefix": "rdma status"}));
    assert_eq!(r, 0, "{d}");
    assert_eq!(d["enabled"], true);
    assert_eq!(d["max_sessions"], 4);
    assert_eq!(d["sessions"], 4);
    assert_eq!(d["devices"][0]["tx_write_wrs"], 6);
    assert_eq!(d["devices"][0]["tx_write_bytes"], 3072);
    assert_eq!(d["devices"][0]["tx_write_doorbells"], 6);
    assert_eq!(d["devices"][0]["tx_write_sq_stalls"], 2);

    assert_eq!(d["devices"][0]["upgraded"], 4);
    assert_eq!(d["devices"][0]["granted_credits"], 12);
    assert_eq!(d["devices"][0]["cq_errors"], 2);
    assert_eq!(d["leaked_cores"], 1);
    assert_eq!(d["teardown_failures"], 2);
    assert_eq!(d["qp_drain_timeouts"], 3);
    assert_eq!(d["quarantined_windows"], 4);
    assert_eq!(d["quarantined_write_sources"], 5);
    assert_eq!(d["cores"].as_array().unwrap().len(), 2);
    assert_eq!(d["unusable"][0]["addr"], "172.28.0.12");
    let p = ask_raw(
        &mut mc,
        &json!({"prefix": "rdma status", "format": "plain"}),
    );
    assert!(
        p.starts_with("rdma enabled, max_sessions 4, sessions 4\n"),
        "{p}"
    );
    assert!(p.contains("172.28.0.11 (mlx5_0): sessions 4"), "{p}");
    assert!(
        p.contains("tx_write_wrs 6 tx_write_bytes 3072 tx_write_doorbells 6 tx_write_sq_stalls 2"),
        "{p}"
    );
    let j = ask_raw(&mut mc, &json!({"prefix": "rdma status", "format": "json"}));
    assert!(serde_json::from_str::<serde_json::Value>(&j).is_ok(), "{j}");
}

/// The raw output text of a command (plain formats are not JSON).
fn ask_raw(mc: &mut Mc, cmd: &serde_json::Value) -> String {
    let (tx, rx) = std::sync::mpsc::channel();
    mc.osds[0].cmds.seq += 1;
    let tok = mc.osds[0].cmds.seq;
    mc.osds[0].cmds.pending.insert(tok, tx);
    let t = mc.t;
    mc.osds[0].set_now(t);
    mc.osds[0].exec_command(&cmd.to_string(), crate::tell::ReplyTo::Asok(tok));
    mc.settle();
    let (r, rs, out) = rx.try_recv().expect("command answered");
    assert_eq!(r, 0, "{rs}");
    String::from_utf8(out.into_bytes()).unwrap()
}

/// Without `flashstore_rdma` the OSD declares no RDMA counters and says nothing.
#[test]
fn rdma_off_declares_nothing() {
    let mut mc = Mc::new(1);
    mc.up();
    assert!(
        mc.osds[0]
            .counters_now()
            .keys()
            .all(|k| !k.contains("rdma"))
    );
    mc.run_for(Duration::from_secs(3));
    assert!(mc.osds[0].logs.iter().all(|l| !l.contains("rdma:")));
}
