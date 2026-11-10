// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Core state machine tests: no sockets, the mon session is replaced by recording hooks.
use super::*;
use crate::meta::FileMetaStore;
use denc::types::Uuid;
use messages::{CompatSet, MOSDBoot, MOSDFailure, MOSDPing, clog};
use monc::MonEvent;
use std::net::{IpAddr, Ipv4Addr};

type Osd = super::Osd<crate::backend::LabDir>;

fn tmpdir(n: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("croit-flashstore-osd-{n}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

const FSID: Uuid = Uuid([7; 16]);

#[test]
fn runtime_crc_policy_reaches_new_monitor_connections_only() {
    for started in [false, true] {
        let key = cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, UTime::new(1, 0)).unwrap();
        let mut o = try_mk_osd(
            &format!("mon-crc-policy-{started}"),
            key.to_base64().unwrap(),
            vec![],
            false,
            false,
        )
        .unwrap();
        if started {
            o.mc.start(Duration::ZERO);
        }
        let cmd = r#"{"prefix":"config set","var":"ms_crc_data","val":"false"}"#;
        assert_eq!(
            o.run_command(cmd, &crate::tell::ReplyTo::Internal)
                .unwrap()
                .0,
            0
        );
        if !started {
            o.mc.start(Duration::ZERO);
        }
        let conn = o.mc.conn_ids()[0];
        o.mc.on_connected(conn, Duration::ZERO);
        let _ = o.mc.poll_output(conn); // our banner
        let mut banner = Vec::new();
        msgr2::Banner {
            supported: msgr2::FEATURE_REVISION_1,
            required: 0,
        }
        .encode(&mut banner);
        o.mc.on_bytes(conn, &banner, Duration::ZERO);
        let hello = o.mc.poll_output(conn);
        assert!(hello.len() >= 36, "missing HELLO: {hello:?}");
        let len = u32::from_le_bytes(hello[2..6].try_into().unwrap()) as usize;
        let crc = u32::from_le_bytes(hello[32 + len..36 + len].try_into().unwrap());
        assert_eq!(
            crc == 0,
            !started,
            "existing connections keep their CRC policy"
        );
    }
}

#[test]
fn runtime_monitor_modes_reach_new_handshakes_only() {
    use cephx::modes::{CON_MODE_CRC, CON_MODE_SECURE};
    use msgr2::payload::{AuthRequest, Hello, Payload};
    for started in [false, true] {
        let key = cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, UTime::new(1, 0)).unwrap();
        let mut o = try_mk_osd(
            &format!("mon-mode-policy-{started}"),
            key.to_base64().unwrap(),
            vec![],
            false,
            false,
        )
        .unwrap();
        if started {
            o.mc.start(Duration::ZERO);
        }
        let cmd = r#"{"prefix":"config set","var":"ms_mon_cluster_mode","val":"secure"}"#;
        assert_eq!(
            o.run_command(cmd, &crate::tell::ReplyTo::Internal)
                .unwrap()
                .0,
            0
        );
        if !started {
            o.mc.start(Duration::ZERO);
        }
        let conn = o.mc.conn_ids()[0];
        o.mc.on_connected(conn, Duration::ZERO);
        let _ = o.mc.poll_output(conn);
        let mut bytes = Vec::new();
        msgr2::Banner {
            supported: msgr2::FEATURE_REVISION_1,
            required: 0,
        }
        .encode(&mut bytes);
        o.mc.on_bytes(conn, &bytes, Duration::ZERO);
        let _ = o.mc.poll_output(conn);
        bytes.clear();
        let hello = Hello {
            entity_type: EntityName::MON,
            peer_addr: EntityAddr::blank(),
        };
        msgr2::Encoder::new(msgr2::Revision::V21)
            .encode_control(Hello::TAG as u8, &hello.to_bytes().unwrap(), &mut bytes)
            .unwrap();
        o.mc.on_bytes(conn, &bytes, Duration::ZERO);
        let request = o.mc.poll_output(conn);
        assert!(request.len() >= 36, "missing AUTH_REQUEST: {request:?}");
        assert_eq!(request[0], AuthRequest::TAG as u8);
        let len = u32::from_le_bytes(request[2..6].try_into().unwrap()) as usize;
        let auth = AuthRequest::from_bytes(&request[32..32 + len]).unwrap();
        let expected = if started {
            vec![CON_MODE_SECURE, CON_MODE_CRC]
        } else {
            vec![CON_MODE_SECURE]
        };
        assert_eq!(auth.preferred_modes, expected);
    }
}

/// NT-config-03: the `mon_client_*` timers reach the daemon's mon session from the local file at start, from the mon
/// config db and from a runtime `config set` (classic reads them on every use); unusable factors keep the default.
#[test]
fn mon_client_timers_reach_the_mon_session_from_every_config_layer() {
    let key = cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, UTime::new(1, 0)).unwrap();
    let mut o = try_mk_osd(
        "mon-client-timers",
        key.to_base64().unwrap(),
        vec![
            ("mon_client_ping_timeout".into(), "0".into()),
            ("mon_client_hunt_parallel".into(), "1".into()),
            ("mon_client_hunt_interval".into(), "0.5".into()),
        ],
        false,
        false,
    )
    .unwrap();
    let t = o.mc.timers();
    assert_eq!(t.ping_timeout, Duration::ZERO, "file layer at start");
    assert_eq!(t.hunt_parallel, 1);
    assert_eq!(t.hunt_interval, Duration::from_millis(500));
    assert_eq!(t.ping_interval, Duration::from_secs(10), "pinned default");
    assert_eq!(t.max_log_entries, 1000, "pinned default");
    assert!(
        o.conf
            .apply_mon(&BTreeMap::from([(
                "mon_client_ping_interval".into(),
                "2.5".into()
            )]))
            .is_empty()
    );
    o.conf_changed();
    assert_eq!(o.mc.timers().ping_interval, Duration::from_millis(2500));
    for (k, v) in [
        ("mon_client_ping_timeout", "45"),
        ("mon_client_hunt_interval_backoff", "0"),
    ] {
        let cmd = serde_json::json!({"prefix": "config set", "var": k, "val": v});
        assert_eq!(
            o.run_command(&cmd.to_string(), &crate::tell::ReplyTo::Internal)
                .unwrap()
                .0,
            0,
            "{k}"
        );
    }
    let t = o.mc.timers();
    assert_eq!(t.ping_timeout, Duration::from_secs(45), "runtime override");
    assert_eq!(t.hunt_backoff, 1.5, "zero backoff keeps the default");
}

#[test]
fn fractional_scrub_intervals_reach_the_scheduler_from_every_config_layer() {
    let mut o = mk_osd("fractional-scrub-config");
    for level in [
        crate::config::Level::File,
        crate::config::Level::Mon,
        crate::config::Level::Override,
    ] {
        match level {
            crate::config::Level::Mon => {
                assert!(
                    o.conf
                        .apply_mon(&BTreeMap::from([
                            ("osd_scrub_min_interval".into(), "0.5".into()),
                            ("osd_deep_scrub_interval".into(), "10.75".into()),
                        ]))
                        .is_empty()
                );
                o.conf_changed();
            }
            crate::config::Level::Override => {
                for (key, value) in [
                    ("osd_scrub_min_interval", "0.5"),
                    ("osd_deep_scrub_interval", "10.75"),
                ] {
                    let cmd = serde_json::json!({"prefix": "config set", "var": key, "val": value});
                    assert_eq!(
                        o.run_command(&cmd.to_string(), &crate::tell::ReplyTo::Internal)
                            .unwrap()
                            .0,
                        0
                    );
                }
            }
            _ => {
                o.conf.set(level, "osd_scrub_min_interval", "0.5").unwrap();
                o.conf
                    .set(level, "osd_deep_scrub_interval", "10.75")
                    .unwrap();
                o.conf_changed();
            }
        }
        let s = o.pg.set.scrub_cfg_mut();
        assert_eq!(s.min_interval, 0.5, "{level:?}");
        assert_eq!(s.deep_interval, 10.75, "{level:?}");
        o.conf.unset(level, "osd_scrub_min_interval");
        o.conf.unset(level, "osd_deep_scrub_interval");
    }
}

/// The RDMA upgrade is offered on the public and cluster messengers only, never on heartbeat links; default off.
#[test]
fn rdma_is_enabled_on_public_and_cluster_messengers_only() {
    for (on, tag) in [(false, "rdma-off"), (true, "rdma-on")] {
        let o = mk_osd_rdma(tag, vec![], on, false);
        let flags: Vec<bool> = o.msgr.iter().map(|m| m.cfg.rdma).collect();
        assert_eq!(flags, [on, on, false, false, false, false], "on={on}");
    }
}

#[test]
fn placement_config_enables_only_public_lossless_client_sessions() {
    let o = mk_osd_rdma("placement-banner", vec![], true, true);
    let flags: Vec<bool> = o.msgr.iter().map(|m| m.cfg.placement).collect();
    assert_eq!(flags, [true, false, false, false, false, false]);
    assert_eq!(
        o.msgr[MsgrId::Public as usize]
            .cfg
            .policies
            .get(EntityName::CLIENT),
        msgr2::Policy::stateful_server(0)
    );
    assert_eq!(
        o.msgr[MsgrId::Cluster as usize]
            .cfg
            .policies
            .get(EntityName::OSD),
        PolicyTable::osd_cluster().get(EntityName::OSD)
    );
}

#[test]
fn connection_timer_queries_visit_only_dirty_connections() {
    let mut o = mk_osd("timer-ready");
    let mut active = 0;
    for _ in 0..1000 {
        active = o.on_accept(
            Listener::Public,
            crate::osd::sock4([10, 0, 0, 5], 10000),
            Duration::from_secs(1),
        );
    }
    let _ = o.next_timer();
    o.t.timer_probes.set(0);
    for _ in 0..1000 {
        let _ = o.next_timer();
    }
    assert_eq!(o.t.timer_probes.get(), 0);
    o.links
        .get_mut(&active)
        .unwrap()
        .conn
        .on_bytes(&[], Duration::from_secs(2));
    let _ = o.next_timer();
    assert_eq!(o.t.timer_probes.get(), 1);
    let indexed = o.conn_timers.borrow().first().map(|(d, _)| d);
    let scanned = o.links.values().filter_map(|l| l.conn.next_timer()).min();
    assert_eq!(indexed, scanned);
    o.close_link(active);
    let _ = o.next_timer();
    assert_eq!(
        o.conn_timers.borrow().first().map(|(d, _)| d),
        o.links.values().filter_map(|l| l.conn.next_timer()).min()
    );
}

#[test]
fn connection_timer_index_matches_scan_across_timeout_and_close() {
    let mut o = mk_osd("timer-transitions");
    for _ in 0..32 {
        o.on_accept(
            Listener::Public,
            crate::osd::sock4([10, 0, 0, 5], 10000),
            Duration::from_secs(1),
        );
    }
    for now in [2, 10, 100] {
        o.on_timer(Duration::from_secs(now));
        let _ = o.next_timer();
        assert_eq!(
            o.conn_timers.borrow().first().map(|(d, _)| d),
            o.links.values().filter_map(|l| l.conn.next_timer()).min()
        );
    }
}

#[test]
#[ignore = "connection deadline benchmark; run explicitly"]
fn connection_timer_bench() {
    for idle in [1, 1000] {
        let mut o = mk_osd(&format!("timer-bench-{idle}"));
        for _ in 0..idle {
            o.on_accept(
                Listener::Public,
                crate::osd::sock4([10, 0, 0, 5], 10000),
                Duration::from_secs(1),
            );
        }
        std::hint::black_box(o.next_timer());
        let n = 20_000;
        let start = std::time::Instant::now();
        for _ in 0..n {
            std::hint::black_box(o.next_timer());
        }
        eprintln!(
            "connection_timer idle={idle} ns/query={}",
            start.elapsed().as_nanos() / n
        );
    }
}

fn mk_osd(tag: &str) -> Osd {
    // these table / benchmark tests hold many links that never handshake; idle links buffer no pre-auth bytes, so the
    // per-messenger budget (its own test) never closes them
    mk_osd_with(tag, vec![])
}

#[test]
#[ignore = "pending-output microbenchmark; run explicitly"]
fn output_flush_bench() {
    for idle in [1, 1000] {
        let mut o = mk_osd(&format!("output-bench-{idle}"));
        for _ in 0..idle {
            o.on_accept(
                Listener::Public,
                crate::osd::sock4([10, 0, 0, 5], 10000),
                Duration::from_secs(1),
            );
        }
        while let Some(id) = o.poll_output_ready() {
            let _ = o.poll_output_chunks(id);
        }
        let rounds = 20_000;
        let t0 = std::time::Instant::now();
        let mut visits = 0;
        for _ in 0..rounds {
            while let Some(id) = o.poll_output_ready() {
                std::hint::black_box(id);
                visits += 1;
            }
        }
        eprintln!(
            "output_flush idle={idle} ns/flush={:.1} visits/flush={:.1}",
            t0.elapsed().as_nanos() as f64 / rounds as f64,
            visits as f64 / rounds as f64
        );
    }
}

#[test]
fn output_ready_ignores_idle_connections_and_deduplicates() {
    let mut o = mk_osd("output-ready");
    for _ in 0..1000 {
        o.on_accept(
            Listener::Public,
            crate::osd::sock4([10, 0, 0, 5], 10000),
            Duration::from_secs(1),
        );
    }
    while let Some(id) = o.poll_output_ready() {
        let _ = o.poll_output_chunks(id);
    }
    assert_eq!(o.poll_output_ready(), None);
    let active = o.on_accept(
        Listener::Public,
        crate::osd::sock4([10, 0, 0, 6], 10001),
        Duration::from_secs(1),
    );
    assert_eq!(o.poll_output_ready(), Some(active));
    assert_eq!(o.poll_output_ready(), None);
    assert!(!o.poll_output_chunks(active).is_empty());
    assert_eq!(o.poll_output_ready(), None, "idle links are never queued");
}

#[test]
fn event_pump_does_not_probe_idle_connections() {
    let mut o = mk_osd("event-ready-idle");
    for _ in 0..1000 {
        o.on_accept(
            Listener::Public,
            crate::osd::sock4([10, 0, 0, 5], 10000),
            Duration::from_secs(1),
        );
    }
    o.pump();
    o.t.event_visits = 0;
    o.pump();
    assert_eq!(
        o.t.event_visits, 0,
        "idle connections must not be probed for events"
    );
}

/// adr 0006 am. 6: the link events a pump hands on raise each source core's share of the next inbox drain.
#[test]
fn link_events_raise_each_source_cores_share_of_the_next_inbox_drain() {
    let mut o = mk_osd("drain-share");
    let base = o.slice.budget();
    assert_eq!(o.start_drain(), base, "no link work yet: one slice");
    let links = o.links.len();
    // 40 closing connections: one link event of at least one block each, more than one slice in all
    for port in 0..40 {
        let id = o.on_accept(
            Listener::Public,
            crate::osd::sock4([10, 0, 0, 5], 10000 + port),
            Duration::from_secs(1),
        );
        o.links
            .get_mut(&id)
            .unwrap()
            .conn
            .on_closed(Duration::from_secs(2));
    }
    o.pump();
    while o.event_pump_pending {
        o.pump();
    }
    assert_eq!(o.links.len(), links, "every close was handled");
    let share = o.start_drain();
    assert!(
        share >= 40 * crate::xcore::SLICE_MIN && share > base,
        "share {share}, slice {base}"
    );
    assert_eq!(
        o.start_drain(),
        base,
        "the count starts over with every drain"
    );
}

#[test]
#[ignore = "local event dispatch benchmark"]
fn perf_event_pump_with_idle_connections() {
    for idle in [1, 1000] {
        let mut o = mk_osd(&format!("event-pump-bench-{idle}"));
        for _ in 0..idle {
            o.on_accept(
                Listener::Public,
                crate::osd::sock4([10, 0, 0, 5], 10000),
                Duration::from_secs(1),
            );
        }
        o.pump();
        while let Some(id) = o.poll_output_ready() {
            let _ = o.poll_output_chunks(id);
        }
        let mut elapsed = 0;
        let mut visits = 0;
        for _ in 0..1000 {
            let active = o.on_accept(
                Listener::Public,
                crate::osd::sock4([10, 0, 0, 6], 10001),
                Duration::from_secs(1),
            );
            o.links
                .get_mut(&active)
                .unwrap()
                .conn
                .on_closed(Duration::from_secs(2));
            o.t.event_visits = 0;
            let t = std::time::Instant::now();
            o.pump();
            elapsed += t.elapsed().as_nanos();
            visits += o.t.event_visits;
            assert!(!o.links.contains_key(&active));
            while let Some(id) = o.poll_output_ready() {
                let _ = o.poll_output_chunks(id);
            }
        }
        println!(
            "event pump idle={idle} ns_per_event={} visits_per_event={}",
            elapsed / 1000,
            visits / 1000
        );
    }
}

/// The trace clock (read with sampling off by the pre-write path) is calibrated by the constructor, not by the first op
/// that reads it (a ~10 ms spin, doc/perf/omap-cold-start-20261024.md).
#[test]
fn construction_calibrates_the_trace_clock() {
    let _o = mk_osd_with("tracecal", vec![]);
    assert!(crate::trace::calibrated());
}

/// Header-time frame admission (adr 0084 am. 2) also bounds a single-core OSD: its ingress credits carry the frame
/// windows, and only the multi-core launcher called `set_ingress_credits`, which used to be the sole place that
/// installed the gates.
#[test]
fn frame_gates_are_installed_on_the_single_core_path() {
    let o = mk_osd_with("frame-gates", vec![]);
    assert!(o.cl.ingress.has_frames(), "ingress has the frame windows");
    assert!(
        o.cl.frame_gates.is_some(),
        "single-core OSD without header-time frame admission"
    );
}

fn mk_osd_with(tag: &str, local_config: Vec<(String, String)>) -> Osd {
    mk_osd_rdma(tag, local_config, false, false)
}

fn mk_osd_rdma(tag: &str, local_config: Vec<(String, String)>, rdma: bool, placement: bool) -> Osd {
    let key = cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, UTime::new(1, 0)).unwrap();
    let mut o = try_mk_osd(tag, key.to_base64().unwrap(), local_config, rdma, placement).unwrap();
    o.start(Duration::from_secs(1));
    o.init = Init::Done;
    o.hb.next_round = None;
    o
}

/// An OSD of the identity `key` (empty = no key, auth none), not started.
fn try_mk_osd(
    tag: &str,
    key: String,
    local_config: Vec<(String, String)>,
    rdma: bool,
    placement: bool,
) -> Result<Osd, String> {
    // Hermetic key sources: without an explicit `osd_data` the default `/var/lib/ceph/osd/ceph-3` would read the
    // host's keyring (a lab runner with a deployed osd.3 turns the keyless tests into keyed ones).
    let mut local_config = local_config;
    if !local_config.iter().any(|(k, _)| k == "osd_data") {
        let data = tmpdir(&format!("{tag}-data"));
        local_config.push(("osd_data".into(), data.to_string_lossy().into_owned()));
    }
    Osd::new(
        test_cfg(local_config, rdma, placement),
        test_store(tag, &key, 0),
    )
}

/// Identity + superblock of the test OSD (osd.3) in a fresh `8 << 30` dev store at `current_epoch`.
fn test_store(tag: &str, key: &str, current_epoch: u32) -> FileMetaStore {
    let mut st = FileMetaStore::open(tmpdir(tag), 8 << 30).unwrap();
    st.store_identity(&Identity {
        whoami: 3,
        cluster_fsid: FSID,
        osd_fsid: Uuid([9; 16]),
        key: key.to_owned(),
        crush_device_class: "nvme".into(),
        created_at: "t".into(),
        ceph_version_when_created: "v".into(),
    })
    .unwrap();
    st.store_superblock(&OsdSuperblock {
        cluster_fsid: FSID,
        whoami: 3,
        osd_fsid: Uuid([9; 16]),
        compat_features: CompatSet::osd_initial(),
        purged_snaps_last: 1000,
        current_epoch,
        ..Default::default()
    })
    .unwrap();
    st
}

fn test_cfg(local_config: Vec<(String, String)>, rdma: bool, placement: bool) -> OsdConfig {
    OsdConfig {
        hostname: "h1".into(),
        public_ips: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4))],
        cluster_ips: vec![IpAddr::V4(Ipv4Addr::new(10, 1, 0, 4))],
        public_port: 6800,
        cluster_port: 6801,
        hb_front_port: 6802,
        hb_back_port: 6803,
        mon_host: monc::parse_mon_host("v2:10.0.0.1:3300").unwrap(),
        wall_origin_unix: 1_700_000_000,
        wall_from_clock: false,
        seed: 42,
        nonce: 555,
        sys_metadata: BTreeMap::new(),
        local_config,
        local_sources: Default::default(),
        data_path: "/d".into(),
        rdma,
        placement,
        source_pull: placement,
    }
}

fn conf(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

/// auth none without any key: cephx leaves the lists, the OSD asks the mon for method NONE.
#[test]
fn keyless_osd_in_an_auth_none_cluster_starts_with_none_only() {
    let local = conf(&[
        ("auth_cluster_required", "none"),
        ("auth_service_required", "none"),
    ]);
    let mut o = try_mk_osd("nokey-none", String::new(), local, false, false).unwrap();
    let l = o.keys.lists();
    assert_eq!((l.cluster, l.service), (vec![1], vec![1]));
    o.start(Duration::from_secs(1));
    let logs = format!("{:?}", o.logs);
    assert!(logs.contains("has no cephx key: cephx removed"), "{logs}");
    assert_eq!(logs.matches("has no cephx key").count(), 1, "{logs}");
}

/// `cephx, none` and no key behaves as none (auth-none spec 2.2).
#[test]
fn keyless_osd_with_cephx_and_none_falls_to_none() {
    let local = conf(&[
        ("auth_cluster_required", "cephx, none"),
        ("auth_service_required", "cephx, none"),
    ]);
    let o = try_mk_osd("nokey-both", String::new(), local, false, false).unwrap();
    assert_eq!(o.keys.lists().cluster, vec![1]);
}

#[test]
fn keyless_osd_with_cephx_only_is_a_clear_startup_error() {
    for local in [vec![], conf(&[("auth_cluster_required", "none")])] {
        let e = try_mk_osd("nokey-cephx", String::new(), local, false, false)
            .err()
            .unwrap();
        assert!(
            e.contains("no cephx key") && e.contains("cannot authenticate"),
            "{e}"
        );
    }
}

/// The key sources of the local config beat the device record: a keyless device with `$osd_data/keyring`
/// keeps cephx; a keyring that has no key for this OSD fails start-up even when `none` is allowed (never a
/// silent fall-back to auth none); `key` beats the keyring.
#[test]
fn key_sources_beat_the_device_and_fail_loudly() {
    let d = tmpdir("keysrc-osd");
    std::fs::create_dir_all(&d).unwrap();
    let k =
        cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, cephx::UTime::new(1, 0)).unwrap();
    let data = d.to_str().unwrap();
    std::fs::write(
        d.join("keyring"),
        format!("[osd.3]\nkey = {}\n", k.to_base64().unwrap()),
    )
    .unwrap();
    let o = try_mk_osd(
        "keysrc-a",
        String::new(),
        conf(&[("osd_data", data)]),
        false,
        false,
    )
    .unwrap();
    assert_eq!(o.keys.lists().cluster, vec![2], "cephx stays");
    std::fs::write(
        d.join("keyring"),
        format!("[osd.9]\nkey = {}\n", k.to_base64().unwrap()),
    )
    .unwrap();
    let both = [
        ("osd_data", data),
        ("auth_cluster_required", "cephx, none"),
        ("auth_service_required", "cephx, none"),
    ];
    let e = try_mk_osd("keysrc-b", String::new(), conf(&both), false, false)
        .err()
        .unwrap();
    assert!(e.contains("no key for osd.3"), "{e}");
    let b64 = k.to_base64().unwrap();
    let with_key = [("osd_data", data), ("key", b64.as_str())];
    let o = try_mk_osd("keysrc-c", String::new(), conf(&with_key), false, false).unwrap();
    assert_eq!(o.keys.lists().cluster, vec![2]);
    // nothing configured, nothing found, no device key, cephx required: start-up fails
    let empty = tmpdir("keysrc-empty");
    let e = try_mk_osd(
        "keysrc-d",
        String::new(),
        conf(&[("osd_data", empty.to_str().unwrap())]),
        false,
        false,
    )
    .err()
    .unwrap();
    assert!(
        e.contains("no cephx key") && e.contains("cannot authenticate"),
        "{e}"
    );
}

/// `ceph config set osd auth_service_required ...` (mon config db) and a runtime `config set` reach the lists the
/// next session uses, with one log line per change (classic re-reads them on every config change).
#[test]
fn auth_lists_follow_central_and_runtime_config() {
    let mut o = mk_osd("authlists");
    assert_eq!(o.keys.lists().service, [2]);
    let mon = BTreeMap::from([("auth_service_required".to_owned(), "cephx, none".to_owned())]);
    o.conf.apply_mon(&mon);
    o.conf_changed();
    assert_eq!(o.keys.lists().service, [2, 1]);
    o.conf
        .set(
            crate::config::Level::Override,
            "auth_cluster_required",
            "cephx, none",
        )
        .unwrap();
    o.conf_changed();
    assert_eq!(o.keys.lists().cluster, [2, 1]);
    o.conf_changed();
    let logs = format!("{:?}", o.logs);
    assert_eq!(
        logs.matches("auth method lists changed").count(),
        2,
        "{logs}"
    );
}

fn addr(ip: [u8; 4], port: u16, nonce: u32) -> EntityAddrVec {
    EntityAddrVec::single(EntityAddr::v4(EntityAddr::TYPE_MSGR2, nonce, ip, port))
}

/// Map with osds 0..max, `up` of them up; osd 3 uses `o`'s real addresses when listed as up.
fn mk_map(epoch: u32, max: i32, up: &[i32], o: &Osd, me_up_from: u32) -> OsdMap {
    let mut m = OsdMap::default();
    m.epoch = epoch;
    m.fsid = FSID;
    m.flags = map_flags::SORTBITWISE;
    m.require_osd_release = release::UMBRELLA;
    m.nearfull_ratio = 0.85;
    m.backfillfull_ratio = 0.9;
    m.full_ratio = 0.95;
    m.max_osd = max;
    let n = max as usize;
    m.osd_state = vec![osd_state::EXISTS; n];
    m.osd_weight = vec![0x10000; n];
    m.client_addrs = vec![EntityAddrVec::default(); n];
    m.cluster_addrs = vec![EntityAddrVec::default(); n];
    m.hb_back_addrs = vec![EntityAddrVec::default(); n];
    m.hb_front_addrs = vec![EntityAddrVec::default(); n];
    m.osd_info = vec![osdmap::OsdInfo::default(); n];
    m.osd_uuid = vec![Uuid::default(); n];
    m.osd_xinfo = vec![osdmap::OsdXInfo::default(); n];
    for &i in up {
        let u = i as usize;
        m.osd_state[u] |= osd_state::UP;
        m.osd_info[u].up_from = if i == 3 { me_up_from } else { 1 };
        if i == 3 {
            m.client_addrs[u] = o.public_addrs.clone();
            m.cluster_addrs[u] = o.cluster_addrs.clone();
            m.hb_back_addrs[u] = o.hb_back_addrs.clone();
            m.hb_front_addrs[u] = o.hb_front_addrs.clone();
        } else {
            let ip = [10, 0, 0, i as u8 + 10];
            let ip2 = [10, 1, 0, i as u8 + 10];
            m.client_addrs[u] = addr(ip, 6800, 100 + i as u32);
            m.cluster_addrs[u] = addr(ip2, 6801, 100 + i as u32);
            m.hb_front_addrs[u] = addr(ip, 6802, 100 + i as u32);
            m.hb_back_addrs[u] = addr(ip2, 6803, 100 + i as u32);
        }
    }
    m
}

/// Deliver `map` as a mon MOSDMap (full map only).
fn deliver(o: &mut Osd, map: OsdMap, newest: u32) {
    let e = map.epoch;
    let blob = map.encode_full().unwrap();
    let msg = MOSDMap {
        fsid: FSID,
        incremental_maps: BTreeMap::new(),
        maps: BTreeMap::from([(e, blob)]),
        cluster_osdmap_trim_lower_bound: 1,
        newest_map: newest,
    };
    o.mc.set_osdmap(map.clone());
    o.on_osdmap_event(std::sync::Arc::new(map), &msg);
}

fn boots(o: &Osd) -> Vec<MOSDBoot> {
    o.t.sent
        .iter()
        .filter_map(|m| match m {
            AnyMessage::MOSDBoot(b) => Some(b.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn pg_map_loading_skips_unstored_epoch_gaps() {
    let mut o = mk_osd("map-loading-sparse-history");
    // Old retained history and the full-map jump when a long-offline OSD rejoins.
    let epochs = [1, 10_000, 10_001];
    let blobs: Vec<_> = epochs
        .iter()
        .map(|&e| {
            (
                e,
                MapKind::Full,
                mk_map(e, 4, &[], &o, 0).encode_full().unwrap(),
            )
        })
        .collect();
    o.sb.mapc = BTreeMap::from([(1, 1), (10_000, 2)]);
    o.sb.current_epoch = 10_001;
    o.store
        .as_mut()
        .unwrap()
        .commit_maps(&blobs, &o.sb)
        .unwrap();
    for (from, want) in [
        (5_000, vec![1, 10_000, 10_001]),
        (0, vec![1, 10_000, 10_001]),
    ] {
        o.store.as_ref().unwrap().map_reads.set(0);
        let got: Vec<_> = o
            .pg_load_maps(from, 10_001)
            .iter()
            .map(|m| m.epoch)
            .collect();
        assert_eq!(got, want);
        let reads = o.store.as_ref().unwrap().map_reads.get();
        assert!(reads <= 8, "{reads} map reads for only three stored epochs");
    }
}

fn count<F: Fn(&AnyMessage) -> bool>(o: &Osd, f: F) -> usize {
    o.t.sent.iter().filter(|m| f(m)).count()
}

#[test]
fn boot_metadata_iface_and_bdev_extras() {
    let mut o = mk_osd("bootmeta");
    let m = o.boot_metadata();
    assert_eq!(m["front_iface"], "");
    // the device/NUMA identity keys of spec 3.3.1: facts this daemon owns; unresolved or non-existent facts
    // (BlueFS/BlueStore internals) are omitted, not invented
    assert!(!m.contains_key("bluefs"));
    assert!(!m.contains_key("bluestore_allocator"));
    assert!(!m.contains_key("bluestore_min_alloc_size"));
    assert_eq!(m["network_numa_unknown_ifaces"], "{back_iface,front_iface}");
    assert!(!m.contains_key("network_numa_nodes"));
    o.cfg
        .sys_metadata
        .insert("front_iface".into(), "eth1".into());
    o.cfg
        .sys_metadata
        .insert("back_iface".into(), "eth1".into());
    let m = o.boot_metadata();
    assert_eq!(m["front_iface"], "eth1");
    assert_eq!(m["back_iface"], "eth1");
}

#[test]
fn boot_sequence_up_and_beacon() {
    let mut o = mk_osd("boot");
    o.state = State::Preboot;
    // no map yet: waits and asks for epoch 1 onwards
    o.preboot(1, 10);
    assert!(o.t.subs.iter().any(|s| s.0 == "osdmap" && s.1 == 1));
    assert!(boots(&o).is_empty());
    // map 8 (osd 3 exists, not up), newest 10: close enough -> boot
    let m8 = mk_map(8, 4, &[0, 1, 2], &o, 0);
    deliver(&mut o, m8, 8);
    let b = boots(&o);
    assert_eq!(b.len(), 1, "log: {:?}", o.logs);
    let b = &b[0];
    assert_eq!(o.state, State::Booting);
    assert_eq!(b.version, 8);
    assert_eq!(b.boot_epoch, 0);
    assert_eq!(b.sb.current_epoch, 8);
    assert_eq!(b.hb_back_addrs, o.hb_back_addrs);
    assert_eq!(b.cluster_addrs, o.cluster_addrs);
    assert_eq!(b.hb_front_addrs, o.hb_front_addrs);
    assert_eq!(b.osd_features, msgr2::FEATURES_SUPPORTED_DEFAULT);
    for k in [
        "hostname",
        "ceph_version_short",
        "ceph_version",
        "osd_objectstore",
        "flashstore_version",
        "default_device_class",
        "rotational",
        "front_addr",
        "back_addr",
        "hb_front_addr",
        "hb_back_addr",
    ] {
        assert!(b.metadata.contains_key(k), "missing metadata key {k}");
    }
    assert_eq!(b.metadata["osd_objectstore"], "bluestore");
    assert!(!b.metadata.contains_key("osd_type")); // classic omits it; any non-crimson value makes the mon log an error
    assert_eq!(b.metadata["rotational"], "0");
    assert_eq!(b.metadata["default_device_class"], "nvme");
    // superblock persisted with the stored interval
    let sb = o
        .store
        .as_ref()
        .unwrap()
        .load_superblock()
        .unwrap()
        .unwrap();
    assert_eq!(sb.current_epoch, 8);
    assert_eq!(sb.mapc.get(&8), Some(&1));
    // mon marks us up in epoch 9 with our addrs -> ACTIVE, beacon, standing osdmap sub
    let m9 = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
    deliver(&mut o, m9, 9);
    assert_eq!(o.state, State::Active, "log: {:?}", o.logs);
    assert_eq!((o.up_epoch, o.boot_epoch), (9, 9));
    assert_eq!(
        count(
            &o,
            |m| matches!(m, AnyMessage::MOSDBeacon(b) if b.version == 9 && b.pgs.is_empty())
        ),
        1
    );
    assert!(
        o.t.subs
            .iter()
            .any(|s| s.0 == "osdmap" && s.1 == 10 && s.2 == 0)
    );
    assert_eq!(o.hb_peer_ids(), vec![0, 1, 2]);
    // a one-shot map request while ACTIVE (YOU_DIED, map gap, PG wait) keeps the osdmap sub standing
    o.mon_sub("osdmap", 10, messages::SubItem::ONETIME);
    assert_eq!(o.t.subs.last(), Some(&("osdmap".to_owned(), 10, 0)));
    let sb = o
        .store
        .as_ref()
        .unwrap()
        .load_superblock()
        .unwrap()
        .unwrap();
    assert_eq!((sb.mounted, sb.clean_thru, sb.current_epoch), (9, 9, 9));
    // beacon cadence: nothing before the interval, then one
    let n = count(&o, |m| matches!(m, AnyMessage::MOSDBeacon(_)));
    o.on_timer(Duration::from_secs(100));
    assert_eq!(count(&o, |m| matches!(m, AnyMessage::MOSDBeacon(_))), n);
    o.on_timer(Duration::from_secs(400));
    assert_eq!(count(&o, |m| matches!(m, AnyMessage::MOSDBeacon(_))), n + 1);
}

#[test]
fn preboot_gates() {
    let mut o = mk_osd("gates");
    o.state = State::Preboot;
    // noup flag
    let mut m = mk_map(5, 4, &[0, 1, 2], &o, 0);
    m.flags |= map_flags::NOUP;
    deliver(&mut o, m, 5);
    assert!(boots(&o).is_empty() && o.state == State::Preboot);
    // sortbitwise missing
    let mut m = mk_map(6, 4, &[0, 1, 2], &o, 0);
    m.flags = 0;
    deliver(&mut o, m, 6);
    assert!(boots(&o).is_empty());
    // far behind the mon: keeps fetching instead of booting
    let m = mk_map(7, 4, &[0, 1, 2], &o, 0);
    deliver(&mut o, m, 100);
    o.preboot(1, 100);
    assert!(boots(&o).is_empty());
    assert!(o.t.subs.iter().any(|s| s.0 == "osdmap" && s.1 == 8));
    // per-osd NOUP
    let mut m = mk_map(8, 4, &[0, 1, 2], &o, 0);
    m.osd_state[3] |= osd_state::NOUP;
    deliver(&mut o, m, 8);
    assert!(boots(&o).is_empty());
    // destroyed in the newest map: clean exit
    let mut m = mk_map(9, 4, &[0, 1, 2], &o, 0);
    m.osd_state[3] |= osd_state::DESTROYED;
    deliver(&mut o, m, 9);
    assert_eq!(o.exit_code(), Some(0));
}

/// A preboot that waits for a map (noup, catching up) does not probe the mon again every tick: the next map or a new
/// mon session re-runs it (spec osd-lifecycle 3.2 re-trigger points); a refused probe is still retried by the tick.
#[test]
fn parked_preboot_does_not_probe_the_mon_every_tick() {
    let mut o = mk_osd("parked");
    o.start_boot();
    assert_eq!((o.state, o.t.version_requests), (State::Preboot, 1));
    let mut m = mk_map(5, 4, &[0, 1, 2], &o, 0);
    m.flags |= map_flags::NOUP;
    o.pending_version = None; // the probe was answered
    deliver(&mut o, m, 5);
    assert!(o.preboot_parked && boots(&o).is_empty());
    for s in 1..=30 {
        o.on_timer(Duration::from_secs(s));
    }
    assert_eq!(
        o.t.version_requests, 1,
        "parked preboot probed the mon again"
    );
    // noup cleared: the map re-runs preboot and boots
    let m = mk_map(6, 4, &[0, 1, 2], &o, 0);
    deliver(&mut o, m, 6);
    assert_eq!(boots(&o).len(), 1);
    // a probe that was refused while the session is up is retried by the tick
    let mut o = mk_osd("refused");
    o.start_boot();
    o.pending_version = None;
    o.on_timer(Duration::from_secs(2));
    assert_eq!(o.t.version_requests, 2);
}

/// CRUSH map with osd.0..3 under host -2 (osd.3, device class 0) / host -3, both under root -1.
fn group_crush() -> Vec<u8> {
    let mut c = crush::CrushMap::new();
    c.type_map = BTreeMap::from([(0, "osd".into()), (1, "host".into()), (10, "root".into())]);
    c.add_bucket(crush::Bucket::straw2(-2, 1, &[(2, 1), (3, 1)]));
    c.add_bucket(crush::Bucket::straw2(-3, 1, &[(0, 1), (1, 1)]));
    c.add_bucket(crush::Bucket::straw2(-1, 10, &[(-2, 2), (-3, 2)]));
    for i in 0..4 {
        c.name_map.insert(i, format!("osd.{i}"));
    }
    c.name_map.insert(-1, "default".into());
    c.name_map.insert(-2, "h1".into());
    c.name_map.insert(-3, "h2".into());
    c.class_name.insert(0, "ssd".into());
    c.class_map.insert(3, 0);
    c.encode()
}

/// `ceph osd set-group noup <bucket|class>` holds the boot like the global / per-OSD flag (spec 3.2); a flag on a
/// bucket we are not under or on another class does not; a group noup change while booting re-boots (classic).
#[test]
fn preboot_honours_group_noup() {
    let mut o = mk_osd("groupnoup");
    o.state = State::Preboot;
    let crush = group_crush();
    let mk = |e: u32, o: &Osd| {
        let mut m = mk_map(e, 4, &[0, 1, 2], o, 0);
        m.set_crush(crush.clone());
        m
    };
    // our host, then the root above it
    for (e, b) in [(5, -2), (6, -1)] {
        let mut m = mk(e, &o);
        m.crush_node_flags.insert(b, osd_state::NOUP);
        deliver(&mut o, m, e);
        assert!(boots(&o).is_empty(), "noup on bucket {b}");
    }
    // our device class
    let mut m = mk(7, &o);
    m.device_class_flags.insert(0, osd_state::NOUP);
    deliver(&mut o, m, 7);
    assert!(boots(&o).is_empty(), "noup on our class");
    // other host / other flag on our host: boot
    let mut m = mk(8, &o);
    m.crush_node_flags.insert(-3, osd_state::NOUP);
    m.crush_node_flags.insert(-2, osd_state::NOOUT);
    deliver(&mut o, m, 8);
    assert_eq!(boots(&o).len(), 1);
    assert_eq!(o.state, State::Booting);
    // a map without a noup change keeps the boot in flight
    let mut m = mk(9, &o);
    m.crush_node_flags.insert(-3, osd_state::NOUP);
    deliver(&mut o, m, 9);
    assert_eq!(o.state, State::Booting);
    // noup appears on our host while the boot is in flight: the boot starts over (preboot, held by noup)
    let mut m = mk(10, &o);
    m.crush_node_flags.insert(-2, osd_state::NOUP);
    deliver(&mut o, m, 10);
    assert_eq!(
        o.state,
        State::Preboot,
        "group noup change while booting restarts the boot"
    );
    assert!(!o.do_restart);
    assert_eq!(boots(&o).len(), 1);
}

#[test]
fn purged_snaps_gate_then_boot() {
    let mut o = mk_osd("purged");
    o.state = State::Preboot;
    // pretend we hold map 5 but never recorded purged snaps (gap): catch-up first
    o.sb.current_epoch = 5;
    o.sb.purged_snaps_last = 0;
    let m = mk_map(5, 4, &[0, 1, 2], &o, 0);
    o.mc.set_osdmap(m.clone());
    o.map = Some(std::sync::Arc::new(m));
    o.preboot(1, 5);
    assert!(boots(&o).is_empty());
    let req =
        o.t.sent
            .iter()
            .find_map(|m| match m {
                AnyMessage::MMonGetPurgedSnaps(r) => Some(r.clone()),
                _ => None,
            })
            .expect("purged snaps request");
    assert_eq!((req.start, req.last), (1, 6));
    o.on_purged_snaps(messages::MMonGetPurgedSnapsReply {
        version: 0,
        start: 1,
        last: 6,
        purged_snaps: BTreeMap::new(),
    });
    assert_eq!(o.sb.purged_snaps_last, 6);
    o.pending_version = None;
    o.start_boot();
    assert_eq!(o.state, State::Preboot);
    o.preboot(1, 5);
    assert_eq!(boots(&o).len(), 1);
}

#[test]
fn wrongly_marked_down_reboots_with_new_nonce() {
    let mut o = mk_osd("wmd");
    o.state = State::Booting;
    o.bind_epoch = 0;
    let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
    deliver(&mut o, m, 9);
    assert_eq!(o.state, State::Active);
    let nonce0 = o.cluster_addrs.0[0].nonce;
    let pub0 = o.public_addrs.clone();
    // the mon marks us down
    let m = mk_map(10, 4, &[0, 1, 2], &o, 0);
    deliver(&mut o, m, 10);
    assert_eq!(o.up_epoch, 0);
    assert_eq!(o.bind_epoch, 10);
    assert_eq!(o.markdown_log.len(), 1);
    assert_ne!(
        o.cluster_addrs.0[0].nonce, nonce0,
        "cluster addr must change"
    );
    assert_eq!(o.public_addrs, pub0, "public messenger keeps identity");
    assert_eq!(
        count(
            &o,
            |m| matches!(m, AnyMessage::MOSDMarkMeDead(d) if d.epoch == 10)
        ),
        1
    );
    assert!(o.state == State::Preboot || o.state == State::WaitingForHealthy);
    // reboot: preboot decides to boot again with boot_epoch kept
    o.pending_version = None;
    o.state = State::Preboot;
    o.preboot(1, 10);
    let b = boots(&o);
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].boot_epoch, 9);
    assert_eq!(b[0].cluster_addrs, o.cluster_addrs);
    // too many markdowns: shut down instead
    o.state = State::Active;
    o.markdown_log = vec![Duration::from_secs(1); 5];
    let m = mk_map(11, 4, &[0, 1, 2], &o, 0);
    deliver(&mut o, m, 11);
    assert!(o.state == State::Stopping || o.exit_code().is_some());
}

/// C2: after a wrong mark-down the OSD rebuilds its heartbeat peers and waits until enough of them answer before it
/// boots again (osd-lifecycle 3.8): without peers it re-booted at once and flapped (map churn per cycle).
#[test]
fn wrongly_marked_down_waits_for_healthy_peers() {
    let mut o = mk_osd("wmd-wait");
    o.state = State::Booting;
    let m = mk_map(9, 6, &[0, 1, 2, 3, 4, 5], &o, 9);
    deliver(&mut o, m, 9);
    assert_eq!(o.state, State::Active);
    let m = mk_map(10, 6, &[0, 1, 2, 4, 5], &o, 0);
    deliver(&mut o, m, 10);
    assert_eq!(
        o.state,
        State::WaitingForHealthy,
        "must not re-boot at once"
    );
    assert_eq!(
        o.hb.peers.keys().copied().collect::<Vec<_>>(),
        [0, 1, 2, 4, 5]
    );
    assert!(!o.is_healthy());
    o.tick();
    assert_eq!(o.state, State::WaitingForHealthy);
    // two of five peers answer on back and front: 2 >= 0.33 * 5 -> boot
    for p in [0, 1] {
        let h = o.hb.peers.get_mut(&p).unwrap();
        h.last_rx_back = Some(o.now);
        h.last_rx_front = Some(o.now);
    }
    o.tick();
    assert_eq!(o.state, State::Preboot);
}

/// A waiting OSD keeps its failure observations to itself: the mon ignores reports from a down reporter.
#[test]
fn waiting_for_healthy_sends_no_failure_reports() {
    let mut o = mk_osd("wmd-nofail");
    o.state = State::Booting;
    let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
    deliver(&mut o, m, 9);
    let m = mk_map(10, 4, &[0, 1, 2], &o, 0);
    deliver(&mut o, m, 10);
    assert_eq!(o.state, State::WaitingForHealthy);
    o.now = Duration::from_secs(100);
    {
        let p = o.hb.peers.get_mut(&0).unwrap();
        p.first_tx = Some(Duration::from_secs(60));
        p.history.insert(
            1,
            crate::hb::Entry::new(Duration::from_secs(80), 2, Duration::ZERO),
        );
    }
    o.tick();
    assert_eq!(count(&o, |m| matches!(m, AnyMessage::MOSDFailure(_))), 0);
}

/// Map of `hosts` x `per` OSDs, all up, with a CRUSH tree root -> host -> osd (ids contiguous per host).
fn hosts_map(hosts: i32, per: i32) -> OsdMap {
    let n = hosts * per;
    let mut m = OsdMap::default();
    m.epoch = 1;
    m.max_osd = n;
    m.osd_state = vec![osd_state::EXISTS | osd_state::UP; n as usize];
    m.osd_weight = vec![0x10000; n as usize];
    m.osd_info = vec![osdmap::OsdInfo::default(); n as usize];
    let mut c = crush::CrushMap::new();
    c.type_map = BTreeMap::from([(0, "osd".into()), (1, "host".into()), (10, "root".into())]);
    let mut root = Vec::new();
    for h in 0..hosts {
        let items: Vec<(i32, u32)> = (h * per..(h + 1) * per).map(|o| (o, 0x10000)).collect();
        c.add_bucket(crush::Bucket::straw2(-2 - h, 1, &items));
        root.push((-2 - h, 0x10000 * per as u32));
    }
    c.add_bucket(crush::Bucket::straw2(-1, 10, &root));
    c.finalize();
    m.set_crush(c.encode());
    m
}

/// C1: with every OSD of one host failed at once, each of them is pinged by OSDs of >= 2 other hosts
/// (`mon_osd_min_down_reporters` = 2 distinct `host` subtrees), without any PG peers. The id-ring-only peer set
/// left the middle of a host covered by the neighbouring host alone (no mark-down for `mon_osd_report_timeout`).
#[test]
fn heartbeat_peers_report_a_failed_host_from_two_other_hosts() {
    for (hosts, per) in [(3, 12), (3, 4), (4, 10), (2, 12), (5, 16)] {
        let map = hosts_map(hosts, per);
        let none = std::collections::BTreeSet::new();
        let peers: Vec<_> = (0..hosts * per)
            .map(|me| {
                crate::hb::want_peers(&map, me, &none, 10, 2, &crate::hb::subtrees(&map, "host"))
            })
            .collect();
        let need = (hosts - 1).min(2) as usize;
        for dead in 0..hosts {
            for t in dead * per..(dead + 1) * per {
                let reporting: std::collections::BTreeSet<i32> = (0..hosts * per)
                    .filter(|o| o / per != dead && peers[*o as usize].contains(&t))
                    .map(|o| o / per)
                    .collect();
                assert!(
                    reporting.len() >= need,
                    "{hosts}x{per}: osd.{t} pinged from hosts {reporting:?}"
                );
            }
        }
        // the subtree pick never adds OSDs of our own host twice and the set reaches min_peers
        for (me, p) in peers.iter().enumerate() {
            assert!(
                p.len() >= 10.min(hosts as usize * per as usize - 1),
                "osd.{me}: {p:?}"
            );
            assert!(!p.contains(&(me as i32)));
        }
    }
}

/// PG peers are always heartbeat peers (when up); a down PG peer is not.
#[test]
fn heartbeat_peers_include_up_pg_peers() {
    let mut map = hosts_map(4, 10);
    map.osd_state[33] &= !osd_state::UP;
    let pg = std::collections::BTreeSet::from([25, 33, 39]);
    let p = crate::hb::want_peers(&map, 0, &pg, 10, 2, &crate::hb::subtrees(&map, "host"));
    assert!(
        p.contains(&25) && p.contains(&39) && !p.contains(&33),
        "{p:?}"
    );
    // stable: the same inputs give the same set (no churn on the periodic recompute)
    assert_eq!(
        p,
        crate::hb::want_peers(&map, 0, &pg, 10, 2, &crate::hb::subtrees(&map, "host"))
    );
}

/// C7: a full map from the mon that does not decode stops the OSD (mark down, exit 1) instead of leaving it up at a
/// stale epoch with its PGs waiting forever.
#[test]
fn undecodable_full_map_stops_the_osd() {
    let mut o = mk_osd("undecodable");
    o.state = State::Booting;
    let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
    deliver(&mut o, m, 9);
    assert_eq!(o.state, State::Active);
    o.stop_on_undecodable_osdmap((10, "bad crc".into()));
    assert_eq!(o.state, State::Stopping);
    assert_eq!(o.fail_code, Some(1));
}

/// `osd_mon_shutdown_timeout` is a float option: 2.5 waits 2.5 s for the mark-down ack, not 2.
#[test]
fn mon_shutdown_timeout_keeps_fractions() {
    let mut o = mk_osd("shutdown-frac");
    o.state = State::Booting;
    let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
    deliver(&mut o, m, 9);
    o.conf
        .set(Level::Mon, "osd_mon_shutdown_timeout", "2.5")
        .unwrap();
    o.begin_shutdown(true);
    assert_eq!(
        o.shutdown_deadline,
        Some(o.now + Duration::from_millis(2500))
    );
}

/// NT-deadcode-04: `osd_fast_shutdown_notify_mon = false` skips the mark-down only for the fast shutdown (default);
/// `osd_fast_shutdown = false` always tells the mon, like classic `prepare_to_stop`.
#[test]
fn full_shutdown_always_notifies_the_mon() {
    for (fast, notify, want) in [
        ("true", "true", true),
        ("true", "false", false),
        ("false", "false", true),
    ] {
        let mut o = mk_osd("shutdown-fast");
        o.state = State::Booting;
        let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
        deliver(&mut o, m, 9);
        o.conf.set(Level::Mon, "osd_fast_shutdown", fast).unwrap();
        o.conf
            .set(Level::Mon, "osd_fast_shutdown_notify_mon", notify)
            .unwrap();
        o.begin_shutdown(true);
        assert_eq!(o.shutdown_notify, want, "fast {fast} notify {notify}");
    }
}

#[test]
fn addr_change_counts_as_wrongly_marked_down() {
    let mut o = mk_osd("addr");
    o.state = State::Booting;
    {
        let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
        deliver(&mut o, m, 9);
    }
    assert_eq!(o.state, State::Active);
    let mut m = mk_map(10, 4, &[0, 1, 2, 3], &o, 9);
    m.cluster_addrs[3] = addr([10, 1, 0, 99], 6801, 1);
    deliver(&mut o, m, 10);
    assert_eq!(o.markdown_log.len(), 1);
    // spec 7.4: log which one, with the addrs the mon has and ours
    let logs = format!("{:?}", o.logs);
    assert!(logs.contains("cluster: map"), "{logs}");
    assert!(logs.contains("10.1.0.99"), "{logs}");
    assert!(logs.contains("10.1.0.4"), "{logs}");
}

/// A want above our map epoch (split gate nudge, up_thru E+1) must still carry `version` = our epoch: the mon parks
/// a message whose version it has not committed (`wait_for_readable`, idle cluster = forever) and records
/// up_thru = version (an epoch we never consumed would over-claim maybe_went_rw).
#[test]
fn alive_version_is_our_epoch_even_when_want_is_ahead() {
    let mut o = mk_osd("alive");
    o.state = State::Booting;
    {
        let mut m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
        m.osd_info[3].up_thru = 9;
        deliver(&mut o, m, 9);
    }
    assert_eq!(o.state, State::Active);
    o.t.sent.clear();
    o.want_up_thru_inner(10);
    let a: Vec<_> =
        o.t.sent
            .iter()
            .filter_map(|m| match m {
                AnyMessage::MOSDAlive(a) => Some((a.version, a.want)),
                _ => None,
            })
            .collect();
    assert_eq!(a, vec![(9, 10)]);
}

#[test]
fn graceful_shutdown_sends_mark_me_down_and_waits_for_ack() {
    let mut o = mk_osd("shut");
    o.state = State::Booting;
    {
        let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
        deliver(&mut o, m, 9);
    }
    assert_eq!(o.state, State::Active);
    o.shutdown(Duration::from_secs(5));
    assert_eq!(o.state, State::Stopping);
    assert!(o.exit_code().is_none());
    let d =
        o.t.sent
            .iter()
            .find_map(|m| match m {
                AnyMessage::MOSDMarkMeDown(d) => Some(d.clone()),
                _ => None,
            })
            .expect("mark me down");
    assert!(d.request_ack && d.down_and_dead);
    assert_eq!((d.target_osd, d.epoch), (3, 9));
    assert_eq!(d.target_addrs, o.public_addrs);
    // ack arrives
    let mut ack = d.clone();
    ack.request_ack = false;
    o.on_mon_message(AnyMessage::MOSDMarkMeDown(ack));
    assert_eq!(o.exit_code(), Some(0));
}

#[test]
fn shutdown_without_ack_times_out() {
    let mut o = mk_osd("shut2");
    o.state = State::Booting;
    {
        let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
        deliver(&mut o, m, 9);
    }
    o.shutdown(Duration::from_secs(5));
    o.on_timer(Duration::from_secs(8));
    assert!(o.exit_code().is_none());
    o.on_timer(Duration::from_secs(11));
    assert_eq!(o.exit_code(), Some(0));
}

#[test]
fn shutdown_while_not_up_exits_at_once() {
    let mut o = mk_osd("shut3");
    o.shutdown(Duration::from_secs(2));
    assert_eq!(o.exit_code(), Some(0));
    assert_eq!(count(&o, |m| matches!(m, AnyMessage::MOSDMarkMeDown(_))), 0);
}

#[test]
fn heartbeat_peer_selection_ring_and_fill() {
    let mut o = mk_osd("hbsel");
    o.state = State::Booting;
    // 15 osds, all up, we are 3
    let up: Vec<i32> = (0..15).collect();
    {
        let m = mk_map(9, 15, &up, &o, 9);
        deliver(&mut o, m, 9);
    }
    let peers = o.hb_peer_ids();
    assert_eq!(peers.len(), 10);
    assert!(
        peers.contains(&4) && peers.contains(&2),
        "next and prev neighbours: {peers:?}"
    );
    assert!(!peers.contains(&3));
    // a peer going down is dropped
    let up2: Vec<i32> = (0..15).filter(|i| *i != 4).collect();
    {
        let m = mk_map(10, 15, &up2, &o, 9);
        deliver(&mut o, m, 10);
    }
    assert!(!o.hb_peer_ids().contains(&4));
}

#[test]
fn ping_gets_reply_and_you_died() {
    let mut o = mk_osd("ping");
    o.state = State::Booting;
    {
        let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
        deliver(&mut o, m, 9);
    }
    // a server-side hb link from osd.1 (fake peer info)
    let id = o.on_accept(
        Listener::HbBack,
        crate::osd::sock4([10, 1, 0, 11], 40000),
        Duration::from_secs(10),
    );
    o.links.get_mut(&id).unwrap().peer = Some(msgr2::PeerInfo {
        name: EntityName::osd(1),
        addrs: addr([10, 1, 0, 11], 40000, 1),
        features: u64::MAX,
        lossy: true,
        resumed: false,
        global_id: 1,
        auth_name: None,
    });
    let p = MOSDPing {
        fsid: FSID,
        map_epoch: 9,
        op: MOSDPing::PING,
        ping_stamp: UTime::new(5, 6),
        pad_len: 1971,
        up_from: 1,
        mono_ping_stamp: messages::span_from_nanos(1_000_000_000),
        mono_send_stamp: messages::span_from_nanos(1_000_000_001),
        delta_ub: None,
    };
    // foreign fsid is dropped silently
    let mut bad = p.clone();
    bad.fsid = Uuid([1; 16]);
    o.on_ping(id, bad);
    let replies = |o: &Osd| o.t.out.iter().filter(|f| f.0 == id).count();
    o.on_ping(id, p.clone());
    // osd.1 is up in our map, so no YOU_DIED: exactly the reply
    assert_eq!(replies(&o), 1);
    // C4: a core stopped making progress (internal watchdog unhealthy): pings are dropped so peers report us down
    let live: &'static crate::liveness::Liveness = Box::leak(Box::default());
    o.set_liveness(live);
    let mut chk = crate::liveness::Checker::default();
    live.beat(2);
    chk.check(live, Duration::from_secs(0), |_| {});
    chk.check(live, Duration::from_secs(16), |_| {});
    assert!(live.unhealthy());
    o.on_ping(id, p.clone());
    assert_eq!(replies(&o), 1, "no reply while unhealthy");
    assert!(!o.is_healthy());
    live.beat(2);
    chk.check(live, Duration::from_secs(17), |_| {});
    o.on_ping(id, p.clone());
    assert_eq!(replies(&o), 2);
    // a ping from an OSD our map does not hold up (osd.7 does not exist): YOU_DIED, padded like every ping
    let dead = o.on_accept(
        Listener::HbBack,
        crate::osd::sock4([10, 1, 0, 17], 40001),
        Duration::from_secs(10),
    );
    o.links.get_mut(&dead).unwrap().peer = Some(msgr2::PeerInfo {
        name: EntityName::osd(7),
        addrs: addr([10, 1, 0, 17], 40001, 1),
        features: u64::MAX,
        lossy: true,
        resumed: false,
        global_id: 2,
        auth_name: None,
    });
    o.on_ping(dead, p);
    let f =
        o.t.out
            .iter()
            .rfind(|f| f.0 == dead)
            .expect("YOU_DIED sent");
    let y = <MOSDPing as messages::Message>::decode(f.2.1, &f.3.front, &[], &[]).unwrap();
    assert_eq!(y.op, MOSDPing::YOU_DIED);
    assert_eq!(
        y.pad_len,
        MOSDPing::pad_len_for(2000),
        "osd_heartbeat_min_size padding"
    );
    assert!(y.pad_len > 0);
}

/// MOSDFull carries the osdmap epoch as its PSM version (classic): the mon replies with incrementals from there,
/// a version of 0 would make it send a full map.
#[test]
fn full_report_psm_version_is_map_epoch() {
    let mut o = mk_osd("fullver");
    o.state = State::Booting;
    {
        let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
        deliver(&mut o, m, 9);
    }
    o.t.sent.clear();
    o.send_full();
    let v =
        o.t.sent
            .iter()
            .find_map(|m| match m {
                messages::AnyMessage::MOSDFull(f) => Some((f.version, f.map_epoch)),
                _ => None,
            })
            .expect("MOSDFull sent");
    assert_eq!(v, (9, 9));
    // same for MOSDPGTemp (every pg_temp request goes through `send_pg_temp`)
    o.t.sent.clear();
    o.send_pg_temp(std::iter::once((denc::types::PgT::new(1, 0), vec![0, 1])).collect());
    let v =
        o.t.sent
            .iter()
            .find_map(|m| match m {
                messages::AnyMessage::MOSDPGTemp(t) => Some((t.version, t.map_epoch)),
                _ => None,
            })
            .expect("MOSDPGTemp sent");
    assert_eq!(v, (9, 9));
}

/// spec 4: the first msgr2 entry is the target. Our OSD holds IPv4 only, so a dual-stack peer that lists IPv6 first
/// (classic default order) is dialled on its IPv4 v2 entry, and the source bind is our cluster address of that family.
#[test]
fn dial_uses_the_peer_entry_of_a_family_we_bind() {
    let mut o = mk_osd("dial-family");
    o.state = State::Booting;
    let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
    deliver(&mut o, m, 9);
    let peer = EntityAddrVec(vec![
        EntityAddr::v6(
            EntityAddr::TYPE_MSGR2,
            7,
            "fd00:77::21"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
            6800,
            0,
        ),
        EntityAddr::v6(
            EntityAddr::TYPE_LEGACY,
            7,
            "fd00:77::21"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
            6789,
            0,
        ),
        EntityAddr::v4(EntityAddr::TYPE_MSGR2, 7, [10, 0, 0, 21], 6800),
        EntityAddr::v4(EntityAddr::TYPE_LEGACY, 7, [10, 0, 0, 21], 6789),
    ]);
    let id = o
        .dial(MsgrId::Cluster, Purpose::Peer(1), EntityName::OSD, &peer)
        .expect("a family we bind");
    o.pump();
    let mut got = None;
    while let Some(c) = o.poll_io() {
        if let IoCmd::Dial { conn, target, src } = c
            && conn == id
        {
            got = Some((target, src));
        }
    }
    let (target, src) = got.expect("dial issued");
    assert_eq!(
        target, peer.0[2],
        "the IPv4 v2 entry, not the IPv6 first entry"
    );
    assert_eq!(src, Some(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 4))));
}

/// A peer that only advertises a family we do not bind is not dialled at all (no link, no queued ping, hence no failure
/// report, spec 8), and the reason is logged loudly once.
#[test]
fn a_peer_of_an_unbound_family_is_not_dialled() {
    let mut o = mk_osd("dial-nofamily");
    o.state = State::Booting;
    let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
    deliver(&mut o, m, 9);
    let v6 = "fd00:77::21"
        .parse::<std::net::Ipv6Addr>()
        .unwrap()
        .octets();
    let peer = EntityAddrVec::single(EntityAddr::v6(EntityAddr::TYPE_MSGR2, 7, v6, 6800, 0));
    assert!(
        o.dial(MsgrId::Cluster, Purpose::Peer(1), EntityName::OSD, &peer)
            .is_none()
    );
    o.pump();
    while let Some(c) = o.poll_io() {
        if let IoCmd::Dial { target, .. } = c {
            assert!(
                target.ip().is_none_or(|ip| ip.is_ipv4()),
                "no socket for a family we cannot speak: {target}"
            );
        }
    }
    let logged: Vec<String> = std::iter::from_fn(|| o.poll_log())
        .map(|l| l.text)
        .filter(|l| l.contains("cannot reach"))
        .collect();
    assert_eq!(logged.len(), 1, "{logged:?}");
    assert!(logged[0].contains("fd00:77::21"), "{}", logged[0]);
    // retried every round: the line is not repeated
    let _ = o.dial(MsgrId::Cluster, Purpose::Peer(1), EntityName::OSD, &peer);
    let again: Vec<String> = std::iter::from_fn(|| o.poll_log())
        .map(|l| l.text)
        .filter(|l| l.contains("cannot reach"))
        .collect();
    assert!(again.is_empty(), "{again:?}");
}

/// A classic peer with one explicit IPv6 address and both families enabled advertises a wildcard entry for the other
/// family (`[v2:[v6]:p, v2:0.0.0.0:p+1]`). Our IPv4-only OSD must not dial `0.0.0.0` (it reaches this host, not the
/// peer): no dial, and the unreachable peer is logged.
#[test]
fn a_wildcard_peer_entry_is_never_dialled() {
    let mut o = mk_osd("dial-wildcard");
    o.state = State::Booting;
    let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
    deliver(&mut o, m, 9);
    let v6 = "fd00:77::10"
        .parse::<std::net::Ipv6Addr>()
        .unwrap()
        .octets();
    let peer = EntityAddrVec(vec![
        EntityAddr::v6(EntityAddr::TYPE_MSGR2, 7, v6, 6801, 0),
        EntityAddr::v4(EntityAddr::TYPE_MSGR2, 7, [0, 0, 0, 0], 6802),
    ]);
    assert!(
        o.dial(MsgrId::Cluster, Purpose::Peer(1), EntityName::OSD, &peer)
            .is_none()
    );
    o.pump();
    while let Some(c) = o.poll_io() {
        if let IoCmd::Dial { target, .. } = c {
            assert!(
                target.ip().is_none_or(|ip| !ip.is_unspecified()),
                "dialled a wildcard address: {target}"
            );
        }
    }
    assert!(
        std::iter::from_fn(|| o.poll_log()).any(|l| l.text.contains("cannot reach")),
        "the unreachable peer is logged"
    );
}

/// S: heartbeat to a classic dual-stack peer whose IPv6 entry comes first must not end in a failure report just
/// because we cannot dial IPv6. The IPv4 entry is dialled; with no reachable family nothing is queued at all.
#[test]
fn heartbeat_never_reports_a_peer_it_cannot_dial_by_family() {
    let mut o = mk_osd("hb-family");
    o.state = State::Booting;
    let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
    deliver(&mut o, m, 9);
    assert_eq!(o.state, State::Active);
    let v6 = "fd00:77::20"
        .parse::<std::net::Ipv6Addr>()
        .unwrap()
        .octets();
    // peer 0: v6 only (a classic peer with ms_bind_ipv4=false) -> nothing to dial for us
    let only6 = EntityAddrVec(vec![
        EntityAddr::v6(EntityAddr::TYPE_MSGR2, 7, v6, 6800, 0),
        EntityAddr::v6(EntityAddr::TYPE_LEGACY, 7, v6, 6789, 0),
    ]);
    // peer 1: dual stack, v6 first -> its v4 entry is dialled
    let both = EntityAddrVec(vec![
        EntityAddr::v6(EntityAddr::TYPE_MSGR2, 8, v6, 6800, 0),
        EntityAddr::v6(EntityAddr::TYPE_LEGACY, 8, v6, 6789, 0),
        EntityAddr::v4(EntityAddr::TYPE_MSGR2, 8, [10, 0, 0, 20], 6800),
        EntityAddr::v4(EntityAddr::TYPE_LEGACY, 8, [10, 0, 0, 20], 6789),
    ]);
    for (osd, addrs) in [(0, only6), (1, both)] {
        o.hb.peers.insert(
            osd,
            crate::hb::HbPeer {
                up_from: 1,
                back_addrs: addrs.clone(),
                front_addrs: addrs,
                ..Default::default()
            },
        );
    }
    o.now = Duration::from_secs(100);
    // keep the peers as inserted: a peer refresh would take the map's (v4) addresses instead
    o.hb.last_update = o.now;
    o.hb_round();
    let p0 = &o.hb.peers[&0];
    assert!(p0.back.is_none() && p0.front.is_none(), "no link to dial");
    assert!(p0.history.is_empty(), "no ping queued, no deadline");
    assert!(p0.first_tx.is_none());
    let p1 = &o.hb.peers[&1];
    assert!(p1.back.is_some() && p1.front.is_some());
    // long after the grace the unreachable peer has produced no failure report
    o.now += Duration::from_secs(120);
    o.heartbeat_check();
    assert!(!o.hb.failure_queue.contains_key(&0));
    assert_eq!(count(&o, |m| matches!(m, AnyMessage::MOSDFailure(_))), 0);
}

#[test]
fn heartbeat_withdrawal_survives_monitor_session_loss() {
    let mut o = mk_osd("hb-withdraw-mon-loss");
    o.state = State::Booting;
    let map = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
    deliver(&mut o, map, 9);
    o.now = Duration::from_secs(100);
    o.on_hb_refused(1, true);
    let addrs = o.hb.failure_pending[&1].1.clone();
    let reports = count(&o, |m| matches!(m, AnyMessage::MOSDFailure(_)));

    // The heartbeat recovers while the public monitor connection is partitioned.
    o.t.mon_send_unavailable = true;
    o.hb_cancel_failure(1);
    assert!(!o.hb.failure_pending.contains_key(&1));
    assert!(!o.hb.failure_queue.contains_key(&1));
    assert_eq!(
        count(&o, |m| matches!(m, AnyMessage::MOSDFailure(_))),
        reports
    );
    // Leaving the heartbeat set must not discard the monitor's outstanding withdrawal.
    o.hb_peer_down(1);
    o.t.mon_send_unavailable = false;
    o.hb_requeue_failures();
    assert!(o.hb.failure_cancelling.is_empty());
    let withdrawal =
        o.t.sent
            .iter()
            .rev()
            .find_map(|m| match m {
                AnyMessage::MOSDFailure(f) => Some(f),
                _ => None,
            })
            .unwrap();
    assert_eq!(withdrawal.target_osd, 1);
    assert_eq!(withdrawal.target_addrs, addrs);
    assert_eq!(withdrawal.flags, MOSDFailure::FLAG_ALIVE);
    assert_eq!(withdrawal.failed_for, 0);
    o.hb_requeue_failures();
    assert_eq!(
        count(&o, |m| matches!(m, AnyMessage::MOSDFailure(_))),
        reports + 1
    );
}

#[test]
fn heartbeat_new_failure_supersedes_undelivered_withdrawal() {
    for immediate in [false, true] {
        let mut o = mk_osd(&format!("hb-withdraw-new-failure-{immediate}"));
        o.state = State::Booting;
        let map = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
        deliver(&mut o, map, 9);
        o.now = Duration::from_secs(100);
        o.on_hb_refused(1, true);
        o.t.mon_send_unavailable = true;
        o.hb_cancel_failure(1);
        assert!(o.hb.failure_cancelling.contains_key(&1));
        o.t.mon_send_unavailable = false;
        if immediate {
            o.on_hb_refused(1, true);
        } else {
            o.hb.failure_queue.insert(
                1,
                crate::hb::Failure {
                    since: o.now,
                    back: true,
                    front: false,
                },
            );
            o.flush_failures();
        }
        assert!(o.hb.failure_cancelling.is_empty());
        assert!(o.hb.failure_pending.contains_key(&1));
        let sent = o.t.sent.len();
        o.hb_requeue_failures();
        assert_eq!(o.t.sent.len(), sent + 1);
        assert!(matches!(o.t.sent.last(), Some(AnyMessage::MOSDFailure(f))
            if f.target_osd == 1 && f.flags & MOSDFailure::FLAG_FAILED != 0));
    }
}

#[test]
fn failure_report_then_cancel() {
    let mut o = mk_osd("fail");
    o.state = State::Booting;
    {
        let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
        deliver(&mut o, m, 9);
    }
    assert_eq!(o.state, State::Active);
    // peer 0 was pinged long ago and never answered
    let now = Duration::from_secs(100);
    o.now = now;
    {
        let p = o.hb.peers.get_mut(&0).unwrap();
        p.first_tx = Some(Duration::from_secs(60));
        p.last_tx = Some(Duration::from_secs(60));
        p.history.insert(
            1,
            crate::hb::Entry::new(Duration::from_secs(80), 2, Duration::ZERO),
        );
    }
    o.heartbeat_check();
    assert!(o.hb.failure_queue.contains_key(&0));
    o.flush_failures();
    let f: Vec<_> =
        o.t.sent
            .iter()
            .filter_map(|m| match m {
                AnyMessage::MOSDFailure(f) => Some(f.clone()),
                _ => None,
            })
            .collect();
    assert_eq!(f.len(), 1);
    assert_eq!(
        (f[0].target_osd, f[0].flags, f[0].failed_for, f[0].epoch),
        (0, 1, 40, 9)
    );
    assert_eq!(f[0].target_addrs, o.map.as_ref().unwrap().client_addrs[0]);
    // not re-sent while pending
    o.flush_failures();
    assert_eq!(count(&o, |m| matches!(m, AnyMessage::MOSDFailure(_))), 1);
    // peer answers again -> cancel with flags ALIVE
    o.hb_cancel_failure(0);
    let last =
        o.t.sent
            .iter()
            .rev()
            .find_map(|m| match m {
                AnyMessage::MOSDFailure(f) => Some(f.clone()),
                _ => None,
            })
            .unwrap();
    assert_eq!((last.flags, last.failed_for), (MOSDFailure::FLAG_ALIVE, 0));
    // connection refused -> immediate failure
    o.on_hb_refused(1, true);
    let last =
        o.t.sent
            .iter()
            .rev()
            .find_map(|m| match m {
                AnyMessage::MOSDFailure(f) => Some(f.clone()),
                _ => None,
            })
            .unwrap();
    assert_eq!(last.target_osd, 1);
    assert_eq!(
        last.flags,
        MOSDFailure::FLAG_FAILED | MOSDFailure::FLAG_IMMEDIATE
    );
    assert_eq!(last.failed_for, 21);
}

/// A one-NIC flap names the silent path (back vs front), the peer address on that path, and the local address/interface
/// (CS-5247 / CS-5002). The front path that keeps answering is not named.
#[test]
fn heartbeat_failure_log_names_the_failed_path_and_endpoints() {
    let mut o = mk_osd("hb-fail-path");
    o.state = State::Booting;
    let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
    deliver(&mut o, m, 9);
    assert_eq!(o.state, State::Active);
    o.cfg
        .sys_metadata
        .insert("front_iface".into(), "eth0".into());
    o.cfg
        .sys_metadata
        .insert("back_iface".into(), "eth1".into());
    let now = Duration::from_secs(100);
    o.now = now;
    {
        let p = o.hb.peers.get_mut(&0).unwrap();
        p.first_tx = Some(Duration::from_secs(60));
        p.last_tx = Some(Duration::from_secs(60));
        p.history.insert(
            1,
            crate::hb::Entry::new(Duration::from_secs(80), 2, Duration::ZERO),
        );
        // only the back path is silent: the front replied well within the grace window
        p.last_rx_front = Some(Duration::from_secs(95));
    }
    o.heartbeat_check();
    let f = o.hb.failure_queue[&0];
    assert!(f.back && !f.front, "the back path is silent: {f:?}");
    o.flush_failures();
    let line = o
        .logs
        .iter()
        .find(|l| l.contains("reporting osd.0 failed"))
        .unwrap();
    assert!(line.contains("back path"), "{line}");
    assert!(!line.contains("front path"), "{line}");
    assert!(line.contains("10.1.0.10"), "back peer address: {line}");
    assert!(line.contains("10.1.0.4"), "local cluster address: {line}");
    assert!(line.contains("eth1"), "back interface: {line}");
}

/// The dial-warning key distinguishes the front and back heartbeat messengers, so a one-NIC flap is deduplicated per
/// direction, never collapsed into one entry (CS-5247 / CS-5002).
#[test]
fn dial_warn_key_distinguishes_heartbeat_directions() {
    use crate::osd::{DialWarn, MsgrId, Purpose};
    let front = DialWarn::Failed(Purpose::Hb(1), 4, MsgrId::HbFrontCli);
    let back = DialWarn::Failed(Purpose::Hb(1), 4, MsgrId::HbBackCli);
    assert_ne!(front, back);
    let mut set = BTreeSet::new();
    assert!(set.insert(front));
    assert!(
        set.insert(back),
        "front and back must not collapse: {set:?}"
    );
    let unreachable_front = DialWarn::Unreachable(Purpose::Hb(1), MsgrId::HbFrontCli);
    let unreachable_back = DialWarn::Unreachable(Purpose::Hb(1), MsgrId::HbBackCli);
    assert_ne!(unreachable_front, unreachable_back);
}

/// Disabling heartbeat randomization uses the configured interval exactly (lifecycle spec 5.3).
#[test]
fn heartbeat_without_randomization_uses_exact_interval() {
    let mut o = mk_osd("hb-exact-interval");
    o.conf
        .set(
            crate::config::Level::Override,
            "debug_disable_randomized_ping",
            "true",
        )
        .unwrap();
    for interval in [1, 6, 60] {
        o.conf
            .set(
                crate::config::Level::Override,
                "osd_heartbeat_interval",
                &interval.to_string(),
            )
            .unwrap();
        o.now = Duration::from_secs(100);
        o.hb_round();
        assert_eq!(o.hb.next_round, Some(o.now + Duration::from_secs(interval)));
    }
}

#[test]
fn crush_commands() {
    let mut o = mk_osd("crush");
    o.conf
        .set(Level::Mon, "osd_crush_initial_weight", "0.000000")
        .unwrap();
    let c = o.crush_create_or_move_cmd();
    let v: serde_json::Value = serde_json::from_str(&c).unwrap();
    assert_eq!(v["prefix"], "osd crush create-or-move");
    assert_eq!(v["id"], 3);
    assert_eq!(v["weight"], 0.0);
    assert_eq!(v["args"], serde_json::json!(["host=h1", "root=default"]));
    // capacity based weight: 8 GiB = 0.0078 TiB
    o.conf
        .set(Level::Mon, "osd_crush_initial_weight", "-1")
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&o.crush_create_or_move_cmd()).unwrap();
    assert_eq!(v["weight"], 0.0078);
    // the location is fixed at start from the local config: any classic separator, sorted by type
    let o = mk_osd_with(
        "crush-loc",
        conf(&[("crush_location", "rack=r1,host=h9;root=default")]),
    );
    let v: serde_json::Value = serde_json::from_str(&o.crush_create_or_move_cmd()).unwrap();
    assert_eq!(
        v["args"],
        serde_json::json!(["host=h9", "rack=r1", "root=default"])
    );
}

/// An unusable `crush_location` refuses the start: never a partial location, never the default under `root=default`.
#[test]
fn bad_crush_location_refuses_the_start() {
    let key = cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, UTime::new(1, 0))
        .unwrap()
        .to_base64()
        .unwrap();
    for bad in ["root=default host", "root=default host=we!rd"] {
        let e = try_mk_osd(
            "crush-bad",
            key.clone(),
            conf(&[("crush_location", bad)]),
            false,
            false,
        )
        .expect_err("refused");
        assert!(e.contains("crush_location"), "{e}");
    }
}

#[test]
fn init_sequence_runs_class_then_location_and_handles_enoent() {
    let mut o = mk_osd("init");
    o.init = Init::WaitAuth;
    o.state = State::Initializing;
    o.keys
        .set(cephx::MonAuthClient::new(cephx::MonAuthConfig::osd(
            cephx::none::EntityName {
                ty: 4,
                id: "3".into(),
            },
            cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, UTime::new(1, 0)).unwrap(),
        )));
    // without rotating keys we stay in WaitKeys
    o.on_mon_session();
    assert!(matches!(o.init, Init::WaitKeys { .. }));
    // pretend keys + config arrived
    o.init = Init::WaitConfig { since: o.now };
    o.cfg_seen = true;
    o.init_advance();
    assert_eq!(o.init, Init::CrushClass);
    let (tid, kind) = o.init_cmd.unwrap();
    assert_eq!(kind, InitCmd::Class);
    o.on_mon_event(MonEvent::CommandOnceReply {
        tid,
        version: 99,
        r: 0,
        rs: "client control".into(),
        cmd: vec![],
        data: vec![],
    });
    o.on_mon_event(MonEvent::CommandOnceLost { tid });
    assert_eq!(o.init, Init::CrushClass);
    assert_eq!(o.init_cmd, Some((tid, kind)));
    // device class: EBUSY counts as success
    o.on_mon_event(MonEvent::CommandReply {
        tid,
        r: -16,
        rs: "has class".into(),
        data: vec![],
    });
    assert_eq!(o.init, Init::CrushLoc);
    let (tid, kind) = o.init_cmd.unwrap();
    assert_eq!(kind, InitCmd::Loc);
    // ENOENT: osd create once, then retry
    o.on_mon_event(MonEvent::CommandReply {
        tid,
        r: -2,
        rs: "no osd".into(),
        data: vec![],
    });
    let (tid, kind) = o.init_cmd.unwrap();
    assert_eq!(kind, InitCmd::Create);
    o.on_mon_event(MonEvent::CommandReply {
        tid,
        r: 0,
        rs: "".into(),
        data: vec![],
    });
    let (tid, kind) = o.init_cmd.unwrap();
    assert_eq!(kind, InitCmd::Loc);
    o.on_mon_event(MonEvent::CommandReply {
        tid,
        r: 0,
        rs: "moved".into(),
        data: vec![],
    });
    assert_eq!(o.init, Init::Done);
    assert_eq!(o.state, State::Preboot);
    assert!(
        o.t.subs.iter().any(|s| s.0 == "mgrmap")
            && o.t.subs.iter().any(|s| s.0 == "osd_pg_creates")
    );
}

#[test]
fn init_crush_commands_warn_while_waiting_for_the_mon_and_complete_on_reply() {
    let mut o = mk_osd("crush-wait-warn");
    o.init = Init::WaitAuth;
    o.state = State::Initializing;
    o.keys
        .set(cephx::MonAuthClient::new(cephx::MonAuthConfig::osd(
            cephx::none::EntityName {
                ty: 4,
                id: "3".into(),
            },
            cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, UTime::new(1, 0)).unwrap(),
        )));
    o.on_mon_session();
    o.init = Init::WaitConfig { since: o.now };
    o.cfg_seen = true;
    o.init_advance();
    assert_eq!(o.init, Init::CrushClass);
    let (tid, kind) = o.init_cmd.unwrap();
    assert_eq!(kind, InitCmd::Class);
    let sent = o.now;
    while o.poll_log().is_some() {} // drop startup lines before timing the wait

    let warn = |o: &mut Osd, s: u64| {
        o.set_now(sent + Duration::from_secs(s));
        o.init_advance();
        std::iter::from_fn(|| o.poll_log().map(|l| l.text)).collect::<Vec<_>>()
    };

    // still silent just before the first line
    assert!(warn(&mut o, 29).is_empty(), "no warning before 30s");

    // first loud line at 30s
    let l = warn(&mut o, 30);
    assert!(
        l.iter().any(
            |t| t == "WARNING TIMEOUT osd crush set-device-class exceeded 30s (still waiting for the mon)"
        ),
        "{l:?}"
    );

    // silent until the next interval
    assert!(warn(&mut o, 89).is_empty());

    // second loud line at 90s
    let l = warn(&mut o, 90);
    assert!(
        l.iter().any(
            |t| t == "WARNING TIMEOUT osd crush set-device-class exceeded 90s (still waiting for the mon)"
        ),
        "{l:?}"
    );

    // the reply advances the boot: CrushLoc command, then Done
    o.on_mon_event(MonEvent::CommandReply {
        tid,
        r: 0,
        rs: "set".into(),
        data: vec![],
    });
    assert_eq!(o.init, Init::CrushLoc);
    let (tid, kind) = o.init_cmd.unwrap();
    assert_eq!(kind, InitCmd::Loc);
    o.on_mon_event(MonEvent::CommandReply {
        tid,
        r: 0,
        rs: "moved".into(),
        data: vec![],
    });
    assert_eq!(o.init, Init::Done);
    assert_eq!(o.state, State::Preboot);
}

#[test]
fn tell_commands() {
    let mut o = mk_osd("tell");
    let run = |o: &mut Osd, c: &str| {
        let (r, rs, out) = o
            .run_command(c, &crate::tell::ReplyTo::Asok(0))
            .expect("sync command");
        (
            r,
            rs,
            String::from_utf8_lossy(&out.into_bytes()).into_owned(),
        )
    };
    let (r, _, out) = run(&mut o, r#"{"prefix":"version"}"#);
    assert_eq!(r, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["version"], crate::version::CEPH_VERSION_SHORT);
    // OSD-level scrub commands are accepted (no PGs hosted here: nothing to scrub, still a clean answer)
    for (c, what) in [
        (r#"{"prefix":"scrub"}"#, "all pgs on osd.3 to scrub"),
        (
            r#"{"prefix":"deep-scrub"}"#,
            "all pgs on osd.3 to deep-scrub",
        ),
        (r#"{"prefix":"repair"}"#, "all pgs on osd.3 to repair"),
        (
            r#"{"prefix":"deep-scrub","pgid":"1.0"}"#,
            "pg 1.0 on osd.3 to deep-scrub",
        ),
    ] {
        let (r, rs, _) = run(&mut o, c);
        assert_eq!(r, 0, "{c}");
        assert!(rs.ends_with(what), "{rs}");
    }
    assert_eq!(run(&mut o, r#"{"prefix":"scrub","pgid":"zz"}"#).0, -22);
    let (r, _, out) = run(&mut o, r#"{"prefix":"status"}"#);
    assert_eq!(r, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        (v["whoami"].as_i64(), v["state"].as_str()),
        (Some(3), Some("initializing"))
    );
    let (r, _, out) = run(
        &mut o,
        r#"{"prefix":"config get","var":"osd_heartbeat_grace"}"#,
    );
    assert_eq!((r, out.as_str()), (0, r#"{"osd_heartbeat_grace":"20"}"#));
    let (r, ..) = run(
        &mut o,
        r#"{"prefix":"config set","var":"osd_heartbeat_grace","val":["30"]}"#,
    );
    assert_eq!(r, 0);
    assert_eq!(o.conf.u64("osd_heartbeat_grace", 0), 30);
    let (r, ..) = run(
        &mut o,
        r#"{"prefix":"injectargs","injected_args":["--osd_heartbeat_grace=25 --osd-heartbeat-interval","3"]}"#,
    );
    assert_eq!(r, 0);
    assert_eq!(
        (
            o.conf.u64("osd_heartbeat_grace", 0),
            o.conf.u64("osd_heartbeat_interval", 0)
        ),
        (25, 3)
    );
    let (r, ..) = run(
        &mut o,
        r#"{"prefix":"config unset","var":"osd_heartbeat_grace"}"#,
    );
    assert_eq!((r, o.conf.u64("osd_heartbeat_grace", 0)), (0, 20));
    let (r, _, _) = run(&mut o, r#"{"prefix":"config get","var":"no_such_option"}"#);
    assert_eq!(r, -2);
    // spec osd-lifecycle.md 9.1: unknown name -ENOENT, invalid value -EINVAL, the value stays
    let (r, rs, _) = run(
        &mut o,
        r#"{"prefix":"config set","var":"no_such_option","val":["1"]}"#,
    );
    assert_eq!(
        (r, rs.as_str()),
        (
            -2,
            "error setting 'no_such_option' to '1': (2) No such file or directory"
        )
    );
    let (r, rs, _) = run(
        &mut o,
        r#"{"prefix":"config set","var":"osd_heartbeat_grace","val":["1.5"]}"#,
    );
    assert_eq!(
        (r, rs.as_str()),
        (
            -22,
            "error setting 'osd_heartbeat_grace' to '1.5': (22) Invalid argument"
        )
    );
    assert_eq!(o.conf.u64("osd_heartbeat_grace", 0), 20);
    let (r, ..) = run(
        &mut o,
        r#"{"prefix":"config set","var":"osd_memory_target","val":["6G"]}"#,
    );
    assert_eq!(r, 0);
    assert_eq!(o.conf.get("osd_memory_target"), Some("6442450944"));
    let (r, rs, out) = run(
        &mut o,
        r#"{"prefix":"injectargs","injected_args":["--osd_heartbeat_grace=x --osd_heartbeat_interval=4 --bogus=1"]}"#,
    );
    assert_eq!(r, -22, "{rs}");
    assert!(
        rs.contains("osd_heartbeat_grace") && rs.contains("--bogus=1"),
        "{rs}"
    );
    assert!(out.is_empty(), "an error reply has an empty body");
    assert_eq!(o.conf.u64("osd_heartbeat_grace", 0), 20);
    assert_eq!(
        o.conf.u64("osd_heartbeat_interval", 0),
        4,
        "a token before the failing one stays applied"
    );
    // config show: flat map with the fields ceph-exporter needs
    let (r, _, out) = run(&mut o, r#"{"prefix":"config show"}"#);
    assert_eq!(r, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        (
            v["name"].as_str(),
            v["cluster"].as_str(),
            v["pid_file"].as_str()
        ),
        (Some("osd.3"), Some("ceph"), Some(""))
    );
    let (r, rs, _) = run(&mut o, r#"{"prefix":"bogus thing"}"#);
    assert_eq!(
        (r, rs.as_str()),
        (-22, "unknown command prefix bogus thing")
    );
    let (r, ..) = run(&mut o, "not json");
    assert_eq!(r, -22);
    // every advertised command is dispatchable (no -ENOENT)
    let (r, _, out) = run(&mut o, r#"{"prefix":"get_command_descriptions"}"#);
    assert_eq!(r, 0);
    let d: serde_json::Value = serde_json::from_str(&out).unwrap();
    for (_, c) in d.as_object().unwrap() {
        let words: Vec<&str> = c["sig"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|x| x.as_str())
            .collect();
        let prefix = words.join(" ");
        // bench and scrub_purged_snaps answer later (chunked, see tellx_tests)
        if matches!(
            prefix.as_str(),
            "debug_up_thru" | "lab_panic" | "bench" | "scrub_purged_snaps"
        ) {
            continue;
        }
        let cmd = format!(r#"{{"prefix":"{prefix}","var":"osd_heartbeat_grace","epoch":1}}"#);
        let (r, ..) = run(&mut o, &cmd);
        assert_ne!(r, -2, "advertised command {prefix} not implemented");
    }
    let (r, _, out) = run(&mut o, r#"{"prefix":"perf dump"}"#);
    assert_eq!(r, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(v["osd"]["op"].is_number() && v["osd"]["stat_bytes"].as_u64().unwrap() > 0);
}

#[test]
fn mgr_report_counters_are_sorted_and_stat_is_sane() {
    let mut o = mk_osd("mgr");
    let c = o.counters_now();
    let keys: Vec<_> = c.keys().cloned().collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
    for k in [
        "osd.op",
        "osd.stat_bytes",
        "osd.numpg",
        "osd.op_latency",
        "osd.stat_bytes_avail",
    ] {
        assert!(c.contains_key(k), "{k}");
    }
    let s = o.osd_stat();
    assert_eq!((s.num_osds, s.num_per_pool_osds), (1, 1));
    assert_eq!(
        s.num_per_pool_omap_osds, 0,
        "OMAP uses primary PG scrub stats"
    );
    assert_eq!(s.kb, (8u64 << 30 >> 10) as i64);
    let s2 = o.osd_stat();
    assert_eq!(s2.seq, s.seq + 1);
    // threshold filters low-priority counters; declared once
    let mut rep = messages::PerfReporter::new();
    let a = rep.build(&c, 5).unwrap();
    let b = rep.build(&c, 5).unwrap();
    assert!(!a.declare_types.is_empty() && b.declare_types.is_empty());
    assert!(
        !a.declare_types
            .iter()
            .any(|t| t.path == "osd.stat_bytes_avail")
    );
}

#[test]
fn clog_prio_values_are_wire_values() {
    assert_eq!((clog::WARN, clog::INFO), (3, 1));
}

#[test]
fn pg_host_starts_empty_and_follows_maps() {
    let mut o = mk_osd("pgs");
    // DevMemStore: nothing survives a restart, a new OSD claims no PGs
    assert_eq!(o.pg_num_pgs(), 0);
    assert!(peering::PgStoreOps::list_pgs(&o.pg.store).is_empty());
    let m = mk_map(5, 6, &[0, 1, 2, 3], &o, 4);
    deliver(&mut o, m, 5);
    assert_eq!(o.pg.set.epoch(), 5);
    assert_eq!(
        o.pg_collect().0,
        5,
        "no primary PGs: min_last_epoch_clean = map epoch"
    );
    assert!(o.pg_stat_list().is_empty());
}

/// Review findings 2 and 9: peer flavor (croit-flashstore-osd or classic) is asked per OSD (`osd metadata <id>`), only for new or
/// restarted OSDs, and an OSD whose `up_from` changed is forgotten (classic until answered) before the PGs see the
/// map that shows its restart.
#[test]
fn peer_flavor_is_asked_per_new_osd_and_forgotten_on_restart() {
    let mut o = mk_osd("flavor");
    let m = mk_map(5, 6, &[0, 1, 2, 3], &o, 4);
    deliver(&mut o, m, 5);
    let mut asked: Vec<(i32, u32)> = o.pg.peer_meta.values().copied().collect();
    asked.sort();
    assert_eq!(asked, vec![(0, 1), (1, 1), (2, 1)], "one query per peer");
    let tids: Vec<(u64, i32)> =
        o.pg.peer_meta
            .iter()
            .map(|(t, (id, _))| (*t, *id))
            .collect();
    for (tid, id) in tids {
        let data = if id == 1 {
            br#"{"id":1,"flashstore_version":"x"}"#.to_vec()
        } else {
            br#"{"id":0,"ceph_version":"y"}"#.to_vec()
        };
        o.on_mon_event(MonEvent::CommandReply {
            tid,
            r: 0,
            rs: String::new(),
            data,
        });
    }
    assert!(o.pg.peer_meta.is_empty());
    assert_eq!(o.pg.peer_nv, std::collections::BTreeSet::from([1]));
    // osd.1 restarted (maybe as classic), the others did not: only osd.1 is forgotten and asked again
    let mut m = mk_map(6, 6, &[0, 1, 2, 3], &o, 4);
    m.osd_info[1].up_from = 6;
    deliver(&mut o, m, 6);
    assert!(
        o.pg.peer_nv.is_empty(),
        "restarted peer must count as classic"
    );
    let asked: Vec<(i32, u32)> = o.pg.peer_meta.values().copied().collect();
    assert_eq!(asked, vec![(1, 6)], "only the restarted OSD is asked");
    // a reply that is not ours is left alone
    assert!(!o.pg_on_peer_meta(u64::MAX, 0, b"{}"));
}

#[test]
fn boot_below_monitor_admission_is_sent_like_classic_and_warns() {
    // The pinned monitor ignores a SERVER_UMBRELLA boot below squid; classic ceph-osd still
    // sends it and stays booting, so raising the release later admits it without a restart.
    for r in release::PACIFIC..=release::UMBRELLA {
        let mut o = mk_osd(&format!("boot-admission-{r}"));
        o.state = State::Preboot;
        let mut m = mk_map(5, 4, &[0, 1, 2], &o, 0);
        m.require_osd_release = r;
        o.map = Some(Arc::new(m));
        o.send_boot();
        assert!(o.exit_code().is_none(), "{r}");
        assert_eq!(boots(&o).len(), 1, "{r}");
        let warned = format!("{:?}", o.logs).contains("monitor ignores this boot");
        assert_eq!(warned, r < release::SQUID, "{r}");
    }
}

#[test]
fn unanswered_peer_metadata_is_retired_when_the_incarnation_changes() {
    let mut o = mk_osd("flavor-churn");
    let m = mk_map_for_flavor_churn(&o, 5);
    deliver(&mut o, m, 5);
    for epoch in 6..32 {
        let old: Vec<_> = o.pg.peer_meta.keys().copied().collect();
        let m = mk_map_for_flavor_churn(&o, epoch);
        deliver(&mut o, m, epoch);
        assert_eq!(o.pg.peer_meta.len(), 3, "one current request per peer");
        for tid in old {
            assert!(!o.mc.cancel_command(tid), "obsolete replay must be gone");
            assert!(!o.pg_on_peer_meta(tid, 0, b"{}"));
        }
        assert!(o.pg.peer_meta.values().all(|(_, uf)| *uf == epoch));
    }
    let old: Vec<_> = o.pg.peer_meta.keys().copied().collect();
    let m = mk_map(32, 6, &[3], &o, 4);
    deliver(&mut o, m, 32);
    assert!(
        o.pg.peer_meta.is_empty(),
        "down peers own no metadata query"
    );
    for tid in old {
        assert!(!o.mc.cancel_command(tid));
    }
}

fn mk_map_for_flavor_churn(o: &Osd, epoch: u32) -> OsdMap {
    let mut m = mk_map(epoch, 6, &[0, 1, 2, 3], o, 4);
    for info in m.osd_info.iter_mut().take(3) {
        info.up_from = epoch;
    }
    m
}

#[test]
fn peer_flavor_discovery_does_not_scan_pending_queries_per_peer() {
    let mut o = mk_osd("flavor-discovery-cost");
    let up: Vec<i32> = (0..128).collect();
    let peers = up.len() - 1;
    let m = mk_map(5, 128, &up, &o, 4);
    deliver(&mut o, m, 5);
    assert_eq!(o.pg.peer_meta.len(), peers);
    assert!(
        o.pg.peer_meta_probes <= 2 * peers,
        "initial discovery examined {} pending entries for {peers} peers",
        o.pg.peer_meta_probes
    );
    o.pg.peer_meta_probes = 0;
    let m = mk_map(6, 128, &up, &o, 4);
    deliver(&mut o, m, 6);
    assert_eq!(o.pg.peer_meta.len(), peers, "pending queries deduplicated");
    assert!(o.pg.peer_meta_probes <= 2 * peers);
    let tid =
        o.pg.peer_meta
            .iter()
            .find(|(_, peer)| **peer == (0, 1))
            .map(|(tid, _)| *tid)
            .unwrap();
    assert!(o.pg_on_peer_meta(tid, -opwire::errno::EIO, &[]));
    let mut m = mk_map(7, 128, &up, &o, 4);
    m.osd_info[1].up_from = 7;
    deliver(&mut o, m, 7);
    // the restart retires the unanswered (1, 1) query (NT-leaks-04): one query per peer remains
    assert_eq!(o.pg.peer_meta.len(), peers);
    assert!(
        o.pg.peer_meta.values().any(|p| *p == (0, 1)),
        "error retried"
    );
    assert!(
        o.pg.peer_meta.values().any(|p| *p == (1, 7)),
        "new incarnation queried"
    );
    assert!(!o.pg.peer_meta.values().any(|p| *p == (1, 1)));
    o.pg.peer_meta_probes = 0;
    let mut m = mk_map(8, 128, &up, &o, 4);
    m.osd_info[1].up_from = 7;
    deliver(&mut o, m, 8);
    assert_eq!(o.pg.peer_meta.len(), peers, "pending queries deduplicated");
    assert!(o.pg.peer_meta_probes <= 2 * peers);
}

#[test]
fn newer_release_fails_closed() {
    let mut o = mk_osd("relnew");
    o.state = State::Preboot;
    let mut m = mk_map(5, 4, &[0, 1, 2], &o, 0);
    m.require_osd_release = crate::release::TRACKED_RELEASE + 1;
    deliver(&mut o, m, 5);
    assert_eq!(o.exit_code(), Some(crate::release::EXIT_REFUSED));
    assert!(boots(&o).is_empty());
    // the refused map is not persisted
    assert_eq!(o.sb.current_epoch, 0);
}

#[test]
fn older_release_fails_closed_and_window_boots() {
    let mut o = mk_osd("relold");
    o.state = State::Preboot;
    let mut m = mk_map(5, 4, &[0, 1, 2], &o, 0);
    m.require_osd_release = crate::release::MIN_RELEASE - 1;
    deliver(&mut o, m, 5);
    assert_eq!(o.exit_code(), Some(crate::release::EXIT_REFUSED));
    let mut o = mk_osd("relok");
    o.state = State::Preboot;
    let mut m = mk_map(5, 4, &[0, 1, 2], &o, 0);
    m.require_osd_release = crate::release::MIN_RELEASE;
    deliver(&mut o, m, 5);
    assert!(o.exit_code().is_none());
}

#[test]
fn purged_in_preboot_exits_clean() {
    let mut o = mk_osd("purge1");
    o.state = State::Preboot;
    // not caught up (mon newest 20): keep going, the id may simply not exist yet in an old map
    let m = mk_map(5, 3, &[0, 1, 2], &o, 0);
    deliver(&mut o, m, 20);
    assert!(o.exit_code().is_none());
    // newest map without our id: purged
    let m = mk_map(21, 3, &[0, 1, 2], &o, 0);
    deliver(&mut o, m, 21);
    assert_eq!(o.exit_code(), Some(0));
}

#[test]
fn purged_while_active_exits_clean() {
    let mut o = mk_osd("purge2");
    o.state = State::Booting;
    let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
    deliver(&mut o, m, 9);
    assert_eq!(o.state, State::Active);
    let m = mk_map(10, 3, &[0, 1, 2], &o, 9);
    deliver(&mut o, m, 10);
    assert_eq!(o.exit_code(), Some(0));
}

#[test]
fn uuid_mismatch_exits_clean() {
    let mut o = mk_osd("uuid1");
    o.state = State::Preboot;
    let mut m = mk_map(5, 4, &[0, 1, 2], &o, 0);
    m.osd_uuid[3] = Uuid([7; 16]);
    deliver(&mut o, m, 5);
    assert_eq!(o.exit_code(), Some(0));
    // matching uuid keeps running
    let mut o = mk_osd("uuid2");
    o.state = State::Preboot;
    let mut m = mk_map(5, 4, &[0, 1, 2], &o, 0);
    m.osd_uuid[3] = Uuid([9; 16]);
    deliver(&mut o, m, 5);
    assert!(o.exit_code().is_none());
}

#[test]
fn secondary_perf_loggers_and_mapping() {
    let o = mk_osd("perfx");
    let c = o.counters_now();
    for k in [
        "bluestore.allocated",
        "bluestore.stored",
        "bluestore.omap_bytes",
        "bluestore.alloc_unit",
        "bluestore.txc_commit_lat",
        "bluestore.kv_commit_lat",
        "bluestore.kv_sync_lat",
        "bluestore.read_lat",
        "bluestore.read_eio",
        "recoverystate_perf.peering_latency",
        "recoverystate_perf.active_latency",
        "recoverystate_perf.replicaactive_latency",
        "recoverystate_perf.pg_vulnerability_duration",
        "recoverystate_perf.pg_vulnerability_duration_min",
        "recoverystate_perf.pg_rebuild_duration",
        "recoverystate_perf.pg_rebuild_duration_min",
        "throttle-osd_client_bytes.val",
        "throttle-osd_client_bytes.max",
        "throttle-osd_client_messages.put",
        "osd.successful_scrubs_replicated",
        "osd.failed_scrubs_replicated_elapsed",
    ] {
        assert!(c.contains_key(k), "{k}");
    }
    // what tooling would misread is not emitted: no BlueFS (dashboards count dedicated WAL/DB devices), no dispatch
    // throttle, no onode cache counters
    assert!(!c.keys().any(|k| k.starts_with("bluefs.")));
    assert!(!c.keys().any(|k| k.contains("msgr_dispatch")));
    assert!(!c.contains_key("bluestore.onode_hits"));
    // classic types: commit latency = time average, space = gauge, throttle gets = counter
    let ty = |k: &str| c[k].0.ty;
    assert_eq!(ty("bluestore.txc_commit_lat"), messages::pct::TIME_AVG);
    assert_eq!(ty("bluestore.allocated"), messages::pct::GAUGE);
    assert_eq!(
        ty("throttle-osd_client_messages.get"),
        messages::pct::COUNTER_U64
    );
    assert_eq!(c["bluestore.alloc_unit"].1.value, 4096);
    // 21.2.0 duration counters: time average + time gauge, zero before the first closed window
    assert_eq!(
        ty("recoverystate_perf.pg_vulnerability_duration"),
        messages::pct::TIME_AVG
    );
    assert_eq!(
        ty("recoverystate_perf.pg_rebuild_duration_min"),
        messages::pct::TIME
    );
    assert_eq!(
        c["recoverystate_perf.pg_vulnerability_duration_min"]
            .1
            .value,
        0
    );
    // dump / schema group by logger, filters match the logger exactly
    let d = o.perf_dump(None, None);
    assert!(d["bluestore"]["txc_commit_lat"]["avgcount"].is_number());
    assert!(d["osd"]["op"].is_number());
    assert_eq!(
        o.perf_dump(Some("bluestore"), Some("alloc_unit")),
        serde_json::json!({"bluestore": {"alloc_unit": 4096}})
    );
    assert_eq!(o.perf_dump(Some("nope"), None), serde_json::json!({}));
    assert_eq!(
        o.perf_schema()["bluestore"]["txc_commit_lat"]["value_type"],
        "real-integer-pair"
    );
    assert!(o.counter_dump(Some("throttle-osd_client_bytes"), None)["throttle-osd_client_bytes"][0]["counters"]["max"].is_number());
    assert!(o.counter_schema()["recoverystate_perf"][0]["counters"]["active_latency"].is_object());
}

/// `ceph osd perf` (spec pg-io-stats.md 4): mean store commit latency of the window since the previous osd_stat, in ns
/// (sub-ms commits must not round to 0); an idle window reports 0.
#[test]
fn osd_perf_reports_window_mean_store_commit_latency_ns() {
    let mut o = mk_osd("osdperf");
    let _ = o.osd_stat();
    o.store_commit_done(200_000, 10);
    o.store_commit_done(400_000, 20);
    let p = o.osd_stat().os_perf_stat;
    assert_eq!(
        (p.os_commit_latency_ns, p.os_apply_latency_ns),
        (300_000, 300_000)
    );
    o.store_commit_done(5_000_000, 30);
    assert_eq!(o.osd_stat().os_perf_stat.os_commit_latency_ns, 5_000_000);
    assert_eq!(
        o.osd_stat().os_perf_stat.os_commit_latency_ns,
        0,
        "idle window"
    );
}

#[test]
fn store_commit_latency_feeds_counters_and_slow_alert() {
    let mut o = mk_osd("slowstore");
    assert!(o.os_alerts().is_empty(), "healthy: no alert");
    o.store_commit_done(2_000_000, 10);
    o.store_commit_done(4_000_000, 20);
    let c = o.counters_now();
    let l = c["bluestore.txc_commit_lat"].1;
    assert_eq!((l.avgcount, l.value), (2, 6_000_000));
    assert_eq!(c["bluestore.txc_count"].1.value, 2);
    assert_eq!(c["bluestore.kv_sync_lat"].1.avgcount, 2);
    assert!(o.os_alerts().is_empty(), "fast commits never alert");
    // one commit slower than bluestore_log_op_age
    o.store_commit_done(6_000_000_000, 30);
    let a = o.os_alerts();
    assert_eq!(a.keys().collect::<Vec<_>>(), ["BLUESTORE_SLOW_OP_ALERT"]);
    // reaches the mon in osd_stat under this OSD's id
    let s = o.osd_stat();
    assert!(s.os_alerts[&o.id.whoami].contains_key("BLUESTORE_SLOW_OP_ALERT"));
    // classic knobs: threshold 0 disables, a higher threshold needs more events
    o.conf
        .set(
            crate::config::Level::Mon,
            "bluestore_slow_ops_warn_threshold",
            "2",
        )
        .unwrap();
    assert!(o.os_alerts().is_empty());
    o.conf
        .set(
            crate::config::Level::Mon,
            "bluestore_slow_ops_warn_threshold",
            "0",
        )
        .unwrap();
    assert!(o.os_alerts().is_empty());
}

/// NT-cs-observe-02: `bluestore_log_op_age` below 1 s is honoured exactly — there is no hidden 1 s floor.
#[test]
fn sub_second_slow_commit_threshold_is_honoured() {
    let mut o = mk_osd("subsecslow");
    o.conf
        .set(crate::config::Level::Mon, "bluestore_log_op_age", "0.5")
        .unwrap();
    // 600 ms >= 0.5 s: slow (a 1 s floor would suppress it)
    o.store_commit_done(600_000_000, 10);
    assert_eq!(o.perf.slow_commits, 1);
    assert!(o.os_alerts().contains_key("BLUESTORE_SLOW_OP_ALERT"));
    // 400 ms < 0.5 s: not slow
    o.store_commit_done(400_000_000, 20);
    assert_eq!(o.perf.slow_commits, 1);
}

/// NT-cs-observe-03: the slow-op window counts every event (no 256 cap), so a threshold above 256 can fire.
#[test]
fn slow_alert_threshold_above_the_old_cap_can_fire() {
    let mut o = mk_osd("many-slow");
    for i in 0..300u64 {
        o.store_commit_done(6_000_000_000, i); // 6 s each, all inside the window
    }
    assert_eq!(o.op_perf_all().slow_store_win, 300, "no 256 cap");
    o.conf
        .set(
            crate::config::Level::Mon,
            "bluestore_slow_ops_warn_threshold",
            "300",
        )
        .unwrap();
    assert!(o.os_alerts().contains_key("BLUESTORE_SLOW_OP_ALERT"));
    o.conf
        .set(
            crate::config::Level::Mon,
            "bluestore_slow_ops_warn_threshold",
            "301",
        )
        .unwrap();
    assert!(o.os_alerts().is_empty());
}

#[test]
fn read_eio_alert_counts_only_failed_client_reads() {
    let mut o = mk_osd("eio");
    assert!(o.os_alerts().is_empty());
    // a failed write or a successful read is no read error
    o.perf.op.read_eio = 0;
    assert!(!o.os_alerts().contains_key("FLASHSTORE_READ_ERRORS"));
    o.perf.op.read_eio += 1;
    o.perf.eio_win.push(
        o.mnow().as_nanos() as u64,
        o.conf
            .u64("flashstore_read_errors_warn_lifetime", 86400)
            .saturating_mul(1_000_000_000),
    );
    let a = o.os_alerts();
    assert!(a["FLASHSTORE_READ_ERRORS"].contains("EIO"));
    assert_eq!(o.counters_now()["bluestore.read_eio"].1.value, 1);
    // and it can be turned off
    o.conf
        .set(
            crate::config::Level::Mon,
            "flashstore_warn_on_read_errors",
            "false",
        )
        .unwrap();
    assert!(o.os_alerts().is_empty());
}

/// PGs stopped by the past-interval bounds check (peering.md 3.8) raise `FLASHSTORE_PG_PAST_INTERVALS` with both ranges,
/// aggregated from every core; the alert is recomputed per stat report and disappears when no PG is stopped.
#[test]
fn stopped_past_bounds_pgs_raise_health_alert() {
    use denc::types::{PgT, ShardId, SpgT};
    let mut o = mk_osd("bounds-alert");
    assert!(o.os_alerts().is_empty(), "healthy: no alert");
    let spg = SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId::NO_SHARD,
    };
    o.cl.stats[0] = Some(crate::xcore::CoreStats {
        pg_bounds_stopped: vec![peering::BoundsStoppedPg {
            spg,
            required: (3, 6),
            past: (3, 5),
        }],
        ..Default::default()
    });
    let a = o.os_alerts();
    assert_eq!(
        a["FLASHSTORE_PG_PAST_INTERVALS"],
        "1 PG(s) stopped, past interval bounds implausible: 1.0 required [3,6) past [3,5)"
    );
    // reaches the mon in osd_stat under this OSD's id
    let s = o.osd_stat();
    assert!(
        s.os_alerts[&o.id.whoami].contains_key("FLASHSTORE_PG_PAST_INTERVALS"),
        "alert ships in osd_stat"
    );
    // never sticky: the next report without a stopped PG has no entry
    o.cl.stats[0] = None;
    assert!(o.os_alerts().is_empty());
}

/// `bluestore.read_eio` and its alert window count a failed client read with the op tracker off too: the accounting
/// does not depend on the per-op record (a device EIO storm must stay visible).
#[test]
fn a_read_eio_is_counted_with_the_tracker_off() {
    let mut o = mk_osd("eio-off");
    o.tracker.lim.enabled = false;
    let eio = |op: u16| {
        let mut r = opwire::MOSDOpReply {
            result: -denc::errno::EIO,
            ..Default::default()
        };
        r.ops.push(opwire::OsdOp {
            op,
            rval: -denc::errno::EIO,
            ..Default::default()
        });
        r
    };
    o.op_done(
        1,
        1,
        opwire::OpClass {
            read: true,
            write: false,
        },
        &eio(opwire::op::READ),
    );
    assert_eq!(o.perf.op.read_eio, 1);
    assert_eq!(o.perf.op.op, 0, "an error reply moves no op counter");
    assert!(
        o.os_alerts().contains_key("FLASHSTORE_READ_ERRORS"),
        "the alert window fills"
    );
    // a class call EIO and a write EIO are no store read errors
    let wr = opwire::OpClass {
        read: false,
        write: true,
    };
    o.op_done(1, 2, wr, &eio(opwire::op::CALL));
    o.op_done(1, 3, wr, &eio(opwire::op::WRITE));
    assert_eq!(o.perf.op.read_eio, 1);
}

#[test]
fn ok_to_upgrade_metadata_is_present_and_consistent() {
    // `ceph osd ok-to-upgrade` (mgr) compares osd metadata `ceph_version_short` with the requested version and refuses
    // (EAGAIN-style report `bad_no_version`) when it is missing or empty
    let o = mk_osd("upg");
    let m = o.boot_metadata();
    let short = &m["ceph_version_short"];
    assert!(!short.is_empty());
    assert!(
        short.split('.').count() >= 3 && short.chars().next().unwrap().is_ascii_digit(),
        "{short}"
    );
    assert!(m["ceph_version"].starts_with(&format!("ceph version {short} (")));
    // the key is a plain string the mgr can compare: never differs between boots of the same build
    assert_eq!(short, &o.boot_metadata()["ceph_version_short"]);
}

/// Regression (RGW e2e): a driver's unix-seconds origin was truncated and taken before the monotonic origin, so every wall stamp
/// (cls `now`, olh epochs) lagged real time by up to seconds and a fresh versioned write sorted OLDER than its own null instance.
/// With `wall_from_clock` `start` anchors the wall clock to the system clock at sub-microsecond precision.
#[test]
fn wall_from_clock_anchors_to_the_system_clock() {
    let mut o = mk_osd("wallclk");
    o.cfg.wall_from_clock = true;
    o.start(Duration::from_millis(7_370)); // an arbitrary monotonic origin offset
    o.set_now(Duration::from_millis(7_370));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let w = o.wall();
    let wall = Duration::new(u64::from(w.sec), w.nsec);
    let d = now.abs_diff(wall);
    assert!(
        d < Duration::from_millis(50),
        "wall {wall:?} vs system {now:?}"
    );
}

static FAKE_SYS_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
fn fake_sys() -> u64 {
    FAKE_SYS_NS.load(std::sync::atomic::Ordering::SeqCst)
}

/// Pure rule: forward only, beyond the threshold.
#[test]
fn reanchored_origin_moves_forward_only() {
    use super::reanchored_origin as r;
    let (o, m, t) = (1_000_000_000_000u64, 5_000_000_000u64, 100_000_000u64);
    let wall = o + m;
    assert_eq!(r(o, m, wall, t), o, "in sync");
    assert_eq!(r(o, m, wall + t, t), o, "at the threshold");
    assert_eq!(
        r(o, m, wall + t + 1, t),
        wall + t + 1 - m,
        "ahead beyond it"
    );
    assert_eq!(r(o, m, wall - 3_000_000_000, t), o, "behind: never back");
}

/// NTP step after start: the 1 s tick re-anchors forward, stamps stay monotonic, a backward step is ignored.
#[test]
fn tick_reanchors_wall_forward_only() {
    let mut o = mk_osd("reanchor");
    o.cfg.wall_from_clock = true;
    o.sys_clock = fake_sys;
    let base = 1_700_000_000_000_000_000u64;
    let at = |ms: u64| base + ms * 1_000_000;
    FAKE_SYS_NS.store(at(0), std::sync::atomic::Ordering::SeqCst);
    o.wall_origin_ns = base;
    o.set_now(Duration::ZERO);
    let ns = |o: &Osd| {
        let w = o.wall();
        u64::from(w.sec) * 1_000_000_000 + u64::from(w.nsec)
    };
    // 1 s later the clock agrees: untouched
    o.set_now(Duration::from_secs(1));
    FAKE_SYS_NS.store(at(1_000), std::sync::atomic::Ordering::SeqCst);
    o.reanchor_wall();
    assert_eq!(ns(&o), at(1_000));
    let before = ns(&o);
    // a 50 ms jitter stays below the threshold
    FAKE_SYS_NS.store(at(1_050), std::sync::atomic::Ordering::SeqCst);
    o.reanchor_wall();
    assert_eq!(ns(&o), before);
    // the clock jumps 40 s ahead
    FAKE_SYS_NS.store(at(41_000), std::sync::atomic::Ordering::SeqCst);
    o.reanchor_wall();
    assert_eq!(ns(&o), at(41_000));
    assert!(ns(&o) > before);
    // a backward step is ignored: the stamp keeps advancing with the monotonic clock
    let high = ns(&o);
    FAKE_SYS_NS.store(at(2_000), std::sync::atomic::Ordering::SeqCst);
    o.set_now(Duration::from_secs(2));
    o.reanchor_wall();
    assert_eq!(ns(&o), high + 1_000_000_000);
}

/// C6: the mon session's cephx clock (rotating-key refresh, ticket expiry) follows the system clock in both
/// directions: forward-only, it refreshed rotating keys `step` seconds late after a forward step and once per second
/// after a backward one.
#[test]
fn tick_reanchors_mon_clock_both_ways() {
    let mut o = mk_osd("reanchor-mon");
    o.cfg.wall_from_clock = true;
    o.sys_clock = fake_sys2;
    let base = 1_700_000_000u64;
    o.wall_origin_ns = base * 1_000_000_000;
    o.set_now(Duration::from_secs(10));
    FAKE_SYS2_NS.store(
        (base + 10) * 1_000_000_000,
        std::sync::atomic::Ordering::SeqCst,
    );
    o.reanchor_wall();
    o.mc.on_timer(o.now); // the OSD drives the mon client with the same monotonic clock
    assert_eq!(o.mc.unix_now(), base + 10);
    // NTP steps 2 h forward
    FAKE_SYS2_NS.store(
        (base + 7210) * 1_000_000_000,
        std::sync::atomic::Ordering::SeqCst,
    );
    o.reanchor_wall();
    o.mc.on_timer(o.now); // the OSD drives the mon client with the same monotonic clock
    assert_eq!(o.mc.unix_now(), base + 7210);
    // and 3 h back
    FAKE_SYS2_NS.store(
        (base - 3590) * 1_000_000_000,
        std::sync::atomic::Ordering::SeqCst,
    );
    o.reanchor_wall();
    o.mc.on_timer(o.now); // the OSD drives the mon client with the same monotonic clock
    assert_eq!(o.mc.unix_now(), base - 3590);
    // A ticket the monitor installed in its corrected wall domain, already past its local expiry: outbound
    // authorizers take no clock, so a backward step cannot block new dials (NT-clocks-01, NT-authrotate-02).
    let mut ticket = cephx::ticket::TicketHandler::new(4);
    ticket.install(
        cephx::ticket::TicketEntry {
            service_id: 4,
            session_key: cephx::CryptoKey::new(
                cephx::key::KeyType::Aes,
                UTime::default(),
                &[7; 16],
            ),
            validity: UTime::new(1, 0),
            blob: cephx::types::TicketBlob::default(),
        },
        Duration::from_secs(o.mc.unix_now()),
    );
    assert!(!ticket.have_key(Duration::from_secs(o.mc.unix_now() + 2)));
    assert!(cephx::authorizer::Authorizer::new(1, 4, &ticket).is_ok());
    o.set_now(Duration::from_secs(11));
    assert_eq!(
        o.wall().sec,
        (base + 7211) as u32,
        "object stamps stay forward-only"
    );
}

static FAKE_SYS2_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
fn fake_sys2() -> u64 {
    FAKE_SYS2_NS.load(std::sync::atomic::Ordering::SeqCst)
}

/// `status` lists the startup `--set` keys that are valid Ceph options croit-flashstore-osd does not use (adr 0021 am. 60).
#[test]
fn status_reports_ignored_options() {
    let kv = |k: &str, v: &str| (k.to_owned(), v.to_owned());
    let mut o = mk_osd_with(
        "ignopt",
        vec![
            kv("rgw_thread_pool_size", "3"),
            kv("mds-cache-memory-limit", "1"),
            kv("rgw_thread_pool_size", "4"),
            kv("osd_heartbeat_grace", "30"),
            kv("flashstore_port_name", "x"),
        ],
    );
    let status = |o: &mut Osd| {
        let (r, _, out) = o
            .run_command(r#"{"prefix":"status"}"#, &crate::tell::ReplyTo::Asok(0))
            .expect("sync command");
        assert_eq!(r, 0);
        serde_json::from_slice::<serde_json::Value>(&out.into_bytes()).unwrap()
    };
    let v = status(&mut o);
    assert_eq!(
        v["ignored_options"],
        serde_json::json!(["mds_cache_memory_limit", "rgw_thread_pool_size"])
    );
    assert_eq!(v["ignored_options_count"], 2);
    let v = status(&mut mk_osd("noign"));
    assert_eq!(v["ignored_options"], serde_json::json!([]));
    assert_eq!(v["ignored_options_count"], 0);
}

/// Startup `--set` EC switches must reach the PG set before any PG exists, so PGs created later (new pools) inherit them.
#[test]
fn startup_ec_switches_reach_new_pgs() {
    let kv = |k: &str, v: &str| (k.to_owned(), v.to_owned());
    let o = mk_osd_with(
        "ecstart",
        vec![
            kv("ec_enable_primary", "true"),
            kv("ec_enable_optimized_primary", "true"),
            kv("ec_pdw", "auto"),
        ],
    );
    let c = o.pg.set.config();
    assert!(c.ec_primary && c.ec_opt_primary);
    assert_ne!(c.ec_pdw, peering::Config::new(0).ec_pdw);
}

/// adr 0039 am. 2, adr 0067 am. 10: legacy and optimized EC (shard + primary) are on by default; pdw stays off; switches are opt-outs.
#[test]
fn ec_defaults_legacy_and_optimized_on() {
    let o = mk_osd("ecdef");
    let c = o.pg.set.config();
    assert!(c.ec_primary && c.ec_opt_primary);
    assert_eq!(c.ec_pdw, peering::Config::new(0).ec_pdw);
    let (en, opt) = o.ec_enables();
    assert_eq!(en, ec::EcEnable::All);
    assert_eq!(opt, ec::EcEnable::All);
    let off = mk_osd_with(
        "ecoff",
        vec![
            ("ec_enable_primary".into(), "false".into()),
            ("ec_enable_pools".into(), "off".into()),
            ("ec_enable_optimized".into(), "off".into()),
            ("ec_enable_optimized_primary".into(), "false".into()),
        ],
    );
    assert!(!off.pg.set.config().ec_primary);
    assert!(!off.pg.set.config().ec_opt_primary);
    assert_eq!(off.ec_enables().0, ec::EcEnable::Off);
    assert_eq!(off.ec_enables().1, ec::EcEnable::Off);
}

#[test]
fn bounded_event_pump_resumes_without_new_network_input() {
    let mut o = mk_osd("event-pump-budget");
    let mut ids = Vec::new();
    for _ in 0..500 {
        ids.push(o.on_accept(
            Listener::Public,
            crate::osd::sock4([10, 0, 0, 5], 10000),
            Duration::from_secs(1),
        ));
    }
    for id in &ids {
        o.links
            .get_mut(id)
            .unwrap()
            .conn
            .on_closed(Duration::from_secs(2));
    }
    o.pump();
    let remaining = ids.iter().filter(|id| o.links.contains_key(id)).count();
    assert!(
        (500 - 128..=500).contains(&remaining),
        "at most 128 link closures; monitor work may consume the first budget (remaining={remaining})"
    );
    assert!(o.event_pump_pending);
    let retained = *ids.iter().find(|id| o.links.contains_key(id)).unwrap();
    assert!(
        !o.input_ready(retained),
        "decoded backlog must pause further transport input"
    );
    assert!(
        o.actor_input_ready(retained),
        "actor progress must remain independent"
    );
    for _ in 0..1000 {
        if !o.event_pump_pending {
            break;
        }
        assert!(o.poll_store(Duration::from_secs(2)));
    }
    assert!(!o.event_pump_pending);
    assert!(ids.iter().all(|id| !o.links.contains_key(id)));
}

#[test]
#[ignore = "comparative close-event dispatch residence benchmark"]
fn perf_bounded_event_residence() {
    for sample in 0..5 {
        let mut o = mk_osd(&format!("event-residence-{sample}"));
        let mut ids = Vec::new();
        for _ in 0..4096 {
            ids.push(o.on_accept(
                Listener::Public,
                crate::osd::sock4([10, 0, 0, 5], 10000),
                Duration::from_secs(1),
            ));
        }
        for id in &ids {
            o.links
                .get_mut(id)
                .unwrap()
                .conn
                .on_closed(Duration::from_secs(2));
        }
        let start = std::time::Instant::now();
        o.pump();
        let first = start.elapsed().as_nanos();
        let remaining = ids.iter().filter(|id| o.links.contains_key(id)).count();
        while ids.iter().any(|id| o.links.contains_key(id)) {
            o.pump();
        }
        println!(
            "sample={sample} first_ns={first} first_events={} total_ns={}",
            ids.len() - remaining,
            start.elapsed().as_nanos()
        );
    }
}

fn live_op(o: &mut Osd, tid: u64) {
    let op = opwire::MOSDOp {
        oid: b"obj".to_vec(),
        flags: opwire::flag::WRITE,
        ops: vec![opwire::OsdOp::new(opwire::op::WRITE)],
        ..Default::default()
    };
    o.tracker.start(crate::optrack::OpRec::new(
        1,
        tid,
        denc::types::EntityName::new(denc::types::EntityName::CLIENT, 7),
        denc::types::EntityAddr::default(),
        &op,
        0,
    ));
}

fn mark_down_sent(o: &Osd) -> bool {
    count(o, |m| matches!(m, AnyMessage::MOSDMarkMeDown(_))) > 0
}

#[test]
fn shutdown_without_mon_notification_still_drains_inflight_ops() {
    let mut o = mk_osd_with(
        "shut-no-notify",
        conf(&[("osd_fast_shutdown_notify_mon", "false")]),
    );
    o.state = State::Booting;
    let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
    deliver(&mut o, m, 9);
    live_op(&mut o, 1);
    o.shutdown(Duration::from_secs(5));
    assert!(
        o.exit_code().is_none(),
        "notification does not govern drain"
    );
    assert!(!mark_down_sent(&o));
    o.tracker.finish(1, 1, 7_000_000_000, 0, 0);
    o.on_timer(Duration::from_secs(7));
    assert_eq!(o.exit_code(), Some(0));
    assert!(!mark_down_sent(&o));
}

#[test]
fn shutdown_drains_inflight_ops_before_mark_me_down() {
    let mut o = mk_osd("shut4");
    o.state = State::Booting;
    let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
    deliver(&mut o, m, 9);
    live_op(&mut o, 1);
    o.shutdown(Duration::from_secs(5));
    // op still running: refuse new ones, no mark-down yet
    assert_eq!(o.state, State::Stopping);
    assert!(!mark_down_sent(&o) && o.exit_code().is_none());
    o.on_timer(Duration::from_secs(7));
    assert!(!mark_down_sent(&o));
    // it replied: the mark-down goes out at the next poll, the ack ends it
    o.tracker.finish(1, 1, 7_000_000_000, 0, 0);
    o.on_timer(Duration::from_secs(7));
    assert!(mark_down_sent(&o) && o.exit_code().is_none());
    let mut ack =
        o.t.sent
            .iter()
            .find_map(|m| match m {
                AnyMessage::MOSDMarkMeDown(d) => Some(d.clone()),
                _ => None,
            })
            .unwrap();
    ack.request_ack = false;
    o.on_mon_message(AnyMessage::MOSDMarkMeDown(ack));
    assert_eq!(o.exit_code(), Some(0));
}

#[test]
fn shutdown_drain_is_bounded() {
    let mut o = mk_osd("shut5");
    o.state = State::Booting;
    let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
    deliver(&mut o, m, 9);
    live_op(&mut o, 1);
    o.shutdown(Duration::from_secs(5)); // drain window until 10 s
    o.on_timer(Duration::from_secs(9));
    assert!(!mark_down_sent(&o));
    o.on_timer(Duration::from_secs(11));
    assert!(mark_down_sent(&o) && o.exit_code().is_none());
    o.on_timer(Duration::from_secs(17)); // mon ack timeout (5 s)
    assert_eq!(o.exit_code(), Some(0));
}

/// `osd_shutdown_drain_timeout` has no schema, so the mon can set any text: a non-finite or out-of-range value must
/// not abort the shutdown in `Duration::from_secs_f64` (the sibling `osd_mon_shutdown_timeout` path already falls back
/// to its default). A valid fractional value still means seconds.
#[test]
fn shutdown_drain_timeout_takes_a_huge_or_non_finite_value_safely() {
    let mut o = mk_osd("drain-odd");
    o.state = State::Booting;
    let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
    deliver(&mut o, m, 9);
    live_op(&mut o, 1); // the drain window stays open
    for (i, v) in ["inf", "-inf", "nan", "1e30"].into_iter().enumerate() {
        o.conf
            .set(Level::Mon, "osd_shutdown_drain_timeout", v)
            .unwrap();
        o.drain_until = None;
        o.drain_begin();
        assert_eq!(
            o.drain_until,
            Some(o.now + Duration::from_secs(5)),
            "{v}: the default drain window"
        );
        let logs = format!("{:?}", o.logs);
        assert_eq!(
            logs.matches("osd_shutdown_drain_timeout").count(),
            i + 1,
            "{v} is reported once: {logs}"
        );
    }
    o.conf
        .set(Level::Mon, "osd_shutdown_drain_timeout", "2.5")
        .unwrap();
    o.drain_until = None;
    o.drain_begin();
    assert_eq!(o.drain_until, Some(o.now + Duration::from_millis(2500)));
}

/// A worker that has not published its drain slot yet is "not reported", not `usize::MAX` ops: the control core must
/// not sum the sentinel into the drain count (it reported 18446744073709551615 unfinished ops at the timeout).
#[test]
fn drain_does_not_count_cores_that_have_not_reported() {
    use std::sync::atomic::Ordering::Relaxed;
    for s in &DRAIN_LEFT[..2] {
        s.store(usize::MAX, Relaxed);
    }
    let key = cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, UTime::new(1, 0)).unwrap();
    let spec = CoreSpec::new(0, 2, 2, 32).unwrap();
    let mut o = Osd::control(
        test_cfg(vec![], false, false),
        test_store("drain-unreported", &key.to_base64().unwrap(), 0),
        crate::devstore::DevMemStore::new(),
        spec,
    )
    .unwrap();
    o.start(Duration::from_secs(1));
    o.drain_begin();
    assert_eq!(o.drain_until, Some(o.now + Duration::from_secs(5)));
    let sentinel = usize::MAX.to_string();
    assert!(!o.logs.iter().any(|l| l.text.contains(&sentinel)));
    o.on_timer(Duration::from_secs(7)); // the drain window is over, core 1 never published
    let logs = format!("{:?}", o.logs);
    assert!(!logs.contains(&sentinel), "{logs}");
    assert!(logs.contains("1 core(s) did not report"), "{logs}");
    assert!(logs.contains("0 op(s) unfinished"), "{logs}");
}

/// `osd_failsafe_full_ratio` in percent (`97` = 0.97, spec osd-lifecycle 4.4) must reach the map thresholds too: with
/// an unset map ratio the failsafe triple decides, so the local gate (0.97) and the FULL state reported to the mon
/// must agree. Before, `full_thresholds` took 97.0 raw and an OSD at 98 % looked healthy.
#[test]
fn failsafe_percent_spelling_reaches_the_map_full_thresholds() {
    let mut o = mk_osd_with("failsafe-pct", conf(&[("osd_failsafe_full_ratio", "97")]));
    o.state = State::Booting;
    let mut m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
    m.nearfull_ratio = 0.0; // any unset ratio: all three fall to the failsafe ratio
    deliver(&mut o, m, 9);
    // fill the dev store to 98 % of its emulated size; only the length counts (`used`), the bytes stay sparse
    let f = std::fs::File::create(o.store.as_ref().unwrap().dir().join("meta/fill")).unwrap();
    f.set_len((8u64 << 30) / 100 * 98).unwrap();
    drop(f);
    assert_eq!(o.full_thresholds(), Some((0.97, 0.97, 0.97)));
    assert_eq!(o.local_fullness(), osd_state::FULL);
}

/// `bench_cleanup` removes the scratch objects of a bench a crash left behind: a cleanup that cannot remove them must
/// be reported, not silently keep the device fuller than the next bench assumes.
#[test]
fn bench_scratch_cleanup_failure_is_reported() {
    let key = cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, UTime::new(1, 0)).unwrap();
    let st = test_store("bench-clean", &key.to_base64().unwrap(), 0);
    std::fs::create_dir(st.dir().join("bench.0")).unwrap(); // remove_file fails on a directory
    let mut o = Osd::new(test_cfg(vec![], false, false), st).unwrap();
    o.start(Duration::from_secs(1));
    let logs = format!("{:?}", o.logs);
    assert!(logs.contains("bench scratch cleanup failed"), "{logs}");
}

/// Startup refuses a superblock carrying any unknown feature bit (compat, ro_compat or incompat, like classic)
/// before monitor traffic; a subset of the supported features is accepted.
#[test]
fn startup_refuses_unknown_required_superblock_features() {
    for kind in ["incompat", "ro_compat", "compat", "known"] {
        let key = cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, UTime::new(1, 0)).unwrap();
        let mut st = test_store(&format!("sb-features-{kind}"), &key.to_base64().unwrap(), 0);
        let mut sb = st.load_superblock().unwrap().unwrap();
        match kind {
            "incompat" => sb.compat_features.incompat.mask |= 1 << 63,
            "ro_compat" => sb.compat_features.ro_compat.mask |= 1 << 63,
            "compat" => sb.compat_features.compat.mask |= 1 << 63,
            "known" => {
                // Missing supported features and informational names do not require refusal.
                sb.compat_features.incompat.mask = 1 << 1;
                sb.compat_features.incompat.names.clear();
            }
            _ => unreachable!(),
        }
        st.store_superblock(&sb).unwrap();
        let cfg = test_cfg(
            vec![("auth_cluster_required".into(), "none".into())],
            false,
            false,
        );
        let result = Osd::new(cfg, st);
        if kind != "known" {
            let err = match result {
                Err(e) => e,
                Ok(_) => panic!("accepted unknown {kind} feature"),
            };
            assert!(err.contains("features unsupported by this build"), "{err}");
        } else if let Err(err) = result {
            panic!("{kind}: {err}");
        }
    }
}

/// A stored map that exists but does not decode is discarded and refetched from the mon: the discarded history must
/// be named loudly, otherwise store corruption looks like a cold start.
#[test]
fn an_unusable_stored_map_is_reported_not_silently_dropped() {
    let key = cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, UTime::new(1, 0)).unwrap();
    let st = test_store("stored-map-bad", &key.to_base64().unwrap(), 42);
    std::fs::write(st.dir().join("maps/42.full"), b"not a map").unwrap();
    let mut o = Osd::new(test_cfg(vec![], false, false), st).unwrap();
    assert_eq!(o.epoch(), 0, "the unusable map is dropped");
    o.start(Duration::from_secs(1));
    let logs = format!("{:?}", o.logs);
    assert!(logs.contains("stored osdmap epoch 42 unusable"), "{logs}");
}

/// adr 0074 am. 4: the core parking with an output notification still queued is a lost wake-up, counted in perf
/// dump (`osd.knet_wake_parked_ready`, must stay 0).
#[test]
fn park_with_queued_output_is_counted_as_lost_wakeup() {
    let mut o = mk_osd("output-park");
    while o.poll_output_ready().is_some() {}
    o.note_park();
    assert_eq!(o.counters_now()["osd.knet_wake_parked_ready"].1.value, 0);
    let id = o.on_accept(
        Listener::Public,
        crate::osd::sock4([10, 0, 0, 7], 10002),
        Duration::from_secs(1),
    );
    o.note_park(); // the banner is queued: parking now strands it
    assert_eq!(o.counters_now()["osd.knet_wake_parked_ready"].1.value, 1);
    assert_eq!(o.poll_output_ready(), Some(id));
    o.note_park();
    assert_eq!(o.counters_now()["osd.knet_wake_parked_ready"].1.value, 1);
}

/// Options consumed at startup (`flashstore_cores`, ...) arrive as local config: `config get/show/diff` report them,
/// an unknown key gets the classic `(2) No such file or directory` error.
#[test]
fn config_reports_startup_options() {
    let mut o = mk_osd_with(
        "cfgstartup",
        vec![
            ("flashstore_cores".into(), "6".into()),
            ("flashstore_dev".into(), "spdk:0000:03:00.0".into()),
        ],
    );
    let mut run = |c: &str| {
        let (r, rs, out) = o
            .run_command(c, &crate::tell::ReplyTo::Asok(0))
            .expect("sync command");
        (
            r,
            rs,
            String::from_utf8_lossy(&out.into_bytes()).into_owned(),
        )
    };
    let (r, _, out) = run(r#"{"prefix":"config get","var":"flashstore_cores"}"#);
    assert_eq!((r, out.as_str()), (0, r#"{"flashstore_cores":"6"}"#));
    let (_, _, out) = run(r#"{"prefix":"config show"}"#);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["flashstore_cores"], "6");
    assert_eq!(v["flashstore_dev"], "spdk:0000:03:00.0");
    let (_, _, out) = run(r#"{"prefix":"config diff"}"#);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["diff"]["flashstore_cores"]["cmdline"], "6");
    assert_eq!(v["diff"]["flashstore_cores"]["final"], "6");
    let (r, rs, _) = run(r#"{"prefix":"config get","var":"no_such_option"}"#);
    assert_eq!(
        (r, rs.as_str()),
        (
            -2,
            "error getting 'no_such_option': (2) No such file or directory"
        )
    );
}

/// PG log sizing, stats re-publish bounds and the recovery chunk come from the options (defaults = classic defaults)
/// and follow a runtime change; the per-PG log target follows the OSD-wide PG count.
#[test]
fn pg_log_and_stats_options_reach_the_pgs() {
    let mut o = mk_osd("pglogopts");
    let c = o.pg.set.config().clone();
    assert_eq!(
        (
            c.min_pg_log_entries,
            c.max_pg_log_entries,
            c.pg_log_trim_min,
            c.pg_log_trim_max,
            c.target_pg_log_entries_per_osd,
            c.log_dups_tracked
        ),
        (250, 10_000, 100, 10_000, 300_000, 3000)
    );
    assert_eq!(
        (c.stats_interval, c.stats_epochs, c.recovery_max_chunk),
        (5_000_000_000, 500, 8 << 20)
    );
    assert_eq!((c.max_push_objects, c.max_push_cost), (10, 8 << 20));
    for (k, v) in [
        ("osd_min_pg_log_entries", "500"),
        ("osd_max_pg_log_entries", "2000"),
        ("osd_pg_log_trim_min", "10"),
        ("osd_pg_log_trim_max", "300"),
        ("osd_target_pg_log_entries_per_osd", "100000"),
        ("osd_pg_log_dups_tracked", "50"),
        ("osd_pg_stat_report_interval_max_seconds", "2"),
        ("osd_pg_stat_report_interval_max_epochs", "40"),
        ("osd_recovery_max_chunk", "1048576"),
        ("osd_max_push_objects", "4"),
        ("osd_max_push_cost", "1048576"),
    ] {
        o.conf
            .set(Level::Override, k, v)
            .expect("valid option value");
    }
    o.conf_changed();
    let c = o.pg.set.config().clone();
    assert_eq!(
        (
            c.min_pg_log_entries,
            c.max_pg_log_entries,
            c.pg_log_trim_min,
            c.pg_log_trim_max,
            c.target_pg_log_entries_per_osd,
            c.log_dups_tracked
        ),
        (500, 2000, 10, 300, 100_000, 50)
    );
    assert_eq!(
        (c.stats_interval, c.stats_epochs, c.recovery_max_chunk),
        (2_000_000_000, 40, 1 << 20)
    );
    assert_eq!((c.max_push_objects, c.max_push_cost), (4, 1 << 20));
    assert_eq!(
        crate::config::classify("osd_pg_stat_report_interval_max_epochs"),
        crate::config::KeyClass::Read
    );
    // OSD-wide PG count (no PGs yet here): the control core hands its total to the PG log target
    o.pg_sync_num_pgs();
    assert_eq!(o.pg.set.config().num_pgs_hint, u64::from(o.pg_num_pgs()));
    assert!(o.pg_set_num_pgs(7));
    assert!(!o.pg_set_num_pgs(7), "unchanged count: no push");
    assert_eq!(o.pg.set.config().num_pgs_hint, 7);
}

/// adr 0160 D5 (am. 9): the object-state cache per PG is the share over the PGs the OSD hosts, re-sized when that count
/// changes; `mon_max_pg_per_osd` (a mon placement limit) does not size it.
#[test]
fn object_cache_per_pg_follows_the_hosted_pg_count() {
    let mut o = mk_osd("objcache-pgs");
    assert!(o.pg_set_num_pgs(128));
    assert_eq!(o.pg.obj_cache, crate::nvmestore::obj_cache_per_pg(128));
    assert!(o.pg.obj_cache > crate::nvmestore::obj_cache_per_pg(500));
    o.conf
        .set(crate::config::Level::Override, "mon_max_pg_per_osd", "100")
        .unwrap();
    o.conf_changed();
    assert_eq!(o.pg.obj_cache, crate::nvmestore::obj_cache_per_pg(128));
    assert!(o.pg_set_num_pgs(1000));
    assert_eq!(o.pg.obj_cache, crate::nvmestore::obj_cache_per_pg(1000));
    o.conf
        .set(
            crate::config::Level::Override,
            "flashstore_obj_cache",
            "false",
        )
        .unwrap();
    o.conf_changed();
    assert_eq!(o.pg.obj_cache, 0);
    assert!(o.pg_set_num_pgs(10));
    assert_eq!(o.pg.obj_cache, 0, "off stays off");
}

/// PG-L6 + H-1: the reservation retry intervals, the recovery sleep pace (with wpq, where mclock does not zero it) and
/// `osd_allow_recovery_below_min_size` reach the shared peering config on every re-apply.
#[test]
fn recovery_retry_sleep_and_min_size_options_reach_the_pgs() {
    let mut o = mk_osd("recopts");
    let c = o.pg.set.config().clone();
    assert_eq!(
        (
            c.recovery_retry,
            c.backfill_retry,
            c.recovery_sleep,
            c.recovery_sleep_degraded,
            c.allow_recovery_below_min_size
        ),
        (30_000_000_000, 30_000_000_000, 0, 0, true)
    );
    for (k, v) in [
        ("osd_op_queue", "wpq"),
        ("osd_recovery_retry_interval", "5"),
        ("osd_backfill_retry_interval", "7"),
        ("osd_recovery_sleep", "1.5"),
        ("osd_recovery_sleep_degraded", "2"),
        ("osd_allow_recovery_below_min_size", "false"),
    ] {
        o.conf
            .set(Level::Override, k, v)
            .expect("valid option value");
    }
    o.conf_changed();
    let c = o.pg.set.config().clone();
    assert_eq!(
        (
            c.recovery_retry,
            c.backfill_retry,
            c.recovery_sleep,
            c.recovery_sleep_degraded,
            c.allow_recovery_below_min_size
        ),
        (
            5_000_000_000,
            7_000_000_000,
            1_500_000_000,
            2_000_000_000,
            false
        )
    );
    assert_eq!(
        crate::config::classify("osd_allow_recovery_below_min_size"),
        crate::config::KeyClass::Read
    );
}

/// `flashstore_report_objectstore` (storeid.rs): the default presents the BlueStore names, `flashstore` renames the
/// metadata value and default, the perf logger, the tell commands and the health codes; a bad value refuses the start.
#[test]
fn report_objectstore_default_keeps_the_bluestore_names() {
    let mut o = mk_osd("repobj-default");
    assert_eq!(o.boot_metadata()["osd_objectstore"], "bluestore");
    let meta = o.config_meta();
    assert_eq!(
        crate::schema::get(&o.conf, &meta, "osd_objectstore").as_deref(),
        Some("bluestore")
    );
    let c = o.counters_now();
    assert!(c.contains_key("bluestore.txc_count"));
    assert!(!c.keys().any(|k| k.starts_with("flashstore.")));
    let desc = o
        .run_command(
            r#"{"prefix":"get_command_descriptions"}"#,
            &crate::tell::ReplyTo::Asok(0),
        )
        .unwrap();
    let text = String::from_utf8_lossy(&desc.2.into_bytes()).into_owned();
    assert!(
        text.contains("\"bluestore\"") && !text.contains("\"flashstore\""),
        "{text}"
    );
    let r = o
        .run_command(
            r#"{"prefix":"bluestore dedup stats","pool":-1}"#,
            &crate::tell::ReplyTo::Asok(0),
        )
        .unwrap();
    assert!(!r.1.contains("unknown command prefix"), "{r:?}");
    let r = o
        .run_command(
            r#"{"prefix":"flashstore dedup stats","pool":-1}"#,
            &crate::tell::ReplyTo::Asok(0),
        )
        .unwrap();
    assert!(
        r.1.contains("unknown command prefix flashstore dedup stats"),
        "{r:?}"
    );
    o.store_commit_done(6_000_000_000, 30);
    assert_eq!(
        o.os_alerts().keys().collect::<Vec<_>>(),
        ["BLUESTORE_SLOW_OP_ALERT"]
    );
}

/// A sustained store slowdown logs one aggregate line per interval (count, worst latency), not one line per commit.
#[test]
fn slow_store_commits_log_one_aggregate_line_per_interval() {
    let mut o = mk_osd("slowcommitlog");
    let slow_lines = |o: &mut Osd| {
        std::iter::from_fn(|| o.poll_log().map(|l| l.text))
            .filter(|t| t.contains("slow store commit"))
            .collect::<Vec<_>>()
    };
    let _ = slow_lines(&mut o);
    for i in 0..100u64 {
        o.store_commit_done(6_000_000_000 + i * 30_000_000, i);
    }
    assert!(slow_lines(&mut o).is_empty(), "no line per commit");
    o.now = std::time::Duration::from_secs(20);
    o.slow_ops_note();
    let lines = slow_lines(&mut o);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].contains("100 commits") && lines[0].contains("worst 8970 ms"),
        "{lines:?}"
    );
    o.store_commit_done(6_000_000_000, 200);
    o.now = std::time::Duration::from_secs(25);
    o.slow_ops_note();
    assert!(slow_lines(&mut o).is_empty(), "inside the interval");
    o.now = std::time::Duration::from_secs(31);
    o.slow_ops_note();
    assert_eq!(slow_lines(&mut o).len(), 1);
}

#[test]
fn report_objectstore_flashstore_renames_every_identity_name() {
    let cfg = vec![(
        "flashstore_report_objectstore".to_owned(),
        "flashstore".to_owned(),
    )];
    let mut o = mk_osd_with("repobj-flash", cfg);
    assert_eq!(o.boot_metadata()["osd_objectstore"], "flashstore");
    let meta = o.config_meta();
    assert_eq!(
        crate::schema::get(&o.conf, &meta, "osd_objectstore").as_deref(),
        Some("flashstore")
    );
    let c = o.counters_now();
    assert!(c.contains_key("flashstore.txc_count"));
    assert!(!c.keys().any(|k| k.starts_with("bluestore.")));
    let desc = o
        .run_command(
            r#"{"prefix":"get_command_descriptions"}"#,
            &crate::tell::ReplyTo::Asok(0),
        )
        .unwrap();
    let text = String::from_utf8_lossy(&desc.2.into_bytes()).into_owned();
    assert!(
        text.contains("\"flashstore\"") && !text.contains("\"bluestore\""),
        "{text}"
    );
    // renamed, not aliased
    let r = o
        .run_command(
            r#"{"prefix":"flashstore dedup stats","pool":-1}"#,
            &crate::tell::ReplyTo::Asok(0),
        )
        .unwrap();
    assert!(!r.1.contains("unknown command prefix"), "{r:?}");
    let r = o
        .run_command(
            r#"{"prefix":"bluestore dedup stats","pool":-1}"#,
            &crate::tell::ReplyTo::Asok(0),
        )
        .unwrap();
    assert!(
        r.1.contains("unknown command prefix bluestore dedup stats"),
        "{r:?}"
    );
    o.store_commit_done(6_000_000_000, 30);
    assert_eq!(
        o.os_alerts().keys().collect::<Vec<_>>(),
        ["FLASHSTORE_SLOW_OP_ALERT"]
    );
}

#[test]
fn report_objectstore_invalid_value_refuses_start() {
    let cfg = vec![(
        "flashstore_report_objectstore".to_owned(),
        "kstore".to_owned(),
    )];
    let key = cephx::CryptoKey::generate(cephx::KeyType::Aes256Krb5, UTime::new(1, 0)).unwrap();
    let Err(e) = try_mk_osd("repobj-bad", key.to_base64().unwrap(), cfg, false, false) else {
        panic!("an invalid flashstore_report_objectstore must refuse the start");
    };
    assert!(
        e.contains("bluestore") && e.contains("flashstore") && e.contains("kstore"),
        "{e}"
    );
}

/// Service-owned message types pass through the generic wire dispatcher with their
/// header compat preserved; reject before typed decoding or PG dispatch.
#[test]
fn incompatible_service_headers_are_rejected_before_dispatch() {
    let make = || AnyMessage::Unknown {
        ty: pgwire::MOSDPGCreate2::MSG_TYPE,
        version: pgwire::MOSDPGCreate2::HEAD_VERSION,
        compat: pgwire::MOSDPGCreate2::HEAD_VERSION + 1,
        segments: pgwire::MOSDPGCreate2::default().encode(u64::MAX).unwrap(),
    };
    for purpose in [
        Purpose::Accepted,
        Purpose::Peer(1),
        Purpose::Copy(1),
        Purpose::Mgr,
    ] {
        let mut o = mk_osd(&format!("header-compat-{purpose:?}"));
        while o.poll_log().is_some() {}
        o.on_link_message(99, purpose, 1, make());
        let logs: Vec<_> = std::iter::from_fn(|| o.poll_log()).collect();
        assert!(
            logs.iter()
                .any(|l| l.contains("undecodable service message header")),
            "{purpose:?}"
        );
    }
    let mut o = mk_osd("mon-header-compat");
    while o.poll_log().is_some() {}
    o.on_mon_message(make());
    let logs: Vec<_> = std::iter::from_fn(|| o.poll_log()).collect();
    assert!(
        logs.iter()
            .any(|l| l.contains("incompatible service message type"))
    );
    assert!(!logs.iter().any(|l| l.contains("MOSDPGCreate2 epoch")));
}

/// A shared driver clock must retain one zero even when worker initialization is delayed.
#[test]
fn heartbeat_and_pg_clocks_share_the_process_origin_across_core_start_times() {
    let mut control = mk_osd("lease-origin-control");
    let mut worker = mk_osd("lease-origin-worker");
    control.start(Duration::from_secs(2));
    worker.start(Duration::from_secs(12));
    control.set_now(Duration::from_secs(20));
    worker.set_now(Duration::from_secs(20));
    assert_eq!(control.mnow(), Duration::from_secs(20));
    assert_eq!(worker.mnow(), control.mnow());
    assert_eq!(worker.pg_mono(), control.pg_mono());
}

#[test]
fn heartbeat_bounds_use_signed_peer_send_times_and_reject_inverted_or_stale_samples() {
    let mut o = mk_osd("lease-clock-bounds");
    o.state = State::Booting;
    let m = mk_map(9, 4, &[0, 1, 2, 3], &o, 9);
    deliver(&mut o, m, 9);
    let id = o.on_accept(
        Listener::HbBack,
        crate::osd::sock4([10, 1, 0, 11], 40000),
        Duration::from_secs(10),
    );
    o.links.get_mut(&id).unwrap().peer = Some(msgr2::PeerInfo {
        name: EntityName::osd(1),
        addrs: addr([10, 1, 0, 11], 40000, 1),
        features: u64::MAX,
        lossy: true,
        resumed: false,
        global_id: 1,
        auth_name: None,
    });
    o.hb.peers.entry(1).or_default().up_from = 1;
    let mut p = MOSDPing {
        fsid: FSID,
        map_epoch: 9,
        op: MOSDPing::PING,
        ping_stamp: UTime::new(1, 0),
        pad_len: 0,
        up_from: 1,
        mono_ping_stamp: messages::span_from_nanos(20_000_000_000),
        mono_send_stamp: messages::span_from_nanos(20_000_000_000),
        delta_ub: Some(messages::span_from_nanos(12_000_000_000)),
    };
    // feature off (no slot): nothing is sampled
    o.on_ping(id, p.clone());
    assert!(o.hb.peers[&1].clock_slot.is_none());
    o.hb_clock_slot(1, true);
    let slot = o.hb.peers[&1].clock_slot.clone().unwrap();
    assert_eq!(slot.load(), None, "attached slot holds no sample");
    let lower = 20_000_000_000 - o.mnow().as_nanos() as i64;
    o.on_ping(id, p.clone());
    let good = slot.load().unwrap();
    assert_eq!(good.lower, Some(lower));
    assert_eq!(good.upper, Some(12_000_000_000));
    p.delta_ub = Some(messages::span_from_nanos(9_000_000_000));
    o.on_ping(id, p.clone());
    assert_eq!(slot.load(), Some(good), "inverted interval rejected");
    p.up_from = 2;
    p.delta_ub = Some(messages::span_from_nanos(15_000_000_000));
    o.on_ping(id, p.clone());
    assert_eq!(
        slot.load(),
        Some(good),
        "incarnation not in the map rejected"
    );
    p.up_from = 1;
    p.mono_send_stamp = messages::span_from_nanos(-1);
    o.on_ping(id, p.clone());
    assert_eq!(
        slot.load(),
        Some(good),
        "negative monotonic timestamp rejected"
    );
    // a PING without delta_ub (our own peers) refreshes the lower bound and keeps the last upper bound
    p.mono_send_stamp = messages::span_from_nanos(21_000_000_000);
    p.delta_ub = None;
    o.on_ping(id, p.clone());
    let kept = slot.load().unwrap();
    assert_eq!(kept.lower, Some(lower + 1_000_000_000));
    assert_eq!(kept.upper, Some(12_000_000_000));
    // a reply echoing our outstanding ping: upper = peer reply send - our ping send, also without delta_ub
    o.links.get_mut(&id).unwrap().purpose = Purpose::Hb(1);
    o.links.get_mut(&id).unwrap().msgr = MsgrId::HbBackCli;
    let stamp = UTime::new(2, 0);
    o.hb.peers.get_mut(&1).unwrap().history.insert(
        stamp.as_nanos(),
        crate::hb::Entry::new(Duration::from_secs(30), 2, Duration::from_secs(4)),
    );
    let mut reply = MOSDPing {
        fsid: FSID,
        map_epoch: 9,
        op: MOSDPing::PING_REPLY,
        ping_stamp: stamp,
        pad_len: 0,
        up_from: 1,
        mono_ping_stamp: messages::span_from_nanos(5_000_000_000),
        mono_send_stamp: messages::span_from_nanos(14_000_000_000),
        delta_ub: None,
    };
    o.on_ping(id, reply.clone());
    assert_eq!(
        slot.load(),
        Some(kept),
        "reply not echoing our send stamp rejected"
    );
    reply.mono_ping_stamp = messages::span_from_nanos(4_000_000_000);
    o.on_ping(id, reply);
    let rt = slot.load().unwrap();
    assert_eq!(rt.lower, Some(14_000_000_000 - o.mnow().as_nanos() as i64));
    assert_eq!(rt.upper, Some(10_000_000_000));
    // steady-state samples never message other cores
    o.cl = crate::xcore::Cl::new(crate::xcore::CoreSpec::new(0, 4, 1, 4).unwrap());
    while o.poll_xmsg().is_some() {}
    p.mono_send_stamp = messages::span_from_nanos(20_000_000_000);
    p.delta_ub = Some(messages::span_from_nanos(30_000_000_000));
    for _ in 0..1000 {
        o.on_ping(id, p.clone());
    }
    let last = slot.load().unwrap();
    assert_eq!(last.upper, Some(30_000_000_000));
    assert!(o.poll_xmsg().is_none());
    // feature off at the next peer refresh: the slot is revoked on every core and nothing is sampled any more
    o.hb_clock_slot(1, false);
    assert!(o.hb.peers[&1].clock_slot.is_none());
    assert_eq!(slot.load(), None, "revoked");
    p.delta_ub = Some(messages::span_from_nanos(40_000_000_000));
    for _ in 0..1000 {
        o.on_ping(id, p.clone());
    }
    assert_eq!(slot.load(), None, "disabled feature publishes nothing");
    assert!(o.poll_xmsg().is_none());
    // re-enabling attaches a fresh slot on every other core (one message each), not per sample
    o.hb_clock_slot(1, true);
    let mut sent = 0;
    while let Some((_, m)) = o.poll_xmsg() {
        assert!(matches!(m, crate::xcore::XMsg::PeerClock { osd: 1, .. }));
        sent += 1;
    }
    assert_eq!(sent, 3);
    for f in o.t.out.iter().filter(|f| f.0 == id) {
        let reply = <MOSDPing as messages::Message>::decode(f.2.1, &f.3.front, &[], &[]).unwrap();
        assert!(
            reply.delta_ub.is_none(),
            "classic-visible replies remain unchanged"
        );
    }
}
