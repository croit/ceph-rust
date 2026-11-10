// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! What the RDMA transport reports (0469-rdma-transport, Visibility): counters and per-(core, device) state, the JSON of
//! `rdma status`, and the rate-limited warnings of the cluster log. Ceph-compatible means only: the numbers travel as
//! OSD perf counters in MMgrReport, the warnings as cluster-log entries; no own health check codes.
//!
//! Sans-IO: the transport fills [`DeviceStatus`] per core and device, the OSD feeds the sums of all cores and the clock
//! into a [`Notifier`] and sends what it returns.
use serde_json::{Value, json};
use std::time::Duration;

/// Cumulative counters (per core and device in the transport, summed by the OSD).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Connections that continued over a QP.
    pub upgraded: u64,
    /// Upgrades that did not happen (no QP, GID mismatch, peer decline): the connection stayed TCP.
    pub declined: u64,
    /// Upgraded sessions that ended by a transport fault (they reconnect over TCP).
    pub faulted: u64,
    /// Upgrades refused because the session cap or the receive pool was full: the connection stayed TCP.
    pub sessions_capped: u64,
    /// Sends refused for lack of peer credits.
    pub credit_stalls: u64,
    /// Sends refused for a full send queue or no free send slot.
    pub queue_stalls: u64,
    /// Time sessions spent credit-blocked (ns), summed over sessions.
    pub credit_stall_ns: u64,
    /// Demand-driven credit lends to credit-blocked sessions.
    pub grants_demand: u64,
    /// Credit extras given at admission of a session.
    pub grants_admission: u64,
    /// Sessions whose window fell back to the minimum after idling.
    pub idle_decays: u64,
    /// Connections woken from the send-slot wait queue.
    pub slot_wakeups: u64,
    /// Graceful closes that ran into the linger limit.
    pub close_fence_timeouts: u64,
    /// Stream bytes sent zero copy from the registered payload heap.
    pub zc_bytes: u64,
    /// Chunks of at least the zero-copy threshold outside the registered heap (copied).
    pub zc_misses: u64,
    /// Stream bytes and SENDs posted, chunks taken (SENDs per chunk < 1 = small chunks packed),
    /// and `ibv_post_send` doorbells (including opt-in window/WRITE WRs when used).
    pub tx_bytes: u64,
    pub tx_sends: u64,
    pub tx_chunks: u64,
    pub tx_doorbells: u64,
    /// Accepted RDMA WRITE work requests; excludes SEND and local window operations.
    pub tx_write_wrs: u64,
    /// Bytes covered by accepted WRITE requests; excludes rejected posts and SEND bytes.
    pub tx_write_bytes: u64,
    /// WRITE provider post calls, including failed calls; no call is made on SQ admission refusal.
    pub tx_write_doorbells: u64,
    /// WRITE admission refusals because the shared SQ is full; counts calls, not stall intervals.
    pub tx_write_sq_stalls: u64,
    /// `ibv_post_srq_recv` doorbells (receive slots re-posted per list).
    pub rx_doorbells: u64,
    /// Completion channel wake-ups of idle cores.
    pub wakes: u64,
    /// Receive re-posts that lost slots (`ibv_post_srq_recv` failed): the core is broken, its sessions fault. Must stay 0.
    pub rx_post_failures: u64,
    /// `ibv_poll_cq` errors: the core is broken, its sessions fault. Must stay 0.
    pub cq_errors: u64,
    /// Receive slots withheld at a detach because a lend still covered them (owner bug). Must stay 0.
    pub rx_withheld: u64,
    /// Data receive slots held (not re-posted, no credit returned) because the upper layer could not take input
    /// (input backpressure: the peer runs out of credits until the slots are delivered).
    pub rx_held: u64,
}

/// Process-wide teardown outcomes of the verbs cores (`rdma::verbs::leaked_cores` / `teardown_failures`,
/// `rdma::control::qp_drain_timeouts`); the same
/// numbers on every core, so they are reported once, not summed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Process {
    /// Cores whose CQ, SRQ and arenas were left allocated because a retire was not confirmed. Must stay 0.
    pub leaked_cores: u64,
    /// Refused QP teardown with bound windows or failed QP/CQ/SRQ/MR teardown; uncertain owners remain allocated. Must stay 0.
    pub teardown_failures: u64,
    /// QPs whose last-WQE event did not come after their move to ERR: kept with their send slots and receive credits.
    /// Must stay 0.
    pub qp_drain_timeouts: u64,
    /// Advertised type-2 windows retained because peer retirement or local CQE was uncertain.
    pub quarantined_windows: u64,
    /// Registered WRITE sources retained because their completion was uncertain.
    pub quarantined_write_sources: u64,
}

/// Every counter field, once: the per-tick sums, the `perf reset` baseline and the JSON document are generated from this
/// list, so a counter added here cannot be forgotten in one of them.
macro_rules! counter_fields {
    ($mac:ident) => {
        $mac! {
            upgraded, declined, faulted, sessions_capped, credit_stalls, queue_stalls, credit_stall_ns,
            grants_demand, grants_admission, idle_decays, slot_wakeups, close_fence_timeouts, zc_bytes,
            zc_misses, tx_bytes, tx_sends, tx_chunks, tx_doorbells, tx_write_wrs, tx_write_bytes,
            tx_write_doorbells, tx_write_sq_stalls, rx_doorbells, wakes, rx_post_failures, cq_errors,
            rx_withheld, rx_held
        }
    };
}

impl Counters {
    pub fn merge(&mut self, o: &Counters) {
        macro_rules! sum {
            ($($f:ident),* $(,)?) => {
                $(self.$f += o.$f;)*
            };
        }
        counter_fields!(sum);
    }

    /// `self - base` (a `perf reset` baseline).
    pub fn since(&self, b: &Counters) -> Counters {
        macro_rules! sub {
            ($($f:ident),* $(,)?) => {
                Counters { $($f: self.$f.saturating_sub(b.$f),)* }
            };
        }
        counter_fields!(sub)
    }

    fn json(&self) -> Value {
        let mut out = serde_json::Map::new();
        macro_rules! insert {
            ($($f:ident),* $(,)?) => {
                $(out.insert(stringify!($f).to_owned(), json!(self.$f));)*
            };
        }
        counter_fields!(insert);
        Value::Object(out)
    }
}

/// One core on one RDMA device.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceStatus {
    /// Local address the device serves.
    pub addr: String,
    /// Device name (`mlx5_0`).
    pub device: String,
    /// Upgraded sessions of the core.
    pub sessions: u32,
    /// Sessions the receive pool can hold (minimum windows).
    pub capacity: u32,
    /// Receive slots of the core (SRQ depth) and the sum of the credits granted out of them.
    pub slots: u32,
    pub granted: u32,
    /// Sum of the live sessions' current windows (equals `granted` unless credits are held by no session).
    pub session_credits: u32,
    /// Receive slots held for connections the OSD does not take input from.
    pub held: u32,
    pub counters: Counters,
}

impl DeviceStatus {
    fn json(&self) -> Value {
        let mut v = json!({
            "addr": self.addr,
            "device": self.device,
            "sessions": self.sessions,
            "capacity": self.capacity,
            "receive_slots": self.slots,
            "granted_credits": self.granted,
            "session_credits": self.session_credits,
            "held_slots": self.held,
        });
        if let (Some(o), Some(c)) = (v.as_object_mut(), self.counters.json().as_object()) {
            o.extend(c.clone());
        }
        v
    }
}

/// A device that could not be used: the connections of its address stay TCP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unusable {
    pub addr: String,
    pub reason: String,
}

/// Process-wide facts the transport tells the OSD once at startup.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Setup {
    /// `flashstore_rdma_max_sessions` (0 = unlimited).
    pub max_sessions: u32,
    pub unusable: Vec<Unusable>,
    /// Every usable device runs READ-capable QPs (spec rdma-read-offer.md): the
    /// OSD may advertise the object source-pull extension. Per-connection READ
    /// depths are still negotiated with each peer and can stay zero.
    pub reads: bool,
}

/// The part of `rdma status` one core answers.
pub fn core_json(core: usize, devices: &[DeviceStatus]) -> Value {
    json!({"core": core, "devices": devices.iter().map(DeviceStatus::json).collect::<Vec<_>>()})
}

/// All cores' parts into the answer: totals per device address, per-core detail, counters.
pub fn merge(enabled: bool, setup: &Setup, process: &Process, parts: &[Value]) -> Value {
    let mut devices: Vec<Value> = Vec::new();
    let mut sessions = 0u64;
    for p in parts {
        for d in p["devices"].as_array().into_iter().flatten() {
            let addr = d["addr"].as_str().unwrap_or("");
            let i = devices
                .iter()
                .position(|t| t["addr"].as_str() == Some(addr))
                .unwrap_or_else(|| {
                    devices.push(json!({"addr": addr, "device": d["device"]}));
                    devices.len() - 1
                });
            let t = devices[i].as_object_mut().expect("object");
            for (k, v) in d.as_object().into_iter().flatten() {
                if let (Some(n), true) = (v.as_u64(), !matches!(k.as_str(), "addr" | "device")) {
                    let cur = t.get(k).and_then(Value::as_u64).unwrap_or(0);
                    t.insert(k.clone(), json!(cur + n));
                }
            }
            sessions += d["sessions"].as_u64().unwrap_or(0);
        }
    }
    json!({
        "enabled": enabled,
        "max_sessions": setup.max_sessions,
        "sessions": sessions,
        "leaked_cores": process.leaked_cores,
        "teardown_failures": process.teardown_failures,
        "qp_drain_timeouts": process.qp_drain_timeouts,
        "quarantined_windows": process.quarantined_windows,
        "quarantined_write_sources": process.quarantined_write_sources,
        "devices": devices,
        "unusable": setup.unusable.iter().map(|u| json!({"addr": u.addr, "reason": u.reason})).collect::<Vec<_>>(),
        "cores": parts,
    })
}

/// `--format plain` rendering of [`merge`]'s document.
pub fn plain(doc: &Value) -> String {
    let n = |v: &Value, k: &str| v[k].as_u64().unwrap_or(0);
    let mut s = format!(
        "rdma {}, max_sessions {}, sessions {}\n",
        if doc["enabled"].as_bool().unwrap_or(false) {
            "enabled"
        } else {
            "disabled"
        },
        match n(doc, "max_sessions") {
            0 => "unlimited".to_owned(),
            m => m.to_string(),
        },
        n(doc, "sessions"),
    );
    s += &format!(
        "leaked_cores {} teardown_failures {} qp_drain_timeouts {} quarantined_windows {} quarantined_write_sources {}\n",
        n(doc, "leaked_cores"),
        n(doc, "teardown_failures"),
        n(doc, "qp_drain_timeouts"),
        n(doc, "quarantined_windows"),
        n(doc, "quarantined_write_sources")
    );
    for u in doc["unusable"].as_array().into_iter().flatten() {
        s += &format!(
            "device {} unusable: {}\n",
            u["addr"].as_str().unwrap_or(""),
            u["reason"].as_str().unwrap_or("")
        );
    }
    let row = |d: &Value| {
        format!(
            "sessions {} (capacity {}), credits {} of {} receive slots, held {}; upgraded {} declined {} faulted {} capped {} \
             credit_stalls {} queue_stalls {} fence_timeouts {} zc_bytes {} zc_misses {} tx_bytes {} tx_sends {} tx_chunks {} tx_doorbells {} tx_write_wrs {} tx_write_bytes {} tx_write_doorbells {} tx_write_sq_stalls {} rx_doorbells {} wakes {} \
             rx_post_failures {} cq_errors {} rx_withheld {}\n",
            n(d, "sessions"),
            n(d, "capacity"),
            n(d, "granted_credits"),
            n(d, "receive_slots"),
            n(d, "held_slots"),
            n(d, "upgraded"),
            n(d, "declined"),
            n(d, "faulted"),
            n(d, "sessions_capped"),
            n(d, "credit_stalls"),
            n(d, "queue_stalls"),
            n(d, "close_fence_timeouts"),
            n(d, "zc_bytes"),
            n(d, "zc_misses"),
            n(d, "tx_bytes"),
            n(d, "tx_sends"),
            n(d, "tx_chunks"),
            n(d, "tx_doorbells"),
            n(d, "tx_write_wrs"),
            n(d, "tx_write_bytes"),
            n(d, "tx_write_doorbells"),
            n(d, "tx_write_sq_stalls"),
            n(d, "rx_doorbells"),
            n(d, "wakes"),
            n(d, "rx_post_failures"),
            n(d, "cq_errors"),
            n(d, "rx_withheld"),
        )
    };
    for d in doc["devices"].as_array().into_iter().flatten() {
        s += &format!(
            "{} ({}): {}",
            d["addr"].as_str().unwrap_or(""),
            d["device"].as_str().unwrap_or(""),
            row(d)
        );
    }
    for c in doc["cores"].as_array().into_iter().flatten() {
        for d in c["devices"].as_array().into_iter().flatten() {
            s += &format!(
                "  core {} {}: {}",
                n(c, "core"),
                d["addr"].as_str().unwrap_or(""),
                row(d)
            );
        }
    }
    s
}

/// Nothing is reported more often than this (cluster log and daemon log).
pub const SUMMARY_INTERVAL: Duration = Duration::from_secs(600);
/// RDMA is configured but not one connection upgraded for this long, although offers were declined.
pub const NO_UPGRADE_GRACE: Duration = Duration::from_secs(600);

/// Severity of a [`Notice`] (cluster-log priority of the OSD: warning or info).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
}

/// A line for the cluster log and the daemon log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub level: Level,
    pub text: String,
}

/// What the notifier looks at, once per OSD tick (sums over all cores).
#[derive(Clone, Copy, Debug)]
pub struct Observed {
    pub now: Duration,
    pub enabled: bool,
    pub max_sessions: u32,
    /// Sessions upgraded now (gauge).
    pub sessions: u64,
    /// Cumulative counters.
    pub counters: Counters,
}

/// One episode of a condition: a line when it begins, at most one summary per [`SUMMARY_INTERVAL`] while new events keep
/// coming, a line when it ends.
#[derive(Debug, Default)]
struct Episode {
    active: bool,
    /// Event counter at the last line.
    reported: u64,
    last: Duration,
}

impl Episode {
    fn begin(&mut self, now: Duration, events: u64) {
        *self = Episode {
            active: true,
            reported: events,
            last: now,
        };
    }

    /// New events since the last line, if a summary is due.
    fn summary(&mut self, now: Duration, events: u64) -> Option<u64> {
        let new = events.saturating_sub(self.reported);
        if self.active && new > 0 && now.saturating_sub(self.last) >= SUMMARY_INTERVAL {
            self.reported = events;
            self.last = now;
            Some(new)
        } else {
            None
        }
    }
}

/// Rate-limited cluster-log lines about the transport: the session cap, "configured but nothing upgrades", unusable
/// devices.
#[derive(Debug, Default)]
pub struct Notifier {
    start: Option<Duration>,
    capped: Episode,
    /// Sessions when the cap was hit (the pool case, no configured limit).
    capped_at: u64,
    idle: Episode,
    devices_told: bool,
}

impl Notifier {
    pub fn new() -> Notifier {
        Notifier::default()
    }

    /// Look at the numbers; returns the lines to log now (usually none).
    pub fn step(&mut self, setup: &Setup, o: &Observed) -> Vec<Notice> {
        let mut out = Vec::new();
        if !o.enabled {
            return out;
        }
        let start = *self.start.get_or_insert(o.now);
        let warn = |text: String| Notice {
            level: Level::Warn,
            text,
        };
        if !self.devices_told {
            self.devices_told = true;
            for u in &setup.unusable {
                out.push(warn(format!(
                    "rdma: device {} unusable: {} (connections of this address stay on TCP)",
                    u.addr, u.reason
                )));
            }
        }
        // session cap / full receive pool
        let capped = o.counters.sessions_capped;
        let limit = u64::from(o.max_sessions);
        if !self.capped.active {
            if capped > self.capped.reported {
                self.capped.begin(o.now, capped);
                self.capped_at = o.sessions;
                out.push(warn(if limit > 0 && o.sessions >= limit {
                    format!("rdma: max_sessions {limit} reached, new connections stay on TCP")
                } else {
                    format!(
                        "rdma: receive pool full at {} sessions (raise flashstore_rdma_memory), new connections stay on TCP",
                        o.sessions
                    )
                }));
            }
        } else {
            let at = if limit > 0 {
                limit.min(self.capped_at.max(1))
            } else {
                self.capped_at
            };
            // leave the state a tenth below where it began, so a session count that wobbles at the cap logs nothing
            if o.sessions + (at / 10).max(1) <= at {
                let n = capped.saturating_sub(self.capped.reported);
                self.capped.active = false;
                self.capped.reported = capped;
                out.push(Notice {
                    level: Level::Info,
                    text: format!(
                        "rdma: sessions back to {} (below the cap), new connections upgrade again{}",
                        o.sessions,
                        if n > 0 {
                            format!(" ({n} connections stayed on TCP since the last message)")
                        } else {
                            String::new()
                        }
                    ),
                });
            } else if let Some(n) = self.capped.summary(o.now, capped) {
                out.push(warn(format!(
                    "rdma: {n} connections stayed on TCP since the last message"
                )));
            }
        }
        // configured, offers were declined, nothing ever upgraded
        let declined = o.counters.declined;
        if o.counters.upgraded > 0 {
            if self.idle.active {
                self.idle.active = false;
                out.push(Notice {
                    level: Level::Info,
                    text: "rdma: connections upgrade now".into(),
                });
            }
            self.idle.reported = declined;
        } else if !self.idle.active {
            if declined > 0 && o.now.saturating_sub(start) >= NO_UPGRADE_GRACE {
                self.idle.begin(o.now, declined);
                out.push(warn(format!(
                    "rdma: configured but no connection upgraded after {}s ({declined} stayed on TCP, see `rdma status`)",
                    NO_UPGRADE_GRACE.as_secs()
                )));
            }
        } else if let Some(n) = self.idle.summary(o.now, declined) {
            out.push(warn(format!(
                "rdma: {n} connections stayed on TCP since the last message"
            )));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(secs: u64, sessions: u64, c: Counters) -> Observed {
        Observed {
            now: Duration::from_secs(secs),
            enabled: true,
            max_sessions: 100,
            sessions,
            counters: c,
        }
    }

    fn texts(v: Vec<Notice>) -> Vec<String> {
        v.into_iter().map(|n| n.text).collect()
    }

    #[test]
    fn cap_reached_summary_at_most_every_ten_minutes_and_recovery() {
        let setup = Setup {
            max_sessions: 100,
            unusable: vec![],
            reads: false,
        };
        let mut n = Notifier::new();
        let mut c = Counters::default();
        assert!(n.step(&setup, &obs(0, 99, c)).is_empty());
        c.sessions_capped = 1;
        let t = texts(n.step(&setup, &obs(1, 100, c)));
        assert_eq!(
            t,
            ["rdma: max_sessions 100 reached, new connections stay on TCP"]
        );
        // a flood of capped connections stays quiet until the interval is over
        for s in 2..590 {
            c.sessions_capped += 3;
            assert!(n.step(&setup, &obs(s, 100, c)).is_empty(), "t={s}");
        }
        c.sessions_capped += 3;
        let t = texts(n.step(&setup, &obs(601, 100, c)));
        assert_eq!(t.len(), 1);
        assert!(
            t[0].starts_with("rdma: ")
                && t[0].ends_with("connections stayed on TCP since the last message"),
            "{t:?}"
        );
        assert!(t[0].contains("1767"), "{t:?}");
        // no new capped connection: no summary however long it lasts
        assert!(n.step(&setup, &obs(5000, 100, c)).is_empty());
        // wobbling at the cap does not end the state, a tenth below does
        assert!(n.step(&setup, &obs(5001, 99, c)).is_empty());
        let r = n.step(&setup, &obs(5002, 90, c));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].level, Level::Info);
        // capped again: a new episode starts with its own line
        c.sessions_capped += 1;
        assert_eq!(texts(n.step(&setup, &obs(5003, 100, c))).len(), 1);
    }

    #[test]
    fn no_upgrade_after_grace_once_then_summaries_then_recovery() {
        let setup = Setup::default();
        let mut n = Notifier::new();
        let mut c = Counters::default();
        assert!(n.step(&setup, &obs(0, 0, c)).is_empty());
        c.declined = 5;
        assert!(
            n.step(&setup, &obs(599, 0, c)).is_empty(),
            "inside the grace time"
        );
        let t = texts(n.step(&setup, &obs(600, 0, c)));
        assert_eq!(t.len(), 1);
        assert!(
            t[0].starts_with("rdma: configured but no connection upgraded after 600s"),
            "{t:?}"
        );
        c.declined = 9;
        assert!(n.step(&setup, &obs(700, 0, c)).is_empty());
        let t = texts(n.step(&setup, &obs(1200, 0, c)));
        assert_eq!(
            t,
            ["rdma: 4 connections stayed on TCP since the last message"]
        );
        c.upgraded = 1;
        let r = n.step(&setup, &obs(1300, 1, c));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].level, Level::Info);
        assert!(n.step(&setup, &obs(9999, 1, c)).is_empty());
    }

    #[test]
    fn unusable_devices_are_told_once_and_off_is_silent() {
        let setup = Setup {
            max_sessions: 0,
            unusable: vec![Unusable {
                addr: "172.28.0.11".into(),
                reason: "path MTU 512 below 1024".into(),
            }],
            reads: false,
        };
        let mut n = Notifier::new();
        let t = texts(n.step(&setup, &obs(0, 0, Counters::default())));
        assert_eq!(
            t,
            [
                "rdma: device 172.28.0.11 unusable: path MTU 512 below 1024 (connections of this address stay on TCP)"
            ]
        );
        assert!(n.step(&setup, &obs(1, 0, Counters::default())).is_empty());
        let mut off = Notifier::new();
        let mut o = obs(0, 0, Counters::default());
        o.enabled = false;
        assert!(off.step(&setup, &o).is_empty());
    }

    #[test]
    fn transport_counters_merge_reset_and_render() {
        let a = Counters {
            credit_stall_ns: 100,
            grants_demand: 2,
            grants_admission: 3,
            idle_decays: 4,
            slot_wakeups: 5,
            tx_sends: 6,
            tx_chunks: 9,
            tx_doorbells: 2,
            tx_write_wrs: 3,
            tx_write_bytes: 1536,
            tx_write_doorbells: 4,
            tx_write_sq_stalls: 1,
            wakes: 7,
            rx_post_failures: 1,
            cq_errors: 2,
            rx_withheld: 3,
            ..Default::default()
        };
        let mut s = a;
        s.merge(&a);
        assert_eq!(
            (s.credit_stall_ns, s.grants_demand, s.slot_wakeups),
            (200, 4, 10)
        );
        let d = s.since(&a);
        assert_eq!(d, a);
        let j = s.json();
        assert_eq!(j["tx_write_wrs"], 2 * a.tx_write_wrs);
        assert_eq!(j["tx_write_bytes"], 2 * a.tx_write_bytes);
        assert_eq!(j["tx_write_doorbells"], 2 * a.tx_write_doorbells);
        assert_eq!(j["tx_write_sq_stalls"], 2 * a.tx_write_sq_stalls);
        assert_eq!(j["credit_stall_ns"], 200);
        assert_eq!(j["grants_admission"], 6);
        assert_eq!(j["idle_decays"], 8);
        assert_eq!(
            (j["tx_sends"].as_u64(), j["tx_chunks"].as_u64()),
            (Some(12), Some(18))
        );
        assert_eq!(
            (j["tx_doorbells"].as_u64(), j["wakes"].as_u64()),
            (Some(4), Some(14))
        );
        assert_eq!(
            (
                j["rx_post_failures"].as_u64(),
                j["cq_errors"].as_u64(),
                j["rx_withheld"].as_u64()
            ),
            (Some(2), Some(4), Some(6))
        );
    }

    #[test]
    fn status_document_sums_cores_and_renders_plain() {
        let d = |sessions, c: Counters| DeviceStatus {
            addr: "172.28.0.11".into(),
            device: "mlx5_0".into(),
            sessions,
            capacity: 106,
            slots: 320,
            granted: 3 * sessions,
            session_credits: 3 * sessions,
            held: 1,
            counters: c,
        };
        let parts = [
            core_json(
                0,
                &[d(
                    2,
                    Counters {
                        upgraded: 2,
                        credit_stalls: 7,
                        ..Default::default()
                    },
                )],
            ),
            core_json(
                1,
                &[d(
                    5,
                    Counters {
                        upgraded: 5,
                        declined: 1,
                        cq_errors: 1,
                        rx_withheld: 3,
                        ..Default::default()
                    },
                )],
            ),
        ];
        let doc = merge(
            true,
            &Setup {
                max_sessions: 0,
                unusable: vec![],
                reads: true,
            },
            &Process {
                leaked_cores: 1,
                teardown_failures: 2,
                qp_drain_timeouts: 4,
                quarantined_windows: 5,
                quarantined_write_sources: 6,
            },
            &parts,
        );
        assert_eq!(
            (
                doc["leaked_cores"].as_u64(),
                doc["teardown_failures"].as_u64(),
                doc["qp_drain_timeouts"].as_u64(),
                doc["quarantined_windows"].as_u64(),
                doc["quarantined_write_sources"].as_u64()
            ),
            (Some(1), Some(2), Some(4), Some(5), Some(6))
        );
        assert_eq!(doc["devices"][0]["cq_errors"], 1);
        assert_eq!(doc["devices"][0]["rx_withheld"], 3);
        assert_eq!(doc["devices"][0]["rx_post_failures"], 0);
        assert_eq!(doc["sessions"], 7);
        assert_eq!(doc["devices"][0]["upgraded"], 7);
        assert_eq!(doc["devices"][0]["credit_stalls"], 7);
        assert_eq!(doc["devices"][0]["granted_credits"], 21);
        assert_eq!(doc["devices"][0]["device"], "mlx5_0");
        assert_eq!(doc["cores"].as_array().unwrap().len(), 2);
        let p = plain(&doc);
        assert!(
            p.starts_with("rdma enabled, max_sessions unlimited, sessions 7\n"),
            "{p}"
        );
        assert!(p.contains("172.28.0.11 (mlx5_0): sessions 7"), "{p}");
        assert!(p.contains("  core 1 172.28.0.11: sessions 5"), "{p}");
        assert!(
            p.contains("\nleaked_cores 1 teardown_failures 2 qp_drain_timeouts 4 quarantined_windows 5 quarantined_write_sources 6\n"),
            "{p}"
        );
        assert!(
            p.contains("rx_post_failures 0 cq_errors 1 rx_withheld 3\n"),
            "{p}"
        );
    }
}
