// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Mgr client (spec 8): follow the MgrMap, connect over the public messenger, MMgrOpen, honour
//! MMgrConfigure, periodic MMgrReport + MPGStats.
use crate::backend::Backend;
use crate::osd::{MsgrId, Osd, Purpose, State};
use denc::types::{EntityAddrVec, EntityName};
use messages::{
    AnyMessage, ConfigBl, DaemonHealthMetric, MMgrConfigure, MMgrMap, MMgrOpen, MMgrReport,
    MPGStats, OsdStat, PerfReporter, encode_config_defaults_bl,
};
use std::time::Duration;

/// `mgr_connect_retry_interval` default (spec osd-lifecycle.md 8.1), used when the option is unusable.
const MGR_RETRY_DEFAULT: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub(crate) struct MgrState {
    pub link: Option<u64>,
    pub addrs: EntityAddrVec,
    pub available: bool,
    pub stats_period: u32,
    pub threshold: u32,
    pub next_report: Option<Duration>,
    pub retry_at: Option<Duration>,
    pub last_attempt: Option<Duration>,
    /// Raw `mgr_connect_retry_interval` of the last "not a usable duration" warning.
    pub retry_warned: Option<String>,
    pub reporter: PerfReporter,
    /// `conf.version()` of the last `config_bl` sent (MMgrOpen or a report): reports send the blob only when it moved.
    pub config_version: u64,
}

impl MgrState {
    pub(crate) fn new() -> Self {
        Self {
            link: None,
            addrs: EntityAddrVec::default(),
            available: false,
            stats_period: 0,
            threshold: 5,
            next_report: None,
            retry_at: None,
            last_attempt: None,
            retry_warned: None,
            reporter: PerfReporter::new(),
            config_version: 0,
        }
    }
}

impl<B: Backend> Osd<B> {
    pub(crate) fn on_mgrmap(&mut self, m: &MMgrMap) {
        let p = &m.prefix;
        self.log(format!(
            "mgrmap e{}: active {:?} available={} addrs {}",
            p.epoch,
            p.active_name,
            p.available,
            crate::osd::addrs_str(&p.active_addrs)
        ));
        self.mgr.available = p.available;
        let changed = self.mgr.addrs != p.active_addrs;
        self.mgr.addrs = p.active_addrs.clone();
        if !p.available {
            if let Some(l) = self.mgr.link {
                self.close_link(l);
            }
            return;
        }
        if changed && let Some(l) = self.mgr.link {
            self.close_link(l);
        }
        if self.mgr.link.is_none() {
            self.mgr_connect();
        }
    }

    /// `mgr_connect_retry_interval` (a schema `float` without min/max): a negative, non-finite or out-of-range value
    /// falls back to the 1 s default instead of aborting a reconnect in the deadline arithmetic; a rejected value is
    /// warned once.
    fn mgr_retry_interval(&mut self) -> Duration {
        let v = self.conf.f64(
            "mgr_connect_retry_interval",
            MGR_RETRY_DEFAULT.as_secs_f64(),
        );
        if let Ok(d) = Duration::try_from_secs_f64(v) {
            return d;
        }
        let raw = self
            .conf
            .get("mgr_connect_retry_interval")
            .unwrap_or("")
            .to_owned();
        if self.mgr.retry_warned.as_deref() != Some(raw.as_str()) {
            self.logl(
                0,
                format!(
                    "WARNING mgr_connect_retry_interval {raw}: not a usable duration, using the {}s default",
                    MGR_RETRY_DEFAULT.as_secs_f64()
                ),
            );
            self.mgr.retry_warned = Some(raw);
        }
        MGR_RETRY_DEFAULT
    }

    pub(crate) fn mgr_connect(&mut self) {
        if !self.mgr.available || self.mgr.link.is_some() || self.state == State::Stopping {
            return;
        }
        let retry = self.mgr_retry_interval();
        if let Some(t) = self.mgr.last_attempt
            && self.now.saturating_sub(t) < retry
        {
            self.mgr.retry_at = Some(t.saturating_add(retry));
            return;
        }
        self.mgr.last_attempt = Some(self.now);
        let a = self.mgr.addrs.clone();
        self.mgr.link = self.dial(MsgrId::Public, Purpose::Mgr, EntityName::MGR, &a);
        if self.mgr.link.is_none() {
            self.log("mgr: no v2 address in MgrMap");
        }
    }

    pub(crate) fn mgr_link_lost(&mut self, id: u64) {
        if self.mgr.link != Some(id) {
            return;
        }
        self.mgr.link = None;
        self.mgr.stats_period = 0;
        self.mgr.next_report = None;
        if self.mgr.available {
            let retry_at = self.now.saturating_add(self.mgr_retry_interval());
            self.mgr.retry_at = Some(retry_at);
        }
    }

    pub(crate) fn mgr_ready(&mut self, id: u64) {
        if self.mgr.link != Some(id) {
            return;
        }
        self.mgr.stats_period = 0;
        self.mgr.next_report = None;
        self.mgr.reporter.reset();
        let config_bl = self.config_bl().unwrap_or_else(|| vec![0; 8]);
        self.mgr.config_version = self.conf.version();
        let defaults =
            encode_config_defaults_bl(&self.conf.defaults()).unwrap_or_else(|_| vec![0; 4]);
        let mut open = MMgrOpen::osd(self.id.whoami);
        open.config_bl = config_bl;
        open.config_defaults_bl = defaults;
        self.log("mgr session open: sending MMgrOpen");
        self.send_link(id, open);
    }

    pub(crate) fn on_mgr_message(&mut self, msg: AnyMessage) {
        match msg {
            AnyMessage::MMgrConfigure(c) => self.on_mgr_configure(c),
            AnyMessage::MMgrClose(_) => self.log("mgr sent MMgrClose (ignored)"),
            other => self.log(format!(
                "mgr: unhandled message type {:#x}",
                other.msg_type()
            )),
        }
    }

    fn on_mgr_configure(&mut self, c: MMgrConfigure) {
        let was = self.mgr.stats_period;
        self.mgr.stats_period = c.stats_period;
        self.mgr.threshold = c.stats_threshold;
        self.log(format!(
            "mgr configure: stats_period {} threshold {}",
            c.stats_period, c.stats_threshold
        ));
        if c.stats_period == 0 {
            self.mgr.next_report = None;
        } else if was == 0 {
            self.mgr_report_tick();
        }
    }

    pub(crate) fn mgr_report_tick(&mut self) {
        let Some(l) = self.mgr.link else {
            self.mgr.next_report = None;
            return;
        };
        if self.mgr.stats_period == 0 {
            self.mgr.next_report = None;
            return;
        }
        self.send_mgr_report(l);
        self.mgr.next_report =
            Some(self.now + Duration::from_secs(u64::from(self.mgr.stats_period)));
    }

    /// `num_shards_repaired` of osd_stat: damaged objects repaired from a peer, minus what `clear_shards_repaired` cleared.
    pub(crate) fn shards_repaired_shown(&self) -> u64 {
        self.op_perf_all()
            .shards_repaired
            .saturating_sub(self.perf.repaired_cleared)
    }

    /// OSD-level statfs: the store's capacity plus the OMAP bytes of the hosted PGs (deep-scrub measurement; adr 0614
    /// am. 1) moved out of internal metadata. The single source for `osd_stat`, `dump_osd_pg_stats` and the
    /// `bluestore.omap_bytes` gauge. Per-pool OMAP allocation stays zero.
    pub(crate) fn osd_statfs(&self) -> messages::StoreStatfs {
        let mut sf = self.statfs_all();
        let omap = self.pg_omap_bytes();
        sf.omap_allocated = omap;
        sf.internal_metadata = (sf.internal_metadata - omap).max(0);
        sf
    }

    pub(crate) fn osd_stat(&mut self) -> OsdStat {
        self.stat_seq += 1;
        let sf = self.osd_statfs();
        let mut st = OsdStat::from_statfs(
            sf,
            self.up_epoch,
            (u64::from(self.up_epoch) << 32) + self.stat_seq,
        );
        st.hb_peers = self.hb.peers.keys().copied().collect();
        st.hb_pingtime = self.hb_pingtime(
            self.wall().sec,
            self.conf.u64("osd_mon_heartbeat_stat_stale", 3600) as u32,
        );
        st.num_shards_repaired = self.shards_repaired_shown();
        st.os_perf_stat = self.os_perf_window();
        st.num_pgs = self.pg_num_pgs();
        let alerts = self.os_alerts();
        if !alerts.is_empty() {
            st.os_alerts.insert(self.id.whoami, alerts);
        }
        let (lce, pgs) = self.pg_collect();
        self.last_collect_epoch = lce;
        self.last_collect_pgs = pgs;
        st
    }

    /// `ceph osd perf` (spec pg-io-stats.md 4): mean durable commit latency of every store transaction (client writes,
    /// sub-writes, recovery, metadata) since the previous osd_stat build; commit = apply (one durable step); 0 without
    /// commits in the window. A counter reset (`perf reset`) starts a new window.
    pub(crate) fn os_perf_window(&mut self) -> messages::ObjectstorePerfStat {
        let now = self.op_perf_all().store_lat;
        let last = std::mem::replace(&mut self.perf.last_store, now);
        let ns = match (
            now.n.checked_sub(last.n),
            now.sum_ns.checked_sub(last.sum_ns),
        ) {
            (Some(n), Some(sum)) if n > 0 => sum / n,
            _ => 0,
        };
        self.perf.last_os_perf = messages::ObjectstorePerfStat {
            os_commit_latency_ns: ns,
            os_apply_latency_ns: ns,
        };
        self.perf.last_os_perf
    }

    /// `config_bl` payload of MMgrOpen / MMgrReport: the full non-default snapshot plus the ignored mon values, never a
    /// delta. `None` = it does not encode.
    fn config_bl(&self) -> Option<Vec<u8>> {
        ConfigBl {
            options: crate::schema::configured(&self.conf)
                .filter(|(k, _)| *k != "fsid" && *k != "host")
                .map(|(k, l)| {
                    let levels = l.iter().map(|(lv, v)| (i32::from(*lv), v.clone()));
                    (k.clone(), levels.collect())
                })
                .collect(),
            ignored_mon_values: self.conf.ignored_mon_values().clone(),
        }
        .encode()
        .ok()
    }

    /// `config_bl` of the next report: the full snapshot when the config changed since the last send, empty otherwise
    /// (spec ops-observability 6.3).
    fn report_config_bl(&mut self) -> Vec<u8> {
        if self.mgr.config_version == self.conf.version() {
            return Vec::new();
        }
        let bl = self.config_bl().unwrap_or_default();
        self.mgr.config_version = self.conf.version();
        bl
    }

    /// Counters report followed by MPGStats (spec 8.4 / 8.5).
    pub(crate) fn send_mgr_report(&mut self, l: u64) {
        let counters = self.counters();
        let threshold = self.mgr.threshold;
        match self.mgr.reporter.build(&counters, threshold) {
            Ok(rep) => {
                let mut r = MMgrReport::new(self.id.whoami.to_string());
                r.set_perf(rep);
                r.daemon_health_metrics = self.health_metrics();
                r.config_bl = self.report_config_bl();
                self.send_link(l, r);
            }
            Err(e) => self.log(format!("mgr report build failed: {e}")),
        }
        let stat = self.osd_stat();
        let m = MPGStats {
            version: 0,
            fsid: self.id.cluster_fsid,
            osd_stat: stat,
            pg_stat: self.pg_stat_list(),
            epoch: self.epoch(),
            dummy: Default::default(),
            pool_stat: self.pg_pool_statfs(),
        };
        self.send_link(l, m);
    }

    /// Control core, after every core shipped fresh numbers (`flush_pg_stats`): send the stats now; returns the
    /// sequence number.
    pub(crate) fn flush_pg_stats(&mut self) -> u64 {
        self.sample_counters();
        if let Some(l) = self.mgr.link
            && self.mgr.stats_period > 0
        {
            self.send_mgr_report(l);
        }
        (u64::from(self.up_epoch) << 32) + self.stat_seq
    }
}

impl<B: Backend> Osd<B> {
    /// Daemon health metrics of MMgrReport: both metrics on every report, also when zero (spec ops-observability
    /// 6.2). SLOW_OPS = count of ops older than `osd_op_complaint_time` in the low 32 bits, oldest age in s in the
    /// high 32 bits, and 0/0 while no op is that old: the mgr raises SLOW_OPS for a non-zero age alone ("0 slow
    /// ops, oldest one blocked for 2 sec"). PENDING_CREATING_PGS = creates of PGs this OSD leads withheld by the PG hard
    /// limit, all cores (peering.md 7.3 rule 3a).
    pub(crate) fn health_metrics(&self) -> Vec<DaemonHealthMetric> {
        let p = self.op_perf_all();
        let slow = if p.slow_n == 0 {
            0
        } else {
            (p.oldest_s.min(u64::from(u32::MAX)) << 32) | p.slow_n.min(u64::from(u32::MAX))
        };
        vec![
            DaemonHealthMetric {
                ty: DaemonHealthMetric::SLOW_OPS,
                value: slow,
            },
            DaemonHealthMetric {
                ty: DaemonHealthMetric::PENDING_CREATING_PGS,
                value: self.pg.set.pending_creating_pgs()
                    + self
                        .cl
                        .stats
                        .iter()
                        .flatten()
                        .map(|s| s.pending_creating)
                        .sum::<u64>(),
            },
        ]
    }
}
