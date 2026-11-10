// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! RDMA visibility at the OSD (0469-rdma-transport, Visibility): the transport hands its numbers in ([`Osd::note_rdma`],
//! once per second per core), they leave as OSD perf counters (`perf.rs`, MMgrReport), as `rdma status` (admin socket /
//! tell, `--format plain|json|json-pretty`) and as rate-limited cluster-log warnings ([`rdma::status::Notifier`]). Ceph
//! compatible means only: no own health check codes.
use crate::backend::Backend;
use crate::osd::Osd;
use crate::tell::Res;
use messages::clog;
use rdma::status::{
    DeviceStatus, Level, Notifier, Observed, Process, Setup, core_json, merge, plain,
};
use serde_json::Value;

/// RDMA state of one core.
#[derive(Debug, Default)]
pub(crate) struct RdmaState {
    /// Process-wide facts from the transport (session limit, unusable devices).
    pub setup: Setup,
    /// This core's devices, as last reported.
    pub devices: Vec<DeviceStatus>,
    /// Process-wide teardown outcomes, as last reported (the same on every core).
    pub process: Process,
    /// Control core: the cluster-log rate limiter.
    pub notifier: Notifier,
}

impl<B: Backend> Osd<B> {
    /// Driver hook, once at startup: the session limit and the devices that could not be used.
    pub fn note_rdma_setup(&mut self, setup: Setup) {
        // The source-pull banner is a promise the transport must keep: it stays off
        // unless every usable device runs READ-capable QPs (spec rdma-read-offer.md).
        for m in &mut self.msgr {
            m.cfg.source_pull &= setup.reads;
        }
        self.rdma.setup = setup;
    }

    /// Driver hook, once per second: this core's status per RDMA device (cumulative counters, sessions, credits) and the
    /// process-wide teardown outcomes (the control core's copy is reported).
    pub fn note_rdma(&mut self, devices: Vec<DeviceStatus>, process: Process) {
        self.rdma.process = process;
        let o = &mut self.perf.op;
        o.rdma = Default::default();
        o.rdma_sessions = 0;
        for d in &devices {
            o.rdma.merge(&d.counters);
            o.rdma_sessions += u64::from(d.sessions);
        }
        self.rdma.devices = devices;
    }

    /// Control core, every tick (also during startup): cluster-log and daemon-log lines when the numbers of all cores call for one.
    pub(crate) fn rdma_notice_tick(&mut self) {
        if !self.cfg.rdma || !self.is_control() {
            return;
        }
        let all = self.op_perf_all();
        let o = Observed {
            now: self.mnow(),
            enabled: true,
            max_sessions: self.rdma.setup.max_sessions,
            sessions: all.rdma_sessions,
            counters: all.rdma,
        };
        for n in self.rdma.notifier.step(&self.rdma.setup, &o) {
            let prio = match n.level {
                Level::Warn => clog::WARN,
                Level::Info => clog::INFO,
            };
            self.clog(prio, &n.text);
            self.logl(0, n.text);
        }
    }

    /// `rdma status`, the part of this core.
    pub(crate) fn rdma_part(&self) -> Value {
        core_json(self.cl.spec.id, &self.rdma.devices)
    }

    /// `rdma status`, the answer from the parts of all cores, in the requested format.
    pub(crate) fn rdma_reply(&self, cmd: &Value, parts: &[(i32, Value)]) -> Res {
        let mut parts: Vec<Value> = parts.iter().map(|(_, p)| p.clone()).collect();
        parts.sort_by_key(|p| p["core"].as_u64().unwrap_or(0));
        let doc = merge(self.cfg.rdma, &self.rdma.setup, &self.rdma.process, &parts);
        match cmd.get("format").and_then(Value::as_str) {
            Some("plain") => (0, String::new(), plain(&doc).into_bytes().into()),
            _ => Self::ok(doc),
        }
    }
}
