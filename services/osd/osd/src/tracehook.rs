// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Glue between the op paths and [`crate::trace`]: which ops are sampled, the stamps that need PG / link context, and
//! the admin commands (`dump_op_traces`, `trace_summary`, `trace_reset`). Every entry is behind a one-word check at
//! the call site (adr 0170-op-trace).
use crate::backend::Backend;
use crate::osd::Osd;
use crate::tell::{EINVAL, Out, Res};
use crate::trace::{self, Ev, Format};
use crate::xcore::XMsg;
use denc::types::EntityName;
use opwire::MOSDOp;
use replwire::ReplMsg;
use serde_json::{Value, json};

/// Payload bytes of an op: write data plus the length requested by reads.
fn op_size(op: &MOSDOp) -> u32 {
    let n: u64 = op
        .ops
        .iter()
        .map(|o| match o.op {
            opwire::op::READ | opwire::op::SPARSE_READ => o.extent().length,
            _ => o.indata.len() as u64,
        })
        .sum();
    n.min(u64::from(u32::MAX)) as u32
}

/// First op that is not an allocation hint (what rbd puts before every write).
fn main_op(op: &MOSDOp) -> u16 {
    op.ops
        .iter()
        .map(|o| o.op)
        .find(|c| *c != opwire::op::SET_ALLOC_HINT)
        .unwrap_or(0)
}

impl<B: Backend> Osd<B> {
    /// The NIC rx call of this loop step returned frames (driver hook, before decode).
    #[inline]
    pub fn trace_rx_polled(&mut self) {
        self.pg.tr.rx_polled();
    }

    /// The tx step of this loop iteration finished (driver hook).
    #[inline]
    pub fn trace_tx_done(&mut self) {
        if self.pg.tr.tx_pending() {
            self.pg.tr.tx_done();
        }
    }

    /// Conn core: client op decoded (sampling on).
    #[cold]
    #[inline(never)]
    pub(crate) fn trace_ingress(&mut self, id: u64, tid: u64, op: &MOSDOp) {
        let Some(info) = self.conn_info(id) else {
            return;
        };
        let key = trace::key_of(&op.effective_reqid(info.who, tid));
        if self.pg.tr.sampled(key) {
            self.pg.tr.ingress(key, false, 0);
        }
    }

    /// PG core: client op reached its PG (sampling on). Returns the trace id, 0 = not sampled.
    #[cold]
    #[inline(never)]
    pub(crate) fn trace_op_in(&mut self, id: u64, tid: u64, op: &MOSDOp, who: EntityName) -> u64 {
        let key = trace::key_of(&op.effective_reqid(who, tid));
        if !self.pg.tr.sampled(key) {
            return 0;
        }
        let pg = trace::pg_aux(op.pgid.pgid.pool, op.pgid.pgid.seed);
        self.pg.tr.op_in(key, id, tid, pg, op_size(op), main_op(op));
        key
    }

    /// Conn core: peer message arrived (sampling on).
    #[cold]
    #[inline(never)]
    pub(crate) fn trace_peer_in(&mut self, body: &peering::Body) {
        if let peering::Body::Repl(ReplMsg::RepOp(r)) = body {
            let key = trace::key_of(&r.reqid);
            if self.pg.tr.sampled(key) {
                self.pg
                    .tr
                    .ingress(key, true, trace::pg_aux(r.pgid.pgid.pool, r.pgid.pgid.seed));
            }
        }
    }

    /// PG core: peer message about to be handled. `true` = a sampled RepOp whose apply must call `repl_done`.
    #[cold]
    #[inline(never)]
    pub(crate) fn trace_peer_pg(&mut self, body: &peering::Body, from: i32, tid: u64) -> bool {
        match body {
            peering::Body::Repl(ReplMsg::RepOp(r)) if self.pg.tr.on() => {
                let key = trace::key_of(&r.reqid);
                if self.pg.tr.sampled(key) {
                    let pg = trace::pg_aux(r.pgid.pgid.pool, r.pgid.pgid.seed);
                    self.pg.tr.repl_pg(key, tid, pg);
                    return true;
                }
                false
            }
            peering::Body::Repl(ReplMsg::RepOpReply(_)) => {
                self.pg.tr.rep_ack(tid, from);
                false
            }
            _ => false,
        }
    }

    /// PG core: PG message encoded for `to`. Returns the trace id and tx stage of a repop / replica ack frame that must get a tx stamp.
    #[cold]
    #[inline(never)]
    pub(crate) fn trace_peer_out(&mut self, s: &peering::Send, to: i32) -> Option<(u64, u8)> {
        match &s.body {
            peering::Body::Repl(ReplMsg::RepOp(_)) => {
                Some((self.pg.tr.rep_send(s.tid, to)?, trace::REP_TX))
            }
            peering::Body::Repl(ReplMsg::RepOpReply(_)) => {
                let spg = peering::body_spg(&s.body)?;
                self.pg
                    .tr
                    .ack_out(s.tid, trace::pg_aux(spg.pgid.pool, spg.pgid.seed))
                    .map(|k| (k, trace::R_TX))
            }
            _ => None,
        }
    }

    /// A frame of sampled op `key` was handed to link core `core`: that core stamps the next tx step.
    #[cold]
    #[inline(never)]
    pub(crate) fn trace_tx_queue(&mut self, key: u64, stage: u8, core: usize) {
        if core == self.cl.spec.id {
            self.pg.tr.await_tx(key, stage);
        } else {
            self.xsend(core, XMsg::TraceTx { key, stage });
        }
    }

    /// Classic historic-op events of sampled op `key` as `(offset ns after reached_pg, name)`.
    pub(crate) fn trace_hist_events(&self, key: u64) -> Vec<(u64, String)> {
        let evs = self.pg.tr.events_of(key);
        let Some(t0) = evs.iter().find(|e| e.stage == trace::PG_IN).map(|e| e.t) else {
            return Vec::new();
        };
        evs.iter()
            .filter_map(|e| {
                Some((
                    trace::to_ns(e.t).saturating_sub(trace::to_ns(t0)),
                    trace::classic_event(e)?,
                ))
            })
            .collect()
    }

    /// This core's part of a trace command.
    pub(crate) fn trace_query_local(&mut self, prefix: &str) -> (i32, Value) {
        match prefix {
            "trace_reset" => {
                self.pg.tr.reset();
                (0, Value::Null)
            }
            _ => (
                0,
                Value::Array(self.pg.tr.snapshot().into_iter().map(Ev::to_json).collect()),
            ),
        }
    }

    /// Control core: the answer of `dump_op_traces` / `trace_summary` / `trace_reset` from every core's part.
    pub(crate) fn trace_merge(&self, prefix: &str, v: &Value, parts: Vec<(i32, Value)>) -> Res {
        if prefix == "trace_reset" {
            return Self::ok(json!({"schema": 1, "reset": true}));
        }
        let Some(f) = Format::parse(v.get("format").and_then(Value::as_str)) else {
            return (
                EINVAL,
                "format: plain|json|json-pretty|jsonl".into(),
                Out::default(),
            );
        };
        let evs: Vec<Ev> = parts
            .iter()
            .flat_map(|(_, p)| p.as_array().into_iter().flatten())
            .filter_map(Ev::from_json)
            .collect();
        let traces = trace::join(evs);
        if prefix == "dump_op_traces" {
            let last = v
                .get("last")
                .and_then(|x| x.as_u64().or_else(|| x.as_str()?.parse().ok()))
                .unwrap_or(0) as usize;
            return (0, String::new(), trace::render_dump(traces, last, f).into());
        }
        if f == Format::Jsonl {
            return (
                EINVAL,
                "trace_summary: format plain|json|json-pretty".into(),
                Out::default(),
            );
        }
        let sample = self.conf.u64("flashstore_trace_sample", 0) as u32;
        let s = trace::summary(&traces, sample);
        if f == Format::Plain {
            (
                0,
                String::new(),
                trace::summary_plain(&s).into_bytes().into(),
            )
        } else {
            Self::ok(s)
        }
    }
}
