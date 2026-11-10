// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Op tracker (spec/ops-observability.md 3): in-flight + historic client ops for `dump_ops_in_flight`,
//! `dump_historic_ops*`, `dump_blocked_ops` and the SLOW_OPS health metric.
//!
//! One tracker per core (the PG core that runs the op). Per op: one fixed-size record (no heap: the object name is
//! copied inline, truncated), one hash insert at start, one remove at reply. Memory is bounded: at most [`MAX_OPS`]
//! live records, the historic rings hold `osd_op_history_size` / `osd_op_history_slow_op_size` records. Descriptions
//! are formatted only when dumped.
use crate::osd::FastMap;
use denc::types::{EntityAddr, EntityName, SpgT, UTime};
use serde_json::{Value, json};
use std::collections::VecDeque;

/// Live records per core; beyond that ops run untracked (counted).
pub(crate) const MAX_OPS: usize = 1 << 16;
const NAME_CAP: usize = 56;
const OPS_CAP: usize = 4;

#[derive(Clone, Debug)]
pub(crate) struct OpRec {
    pub conn: u64,
    pub tid: u64,
    pub client: EntityName,
    pub addr: EntityAddr,
    pub spg: SpgT,
    pub epoch: u32,
    pub flags: u32,
    pub nops: u8,
    pub ops: [u16; OPS_CAP],
    pub oid_len: u8,
    pub oid: [u8; NAME_CAP],
    /// Write payload bytes of the request.
    pub inb: u64,
    /// Ns on the OSD clock ([`crate::Osd`] `now`): op reached the PG core / finished.
    pub start: u64,
    pub end: u64,
    pub outb: u64,
    pub result: i32,
    /// Trace id when the op is sampled (trace.rs), else 0.
    pub trace_key: u64,
}

impl OpRec {
    pub fn new(
        conn: u64,
        tid: u64,
        client: EntityName,
        addr: EntityAddr,
        op: &opwire::MOSDOp,
        start: u64,
    ) -> OpRec {
        let mut ops = [0u16; OPS_CAP];
        for (d, o) in ops.iter_mut().zip(&op.ops) {
            *d = o.op;
        }
        let mut oid = [0u8; NAME_CAP];
        let n = op.oid.len().min(NAME_CAP);
        oid[..n].copy_from_slice(&op.oid[..n]);
        OpRec {
            conn,
            tid,
            client,
            addr,
            spg: op.pgid,
            epoch: op.osdmap_epoch,
            flags: op.flags,
            nops: op.ops.len().min(OPS_CAP) as u8,
            ops,
            oid_len: n as u8,
            oid,
            inb: op.ops.iter().map(|o| o.indata.len() as u64).sum(),
            start,
            end: 0,
            outb: 0,
            result: 0,
            trace_key: 0,
        }
    }

    fn description(&self) -> String {
        let oid = String::from_utf8_lossy(&self.oid[..self.oid_len as usize]);
        let ops: Vec<String> = self.ops[..self.nops as usize]
            .iter()
            .map(|c| opwire::op::name(*c).map_or_else(|| format!("{c:#x}"), str::to_owned))
            .collect();
        let rw = match (
            self.flags & opwire::flag::READ != 0,
            self.flags & opwire::flag::WRITE != 0,
        ) {
            (true, true) => "read+write",
            (false, true) => "write",
            (true, false) => "read",
            _ => "",
        };
        format!(
            "osd_op({}:{} {} {} [{}] {} e{})",
            self.client,
            self.tid,
            self.spg,
            oid,
            ops.join(","),
            rw,
            self.epoch
        )
    }

    /// Classic JSON shape. `wall(ns)` = classic timestamp text of an OSD-clock instant.
    fn json(
        &self,
        now: u64,
        wall: &dyn Fn(u64) -> String,
        done: bool,
        extra: &[(u64, String)],
    ) -> Value {
        let dur = if done {
            self.end - self.start
        } else {
            now.saturating_sub(self.start)
        };
        let s = |ns: u64| ns as f64 / 1e9;
        let mut events = vec![
            json!({"event": "initiated", "time": wall(self.start), "duration": 0.0}),
            json!({"event": "reached_pg", "time": wall(self.start), "duration": 0.0}),
        ];
        // stamps of a sampled op (trace.rs), classic event names; duration = time since the previous event
        let mut prev = 0;
        for (off, name) in extra {
            events.push(json!({"event": name, "time": wall(self.start + off), "duration": s(off.saturating_sub(prev))}));
            prev = prev.max(*off);
        }
        if done {
            events.push(json!({"event": "done", "time": wall(self.end), "duration": s(dur)}));
        }
        json!({
            "description": self.description(),
            "initiated_at": wall(self.start),
            "age": s(now.saturating_sub(self.start)),
            "duration": s(dur),
            "type_data": {
                "flag_point": if done { "done" } else { "reached pg" },
                "client_info": {"client": self.client.to_string(), "client_addr": self.addr.to_string(), "tid": self.tid},
                "events": events,
            }
        })
    }
}

impl OpRec {
    /// JSON of an op that has not reached its PG yet (`why` = flag point / event, e.g. `waiting for map`).
    pub fn json_waiting(&self, now: u64, wall: &dyn Fn(u64) -> String, why: &str) -> Value {
        let mut v = self.json(now, wall, false, &[]);
        v["type_data"]["flag_point"] = json!(why);
        v["type_data"]["events"] = json!([
            {"event": "initiated", "time": wall(self.start), "duration": 0.0},
            {"event": why, "time": wall(self.start), "duration": 0.0},
        ]);
        v
    }
}

/// What the caller needs to account a finished op.
#[derive(Clone, Copy)]
pub(crate) struct Done {
    pub inb: u64,
    pub lat: u64,
}

/// Bounds (refreshed from the config once a tick).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub hist_size: usize,
    pub hist_dur_ns: u64,
    pub slow_size: usize,
    pub slow_ns: u64,
    pub complaint_ns: u64,
    /// `osd_enable_op_tracker`: false = no per-op record at all (no live map, no rings).
    pub enabled: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            hist_size: 20,
            hist_dur_ns: 600_000_000_000,
            slow_size: 20,
            slow_ns: 10_000_000_000,
            complaint_ns: 30_000_000_000,
            enabled: true,
        }
    }
}

#[derive(Default)]
pub(crate) struct OpTracker {
    live: FastMap<(u64, u64), OpRec>,
    hist: VecDeque<OpRec>,
    slow: VecDeque<OpRec>,
    pub lim: Limits,
    /// Ops that ran untracked because [`MAX_OPS`] was reached.
    pub untracked: u64,
    /// Lab: tracked ops answered after > 100 ms / 1 s / 5 s, and the longest (ns).
    pub lat_over: [u64; 3],
    pub lat_max: u64,
}

impl std::fmt::Debug for OpTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpTracker({} live)", self.live.len())
    }
}

impl OpTracker {
    pub fn len(&self) -> usize {
        self.live.len()
    }

    /// Write payload bytes of the live ops.
    pub fn inflight_bytes(&self) -> u64 {
        self.live.values().map(|r| r.inb).sum()
    }

    /// An op reached its PG. A repeat of a live `(conn, tid)` (client resend) keeps the original start.
    pub fn start(&mut self, r: OpRec) {
        let k = (r.conn, r.tid);
        if self.live.len() >= MAX_OPS && !self.live.contains_key(&k) {
            self.untracked += 1;
            return;
        }
        self.live.entry(k).or_insert(r);
    }

    /// The op was answered. `None` = not tracked (internal op, untracked, already dropped).
    pub fn finish(
        &mut self,
        conn: u64,
        tid: u64,
        now: u64,
        outb: u64,
        result: i32,
    ) -> Option<Done> {
        let mut r = self.live.remove(&(conn, tid))?;
        r.end = now;
        r.outb = outb;
        r.result = result;
        let d = Done {
            inb: r.inb,
            lat: now.saturating_sub(r.start),
        };
        for (i, t) in [100_000_000u64, 1_000_000_000, 5_000_000_000]
            .iter()
            .enumerate()
        {
            self.lat_over[i] += u64::from(d.lat >= *t);
        }
        self.lat_max = self.lat_max.max(d.lat);
        let lim = self.lim;
        if d.lat >= lim.slow_ns && lim.slow_size > 0 {
            self.slow.push_back(r.clone());
            while self.slow.len() > lim.slow_size {
                self.slow.pop_front();
            }
        }
        if lim.hist_size > 0 {
            self.hist.push_back(r);
            while self.hist.len() > lim.hist_size
                || self
                    .hist
                    .front()
                    .is_some_and(|f| f.end.saturating_add(lim.hist_dur_ns) < now)
            {
                self.hist.pop_front();
            }
        }
        Some(d)
    }

    /// The op `(conn, tid)` was dropped without a reply (engine `take_dropped`: inside a backoff, stale, gate full,
    /// PG torn down). The client resends it (a new record starts) or supersedes it with a new tid (linger
    /// re-registration); either way this record would never see its reply.
    pub fn forget(&mut self, conn: u64, tid: u64) {
        self.live.remove(&(conn, tid));
    }

    /// Drop every live op of PG `spg` (its engine was reset or torn down: the client resends or the op re-runs and
    /// registers again).
    pub fn forget_pg(&mut self, spg: SpgT) {
        if self.live.values().any(|r| r.spg == spg) {
            self.live.retain(|_, r| r.spg != spg);
        }
    }

    /// Connection `conn` closed: its ops will never be answered.
    pub fn forget_conn(&mut self, conn: u64) {
        if self.live.values().any(|r| r.conn == conn) {
            self.live.retain(|_, r| r.conn != conn);
        }
    }

    /// `(count older than the complaint time, age of the oldest live op in ns)`.
    pub fn slow(&self, now: u64) -> (u64, u64) {
        let mut n = 0;
        let mut oldest = 0;
        for r in self.live.values() {
            let age = now.saturating_sub(r.start);
            oldest = oldest.max(age);
            n += u64::from(age >= self.lim.complaint_ns);
        }
        (n, oldest)
    }

    /// PGs of the live ops, oldest op first.
    pub fn live_spgs(&self) -> Vec<SpgT> {
        let mut v: Vec<(u64, SpgT)> = self.live.values().map(|r| (r.start, r.spg)).collect();
        v.sort_by_key(|x| x.0);
        v.into_iter().map(|x| x.1).collect()
    }

    /// Live ops, oldest first (`blocked_only` = older than the complaint time).
    pub fn dump_live(
        &self,
        now: u64,
        wall: &dyn Fn(u64) -> String,
        blocked_only: bool,
    ) -> Vec<(u64, Value)> {
        self.dump_live_with(now, wall, blocked_only, &|_| None)
    }

    /// [`Self::dump_live`] where `waiting((conn, tid))` names the peers a write still awaits (classic flag point
    /// `waiting for sub ops` and event `waiting for subops from N,M`).
    pub fn dump_live_with(
        &self,
        now: u64,
        wall: &dyn Fn(u64) -> String,
        blocked_only: bool,
        waiting: &dyn Fn((u64, u64)) -> Option<String>,
    ) -> Vec<(u64, Value)> {
        let mut v: Vec<&OpRec> = self
            .live
            .values()
            .filter(|r| !blocked_only || now.saturating_sub(r.start) >= self.lim.complaint_ns)
            .collect();
        v.sort_by_key(|r| r.start);
        v.into_iter()
            .map(|r| {
                let mut v = r.json(now, wall, false, &[]);
                if let Some(peers) = waiting((r.conn, r.tid)) {
                    v["type_data"]["flag_point"] = json!("waiting for sub ops");
                    if let Some(ev) = v["type_data"]["events"].as_array_mut() {
                        ev.push(json!({"event": format!("waiting for subops from {peers}"),
                            "time": wall(r.start), "duration": 0.0}));
                    }
                }
                (r.start, v)
            })
            .collect()
    }

    /// Finished ops `(duration ns, json)`; `slow_ring` = the slow-op ring instead of the recent ring.
    pub fn dump_hist(
        &self,
        now: u64,
        wall: &dyn Fn(u64) -> String,
        slow_ring: bool,
        extra: &dyn Fn(u64) -> Vec<(u64, String)>,
    ) -> Vec<(u64, u64, Value)> {
        let ring = if slow_ring { &self.slow } else { &self.hist };
        ring.iter()
            .filter(|r| slow_ring || r.end.saturating_add(self.lim.hist_dur_ns) >= now)
            .map(|r| {
                let x = if r.trace_key != 0 {
                    extra(r.trace_key)
                } else {
                    Vec::new()
                };
                (r.end, r.end - r.start, r.json(now, wall, true, &x))
            })
            .collect()
    }
}

/// Classic timestamp of an OSD-clock instant.
pub(crate) fn wall_str(origin_ns: u64, ns: u64) -> String {
    let t = origin_ns + ns;
    crate::pgs::utime_str(UTime::new(
        (t / 1_000_000_000) as u32,
        (t % 1_000_000_000) as u32,
    ))
}

/// Merge per-core dumps into the classic reply object.
pub(crate) fn live_reply(mut ops: Vec<(u64, Value)>) -> Value {
    ops.sort_by_key(|o| o.0);
    let n = ops.len();
    json!({"ops": ops.into_iter().map(|o| o.1).collect::<Vec<_>>(), "num_ops": n})
}

/// `dump_historic_ops` (recent order), `dump_historic_ops_by_duration`, `dump_historic_slow_ops`.
pub(crate) fn hist_reply(
    mut ops: Vec<(u64, u64, Value)>,
    size: usize,
    dur_s: u64,
    by_duration: bool,
) -> Value {
    if by_duration {
        ops.sort_by_key(|o| std::cmp::Reverse(o.1));
    } else {
        ops.sort_by_key(|o| o.0);
    }
    if ops.len() > size {
        if by_duration {
            ops.truncate(size);
        } else {
            ops.drain(..ops.len() - size);
        }
    }
    json!({"size": size, "duration": dur_s, "ops": ops.into_iter().map(|o| o.2).collect::<Vec<_>>()})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(conn: u64, tid: u64, start: u64) -> OpRec {
        let op = opwire::MOSDOp {
            oid: b"obj".to_vec(),
            flags: opwire::flag::WRITE,
            ops: vec![opwire::OsdOp::new(opwire::op::WRITE)],
            ..Default::default()
        };
        OpRec::new(
            conn,
            tid,
            EntityName::new(EntityName::CLIENT, 7),
            denc::types::EntityAddr::default(),
            &op,
            start,
        )
    }

    #[test]
    fn live_slow_and_history() {
        let mut t = OpTracker::default();
        t.start(rec(1, 1, 0));
        t.start(rec(1, 2, 20_000_000_000));
        assert_eq!(t.len(), 2);
        assert_eq!(t.slow(31_000_000_000), (1, 31_000_000_000));
        let d = t.finish(1, 1, 40_000_000_000, 0, 0).unwrap();
        assert_eq!(d.lat, 40_000_000_000);
        assert!(t.finish(1, 1, 41_000_000_000, 0, 0).is_none());
        let w = |ns: u64| format!("t{ns}");
        assert_eq!(
            t.dump_hist(41_000_000_000, &w, false, &|_| Vec::new())
                .len(),
            1
        );
        assert_eq!(
            t.dump_hist(41_000_000_000, &w, true, &|_| Vec::new()).len(),
            1
        ); // 40 s >= 10 s slow threshold
        let live = t.dump_live(41_000_000_000, &w, true);
        assert_eq!(live.len(), 0); // 21 s < 30 s complaint
        t.forget_conn(1);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn slow_write_names_the_peers_it_waits_for() {
        use denc::types::{PgShard, ShardId};
        let mut t = OpTracker::default();
        t.start(rec(1, 1, 5));
        t.start(rec(1, 2, 6));
        let w = |n: u64| n.to_string();
        let rep = [
            PgShard {
                osd: 1,
                shard: ShardId::NO_SHARD,
            },
            PgShard {
                osd: 4,
                shard: ShardId::NO_SHARD,
            },
        ];
        let ec = [
            PgShard {
                osd: 2,
                shard: ShardId(0),
            },
            PgShard {
                osd: 7,
                shard: ShardId(2),
            },
        ];
        assert_eq!(crate::tell::waiting_text(&rep), "1,4");
        assert_eq!(crate::tell::waiting_text(&ec), "2(s0),7(s2)");
        let live = t.dump_live_with(100, &w, false, &|(_, tid)| {
            (tid == 1).then(|| crate::tell::waiting_text(&rep))
        });
        let (a, b) = (&live[0].1["type_data"], &live[1].1["type_data"]);
        assert_eq!(a["flag_point"], "waiting for sub ops");
        let ev = a["events"].as_array().unwrap();
        assert_eq!(ev.last().unwrap()["event"], "waiting for subops from 1,4");
        // an op with nothing outstanding keeps the plain flag point
        assert_eq!(b["flag_point"], "reached pg");
        assert_eq!(b["events"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn bounded() {
        let mut t = OpTracker::default();
        t.lim.hist_size = 3;
        for i in 0..10 {
            t.start(rec(1, i, i));
            t.finish(1, i, i + 1, 0, 0);
        }
        assert_eq!(
            t.dump_hist(100, &|_| String::new(), false, &|_| Vec::new())
                .len(),
            3
        );
        let r = hist_reply(
            t.dump_hist(100, &|_| String::new(), false, &|_| Vec::new()),
            2,
            600,
            true,
        );
        assert_eq!(r["ops"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn resend_keeps_first_start_and_drop_forgets_exactly_that_op() {
        let mut t = OpTracker::default();
        t.start(rec(1, 1, 5));
        t.start(rec(1, 1, 99));
        assert_eq!(t.dump_live(100, &|n| n.to_string(), false)[0].0, 5);
        t.start(rec(2, 9, 6));
        t.start(rec(2, 10, 7));
        // the engine dropped (2, 9) (e.g. inside a backoff): only that record ends, the later op of the session stays
        t.forget(2, 9);
        assert_eq!(t.len(), 2);
        assert!(t.finish(2, 9, 50, 0, 0).is_none());
        assert!(t.finish(2, 10, 50, 0, 0).is_some());
        t.forget(1, 2); // not tracked: no effect
        assert_eq!(t.len(), 1);
    }
}
