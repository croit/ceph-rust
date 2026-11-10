// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Replica ack invariants (adr 0636), checked on every simulated delivery and send: a replica / EC shard process acks
//! only a write (repop, sub-write, log update) that was delivered to it, once, in log order per primary and shard, and
//! only once the write's log entries are durable in its store: the primary (classic or croit-flashstore-osd) completes the client
//! write on these acks. A violation fails the test when its `Sim` drops.
use super::Sim;
use denc::types::{Eversion, SpgT};
use peering::{Body, Send};
use replwire::ReplMsg;
use std::collections::{BTreeMap, BTreeSet};

/// `(replica, its incarnation, primary, replica shard, tid)`: two shards of one EC PG may sit on one OSD.
type Key = (i32, u64, i32, SpgT, u64);

#[derive(Debug, Default)]
pub struct Acks {
    /// Delivered writes: the replica's PG instance, the version of the write's last log entry, the map epoch it was
    /// sent in.
    delivered: BTreeMap<Key, (SpgT, Option<Eversion>, u32)>,
    acked: BTreeSet<Key>,
    /// Last acked version per `(replica, incarnation, primary, replica shard)`.
    last: BTreeMap<(i32, u64, i32, SpgT), Eversion>,
    /// Acks checked.
    pub acks: u64,
    pub violations: Vec<String>,
}

impl Sim {
    /// A write reaches replica `to` (incarnation alive now).
    pub(super) fn acks_deliver(&mut self, to: i32, from: i32, tid: u64, body: &Body) {
        let (spg, tid, last, epoch) = match body {
            Body::Repl(ReplMsg::RepOp(m)) => {
                let Ok(es) = denc::from_slice::<Vec<pgwire::LogEntry>>(&m.logbl) else {
                    return;
                };
                (m.pgid, tid, es.last().map(|e| e.version), m.map_epoch)
            }
            Body::Repl(ReplMsg::UpdateLogMissing(m)) => {
                let Ok(es) = denc::from_slice::<Vec<pgwire::LogEntry>>(&m.entries) else {
                    return;
                };
                (m.pgid, m.rep_tid, es.last().map(|e| e.version), m.map_epoch)
            }
            Body::Ec(ecwire::EcMsg::Write(m)) => {
                let last = m.op.log_entries.last().map(|e| e.version);
                (m.pgid, m.op.tid, last, m.map_epoch)
            }
            _ => return,
        };
        let inc = self.nodes[&to].inc;
        let a = &mut self.acks;
        let key = (to, inc, from, spg, tid);
        // a primary PG instance numbers its writes from 1: the same tid with another version or map epoch is a write of a
        // newer instance (a duplicated delivery carries the same ones and keeps its ack state)
        if a.delivered.insert(key, (spg, last, epoch)) != Some((spg, last, epoch)) {
            a.acked.remove(&key);
        }
    }

    /// Replica `osd` sends `s`: an ack must match a delivered write, be its first, follow the previous ack's version and
    /// find the write durable.
    pub(super) fn acks_send(&mut self, osd: i32, s: &Send) {
        let (pgid, shard, tid, what) = match &s.body {
            Body::Repl(ReplMsg::RepOpReply(r)) => (r.pgid.pgid, r.from.shard, s.tid, "repop"),
            Body::Repl(ReplMsg::UpdateLogMissingReply(r)) => {
                (r.pgid.pgid, r.from, r.rep_tid, "log update")
            }
            Body::Ec(ecwire::EcMsg::WriteReply(r)) => {
                (r.pgid.pgid, r.op.from.shard, r.op.tid, "sub-write")
            }
            _ => return,
        };
        let me = SpgT { pgid, shard };
        let n = &self.nodes[&osd];
        let key = (osd, n.inc, s.to, me, tid);
        let at = self.now;
        let a = &mut self.acks;
        a.acks += 1;
        let Some(&(spg, v, _)) = a.delivered.get(&key) else {
            a.violations.push(format!(
                "{at}: osd.{osd} acks {what} tid {tid} of {me} to osd.{} that was never delivered",
                s.to
            ));
            return;
        };
        if !a.acked.insert(key) {
            a.violations.push(format!(
                "{at}: osd.{osd} acks {what} tid {tid} of {me} to osd.{} twice",
                s.to
            ));
        }
        let Some(v) = v else {
            return;
        };
        let prev = a.last.insert((osd, n.inc, s.to, me), v);
        if prev.is_some_and(|p| p >= v) {
            a.violations.push(format!(
                "{at}: osd.{osd} acks {what} {v} of {me} to osd.{} after {:?} (out of log order)",
                s.to, prev
            ));
        }
        // the committed store: `_loghead` may lag the appended entries (`LogAppendFast`), the newest entry is the head
        let store = n.durable.as_ref().unwrap_or(&n.store);
        let head = store.pgs.get(&spg).map(|p| {
            p.p.log
                .log
                .back()
                .map_or(p.p.log.head, |e| e.version.max(p.p.log.head))
        });
        if head.is_none_or(|h| h < v) {
            a.violations.push(format!(
                "{at}: osd.{osd} acks {what} {v} of {spg} to osd.{} before it is durable (durable head {head:?})",
                s.to
            ));
        }
    }
}
