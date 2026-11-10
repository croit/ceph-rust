// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Sender-side repop credits between croit-flashstore-osd peers (adr 0084 am. 3). Per (peer, physical shard) the PG core keeps the
//! repop / EC sub-write bytes and count in flight (charged at send, released by the reply with the same tid); a
//! write over the budget waits in a local FIFO. The receiver then never has to stop reading a peer link for peer data
//! (its reservation fits the sum of the budgets), so acks, leases and controls never sit behind a congested shard.
//! Purely local pacing: no message, no wire change; classic peers are never throttled and keep the old receive path.
//! Holding a request never reorders its PG (adr 0084 am. 6): every later message of that PG to that peer (update
//! log missing, lease, trim, recovery, EC read, ...) waits behind it in the same FIFO and leaves uncharged right after
//! it. A replica needs its PG's messages in send order: an UpdateLogMissing ahead of an older held repop moves its
//! `last_update` past the repop, which it then discards as a duplicate (log hole, the write never completes).
//! A request whose reply never comes is one its primary aborted: a new interval or a merge (the replica discards an
//! older interval's request unanswered, peering.md 7.3). The PG reports each such request still unanswered
//! (`Action::SubWritesAborted`, `flow_aborted`) and its credit returns then; a map returns the credits of PGs that left
//! the core (`flow_after_map`). There is no expiry timer. Perf dump (`osd`) shows the lanes with requests waiting for
//! credit and the age of the oldest credit (`repop_credit_blocked_lanes`, `repop_credit_oldest_ms`): a leaked credit
//! would show as an age that only grows.
use crate::backend::Backend;
use crate::osd::{FastMap, Osd};
use crate::xcore::DataX;
use denc::types::{PgT, SpgT};
use messages::Segments;
use peering::Body;
use std::collections::{BTreeSet, VecDeque};
use std::time::Duration;

/// Receiver window per physical shard (`ingress`): the budgets of all croit-flashstore-osd peers must fit into it.
const WINDOW_BYTES: usize = 64 << 20;
const WINDOW_OPS: usize = 128;

/// An encoded, not yet forwarded peer message.
pub(crate) struct Tx {
    pub to: i32,
    /// Map epoch of the sending PG ([`peering::Send::epoch`]): the link core never sends a frame stamped before its
    /// rebind ([`Osd::rebind_epoch`]).
    pub epoch: u32,
    pub tid: u64,
    pub prio: u16,
    pub hdr: (u16, u16, u16),
    pub segs: Segments,
    pub data: DataX,
}

impl Tx {
    /// Encoded bytes (payload ropes included): what a credit charges.
    fn bytes(&self) -> usize {
        self.segs.front_len()
            + self.segs.middle.len()
            + self.segs.data.len()
            + self.data.more.iter().map(|(b, _)| b.len()).sum::<usize>()
    }
}

#[derive(Default)]
struct Lane {
    bytes: usize,
    ops: usize,
    wait: VecDeque<Waiting>,
}

impl Lane {
    /// Room for one more credited request of `bytes` within `budget` (bytes, ops)? An empty lane admits any size.
    fn admits(&self, bytes: usize, budget: (usize, usize)) -> bool {
        self.ops == 0 || (self.ops < budget.1 && self.bytes + bytes <= budget.0)
    }
}

/// A held message: a credited request waiting for credit (`credit` = its key and bytes, charged when it is sent), or
/// a later message of the same PG kept behind it (`credit` = `None`: sent as soon as everything before it left).
struct Waiting {
    tx: Tx,
    credit: Option<(Key, usize)>,
    pg: PgT,
}

struct Sent {
    shard: u32,
    bytes: usize,
    /// When the credit was charged (diagnostics only: the age gauge).
    at: Duration,
}

#[derive(Default)]
pub(crate) struct Flow {
    pub on: bool,
    /// Budget per (peer, shard): bytes and ops.
    bytes: usize,
    ops: usize,
    lanes: FastMap<(i32, u32), Lane>,
    sent: FastMap<Key, Sent>,
    /// Held messages per (peer, PG): the shard of the lane they wait in and how many. A later message of the PG to
    /// that peer joins them there (per-PG send order).
    held: FastMap<(i32, PgT), (u32, usize)>,
}

/// One message of `(peer, pg)` left the lane (sent or dropped).
fn unhold(held: &mut FastMap<(i32, PgT), (u32, usize)>, peer: i32, pg: PgT) {
    if let Some(h) = held.get_mut(&(peer, pg)) {
        h.1 -= 1;
        if h.1 == 0 {
            held.remove(&(peer, pg));
        }
    }
}

impl Flow {
    /// Nothing charged and nothing waiting.
    #[cfg(test)]
    pub fn idle(&self) -> bool {
        self.sent.is_empty()
            && self.held.is_empty()
            && self
                .lanes
                .values()
                .all(|l| l.ops == 0 && l.bytes == 0 && l.wait.is_empty())
    }

    /// Messages held (credited requests and the PG messages behind them).
    #[cfg(test)]
    fn waiting(&self) -> usize {
        self.lanes.values().map(|l| l.wait.len()).sum()
    }

    /// `peers`: croit-flashstore-osd peers whose budgets share one receiver window.
    pub fn configure(&mut self, on: bool, peers: usize) {
        let n = peers.max(2);
        self.on = on;
        self.bytes = (WINDOW_BYTES / n).max(4 << 20);
        self.ops = (WINDOW_OPS / n).max(8);
    }

    /// Does any message wait (credited or behind one)?
    fn holds_any(&self) -> bool {
        !self.held.is_empty()
    }

    /// Send `tx` of PG `pg` now (returned) or hold it. `credit`: a credited request (key, receiver shard, bytes); it is
    /// charged when it leaves. A message of a PG with a message held towards the same peer always queues behind it,
    /// credited or not (per-PG order); otherwise an uncredited message goes at once and a credited one when its lane
    /// has nothing waiting and room in the budget.
    fn admit(
        &mut self,
        tx: Tx,
        pg: PgT,
        credit: Option<(Key, u32, usize)>,
        now: Duration,
    ) -> Option<Tx> {
        let shard = match (self.held.get(&(tx.to, pg)), credit) {
            (Some(&(shard, _)), _) => shard,
            (None, None) => return Some(tx),
            (None, Some((key, shard, bytes))) => {
                let budget = (self.bytes, self.ops);
                let l = self.lanes.entry((tx.to, shard)).or_default();
                if l.wait.is_empty() && l.admits(bytes, budget) {
                    self.charge(key, shard, bytes, now);
                    return Some(tx);
                }
                shard
            }
        };
        let peer = tx.to;
        self.lanes
            .entry((peer, shard))
            .or_default()
            .wait
            .push_back(Waiting {
                tx,
                credit: credit.map(|(k, _, b)| (k, b)),
                pg,
            });
        self.held.entry((peer, pg)).or_insert((shard, 0)).1 += 1;
        None
    }

    fn charge(&mut self, key: Key, shard: u32, bytes: usize, at: Duration) {
        // A second charge of the same (peer, PG, tid) supersedes the earlier one: one reply releases one key, so the
        // earlier bytes/ops would stay in its lane for good and lock it (no expiry, by design).
        self.release(key);
        let l = self.lanes.entry((key.0, shard)).or_default();
        l.bytes += bytes;
        l.ops += 1;
        self.sent.insert(key, Sent { shard, bytes, at });
    }

    /// Drop the accounting of `(to, tid)`; the lane to drain, if it was charged.
    fn release(&mut self, key: Key) -> Option<(i32, u32)> {
        let s = self.sent.remove(&key)?;
        let l = self.lanes.get_mut(&(key.0, s.shard))?;
        l.bytes = l.bytes.saturating_sub(s.bytes);
        l.ops = l.ops.saturating_sub(1);
        Some((key.0, s.shard))
    }

    /// Next held message of `lane` that may leave now: an uncredited one at once, a credited one if it fits (charged).
    fn next(&mut self, lane: (i32, u32), now: Duration) -> Option<Tx> {
        let budget = (self.bytes, self.ops);
        let l = self.lanes.get_mut(&lane)?;
        if let Some((_, bytes)) = l.wait.front()?.credit
            && !l.admits(bytes, budget)
        {
            return None;
        }
        let w = l.wait.pop_front()?;
        if let Some((key, bytes)) = w.credit {
            self.charge(key, lane.1, bytes, now);
        }
        unhold(&mut self.held, lane.0, w.pg);
        Some(w.tx)
    }

    /// Release the credits and drop the waiting requests `gone(key)` names (no reply comes for them: aborted by their
    /// PG, or their PG left the core), then the empty lanes. The uncredited messages behind them stay and leave at the
    /// drain, in order (a replica discards those of an older interval itself). Returns the lanes to drain and the number
    /// of requests released or dropped.
    fn drop_where(&mut self, gone: impl Fn(&Key) -> bool) -> (Vec<(i32, u32)>, usize) {
        if self.sent.is_empty() && self.held.is_empty() {
            return (Vec::new(), 0);
        }
        let old: Vec<Key> = self.sent.keys().filter(|k| gone(k)).copied().collect();
        let mut n = old.len();
        let mut lanes: Vec<(i32, u32)> = old.into_iter().filter_map(|k| self.release(k)).collect();
        let held = &mut self.held;
        for (lane, l) in self.lanes.iter_mut() {
            let before = l.wait.len();
            l.wait.retain(|w| {
                let drop = w.credit.is_some_and(|(k, _)| gone(&k));
                if drop {
                    unhold(held, lane.0, w.pg);
                }
                !drop
            });
            let gone = before - l.wait.len();
            if gone > 0 {
                n += gone;
                lanes.push(*lane);
            }
        }
        self.lanes.retain(|_, l| l.ops > 0 || !l.wait.is_empty());
        lanes.sort_unstable();
        lanes.dedup();
        (lanes, n)
    }

    /// Lanes with requests waiting for credit (gauge).
    fn blocked_lanes(&self) -> usize {
        self.lanes.values().filter(|l| !l.wait.is_empty()).count()
    }

    /// When the oldest credit still out was charged.
    fn oldest(&self) -> Option<Duration> {
        self.sent.values().map(|s| s.at).min()
    }
}

/// (peer, PG shard, tid) of a credited bulk message (replicated sub-write: header tid; EC sub-write: the tid in its
/// body); the reply carries the same. Tids count per PG and one EC sub-write per shard position shares the tid, so the
/// shard (acting `[a, b, b]`: two positions on one OSD) is part of the key.
pub(crate) type Key = (i32, SpgT, u64);

fn credit_key(b: &Body, peer: i32, header_tid: u64) -> Option<Key> {
    let (spg, tid) = match b {
        Body::Repl(replwire::ReplMsg::RepOp(_) | replwire::ReplMsg::RepOpReply(_)) => {
            (peering::body_spg(b)?, header_tid)
        }
        Body::Ec(ecwire::EcMsg::Write(w)) => (w.pgid, w.op.tid),
        // the reply's pgid names the primary's shard; the replica names itself in `from`: the request's destination
        Body::Ec(ecwire::EcMsg::WriteReply(w)) => (
            SpgT {
                pgid: w.pgid.pgid,
                shard: w.op.from.shard,
            },
            w.op.tid,
        ),
        _ => return None,
    };
    Some((peer, spg, tid))
}

/// Credit key if `b` is a reply of a credited request.
pub(crate) fn reply_key(b: &Body, from: i32, header_tid: u64) -> Option<Key> {
    match b {
        Body::Repl(replwire::ReplMsg::RepOpReply(_)) | Body::Ec(ecwire::EcMsg::WriteReply(_)) => {
            credit_key(b, from, header_tid)
        }
        _ => None,
    }
}

/// Is `b` a credited request (not a reply)?
pub(crate) fn is_request(b: &Body) -> bool {
    matches!(
        b,
        Body::Repl(replwire::ReplMsg::RepOp(_)) | Body::Ec(ecwire::EcMsg::Write(_))
    )
}

impl<B: Backend> Osd<B> {
    /// (Re)read the switch and the budget (every map: the croit-flashstore-osd peer count changes the share of the window).
    pub(crate) fn flow_configure(&mut self) {
        let on = self.conf.bool("flashstore_repop_credit", true);
        let peers = self.pg.peer_nv.len();
        if on != self.pg.flow.on || peers != self.pg.flow_peers {
            self.pg.flow_peers = peers;
            self.pg.flow.configure(on, peers);
        }
    }

    /// Is `from` a peer whose repops obey the credits (known croit-flashstore-osd, switch on)? Then its data never needs the
    /// link-level store gate: the reservation bounds what we retain, the sender bounds the reservation.
    pub(crate) fn flow_peer(&self, from: i32) -> bool {
        self.pg.flow.on && self.pg.peer_nv.contains(&from)
    }

    /// Forward an encoded message of PG `spg` now, or hold it: a credited request until the replies of earlier ones
    /// return credit, any message of a PG behind that PG's held messages to the same peer (per-PG order, also when the
    /// switch went off or the peer is no longer known as croit-flashstore-osd meanwhile). Not a PG message (`spg` = `None`): now.
    pub(crate) fn flow_send(&mut self, body: &Body, tx: Tx, spg: Option<SpgT>) {
        if self.pg.peer_nv.len() != self.pg.flow_peers {
            self.flow_configure();
        }
        let Some(spg) = spg else {
            return self.pg_forward(tx);
        };
        let credited = self.pg.flow.on && is_request(body) && self.pg.peer_nv.contains(&tx.to);
        if !credited && !self.pg.flow.holds_any() {
            return self.pg_forward(tx);
        }
        let credit = credited
            .then(|| credit_key(body, tx.to, tx.tid))
            .flatten()
            .map(|key| (key, self.input_shard(spg.pgid) as u32, tx.bytes()));
        let now = self.now;
        match self.pg.flow.admit(tx, spg.pgid, credit, now) {
            Some(tx) => self.pg_forward(tx),
            None if credit.is_some() => self.pg.c.link_count("repop_credit_wait"),
            None => self.pg.c.link_count("repop_credit_order_wait"),
        }
    }

    /// A reply for `(from, tid)` arrived: return its credit and send what now fits.
    pub(crate) fn flow_reply(&mut self, key: Key) {
        if let Some(lane) = self.pg.flow.release(key) {
            self.flow_drain(lane);
        }
    }

    fn flow_drain(&mut self, lane: (i32, u32)) {
        let now = self.now;
        while let Some(tx) = self.pg.flow.next(lane, now) {
            self.pg_forward(tx);
        }
    }

    /// A PG aborted sub-writes still unanswered (`Action::SubWritesAborted`: a new interval, a merge): no reply comes
    /// for them, their credits return and the ones still waiting are dropped; then what that frees is sent. A peer that
    /// went down or restarted is covered too: it leaves the acting set, a new interval.
    pub(crate) fn flow_aborted(&mut self, keys: &[Key]) {
        let keys: BTreeSet<Key> = keys.iter().copied().collect();
        let (lanes, n) = self.pg.flow.drop_where(|k| keys.contains(k));
        self.flow_returned(lanes, n);
    }

    /// After a map: credits and waiting requests of PGs that left this core (removed, merged away, moved to another
    /// core) are dropped: their replies, if any, reach another core or none.
    pub(crate) fn flow_after_map(&mut self) {
        let (lanes, n) = {
            let (flow, set) = (&mut self.pg.flow, &self.pg.set);
            flow.drop_where(|k| !set.holds(k.1.pgid))
        };
        self.flow_returned(lanes, n);
    }

    fn flow_returned(&mut self, lanes: Vec<(i32, u32)>, n: usize) {
        if n > 0 {
            *self
                .pg
                .c
                .link_events
                .entry("repop_credit_aborted")
                .or_default() += n as u64;
        }
        for lane in lanes {
            self.flow_drain(lane);
        }
    }

    /// Perf gauges: lanes with requests waiting for credit; age of the oldest credit out (ms).
    pub(crate) fn flow_gauges(&self) -> (u64, u64) {
        let f = &self.pg.flow;
        let age = f
            .oldest()
            .map_or(0, |at| self.now.saturating_sub(at).as_millis() as u64);
        (f.blocked_lanes() as u64, age)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use denc::types::ShardId;

    const T0: Duration = Duration::ZERO;

    fn spg(seed: u32, shard: i8) -> SpgT {
        SpgT {
            pgid: PgT::new(1, seed),
            shard: ShardId(shard),
        }
    }

    fn k(to: i32, tid: u64) -> Key {
        (to, spg(0, -1), tid)
    }

    fn tx(to: i32, tid: u64) -> Tx {
        Tx {
            to,
            epoch: 0,
            tid,
            prio: 0,
            hdr: (0, 0, 0),
            segs: Segments::front(Vec::new()),
            data: DataX::default(),
        }
    }

    /// `admit` of the credited request `key` (its PG's receiver shard `shard`): true = sent now.
    fn send_pg(f: &mut Flow, key: Key, shard: u32, bytes: usize, now: Duration) -> bool {
        f.admit(tx(key.0, key.2), key.1.pgid, Some((key, shard, bytes)), now)
            .is_some()
    }

    fn send(f: &mut Flow, to: i32, shard: u32, tid: u64, bytes: usize) -> bool {
        send_pg(f, k(to, tid), shard, bytes, T0)
    }

    /// `admit` of an uncredited message of `pg` (update log missing, lease, trim, push, EC read, ...): true = sent now.
    fn other(f: &mut Flow, to: i32, pg: SpgT, tid: u64) -> bool {
        f.admit(tx(to, tid), pg.pgid, None, T0).is_some()
    }

    fn drain(f: &mut Flow, lane: (i32, u32)) -> Vec<u64> {
        drain_at(f, lane, T0)
    }

    fn drain_at(f: &mut Flow, lane: (i32, u32), now: Duration) -> Vec<u64> {
        let mut out = Vec::new();
        while let Some(t) = f.next(lane, now) {
            out.push(t.tid);
        }
        out
    }

    #[test]
    fn budget_is_per_peer_and_shard_and_fifo() {
        let mut f = Flow::default();
        f.configure(true, 2); // 32 MiB, 64 ops per (peer, shard)
        let mib4 = 4 << 20;
        // peer 1, shard 0: 8 x 4 MiB fit, the rest waits in order
        for t in 0..8 {
            assert!(send(&mut f, 1, 0, t, mib4));
        }
        for t in 8..12 {
            assert!(!send(&mut f, 1, 0, t, mib4));
        }
        // another peer and another shard (another PG) are untouched (a flooding primary cannot use the budget of the others)
        assert!(send(&mut f, 2, 0, 100, mib4));
        assert!(send_pg(&mut f, (1, spg(1, -1), 101), 1, mib4, T0));
        // a small message queues behind the waiting ones (order), never overtakes
        assert!(!send(&mut f, 1, 0, 12, 4096));
        // replies return credit, waiting ones go in FIFO order
        assert_eq!(f.release(k(1, 0)), Some((1, 0)));
        assert_eq!(drain(&mut f, (1, 0)), vec![8]);
        f.release(k(1, 1));
        f.release(k(1, 2));
        assert_eq!(drain(&mut f, (1, 0)), vec![9, 10]);
        assert_eq!(f.release(k(1, 99)), None, "unknown reply: no effect");
        f.release(k(1, 3));
        f.release(k(1, 4));
        assert_eq!(drain(&mut f, (1, 0)), vec![11, 12]);
        assert_eq!(f.waiting(), 0);
    }

    /// adr 0084 am. 6: a PG's later messages to a peer never overtake its request held for credit (was: they went at
    /// once; an UpdateLogMissing moved the replica's `last_update` past the held repop, which it then discarded as a
    /// duplicate: log hole, the write never completed). Other PGs, other peers are not delayed.
    #[test]
    fn a_held_request_keeps_its_pgs_later_messages_behind_it() {
        let mut f = Flow::default();
        f.configure(true, 1000); // 8 ops per (peer, shard)
        let (a, b) = (spg(0, -1), spg(1, -1));
        for t in 0..8 {
            assert!(send_pg(&mut f, (1, a, t), 0, 4096, T0));
        }
        assert!(
            !send_pg(&mut f, (1, a, 8), 0, 4096, T0),
            "repop 8 waits for credit"
        );
        assert!(
            !other(&mut f, 1, a, 100),
            "a later message of its PG waits behind it"
        );
        assert!(other(&mut f, 1, b, 101), "another PG: nothing of it held");
        assert!(other(&mut f, 2, a, 102), "another peer: its own order");
        assert!(!send_pg(&mut f, (1, a, 9), 0, 4096, T0));
        assert!(!other(&mut f, 1, a, 103));
        assert_eq!((f.waiting(), f.blocked_lanes()), (4, 1));
        // one credit back: repop 8 and the message behind it leave in send order (uncharged); repop 9 needs the next
        f.release((1, a, 0));
        assert_eq!(drain(&mut f, (1, 0)), vec![8, 100]);
        f.release((1, a, 1));
        assert_eq!(drain(&mut f, (1, 0)), vec![9, 103]);
        assert_eq!(f.waiting(), 0);
        assert!(other(&mut f, 1, a, 104), "nothing held any more: at once");
        assert_eq!(f.sent.len(), 8, "only the requests are charged");
        for t in 2..10 {
            assert!(f.release((1, a, t)).is_some());
        }
        assert!(f.idle());
    }

    /// The lane is one FIFO: a held message of PG a also waits for another PG's request queued before it, and leaves
    /// right after it, uncharged.
    #[test]
    fn a_pgs_held_message_waits_behind_the_lane_requests_before_it() {
        let mut f = Flow::default();
        f.configure(true, 1000);
        let (a, b) = (spg(0, -1), spg(1, -1));
        for t in 0..8 {
            assert!(send_pg(&mut f, (1, b, t), 0, 4096, T0));
        }
        assert!(!send_pg(&mut f, (1, a, 50), 0, 4096, T0));
        assert!(!send_pg(&mut f, (1, b, 8), 0, 4096, T0));
        assert!(!other(&mut f, 1, a, 100));
        f.release((1, b, 0));
        assert_eq!(drain(&mut f, (1, 0)), vec![50]);
        f.release((1, b, 1));
        assert_eq!(drain(&mut f, (1, 0)), vec![8, 100]);
        assert_eq!((f.waiting(), f.sent.len()), (0, 8));
    }

    /// EC (acting `[a, b, b]`): the sub-writes to shards 1 and 2 of one PG on OSD 2 share the PG's lane; a held one keeps
    /// every later message of the PG to that OSD (sub-read, update log missing, either shard position) behind it.
    #[test]
    fn ec_sub_write_held_keeps_the_pgs_later_messages_behind_it() {
        let mut f = Flow::default();
        f.configure(true, 1000);
        let (s1, s2) = (spg(0, 1), spg(0, 2));
        for t in 0..4 {
            assert!(send_pg(&mut f, (2, s1, t), 0, 4096, T0));
            assert!(send_pg(&mut f, (2, s2, t), 0, 4096, T0));
        }
        assert!(!send_pg(&mut f, (2, s1, 4), 0, 4096, T0));
        assert!(
            !other(&mut f, 2, s2, 200),
            "the PG's sub-read to its other shard position"
        );
        assert!(!send_pg(&mut f, (2, s2, 4), 0, 4096, T0));
        f.release((2, s2, 0));
        assert_eq!(drain(&mut f, (2, 0)), vec![4, 200]);
        f.release((2, s1, 0));
        assert_eq!(drain(&mut f, (2, 0)), vec![4]);
        assert_eq!(f.waiting(), 0);
    }

    #[test]
    fn equal_tids_of_different_pgs_are_different_credits() {
        // tids count per PG: PG 1.0 and PG 1.1 both use tid 7 towards the same peer and shard (first live build hung on this)
        let mut f = Flow::default();
        f.configure(true, 2);
        let (a, b) = ((1, spg(0, -1), 7), (1, spg(1, -1), 7));
        f.charge(a, 0, 4096, T0);
        f.charge(b, 0, 4096, T0);
        assert_eq!(f.release(a), Some((1, 0)));
        assert_eq!(f.release(b), Some((1, 0)));
        assert!(f.idle());
    }

    /// A resent request (same peer, PG, tid) replaces its earlier charge: one reply releases one key, so keeping both
    /// bytes/ops would leave the lane permanently over budget (no expiry, by design).
    #[test]
    fn a_repeated_charge_replaces_the_earlier_one() {
        let mut f = Flow::default();
        f.configure(true, 2);
        let key = k(1, 7);
        f.charge(key, 0, 4096, T0);
        f.charge(key, 0, 4096, T0);
        assert_eq!(f.sent.len(), 1, "one key, one charge");
        assert_eq!(f.release(key), Some((1, 0)));
        assert!(f.idle(), "the single reply returned everything charged");
    }

    /// Acting `[a, b, b]`, credits on: the sub-writes to shards 1 and 2 of one PG go to OSD 2 with the same tid; the
    /// replies (pgid = the primary's shard, `from` = the replica) must return exactly the credit of their request.
    #[test]
    fn ec_reply_key_matches_its_request_per_shard() {
        let mut f = Flow::default();
        f.configure(true, 2);
        let mut keys = Vec::new();
        for shard in [1i8, 2] {
            let req = Body::Ec(ecwire::EcMsg::Write(ecwire::MOSDECSubOpWrite {
                pgid: spg(0, shard),
                op: ecwire::ECSubWrite {
                    tid: 7,
                    ..Default::default()
                },
                ..Default::default()
            }));
            assert!(is_request(&req));
            let k = credit_key(&req, 2, 0).unwrap();
            f.charge(k, 0, 4096, T0);
            keys.push((shard, k));
        }
        assert_eq!(f.sent.len(), 2, "two positions, two credits");
        for (shard, k) in keys {
            let rep = Body::Ec(ecwire::EcMsg::WriteReply(ecwire::MOSDECSubOpWriteReply {
                pgid: spg(0, 0),
                op: ecwire::ECSubWriteReply {
                    from: denc::types::PgShard {
                        osd: 2,
                        shard: ShardId(shard),
                    },
                    tid: 7,
                    ..Default::default()
                },
                ..Default::default()
            }));
            assert_eq!(reply_key(&rep, 2, 0), Some(k));
            assert!(f.release(k).is_some());
        }
        assert!(f.idle(), "every credit returned without expiry");
    }

    /// A PG aborts its unanswered sub-writes (a new interval, a merge): exactly those credits return and its waiting
    /// requests are dropped, never sent (no time-based expiry). Another PG on the same lane keeps its credits and its
    /// waiting requests go out in order.
    #[test]
    fn aborted_sub_writes_return_their_credits() {
        let mut f = Flow::default();
        f.configure(true, 2); // 64 ops per (peer, shard)
        let (a, b) = (spg(0, -1), spg(1, -1));
        for t in 0..40 {
            assert!(send_pg(&mut f, (1, a, t), 0, 4096, T0));
        }
        for t in 0..24 {
            assert!(send_pg(&mut f, (1, b, t), 0, 4096, T0));
        }
        // lane full: both PGs wait
        assert!(!send_pg(&mut f, (1, a, 40), 0, 4096, T0));
        assert!(!send_pg(&mut f, (1, b, 24), 0, 4096, T0));
        assert!(!send_pg(&mut f, (1, b, 25), 0, 4096, T0));
        assert_eq!(f.waiting(), 3);
        assert_eq!(f.blocked_lanes(), 1);
        // PG a starts a new interval: it reports its 41 sub-writes still unanswered (charged or waiting)
        let aborted: Vec<Key> = (0..41).map(|t| (1, a, t)).collect();
        let (lanes, n) = f.drop_where(|k| aborted.contains(k));
        assert_eq!(lanes, vec![(1, 0)]);
        assert_eq!(n, 41, "a's 40 credits and its waiting request");
        assert_eq!(
            drain(&mut f, (1, 0)),
            vec![24, 25],
            "b's waiting requests go in order"
        );
        assert_eq!((f.waiting(), f.blocked_lanes()), (0, 0));
        assert_eq!(f.sent.len(), 26, "only b's credits remain");
        for t in 0..26 {
            assert!(f.release((1, b, t)).is_some());
        }
        assert!(f.idle());
        // a late reply of an aborted sub-write changes nothing
        assert_eq!(f.release((1, a, 3)), None);
        assert!(f.idle());
    }

    /// The abort drops a PG's waiting requests, never the uncredited messages queued behind them: those leave at the
    /// drain in send order (a replica discards an older interval's message itself), and nothing stays held.
    #[test]
    fn an_abort_drops_the_requests_but_sends_the_messages_behind_them() {
        let mut f = Flow::default();
        f.configure(true, 1000);
        let a = spg(0, -1);
        for t in 0..8 {
            assert!(send_pg(&mut f, (1, a, t), 0, 4096, T0));
        }
        assert!(!send_pg(&mut f, (1, a, 8), 0, 4096, T0));
        assert!(!other(&mut f, 1, a, 100));
        assert!(!send_pg(&mut f, (1, a, 9), 0, 4096, T0));
        assert!(!other(&mut f, 1, a, 101));
        let (lanes, n) = f.drop_where(|k| k.1 == a);
        assert_eq!(
            (lanes, n),
            (vec![(1, 0)], 10),
            "8 credits, 2 waiting requests"
        );
        assert_eq!(drain(&mut f, (1, 0)), vec![100, 101]);
        assert!(f.idle());
    }

    /// A PG that left this core (removed, merged away, moved to another core): its credits go at the map.
    #[test]
    fn credits_of_a_pg_gone_from_the_core_are_dropped() {
        let mut f = Flow::default();
        f.configure(true, 2);
        let (a, b) = (spg(0, -1), spg(1, -1));
        assert!(send_pg(&mut f, (1, a, 1), 0, 4096, T0));
        assert!(send_pg(&mut f, (2, b, 1), 0, 4096, T0));
        let (lanes, n) = f.drop_where(|k| k.1.pgid != b.pgid);
        assert_eq!((lanes, n), (vec![(1, 0)], 1));
        assert_eq!(f.sent.len(), 1);
        assert!(f.lanes.contains_key(&(2, 0)) && !f.lanes.contains_key(&(1, 0)));
    }

    /// The age gauge follows the oldest credit still out: a credit taken from the wait queue is charged when it is
    /// sent, a returned one no longer counts.
    #[test]
    fn oldest_credit_is_the_one_charged_first() {
        let mut f = Flow::default();
        f.configure(true, 1000); // 8 ops per (peer, shard)
        let s = Duration::from_secs;
        assert_eq!(f.oldest(), None);
        for t in 0..8 {
            assert!(send_pg(&mut f, k(1, t), 0, 4096, s(10 + t)));
        }
        assert!(!send_pg(&mut f, k(1, 8), 0, 4096, s(20)));
        assert_eq!(f.oldest(), Some(s(10)));
        f.release(k(1, 0));
        assert_eq!(drain_at(&mut f, (1, 0), s(30)), vec![8]);
        assert_eq!(f.oldest(), Some(s(11)));
        for t in 1..8 {
            f.release(k(1, t));
        }
        assert_eq!(
            f.oldest(),
            Some(s(30)),
            "charged when sent, not when queued"
        );
        f.release(k(1, 8));
        assert_eq!(f.oldest(), None);
    }

    #[test]
    fn one_oversized_message_always_goes_alone() {
        let mut f = Flow::default();
        f.configure(true, 2);
        assert!(
            send(&mut f, 1, 0, 1, 100 << 20),
            "an empty lane admits any size"
        );
        assert!(!send(&mut f, 1, 0, 2, 4096));
        f.release(k(1, 1));
        assert_eq!(drain(&mut f, (1, 0)), vec![2]);
    }

    #[test]
    fn budget_shrinks_with_the_number_of_flashstore_peers_to_a_floor() {
        let mut f = Flow::default();
        f.configure(true, 4);
        assert_eq!((f.bytes, f.ops), (16 << 20, 32));
        f.configure(true, 1000);
        assert_eq!((f.bytes, f.ops), (4 << 20, 8));
        f.configure(true, 0);
        assert_eq!((f.bytes, f.ops), (32 << 20, 64));
    }
}
