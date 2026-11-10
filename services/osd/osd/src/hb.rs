// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Heartbeats (spec 5) and failure reporting (spec 7.1-7.2).
use crate::backend::Backend;
use crate::osd::{MsgrId, Osd, Purpose, State};
use denc::types::{EntityAddrVec, EntityName, UTime};
use messages::{MOSDFailure, MOSDPing, span_from_nanos};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

/// Heartbeat peers of `me` (spec osd-lifecycle 5.2), sorted: the up OSDs of `pg_osds`, the next and previous up
/// OSD id (ring), one up OSD from each of up to `max(min_reporters, min_peers)` CRUSH subtrees (`tree`: OSD ->
/// subtree of the reporter level, [`subtrees`]) other than ours (so a whole failed subtree, e.g. a host, is reported from >= `mon_osd_min_down_reporters` other
/// subtrees), then successive up ids after `next` until `min_peers`. The subtree order is a fixed per-OSD
/// permutation (hash of `me` and the bucket id): different OSDs pick different subtrees, and the set stays stable
/// across recomputations (no connection churn). The pick inside a subtree is its `me mod n`-th up OSD.
pub(crate) fn want_peers(
    map: &osdmap::OsdMap,
    me: i32,
    pg_osds: &BTreeSet<i32>,
    min_peers: usize,
    min_reporters: usize,
    tree: &BTreeMap<i32, i32>,
) -> BTreeSet<i32> {
    let ups: Vec<i32> = (0..map.max_osd)
        .filter(|o| *o != me && map.exists(*o) && map.is_up(*o))
        .collect();
    let mut want: BTreeSet<i32> = pg_osds
        .iter()
        .copied()
        .filter(|o| *o != me && map.exists(*o) && map.is_up(*o))
        .collect();
    let (Some(&first), Some(&last)) = (ups.first(), ups.last()) else {
        return want;
    };
    let next = ups.iter().copied().find(|o| *o > me).unwrap_or(first);
    let prev = ups.iter().copied().rev().find(|o| *o < me).unwrap_or(last);
    want.insert(next);
    want.insert(prev);
    let mine = tree.get(&me).copied();
    let mut by_tree: BTreeMap<i32, Vec<i32>> = BTreeMap::new();
    for o in &ups {
        if let Some(&t) = tree.get(o)
            && Some(t) != mine
        {
            by_tree.entry(t).or_default().push(*o);
        }
    }
    let mut order: Vec<(u64, i32)> = by_tree
        .keys()
        .map(|t| {
            let mut s = (u64::from(me as u32) << 32) | u64::from(*t as u32);
            (crate::osd::splitmix(&mut s), *t)
        })
        .collect();
    order.sort_unstable();
    for (_, t) in order.into_iter().take(min_reporters.max(min_peers)) {
        let v = &by_tree[&t];
        want.insert(v[me.unsigned_abs() as usize % v.len()]);
    }
    let start = ups.iter().position(|o| *o == next).unwrap_or(0);
    for i in 0..ups.len() {
        if want.len() >= min_peers {
            break;
        }
        want.insert(ups[(start + i) % ups.len()]);
    }
    want
}

/// Other OSDs (not `me`, no empty slot) in the up or acting set of `p`.
pub(crate) fn pg_peer_osds(p: &peering::Pg, me: i32) -> impl Iterator<Item = i32> + '_ {
    p.up()
        .iter()
        .chain(p.acting())
        .copied()
        .filter(move |o| *o >= 0 && *o != me && *o != osdmap::consts::ITEM_NONE)
}

/// OSD -> its CRUSH subtree of type `level` (empty without a CRUSH map); tests (the daemon uses the memoized map).
#[cfg(test)]
pub(crate) fn subtrees(map: &osdmap::OsdMap, level: &str) -> BTreeMap<i32, i32> {
    map.crush_state()
        .map_or_else(BTreeMap::new, |c| c.map.subtrees_of_type(level))
}

/// One closed 60 s RTT window: integer µs mean, min and max.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PingSlot {
    mean: u32,
    min: u32,
    max: u32,
}

/// Ring slots per peer and direction (spec ops-observability 6.4).
pub(crate) const PING_RING: usize = 16;

/// Heartbeat RTT statistics of one peer and direction: samples of the open window, the closed-window ring and the
/// most recent round.
#[derive(Debug, Clone, Default)]
pub(crate) struct PingStats {
    /// Unix seconds the open window started (0 = no sample yet).
    win_start: u32,
    sum_us: u64,
    n: u64,
    win_min: u32,
    win_max: u32,
    ring: [PingSlot; PING_RING],
    /// Next ring slot to write.
    next: usize,
    /// Slots with data (the first closed window pre-fills all of them).
    filled: usize,
    /// RTT of the most recent completed round.
    last: u32,
    /// Unix seconds of the last window close (0 = none).
    last_update: u32,
}

impl PingStats {
    /// Add one round RTT; closes the open window first when `span` seconds have passed.
    pub(crate) fn add(&mut self, now_s: u32, rtt_us: u32, span: u32) {
        let span = span.max(1);
        if self.win_start == 0 {
            self.win_start = now_s;
        } else if self.n > 0 && now_s >= self.win_start.saturating_add(span) {
            self.close(now_s);
            self.win_start = now_s;
        }
        self.sum_us += u64::from(rtt_us);
        self.n += 1;
        self.win_min = if self.n == 1 {
            rtt_us
        } else {
            self.win_min.min(rtt_us)
        };
        self.win_max = self.win_max.max(rtt_us);
        self.last = rtt_us;
    }

    fn close(&mut self, now_s: u32) {
        let slot = PingSlot {
            mean: (self.sum_us / self.n) as u32,
            min: self.win_min,
            max: self.win_max,
        };
        if self.filled == 0 {
            self.ring = [slot; PING_RING];
            self.filled = PING_RING;
            self.next = 0;
        } else {
            self.ring[self.next] = slot;
            self.next = (self.next + 1) % PING_RING;
            self.filled = (self.filled + 1).min(PING_RING);
        }
        self.sum_us = 0;
        self.n = 0;
        self.win_min = 0;
        self.win_max = 0;
        self.last_update = now_s;
    }

    /// `(average, min, max)` over the last 1, 5 and 15 closed windows.
    pub(crate) fn aggregates(&self) -> ([u32; 3], [u32; 3], [u32; 3]) {
        let mut avg = [0; 3];
        let mut mn = [0; 3];
        let mut mx = [0; 3];
        if self.filled == 0 {
            return (avg, mn, mx);
        }
        for (i, k) in [1usize, 5, 15].into_iter().enumerate() {
            let n = k.min(self.filled);
            let (mut sum, mut lo, mut hi) = (0u64, u32::MAX, 0u32);
            for j in 0..n {
                let idx = (self.next + PING_RING - n + j) % PING_RING;
                let s = self.ring[idx];
                sum += u64::from(s.mean);
                lo = lo.min(s.min);
                hi = hi.max(s.max);
            }
            avg[i] = (sum / n as u64) as u32;
            mn[i] = lo;
            mx[i] = hi;
        }
        (avg, mn, mx)
    }

    pub(crate) fn last_update(&self) -> u32 {
        self.last_update
    }

    pub(crate) fn last(&self) -> u32 {
        self.last
    }
}

/// One `dump_osd_network` row (spec 6.5).
#[derive(Debug, Clone, Copy)]
pub(crate) struct PingRow {
    pub osd: i32,
    /// `true` = back, `false` = front.
    pub back: bool,
    /// Max of the three window averages (µs); the dump threshold and sort key.
    pub ping: u32,
    pub avg: [u32; 3],
    pub min: [u32; 3],
    pub max: [u32; 3],
    pub last_update: u32,
    pub last: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Entry {
    deadline: Duration,
    remaining: u8,
    /// Local monotonic send time of this round; a reply must echo it to count as a clock sample.
    mono_ping: Duration,
}

#[derive(Debug, Default)]
pub(crate) struct HbPeer {
    pub back: Option<u64>,
    pub front: Option<u64>,
    pub history: BTreeMap<u64, Entry>,
    pub first_tx: Option<Duration>,
    pub last_tx: Option<Duration>,
    pub last_rx_back: Option<Duration>,
    pub last_rx_front: Option<Duration>,
    /// up_from the addresses below belong to.
    pub up_from: u32,
    /// Published clock bounds of this incarnation; only while `ec_optimized_direct` is on (adr 0683).
    pub clock_slot: Option<Arc<peering::PeerClockSlot>>,
    pub back_addrs: EntityAddrVec,
    pub front_addrs: EntityAddrVec,
    /// Heartbeat RTT statistics; `[0]` = back, `[1]` = front (spec 6.4).
    pub rtt: [PingStats; 2],
}

impl Entry {
    #[cfg(test)]
    pub(crate) fn new(deadline: Duration, remaining: u8, mono_ping: Duration) -> Self {
        Entry {
            deadline,
            remaining,
            mono_ping,
        }
    }
}

impl HbPeer {
    pub(crate) fn is_unhealthy(&self, now: Duration) -> bool {
        self.history
            .values()
            .next()
            .is_some_and(|e| now > e.deadline)
    }
    pub(crate) fn is_healthy(&self, now: Duration) -> bool {
        self.last_rx_back.is_some() && self.last_rx_front.is_some() && !self.is_unhealthy(now)
    }

    /// One PING_REPLY of the `front` (else back) connection: its own direction's RTT sample (spec 6.4), closing the
    /// round when both replies arrived.
    fn note_reply(&mut self, front: bool, stamp: UTime, wall: UTime, span: u32) {
        let key = stamp.as_nanos();
        let Some(e) = self.history.get_mut(&key) else {
            return;
        };
        self.rtt[usize::from(front)].add(wall.sec, rtt_us(wall, stamp), span);
        e.remaining = e.remaining.saturating_sub(1);
        if e.remaining == 0 {
            // the round is closed: nothing older than it is waited for any more
            self.history = self.history.split_off(&key.saturating_add(1));
        }
    }

    /// Which directions stopped answering: a direction is silent when it never replied or its last reply is older than
    /// the grace window. Returns `(back, front)` (CS-5247 / CS-5002: a one-NIC flap is reported per direction).
    fn silent_paths(&self, now: Duration, grace: Duration) -> (bool, bool) {
        let stale = |rx: Option<Duration>| rx.is_none_or(|t| now.saturating_sub(t) > grace);
        (stale(self.last_rx_back), stale(self.last_rx_front))
    }
}

/// One queued failure report: since when, and which heartbeat direction(s) went silent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Failure {
    /// Since when the peer stopped answering (`failed_for` seconds at send time).
    pub since: Duration,
    /// The back (cluster) path went silent.
    pub back: bool,
    /// The front (public) path went silent.
    pub front: bool,
}

#[derive(Debug, Default)]
pub(crate) struct Hb {
    pub peers: BTreeMap<i32, HbPeer>,
    pub next_round: Option<Duration>,
    pub failure_queue: BTreeMap<i32, Failure>,
    pub failure_pending: BTreeMap<i32, (Failure, EntityAddrVec)>,
    /// Reports withdrawn while the monitor could not accept the ALIVE message.
    pub failure_cancelling: BTreeMap<i32, EntityAddrVec>,
    pub last_update: Duration,
    /// [`subtrees`] of the last peer computation, kept while the CRUSH map (same decoded instance, carried across
    /// incrementals that do not replace it) and the level stay the same.
    subtrees: Option<(Arc<osdmap::CrushState>, String, BTreeMap<i32, i32>)>,
}

/// RTT of a round in µs: receiver wall clock at the last reply minus the sender's ping stamp (spec 6.4).
fn rtt_us(now: UTime, stamp: UTime) -> u32 {
    let ns = |t: UTime| u64::from(t.sec) * 1_000_000_000 + u64::from(t.nsec);
    (ns(now).saturating_sub(ns(stamp)) / 1000).min(u64::from(u32::MAX)) as u32
}

impl<B: Backend> Osd<B> {
    fn hb_active(&self) -> bool {
        matches!(self.state, State::Active | State::WaitingForHealthy)
    }

    /// Other OSDs in the up or acting set of this core's PGs.
    pub(crate) fn pg_osds_local(&self) -> BTreeSet<i32> {
        let me = self.id.whoami;
        self.pg
            .set
            .pgs()
            .flat_map(|(_, p)| pg_peer_osds(p, me))
            .collect()
    }

    /// Recompute the heartbeat peer set (spec 5.2, [`want_peers`]). PG peers come from every core (the workers'
    /// last per-second report).
    pub(crate) fn hb_update_peers(&mut self) {
        self.hb.last_update = self.now;
        let Some(map) = self.map.clone() else { return };
        let me = self.id.whoami;
        let mut pg_osds = BTreeSet::new();
        if self.state != State::WaitingForHealthy {
            pg_osds = self.pg_osds_local();
            for s in self.cl.stats.iter().flatten() {
                pg_osds.extend(s.pg_osds.iter().copied());
            }
        }
        let level = self
            .conf
            .get("mon_osd_reporter_subtree_level")
            .unwrap_or("host");
        let crush = map.crush_state();
        let fresh =
            self.hb.subtrees.as_ref().is_some_and(|(c, l, _)| {
                crush.is_some_and(|cur| Arc::ptr_eq(c, cur)) && l == level
            });
        if !fresh {
            self.hb.subtrees =
                crush.map(|c| (c.clone(), level.to_owned(), c.map.subtrees_of_type(level)));
        }
        let none = BTreeMap::new();
        let tree = self.hb.subtrees.as_ref().map_or(&none, |(.., t)| t);
        let want = want_peers(
            &map,
            me,
            &pg_osds,
            self.conf.u64("osd_heartbeat_min_peers", 10) as usize,
            self.conf.u64("mon_osd_min_down_reporters", 2) as usize,
            tree,
        );
        let gone: Vec<i32> = self
            .hb
            .peers
            .keys()
            .copied()
            .filter(|o| !want.contains(o))
            .collect();
        for o in gone {
            self.hb_remove_peer(o);
        }
        if !self.hb.peers.keys().copied().eq(want.iter().copied()) {
            self.log(format!("heartbeat peers: {want:?}"));
        }
        let direct = self.conf.bool("ec_optimized_direct", false);
        for o in want {
            let info = map.osd_info.get(o as usize).copied().unwrap_or_default();
            let b = map
                .hb_back_addrs
                .get(o as usize)
                .cloned()
                .unwrap_or_default();
            let f = map
                .hb_front_addrs
                .get(o as usize)
                .cloned()
                .unwrap_or_default();
            let changed = self.hb.peers.get(&o).is_some_and(|p| {
                p.up_from != info.up_from || p.back_addrs != b || p.front_addrs != f
            });
            if changed {
                self.hb_remove_peer(o);
            }
            self.hb.peers.entry(o).or_insert_with(|| HbPeer {
                up_from: info.up_from,
                back_addrs: b,
                front_addrs: f,
                ..Default::default()
            });
            self.hb_clock_slot(o, direct);
        }
    }

    /// `debug_heartbeat_testing_span` shortens the RTT window (0 = 60 s, spec 6.4).
    fn ping_span(&self) -> u32 {
        match self.conf.u64("debug_heartbeat_testing_span", 0) {
            0 => 60,
            s => s.min(u64::from(u32::MAX)) as u32,
        }
    }

    /// This core's heartbeat RTT rows, one per peer and direction with a closed window (spec 6.4).
    fn ping_rows(&self) -> Vec<(i32, bool, &PingStats)> {
        let mut v = Vec::new();
        for (o, p) in &self.hb.peers {
            if p.rtt[0].last_update() != 0 {
                v.push((*o, true, &p.rtt[0]));
            }
            if p.front.is_some() && p.rtt[1].last_update() != 0 {
                v.push((*o, false, &p.rtt[1]));
            }
        }
        v
    }

    /// `osd_stat.hb_pingtime`: one entry per peer, both directions, entries older than
    /// `osd_mon_heartbeat_stat_stale` dropped (spec 6.4).
    pub(crate) fn hb_pingtime(&self, now_s: u32, stale: u32) -> Vec<messages::HbPingtime> {
        let mut m: BTreeMap<i32, messages::HbPingtime> = BTreeMap::new();
        for (o, back, st) in self.ping_rows() {
            if now_s.saturating_sub(st.last_update()) > stale {
                continue;
            }
            let (avg, mn, mx) = st.aggregates();
            let e = m.entry(o).or_insert_with(|| messages::HbPingtime {
                osd: o,
                ..Default::default()
            });
            e.last_update = e.last_update.max(st.last_update());
            if back {
                e.back_pingtime = avg;
                e.back_min = mn;
                e.back_max = mx;
                e.back_last = st.last();
            } else {
                e.front_pingtime = avg;
                e.front_min = mn;
                e.front_max = mx;
                e.front_last = st.last();
            }
        }
        m.into_values().collect()
    }

    /// `dump_osd_network` rows: peers with a closed window, both directions (spec 6.5).
    pub(crate) fn ping_dump_rows(&self) -> Vec<PingRow> {
        self.ping_rows()
            .into_iter()
            .map(|(osd, back, st)| {
                let (avg, min, max) = st.aggregates();
                PingRow {
                    osd,
                    back,
                    ping: avg[0].max(avg[1]).max(avg[2]),
                    avg,
                    min,
                    max,
                    last_update: st.last_update(),
                    last: st.last(),
                }
            })
            .collect()
    }

    fn hb_remove_peer(&mut self, o: i32) {
        if let Some(p) = self.hb.peers.remove(&o) {
            if let Some(slot) = p.clock_slot {
                slot.store(None);
            }
            for l in [p.back, p.front].into_iter().flatten() {
                self.close_link(l);
            }
        }
        self.hb_cancel_failure(o);
    }

    pub(crate) fn hb_peer_down(&mut self, o: i32) {
        self.hb_remove_peer(o);
    }

    pub(crate) fn hb_drop_all(&mut self) {
        let ids: Vec<i32> = self.hb.peers.keys().copied().collect();
        for o in ids {
            self.hb_remove_peer(o);
        }
        self.hb.failure_queue.clear();
        self.hb.failure_pending.clear();
    }

    pub(crate) fn hb_link_lost(&mut self, o: i32, id: u64) {
        if let Some(p) = self.hb.peers.get_mut(&o) {
            if p.back == Some(id) {
                p.back = None;
            }
            if p.front == Some(id) {
                p.front = None;
            }
        }
    }

    /// Every ping kind (PING, PING_REPLY, YOU_DIED) is padded to `osd_heartbeat_min_size` like classic, so a path that
    /// drops large frames fails for all of them alike.
    fn ping_msg(&self, op: u8, stamp: UTime, mono_ping: Duration) -> MOSDPing {
        let pad = MOSDPing::pad_len_for(self.conf.u64("osd_heartbeat_min_size", 2000) as u32);
        MOSDPing {
            fsid: self.id.cluster_fsid,
            map_epoch: self.epoch(),
            op,
            ping_stamp: stamp,
            pad_len: pad,
            up_from: self.up_epoch,
            mono_ping_stamp: span_from_nanos(mono_ping.as_nanos() as i64),
            mono_send_stamp: span_from_nanos(self.mnow().as_nanos() as i64),
            delta_ub: None,
        }
    }

    /// One heartbeat round: ping every peer on back and front, then schedule the next round
    /// (0.5 + rand(0..9)/10 * osd_heartbeat_interval s, or exactly the interval when
    /// debug_disable_randomized_ping is set; spec 5.3).
    pub(crate) fn hb_round(&mut self) {
        let iv = self.conf.f64("osd_heartbeat_interval", 6.0);
        let interval = if self.conf.bool("debug_disable_randomized_ping", false) {
            iv
        } else {
            0.5 + (self.rand() % 10) as f64 / 10.0 * iv
        };
        self.hb.next_round = Some(self.now + Duration::from_secs_f64(interval));
        if !self.hb_active() {
            return;
        }
        if self.now.saturating_sub(self.hb.last_update)
            >= Duration::from_secs(self.conf.u64("osd_heartbeat_grace", 20))
        {
            self.hb_update_peers();
        }
        let grace = Duration::from_secs(self.conf.u64("osd_heartbeat_grace", 20));
        let stale = Duration::from_secs(self.conf.u64("osd_heartbeat_stale", 600));
        let stamp = self.wall();
        let mono = self.mnow();
        let ids: Vec<i32> = self.hb.peers.keys().copied().collect();
        for o in ids {
            let (ba, fa) = {
                let p = &self.hb.peers[&o];
                (p.back_addrs.clone(), p.front_addrs.clone())
            };
            let need_back = self.hb.peers[&o]
                .back
                .is_none_or(|l| !self.links.contains_key(&l));
            let need_front = self.hb.peers[&o]
                .front
                .is_none_or(|l| !self.links.contains_key(&l));
            if need_back {
                let l = self.dial(MsgrId::HbBackCli, Purpose::Hb(o), EntityName::OSD, &ba);
                if let Some(p) = self.hb.peers.get_mut(&o) {
                    p.back = l;
                }
            }
            if need_front {
                let l = self.dial(MsgrId::HbFrontCli, Purpose::Hb(o), EntityName::OSD, &fa);
                if let Some(p) = self.hb.peers.get_mut(&o) {
                    p.front = l;
                }
            }
            let (back, front) = {
                let p = &self.hb.peers[&o];
                (p.back, p.front)
            };
            if back.is_none() || front.is_none() {
                continue;
            }
            let now = self.now;
            if let Some(p) = self.hb.peers.get_mut(&o) {
                p.history.retain(|_, e| e.deadline + stale > now);
                p.history.insert(
                    stamp.as_nanos(),
                    Entry {
                        deadline: now + grace,
                        remaining: 2,
                        mono_ping: mono,
                    },
                );
                p.first_tx.get_or_insert(now);
                p.last_tx = Some(now);
            }
            for l in [back, front].into_iter().flatten() {
                let m = self.ping_msg(MOSDPing::PING, stamp, mono);
                self.send_link(l, m);
            }
        }
        self.perf.heartbeat_to_peers = self.hb.peers.len() as u64;
    }

    /// Attach a clock slot to every core while `ec_optimized_direct` is on, detach (revoke) it when off: samples are
    /// taken only for peers with a slot (adr 0683). Runs at peer refresh, never per ping.
    pub(crate) fn hb_clock_slot(&mut self, o: i32, direct: bool) {
        let Some(p) = self.hb.peers.get_mut(&o) else {
            return;
        };
        match (direct, p.clock_slot.is_some()) {
            (true, false) => {
                let slot = Arc::new(peering::PeerClockSlot::default());
                p.clock_slot = Some(slot.clone());
                self.xbcast(|| crate::xcore::XMsg::PeerClock {
                    osd: o,
                    slot: slot.clone(),
                });
                self.pg.set.attach_peer_clock(o, slot);
            }
            (false, true) => {
                if let Some(slot) = p.clock_slot.take() {
                    slot.store(None);
                }
            }
            _ => {}
        }
    }

    /// Clock sample from a PING / PING_REPLY of a peer with a clock slot (spec osd-lifecycle.md 5.3, adr 0683):
    /// lower = peer send - local receipt; upper = min(the peer's `delta_ub`, and for a reply echoing our outstanding
    /// ping: peer send - our ping send). A sample without an upper bound keeps the last one of the same incarnation.
    /// Only the incarnation the map shows is sampled; an unusable sample changes nothing. Never affects the ping
    /// handling itself (replies, YOU_DIED).
    fn observe_peer_clock(&mut self, peer_name: Option<EntityName>, p: &MOSDPing) {
        if !matches!(p.op, MOSDPing::PING | MOSDPing::PING_REPLY) {
            return;
        }
        let Some(osd) = peer_name
            .filter(|n| n.ty == EntityName::OSD)
            .and_then(|n| i32::try_from(n.num).ok())
        else {
            return;
        };
        let Some(peer) = self.hb.peers.get(&osd) else {
            return;
        };
        let Some(slot) = peer.clock_slot.as_ref() else {
            return;
        };
        let current = p.up_from != 0
            && self
                .map
                .as_ref()
                .and_then(|m| m.osd_info.get(osd as usize))
                .is_some_and(|i| i.up_from == p.up_from);
        let remote = messages::span_to_nanos(p.mono_send_stamp);
        let Ok(now) = i64::try_from(self.mnow().as_nanos()) else {
            return;
        };
        if !current || remote < 0 {
            return;
        }
        let mut upper = p.delta_ub.map(messages::span_to_nanos);
        if p.op == MOSDPing::PING_REPLY {
            // the peer sent the reply after our ping left: peer send - our send bounds the delta from above
            let Some(sent) = peer
                .history
                .get(&p.ping_stamp.as_nanos())
                .and_then(|e| i64::try_from(e.mono_ping.as_nanos()).ok())
                .filter(|&s| s == messages::span_to_nanos(p.mono_ping_stamp))
            else {
                return;
            };
            let own = remote.checked_sub(sent);
            upper = match (upper, own) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        // single writer (this core): the slot reads back what we stored last
        let last = slot.load().filter(|b| b.up_from == p.up_from);
        let bounds = peering::PeerClockBounds {
            up_from: p.up_from,
            lower: remote.checked_sub(now),
            upper: upper.or(last.and_then(|b| b.upper)),
        };
        if bounds.valid() {
            slot.store(Some(bounds));
        }
    }

    pub(crate) fn on_ping(&mut self, link: u64, p: MOSDPing) {
        if p.fsid != self.id.cluster_fsid || self.state == State::Stopping {
            return;
        }
        let Some((purpose, msgr, peer_name)) = self
            .links
            .get(&link)
            .map(|l| (l.purpose, l.msgr, l.peer.as_ref().map(|i| i.name)))
        else {
            return;
        };
        self.observe_peer_clock(peer_name, &p);
        match p.op {
            // internal watchdog unhealthy (a core stopped making progress): stay silent so peers report us (spec 5.4)
            MOSDPing::PING if self.live.is_some_and(|l| l.unhealthy()) => {}
            MOSDPing::PING => {
                let mono =
                    Duration::from_nanos(messages::span_to_nanos(p.mono_ping_stamp).max(0) as u64);
                let r = self.ping_msg(MOSDPing::PING_REPLY, p.ping_stamp, mono);
                self.send_link(link, r);
                // a peer we consider dead (or that is not up) learns that it was marked down
                if let (Some(n), Some(map)) = (peer_name, self.map.as_ref())
                    && n.ty == EntityName::OSD
                    && n.num >= 0
                {
                    let o = n.num as i32;
                    let died = !map.is_up(o)
                        && (!map.exists(o)
                            || map
                                .osd_info
                                .get(o as usize)
                                .is_some_and(|i| i.down_at > p.map_epoch));
                    if died && self.state == State::Active {
                        let y = self.ping_msg(MOSDPing::YOU_DIED, p.ping_stamp, mono);
                        self.send_link(link, y);
                    }
                }
            }
            MOSDPing::PING_REPLY => {
                let Purpose::Hb(o) = purpose else { return };
                let front = msgr == MsgrId::HbFrontCli;
                let now = self.now;
                let wall = self.wall();
                let span = self.ping_span();
                let mut healthy = false;
                if let Some(peer) = self.hb.peers.get_mut(&o) {
                    if !peer.history.contains_key(&p.ping_stamp.as_nanos()) {
                        return;
                    }
                    // each direction's RTT comes from its own reply, so a slow back path cannot hide in the front sample
                    peer.note_reply(front, p.ping_stamp, wall, span);
                    if front {
                        peer.last_rx_front = Some(now);
                    } else {
                        peer.last_rx_back = Some(now);
                    }
                    healthy = peer.is_healthy(now);
                }
                if healthy {
                    self.hb_cancel_failure(o);
                }
            }
            MOSDPing::YOU_DIED => {
                self.log("peer sent YOU_DIED: re-subscribing to maps");
                let e = u64::from(self.epoch()) + 1;
                self.mon_sub("osdmap", e, messages::SubItem::ONETIME);
            }
            _ => {}
        }
    }

    // ---------------------------------------------------------------- failure detection (5.5, 7.2)

    pub(crate) fn heartbeat_check(&mut self) {
        let now = self.now;
        let grace = Duration::from_secs(self.conf.u64("osd_heartbeat_grace", 20));
        let mut fails = Vec::new();
        for (o, p) in &self.hb.peers {
            if p.first_tx.is_none() || !p.is_unhealthy(now) {
                continue;
            }
            let since = if p.last_rx_back.is_none() || p.last_rx_front.is_none() {
                p.first_tx.unwrap_or(now)
            } else {
                p.last_rx_back.min(p.last_rx_front).unwrap_or(now)
            };
            let (back, front) = p.silent_paths(now, grace);
            fails.push((*o, Failure { since, back, front }));
        }
        for (o, f) in fails {
            self.hb.failure_queue.entry(o).or_insert(f);
        }
    }

    fn failure_msg(&self, o: i32, flags: u8, failed_for: i32, addrs: EntityAddrVec) -> MOSDFailure {
        MOSDFailure {
            version: u64::from(self.epoch()),
            fsid: self.id.cluster_fsid,
            target_osd: o,
            target_addrs: addrs,
            epoch: self.epoch(),
            flags,
            failed_for,
        }
    }

    pub(crate) fn flush_failures(&mut self) {
        self.flush_failure_cancellations();
        let Some(map) = self.map.clone() else { return };
        let q: Vec<(i32, Failure)> = self
            .hb
            .failure_queue
            .iter()
            .map(|(a, b)| (*a, *b))
            .collect();
        for (o, f) in q {
            if self.hb.failure_pending.contains_key(&o) {
                continue;
            }
            let addrs = map
                .client_addrs
                .get(o as usize)
                .cloned()
                .unwrap_or_default();
            let secs = self.now.saturating_sub(f.since).as_secs() as i32;
            let m = self.failure_msg(o, MOSDFailure::FLAG_FAILED, secs, addrs.clone());
            let paths = self.failure_paths(o, f);
            self.log(format!(
                "reporting osd.{o} failed (no heartbeat for {secs}s){paths}"
            ));
            if self.send_mon(m).is_some() {
                self.hb.failure_cancelling.remove(&o);
                self.hb.failure_pending.insert(o, (f, addrs));
            }
        }
    }

    /// The silent path(s) of a failure report as a log suffix: `: back path (peer …, local …), front path (…)`.
    fn failure_paths(&self, o: i32, f: Failure) -> String {
        let mut parts = Vec::new();
        for (silent, back, name) in [(f.back, true, "back"), (f.front, false, "front")] {
            if silent {
                parts.push(format!("{name} path ({})", self.hb_path_desc(o, back)));
            }
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!(": {}", parts.join(", "))
        }
    }

    /// The operator-facing endpoints of one heartbeat path: `peer <addrvec>, local <ip[,ip]> on <iface>` (the interface
    /// is omitted when unknown). `back` = the cluster/back path (CS-5247 / CS-5002).
    pub(crate) fn hb_path_desc(&self, o: i32, back: bool) -> String {
        let peer = self
            .hb
            .peers
            .get(&o)
            .map(|p| crate::osd::addrs_str(if back { &p.back_addrs } else { &p.front_addrs }))
            .unwrap_or_default();
        let ips = if back {
            &self.cfg.cluster_ips
        } else {
            &self.cfg.public_ips
        };
        let iface_key = if back { "back_iface" } else { "front_iface" };
        let local = ips
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let iface = self
            .cfg
            .sys_metadata
            .get(iface_key)
            .map(String::as_str)
            .unwrap_or("");
        if iface.is_empty() {
            format!("peer {peer}, local {local}")
        } else {
            format!("peer {peer}, local {local} on {iface}")
        }
    }

    pub(crate) fn hb_cancel_failure(&mut self, o: i32) {
        self.hb.failure_queue.remove(&o);
        if let Some((_, addrs)) = self.hb.failure_pending.remove(&o) {
            self.log(format!("cancelling failure report for osd.{o}"));
            let m = self.failure_msg(o, MOSDFailure::FLAG_ALIVE, 0, addrs.clone());
            if self.send_mon(m).is_some() {
                self.hb.failure_cancelling.remove(&o);
            } else {
                self.hb.failure_cancelling.insert(o, addrs);
            }
        }
    }

    /// Keep withdrawals until a monitor session accepts them, including after the peer leaves the heartbeat set.
    fn flush_failure_cancellations(&mut self) {
        let ids: Vec<i32> = self.hb.failure_cancelling.keys().copied().collect();
        for o in ids {
            let addrs = self.hb.failure_cancelling[&o].clone();
            let m = self.failure_msg(o, MOSDFailure::FLAG_ALIVE, 0, addrs);
            if self.send_mon(m).is_some() {
                self.hb.failure_cancelling.remove(&o);
            }
        }
    }

    pub(crate) fn hb_cancel_all_failures(&mut self) {
        let ids: Vec<i32> = self.hb.failure_pending.keys().copied().collect();
        for o in ids {
            self.hb_cancel_failure(o);
        }
        self.hb.failure_queue.clear();
    }

    /// New mon session: pending reports go back to the queue and are re-sent.
    pub(crate) fn hb_requeue_failures(&mut self) {
        let pend: Vec<(i32, Failure)> = self
            .hb
            .failure_pending
            .iter()
            .map(|(o, (f, _))| (*o, *f))
            .collect();
        self.hb.failure_pending.clear();
        for (o, f) in pend {
            self.hb.failure_queue.insert(o, f);
        }
        self.flush_failures();
    }

    /// Connection refused to a peer's heartbeat address on the `back` (else front) path: it crashed (spec 7.2).
    pub(crate) fn on_hb_refused(&mut self, o: i32, back: bool) {
        if !self.conf.bool("osd_fast_fail_on_connection_refused", true)
            || self.state != State::Active
            || self.hb.failure_pending.contains_key(&o)
        {
            return;
        }
        let Some(map) = self.map.as_ref() else { return };
        if !map.is_up(o) {
            return;
        }
        let addrs = map
            .client_addrs
            .get(o as usize)
            .cloned()
            .unwrap_or_default();
        let grace = self.conf.u64("osd_heartbeat_grace", 20) as i32;
        let m = self.failure_msg(
            o,
            MOSDFailure::FLAG_FAILED | MOSDFailure::FLAG_IMMEDIATE,
            grace + 1,
            addrs.clone(),
        );
        self.log(format!(
            "osd.{o} refused connection on {} path ({}): reporting immediate failure",
            if back { "back" } else { "front" },
            self.hb_path_desc(o, back)
        ));
        if self.send_mon(m).is_some() {
            // A new accepted FAILED report supersedes any withdrawal that could not be sent.
            self.hb.failure_cancelling.remove(&o);
            self.hb.failure_pending.insert(
                o,
                (
                    Failure {
                        since: self.now,
                        back,
                        front: !back,
                    },
                    addrs,
                ),
            );
        }
    }
}

#[cfg(test)]
mod ping_tests {
    use super::*;

    /// Heartbeat RTT aggregation (spec ops-observability 6.4): a completed round feeds one sample per direction, the
    /// first closed window pre-fills all 16 ring slots, later windows advance the ring round-robin, and the 1/5/15
    /// aggregates are the mean of the last n window means with min/max over their minima/maxima.
    #[test]
    fn ping_windows_roll_and_aggregate() {
        let mut s = PingStats::default();
        assert_eq!(s.aggregates(), ([0; 3], [0; 3], [0; 3]));
        // window at t=100: samples 100, 200, 300 us (mean 200, min 100, max 300)
        s.add(100, 100, 60);
        s.add(110, 200, 60);
        s.add(120, 300, 60);
        assert_eq!(s.last_update(), 0, "window still open");
        assert_eq!(s.last(), 300);
        // the next sample after the span closes the window and pre-fills all 16 slots
        s.add(161, 500, 60);
        assert_eq!(s.last_update(), 161);
        let (avg, mn, mx) = s.aggregates();
        assert_eq!(avg, [200, 200, 200]);
        assert_eq!(mn, [100, 100, 100]);
        assert_eq!(mx, [300, 300, 300]);
        // second window: 500 then 100 -> mean 300
        s.add(162, 100, 60);
        s.add(222, 400, 60);
        assert_eq!(s.last_update(), 222);
        let (avg, mn, mx) = s.aggregates();
        assert_eq!(avg[0], 300, "last window mean");
        assert_eq!(mn[0], 100);
        assert_eq!(mx[0], 500);
        // five windows: four pre-filled at 200 + the new 300
        assert_eq!(avg[1], (4 * 200 + 300) / 5);
        assert_eq!(mn[1], 100);
        assert_eq!(mx[1], 500);
        assert_eq!(avg[2], (14 * 200 + 300) / 15);
    }

    #[test]
    fn rtt_is_receiver_wall_minus_stamp() {
        let stamp = UTime::new(1_000, 250_000_000);
        assert_eq!(rtt_us(UTime::new(1_000, 250_500_000), stamp), 500);
        assert_eq!(rtt_us(UTime::new(1_001, 250_000_000), stamp), 1_000_000);
        // a reply older than the stamp cannot go negative
        assert_eq!(rtt_us(UTime::new(999, 0), stamp), 0);
    }

    /// Back and front replies feed their own direction's sample (spec 6.4): a slow path shows up in its direction only,
    /// and the round closes when the second reply arrived.
    #[test]
    fn back_and_front_replies_feed_separate_samples() {
        let mut p = HbPeer::default();
        let stamp = UTime::new(1_000, 0);
        p.history.insert(
            stamp.as_nanos(),
            Entry {
                deadline: Duration::from_secs(20),
                remaining: 2,
                mono_ping: Duration::ZERO,
            },
        );
        p.note_reply(false, stamp, UTime::new(1_000, 500_000), 60);
        assert_eq!(p.rtt[0].last(), 500, "back sample from the back reply");
        assert_eq!(p.rtt[1].last(), 0, "front has no sample yet");
        assert!(p.history.contains_key(&stamp.as_nanos()), "round is open");
        p.note_reply(true, stamp, UTime::new(1_001, 0), 60);
        assert_eq!(p.rtt[0].last(), 500, "back sample unchanged");
        assert_eq!(
            p.rtt[1].last(),
            1_000_000,
            "front sample from the front reply"
        );
        assert!(
            !p.history.contains_key(&stamp.as_nanos()),
            "round closed after both replies"
        );
    }
}
