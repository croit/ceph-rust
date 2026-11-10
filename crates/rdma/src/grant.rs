// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Credit grants of one core (0469-rdma-transport, design D7 "Scaling"): the sessions of a core share one SRQ of `depth`
//! receive slots, so memory is per core and never grows with the number of peers. The peer of a new session holds
//! [`MIN_WINDOW`] credits (endpoint record); the pool adds a fair share of the free slots at admission ([`Pool::admit`]),
//! lends more at once to a session that is credit-blocked ([`Pool::on_recv`]) and takes credits back from idle ones
//! (tick).
//!
//! Invariants (checked by the model tests below):
//! - no overcommit: the sum of granted credits (`sum`, pending shrinks included) never exceeds `depth`; a credit is a
//!   posted receive slot, and a consumed slot is re-posted before its credit is owed back ([`crate::credit`]);
//! - a removed session's credits stay reserved (in `sum`, not lendable) until its QP is destroyed ([`Pool::remove`],
//!   [`Pool::release`]): the dead QP's peer may still land SENDs in the shared SRQ until then;
//! - lending stops `headroom` short of `depth`, so a new session always finds room for its minimum window while the
//!   existing sessions shrink;
//! - every session keeps at least [`MIN_WINDOW`] credits (deadlock freedom of the reserved credit-only SEND);
//! - fairness: under pressure the extras (`depth - headroom - sessions * MIN_WINDOW`) are shared max-min fair: sessions
//!   that want more get an equal level, sessions that want less keep what they want.
//!
//! Growth is demand-driven, not timed: a session whose peer sent a whole window of data SENDs since the last tick is
//! credit-blocked (the peer sends at most `window - 1` before it must wait); on that arrival it is lent free credits up
//! to the fair level of the last tick and `max_window`, and the caller returns them in the same poll pass. The tick only
//! reclaims and rebalances. Admission may take back credits that were never sent (the initial extras of idle sessions),
//! so extras at the start never cost session capacity.
//!
//! Demand is observed per tick ([`TICK`]): a session that received at least a window's worth of SENDs wants twice its
//! window (up to `max_window`); one that received nothing for [`IDLE_TICKS`] ticks wants the minimum; one that used less
//! than a quarter of its window for that long wants half. Growth is only lent from slots that are free now; shrinking
//! drops credits we still owe at once and asks the peer for the rest (REVOKE / SURRENDER, [`crate::credit`]).
//!
//! Sans-IO: the caller owns time (one [`Pool::tick`] per [`TICK`]) and sends the control SENDs of the sessions
//! `tick` reports.
use crate::credit::{Credits, MIN_WINDOW, Overflow};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// Interval of the demand observation and rebalancing.
pub const TICK: Duration = Duration::from_millis(10);
/// Ticks without (enough) traffic before a session gives credits back.
pub const IDLE_TICKS: u8 = 10;

/// Sizing of one core's pool.
#[derive(Clone, Copy, Debug)]
pub struct GrantCfg {
    /// Receive slots of the core (SRQ depth).
    pub depth: u32,
    /// Largest window one session may hold.
    pub max_window: u32,
    /// Most sessions (slab size; `depth / MIN_WINDOW` at most).
    pub max_sessions: u32,
}

impl GrantCfg {
    /// Most sessions a pool of `depth` slots can hold at the minimum window.
    pub fn capacity(depth: u32) -> u32 {
        depth / MIN_WINDOW
    }
}

/// A session of the pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sid(u32);

#[derive(Debug)]
struct Sess {
    key: u32,
    c: Credits,
    /// Data SENDs received in this tick.
    arrived: u32,
    /// Consecutive ticks without any data / with less than a quarter of the window used.
    quiet: u8,
    light: u8,
}

/// Cumulative grant-policy counters of one core (plain integers, bumped where the policy acts).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GrantStats {
    /// Demand-driven lends: a credit-blocked session was lent credits on arrival ([`Pool::on_recv`]).
    pub grants_demand: u64,
    /// Extras given to a session at admission ([`Pool::admit`]).
    pub grants_admission: u64,
    /// Sessions whose wanted window fell back to the minimum after [`IDLE_TICKS`] quiet ticks (tick).
    pub idle_decays: u64,
    /// Largest window one session was granted so far.
    pub window_max: u32,
}

/// The grant pool of one core.
#[derive(Debug)]
pub struct Pool {
    /// Policy counters.
    pub stats: GrantStats,
    cfg: GrantCfg,
    headroom: u32,
    sess: Vec<Option<Sess>>,
    free: Vec<u32>,
    live: u32,
    /// Sum of the granted credits of all sessions, plus `reserved`.
    sum: u32,
    /// Credits of removed sessions whose QP is not destroyed yet ([`Pool::remove`]): its peer may still consume them.
    reserved: u32,
    /// Wanted window per slab slot during a tick.
    want: Vec<u32>,
    /// Round-robin start of the growth pass.
    rr: usize,
    /// Fair level of the extras at the last tick (`u32::MAX` = every wish fit): the cap of demand-driven growth.
    level: u32,
}

impl Pool {
    pub fn new(cfg: GrantCfg) -> Pool {
        assert!(cfg.max_window >= MIN_WINDOW && cfg.depth >= MIN_WINDOW);
        let n = cfg.max_sessions.min(GrantCfg::capacity(cfg.depth)) as usize;
        Pool {
            stats: GrantStats {
                window_max: MIN_WINDOW,
                ..GrantStats::default()
            },
            headroom: (cfg.depth / 16).max(2 * MIN_WINDOW),
            sess: (0..n).map(|_| None).collect(),
            free: (0..n as u32).rev().collect(),
            live: 0,
            sum: 0,
            reserved: 0,
            want: vec![0; n],
            rr: 0,
            level: u32::MAX,
            cfg,
        }
    }

    /// Credits the pool may still lend: free slots minus the headroom kept for new sessions.
    fn free(&self) -> u32 {
        self.cfg
            .depth
            .saturating_sub(self.headroom)
            .saturating_sub(self.sum)
    }

    /// Most sessions the pool holds.
    pub fn capacity(&self) -> usize {
        self.sess.len()
    }

    pub fn sessions(&self) -> usize {
        self.live as usize
    }

    /// Sum of the granted credits, reserved ones included (never above the depth).
    pub fn granted(&self) -> u32 {
        self.sum
    }

    /// Credits of removed sessions not released yet ([`Pool::remove`]).
    pub fn reserved(&self) -> u32 {
        self.reserved
    }

    /// New session `key` (the QP number); `peer_window` is what the peer granted us. The peer holds [`MIN_WINDOW`] credits
    /// (the endpoint record); the session starts with `min(max_window, MIN_WINDOW + fair share of the free pool)`: the
    /// extra credits are owed and travel with the first SEND or credit-only SEND after the peer's first message (never
    /// before: the peer may not have attached its end yet). `None` when no room is left (no slab slot, or the minimum
    /// windows of all sessions fill the pool).
    pub fn admit(&mut self, key: u32, peer_window: u32) -> Option<Sid> {
        if self.free.is_empty() {
            return None;
        }
        // credits that were never sent (initial extras of fresh sessions) make room at once
        let need = (self.sum + MIN_WINDOW).saturating_sub(self.cfg.depth);
        if need > 0 && self.reclaim_owed(need) < need {
            return None;
        }
        let i = self.free.pop()?;
        self.sess[i as usize] = Some(Sess {
            key,
            c: Credits::new(MIN_WINDOW, peer_window),
            arrived: 0,
            quiet: 0,
            light: 0,
        });
        self.live += 1;
        self.sum += MIN_WINDOW;
        let share = (self.free() / self.live).min(self.cfg.max_window - MIN_WINDOW);
        if share > 0 {
            self.s(Sid(i)).c.grow(share);
            self.sum += share;
            self.stats.grants_admission += 1;
            self.stats.window_max = self.stats.window_max.max(MIN_WINDOW + share);
        }
        Some(Sid(i))
    }

    /// Take back up to `need` credits that are still owed (not sent to a peer), from sessions above the minimum.
    fn reclaim_owed(&mut self, need: u32) -> u32 {
        let mut got = 0;
        for s in self.sess.iter_mut().flatten() {
            got += s.c.drop_owed(need - got);
            if got == need {
                break;
            }
        }
        self.sum -= got;
        got
    }

    /// The session ended: its slab slot is free at once, its granted credits stay reserved and are returned: the peer
    /// may still hold them and land SENDs in the shared SRQ until the session's QP is destroyed, so lending them to
    /// another session before would let that session's peer find no posted slot (RNR). Hand them to
    /// [`Pool::release`] once no SEND of the old QP can land any more (destroy confirmed, its receive completions
    /// processed); never, if the destroy failed.
    #[must_use = "the credits stay reserved until released"]
    pub fn remove(&mut self, sid: Sid) -> u32 {
        let Some(s) = self.sess[sid.0 as usize].take() else {
            return 0;
        };
        let g = s.c.granted();
        self.reserved += g;
        self.live -= 1;
        self.free.push(sid.0);
        g
    }

    /// Credits reserved by [`Pool::remove`] go back to the pool.
    pub fn release(&mut self, credits: u32) {
        assert!(
            credits <= self.reserved,
            "release of {credits} credits, {} reserved",
            self.reserved
        );
        self.reserved -= credits;
        self.sum -= credits;
    }

    fn s(&mut self, sid: Sid) -> &mut Sess {
        self.sess[sid.0 as usize].as_mut().expect("live session id")
    }

    /// The credit state of a session (send side: take credits, control SENDs).
    pub fn credits(&mut self, sid: Sid) -> &mut Credits {
        &mut self.s(sid).c
    }

    /// A SEND of the session arrived carrying `imm` (`data`: it carried stream bytes). Returns true when the session
    /// was credit-blocked (the peer sent a whole window in this tick) and the pool lent it credits at once, without
    /// waiting for the tick: the caller sends them now ([`Pool::next_send`]). They are backed by free slots, not by the
    /// slot of this SEND.
    pub fn on_recv(&mut self, sid: Sid, imm: u32, data: bool) -> Result<bool, Overflow> {
        let s = self.s(sid);
        let shrunk = s.c.on_recv(imm)?;
        s.arrived += u32::from(data);
        self.sum -= shrunk;
        Ok(data && self.grow_on_demand(sid))
    }

    /// Demand-driven growth: a session that received a whole window of data SENDs in this tick (the peer sends at most
    /// `window - 1` data SENDs before it must wait for credits) is lent the free credits up to its fair level (the
    /// last tick's), at most `max_window`. A session with a shrink pending is left to the tick.
    fn grow_on_demand(&mut self, sid: Sid) -> bool {
        let (max, level, free) = (self.cfg.max_window, self.level, self.free());
        let s = self.s(sid);
        let g = s.c.granted();
        if s.c.effective() != g || g >= max || s.arrived + 1 < g {
            return false;
        }
        let n = MIN_WINDOW
            .saturating_add(level)
            .min(max)
            .saturating_sub(g)
            .min(free);
        if n == 0 {
            return false;
        }
        s.c.grow(n);
        self.sum += n;
        self.stats.grants_demand += 1;
        self.stats.window_max = self.stats.window_max.max(g + n);
        true
    }

    /// A slot consumed by the session is posted again.
    pub fn on_reposted(&mut self, sid: Sid) {
        let shrunk = self.s(sid).c.on_reposted();
        self.sum -= shrunk;
    }

    /// A control or credit-only SEND is due (it may wait for send queue room).
    pub fn due(&mut self, sid: Sid) -> bool {
        let c = self.credits(sid);
        c.want_control() || c.want_credit_only()
    }

    /// The next control or credit-only SEND the session owes and may send now (its immediate), if any. Call after
    /// [`Pool::on_reposted`] and [`Pool::on_recv`], per completion.
    pub fn next_send(&mut self, sid: Sid) -> Option<u32> {
        let c = self.credits(sid);
        if c.want_control() {
            Some(c.take_control())
        } else if c.want_credit_only() {
            Some(c.take_credit_only())
        } else {
            None
        }
    }

    /// `(key, granted, effective)` of every session.
    pub fn sessions_iter(&self) -> impl Iterator<Item = (u32, u32, u32)> + '_ {
        self.sess
            .iter()
            .flatten()
            .map(|s| (s.key, s.c.granted(), s.c.effective()))
    }

    /// Observe demand, rebalance; `touched(key)` is called for every session whose credit state changed (it may owe
    /// credits or a control SEND now).
    pub fn tick(&mut self, mut touched: impl FnMut(u32)) {
        if self.live == 0 {
            return;
        }
        let max = self.cfg.max_window;
        let lend = self.cfg.depth.saturating_sub(self.headroom);
        let extras = lend.saturating_sub(self.reserved + self.live * MIN_WINDOW);
        // 1. wanted window per session
        let mut desire = 0u64;
        for (s, w) in self.sess.iter_mut().zip(self.want.iter_mut()) {
            let Some(s) = s else {
                *w = 0;
                continue;
            };
            let eff = s.c.effective();
            s.quiet = if s.arrived == 0 {
                s.quiet.saturating_add(1)
            } else {
                0
            };
            s.light = if s.arrived * 4 < eff {
                s.light.saturating_add(1)
            } else {
                0
            };
            *w = if s.arrived >= eff {
                eff.saturating_mul(2).min(max)
            } else if s.quiet >= IDLE_TICKS {
                self.stats.idle_decays += u64::from(eff > MIN_WINDOW);
                MIN_WINDOW
            } else if s.light >= IDLE_TICKS {
                s.light = 0;
                (eff / 2).max(MIN_WINDOW)
            } else {
                eff
            };
            s.arrived = 0;
            desire += u64::from(*w - MIN_WINDOW);
        }
        // 2. max-min fair level of the extras
        let level = if desire <= u64::from(extras) {
            u32::MAX
        } else {
            let sum_at = |l: u32| -> u64 {
                self.want
                    .iter()
                    .zip(&self.sess)
                    .filter(|(_, s)| s.is_some())
                    .map(|(w, _)| u64::from((*w - MIN_WINDOW).min(l)))
                    .sum()
            };
            let (mut lo, mut hi) = (0, max);
            while lo < hi {
                let mid = lo + (hi - lo).div_ceil(2);
                if sum_at(mid) <= u64::from(extras) {
                    lo = mid;
                } else {
                    hi = mid - 1;
                }
            }
            lo
        };
        self.level = level;
        let target = |w: u32| MIN_WINDOW + (w - MIN_WINDOW).min(level);
        // 3. shrink first (frees credits as far as they are owed here), then lend what is free
        for (s, w) in self.sess.iter_mut().zip(&self.want) {
            let Some(s) = s else { continue };
            let (eff, t) = (s.c.effective(), target(*w));
            if t < eff {
                self.sum -= s.c.shrink(eff - t);
                touched(s.key);
            }
        }
        let mut free = lend.saturating_sub(self.sum);
        let n = self.sess.len();
        for k in 0..n {
            let i = (self.rr + k) % n;
            let Some(s) = self.sess[i].as_mut() else {
                continue;
            };
            let (eff, t) = (s.c.effective(), target(self.want[i]));
            if t > eff {
                let rest = s.c.cancel_shrink(t - eff);
                // a pending shrink still counts as granted: the session's hold queue never outgrows `max_window`
                let g = rest.min(free).min(max.saturating_sub(s.c.granted()));
                if g > 0 {
                    s.c.grow(g);
                    self.sum += g;
                    free -= g;
                    self.stats.window_max = self.stats.window_max.max(s.c.granted());
                }
                touched(s.key);
            }
        }
        self.rr = (self.rr + 1) % n;
    }
}

/// Process-wide limit of upgraded sessions (`flashstore_rdma_max_sessions`): a connection that cannot get a [`Permit`] stays
/// TCP (a decline, never an error).
#[derive(Debug)]
pub struct SessionCap {
    limit: u32,
    live: AtomicU32,
}

impl SessionCap {
    /// `limit` 0 = unlimited.
    pub fn new(limit: u32) -> Arc<SessionCap> {
        Arc::new(SessionCap {
            limit,
            live: AtomicU32::new(0),
        })
    }

    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// Sessions (and upgrades in progress) holding a permit now.
    pub fn live(&self) -> u32 {
        self.live.load(Ordering::Relaxed)
    }

    /// Take a slot; `None` when the limit is reached.
    pub fn acquire(self: &Arc<SessionCap>) -> Option<Permit> {
        self.live
            .try_update(Ordering::AcqRel, Ordering::Relaxed, |n| {
                (self.limit == 0 || n < self.limit).then_some(n + 1)
            })
            .ok()
            .map(|_| Permit(self.clone()))
    }
}

/// One slot of the [`SessionCap`], released on drop.
#[derive(Debug)]
pub struct Permit(Arc<SessionCap>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credit::Imm;
    use std::collections::VecDeque;

    /// SENDs one session moves per round in each direction.
    const BURST: usize = 4;

    /// The far end of a session: a plain credit state (its own window to us is fixed) that sends `left` data SENDs.
    struct Peer {
        c: Credits,
        left: u32,
        /// SENDs on the wire to the hub: (imm, carries data).
        wire: VecDeque<(u32, bool)>,
        /// SENDs on the wire to the peer.
        inbox: VecDeque<u32>,
    }

    /// A pool with its peers, one in-order wire per direction, and the receive-buffer accounting of the SRQ.
    struct Sim {
        pool: Pool,
        sids: Vec<Sid>,
        peers: Vec<Peer>,
        /// Receive slots posted in the SRQ; a SEND that finds none would be an RNR.
        posted: i64,
        /// Consumed slots not re-posted yet (owner session).
        consumed: VecDeque<usize>,
        rng: u64,
        steps: u64,
    }

    impl Sim {
        fn new(depth: u32, max_window: u32, n: usize) -> Sim {
            let mut pool = Pool::new(GrantCfg {
                depth,
                max_window,
                max_sessions: n as u32,
            });
            let mut sids = Vec::new();
            let mut peers = Vec::new();
            for i in 0..n {
                sids.push(pool.admit(i as u32, MIN_WINDOW).expect("admit"));
                peers.push(Peer {
                    // the peer grants the hub the minimum window (its end of the same session; both ends start equal)
                    c: Credits::new(MIN_WINDOW, MIN_WINDOW),
                    left: 0,
                    wire: VecDeque::new(),
                    inbox: VecDeque::new(),
                });
            }
            Sim {
                pool,
                sids,
                peers,
                posted: i64::from(depth),
                consumed: VecDeque::new(),
                rng: 0x9E37_79B9_7F4A_7C15,
                steps: 0,
            }
        }

        fn rand(&mut self) -> u64 {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            self.rng
        }

        /// One round: peers send, the hub receives and re-posts with a delay, answers, control SENDs flow.
        fn step(&mut self, tick: bool) {
            self.steps += 1;
            let n = self.peers.len();
            // peers
            for i in 0..n {
                let p = &mut self.peers[i];
                while let Some(imm) = p.inbox.pop_front() {
                    p.c.on_recv(imm).expect("hub message valid");
                    p.c.on_reposted();
                }
                for _ in 0..BURST {
                    if p.c.want_control() {
                        p.wire.push_back((p.c.take_control(), false));
                    } else if p.left > 0 && p.c.can_send_data() {
                        p.wire.push_back((p.c.take_data(), true));
                        p.left -= 1;
                    } else if p.c.want_credit_only() {
                        p.wire.push_back((p.c.take_credit_only(), false));
                    }
                }
            }
            // hub receives
            for i in 0..n {
                for _ in 0..BURST {
                    let Some((imm, data)) = self.peers[i].wire.pop_front() else {
                        break;
                    };
                    self.posted -= 1;
                    assert!(
                        self.posted >= 0,
                        "SRQ ran dry: a SEND without a posted slot (RNR)"
                    );
                    self.pool
                        .on_recv(self.sids[i], imm, data)
                        .expect("peer message valid");
                    self.consumed.push_back(i);
                }
            }
            // re-post some consumed slots (the rest later)
            let k = 1 + (self.rand() % self.consumed.len().max(1) as u64) as usize;
            for _ in 0..k.min(self.consumed.len()) {
                let i = self.consumed.pop_front().unwrap();
                self.posted += 1;
                self.pool.on_reposted(self.sids[i]);
            }
            if tick {
                let mut touched = Vec::new();
                self.pool.tick(|k| touched.push(k));
            }
            // hub sends: returns and control
            for i in 0..n {
                let c = self.pool.credits(self.sids[i]);
                if c.want_control() {
                    let imm = c.take_control();
                    self.peers[i].inbox.push_back(imm);
                } else if c.want_credit_only() {
                    let imm = c.take_credit_only();
                    self.peers[i].inbox.push_back(imm);
                }
            }
            self.check();
        }

        fn check(&mut self) {
            let depth = self.pool.cfg.depth;
            assert!(
                self.pool.sum <= depth,
                "overcommit: {} > {depth}",
                self.pool.sum
            );
            let total: u32 = self.pool.sessions_iter().map(|(_, g, _)| g).sum();
            assert_eq!(total, self.pool.sum, "pool sum drifted");
            let unposted = self.consumed.len() as i64;
            assert_eq!(self.posted + unposted, i64::from(depth), "slot accounting");
            for (k, g, e) in self.pool.sessions_iter().collect::<Vec<_>>() {
                assert!(
                    e >= MIN_WINDOW && g >= e && g <= self.pool.cfg.max_window,
                    "session {k}: granted {g} effective {e}"
                );
            }
        }

        fn ticks(&mut self, rounds: u64, every: u64) {
            for r in 0..rounds {
                self.step(r % every == 0);
            }
        }

        fn run_until_done(&mut self, limit: u64, every: u64) -> bool {
            for r in 0..limit {
                self.step(r % every == 0);
                if self.peers.iter().all(|p| p.left == 0 && p.wire.is_empty())
                    && self.consumed.is_empty()
                {
                    return true;
                }
            }
            false
        }

        fn effective_of(&self, i: usize) -> u32 {
            self.pool
                .sessions_iter()
                .find(|(k, ..)| *k == i as u32)
                .map(|(_, _, e)| e)
                .unwrap()
        }
    }

    #[test]
    fn many_sessions_bursty_demand_no_overcommit_no_deadlock() {
        // 150 sessions x 3 = 450 of 512 slots at the minimum
        let mut sim = Sim::new(512, 64, 150);
        for round in 0..40 {
            for i in 0..150 {
                if sim.rand().is_multiple_of(7) {
                    sim.peers[i].left += (sim.rand() % 200) as u32;
                }
            }
            sim.ticks(50 + round, 5);
        }
        assert!(sim.run_until_done(200_000, 5), "sessions stalled");
        // everything delivered; idle sessions return to the minimum
        sim.ticks(400, 5);
        for i in 0..150 {
            assert_eq!(
                sim.effective_of(i),
                MIN_WINDOW,
                "session {i} did not give its credits back"
            );
        }
        assert_eq!(
            sim.pool.granted(),
            150 * MIN_WINDOW,
            "every credit came back"
        );
    }

    #[test]
    fn all_sessions_exhausted_at_once_still_finish() {
        let mut sim = Sim::new(512, 64, 150);
        for p in &mut sim.peers {
            p.left = 3000;
        }
        assert!(
            sim.run_until_done(2_000_000, 3),
            "deadlock with every session saturated"
        );
    }

    #[test]
    fn idle_sessions_are_reclaimed_for_busy_ones() {
        let mut sim = Sim::new(320, 64, 20);
        // session 0 gets busy and grows to the maximum
        sim.peers[0].left = 1_000_000;
        sim.ticks(2_000, 10);
        assert!(
            sim.effective_of(0) > 32,
            "busy session grows: {}",
            sim.effective_of(0)
        );
        // it stops; another one takes over
        sim.peers[0].left = 0;
        sim.peers[1].left = 1_000_000;
        sim.ticks(3_000, 10);
        assert_eq!(
            sim.effective_of(0),
            MIN_WINDOW,
            "idle session gave its credits back"
        );
        assert!(sim.effective_of(1) > 32);
    }

    #[test]
    fn busy_sessions_share_the_extras_fairly() {
        let (depth, n, busy) = (512u32, 100usize, 10usize);
        let mut sim = Sim::new(depth, 256, n);
        for i in 0..busy {
            sim.peers[i].left = u32::MAX;
        }
        sim.ticks(8_000, 10);
        let lend = depth - sim.pool.headroom;
        let level = (lend - n as u32 * MIN_WINDOW) / busy as u32;
        for i in 0..busy {
            let e = sim.effective_of(i);
            // equal share of the extras (the level is a whole number of credits; growth is in doubling steps)
            assert!(
                e + 1 >= MIN_WINDOW + level / 2 && e <= MIN_WINDOW + level,
                "busy session {i} holds {e}, fair share {}",
                MIN_WINDOW + level
            );
        }
        let (lo, hi) = (0..busy)
            .map(|i| sim.effective_of(i))
            .fold((u32::MAX, 0), |(l, h), e| (l.min(e), h.max(e)));
        assert!(
            hi <= 2 * lo,
            "busy sessions differ more than 2x: {lo}..{hi}"
        );
        for i in busy..n {
            assert_eq!(sim.effective_of(i), MIN_WINDOW);
        }
    }

    #[test]
    fn admission_is_bounded_by_the_minimum_windows_only() {
        let mut pool = Pool::new(GrantCfg {
            depth: 300,
            max_window: 64,
            max_sessions: 1000,
        });
        assert_eq!(pool.capacity(), 100);
        let ids: Vec<_> = (0..100).map(|k| pool.admit(k, MIN_WINDOW)).collect();
        assert!(ids.iter().all(Option::is_some));
        assert!(
            pool.admit(100, MIN_WINDOW).is_none(),
            "pool is full of minimum windows"
        );
        let reserved = pool.remove(ids[3].unwrap());
        assert_eq!((reserved, pool.reserved()), (MIN_WINDOW, MIN_WINDOW));
        assert!(
            pool.admit(101, MIN_WINDOW).is_none(),
            "the ended session's credits stay reserved until its QP is destroyed"
        );
        pool.release(reserved);
        assert!(
            pool.admit(101, MIN_WINDOW).is_some(),
            "room again after the ended session's QP is destroyed"
        );
        assert_eq!((pool.granted(), pool.reserved()), (300, 0));
    }

    #[test]
    fn removed_credits_are_not_lent_before_release() {
        let mut pool = Pool::new(GrantCfg {
            depth: 96,
            max_window: 64,
            max_sessions: 4,
        });
        let a = pool.admit(1, MIN_WINDOW).unwrap();
        let b = pool.admit(2, MIN_WINDOW).unwrap();
        let ga = pool.credits(a).granted();
        assert!(ga > MIN_WINDOW, "a holds extras from admission");
        assert_eq!(pool.remove(a), ga);
        assert_eq!(pool.remove(a), 0, "a second remove reserves nothing");
        let gb = pool.credits(b).granted();
        assert_eq!(pool.granted(), ga + gb, "reserved credits stay counted");
        assert_eq!(pool.free(), (96 - pool.headroom).saturating_sub(ga + gb));
        // the fair level leaves the reserved credits out of the extras
        let extras = 96 - pool.headroom - ga - MIN_WINDOW;
        pool.tick(|_| {});
        assert!(pool.level == u32::MAX || pool.level <= extras);
        pool.release(ga);
        assert_eq!((pool.granted(), pool.reserved()), (gb, 0));
        assert_eq!(pool.free(), 96 - pool.headroom - gb);
    }

    #[test]
    #[should_panic(expected = "release of")]
    fn releasing_more_than_reserved_panics() {
        let mut pool = Pool::new(GrantCfg {
            depth: 96,
            max_window: 64,
            max_sessions: 4,
        });
        pool.release(1);
    }

    #[test]
    fn session_cap_counts_permits() {
        let cap = SessionCap::new(2);
        let a = cap.acquire().unwrap();
        let _b = cap.acquire().unwrap();
        assert!(cap.acquire().is_none());
        drop(a);
        assert_eq!(cap.live(), 1);
        assert!(cap.acquire().is_some());
        let unlimited = SessionCap::new(0);
        let held: Vec<_> = (0..10_000).map(|_| unlimited.acquire().unwrap()).collect();
        assert_eq!(unlimited.live(), held.len() as u32);
    }

    #[test]
    fn a_credit_blocked_session_is_lent_credits_on_arrival() {
        let mut pool = Pool::new(GrantCfg {
            depth: 320,
            max_window: 16,
            max_sessions: 4,
        });
        let sid = pool.admit(7, MIN_WINDOW).unwrap();
        // the initial extras are dropped: a session at the minimum, as after idle
        let owed = pool.credits(sid).owed();
        let d = pool.credits(sid).drop_owed(owed);
        pool.sum -= d;
        assert_eq!(pool.credits(sid).granted(), MIN_WINDOW);
        // the peer sends its 2 data SENDs (window 3 minus the reserved credit): blocked, so the pool lends at once
        assert!(!pool.on_recv(sid, Imm::Credits(0).encode(), true).unwrap());
        assert!(pool.on_recv(sid, Imm::Credits(0).encode(), true).unwrap());
        assert_eq!(pool.credits(sid).granted(), 16);
        assert!(pool.credits(sid).want_credit_only(), "owed: sent now");
        let st = pool.stats;
        assert_eq!(
            (st.grants_demand, st.grants_admission, st.window_max),
            (1, 1, 16)
        );
    }

    #[test]
    fn admission_gives_a_fair_share_and_never_costs_capacity() {
        let mut pool = Pool::new(GrantCfg {
            depth: 320,
            max_window: 16,
            max_sessions: 1000,
        });
        let first = pool.admit(0, MIN_WINDOW).unwrap();
        assert_eq!(pool.credits(first).granted(), 16, "alone: the ceiling");
        let second = pool.admit(1, MIN_WINDOW).unwrap();
        assert_eq!(pool.credits(second).granted(), 16, "room for both");
        // the extras are owed, not sent: the peer still holds the minimum
        assert!(pool.credits(first).owed() >= 13);
        assert!(pool.credits(first).avail() == MIN_WINDOW);
        // every other session still fits: unsent extras make room at admission
        let more: Vec<_> = (2..106).map(|k| pool.admit(k, MIN_WINDOW)).collect();
        assert!(more.iter().all(Option::is_some), "capacity 106 of 320/3");
        assert!(pool.granted() <= 320);
        assert!(
            pool.sessions_iter()
                .all(|(_, g, e)| e >= MIN_WINDOW && g <= 16)
        );
    }

    #[test]
    fn burst_after_idle_reaches_the_ceiling_within_round_trips_not_ticks() {
        // 4 sessions idle until every window is back at the minimum, then one bursts; the tick never runs again
        let mut sim = Sim::new(320, 16, 4);
        sim.ticks(300, 1);
        for i in 0..4 {
            assert_eq!(sim.effective_of(i), MIN_WINDOW);
        }
        assert_eq!(sim.pool.stats.idle_decays, 4, "one decay per idle session");
        assert_eq!(sim.pool.stats.grants_admission, 4);
        assert!(sim.pool.stats.window_max > MIN_WINDOW);
        sim.peers[0].left = 100_000;
        let mut rounds = 0;
        while sim.effective_of(0) < 16 {
            sim.step(false);
            rounds += 1;
            assert!(
                rounds <= 4,
                "window {} after {rounds} rounds",
                sim.effective_of(0)
            );
        }
        // and it keeps the window while it streams, without a tick
        sim.peers[0].left = u32::MAX;
        for _ in 0..200 {
            sim.step(false);
        }
        assert_eq!(sim.effective_of(0), 16);
    }

    #[test]
    fn demand_growth_never_overcommits_and_stops_at_the_headroom() {
        let mut pool = Pool::new(GrantCfg {
            depth: 48,
            max_window: 64,
            max_sessions: 16,
        });
        let ids: Vec<_> = (0..3).map(|k| pool.admit(k, MIN_WINDOW).unwrap()).collect();
        for _ in 0..10 {
            for &s in &ids {
                for _ in 0..40 {
                    pool.on_recv(s, Imm::Credits(0).encode(), true).unwrap();
                    assert!(pool.granted() <= 48, "overcommit");
                    pool.on_reposted(s);
                    let _ = pool.next_send(s);
                }
            }
        }
        assert!(
            pool.granted() <= 48 - pool.headroom + 3 * MIN_WINDOW,
            "lending stops at the headroom"
        );
        assert!(pool.sessions_iter().all(|(_, _, e)| e >= MIN_WINDOW));
    }

    /// The receiver of the poll loop: per completion `on_recv`, dispatch (work), re-post, credit SEND; returns for
    /// every credit SEND the number of messages dispatched before it left and its immediate.
    fn poll_batch(pool: &mut Pool, sid: Sid, batch: u32) -> Vec<(u32, u32)> {
        let (mut out, mut dispatched) = (Vec::new(), 0);
        for _ in 0..batch {
            let grown = pool.on_recv(sid, Imm::Credits(0).encode(), true).unwrap();
            if grown && let Some(imm) = pool.next_send(sid) {
                out.push((dispatched, imm));
            }
            dispatched += 1; // the upper layer works on the slot (copy, checksum, dispatch) ...
            pool.on_reposted(sid); // ... only then it is posted again ...
            if let Some(imm) = pool.next_send(sid) {
                out.push((dispatched, imm)); // ... and its credit goes out at once, not after the batch
            }
        }
        out
    }

    #[test]
    fn credits_leave_before_the_batch_is_dispatched() {
        let mut pool = Pool::new(GrantCfg {
            depth: 320,
            max_window: 16,
            max_sessions: 4,
        });
        let sid = pool.admit(1, MIN_WINDOW).unwrap();
        // 16 completions in one CQ batch of a session with a window of 16
        let sends = poll_batch(&mut pool, sid, 16);
        let (first_at, imm) = sends[0];
        assert!(
            first_at <= 8,
            "first credit SEND after {first_at} of 16 dispatched"
        );
        assert!(matches!(Imm::decode(imm), Some(Imm::Credits(n)) if n >= 8));
        // a credit returned only for a slot re-posted: the owed extras of admission are the only surplus
        let returned: u32 = sends
            .iter()
            .map(|&(_, i)| match Imm::decode(i).unwrap() {
                Imm::Credits(n) => n,
                _ => 0,
            })
            .sum();
        assert!(returned <= 16 + 13, "returned {returned}");
    }
}
