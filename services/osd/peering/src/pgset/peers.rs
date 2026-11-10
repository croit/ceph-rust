// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Peer session health (adr 0071): the OSD reports msgr faults / resets / connects of the cluster session to a peer.
//! A peer whose session was lost gets the outstanding peering requests of every PG sent again (`Pg::redrive_peering`)
//! with a per-peer exponential back-off. Until the session is back (READY or a message from the peer), new queries to
//! it are held: the redrive carries them, so map churn cannot flood a peer that does not answer.

use super::*;

/// The first loss is redriven at once; every further loss, or a redrive the peer did not answer, doubles the back-off
/// from `PEER_BACKOFF_MIN` up to `PEER_BACKOFF_MAX`. A message from the peer resets it.
pub const PEER_BACKOFF_MIN: Mono = SEC;
pub const PEER_BACKOFF_MAX: Mono = 30 * SEC;

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct PeerLink {
    /// Losses since the peer was last heard.
    faults: u32,
    /// Session lost and not back yet: queries to the peer are held.
    lost: bool,
    /// Redrive pending at `retry_at`.
    due: bool,
    retry_at: Mono,
    /// The peer's incarnation (`up_from`) the entry is about.
    up_from: u32,
    /// The batch being finished is a redrive: its queries pass the hold.
    probe: bool,
}

fn backoff(faults: u32) -> Mono {
    match faults {
        0 | 1 => 0,
        n => (PEER_BACKOFF_MIN << (n - 2).min(16)).min(PEER_BACKOFF_MAX),
    }
}

impl PgSet {
    /// The cluster session to `osd` faulted, was reset or closed: peering messages to it may be lost.
    pub fn peer_fault(&mut self, osd: i32, now: Mono, store: &impl PgStoreOps) -> Vec<Action> {
        match self.peer_incarnation(osd) {
            Some(up_from) => {
                let e = self.peer_links.entry(osd).or_default();
                if e.up_from != up_from {
                    *e = PeerLink {
                        up_from,
                        ..Default::default()
                    };
                }
                if !e.lost {
                    e.lost = true;
                    e.due = true;
                    e.faults = e.faults.saturating_add(1);
                    e.retry_at = now + backoff(e.faults);
                    self.peer_stats.faults += 1;
                }
                self.peer_due(now, store);
            }
            None => {
                self.peer_links.remove(&osd);
            }
        }
        self.finish_at(now, store)
    }

    /// A cluster session to `osd` reached READY: held queries flow again. After a single loss the redrive goes out at
    /// once; a peer that keeps failing stays on its back-off.
    pub fn peer_connected(&mut self, osd: i32, now: Mono, store: &impl PgStoreOps) -> Vec<Action> {
        if let Some(e) = self.peer_links.get_mut(&osd) {
            e.lost = false;
            if e.due && e.faults <= 1 {
                e.retry_at = e.retry_at.min(now);
            }
        }
        self.peer_due(now, store);
        self.finish_at(now, store)
    }

    /// A message from `from` arrived: its session works, the back-off restarts.
    pub(super) fn peer_heard(&mut self, from: i32) {
        if let Some(e) = self.peer_links.get_mut(&from) {
            e.faults = 0;
            e.lost = false;
            if e.due {
                e.retry_at = 0;
            } else {
                self.peer_links.remove(&from);
            }
        }
    }

    /// Redrive every peer whose back-off ran out (called from `tick` and the link entry points).
    pub(super) fn peer_due(&mut self, now: Mono, store: &impl PgStoreOps) {
        if self.peer_links.is_empty() {
            return;
        }
        let due: Vec<i32> = self
            .peer_links
            .iter()
            .filter(|(_, e)| e.due && e.retry_at <= now)
            .map(|(o, _)| *o)
            .collect();
        for osd in due {
            let same = self.peer_incarnation(osd);
            let Some(e) = self
                .peer_links
                .get_mut(&osd)
                .filter(|e| Some(e.up_from) == same)
            else {
                // down or restarted: peering restarts with the map, nothing to redrive
                self.peer_links.remove(&osd);
                continue;
            };
            e.probe = true;
            if e.lost {
                // not back yet: probe again later, slower
                e.faults = e.faults.saturating_add(1);
                e.retry_at = now + backoff(e.faults).max(PEER_BACKOFF_MIN);
            } else {
                e.due = false;
            }
            self.peer_stats.redrives += 1;
            let keys: Vec<SpgT> = self.pgs.keys().copied().collect();
            for k in keys {
                let nv = &self.flashstore;
                let n = self
                    .pgs
                    .get_mut(&k)
                    .map_or(0, |pg| pg.redrive_peering(osd, &|o| nv.contains(&o)));
                if n > 0 {
                    self.peer_stats.redriven_msgs += n as u64;
                    self.collect(k, now, store);
                }
            }
        }
    }

    pub(super) fn peer_deadline(&self) -> Option<Mono> {
        self.peer_links
            .values()
            .filter(|e| e.due)
            .map(|e| e.retry_at.max(1))
            .min()
    }

    /// `finish`: a query to a peer whose session is not back is held (the redrive sends it).
    pub(super) fn peer_holds(&self, s: &Send) -> bool {
        matches!(&s.body, Body::Peering(PeeringMsg::MOSDPGQuery2(_)))
            && self
                .peer_links
                .get(&s.to)
                .is_some_and(|e| e.lost && !e.probe)
    }

    pub(super) fn peer_probe_done(&mut self) {
        for e in self.peer_links.values_mut() {
            e.probe = false;
        }
    }

    fn peer_incarnation(&self, osd: i32) -> Option<u32> {
        let cur = self.cur.as_ref()?;
        cur.is_up(osd).then(|| cur.up_from(osd))
    }
}

/// Counters of the peer session tracking (adr 0071).
#[derive(Debug, Clone, Copy, Default)]
pub struct PeerStats {
    /// Session losses counted (repeats while a peer is still lost are not).
    pub faults: u64,
    /// Redrive rounds (one per peer and back-off expiry).
    pub redrives: u64,
    /// Messages those rounds sent again.
    pub redriven_msgs: u64,
    /// Queries held for a peer whose session is not back.
    pub held_queries: u64,
}
