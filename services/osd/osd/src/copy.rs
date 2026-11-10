// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Source reads of copy-from (spec copy.md 5): the destination PG's engine emits `Out::CopyRead`; this routes it to
//! the primary PG of the source (this core, another core, or another OSD) and brings the answer back.
//!
//! A read in flight is a [`Pend`] on the core of the destination PG (`origin`). Same-OSD sources: its engine request
//! carries a pseudo connection id ([`COPY_BIT`] | origin core << 40 | id), never a link: the source engine's replies /
//! backoffs / drops for it are caught in `pg_send_outs` / `pg_run`, never encoded. Other-OSD sources: the read goes as
//! an MOSDOp over a client link (public messenger, entity `osd.N`, like classic's objecter) owned by the core
//! `peer_core(osd)`; wire tid = origin core << 40 | id. Anything that is not a clean answer (source PG not primary
//! there any more, backoff, dropped as stale, link lost, primary moved) is re-sent after a short pause with the
//! then-current map; the destination engine's own timeout bounds all of it.

use crate::backend::Backend;
use crate::osd::{MON_BASE, MsgrId, Osd, Purpose};
use crate::xcore::XMsg;
use denc::types::{EntityAddrVec, EntityName, SpgT};
use opexec::ClientReq;
use opwire::{ClientMsg, MOSDBackoff, MOSDOp, MOSDOpReply, errno};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

/// Marks a pseudo connection id (link ids are `core << 48 | counter`, the mon's carry [`MON_BASE`]).
pub(crate) const COPY_BIT: u64 = 1 << 61;
const ORIGIN_SHIFT: u32 = 40;
const ID_MASK: u64 = (1 << ORIGIN_SHIFT) - 1;
/// Pause before a source read is sent again.
const RETRY_AFTER: Duration = Duration::from_millis(100);
/// A read older than this is forgotten (the destination engine timed its copy out long before).
const PEND_MAX_AGE: Duration = Duration::from_secs(150);
/// A client link without reads for this long is closed.
const LINK_IDLE: Duration = Duration::from_secs(60);

#[inline]
pub(crate) fn is_copy_conn(conn: u64) -> bool {
    conn & COPY_BIT != 0 && conn & MON_BASE == 0
}

#[inline]
fn origin_of(x: u64) -> usize {
    ((x >> ORIGIN_SHIFT) & 0xff) as usize
}

/// One source read in flight (on the core of the destination PG).
pub(crate) struct Pend {
    /// Destination PG whose engine asked, and its step id.
    origin: SpgT,
    step: u64,
    /// The read, kept for re-sending.
    op: MOSDOp,
    born: Duration,
    /// Re-send at this time (None = sent, waiting for the answer).
    due: Option<Duration>,
    tries: u32,
    /// OSD the read went to last (-1 = none yet).
    target: i32,
}

/// Client link to another OSD (on the core that owns links to it).
struct CLink {
    link: u64,
    addrs: EntityAddrVec,
    ready: bool,
    /// Reads not answered yet by wire tid; `sent` = already on the link.
    out: BTreeMap<u64, MOSDOp>,
    sent: BTreeSet<u64>,
    /// Backoffs the peer holds on this session: `(pg, backoff id)`. Reads of a blocked PG stay here unsent (the peer
    /// drops ops inside a backoff) until its UNBLOCK.
    blocked: Vec<(SpgT, u64)>,
    used: Duration,
}

#[derive(Default)]
pub(crate) struct Routes {
    next: u64,
    pend: BTreeMap<u64, Pend>,
    links: BTreeMap<i32, CLink>,
}

impl Routes {
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.pend.is_empty()
    }
    /// Client links whose session the test harness has not marked up yet: `(osd, link)`.
    #[cfg(test)]
    pub(crate) fn unready(&self) -> Vec<(i32, u64)> {
        self.links
            .iter()
            .filter(|(_, l)| !l.ready)
            .map(|(o, l)| (*o, l.link))
            .collect()
    }
    /// `(link, reads held, reads on the wire, backoffs)` of the client link to `osd`.
    #[cfg(test)]
    pub(crate) fn link_state(&self, osd: i32) -> Option<(u64, usize, usize, usize)> {
        self.links
            .get(&osd)
            .map(|l| (l.link, l.out.len(), l.sent.len(), l.blocked.len()))
    }
    pub(crate) fn next_due(&self) -> Option<Duration> {
        self.pend.values().filter_map(|p| p.due).min()
    }
}

impl<B: Backend> Osd<B> {
    /// The engine of `origin` wants `op` (a read MOSDOp for PG `op.pgid`) answered: route it.
    pub(crate) fn copy_start(&mut self, origin: SpgT, step: u64, op: MOSDOp) {
        self.pg.cp.next += 1;
        let id = self.pg.cp.next & ID_MASK;
        self.pg.cp.pend.insert(
            id,
            Pend {
                origin,
                step,
                op,
                born: self.now,
                due: None,
                tries: 0,
                target: -1,
            },
        );
        self.copy_send(id);
    }

    fn wire_tid(&self, id: u64) -> u64 {
        ((self.cl.spec.id as u64) << ORIGIN_SHIFT) | id
    }

    /// (Re)send pending read `id` to the primary of its source PG.
    fn copy_send(&mut self, id: u64) {
        let Some(map) = self.map.clone() else {
            return self.copy_later(id);
        };
        let tid = self.wire_tid(id);
        if let Some(p) = self.pg.cp.pend.get(&id) {
            self.copy_cancel_target(id, p.target);
        }
        let Some(p) = self.pg.cp.pend.get_mut(&id) else {
            return;
        };
        p.due = None;
        p.op.osdmap_epoch = map.epoch;
        let (src, op) = (p.op.pgid, p.op.clone());
        let primary = crate::pgs::cur_mapping(&self.pg.set, &map, src.pgid).acting_primary;
        p.target = primary;
        if primary < 0 {
            return self.copy_later(id);
        }
        if primary != self.id.whoami {
            let lc = self.cl.spec.peer_core(primary);
            if lc == self.cl.spec.id {
                self.copy_out(primary, tid, op);
            } else {
                self.xsend(
                    lc,
                    XMsg::CopyOut {
                        osd: primary,
                        tid,
                        op: Box::new(op),
                    },
                );
            }
            return;
        }
        let conn = COPY_BIT | tid;
        if self.pg.set.core_of(src.pgid) == self.cl.spec.id && !self.mig_busy(src.pgid) {
            self.copy_exec(conn, op);
        } else {
            self.pg_item(
                None,
                XMsg::CopyRead {
                    conn,
                    op: Box::new(op),
                },
            );
        }
    }

    /// A source read outlived `PEND_MAX_AGE` and is forgotten (its destination engine times the copy out itself).
    fn copy_pend_timeout(&mut self, origin: SpgT, tries: u32) {
        self.logl(
            0,
            format!(
                "WARNING TIMEOUT copy source read exceeded {:.3}s (pg {}.{}, {tries} tries, forgotten)",
                PEND_MAX_AGE.as_secs_f64(),
                origin.pgid.pool,
                origin.pgid.seed
            ),
        );
    }

    /// Send again after a pause (bounded by the age limit).
    fn copy_later(&mut self, id: u64) {
        let now = self.now;
        let Some(p) = self.pg.cp.pend.get_mut(&id) else {
            return;
        };
        p.tries += 1;
        if now.saturating_sub(p.born) > PEND_MAX_AGE {
            let (spg, tries, target) = (p.origin, p.tries, p.target);
            self.pg.cp.pend.remove(&id);
            self.copy_cancel_target(id, target);
            self.copy_pend_timeout(spg, tries);
            return;
        }
        p.due = Some(now + RETRY_AFTER * p.tries.min(20));
    }

    /// PG core of the source: run the read on its engine; whatever cannot run here goes back as EAGAIN (re-sent).
    pub(crate) fn copy_exec(&mut self, conn: u64, op: MOSDOp) {
        let spg = op.pgid;
        let ready = !self.pg.dead
            && self
                .pg
                .set
                .pg(spg)
                .is_some_and(|p| p.is_primary() && p.refusal().is_none());
        if !ready {
            return self.copy_answer(conn & !COPY_BIT, Err(errno::EAGAIN));
        }
        let req = ClientReq {
            placement_read: None,
            conn,
            tid: conn & ID_MASK,
            caps: None,
            op: Box::new(op),
            who: EntityName::osd(i64::from(self.id.whoami)),
            addr: Default::default(),
            peer_addr: Default::default(),
            features: denc::features::ALL,
        };
        self.pg_run(spg, move |e, env| e.on_op(env, req));
        self.pg_post();
    }

    /// Answer for read `tid` (a pseudo connection id or a wire tid; origin core in the bits above the id) from the
    /// executing core (this one or another).
    pub(crate) fn copy_answer(&mut self, tid: u64, r: Result<MOSDOpReply, i32>) {
        let (origin, id) = (origin_of(tid), tid & ID_MASK);
        if origin == self.cl.spec.id {
            return self.copy_back(id, r);
        }
        self.xsend(
            origin,
            XMsg::CopyReply {
                id,
                r: r.map(Box::new),
            },
        );
    }

    /// Origin core: the executing engine / remote OSD answered (or could not run the read).
    pub(crate) fn copy_back(&mut self, id: u64, r: Result<MOSDOpReply, i32>) {
        match r {
            // not runnable there right now: ask again with the current map
            Err(e) if e == errno::EAGAIN => self.copy_later(id),
            r => self.copy_finish(id, r),
        }
    }

    /// Hand the final answer to the destination engine.
    fn copy_finish(&mut self, id: u64, r: Result<MOSDOpReply, i32>) {
        let Some(p) = self.pg.cp.pend.remove(&id) else {
            return;
        };
        let (spg, step) = (p.origin, p.step);
        self.pg_run(spg, move |e, env| e.on_copy_reply(env, step, r));
        self.pg_post();
    }

    /// Timer: re-send reads that are due, forget ancient ones, close idle client links.
    pub(crate) fn copy_tick(&mut self) {
        let now = self.now;
        let expired: Vec<u64> = self
            .pg
            .cp
            .pend
            .iter()
            .filter(|(_, p)| now.saturating_sub(p.born) > PEND_MAX_AGE)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            if let Some(p) = self.pg.cp.pend.remove(&id) {
                self.copy_cancel_target(id, p.target);
                self.copy_pend_timeout(p.origin, p.tries);
            }
        }
        let due: Vec<u64> = self
            .pg
            .cp
            .pend
            .iter()
            .filter(|(_, p)| p.due.is_some_and(|d| d <= now))
            .map(|(id, _)| *id)
            .collect();
        for id in due {
            self.copy_send(id);
        }
        let idle: Vec<i32> = self
            .pg
            .cp
            .links
            .iter()
            .filter(|(_, l)| now.saturating_sub(l.used) > LINK_IDLE)
            .map(|(o, _)| *o)
            .collect();
        for o in idle {
            // also a link whose reads were re-routed elsewhere (primary moved) or that waits for an UNBLOCK for long:
            // what is still on it is asked for again (stale origins ignore the answer)
            if let Some(l) = self.pg.cp.links.remove(&o) {
                self.close_link(l.link);
                self.copy_fail_all(l.out.keys().copied().collect());
            }
        }
    }

    /// New map: reads whose source primary moved are sent to the new one (the old one drops them silently).
    pub(crate) fn copy_after_map(&mut self) {
        let Some(map) = self.map.clone() else { return };
        let moved: Vec<u64> = self
            .pg
            .cp
            .pend
            .iter()
            .filter(|(_, p)| {
                p.due.is_none()
                    && p.target >= 0
                    && map.pg_to_up_acting(p.op.pgid.pgid).acting_primary != p.target
            })
            .map(|(id, _)| *id)
            .collect();
        for id in moved {
            self.copy_send(id);
        }
    }

    // ---------------------------------------------------------------------------- client links to other OSDs

    /// Retire the link owner's retained request when its origin expires or changes targets. Cancellation uses the
    /// same cross-core FIFO as CopyOut, so it cannot overtake an earlier send or remove a later resend.
    fn copy_cancel_target(&mut self, id: u64, target: i32) {
        if target < 0 || target == self.id.whoami {
            return;
        }
        let tid = self.wire_tid(id);
        let core = self.cl.spec.peer_core(target);
        if core == self.cl.spec.id {
            self.copy_cancel_out(target, tid);
        } else {
            self.xsend(core, XMsg::CopyCancel { osd: target, tid });
        }
    }

    pub(crate) fn copy_cancel_out(&mut self, osd: i32, tid: u64) {
        if let Some(l) = self.pg.cp.links.get_mut(&osd) {
            l.out.remove(&tid);
            l.sent.remove(&tid);
        }
    }

    /// Link core: put read `tid` on the client link to OSD `osd` (dialed on demand).
    pub(crate) fn copy_out(&mut self, osd: i32, tid: u64, op: MOSDOp) {
        let Some(map) = self.map.clone() else {
            return self.copy_answer(tid, Err(errno::EAGAIN));
        };
        let addrs = map
            .client_addrs
            .get(osd as usize)
            .cloned()
            .unwrap_or_default();
        if !map.is_up(osd) || addrs.v2().is_none() {
            return self.copy_answer(tid, Err(errno::EAGAIN));
        }
        // the OSD restarted (new address): the old link is for a dead incarnation
        if self.pg.cp.links.get(&osd).is_some_and(|l| l.addrs != addrs)
            && let Some(l) = self.pg.cp.links.remove(&osd)
        {
            self.close_link(l.link);
            self.copy_fail_all(l.out.keys().copied().collect());
        }
        if !self.pg.cp.links.contains_key(&osd) {
            let Some(link) = self.dial(MsgrId::Public, Purpose::Copy(osd), EntityName::OSD, &addrs)
            else {
                return self.copy_answer(tid, Err(errno::EAGAIN));
            };
            self.pg.cp.links.insert(
                osd,
                CLink {
                    link,
                    addrs,
                    ready: false,
                    out: BTreeMap::new(),
                    sent: BTreeSet::new(),
                    blocked: Vec::new(),
                    used: self.now,
                },
            );
        }
        if let Some(l) = self.pg.cp.links.get_mut(&osd) {
            l.out.insert(tid, op);
            l.sent.remove(&tid);
            l.used = self.now;
        }
        self.copy_flush(osd);
    }

    /// Put every read of the link to `osd` that is not on the wire yet on the wire (once the session is up).
    fn copy_flush(&mut self, osd: i32) {
        let Some(l) = self.pg.cp.links.get(&osd) else {
            return;
        };
        if !l.ready {
            return;
        }
        let link = l.link;
        let feats = self
            .links
            .get(&link)
            .and_then(|x| x.peer.as_ref())
            .map_or(denc::features::ALL, |p| p.features);
        let todo: Vec<(u64, MOSDOp)> = l
            .out
            .iter()
            .filter(|(t, o)| !l.sent.contains(*t) && !l.blocked.iter().any(|(pg, _)| *pg == o.pgid))
            .map(|(t, o)| (*t, o.clone()))
            .collect();
        for (tid, op) in todo {
            match ClientMsg::Op(op).encode(feats) {
                Ok((ty, v, c, segs)) => {
                    self.send_raw(link, tid, 0, (ty, v, c), segs);
                    if let Some(l) = self.pg.cp.links.get_mut(&osd) {
                        l.sent.insert(tid);
                    }
                }
                Err(e) => {
                    self.log(format!("copy: encode source read: {e}"));
                    if let Some(l) = self.pg.cp.links.get_mut(&osd) {
                        l.out.remove(&tid);
                    }
                    self.copy_answer(tid, Err(errno::EIO));
                }
            }
        }
    }

    pub(crate) fn copy_link_ready(&mut self, osd: i32, id: u64) {
        if let Some(l) = self.pg.cp.links.get_mut(&osd)
            && l.link == id
        {
            l.ready = true;
            self.copy_flush(osd);
        }
    }

    /// The link closed: whatever was on it is asked for again (new link, current map).
    pub(crate) fn copy_link_gone(&mut self, osd: i32, id: u64) {
        if self.pg.cp.links.get(&osd).is_some_and(|l| l.link == id)
            && let Some(l) = self.pg.cp.links.remove(&osd)
        {
            self.copy_fail_all(l.out.keys().copied().collect());
        }
    }

    fn copy_fail_all(&mut self, tids: Vec<u64>) {
        for t in tids {
            self.copy_answer(t, Err(errno::EAGAIN));
        }
    }

    /// A message on the client link to `osd`: an answer, or a backoff.
    pub(crate) fn copy_link_message(
        &mut self,
        id: u64,
        osd: i32,
        tid: u64,
        ty: u16,
        version: u16,
        segs: &messages::Segments,
    ) {
        match opwire::decode_client(ty, version, segs) {
            Ok(ClientMsg::OpReply(r)) => {
                let known = self.pg.cp.links.get_mut(&osd).is_some_and(|l| {
                    l.sent.remove(&tid);
                    l.used = self.now;
                    l.out.remove(&tid).is_some()
                });
                if known {
                    self.copy_answer(tid, Ok(r));
                }
            }
            Ok(ClientMsg::Backoff(b)) if b.op == opwire::consts::backoff::BLOCK => {
                // the PG cannot serve right now: acknowledge and hold its reads until the UNBLOCK (the peer drops
                // every op of this session inside the backoff, a re-send would be lost; classic objecter semantics)
                let ack = MOSDBackoff {
                    op: opwire::consts::backoff::ACK_BLOCK,
                    ..b.clone()
                };
                let feats = self
                    .links
                    .get(&id)
                    .and_then(|x| x.peer.as_ref())
                    .map_or(denc::features::ALL, |p| p.features);
                if let Ok((ty, v, c, segs)) = ClientMsg::Backoff(ack).encode(feats) {
                    self.send_raw(id, 0, 0, (ty, v, c), segs);
                }
                if let Some(l) = self.pg.cp.links.get_mut(&osd)
                    && l.link == id
                {
                    l.used = self.now;
                    if !l.blocked.contains(&(b.pgid, b.id)) {
                        l.blocked.push((b.pgid, b.id));
                    }
                    // what is on the wire for that PG was dropped over there: send it again after the UNBLOCK
                    let held: Vec<u64> = l
                        .out
                        .iter()
                        .filter(|(_, o)| o.pgid == b.pgid)
                        .map(|(t, _)| *t)
                        .collect();
                    for t in held {
                        l.sent.remove(&t);
                    }
                }
            }
            Ok(ClientMsg::Backoff(b)) if b.op == opwire::consts::backoff::UNBLOCK => {
                if let Some(l) = self.pg.cp.links.get_mut(&osd)
                    && l.link == id
                {
                    l.used = self.now;
                    l.blocked.retain(|x| *x != (b.pgid, b.id));
                }
                self.copy_flush(osd);
            }
            Ok(_) => {}
            Err(e) => self.log(format!("copy link {id}: bad message type {ty}: {e}")),
        }
    }
}
