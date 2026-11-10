// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Peer OSD connections that land on a core other than the one owning the peer's sessions (open question 15).
//!
//! Sessions of OSD `n` live on core `n % net` (`CoreSpec::peer_core`; our own dials go there too). A connection the NIC
//! (RSS) or the kernel delivers elsewhere stops in msgr2 right before CLIENT_IDENT / SESSION_RECONNECT
//! (`msgr2::Event::Handoff`), because answering there would ask a session table that does not hold the peer's session:
//! a reconnect gets `SESSION_RESET(full)` and classic drops its whole out queue (unsent pg_query2 included).
//!
//! The *socket* stays with the landing core (a TCP flow cannot move between userspace stacks); the handshake state moves
//! to the owner ([`msgr2::Handoff`]), which resumes the connection in its own table. From then on the landing core is a
//! byte relay: socket input travels as [`XMsg::PipeIn`], the owner's output as [`XMsg::PipeOut`], closes in both
//! directions. All of it lives in this layer, so every transport driver (kernel TCP, sim) works unchanged: the
//! landing core's link id keeps being the driver's connection id, it just has no msgr2 behind it.
use crate::auth::PeerAuth;
use crate::backend::Backend;
use crate::osd::{IoCmd, Link, MsgrId, Osd, Purpose};
use crate::xcore::XMsg;
use bytes::Bytes;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::rc::Rc;

/// Sweeps a closing pipe survives while the driver has not collected its last output.
const CLOSING_SWEEPS: u8 = 64;

/// Landing core: relay for the socket of connection `zid`.
#[derive(Debug)]
pub(crate) struct PipeZ {
    pub input: ingress::IngressCredits,
    pub pending_rx: Option<Bytes>,
    pub socket_closed: bool,
    pub ready: msgr2::OutputNotify,
    /// Owning core.
    pub core: usize,
    /// Output of the owner not yet taken by the driver.
    pub out: VecDeque<Bytes>,
    /// The owner closed: close the socket once `out` is written.
    pub closing: Option<u8>,
}

/// Owning core: where the socket of one resumed connection is.
#[derive(Debug)]
pub(crate) struct PipeH {
    pub rx_resume: msgr2::EventNotify,
    pub input: VecDeque<(Bytes, ingress::InputGuard)>,
    pub closed: bool,
    /// Landing core.
    pub core: usize,
    /// Its connection id for the socket.
    pub zid: u64,
}

/// Pipe tables of one core.
#[derive(Debug, Default)]
pub(crate) struct Pipes {
    pub rx_resume: msgr2::EventQueue,
    pub ready: msgr2::OutputQueue,
    /// Landing side, by the driver's connection id.
    pub z: crate::osd::FastMap<u64, PipeZ>,
    /// Owning side, by the resumed link id.
    pub h: crate::osd::FastMap<u64, PipeH>,
    /// Owning side: landing connection id -> resumed link id.
    pub h_by_z: crate::osd::FastMap<u64, u64>,
    pub rx_pending: VecDeque<u64>,
    /// Connections handed over (diagnostics).
    pub handed_off: u64,
}

impl<B: Backend> Osd<B> {
    /// Landing core: the connection `id` of a peer OSD belongs to core `owner`.
    pub(crate) fn handoff_link(&mut self, id: u64, owner: usize) {
        let Some(l) = self.links.remove(&id) else {
            return;
        };
        self.link_left(&l);
        self.conn_timers.get_mut().unregister(id);
        self.forget_input(id);
        let sock = l.sock;
        let auth = l.auth.borrow().clone();
        let Some(h) = l.conn.into_handoff() else {
            self.log(format!("link {id}: handoff in a wrong state"));
            self.io.push_back(IoCmd::Close { conn: id });
            return;
        };
        self.pipes.handed_off += 1;
        self.pipes
            .rx_pending
            .reserve(self.pipes.z.len() + 1 - self.pipes.rx_pending.len());
        self.log(format!(
            "link {id}: peer OSD belongs to core {owner}, handing the connection over"
        ));
        self.pipes.z.insert(
            id,
            PipeZ {
                input: ingress::IngressCredits::relay(),
                pending_rx: None,
                socket_closed: false,
                ready: self.output_ready.register(id),
                core: owner,
                out: VecDeque::new(),
                closing: None,
            },
        );
        let ingress = ingress::InputGuard(self.pipes.z[&id].input.reserve(0, 0));
        self.xsend(
            owner,
            XMsg::Handoff {
                ingress,
                zid: id,
                sock,
                h,
                auth,
            },
        );
    }

    /// Owning core: take over the connection `zid` of core `from`.
    pub(crate) fn on_handoff(
        &mut self,
        from: usize,
        zid: u64,
        sock: Option<SocketAddr>,
        h: msgr2::Handoff,
        auth: PeerAuth,
        ingress: ingress::InputGuard,
    ) {
        let hid = self.alloc_link_id();
        let ms = &self.msgr[MsgrId::Cluster as usize];
        let mut conn = msgr2::Connection::from_handoff_guarded(
            h,
            hid,
            ms.cfg.clone(),
            ms.table.clone(),
            self.now,
            ingress,
        );
        conn.set_output_queue(&self.pipes.ready, hid);
        conn.set_event_queue(&self.event_ready, hid);
        conn.set_timer_queue(&self.timer_ready, hid);
        self.conn_timers.get_mut().register(hid);
        self.reserve_input_links();
        let caps_peer = opexec::caps::Peer::from_addr(&conn.target());
        self.links.insert(
            hid,
            Link {
                pull: None,
                pending_input: None,
                held: Default::default(),
                conn,
                msgr: MsgrId::Cluster,
                purpose: Purpose::Accepted,
                auth: Rc::new(RefCell::new(auth)), // the cephx result stays with the link (tell caps, entity)
                peer: None,
                sock,
                caps: None,
                caps_peer,
                info: None,
                fwd: 0,
                pre: None,
                placement: Default::default(),
                // a handoff happens after AUTH_SIGNATURE: the link is authenticated (counted on its old core)
                preauth_charged: 0,
            },
        );
        self.pipes.h.insert(
            hid,
            PipeH {
                rx_resume: self.pipes.rx_resume.register(hid),
                core: from,
                zid,
                input: VecDeque::with_capacity(32),
                closed: false,
            },
        );
        self.pipes.h_by_z.insert(zid, hid);
    }

    /// Owning core: bytes the landing core read from the socket. True if the connection has events to pump.
    pub(crate) fn on_pipe_in(
        &mut self,
        zid: u64,
        data: Bytes,
        ingress: ingress::InputGuard,
    ) -> bool {
        if let Some(hid) = self.pipes.h_by_z.get(&zid).copied() {
            if !self.input_ready(hid) || self.pipes.h.get(&hid).is_some_and(|p| !p.input.is_empty())
            {
                let pipe = self.pipes.h.get_mut(&hid).unwrap();
                assert!(pipe.input.len() < 32, "relay input reservation exceeded");
                pipe.input.push_back((data, ingress));
                pipe.rx_resume.notify();
                return false;
            }
            let Some(l) = self.links.get_mut(&hid) else {
                return false;
            };
            l.conn.on_bytes_guarded(&data, self.now, ingress);
            if l.pre_due() {
                self.pre_scan(hid);
            }
            return self.links.get(&hid).is_some_and(|l| l.conn.has_events());
        }
        false
    }

    /// Owning core: the landing core's socket closed.
    pub(crate) fn on_pipe_closed(&mut self, zid: u64) {
        if let Some(&hid) = self.pipes.h_by_z.get(&zid)
            && (self.pipes.h.get(&hid).is_some_and(|p| !p.input.is_empty())
                || self
                    .links
                    .get(&hid)
                    .is_some_and(|l| l.pending_input.is_some() || l.conn.has_events()))
        {
            let pipe = self.pipes.h.get_mut(&hid).unwrap();
            pipe.closed = true;
            pipe.rx_resume.notify();
            return;
        }
        if let Some(hid) = self.pipes.h_by_z.remove(&zid) {
            self.pipes.h.remove(&hid);
            if let Some(l) = self.links.get_mut(&hid) {
                l.conn.on_closed(self.now);
            }
        }
    }

    /// Landing core: the owner produced output for the socket of `zid`.
    pub(crate) fn on_pipe_out(&mut self, zid: u64, runs: Vec<Bytes>) {
        if let Some(p) = self.pipes.z.get_mut(&zid) {
            p.out.extend(runs);
            p.ready.notify();
        }
    }

    /// Landing core: the owner closed its end; the socket follows after the last output.
    pub(crate) fn on_pipe_close(&mut self, zid: u64) {
        if let Some(p) = self.pipes.z.get_mut(&zid) {
            p.closing = Some(0);
            self.io.push_back(IoCmd::Close { conn: zid });
        }
    }

    /// Landing core: socket input of a relayed connection.
    #[inline]
    pub(crate) fn pipe_rx(&mut self, conn: u64, data: &[u8]) -> bool {
        if !self.pipes.z.contains_key(&conn) {
            return false;
        }
        self.pipe_rx_owned(conn, Bytes::copy_from_slice(data))
    }

    /// [`Self::pipe_rx`] with an owned buffer (a whole receive batch: one fragment, one relay credit).
    pub(crate) fn pipe_rx_owned(&mut self, conn: u64, data: Bytes) -> bool {
        let Some(p) = self.pipes.z.get_mut(&conn) else {
            return false;
        };
        let core = p.core;
        // The owner may charge a completed frame between the receive readiness check and this reservation.
        // Keep one already-received fragment locally on that race, then pause its socket; never discard the bytes.
        let Some(lease) = p.input.reserve(0, data.len()) else {
            assert!(
                p.pending_rx.is_none(),
                "transport delivered paused relay input"
            );
            p.pending_rx = Some(data);
            self.pipes.rx_pending.push_back(conn);
            // not parked: the idle re-check must not sleep before resume_pipe_sources retried (and parked) it
            if let Some(w) = &self.cl.waker {
                w.disarm();
            }
            return true;
        };
        self.xsend(
            core,
            XMsg::PipeIn {
                zid: conn,
                data,
                ingress: ingress::InputGuard(Some(lease)),
            },
        );
        true
    }

    pub(crate) fn resume_pipe_sources(&mut self) -> bool {
        let mut work = false;
        for _ in 0..self.pipes.rx_pending.len() {
            let conn = self.pipes.rx_pending.pop_front().unwrap();
            let Some(pipe) = self.pipes.z.get_mut(&conn) else {
                continue;
            };
            let Some(data) = pipe.pending_rx.as_ref() else {
                continue;
            };
            let Some(lease) = pipe.input.reserve(0, data.len()) else {
                if let Some(w) = &self.cl.waker {
                    pipe.input.ready_or_park(0, data.len(), w);
                }
                self.pipes.rx_pending.push_back(conn);
                continue;
            };
            let core = pipe.core;
            let closed = pipe.socket_closed;
            let data = pipe.pending_rx.take().unwrap();
            self.xsend(
                core,
                XMsg::PipeIn {
                    zid: conn,
                    data,
                    ingress: ingress::InputGuard(Some(lease)),
                },
            );
            if closed {
                self.pipes.z.remove(&conn);
                self.xsend(core, XMsg::PipeClosed { zid: conn });
            }
            work = true;
        }
        work
    }

    /// Resume bounded raw relay queues after a decoded-event budget yield, even
    /// when no typed pending head exists. Registration preallocates notifications.
    pub(crate) fn resume_event_pipes(&mut self) -> bool {
        // Preserve the pump's yield, including a count/time yield that happened
        // to consume the last decoded event. Do not reset it on another raw chunk.
        if self.event_pump_pending {
            return false;
        }
        let Some(first) = self.pipes.rx_resume.pop() else {
            return false;
        };
        let started = std::time::Instant::now();
        let mut work = false;
        for visit in 0..32 {
            if visit != 0 && started.elapsed() >= std::time::Duration::from_micros(100) {
                break;
            }
            let hid = if visit == 0 {
                first
            } else {
                let Some(hid) = self.pipes.rx_resume.pop() else {
                    break;
                };
                hid
            };
            if !self.input_ready(hid) {
                // Typed admission resumes through resume_inputs. A decoded queue
                // resumes through the independent event pump; retain its token.
                if self
                    .links
                    .get(&hid)
                    .is_some_and(|l| l.pending_input.is_none() && l.conn.has_events())
                    && let Some(pipe) = self.pipes.h.get(&hid)
                {
                    pipe.rx_resume.notify();
                }
                continue;
            }
            if self
                .pipes
                .h
                .get(&hid)
                .is_some_and(|p| !p.input.is_empty() || p.closed)
            {
                self.resume_pipe_input(hid);
                work = true;
                if self.event_pump_pending {
                    break;
                }
            }
        }
        work
    }

    pub(crate) fn resume_pipe_input(&mut self, hid: u64) {
        // Drain partial frames too: they need no actor continuation to make another fragment ready.
        // The relay reservation bounds this queue to 32 fragments, so one drain has a fixed limit.
        for _ in 0..32 {
            if !self.input_ready(hid) {
                break;
            }
            let Some(pipe) = self.pipes.h.get_mut(&hid) else {
                return;
            };
            let Some((data, ingress)) = pipe.input.pop_front() else {
                break;
            };
            let Some(link) = self.links.get_mut(&hid) else {
                return;
            };
            link.conn.on_bytes_guarded(&data, self.now, ingress);
            if link.pre_due() {
                self.pre_scan(hid);
            }
            if self.links.get(&hid).is_some_and(|l| l.conn.has_events()) {
                self.pump();
                if self.event_pump_pending {
                    break;
                }
            }
        }
        if let Some(pipe) = self.pipes.h.get(&hid)
            && pipe.closed
            && pipe.input.is_empty()
            && self.input_ready(hid)
        {
            let zid = pipe.zid;
            self.on_pipe_closed(zid);
        }
        if let Some(pipe) = self.pipes.h.get(&hid)
            && (!pipe.input.is_empty() || pipe.closed)
        {
            pipe.rx_resume.notify();
        }
        // Closing a drained relay queues its final connection event too.
        self.event_pump_pending |= self
            .links
            .get(&hid)
            .is_some_and(|l| l.conn.has_events() && l.pending_input.is_none());
    }

    /// Landing core: the socket of a relayed connection closed.
    pub(crate) fn pipe_socket_closed(&mut self, conn: u64) -> bool {
        if let Some(pipe) = self.pipes.z.get_mut(&conn)
            && pipe.pending_rx.is_some()
        {
            pipe.socket_closed = true;
            return true;
        }
        let Some(p) = self.pipes.z.remove(&conn) else {
            return false;
        };
        self.xsend(p.core, XMsg::PipeClosed { zid: conn });
        true
    }

    /// Landing core: output waiting for the socket of `conn`.
    pub(crate) fn pipe_tx(&mut self, conn: u64) -> Option<Vec<Bytes>> {
        let p = self.pipes.z.get_mut(&conn)?;
        Some(p.out.drain(..).collect())
    }

    /// Landing core: forget closing relays that drained (the driver collects before it closes).
    pub(crate) fn pipe_sweep(&mut self) {
        self.pipes.z.retain(|_, p| match &mut p.closing {
            Some(n) => {
                *n = n.saturating_add(1);
                !(p.out.is_empty() || *n > CLOSING_SWEEPS)
            }
            None => true,
        });
    }

    /// Owning core: move the output of resumed connections to their sockets (called before the driver collects
    /// cross-core messages).
    pub(crate) fn flush_pipes(&mut self) {
        if self.pipes.h.is_empty() {
            return;
        }
        while let Some(hid) = self.pipes.ready.pop() {
            if let Some(p) = self.pipes.h.get(&hid)
                && let Some(l) = self.links.get_mut(&hid)
            {
                let (core, zid) = (p.core, p.zid);
                let runs = l.conn.poll_output_chunks();
                if !runs.is_empty() {
                    self.xsend(core, XMsg::PipeOut { zid, runs });
                }
            }
        }
    }

    /// Owning core: the driver command to close link `hid` becomes a close of the landing core's socket.
    pub(crate) fn pipe_close_cmd(&mut self, hid: u64) -> bool {
        let Some(p) = self.pipes.h.remove(&hid) else {
            return false;
        };
        self.pipes.h_by_z.remove(&p.zid);
        self.xsend(p.core, XMsg::PipeClose { zid: p.zid });
        true
    }

    /// Time-independent summary for tests / diagnostics.
    #[cfg(test)]
    pub(crate) fn pipe_counts(&self) -> (usize, usize) {
        (self.pipes.z.len(), self.pipes.h.len())
    }
}
