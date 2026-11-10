// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Receiver-side pre-write, OSD half (adr 0477 D2 steps 1-3, conf `flashstore_prewrite`).
//!
//! Connection core: a link whose decoder shares the data segment of the frame being received
//! (`msgr2::Connection::rx_early`) is checked once per frame for a candidate (a client write whose single data op is a
//! block-aligned WRITE / WRITEFULL; a repop from its payload grid). While the data arrives, every complete piece of
//! [`Pre::min`] bytes (the store's data run, `PgStoreOps::pre_piece`) of the candidate range goes as an immutable view to the PG core ([`XMsg::PrePiece`], same lane as the
//! op that follows), which writes it to free blocks of the PG's store shard (`PgStoreOps::pre_write`). Only the first
//! message of a frame wakes the PG core: the later ones wait for its next drain (the completion of the pieces it wrote,
//! other input, at the latest the op), so a frame costs the PG core one wake, not one per receive scan.
//!
//! Nothing else changes: the frame is delivered when it is complete and verified, the op runs as before, and its txn
//! takes the pre-written blocks only where a data run starts at a piece's first byte (the same memory). The PG core keeps
//! each piece's ticket with the segment's watch; a segment that is gone (bad crc, connection loss, op dropped or done)
//! returns its unclaimed pieces ([`Osd::pre_reap`]). The front is unverified while the data arrives: it only picks a
//! PG and a range, a wrong guess costs device bytes, never correctness — and no byte reaches the device unless the
//! session holds a write grant for that pool ([`pre_allowed`], adr 0477 am. 6).
use crate::backend::Backend;
use crate::osd::{MsgrId, Osd};
use crate::xcore::XMsg;
use bytes::Bytes;
use denc::types::{EntityName, SpgT};
use msgr2::{RxEarly, SegWatch};
use peering::PgStoreOps;

const BLK: usize = 4096;

/// Per-core state of the pre-write.
#[derive(Debug, Default)]
pub(crate) struct Pre {
    /// Piece size = the store's data run (`PgStoreOps::pre_piece`) when on, 0 = off; also the smallest candidate and
    /// the decoder setting of this core's links (`msgr2::Connection::set_prewrite`).
    pub min: usize,
    /// PG core: pieces written ahead, with the watch of their segment.
    live: Vec<(SegWatch, peering::store::PreTicket)>,
    /// PG core: (store `pre_closed`, `SegWatch::gone_epoch`) at the last reap: while both stand, no ticket changed.
    seen: (u64, u64),
    /// Connection core: pieces of one scan (with the wake flag of [`XMsg::PrePiece`]), handed out after the link borrow ends.
    out: Vec<(SpgT, SegWatch, Bytes, bool)>,
    pub stats: PreStats,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PreStats {
    /// Connection core: frames with a shared data segment / of them candidates / pieces sent.
    pub frames: u64,
    pub candidates: u64,
    pub pieces: u64,
    /// PG core: pieces the store wrote ahead / refused (pool type, store) / returned unclaimed by the reap.
    pub written: u64,
    pub refused: u64,
    pub reaped: u64,
    /// PG core: messages from a connection core, summed / longest ns from the cut to their handling here (a later piece
    /// waits for the PG core's next drain).
    pub msgs: u64,
    pub lag_ns: u64,
    pub lag_max_ns: u64,
}

/// Connection core: the frame of a link whose data segment is shared while it arrives.
#[derive(Debug)]
pub(crate) struct PreRx {
    watch: SegWatch,
    /// PG of the candidate (`None`: not a candidate, nothing is sent for this frame).
    spg: Option<SpgT>,
    /// Next piece start and end of the candidate range (buffer offsets).
    next: usize,
    end: usize,
    /// A repop whose range waits for its first write payload's length ([`PreRx::size`]).
    sized: bool,
    /// Pieces of this frame went out already (the next ones do not wake the PG core).
    sent: bool,
}

impl PreRx {
    fn start(e: &RxEarly<'_>, msgr: MsgrId, piece: usize, pool_ok: impl Fn(u64) -> bool) -> PreRx {
        let (spg, next, end, sized) = match candidate(e, msgr, piece) {
            Some((spg, at, len, sized)) if pool_ok(spg.pgid.pool) => {
                (Some(spg), e.pad + at, e.pad + at + len / BLK * BLK, sized)
            }
            _ => (None, 0, 0, true),
        };
        PreRx {
            watch: e.data.clone(),
            spg,
            next,
            end,
            sized,
            sent: false,
        }
    }

    /// A repop's range from the op shape, once the blob's head bytes arrived (`false`: not yet): the u32 length of the
    /// inline stream and the u32 length of its first item (`replwire::txn::PAYLOAD_AT`). A first write payload of at
    /// least one piece lies inside the stream and the segment, and the range ends at its last block; any other first
    /// item (an omap batch, attrs: its count, no payload) leaves no candidate, so a txn without a large first write
    /// costs no device bytes and no PG-core work. A wrong reading still only costs device bytes.
    fn size(&mut self, piece: usize) -> bool {
        let at = self.next;
        let Some(h) = self.watch.peek(at - 8, 8) else {
            return false;
        };
        let stream = u32::from_le_bytes([h[0], h[1], h[2], h[3]]) as usize;
        let len = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
        if len >= piece && len + 4 <= stream {
            // up to the payload's last block, at most the segment's last whole block (a run claims a piece's prefix)
            self.end = self.end.min(at + len.next_multiple_of(BLK));
        } else {
            self.spg = None;
        }
        self.sized = true;
        true
    }
}

/// The candidate range of a frame: (PG, start in the data segment, bytes, sized). A client write: its single data op is
/// a WRITE / WRITEFULL at a block-aligned object offset (the txn's first data run starts at the payload's first byte). A
/// repop: from the payload grid at [`replwire::txn::PAYLOAD_AT`] (placed by its `data_off`, adr 0061 am. 7), at most to the segment's last whole block, not yet sized:
/// [`PreRx::size`] cuts it to the first write payload or drops it once the blob's head arrived.
fn candidate(e: &RxEarly<'_>, msgr: MsgrId, piece: usize) -> Option<(SpgT, usize, usize, bool)> {
    let h = msgr2::MsgHeader2::from_bytes(e.header).ok()?;
    let (spg, at, len, sized) = match msgr {
        MsgrId::Public if h.msg_type == opwire::consts::ty::OSD_OP => {
            let p = opwire::MOSDOp::peek_write(h.version, e.front).ok()?;
            let w = p.write?;
            if !w.offset.is_multiple_of(BLK as u64) {
                return None;
            }
            (p.pgid, w.at, w.len, true)
        }
        MsgrId::Cluster
            if h.msg_type == <replwire::MOSDRepOp as messages::Message>::MSG_TYPE
                && e.head == replwire::txn::PAYLOAD_AT
                && e.len > e.head =>
        {
            let spg = replwire::MOSDRepOp::peek_pgid(h.version, e.front).ok()?;
            (spg, e.head, e.len - e.head, false)
        }
        _ => return None,
    };
    (len >= piece && at.checked_add(len)? <= e.len).then_some((spg, at, len, sized))
}

/// Writes of `pool` can claim a piece written ahead: a replicated pool of the map (an erasure primary encodes the whole
/// stripe, D2.6) whose writes the store keeps raw (`PgStoreOps::pre_pool`: not compressing).
pub(crate) fn pre_pool(map: Option<&osdmap::OsdMap>, store: &impl PgStoreOps, pool: u64) -> bool {
    map.and_then(|m| m.pool(pool as i64))
        .is_some_and(|p| !p.is_erasure())
        && store.pre_pool(pool)
}

/// May a frame of this link touch the device ahead: its pool can claim a piece AND the session may write there.
/// `peer_osd`: the link authenticated as an OSD peer on the cluster messenger (repop). No other session gets the
/// pre-write exemption, whatever it authenticated as and whatever caps it carries: a client on the public messenger
/// needs a write grant for the frame's pool (adr 0477 am. 6), and a non-OSD entity that authenticated on the cluster
/// listener (auth none, or any cephx caps) gets nothing at all. The front is unverified, so nothing reaches the device
/// for a session that may not write there.
pub(crate) fn pre_allowed(
    map: Option<&osdmap::OsdMap>,
    store: &impl PgStoreOps,
    caps: Option<&opexec::caps::Caps>,
    peer: opexec::caps::Peer,
    msgr: MsgrId,
    peer_osd: bool,
    pool: u64,
) -> bool {
    pre_pool(map, store, pool)
        && (peer_osd
            || (msgr == MsgrId::Public
                && caps.is_some_and(|c| {
                    let (name, apps) = crate::ops::pool_caps_info(map, pool as i64);
                    c.may_write_pool(name, apps, peer)
                })))
}

impl Pre {
    /// One scan of the frame in `slot` (a new frame replaces it): the complete pieces of its candidate range go to `out`.
    /// `pool_ok` ([`Osd::pre_pool`]) is asked once per frame: a frame of a pool whose writes cannot claim a piece is no
    /// candidate, so it costs no message and no PG-core wake.
    fn cut(
        &mut self,
        slot: &mut Option<PreRx>,
        e: &RxEarly<'_>,
        msgr: MsgrId,
        pool_ok: impl Fn(u64) -> bool,
    ) {
        // `flashstore_prewrite` went off while this frame's data segment is still shared (the decoder keeps the buffer kind
        // of a frame in flight): no piece exists to cut, and no arithmetic runs below a piece size.
        if self.min == 0 {
            *slot = None;
            return;
        }
        if !slot.as_ref().is_some_and(|p| p.watch.same(e.data)) {
            let p = PreRx::start(e, msgr, self.min, pool_ok);
            self.stats.frames += 1;
            self.stats.candidates += u64::from(p.spg.is_some() && p.sized);
            *slot = Some(p);
        }
        let p = slot.as_mut().expect("set above");
        if p.spg.is_some() && !p.sized {
            if !p.size(self.min) {
                return;
            }
            self.stats.candidates += u64::from(p.spg.is_some());
        }
        let Some(spg) = p.spg else {
            return;
        };
        // the complete pieces since the last scan, as one view (the PG core cuts it): one message per scan
        let filled = p.watch.filled().min(p.end);
        let stop = if filled == p.end {
            p.end
        } else {
            p.next + filled.saturating_sub(p.next) / self.min * self.min
        };
        if stop <= p.next {
            return;
        }
        let Some(v) = p.watch.view(p.next, stop - p.next) else {
            return;
        };
        self.stats.pieces += v.len().div_ceil(self.min) as u64;
        self.out.push((spg, p.watch.clone(), v, !p.sent));
        p.next = stop;
        p.sent = true;
    }
}

impl<B: Backend> Osd<B> {
    /// `flashstore_prewrite` (re)read: the decoder setting of every link of this core (a frame being received keeps its
    /// buffer kind; the next one follows the setting). The piece is the store's data run; a store without pre-write
    /// leaves it off.
    pub(crate) fn pre_configure(&mut self, on: bool) {
        let min = if on { self.pg.store.pre_piece() } else { 0 };
        if self.pre.min == min {
            return;
        }
        self.pre.min = min;
        for l in self.links.values_mut() {
            l.conn.set_prewrite(min);
        }
    }

    /// Connection core, after input on link `id` (bytes fed, a direct-receive piece, the lent buffer back): send the
    /// pieces of the candidate range that are complete now; forget the frame once it is delivered or gone.
    pub(crate) fn pre_scan(&mut self, id: u64) {
        let Some(l) = self.links.get_mut(&id) else {
            return;
        };
        // session caps, peer identity and address belong to the link (set once); a scan only borrows them
        let (msgr, peer, peer_osd) = (
            l.msgr,
            l.caps_peer,
            l.msgr == MsgrId::Cluster
                && l.peer
                    .as_ref()
                    .is_some_and(|p| p.name.ty == EntityName::OSD),
        );
        match l.conn.rx_early() {
            Some(e) => {
                let (caps, pre) = (l.caps.as_deref(), &mut l.pre);
                let (map, store) = (&self.map, &self.pg.store);
                self.pre.cut(pre, &e, msgr, |p| {
                    pre_allowed(map.as_deref(), store, caps, peer, msgr, peer_osd, p)
                })
            }
            None => l.pre = None,
        }
        self.pre_send();
    }

    /// [`pre_scan`](Self::pre_scan) of a frame received outside a link (tests drive a decoder by hand).
    #[cfg(test)]
    pub(crate) fn pre_feed(
        &mut self,
        slot: &mut Option<PreRx>,
        e: &RxEarly<'_>,
        msgr: MsgrId,
        peer_osd: bool,
        caps: Option<&opexec::caps::Caps>,
    ) {
        let (map, store) = (&self.map, &self.pg.store);
        self.pre.cut(slot, e, msgr, |p| {
            pre_allowed(
                map.as_deref(),
                store,
                caps,
                opexec::caps::Peer::Unknown,
                msgr,
                peer_osd,
                p,
            )
        });
        self.pre_send();
    }

    /// The pieces cut by the last scan go to their PG cores (in order: one lane per PG, the op follows on it), one
    /// message per scan; only a frame's first one wakes its PG core.
    fn pre_send(&mut self) {
        if self.pre.out.is_empty() {
            return;
        }
        let mut out = std::mem::take(&mut self.pre.out);
        let at = crate::trace::now();
        for (spg, watch, pieces, wake) in out.drain(..) {
            if self.pg.set.core_of(spg.pgid) == self.cl.spec.id && !self.mig_busy(spg.pgid) {
                self.pre_pieces(spg, watch, pieces);
            } else {
                self.pg_item(
                    None,
                    XMsg::PrePiece {
                        spg,
                        watch,
                        pieces,
                        wake,
                        at,
                    },
                );
            }
        }
        self.pre.out = out;
    }

    /// PG core: a [`XMsg::PrePiece`] cut at `at` (`trace::now()` of the connection core) is handled now.
    pub(crate) fn pre_lag(&mut self, at: u64) {
        let ns = crate::trace::span_ns(at, crate::trace::now());
        let s = &mut self.pre.stats;
        s.msgs += 1;
        s.lag_ns += ns;
        s.lag_max_ns = s.lag_max_ns.max(ns);
    }

    /// PG core: write the pieces of `pieces` (whole pieces from a piece start; the last one may be shorter) ahead.
    /// Passive where it cannot pay: an erasure pool (its primary encodes the whole stripe), a pool or PG this core does
    /// not know, a frame already gone, pre-write off on this core, a store that declines.
    pub(crate) fn pre_pieces(&mut self, spg: SpgT, watch: SegWatch, pieces: Bytes) {
        let piece = self.pre.min;
        // the connection core checked the pool with its map; this core's map may be newer
        let ok = pre_pool(self.map.as_deref(), &self.pg.store, spg.pgid.pool);
        if piece == 0 || !ok || self.pg.dead || watch.gone() {
            self.pre.stats.refused += pieces.len().div_ceil(piece.max(1)) as u64;
            return;
        }
        for a in (0..pieces.len()).step_by(piece) {
            match self
                .pg
                .store
                .pre_write(spg, &pieces.slice(a..(a + piece).min(pieces.len())))
            {
                Some(t) => {
                    self.pre.stats.written += 1;
                    self.pre.live.push((watch.clone(), t));
                }
                None => self.pre.stats.refused += 1,
            }
        }
    }

    /// PG core (store poll): forget the tickets of pieces a txn took or that were returned at staging, return the open
    /// pieces of segments that are gone. Looks at the tickets only when a piece closed or a segment turned gone since
    /// the last look (the poll loop runs far more often than either).
    pub(crate) fn pre_reap(&mut self) {
        if self.pre.live.is_empty() {
            return;
        }
        let store = &self.pg.store;
        let now = (store.pre_closed(), SegWatch::gone_epoch());
        if now == self.pre.seen {
            return;
        }
        let stats = &mut self.pre.stats;
        self.pre.live.retain(|(w, t)| {
            if !store.pre_open(*t) {
                return false;
            }
            if !w.gone() {
                return true;
            }
            store.pre_release(*t);
            stats.reaped += 1;
            false
        });
        // the releases above closed pieces themselves: the next look is due only for changes after this one
        self.pre.seen = (store.pre_closed(), now.1);
    }

    /// Pieces written ahead whose segment is not gone yet (tests, diagnostics).
    #[cfg(test)]
    pub(crate) fn pre_live(&self) -> usize {
        self.pre.live.len()
    }

    /// The store counters of this core with the pre-write counters of its OSD half (`flashstore_store_<core>.pre_rx_*`).
    pub(crate) fn store_counters_local(&self) -> Vec<(&'static str, bool, u64)> {
        let mut v = self.pg.store.store_counters();
        v.extend(self.pre_counters());
        v
    }

    fn pre_counters(&self) -> [(&'static str, bool, u64); 10] {
        let s = &self.pre.stats;
        [
            ("pre_rx_frames", false, s.frames),
            ("pre_rx_candidates", false, s.candidates),
            ("pre_rx_pieces", false, s.pieces),
            ("pre_rx_written", false, s.written),
            ("pre_rx_refused", false, s.refused),
            ("pre_rx_reaped", false, s.reaped),
            ("pre_rx_live", true, self.pre.live.len() as u64),
            ("pre_rx_msgs", false, s.msgs),
            ("pre_rx_lag_ns", false, s.lag_ns),
            ("pre_rx_lag_max_ns", true, s.lag_max_ns),
        ]
    }
}

impl crate::osd::Link {
    /// Input on this link may have completed a piece or ended a pre-write frame ([`Osd::pre_scan`] is due).
    #[inline]
    pub(crate) fn pre_due(&self) -> bool {
        self.pre.is_some() || self.conn.rx_early().is_some()
    }
}
