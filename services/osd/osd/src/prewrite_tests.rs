// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Receiver-side pre-write through the OSD (adr 0477): a large write is received like a link does it (msgr2 decoder with
//! pre-write, a scan after every chunk), its pieces go to the PG core's store while the frame arrives, and the op that
//! follows takes them. Every way a frame or its op can end leaves the store with no piece held and the bytes right.
use super::*;
use crate::osd::MsgrId;
use crate::prewrite::PreRx;
use messages::Segments;
use msgr2::{Decoder, Encoder, MsgHeader2, Revision};

/// The piece of the test stores (sim device: no transfer limit below one run).
const PIECE: usize = store::obj::PRE_PIECE;

/// The msgr2 crc frame a peer sends for message `ty` (`segs` as encoded).
fn wire(tid: u64, ty: u16, ver: u16, segs: &Segments) -> Vec<u8> {
    let h = MsgHeader2 {
        seq: tid,
        tid,
        msg_type: ty,
        version: ver,
        // as `pg_send` states it for a repop (spec msgr2.md 3.1)
        data_off: if ty == <replwire::MOSDRepOp as messages::Message>::MSG_TYPE {
            replwire::REPOP_DATA_OFF
        } else {
            0
        },
        ..Default::default()
    }
    .to_bytes();
    let mut out = Vec::new();
    Encoder::new(Revision::V21)
        .encode_message(
            &h,
            &segs.front_bytes().unwrap(),
            &segs.middle,
            &segs.data,
            &mut out,
        )
        .unwrap();
    out
}

/// A frame being received by hand: the decoder a link of `msgr` has (placement and pre-write on).
struct Rx {
    dec: Decoder,
    slot: Option<PreRx>,
    msgr: MsgrId,
    /// The authenticated peer type: a cluster link of an OSD peer (repop) unless the test says otherwise.
    peer_osd: bool,
    /// Session caps of the simulated link (`None`: a cluster link, an authenticated OSD peer).
    caps: Option<std::sync::Arc<opexec::caps::Caps>>,
    w: Vec<u8>,
    pos: usize,
}

impl Rx {
    fn new(msgr: MsgrId, w: Vec<u8>) -> Rx {
        let mut dec = Decoder::new(Revision::V21);
        dec.set_rx_place(true);
        dec.set_prewrite(PIECE);
        Rx {
            dec,
            slot: None,
            msgr,
            peer_osd: msgr == MsgrId::Cluster,
            caps: (msgr == MsgrId::Public)
                .then(|| std::sync::Arc::new(opexec::caps::Caps::parse("allow *").unwrap())),
            w,
            pos: 0,
        }
    }

    /// The session caps of the simulated link (e.g. a read-only client).
    fn with_caps(mut self, caps: &str) -> Rx {
        self.caps = Some(std::sync::Arc::new(
            opexec::caps::Caps::parse(caps).unwrap_or_else(|e| panic!("{caps}: {e}")),
        ));
        self
    }

    /// Feed the next `n` bytes and scan like `Osd::pre_scan`; false when everything was fed.
    fn step(&mut self, o: &mut Osd<B>, n: usize) -> bool {
        let end = (self.pos + n).min(self.w.len());
        self.dec.feed(&self.w[self.pos..end]);
        self.pos = end;
        if let Some(e) = self.dec.early() {
            o.pre_feed(
                &mut self.slot,
                &e,
                self.msgr,
                self.peer_osd,
                self.caps.as_deref(),
            );
        }
        self.pos < self.w.len()
    }

    /// Feed the rest; the delivered message (`None`: the frame failed).
    fn finish(mut self) -> Option<Segments> {
        self.dec.feed(&self.w[self.pos..]);
        let f = self.dec.poll_owned().ok()??;
        assert!(self.dec.early().is_none(), "the frame is done");
        let seg = |i: usize| f.segs.get(i).cloned().unwrap_or_default();
        Some(Segments {
            front: seg(1).to_vec(),
            front_zc: Vec::new(),
            front_hints: Default::default(),
            middle: seg(2).to_vec(),
            data: seg(3),
        })
    }
}

/// A peer frame (`Pair::exchange` with `pre_wire`) received on `o` like a cluster link: whole, in receive pieces, the
/// pre-write scan after each; the delivered segments.
pub(super) fn receive_on(o: &mut Osd<B>, tid: u64, ty: u16, ver: u16, segs: &Segments) -> Segments {
    let mut rx = Rx::new(MsgrId::Cluster, wire(tid, ty, ver, segs));
    // like knet: the headers from the ring, the data segment in direct pieces, the epilogue from the ring again
    let end = rx.w.len() - EPILOGUE;
    rx.step(o, end - segs.data.len());
    while rx.pos < end {
        rx.step(o, PIECE.min(end - rx.pos));
    }
    rx.finish().expect("a peer frame decodes")
}

/// Sum of counter `name` over the cores of `m` (store and OSD-side pre-write counters).
fn ctr(m: &Mc, name: &str) -> u64 {
    m.osds
        .iter()
        .flat_map(|o| o.store_counters_local())
        .filter(|c| c.0 == name)
        .map(|c| c.2)
        .sum()
}

/// Nothing is held anywhere: no piece written ahead and unclaimed, no ticket, no reserved block.
fn assert_nothing_held(m: &Mc) {
    assert_eq!(ctr(m, "pre_live"), 0, "store slots");
    assert_eq!(
        m.osds.iter().map(|o| o.pre_live()).sum::<usize>(),
        0,
        "tickets"
    );
    assert_eq!(
        ctr(m, "pre_writes"),
        ctr(m, "pre_claimed") + ctr(m, "pre_released"),
        "every piece claimed or released"
    );
}

/// adr 0477 am. 3: the pre-write is on by default (`flashstore_prewrite` true) on every core of a started OSD; `config set`
/// false switches it off, true back on.
#[test]
fn prewrite_is_on_by_default_and_switchable() {
    let mut p = Pair::new(2, 2);
    p.up();
    let piece = |p: &Pair| p.a.osds.iter().map(|o| o.pre.min).collect::<Vec<_>>();
    assert_eq!(piece(&p), vec![PIECE; 2], "on by default");
    for o in &mut p.a.osds {
        o.pre_configure(false);
    }
    assert_eq!(piece(&p), vec![0; 2]);
    for o in &mut p.a.osds {
        o.pre_configure(true);
    }
    assert_eq!(piece(&p), vec![PIECE; 2]);
}

/// `flashstore_prewrite false` while a frame's data segment is still shared: the rest of the frame cuts no further piece
/// (no arithmetic below a piece size, no crash on the core that owns the link), the frame and its op are unaffected.
#[test]
fn prewrite_off_mid_frame_cuts_no_further_piece() {
    let mut p = Pair::new(2, 2);
    p.up();
    on(&mut p);
    let name = object(&p, 0);
    let cl = p.a.client(0);
    let payload = data(4 * PIECE, 21);
    let op = p.a.op(1, &name, vec![OsdOp::write(0, payload.clone())]);
    let (ty, ver, _, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
    let mut rx = Rx::new(MsgrId::Public, wire(1, ty, ver, &segs));
    let end = rx.w.len() - EPILOGUE;
    rx.step(&mut p.a.osds[0], end - payload.len()); // the headers: the segment is shared, no data yet
    rx.step(&mut p.a.osds[0], PIECE); // one whole piece
    p.settle();
    assert_eq!(ctr(&p.a, "pre_rx_pieces"), 1);
    p.a.osds[0].pre_configure(false);
    while rx.pos < end {
        rx.step(&mut p.a.osds[0], PIECE.min(end - rx.pos));
        p.settle();
    }
    assert_eq!(ctr(&p.a, "pre_rx_pieces"), 1, "no piece after the switch");
    let segs = rx.finish().expect("frame");
    let r = deliver(&mut p, cl, 1, ver, &segs);
    drop(segs);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].1.result, 0);
    p.settle();
    assert_nothing_held(&p.a);
    assert_eq!(read(&mut p, cl, 2, &name, payload.len() as u64), payload);
}

fn on(p: &mut Pair) {
    for who in [0, 1] {
        for o in &mut p.node(who).osds {
            o.pre_configure(true);
        }
    }
}

/// An object of pool 1 whose primary is osd.0 and whose PG lives on another core than `conn_core` (the pieces cross).
fn object(p: &Pair, conn_core: usize) -> String {
    let map = p.a.osds[0].osdmap().unwrap().clone();
    (0..)
        .map(|i| format!("pw{i}"))
        .find(|n| {
            let raw = map.object_to_raw_pg(1, n.as_bytes(), b"", b"", -1).unwrap();
            let pg = PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32));
            map.pg_to_up_acting(pg).acting_primary == 0 && p.a.owner(1, pg.seed) != conn_core
        })
        .unwrap()
}

fn data(len: usize, seed: u32) -> Vec<u8> {
    (0..len as u32).map(|i| (i * 31 + seed) as u8).collect()
}

/// Epilogue of a rev 2.1 crc frame: late flags + crcs of segments 1..3.
const EPILOGUE: usize = 13;

/// Client write of `payload` at `off` (one MOSDOp frame, tid `tid`) received on core 0 of osd.0 up to its epilogue, the
/// data in receive steps of `step` bytes (`settle` after each: the pre-writes complete before the next bytes arrive).
/// Returns the receive and the message version.
fn client_write(
    p: &mut Pair,
    tid: u64,
    name: &str,
    off: u64,
    payload: &[u8],
    settle: bool,
    step: usize,
) -> (Rx, u16) {
    client_write_caps(p, tid, name, off, payload, settle, step, "allow *")
}

/// [`client_write`] as a session with the caps text `caps`.
#[expect(clippy::too_many_arguments)]
fn client_write_caps(
    p: &mut Pair,
    tid: u64,
    name: &str,
    off: u64,
    payload: &[u8],
    settle: bool,
    step: usize,
    caps: &str,
) -> (Rx, u16) {
    let op = p.a.op(1, name, vec![OsdOp::write(off, payload.to_vec())]);
    let (ty, ver, _, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
    let mut rx = Rx::new(MsgrId::Public, wire(tid, ty, ver, &segs)).with_caps(caps);
    let end = rx.w.len() - EPILOGUE;
    rx.step(&mut p.a.osds[0], end - payload.len());
    while rx.pos < end {
        rx.step(&mut p.a.osds[0], step.min(end - rx.pos));
        if settle {
            p.settle();
        }
    }
    (rx, ver)
}

/// Name of pool `id` in the test map (a caps text needs it).
fn pool_name(p: &Pair, id: i64) -> String {
    let n = p.a.osds[0].osdmap().unwrap().pool_name[&id]
        .as_bytes()
        .to_vec();
    String::from_utf8(n).unwrap()
}

/// Deliver a received MOSDOp (version `ver`) on `cl` (core 0) and settle; the replies on `cl`.
fn deliver(p: &mut Pair, cl: u64, tid: u64, ver: u16, segs: &Segments) -> Vec<(u64, MOSDOpReply)> {
    let t = p.a.t;
    let o = &mut p.a.osds[0];
    o.set_now(t);
    o.on_unknown_message(cl, tid, opwire::consts::ty::OSD_OP, ver, segs);
    p.settle();
    p.a.replies(0, cl)
}

fn read(p: &mut Pair, cl: u64, tid: u64, name: &str, len: u64) -> Vec<u8> {
    let op = p.a.op(1, name, vec![OsdOp::read(0, len)]);
    let mut r = p.a.call(0, cl, tid, op);
    p.settle();
    r.extend(p.a.replies(0, cl));
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].1.result, 0);
    r.remove(0).1.ops.remove(0).outdata.to_vec()
}

#[test]
fn client_write_takes_the_pieces_written_while_it_arrived() {
    // receive steps of one piece, and of three (one view of several pieces per scan, cut by the PG core)
    for (settle, step) in [(true, PIECE), (false, PIECE), (true, 3 * PIECE)] {
        let mut p = Pair::new(2, 2);
        p.up();
        on(&mut p);
        let name = object(&p, 0);
        let cl = p.a.client(0);
        let payload = data((1 << 20) + 8192 + 100, 7);
        let (rx, ver) = client_write(&mut p, 1, &name, 0, &payload, settle, step);
        // four whole pieces and the 8 KiB tail piece (the last partial block stays with the txn)
        assert_eq!(ctr(&p.a, "pre_rx_pieces"), 5, "settle {settle}");
        let segs = rx.finish().expect("frame");
        let r = deliver(&mut p, cl, 1, ver, &segs);
        drop(segs);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].1.result, 0);
        p.settle();
        assert_eq!(ctr(&p.a, "pre_rx_written"), 5);
        assert_eq!(
            ctr(&p.a, "pre_claimed"),
            5,
            "settle {settle}: the txn took every piece"
        );
        assert_eq!(ctr(&p.a, "pre_released"), 0);
        assert_nothing_held(&p.a);
        assert_eq!(read(&mut p, cl, 2, &name, payload.len() as u64), payload);
    }
}

/// adr 0477 am. 6: a session without a write grant for the frame's pool gets no device byte, not even while its data
/// arrives (the front is unverified, so the caps check comes before the first piece); with the grant nothing changes.
#[test]
fn a_session_without_write_caps_pre_writes_nothing() {
    for (grants, pieces) in [("r", 0u64), ("rw", 4)] {
        let mut p = Pair::new(2, 2);
        p.up();
        on(&mut p);
        let name = object(&p, 0);
        let caps = format!("allow {grants} pool='{}'", pool_name(&p, 1));
        let cl = p.a.client_caps(0, &caps);
        let payload = data(4 * PIECE, 9);
        let (rx, ver) = client_write_caps(&mut p, 1, &name, 0, &payload, true, PIECE, &caps);
        assert_eq!(ctr(&p.a, "pre_rx_pieces"), pieces, "caps {caps}");
        let segs = rx.finish().expect("frame");
        let r = deliver(&mut p, cl, 1, ver, &segs);
        drop(segs);
        assert_eq!(r.len(), 1);
        // the op itself is decided by the full caps check as before: a read-only session is refused
        assert_eq!(
            r[0].1.result,
            if pieces == 0 { -1 } else { 0 },
            "caps {caps}"
        );
        p.settle();
        assert_eq!(ctr(&p.a, "pre_rx_written"), pieces, "caps {caps}");
        assert_nothing_held(&p.a);
    }
}

/// adr 0477 am. 6: the pre-write exemption belongs to the authenticated peer type (an OSD on the cluster messenger),
/// not to the listener. A client that authenticated on the cluster listener — auth none, or any cephx caps — is no OSD
/// peer, so a repop-shaped frame it sends gets no device byte before the op check, which drops the frame and closes the
/// link. A client write on the public messenger keeps its write-grant gate.
#[test]
fn the_pre_write_exemption_follows_the_peer_type_not_the_listener() {
    use crate::prewrite::pre_allowed;
    let p = {
        let mut p = Pair::new(2, 2);
        p.up();
        p
    };
    let o = &p.a.osds[0];
    let map = o.osdmap().unwrap();
    let store = &o.pg.store;
    let all = opexec::caps::Caps::parse("allow *").unwrap();
    let peer = opexec::caps::Peer::Unknown;
    assert!(
        pre_allowed(Some(map), store, None, peer, MsgrId::Cluster, true, 1),
        "an authenticated OSD peer's repop"
    );
    assert!(
        !pre_allowed(
            Some(map),
            store,
            Some(&all),
            peer,
            MsgrId::Cluster,
            false,
            1
        ),
        "a client on the cluster listener gets no pre-write, whatever caps it carries"
    );
    assert!(
        pre_allowed(Some(map), store, Some(&all), peer, MsgrId::Public, false, 1),
        "a public client with the grant"
    );
    let ro = format!("allow r pool='{}'", pool_name(&p, 1));
    let ro = opexec::caps::Caps::parse(&ro).unwrap();
    assert!(
        !pre_allowed(Some(map), store, Some(&ro), peer, MsgrId::Public, false, 1),
        "a read-only public client"
    );
}

#[test]
fn only_the_first_pieces_of_a_frame_wake_the_pg_core() {
    // one receive scan per piece, nothing drained in between: one message per scan, the first one wakes; the frame
    // ends with no other traffic: the next message to that PG core is the op of the frame, it wakes the core and its
    // lane drain takes the later pieces first (rt xport test `later_pieces_wait_for_the_op_of_their_frame_...`)
    use crate::xcore::XMsg;
    let mut p = Pair::new(2, 2);
    p.up();
    on(&mut p);
    let name = object(&p, 0);
    let cl = p.a.client(0);
    let payload = data(1 << 20, 5);
    let (rx, ver) = client_write(&mut p, 1, &name, 0, &payload, false, PIECE);
    let segs = rx.finish().expect("frame");
    let o = &mut p.a.osds[0];
    o.on_unknown_message(cl, 1, opwire::consts::ty::OSD_OP, ver, &segs);
    let mut seq = Vec::new();
    while let Some((dst, m)) = o.poll_xmsg() {
        match &m {
            XMsg::PrePiece { wake, .. } => {
                assert_eq!(m.wakes(), *wake);
                seq.push((dst, if *wake { "first" } else { "later" }));
            }
            XMsg::Op { .. } => {
                assert!(m.wakes());
                seq.push((dst, "op"));
            }
            _ => assert!(m.wakes()),
        }
    }
    let pg_core = seq[0].0;
    assert!(seq.iter().all(|s| s.0 == pg_core), "{seq:?}");
    let kinds: Vec<_> = seq.iter().map(|s| s.1).collect();
    assert!(
        kinds.len() >= 3 && kinds[0] == "first" && kinds[kinds.len() - 1] == "op",
        "{kinds:?}"
    );
    assert!(
        kinds[1..kinds.len() - 1].iter().all(|k| *k == "later"),
        "{kinds:?}"
    );
}

#[test]
fn unaligned_or_small_writes_are_no_candidates() {
    let mut p = Pair::new(2, 2);
    p.up();
    on(&mut p);
    let name = object(&p, 0);
    let cl = p.a.client(0);
    for (tid, off, len) in [(1u64, 1000u64, 1 << 20), (2, 0, PIECE - 4096)] {
        let payload = data(len, tid as u32);
        let (rx, ver) = client_write(&mut p, tid, &name, off, &payload, true, PIECE);
        let segs = rx.finish().unwrap();
        assert_eq!(deliver(&mut p, cl, tid, ver, &segs)[0].1.result, 0);
    }
    assert_eq!(ctr(&p.a, "pre_rx_candidates"), 0);
    assert_eq!(ctr(&p.a, "pre_writes"), 0);
}

/// A frame whose pool cannot claim a piece (an erasure pool: its primary encodes the whole stripe; a compressing pool:
/// the store writes through the codec) is no candidate on the connection core: no message to the PG core, no wake.
#[test]
fn erasure_or_compressing_pool_writes_cost_no_message() {
    use crate::xcore::XMsg;
    let mut p = Pair::new(2, 2);
    p.up();
    on(&mut p);
    let mut map = p.a.osds[0].osdmap().unwrap().clone();
    let store = &p.a.osds[0].pg.store;
    assert!(crate::prewrite::pre_pool(Some(&map), store, 1));
    assert!(!crate::prewrite::pre_pool(None, store, 1), "no map");
    map.pools.get_mut(&1).unwrap().ptype = osdmap::pool::TYPE_ERASURE;
    assert!(!crate::prewrite::pre_pool(Some(&map), store, 1), "erasure");
    let name = object(&p, 0);
    let mut m = p.map(11, [10, 10]);
    m.pools
        .get_mut(&1)
        .unwrap()
        .opts
        .0
        .insert(6, osdmap::pool::OptVal::Str("force".into()));
    p.deliver(m);
    let cl = p.a.client(0);
    let payload = data(1 << 20, 3);
    let (rx, ver) = client_write(&mut p, 1, &name, 0, &payload, false, PIECE);
    let segs = rx.finish().unwrap();
    let o = &mut p.a.osds[0];
    o.on_unknown_message(cl, 1, opwire::consts::ty::OSD_OP, ver, &segs);
    while let Some((_, m)) = o.poll_xmsg() {
        assert!(!matches!(m, XMsg::PrePiece { .. }), "no piece message");
    }
    assert!(ctr(&p.a, "pre_rx_frames") > 0, "the frame was shared");
    assert_eq!(ctr(&p.a, "pre_rx_candidates"), 0);
    assert_eq!(ctr(&p.a, "pre_writes"), 0);
}

#[test]
fn bad_crc_frame_returns_every_piece_and_writes_nothing() {
    let mut p = Pair::new(2, 2);
    p.up();
    on(&mut p);
    let name = object(&p, 0);
    let cl = p.a.client(0);
    let payload = data(1 << 20, 3);
    let op = p.a.op(1, &name, vec![OsdOp::write(0, payload.clone())]);
    let (ty, ver, _, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
    let mut w = wire(1, ty, ver, &segs);
    let at = w.len() - 13 - 1000;
    w[at] ^= 1; // in the last piece's tail: every piece is written before the frame fails
    let mut rx = Rx::new(MsgrId::Public, w);
    while rx.step(&mut p.a.osds[0], PIECE) {
        p.settle();
    }
    assert!(ctr(&p.a, "pre_writes") >= 3);
    assert!(rx.finish().is_none(), "crc failure");
    p.settle();
    assert_eq!(ctr(&p.a, "pre_claimed"), 0);
    assert_eq!(ctr(&p.a, "pre_released"), ctr(&p.a, "pre_writes"));
    assert_nothing_held(&p.a);
    // no object, no reply
    assert!(p.a.replies(0, cl).is_empty());
    let r = p.a.call(0, cl, 2, p.a.op(1, &name, vec![OsdOp::stat()]));
    assert_eq!(r[0].1.result, -opwire::errno::ENOENT);
}

#[test]
fn connection_loss_mid_frame_returns_the_pieces() {
    for settle in [true, false] {
        let mut p = Pair::new(2, 2);
        p.up();
        on(&mut p);
        let name = object(&p, 0);
        let payload = data(1 << 20, 5);
        let op = p.a.op(1, &name, vec![OsdOp::write(0, payload)]);
        let (ty, ver, _, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
        let mut rx = Rx::new(MsgrId::Public, wire(1, ty, ver, &segs));
        let half = rx.w.len() / 2 + PIECE;
        while rx.pos < half {
            rx.step(&mut p.a.osds[0], PIECE);
            if settle {
                p.settle();
            }
        }
        assert!(ctr(&p.a, "pre_rx_pieces") >= 2);
        drop(rx); // the link faults: its decoder (and the half filled segment) is gone
        p.settle();
        assert_eq!(ctr(&p.a, "pre_claimed"), 0);
        assert_nothing_held(&p.a);
    }
}

#[test]
fn op_dropped_after_the_frame_returns_the_pieces() {
    let mut p = Pair::new(2, 2);
    p.up();
    on(&mut p);
    let name = object(&p, 0);
    let cl = p.a.client(0);
    let payload = data(1 << 20, 9);
    let mut op = p.a.op(1, &name, vec![OsdOp::write(0, payload)]);
    op.osdmap_epoch += 5; // from a map this OSD does not have yet: the op is parked
    let (ty, ver, _, segs) = ClientMsg::Op(op).encode(u64::MAX).unwrap();
    let mut rx = Rx::new(MsgrId::Public, wire(1, ty, ver, &segs));
    while rx.step(&mut p.a.osds[0], PIECE) {
        p.settle();
    }
    let segs = rx.finish().unwrap();
    let t = p.a.t;
    p.a.osds[0].set_now(t);
    p.a.osds[0].on_unknown_message(cl, 1, ty, ver, &segs);
    drop(segs);
    p.settle();
    assert!(p.a.replies(0, cl).is_empty(), "parked");
    // (the receive steps straddle the pieces: the last one completes with the frame and is not written ahead)
    assert_eq!(ctr(&p.a, "pre_writes"), 3);
    assert_eq!(ctr(&p.a, "pre_live"), 3, "held for the parked op");
    // the client goes away: its parked op is dropped with the frame's bytes
    p.a.osds[0].close_link(cl);
    p.settle();
    p.run_for(Duration::from_millis(200));
    assert_eq!(ctr(&p.a, "pre_claimed"), 0);
    assert_nothing_held(&p.a);
}

#[test]
fn interval_change_between_the_pieces_and_the_op_keeps_the_bytes_right() {
    let mut p = Pair::new(2, 2);
    p.up();
    on(&mut p);
    let name = object(&p, 0);
    let cl = p.a.client(0);
    let payload = data(1 << 20, 11);
    let (rx, ver) = client_write(&mut p, 1, &name, 0, &payload, true, PIECE);
    // the mon marks osd.1 down while the frame is still arriving: a new interval, the primary writes alone (min_size 1)
    let mut m = p.map(11, [10, 10]);
    m.osd_state[1] = osd_state::EXISTS;
    p.a.deliver(m);
    p.a.settle();
    let segs = rx.finish().unwrap();
    let t = p.a.t;
    p.a.osds[0].set_now(t);
    p.a.osds[0].on_unknown_message(cl, 1, opwire::consts::ty::OSD_OP, ver, &segs);
    drop(segs);
    // (the prior interval's read lease expires first: PG state `wait`)
    p.a.run_for(Duration::from_secs(30));
    let r = p.a.replies(0, cl);
    assert_eq!(r.len(), 1, "write completed in the new interval");
    assert_eq!(r[0].1.result, 0);
    assert_eq!(
        ctr(&p.a, "pre_claimed"),
        4,
        "the pieces stay valid across the interval"
    );
    assert_nothing_held(&p.a);
    let cl2 = p.a.client(0); // the first link went idle while time ran
    let op = p.a.op(1, &name, vec![OsdOp::read(0, payload.len() as u64)]);
    let r = p.a.call(0, cl2, 2, op);
    assert_eq!(r[0].1.ops[0].outdata.as_ref(), payload.as_slice());
}

#[test]
fn replica_takes_the_pieces_of_its_repop_payload_grid() {
    let mut p = Pair::new(2, 2);
    p.up();
    on(&mut p);
    p.pre_wire = true;
    let name = object(&p, 0);
    let cl = p.a.client(0);
    let payload = data((1 << 20) + 4096, 13);
    let op = p.a.op(1, &name, vec![OsdOp::write(0, payload.clone())]);
    let r = p.a.call(0, cl, 1, op);
    p.settle();
    let mut r = r;
    r.extend(p.a.replies(0, cl));
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].1.result, 0);
    assert_eq!(
        ctr(&p.b, "pre_rx_candidates"),
        1,
        "the repop is a candidate"
    );
    // the grid starts at the blob's payload; the range ends at the payload's last block (its length from the blob's
    // head): 4 whole pieces and the 4 KiB tail, all taken
    assert_eq!(ctr(&p.b, "pre_rx_pieces"), 5);
    assert_eq!(ctr(&p.b, "pre_claimed"), 5, "replica claims");
    assert_nothing_held(&p.b);
    assert_eq!(read(&mut p, cl, 2, &name, payload.len() as u64), payload);
    // the replica's own copy
    let map = p.a.osds[0].osdmap().unwrap().clone();
    let raw = map
        .object_to_raw_pg(1, name.as_bytes(), b"", b"", -1)
        .unwrap();
    let pg = PgT::new(1, pgwire::pgmath::object_pg(raw.seed, 32));
    let mut h = denc::types::Hobject::new(
        name.as_bytes(),
        denc::types::SnapId::NOSNAP,
        raw.seed,
        1,
        b"",
    );
    h.set_key(b"");
    let oid = denc::types::Ghobject::head(h, denc::types::ShardId::NO_SHARD);
    let c = denc::types::CollT::Pg(SpgT {
        pgid: pg,
        shard: denc::types::ShardId::NO_SHARD,
    });
    let core = p.b.owner(1, pg.seed);
    let got = p.b.osds[core]
        .pg
        .store
        .with_store(|s| s.read(&c, &oid, 0, payload.len() as u64).unwrap());
    assert_eq!(got, payload, "replica bytes");
}

/// A repop whose blob does not start with a write payload of at least one piece (an omap batch: its first stream item is
/// the key count) is no candidate once its head arrived: no piece, no device byte, no PG-core message on the replica,
/// however large the segment.
#[test]
fn replica_omap_batch_is_no_candidate() {
    let mut p = Pair::new(2, 2);
    p.up();
    on(&mut p);
    p.pre_wire = true;
    let name = object(&p, 0);
    let cl = p.a.client(0);
    let kv: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = (0..2000u32)
        .map(|i| (format!("key.{i:08}").into_bytes(), vec![i as u8; 1000]))
        .collect();
    let op = p.a.op(1, &name, vec![OsdOp::omap_set_vals(&kv)]);
    let r = p.a.call(0, cl, 1, op);
    p.settle();
    let mut r = r;
    r.extend(p.a.replies(0, cl));
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].1.result, 0);
    assert!(
        ctr(&p.b, "pre_rx_frames") >= 1,
        "the repop data segment was shared"
    );
    assert_eq!(ctr(&p.b, "pre_rx_candidates"), 0, "no write payload");
    assert_eq!(ctr(&p.b, "pre_rx_pieces"), 0);
    assert_eq!(ctr(&p.b, "pre_writes"), 0, "no device bytes");
    assert_nothing_held(&p.b);
}
