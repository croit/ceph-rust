// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Session state (spec 10.1) and the messenger-level [`SessionTable`] (no IO).
//!
//! A session is the durable part of a peer relationship (cookies, sequence numbers, queues). It is
//! independent of the TCP stream: "adopting a socket" = pointing `active` at another connection.
//! The table is a cheap cloneable handle (single-owner per core, ADR 0006: `Rc<RefCell<..>>`,
//! never held across calls). Sessions are keyed by the peer's full advertised addrvec.
use crate::Policy;
use crate::payload::SessionReconnect;
use denc::types::{EntityAddr, EntityAddrVec, EntityName};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::rc::Rc;

/// Handle of a live session in the [`SessionTable`] slab (index + version; stale after removal).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessId {
    idx: u32,
    ver: u32,
}

#[derive(Debug)]
struct Slot {
    ver: u32,
    s: Option<Session>,
}

/// Key -> slot index; foldhash with a per-process random seed (keys are remote-controlled).
type KeyMap = HashMap<SessionKey, SessId, foldhash::fast::RandomState>;

/// Default message priority (0 on the API is replaced by this).
pub const PRIO_DEFAULT: u16 = 127;

/// Tail parts of a data segment, see [`Message::data_more`].
pub type DataMore = Vec<(bytes::Bytes, crc::CrcHint)>;

/// An outgoing message (header2 fields + three body segments).
#[derive(Clone, Debug, Default)]
pub struct Message {
    /// Message type.
    pub msg_type: u16,
    /// Transaction id.
    pub tid: u64,
    /// Priority (0 = default 127).
    pub priority: u16,
    /// Encoding version of the payload.
    pub version: u16,
    /// Compat version (0 = same as `version`).
    pub compat_version: u16,
    /// Data offset hint.
    pub data_off: u16,
    /// Front segment.
    pub front: Vec<u8>,
    /// Shared runs spliced into `front` (`(offset in front, run)`, ascending; logical front = `front` with each run
    /// inserted): large runs go out by reference (`Encoder::encode_message_rope`).
    pub front_zc: Vec<(usize, bytes::Bytes)>,
    /// Known crc32c (seed `!0`) of `front_zc` runs: a CRC-mode frame joins the hinted runs' crcs ([`crc::crc32c_append_ones`])
    /// instead of reading their bytes. A hint counts only for a run viewing exactly the hinted bytes; others are computed.
    pub front_hints: crc::CrcHints,
    /// Middle segment.
    pub middle: Vec<u8>,
    /// Data segment.
    pub data: bytes::Bytes,
    /// Known crc32c (seed `!0`) of `data` (e.g. derived from store block checksums): the CRC-mode zero-copy frame
    /// then skips its own pass. Used only if `data` views exactly the hinted bytes, else computed.
    pub data_crc: crc::CrcHint,
    /// Further parts of the data segment (segment = `data` ++ these, in order), each with an optional crc hint: a large
    /// payload shared with another buffer between small encoded pieces, sent by reference (no copy into one blob).
    pub data_more: DataMore,
}

impl Message {
    /// The frame of this message can be encoded: every segment within `l` (segment and frame size) and the front rope
    /// well formed (offsets ascending inside `front`). Checked when it is queued, so no sequence number is spent on a
    /// message the encoder would refuse. Exposed so a sender can tell a refused frame from a closed connection before
    /// [`Connection::send_message`](crate::Connection::send_message).
    pub fn fits(&self, l: &crate::Limits) -> bool {
        let add = |n: u64, len: usize| n.saturating_add(len as u64);
        let segs = [
            crate::payload::HEADER2_LEN as u64,
            self.front_zc
                .iter()
                .fold(self.front.len() as u64, |n, (_, b)| add(n, b.len())),
            self.middle.len() as u64,
            self.data_more
                .iter()
                .fold(self.data.len() as u64, |n, (b, _)| add(n, b.len())),
        ];
        segs.iter().all(|&n| n <= u64::from(l.max_segment))
            && segs.iter().fold(0u64, |n, &x| n.saturating_add(x)) <= l.max_frame
            && crate::encode::check_rope(&self.front, &self.front_zc).is_ok()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Queued {
    /// 0 = not yet assigned.
    pub seq: u64,
    pub msg: Message,
    /// Same-QP placement proof: never replay or carry onto a replacement connection.
    pub placement: bool,
    pub write: Option<crate::write_receipt::WriteToken>,
}

/// Session registry key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SessionKey {
    /// Peer's advertised addrvec.
    Peer(EntityAddrVec),
    /// Unregistered lossy server-side session (connection id).
    Anon(u64),
}

/// Session state as seen by the connection-race rules. A closed session is removed from the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessState {
    /// No transport, waiting for a message to send or for the peer to connect.
    Standby,
    /// A client-role connection is dialling / handshaking / in backoff.
    Connecting,
    /// Got WAIT: the peer's own connection should win.
    Wait,
    /// Transport established.
    Ready,
}

/// Durable per-peer state.
#[derive(Debug)]
pub struct Session {
    pub(crate) key: SessionKey,
    pub(crate) policy: Policy,
    pub(crate) peer_name: EntityName,
    pub(crate) peer_addrs: EntityAddrVec,
    pub(crate) client_cookie: u64,
    pub(crate) server_cookie: u64,
    pub(crate) global_seq: u64,
    pub(crate) peer_global_seq: u64,
    pub(crate) connect_seq: u64,
    pub(crate) in_seq: u64,
    pub(crate) out_seq: u64,
    pub(crate) lossy: bool,
    pub(crate) features: u64,
    pub(crate) state: SessState,
    pub(crate) active: Option<u64>,
    /// Client-role connection currently dialling/handshaking/backing off for this session.
    pub(crate) dialer: Option<u64>,
    /// Highest in_seq already advertised to the peer (header ack_seq or ACK frame).
    pub(crate) acked_out: u64,
    out: BTreeMap<u16, VecDeque<Queued>>,
    /// One drained priority queue, reused by the next new priority. Retaining
    /// only one avoids accumulating capacity for every priority ever used.
    spare_out: VecDeque<Queued>,
    replay: VecDeque<Queued>,
    /// A terminal placed reply precedes ordinary messages queued during the WRITE lifetime.
    placement: VecDeque<Queued>,
    sent: VecDeque<Queued>,
    pub(crate) writes: crate::write_receipt::WritePool,
}

impl Session {
    pub(crate) fn new(key: SessionKey, policy: Policy, peer_addrs: EntityAddrVec) -> Self {
        Self {
            key,
            policy,
            peer_name: EntityName::default(),
            peer_addrs,
            client_cookie: 0,
            server_cookie: 0,
            global_seq: 0,
            peer_global_seq: 0,
            connect_seq: 0,
            in_seq: 0,
            out_seq: 0,
            lossy: policy.lossy,
            features: 0,
            state: SessState::Standby,
            active: None,
            dialer: None,
            acked_out: 0,
            out: BTreeMap::new(),
            spare_out: VecDeque::new(),
            replay: VecDeque::new(),
            placement: VecDeque::new(),
            sent: VecDeque::new(),
            writes: Default::default(),
        }
    }

    pub(crate) fn queue(&mut self, mut m: Message) {
        if m.priority == 0 {
            m.priority = PRIO_DEFAULT;
        }
        self.queue_carried(Queued {
            seq: 0,
            msg: m,
            placement: false,
            write: None,
        });
    }
    pub(crate) fn queue_write(
        &mut self,
        mut m: Message,
        write: Option<crate::write_receipt::WriteToken>,
    ) {
        if m.priority == 0 {
            m.priority = PRIO_DEFAULT;
        }
        self.queue_carried(Queued {
            seq: 0,
            msg: m,
            placement: false,
            write,
        });
    }

    pub(crate) fn queue_placement(&mut self, mut msg: Message) {
        if msg.priority == 0 {
            msg.priority = PRIO_DEFAULT;
        }
        self.placement.push_back(Queued {
            seq: 0,
            msg,
            placement: true,
            write: None,
        });
    }

    pub(crate) fn next_placement_to_send(&mut self) -> Option<Queued> {
        self.placement.pop_front()
    }

    pub(crate) fn drop_placement(&mut self) {
        self.placement.clear();
    }

    /// Next message to put on the wire: replays first, then highest priority FIFO.
    pub(crate) fn next_to_send(&mut self) -> Option<Queued> {
        if let Some(q) = self.replay.pop_front() {
            return Some(q);
        }
        if let Some(q) = self.placement.pop_front() {
            return Some(q);
        }
        let mut e = self.out.last_entry()?;
        let q = e.get_mut().pop_front();
        if e.get().is_empty() {
            let drained = e.remove();
            if drained.capacity() > self.spare_out.capacity() {
                self.spare_out = drained;
            }
        }
        q
    }

    /// Record a transmitted message (lossless keeps it for replay).
    pub(crate) fn mark_sent(&mut self, q: Queued) {
        if !self.lossy && !q.placement {
            self.sent.push_back(q);
        }
    }

    /// Drop sent messages with seq <= `upto`.
    pub(crate) fn trim_sent(&mut self, upto: u64) {
        for queue in [&mut self.sent, &mut self.replay] {
            while queue.front().is_some_and(|q| q.seq != 0 && q.seq <= upto) {
                if let Some(q) = queue.pop_front()
                    && let Some(token) = &q.write
                {
                    token.complete(crate::WriteStatus::Written);
                }
            }
        }
    }

    /// Unacked sent messages go back to the front of the send order, keeping their seqs.
    pub(crate) fn requeue_for_replay(&mut self) {
        let mut s = core::mem::take(&mut self.sent);
        s.append(&mut self.replay);
        self.replay = s;
    }

    /// New session on the wire: everything unsent/unacked is renumbered from 1.
    pub(crate) fn restart_seqs(&mut self) {
        self.requeue_for_replay();
        for q in &mut self.replay {
            q.seq = 0;
        }
        self.in_seq = 0;
        self.out_seq = 0;
        self.acked_out = 0;
    }

    /// Forget the protocol state (cookies, seqs) and the queues. `keep_unsent`: frames that never reached the wire stay queued for
    /// the next session (OSD cluster peers, see `Policy::keep_owed`); sent-unacked and replay frames are always dropped (spec
    /// 10.3): they may have been delivered already and PG messages are not duplicate-tolerant (peering chaos with duplicated
    /// messages fails), so a replay could corrupt state.
    pub(crate) fn reset_all(&mut self, keep_unsent: bool) {
        if !keep_unsent || self.lossy {
            for q in self.out.values().flatten() {
                Self::discard_write(q);
            }
            self.out.clear();
        }
        for q in self.placement.iter().chain(&self.replay).chain(&self.sent) {
            Self::discard_write(q);
        }
        self.placement.clear();
        self.replay.clear();
        self.sent.clear();
        self.client_cookie = 0;
        self.server_cookie = 0;
        self.connect_seq = 0;
        self.in_seq = 0;
        self.out_seq = 0;
        self.acked_out = 0;
    }

    /// The frames that never reached the wire, in send order (by priority); the session is left without them.
    fn discard_write(q: &Queued) {
        if let Some(token) = &q.write {
            token.complete(crate::WriteStatus::Discarded);
        }
    }
    #[cfg(feature = "test-hooks")]
    pub(crate) fn take_unsent(&mut self) -> Vec<Message> {
        self.take_unsent_tracked()
            .into_iter()
            .map(|q| {
                Self::discard_write(&q);
                q.msg
            })
            .collect()
    }
    pub(crate) fn take_unsent_tracked(&mut self) -> Vec<Queued> {
        self.placement.clear();
        let mut queued = Vec::new();
        for (_, queue) in core::mem::take(&mut self.out).into_iter().rev() {
            queued.extend(queue);
        }
        queued
    }
    /// Carry never-sent messages and their receipt pool into a fresh session.
    /// Already-sent/replay messages follow reset policy and are not carried.
    pub(crate) fn carry_writes(&mut self) -> crate::write_receipt::WritePool {
        for q in self.sent.iter().chain(&self.replay) {
            Self::discard_write(q);
        }
        core::mem::take(&mut self.writes)
    }
    pub(crate) fn queue_carried(&mut self, queued: Queued) {
        self.out
            .entry(queued.msg.priority)
            .or_insert_with(|| core::mem::take(&mut self.spare_out))
            .push_back(queued);
    }

    /// Connection `id` carries (`active`) or dials (`dialer`) this session.
    pub(crate) fn owned_by(&self, id: u64) -> bool {
        self.active == Some(id) || self.dialer == Some(id)
    }

    /// A message is queued or an ACK is owed: framing would emit something. O(1) (`out` holds no empty priority).
    pub(crate) fn has_frame_work(&self) -> bool {
        !self.replay.is_empty()
            || !self.placement.is_empty()
            || !self.out.is_empty()
            || (!self.lossy && self.in_seq > self.acked_out)
    }

    /// Messages waiting to be sent (excludes sent-unacked).
    pub(crate) fn unsent(&self) -> usize {
        self.replay.len()
            + self.placement.len()
            + self.out.values().map(VecDeque::len).sum::<usize>()
    }

    pub(crate) fn unacked(&self) -> usize {
        self.sent.len()
    }

    /// Nothing queued in any queue.
    pub(crate) fn queues_empty(&self) -> bool {
        self.unsent() == 0 && self.sent.is_empty()
    }
}

/// Read-only snapshot of a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    /// State.
    pub state: SessState,
    /// Peer name.
    pub peer_name: EntityName,
    /// Client cookie.
    pub client_cookie: u64,
    /// Server cookie.
    pub server_cookie: u64,
    /// connect_seq.
    pub connect_seq: u64,
    /// Last received message seq.
    pub in_seq: u64,
    /// Last sent message seq.
    pub out_seq: u64,
    /// Messages waiting to be sent.
    pub unsent: usize,
    /// Messages sent but not acked (lossless only).
    pub unacked: usize,
    /// Connection id currently carrying the session.
    pub active: Option<u64>,
}

/// Result of [`SessionTable::queue`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Queue {
    /// Queued; poll the connection with this id for output.
    Conn(u64),
    /// Queued but no connection carries the session: create a client `Connection` for it.
    NeedDial,
    /// No such session.
    NoSession,
}

#[derive(Debug)]
struct Inner {
    slots: RefCell<Vec<Slot>>,
    free: RefCell<Vec<u32>>,
    by_key: RefCell<KeyMap>,
    global_seq: Cell<u64>,
    rng: Cell<u64>,
    superseded: RefCell<Vec<u64>>,
    /// A session lost its accepted connection while it still owed the peer messages (see `take_owed`).
    owed: Cell<bool>,
    next_anon: Cell<u64>,
    /// Peers (entity numbers) for which `Policy::keep_owed` applies; None = every peer of a keep_owed policy.
    keep_owed_peers: RefCell<Option<std::collections::BTreeSet<i64>>>,
}

/// Messenger-wide session registry, global_seq counter and cookie source. Clone = same table.
#[derive(Clone, Debug)]
pub struct SessionTable(Rc<Inner>);

impl SessionTable {
    /// New table. `seed` seeds cookie generation (use OS randomness in production).
    pub fn new(seed: u64) -> Self {
        Self(Rc::new(Inner {
            slots: RefCell::new(Vec::new()),
            free: RefCell::new(Vec::new()),
            by_key: RefCell::new(KeyMap::default()),
            global_seq: Cell::new(0),
            rng: Cell::new(seed ^ 0x9E37_79B9_7F4A_7C15),
            superseded: RefCell::new(Vec::new()),
            owed: Cell::new(false),
            next_anon: Cell::new(1),
            keep_owed_peers: RefCell::new(None),
        }))
    }

    /// Restrict `Policy::keep_owed` to these peers (the OSDs known to run croit-flashstore-osd; classic peers keep spec 10.3 behaviour).
    pub fn set_keep_owed_peers(&self, peers: std::collections::BTreeSet<i64>) {
        *self.0.keep_owed_peers.borrow_mut() = Some(peers);
    }

    /// Does a reset of the session with `peer` keep the frames that never reached the wire? (policy flag and peer filter)
    pub(crate) fn keeps_owed(&self, policy: &Policy, peer: i64) -> bool {
        policy.keep_owed
            && self
                .0
                .keep_owed_peers
                .borrow()
                .as_ref()
                .is_none_or(|s| s.contains(&peer))
    }

    /// Global counter step (spec 10.5): `if old > counter {counter = old}; counter += 1`. `old` is peer-supplied
    /// (SESSION_RETRY_GLOBAL): the step saturates (no panic, and a wrap to 0 would retry forever).
    pub fn next_global_seq(&self, old: u64) -> u64 {
        let g = self.0.global_seq.get().max(old).saturating_add(1);
        self.0.global_seq.set(g);
        g
    }

    /// Non-zero pseudo-random cookie (splitmix64).
    pub fn random_cookie(&self) -> u64 {
        loop {
            let s = self.0.rng.get().wrapping_add(0x9E37_79B9_7F4A_7C15);
            self.0.rng.set(s);
            let mut z = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            if z != 0 {
                return z;
            }
        }
    }

    pub(crate) fn new_anon_key(&self) -> SessionKey {
        let n = self.0.next_anon.get() + 1;
        self.0.next_anon.set(n);
        SessionKey::Anon(n)
    }

    pub(crate) fn id_of(&self, k: &SessionKey) -> Option<SessId> {
        self.0.by_key.borrow().get(k).copied()
    }

    /// Insert (replacing a session with the same key).
    pub(crate) fn insert(&self, s: Session) -> SessId {
        self.remove_key(&s.key);
        let key = s.key.clone();
        let mut slots = self.0.slots.borrow_mut();
        let id = match self.0.free.borrow_mut().pop() {
            Some(idx) => {
                let sl = &mut slots[idx as usize];
                sl.s = Some(s);
                SessId { idx, ver: sl.ver }
            }
            None => {
                slots.push(Slot { ver: 0, s: Some(s) });
                SessId {
                    idx: (slots.len() - 1) as u32,
                    ver: 0,
                }
            }
        };
        self.0.by_key.borrow_mut().insert(key, id);
        id
    }

    pub(crate) fn remove_key(&self, k: &SessionKey) -> Option<Session> {
        let id = self.0.by_key.borrow_mut().remove(k)?;
        self.take_slot(id)
    }

    pub(crate) fn remove(&self, id: SessId) -> Option<Session> {
        let s = self.take_slot(id)?;
        self.0.by_key.borrow_mut().remove(&s.key);
        Some(s)
    }

    fn take_slot(&self, id: SessId) -> Option<Session> {
        let mut slots = self.0.slots.borrow_mut();
        let sl = slots
            .get_mut(id.idx as usize)
            .filter(|sl| sl.ver == id.ver)?;
        let s = sl.s.take()?;
        sl.ver = sl.ver.wrapping_add(1);
        self.0.free.borrow_mut().push(id.idx);
        Some(s)
    }

    /// Run `f` on a session (direct slab index, no hashing).
    pub(crate) fn with<R>(&self, id: SessId, f: impl FnOnce(&mut Session) -> R) -> Option<R> {
        let mut slots = self.0.slots.borrow_mut();
        let sl = slots
            .get_mut(id.idx as usize)
            .filter(|sl| sl.ver == id.ver)?;
        sl.s.as_mut().map(f)
    }

    /// Run `f` on the session with key `k` (handshake / API paths).
    pub(crate) fn with_key<R>(
        &self,
        k: &SessionKey,
        f: impl FnOnce(&mut Session) -> R,
    ) -> Option<R> {
        let id = self.id_of(k)?;
        self.with(id, f)
    }

    /// Mark connection `old` as replaced; the messenger should close it ([`take_superseded`](Self::take_superseded)).
    pub(crate) fn supersede(&self, old: u64) {
        self.0.superseded.borrow_mut().push(old);
    }

    /// Connections that lost their session to another connection since the last call.
    pub fn take_superseded(&self) -> Vec<u64> {
        core::mem::take(&mut *self.0.superseded.borrow_mut())
    }

    pub(crate) fn note_owed(&self) {
        self.0.owed.set(true);
    }

    /// True once after an accepted connection of a lossless dialable session faulted while the session still owed the peer
    /// messages: the application then dials [`needs_dial`](Self::needs_dial) (cheap check for the event loop).
    pub fn take_owed(&self) -> bool {
        self.0.owed.replace(false)
    }

    /// Snapshot of the session for `peer`.
    pub fn info(&self, peer: &EntityAddrVec) -> Option<SessionInfo> {
        self.with_key(&SessionKey::Peer(peer.clone()), |s| SessionInfo {
            state: s.state,
            peer_name: s.peer_name,
            client_cookie: s.client_cookie,
            server_cookie: s.server_cookie,
            connect_seq: s.connect_seq,
            in_seq: s.in_seq,
            out_seq: s.out_seq,
            unsent: s.unsent(),
            unacked: s.unacked(),
            active: s.active,
        })
    }

    /// The connection that carries the session for `peer` (READY) or resumes it (dialling, backoff, standby), if any. An
    /// application sends on it instead of creating a client [`crate::Connection`]: a new one takes the session over and
    /// stops the current carrier (spec 10.3), a needless reconnect.
    pub fn carrier(&self, peer: &EntityAddrVec) -> Option<u64> {
        self.with_key(&SessionKey::Peer(peer.clone()), |s| s.active.or(s.dialer))
            .flatten()
    }

    /// Number of sessions.
    pub fn len(&self) -> usize {
        self.0.by_key.borrow().len()
    }

    /// True if no sessions.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Queue a message for `peer` without a connection handle (e.g. the peer only has a session
    /// because it dialled us earlier).
    pub fn queue(&self, peer: &EntityAddrVec, m: Message) -> Queue {
        self.with_key(&SessionKey::Peer(peer.clone()), |s| {
            s.queue(m);
            s.active.map_or(Queue::NeedDial, Queue::Conn)
        })
        .unwrap_or(Queue::NoSession)
    }

    /// Lossless dialable sessions that have pending output (unsent or sent-unacked) but neither a carrying nor a dialling
    /// connection: `(peer addrs, peer name)`. Spec 10.7 step 7: the side that accepted the faulted connection reconnects when
    /// it still owes the peer messages (classic: the accepted connection object dials); here the application creates a client
    /// [`crate::Connection`] for the session, which resumes it (SESSION_RECONNECT) and replays what the peer has not acked.
    pub fn needs_dial(&self) -> Vec<(EntityAddrVec, EntityName)> {
        self.0
            .slots
            .borrow()
            .iter()
            .filter_map(|sl| sl.s.as_ref())
            .filter(|s| {
                s.active.is_none()
                    && s.dialer.is_none()
                    && !s.policy.server
                    && !s.lossy
                    && !s.queues_empty()
            })
            .filter_map(|s| match &s.key {
                SessionKey::Peer(a) => Some((a.clone(), s.peer_name)),
                SessionKey::Anon(_) => None,
            })
            .collect()
    }
}

/// Server-side CLIENT_IDENT facts relevant to the existing-session decision.
#[derive(Clone, Copy, Debug)]
pub(crate) struct IdentIn {
    pub client_cookie: u64,
    pub peer_global_seq: u64,
}

/// Outcome of spec 10.4 rule 8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IdentAct {
    /// Drop the incoming connection.
    CloseThis,
    /// Send WAIT.
    Wait,
    /// Discard X, start a fresh session.
    Fresh,
    /// Peer restarted: reset X's state if policy.resetcheck, then adopt.
    ResetAdopt,
    /// X adopts the new socket.
    Adopt,
}

pub(crate) fn addr_lt(a: Option<&EntityAddr>, b: Option<&EntityAddr>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a < b,
        _ => false,
    }
}

/// Spec 10.4 rule 8 (a-i) for an existing session `x`. `my_addr`/`peer_addr` are the v2 entries of
/// our own and the incoming peer's addrvecs (race tie-break, 10.6).
pub(crate) fn decide_ident(
    x: &Session,
    this: &IdentIn,
    my_addr: Option<&EntityAddr>,
    peer_addr: Option<&EntityAddr>,
) -> IdentAct {
    let settled = matches!(x.state, SessState::Ready | SessState::Standby);
    // no restart-detection rule (spec 10.4 rule 8c, absent since Ceph 21.1.2): a lower global_seq always loses
    if x.peer_global_seq > this.peer_global_seq {
        return IdentAct::CloseThis;
    }
    if x.lossy {
        return IdentAct::Fresh;
    }
    if x.server_cookie != 0 && x.client_cookie != 0 && x.client_cookie != this.client_cookie {
        return IdentAct::ResetAdopt;
    }
    if x.client_cookie == this.client_cookie || settled || x.state == SessState::Wait {
        return IdentAct::Adopt;
    }
    // both sides connecting: race
    if addr_lt(peer_addr, my_addr) || x.policy.server {
        IdentAct::Adopt
    } else {
        IdentAct::Wait
    }
}

/// Outcome of spec 10.5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReconnectAct {
    Reset(bool),
    RetryGlobal(u64),
    Retry(u64),
    Wait,
    Accept,
}

/// Spec 10.5 rules 1-9. `resetcheck` is the policy of the incoming connection.
pub(crate) fn decide_reconnect(
    x: Option<&Session>,
    rc: &SessionReconnect,
    resetcheck: bool,
    my_addr: Option<&EntityAddr>,
) -> ReconnectAct {
    let Some(x) = x else {
        return ReconnectAct::Reset(true);
    };
    if x.client_cookie != rc.client_cookie {
        return ReconnectAct::Reset(resetcheck);
    }
    if x.server_cookie == 0 {
        return ReconnectAct::Reset(false);
    }
    if x.peer_global_seq > rc.global_seq {
        return ReconnectAct::RetryGlobal(x.peer_global_seq);
    }
    if x.connect_seq > rc.connect_seq {
        return ReconnectAct::Retry(x.connect_seq);
    }
    if x.connect_seq == rc.connect_seq && !x.policy.server && addr_lt(my_addr, x.peer_addrs.v2()) {
        return ReconnectAct::Wait;
    }
    ReconnectAct::Accept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sess() -> Session {
        let a = EntityAddrVec::single(EntityAddr::v4(2, 1, [1, 1, 1, 1], 1));
        let mut s = Session::new(SessionKey::Peer(a.clone()), Policy::lossless_peer(0), a);
        s.client_cookie = 10;
        s.server_cookie = 20;
        s.state = SessState::Ready;
        s
    }

    fn rc() -> SessionReconnect {
        SessionReconnect {
            client_cookie: 10,
            server_cookie: 20,
            global_seq: 5,
            connect_seq: 1,
            ..Default::default()
        }
    }

    #[test]
    fn global_seq_counter() {
        let t = SessionTable::new(1);
        assert_eq!(t.next_global_seq(0), 1);
        assert_eq!(t.next_global_seq(0), 2);
        assert_eq!(t.next_global_seq(10), 11);
        assert_eq!(t.next_global_seq(3), 12);
        assert_eq!(t.next_global_seq(u64::MAX), u64::MAX);
        assert_ne!(t.random_cookie(), 0);
    }

    #[test]
    fn queue_priority_and_replay() {
        let mut s = sess();
        for (t, p) in [(1, 0), (2, 255), (3, 64), (4, 255)] {
            s.queue(Message {
                tid: t,
                priority: p,
                ..Default::default()
            });
        }
        let order: Vec<u64> = std::iter::from_fn(|| s.next_to_send())
            .map(|q| q.msg.tid)
            .collect();
        assert_eq!(order, [2, 4, 1, 3]);
        // sent -> replay keeps order and seq
        let mut s = sess();
        for i in 1..=3 {
            s.mark_sent(Queued {
                seq: i,
                msg: Message::default(),
                placement: false,
                write: None,
            });
        }
        s.trim_sent(1);
        s.requeue_for_replay();
        assert_eq!(s.next_to_send().unwrap().seq, 2);
        assert_eq!(s.next_to_send().unwrap().seq, 3);
        assert!(s.next_to_send().is_none());
    }

    #[test]
    fn placed_reply_precedes_later_output_and_never_replays() {
        let mut s = sess();
        s.queue(Message {
            tid: 2,
            ..Default::default()
        });
        s.queue_placement(Message {
            tid: 1,
            ..Default::default()
        });
        let reply = s.next_to_send().expect("placed reply");
        assert_eq!(reply.msg.tid, 1);
        assert_eq!(reply.msg.priority, PRIO_DEFAULT);
        s.mark_sent(reply);
        s.requeue_for_replay();
        assert_eq!(s.next_to_send().unwrap().msg.tid, 2);
        assert!(s.next_to_send().is_none());
        s.queue_placement(Message {
            tid: 3,
            ..Default::default()
        });
        s.drop_placement();
        assert!(s.next_to_send().is_none());
    }

    #[test]
    fn ident_rules() {
        let mut x = sess();
        let this = IdentIn {
            client_cookie: 10,
            peer_global_seq: 5,
        };
        let a1 = EntityAddr::v4(2, 1, [1, 1, 1, 1], 1);
        let a2 = EntityAddr::v4(2, 1, [2, 2, 2, 2], 1);
        // same cookie -> adopt
        assert_eq!(
            decide_ident(&x, &this, Some(&a2), Some(&a1)),
            IdentAct::Adopt
        );
        // stale
        x.peer_global_seq = 9;
        assert_eq!(
            decide_ident(&x, &this, Some(&a2), Some(&a1)),
            IdentAct::CloseThis
        );
        // a lower global_seq with a different non-zero cookie is stale too, settled or not (no rule 8c)
        let this2 = IdentIn {
            client_cookie: 11,
            peer_global_seq: 5,
        };
        assert_eq!(
            decide_ident(&x, &this2, Some(&a2), Some(&a1)),
            IdentAct::CloseThis
        );
        x.state = SessState::Connecting;
        assert_eq!(
            decide_ident(&x, &this2, Some(&a2), Some(&a1)),
            IdentAct::CloseThis
        );
        // peer restarted (cookie differs), settled
        x.peer_global_seq = 1;
        x.state = SessState::Ready;
        assert_eq!(
            decide_ident(&x, &this2, Some(&a2), Some(&a1)),
            IdentAct::ResetAdopt
        );
        // race: connecting, same-or-zero cookie path
        x.state = SessState::Connecting;
        x.client_cookie = 0;
        x.server_cookie = 0;
        assert_eq!(
            decide_ident(&x, &this2, Some(&a2), Some(&a1)),
            IdentAct::Adopt
        );
        assert_eq!(
            decide_ident(&x, &this2, Some(&a1), Some(&a2)),
            IdentAct::Wait
        );
        // lossy existing -> fresh
        x.lossy = true;
        assert_eq!(
            decide_ident(&x, &this2, Some(&a1), Some(&a2)),
            IdentAct::Fresh
        );
    }

    #[test]
    fn reconnect_rules() {
        let a_low = EntityAddr::v4(2, 1, [0, 0, 0, 1], 1);
        let mut x = sess();
        let r = rc();
        assert_eq!(
            decide_reconnect(None, &r, false, None),
            ReconnectAct::Reset(true)
        );
        assert_eq!(
            decide_reconnect(
                Some(&x),
                &SessionReconnect {
                    client_cookie: 99,
                    ..r.clone()
                },
                true,
                None
            ),
            ReconnectAct::Reset(true)
        );
        x.server_cookie = 0;
        assert_eq!(
            decide_reconnect(Some(&x), &r, false, None),
            ReconnectAct::Reset(false)
        );
        x.server_cookie = 20;
        x.peer_global_seq = 6;
        assert_eq!(
            decide_reconnect(Some(&x), &r, false, None),
            ReconnectAct::RetryGlobal(6)
        );
        x.peer_global_seq = 5;
        x.connect_seq = 3;
        assert_eq!(
            decide_reconnect(Some(&x), &r, false, None),
            ReconnectAct::Retry(3)
        );
        x.connect_seq = 1;
        // race: X.peer (1.1.1.1) > my (0.0.0.1) -> existing wins -> WAIT
        assert_eq!(
            decide_reconnect(Some(&x), &r, false, Some(&a_low)),
            ReconnectAct::Wait
        );
        x.policy.server = true;
        assert_eq!(
            decide_reconnect(Some(&x), &r, false, Some(&a_low)),
            ReconnectAct::Accept
        );
        x.policy.server = false;
        x.connect_seq = 0;
        assert_eq!(
            decide_reconnect(Some(&x), &r, false, Some(&a_low)),
            ReconnectAct::Accept
        );
    }
}
