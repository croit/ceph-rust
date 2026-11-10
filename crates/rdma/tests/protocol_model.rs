// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Deterministic seeded model of the sans-IO RDMA protocol state (adr 0469): two cores, each with a grant pool over one
//! SRQ of `depth` receive slots, a send-slot pool, and many sessions between them. Every session end runs the same calls
//! as `verbs::Core` (pool admit/on_recv/on_reposted/next_send/tick/remove/release, Tx gather/completed/wake/reclaim, SendQueue
//! drain and leases, Hold pause/push/resume/lend/settle/unlend/drain, Fence) over an in-order lossless wire with random
//! delivery, completion and re-post delays, and random sends, pauses, lends, closes, aborts and failed posts.
//!
//! Checked at every step: no overcommit, no SEND without a posted receive slot (RNR, strict: also while a detached QP is
//! not destroyed yet), every SEND on the wire and every credit a peer may still use is backed by a posted slot (dead QPs
//! not destroyed yet included: their credits stay reserved until destroy), credits a peer holds never exceed
//! what the receiver granted (`avail + in flight + used + owed + returns on the wire <= granted`), slot conservation,
//! window bounds (3 .. max_window), every lease released once and only after its WR retired, send slots never owned
//! twice. At the end: byte streams exact and in order, no deadlock (a drain phase must finish in bounded steps), credits
//! and slots all back in the pools.
//!
//! QP teardown (adr 0469, `rdma::control`): detach, later ERR (nothing lands any more), later the last-WQE event, then
//! the core drains its CQ (a poll pass that finds it empty), later the destroy, which drops every completion of the QP
//! still in the CQ (mlx5 semantics: their slots would be lost; asserted never to happen), then slots, leases and credits
//! are released.
//!
//! Repro: `RDMA_MODEL_SEEDS=1 RDMA_MODEL_SEED0=<seed> cargo test -p rdma --test protocol_model <test>`; the failing seed is
//! printed. Count per property: `RDMA_MODEL_SEEDS` (default 40), steps: `RDMA_MODEL_STEPS` (default 3000).

use bytes::Bytes;
use rdma::credit::{Imm, MIN_WINDOW};
use rdma::fence::{Fence, Step};
use rdma::grant::{GrantCfg, Pool, Sid};
use rdma::hold::{Flow, Hold};
use rdma::ring::NO_SLOT;
use rdma::tx::{Pos, Seg, Sender, Stall, Tx, Wr};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------------------------------------------- rng

#[derive(Clone)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD6E8_FEB8_6659_FD93);
        r.next();
        r
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
    fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }
    fn pick<T: Copy>(&mut self, v: &[T]) -> T {
        v[self.below(v.len() as u64) as usize]
    }
}

fn pat(tag: u64, off: u64) -> u8 {
    let x = off.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ tag.wrapping_mul(0xD6E8_FEB8_6659_FD93);
    (x >> 29) as u8
}

fn bytes_of(tag: u64, off: u64, len: usize) -> Vec<u8> {
    (0..len as u64).map(|i| pat(tag, off + i)).collect()
}

// ------------------------------------------------------------------------------------------------------------- config

#[derive(Clone, Copy, Debug)]
struct NodeCfg {
    depth: u32,
    max_window: u32,
    tx_slots: u32,
    sq_depth: u32,
    slot: u32,
    inline: u32,
    max_sge: u32,
}

fn node_cfg(r: &mut Rng, churn: bool) -> NodeCfg {
    if churn {
        return NodeCfg {
            depth: r.pick(&[12, 24, 48, 96]),
            max_window: r.pick(&[16, 64]),
            tx_slots: r.pick(&[8, 32, 64]),
            sq_depth: r.pick(&[16, 64, 256]),
            slot: r.pick(&[64, 256]),
            inline: r.pick(&[0, 64]),
            max_sge: r.pick(&[1, 2]),
        };
    }
    NodeCfg {
        depth: r.pick(&[6, 9, 12, 24, 48, 96, 200, 512]),
        max_window: r.pick(&[3, 4, 5, 8, 16, 64]),
        tx_slots: r.pick(&[1, 2, 3, 8, 32, 64]),
        sq_depth: r.pick(&[2, 4, 8, 16, 64, 256]),
        slot: r.pick(&[64, 100, 256, 1024, 4096]),
        inline: r.pick(&[0, 16, 64]),
        max_sge: r.pick(&[1, 2]),
    }
}

// ----------------------------------------------------------------------------------------------------- zero-copy data

/// Payload memory a zero-copy segment points into; dropping it is the "lease released" event.
struct Tracked {
    id: usize,
    v: Vec<u8>,
    log: Arc<Mutex<Vec<usize>>>,
}

impl AsRef<[u8]> for Tracked {
    fn as_ref(&self) -> &[u8] {
        &self.v
    }
}

impl Drop for Tracked {
    fn drop(&mut self) {
        self.log.lock().unwrap().push(self.id);
    }
}

struct Chunk {
    b: Bytes,
    zc: bool,
    /// Lease record of a zero-copy chunk.
    id: usize,
}

struct LeaseRec {
    retired: bool,
    dropped: bool,
}

// ---------------------------------------------------------------------------------------------------------- the world

struct Msg {
    imm: u32,
    data: Vec<u8>,
    seq: u32,
    signal: bool,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum St {
    Posted,
    Rq,
    Used(u32),
}

struct Slot {
    st: St,
    data: Vec<u8>,
}

/// Teardown stage of a detached QP (`rdma::control`, `Core::quiesced` / `Core::drained`).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Stage {
    /// Detached; the control thread moves it to ERR at `at`.
    Err(u64),
    /// In ERR (nothing lands); its last-WQE event comes at `at`.
    Event(u64),
    /// Quiesced: waits for a poll pass that finds the CQ empty.
    Quiesced,
    /// Drained; destroyed at `at`.
    Drained(u64),
}

struct Destroy {
    link: usize,
    side: usize,
    slots: Vec<u32>,
    /// Receive credits reserved at detach (`Pool::remove`), given back after the destroy.
    credits: u32,
    leases: Vec<Bytes>,
    lease_ids: Vec<usize>,
    stage: Stage,
}

/// A receive completion: the SEND landed in `slot` (NIC), the poll loop has not processed it yet (CPU).
struct Cqe {
    li: usize,
    side: usize,
    slot: u32,
    imm: u32,
}

struct Node {
    /// Completions in arrival order, across all sessions of the core.
    cq: VecDeque<Cqe>,
    /// Connections waiting for send slots, oldest first (mirror of the `Tx` wait queue, I2).
    waitq: VecDeque<u32>,
    cfg: NodeCfg,
    pool: Pool,
    tx: Tx,
    posted: Vec<u32>,
    rq: Vec<u32>,
    slot: Vec<Slot>,
    destroy: Vec<Destroy>,
    /// Send slots held by WRs of ends that were detached (until their QP is destroyed).
    zombie_tx_slots: usize,
    /// Send slots held by an outstanding WR (never two).
    tx_owner: Vec<bool>,
}

struct End {
    sid: Sid,
    s: Sender,
    hold: Hold,
    fence: Fence,
    pending: VecDeque<Chunk>,
    want_left: u64,
    gen_off: u64,
    taken: u64,
    rx_off: u64,
    app_wait: bool,
    writable_ev: bool,
    /// Lent ranges handed to the borrower, not consumed yet: (slot, offset, length), oldest first.
    lent: VecDeque<(u32, u32, u32)>,
    /// Outstanding WRs: (seq, send slot).
    wrs: VecDeque<(u32, u32)>,
    leases: Vec<(usize, u32)>,
    used: u32,
    fence_open: bool,
}

struct Link {
    node: [usize; 2],
    key: [u32; 2],
    ends: [Option<End>; 2],
    /// Messages in flight TO the side.
    wire: [VecDeque<Msg>; 2],
    /// Signaled send completions for the side's WRs, not applied yet.
    comps: [VecDeque<u32>; 2],
    dead: [bool; 2],
    destroyed: [bool; 2],
    /// The side that closes gracefully (fence), once its data is out.
    closing: Option<usize>,
    /// Bytes each side sent in its stream when the close finished (for the final check).
    done: bool,
}

#[derive(Default)]
struct Stats {
    sessions: u64,
    graceful: u64,
    aborts: u64,
    sends: u64,
    bytes: u64,
    resumes: u64,
    lends: u64,
    fails: u64,
    admits_refused: u64,
    max_granted: u32,
    zombie_arrivals: u64,
    /// Credits released after a destroy (reserved from detach until then).
    released: u64,
    /// REVOKE, SURRENDER, credit stalls, queue stalls, slot stalls, demand grants.
    cov: [u64; 6],
}

struct World {
    nodes: [Node; 2],
    links: Vec<Link>,
    rng: Rng,
    leases: Vec<LeaseRec>,
    log: Arc<Mutex<Vec<usize>>>,
    now: u64,
    fail_posts: bool,
    /// Large sessions on small pools, aborted and replaced all the time.
    churn: bool,
    /// Every slot is delivered at once (no Pause, no Keep).
    plain: bool,
    abort_q: Vec<usize>,
    stats: Stats,
}

const BATCH: usize = 32;

impl World {
    fn new(seed: u64, churn: bool) -> World {
        let mut rng = Rng::new(seed);
        let c = [node_cfg(&mut rng, churn), node_cfg(&mut rng, churn)];
        World::with_cfg(rng, c, churn)
    }

    fn with_cfg(mut rng: Rng, c: [NodeCfg; 2], churn: bool) -> World {
        let mk = |c: NodeCfg| Node {
            cfg: c,
            pool: Pool::new(GrantCfg {
                depth: c.depth,
                max_window: c.max_window,
                max_sessions: 64,
            }),
            tx: Tx::new(c.tx_slots, 64),
            posted: (0..c.depth).collect(),
            rq: Vec::new(),
            slot: (0..c.depth)
                .map(|_| Slot {
                    st: St::Posted,
                    data: Vec::new(),
                })
                .collect(),
            cq: VecDeque::new(),
            waitq: VecDeque::new(),
            destroy: Vec::new(),
            zombie_tx_slots: 0,
            tx_owner: vec![false; c.tx_slots as usize],
        };
        let fail_posts = rng.chance(1, 4);
        World {
            nodes: [mk(c[0]), mk(c[1])],
            links: Vec::new(),
            rng,
            leases: Vec::new(),
            log: Arc::new(Mutex::new(Vec::new())),
            now: 0,
            fail_posts,
            churn,
            plain: false,
            abort_q: Vec::new(),
            stats: Stats::default(),
        }
    }
}

// ------------------------------------------------------------------------------------------------------ receive side

/// Debug aid: `TRACEL=<link>` prints that link's credit traffic.
fn trace(li: usize) -> bool {
    static LINK: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *LINK.get_or_init(|| std::env::var("TRACEL").ok().and_then(|v| v.parse().ok())) == Some(li)
}

fn post_recvs(n: &mut Node) {
    for s in n.rq.drain(..) {
        n.slot[s as usize].st = St::Posted;
        n.posted.push(s);
    }
}

/// `Core::flush_conn`: control and credit-only SENDs the session owes, while the send queue has room.
fn flush_conn(
    n: &mut Node,
    l: &mut Link,
    side: usize,
    rng: &mut Rng,
    fail: bool,
    abort: &mut Vec<usize>,
    li: usize,
) {
    let Some(e) = l.ends[side].as_mut() else {
        return;
    };
    if l.dead[side] {
        return;
    }
    while !e.s.sq.full() {
        let Some(imm) = n.pool.next_send(e.sid) else {
            break;
        };
        let (seq, sig) = e.s.sq.push(NO_SLOT, false);
        e.wrs.push_back((seq, NO_SLOT));
        if fail && rng.chance(1, 4000) {
            abort.push(li);
            return;
        }
        if trace(li) {
            eprintln!(
                "  send side {side}: credit-only/control {:?}",
                Imm::decode(imm)
            );
        }
        l.wire[1 - side].push_back(Msg {
            imm,
            data: Vec::new(),
            seq,
            signal: sig,
        });
    }
}

/// `Core::repost`: the consumed slot is queued for the next list post, its credit is owed; a due credit goes out after the
/// post.
fn repost(w: &mut World, ni: usize, li: usize, side: usize, slot: u32) {
    let n = &mut w.nodes[ni];
    if let St::Used(k) = n.slot[slot as usize].st {
        debug_assert_eq!(k, w.links[li].key[side]);
    } else {
        panic!(
            "repost of slot {slot} in state {:?}",
            n.slot[slot as usize].st
        );
    }
    if let Some(e) = w.links[li].ends[side].as_ref() {
        assert!(
            !e.lent.iter().any(|r| r.0 == slot),
            "slot {slot} re-posted while lent"
        );
    }
    n.slot[slot as usize].st = St::Rq;
    n.rq.push(slot);
    if n.rq.len() == BATCH {
        post_recvs(n);
    }
    let l = &mut w.links[li];
    if l.dead[side] {
        return;
    }
    let Some(e) = l.ends[side].as_mut() else {
        return;
    };
    e.used -= 1;
    n.pool.on_reposted(e.sid);
    if n.pool.due(e.sid) {
        post_recvs(n);
        flush_conn(n, l, side, &mut w.rng, w.fail_posts, &mut w.abort_q, li);
    }
}

fn deliver(e: &mut End, tag: u64, data: &[u8]) {
    assert_eq!(
        data,
        &bytes_of(tag, e.rx_off, data.len())[..],
        "stream corrupted at {}",
        e.rx_off
    );
    e.rx_off += data.len() as u64;
}

/// The NIC lands one SEND of the wire to `side` of link `li` in a posted receive slot (a completion is queued; a signaled
/// SEND is acknowledged to its sender). No posted slot would be an RNR: the credits make that impossible.
fn land(w: &mut World, li: usize, side: usize) {
    let ni = w.links[li].node[side];
    let n = &mut w.nodes[ni];
    if !w.links[li].destroyed[side] && n.posted.is_empty() {
        // RNR: the credits make it impossible, also for a detached QP that is not destroyed yet (its credits stay
        // reserved until then)
        let mut who = String::new();
        for (lj, l) in w.links.iter().enumerate() {
            for s in 0..2 {
                if l.node[s] == ni
                    && let Some(e) = l.ends[s].as_ref()
                {
                    let c = n.pool.credits(e.sid);
                    who += &format!(
                        "\n  link {lj} side {s}: used {} held {} paused {} avail {} granted {} owed {} eff {}",
                        e.used,
                        e.hold.len(),
                        e.hold.paused(),
                        c.avail(),
                        c.granted(),
                        c.owed(),
                        c.effective()
                    );
                }
            }
        }
        panic!(
            "RNR: a SEND arrived on link {li} side {side} with no posted receive slot (depth {}, rq {}, cq {}, reserved {}, teardowns {}, imm {:?}){who}",
            n.cfg.depth,
            n.rq.len(),
            n.cq.len(),
            n.pool.reserved(),
            n.destroy.len(),
            Imm::decode(w.links[li].wire[side][0].imm)
        );
    }
    let msg = w.links[li].wire[side].pop_front().unwrap();
    if msg.signal {
        w.links[li].comps[1 - side].push_back(msg.seq);
    }
    if w.links[li].destroyed[side] {
        return; // the QP is gone: the packet is dropped
    }
    let at = w.rng.below(n.posted.len() as u64) as usize;
    let slot = n.posted.swap_remove(at);
    n.slot[slot as usize].st = St::Used(w.links[li].key[side]);
    n.slot[slot as usize].data = msg.data;
    n.cq.push_back(Cqe {
        li,
        side,
        slot,
        imm: msg.imm,
    });
    if !w.links[li].dead[side]
        && let Some(e) = w.links[li].ends[side].as_mut()
    {
        e.used += 1;
    }
}

/// The poll loop processes one receive completion (`Core::poll_flow`).
fn process(w: &mut World, c: Cqe) {
    let Cqe {
        li,
        side,
        slot,
        imm,
    } = c;
    let ni = w.links[li].node[side];
    let msg = Msg {
        imm,
        data: Vec::new(),
        seq: 0,
        signal: false,
    };
    let live = !w.links[li].dead[side] && w.links[li].ends[side].is_some();
    if !live {
        w.stats.zombie_arrivals += 1;
        repost(w, ni, li, side, slot);
        return;
    }
    let tag = w.links[li].key[1 - side] as u64;
    let len = w.nodes[ni].slot[slot as usize].data.len();
    let n = &mut w.nodes[ni];
    let l = &mut w.links[li];
    let e = l.ends[side].as_mut().unwrap();
    match Imm::decode(msg.imm) {
        Some(Imm::Revoke(_)) => w.stats.cov[0] += 1,
        Some(Imm::Surrender(_)) => w.stats.cov[1] += 1,
        _ => {}
    }
    let before = {
        let c = n.pool.credits(e.sid);
        (c.avail(), c.granted(), c.owed(), c.effective())
    };
    let grown = match n.pool.on_recv(e.sid, msg.imm, len > 0) {
        Ok(g) => g,
        Err(_) => panic!(
            "honest peer sent an invalid message {:?}",
            Imm::decode(msg.imm)
        ),
    };
    if trace(li) {
        let c = n.pool.credits(e.sid);
        eprintln!(
            "  now {} recv at side {side}: {:?} len {len} grown {grown}: (avail,granted,owed,eff) {before:?} -> {:?}",
            w.now,
            Imm::decode(msg.imm),
            (c.avail(), c.granted(), c.owed(), c.effective())
        );
    }
    if grown {
        post_recvs(n);
        flush_conn(n, l, side, &mut w.rng, w.fail_posts, &mut w.abort_q, li);
    }
    let e = l.ends[side].as_mut().unwrap();
    if len > 0 {
        let mut hold_it = e.hold.paused();
        if !hold_it {
            match if w.plain { 99 } else { w.rng.below(20) } {
                0 => {
                    // Pause: the slot was taken, hold the later ones
                    deliver(e, tag, &n.slot[slot as usize].data);
                    e.hold.pause();
                }
                1 => {
                    // Keep: not taken, held
                    e.hold.pause();
                    hold_it = true;
                }
                _ => deliver(e, tag, &n.slot[slot as usize].data),
            }
        }
        if hold_it {
            assert!(
                e.hold.push(slot, len as u32).is_ok(),
                "honest peer overran its window (held {}, link {li})",
                e.hold.len()
            );
            writable(w, ni, li, side);
            return;
        }
    }
    writable(w, ni, li, side);
    if len > 0 && w.rng.chance(1, 3) {
        // the upper layer answers from inside the data event (before this slot is posted again)
        app_send(w, li, side);
    }
    repost(w, ni, li, side, slot);
}

fn writable(w: &mut World, ni: usize, li: usize, side: usize) {
    let n = &mut w.nodes[ni];
    let l = &mut w.links[li];
    let dead = l.dead[side];
    if let Some(e) = l.ends[side].as_mut()
        && !dead
        && e.s.unblock(n.pool.credits(e.sid))
    {
        e.app_wait = false;
        e.writable_ev = true;
    }
}

// ---------------------------------------------------------------------------------------------------------- send side

fn process_log(w: &mut World) {
    let ids: Vec<usize> = std::mem::take(&mut *w.log.lock().unwrap());
    for id in ids {
        let r = &mut w.leases[id];
        assert!(!r.dropped, "lease {id} released twice");
        assert!(r.retired, "lease {id} released before its WR retired");
        r.dropped = true;
    }
}

/// A send completion `seq` of a side (signaled or error): `Core::poll` send branch.
fn complete(w: &mut World, li: usize, side: usize, seq: u32) {
    let ni = w.links[li].node[side];
    let l = &mut w.links[li];
    if l.dead[side] {
        return;
    }
    let Some(e) = l.ends[side].as_mut() else {
        return;
    };
    let n = &mut w.nodes[ni];
    n.tx.completed(&mut e.s, seq);
    while let Some(&(s, slot)) = e.wrs.front() {
        if e.s.sq.retired(s) {
            if slot != NO_SLOT {
                n.tx_owner[slot as usize] = false;
            }
            e.wrs.pop_front();
        } else {
            break;
        }
    }
    for &(id, last) in &e.leases {
        if e.s.sq.retired(last) {
            w.leases[id].retired = true;
        }
    }
    if e.s.sq.outstanding() == 0 {
        assert_eq!(
            e.s.sq.leases(),
            0,
            "I1: leases held with nothing outstanding"
        );
    }
    let fenced = e.fence.completed(&e.s.sq);
    if e.s.unblock(n.pool.credits(e.sid)) || fenced {
        e.app_wait = false;
        e.writable_ev = true;
    }
    process_log(w);
}

/// The wake-up pass of `Core::poll` and the pass-end flush.
fn pass_end(w: &mut World, ni: usize) {
    let n = &mut w.nodes[ni];
    // slots freed by any connection go to the waiters in queue order (I2)
    let links = &mut w.links;
    let woken = n.tx.wake(|key| {
        assert_eq!(
            n.waitq.pop_front(),
            Some(key),
            "I2: waiters are woken in queue order"
        );
        let (li, side) = ((key / 2) as usize, (key % 2) as usize);
        if links[li].dead[side] {
            return false;
        }
        let Some(e) = links[li].ends[side].as_mut() else {
            return false;
        };
        let woke = e.s.dequeued();
        if woke {
            e.app_wait = false;
            e.writable_ev = true;
        }
        woke
    });
    assert!(
        n.waitq.is_empty() || woken >= n.tx.free(),
        "I2: free send slots left while connections wait"
    );
    post_recvs(n);
    for li in 0..w.links.len() {
        for side in 0..2 {
            if w.links[li].node[side] == ni
                && w.links[li].ends[side].is_some()
                && !w.links[li].dead[side]
            {
                let n = &mut w.nodes[ni];
                flush_conn(
                    n,
                    &mut w.links[li],
                    side,
                    &mut w.rng,
                    w.fail_posts,
                    &mut w.abort_q,
                    li,
                );
            }
        }
    }
}

/// Wire messages of the node's sessions the NIC may land, and send completions: `(link, side, is_completion)`.
fn nic_work(w: &World, ni: usize) -> Vec<(usize, usize, bool)> {
    let mut v = Vec::new();
    for (li, l) in w.links.iter().enumerate() {
        for side in 0..2 {
            if l.node[side] != ni {
                continue;
            }
            if !l.wire[side].is_empty() {
                v.push((li, side, false));
            }
            if !l.comps[side].is_empty() {
                v.push((li, side, true));
            }
        }
    }
    v
}

/// The NIC lands up to `k` SENDs while the CPU does something else.
fn nic(w: &mut World, ni: usize, k: usize) {
    for _ in 0..k {
        let cands = nic_work(w, ni);
        if cands.is_empty() {
            return;
        }
        let (li, side, comp) = cands[w.rng.below(cands.len() as u64) as usize];
        if comp {
            let seq = w.links[li].comps[side].pop_front().unwrap();
            complete(w, li, side, seq);
        } else {
            land(w, li, side);
        }
    }
}

/// One poll pass: up to 32 completions in CQ order (the NIC keeps landing SENDs meanwhile), then the pass-end flush.
fn poll(w: &mut World, ni: usize) {
    let k = 1 + w.rng.below(8) as usize;
    let mut drained = false;
    for _ in 0..k {
        if w.rng.chance(1, 3) {
            nic(w, ni, 1);
        }
        let Some(c) = w.nodes[ni].cq.pop_front() else {
            drained = true;
            nic(w, ni, 1);
            continue;
        };
        process(w, c);
    }
    pass_end(w, ni);
    if drained {
        cq_drained(w, ni);
    }
}

/// `Core::poll_flow` after a pass that found the CQ empty: the QPs quiesced before it are drained (every completion of
/// theirs was in the CQ at their last-WQE event and is processed now, its slot posted again by the pass end).
fn cq_drained(w: &mut World, ni: usize) {
    let now = w.now;
    for d in &mut w.nodes[ni].destroy {
        if d.stage == Stage::Quiesced {
            d.stage = Stage::Drained(now + w.rng.below(10));
        }
    }
}

/// One app send call on an end: build segments from pending chunks (generating more), `Tx::gather`, lease the zero-copy
/// parts of the taken prefix.
fn app_send(w: &mut World, li: usize, side: usize) {
    let ni = w.links[li].node[side];
    let tag = w.links[li].key[side] as u64;
    let peer_slot = w.nodes[0].cfg.slot.min(w.nodes[1].cfg.slot) as usize;
    let l = &mut w.links[li];
    // a failed post faulted the connection (abort pending): `Core::gather_send` sends nothing on it any more
    if l.dead[side] || l.ends[side].is_none() || w.abort_q.contains(&li) {
        return;
    }
    let e = l.ends[side].as_mut().unwrap();
    if e.app_wait {
        return;
    }
    while e.pending.len() < 4 && e.want_left > 0 && w.rng.chance(3, 4) {
        let max = w.rng.pick(&[
            1usize,
            5,
            40,
            300,
            peer_slot / 2,
            peer_slot,
            peer_slot * 2 + 7,
        ]);
        let len = (1 + w.rng.below(max as u64) as usize).min(e.want_left as usize);
        let v = bytes_of(tag, e.gen_off, len);
        e.gen_off += len as u64;
        e.want_left -= len as u64;
        let zc = w.rng.chance(2, 5);
        let mut id = 0;
        let b = if zc {
            id = w.leases.len();
            w.leases.push(LeaseRec {
                retired: false,
                dropped: false,
            });
            Bytes::from_owner(Tracked {
                id,
                v,
                log: w.log.clone(),
            })
        } else {
            Bytes::from(v)
        };
        e.pending.push_back(Chunk { b, zc, id });
    }
    if e.pending.is_empty() {
        return;
    }
    let segs: Vec<Seg> = e
        .pending
        .iter()
        .map(|c| Seg {
            len: c.b.len(),
            zc: c.zc,
        })
        .collect();
    let mut seg_seq = vec![u32::MAX; segs.len()];
    let n = &mut w.nodes[ni];
    let mut planned = 0usize; // stream bytes of the WRs planned in this call (must be contiguous from 0)
    let mut fail_at = if w.fail_posts && w.rng.chance(1, 3000) {
        Some(w.rng.below(4))
    } else {
        None
    };
    let mut owners: Vec<u32> = Vec::new();
    post_recvs(n); // `Core::gather_send`: the SENDs return owed credits, their slots are posted first
    let r = {
        let wire = &mut l.wire[1 - side];
        let wrs = &mut e.wrs;
        let pending = &e.pending;
        let owners = &mut owners;
        let cfg = n.cfg;
        let pool = &mut n.pool;
        let tx = &mut n.tx;
        tx.gather(
            l.key[side],
            &mut e.s,
            pool.credits(e.sid),
            &segs,
            |wr: Wr| {
                if let Some(k) = fail_at.as_mut() {
                    if *k == 0 {
                        // the provider refuses: the WR is in the queue (slot and credit are gone) but never posted
                        wrs.push_back((wr.seq, wr.slot));
                        if wr.slot != NO_SLOT {
                            owners.push(wr.slot);
                        }
                        return false;
                    }
                    *k -= 1;
                }
                assert_eq!(
                    wr.inline,
                    wr.slot == NO_SLOT && wr.parts().iter().all(|p| !p.zc),
                    "inline iff slotless copy"
                );
                assert!(wr.len <= peer_slot && wr.len > 0);
                assert!(wr.nparts >= 1 && wr.nparts as u32 <= cfg.max_sge);
                let mut pos = wr.from;
                let mut data = Vec::new();
                for p in wr.parts() {
                    if p.zc {
                        assert!(pending[pos.seg].zc, "zc part over a copy segment");
                        assert!(
                            pos.off + p.len <= pending[pos.seg].b.len(),
                            "zc part spans segments"
                        );
                        seg_seq[pos.seg] = wr.seq;
                    } else {
                        // a copy part may span copy segments only
                        let mut left = p.len;
                        let mut q = pos;
                        while left > 0 {
                            assert!(!pending[q.seg].zc, "copy part over a zc segment");
                            let t = (pending[q.seg].b.len() - q.off).min(left);
                            left -= t;
                            q.off += t;
                            q.normalize(&segs);
                        }
                    }
                    let mut left = p.len;
                    while left > 0 {
                        let t = (pending[pos.seg].b.len() - pos.off).min(left);
                        data.extend_from_slice(&pending[pos.seg].b[pos.off..pos.off + t]);
                        left -= t;
                        pos.off += t;
                        pos.normalize(&segs);
                    }
                }
                assert_eq!(data.len(), wr.len);
                let mut start = Pos::default();
                start.advance(&segs, planned);
                assert_eq!(
                    (start.seg, start.off),
                    (wr.from.seg, wr.from.off),
                    "WRs not contiguous in stream order"
                );
                planned += wr.len;
                if wr.slot != NO_SLOT {
                    owners.push(wr.slot);
                }
                wrs.push_back((wr.seq, wr.slot));
                if trace(li) {
                    eprintln!(
                        "  send side {side}: data {} imm {:?} signal {}",
                        data.len(),
                        Imm::decode(wr.imm),
                        wr.signal
                    );
                }
                wire.push_back(Msg {
                    imm: wr.imm,
                    data,
                    seq: wr.seq,
                    signal: wr.signal,
                });
                true
            },
        )
    };
    assert_eq!(r.taken, planned, "taken counts the posted WRs");
    for s in owners {
        let n = &mut w.nodes[ni];
        assert!(!n.tx_owner[s as usize], "send slot {s} handed out twice");
        n.tx_owner[s as usize] = true;
    }
    assert!(
        r.failed || e.s.sq.covered(),
        "I1: a slot or lease holder behind the last signaled WR"
    );
    w.stats.sends += u64::from(r.posts);
    w.stats.bytes += r.taken as u64;
    // consume the taken prefix: whole chunks, a partial one; lease the zero-copy parts to the WR that read them last
    let mut taken = r.taken;
    let mut i = 0;
    let mut done_chunks = 0;
    while taken > 0 {
        let c = &mut e.pending[i];
        let t = c.b.len().min(taken);
        taken -= t;
        if c.zc {
            let piece = if t == c.b.len() {
                std::mem::take(&mut c.b)
            } else {
                c.b.split_to(t)
            };
            let seq = seg_seq[i];
            assert_ne!(seq, u32::MAX, "taken zc bytes with no zc WR");
            e.s.sq.lease_at(seq, piece);
            w.leases[c.id].retired = false;
            e.leases.retain(|x| x.0 != c.id);
            e.leases.push((c.id, seq));
        } else if t == c.b.len() {
            c.b = Bytes::new();
        } else {
            let _ = c.b.split_to(t);
        }
        if c.b.is_empty() {
            done_chunks += 1;
        }
        i += 1;
    }
    for _ in 0..done_chunks {
        e.pending.pop_front();
    }
    e.taken += r.taken as u64;
    if let Some(stall) = r.stall {
        e.app_wait = true;
        w.stats.cov[match stall {
            Stall::Credits => 2,
            Stall::Queue => 3,
            Stall::Slots => 4,
        }] += 1;
        if stall == Stall::Slots {
            let (n, key) = (&mut w.nodes[ni], w.links[li].key[side]);
            if !n.waitq.contains(&key) {
                n.waitq.push_back(key);
            }
        }
    }
    if r.failed {
        w.stats.fails += 1;
        w.abort_q.push(li);
    }
}

// ------------------------------------------------------------------------------------------------- hold, lend, close

/// `Core::resume`; `force`: every slot answers `Go` (a close drains the peer).
fn resume(w: &mut World, li: usize, side: usize, force: bool) {
    let ni = w.links[li].node[side];
    let tag = w.links[li].key[1 - side] as u64;
    {
        let l = &mut w.links[li];
        let Some(e) = l.ends[side].as_mut() else {
            return;
        };
        if l.dead[side] || e.hold.lent() != 0 {
            return;
        }
        e.hold.resume();
        w.stats.resumes += 1;
    }
    loop {
        let flow = if force {
            Flow::Go
        } else {
            match w.rng.below(12) {
                0 => Flow::Pause,
                1 => Flow::Keep,
                _ => Flow::Go,
            }
        };
        let e = w.links[li].ends[side].as_mut().unwrap();
        let Some((slot, off, len)) = e.hold.front() else {
            break;
        };
        if flow == Flow::Keep {
            e.hold.pause();
            break;
        }
        let data = &w.nodes[ni].slot[slot as usize].data;
        assert_eq!(data.len() as u32, len);
        deliver(e, tag, &data[off as usize..]);
        e.hold.pop();
        if flow == Flow::Pause {
            e.hold.pause();
        }
        repost(w, ni, li, side, slot);
        if flow == Flow::Pause {
            break;
        }
    }
    pass_end(w, ni);
}

fn lend(w: &mut World, li: usize, side: usize) {
    let l = &mut w.links[li];
    let Some(e) = l.ends[side].as_mut() else {
        return;
    };
    if l.dead[side] {
        return;
    }
    let slot = w.nodes[0].cfg.slot.max(w.nodes[1].cfg.slot);
    let max = w.rng.pick(&[1, 10, slot / 2, slot, slot * 3, u32::MAX]);
    let parts = w.rng.pick(&[1u32, 2, 3, 8]);
    let mut got = Vec::new();
    let n = e.hold.lend(max, parts, |s, o, l| got.push((s, o, l)));
    assert_eq!(n, got.iter().map(|r| r.2).sum::<u32>());
    assert!(n <= max && got.len() as u32 <= parts);
    w.stats.lends += u64::from(n > 0);
    e.lent.extend(got);
    assert_eq!(
        e.hold.lent(),
        e.lent.iter().map(|r| r.2).sum::<u32>(),
        "lent bytes drifted"
    );
}

fn settle(w: &mut World, li: usize, side: usize) {
    let ni = w.links[li].node[side];
    let tag = w.links[li].key[1 - side] as u64;
    let total = {
        let l = &w.links[li];
        match l.ends[side].as_ref() {
            Some(e) if !l.dead[side] => e.lent.iter().map(|r| r.2).sum::<u32>(),
            _ => return,
        }
    };
    if total == 0 {
        return;
    }
    let k = 1 + w.rng.below(u64::from(total)) as u32;
    let e = w.links[li].ends[side].as_mut().unwrap();
    let mut rest = k;
    while rest > 0 {
        let r = e.lent.front_mut().unwrap();
        let t = r.2.min(rest);
        let data = &w.nodes[ni].slot[r.0 as usize].data;
        let (a, b) = (r.1 as usize, (r.1 + t) as usize);
        assert_eq!(
            data[a..b],
            bytes_of(tag, e.rx_off, t as usize)[..],
            "stream corrupted at {}",
            e.rx_off
        );
        e.rx_off += u64::from(t);
        rest -= t;
        r.1 += t;
        r.2 -= t;
        if r.2 == 0 {
            e.lent.pop_front();
        }
    }
    let mut left = k;
    loop {
        let e = w.links[li].ends[side].as_mut().unwrap();
        let Some(slot) = e.hold.settle(&mut left) else {
            break;
        };
        repost(w, ni, li, side, slot);
    }
    let e = w.links[li].ends[side].as_ref().unwrap();
    assert_eq!(left, 0);
    assert_eq!(
        e.hold.lent(),
        e.lent.iter().map(|r| r.2).sum::<u32>(),
        "lent bytes drifted after settle"
    );
    pass_end(w, ni);
}

fn unlend(w: &mut World, li: usize, side: usize) {
    if let Some(e) = w.links[li].ends[side].as_mut() {
        e.hold.unlend();
        e.lent.clear();
    }
}

// ---------------------------------------------------------------------------------------------------- teardown

/// `Core::detach`: the session leaves the pool, its send queue is drained, held receive slots go back to the SRQ; the QP
/// is destroyed a little later (send slots and leases are released then, arrivals before are consumed and dropped).
fn detach(w: &mut World, li: usize, side: usize) {
    let ni = w.links[li].node[side];
    unlend(w, li, side);
    let Some(mut e) = w.links[li].ends[side].take() else {
        return;
    };
    w.links[li].dead[side] = true;
    let n = &mut w.nodes[ni];
    let credits = n.pool.remove(e.sid);
    n.tx.forget(w.links[li].key[side], &e.s);
    let key = w.links[li].key[side];
    n.waitq.retain(|&k| k != key);
    let (mut slots, mut leases) = (Vec::new(), Vec::new());
    e.s.sq.drain(|s| slots.push(s), |b| leases.push(b));
    {
        let nslot = &mut n.slot;
        let rq = &mut n.rq;
        e.hold.drain(|slot, lent| {
            assert!(!lent);
            nslot[slot as usize].st = St::Rq;
            rq.push(slot);
        });
    }
    post_recvs(n);
    n.zombie_tx_slots += slots.len();
    for c in &e.pending {
        if c.zc && !e.leases.iter().any(|x| x.0 == c.id) {
            w.leases[c.id].retired = true; // never referenced by a WR
        }
    }
    let at = w.now + w.rng.below(30);
    n.destroy.push(Destroy {
        link: li,
        side,
        slots,
        credits,
        leases,
        lease_ids: e.leases.iter().map(|x| x.0).collect(),
        stage: Stage::Err(at),
    });
    drop(e);
    process_log(w);
}

/// Teardown progress of the detached QPs (one stage per call; `force`: whatever is due later is due now).
fn destroy_due(w: &mut World, force: bool) {
    let now = w.now;
    for ni in 0..2 {
        let mut i = 0;
        while i < w.nodes[ni].destroy.len() {
            let due = |at: u64| force || at <= now;
            let (link, side) = (w.nodes[ni].destroy[i].link, w.nodes[ni].destroy[i].side);
            match w.nodes[ni].destroy[i].stage {
                Stage::Err(at) if due(at) => {
                    // ERR: the QP takes no SEND any more (its peer's packets are dropped)
                    w.links[link].destroyed[side] = true;
                    w.links[link].wire[side].clear();
                    // every completion it caused is in the CQ now; the event follows
                    w.nodes[ni].destroy[i].stage = Stage::Event(now + w.rng.below(10));
                }
                Stage::Event(at) if due(at) => w.nodes[ni].destroy[i].stage = Stage::Quiesced,
                Stage::Drained(at) if due(at) => {
                    let d = w.nodes[ni].destroy.swap_remove(i);
                    let n = &mut w.nodes[ni];
                    // the destroy drops the QP's completions still in the CQ (mlx5): their slots would be lost
                    let left =
                        n.cq.iter()
                            .filter(|c| c.li == link && c.side == side)
                            .count();
                    assert_eq!(
                        left, 0,
                        "node {ni}: link {link} side {side} destroyed with {left} completions in the CQ (slots lost)"
                    );
                    n.zombie_tx_slots -= d.slots.len();
                    for &s in &d.slots {
                        n.tx_owner[s as usize] = false;
                    }
                    n.tx.reclaim(&d.slots);
                    n.pool.release(d.credits);
                    w.stats.released += u64::from(d.credits);
                    for id in d.lease_ids {
                        w.leases[id].retired = true;
                    }
                    drop(d.leases);
                    process_log(w);
                    continue;
                }
                _ => {}
            }
            i += 1;
        }
    }
}

fn abort(w: &mut World, li: usize) {
    if w.links[li].done {
        return;
    }
    for side in 0..2 {
        detach(w, li, side);
    }
    w.links[li].done = true;
    w.links[li].closing = None;
    w.stats.aborts += 1;
}

/// The graceful close of `x` finished (its fence completed): the peer takes everything, then both ends go.
fn finish_close(w: &mut World, li: usize, x: usize) {
    let y = 1 - x;
    assert!(
        w.links[li].wire[y].iter().all(|m| m.data.is_empty()),
        "data SEND still in flight to the peer after the fence completed"
    );
    // the peer's poll loop works off the completions of the node (the fence proves the data landed, not that it was read)
    let ny = w.links[li].node[y];
    while let Some(c) = w.nodes[ny].cq.pop_front() {
        process(w, c);
    }
    unlend(w, li, y);
    resume(w, li, y, true);
    let (ex, ey) = (
        w.links[li].ends[x].as_ref().unwrap(),
        w.links[li].ends[y].as_ref().unwrap(),
    );
    assert!(
        ey.hold.is_empty(),
        "peer still holds slots after a forced resume"
    );
    assert_eq!(
        ey.rx_off, ex.taken,
        "peer received {} of {} bytes",
        ey.rx_off, ex.taken
    );
    assert_eq!(
        ex.want_left + ex.pending.iter().map(|c| c.b.len() as u64).sum::<u64>(),
        0
    );
    for side in 0..2 {
        detach(w, li, side);
    }
    w.links[li].done = true;
    w.links[li].closing = None;
    w.stats.graceful += 1;
}

/// Advance a closing link: finish the output, then the fence (`Core::fence`).
fn service_close(w: &mut World, li: usize) {
    let Some(x) = w.links[li].closing else {
        return;
    };
    let ni = w.links[li].node[x];
    let (idle, open, ev) = {
        let l = &w.links[li];
        let Some(e) = l.ends[x].as_ref() else {
            return;
        };
        (
            e.pending.is_empty() && e.want_left == 0,
            e.fence_open,
            e.writable_ev,
        )
    };
    if !idle {
        app_send(w, li, x);
        return;
    }
    if open && !ev {
        return;
    }
    let l = &mut w.links[li];
    let e = l.ends[x].as_mut().unwrap();
    e.writable_ev = false;
    let n = &mut w.nodes[ni];
    post_recvs(n); // `Core::fence`: the fence SEND returns owed credits, their slots are posted first
    match e.fence.step(&mut e.s.sq, n.pool.credits(e.sid)) {
        Step::Done => finish_close(w, li, x),
        Step::Pending => e.fence_open = true,
        Step::Blocked => {
            e.s.blocked = true;
            e.fence_open = true;
        }
        Step::Post { seq, imm } => {
            e.fence_open = true;
            e.wrs.push_back((seq, NO_SLOT));
            if w.fail_posts && w.rng.chance(1, 500) {
                w.abort_q.push(li);
                return;
            }
            l.wire[1 - x].push_back(Msg {
                imm,
                data: Vec::new(),
                seq,
                signal: true,
            });
        }
    }
}

// ------------------------------------------------------------------------------------------------------ sessions

fn new_session(w: &mut World) {
    let li = w.links.len();
    let swap = w.rng.chance(1, 2);
    let node = if swap { [1, 0] } else { [0, 1] };
    let key = [li as u32 * 2, li as u32 * 2 + 1];
    let Some(a) = w.nodes[node[0]].pool.admit(key[0], MIN_WINDOW) else {
        w.stats.admits_refused += 1;
        return;
    };
    let Some(b) = w.nodes[node[1]].pool.admit(key[1], MIN_WINDOW) else {
        // no QP was attached: nothing can land, the credits are free at once
        let p = &mut w.nodes[node[0]].pool;
        let r = p.remove(a);
        p.release(r);
        w.stats.admits_refused += 1;
        return;
    };
    let slot = w.nodes[0].cfg.slot.min(w.nodes[1].cfg.slot);
    let cfgs = [w.nodes[node[0]].cfg, w.nodes[node[1]].cfg];
    let mut mk = |c: NodeCfg, sid: Sid| End {
        sid,
        s: Sender::new(c.sq_depth, slot, c.inline, c.max_sge),
        hold: Hold::new(c.max_window),
        fence: Fence::default(),
        pending: VecDeque::new(),
        want_left: w
            .rng
            .below(u64::from(slot) * if w.churn { 400 } else { 30 }),
        gen_off: 0,
        taken: 0,
        rx_off: 0,
        app_wait: false,
        writable_ev: false,
        lent: VecDeque::new(),
        wrs: VecDeque::new(),
        leases: Vec::new(),
        used: 0,
        fence_open: false,
    };
    let ends = [Some(mk(cfgs[0], a)), Some(mk(cfgs[1], b))];
    w.links.push(Link {
        node,
        key,
        ends,
        wire: Default::default(),
        comps: Default::default(),
        dead: [false; 2],
        destroyed: [false; 2],
        closing: None,
        done: false,
    });
    w.stats.sessions += 1;
}

fn live_ends(w: &World) -> Vec<(usize, usize)> {
    let mut v = Vec::new();
    for (li, l) in w.links.iter().enumerate() {
        if !l.done {
            v.push((li, 0));
            v.push((li, 1));
        }
    }
    v
}

// --------------------------------------------------------------------------------------------------------- checks

fn check(w: &mut World) {
    for ni in 0..2 {
        let held: u32 = w
            .links
            .iter()
            .flat_map(|l| {
                (0..2)
                    .filter(move |&s| l.node[s] == ni)
                    .map(move |s| l.ends[s].as_ref())
            })
            .flatten()
            .map(|e| e.used)
            .sum();
        let n = &mut w.nodes[ni];
        let depth = n.cfg.depth;
        assert!(
            n.pool.granted() <= depth,
            "overcommit: granted {} > depth {depth}",
            n.pool.granted()
        );
        let mut sum = 0;
        for (k, g, e) in n.pool.sessions_iter() {
            assert!(
                e >= MIN_WINDOW && g >= e && g <= n.cfg.max_window,
                "session {k}: granted {g} effective {e} (window ceiling {})",
                n.cfg.max_window
            );
            sum += g;
        }
        assert_eq!(
            sum + n.pool.reserved(),
            n.pool.granted(),
            "pool sum drifted"
        );
        let pending: u32 = n.destroy.iter().map(|d| d.credits).sum();
        assert_eq!(
            n.pool.reserved(),
            pending,
            "reserved credits vs detached QPs not destroyed yet"
        );
        w.stats.max_granted = w.stats.max_granted.max(sum);
        let (mut posted, mut rq, mut used) = (0, 0, 0);
        for s in &n.slot {
            match s.st {
                St::Posted => posted += 1,
                St::Rq => rq += 1,
                St::Used(_) => used += 1,
            }
        }
        assert_eq!(
            (posted, rq),
            (n.posted.len() as u32, n.rq.len() as u32),
            "slot state vs lists"
        );
        assert_eq!(posted + rq + used, depth);
        let orphans = n.cq.iter().filter(|c| w.links[c.li].dead[c.side]).count() as u32;
        assert_eq!(used, held + orphans, "Used slots vs ends");
        // send slots: free + owned by outstanding WRs (live ends and zombies)
        let owned = n.tx_owner.iter().filter(|&&b| b).count();
        assert_eq!(
            n.tx.free() + owned,
            n.cfg.tx_slots as usize,
            "send slots leaked or doubled"
        );
    }
    // Every SEND on the wire to a QP that is not destroyed, and every credit a live peer may still spend (its avail and
    // the credits returned to it on the wire or in its CQ), lands in a posted slot: no credit is lent for a slot a
    // detached-but-not-destroyed QP can consume.
    for ni in 0..2 {
        let mut need = 0u32;
        for (li, l) in w.links.iter().enumerate() {
            for s in (0..2).filter(|&s| l.node[s] == ni && !l.destroyed[s]) {
                need += l.wire[s].len() as u32;
                let p = 1 - s;
                let Some(ep) = l.ends[p].as_ref().filter(|_| !l.dead[p]) else {
                    continue;
                };
                let np = &mut w.nodes[l.node[p]];
                let back = l.wire[p]
                    .iter()
                    .map(|m| m.imm)
                    .chain(
                        np.cq
                            .iter()
                            .filter(|c| c.li == li && c.side == p)
                            .map(|c| c.imm),
                    )
                    .map(|i| match Imm::decode(i) {
                        Some(Imm::Credits(c)) => c,
                        _ => 0,
                    })
                    .sum::<u32>();
                need += np.pool.credits(ep.sid).avail() + back;
            }
        }
        let n = &w.nodes[ni];
        assert!(
            need <= n.posted.len() as u32,
            "step {}: node {ni}: {need} SENDs in flight or spendable credits, {} posted slots (reserved {}, teardowns {})",
            w.now,
            n.posted.len(),
            n.pool.reserved(),
            n.destroy.len()
        );
    }
    for li in 0..w.links.len() {
        let l = &w.links[li];
        if l.dead[0] || l.dead[1] || l.ends[0].is_none() || l.ends[1].is_none() {
            continue;
        }
        for s in 0..2 {
            let r = 1 - s;
            // SENDs towards a side: on the wire, or landed (CQ) and not applied yet
            let imms = |to: usize| -> Vec<u32> {
                let mut v: Vec<u32> = l.wire[to].iter().map(|m| m.imm).collect();
                v.extend(
                    w.nodes[l.node[to]]
                        .cq
                        .iter()
                        .filter(|c| c.li == li && c.side == to)
                        .map(|c| c.imm),
                );
                v
            };
            let (to_s, to_r) = (imms(s), imms(r));
            let credits_back: u32 = to_s
                .iter()
                .map(|&i| match Imm::decode(i) {
                    Some(Imm::Credits(c)) => c,
                    _ => 0,
                })
                .sum();
            let (es, er) = (l.ends[s].as_ref().unwrap(), l.ends[r].as_ref().unwrap());
            let (ns, nr) = (l.node[s], l.node[r]);
            let avail = w.nodes[ns].pool.credits(es.sid).avail();
            let (granted, owed) = {
                let c = w.nodes[nr].pool.credits(er.sid);
                (c.granted(), c.owed())
            };
            let lhs = avail + l.wire[r].len() as u32 + er.used + owed + credits_back;
            let surr: u32 = to_r
                .iter()
                .map(|&i| match Imm::decode(i) {
                    Some(Imm::Surrender(k)) => k,
                    _ => 0,
                })
                .sum();
            let ans = w.nodes[ns].pool.credits(es.sid).answer_k();
            assert_eq!(
                lhs + surr + ans,
                granted,
                "step {}: link {li} dir {s}->{r}: credits leaked: avail {avail} in flight {} used {} owed {owed} returned {credits_back} surrender {surr} answer {ans} vs granted {granted}",
                w.now,
                l.wire[r].len(),
                er.used
            );
        }
    }
}

// ----------------------------------------------------------------------------------------------------- the schedule

fn step(w: &mut World, drain: bool) {
    w.now += 1;
    let ends = live_ends(w);
    let ni = w.rng.below(2) as usize;
    let pick = |w: &mut World, v: &[(usize, usize)]| -> Option<(usize, usize)> {
        (!v.is_empty()).then(|| v[w.rng.below(v.len() as u64) as usize])
    };
    let op = w.rng.below(100);
    match op {
        0..=17 => poll(w, ni),
        18..=24 => {
            let k = 1 + w.rng.below(6) as usize;
            nic(w, ni, k);
        }
        25..=39 => {
            if let Some((li, s)) = pick(w, &ends) {
                app_send(w, li, s);
            }
        }
        40..=42 => {
            if let Some((li, s)) = pick(w, &ends)
                && !drain
                && w.links[li].closing != Some(s)
            {
                let more = 1 + w.rng.below(5000);
                if let Some(e) = w.links[li].ends[s].as_mut() {
                    e.want_left += more;
                }
            }
        }
        43..=46 => {
            w.nodes[ni].pool.tick(|_| {});
            pass_end(w, ni);
        }
        47..=51 => {
            if !drain
                && let Some((li, s)) = pick(w, &ends)
                && let Some(e) = w.links[li].ends[s].as_mut()
            {
                e.hold.pause();
            }
        }
        52..=59 => {
            if let Some((li, s)) = pick(w, &ends) {
                resume(w, li, s, drain);
            }
        }
        60..=65 => {
            if !drain && let Some((li, s)) = pick(w, &ends) {
                lend(w, li, s);
            }
        }
        66..=72 => {
            if let Some((li, s)) = pick(w, &ends) {
                settle(w, li, s);
            }
        }
        73..=74 => {
            if let Some((li, s)) = pick(w, &ends) {
                unlend(w, li, s);
            }
        }
        75..=77 => {
            if !drain {
                new_session(w);
            }
        }
        78 => {
            if let Some((li, s)) = pick(w, &ends)
                && w.links[li].closing.is_none()
            {
                w.links[li].closing = Some(s);
            }
        }
        79 => {
            if !drain
                && (w.churn || w.rng.chance(1, 3))
                && let Some((li, _)) = pick(w, &ends)
            {
                abort(w, li);
                if w.churn {
                    new_session(w);
                }
            }
        }
        _ => poll(w, ni),
    }
    for li in 0..w.links.len() {
        if w.links[li].closing.is_some() && !w.links[li].done {
            service_close(w, li);
        }
    }
    while let Some(li) = w.abort_q.pop() {
        abort(w, li);
    }
    destroy_due(w, false);
    check(w);
}

/// Finish: everything resumes, no new input, every session closes gracefully; bounded.
fn drain_all(w: &mut World, limit: u64) {
    for li in 0..w.links.len() {
        if !w.links[li].done {
            for s in 0..2 {
                unlend(w, li, s);
                resume(w, li, s, true);
            }
            if w.links[li].closing.is_none() {
                w.links[li].closing = Some(w.rng.below(2) as usize);
            }
        }
    }
    for i in 0..limit {
        step(w, true);
        if i % 4 == 0 {
            for li in 0..w.links.len() {
                if !w.links[li].done {
                    for s in 0..2 {
                        unlend(w, li, s);
                        resume(w, li, s, true);
                    }
                }
            }
        }
        if w.links.iter().all(|l| l.done) && w.nodes.iter().all(|n| n.destroy.is_empty()) {
            return;
        }
    }
    let mut why = String::new();
    for (li, l) in w.links.iter().enumerate().filter(|(_, l)| !l.done) {
        for s in 0..2 {
            if let Some(e) = &l.ends[s] {
                let c = w.nodes[l.node[s]].pool.credits(e.sid);
                why += &format!(
                    "\n link {li} side {s} closing {:?}: want {} pending {} app_wait {} sq out {} fence_open {} held {} paused {} avail {} granted {} owed {} rx_off {} taken {} wire_in {} comps {}",
                    l.closing,
                    e.want_left,
                    e.pending.len(),
                    e.app_wait,
                    e.s.sq.outstanding(),
                    e.fence_open,
                    e.hold.len(),
                    e.hold.paused(),
                    c.avail(),
                    c.granted(),
                    c.owed(),
                    e.rx_off,
                    e.taken,
                    l.wire[s].len(),
                    l.comps[s].len()
                );
            }
        }
    }
    panic!("no progress: sessions did not finish in {limit} drain steps (deadlock){why}");
}

fn final_checks(w: &mut World) {
    for ni in 0..2 {
        while let Some(c) = w.nodes[ni].cq.pop_front() {
            process(w, c);
        }
        pass_end(w, ni);
    }
    // every teardown stage, each followed by a drained CQ
    for _ in 0..4 {
        destroy_due(w, true);
        for ni in 0..2 {
            while let Some(c) = w.nodes[ni].cq.pop_front() {
                process(w, c);
            }
            pass_end(w, ni);
            cq_drained(w, ni);
        }
    }
    assert!(
        w.nodes.iter().all(|n| n.destroy.is_empty()),
        "teardowns left"
    );
    check(w);
    for (ni, n) in w.nodes.iter().enumerate() {
        assert_eq!(n.pool.sessions(), 0, "node {ni}: sessions left");
        assert_eq!(
            n.pool.granted(),
            0,
            "node {ni}: credits did not return to the pool"
        );
        assert_eq!(n.rq.len(), 0);
        assert_eq!(
            n.posted.len() as u32,
            n.cfg.depth,
            "node {ni}: receive slots lost"
        );
        assert_eq!(
            n.tx.free() as u32,
            n.cfg.tx_slots,
            "node {ni}: send slots lost"
        );
        assert_eq!(n.zombie_tx_slots, 0);
    }
    for (id, r) in w.leases.iter().enumerate() {
        assert!(r.dropped, "lease {id} never released");
    }
}

fn run_world(seed: u64, steps: u64, churn: bool) -> Stats {
    let mut w = World::new(seed, churn);
    for _ in 0..if churn { 12 } else { 2 } {
        new_session(&mut w);
    }
    for _ in 0..steps {
        step(&mut w, false);
    }
    drain_all(&mut w, 400_000);
    final_checks(&mut w);
    w.stats.cov[5] = w.nodes.iter().map(|n| n.pool.stats.grants_demand).sum();
    w.stats
}

// ----------------------------------------------------------------------------------------------------- the harness

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Run `f(seed)` for many seeds on all cores; the failing seed is printed first.
fn for_seeds(name: &str, f: impl Fn(u64) + Sync) {
    let seeds = env_u64("RDMA_MODEL_SEEDS", 40);
    let seed0 = env_u64("RDMA_MODEL_SEED0", 0);
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(16) as u64;
    let next = std::sync::atomic::AtomicU64::new(0);
    let failed = std::sync::atomic::AtomicBool::new(false);
    let t0 = std::time::Instant::now();
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= seeds || failed.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    let seed = seed0 + i;
                    if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(seed))) {
                        failed.store(true, std::sync::atomic::Ordering::Relaxed);
                        eprintln!("FAILING SEED {name} {seed} (RDMA_MODEL_SEEDS=1 RDMA_MODEL_SEED0={seed})");
                        std::panic::resume_unwind(e);
                    }
                }
            });
        }
    });
    eprintln!(
        "{name}: {seeds} seeds from {seed0} in {:.1}s",
        t0.elapsed().as_secs_f64()
    );
}

/// Mixed configurations, all operations.
#[test]
fn sessions_fuzz_two_cores() {
    property("sessions_fuzz_two_cores", false);
}

/// Small pools, big windows, sessions aborted and replaced all the time (SRQ reuse while the dead one's SENDs land).
#[test]
fn sessions_fuzz_churn() {
    property("sessions_fuzz_churn", true);
}

fn property(name: &str, churn: bool) {
    let steps = env_u64("RDMA_MODEL_STEPS", 3000);
    let total = Mutex::new(Stats::default());
    for_seeds(name, |seed| {
        let s = run_world(seed, steps, churn);
        let mut t = total.lock().unwrap();
        t.sessions += s.sessions;
        t.graceful += s.graceful;
        t.aborts += s.aborts;
        t.sends += s.sends;
        t.bytes += s.bytes;
        t.resumes += s.resumes;
        t.lends += s.lends;
        t.fails += s.fails;
        t.admits_refused += s.admits_refused;
        t.zombie_arrivals += s.zombie_arrivals;
        t.released += s.released;
        for i in 0..6 {
            t.cov[i] += s.cov[i];
        }
        t.max_granted = t.max_granted.max(s.max_granted);
    });
    let t = total.lock().unwrap();
    eprintln!(
        "coverage: revoke {} surrender {} stalls credits {} queue {} slots {} demand grants {} credits released after drain + destroy {}",
        t.cov[0], t.cov[1], t.cov[2], t.cov[3], t.cov[4], t.cov[5], t.released
    );
    eprintln!(
        "sessions {} graceful {} aborts {} sends {} bytes {} resumes {} lends {} failed posts {} refused {} zombie arrivals {} max granted {}",
        t.sessions,
        t.graceful,
        t.aborts,
        t.sends,
        t.bytes,
        t.resumes,
        t.lends,
        t.fails,
        t.admits_refused,
        t.zombie_arrivals,
        t.max_granted
    );
}

/// Fairness: sessions that all want more than their share get the same window (max-min fair), none is starved below the
/// minimum, and the pool never lends more than the depth.
#[test]
fn saturated_sessions_share_the_pool_fairly() {
    let seeds = (env_u64("RDMA_MODEL_SEEDS", 40) / 20 + 1).min(400);
    for seed in 0..seeds {
        let mut rng = Rng::new(seed ^ 0xFA1B);
        let depth = rng.pick(&[48u32, 96, 200]);
        let max_window = rng.pick(&[16u32, 64]);
        let n = 2 + rng.below(10) as usize;
        let c = NodeCfg {
            depth,
            max_window,
            tx_slots: 64,
            sq_depth: 256,
            slot: 256,
            inline: 0,
            max_sge: 1,
        };
        let mut w = World::with_cfg(rng, [c, c], false);
        w.plain = true;
        w.fail_posts = false;
        for _ in 0..n {
            new_session(&mut w);
        }
        for l in &mut w.links {
            for e in l.ends.iter_mut().flatten() {
                e.want_left = u64::MAX / 4;
            }
        }
        let live = w.links.len();
        let mut sums = [[0u64; 16]; 2];
        let mut samples = 0u64;
        for i in 0..90_000 {
            w.now += 1;
            for ni in 0..2 {
                poll(&mut w, ni);
            }
            for li in 0..live {
                for s in 0..2 {
                    app_send(&mut w, li, s);
                }
            }
            if i % 300 == 0 {
                for (ni, acc) in sums.iter_mut().enumerate() {
                    w.nodes[ni].pool.tick(|_| {});
                    pass_end(&mut w, ni);
                    if i >= 60_000 {
                        // the windows jitter with the per-tick arrival counts: judge their mean over the last ticks
                        for (k, (_, _, e)) in w.nodes[ni].pool.sessions_iter().enumerate() {
                            acc[k] += u64::from(e);
                        }
                    }
                }
                samples += u64::from(i >= 60_000);
            }
            if i % 100 == 0 {
                check(&mut w);
            }
        }
        for (ni, acc) in sums.iter().enumerate() {
            let a: Vec<f64> = acc[..live]
                .iter()
                .map(|&s| s as f64 / samples as f64)
                .collect();
            let (lo, hi) = (
                a.iter().cloned().fold(f64::MAX, f64::min),
                a.iter().cloned().fold(0.0, f64::max),
            );
            eprintln!(
                "seed {seed} node {ni}: {live} sessions depth {depth} ceiling {max_window}: mean windows {a:.1?}"
            );
            assert!(lo >= f64::from(MIN_WINDOW));
            assert!(
                hi - lo <= (0.1 * hi).max(2.0),
                "seed {seed} node {ni}: unfair mean windows {a:.1?}"
            );
        }
    }
}

static HOSTILE_OK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A hostile peer: arbitrary immediates (valid and invalid kinds, huge counts, unsolicited control) against a pool whose
/// local side behaves. A violation must be an `Err` (session fault), never a panic or an accounting drift.
#[test]
fn hostile_immediates_never_panic_or_drift() {
    let steps = env_u64("RDMA_MODEL_STEPS", 3000);
    for_seeds("hostile_immediates", |seed| {
        let mut rng = Rng::new(seed ^ 0x0405_711E);
        let depth = rng.pick(&[6u32, 12, 48, 200]);
        let max_window = rng.pick(&[3u32, 8, 64]);
        let mut pool = Pool::new(GrantCfg {
            depth,
            max_window,
            max_sessions: 32,
        });
        // (sid, key, slots consumed and not re-posted yet)
        let mut sess: Vec<(Sid, u32, u32)> = Vec::new();
        // credits of removed sessions whose QP is not destroyed yet
        let mut reserved: Vec<u32> = Vec::new();
        let mut next_key = 0;
        for _ in 0..steps {
            match rng.below(10) {
                0 => {
                    if let Some(sid) = pool.admit(next_key, rng.pick(&[3u32, 5, 64, 1 << 16])) {
                        sess.push((sid, next_key, 0));
                    }
                    next_key += 1;
                }
                1 if !sess.is_empty() => {
                    let (sid, ..) = sess.swap_remove(rng.below(sess.len() as u64) as usize);
                    reserved.push(pool.remove(sid));
                }
                9 if !reserved.is_empty() => {
                    pool.release(reserved.swap_remove(rng.below(reserved.len() as u64) as usize));
                }
                2..=5 if !sess.is_empty() => {
                    let i = rng.below(sess.len() as u64) as usize;
                    let kind = [0u32, 0, 0, 0, 0, 0, 0, 1, 2, 3][rng.below(10) as usize];
                    let count = match if kind == 0 && rng.chance(4, 5) {
                        2
                    } else {
                        rng.below(5)
                    } {
                        0 => 0,
                        1 => 1,
                        2 => rng.below(8) as u32,
                        3 => rng.below(1 << 17) as u32,
                        _ => (1 << 30) - 1,
                    };
                    // kind 3 and a stray high bit pattern are invalid kinds
                    let imm = (kind << 30) | count;
                    match pool.on_recv(sess[i].0, imm, rng.chance(1, 2)) {
                        Ok(_) => {
                            sess[i].2 += 1;
                            HOSTILE_OK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        Err(_) => {
                            // a fault detaches the session
                            let (sid, ..) = sess.swap_remove(i);
                            reserved.push(pool.remove(sid));
                        }
                    }
                }
                6 | 7 if !sess.is_empty() => {
                    let i = rng.below(sess.len() as u64) as usize;
                    if sess[i].2 > 0 {
                        sess[i].2 -= 1;
                        pool.on_reposted(sess[i].0);
                    }
                    while pool.next_send(sess[i].0).is_some() && rng.chance(3, 4) {}
                }
                8 => pool.tick(|_| {}),
                _ => {}
            }
            let mut sum = 0;
            for (_, g, e) in pool.sessions_iter() {
                assert!(e >= MIN_WINDOW && g >= e, "granted {g} effective {e}");
                sum += g;
            }
            assert_eq!(sum + pool.reserved(), pool.granted());
            assert_eq!(pool.reserved(), reserved.iter().sum::<u32>());
            assert!(
                pool.granted() <= depth,
                "overcommit {} > {depth}",
                pool.granted()
            );
            assert_eq!(pool.sessions(), sess.len());
        }
    });
    eprintln!(
        "hostile immediates accepted: {}",
        HOSTILE_OK.load(std::sync::atomic::Ordering::Relaxed)
    );
}

/// Handover records: arbitrary and mutated bytes never panic; whatever decodes is valid and round-trips.
#[test]
fn endpoint_decode_fuzz() {
    use rdma::{Endpoint, MIN_SLOT, credit};
    let good = Endpoint {
        qpn: 0x12_3456,
        psn: 0xFF_FFFF,
        gid: [7; 16],
        window: 64,
        slot: 65536,
        mtu: 4096,
        reads: None,
    };
    let n = env_u64("RDMA_MODEL_SEEDS", 40) * 5_000;
    let mut rng = Rng::new(0xE0D);
    let (mut ok, mut rejected) = (0u64, 0u64);
    for i in 0..n {
        let mut b: Vec<u8> = match i % 4 {
            0 => (0..rng.below(64)).map(|_| rng.next() as u8).collect(),
            1 => good.encode(),
            2 => (0..Endpoint::LEN).map(|_| rng.next() as u8).collect(),
            _ => {
                let mut v = good.encode();
                v.extend((0..rng.below(8)).map(|_| rng.next() as u8));
                v
            }
        };
        if i % 4 != 0 {
            for _ in 0..rng.below(4) {
                let at = rng.below(b.len() as u64) as usize;
                b[at] = match rng.below(4) {
                    0 => 0,
                    1 => 0xFF,
                    2 => b[at] ^ (1 << rng.below(8)),
                    _ => rng.next() as u8,
                };
            }
        }
        match Endpoint::decode(&b) {
            Some(e) => {
                ok += 1;
                assert!(b.len() >= Endpoint::MIN_LEN);
                assert!(e.qpn < 1 << 24 && e.psn < 1 << 24, "24-bit fields: {e:?}");
                assert!((credit::MIN_WINDOW..=credit::MAX_PEER_WINDOW).contains(&e.window));
                assert!(e.slot >= MIN_SLOT);
                assert_eq!(Endpoint::decode(&e.encode()), Some(e));
                assert_eq!(
                    e.encode()[..Endpoint::MIN_LEN],
                    b[..Endpoint::MIN_LEN],
                    "decode must not normalize bytes"
                );
            }
            None => rejected += 1,
        }
    }
    eprintln!("endpoint decode fuzz: {n} inputs, {ok} accepted, {rejected} rejected");
    assert!(ok > 0 && rejected > 0);
}

/// `budget::size`: any budget either errors (below the minimum) or gives arenas that fit it, a window between the
/// line-rate window and the ceiling, with room for the minimum number of sessions at that window.
#[test]
fn budget_sizing_fuzz() {
    use rdma::budget::{MIN_CONNECTIONS, MIN_TX_WINDOWS, min_bytes, size};
    let mut rng = Rng::new(0xB0D6E7);
    for _ in 0..200_000 {
        let slot = rng.pick(&[4096u32, 8192, 65536, 1 << 20]);
        let bytes = match rng.below(3) {
            0 => rng.below(1 << 30),
            1 => rng.below(10 * min_bytes(slot) + 1),
            _ => rng.next() >> rng.below(40),
        };
        let ceiling = rng.pick(&[3u32, 16, 64, 1000]);
        match size(bytes, slot, ceiling) {
            Ok(z) => {
                assert!(bytes >= min_bytes(slot));
                assert!(
                    (u64::from(z.rx) + u64::from(z.tx)) * u64::from(slot) <= bytes.max(1)
                        || z.rx == u32::MAX
                );
                assert!(z.window <= ceiling);
                assert!(z.window >= ceiling.min(rdma::LINE_RATE_WINDOW));
                assert!(u64::from(z.window) * u64::from(MIN_CONNECTIONS) <= u64::from(z.rx));
                assert!(z.tx >= MIN_TX_WINDOWS * rdma::LINE_RATE_WINDOW);
            }
            Err(e) => {
                assert!(
                    bytes < min_bytes(slot),
                    "refused {bytes} >= {}",
                    min_bytes(slot)
                );
                assert_eq!((e.have, e.need), (bytes, min_bytes(slot)));
            }
        }
    }
}

/// Send-queue sequence numbers wrap at 2^32: slots, leases, signals and `retired` keep working across the wrap. Long
/// (a few seconds in release): `cargo test --release -p rdma --test protocol_model -- --ignored`.
#[test]
#[ignore = "walks 2^32 work requests; run in release"]
fn send_queue_sequence_wraparound() {
    use rdma::ring::SendQueue;
    let depth = 128u32;
    let mut sq = SendQueue::new(depth);
    let mut rng = Rng::new(0x57A9);
    let total: u64 = (1 << 32) + 1_000_000;
    let mut posted = 0u64;
    let mut last_signal_seq = None;
    let (mut freed, mut expect_freed) = (0u64, 0u64);
    while posted < total {
        let n = 1 + rng.below(u64::from(depth / 2)) as u32;
        let n = n.min(sq.room());
        for k in 0..n {
            let slot = if rng.chance(1, 2) {
                (posted % 1000) as u32
            } else {
                NO_SLOT
            };
            let (seq, sig) = sq.push(slot, k == n - 1);
            if slot != NO_SLOT {
                expect_freed += 1;
            }
            if sig {
                last_signal_seq = Some(seq);
            }
            assert!(!sq.retired(seq), "a posted WR is not retired");
            posted += 1;
        }
        assert!(sq.covered(), "no slot holder behind the last signal");
        // the HCA completes the last signaled WR (retires everything before it)
        if let Some(seq) = last_signal_seq.take() {
            sq.complete(seq, |_| freed += 1);
            assert!(sq.retired(seq));
        }
        assert_eq!(sq.outstanding(), sq.outstanding().min(depth));
        if sq.room() < depth / 2 {
            let last = sq.outstanding();
            let _ = last;
            // retire all: a signaled WR is guaranteed within a half depth
        }
    }
    sq.drain(|_| freed += 1, |_| {});
    assert_eq!(
        freed, expect_freed,
        "every slot came back exactly once across {posted} WRs"
    );
}

/// Regression: seed 3144 of `sessions_fuzz_two_cores` (3000 steps). Both sides of a session sent a REVOKE at once, both
/// answered with their last credit (SURRENDER used the reserved one), both ended at 0 credits owing each other credits: no
/// SEND could return them (`credit::Credits::want_control` now needs a spare credit).
#[test]
fn regression_crossing_revokes_seed_3144() {
    run_world(3144, 3000, false);
}

/// Regression: seed 9367 of `sessions_fuzz_two_cores` (3000 steps). A lazy shrink left the grant at 19 with an effective
/// window of 3; the credit-only threshold followed the grant (9), the peer sat at its reserved credit and the 2 owed
/// credits never went out.
#[test]
fn regression_credit_threshold_follows_the_effective_window_seed_9367() {
    run_world(9367, 3000, false);
}
