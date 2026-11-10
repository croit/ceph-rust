// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Control thread (0469-rdma-transport): verbs control calls (QP create, modify, destroy; 0.6-1.2 ms blocking ioctls
//! each) never run on a data-path core. One thread per process serves every core through a pair of bounded lock-free
//! SPSC queues per core. It keeps a pool of pre-created INIT QPs per core, refilled in the background; a core asks for
//! one ([`CoreLink::prepare`]), connects it ([`CoreLink::connect`]) and hands it back for teardown
//! ([`CoreLink::quiesce`], then [`CoreLink::destroy`]). Every request gets exactly one [`Reply`], so a core bounds its in-flight requests to the
//! queue capacity and neither queue can overflow. Replies are signalled with the caller's wake function (an eventfd
//! write, a knet `Wake` poke). An empty pool never blocks a core: the request waits and is answered when a QP exists.
//!
//! Teardown of a QP on a core's SRQ (provider independent; mlx5 drops the completions of a destroyed QP still in the CQ,
//! so the receive slots they consumed would never be posted again): [`CoreLink::quiesce`] moves it to ERR and answers
//! [`Reply::Quiesced`] when its `IBV_EVENT_QP_LAST_WQE_REACHED` came (every completion it causes is in the CQ then); the
//! core drains its CQ (`Core::quiesced` / `Core::drained`), then [`CoreLink::destroy`]; what it held (send slots,
//! receive credits) is released only after that. The event is state, not an edge: a QP raises it once, when it enters ERR,
//! which may be long before its teardown asks (retry exceeded, a forced error; the teardown's own move to ERR is then ERR
//! to ERR and raises none). An event nobody waits for yet is kept per QP number until that QP's quiesce (answered at
//! once) or its destroy (forgotten: the async thread acknowledges an event only after reporting it and a destroy waits for
//! the acknowledgements, so a later QP with the same number never inherits it). An event that does not come within
//! [`QP_DRAIN_LIMIT`] is loud (`WARNING TIMEOUT`, [`qp_drain_timeouts`]): the QP is never destroyed and what it held
//! never released (a leak).
//!
//! A prepare is refused ([`Reply::Failed`], the connection stays TCP) while [`Backend::ready`] reports the device unable
//! to connect (the local RoCEv2 GID is not on the port: address removed); the GID index is looked up again at every
//! connect, so new sessions upgrade again once the address is back.
//!
//! The queue and pool state machine ([`Engine`]) is generic over [`Backend`] and runs without hardware; feature
//! `verbs` adds the libibverbs backend ([`VerbsBackend`], [`start_verbs`]).
use crate::{Endpoint, Release};
use spsc::{Consumer, Producer, channel};
use std::collections::{HashSet, VecDeque};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle, Thread};
use std::time::{Duration, Instant};

/// Bound of the wait for a QP's last-WQE event after its move to ERR ([`CoreLink::quiesce`]). Both are device-local (no
/// peer round trip): milliseconds on a working device; beyond this the device or provider does not deliver the event.
pub const QP_DRAIN_LIMIT: Duration = Duration::from_secs(10);

static QP_DRAIN_TIMEOUTS: AtomicU64 = AtomicU64::new(0);

/// QPs whose last-WQE event did not come within [`QP_DRAIN_LIMIT`] in this process: never destroyed, what they held
/// (send slots, receive credits) never released. Must stay 0.
pub fn qp_drain_timeouts() -> u64 {
    QP_DRAIN_TIMEOUTS.load(Ordering::Relaxed)
}

/// The verbs calls the control thread makes; `Qp` is the handle that travels between control thread and core.
pub trait Backend: Send + 'static {
    type Qp: Send + 'static;
    /// New QP in INIT for core `core`.
    fn create(&mut self, core: usize) -> io::Result<Self::Qp>;
    /// Our handover record of `qp`.
    fn endpoint(&self, core: usize, qp: &Self::Qp) -> Endpoint;
    /// Whether a QP could be connected now (the device's local address is usable); checked before a prepare is served.
    /// The backend logs a change of the answer, not each refusal.
    fn ready(&mut self) -> io::Result<()>;
    /// INIT -> RTR -> RTS towards `peer`.
    fn connect(&mut self, core: usize, qp: &Self::Qp, peer: &Endpoint) -> io::Result<()>;
    /// First teardown step: to ERR. `Ok(true)`: wait for its last-WQE event ([`Backend::last_wqe`]); `Ok(false)`: it
    /// never received (never connected), no event to wait for.
    fn quiesce(&mut self, qp: &mut Self::Qp) -> io::Result<bool>;
    fn qpn(&self, qp: &Self::Qp) -> u32;
    /// Append the QP numbers whose last-WQE event arrived since the last call.
    fn last_wqe(&mut self, out: &mut Vec<u32>);
    /// On the control thread before it serves requests; `control` is unparked when an async event arrives.
    fn start(&mut self, control: Thread);
    /// Consume a newly observed shared-resource failure. Wake all owning cores
    /// so even idle sessions can observe their backend's terminal state.
    fn take_fatal(&mut self) -> bool;
    /// Tear the QP down (to ERR, destroy).
    fn destroy(&mut self, qp: Self::Qp) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug)]
pub struct ControlCfg {
    /// Pre-created INIT QPs kept ready per core.
    pub pool_depth: u32,
    /// Capacity of each per-core queue (rounded up to a power of two) = most in-flight requests of one core.
    pub queue_depth: u32,
}

impl Default for ControlCfg {
    fn default() -> Self {
        ControlCfg {
            pool_depth: 8,
            queue_depth: 64,
        }
    }
}

/// Answer to one request; `tag` is the caller's token from the request.
#[derive(Debug)]
pub enum Reply<Q> {
    /// A pooled QP and its handover record.
    Prepared { tag: u64, qp: Q, endpoint: Endpoint },
    /// The QP is in RTS.
    Connected { tag: u64, qp: Q },
    /// Prepare, connect or destroy failed (logged on the control thread). A failed connect destroyed the QP; after a
    /// failed destroy what it held must be treated as lost (the HCA may still reference its send slots, its peer may
    /// still land SENDs in the receive slots its credits cover).
    Failed { tag: u64, error: String },
    /// The QP is in ERR and its last-WQE event came (or it never received): hand it to `Core::quiesced`; once the core
    /// drained its CQ (`Core::drained`), destroy it ([`CoreLink::destroy`]).
    Quiesced { tag: u64, qp: Q, held: Release },
    /// The connect failed after the QP may have reached RTR: the QP is quiesced like [`Reply::Quiesced`] (ERR, last-WQE
    /// event) and goes the same way (`Core::quiesced`, CQ drain, [`CoreLink::destroy`]); the connect is failed.
    ConnectFailed { tag: u64, error: String, qp: Q },
    /// The QP is gone: give what it held back with `Core::reclaim`.
    Destroyed { tag: u64, held: Release },
}

#[derive(Debug)]
enum Request<Q> {
    Prepare { tag: u64 },
    Connect { tag: u64, qp: Q, peer: Endpoint },
    Quiesce { tag: u64, qp: Q, held: Release },
    Destroy { tag: u64, qp: Q, held: Release },
    Retire { tag: u64 },
}

/// A request refused because the core already has [`ControlCfg::queue_depth`] requests in flight; carries the payload
/// back. Retry after draining replies with [`CoreLink::poll`].
#[derive(Debug)]
pub struct Full<T>(pub T);

/// One core's end of the control thread: submit requests, poll replies. Owned by the core; never blocks, locks or
/// allocates (a submit is a queue write plus a thread unpark, which is a syscall only while the thread sleeps).
#[derive(Debug)]
pub struct CoreLink<Q> {
    req: Producer<Request<Q>>,
    rep: Consumer<Reply<Q>>,
    thread: Thread,
    inflight: usize,
    cap: usize,
}

impl<Q> CoreLink<Q> {
    fn submit(&mut self, r: Request<Q>) -> Result<(), Request<Q>> {
        if self.inflight == self.cap {
            return Err(r);
        }
        self.req.push(r)?;
        self.inflight += 1;
        self.thread.unpark();
        Ok(())
    }

    /// Ask for a pooled QP; answered with [`Reply::Prepared`] or [`Reply::Failed`].
    pub fn prepare(&mut self, tag: u64) -> Result<(), Full<()>> {
        self.submit(Request::Prepare { tag }).map_err(|_| Full(()))
    }

    /// Connect `qp` to `peer`; answered with [`Reply::Connected`], [`Reply::ConnectFailed`] (the QP comes back quiesced
    /// for its drain and destroy) or [`Reply::Failed`] (its quiesce failed or timed out: kept by the control thread).
    pub fn connect(&mut self, tag: u64, qp: Q, peer: Endpoint) -> Result<(), Full<Q>> {
        match self.submit(Request::Connect { tag, qp, peer }) {
            Ok(()) => Ok(()),
            Err(Request::Connect { qp, .. }) => Err(Full(qp)),
            Err(_) => unreachable!("submit returns the request it was given"),
        }
    }

    /// Start the teardown of `qp` (detached, `Core::detach`, or never attached); `held` is what it holds of the core.
    /// Answered with [`Reply::Quiesced`] or [`Reply::Failed`] (move to ERR failed, or no last-WQE event within
    /// [`QP_DRAIN_LIMIT`]: the QP and `held` stay with the control thread for good).
    pub fn quiesce(&mut self, tag: u64, qp: Q, held: Release) -> Result<(), Full<(Q, Release)>> {
        match self.submit(Request::Quiesce { tag, qp, held }) {
            Ok(()) => Ok(()),
            Err(Request::Quiesce { qp, held, .. }) => Err(Full((qp, held))),
            Err(_) => unreachable!("submit returns the request it was given"),
        }
    }

    /// Destroy `qp` after the core drained its completions ([`Reply::Quiesced`], `Core::drained`). Answered with
    /// [`Reply::Destroyed`] (hand `held` to `Core::reclaim`) or [`Reply::Failed`].
    pub fn destroy(&mut self, tag: u64, qp: Q, held: Release) -> Result<(), Full<(Q, Release)>> {
        match self.submit(Request::Destroy { tag, qp, held }) {
            Ok(()) => Ok(()),
            Err(Request::Destroy { qp, held, .. }) => Err(Full((qp, held))),
            Err(_) => unreachable!("submit returns the request it was given"),
        }
    }

    /// The core is going away (its CQ/SRQ are destroyed next): the control thread destroys the pooled QPs of this core,
    /// refuses further prepares and answers with [`Reply::Destroyed`] (nothing held). Requests queued before it are served
    /// first.
    pub fn retire(&mut self, tag: u64) -> Result<(), Full<()>> {
        self.submit(Request::Retire { tag }).map_err(|_| Full(()))
    }

    /// Next reply, if any. Call until `None` after a wake.
    pub fn poll(&mut self) -> Option<Reply<Q>> {
        let r = self.rep.pop()?;
        self.inflight -= 1;
        Some(r)
    }
}

#[derive(Debug)]
struct CoreState<Q> {
    req: Consumer<Request<Q>>,
    rep: Producer<Reply<Q>>,
    /// Ready INIT QPs.
    pool: Vec<Q>,
    /// Prepare requests waiting for a QP, oldest first.
    waiters: VecDeque<u64>,
    /// A refill create failed: stop refilling until the core asks again (a failing device is not hammered).
    refill_failed: bool,
    /// The core retired: no pool, no creates for it.
    retired: bool,
    /// Replies queued since the last wake.
    unsignaled: bool,
}

/// A QP in ERR waiting for its last-WQE event.
#[derive(Debug)]
struct Quiescing<Q> {
    core: usize,
    tag: u64,
    qpn: u32,
    qp: Q,
    held: Release,
    since: Instant,
    /// A failed connect: answered with [`Reply::ConnectFailed`].
    failed: Option<String>,
}

/// The pool and queue state machine; the control thread runs [`Engine::step`] in a loop.
#[derive(Debug)]
struct Engine<B: Backend, W> {
    backend: B,
    cores: Vec<CoreState<B::Qp>>,
    pool_depth: usize,
    wake: W,
    /// Round-robin start for the next create.
    next: usize,
    quiescing: Vec<Quiescing<B::Qp>>,
    /// QPs whose quiesce failed or timed out, by core: never destroyed while the core runs, what they held never
    /// released.
    stuck: Vec<(usize, B::Qp, Release)>,
    /// Last-WQE events read from the backend (scratch).
    events: Vec<u32>,
    /// Last-WQE events of QPs nobody waited for yet, by QP number: kept until the QP's quiesce or destroy. Bounded by the
    /// QPs of the device.
    early: HashSet<u32>,
    drain_limit: Duration,
}

impl<B: Backend, W: Fn(usize)> Engine<B, W> {
    fn reply(&mut self, core: usize, r: Reply<B::Qp>) {
        let c = &mut self.cores[core];
        // cannot fail: each request produces one reply and a core keeps at most `cap` requests in flight
        if c.rep.push(r).is_err() {
            diag::diag!("rdma control: core {core} reply queue overflow, reply dropped (bug)");
        }
        c.unsignaled = true;
    }

    fn fail(&mut self, core: usize, tag: u64, op: &str, e: &io::Error) {
        diag::diag!("rdma control: {op} failed (core {core}, tag {tag}): {e}");
        self.reply(
            core,
            Reply::Failed {
                tag,
                error: format!("{op}: {e}"),
            },
        );
    }

    fn prepared(&mut self, core: usize, tag: u64, qp: B::Qp) {
        let endpoint = self.backend.endpoint(core, &qp);
        self.reply(core, Reply::Prepared { tag, qp, endpoint });
    }

    fn signal(&mut self) {
        for (i, c) in self.cores.iter_mut().enumerate() {
            if std::mem::take(&mut c.unsignaled) {
                (self.wake)(i);
            }
        }
    }

    fn handle(&mut self, core: usize, r: Request<B::Qp>) {
        match r {
            Request::Prepare { tag } if self.cores[core].retired => {
                self.fail(core, tag, "qp prepare", &io::Error::other("core retired"));
            }
            Request::Prepare { tag } => {
                if let Err(e) = self.backend.ready() {
                    // logged by the backend when the device became unready, not per refusal
                    let error = format!("qp prepare: {e}");
                    return self.reply(core, Reply::Failed { tag, error });
                }
                self.cores[core].refill_failed = false;
                match self.cores[core].pool.pop() {
                    Some(qp) => self.prepared(core, tag, qp),
                    None => self.cores[core].waiters.push_back(tag),
                }
            }
            Request::Connect { tag, qp, peer } => match self.backend.connect(core, &qp, &peer) {
                Ok(()) => self.reply(core, Reply::Connected { tag, qp }),
                Err(e) => {
                    // it may have reached RTR: SENDs of the peer may be in the SRQ; never destroyed undrained
                    diag::diag!("rdma control: qp connect failed (core {core}, tag {tag}): {e}");
                    let error = format!("qp connect: {e}");
                    self.quiesce(core, tag, qp, Release::default(), Some(error));
                }
            },
            Request::Quiesce { tag, qp, held } => self.quiesce(core, tag, qp, held, None),
            Request::Destroy { tag, qp, held } => match self.destroy_qp(qp) {
                Ok(()) => self.reply(core, Reply::Destroyed { tag, held }),
                Err(e) => self.fail(core, tag, "qp destroy", &e),
            },
            Request::Retire { tag } => {
                let c = &mut self.cores[core];
                c.retired = true;
                let pool = std::mem::take(&mut c.pool);
                let waiters = std::mem::take(&mut c.waiters);
                for qp in pool {
                    if let Err(e) = self.destroy_qp(qp) {
                        diag::diag!("rdma control: pool qp destroy at retire (core {core}): {e}");
                    }
                }
                for w in waiters {
                    self.fail(core, w, "qp prepare", &io::Error::other("core retired"));
                }
                // its CQ/SRQ are destroyed next: QPs on them go first (their completions do not matter any more)
                let (mine, rest) = std::mem::take(&mut self.quiescing)
                    .into_iter()
                    .partition(|q| q.core == core);
                self.quiescing = rest;
                for q in mine {
                    self.fail(core, q.tag, "qp drain", &io::Error::other("core retired"));
                    self.destroy_logged(core, q.qp);
                }
                let (mine, rest) = std::mem::take(&mut self.stuck)
                    .into_iter()
                    .partition(|s| s.0 == core);
                self.stuck = rest;
                for (_, qp, _) in mine {
                    self.destroy_logged(core, qp);
                }
                self.reply(
                    core,
                    Reply::Destroyed {
                        tag,
                        held: Release::default(),
                    },
                );
            }
        }
    }

    /// Create one QP for the first core (round-robin) with a waiting Prepare, else with a pool deficit. Waiters win.
    fn refill(&mut self) -> bool {
        let n = self.cores.len();
        let pick = |s: &Self, waiting: bool| {
            (0..n).map(|i| (s.next + i) % n).find(|&i| {
                let c = &s.cores[i];
                if c.retired {
                    false
                } else if waiting {
                    !c.waiters.is_empty()
                } else {
                    c.pool.len() < s.pool_depth && !c.refill_failed
                }
            })
        };
        let Some(core) = pick(self, true).or_else(|| pick(self, false)) else {
            return false;
        };
        self.next = (core + 1) % n;
        match self.backend.create(core) {
            Ok(qp) => match self.cores[core].waiters.pop_front() {
                Some(tag) => self.prepared(core, tag, qp),
                None => self.cores[core].pool.push(qp),
            },
            Err(e) => match self.cores[core].waiters.pop_front() {
                Some(tag) => self.fail(core, tag, "qp create", &e),
                None => {
                    diag::diag!("rdma control: pool refill failed (core {core}): {e}");
                    self.cores[core].refill_failed = true;
                }
            },
        }
        true
    }

    /// Destroy `qp` and forget its last-WQE event: once the destroy returned, every event of the QP has been reported
    /// (the async thread acknowledges after reporting, the destroy waits for the acknowledgements), so it is read here
    /// and a later QP with the same number starts without one.
    fn destroy_qp(&mut self, qp: B::Qp) -> io::Result<()> {
        let qpn = self.backend.qpn(&qp);
        let r = self.backend.destroy(qp);
        self.take_events();
        self.early.remove(&qpn);
        r
    }

    fn destroy_logged(&mut self, core: usize, qp: B::Qp) {
        if let Err(e) = self.destroy_qp(qp) {
            diag::diag!("rdma control: qp destroy at retire (core {core}): {e}");
        }
    }

    /// To ERR, then [`Engine::quiesced`] at once (never received) or after its last-WQE event.
    fn quiesce(
        &mut self,
        core: usize,
        tag: u64,
        mut qp: B::Qp,
        held: Release,
        failed: Option<String>,
    ) {
        match self.backend.quiesce(&mut qp) {
            Ok(true) => {
                let qpn = self.backend.qpn(&qp);
                self.take_events();
                if self.early.remove(&qpn) {
                    // it entered ERR before (retry exceeded, a forced error) and its event came then
                    return self.quiesced(core, tag, qp, held, failed);
                }
                self.quiescing.push(Quiescing {
                    core,
                    tag,
                    qpn,
                    qp,
                    held,
                    since: Instant::now(),
                    failed,
                });
            }
            Ok(false) => self.quiesced(core, tag, qp, held, failed),
            Err(e) => {
                self.fail(core, tag, "qp to ERR", &e);
                self.stuck.push((core, qp, held));
            }
        }
    }

    fn quiesced(
        &mut self,
        core: usize,
        tag: u64,
        qp: B::Qp,
        held: Release,
        failed: Option<String>,
    ) {
        let r = match failed {
            Some(error) => Reply::ConnectFailed { tag, error, qp },
            None => Reply::Quiesced { tag, qp, held },
        };
        self.reply(core, r);
    }

    /// Read the backend's last-WQE events: a waiting QP is quiesced, any other event is kept for its QP ([`Engine::early`]).
    /// Returns whether a QP was quiesced.
    fn take_events(&mut self) -> bool {
        let mut worked = false;
        self.backend.last_wqe(&mut self.events);
        for qpn in std::mem::take(&mut self.events) {
            match self.quiescing.iter().position(|q| q.qpn == qpn) {
                Some(i) => {
                    let q = self.quiescing.swap_remove(i);
                    self.quiesced(q.core, q.tag, q.qp, q.held, q.failed);
                    worked = true;
                }
                None => {
                    self.early.insert(qpn);
                }
            }
        }
        worked
    }

    /// Last-WQE events: the QP is quiesced. A QP waiting longer than the limit is given up: loud, counted, kept.
    fn quiesce_progress(&mut self) -> bool {
        let mut worked = self.take_events();
        let limit = self.drain_limit;
        let mut i = 0;
        while i < self.quiescing.len() {
            if self.quiescing[i].since.elapsed() < limit {
                i += 1;
                continue;
            }
            let q = self.quiescing.swap_remove(i);
            QP_DRAIN_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            diag::diag!(
                "WARNING TIMEOUT rdma qp drain exceeded {}s (core {}, qp {}: no last-WQE event; QP and its {} send slots and {} receive credits kept for good)",
                limit.as_secs_f64(),
                q.core,
                q.qpn,
                q.held.slots.len(),
                q.held.credits
            );
            self.fail(
                q.core,
                q.tag,
                "qp drain",
                &io::Error::other("no last-WQE event"),
            );
            self.stuck.push((q.core, q.qp, q.held));
            worked = true;
        }
        worked
    }

    /// When the oldest quiescing QP times out, if any.
    fn next_deadline(&self) -> Option<Duration> {
        self.quiescing
            .iter()
            .map(|q| self.drain_limit.saturating_sub(q.since.elapsed()))
            .min()
    }

    /// Serve every queued request, then create at most one QP (so requests are never held up behind more than one
    /// create). Returns whether there was any work; the thread sleeps when there was none.
    fn step(&mut self) -> bool {
        let mut worked = false;
        if self.backend.take_fatal() {
            for core in 0..self.cores.len() {
                (self.wake)(core);
            }
            worked = true;
        }
        for core in 0..self.cores.len() {
            while let Some(r) = self.cores[core].req.pop() {
                self.handle(core, r);
                worked = true;
            }
        }
        worked |= self.quiesce_progress();
        self.signal();
        if self.refill() {
            worked = true;
            self.signal();
        }
        worked
    }

    /// Final drain: queued requests are discarded and every QP that is still ours (queued, pooled) is destroyed.
    fn shutdown(&mut self) {
        for core in 0..self.cores.len() {
            let mut qps = std::mem::take(&mut self.cores[core].pool);
            while let Some(r) = self.cores[core].req.pop() {
                match r {
                    Request::Connect { qp, .. }
                    | Request::Destroy { qp, .. }
                    | Request::Quiesce { qp, .. } => qps.push(qp),
                    Request::Prepare { .. } | Request::Retire { .. } => {}
                }
            }
            for qp in qps {
                if let Err(e) = self.backend.destroy(qp) {
                    diag::diag!("rdma control: qp destroy at shutdown (core {core}): {e}");
                }
            }
        }
        let qs = std::mem::take(&mut self.quiescing);
        let stuck = std::mem::take(&mut self.stuck);
        for (core, qp) in qs
            .into_iter()
            .map(|q| (q.core, q.qp))
            .chain(stuck.into_iter().map(|s| (s.0, s.1)))
        {
            if let Err(e) = self.backend.destroy(qp) {
                diag::diag!("rdma control: qp destroy at shutdown (core {core}): {e}");
            }
        }
    }
}

/// The running control thread. Dropping it (or [`Control::shutdown`]) stops the thread after it destroyed the pooled
/// QPs and the ones still queued; QPs a core still holds are its own to destroy first (`Core::detach` + destroy).
#[derive(Debug)]
pub struct Control {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Control {
    /// Spawn the thread for `cores` data-path cores; returns it with one [`CoreLink`] per core (index = core number
    /// passed to `backend` and `wake`). `wake(core)` is called from the control thread after replies were queued for
    /// `core` (once per batch); it must be cheap and thread-safe (eventfd write, knet `Wake` poke).
    pub fn start<B: Backend, W: Fn(usize) + Send + 'static>(
        backend: B,
        cores: usize,
        cfg: ControlCfg,
        wake: W,
    ) -> io::Result<(Control, Vec<CoreLink<B::Qp>>)> {
        let cap = (cfg.queue_depth as usize).next_power_of_two().max(2);
        let (states, ends): (Vec<_>, Vec<_>) = (0..cores).map(|_| endpoints(cap)).unzip();
        let mut engine = Engine {
            backend,
            cores: states,
            pool_depth: cfg.pool_depth as usize,
            wake,
            next: 0,
            quiescing: Vec::new(),
            stuck: Vec::new(),
            events: Vec::new(),
            early: HashSet::new(),
            drain_limit: QP_DRAIN_LIMIT,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let handle = thread::Builder::new()
            .name("rdma-control".into())
            .spawn(move || {
                engine.backend.start(thread::current());
                while !s.load(Ordering::Acquire) {
                    if !engine.step() {
                        match engine.next_deadline() {
                            Some(d) => thread::park_timeout(d),
                            None => thread::park(),
                        }
                    }
                }
                engine.shutdown();
            })?;
        let t = handle.thread().clone();
        let links = ends
            .into_iter()
            .map(|(req, rep)| CoreLink::new(req, rep, t.clone(), cap))
            .collect();
        Ok((
            Control {
                stop,
                thread: Some(handle),
            },
            links,
        ))
    }

    /// Stop and join the thread (what Drop does).
    pub fn shutdown(self) {}
}

impl Drop for Control {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(h) = self.thread.take() {
            h.thread().unpark();
            if h.join().is_err() {
                diag::diag!("rdma control: thread panicked");
            }
        }
    }
}

type Ends<Q> = (Producer<Request<Q>>, Consumer<Reply<Q>>);

/// Both queue pairs of one core: the control side state and the core side ends.
fn endpoints<Q: Send>(cap: usize) -> (CoreState<Q>, Ends<Q>) {
    let (req_p, req_c) = channel(cap);
    let (rep_p, rep_c) = channel(cap);
    (
        CoreState {
            req: req_c,
            rep: rep_p,
            pool: Vec::new(),
            waiters: VecDeque::new(),
            refill_failed: false,
            retired: false,
            unsignaled: false,
        },
        (req_p, rep_c),
    )
}

impl<Q> CoreLink<Q> {
    fn new(req: Producer<Request<Q>>, rep: Consumer<Reply<Q>>, thread: Thread, cap: usize) -> Self {
        CoreLink {
            req,
            rep,
            thread,
            inflight: 0,
            cap,
        }
    }
}

#[cfg(all(feature = "verbs", target_os = "linux"))]
pub use verbs_backend::{VerbsBackend, start_verbs};
#[cfg(all(feature = "memory-windows", target_os = "linux"))]
pub use verbs_backend::{start_verbs_for_reads, start_verbs_prefer_reads};

#[cfg(all(feature = "verbs", target_os = "linux"))]
mod verbs_backend {
    use super::*;
    use crate::verbs::{AsyncEvents, CoreHandles, Device, Qp};

    /// libibverbs backend: one device, the CQ/SRQ handles of every core, the device's async-event thread.
    #[derive(Debug)]
    pub struct VerbsBackend {
        dev: Arc<Device>,
        handles: Vec<CoreHandles>,
        /// xorshift state for initial PSNs.
        rng: u64,
        /// Last-WQE events from the async-event thread (control plane: a lock is fine).
        last_wqe: Arc<std::sync::Mutex<Vec<u32>>>,
        events: Option<AsyncEvents>,
        /// The last [`Backend::ready`] failed (logged once per change).
        unready: bool,
        fatal_reported: bool,
        #[cfg(feature = "memory-windows")]
        reads: Option<crate::verbs::ReadLimits>,
    }

    impl VerbsBackend {
        pub fn new(dev: Arc<Device>, handles: Vec<CoreHandles>) -> VerbsBackend {
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as u64);
            VerbsBackend {
                dev,
                handles,
                rng: t ^ (u64::from(std::process::id()) << 32) | 1,
                last_wqe: Arc::default(),
                events: None,
                unready: false,
                fatal_reported: false,
                #[cfg(feature = "memory-windows")]
                reads: None,
            }
        }

        /// Explicit control-path opt-in. Ordinary backends never query/offer
        /// READ capabilities. This prepares QPs, not object handlers or grants.
        #[cfg(feature = "memory-windows")]
        pub fn new_for_reads(dev: Arc<Device>, handles: Vec<CoreHandles>) -> io::Result<Self> {
            let caps = dev.read_limits()?;
            if caps.responder == 0 && (caps.initiator == 0 || caps.max_sge == 0) {
                return Err(io::ErrorKind::Unsupported.into());
            }
            let mut backend = Self::new(dev, handles);
            backend.reads = Some(caps);
            Ok(backend)
        }

        fn psn(&mut self) -> u32 {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            (self.rng >> 8) as u32 & 0xff_ffff
        }
    }

    impl Backend for VerbsBackend {
        type Qp = Qp;

        fn create(&mut self, core: usize) -> io::Result<Qp> {
            let psn = self.psn();
            #[cfg(feature = "memory-windows")]
            if let Some(caps) = self.reads {
                return Qp::create_with_read_limits(&self.dev, self.handles[core], psn, caps);
            }
            Qp::create(&self.dev, self.handles[core], psn)
        }

        fn endpoint(&self, core: usize, qp: &Qp) -> Endpoint {
            qp.endpoint(&self.handles[core])
        }

        fn ready(&mut self) -> io::Result<()> {
            if self.dev.failed() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "fatal RDMA shared-resource event",
                ));
            }
            match self.dev.gid_index() {
                Ok(i) => {
                    if std::mem::take(&mut self.unready) {
                        diag::diag!(
                            "rdma control: {}: local RoCEv2 GID back (index {i}): new connections upgrade again",
                            self.dev.name()
                        );
                    }
                    Ok(())
                }
                Err(e) => {
                    if !std::mem::replace(&mut self.unready, true) {
                        diag::diag!(
                            "rdma control: {}: local RoCEv2 GID not on the port ({e}): new connections stay TCP until it is back",
                            self.dev.name()
                        );
                    }
                    Err(e)
                }
            }
        }

        fn connect(&mut self, core: usize, qp: &Qp, peer: &Endpoint) -> io::Result<()> {
            #[cfg(feature = "memory-windows")]
            if self.reads.is_some() {
                qp.connect_negotiated_reads(&self.handles[core], peer)?;
                return Ok(());
            }
            qp.connect(&self.handles[core], peer)
        }

        fn quiesce(&mut self, qp: &mut Qp) -> io::Result<bool> {
            qp.to_err()
        }

        fn qpn(&self, qp: &Qp) -> u32 {
            qp.qpn()
        }

        fn last_wqe(&mut self, out: &mut Vec<u32>) {
            out.append(&mut self.last_wqe.lock().unwrap_or_else(|p| p.into_inner()));
        }

        fn start(&mut self, control: Thread) {
            let q = self.last_wqe.clone();
            let fault_wake = control.clone();
            match AsyncEvents::start(
                self.dev.clone(),
                move |qpn| {
                    q.lock().unwrap_or_else(|p| p.into_inner()).push(qpn);
                    control.unpark();
                },
                move || fault_wake.unpark(),
            ) {
                Ok(e) => self.events = Some(e),
                // every teardown of a connected QP then times out (loud, counted, kept)
                Err(e) => diag::diag!("rdma control: {}: async event thread: {e}", self.dev.name()),
            }
        }

        fn take_fatal(&mut self) -> bool {
            if self.dev.failed() && !self.fatal_reported {
                self.fatal_reported = true;
                true
            } else {
                false
            }
        }

        fn destroy(&mut self, qp: Qp) -> io::Result<()> {
            qp.destroy()
        }
    }

    /// Control thread over `dev` for the cores whose `Core::handles()` are `handles` (index = core number).
    pub fn start_verbs<W: Fn(usize) + Send + 'static>(
        dev: Arc<Device>,
        handles: Vec<CoreHandles>,
        cfg: ControlCfg,
        wake: W,
    ) -> io::Result<(Control, Vec<CoreLink<Qp>>)> {
        let n = handles.len();
        Control::start(VerbsBackend::new(dev, handles), n, cfg, wake)
    }

    /// [`Control::start_verbs`] with READ-capable QPs (spec rdma-read-offer.md): the
    /// backend caches the device's READ limits, emits the 44-byte endpoint offer and
    /// programs the negotiated depths per peer. Fails with `Unsupported` when the
    /// device cannot answer or post single-SGE READs, so a caller never advertises
    /// a capability the device lacks.
    #[cfg(feature = "memory-windows")]
    pub fn start_verbs_for_reads<W: Fn(usize) + Send + 'static>(
        dev: Arc<Device>,
        handles: Vec<CoreHandles>,
        cfg: ControlCfg,
        wake: W,
    ) -> io::Result<(Control, Vec<CoreLink<Qp>>)> {
        let n = handles.len();
        Control::start(VerbsBackend::new_for_reads(dev, handles)?, n, cfg, wake)
    }

    /// [`start_verbs_for_reads`], falling back to [`start_verbs`] (SEND/WRITE only) on a device that cannot post or
    /// answer READs; the fallback is logged. The flag says whether the QPs are READ-capable.
    #[cfg(feature = "memory-windows")]
    pub fn start_verbs_prefer_reads<W: Fn(usize) + Send + Sync + 'static>(
        dev: Arc<Device>,
        handles: Vec<CoreHandles>,
        cfg: ControlCfg,
        wake: W,
    ) -> io::Result<(Control, Vec<CoreLink<Qp>>, bool)> {
        let wake = Arc::new(wake);
        let for_reads = Arc::clone(&wake);
        match start_verbs_for_reads(dev.clone(), handles.clone(), cfg, move |c| for_reads(c)) {
            Ok((control, links)) => Ok((control, links, true)),
            Err(e) => {
                diag::diag!(
                    "rdma control: {}: device cannot post/answer RDMA READs ({e}): source-pull stays off, \
                     connections upgrade SEND/WRITE only",
                    dev.name()
                );
                let (control, links) = start_verbs(dev, handles, cfg, move |c| wake(c))?;
                Ok((control, links, false))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::time::{Duration, Instant};

    #[derive(Debug)]
    struct FakeQp(u32);

    #[derive(Debug, Default)]
    struct Shared {
        created: AtomicU32,
        destroyed: AtomicU32,
        connected: AtomicU32,
        fail_create: AtomicBool,
        fail_connect: AtomicBool,
        fail_destroy: AtomicBool,
        fail_quiesce: AtomicBool,
        fatal: AtomicBool,
        /// The local address is gone ([`Backend::ready`] fails).
        unready: AtomicBool,
        /// A destroy reports the QP's last-WQE event before it returns (the async thread read it while the destroy waited
        /// for its acknowledgement).
        event_at_destroy: AtomicBool,
        /// Last-WQE events the device "delivered".
        events: std::sync::Mutex<Vec<u32>>,
    }

    #[derive(Debug)]
    struct Fake(Arc<Shared>);

    impl Backend for Fake {
        type Qp = FakeQp;
        fn create(&mut self, _core: usize) -> io::Result<FakeQp> {
            if self.0.fail_create.load(Ordering::Relaxed) {
                return Err(io::Error::other("create refused"));
            }
            Ok(FakeQp(self.0.created.fetch_add(1, Ordering::Relaxed) + 1))
        }
        fn endpoint(&self, core: usize, qp: &FakeQp) -> Endpoint {
            Endpoint {
                qpn: qp.0,
                psn: core as u32,
                gid: [0; 16],
                window: 64,
                slot: 4096,
                mtu: 4096,
                reads: None,
            }
        }
        fn ready(&mut self) -> io::Result<()> {
            if self.0.unready.load(Ordering::Relaxed) {
                return Err(io::Error::from(io::ErrorKind::AddrNotAvailable));
            }
            Ok(())
        }
        fn connect(&mut self, _core: usize, _qp: &FakeQp, _peer: &Endpoint) -> io::Result<()> {
            if self.0.fail_connect.load(Ordering::Relaxed) {
                return Err(io::Error::other("connect refused"));
            }
            self.0.connected.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        /// QP 0 never connected (no event to wait for).
        fn quiesce(&mut self, qp: &mut FakeQp) -> io::Result<bool> {
            if self.0.fail_quiesce.load(Ordering::Relaxed) {
                return Err(io::Error::other("modify refused"));
            }
            Ok(qp.0 != 0)
        }
        fn qpn(&self, qp: &FakeQp) -> u32 {
            qp.0
        }
        fn last_wqe(&mut self, out: &mut Vec<u32>) {
            out.append(&mut self.0.events.lock().unwrap());
        }
        fn start(&mut self, _control: Thread) {}
        fn take_fatal(&mut self) -> bool {
            self.0.fatal.swap(false, Ordering::AcqRel)
        }
        fn destroy(&mut self, qp: FakeQp) -> io::Result<()> {
            self.0.destroyed.fetch_add(1, Ordering::Relaxed);
            if self.0.event_at_destroy.load(Ordering::Relaxed) {
                self.0.events.lock().unwrap().push(qp.0);
            }
            if self.0.fail_destroy.load(Ordering::Relaxed) {
                return Err(io::Error::other("destroy refused"));
            }
            Ok(())
        }
    }

    fn peer() -> Endpoint {
        Endpoint {
            qpn: 9,
            psn: 1,
            gid: [0; 16],
            window: 64,
            slot: 4096,
            mtu: 4096,
            reads: None,
        }
    }

    type Woken = Arc<std::sync::Mutex<Vec<usize>>>;
    type Rig = (
        Engine<Fake, Box<dyn Fn(usize)>>,
        Vec<CoreLink<FakeQp>>,
        Arc<Shared>,
        Woken,
    );

    /// Engine driven by hand (no thread) with `cores` links.
    fn rig(cores: usize, pool: usize, cap: usize) -> Rig {
        let sh = Arc::new(Shared::default());
        let woken: Woken = Arc::default();
        let w = woken.clone();
        let (states, ends): (Vec<_>, Vec<_>) = (0..cores).map(|_| endpoints(cap)).unzip();
        let wake: Box<dyn Fn(usize)> = Box::new(move |i| w.lock().unwrap().push(i));
        let e = Engine {
            backend: Fake(sh.clone()),
            cores: states,
            pool_depth: pool,
            wake,
            next: 0,
            quiescing: Vec::new(),
            stuck: Vec::new(),
            events: Vec::new(),
            early: HashSet::new(),
            drain_limit: QP_DRAIN_LIMIT,
        };
        let links = ends
            .into_iter()
            .map(|(rq, rp)| CoreLink::new(rq, rp, thread::current(), cap))
            .collect();
        (e, links, sh, woken)
    }

    fn run<B: Backend, W: Fn(usize)>(e: &mut Engine<B, W>) {
        while e.step() {}
    }

    #[test]
    fn pool_fills_to_depth_per_core_and_stops() {
        let (mut e, _links, sh, woken) = rig(3, 2, 8);
        run(&mut e);
        assert_eq!(sh.created.load(Ordering::Relaxed), 6);
        assert!(e.cores.iter().all(|c| c.pool.len() == 2));
        assert!(!e.step(), "idle once full");
        assert!(woken.lock().unwrap().is_empty(), "pool refill wakes nobody");
    }

    #[test]
    fn fatal_resource_event_wakes_every_idle_core_without_a_pending_request() {
        let (mut e, _links, sh, woken) = rig(3, 0, 8);
        assert!(!e.step());
        sh.fatal.store(true, Ordering::Release);
        assert!(e.step());
        assert_eq!(*woken.lock().unwrap(), vec![0, 1, 2]);
        assert!(!e.step(), "terminal failure wakes each core only once");
    }

    #[test]
    fn prepare_takes_pooled_qp_replies_on_own_core_and_refills() {
        let (mut e, mut links, sh, woken) = rig(2, 2, 8);
        run(&mut e);
        links[1].prepare(7).unwrap();
        run(&mut e);
        assert_eq!(*woken.lock().unwrap(), vec![1]);
        assert!(links[0].poll().is_none());
        match links[1].poll().unwrap() {
            Reply::Prepared { tag, qp, endpoint } => {
                assert_eq!((tag, endpoint.qpn, endpoint.psn), (7, qp.0, 1));
            }
            r => panic!("{r:?}"),
        }
        assert!(links[1].poll().is_none());
        assert_eq!(e.cores[1].pool.len(), 2, "refilled in the background");
        assert_eq!(sh.created.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn empty_pool_queues_the_request_and_never_blocks_the_core() {
        let (mut e, mut links, sh, _) = rig(1, 0, 8);
        for tag in 0..3 {
            links[0].prepare(tag).unwrap(); // returns at once, nothing created yet
        }
        assert_eq!(sh.created.load(Ordering::Relaxed), 0);
        e.step();
        // one create per step: the first waiter is served, the others still wait
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Prepared { tag: 0, .. })
        ));
        assert!(links[0].poll().is_none());
        assert_eq!(e.cores[0].waiters.len(), 2);
        run(&mut e);
        let tags: Vec<u64> = std::iter::from_fn(|| links[0].poll())
            .map(|r| match r {
                Reply::Prepared { tag, .. } => tag,
                r => panic!("{r:?}"),
            })
            .collect();
        assert_eq!(tags, vec![1, 2], "FIFO");
    }

    #[test]
    fn waiters_are_served_before_pool_refill() {
        let (mut e, mut links, _, _) = rig(2, 4, 8);
        e.step(); // creates one pool QP for core 0
        e.cores[1].pool.clear(); // core 1 pool empty
        links[1].prepare(5).unwrap();
        e.step();
        assert!(matches!(
            links[1].poll(),
            Some(Reply::Prepared { tag: 5, .. })
        ));
    }

    #[test]
    fn create_failure_fails_the_waiter_and_backs_off_the_refill() {
        let (mut e, mut links, sh, _) = rig(1, 2, 8);
        sh.fail_create.store(true, Ordering::Relaxed);
        links[0].prepare(1).unwrap();
        run(&mut e);
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Failed { tag: 1, .. })
        ));
        assert!(e.cores[0].refill_failed);
        assert!(!e.step(), "no hammering of a failing device");
        sh.fail_create.store(false, Ordering::Relaxed);
        links[0].prepare(2).unwrap(); // demand re-arms the refill
        run(&mut e);
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Prepared { tag: 2, .. })
        ));
        assert_eq!(e.cores[0].pool.len(), 2);
    }

    #[test]
    fn connect_ok_returns_the_qp_failure_destroys_it() {
        let (mut e, mut links, sh, _) = rig(1, 1, 8);
        run(&mut e);
        links[0].prepare(1).unwrap();
        run(&mut e);
        let Some(Reply::Prepared { qp, .. }) = links[0].poll() else {
            panic!()
        };
        links[0].connect(2, qp, peer()).unwrap();
        run(&mut e);
        let Some(Reply::Connected { tag: 2, qp }) = links[0].poll() else {
            panic!()
        };
        assert_eq!(sh.connected.load(Ordering::Relaxed), 1);
        sh.fail_connect.store(true, Ordering::Relaxed);
        let before = sh.destroyed.load(Ordering::Relaxed);
        let qpn = qp.0;
        links[0].connect(3, qp, peer()).unwrap();
        run(&mut e);
        // the failed connect may have reached RTR: quiesced (ERR, last-WQE event), never destroyed here
        assert!(links[0].poll().is_none(), "answered only after the event");
        sh.events.lock().unwrap().push(qpn);
        run(&mut e);
        let Some(Reply::ConnectFailed { tag: 3, qp, .. }) = links[0].poll() else {
            panic!("connect failed, QP back quiesced")
        };
        assert_eq!(qp.0, qpn);
        assert_eq!(sh.destroyed.load(Ordering::Relaxed), before);
        // after the core's drain the QP is destroyed like any other
        links[0].destroy(4, qp, Release::default()).unwrap();
        run(&mut e);
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Destroyed { tag: 4, .. })
        ));
        assert_eq!(sh.destroyed.load(Ordering::Relaxed), before + 1);
        // no event: the connect is Failed, the QP kept
        e.drain_limit = Duration::ZERO;
        links[0].connect(5, FakeQp(77), peer()).unwrap();
        run(&mut e);
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Failed { tag: 5, .. })
        ));
        assert_eq!(e.stuck.len(), 1);
    }

    #[test]
    fn destroy_returns_slots_and_reports_failure() {
        let (mut e, mut links, sh, _) = rig(1, 0, 8);
        let held = |slots: Vec<u32>, credits| Release { slots, credits };
        links[0].destroy(1, FakeQp(1), held(vec![4, 5], 7)).unwrap();
        run(&mut e);
        let Some(Reply::Destroyed { tag: 1, held: h }) = links[0].poll() else {
            panic!()
        };
        assert_eq!(h, held(vec![4, 5], 7));
        sh.fail_destroy.store(true, Ordering::Relaxed);
        links[0].destroy(2, FakeQp(2), held(vec![6], 3)).unwrap();
        run(&mut e);
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Failed { tag: 2, .. })
        ));
    }

    fn held(slots: Vec<u32>, credits: u32) -> Release {
        Release { slots, credits }
    }

    /// Quiesce answers only after the QP's last-WQE event; a never-connected QP at once; the destroy comes after.
    #[test]
    fn quiesce_waits_for_the_last_wqe_event() {
        let (mut e, mut links, sh, _) = rig(2, 0, 8);
        links[1].quiesce(1, FakeQp(7), held(vec![1], 5)).unwrap();
        links[1].quiesce(2, FakeQp(0), held(vec![], 3)).unwrap();
        run(&mut e);
        let Some(Reply::Quiesced {
            tag: 2,
            qp,
            held: h,
        }) = links[1].poll()
        else {
            panic!("a never-connected QP is quiesced at once")
        };
        assert_eq!((qp.0, h), (0, held(vec![], 3)));
        assert!(links[1].poll().is_none(), "no answer before the event");
        assert_eq!(
            sh.destroyed.load(Ordering::Relaxed),
            0,
            "never destroyed before"
        );
        sh.events.lock().unwrap().extend([99, 7]); // 99: nobody waits for it
        run(&mut e);
        let Some(Reply::Quiesced {
            tag: 1,
            qp,
            held: h,
        }) = links[1].poll()
        else {
            panic!("quiesced after the event")
        };
        assert_eq!((qp.0, &h), (7, &held(vec![1], 5)));
        links[1].destroy(3, qp, h).unwrap();
        run(&mut e);
        assert!(matches!(
            links[1].poll(),
            Some(Reply::Destroyed { tag: 3, .. })
        ));
        assert_eq!(sh.destroyed.load(Ordering::Relaxed), 1);
        assert!(e.quiescing.is_empty() && e.next_deadline().is_none());
    }

    /// No event within the limit: loud, counted, Failed; the QP is kept (never destroyed, `held` never handed back) and
    /// destroyed only when its core retires.
    #[test]
    fn a_missing_last_wqe_event_keeps_the_qp_and_what_it_held() {
        let (mut e, mut links, sh, _) = rig(1, 0, 8);
        e.drain_limit = Duration::ZERO;
        let before = qp_drain_timeouts();
        links[0].quiesce(1, FakeQp(7), held(vec![2], 4)).unwrap();
        run(&mut e);
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Failed { tag: 1, .. })
        ));
        assert!(qp_drain_timeouts() > before);
        assert_eq!(e.stuck.len(), 1);
        assert_eq!(e.stuck[0].2, held(vec![2], 4));
        // a late event changes nothing
        sh.events.lock().unwrap().push(7);
        run(&mut e);
        assert!(links[0].poll().is_none());
        assert_eq!(sh.destroyed.load(Ordering::Relaxed), 0);
        // a failed move to ERR is kept the same way
        sh.fail_quiesce.store(true, Ordering::Relaxed);
        links[0].quiesce(2, FakeQp(8), held(vec![], 1)).unwrap();
        run(&mut e);
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Failed { tag: 2, .. })
        ));
        assert_eq!(e.stuck.len(), 2);
        // the core retires: its QPs go before its CQ/SRQ
        links[0].retire(9).unwrap();
        run(&mut e);
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Destroyed { tag: 9, .. })
        ));
        assert_eq!(sh.destroyed.load(Ordering::Relaxed), 2);
        assert!(e.stuck.is_empty());
        assert!(e.early.is_empty(), "the late event of QP 7 went with it");
    }

    /// Finding F1 (doc/perf/rdma-fault-20261022.md): a last-WQE event that arrives before the teardown asks for it (the QP
    /// went to ERR by itself: retry exceeded, or an earlier move to ERR) must not be lost: the later quiesce gets no event
    /// (ERR to ERR raises none). The early event is kept until the QP is quiesced or destroyed.
    #[test]
    fn an_early_last_wqe_event_is_not_lost() {
        let (mut e, mut links, sh, _) = rig(1, 0, 8);
        e.drain_limit = Duration::ZERO; // a wait would time out at once: only the kept event can answer
        sh.events.lock().unwrap().push(7); // the event of QP 7 comes first ...
        run(&mut e); // ... and a control step with nobody waiting for it reads it
        links[0].quiesce(1, FakeQp(7), held(vec![2], 4)).unwrap(); // ... then the teardown moves it to ERR
        run(&mut e);
        assert!(
            matches!(links[0].poll(), Some(Reply::Quiesced { tag: 1, .. })),
            "the QP is quiesced by the event that came before"
        );
        assert!(e.early.is_empty() && e.stuck.is_empty());
        // the same when the event is read in the step that also serves the quiesce
        sh.events.lock().unwrap().push(8);
        links[0].quiesce(2, FakeQp(8), held(vec![], 1)).unwrap();
        run(&mut e);
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Quiesced { tag: 2, .. })
        ));
        assert!(e.early.is_empty() && e.stuck.is_empty());
    }

    /// A kept event belongs to the QP that raised it: its destroy forgets it, also when the event was reported while the
    /// destroy waited for its acknowledgement; a later QP with the same number waits for its own event.
    #[test]
    fn a_destroy_forgets_the_event_of_its_qp() {
        let (mut e, mut links, sh, _) = rig(1, 0, 8);
        sh.events.lock().unwrap().push(7);
        run(&mut e);
        assert!(e.early.contains(&7));
        links[0].destroy(1, FakeQp(7), held(vec![], 0)).unwrap();
        run(&mut e);
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Destroyed { tag: 1, .. })
        ));
        assert!(e.early.is_empty());
        sh.event_at_destroy.store(true, Ordering::Relaxed);
        links[0].destroy(2, FakeQp(8), held(vec![], 0)).unwrap();
        run(&mut e);
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Destroyed { tag: 2, .. })
        ));
        assert!(e.early.is_empty(), "reported during the destroy, forgotten");
        // new QPs with both numbers wait for their own events
        links[0].quiesce(3, FakeQp(7), held(vec![], 1)).unwrap();
        links[0].quiesce(4, FakeQp(8), held(vec![], 1)).unwrap();
        run(&mut e);
        assert!(links[0].poll().is_none(), "no inherited event");
        assert_eq!(e.quiescing.len(), 2);
    }

    /// While the device cannot connect (local GID gone) a prepare fails at once (the connection stays TCP, no QP is
    /// handed out); once it can, prepares are served again.
    #[test]
    fn a_prepare_fails_while_the_device_is_not_ready() {
        let (mut e, mut links, sh, _) = rig(1, 1, 8);
        run(&mut e);
        sh.unready.store(true, Ordering::Relaxed);
        links[0].prepare(1).unwrap();
        run(&mut e);
        let Some(Reply::Failed { tag: 1, error }) = links[0].poll() else {
            panic!("prepare refused")
        };
        assert!(error.starts_with("qp prepare"), "{error}");
        assert_eq!(e.cores[0].pool.len(), 1, "pooled QP kept");
        sh.unready.store(false, Ordering::Relaxed);
        links[0].prepare(2).unwrap();
        run(&mut e);
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Prepared { tag: 2, .. })
        ));
    }

    /// A retire answers the quiescing QPs of its core (Failed) and destroys them; other cores keep theirs.
    #[test]
    fn retire_ends_the_quiescing_qps_of_its_core_only() {
        let (mut e, mut links, sh, _) = rig(2, 0, 8);
        links[0].quiesce(1, FakeQp(5), held(vec![], 1)).unwrap();
        links[1].quiesce(1, FakeQp(6), held(vec![], 1)).unwrap();
        links[0].retire(2).unwrap();
        run(&mut e);
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Failed { tag: 1, .. })
        ));
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Destroyed { tag: 2, .. })
        ));
        assert_eq!(sh.destroyed.load(Ordering::Relaxed), 1);
        assert_eq!(e.quiescing.len(), 1);
        e.shutdown();
        assert_eq!(
            sh.destroyed.load(Ordering::Relaxed),
            2,
            "shutdown destroys the rest"
        );
    }

    #[test]
    fn inflight_is_bounded_by_the_queue_depth_and_frees_on_reply() {
        let (mut e, mut links, _, _) = rig(1, 0, 4);
        for t in 0..4 {
            links[0].prepare(t).unwrap();
        }
        assert!(links[0].prepare(4).is_err());
        let h = Release {
            slots: vec![1],
            credits: 2,
        };
        let Full((qp, held)) = links[0].destroy(9, FakeQp(9), h).unwrap_err();
        assert_eq!((qp.0, held.slots, held.credits), (9, vec![1], 2));
        assert!(links[0].connect(9, FakeQp(9), peer()).is_err());
        run(&mut e);
        // replies are not consumed yet: still full
        assert!(links[0].prepare(5).is_err());
        while links[0].poll().is_some() {}
        links[0].prepare(5).unwrap();
        run(&mut e);
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Prepared { tag: 5, .. })
        ));
    }

    #[test]
    fn retire_destroys_the_pool_of_that_core_and_refuses_further_work() {
        let (mut e, mut links, sh, _) = rig(2, 3, 8);
        run(&mut e);
        links[0].prepare(1).unwrap(); // served from the pool before the retire (FIFO)
        links[0].retire(2).unwrap();
        links[0].prepare(3).unwrap();
        run(&mut e);
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Prepared { tag: 1, .. })
        ));
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Destroyed { tag: 2, .. })
        ));
        assert!(matches!(
            links[0].poll(),
            Some(Reply::Failed { tag: 3, .. })
        ));
        // the 2 pooled QPs left of core 0 are gone, core 1 keeps its 3 and nothing is created for core 0 again
        assert_eq!(sh.destroyed.load(Ordering::Relaxed), 2);
        assert_eq!(
            sh.created.load(Ordering::Relaxed),
            6,
            "no create for a retired core"
        );
        assert!(e.cores[0].pool.is_empty() && e.cores[1].pool.len() == 3);
    }

    #[test]
    fn shutdown_destroys_pooled_and_queued_qps() {
        let (mut e, mut links, sh, _) = rig(2, 3, 8);
        run(&mut e);
        links[0]
            .destroy(1, FakeQp(100), Release::default())
            .unwrap();
        links[1].connect(2, FakeQp(101), peer()).unwrap();
        links[1].prepare(3).unwrap();
        e.shutdown();
        // 6 pooled + 2 queued (the waiting Prepare owns no QP)
        assert_eq!(sh.destroyed.load(Ordering::Relaxed), 8);
    }

    #[test]
    fn thread_serves_requests_wakes_the_core_and_drains_on_drop() {
        let sh = Arc::new(Shared::default());
        let woke = Arc::new(AtomicU32::new(0));
        let w = woke.clone();
        let cfg = ControlCfg {
            pool_depth: 2,
            queue_depth: 8,
        };
        let (ctl, mut links) = Control::start(Fake(sh.clone()), 2, cfg, move |_| {
            w.fetch_add(1, Ordering::Release);
        })
        .unwrap();
        links[0].prepare(1).unwrap();
        let t = Instant::now();
        let qp = loop {
            if let Some(r) = links[0].poll() {
                let Reply::Prepared { qp, .. } = r else {
                    panic!("{r:?}")
                };
                break qp;
            }
            assert!(t.elapsed() < Duration::from_secs(10), "no reply");
            thread::yield_now();
        };
        // the wake follows the queue write: it may land a moment after the reply is visible
        let t = Instant::now();
        while woke.load(Ordering::Acquire) == 0 {
            assert!(t.elapsed() < Duration::from_secs(10), "no wake");
            thread::yield_now();
        }
        let h = Release {
            slots: vec![3],
            credits: 0,
        };
        links[0].destroy(2, qp, h).unwrap();
        let t = Instant::now();
        loop {
            if let Some(Reply::Destroyed { held, .. }) = links[0].poll() {
                assert_eq!(held.slots, vec![3]);
                break;
            }
            assert!(t.elapsed() < Duration::from_secs(10), "no reply");
            thread::yield_now();
        }
        // let the pool fill, then stop: everything created is destroyed
        let t = Instant::now();
        while sh.created.load(Ordering::Relaxed) < 5 {
            assert!(t.elapsed() < Duration::from_secs(10), "pool not filled");
            thread::yield_now();
        }
        ctl.shutdown();
        assert_eq!(
            sh.created.load(Ordering::Relaxed),
            sh.destroyed.load(Ordering::Relaxed)
        );
    }
}
