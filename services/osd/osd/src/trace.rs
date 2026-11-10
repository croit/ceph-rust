// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Sampled per-op stage tracing (adr 0170-op-trace, doc/ops/op-trace.md). Always compiled in; `flashstore_trace_sample`
//! (0 = off) picks 1 of N client ops by a hash of the request id, so every core and every replica reaches the same
//! verdict without carrying a context. Each core owns a ring of 32-byte events (single writer, no atomics, no lock);
//! the admin commands copy the rings core by core and join the events by trace id on the control core.
use denc::types::OsdReqId;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Instant;

// ---------------------------------------------------------------------------------------------------------- clock

struct Cal {
    /// Tick at calibration time (origin of all trace times).
    origin: u64,
    /// Nanoseconds per tick.
    ns_per_tick: f64,
    tsc: bool,
}

static CAL: OnceLock<Cal> = OnceLock::new();
static T0: OnceLock<Instant> = OnceLock::new();

#[cfg(target_arch = "x86_64")]
fn invariant_tsc() -> bool {
    // CPUID.80000007H:EDX[8]
    let max = core::arch::x86_64::__cpuid(0x8000_0000).eax;
    max >= 0x8000_0007 && core::arch::x86_64::__cpuid(0x8000_0007).edx & (1 << 8) != 0
}

#[cfg(not(target_arch = "x86_64"))]
fn invariant_tsc() -> bool {
    cfg!(target_arch = "aarch64")
}

#[cfg(target_arch = "x86_64")]
fn tsc_now() -> u64 {
    // SAFETY: rdtsc has no preconditions; it only reads the time-stamp counter.
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[cfg(target_arch = "aarch64")]
fn tsc_now() -> u64 {
    let v: u64;
    // SAFETY: reads the architectural virtual counter; no memory access.
    unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) v, options(nomem, nostack)) };
    v
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn tsc_now() -> u64 {
    0
}

#[cfg(target_arch = "aarch64")]
fn tsc_hz() -> f64 {
    let v: u64;
    // SAFETY: reads the architectural counter frequency; no memory access.
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack)) };
    v as f64
}

fn mono_ns() -> u64 {
    T0.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

fn cal() -> &'static Cal {
    CAL.get_or_init(|| {
        if !invariant_tsc() {
            return Cal {
                origin: mono_ns(),
                ns_per_tick: 1.0,
                tsc: false,
            };
        }
        #[cfg(target_arch = "aarch64")]
        let ns_per_tick = 1e9 / tsc_hz();
        #[cfg(not(target_arch = "aarch64"))]
        let ns_per_tick = {
            let (t0, c0) = (Instant::now(), tsc_now());
            while t0.elapsed().as_millis() < 10 {
                std::hint::spin_loop();
            }
            let (t1, c1) = (Instant::now(), tsc_now());
            (t1 - t0).as_nanos() as f64 / c1.saturating_sub(c0).max(1) as f64
        };
        Cal {
            origin: tsc_now(),
            ns_per_tick,
            tsc: true,
        }
    })
}

/// Calibrate the clock now (`Osd` construction, before a core takes traffic): the calibration spins ~10 ms on x86_64,
/// and every caller of the clock waits for it, so no op may be the first caller.
pub fn init() {
    let _ = cal();
}

/// The clock is calibrated (a later read does not spin).
#[cfg(test)]
pub(crate) fn calibrated() -> bool {
    CAL.get().is_some()
}

/// Current time in ticks.
#[inline]
pub fn now() -> u64 {
    if cal().tsc { tsc_now() } else { mono_ns() }
}

/// Ticks to nanoseconds since the trace origin.
pub fn to_ns(t: u64) -> u64 {
    let c = cal();
    (t.saturating_sub(c.origin) as f64 * c.ns_per_tick) as u64
}

/// Nanoseconds of a tick difference.
pub(crate) fn span_ns(a: u64, b: u64) -> u64 {
    (b.saturating_sub(a) as f64 * cal().ns_per_tick) as u64
}

// ---------------------------------------------------------------------------------------------------------- stages

pub const RX: u8 = 1;
pub const ROUTED: u8 = 2;
pub const PG_IN: u8 = 3;
pub const SUBMIT: u8 = 4;
pub const DURABLE: u8 = 5;
pub const REP_SEND: u8 = 6;
pub const REP_ACK: u8 = 7;
pub const REPLY: u8 = 8;
pub const TX: u8 = 9;
pub const REP_TX: u8 = 10;
pub const REP_LINK: u8 = 11;
pub const PG_RUN: u8 = 12;
pub const PG_GATE: u8 = 13;
pub const R_RX: u8 = 16;
pub const R_IN: u8 = 17;
pub const R_PG: u8 = 18;
pub const R_SUBMIT: u8 = 19;
pub const R_DURABLE: u8 = 20;
pub const R_ACK_OUT: u8 = 21;
pub const R_TX: u8 = 22;

fn stage_name(s: u8) -> &'static str {
    match s {
        RX => "rx",
        ROUTED => "routed",
        PG_IN => "pg_in",
        SUBMIT => "submit",
        DURABLE => "durable",
        REP_SEND => "rep_send",
        REP_ACK => "rep_ack",
        REPLY => "reply",
        TX => "tx",
        REP_TX => "rep_tx",
        REP_LINK => "rep_link",
        PG_RUN => "pg_run",
        PG_GATE => "pg_gate",
        R_RX => "r_rx",
        R_IN => "r_in",
        R_PG => "r_pg",
        R_SUBMIT => "r_submit",
        R_DURABLE => "r_durable",
        R_ACK_OUT => "r_ack_out",
        R_TX => "r_tx",
        _ => "unknown",
    }
}

/// One stamp. `aux`: PG key (`pool << 32 | seed`) at `PG_IN`/`R_IN`, peer osd at `REP_SEND`/`REP_ACK`. `aux2` = payload
/// bytes, `x` = main op code (both at `PG_IN`). At `PG_RUN`: `aux` = number of engine runs of the op so far (1 = ran at
/// once, more = re-run after a gate / object wait / refused run). At `PG_GATE`: `aux` = why the op waits in the PG gate
/// on arrival (`opexec::view::gate_why`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ev {
    pub key: u64,
    pub t: u64,
    pub aux: u64,
    pub aux2: u32,
    pub x: u16,
    pub stage: u8,
    pub core: u8,
}

impl Ev {
    pub fn to_json(self) -> Value {
        json!([
            self.key, self.t, self.aux, self.aux2, self.x, self.stage, self.core
        ])
    }

    pub fn from_json(v: &Value) -> Option<Ev> {
        let a = v.as_array()?;
        let n = |i: usize| a.get(i).and_then(Value::as_u64);
        Some(Ev {
            key: n(0)?,
            t: n(1)?,
            aux: n(2)?,
            aux2: n(3)? as u32,
            x: n(4)? as u16,
            stage: n(5)? as u8,
            core: n(6)? as u8,
        })
    }
}

// ---------------------------------------------------------------------------------------------------------- sampling

/// Trace id of a request: a splitmix64 finalizer over (client type, number, incarnation, tid). Never 0.
pub fn key_of(r: &OsdReqId) -> u64 {
    let mut z = (r.name.num as u64)
        ^ (u64::from(r.name.ty) << 56)
        ^ (r.tid.rotate_left(17))
        ^ ((r.inc as u64) << 40);
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    z.max(1)
}

/// The PG part of a stamp's `aux`.
pub fn pg_aux(pool: u64, seed: u32) -> u64 {
    pool << 32 | u64::from(seed)
}

// ---------------------------------------------------------------------------------------------------------- tracer

/// Live sampled ops per core (the oldest is overwritten when full; an op that never ends is simply replaced).
const LIVE_CAP: usize = 64;
/// Frames of sampled ops waiting for the next tx step of this core.
const TX_CAP: usize = 64;
pub const DEFAULT_RING: usize = 16384;

#[derive(Clone, Copy, Debug, Default)]
struct Live {
    key: u64,
    conn: u64,
    tid: u64,
    token: u64,
    /// Primary: repop tid; replica: PG key.
    pg: u64,
    wtid: u64,
    /// Engine runs of the op so far (`PG_RUN` stamps).
    runs: u64,
    replica: bool,
}

/// Per-core tracing state (lives in the PG host struct of every core).
#[derive(Debug, Default)]
pub struct Tracer {
    /// Sample 1 of `n` ops; 0 = off.
    n: u32,
    core: u8,
    ring: Vec<Ev>,
    head: u64,
    live: Vec<Live>,
    next: usize,
    /// Number of occupied `live` slots: the one word every site checks.
    pub live_n: usize,
    last_rx: u64,
    await_tx: Vec<(u64, u8)>,
    /// Replica apply in progress: the key `on_persist` binds the next store token to.
    cur_key: u64,
    /// Stamps that found no room (live table / tx list full).
    pub dropped: u64,
}

impl Tracer {
    /// Apply the config: sample 1 of `n` (0 = off), `ring` events per core. A changed config starts a new sampling
    /// period: the events and live ops of the previous one would otherwise mix into the same `dump_op_traces`.
    pub fn configure(&mut self, n: u32, ring: usize, core: usize) {
        self.core = core.min(255) as u8;
        let cap = ring.clamp(64, 1 << 24).next_power_of_two();
        if n != 0 && (n != self.n || self.ring.len() != cap) {
            if self.ring.len() != cap {
                self.ring = vec![Ev::default(); cap];
                self.live = vec![Live::default(); LIVE_CAP];
                self.await_tx = Vec::with_capacity(TX_CAP);
            }
            self.reset();
        }
        self.n = n;
    }

    #[inline]
    pub fn on(&self) -> bool {
        self.n != 0
    }

    /// Is the request sampled (only call when [`Self::on`])?
    #[inline]
    pub fn sampled(&self, key: u64) -> bool {
        key.is_multiple_of(u64::from(self.n.max(1)))
    }

    /// Forget all events and live ops.
    pub fn reset(&mut self) {
        self.head = 0;
        self.live.iter_mut().for_each(|l| l.key = 0);
        self.live_n = 0;
        self.next = 0;
        self.await_tx.clear();
        self.cur_key = 0;
        self.dropped = 0;
    }

    #[inline]
    fn emit_at(&mut self, t: u64, key: u64, stage: u8, aux: u64, aux2: u32, x: u16) {
        let mask = self.ring.len() - 1;
        self.ring[(self.head as usize) & mask] = Ev {
            key,
            t,
            aux,
            aux2,
            x,
            stage,
            core: self.core,
        };
        self.head += 1;
    }

    fn emit(&mut self, key: u64, stage: u8, aux: u64) {
        self.emit_at(now(), key, stage, aux, 0, 0);
    }

    /// The NIC rx call of this loop step returned frames (stamped before they are decoded).
    #[inline]
    pub fn rx_polled(&mut self) {
        if self.n != 0 {
            self.last_rx = now();
        }
    }

    /// Conn core: a sampled client op (`replica`: peer RepOp) was decoded.
    #[cold]
    #[inline(never)]
    pub fn ingress(&mut self, key: u64, replica: bool, pg: u64) {
        let t = now();
        let rx = if self.last_rx == 0 {
            t
        } else {
            self.last_rx.min(t)
        };
        let (s_rx, s_in) = if replica { (R_RX, R_IN) } else { (RX, ROUTED) };
        self.emit_at(rx, key, s_rx, 0, 0, 0);
        self.emit_at(t, key, s_in, if replica { pg } else { 0 }, 0, 0);
    }

    fn slot(&mut self, l: Live) {
        let i = if let Some(i) = self.live.iter().position(|x| x.key == 0) {
            i
        } else {
            self.dropped += 1;
            self.live_n -= 1;
            let i = self.next;
            self.next = (self.next + 1) % LIVE_CAP;
            i
        };
        self.live_n += 1;
        self.live[i] = l;
    }

    fn find(&mut self, f: impl Fn(&Live) -> bool) -> Option<&mut Live> {
        self.live.iter_mut().find(|l| l.key != 0 && f(l))
    }

    fn free(&mut self, key: u64) {
        if let Some(l) = self.live.iter_mut().find(|l| l.key == key) {
            l.key = 0;
            self.live_n -= 1;
        }
    }

    /// PG core: a sampled client op reached its PG. `main_op`, `size`: what the dump shows.
    #[cold]
    #[inline(never)]
    pub fn op_in(&mut self, key: u64, conn: u64, tid: u64, pg: u64, size: u32, main_op: u16) {
        // a client resend of the same request keeps one entry
        self.free(key);
        self.slot(Live {
            key,
            conn,
            tid,
            pg,
            ..Live::default()
        });
        self.emit_at(now(), key, PG_IN, pg, size, main_op);
    }

    /// PG core: the engine starts a run of sampled op `key` (the first run, or a re-run after the op waited in the
    /// gate, behind an earlier write of its object, or for a refused store read). The last stamp before `SUBMIT` is
    /// the run that submits.
    #[cold]
    #[inline(never)]
    pub fn run_start(&mut self, key: u64) {
        let Some(l) = self.find(|l| l.key == key && !l.replica) else {
            return;
        };
        l.runs += 1;
        let runs = l.runs;
        self.emit_at(now(), key, PG_RUN, runs, 0, 0);
    }

    /// PG core: sampled op `key` arrived and waits in the PG gate for `why` (`opexec::view::gate_why`).
    #[cold]
    #[inline(never)]
    pub fn gate_in(&mut self, key: u64, why: u8) {
        if self.find(|l| l.key == key && !l.replica).is_some() {
            self.emit_at(now(), key, PG_GATE, why as u64, 0, 0);
        }
    }

    /// The engine submitted write `reqid`: remember its repop tid and its local store token.
    #[cold]
    #[inline(never)]
    pub fn bind_write(&mut self, key: u64, wtid: u64, token: u64) {
        if let Some(l) = self.find(|l| l.key == key && !l.replica) {
            l.wtid = wtid;
            l.token = token;
        }
    }

    /// Replica: a sampled RepOp reached the PG core (`tid` = repop tid).
    #[cold]
    #[inline(never)]
    pub fn repl_pg(&mut self, key: u64, tid: u64, pg: u64) {
        self.slot(Live {
            key,
            tid,
            pg,
            replica: true,
            ..Live::default()
        });
        self.cur_key = key;
        self.emit_at(now(), key, R_PG, pg, 0, 0);
    }

    /// The replica apply call is over.
    #[cold]
    #[inline(never)]
    pub fn repl_done(&mut self) {
        self.cur_key = 0;
    }

    /// A store txn with `token` was queued.
    #[cold]
    #[inline(never)]
    pub fn on_persist(&mut self, token: u64) {
        let ck = self.cur_key;
        let hit = self
            .find(|l| l.token == token && token != 0 || ck != 0 && l.key == ck && l.replica)
            .map(|l| {
                l.token = token;
                (l.key, l.replica)
            });
        if let Some((k, repl)) = hit {
            self.emit(k, if repl { R_SUBMIT } else { SUBMIT }, 0);
        }
    }

    /// The store txn `token` is durable.
    #[cold]
    #[inline(never)]
    pub fn durable(&mut self, token: u64) {
        let hit = self
            .find(|l| l.token == token && token != 0)
            .map(|l| (l.key, l.replica));
        if let Some((k, repl)) = hit {
            self.emit(k, if repl { R_DURABLE } else { DURABLE }, 0);
        }
    }

    /// Primary: repop `wtid` was encoded for `peer`.
    #[cold]
    #[inline(never)]
    pub fn rep_send(&mut self, wtid: u64, peer: i32) -> Option<u64> {
        let k = self.find(|l| !l.replica && l.wtid == wtid).map(|l| l.key)?;
        self.emit(k, REP_SEND, peer as u64);
        Some(k)
    }

    /// Primary: the ack of repop `wtid` from `peer` was processed.
    #[cold]
    #[inline(never)]
    pub fn rep_ack(&mut self, wtid: u64, peer: i32) {
        let k = self.find(|l| !l.replica && l.wtid == wtid).map(|l| l.key);
        if let Some(k) = k {
            self.emit(k, REP_ACK, peer as u64);
        }
    }

    /// Replica: the ack of repop `tid` in PG `pg` was encoded. Returns the key whose frame now waits for tx.
    #[cold]
    #[inline(never)]
    pub fn ack_out(&mut self, tid: u64, pg: u64) -> Option<u64> {
        let k = self
            .find(|l| l.replica && l.tid == tid && l.pg == pg)
            .map(|l| l.key)?;
        self.emit(k, R_ACK_OUT, 0);
        self.free(k);
        Some(k)
    }

    /// Primary: the reply of `(conn, tid)` was encoded. Returns the key whose frame now waits for tx.
    #[cold]
    #[inline(never)]
    pub fn reply(&mut self, conn: u64, tid: u64) -> Option<u64> {
        let k = self
            .find(|l| !l.replica && l.conn == conn && l.tid == tid)
            .map(|l| l.key)?;
        self.emit(k, REPLY, 0);
        self.free(k);
        Some(k)
    }

    /// A frame of sampled op `key` is queued on this (the link) core; `stage` = `TX`, `R_TX` or `REP_TX`.
    #[cold]
    #[inline(never)]
    pub fn await_tx(&mut self, key: u64, stage: u8) {
        if stage == REP_TX {
            self.emit(key, REP_LINK, 0); // the repop frame reached its link core
        }
        if self.await_tx.len() < TX_CAP {
            self.await_tx.push((key, stage));
        } else {
            self.dropped += 1;
        }
    }

    /// Whether frames wait for the tx stamp.
    #[inline]
    pub fn tx_pending(&self) -> bool {
        !self.await_tx.is_empty()
    }

    /// The tx step of this core finished: stamp every waiting frame.
    #[cold]
    #[inline(never)]
    pub fn tx_done(&mut self) {
        let t = now();
        for i in 0..self.await_tx.len() {
            let (k, s) = self.await_tx[i];
            self.emit_at(t, k, s, 0, 0, 0);
        }
        self.await_tx.clear();
    }

    /// The ring's occupied events, oldest first (no copy: one pass over the ring).
    fn ring(&self) -> impl Iterator<Item = &Ev> {
        let cap = self.ring.len() as u64;
        let n = self.head.min(cap);
        let mask = cap.saturating_sub(1) as usize;
        (self.head - n..self.head).map(move |i| &self.ring[(i as usize) & mask])
    }

    /// Copy of the ring, oldest first.
    pub fn snapshot(&self) -> Vec<Ev> {
        self.ring().copied().collect()
    }

    /// Stamps of one op in this core's ring `(event, ticks)`: for the historic op dump.
    pub fn events_of(&self, key: u64) -> Vec<Ev> {
        self.ring().filter(|e| e.key == key).copied().collect()
    }
}

// ---------------------------------------------------------------------------------------------------------- join

/// All events of one op (one role), time ordered.
#[derive(Debug)]
pub struct Trace {
    pub key: u64,
    pub replica: bool,
    pub evs: Vec<Ev>,
}

fn find(evs: &[Ev], s: u8) -> Option<&Ev> {
    evs.iter().find(|e| e.stage == s)
}

impl Trace {
    fn at(&self, s: u8) -> Option<u64> {
        find(&self.evs, s).map(|e| e.t)
    }

    pub fn complete(&self) -> bool {
        let need: &[u8] = if self.replica {
            &[R_RX, R_IN, R_PG, R_ACK_OUT, R_TX]
        } else {
            &[RX, ROUTED, PG_IN, REPLY, TX]
        };
        let paired = self.at(SUBMIT).is_none() == self.at(DURABLE).is_none()
            && self.at(R_SUBMIT).is_none() == self.at(R_DURABLE).is_none();
        paired && need.iter().all(|s| self.at(*s).is_some())
    }

    /// Start of the engine run that ended the op (the last `pg_run` stamp).
    fn run_at(&self) -> Option<u64> {
        self.evs
            .iter()
            .rev()
            .find(|e| e.stage == PG_RUN)
            .map(|e| e.t)
    }

    fn meta(&self) -> (u64, u32, u16) {
        find(&self.evs, PG_IN)
            .or_else(|| find(&self.evs, R_IN))
            .map_or((0, 0, 0), |e| (e.aux, e.aux2, e.x))
    }

    /// `write` when a store txn was queued, else `read` for read opcodes, else `other`.
    pub fn kind(&self) -> &'static str {
        if self.at(SUBMIT).is_some() || self.at(R_SUBMIT).is_some() {
            "write"
        } else if self.meta().2 & 0xf000 == 0x1000 {
            "read"
        } else {
            "other"
        }
    }

    fn core(&self) -> u8 {
        find(&self.evs, PG_IN)
            .or_else(|| find(&self.evs, R_PG))
            .map_or(0, |e| e.core)
    }

    /// Named segments in ns (stable names, doc/ops/op-trace.md). `repop_rtt` = slowest peer.
    pub fn segments(&self) -> Vec<(&'static str, u64)> {
        let mut v = Vec::new();
        let mut seg = |name: &'static str, a: u8, b: u8| {
            if let (Some(x), Some(y)) = (self.at(a), self.at(b)) {
                v.push((name, span_ns(x, y)));
            }
        };
        if self.replica {
            seg("decode", R_RX, R_IN);
            seg("xcore_in", R_IN, R_PG);
            seg("exec", R_PG, R_SUBMIT);
            seg("store", R_SUBMIT, R_DURABLE);
            seg("ack_encode", R_DURABLE, R_ACK_OUT);
            seg("ack_tx", R_ACK_OUT, R_TX);
            seg("total", R_RX, R_TX);
        } else {
            seg("decode", RX, ROUTED);
            seg("xcore_in", ROUTED, PG_IN);
            if self.at(SUBMIT).is_some() {
                seg("exec", PG_IN, SUBMIT);
                seg("store", SUBMIT, DURABLE);
                seg("commit_wait", DURABLE, REPLY);
            } else {
                seg("exec", PG_IN, REPLY);
            }
            seg("reply_tx", REPLY, TX);
            seg("total", RX, TX);
            // exec = pg_wait + pg_work: the wait (gate, object waiters, refused runs) before the last engine run of
            // the op, then that run up to the txn queued (reads: up to the reply)
            if let (Some(a), Some(r)) = (self.at(PG_IN), self.run_at()) {
                v.push(("pg_wait", span_ns(a, r)));
                if let Some(e) = self.at(SUBMIT).or_else(|| self.at(REPLY)) {
                    v.push(("pg_work", span_ns(r, e)));
                }
            }
            // first repop encoded -> last repop frame sent by its link core (send-first: before the local store work)
            let first = self
                .evs
                .iter()
                .filter(|e| e.stage == REP_SEND)
                .map(|e| e.t)
                .min();
            let last = self
                .evs
                .iter()
                .filter(|e| e.stage == REP_TX)
                .map(|e| e.t)
                .max();
            if let (Some(a), Some(b)) = (first, last) {
                v.push(("rep_tx", span_ns(a, b)));
            }
            let rtt = self
                .evs
                .iter()
                .filter(|e| e.stage == REP_SEND)
                .filter_map(|s| {
                    self.evs
                        .iter()
                        .find(|a| a.stage == REP_ACK && a.aux == s.aux)
                        .map(|a| span_ns(s.t, a.t))
                })
                .max();
            if let Some(r) = rtt {
                v.push(("repop_rtt", r));
            }
        }
        v
    }

    pub fn size(&self) -> u32 {
        self.meta().1
    }

    pub fn to_json(&self) -> Value {
        let (pg, size, code) = self.meta();
        let first = self.evs.first().map_or(0, |e| e.t);
        let last = self.evs.last().map_or(0, |e| e.t);
        let mut prev = first;
        let stages: Vec<Value> = self
            .evs
            .iter()
            .map(|e| {
                let mut s = json!({"stage": stage_name(e.stage), "core": e.core,
                    "t_ns": to_ns(e.t), "delta_ns": span_ns(prev, e.t)});
                if e.stage == REP_SEND || e.stage == REP_ACK {
                    s["peer"] = json!(e.aux as i64);
                }
                if e.stage == PG_GATE {
                    s["why"] = json!(opexec::view::gate_why::name(e.aux as u8));
                }
                prev = prev.max(e.t);
                s
            })
            .collect();
        let segs: serde_json::Map<String, Value> = self
            .segments()
            .into_iter()
            .map(|(n, v)| (n.to_owned(), json!(v)))
            .collect();
        json!({
            "trace_id": format!("{:016x}", self.key),
            "role": if self.replica { "replica" } else { "primary" },
            "core": self.core(),
            "pg": format!("{}.{:x}", pg >> 32, pg & 0xffff_ffff),
            "op": opwire::op::name(code).unwrap_or("none"),
            "type": self.kind(),
            "size": size,
            "complete": self.complete(),
            "start_ns": to_ns(first),
            "total_ns": span_ns(first, last),
            "stages": stages,
            "segments": segs,
        })
    }
}

/// Join the events of all cores into traces, ordered by their first stamp.
pub fn join(evs: Vec<Ev>) -> Vec<Trace> {
    let mut g: BTreeMap<(u64, bool), Vec<Ev>> = BTreeMap::new();
    for e in evs {
        g.entry((e.key, e.stage >= R_RX)).or_default().push(e);
    }
    let mut v: Vec<Trace> = g
        .into_iter()
        .map(|((key, replica), mut evs)| {
            evs.sort_by_key(|e| e.t);
            Trace { key, replica, evs }
        })
        .collect();
    v.sort_by_key(|t| t.evs[0].t);
    v
}

// ---------------------------------------------------------------------------------------------------------- output

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    Plain,
    Json,
    JsonPretty,
    Jsonl,
}

impl Format {
    /// Ceph `format` argument; unknown = `None`. Absent = json-pretty (admin socket default).
    pub fn parse(s: Option<&str>) -> Option<Format> {
        match s {
            None | Some("json-pretty") => Some(Format::JsonPretty),
            Some("json") => Some(Format::Json),
            Some("jsonl") => Some(Format::Jsonl),
            Some("plain") => Some(Format::Plain),
            Some(_) => None,
        }
    }
}

/// `dump_op_traces` body: the last `last` traces (0 = all).
pub fn render_dump(mut traces: Vec<Trace>, last: usize, f: Format) -> Vec<u8> {
    if last > 0 && traces.len() > last {
        traces.drain(..traces.len() - last);
    }
    match f {
        Format::Jsonl => {
            let mut out = Vec::new();
            for t in &traces {
                out.extend(t.to_json().to_string().into_bytes());
                out.push(b'\n');
            }
            out
        }
        Format::Plain => {
            let mut s = String::new();
            for t in &traces {
                let j = t.to_json();
                s += &format!(
                    "{} {} core {} pg {} {} {} size {} total {:.1} us{}\n",
                    j["trace_id"].as_str().unwrap_or(""),
                    j["role"].as_str().unwrap_or(""),
                    j["core"],
                    j["pg"].as_str().unwrap_or(""),
                    j["type"].as_str().unwrap_or(""),
                    j["op"].as_str().unwrap_or(""),
                    j["size"],
                    j["total_ns"].as_u64().unwrap_or(0) as f64 / 1e3,
                    if t.complete() { "" } else { " INCOMPLETE" }
                );
                for st in j["stages"].as_array().into_iter().flatten() {
                    s += &format!(
                        "  {:<10} core {:<3} +{:>9.1} us{}\n",
                        st["stage"].as_str().unwrap_or(""),
                        st["core"],
                        st["delta_ns"].as_u64().unwrap_or(0) as f64 / 1e3,
                        st.get("peer")
                            .map_or(String::new(), |p| format!("  osd.{p}"))
                    );
                }
            }
            s.into_bytes()
        }
        Format::Json | Format::JsonPretty => {
            let ops: Vec<Value> = traces.iter().map(Trace::to_json).collect();
            json!({"schema": 1, "num_traces": ops.len(), "traces": ops})
                .to_string()
                .into_bytes()
        }
    }
}

/// Percentile (nearest rank) of a sorted slice, `p` in (0, 1].
fn pct(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (p * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn size_class(size: u32) -> &'static str {
    match size {
        0..=4096 => "le4k",
        4097..=65536 => "le64k",
        65537..=1048576 => "le1m",
        _ => "gt1m",
    }
}

/// `trace_summary`: per (role, type, size class) percentiles of every segment, from complete traces.
pub fn summary(traces: &[Trace], sample: u32) -> Value {
    type Key = (&'static str, &'static str, &'static str);
    let mut g: BTreeMap<Key, BTreeMap<&'static str, Vec<u64>>> = BTreeMap::new();
    let mut counts: BTreeMap<Key, u64> = BTreeMap::new();
    let mut complete = 0u64;
    for t in traces.iter().filter(|t| t.complete()) {
        complete += 1;
        let k = (
            if t.replica { "replica" } else { "primary" },
            t.kind(),
            size_class(t.size()),
        );
        *counts.entry(k).or_default() += 1;
        let m = g.entry(k).or_default();
        for (n, v) in t.segments() {
            m.entry(n).or_default().push(v);
        }
    }
    let classes: Vec<Value> = g
        .into_iter()
        .map(|(k, segs)| {
            let segs: serde_json::Map<String, Value> = segs
                .into_iter()
                .map(|(n, mut v)| {
                    v.sort_unstable();
                    let mean = v.iter().sum::<u64>() / v.len() as u64;
                    (
                        n.to_owned(),
                        json!({"n": v.len(), "p50_ns": pct(&v, 0.5), "p99_ns": pct(&v, 0.99),
                            "p999_ns": pct(&v, 0.999), "max_ns": v[v.len() - 1], "mean_ns": mean}),
                    )
                })
                .collect();
            json!({"role": k.0, "type": k.1, "size_class": k.2, "n": counts[&k], "segments": segs})
        })
        .collect();
    json!({"schema": 1, "sample": sample, "traces": traces.len(), "complete": complete, "classes": classes,
        "clock": clock_anchor()})
}

/// The trace clock next to CLOCK_MONOTONIC, read together: `t_ns` / `start_ns` of the traces map to the monotonic clock
/// (kernel tracepoints, `perf -k CLOCK_MONOTONIC`) by `monotonic_ns - trace_ns`.
fn clock_anchor() -> Value {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let t = to_ns(now());
    // SAFETY: clock_gettime writes one timespec we own.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts) };
    let mono = (rc == 0).then(|| ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64);
    json!({"trace_ns": t, "monotonic_ns": mono})
}

/// Plain text of a [`summary`] value.
pub fn summary_plain(s: &Value) -> String {
    let mut o = format!(
        "sample 1/{} traces {} complete {}\n",
        s["sample"], s["traces"], s["complete"]
    );
    for c in s["classes"].as_array().into_iter().flatten() {
        o += &format!(
            "{} {} {} n={}\n  {:<12} {:>9} {:>9} {:>9} {:>9} {:>9}\n",
            c["role"].as_str().unwrap_or(""),
            c["type"].as_str().unwrap_or(""),
            c["size_class"].as_str().unwrap_or(""),
            c["n"],
            "segment (us)",
            "p50",
            "p99",
            "p999",
            "max",
            "mean"
        );
        for (n, v) in c["segments"].as_object().into_iter().flatten() {
            let us = |k: &str| v[k].as_u64().unwrap_or(0) as f64 / 1e3;
            o += &format!(
                "  {:<12} {:>9.1} {:>9.1} {:>9.1} {:>9.1} {:>9.1}\n",
                n,
                us("p50_ns"),
                us("p99_ns"),
                us("p999_ns"),
                us("max_ns"),
                us("mean_ns")
            );
        }
    }
    o
}

/// Classic historic-op event for a primary stage, if it has one.
pub fn classic_event(e: &Ev) -> Option<String> {
    Some(match e.stage {
        SUBMIT => "started".to_owned(),
        DURABLE => "op_commit".to_owned(),
        REP_SEND => format!("waiting for subops from {}", e.aux as i64),
        REP_ACK => format!("sub_op_commit_rec from {}", e.aux as i64),
        REPLY => "commit_sent".to_owned(),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use denc::types::EntityName;

    fn rid(num: i64, tid: u64) -> OsdReqId {
        OsdReqId {
            name: EntityName::new(EntityName::CLIENT, num),
            tid,
            inc: 0,
        }
    }

    fn on(n: u32, ring: usize) -> Tracer {
        let mut t = Tracer::default();
        t.configure(n, ring, 3);
        t
    }

    #[test]
    fn off_is_inert() {
        let mut t = Tracer::default();
        assert!(!t.on());
        t.rx_polled();
        assert_eq!(t.live_n, 0);
        assert!(t.snapshot().is_empty());
    }

    #[test]
    fn sampling_is_deterministic_and_proportional() {
        let t = on(100, 64);
        let hits = (0..100_000u64)
            .filter(|i| t.sampled(key_of(&rid(4123, *i))))
            .count();
        assert!((800..1200).contains(&hits), "{hits}");
        // same verdict on another core / replica with the same N
        let u = on(100, 64);
        assert!(
            (0..2000u64).all(|i| t.sampled(key_of(&rid(7, i))) == u.sampled(key_of(&rid(7, i))))
        );
        assert_ne!(key_of(&rid(1, 1)), key_of(&rid(1, 2)));
        assert_ne!(key_of(&rid(1, 1)), key_of(&rid(2, 1)));
        assert!(on(1, 64).sampled(key_of(&rid(1, 1))));
    }

    #[test]
    fn pg_run_of_the_last_run_splits_exec() {
        let mut t = on(1, 64);
        let k = key_of(&rid(1, 1));
        t.run_start(k); // not a live op: no stamp
        assert!(t.snapshot().is_empty());
        t.op_in(k, 1, 1, 0, 4096, 0);
        let c = t.snapshot()[0].t;
        // a refused first run, then the run that submits
        t.run_start(k);
        t.run_start(k);
        t.bind_write(k, 7, 9);
        t.on_persist(9);
        let evs = t.snapshot();
        let runs: Vec<u64> = evs
            .iter()
            .filter(|e| e.stage == PG_RUN)
            .map(|e| e.aux)
            .collect();
        assert_eq!(runs, [1, 2]);
        let tr = Trace {
            key: k,
            replica: false,
            evs: vec![
                Ev {
                    t: c,
                    stage: PG_IN,
                    ..Ev::default()
                },
                Ev {
                    t: c + 100,
                    stage: PG_RUN,
                    aux: 1,
                    ..Ev::default()
                },
                Ev {
                    t: c + 300,
                    stage: PG_RUN,
                    aux: 2,
                    ..Ev::default()
                },
                Ev {
                    t: c + 450,
                    stage: SUBMIT,
                    ..Ev::default()
                },
            ],
        };
        let s: BTreeMap<_, _> = tr.segments().into_iter().collect();
        let ns = |a: u64| span_ns(c, c + a);
        assert_eq!(
            (s["pg_wait"], s["pg_work"], s["exec"]),
            (ns(300), span_ns(c + 300, c + 450), ns(450))
        );
    }

    #[test]
    fn ring_wraps_and_keeps_newest() {
        let mut t = on(1, 64);
        for i in 0..200u64 {
            t.emit_at(i + 1, 5, RX, i, 0, 0);
        }
        let s = t.snapshot();
        assert_eq!(s.len(), 64);
        assert_eq!(s[0].aux, 136);
        assert_eq!(s[63].aux, 199);
        t.reset();
        assert!(t.snapshot().is_empty());
        t.emit_at(1, 5, RX, 9, 0, 0);
        assert_eq!(t.snapshot().len(), 1);
    }

    /// Primary write with one peer, replica on another tracer: every stage lands, joins, completes.
    #[test]
    fn write_trace_joins_across_cores() {
        let (mut conn, mut pgc, mut link) = (on(1, 256), on(1, 256), on(1, 256));
        let key = key_of(&rid(9, 1));
        conn.rx_polled();
        conn.ingress(key, false, 0);
        pgc.op_in(key, 11, 1, pg_aux(2, 0x1f), 4096, 0x2201);
        pgc.bind_write(key, 77, 5);
        pgc.on_persist(5);
        pgc.rep_send(77, 2);
        pgc.rep_ack(77, 2);
        pgc.durable(5);
        assert_eq!(pgc.reply(11, 1), Some(key));
        assert_eq!(pgc.live_n, 0);
        link.await_tx(key, TX);
        assert!(link.tx_pending());
        link.tx_done();
        let mut all = conn.snapshot();
        all.extend(pgc.snapshot());
        all.extend(link.snapshot());
        let tr = join(all);
        assert_eq!(tr.len(), 1);
        let t = &tr[0];
        assert!(t.complete());
        assert_eq!(t.kind(), "write");
        let j = t.to_json();
        assert_eq!(j["pg"], "2.1f");
        assert_eq!(j["size"], 4096);
        assert_eq!(j["op"], "write");
        let names: Vec<_> = j["stages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["stage"].as_str().unwrap())
            .collect();
        for n in [
            "rx", "routed", "pg_in", "submit", "durable", "rep_send", "rep_ack", "reply", "tx",
        ] {
            assert!(names.contains(&n), "{n} in {names:?}");
        }
        assert!(j["segments"]["repop_rtt"].is_u64());
    }

    #[test]
    fn replica_trace() {
        let (mut conn, mut pgc) = (on(1, 256), on(1, 256));
        let key = key_of(&rid(9, 2));
        let pg = pg_aux(2, 3);
        conn.ingress(key, true, pg);
        pgc.repl_pg(key, 40, pg);
        pgc.on_persist(8);
        pgc.repl_done();
        pgc.durable(8);
        assert_eq!(pgc.ack_out(40, pg), Some(key));
        pgc.await_tx(key, R_TX);
        pgc.tx_done();
        let mut all = conn.snapshot();
        all.extend(pgc.snapshot());
        let tr = join(all);
        assert_eq!(tr.len(), 1);
        assert!(tr[0].replica && tr[0].complete());
        assert_eq!(tr[0].to_json()["role"], "replica");
    }

    #[test]
    fn live_table_overwrites_oldest() {
        let mut t = on(1, 64);
        for i in 0..(LIVE_CAP as u64 + 5) {
            t.op_in(i + 1, 1, i, 0, 0, 0);
        }
        assert_eq!(t.live_n, LIVE_CAP);
        assert_eq!(t.dropped, 5);
        assert_eq!(t.reply(1, 0), None); // evicted
        assert!(t.reply(1, 68).is_some());
    }

    /// A changed trace config starts a new sampling period: the events and live ops of the previous one must not show up
    /// in the next `dump_op_traces` (turning the sampler off and on again, or changing `n`).
    #[test]
    fn a_new_sampling_period_starts_empty() {
        let mut t = on(100, 4096);
        let k = key_of(&rid(1, 1));
        t.op_in(k, 1, 1, 0, 8, 0x1201);
        assert!(!t.snapshot().is_empty());
        assert_eq!(t.live_n, 1);
        t.configure(0, 4096, 3);
        assert!(!t.on());
        t.configure(100, 4096, 3);
        assert!(t.snapshot().is_empty());
        assert_eq!(t.live_n, 0);
        // a different sample rate is a new period too
        t.op_in(k, 1, 1, 0, 8, 0x1201);
        t.configure(50, 4096, 3);
        assert!(t.snapshot().is_empty());
        assert_eq!(t.live_n, 0);
        // an unchanged config keeps the running period
        t.op_in(k, 1, 1, 0, 8, 0x1201);
        t.configure(50, 4096, 3);
        assert!(!t.snapshot().is_empty());
        assert_eq!(t.live_n, 1);
    }

    #[test]
    fn percentile_math() {
        let v: Vec<u64> = (1..=1000).collect();
        assert_eq!(pct(&v, 0.5), 500);
        assert_eq!(pct(&v, 0.99), 990);
        assert_eq!(pct(&v, 0.999), 999);
        assert_eq!(pct(&[7], 0.999), 7);
        assert_eq!(pct(&[], 0.5), 0);
    }

    #[test]
    fn jsonl_lines_are_complete_objects() {
        let mut t = on(1, 256);
        for i in 0..3u64 {
            let k = key_of(&rid(1, i));
            t.ingress(k, false, 0);
            t.op_in(k, 1, i, pg_aux(1, 0), 512, 0x1201);
            t.reply(1, i);
        }
        let out = render_dump(join(t.snapshot()), 2, Format::Jsonl);
        let s = String::from_utf8(out).unwrap();
        assert!(s.ends_with('\n'));
        let lines: Vec<_> = s.lines().collect();
        assert_eq!(lines.len(), 2);
        for l in lines {
            let v: Value = serde_json::from_str(l).unwrap();
            assert_eq!(v["type"], "read");
            assert_eq!(v["complete"], false); // no tx stamp
        }
    }

    /// The JSON field set is the interface (doc/ops/op-trace.md, schema 1): renames must bump `schema`.
    #[test]
    fn json_schema_is_stable() {
        let mut t = on(1, 256);
        let k = key_of(&rid(1, 1));
        t.ingress(k, false, 0);
        t.op_in(k, 1, 1, pg_aux(1, 0), 4096, 0x2201);
        t.bind_write(k, 5, 6);
        t.on_persist(6);
        t.durable(6);
        t.reply(1, 1);
        t.await_tx(k, TX);
        t.tx_done();
        let tr = join(t.snapshot());
        let mut keys: Vec<_> = tr[0]
            .to_json()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "complete", "core", "op", "pg", "role", "segments", "size", "stages", "start_ns",
                "total_ns", "trace_id", "type"
            ]
        );
        let st = &tr[0].to_json()["stages"][0];
        let mut sk: Vec<_> = st.as_object().unwrap().keys().cloned().collect();
        sk.sort();
        assert_eq!(sk, ["core", "delta_ns", "stage", "t_ns"]);
        let s = summary(&tr, 1);
        let mut sk: Vec<_> = s.as_object().unwrap().keys().cloned().collect();
        sk.sort();
        assert_eq!(
            sk,
            ["classes", "clock", "complete", "sample", "schema", "traces"]
        );
        assert!(s["clock"]["trace_ns"].is_u64() && s["clock"]["monotonic_ns"].is_u64());
        let seg = &s["classes"][0]["segments"]["store"];
        let mut sk: Vec<_> = seg.as_object().unwrap().keys().cloned().collect();
        sk.sort();
        assert_eq!(
            sk,
            ["max_ns", "mean_ns", "n", "p50_ns", "p999_ns", "p99_ns"]
        );
        assert_eq!(s["classes"][0]["size_class"], "le4k");
    }

    #[test]
    fn format_parse() {
        assert_eq!(Format::parse(None), Some(Format::JsonPretty));
        assert_eq!(Format::parse(Some("jsonl")), Some(Format::Jsonl));
        assert_eq!(Format::parse(Some("xml")), None);
    }
}
