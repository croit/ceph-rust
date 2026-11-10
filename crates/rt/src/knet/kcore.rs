// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! The per-core loop of the kernel tier: completions -> store -> mesh -> OSD timers -> OSD output -> submit,
//! with io_uring completions as the network input.
use super::{KNet, Waited};
use crate::{Idle, XPort};
use osd::{Backend, Osd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Longest sleep of a deep-idle core: the store sweep (1 ms) runs at least this often; also the first-op-after-idle latency
/// policy (doc/perf/idle-wake-20261025.md, adr 0638 rule 7).
const DEEP_IDLE: Duration = Duration::from_millis(1);
/// Wake probes at core start (median = first estimate of the sleep break-even) and their length.
const WAKE_PROBES: usize = 9;
const WAKE_PROBE: Duration = Duration::from_micros(10);

#[derive(Default)]
struct IdleState {
    /// The last iteration did work: the next idle iteration starts the idle period (its clock read = the end of the work).
    after_work: bool,
    /// Start of the current idle period.
    last_work: Duration,
    /// Device-wait parking (adr 0162): start of the current store busy span, learned short-span latency (ns, ~p20),
    /// and the instant until which an idle core sleeps in the ring instead of polling for the completion.
    io_since: Option<Duration>,
    io_est_ns: u64,
    park_until: Duration,
    /// Park fraction of the learned latency in percent (0 = off).
    park_pct: u32,
    parks: u64,
    /// Parks timed by the device hint (part of `parks`).
    hint_parks: u64,
    /// Store completions wake the ring (`kernel:` devices, adr 0169) and an idle core with IO in flight sleeps until one
    /// does (no timer, capped by [`IRQ_PARK`]).
    irq_full: bool,
    /// Start of the device's expected completion window, from the last wait hint before it (adr 0004 am. 1).
    window_at: Duration,
}

/// Longest sleep of a core waiting for a waking store completion: bounds store states that are busy without device IO.
const IRQ_PARK: Duration = Duration::from_micros(200);

/// Shortest worthwhile park: a ring wait costs a syscall + timer; below this spinning is cheaper.
const MIN_PARK: Duration = Duration::from_micros(15);

impl IdleState {
    /// Track store busy spans on the loop time `now`: start and end come from the same per-iteration clock read (adr 0006
    /// am. 4).
    /// `learn`: a span end seen on a work iteration is a completion (an idle-iteration end is not timed).
    fn io_note(&mut self, quiet: bool, now: Duration, learn: bool) {
        if self.park_pct == 0 {
            return;
        }
        match (quiet, self.io_since) {
            (false, None) => {
                self.io_since = Some(now);
                let park = Duration::from_nanos(self.io_est_ns * u64::from(self.park_pct) / 100);
                self.park_until = if park >= MIN_PARK {
                    now + park
                } else {
                    Duration::ZERO
                };
            }
            (true, Some(s)) => {
                if learn {
                    let lat = now.saturating_sub(s).as_nanos().min(2_000_000) as u64;
                    let e = self.io_est_ns;
                    self.io_est_ns = if e == 0 {
                        lat
                    } else if lat < e {
                        e - (e - lat) / 4
                    } else {
                        e + (lat - e) / 16
                    };
                }
                self.io_since = None;
                self.park_until = Duration::ZERO;
            }
            _ => {}
        }
    }

    /// Ring sleep cap of an idle iteration (`None` = poll on); `wake` = measured wake latency of a ring sleep (`KCore::wake_ns`).
    /// Wakeable wait (quiet store, wake handles): every event that can end it wakes the ring, so the core sleeps at once, up to
    /// [`DEEP_IDLE`] (polling first only burns CPU: measured, no gain). A wait that only polling can end (store IO in flight, mesh
    /// without wake handle) polls until the idle period is as old as one wake latency, then sleeps: a timer sleep shorter than
    /// the wake latency costs more than it saves, so there is no fixed re-sleep time; the cap is `park_pct` percent of the
    /// period's age, at least `wake` (a long wait costs a logarithmic number of wake-ups, the completion is late by at most
    /// that share).
    /// `hint` (polled store devices, adr 0004 am. 1): the earliest in-flight command may complete in `hint` by the device's
    /// learned service times. A hint of at least two late wake latencies (`wake.late`, ~p80 overshoot) parks until one late
    /// wake latency before it (the wake-up lands before the completion); a shorter one polls (a sleep would oversleep
    /// it). Without a hint (none learned, every command past its learned bound) the rules above apply.
    fn cap(
        &mut self,
        idle: Idle,
        now: Duration,
        work: bool,
        store: StoreWait,
        deep_ready: bool,
        wake: Wake,
    ) -> Option<Duration> {
        let Wake { typ: wake, late } = wake;
        let (quiet, hint) = match store {
            StoreWait::Quiet => (true, None),
            StoreWait::Busy(h) => (false, h),
        };
        if work {
            self.after_work = true;
            return None;
        }
        if std::mem::take(&mut self.after_work) {
            self.last_work = now;
        }
        if !matches!(idle, Idle::Sleep) {
            return None;
        }
        if !quiet && self.irq_full {
            self.parks += 1;
            return Some(IRQ_PARK);
        }
        // The device hint (adr 0004 am. 1): before the window park until one late wake before it, poll its start; inside it
        // the age rule runs from the window start, so a long window (deep queues, large commands) is not spun through.
        let mut since = self.last_work;
        if !quiet && let Some(h) = hint {
            if h >= late * 2 {
                self.parks += 1;
                self.hint_parks += 1;
                return Some(h - late);
            }
            if !h.is_zero() {
                self.window_at = now + h;
                return None;
            }
            since = since.max(self.window_at);
        } else if !quiet && now < self.park_until {
            self.parks += 1;
            return Some(self.park_until - now);
        }
        let age = now.saturating_sub(since);
        if quiet && deep_ready {
            Some(DEEP_IDLE)
        } else if age < wake {
            None
        } else if quiet {
            Some(wake)
        } else {
            let share = age * self.park_pct / 100;
            Some(share.clamp(wake, DEEP_IDLE))
        }
    }
}

/// Measured wake latency (overshoot) of a timed ring sleep: `typ` tracks the low end (sleep break-even), `late` the high end
/// (~p80: how early a sleep must end to be awake before a deadline).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Wake {
    typ: Duration,
    late: Duration,
}

/// Store state of an idle iteration: quiet (nothing in flight or queued), or busy with the devices' wait hint (see
/// `IdleState::cap`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreWait {
    Quiet,
    Busy(Option<Duration>),
}

/// A ring sleep of an idle iteration: its cap, whether store IO was in flight (a park), the poke wake latency.
#[derive(Debug, Clone, Copy)]
struct Slept {
    cap: Duration,
    park: bool,
    /// How it ended; a sleep that ran into its cap (no completion, no poke) overshoots by one wake latency.
    end: Waited,
}

/// One core of the kernel tier: transport plus loop state.
#[derive(Debug)]
pub struct KCore {
    /// Transport.
    pub net: KNet,
    idle: Idle,
    t0: crate::fastclock::Mono,
    osd_due: Option<Duration>,
    /// Loop iterations.
    pub iters: u64,
    /// Idle iterations.
    pub idle_iters: u64,
    /// Sleeps taken in deep idle (store quiet, wake handles installed).
    pub deep_sleeps: u64,
    /// Idle iterations with store IO in flight (polled the device) and ring parks until the expected completion (adr 0162).
    pub store_waits: u64,
    pub io_parks: u64,
    /// Parks timed by the device hint (adr 0004 am. 1) and parks an event ended before their cap (a message or poke
    /// arrived: it waited one wake latency).
    pub hint_parks: u64,
    pub park_cut: u64,
    /// Wall ns slept while store IO was in flight, and the part beyond the requested cap (timer/wake overshoot).
    pub park_ns: u64,
    pub park_over_ns: u64,
    /// Learned short store-span latency (ns).
    pub io_est_ns: u64,
    /// Wake latency of this core's ring sleeps (ns, ~p20 of the overshoot of sleeps that ended by their cap): what a sleep
    /// costs in CPU and in the latency of whatever completes meanwhile = how long an idle core polls before it sleeps.
    pub wake_ns: u64,
    /// Late wake latency (ns, ~p80 of the same overshoot): hinted device parks end this early (adr 0004 am. 1).
    pub wake_late_ns: u64,
    /// Wall ns of iterations that did work.
    pub busy_ns: u64,
    /// Longest working iteration (ns) = longest time the sockets of this core went unpolled, and working iterations by
    /// duration: >= 1 ms, >= 10 ms, >= 100 ms (diagnostics: a long iteration leaves every socket of the core unread).
    pub busy_max_ns: u64,
    pub busy_hist: [u64; 3],
    /// Longest time per phase of a working iteration: [net poll (socket reads + the OSD work they drive), store
    /// completions + cross-core pump + timers, output + submit] (ns), and the iterations >= 1 ms by their longest phase.
    pub phase_max_ns: [u64; 3],
    pub long_by_phase: [u64; 3],
    /// Lab (NV_PHASE=<us>, default 10000): store section timing on (`store::diag`) when > 0, and the stall line of the
    /// last iteration at least that long.
    phase_diag: u64,
    stall: Option<String>,
    /// Lab (NV_TL=<ms>): the store timeline line of every window of that many ms (`store::diag::tl_take`), logged as a
    /// stall line with `core=<thread> epoch_ms=<wall clock>` appended (doc/perf/omap-p99-20261024.md).
    tl: bool,
    /// Phase ends of the current iteration (after net poll, after timers).
    phase_at: [Duration; 2],
    /// Lab diag (`NV_PHASE`): ends of the store phase's parts (store poll, cross-core pump; timers end at `phase_at[1]`).
    store_at: [Duration; 2],
    /// Lab diag (`NV_PHASE`): end of the last idle iteration's body (before its ring sleep).
    idle_end: Duration,
    /// Lab diag (`NV_PHASE`): transport and cross-core counters at the start of the current iteration; its stall line
    /// reports the deltas (what the iteration received, sent and handled).
    io_at: IterIo,
    prev_now: Duration,
    prev_work: bool,
    /// The previous iteration ended in a ring sleep: accounted with the next iteration's clock read.
    slept: Option<Slept>,
    /// Ring enters already reported to the OSD (`[poll, submit, wait]`, see `KStats`).
    enters_seen: [u64; 4],
    /// Wake writes already reported to the OSD.
    wake_writes_seen: u64,
}

impl KCore {
    /// Build a core; `t0` is the clock origin shared with `Osd::start`.
    pub fn new(net: KNet, idle: Idle, t0: Instant) -> KCore {
        KCore {
            net,
            idle,
            t0: crate::fastclock::Mono::at(t0),
            osd_due: None,
            iters: 0,
            idle_iters: 0,
            deep_sleeps: 0,
            store_waits: 0,
            io_parks: 0,
            hint_parks: 0,
            park_cut: 0,
            park_ns: 0,
            park_over_ns: 0,
            io_est_ns: 0,
            wake_ns: 0,
            wake_late_ns: 0,
            busy_ns: 0,
            busy_max_ns: 0,
            busy_hist: [0; 3],
            phase_max_ns: [0; 3],
            long_by_phase: [0; 3],
            phase_diag: match std::env::var("NV_PHASE") {
                Ok(v) => {
                    store::diag::enable();
                    // a bare switch ("1", as for the other cores' 1 s stall lines) = 10 ms
                    v.parse::<u64>().ok().filter(|&us| us > 1).unwrap_or(10_000) * 1000
                }
                Err(_) => 0,
            },
            stall: None,
            tl: match super::env_num("NV_TL") {
                Some(ms) if ms > 0 => {
                    store::diag::tl_enable(ms);
                    true
                }
                _ => false,
            },
            phase_at: [Duration::ZERO; 2],
            store_at: [Duration::ZERO; 2],
            idle_end: Duration::ZERO,
            io_at: IterIo::default(),
            prev_now: Duration::ZERO,
            prev_work: false,
            slept: None,
            enters_seen: [0; 4],
            wake_writes_seen: 0,
        }
    }

    /// Fold one measured wake latency into `wake_ns`: down fast, up slowly (a hypervisor stall must not make the core poll for it),
    /// and into `wake_late_ns` mirrored (up fast, down slowly: ~p80; a stall raises it, so hinted parks get rarer, never late).
    fn note_wake_latency(&mut self, over: Duration) {
        let o = over.as_nanos().min(DEEP_IDLE.as_nanos()) as u64;
        let e = self.wake_ns;
        self.wake_ns = if e == 0 {
            o
        } else if o < e {
            e - (e - o) / 4
        } else {
            e + (o - e) / 16
        };
        let l = self.wake_late_ns;
        self.wake_late_ns = if l == 0 {
            o
        } else if o > l {
            l + (o - l) / 4
        } else {
            l - (l - o) / 16
        };
    }

    /// Store phase of the last iteration split into store poll, cross-core pump and timers, in us (stall lines).
    fn store_split(&self) -> [u64; 3] {
        let [a, b] = self.phase_at;
        let [p, x] = self.store_at;
        [
            p.saturating_sub(a),
            x.saturating_sub(p),
            b.saturating_sub(x),
        ]
        .map(|d| d.as_micros() as u64)
    }

    fn wake(&self) -> Wake {
        Wake {
            typ: Duration::from_nanos(self.wake_ns),
            late: Duration::from_nanos(self.wake_late_ns.max(self.wake_ns)),
        }
    }

    /// First estimate of `wake_ns`: median overshoot of a few short ring sleeps of an idle core, before the loop starts.
    fn probe_wake(&mut self) {
        let mut v = [0u64; WAKE_PROBES];
        for o in &mut v {
            let t = Instant::now();
            self.net.wait(WAKE_PROBE);
            *o = t.elapsed().saturating_sub(WAKE_PROBE).as_nanos() as u64;
        }
        v.sort_unstable();
        self.wake_ns = v[WAKE_PROBES / 2].min(DEEP_IDLE.as_nanos() as u64);
        self.wake_late_ns = v[WAKE_PROBES * 4 / 5].min(DEEP_IDLE.as_nanos() as u64);
    }

    /// One loop iteration; true if any work was done.
    fn step<B: Backend>(
        &mut self,
        osd: &mut Osd<B>,
        x: &mut Option<&mut XPort>,
        driven: &mut bool,
    ) -> bool {
        let now = self.t0.elapsed(); // the only clock read of the iteration
        // lab diag: the counters now = at the end of the previous iteration (its stall line reports the deltas)
        let io = (self.phase_diag > 0).then(|| IterIo::of(&self.net.stats, x.as_deref()));
        if self.prev_work {
            let ns = (now - self.prev_now).as_nanos() as u64;
            self.busy_ns += ns;
            self.busy_max_ns = self.busy_max_ns.max(ns);
            for (i, lim) in [1_000_000, 10_000_000, 100_000_000].into_iter().enumerate() {
                self.busy_hist[i] += u64::from(ns >= lim);
            }
            let [a, b] = self.phase_at;
            let ph = [a - self.prev_now, b - a, now - b].map(|d| d.as_nanos() as u64);
            for (m, p) in self.phase_max_ns.iter_mut().zip(ph) {
                *m = (*m).max(p);
            }
            if ns >= 1_000_000 {
                let top = (0..3).max_by_key(|&i| ph[i]).unwrap_or(0);
                self.long_by_phase[top] += 1;
            }
            if self.phase_diag > 0 {
                // the store sections of exactly this iteration (taken after every working one)
                let st = iter_diag();
                if ns >= self.phase_diag {
                    let ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_millis());
                    self.stall = Some(format!(
                        "stall: {} epoch_ms={ms} step_us={} phase_us(net,store,out)={:?} store_split_us(poll,xpump,timer)={:?} store_us=[{st}] {}",
                        std::thread::current().name().unwrap_or("-"),
                        ns / 1000,
                        ph.map(|v| v / 1000),
                        self.store_split(),
                        io.unwrap_or_default().since(&self.io_at)
                    ));
                }
            }
            osd.note_core_busy(ns);
        } else if self.phase_diag > 0 {
            // an idle iteration (no completion, no output) can still run store background work (merge / checkpoint /
            // compaction slices): its body (receive .. end of pass) holds the core the same way
            let st = iter_diag();
            let ns = self.idle_end.saturating_sub(self.prev_now).as_nanos() as u64;
            if ns >= self.phase_diag {
                let [a, b] = self.phase_at;
                let ph = [a - self.prev_now, b - a, self.idle_end.saturating_sub(b)]
                    .map(|d| d.as_nanos() as u64);
                let ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis());
                self.stall = Some(format!(
                    "stall: {} idle-iter epoch_ms={ms} step_us={} phase_us(net,store,out)={:?} store_split_us(poll,xpump,timer)={:?} store_us=[{st}] {}",
                    std::thread::current().name().unwrap_or("-"),
                    ns / 1000,
                    ph.map(|v| v / 1000),
                    self.store_split(),
                    io.unwrap_or_default().since(&self.io_at)
                ));
            }
        }
        if let Some(io) = io {
            self.io_at = io;
            self.net.stats.cqe_peak_ns = 0;
        }
        if let Some(s) = self.slept.take() {
            let d = now.saturating_sub(self.prev_now);
            let slept = d.as_nanos() as u64;
            // a poke stamped before this sleep began (race with the previous one) is no wake of it
            let over = s.end.timed_out.then(|| d.saturating_sub(s.cap));
            osd.note_sleep(
                slept,
                s.end.poke_ns.filter(|&w| w <= slept),
                over.map(|o| o.as_nanos() as u64),
            );
            if let Some(o) = over {
                self.note_wake_latency(o);
            }
            if s.park {
                self.park_cut += u64::from(!s.end.timed_out);
                self.park_ns += slept;
                self.park_over_ns += d.saturating_sub(s.cap).as_nanos() as u64;
            }
        }
        self.prev_now = now;
        let mut work = false;
        // stamp BEFORE the ring is reaped and decoded: rx_poll->routed = the TCP read + msgr2 decode of this iteration
        osd.trace_rx_polled();
        if self.net.poll(osd, now) {
            *driven = true;
            work = true;
        }
        // what this pass queued for other cores (ops decoded here for their PG cores, repops, replies) leaves before the
        // store poll, whose checkpoint step may take a while (adr 0021 am. 80)
        if let Some(x) = x.as_deref_mut()
            && x.flush_out(osd)
        {
            *driven = true;
        }
        if osd.late_pending() {
            // send-first (adr 0008 am. 3): a client write decoded on its own PG core leaves its repops before its local txn
            if self.net.flush_out(osd) {
                self.net.submit_sf(); // frames of a local link only: no enter for re-arms the end of the step submits anyway
            }
            osd.apply_late();
        }
        self.phase_at[0] = self.t0.elapsed();
        if osd.poll_store(now) {
            *driven = true;
        }
        if self.phase_diag > 0 {
            self.store_at[0] = self.t0.elapsed();
        }
        if let Some(x) = x.as_deref_mut()
            && x.pump_with(osd, now, &mut |o| {
                if self.net.flush_out(o) {
                    self.net.submit_sf();
                }
            })
        {
            *driven = true;
        }
        if self.phase_diag > 0 {
            self.store_at[1] = self.t0.elapsed();
        }
        if self.osd_due.is_some_and(|d| d <= now) {
            osd.on_timer(now);
            *driven = true;
        }
        self.phase_at[1] = self.t0.elapsed();
        // every iteration: output queued outside a "driven" producer leaves before the core parks (adr 0074 am. 4)
        if self.net.output_pass(osd, now, *driven) || *driven {
            self.osd_due = osd.next_timer();
            *driven = false;
            work = true;
        }
        osd.end_pass(); // WAL group commit of the txns this pass submitted (adr 0021 am. 67)
        #[cfg(feature = "kernel-nvme")]
        nvme::kdev::flush(); // store IO queued in this iteration: one submit for all queues (adr 0169)
        self.net.submit();
        let s = &self.net.stats;
        let e = [s.enters_poll, s.enters_submit, s.enters_wait, s.enters_sf];
        osd.note_ring_enters([0, 1, 2, 3].map(|i| e[i] - self.enters_seen[i]));
        self.enters_seen = e;
        osd.note_net_diag(s.rx_bytes, s.rx_pauses, s.rx_pause_ns, self.busy_hist);
        let w = self.net.wake_writes();
        osd.note_wake_writes(w - self.wake_writes_seen);
        self.wake_writes_seen = w;
        #[cfg(feature = "rdma")]
        if let Some(st) = self.net.rdma_status(now) {
            osd.note_rdma(st, super::krdma::process());
        }
        if work {
            osd.trace_tx_done();
        } else if self.phase_diag > 0 {
            self.idle_end = self.t0.elapsed();
        }
        self.prev_work = work;
        work
    }

    /// Run the OSD until it exits or `stop` is set (then graceful shutdown first). Returns the exit code.
    pub fn run_osd_x<B: Backend>(
        &mut self,
        osd: &mut Osd<B>,
        mut x: Option<&mut XPort>,
        stop: &Arc<AtomicBool>,
        mut log: impl FnMut(osd::LogLine),
    ) -> i32 {
        osd.start(self.t0.elapsed());
        osd.set_local_send_first(true);
        self.probe_wake();
        let mut driven = true;
        let mut stopping = false;
        let store_irq = self.store_wake_setup(&mut log);
        let irq_pct = self.net.cfg.store_irq_park_pct;
        let mut idle_state = IdleState {
            park_pct: if store_irq {
                irq_pct % 100
            } else {
                self.net.cfg.store_park_pct
            },
            irq_full: store_irq && irq_pct >= 100,
            ..IdleState::default()
        };
        // store state seen at the end of a work iteration: its IO was submitted / completed during that iteration's work, so
        // it is timed by the next iteration's clock read (the end of that work), not by this iteration's start
        let mut io_late: Option<bool> = None;
        loop {
            if !stopping && stop.load(Ordering::Relaxed) {
                stopping = true;
                osd.shutdown(self.t0.elapsed());
                driven = true;
            }
            let work = self.step(osd, &mut x, &mut driven);
            if let Some(l) = self.stall.take() {
                log(osd::LogLine { prio: 0, text: l });
            }
            if self.tl
                && let Some(l) = store::diag::tl_take(self.busy_ns)
            {
                // core and wall clock appended (parsers read `tl win_us=..` first): lines of several cores and hosts line up
                // with client-side and host samples
                let ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis());
                log(osd::LogLine {
                    prio: 0,
                    text: format!(
                        "stall: {l} core={} epoch_ms={ms}",
                        std::thread::current().name().unwrap_or("-")
                    ),
                });
            }
            if let Some(q) = io_late.take() {
                idle_state.io_note(q, self.prev_now, true);
            }
            self.iters += 1;
            while let Some(l) = osd.poll_log() {
                log(l);
            }
            // exit at once (classic fast shutdown; RDMA sessions, upgraded knet sessions, leave here too): the mon acked
            // the mark-down. A socket closed with unread inbound data sends RST and its send buffer is dropped; replies lost
            // so (or still queued in user space) are resent by the clients and answered from the PG log dup (reqid)
            if let Some(code) = osd.exit_code() {
                while let Some(l) = osd.poll_log() {
                    log(l);
                }
                return code;
            }
            if work {
                if idle_state.park_pct != 0 {
                    io_late = Some(osd.store_quiet());
                }
                idle_state.cap(
                    self.idle,
                    self.prev_now,
                    true,
                    StoreWait::Busy(None),
                    false,
                    Wake::default(),
                );
                continue;
            }
            self.idle_iters += 1;
            osd.note_idle_iter();
            match self.idle {
                Idle::Spin => std::hint::spin_loop(),
                Idle::Sleep => {
                    // deep idle (wake handles installed: mesh senders poke us, so does a receiver that frees ring space
                    // for our backlog): nothing in flight in the store, so nothing needs polling; once the idle period is
                    // as old as a wake costs, sleep until a ring completion / poke / timer (cap DEEP_IDLE: store sweep)
                    let deep_ready = self.net.has_wake();
                    let quiet = osd.store_quiet();
                    idle_state.io_note(quiet, self.prev_now, false);
                    // polled devices (no completion wake-up): when may the store's IO complete (adr 0004 am. 1)
                    let store = if quiet {
                        StoreWait::Quiet
                    } else if idle_state.irq_full {
                        StoreWait::Busy(None)
                    } else {
                        StoreWait::Busy(osd.store_wait_hint())
                    };
                    self.store_waits += u64::from(!quiet);
                    if let Some(mut cap) = idle_state.cap(
                        self.idle,
                        self.prev_now,
                        false,
                        store,
                        deep_ready,
                        self.wake(),
                    ) {
                        // block in the ring: a completion wakes us at once, the cap bounds the latency of what the
                        // ring cannot signal (store completions, mesh messages without wake)
                        for d in [self.osd_due, self.net.next_due()].into_iter().flatten() {
                            cap = cap.min(d.saturating_sub(self.prev_now));
                        }
                        // RDMA: request a CQ event, put its channel into the ring and look at the CQ once more; a
                        // completion that arrived before the arming raises no event (verbs rule), so work found here
                        // means no sleep
                        #[cfg(feature = "rdma")]
                        if self.net.rdma_sleep_check(osd, self.prev_now) {
                            driven = true;
                            continue;
                        }
                        if !quiet && store_irq {
                            #[cfg(feature = "kernel-nvme")]
                            if nvme::kdev::thread_ready() {
                                continue; // a device completion is already there: no sleep
                            }
                            self.net.arm_store_wake();
                        }
                        // the last re-check, after the sleep is announced; only a sleep that happens is booked (the
                        // output audit of adr 0074 am. 4 included)
                        let end = self.net.wait_if(cap, || {
                            let idle = x
                                .as_deref()
                                .is_none_or(|x| x.inbox_empty() && !x.backlog_movable())
                                && !osd.input_resumable()
                                && !osd.handed_work();
                            if idle {
                                osd.note_park();
                            }
                            idle
                        });
                        if let Some(end) = end {
                            self.deep_sleeps += u64::from(quiet && deep_ready);
                            // timed by the next iteration's clock read, from this idle iteration's
                            self.slept = Some(Slept {
                                cap,
                                park: !quiet,
                                end,
                            });
                        }
                        self.io_parks = idle_state.parks;
                        self.hint_parks = idle_state.hint_parks;
                        self.io_est_ns = idle_state.io_est_ns;
                    } else {
                        std::hint::spin_loop();
                    }
                }
            }
        }
    }

    /// `kernel:` store devices in this process (adr 0169): this core's device ring wakes the ring sleep. Returns whether it does.
    fn store_wake_setup(&mut self, log: &mut impl FnMut(osd::LogLine)) -> bool {
        #[cfg(feature = "kernel-nvme")]
        if nvme::kdev::active() {
            match nvme::kdev::thread_ring_fd() {
                Ok(fd) => {
                    self.net.set_store_wake(fd);
                    return true;
                }
                Err(e) => log(osd::LogLine {
                    prio: 0,
                    text: format!("knet: store device ring: {e} (store completions polled)"),
                }),
            }
        }
        let _ = log;
        false
    }
}

/// Store sections of this iteration plus, with the payload hugepage heap (feature `eal-heap`), its EAL heap calls
/// (`eal_alloc` / `eal_free` = calls:KiB; every `rte_free` zeroes its block on this core), for `NV_PHASE` stall lines.
fn iter_diag() -> String {
    let st = store::diag::take().unwrap_or_default();
    #[cfg(feature = "eal-heap")]
    {
        let [ac, ab, fc, fb] = eal_heap::eal_diag_take();
        if ac + fc > 0 {
            let sep = if st.is_empty() { "" } else { "," };
            return format!(
                "{st}{sep}eal_alloc={ac}:{},eal_free={fc}:{}",
                ab >> 10,
                fb >> 10
            );
        }
    }
    st
}

/// Lab diag (`NV_PHASE`): transport and cross-core counters of one core at an iteration boundary. Two snapshots give
/// what one iteration received, sent and handled: a long net phase that drained many sockets (bytes, completions,
/// re-reap passes) differs from one long completion that ran an op inline (`cqe_peak`), and a long cross-core pump
/// shows its messages by kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct IterIo {
    rx_bytes: u64,
    rx_cqes: u64,
    tx_bytes: u64,
    tx_cqes: u64,
    more: u64,
    /// Longest single completion handler since the last reset (ns) and its kind.
    cqe_peak: (u64, u64),
    /// Cross-core messages handled by kind (op, wire, other): count, ns (`XPort::msg_stat`, kept under `NV_PHASE`).
    xmsg: [(u64, u64); 3],
}

impl IterIo {
    fn of(s: &super::KStats, x: Option<&XPort>) -> IterIo {
        IterIo {
            rx_bytes: s.rx_bytes,
            rx_cqes: s.rx_cqes,
            tx_bytes: s.tx_bytes,
            tx_cqes: s.tx_cqes,
            more: s.rx_more_passes,
            cqe_peak: (s.cqe_peak_ns, s.cqe_peak_kind),
            xmsg: x.map_or([(0, 0); 3], |x| x.msg_stat.map(|(n, ns, _)| (n, ns))),
        }
    }

    /// Stall-line fields of the iteration from `start` to `self`.
    fn since(&self, start: &IterIo) -> String {
        let d = |a: u64, b: u64| a.saturating_sub(b);
        let x: Vec<String> = (0..3)
            .map(|k| {
                format!(
                    "{}:{}",
                    d(self.xmsg[k].0, start.xmsg[k].0),
                    d(self.xmsg[k].1, start.xmsg[k].1) / 1000
                )
            })
            .collect();
        format!(
            "net_io(rx_kib,rx_cqes,tx_kib,tx_cqes,passes)=[{}, {}, {}, {}, {}] cqe_peak_us={}:{} xmsg_n:us(op,wire,other)=[{}]",
            d(self.rx_bytes, start.rx_bytes) >> 10,
            d(self.rx_cqes, start.rx_cqes),
            d(self.tx_bytes, start.tx_bytes) >> 10,
            d(self.tx_cqes, start.tx_cqes),
            d(self.more, start.more),
            self.cqe_peak.0 / 1000,
            super::cqe_kind_name(self.cqe_peak.1),
            x.join(", ")
        )
    }
}

#[cfg(test)]
mod iter_io_tests {
    use super::IterIo;

    #[test]
    fn stall_fields_are_the_iteration_deltas() {
        let start = IterIo {
            rx_bytes: 1 << 20,
            rx_cqes: 10,
            tx_bytes: 4 << 10,
            tx_cqes: 3,
            more: 7,
            cqe_peak: (0, 0),
            xmsg: [(5, 1_000), (1, 0), (0, 0)],
        };
        let end = IterIo {
            rx_bytes: (1 << 20) + (300 << 20),
            rx_cqes: 1_210,
            tx_bytes: (4 << 10) + (8 << 20),
            tx_cqes: 5,
            more: 47,
            cqe_peak: (140_000_000, 5),
            xmsg: [(17, 121_001_000), (1, 0), (2, 3_000)],
        };
        assert_eq!(
            end.since(&start),
            "net_io(rx_kib,rx_cqes,tx_kib,tx_cqes,passes)=[307200, 1200, 8192, 2, 40] cqe_peak_us=140000:drecv \
             xmsg_n:us(op,wire,other)=[12:121000, 0:0, 2:3]"
        );
        // counters that went backwards (never: monotonic) clamp at 0 instead of wrapping
        assert!(
            start
                .since(&end)
                .starts_with("net_io(rx_kib,rx_cqes,tx_kib,tx_cqes,passes)=[0, 0, 0, 0, 0]")
        );
    }
}

#[cfg(test)]
#[path = "idle_tests.rs"]
mod idle_tests;
